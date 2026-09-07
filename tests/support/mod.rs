//! Shared plumbing for the fixture-driven tests: fixture discovery and
//! schema validation.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use universal_devops_converter::registry::{self, FormatSpec};

pub fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

pub fn fixtures_dir() -> PathBuf {
    manifest_dir().join("tests/fixtures")
}

pub fn schemas_dir() -> PathBuf {
    manifest_dir().join("tests/schemas")
}

// ---------------------------------------------------------------------------
// Fixture discovery
// ---------------------------------------------------------------------------

/// One sample report on disk.
pub struct Fixture {
    pub format: &'static FormatSpec,
    pub path: PathBuf,
    /// True for files under `<format>/invalid/`: reading them must fail.
    pub must_be_rejected: bool,
}

impl Fixture {
    /// Short path used in assertion messages, e.g. `lcov/nyc-istanbul.info`.
    pub fn label(&self) -> String {
        self.path
            .strip_prefix(fixtures_dir())
            .unwrap_or(&self.path)
            .display()
            .to_string()
    }

    pub fn read(&self) -> Vec<u8> {
        std::fs::read(&self.path)
            .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", self.label()))
    }
}

/// Every fixture in `tests/fixtures`, keyed by the format its directory names.
///
/// The directory layout *is* the registration mechanism: dropping a file into
/// `tests/fixtures/<format-id>/` is all it takes for the whole matrix to start
/// exercising it. Nothing here needs editing when a fixture is added.
pub fn fixtures() -> Vec<Fixture> {
    let mut found = Vec::new();
    let root = fixtures_dir();

    let entries =
        std::fs::read_dir(&root).unwrap_or_else(|e| panic!("cannot list {}: {e}", root.display()));

    for entry in entries {
        let dir = entry.expect("readable directory entry").path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .expect("fixture directory has a UTF-8 name")
            .to_string();

        let format = registry::find(&name).unwrap_or_else(|e| {
            panic!(
                "fixture directory 'tests/fixtures/{name}' does not name a known format: {e}\n\
                 Name the directory after a format id from `udc formats`."
            )
        });

        collect_files(&dir, format, false, &mut found);
        let invalid_dir = dir.join("invalid");
        if invalid_dir.is_dir() {
            collect_files(&invalid_dir, format, true, &mut found);
        }
    }

    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

fn collect_files(
    dir: &Path,
    format: &'static FormatSpec,
    must_be_rejected: bool,
    out: &mut Vec<Fixture>,
) {
    for entry in std::fs::read_dir(dir).expect("readable fixture directory") {
        let path = entry.expect("readable directory entry").path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Documentation and editor droppings are not fixtures.
        if name.starts_with('.') || name.eq_ignore_ascii_case("README.md") {
            continue;
        }
        out.push(Fixture {
            format,
            path,
            must_be_rejected,
        });
    }
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

/// How a format's documents are validated, if at all.
pub enum Schema {
    /// JSON Schema, validated in-process.
    Json(&'static str),
    /// XML Schema, validated with `xmllint --schema`.
    Xsd(&'static str),
    /// Document Type Definition, validated with `xmllint --dtdvalid`.
    Dtd(&'static str),
    /// No schema exists for this format; the reason is worth stating.
    None(&'static str),
}

/// The schema each format's documents are checked against.
///
/// Adding a format means adding a line here — deliberately exhaustive rather
/// than defaulting to "no schema", so a new format cannot quietly skip
/// validation. See `tests/schemas/README.md` for provenance.
pub fn schema_for(format_id: &str) -> Schema {
    match format_id {
        "clover" => Schema::Xsd("clover.xsd"),
        "cobertura" => Schema::Dtd("cobertura-04.dtd"),
        "jacoco" => Schema::Dtd("jacoco-report-1.1.dtd"),
        "junit" => Schema::Xsd("junit.xsd"),
        "sarif" => Schema::Json("sarif-2.1.0.json"),
        "codeclimate" => Schema::Json("codeclimate.schema.json"),
        "codeclimate-gitlab" => Schema::Json("codeclimate-gitlab.schema.json"),
        "gitlab-sast" => Schema::Json("gitlab-sast-15.2.5.json"),
        "lcov" => Schema::None("a line-oriented text format with no formal grammar"),
        "checkstyle" => Schema::None("upstream publishes no schema"),
        other => panic!(
            "format '{other}' has no entry in `schema_for`. Add one: either the schema its \
             documents are validated against, or `Schema::None(<why not>)`."
        ),
    }
}

/// Validate `bytes` as a document of `format_id`. `origin` names the thing
/// being checked, for the failure message.
pub fn validate(format_id: &str, bytes: &[u8], origin: &str) -> Result<(), String> {
    match schema_for(format_id) {
        Schema::None(_) => Ok(()),
        Schema::Json(file) => validate_json(&schemas_dir().join(file), bytes, origin),
        Schema::Xsd(file) => validate_xml(&["--schema"], &schemas_dir().join(file), bytes, origin),
        Schema::Dtd(file) => {
            validate_xml(&["--dtdvalid"], &schemas_dir().join(file), bytes, origin)
        }
    }
}

fn validate_json(schema_path: &Path, bytes: &[u8], origin: &str) -> Result<(), String> {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(schema_path).map_err(|e| format!("cannot read {schema_path:?}: {e}"))?,
    )
    .map_err(|e| format!("{schema_path:?} is not valid JSON: {e}"))?;

    let instance: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("{origin} is not valid JSON: {e}"))?;

    let validator = jsonschema::validator_for(&schema)
        .map_err(|e| format!("{schema_path:?} is not a usable JSON Schema: {e}"))?;

    let problems: Vec<String> = validator
        .iter_errors(&instance)
        .map(|error| format!("  at {}: {error}", error.instance_path))
        .take(10)
        .collect();

    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{origin} does not satisfy {}:\n{}",
            schema_path.file_name().unwrap().to_string_lossy(),
            problems.join("\n")
        ))
    }
}

/// True when `xmllint` is on `PATH`. XML schema validation needs it; there is
/// no comparable pure-Rust validator, and shelling out keeps the build free of
/// a libxml2 link dependency.
pub fn xmllint_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Command::new("xmllint")
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    })
}

fn validate_xml(
    flags: &[&str],
    schema_path: &Path,
    bytes: &[u8],
    origin: &str,
) -> Result<(), String> {
    if !xmllint_available() {
        // Not silently ignored: `xmllint_is_available_in_ci` fails the suite
        // where it matters.
        return Ok(());
    }

    // Name the temp file after what is being checked: xmllint prefixes every
    // diagnostic with the path, and "udc-validate-1234.xml:7" tells nobody
    // which fixture or conversion broke.
    let slug: String = origin
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let temp = std::env::temp_dir().join(format!(
        "{slug}--{}-{:?}.xml",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&temp, bytes).map_err(|e| format!("cannot write {temp:?}: {e}"))?;

    let output = Command::new("xmllint")
        .arg("--noout")
        // Never fetch the DOCTYPE's SYSTEM id: validation must use the vendored
        // schema, and the suite must not touch the network.
        .arg("--nonet")
        .args(flags)
        .arg(schema_path)
        .arg(&temp)
        .output()
        .map_err(|e| format!("cannot run xmllint: {e}"))?;

    let kept = temp.clone();
    let _ = std::fs::remove_file(&kept);

    if output.status.success() {
        return Ok(());
    }

    // "failed to load external entity" is the expected consequence of --nonet
    // on a document whose doctype points at a URL; it is a warning, not a
    // validity error, and xmllint still exits 0 when the document is valid.
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "{origin} does not satisfy {}:\n{}",
        schema_path.file_name().unwrap().to_string_lossy(),
        stderr
            .lines()
            .filter(|l| !l.contains("failed to load external entity"))
            .take(10)
            .collect::<Vec<_>>()
            .join("\n")
    ))
}
