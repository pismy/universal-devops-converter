//! Shared plumbing for the fixture-driven tests: fixture discovery and
//! schema validation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

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
    /// One JSON Schema per spec version, selected from the document's own
    /// `specVersion`. The prefix names the file family,
    /// e.g. `cyclonedx` for `cyclonedx-1.6.schema.json`.
    JsonPerVersion(&'static str),
    /// One XML Schema per spec version, selected from the document's namespace.
    XsdPerVersion(&'static str),
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
        "trx" => Schema::Xsd("trx.xsd"),
        "istanbul" => Schema::Json("istanbul.schema.json"),
        "eslint" => Schema::Json("eslint.schema.json"),
        "sarif" => Schema::Json("sarif-2.1.0.json"),
        // CycloneDX ships one schema per spec version, and a document says
        // which it claims; validating against the wrong one proves nothing.
        "cyclonedx-json" => Schema::JsonPerVersion("cyclonedx"),
        "spdx-json" => Schema::JsonPerVersion("spdx"),
        "spdx3-json" => Schema::Json("spdx3-3.0.1.schema.json"),
        "cyclonedx-xml" => Schema::XsdPerVersion("cyclonedx"),
        "codeclimate" => Schema::Json("codeclimate.schema.json"),
        "codeclimate-gitlab" => Schema::Json("codeclimate-gitlab.schema.json"),
        "gitlab-sast" => Schema::Json("gitlab-sast-15.2.5.json"),
        "gitlab-dependency-scanning" => Schema::Json("gitlab-dependency-scanning-15.2.5.json"),
        "gitlab-container-scanning" => Schema::Json("gitlab-container-scanning-15.2.5.json"),
        "trivy-json" => {
            Schema::None("Trivy documents the report in its own docs and publishes no JSON Schema")
        }
        "go-coverprofile" | "lcov" | "tap" => {
            Schema::None("a line-oriented text format with no formal grammar")
        }
        "go-test-json" => Schema::None(
            "a stream of JSON documents, one per line; a JSON Schema describes one document, \
             not a stream",
        ),
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
        Schema::XsdPerVersion(family) => {
            // The spec version is in the namespace, which is the only place an
            // XML CycloneDX document states it.
            let version = xml_namespace_version(bytes).ok_or_else(|| {
                format!("{origin} declares no CycloneDX namespace, so no schema could be chosen")
            })?;
            let file = format!("{family}-{version}.xsd");
            let path = schemas_dir().join(&file);
            if !path.exists() {
                return Err(format!(
                    "{origin} declares namespace version {version}, but {file} is not vendored"
                ));
            }
            validate_xml(&["--schema"], &path, bytes, origin)
        }
        Schema::JsonPerVersion(family) => {
            let version = spec_version(bytes).ok_or_else(|| {
                format!("{origin} declares no `specVersion`, so no schema could be chosen")
            })?;
            let file = format!("{family}-{version}.schema.json");
            let path = schemas_dir().join(&file);
            if !path.exists() {
                return Err(format!(
                    "{origin} declares specVersion {version}, but {file} is not vendored"
                ));
            }
            validate_json(&path, bytes, origin)
        }
        Schema::Xsd(file) => validate_xml(&["--schema"], &schemas_dir().join(file), bytes, origin),
        Schema::Dtd(file) => {
            validate_xml(&["--dtdvalid"], &schemas_dir().join(file), bytes, origin)
        }
    }
}

/// The spec version out of a CycloneDX XML namespace declaration.
fn xml_namespace_version(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
    let marker = "http://cyclonedx.org/schema/bom/";
    let start = text.find(marker)? + marker.len();
    let version: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!version.is_empty()).then_some(version)
}

/// The `specVersion` a JSON document claims, used to pick its schema.
fn spec_version(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    // CycloneDX calls it `specVersion`, SPDX `spdxVersion`.
    value
        .get("specVersion")
        .or_else(|| value.get("spdxVersion"))?
        .as_str()
        .map(str::to_string)
}

/// Resolves the `$ref`s a schema makes to other schemas, from
/// `tests/schemas/` instead of over the network.
///
/// CycloneDX's schema references `jsf-0.82.schema.json` and
/// `spdx.schema.json` by absolute URL. Fetching those at test time would make
/// the suite depend on the network and on those files not changing, which is
/// exactly what vendoring is for — so they are vendored too, and looked up by
/// file name.
struct VendoredSchemas;

impl jsonschema::Retrieve for VendoredSchemas {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let name = uri
            .path()
            .as_str()
            .rsplit('/')
            .next()
            .ok_or("the reference names no file")?;
        let path = schemas_dir().join(name);
        if !path.exists() {
            return Err(format!(
                "{uri} is referenced by a vendored schema but {name} is not vendored; \
                 download it into tests/schemas/ rather than letting the suite reach the network"
            )
            .into());
        }
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

/// Compiled validators, kept for the life of the test run.
///
/// Compiling a schema is not free — SPDX 3's is 265 KB across 449 definitions,
/// and rebuilding it for every conversion took the matrix from under a second
/// to nearly two minutes. The schemas are immutable files, so one compilation
/// each is enough.
fn validator_for(schema_path: &Path) -> Result<Arc<jsonschema::Validator>, String> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<jsonschema::Validator>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    if let Some(validator) = cache
        .lock()
        .expect("the cache is not poisoned")
        .get(schema_path)
    {
        return Ok(Arc::clone(validator));
    }

    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(schema_path).map_err(|e| format!("cannot read {schema_path:?}: {e}"))?,
    )
    .map_err(|e| format!("{schema_path:?} is not valid JSON: {e}"))?;

    let validator = Arc::new(
        jsonschema::options()
            .with_retriever(VendoredSchemas)
            .build(&schema)
            .map_err(|e| format!("{schema_path:?} is not a usable JSON Schema: {e}"))?,
    );
    cache
        .lock()
        .expect("the cache is not poisoned")
        .insert(schema_path.to_path_buf(), Arc::clone(&validator));
    Ok(validator)
}

fn validate_json(schema_path: &Path, bytes: &[u8], origin: &str) -> Result<(), String> {
    let instance: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("{origin} is not valid JSON: {e}"))?;

    let validator = validator_for(schema_path)?;

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
        // CycloneDX's XSD imports another schema by absolute URL; the catalog
        // redirects it to the vendored copy so validation never touches the
        // network. See tests/schemas/catalog.xml.
        .env("XML_CATALOG_FILES", schemas_dir().join("catalog.xml"))
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
