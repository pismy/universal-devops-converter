//! The format registry: the single place where a format id becomes a reader
//! and/or a writer.
//!
//! Adding a format means writing its module and adding one entry here. Nothing
//! else in the codebase enumerates formats.

use std::io::Write;

use crate::error::{Error, Result};
use crate::formats;
use crate::model::coverage::CoverageDoc;
use crate::model::findings::FindingsDoc;
use crate::model::tests::TestReport;
use crate::paths::PathMapper;
use crate::warn::{FormatCtx, NoteKind};

/// Report categories. Conversion is only ever defined *within* a category.
///
/// A format may belong to several: SARIF is the canonical case, describing
/// code-quality findings and security findings with the same document shape.
/// That is modelled as a set on the format rather than as two registry entries,
/// because it is what the format actually is — duplicating it under two ids
/// would make `-t sarif` ambiguous for no gain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Category {
    Coverage,
    Tests,
    Quality,
    Security,
    Sbom,
    Accessibility,
    Performance,
}

impl Category {
    /// Every category, in listing order.
    pub const ALL: &'static [Category] = &[
        Category::Coverage,
        Category::Tests,
        Category::Quality,
        Category::Security,
        Category::Sbom,
        Category::Accessibility,
        Category::Performance,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Coverage => "coverage",
            Category::Tests => "tests",
            Category::Quality => "quality",
            Category::Security => "security",
            Category::Sbom => "sbom",
            Category::Accessibility => "accessibility",
            Category::Performance => "performance",
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed report, in pivot form. One variant per pivot model — several
/// categories may share a variant (quality and security both use `Findings`)
/// while still being kept apart by [`Category`].
#[derive(Debug, Clone)]
pub enum Doc {
    Coverage(CoverageDoc),
    Tests(TestReport),
    Findings(FindingsDoc),
}

impl Doc {
    pub fn as_coverage(&self) -> Result<&CoverageDoc> {
        match self {
            Doc::Coverage(doc) => Ok(doc),
            _ => Err(Error::config("expected a coverage report")),
        }
    }

    pub fn as_tests(&self) -> Result<&TestReport> {
        match self {
            Doc::Tests(doc) => Ok(doc),
            _ => Err(Error::config("expected a test report")),
        }
    }

    pub fn as_findings(&self) -> Result<&FindingsDoc> {
        match self {
            Doc::Findings(doc) => Ok(doc),
            _ => Err(Error::config("expected a findings report")),
        }
    }

    /// Fold a second input into this one (repeatable `--input-file`).
    pub fn merge(&mut self, other: Doc) -> Result<()> {
        match (self, other) {
            (Doc::Coverage(a), Doc::Coverage(b)) => a.merge(b),
            (Doc::Tests(a), Doc::Tests(b)) => a.merge(b),
            (Doc::Findings(a), Doc::Findings(b)) => a.merge(b),
            _ => {
                return Err(Error::config(
                    "cannot merge inputs of different report categories",
                ))
            }
        }
        Ok(())
    }

    pub fn normalize_paths(&mut self, mapper: &PathMapper) {
        match self {
            Doc::Coverage(doc) => doc.normalize_paths(mapper),
            Doc::Tests(doc) => doc.normalize_paths(mapper),
            Doc::Findings(doc) => doc.normalize_paths(mapper),
        }
    }

    /// Canonical ordering, so that converting the same input twice yields
    /// byte-identical output.
    pub fn sort(&mut self) {
        match self {
            Doc::Coverage(doc) => doc.sort(),
            Doc::Findings(doc) => doc.sort(),
            // Test suites keep their execution order on purpose.
            Doc::Tests(_) => {}
        }
    }
}

pub type ReadFn = fn(&[u8], &mut FormatCtx) -> Result<Doc>;
pub type WriteFn = fn(&Doc, &mut dyn Write, &mut FormatCtx) -> Result<()>;

/// Separator between a format id and a spec version: `cyclonedx-json@1.6`.
pub const VERSION_SEPARATOR: char = '@';

#[derive(Debug)]
pub struct FormatSpec {
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    /// Every category this format belongs to, most representative first.
    /// Conversion between two formats is allowed when their sets intersect.
    pub categories: &'static [Category],
    pub description: &'static str,
    /// Known notices raised when *writing* this format, shown by `udc formats`.
    /// The kind must match what the writer actually emits at runtime, so the
    /// listing and the stderr output tell the same story.
    pub write_notes: &'static [(NoteKind, &'static str)],
    /// Spec versions this format understands, oldest first. Empty means the
    /// format is not versioned, and an `@version` suffix on it is rejected
    /// rather than silently ignored.
    pub versions: &'static [&'static str],
    /// Version targeted when none is requested.
    ///
    /// Deliberately **not** necessarily the newest one: the newest spec version
    /// is the one the fewest consumers accept, and a report a platform rejects
    /// is worse than one missing a recent field.
    pub default_version: Option<&'static str>,
    pub read: Option<ReadFn>,
    pub write: Option<WriteFn>,
}

impl FormatSpec {
    /// The category a format is listed under first; used in messages.
    pub fn primary_category(&self) -> Category {
        *self
            .categories
            .first()
            .expect("every format declares at least one category")
    }

    pub fn is_in(&self, category: Category) -> bool {
        self.categories.contains(&category)
    }

    /// The category two formats have in common, if any. `None` means the
    /// conversion is undefined, not merely lossy.
    pub fn shared_category(&self, other: &FormatSpec) -> Option<Category> {
        self.categories
            .iter()
            .copied()
            .find(|c| other.categories.contains(c))
    }

    pub fn matches(&self, id: &str) -> bool {
        self.id.eq_ignore_ascii_case(id) || self.aliases.iter().any(|a| a.eq_ignore_ascii_case(id))
    }

    pub fn reader(&self) -> Result<ReadFn> {
        self.read.ok_or_else(|| {
            Error::config(format!(
                "format '{}' cannot be read (it is write-only)",
                self.id
            ))
        })
    }

    pub fn writer(&self) -> Result<WriteFn> {
        self.write.ok_or_else(|| {
            Error::config(format!(
                "format '{}' cannot be written (it is read-only)",
                self.id
            ))
        })
    }
}

/// Every supported format. Order drives the `udc formats` listing.
pub static FORMATS: &[FormatSpec] = &[
    // ---- Code coverage -----------------------------------------------------
    FormatSpec {
        id: "lcov",
        aliases: &["lcov-info"],
        categories: &[Category::Coverage],
        description: "LCOV tracefile (gcov, nyc/istanbul, cargo-llvm-cov, tarpaulin)",
        write_notes: &[
            (
                NoteKind::Degraded,
                "branch block/index identity is synthesized",
            ),
            (
                NoteKind::Lossy,
                "JaCoCo instruction/complexity/method counters are dropped",
            ),
        ],
        versions: &[],
        default_version: None,
        read: Some(formats::coverage::lcov::read),
        write: Some(formats::coverage::lcov::write),
    },
    FormatSpec {
        id: "clover",
        aliases: &[],
        categories: &[Category::Coverage],
        description: "Clover XML (PHPUnit --coverage-clover, Jest's clover reporter)",
        write_notes: &[
            (
                NoteKind::Degraded,
                "a conditional line has exactly two outcomes; branches beyond the second are \
                 folded into them",
            ),
            (
                NoteKind::Lossy,
                "JaCoCo instruction/complexity/method counters are dropped",
            ),
        ],
        versions: &[],
        default_version: None,
        read: Some(formats::coverage::clover::read),
        write: Some(formats::coverage::clover::write),
    },
    FormatSpec {
        id: "cobertura",
        aliases: &["coverage.py"],
        categories: &[Category::Coverage],
        description: "Cobertura XML — the coverage format GitLab CI ingests",
        write_notes: &[(
            NoteKind::Lossy,
            "JaCoCo instruction/complexity/method counters are dropped",
        )],
        versions: &[],
        default_version: None,
        read: Some(formats::coverage::cobertura::read),
        write: Some(formats::coverage::cobertura::write),
    },
    FormatSpec {
        id: "go-coverprofile",
        aliases: &["gocover", "gocoverprofile"],
        categories: &[Category::Coverage],
        description: "Go coverage profile (`go test -coverprofile`)",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::coverage::gocover::read),
        // Read-only: a profile records basic blocks with column positions and
        // statement counts, none of which the pivot holds, and the only
        // consumer is `go tool cover` reading what Go itself just wrote.
        write: None,
    },
    FormatSpec {
        id: "istanbul",
        aliases: &["coverage-final", "nyc"],
        categories: &[Category::Coverage],
        description: "Istanbul JSON coverage map (nyc, Jest's json reporter)",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::coverage::istanbul::read),
        // Read-only on purpose: the format is position-based and the pivot has
        // no columns, so writing it would fabricate every start/end position.
        write: None,
    },
    FormatSpec {
        id: "jacoco",
        aliases: &[],
        categories: &[Category::Coverage],
        description: "JaCoCo XML report",
        write_notes: &[
            (
                NoteKind::Degraded,
                "hit counts are flattened to covered/not-covered (JaCoCo has no hit counter)",
            ),
            (
                NoteKind::Degraded,
                "instruction counters are approximated when the source has none",
            ),
        ],
        versions: &[],
        default_version: None,
        read: Some(formats::coverage::jacoco::read),
        write: Some(formats::coverage::jacoco::write),
    },
    // ---- Tests -------------------------------------------------------------
    FormatSpec {
        id: "junit",
        aliases: &["junit-xml", "surefire"],
        categories: &[Category::Tests],
        description: "JUnit XML (tolerant reader covering the usual dialects)",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::tests::junit::read),
        write: Some(formats::tests::junit::write),
    },
    FormatSpec {
        id: "go-test-json",
        aliases: &["gotest", "gotestjson"],
        categories: &[Category::Tests],
        description: "`go test -json` event stream (NDJSON)",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::tests::gotest::read),
        // Read-only: the stream is a runner's log, and nothing replays one.
        write: None,
    },
    FormatSpec {
        id: "tap",
        aliases: &["tap13", "tap14"],
        categories: &[Category::Tests],
        description: "TAP — Test Anything Protocol 12/13/14",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::tests::tap::read),
        // Read-only: TAP's consumers are test harnesses and a few CI plugins,
        // all of which read JUnit too.
        write: None,
    },
    FormatSpec {
        id: "trx",
        aliases: &["mstest", "vstest"],
        categories: &[Category::Tests],
        description: "TRX — Visual Studio test results (`dotnet test`)",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::tests::trx::read),
        // Read-only: a TRX file is a web of GUID cross-references between
        // Results, TestDefinitions, TestEntries and TestLists that would all
        // have to be fabricated, and its consumers read JUnit too.
        write: None,
    },
    // ---- Code quality ------------------------------------------------------
    FormatSpec {
        id: "checkstyle",
        aliases: &[],
        categories: &[Category::Quality],
        description: "Checkstyle XML (ESLint, PHP_CodeSniffer, golangci-lint, ktlint…)",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::quality::checkstyle::read),
        write: None,
    },
    FormatSpec {
        id: "eslint",
        aliases: &["eslint-json"],
        categories: &[Category::Quality],
        description: "ESLint json formatter output",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::quality::eslint::read),
        // Read-only: ESLint's JSON is consumed by ESLint's own formatters and
        // by editors talking to ESLint, and the pivot has no `fix`,
        // `suggestions` or `nodeType` to put back.
        write: None,
    },
    FormatSpec {
        id: "sarif",
        aliases: &["sarif-json"],
        categories: &[Category::Quality, Category::Security],
        description: "SARIF 2.1.0 (semgrep, CodeQL, gosec, bandit, Checkov…)",
        write_notes: &[
            (
                NoteKind::Degraded,
                "rule metadata is rebuilt by deduplicating findings on their rule id; the first \
                 one seen defines the rule",
            ),
            (
                NoteKind::Degraded,
                "critical and blocker collapse to level \"error\" unless the finding carries a \
                 security identifier",
            ),
            (
                NoteKind::Lossy,
                "identifiers other than CWE survive only as rule tags",
            ),
        ],
        // SARIF 1.0 and the 2.0 drafts are structurally different documents
        // (`resources.rules` moved to `tool.driver.rules`, `files` became
        // `artifacts`); if they ever get support they become their own format
        // id, not another version of this one.
        versions: &["2.1.0"],
        default_version: Some("2.1.0"),
        read: Some(formats::quality::sarif::read),
        write: Some(formats::quality::sarif::write),
    },
    FormatSpec {
        id: "codeclimate",
        aliases: &["code-climate"],
        categories: &[Category::Quality],
        description: "Code Climate issue JSON (full specification)",
        write_notes: &[(
            NoteKind::Lossy,
            "SARIF rule metadata and code flows are not represented",
        )],
        versions: &[],
        default_version: None,
        read: Some(formats::quality::codeclimate::read),
        write: Some(formats::quality::codeclimate::write_full),
    },
    FormatSpec {
        id: "codeclimate-gitlab",
        aliases: &["gitlab-codequality", "codequality"],
        categories: &[Category::Quality],
        description: "Code Climate JSON, GitLab Code Quality subset",
        write_notes: &[(
            NoteKind::Lossy,
            "only description, check_name, fingerprint, severity and the begin location are kept",
        )],
        versions: &[],
        default_version: None,
        read: Some(formats::quality::codeclimate::read),
        write: Some(formats::quality::codeclimate::write_gitlab),
    },
    // ---- Security ----------------------------------------------------------
    FormatSpec {
        id: "trivy-json",
        aliases: &["trivy"],
        categories: &[Category::Security],
        description: "Trivy JSON — dependencies, images, IaC and secrets in one report",
        write_notes: &[],
        versions: &["2"],
        default_version: Some("2"),
        read: Some(formats::security::trivy::read),
        // Read-only: Trivy writes this and nothing else does, and Trivy already
        // emits SARIF, CycloneDX and GitLab's own format on request.
        write: None,
    },
    FormatSpec {
        id: "gitlab-sast",
        aliases: &["gitlab-security"],
        categories: &[Category::Security],
        description: "GitLab SAST security report — feeds the security dashboard",
        write_notes: &[
            (
                NoteKind::Degraded,
                "the schema requires a scan window; a source without one gets a fixed epoch so \
                 the output stays reproducible",
            ),
            (
                NoteKind::Lossy,
                "findings with neither an identifier nor a rule id are dropped (the schema \
                 requires at least one identifier)",
            ),
            (
                NoteKind::Lossy,
                "issue categories have no field in the security report",
            ),
        ],
        versions: &["15.2.5"],
        default_version: Some("15.2.5"),
        read: None,
        write: Some(formats::security::gitlab_sast::write),
    },
];

/// A format plus the spec version to use with it, as named on the command line.
#[derive(Debug, Clone, Copy)]
pub struct Selection {
    pub spec: &'static FormatSpec,
    /// The version to target: the one requested, else the format's default,
    /// else `None` for an unversioned format.
    pub version: Option<&'static str>,
}

impl Selection {
    /// A context for a reader or writer to work in.
    pub fn ctx(&self) -> crate::warn::FormatCtx {
        crate::warn::FormatCtx::new(self.version)
    }
}

/// Resolve a format id or alias, case-insensitively.
pub fn find(id: &str) -> Result<&'static FormatSpec> {
    FORMATS.iter().find(|f| f.matches(id)).ok_or_else(|| {
        let known: Vec<&str> = FORMATS.iter().map(|f| f.id).collect();
        Error::config(format!(
            "unknown format '{id}'. Known formats: {}. Run `udc formats` for details.",
            known.join(", ")
        ))
    })
}

/// Resolve a `<format>[@<version>]` selector, as accepted by `--input-format`
/// and `--output-format`.
pub fn resolve(selector: &str) -> Result<Selection> {
    let selector = selector.trim();

    // Docker-style `format:version` is a natural guess; say so rather than
    // reporting "unknown format 'sarif:2.1.0'".
    if let Some((id, version)) = selector.split_once(':') {
        return Err(Error::config(format!(
            "'{selector}': use '{id}{VERSION_SEPARATOR}{version}' to pin a spec version \
             ('{VERSION_SEPARATOR}', not ':')."
        )));
    }

    let (id, requested) = match selector.split_once(VERSION_SEPARATOR) {
        Some((id, version)) => (id, Some(version.trim())),
        None => (selector, None),
    };
    let spec = find(id)?;

    let Some(requested) = requested else {
        return Ok(Selection {
            spec,
            version: spec.default_version,
        });
    };

    if requested.is_empty() {
        return Err(Error::config(format!(
            "'{selector}': no version after '{VERSION_SEPARATOR}'"
        )));
    }
    if spec.versions.is_empty() {
        return Err(Error::config(format!(
            "format '{}' is not versioned: drop the '{VERSION_SEPARATOR}{requested}' suffix",
            spec.id
        )));
    }

    let version = spec
        .versions
        .iter()
        .find(|v| v.eq_ignore_ascii_case(requested))
        .ok_or_else(|| {
            Error::config(format!(
                "format '{}' does not support version '{requested}'. Supported: {}",
                spec.id,
                spec.versions.join(", ")
            ))
        })?;

    Ok(Selection {
        spec,
        version: Some(version),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_ids_and_aliases_case_insensitively() {
        assert_eq!(find("LCOV").unwrap().id, "lcov");
        assert_eq!(find("gitlab-codequality").unwrap().id, "codeclimate-gitlab");
        assert!(find("nope").is_err());
    }

    #[test]
    fn ids_and_aliases_are_unique() {
        let mut seen: Vec<&str> = Vec::new();
        for format in FORMATS {
            for name in std::iter::once(&format.id).chain(format.aliases) {
                assert!(!seen.contains(name), "duplicate format name '{name}'");
                seen.push(name);
            }
        }
    }

    #[test]
    fn a_declared_default_version_is_one_of_the_declared_versions() {
        for format in FORMATS {
            match format.default_version {
                Some(default) => assert!(
                    format.versions.contains(&default),
                    "format '{}' defaults to a version it does not declare",
                    format.id
                ),
                None => assert!(
                    format.versions.is_empty(),
                    "format '{}' declares versions but no default",
                    format.id
                ),
            }
        }
    }

    #[test]
    fn resolves_a_bare_id_to_its_default_version() {
        let unversioned = resolve("junit").unwrap();
        assert_eq!(unversioned.spec.id, "junit");
        assert_eq!(unversioned.version, None);

        let versioned = resolve("sarif").unwrap();
        assert_eq!(versioned.version, Some("2.1.0"));
    }

    #[test]
    fn resolves_an_explicit_version() {
        let selection = resolve("sarif@2.1.0").unwrap();
        assert_eq!(selection.spec.id, "sarif");
        assert_eq!(selection.version, Some("2.1.0"));
    }

    #[test]
    fn rejects_an_unsupported_version_and_lists_the_supported_ones() {
        let error = resolve("sarif@1.0.0").unwrap_err().to_string();
        assert!(
            error.contains("does not support version '1.0.0'"),
            "{error}"
        );
        assert!(error.contains("2.1.0"), "{error}");
    }

    #[test]
    fn rejects_a_version_on_an_unversioned_format() {
        let error = resolve("junit@1.0").unwrap_err().to_string();
        assert!(error.contains("is not versioned"), "{error}");
    }

    #[test]
    fn rejects_an_empty_version() {
        assert!(resolve("sarif@").is_err());
    }

    #[test]
    fn a_colon_separator_points_at_the_at_sign() {
        let error = resolve("sarif:2.1.0").unwrap_err().to_string();
        assert!(error.contains("sarif@2.1.0"), "{error}");
    }

    #[test]
    fn every_format_declares_at_least_one_category() {
        for format in FORMATS {
            assert!(
                !format.categories.is_empty(),
                "format '{}' belongs to no category",
                format.id
            );
        }
    }

    #[test]
    fn a_shared_category_is_what_makes_a_conversion_legal() {
        let sarif = find("sarif").unwrap();
        let checkstyle = find("checkstyle").unwrap();
        let cobertura = find("cobertura").unwrap();

        assert_eq!(sarif.shared_category(checkstyle), Some(Category::Quality));
        assert_eq!(checkstyle.shared_category(cobertura), None);
    }

    #[test]
    fn every_format_can_be_read_or_written() {
        for format in FORMATS {
            assert!(
                format.read.is_some() || format.write.is_some(),
                "format '{}' does nothing",
                format.id
            );
        }
    }
}
