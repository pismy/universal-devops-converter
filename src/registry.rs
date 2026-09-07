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
///
/// `@` rather than `:` on purpose — `:` is reserved for a future category
/// qualifier (`security:sarif` vs `quality:sarif`, since SARIF legitimately
/// belongs to both).
pub const VERSION_SEPARATOR: char = '@';

#[derive(Debug)]
pub struct FormatSpec {
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    pub category: Category,
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
        category: Category::Coverage,
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
        id: "cobertura",
        aliases: &["coverage.py"],
        category: Category::Coverage,
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
        id: "jacoco",
        aliases: &[],
        category: Category::Coverage,
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
        category: Category::Tests,
        description: "JUnit XML (tolerant reader covering the usual dialects)",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::tests::junit::read),
        write: Some(formats::tests::junit::write),
    },
    // ---- Code quality ------------------------------------------------------
    FormatSpec {
        id: "checkstyle",
        aliases: &[],
        category: Category::Quality,
        description: "Checkstyle XML (ESLint, PHP_CodeSniffer, golangci-lint, ktlint…)",
        write_notes: &[],
        versions: &[],
        default_version: None,
        read: Some(formats::quality::checkstyle::read),
        write: None,
    },
    FormatSpec {
        id: "sarif",
        aliases: &["sarif-json"],
        category: Category::Quality,
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
        category: Category::Quality,
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
        category: Category::Quality,
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

    // `:` is reserved for a future category qualifier; a user reaching for it
    // deserves a pointer rather than "unknown format 'sarif:2.1.0'".
    if let Some((id, version)) = selector.split_once(':') {
        return Err(Error::config(format!(
            "'{selector}': ':' is reserved for a future category qualifier. \
             Use '{id}{VERSION_SEPARATOR}{version}' to pin a spec version."
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
    fn colon_is_reserved_and_points_at_the_at_sign() {
        let error = resolve("sarif:2.1.0").unwrap_err().to_string();
        assert!(error.contains("reserved"), "{error}");
        assert!(error.contains("sarif@2.1.0"), "{error}");
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
