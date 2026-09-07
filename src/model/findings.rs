//! Pivot model for "located findings" — code quality issues today, security
//! vulnerabilities next (SPECS.md §5.3 and §5.4).
//!
//! Quality and security are two *categories* sharing one pivot: both describe a
//! problem attached to a place in the codebase. What differs is the payload —
//! a quality issue carries `check_name`/`categories`, a vulnerability carries
//! `identifiers[]` and an affected component. The registry keeps the two
//! categories apart so a Checkstyle report can never be written as a
//! dependency-scanning report.

use crate::paths::PathMapper;

/// Code Climate's five levels. They are the sink's vocabulary, so the pivot
/// adopts them and every reader maps onto them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Minor,
    Major,
    Critical,
    Blocker,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Minor => "minor",
            Severity::Major => "major",
            Severity::Critical => "critical",
            Severity::Blocker => "blocker",
        }
    }

    /// Tolerant parsing: covers Code Climate's own vocabulary plus the
    /// synonyms linters actually emit (`warning`, `error`, `note`, `high`…).
    pub fn parse(raw: &str) -> Option<Severity> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "info" | "note" | "notice" | "ignore" | "low" | "informational" => Some(Severity::Info),
            "minor" | "warning" | "warn" | "medium" | "moderate" => Some(Severity::Minor),
            "major" | "error" | "high" => Some(Severity::Major),
            "critical" => Some(Severity::Critical),
            "blocker" | "fatal" => Some(Severity::Blocker),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A machine-readable identifier for a finding: `CWE-79`, `CVE-2024-1234`,
/// `GHSA-xxxx`… Unused by the quality writers, required by the security ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identifier {
    pub kind: String,
    pub value: String,
    pub url: Option<String>,
}

/// The component a finding is about, when the subject is a dependency rather
/// than a line of code.
///
/// A vulnerability is not located at a place in a file the way a lint is: it is
/// located at *a version of a package*, and the fix is another version. Sinks
/// that accept vulnerabilities require exactly that, which is why it lives here
/// and not in the description text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    /// The first version that is not affected, when the source knows one.
    pub fixed_version: Option<String>,
    /// Package URL, the one identifier that travels between ecosystems.
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    /// Repository-relative path, `/`-separated. Empty for a finding that is not
    /// in a file at all — an operating-system package inside an image.
    pub path: String,
    pub begin_line: Option<u32>,
    pub end_line: Option<u32>,
    pub begin_column: Option<u32>,
    pub end_column: Option<u32>,
    /// Container image the finding was found in.
    ///
    /// Per-finding rather than per-document because merging two reports must
    /// not blur which image each finding came from.
    pub image: Option<String>,
    /// Operating system of that image, e.g. `debian 12.5`.
    pub operating_system: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    pub version: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Rule that produced the finding (Code Climate's `check_name`,
    /// Checkstyle's `source`, SARIF's `ruleId`).
    pub rule_id: Option<String>,
    /// Short human title, when distinct from the description.
    pub title: Option<String>,
    pub description: String,
    pub severity: Severity,
    pub categories: Vec<String>,
    pub location: Location,
    /// Stable identity across runs. Synthesized by
    /// [`Finding::ensure_fingerprint`] when the source has none.
    pub fingerprint: Option<String>,
    /// Remediation guidance.
    pub help: Option<String>,
    pub links: Vec<String>,
    pub identifiers: Vec<Identifier>,
    /// The affected component, for a finding about a dependency.
    pub component: Option<Component>,
}

impl Finding {
    pub fn new(description: impl Into<String>, severity: Severity) -> Self {
        Finding {
            rule_id: None,
            title: None,
            description: description.into(),
            severity,
            categories: Vec::new(),
            location: Location::default(),
            fingerprint: None,
            help: None,
            links: Vec::new(),
            identifiers: Vec::new(),
            component: None,
        }
    }

    /// GitLab rejects Code Quality entries without a `fingerprint`, and most
    /// sources (Checkstyle, plain SARIF) do not provide one. Derive it from the
    /// stable parts of the finding — deliberately *not* including the line
    /// number, so that inserting a line above an issue does not report it as new.
    pub fn ensure_fingerprint(&mut self) {
        if self.fingerprint.is_some() {
            return;
        }
        // A finding about a component is identified by the component, not by
        // where a scanner happened to write it down: the same CVE in the same
        // package is the same finding whether it was reported against the image
        // or against the lockfile.
        self.fingerprint = Some(match &self.component {
            Some(component) => crate::hash::fingerprint(&[
                self.location
                    .image
                    .as_deref()
                    .unwrap_or(&self.location.path),
                &component.name,
                component.version.as_deref().unwrap_or(""),
                self.rule_id.as_deref().unwrap_or(&self.description),
            ]),
            None => crate::hash::fingerprint(&[
                &self.location.path,
                self.rule_id.as_deref().unwrap_or(""),
                &self.description,
            ]),
        });
    }
}

/// When the analysis ran, as `yyyy-mm-ddThh:mm:ss` in UTC.
///
/// Carried only because some sinks *require* it — GitLab's security reports
/// will not validate without both ends. Most formats say nothing about it, so
/// it is optional here and the writers that need it have to decide what to do
/// with `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanWindow {
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingsDoc {
    pub tool: Option<Tool>,
    pub scan: ScanWindow,
    pub findings: Vec<Finding>,
}

impl FindingsDoc {
    /// Concatenate, dropping exact duplicates: running the same linter over
    /// overlapping file sets is common and platforms display duplicates twice.
    pub fn merge(&mut self, other: FindingsDoc) {
        self.tool = self.tool.take().or(other.tool);
        // Merging shards widens the window rather than picking one side.
        self.scan.start = min_time(self.scan.start.take(), other.scan.start);
        self.scan.end = max_time(self.scan.end.take(), other.scan.end);
        for finding in other.findings {
            if !self.findings.contains(&finding) {
                self.findings.push(finding);
            }
        }
    }

    pub fn normalize_paths(&mut self, mapper: &PathMapper) {
        if mapper.is_noop() {
            return;
        }
        for finding in &mut self.findings {
            finding.location.path = mapper.map(&finding.location.path);
        }
    }

    /// Deterministic ordering, so a conversion is byte-stable across runs.
    pub fn sort(&mut self) {
        self.findings.sort_by(|a, b| {
            a.location
                .path
                .cmp(&b.location.path)
                .then_with(|| a.location.begin_line.cmp(&b.location.begin_line))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.description.cmp(&b.description))
        });
    }
}

/// ISO8601 `yyyy-mm-ddThh:mm:ss` sorts correctly as text, so no date parsing.
fn min_time(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn max_time(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linter_severity_synonyms() {
        assert_eq!(Severity::parse("WARNING"), Some(Severity::Minor));
        assert_eq!(Severity::parse("error"), Some(Severity::Major));
        assert_eq!(Severity::parse(" note "), Some(Severity::Info));
        assert_eq!(Severity::parse("nonsense"), None);
    }

    #[test]
    fn fingerprint_is_line_independent() {
        let mut a = Finding::new("unused variable", Severity::Minor);
        a.rule_id = Some("no-unused".into());
        a.location = Location {
            path: "src/a.js".into(),
            begin_line: Some(3),
            ..Default::default()
        };
        let mut b = a.clone();
        b.location.begin_line = Some(42);

        a.ensure_fingerprint();
        b.ensure_fingerprint();
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn a_component_finding_is_identified_by_its_component() {
        // The same CVE in the same package, reported once against the image and
        // once against the lockfile, is one finding.
        let make = |path: &str, version: &str| {
            let mut finding = Finding::new("openssl is vulnerable", Severity::Critical);
            finding.rule_id = Some("CVE-2024-1234".into());
            finding.location = Location {
                path: path.into(),
                image: Some("acme/api:1.2.3".into()),
                ..Default::default()
            };
            finding.component = Some(Component {
                name: "libssl3".into(),
                version: Some(version.into()),
                ..Default::default()
            });
            finding.ensure_fingerprint();
            finding.fingerprint.unwrap()
        };

        assert_eq!(make("", "3.0.11-1"), make("package-lock.json", "3.0.11-1"));
        // A different version is a different finding: one may be fixed.
        assert_ne!(make("", "3.0.11-1"), make("", "3.0.11-2"));
    }

    #[test]
    fn merge_drops_exact_duplicates() {
        let finding = Finding::new("dup", Severity::Minor);
        let mut doc = FindingsDoc {
            findings: vec![finding.clone()],
            ..Default::default()
        };
        doc.merge(FindingsDoc {
            findings: vec![finding],
            ..Default::default()
        });
        assert_eq!(doc.findings.len(), 1);
    }
}
