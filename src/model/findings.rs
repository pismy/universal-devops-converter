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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    /// Repository-relative path, `/`-separated.
    pub path: String,
    pub begin_line: Option<u32>,
    pub end_line: Option<u32>,
    pub begin_column: Option<u32>,
    pub end_column: Option<u32>,
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
        self.fingerprint = Some(crate::hash::fingerprint(&[
            &self.location.path,
            self.rule_id.as_deref().unwrap_or(""),
            &self.description,
        ]));
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingsDoc {
    pub tool: Option<Tool>,
    pub findings: Vec<Finding>,
}

impl FindingsDoc {
    /// Concatenate, dropping exact duplicates: running the same linter over
    /// overlapping file sets is common and platforms display duplicates twice.
    pub fn merge(&mut self, other: FindingsDoc) {
        self.tool = self.tool.take().or(other.tool);
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
