//! GitLab SAST security report.
//!
//! This is what puts findings in GitLab's security dashboard and its merge
//! request security widget, and nothing but GitLab's own analyzers emits it —
//! so `sarif → gitlab-sast` is the bridge that lets semgrep, CodeQL, gosec,
//! bandit or Checkov feed it.
//!
//! The schema (`security-report-schemas`, 15.2.5) is stricter than the pivot in
//! three places, and each one forces a decision:
//!
//! - **`scan.start_time` / `scan.end_time` are required**, with a fixed
//!   `yyyy-mm-ddThh:mm:ss` shape. Reading the clock would make the output
//!   differ on every run, which the project guarantees it does not. The window
//!   is therefore taken from the source when it has one and falls back to a
//!   fixed epoch, with a `degraded:` notice — a wrong date the report admits to
//!   beats a report that cannot be diffed.
//! - **`identifiers` needs at least one entry**, while a finding from a linter
//!   has none. One is synthesized from the rule id.
//! - **`id` should be a UUID.** The pivot's fingerprint is 128 bits of hex, so
//!   it is formatted as one rather than inventing a random value that would
//!   change between runs.
//!
//! Only the SAST profile is implemented. Dependency and container scanning
//! share this family but require a versioned component or an image, which the
//! pivot does not carry yet; writing them today would mean emitting invented
//! data that validates and lies.

use std::io::Write;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::model::findings::{Finding, Severity};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "gitlab-sast";

/// Schema version the output declares. Matches the vendored schema.
const SCHEMA_VERSION: &str = "15.2.5";

/// Stand-in for an unknown scan window. Deliberately recognizable: a reader
/// seeing 1970 knows the time was not measured, where a plausible-looking date
/// would quietly pass for real.
const UNKNOWN_TIME: &str = "1970-01-01T00:00:00";

#[derive(Debug, Serialize)]
struct Report<'a> {
    version: &'static str,
    scan: Scan<'a>,
    vulnerabilities: Vec<Vulnerability<'a>>,
}

#[derive(Debug, Serialize)]
struct Scan<'a> {
    analyzer: Analyzer<'a>,
    scanner: Analyzer<'a>,
    #[serde(rename = "type")]
    kind: &'static str,
    status: &'static str,
    start_time: &'a str,
    end_time: &'a str,
}

#[derive(Debug, Serialize)]
struct Analyzer<'a> {
    id: String,
    name: &'a str,
    version: &'a str,
    vendor: Vendor<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct Vendor<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
struct Vulnerability<'a> {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    description: &'a str,
    severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution: Option<&'a str>,
    identifiers: Vec<ReportIdentifier<'a>>,
    location: Location<'a>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    links: Vec<Link<'a>>,
}

#[derive(Debug, Serialize)]
struct ReportIdentifier<'a> {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct Location<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
}

#[derive(Debug, Serialize)]
struct Link<'a> {
    url: &'a str,
}

/// The pivot's five levels onto GitLab's six, order-preserving and injective:
/// no two pivot severities collapse, so nothing is lost on the way out.
/// GitLab's `Unknown` is left unused — the pivot always knows.
fn severity_of(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Minor => "Low",
        Severity::Major => "Medium",
        Severity::Critical => "High",
        Severity::Blocker => "Critical",
    }
}

/// Format 32 hex characters as a UUID. The schema only asks for a unique
/// string, but consumers display it, and a fingerprint that is stable across
/// runs is what lets GitLab tell a returning finding from a new one.
fn is_hex_128(value: &str) -> bool {
    value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn as_uuid(hex: &str) -> Option<String> {
    if !is_hex_128(hex) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

fn identifiers_of(finding: &Finding) -> Vec<ReportIdentifier<'_>> {
    let mut identifiers: Vec<ReportIdentifier> = finding
        .identifiers
        .iter()
        .map(|identifier| ReportIdentifier {
            kind: identifier.kind.to_ascii_lowercase(),
            name: identifier.value.clone(),
            value: &identifier.value,
            url: identifier.url.as_deref(),
        })
        .collect();

    // The schema requires at least one. A linter finding has none, so the rule
    // it broke stands in — which is also what a reader would key on.
    if identifiers.is_empty() {
        if let Some(rule) = finding.rule_id.as_deref() {
            identifiers.push(ReportIdentifier {
                kind: "udc_rule".to_string(),
                name: rule.to_string(),
                value: rule,
                url: finding.links.first().map(String::as_str),
            });
        }
    }
    identifiers
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_findings()?;

    let start = doc.scan.start.as_deref().unwrap_or(UNKNOWN_TIME);
    let end = doc.scan.end.as_deref().unwrap_or(UNKNOWN_TIME);
    if doc.scan.start.is_none() || doc.scan.end.is_none() {
        ctx.degraded(
            "gitlab-sast: the report requires a scan window and the source carried none; \
             1970-01-01T00:00:00 is emitted so the output stays reproducible",
        );
    }

    let mut vulnerabilities = Vec::with_capacity(doc.findings.len());
    let mut unidentified = 0usize;

    for finding in &doc.findings {
        let identifiers = identifiers_of(finding);
        if identifiers.is_empty() {
            // No identifier and no rule id: the entry could not satisfy the
            // schema, and a report GitLab rejects wholesale is worse than one
            // missing a finding.
            unidentified += 1;
            continue;
        }

        // Always UUID-shaped, and always derived from something stable: the
        // source fingerprint when there is one, so a finding keeps its identity
        // across runs and GitLab can tell it apart from a new one.
        let hex = match finding.fingerprint.as_deref() {
            Some(fingerprint) if is_hex_128(fingerprint) => fingerprint.to_string(),
            Some(fingerprint) => crate::hash::fingerprint(&[fingerprint]),
            None => crate::hash::fingerprint(&[&finding.location.path, &finding.description]),
        };
        let id = as_uuid(&hex).expect("a 128-bit hex digest");

        vulnerabilities.push(Vulnerability {
            id,
            name: finding.title.clone(),
            description: &finding.description,
            severity: severity_of(finding.severity),
            solution: finding.help.as_deref(),
            identifiers,
            location: Location {
                file: Some(finding.location.path.as_str()).filter(|p| !p.is_empty()),
                start_line: finding.location.begin_line,
                end_line: finding.location.end_line,
            },
            links: finding.links.iter().map(|url| Link { url }).collect(),
        });
    }

    if unidentified > 0 {
        ctx.lossy(format!(
            "gitlab-sast: {unidentified} finding(s) had neither an identifier nor a rule id and \
             were dropped (the schema requires at least one identifier)"
        ));
    }
    if doc.findings.iter().any(|f| !f.categories.is_empty()) {
        ctx.lossy("gitlab-sast: issue categories have no field in the security report");
    }

    let tool = doc.tool.as_ref();
    let name = tool.map_or("udc", |t| t.name.as_str());
    let version = tool.and_then(|t| t.version.as_deref()).unwrap_or("unknown");
    let analyzer = || Analyzer {
        id: name.to_ascii_lowercase().replace(' ', "-"),
        name,
        version,
        vendor: Vendor { name },
        url: tool.and_then(|t| t.url.as_deref()),
    };

    let report = Report {
        version: SCHEMA_VERSION,
        scan: Scan {
            analyzer: analyzer(),
            scanner: analyzer(),
            kind: "sast",
            status: "success",
            start_time: start,
            end_time: end,
        },
        vulnerabilities,
    };

    serde_json::to_writer_pretty(&mut *out, &report).map_err(|e| Error::parse(FORMAT, e))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::findings::{
        FindingsDoc, Identifier, Location as PivotLocation, ScanWindow, Tool,
    };
    use crate::warn::Warnings;

    fn render(doc: &FindingsDoc) -> (serde_json::Value, Warnings) {
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(Some(SCHEMA_VERSION));
        write(&Doc::Findings(doc.clone()), &mut buffer, &mut ctx).unwrap();
        (
            serde_json::from_slice(&buffer).expect("the writer emits valid JSON"),
            ctx.into_warnings(),
        )
    }

    fn finding(rule: Option<&str>, severity: Severity) -> Finding {
        let mut finding = Finding::new("Dangerous call", severity);
        finding.rule_id = rule.map(str::to_string);
        finding.location = PivotLocation {
            path: "app/shell.py".into(),
            begin_line: Some(12),
            end_line: Some(14),
            ..Default::default()
        };
        finding.ensure_fingerprint();
        finding
    }

    #[test]
    fn maps_the_five_pivot_levels_without_collapsing_any() {
        let mapped: Vec<&str> = [
            Severity::Info,
            Severity::Minor,
            Severity::Major,
            Severity::Critical,
            Severity::Blocker,
        ]
        .iter()
        .map(|s| severity_of(*s))
        .collect();

        assert_eq!(mapped, ["Info", "Low", "Medium", "High", "Critical"]);
        let unique: std::collections::HashSet<_> = mapped.iter().collect();
        assert_eq!(unique.len(), mapped.len(), "a severity was collapsed");
    }

    #[test]
    fn synthesizes_an_identifier_from_the_rule_when_there_is_none() {
        let (json, _) = render(&FindingsDoc {
            findings: vec![finding(Some("dangerous-subprocess"), Severity::Major)],
            ..Default::default()
        });

        let identifiers = &json["vulnerabilities"][0]["identifiers"];
        assert_eq!(identifiers.as_array().unwrap().len(), 1);
        assert_eq!(identifiers[0]["type"], "udc_rule");
        assert_eq!(identifiers[0]["value"], "dangerous-subprocess");
    }

    #[test]
    fn keeps_real_identifiers_when_the_finding_has_them() {
        let mut vuln = finding(Some("xss"), Severity::Critical);
        vuln.identifiers.push(Identifier {
            kind: "CWE".into(),
            value: "CWE-079".into(),
            url: Some("https://cwe.mitre.org/data/definitions/79.html".into()),
        });

        let (json, _) = render(&FindingsDoc {
            findings: vec![vuln],
            ..Default::default()
        });
        let identifier = &json["vulnerabilities"][0]["identifiers"][0];
        assert_eq!(identifier["type"], "cwe");
        assert_eq!(identifier["value"], "CWE-079");
        assert_eq!(json["vulnerabilities"][0]["severity"], "High");
    }

    #[test]
    fn drops_a_finding_that_could_not_satisfy_the_schema() {
        let (json, warnings) = render(&FindingsDoc {
            findings: vec![finding(None, Severity::Minor)],
            ..Default::default()
        });

        // Better one finding short than a document GitLab rejects entirely.
        assert!(json["vulnerabilities"].as_array().unwrap().is_empty());
        assert!(warnings.messages().any(|m| m.contains("were dropped")));
    }

    #[test]
    fn an_absent_scan_window_is_reproducible_and_admitted() {
        let doc = FindingsDoc {
            findings: vec![finding(Some("r"), Severity::Major)],
            ..Default::default()
        };
        let (json, warnings) = render(&doc);

        assert_eq!(json["scan"]["start_time"], UNKNOWN_TIME);
        assert!(warnings.messages().any(|m| m.contains("scan window")));

        let (again, _) = render(&doc);
        assert_eq!(json, again, "output must not depend on the clock");
    }

    #[test]
    fn a_scan_window_from_the_source_is_used_as_is() {
        let (json, warnings) = render(&FindingsDoc {
            scan: ScanWindow {
                start: Some("2026-06-26T12:00:00".into()),
                end: Some("2026-06-26T12:00:09".into()),
            },
            tool: Some(Tool {
                name: "semgrep".into(),
                version: Some("1.75.0".into()),
                url: None,
            }),
            findings: vec![finding(Some("r"), Severity::Major)],
        });

        assert_eq!(json["scan"]["start_time"], "2026-06-26T12:00:00");
        assert_eq!(json["scan"]["scanner"]["name"], "semgrep");
        assert!(!warnings.messages().any(|m| m.contains("scan window")));
    }

    #[test]
    fn the_id_is_uuid_shaped_whatever_the_source_fingerprint_looks_like() {
        for fingerprint in [
            None,                                     // nothing to go on
            Some("7d0a8f6c1b2e"),                     // SARIF's short matchBasedId
            Some("9f2c1a4b6d8e0f3a5c7b9d1e2f4a6b8c"), // already 128 bits
        ] {
            let mut f = finding(Some("r"), Severity::Major);
            f.fingerprint = fingerprint.map(str::to_string);
            let (json, _) = render(&FindingsDoc {
                findings: vec![f],
                ..Default::default()
            });
            let id = json["vulnerabilities"][0]["id"].as_str().unwrap();
            assert_eq!(id.len(), 36, "{fingerprint:?} produced {id}");
            assert_eq!(id.matches('-').count(), 4, "{fingerprint:?} produced {id}");
        }
    }

    #[test]
    fn the_id_is_stable_and_follows_the_source_fingerprint() {
        let make = |fingerprint: &str| {
            let mut f = finding(Some("r"), Severity::Major);
            f.fingerprint = Some(fingerprint.to_string());
            render(&FindingsDoc {
                findings: vec![f],
                ..Default::default()
            })
            .0["vulnerabilities"][0]["id"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(make("abc"), make("abc"));
        assert_ne!(make("abc"), make("def"));
    }
}
