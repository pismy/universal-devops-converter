//! SARIF 2.1.0 — the OASIS standard behind GitHub code scanning, and the one
//! format that crosses the quality/security divide. Semgrep, CodeQL, gosec,
//! bandit, Checkov, Trivy and Snyk all emit it, which makes it the most
//! valuable *entry point* into the tool.
//!
//! Only the subset that survives a projection onto a findings model is read:
//! `runs[].results[]` with their rule metadata and first physical location.
//! Code flows, related locations, taxonomies and fixes have no counterpart in
//! any target format yet and are reported as losses.

use std::collections::HashMap;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::model::findings::{Finding, FindingsDoc, Identifier, Location, Severity, Tool};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "sarif";

/// The only version this reader understands. SARIF 1.x is not an older version
/// of this document shape, it is a different one; if it ever gets support it
/// becomes its own format id.
const SUPPORTED_MAJOR: &str = "2.";

#[derive(Debug, Deserialize)]
struct RawLog {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    runs: Vec<RawRun>,
}

#[derive(Debug, Deserialize)]
struct RawRun {
    #[serde(default)]
    tool: Option<RawTool>,
    #[serde(default)]
    results: Vec<RawResult>,
}

#[derive(Debug, Deserialize)]
struct RawTool {
    #[serde(default)]
    driver: Option<RawDriver>,
}

#[derive(Debug, Deserialize)]
struct RawDriver {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "informationUri")]
    information_uri: Option<String>,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "shortDescription")]
    short_description: Option<RawText>,
    #[serde(default, rename = "fullDescription")]
    full_description: Option<RawText>,
    #[serde(default)]
    help: Option<RawText>,
    #[serde(default, rename = "helpUri")]
    help_uri: Option<String>,
    #[serde(default, rename = "defaultConfiguration")]
    default_configuration: Option<RawConfiguration>,
    #[serde(default)]
    properties: Option<RawProperties>,
}

#[derive(Debug, Deserialize)]
struct RawConfiguration {
    #[serde(default)]
    level: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawProperties {
    #[serde(default)]
    tags: Vec<String>,
    /// GitHub's convention for a CVSS-like score, honoured by most producers.
    #[serde(default, rename = "security-severity")]
    security_severity: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawText {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    markdown: Option<String>,
}

impl RawText {
    fn value(&self) -> Option<&str> {
        self.text.as_deref().or(self.markdown.as_deref())
    }
}

#[derive(Debug, Deserialize)]
struct RawResult {
    #[serde(default, rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(default, rename = "ruleIndex")]
    rule_index: Option<usize>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    message: Option<RawText>,
    #[serde(default)]
    locations: Vec<RawLocation>,
    #[serde(default, rename = "relatedLocations")]
    related_locations: Vec<RawLocation>,
    #[serde(default, rename = "codeFlows")]
    code_flows: Vec<serde_json::Value>,
    #[serde(default)]
    fingerprints: HashMap<String, String>,
    #[serde(default, rename = "partialFingerprints")]
    partial_fingerprints: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct RawLocation {
    #[serde(default, rename = "physicalLocation")]
    physical_location: Option<RawPhysicalLocation>,
}

#[derive(Debug, Deserialize)]
struct RawPhysicalLocation {
    #[serde(default, rename = "artifactLocation")]
    artifact_location: Option<RawArtifactLocation>,
    #[serde(default)]
    region: Option<RawRegion>,
}

#[derive(Debug, Deserialize)]
struct RawArtifactLocation {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawRegion {
    #[serde(default, rename = "startLine")]
    start_line: Option<u32>,
    #[serde(default, rename = "endLine")]
    end_line: Option<u32>,
    #[serde(default, rename = "startColumn")]
    start_column: Option<u32>,
    #[serde(default, rename = "endColumn")]
    end_column: Option<u32>,
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let log: RawLog = serde_json::from_slice(input).map_err(|e| Error::parse(FORMAT, e))?;
    if log.runs.is_empty() {
        return Err(Error::parse(
            FORMAT,
            "no `runs` array — this does not look like a SARIF log",
        ));
    }
    check_version(log.version.as_deref(), ctx)?;

    let mut doc = FindingsDoc::default();

    for run in log.runs {
        let driver = run.tool.and_then(|t| t.driver);
        if doc.tool.is_none() {
            if let Some(driver) = &driver {
                doc.tool = Some(Tool {
                    name: driver.name.clone().unwrap_or_else(|| "sarif".into()),
                    version: driver.version.clone(),
                    url: driver.information_uri.clone(),
                });
            }
        }
        let rules = driver.map(|d| d.rules).unwrap_or_default();

        for result in run.results {
            if !result.code_flows.is_empty() {
                ctx.lossy(
                    "sarif: code flows have no equivalent in the findings model and were dropped",
                );
            }
            if !result.related_locations.is_empty() {
                ctx.lossy("sarif: related locations were dropped (only the primary one is kept)");
            }

            let rule = lookup_rule(&rules, result.rule_id.as_deref(), result.rule_index);
            doc.findings.push(build(result, rule));
        }
    }

    for finding in &mut doc.findings {
        finding.ensure_fingerprint();
    }
    doc.sort();
    Ok(Doc::Findings(doc))
}

/// Refuse a document whose declared version this reader cannot honestly read,
/// and flag a mismatch with the version the caller pinned via `sarif@<version>`.
fn check_version(declared: Option<&str>, ctx: &mut FormatCtx) -> Result<()> {
    let Some(declared) = declared.map(str::trim).filter(|v| !v.is_empty()) else {
        // `version` is required by the spec but omitted often enough in the
        // wild that refusing over it would help nobody.
        return Ok(());
    };

    if !declared.starts_with(SUPPORTED_MAJOR) {
        return Err(Error::parse(
            FORMAT,
            format!(
                "document declares SARIF {declared}, which is a structurally different format \
                 (`files` dictionary, `resources.rules`, `formattedRuleMessage`), not an older \
                 version of SARIF 2. It is not supported."
            ),
        ));
    }

    if let Some(requested) = ctx.version() {
        if declared != requested {
            ctx.degraded(format!(
                "sarif: document declares version {declared} but {requested} was requested; \
                 parsed leniently, fields specific to {declared} were ignored"
            ));
        }
    }
    Ok(())
}

fn lookup_rule<'a>(
    rules: &'a [RawRule],
    id: Option<&str>,
    index: Option<usize>,
) -> Option<&'a RawRule> {
    // `ruleIndex` is the fast path SARIF defines; `ruleId` is the one producers
    // actually fill in reliably.
    index
        .and_then(|i| rules.get(i))
        .or_else(|| id.and_then(|id| rules.iter().find(|r| r.id.as_deref() == Some(id))))
}

fn build(result: RawResult, rule: Option<&RawRule>) -> Finding {
    let description = result
        .message
        .as_ref()
        .and_then(RawText::value)
        .map(str::to_string)
        .or_else(|| {
            rule.and_then(|r| r.short_description.as_ref())
                .and_then(RawText::value)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "(no message)".into());

    let severity = severity_of(&result, rule);

    let mut finding = Finding::new(description, severity);
    finding.rule_id = result
        .rule_id
        .clone()
        .or_else(|| rule.and_then(|r| r.id.clone()))
        .filter(|id| !id.is_empty());
    finding.title = rule.and_then(|r| {
        r.name.clone().or_else(|| {
            r.short_description
                .as_ref()
                .and_then(RawText::value)
                .map(str::to_string)
        })
    });
    finding.help = rule.and_then(|r| {
        r.help
            .as_ref()
            .and_then(RawText::value)
            .or_else(|| r.full_description.as_ref().and_then(RawText::value))
            .map(str::to_string)
    });
    if let Some(url) = rule.and_then(|r| r.help_uri.clone()) {
        finding.links.push(url);
    }

    if let Some(properties) = rule.and_then(|r| r.properties.as_ref()) {
        for tag in &properties.tags {
            // `external/cwe/cwe-079` and `CWE-79` both appear in the wild.
            if let Some(cwe) = tag
                .rsplit('/')
                .next()
                .filter(|t| t.len() > 4 && t[..4].eq_ignore_ascii_case("cwe-"))
            {
                finding.identifiers.push(Identifier {
                    kind: "cwe".into(),
                    value: cwe.to_uppercase(),
                    url: None,
                });
            } else {
                finding.categories.push(tag.clone());
            }
        }
    }

    finding.fingerprint = pick_fingerprint(&result);
    finding.location = location_of(&result);
    finding
}

/// SARIF severity comes from three places, in decreasing priority: the result's
/// own `level`, the rule's `security-severity` score, the rule's default level.
fn severity_of(result: &RawResult, rule: Option<&RawRule>) -> Severity {
    if let Some(level) = result.level.as_deref().and_then(map_level) {
        return level;
    }
    if let Some(score) = rule
        .and_then(|r| r.properties.as_ref())
        .and_then(|p| p.security_severity.as_ref())
        .and_then(as_number)
    {
        // The CVSS v3 qualitative bands.
        return match score {
            s if s >= 9.0 => Severity::Blocker,
            s if s >= 7.0 => Severity::Critical,
            s if s >= 4.0 => Severity::Major,
            s if s > 0.0 => Severity::Minor,
            _ => Severity::Info,
        };
    }
    rule.and_then(|r| r.default_configuration.as_ref())
        .and_then(|c| c.level.as_deref())
        .and_then(map_level)
        // SARIF's own default when `level` is absent everywhere.
        .unwrap_or(Severity::Minor)
}

fn map_level(level: &str) -> Option<Severity> {
    match level.trim().to_ascii_lowercase().as_str() {
        "error" => Some(Severity::Major),
        "warning" => Some(Severity::Minor),
        "note" => Some(Severity::Info),
        // `none` means "not a problem", not "unknown": keep it informational.
        "none" => Some(Severity::Info),
        _ => None,
    }
}

fn as_number(value: &serde_json::Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Prefer `partialFingerprints` — SARIF defines those as stable across
/// unrelated edits, which is exactly what a platform needs to tell a new issue
/// from a moved one.
fn pick_fingerprint(result: &RawResult) -> Option<String> {
    let mut keys: Vec<&String> = result.partial_fingerprints.keys().collect();
    keys.sort();
    if let Some(key) = keys.first() {
        return result.partial_fingerprints.get(*key).cloned();
    }
    let mut keys: Vec<&String> = result.fingerprints.keys().collect();
    keys.sort();
    keys.first()
        .and_then(|key| result.fingerprints.get(*key).cloned())
}

fn location_of(result: &RawResult) -> Location {
    let Some(physical) = result
        .locations
        .first()
        .and_then(|l| l.physical_location.as_ref())
    else {
        return Location::default();
    };

    let path = physical
        .artifact_location
        .as_ref()
        .and_then(|a| a.uri.as_deref())
        // Producers emit `file:///builds/x/src/a.js` as often as `src/a.js`.
        .map(|uri| crate::paths::normalize(uri.strip_prefix("file://").unwrap_or(uri)))
        .unwrap_or_default();

    let region = physical.region.as_ref();
    Location {
        path,
        begin_line: region.and_then(|r| r.start_line),
        end_line: region.and_then(|r| r.end_line.or(r.start_line)),
        begin_column: region.and_then(|r| r.start_column),
        end_column: region.and_then(|r| r.end_column),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warn::Warnings;

    const SAMPLE: &str = r#"{
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "tool": {"driver": {
          "name": "semgrep",
          "version": "1.2.3",
          "rules": [{
            "id": "python.lang.security.audit",
            "name": "audit",
            "shortDescription": {"text": "Audit finding"},
            "help": {"text": "Do not do that"},
            "helpUri": "https://example.test/rule",
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["security", "external/cwe/cwe-079"], "security-severity": "8.1"}
          }]
        }},
        "results": [
          {
            "ruleId": "python.lang.security.audit",
            "ruleIndex": 0,
            "message": {"text": "Dangerous call"},
            "locations": [{"physicalLocation": {
              "artifactLocation": {"uri": "file:///builds/acme/app.py"},
              "region": {"startLine": 7, "startColumn": 3, "endLine": 9}
            }}],
            "partialFingerprints": {"primaryLocationLineHash": "deadbeef"}
          },
          {
            "ruleId": "python.lang.security.audit",
            "ruleIndex": 0,
            "level": "error",
            "message": {"text": "Another one"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}],
            "codeFlows": [{"threadFlows": []}]
          }
        ]
      }]
    }"#;

    fn parse(input: &str) -> (FindingsDoc, Warnings) {
        let mut ctx = FormatCtx::new(None);
        let doc = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Findings(doc) => doc,
            _ => panic!("expected a findings document"),
        };
        (doc, ctx.into_warnings())
    }

    #[test]
    fn reads_results_with_rule_metadata() {
        let (doc, _) = parse(SAMPLE);
        assert_eq!(doc.tool.as_ref().unwrap().name, "semgrep");
        assert_eq!(doc.findings.len(), 2);

        let first = &doc.findings[0];
        assert_eq!(first.description, "Dangerous call");
        assert_eq!(first.rule_id.as_deref(), Some("python.lang.security.audit"));
        assert_eq!(first.help.as_deref(), Some("Do not do that"));
        assert_eq!(first.links, vec!["https://example.test/rule".to_string()]);
        assert_eq!(first.fingerprint.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn strips_file_uris_and_keeps_the_region() {
        let (doc, _) = parse(SAMPLE);
        let location = &doc.findings[0].location;
        assert_eq!(location.path, "/builds/acme/app.py");
        assert_eq!(location.begin_line, Some(7));
        assert_eq!(location.end_line, Some(9));
        assert_eq!(location.begin_column, Some(3));
    }

    #[test]
    fn security_severity_outranks_the_default_level() {
        let (doc, _) = parse(SAMPLE);
        // 8.1 → critical, even though defaultConfiguration says "warning".
        let scored = doc
            .findings
            .iter()
            .find(|f| f.description == "Dangerous call")
            .unwrap();
        assert_eq!(scored.severity, Severity::Critical);

        // An explicit result-level `error` wins over everything.
        let explicit = doc
            .findings
            .iter()
            .find(|f| f.description == "Another one")
            .unwrap();
        assert_eq!(explicit.severity, Severity::Major);
    }

    #[test]
    fn extracts_cwe_tags_as_identifiers() {
        let (doc, _) = parse(SAMPLE);
        let identifiers = &doc.findings[0].identifiers;
        assert_eq!(identifiers.len(), 1);
        assert_eq!(identifiers[0].value, "CWE-079");
        assert_eq!(doc.findings[0].categories, vec!["security".to_string()]);
    }

    #[test]
    fn reports_dropped_code_flows() {
        let (_, warnings) = parse(SAMPLE);
        assert!(warnings.messages().any(|w| w.contains("code flows")));
    }

    #[test]
    fn rejects_json_without_runs() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(br#"{"version":"2.1.0"}"#, &mut ctx).is_err());
    }

    #[test]
    fn rejects_sarif_1_x_as_a_different_format() {
        let mut ctx = FormatCtx::new(Some("2.1.0"));
        let error = read(br#"{"version":"1.0.0","runs":[{"results":[]}]}"#, &mut ctx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("structurally different"), "{error}");
    }

    #[test]
    fn flags_a_mismatch_with_the_pinned_version() {
        let mut ctx = FormatCtx::new(Some("2.1.0"));
        read(br#"{"version":"2.0.0","runs":[{"results":[]}]}"#, &mut ctx).unwrap();
        assert!(ctx
            .warnings()
            .messages()
            .any(|m| m.contains("declares version 2.0.0")));
    }

    #[test]
    fn accepts_a_document_with_no_declared_version() {
        let mut ctx = FormatCtx::new(Some("2.1.0"));
        read(br#"{"runs":[{"results":[]}]}"#, &mut ctx).unwrap();
        assert!(ctx.warnings().is_empty());
    }
}
