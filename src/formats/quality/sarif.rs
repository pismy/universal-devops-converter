//! SARIF 2.1.0 — the OASIS standard behind GitHub code scanning, and the one
//! format that crosses the quality/security divide. Semgrep, CodeQL, gosec,
//! bandit, Checkov, Trivy and Snyk all emit it, which makes it the most
//! valuable *entry point* into the tool.
//!
//! Only the subset that survives a projection onto a findings model is read:
//! `runs[].results[]` with their rule metadata and first physical location.
//! Code flows, related locations, taxonomies and fixes have no counterpart in
//! any target format yet and are reported as losses.
//!
//! Writing SARIF is what lets any linter reach GitHub code scanning, the mirror
//! of what `codeclimate-gitlab` does for GitLab. The awkward part is
//! `tool.driver.rules[]`: the pivot stores rule metadata per *finding*, so the
//! rule table has to be rebuilt by deduplicating on `ruleId` (see
//! [`RuleTable`]).

use std::collections::HashMap;
use std::io::Write;

use serde::{Deserialize, Serialize};

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
    invocations: Vec<RawInvocation>,
    #[serde(default)]
    results: Vec<RawResult>,
}

#[derive(Debug, Deserialize)]
struct RawInvocation {
    #[serde(default, rename = "startTimeUtc")]
    start_time_utc: Option<String>,
    #[serde(default, rename = "endTimeUtc")]
    end_time_utc: Option<String>,
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
    /// What semgrep and several others fill in instead of `version`.
    #[serde(default, rename = "semanticVersion")]
    semantic_version: Option<String>,
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
        for invocation in &run.invocations {
            if doc.scan.start.is_none() {
                doc.scan.start = invocation.start_time_utc.as_deref().and_then(iso_seconds);
            }
            if doc.scan.end.is_none() {
                doc.scan.end = invocation.end_time_utc.as_deref().and_then(iso_seconds);
            }
        }

        let driver = run.tool.and_then(|t| t.driver);
        if doc.tool.is_none() {
            if let Some(driver) = &driver {
                doc.tool = Some(Tool {
                    name: driver.name.clone().unwrap_or_else(|| "sarif".into()),
                    version: driver
                        .version
                        .clone()
                        .or_else(|| driver.semantic_version.clone()),
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

/// SARIF timestamps carry fractional seconds and a zone (`2026-06-26T12:00:00.123Z`);
/// the pivot stores the `yyyy-mm-ddThh:mm:ss` prefix, which is what the sinks
/// that need a time accept.
fn iso_seconds(raw: &str) -> Option<String> {
    let candidate = raw.get(..19)?;
    let shape_ok = candidate.len() == 19
        && candidate.as_bytes()[4] == b'-'
        && candidate.as_bytes()[7] == b'-'
        && candidate.as_bytes()[10] == b'T'
        && candidate.as_bytes()[13] == b':'
        && candidate.as_bytes()[16] == b':';
    shape_ok.then(|| candidate.to_string())
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

/// SARIF severity comes from three places. `security-severity` wins, then the
/// result's own `level`, then the rule's default level.
///
/// Putting the score first is deliberate: `level` has three values, the score
/// has a hundred. A tool that emits both is saying "error, and precisely 8.6";
/// letting `level` win would throw away the half of that statement that
/// distinguishes a critical from a merely major finding — and would make a
/// SARIF round trip lose severity, since writing back can only choose one of
/// three levels.
fn severity_of(result: &RawResult, rule: Option<&RawRule>) -> Severity {
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
    if let Some(level) = result.level.as_deref().and_then(map_level) {
        return level;
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

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Canonical schema URI for SARIF 2.1.0.
const SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
const VERSION: &str = "2.1.0";

#[derive(Debug, Serialize)]
struct OutLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [OutRun<'a>; 1],
}

#[derive(Debug, Serialize)]
struct OutRun<'a> {
    tool: OutTool<'a>,
    results: Vec<OutResult<'a>>,
}

#[derive(Debug, Serialize)]
struct OutTool<'a> {
    driver: OutDriver<'a>,
}

#[derive(Debug, Serialize)]
struct OutDriver<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(rename = "informationUri", skip_serializing_if = "Option::is_none")]
    information_uri: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<OutRule<'a>>,
}

#[derive(Debug, Serialize)]
struct OutRule<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(rename = "shortDescription")]
    short_description: OutText<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<OutText<'a>>,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<&'a str>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: OutConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<OutProperties>,
}

#[derive(Debug, Serialize)]
struct OutConfiguration {
    level: &'static str,
}

#[derive(Debug, Serialize)]
struct OutProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(rename = "security-severity", skip_serializing_if = "Option::is_none")]
    security_severity: Option<String>,
}

#[derive(Debug, Serialize)]
struct OutText<'a> {
    text: &'a str,
}

#[derive(Debug, Serialize)]
struct OutResult<'a> {
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'a str>,
    #[serde(rename = "ruleIndex", skip_serializing_if = "Option::is_none")]
    rule_index: Option<usize>,
    level: &'static str,
    message: OutText<'a>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<OutLocation<'a>>,
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "Option::is_none"
    )]
    partial_fingerprints: Option<HashMap<&'static str, &'a str>>,
}

#[derive(Debug, Serialize)]
struct OutLocation<'a> {
    #[serde(rename = "physicalLocation")]
    physical_location: OutPhysicalLocation<'a>,
}

#[derive(Debug, Serialize)]
struct OutPhysicalLocation<'a> {
    #[serde(rename = "artifactLocation")]
    artifact_location: OutArtifactLocation<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<OutRegion>,
}

#[derive(Debug, Serialize)]
struct OutArtifactLocation<'a> {
    uri: &'a str,
}

#[derive(Debug, Serialize)]
struct OutRegion {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
}

/// Rebuilds `tool.driver.rules[]` from findings.
///
/// SARIF puts rule metadata in one table and has results point at it by index;
/// the pivot carries that metadata on every finding instead. Rebuilding means
/// deduplicating on `rule_id` — and deciding what to do when two findings claim
/// the same rule with different metadata. First one wins, and the caller is
/// told, because silently preferring one description over another would make
/// the report quietly disagree with its source.
#[derive(Default)]
struct RuleTable<'a> {
    order: Vec<&'a str>,
    index: HashMap<&'a str, usize>,
    rules: Vec<OutRule<'a>>,
    conflicts: bool,
}

impl<'a> RuleTable<'a> {
    fn intern(&mut self, finding: &'a Finding) -> Option<usize> {
        let id = finding.rule_id.as_deref()?;
        if let Some(existing) = self.index.get(id) {
            let rule = &self.rules[*existing];
            if rule.short_description.text != summary(finding) {
                self.conflicts = true;
            }
            return Some(*existing);
        }

        let position = self.rules.len();
        self.rules.push(OutRule {
            id,
            name: finding.title.as_deref(),
            short_description: OutText {
                text: summary(finding),
            },
            help: finding.help.as_deref().map(|text| OutText { text }),
            help_uri: finding.links.first().map(String::as_str),
            default_configuration: OutConfiguration {
                level: level_of(finding.severity),
            },
            properties: properties_of(finding),
        });
        self.order.push(id);
        self.index.insert(id, position);
        Some(position)
    }
}

/// What a rule is *about*, as opposed to what one occurrence says.
fn summary(finding: &Finding) -> &str {
    finding.title.as_deref().unwrap_or(&finding.description)
}

/// SARIF has three levels; the pivot has five. `note`/`warning`/`error` is the
/// whole vocabulary, so anything above "major" collapses.
fn level_of(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "note",
        Severity::Minor => "warning",
        Severity::Major | Severity::Critical | Severity::Blocker => "error",
    }
}

/// The midpoint of the CVSS band the reader maps back to, so a severity
/// survives a SARIF round trip instead of flattening into `error`.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Blocker => "9.5",
        Severity::Critical => "8.0",
        Severity::Major => "5.5",
        Severity::Minor => "2.0",
        Severity::Info => "0.0",
    }
}

fn properties_of(finding: &Finding) -> Option<OutProperties> {
    let mut tags: Vec<String> = finding.categories.clone();
    tags.extend(finding.identifiers.iter().map(|i| i.value.clone()));

    // `security-severity` is GitHub's marker for "this belongs in the security
    // tab". Emitting it for a style lint would misfile it, so it is reserved
    // for findings that actually carry a security identifier.
    let security_severity =
        (!finding.identifiers.is_empty()).then(|| security_severity(finding.severity).to_string());

    (!tags.is_empty() || security_severity.is_some()).then_some(OutProperties {
        tags,
        security_severity,
    })
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_findings()?;

    let mut rules = RuleTable::default();
    let mut results = Vec::with_capacity(doc.findings.len());
    let mut unruled = false;
    let mut collapsed = false;
    let mut extra_links = false;

    for finding in &doc.findings {
        let rule_index = rules.intern(finding);
        unruled |= rule_index.is_none();
        collapsed |= matches!(finding.severity, Severity::Critical | Severity::Blocker)
            && finding.identifiers.is_empty();
        extra_links |= finding.links.len() > 1;

        results.push(OutResult {
            rule_id: finding.rule_id.as_deref(),
            rule_index,
            level: level_of(finding.severity),
            message: OutText {
                text: &finding.description,
            },
            locations: out_locations(&finding.location),
            partial_fingerprints: finding
                .fingerprint
                .as_deref()
                .map(|fingerprint| HashMap::from([("udc/v1", fingerprint)])),
        });
    }

    if rules.conflicts {
        ctx.degraded(
            "sarif: findings sharing a rule id disagreed on its metadata; the first one seen \
             defines the rule",
        );
    }
    if unruled {
        ctx.lossy("sarif: findings with no rule id were emitted without a `ruleId`");
    }
    if collapsed {
        ctx.degraded(
            "sarif: critical and blocker collapsed to level \"error\" (SARIF has three levels); \
             only findings carrying a security identifier keep their rank via `security-severity`",
        );
    }
    if extra_links {
        ctx.lossy("sarif: a rule has a single `helpUri`, so only the first link was kept");
    }
    if doc.findings.iter().any(|f| {
        f.identifiers
            .iter()
            .any(|i| !i.kind.eq_ignore_ascii_case("cwe"))
    }) {
        ctx.lossy(
            "sarif: identifiers other than CWE (CVE, GHSA…) survive only as rule tags, not as \
             taxonomies",
        );
    }

    let tool = doc.tool.as_ref();
    let log = OutLog {
        schema: SCHEMA_URI,
        version: VERSION,
        runs: [OutRun {
            tool: OutTool {
                driver: OutDriver {
                    name: tool.map_or("udc", |t| t.name.as_str()),
                    version: tool.and_then(|t| t.version.as_deref()),
                    information_uri: tool.and_then(|t| t.url.as_deref()),
                    rules: rules.rules,
                },
            },
            results,
        }],
    };

    serde_json::to_writer_pretty(&mut *out, &log).map_err(|e| Error::parse(FORMAT, e))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn out_locations(location: &Location) -> Vec<OutLocation<'_>> {
    if location.path.is_empty() {
        return Vec::new();
    }
    vec![OutLocation {
        physical_location: OutPhysicalLocation {
            artifact_location: OutArtifactLocation {
                uri: &location.path,
            },
            region: location.begin_line.map(|start_line| OutRegion {
                start_line,
                start_column: location.begin_column,
                end_line: location.end_line,
                end_column: location.end_column,
            }),
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warn::Warnings;

    const SAMPLE: &str = r#"{
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "invocations": [{
          "executionSuccessful": true,
          "startTimeUtc": "2026-06-26T12:00:00.123456Z",
          "endTimeUtc": "2026-06-26T12:00:09.987654Z"
        }],
        "tool": {"driver": {
          "name": "semgrep",
          "semanticVersion": "1.75.0",
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
    fn security_severity_outranks_every_level() {
        let (doc, _) = parse(SAMPLE);
        // 8.6 → critical, even though defaultConfiguration says "warning"…
        let scored = doc
            .findings
            .iter()
            .find(|f| f.description == "Dangerous call")
            .unwrap();
        assert_eq!(scored.severity, Severity::Critical);

        // …and even though this result carries an explicit `level: "error"`.
        // The score is the more precise of the two statements.
        let explicit = doc
            .findings
            .iter()
            .find(|f| f.description == "Another one")
            .unwrap();
        assert_eq!(explicit.severity, Severity::Critical);
    }

    #[test]
    fn level_drives_severity_when_there_is_no_score() {
        let (doc, _) = parse(
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},"results":[
                 {"ruleId":"a","level":"error","message":{"text":"x"}},
                 {"ruleId":"b","level":"note","message":{"text":"y"}},
                 {"ruleId":"c","message":{"text":"z"}}
               ]}]}"#,
        );
        let by = |d: &str| {
            doc.findings
                .iter()
                .find(|f| f.description == d)
                .unwrap()
                .severity
        };
        assert_eq!(by("x"), Severity::Major);
        assert_eq!(by("y"), Severity::Info);
        // SARIF's own default when nothing says otherwise.
        assert_eq!(by("z"), Severity::Minor);
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

    // ---- writing --------------------------------------------------------

    fn render(doc: &FindingsDoc) -> (serde_json::Value, Warnings) {
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(Some("2.1.0"));
        write(&Doc::Findings(doc.clone()), &mut buffer, &mut ctx).unwrap();
        (
            serde_json::from_slice(&buffer).expect("the writer emits valid JSON"),
            ctx.into_warnings(),
        )
    }

    fn finding(rule: Option<&str>, description: &str, severity: Severity) -> Finding {
        let mut finding = Finding::new(description, severity);
        finding.rule_id = rule.map(str::to_string);
        finding.location = Location {
            path: "src/a.js".into(),
            begin_line: Some(3),
            ..Default::default()
        };
        finding
    }

    #[test]
    fn builds_a_rule_table_deduplicated_by_rule_id() {
        let doc = FindingsDoc {
            findings: vec![
                finding(Some("no-var"), "Unexpected var", Severity::Minor),
                finding(Some("no-var"), "Unexpected var", Severity::Minor),
                finding(Some("semi"), "Missing semicolon", Severity::Major),
            ],
            ..Default::default()
        };
        let (json, _) = render(&doc);

        let rules = &json["runs"][0]["tool"]["driver"]["rules"];
        assert_eq!(rules.as_array().unwrap().len(), 2);
        assert_eq!(rules[0]["id"], "no-var");
        assert_eq!(rules[1]["id"], "semi");

        // Results point at the table by index, and the two `no-var` findings
        // share one entry.
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[1]["ruleIndex"], 0);
        assert_eq!(results[2]["ruleIndex"], 1);
    }

    #[test]
    fn reports_conflicting_metadata_for_one_rule() {
        let doc = FindingsDoc {
            findings: vec![
                finding(Some("no-var"), "Unexpected var", Severity::Minor),
                finding(Some("no-var"), "Something else entirely", Severity::Minor),
            ],
            ..Default::default()
        };
        let (json, warnings) = render(&doc);

        // First one wins…
        assert_eq!(
            json["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"],
            "Unexpected var"
        );
        // …and that is not silent.
        assert!(warnings
            .messages()
            .any(|m| m.contains("disagreed on its metadata")));
    }

    #[test]
    fn security_severity_is_reserved_for_findings_with_identifiers() {
        let mut lint = finding(Some("no-var"), "style nit", Severity::Critical);
        let mut vuln = finding(Some("cwe-79"), "XSS", Severity::Critical);
        vuln.identifiers.push(Identifier {
            kind: "cwe".into(),
            value: "CWE-079".into(),
            url: None,
        });
        lint.location.path = "a.js".into();
        vuln.location.path = "b.js".into();

        let (json, warnings) = render(&FindingsDoc {
            findings: vec![lint, vuln],
            ..Default::default()
        });
        let rules = &json["runs"][0]["tool"]["driver"]["rules"];

        // A style lint must not be filed as a security finding…
        assert!(rules[0]["properties"]["security-severity"].is_null());
        // …while a real one keeps its rank, which `level` alone cannot express.
        assert_eq!(rules[1]["properties"]["security-severity"], "8.0");
        assert!(warnings
            .messages()
            .any(|m| m.contains("collapsed to level")));
    }

    #[test]
    fn findings_without_a_rule_id_are_still_emitted() {
        let (json, warnings) = render(&FindingsDoc {
            findings: vec![finding(None, "no rule here", Severity::Minor)],
            ..Default::default()
        });

        let result = &json["runs"][0]["results"][0];
        assert!(result["ruleId"].is_null());
        assert!(result["ruleIndex"].is_null());
        assert_eq!(result["message"]["text"], "no rule here");
        assert!(warnings.messages().any(|m| m.contains("no rule id")));
    }

    #[test]
    fn a_security_finding_keeps_its_severity_across_a_round_trip() {
        let (doc, _) = parse(SAMPLE);
        let original = doc
            .findings
            .iter()
            .find(|f| f.description == "Dangerous call")
            .unwrap()
            .clone();
        assert_eq!(original.severity, Severity::Critical);

        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(Some("2.1.0"));
        write(&Doc::Findings(doc), &mut buffer, &mut ctx).unwrap();

        let (again, _) = parse(std::str::from_utf8(&buffer).unwrap());
        let reread = again
            .findings
            .iter()
            .find(|f| f.description == "Dangerous call")
            .unwrap();
        assert_eq!(reread.severity, Severity::Critical);
        assert_eq!(reread.location, original.location);
        assert_eq!(reread.fingerprint, original.fingerprint);
    }

    #[test]
    fn reads_the_scan_window_and_the_semantic_version() {
        let (doc, _) = parse(SAMPLE);
        assert_eq!(doc.scan.start.as_deref(), Some("2026-06-26T12:00:00"));
        assert_eq!(doc.scan.end.as_deref(), Some("2026-06-26T12:00:09"));
        // semgrep fills in semanticVersion, not version.
        assert_eq!(
            doc.tool.as_ref().unwrap().version.as_deref(),
            Some("1.75.0")
        );
    }

    #[test]
    fn a_malformed_timestamp_is_ignored_rather_than_propagated() {
        let (doc, _) = parse(
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
                 "invocations":[{"startTimeUtc":"yesterday"}],"results":[]}]}"#,
        );
        assert_eq!(doc.scan.start, None);
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
