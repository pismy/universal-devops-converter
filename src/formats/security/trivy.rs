//! Trivy JSON — the one scanner that covers dependencies, container images,
//! infrastructure-as-code and secrets in a single report.
//!
//! ```json
//! {
//!   "SchemaVersion": 2,
//!   "ArtifactName": "acme/api:1.2.3",
//!   "Metadata": { "OS": { "Family": "debian", "Name": "12.5" } },
//!   "Results": [
//!     { "Target": "acme/api:1.2.3 (debian 12.5)", "Class": "os-pkgs", "Type": "debian",
//!       "Vulnerabilities": [ { "VulnerabilityID": "CVE-2024-1234", "PkgName": "libssl3",
//!                              "InstalledVersion": "3.0.11-1", "FixedVersion": "3.0.11-2",
//!                              "Severity": "HIGH" } ] }
//!   ]
//! }
//! ```
//!
//! A result's `Class` says what kind of finding it holds and, with it, where
//! that finding *is*:
//!
//! | Class | Findings | Located by |
//! |---|---|---|
//! | `os-pkgs` | vulnerabilities | the image and its operating system — there is no file |
//! | `lang-pkgs` | vulnerabilities | the manifest or lock file in `Target` |
//! | `config` | misconfigurations | the file in `Target`, with lines from `CauseMetadata` |
//! | `secret` | secrets | the file in `Target`, with the rule's own lines |
//!
//! Severity maps so that a round trip through GitLab's scale is exact:
//! `CRITICAL` → blocker → `Critical`, `HIGH` → critical → `High`, and so on
//! down. Trivy's `UNKNOWN` is the one that does not survive, the pivot having
//! no such rank.
//!
//! Read-only: Trivy writes this, nothing else does, and Trivy already emits
//! SARIF, CycloneDX and GitLab's own format when asked.

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::model::findings::{
    Component, Finding, FindingsDoc, Identifier, Location, ScanWindow, Severity, Tool,
};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "trivy-json";

#[derive(Debug, Deserialize)]
struct RawReport {
    #[serde(default, rename = "SchemaVersion")]
    schema_version: Option<u32>,
    #[serde(default, rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(default, rename = "ArtifactName")]
    artifact_name: Option<String>,
    #[serde(default, rename = "ArtifactType")]
    artifact_type: Option<String>,
    #[serde(default, rename = "Metadata")]
    metadata: Option<RawMetadata>,
    #[serde(default, rename = "Results")]
    results: Vec<RawResult>,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    #[serde(default, rename = "OS")]
    os: Option<RawOs>,
}

#[derive(Debug, Deserialize)]
struct RawOs {
    #[serde(default, rename = "Family")]
    family: Option<String>,
    #[serde(default, rename = "Name")]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawResult {
    #[serde(default, rename = "Target")]
    target: Option<String>,
    #[serde(default, rename = "Class")]
    class: Option<String>,
    #[serde(default, rename = "Type")]
    kind: Option<String>,
    #[serde(default, rename = "Vulnerabilities")]
    vulnerabilities: Vec<RawVulnerability>,
    #[serde(default, rename = "Misconfigurations")]
    misconfigurations: Vec<RawMisconfiguration>,
    #[serde(default, rename = "Secrets")]
    secrets: Vec<RawSecret>,
}

#[derive(Debug, Deserialize)]
struct RawVulnerability {
    #[serde(default, rename = "VulnerabilityID")]
    id: Option<String>,
    #[serde(default, rename = "PkgName")]
    package: Option<String>,
    #[serde(default, rename = "PkgIdentifier")]
    package_identifier: Option<RawPkgIdentifier>,
    #[serde(default, rename = "InstalledVersion")]
    installed_version: Option<String>,
    #[serde(default, rename = "FixedVersion")]
    fixed_version: Option<String>,
    #[serde(default, rename = "Title")]
    title: Option<String>,
    #[serde(default, rename = "Description")]
    description: Option<String>,
    #[serde(default, rename = "Severity")]
    severity: Option<String>,
    #[serde(default, rename = "CweIDs")]
    cwe_ids: Vec<String>,
    #[serde(default, rename = "PrimaryURL")]
    primary_url: Option<String>,
    #[serde(default, rename = "References")]
    references: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawPkgIdentifier {
    #[serde(default, rename = "PURL")]
    purl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMisconfiguration {
    #[serde(default, rename = "ID")]
    id: Option<String>,
    #[serde(default, rename = "Title")]
    title: Option<String>,
    #[serde(default, rename = "Description")]
    description: Option<String>,
    #[serde(default, rename = "Message")]
    message: Option<String>,
    #[serde(default, rename = "Severity")]
    severity: Option<String>,
    #[serde(default, rename = "Resolution")]
    resolution: Option<String>,
    #[serde(default, rename = "PrimaryURL")]
    primary_url: Option<String>,
    #[serde(default, rename = "CauseMetadata")]
    cause: Option<RawCause>,
}

#[derive(Debug, Deserialize)]
struct RawCause {
    #[serde(default, rename = "StartLine")]
    start_line: Option<u32>,
    #[serde(default, rename = "EndLine")]
    end_line: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawSecret {
    #[serde(default, rename = "RuleID")]
    rule_id: Option<String>,
    #[serde(default, rename = "Category")]
    category: Option<String>,
    #[serde(default, rename = "Severity")]
    severity: Option<String>,
    #[serde(default, rename = "Title")]
    title: Option<String>,
    #[serde(default, rename = "StartLine")]
    start_line: Option<u32>,
    #[serde(default, rename = "EndLine")]
    end_line: Option<u32>,
}

/// Trivy's five ranks onto the pivot's five, order-preserving.
///
/// Chosen so a Trivy severity survives the trip to GitLab intact:
/// `CRITICAL` → blocker → `Critical`, `HIGH` → critical → `High`,
/// `MEDIUM` → major → `Medium`, `LOW` → minor → `Low`.
fn severity_of(raw: Option<&str>) -> Severity {
    match raw.unwrap_or("").to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Blocker,
        "HIGH" => Severity::Critical,
        "MEDIUM" => Severity::Major,
        "LOW" => Severity::Minor,
        _ => Severity::Info,
    }
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let report: RawReport = serde_json::from_slice(input).map_err(|e| Error::parse(FORMAT, e))?;

    match report.schema_version {
        Some(2) => {}
        Some(1) => {
            return Err(Error::parse(
                FORMAT,
                "schema version 1 is a structurally different report and is not supported; \
                 re-run Trivy, which has emitted version 2 for years",
            ))
        }
        Some(other) => ctx.degraded(format!(
            "trivy-json: schema version {other} is newer than the version 2 this reader knows; \
             fields it added were ignored"
        )),
        None => {
            return Err(Error::parse(
                FORMAT,
                "no `SchemaVersion` — this does not look like a Trivy report",
            ))
        }
    }

    let image = report
        .artifact_type
        .as_deref()
        .is_some_and(|kind| kind.contains("image"))
        .then(|| report.artifact_name.clone())
        .flatten();
    let operating_system = report
        .metadata
        .as_ref()
        .and_then(|m| m.os.as_ref())
        .map(|os| match (os.family.as_deref(), os.name.as_deref()) {
            (Some(family), Some(name)) => format!("{family} {name}"),
            (Some(family), None) => family.to_string(),
            (None, Some(name)) => name.to_string(),
            (None, None) => String::new(),
        });

    let mut doc = FindingsDoc {
        tool: Some(Tool {
            name: "trivy".into(),
            version: None,
            url: Some("https://trivy.dev".into()),
        }),
        scan: ScanWindow {
            start: report.created_at.as_deref().and_then(iso_seconds),
            end: report.created_at.as_deref().and_then(iso_seconds),
        },
        ..Default::default()
    };

    let mut ecosystems: Vec<String> = Vec::new();

    for result in report.results {
        let class = result.class.clone().unwrap_or_default();
        let target = result.target.clone().unwrap_or_default();
        if let Some(kind) = result.kind.clone() {
            if !kind.is_empty() && !ecosystems.contains(&kind) {
                ecosystems.push(kind);
            }
        }

        // An operating-system package is not in a file; a language package is
        // declared in the manifest that `Target` names.
        let in_a_file = class != "os-pkgs";
        let base = Location {
            path: if in_a_file {
                crate::paths::normalize(&target)
            } else {
                String::new()
            },
            image: image.clone(),
            operating_system: (class == "os-pkgs")
                .then(|| operating_system.clone())
                .flatten()
                .filter(|os| !os.is_empty()),
            ..Default::default()
        };

        for raw in result.vulnerabilities {
            doc.findings.push(vulnerability(raw, &base));
        }
        for raw in result.misconfigurations {
            doc.findings.push(misconfiguration(raw, &base));
        }
        for raw in result.secrets {
            doc.findings.push(secret(raw, &base));
        }
    }

    if doc.findings.is_empty() {
        // A clean scan is a legitimate report, and converting it must not fail.
        log::debug!("trivy-json: the report contains no finding");
    }
    if !ecosystems.is_empty() {
        log::debug!("trivy-json: ecosystems {}", ecosystems.join(", "));
    }

    for finding in &mut doc.findings {
        finding.ensure_fingerprint();
    }
    doc.sort();
    Ok(Doc::Findings(doc))
}

fn vulnerability(raw: RawVulnerability, base: &Location) -> Finding {
    let id = raw.id.clone().unwrap_or_default();
    let package = raw.package.clone().unwrap_or_default();

    // `Title` is the headline, `Description` the essay. Sinks show one line.
    let description = raw
        .title
        .clone()
        .filter(|t| !t.is_empty())
        .or_else(|| raw.description.clone().filter(|d| !d.is_empty()))
        .unwrap_or_else(|| format!("{id} affects {package}"));

    let mut finding = Finding::new(description, severity_of(raw.severity.as_deref()));
    finding.rule_id = (!id.is_empty()).then(|| id.clone());
    finding.title = raw.title.clone();

    if !id.is_empty() {
        finding.identifiers.push(Identifier {
            kind: identifier_kind(&id),
            value: id,
            url: raw.primary_url.clone(),
        });
    }
    for cwe in raw.cwe_ids {
        finding.identifiers.push(Identifier {
            kind: "cwe".into(),
            value: cwe,
            url: None,
        });
    }

    finding.help = raw
        .fixed_version
        .as_deref()
        .map(|fixed| format!("Upgrade {package} to {fixed}."));
    finding.links = raw
        .primary_url
        .into_iter()
        .chain(raw.references)
        .filter(|url| !url.is_empty())
        .collect();
    finding.links.dedup();

    finding.component = Some(Component {
        name: package,
        version: raw.installed_version,
        fixed_version: raw.fixed_version,
        purl: raw.package_identifier.and_then(|p| p.purl),
    });
    finding.location = base.clone();
    finding
}

fn misconfiguration(raw: RawMisconfiguration, base: &Location) -> Finding {
    let description = raw
        .message
        .clone()
        .filter(|m| !m.is_empty())
        .or_else(|| raw.title.clone().filter(|t| !t.is_empty()))
        .or_else(|| raw.description.clone())
        .unwrap_or_else(|| "(no message)".into());

    let mut finding = Finding::new(description, severity_of(raw.severity.as_deref()));
    finding.rule_id = raw.id.filter(|id| !id.is_empty());
    finding.title = raw.title;
    finding.help = raw.resolution.filter(|r| !r.is_empty());
    finding.links = raw
        .primary_url
        .into_iter()
        .filter(|u| !u.is_empty())
        .collect();
    finding.categories.push("misconfiguration".into());
    finding.location = Location {
        begin_line: raw.cause.as_ref().and_then(|c| c.start_line),
        end_line: raw.cause.as_ref().and_then(|c| c.end_line),
        ..base.clone()
    };
    finding
}

fn secret(raw: RawSecret, base: &Location) -> Finding {
    let description = raw
        .title
        .clone()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "a secret was found".into());

    let mut finding = Finding::new(description, severity_of(raw.severity.as_deref()));
    finding.rule_id = raw.rule_id.filter(|id| !id.is_empty());
    finding.categories.push("secret".into());
    if let Some(category) = raw.category.filter(|c| !c.is_empty()) {
        finding.categories.push(category);
    }
    finding.location = Location {
        begin_line: raw.start_line,
        end_line: raw.end_line,
        ..base.clone()
    };
    finding
}

/// `CVE-2024-1234` → `cve`, `GHSA-xxxx` → `ghsa`, and the vendor advisories
/// Trivy reports under their own prefix.
fn identifier_kind(id: &str) -> String {
    id.split('-')
        .next()
        .filter(|prefix| !prefix.is_empty())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "unknown".into())
}

/// `2026-06-26T12:00:00.123456789Z` → `2026-06-26T12:00:00`.
fn iso_seconds(raw: &str) -> Option<String> {
    let candidate = raw.get(..19)?;
    let bytes = candidate.as_bytes();
    (candidate.len() == 19
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':')
        .then(|| candidate.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "SchemaVersion": 2,
      "CreatedAt": "2026-06-26T12:00:00.123456789Z",
      "ArtifactName": "acme/api:1.2.3",
      "ArtifactType": "container_image",
      "Metadata": { "OS": { "Family": "debian", "Name": "12.5" } },
      "Results": [
        {
          "Target": "acme/api:1.2.3 (debian 12.5)",
          "Class": "os-pkgs",
          "Type": "debian",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2024-1234",
              "PkgName": "libssl3",
              "InstalledVersion": "3.0.11-1",
              "FixedVersion": "3.0.11-2",
              "Title": "openssl: out-of-bounds read",
              "Description": "A very long paragraph nobody reads in a list view.",
              "Severity": "HIGH",
              "CweIDs": ["CWE-125"],
              "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-1234",
              "References": ["https://openssl.org/news/secadv/20240101.txt"]
            }
          ]
        },
        {
          "Target": "package-lock.json",
          "Class": "lang-pkgs",
          "Type": "npm",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "GHSA-abcd-1234-efgh",
              "PkgName": "lodash",
              "PkgIdentifier": { "PURL": "pkg:npm/lodash@4.17.20" },
              "InstalledVersion": "4.17.20",
              "FixedVersion": "4.17.21",
              "Title": "Prototype pollution in lodash",
              "Severity": "CRITICAL"
            }
          ]
        },
        {
          "Target": "Dockerfile",
          "Class": "config",
          "Type": "dockerfile",
          "Misconfigurations": [
            {
              "ID": "DS002",
              "Title": "Image user should not be root",
              "Message": "Specify at least 1 USER command",
              "Severity": "MEDIUM",
              "Resolution": "Add a USER command",
              "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
              "CauseMetadata": { "StartLine": 1, "EndLine": 12 }
            }
          ]
        },
        {
          "Target": ".env",
          "Class": "secret",
          "Secrets": [
            {
              "RuleID": "aws-access-key-id",
              "Category": "AWS",
              "Severity": "CRITICAL",
              "Title": "AWS Access Key ID",
              "StartLine": 3,
              "EndLine": 3
            }
          ]
        }
      ]
    }"#;

    fn parse(input: &str) -> (FindingsDoc, crate::warn::Warnings) {
        let mut ctx = FormatCtx::new(None);
        let doc = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Findings(doc) => doc,
            _ => panic!("expected a findings document"),
        };
        (doc, ctx.into_warnings())
    }

    fn by_rule<'a>(doc: &'a FindingsDoc, rule: &str) -> &'a Finding {
        doc.findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some(rule))
            .unwrap_or_else(|| panic!("no finding for {rule}"))
    }

    #[test]
    fn an_os_package_is_located_by_the_image_not_a_file() {
        let (doc, _) = parse(SAMPLE);
        let finding = by_rule(&doc, "CVE-2024-1234");

        assert_eq!(finding.location.path, "");
        assert_eq!(finding.location.image.as_deref(), Some("acme/api:1.2.3"));
        assert_eq!(
            finding.location.operating_system.as_deref(),
            Some("debian 12.5")
        );
    }

    #[test]
    fn a_language_package_is_located_by_its_manifest() {
        let (doc, _) = parse(SAMPLE);
        let finding = by_rule(&doc, "GHSA-abcd-1234-efgh");

        assert_eq!(finding.location.path, "package-lock.json");
        // Still the same image, but the operating system says nothing here.
        assert_eq!(finding.location.image.as_deref(), Some("acme/api:1.2.3"));
        assert_eq!(finding.location.operating_system, None);
    }

    #[test]
    fn carries_the_component_and_its_fix() {
        let (doc, _) = parse(SAMPLE);
        let component = by_rule(&doc, "GHSA-abcd-1234-efgh")
            .component
            .as_ref()
            .unwrap();

        assert_eq!(component.name, "lodash");
        assert_eq!(component.version.as_deref(), Some("4.17.20"));
        assert_eq!(component.fixed_version.as_deref(), Some("4.17.21"));
        assert_eq!(component.purl.as_deref(), Some("pkg:npm/lodash@4.17.20"));
    }

    #[test]
    fn severity_is_ordered_so_a_gitlab_round_trip_is_exact() {
        let (doc, _) = parse(SAMPLE);
        // HIGH is not the top of Trivy's scale, so it must not be the top here.
        assert_eq!(by_rule(&doc, "CVE-2024-1234").severity, Severity::Critical);
        assert_eq!(
            by_rule(&doc, "GHSA-abcd-1234-efgh").severity,
            Severity::Blocker
        );
        assert_eq!(by_rule(&doc, "DS002").severity, Severity::Major);
    }

    #[test]
    fn prefers_the_title_over_the_essay() {
        let (doc, _) = parse(SAMPLE);
        let finding = by_rule(&doc, "CVE-2024-1234");
        assert_eq!(finding.description, "openssl: out-of-bounds read");
        assert_eq!(
            finding.help.as_deref(),
            Some("Upgrade libssl3 to 3.0.11-2.")
        );
    }

    #[test]
    fn reads_identifiers_with_their_kind() {
        let (doc, _) = parse(SAMPLE);
        let kinds: Vec<&str> = by_rule(&doc, "CVE-2024-1234")
            .identifiers
            .iter()
            .map(|i| i.kind.as_str())
            .collect();
        assert_eq!(kinds, ["cve", "cwe"]);

        let ghsa = by_rule(&doc, "GHSA-abcd-1234-efgh");
        assert_eq!(ghsa.identifiers[0].kind, "ghsa");
    }

    #[test]
    fn reads_misconfigurations_and_secrets_with_their_lines() {
        let (doc, _) = parse(SAMPLE);

        let misconfig = by_rule(&doc, "DS002");
        assert_eq!(misconfig.location.path, "Dockerfile");
        assert_eq!(misconfig.location.begin_line, Some(1));
        assert_eq!(misconfig.description, "Specify at least 1 USER command");
        assert!(misconfig
            .categories
            .contains(&"misconfiguration".to_string()));

        let secret = by_rule(&doc, "aws-access-key-id");
        assert_eq!(secret.location.path, ".env");
        assert_eq!(secret.location.begin_line, Some(3));
        assert!(secret.categories.contains(&"secret".to_string()));
    }

    #[test]
    fn reads_the_scan_time() {
        let (doc, _) = parse(SAMPLE);
        assert_eq!(doc.scan.start.as_deref(), Some("2026-06-26T12:00:00"));
    }

    #[test]
    fn a_filesystem_scan_has_no_image() {
        let (doc, _) = parse(
            r#"{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem",
                "Results":[{"Target":"go.sum","Class":"lang-pkgs","Type":"gomod",
                  "Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"x","Severity":"LOW"}]}]}"#,
        );
        assert_eq!(doc.findings[0].location.image, None);
        assert_eq!(doc.findings[0].location.path, "go.sum");
    }

    #[test]
    fn a_clean_scan_is_a_valid_report() {
        let (doc, _) = parse(r#"{"SchemaVersion":2,"ArtifactName":".","Results":[]}"#);
        assert!(doc.findings.is_empty());
    }

    #[test]
    fn rejects_schema_version_one_rather_than_misreading_it() {
        let mut ctx = FormatCtx::new(None);
        let error = read(br#"{"SchemaVersion":1,"Results":[]}"#, &mut ctx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("structurally different"), "{error}");
    }

    #[test]
    fn a_newer_schema_version_is_read_but_flagged() {
        let mut ctx = FormatCtx::new(None);
        read(br#"{"SchemaVersion":99,"Results":[]}"#, &mut ctx).unwrap();
        assert!(ctx.warnings().messages().any(|m| m.contains("newer than")));
    }

    #[test]
    fn rejects_json_with_no_schema_version() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(br#"{"Results":[]}"#, &mut ctx).is_err());
    }
}
