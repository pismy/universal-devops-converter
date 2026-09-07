//! GitLab's security report formats: SAST, dependency scanning and container
//! scanning.
//!
//! These are what fill GitLab's security dashboard and its merge request
//! security widget, and only GitLab's own analyzers emit them — so converting
//! into them is what lets semgrep, Trivy, CodeQL or anything else feed it.
//!
//! They are three *formats*, not one with a switch. Each has its own schema,
//! its own `scan.type`, and — the part that matters — its own required
//! location:
//!
//! | Profile | `location` must carry |
//! |---|---|
//! | `sast` | nothing; a file and lines when known |
//! | `dependency_scanning` | `file` and `dependency` (package name + version) |
//! | `container_scanning` | `dependency`, `image` and `operating_system` |
//!
//! A finding that cannot satisfy its target's location is **dropped, and
//! counted**. That is not a failure of the conversion: an operating-system
//! package has no manifest file, so it belongs in a container-scanning report
//! and not in a dependency-scanning one. Sending the whole document to GitLab
//! with one invalid entry would get all of it rejected.
//!
//! The schemas (`security-report-schemas` 15.2.5) are stricter than the pivot
//! in three further places, and each forces a decision:
//!
//! - **`scan.start_time` / `scan.end_time` are required**, with a fixed
//!   `yyyy-mm-ddThh:mm:ss` shape. Reading the clock would make the output
//!   differ on every run, which the project guarantees it does not. The window
//!   is taken from the source when it has one and falls back to a fixed epoch,
//!   with a `degraded:` notice — a wrong date the report admits to beats a
//!   report that cannot be diffed.
//! - **`identifiers` needs at least one entry**, while a finding from a linter
//!   has none. One is synthesized from the rule id.
//! - **`id` should be a UUID.** The pivot's fingerprint is 128 bits of hex, so
//!   it is formatted as one rather than invented afresh on every run.

use std::io::Write;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::model::findings::{Finding, Severity};
use crate::registry::Doc;
use crate::warn::FormatCtx;

/// Schema version the output declares. Matches the vendored schemas.
const SCHEMA_VERSION: &str = "15.2.5";

/// Which report is being written. They differ only in `scan.type` and in what
/// `location` must carry, but those differences are load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    Sast,
    DependencyScanning,
    ContainerScanning,
}

impl Profile {
    fn scan_type(self) -> &'static str {
        match self {
            Profile::Sast => "sast",
            Profile::DependencyScanning => "dependency_scanning",
            Profile::ContainerScanning => "container_scanning",
        }
    }

    fn format_id(self) -> &'static str {
        match self {
            Profile::Sast => "gitlab-sast",
            Profile::DependencyScanning => "gitlab-dependency-scanning",
            Profile::ContainerScanning => "gitlab-container-scanning",
        }
    }

    /// What a finding must carry to be expressible here.
    fn requirement(self) -> &'static str {
        match self {
            Profile::Sast => "an identifier or a rule id",
            Profile::DependencyScanning => "a file path and a named package",
            Profile::ContainerScanning => "an image, an operating system and a named package",
        }
    }
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    dependency: Option<Dependency<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operating_system: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct Dependency<'a> {
    package: Package<'a>,
    /// Required by the schema even when unknown, so an empty string stands in
    /// rather than the whole finding being dropped: a vulnerability with an
    /// unknown version is still worth showing.
    version: &'a str,
}

#[derive(Debug, Serialize)]
struct Package<'a> {
    name: &'a str,
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

/// SAST: findings in source code. The location is free-form, so anything with
/// an identifier fits.
pub fn write_sast(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    emit(doc, out, ctx, Profile::Sast)
}

/// Dependency scanning: a vulnerable package declared in a manifest. Needs both
/// the manifest path and the package.
pub fn write_dependency_scanning(
    doc: &Doc,
    out: &mut dyn Write,
    ctx: &mut FormatCtx,
) -> Result<()> {
    emit(doc, out, ctx, Profile::DependencyScanning)
}

/// Container scanning: a vulnerable package inside an image. Needs the image
/// and its operating system, and has no manifest file at all.
pub fn write_container_scanning(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    emit(doc, out, ctx, Profile::ContainerScanning)
}

/// Build the `location` this profile requires, or `None` when the finding
/// cannot satisfy it.
fn location_of<'a>(finding: &'a Finding, profile: Profile) -> Option<Location<'a>> {
    let dependency = || {
        let component = finding.component.as_ref()?;
        (!component.name.is_empty()).then(|| Dependency {
            package: Package {
                name: &component.name,
            },
            version: component.version.as_deref().unwrap_or(""),
        })
    };

    match profile {
        Profile::Sast => Some(Location {
            file: Some(finding.location.path.as_str()).filter(|p| !p.is_empty()),
            start_line: finding.location.begin_line,
            end_line: finding.location.end_line,
            dependency: None,
            image: None,
            operating_system: None,
        }),
        Profile::DependencyScanning => {
            // The manifest that declares the package. An operating-system
            // package has none, which is why it belongs in a container report.
            let file = Some(finding.location.path.as_str()).filter(|p| !p.is_empty())?;
            Some(Location {
                file: Some(file),
                start_line: None,
                end_line: None,
                dependency: Some(dependency()?),
                image: None,
                operating_system: None,
            })
        }
        Profile::ContainerScanning => Some(Location {
            file: None,
            start_line: None,
            end_line: None,
            dependency: Some(dependency()?),
            image: Some(
                finding
                    .location
                    .image
                    .as_deref()
                    .filter(|i| !i.is_empty())?,
            ),
            operating_system: Some(
                finding
                    .location
                    .operating_system
                    .as_deref()
                    .filter(|os| !os.is_empty())?,
            ),
        }),
    }
}

fn emit(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx, profile: Profile) -> Result<()> {
    let doc = doc.as_findings()?;
    let format = profile.format_id();

    let start = doc.scan.start.as_deref().unwrap_or(UNKNOWN_TIME);
    let end = doc.scan.end.as_deref().unwrap_or(UNKNOWN_TIME);
    if doc.scan.start.is_none() || doc.scan.end.is_none() {
        ctx.degraded(format!(
            "{format}: the report requires a scan window and the source carried none; \
             1970-01-01T00:00:00 is emitted so the output stays reproducible"
        ));
    }

    let mut vulnerabilities = Vec::with_capacity(doc.findings.len());
    let mut unidentified = 0usize;
    let mut unplaceable = 0usize;
    let mut versionless = 0usize;

    for finding in &doc.findings {
        let identifiers = identifiers_of(finding);
        if identifiers.is_empty() {
            // No identifier and no rule id: the entry could not satisfy the
            // schema, and a report GitLab rejects wholesale is worse than one
            // missing a finding.
            unidentified += 1;
            continue;
        }
        let Some(location) = location_of(finding, profile) else {
            unplaceable += 1;
            continue;
        };
        if location
            .dependency
            .as_ref()
            .is_some_and(|d| d.version.is_empty())
        {
            versionless += 1;
        }

        // Always UUID-shaped, and always derived from something stable: the
        // source fingerprint when there is one, so a finding keeps its identity
        // across runs and GitLab can tell it apart from a new one.
        let hex = match finding.fingerprint.as_deref() {
            Some(fingerprint) if is_hex_128(fingerprint) => fingerprint.to_string(),
            Some(fingerprint) => crate::hash::fingerprint(&[fingerprint]),
            None => crate::hash::fingerprint(&[&finding.location.path, &finding.description]),
        };

        vulnerabilities.push(Vulnerability {
            id: as_uuid(&hex).expect("a 128-bit hex digest"),
            name: finding.title.clone(),
            description: &finding.description,
            severity: severity_of(finding.severity),
            solution: finding.help.as_deref(),
            identifiers,
            location,
            links: finding.links.iter().map(|url| Link { url }).collect(),
        });
    }

    if unidentified > 0 {
        ctx.lossy(format!(
            "{format}: {unidentified} finding(s) had neither an identifier nor a rule id and were \
             dropped (the schema requires at least one identifier)"
        ));
    }
    if unplaceable > 0 {
        ctx.lossy(format!(
            "{format}: {unplaceable} finding(s) were dropped for lacking {} — the schema requires \
             it, and one invalid entry would have GitLab reject the whole report",
            profile.requirement()
        ));
    }
    if versionless > 0 {
        ctx.degraded(format!(
            "{format}: {versionless} finding(s) had no package version; the schema requires the \
             field, so it is emitted empty rather than losing the vulnerability"
        ));
    }
    if doc.findings.iter().any(|f| !f.categories.is_empty()) {
        ctx.lossy(format!(
            "{format}: issue categories have no field in the security report"
        ));
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
            kind: profile.scan_type(),
            status: "success",
            start_time: start,
            end_time: end,
        },
        vulnerabilities,
    };

    serde_json::to_writer_pretty(&mut *out, &report).map_err(|e| Error::parse(format, e))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::findings::{
        Component, FindingsDoc, Identifier, Location as PivotLocation, ScanWindow, Tool,
    };
    use crate::warn::Warnings;

    fn render(doc: &FindingsDoc) -> (serde_json::Value, Warnings) {
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(Some(SCHEMA_VERSION));
        write_sast(&Doc::Findings(doc.clone()), &mut buffer, &mut ctx).unwrap();
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

    fn render_as(
        doc: &FindingsDoc,
        write: fn(&Doc, &mut dyn Write, &mut FormatCtx) -> Result<()>,
    ) -> (serde_json::Value, Warnings) {
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(Some(SCHEMA_VERSION));
        write(&Doc::Findings(doc.clone()), &mut buffer, &mut ctx).unwrap();
        (
            serde_json::from_slice(&buffer).expect("the writer emits valid JSON"),
            ctx.into_warnings(),
        )
    }

    /// A vulnerable npm package declared in a lock file: expressible as
    /// dependency scanning, and not as container scanning.
    fn lang_package() -> Finding {
        let mut finding = Finding::new("Prototype pollution in lodash", Severity::Blocker);
        finding.rule_id = Some("GHSA-abcd".into());
        finding.location = PivotLocation {
            path: "package-lock.json".into(),
            ..Default::default()
        };
        finding.component = Some(Component {
            name: "lodash".into(),
            version: Some("4.17.20".into()),
            fixed_version: Some("4.17.21".into()),
            purl: None,
        });
        finding.ensure_fingerprint();
        finding
    }

    /// An operating-system package inside an image: the mirror case.
    fn os_package() -> Finding {
        let mut finding = Finding::new("openssl: out-of-bounds read", Severity::Critical);
        finding.rule_id = Some("CVE-2024-1234".into());
        finding.location = PivotLocation {
            image: Some("acme/api:1.2.3".into()),
            operating_system: Some("debian 12.5".into()),
            ..Default::default()
        };
        finding.component = Some(Component {
            name: "libssl3".into(),
            version: Some("3.0.11-1".into()),
            fixed_version: Some("3.0.11-2".into()),
            purl: None,
        });
        finding.ensure_fingerprint();
        finding
    }

    #[test]
    fn dependency_scanning_keeps_manifest_packages_and_drops_the_rest() {
        let doc = FindingsDoc {
            findings: vec![lang_package(), os_package()],
            ..Default::default()
        };
        let (json, warnings) = render_as(&doc, write_dependency_scanning);

        assert_eq!(json["scan"]["type"], "dependency_scanning");
        let vulns = json["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1, "an OS package has no manifest file");
        assert_eq!(vulns[0]["location"]["file"], "package-lock.json");
        assert_eq!(
            vulns[0]["location"]["dependency"]["package"]["name"],
            "lodash"
        );
        assert_eq!(vulns[0]["location"]["dependency"]["version"], "4.17.20");
        // Dropping is deliberate, so it is counted rather than silent.
        assert!(warnings
            .messages()
            .any(|m| m.contains("file path and a named package")));
    }

    #[test]
    fn container_scanning_keeps_image_packages_and_drops_the_rest() {
        let doc = FindingsDoc {
            findings: vec![lang_package(), os_package()],
            ..Default::default()
        };
        let (json, warnings) = render_as(&doc, write_container_scanning);

        assert_eq!(json["scan"]["type"], "container_scanning");
        let vulns = json["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1, "a lock-file package has no image");
        assert_eq!(vulns[0]["location"]["image"], "acme/api:1.2.3");
        assert_eq!(vulns[0]["location"]["operating_system"], "debian 12.5");
        assert_eq!(
            vulns[0]["location"]["dependency"]["package"]["name"],
            "libssl3"
        );
        // A container location has no file at all.
        assert!(vulns[0]["location"]["file"].is_null());
        assert!(warnings
            .messages()
            .any(|m| m.contains("image, an operating system")));
    }

    #[test]
    fn a_package_with_no_version_is_kept_with_an_empty_one() {
        let mut finding = lang_package();
        finding.component.as_mut().unwrap().version = None;
        let (json, warnings) = render_as(
            &FindingsDoc {
                findings: vec![finding],
                ..Default::default()
            },
            write_dependency_scanning,
        );

        // The schema requires the field; losing the vulnerability would be the
        // worse trade.
        assert_eq!(
            json["vulnerabilities"][0]["location"]["dependency"]["version"],
            ""
        );
        assert!(warnings
            .messages()
            .any(|m| m.contains("no package version")));
    }

    #[test]
    fn the_three_profiles_declare_their_own_scan_type() {
        let doc = FindingsDoc {
            findings: vec![lang_package()],
            ..Default::default()
        };
        assert_eq!(render_as(&doc, write_sast).0["scan"]["type"], "sast");
        assert_eq!(
            render_as(&doc, write_dependency_scanning).0["scan"]["type"],
            "dependency_scanning"
        );
        assert_eq!(
            render_as(&doc, write_container_scanning).0["scan"]["type"],
            "container_scanning"
        );
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
