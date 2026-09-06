//! Code Climate issue JSON, in two flavours.
//!
//! - **`codeclimate`** — the full specification: `type`, `check_name`,
//!   `description`, `content`, `categories`, `location` (lines *or* positions),
//!   `severity`, `fingerprint`.
//! - **`codeclimate-gitlab`** — the strict subset GitLab's Code Quality report
//!   consumes. GitLab ignores everything else and *rejects entries without a
//!   `fingerprint`*, which is why the pivot synthesizes one (see
//!   [`Finding::ensure_fingerprint`]).
//!
//! Both are arrays of issue objects, which is also why neither can be
//! auto-detected: a bare JSON array is indistinguishable from a pa11y report.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::findings::{Finding, FindingsDoc, Location, Severity};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "codeclimate";

#[derive(Debug, Deserialize)]
struct RawIssue {
    #[serde(default)]
    check_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    content: Option<RawContent>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    location: Option<RawLocation>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawContent {
    #[serde(default)]
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawLocation {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    lines: Option<RawLines>,
    #[serde(default)]
    positions: Option<RawPositions>,
}

#[derive(Debug, Deserialize)]
struct RawLines {
    #[serde(default)]
    begin: Option<u32>,
    #[serde(default)]
    end: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawPositions {
    #[serde(default)]
    begin: Option<RawCoords>,
    #[serde(default)]
    end: Option<RawCoords>,
}

#[derive(Debug, Deserialize)]
struct RawCoords {
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    column: Option<u32>,
}

pub fn read(input: &[u8], _ctx: &mut FormatCtx) -> Result<Doc> {
    let issues: Vec<RawIssue> =
        serde_json::from_slice(input).map_err(|e| Error::parse(FORMAT, e))?;

    let mut doc = FindingsDoc::default();
    for issue in issues {
        let description = issue
            .description
            .or_else(|| issue.content.as_ref().and_then(|c| c.body.clone()))
            .unwrap_or_else(|| "(no description)".into());
        let severity = issue
            .severity
            .as_deref()
            .and_then(Severity::parse)
            .unwrap_or(Severity::Minor);

        let mut finding = Finding::new(description, severity);
        finding.rule_id = issue.check_name.filter(|c| !c.is_empty());
        finding.categories = issue.categories;
        finding.fingerprint = issue.fingerprint.filter(|f| !f.is_empty());
        finding.location = location(issue.location);
        finding.ensure_fingerprint();
        doc.findings.push(finding);
    }

    doc.sort();
    Ok(Doc::Findings(doc))
}

/// Code Climate allows either `lines: {begin, end}` or the richer
/// `positions: {begin: {line, column}, …}`. Accept both, prefer the richer one.
fn location(raw: Option<RawLocation>) -> Location {
    let Some(raw) = raw else {
        return Location::default();
    };
    let path = raw
        .path
        .map(|p| crate::paths::normalize(&p))
        .unwrap_or_default();

    if let Some(positions) = raw.positions {
        return Location {
            path,
            begin_line: positions.begin.as_ref().and_then(|c| c.line),
            end_line: positions.end.as_ref().and_then(|c| c.line),
            begin_column: positions.begin.as_ref().and_then(|c| c.column),
            end_column: positions.end.as_ref().and_then(|c| c.column),
        };
    }

    let lines = raw.lines;
    Location {
        path,
        begin_line: lines.as_ref().and_then(|l| l.begin),
        end_line: lines.as_ref().and_then(|l| l.end),
        begin_column: None,
        end_column: None,
    }
}

#[derive(Debug, Serialize)]
struct OutIssue<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    check_name: &'a str,
    description: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<OutContent<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    categories: Vec<&'a str>,
    location: OutLocation<'a>,
    severity: &'static str,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
struct OutContent<'a> {
    body: &'a str,
}

#[derive(Debug, Serialize)]
struct OutLocation<'a> {
    path: &'a str,
    lines: OutLines,
    #[serde(skip_serializing_if = "Option::is_none")]
    positions: Option<OutPositions>,
}

#[derive(Debug, Serialize)]
struct OutLines {
    begin: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    end: Option<u32>,
}

#[derive(Debug, Serialize)]
struct OutPositions {
    begin: OutCoords,
    #[serde(skip_serializing_if = "Option::is_none")]
    end: Option<OutCoords>,
}

#[derive(Debug, Serialize)]
struct OutCoords {
    line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<u32>,
}

/// Full Code Climate output: keeps categories, remediation content and columns.
pub fn write_full(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    emit(doc, out, ctx, false)
}

/// GitLab Code Quality output: the strict subset GitLab reads. Anything else is
/// dropped rather than emitted and ignored, so the file stays small and the
/// loss is reported.
pub fn write_gitlab(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    emit(doc, out, ctx, true)
}

fn emit(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx, gitlab: bool) -> Result<()> {
    let doc = doc.as_findings()?;

    if gitlab {
        if doc.findings.iter().any(|f| !f.categories.is_empty()) {
            ctx.lossy(
                "codeclimate-gitlab: issue categories are not read by GitLab and were dropped",
            );
        }
        if doc.findings.iter().any(|f| f.help.is_some()) {
            ctx.lossy("codeclimate-gitlab: remediation guidance has no field in the GitLab subset");
        }
        if doc
            .findings
            .iter()
            .any(|f| f.location.begin_column.is_some())
        {
            ctx.lossy(
                "codeclimate-gitlab: column positions are not read by GitLab and were dropped",
            );
        }
    }
    if doc.findings.iter().any(|f| !f.identifiers.is_empty()) {
        ctx.lossy(
            "codeclimate: security identifiers (CVE/CWE) have no place in a code quality report",
        );
    }

    let issues: Vec<OutIssue> = doc
        .findings
        .iter()
        .map(|finding| {
            // GitLab requires a begin line; findings attached to a whole file
            // are anchored at line 1 rather than dropped.
            let begin = finding.location.begin_line.unwrap_or(1);
            OutIssue {
                kind: "issue",
                check_name: finding.rule_id.as_deref().unwrap_or("unknown"),
                description: &finding.description,
                content: if gitlab {
                    None
                } else {
                    finding.help.as_deref().map(|body| OutContent { body })
                },
                categories: if gitlab {
                    Vec::new()
                } else {
                    finding.categories.iter().map(String::as_str).collect()
                },
                location: OutLocation {
                    path: &finding.location.path,
                    lines: OutLines {
                        begin,
                        end: if gitlab {
                            None
                        } else {
                            finding.location.end_line
                        },
                    },
                    positions: if gitlab || finding.location.begin_column.is_none() {
                        None
                    } else {
                        Some(OutPositions {
                            begin: OutCoords {
                                line: begin,
                                column: finding.location.begin_column,
                            },
                            end: finding.location.end_line.map(|line| OutCoords {
                                line,
                                column: finding.location.end_column,
                            }),
                        })
                    },
                },
                severity: finding.severity.as_str(),
                fingerprint: finding
                    .fingerprint
                    .clone()
                    .unwrap_or_else(|| synth_fingerprint(finding)),
            }
        })
        .collect();

    serde_json::to_writer_pretty(&mut *out, &issues).map_err(|e| Error::parse(FORMAT, e))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn synth_fingerprint(finding: &Finding) -> String {
    crate::hash::fingerprint(&[
        &finding.location.path,
        finding.rule_id.as_deref().unwrap_or(""),
        &finding.description,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warn::Warnings;

    const SAMPLE: &str = r#"[
      {
        "type": "issue",
        "check_name": "no-var",
        "description": "Unexpected var",
        "categories": ["Style"],
        "location": {"path": "src/app.js", "lines": {"begin": 12, "end": 12}},
        "severity": "minor",
        "fingerprint": "abc123"
      },
      {
        "check_name": "complexity",
        "content": {"body": "Split this function"},
        "location": {"path": "src/app.js", "positions": {"begin": {"line": 40, "column": 3}}},
        "severity": "major"
      }
    ]"#;

    fn parse(input: &str) -> FindingsDoc {
        let mut ctx = FormatCtx::new(None);
        match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Findings(doc) => doc,
            _ => panic!("expected a findings document"),
        }
    }

    fn render(doc: &FindingsDoc, gitlab: bool) -> (String, Warnings) {
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        emit(&Doc::Findings(doc.clone()), &mut buffer, &mut ctx, gitlab).unwrap();
        (String::from_utf8(buffer).unwrap(), ctx.into_warnings())
    }

    #[test]
    fn reads_both_lines_and_positions_locations() {
        let doc = parse(SAMPLE);
        assert_eq!(doc.findings.len(), 2);
        assert_eq!(doc.findings[0].location.begin_line, Some(12));
        assert_eq!(doc.findings[0].fingerprint.as_deref(), Some("abc123"));

        let second = &doc.findings[1];
        assert_eq!(second.location.begin_line, Some(40));
        assert_eq!(second.location.begin_column, Some(3));
        assert_eq!(second.description, "Split this function");
        // Missing in the source, so it must have been synthesized.
        assert!(second.fingerprint.is_some());
    }

    #[test]
    fn gitlab_output_keeps_only_the_subset_gitlab_reads() {
        let (json, warnings) = render(&parse(SAMPLE), true);
        assert!(json.contains(r#""check_name": "no-var""#));
        assert!(json.contains(r#""fingerprint""#));
        assert!(!json.contains("categories"));
        assert!(!json.contains("positions"));
        assert!(warnings.messages().any(|w| w.contains("categories")));
    }

    #[test]
    fn full_output_keeps_categories_and_positions() {
        let (json, _) = render(&parse(SAMPLE), false);
        assert!(json.contains(r#""categories""#));
        assert!(json.contains(r#""positions""#));
    }

    #[test]
    fn round_trips_through_the_full_writer() {
        let doc = parse(SAMPLE);
        let (json, _) = render(&doc, false);
        let again = parse(&json);
        assert_eq!(again.findings.len(), doc.findings.len());
        assert_eq!(again.findings[0].fingerprint, doc.findings[0].fingerprint);
        assert_eq!(again.findings[1].location, doc.findings[1].location);
    }

    #[test]
    fn every_emitted_issue_carries_a_fingerprint_and_a_begin_line() {
        let mut doc = FindingsDoc::default();
        doc.findings
            .push(Finding::new("file-wide", Severity::Major));
        let (json, _) = render(&doc, true);
        assert!(json.contains(r#""begin": 1"#));
        assert!(json.contains(r#""fingerprint""#));
    }
}
