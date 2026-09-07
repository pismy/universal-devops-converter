//! ESLint's `json` formatter output.
//!
//! ```json
//! [
//!   {
//!     "filePath": "/abs/src/index.js",
//!     "messages": [
//!       { "ruleId": "no-unused-vars", "severity": 2, "message": "…",
//!         "line": 3, "column": 1, "endLine": 3, "endColumn": 10 }
//!     ],
//!     "suppressedMessages": [],
//!     "errorCount": 1, "warningCount": 0
//!   }
//! ]
//! ```
//!
//! ESLint already offers a `checkstyle` formatter, which this tool reads — but
//! that one flattens away `endLine`/`endColumn` and cannot express a fatal
//! parse error as anything but another error. Reading the native output keeps
//! both.
//!
//! Read-only. ESLint's JSON is consumed by ESLint's own formatters and by
//! editors talking to ESLint directly; nothing asks a third party to produce
//! it, and the pivot has no `fix`, `suggestions` or `nodeType` to put back.

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::model::findings::{Finding, FindingsDoc, Location, Severity, Tool};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "eslint";

#[derive(Debug, Deserialize)]
struct RawFile {
    #[serde(default, rename = "filePath")]
    file_path: Option<String>,
    #[serde(default)]
    messages: Vec<RawMessage>,
    /// Messages silenced by an inline directive. Reported as dropped rather
    /// than emitted: the author said they did not want them.
    #[serde(default, rename = "suppressedMessages")]
    suppressed_messages: Vec<RawMessage>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    #[serde(default, rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(default)]
    severity: Option<u8>,
    #[serde(default)]
    message: Option<String>,
    /// Set on a parse error, which is not a rule violation at all.
    #[serde(default)]
    fatal: Option<bool>,
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    column: Option<u32>,
    #[serde(default, rename = "endLine")]
    end_line: Option<u32>,
    #[serde(default, rename = "endColumn")]
    end_column: Option<u32>,
    #[serde(default)]
    fix: Option<serde_json::Value>,
    #[serde(default)]
    suggestions: Vec<serde_json::Value>,
}

/// ESLint has two levels plus a fatal flag, against the pivot's five.
///
/// A fatal message is a parse failure: the file was not linted at all, so it
/// outranks any rule violation found in a file that *was*. `critical` rather
/// than `blocker` leaves the top of the scale to whatever a project decides
/// must never merge.
fn severity_of(message: &RawMessage) -> Severity {
    if message.fatal == Some(true) {
        return Severity::Critical;
    }
    match message.severity {
        Some(2) => Severity::Major,
        Some(1) => Severity::Minor,
        // `0` means the rule is off, so it should not have been reported;
        // anything else is a version this reader predates.
        _ => Severity::Info,
    }
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let files: Vec<RawFile> = serde_json::from_slice(input).map_err(|e| Error::parse(FORMAT, e))?;

    // An array of objects is the shape of several unrelated formats; `filePath`
    // plus `messages` is what makes this one ESLint's.
    if !files.iter().any(|f| f.file_path.is_some()) {
        return Err(Error::parse(
            FORMAT,
            "no entry carries a `filePath` — this does not look like ESLint's json output",
        ));
    }

    let mut doc = FindingsDoc {
        tool: Some(Tool {
            name: "eslint".into(),
            version: None,
            url: Some("https://eslint.org".into()),
        }),
        ..Default::default()
    };

    let mut suppressed = 0usize;
    let mut fixes = false;

    for file in files {
        let path = file
            .file_path
            .map(|p| crate::paths::normalize(&p))
            .unwrap_or_default();
        suppressed += file.suppressed_messages.len();

        for message in file.messages {
            fixes |= message.fix.is_some() || !message.suggestions.is_empty();

            let mut finding = Finding::new(
                message
                    .message
                    .clone()
                    .unwrap_or_else(|| "(no message)".into()),
                severity_of(&message),
            );
            finding.rule_id = message.rule_id.clone().filter(|r| !r.is_empty());
            finding.location = Location {
                path: path.clone(),
                begin_line: message.line,
                end_line: message.end_line.or(message.line),
                begin_column: message.column,
                end_column: message.end_column,
                ..Default::default()
            };
            if message.fatal == Some(true) {
                // There is no rule to blame, so say what happened instead —
                // otherwise the finding arrives as `check_name: unknown`.
                finding
                    .rule_id
                    .get_or_insert_with(|| "fatal-parse-error".into());
            }
            finding.ensure_fingerprint();
            doc.findings.push(finding);
        }
    }

    if suppressed > 0 {
        ctx.lossy(format!(
            "eslint: {suppressed} message(s) suppressed by an inline directive were not carried \
             over"
        ));
    }
    if fixes {
        ctx.lossy("eslint: autofixes and suggestions have no equivalent in the findings model");
    }

    doc.sort();
    Ok(Doc::Findings(doc))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
      {
        "filePath": "/home/runner/work/acme/acme/src/index.js",
        "messages": [
          {
            "ruleId": "no-unused-vars",
            "severity": 2,
            "message": "'fs' is defined but never used.",
            "line": 3,
            "column": 1,
            "nodeType": "Identifier",
            "messageId": "unusedVar",
            "endLine": 3,
            "endColumn": 10
          },
          {
            "ruleId": "no-var",
            "severity": 1,
            "message": "Unexpected var, use let or const instead.",
            "line": 11,
            "column": 5,
            "endLine": 11,
            "endColumn": 8,
            "fix": { "range": [120, 123], "text": "let" }
          }
        ],
        "suppressedMessages": [
          { "ruleId": "no-console", "severity": 1, "message": "Unexpected console statement.",
            "line": 20, "column": 3 }
        ],
        "errorCount": 1,
        "warningCount": 1
      },
      {
        "filePath": "/home/runner/work/acme/acme/src/broken.js",
        "messages": [
          {
            "ruleId": null,
            "fatal": true,
            "severity": 2,
            "message": "Parsing error: Unexpected token }",
            "line": 7,
            "column": 1
          }
        ],
        "suppressedMessages": [],
        "errorCount": 1,
        "warningCount": 0
      },
      { "filePath": "/home/runner/work/acme/acme/src/clean.js", "messages": [],
        "suppressedMessages": [], "errorCount": 0, "warningCount": 0 }
    ]"#;

    fn parse(input: &str) -> (FindingsDoc, crate::warn::Warnings) {
        let mut ctx = FormatCtx::new(None);
        let doc = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Findings(doc) => doc,
            _ => panic!("expected a findings document"),
        };
        (doc, ctx.into_warnings())
    }

    #[test]
    fn maps_eslint_levels_onto_the_pivot() {
        let (doc, _) = parse(SAMPLE);
        assert_eq!(doc.findings.len(), 3);

        let by = |rule: &str| {
            doc.findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some(rule))
                .unwrap()
        };
        assert_eq!(by("no-unused-vars").severity, Severity::Major);
        assert_eq!(by("no-var").severity, Severity::Minor);
    }

    #[test]
    fn a_parse_error_outranks_a_rule_violation_and_gets_a_name() {
        let (doc, _) = parse(SAMPLE);
        let fatal = doc
            .findings
            .iter()
            .find(|f| f.description.starts_with("Parsing error"))
            .unwrap();

        // The file was not linted at all, which is worse than anything found
        // in a file that was.
        assert_eq!(fatal.severity, Severity::Critical);
        // `ruleId` is null on a parse error; without a stand-in the finding
        // would land as `check_name: unknown`.
        assert_eq!(fatal.rule_id.as_deref(), Some("fatal-parse-error"));
    }

    #[test]
    fn keeps_the_range_that_the_checkstyle_formatter_would_have_dropped() {
        let (doc, _) = parse(SAMPLE);
        let finding = doc
            .findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("no-unused-vars"))
            .unwrap();
        assert_eq!(
            finding.location.path,
            "/home/runner/work/acme/acme/src/index.js"
        );
        assert_eq!(finding.location.begin_line, Some(3));
        assert_eq!(finding.location.end_line, Some(3));
        assert_eq!(finding.location.begin_column, Some(1));
        assert_eq!(finding.location.end_column, Some(10));
    }

    #[test]
    fn suppressed_messages_are_dropped_and_reported() {
        let (doc, warnings) = parse(SAMPLE);
        assert!(!doc
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("no-console")));
        assert!(warnings.messages().any(|m| m.contains("suppressed")));
    }

    #[test]
    fn reports_autofixes_it_cannot_carry() {
        let (_, warnings) = parse(SAMPLE);
        assert!(warnings.messages().any(|m| m.contains("autofixes")));
    }

    #[test]
    fn a_file_with_no_message_contributes_nothing() {
        let (doc, _) = parse(SAMPLE);
        assert!(!doc
            .findings
            .iter()
            .any(|f| f.location.path.ends_with("clean.js")));
    }

    #[test]
    fn rejects_an_array_that_is_not_eslint_output() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(br#"[{"check_name":"x","description":"y"}]"#, &mut ctx).is_err());
        assert!(read(b"[]", &mut ctx).is_err());
    }
}
