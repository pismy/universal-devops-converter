//! Checkstyle XML — far and away the most widely *produced* linter format:
//! ESLint, PHP_CodeSniffer, golangci-lint, ktlint, stylelint, RuboCop and many
//! others all offer a `checkstyle` reporter, which makes it the cheapest bridge
//! into GitLab Code Quality.
//!
//! ```xml
//! <checkstyle version="8.0">
//!   <file name="src/app.js">
//!     <error line="12" column="5" severity="warning"
//!            message="Unexpected var" source="no-var"/>
//!   </file>
//! </checkstyle>
//! ```

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::{Error, Result};
use crate::model::findings::{Finding, FindingsDoc, Location, Severity, Tool};
use crate::registry::Doc;
use crate::warn::FormatCtx;
use crate::xml::{get_attr, get_parsed, local_name, xml_error};

const FORMAT: &str = "checkstyle";

pub fn read(input: &[u8], _ctx: &mut FormatCtx) -> Result<Doc> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(true);

    let mut doc = FindingsDoc::default();
    let mut buffer = Vec::new();
    let mut current_file = String::new();
    let mut saw_root = false;

    loop {
        match reader
            .read_event_into(&mut buffer)
            .map_err(|e| xml_error(FORMAT, e))?
        {
            Event::Eof => break,
            Event::Start(ref element) | Event::Empty(ref element) => {
                match local_name(element).as_str() {
                    "checkstyle" => {
                        saw_root = true;
                        doc.tool = Some(Tool {
                            name: "checkstyle".into(),
                            version: get_attr(element, "version"),
                            url: None,
                        });
                    }
                    "file" => {
                        current_file = get_attr(element, "name")
                            .map(|n| crate::paths::normalize(&n))
                            .unwrap_or_default();
                    }
                    // Checkstyle's own reporter emits <error>; a few producers
                    // (and Checkstyle itself for parse failures) emit <exception>.
                    "error" | "warning" | "info" | "exception" => {
                        doc.findings.push(finding(element, &current_file));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        buffer.clear();
    }

    if !saw_root {
        return Err(Error::parse(
            FORMAT,
            "no <checkstyle> root element — this does not look like a Checkstyle report",
        ));
    }

    for finding in &mut doc.findings {
        finding.ensure_fingerprint();
    }
    doc.sort();
    Ok(Doc::Findings(doc))
}

fn finding(element: &quick_xml::events::BytesStart, path: &str) -> Finding {
    let description = get_attr(element, "message").unwrap_or_else(|| "(no message)".into());
    // `severity` is optional in the wild; fall back to the element name, which
    // is how the `<warning>` / `<info>` variants encode it.
    let severity = get_attr(element, "severity")
        .as_deref()
        .and_then(Severity::parse)
        .or_else(|| Severity::parse(&local_name(element)))
        .unwrap_or(Severity::Minor);

    let begin_line = get_parsed::<u32>(element, "line");
    let mut finding = Finding::new(description, severity);
    finding.rule_id = get_attr(element, "source").filter(|s| !s.is_empty());
    finding.location = Location {
        path: path.to_string(),
        begin_line,
        end_line: begin_line,
        begin_column: get_parsed(element, "column"),
        ..Default::default()
    };
    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<checkstyle version="8.36">
  <file name="./src/app.js">
    <error line="12" column="5" severity="warning" message="Unexpected var" source="no-var"/>
    <error line="30" severity="error" message="Missing semicolon" source="semi"/>
  </file>
  <file name="src/clean.js"/>
</checkstyle>
"#;

    fn parse(input: &str) -> FindingsDoc {
        let mut ctx = FormatCtx::new(None);
        match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Findings(doc) => doc,
            _ => panic!("expected a findings document"),
        }
    }

    #[test]
    fn reads_findings_with_normalized_paths_and_severities() {
        let doc = parse(SAMPLE);
        assert_eq!(doc.findings.len(), 2);
        assert_eq!(doc.tool.as_ref().unwrap().version.as_deref(), Some("8.36"));

        let first = &doc.findings[0];
        assert_eq!(first.location.path, "src/app.js");
        assert_eq!(first.location.begin_line, Some(12));
        assert_eq!(first.location.begin_column, Some(5));
        assert_eq!(first.severity, Severity::Minor);
        assert_eq!(first.rule_id.as_deref(), Some("no-var"));

        assert_eq!(doc.findings[1].severity, Severity::Major);
    }

    #[test]
    fn synthesizes_a_fingerprint_for_every_finding() {
        let doc = parse(SAMPLE);
        assert!(doc.findings.iter().all(|f| f.fingerprint.is_some()));
        assert_ne!(doc.findings[0].fingerprint, doc.findings[1].fingerprint);
    }

    #[test]
    fn rejects_input_without_a_checkstyle_root() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"<pmd/>", &mut ctx).is_err());
    }
}
