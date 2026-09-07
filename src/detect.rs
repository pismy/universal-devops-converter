//! Input format detection for `--input-format auto`.
//!
//! Two rules, from SPECS.md §4.3:
//!
//! 1. `auto` exists on the **input** side only — the output format is always
//!    stated explicitly.
//! 2. **Ambiguity is a failure, not a guess.** A bare JSON array is equally
//!    plausible as Code Climate or pa11y; picking one at random would silently
//!    produce a wrong report, which is worse than asking.

use crate::error::{Error, Result};
use crate::registry::{self, FormatSpec};

/// How much of the input is inspected. Enough to reach the discriminating keys
/// of every supported format, small enough to stay cheap.
pub const SNIFF_LIMIT: usize = 64 * 1024;

/// A format we recognize but do not implement yet. Naming it turns a dead-end
/// error into a useful one.
struct Planned {
    name: &'static str,
    category: &'static str,
}

pub fn detect(input: &[u8], origin: &str) -> Result<&'static FormatSpec> {
    let head = &input[..input.len().min(SNIFF_LIMIT)];
    let text = String::from_utf8_lossy(head);
    let trimmed = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);

    let outcome = if trimmed.starts_with('<') {
        sniff_xml(trimmed)
    } else if trimmed.starts_with('{') || trimmed.starts_with('[') {
        sniff_json(trimmed)
    } else {
        sniff_lines(trimmed)
    };

    match outcome {
        Some(Ok(id)) => registry::find(id),
        Some(Err(planned)) => Err(Error::Detect(format!(
            "{origin} looks like {} ({}), which is recognized but not supported yet",
            planned.name, planned.category
        ))),
        None => Err(Error::Detect(format!(
            "could not identify {origin}. Pass --input-format explicitly; \
             run `udc formats` to list the supported ones"
        ))),
    }
}

type Outcome = Option<std::result::Result<&'static str, Planned>>;

fn sniff_xml(text: &str) -> Outcome {
    let (root, attributes) = xml_root_tag(text)?;
    match root.as_str() {
        // Cobertura and Clover both root at <coverage>; only the attributes
        // tell them apart. Getting this wrong is silent: a Clover file read as
        // Cobertura yields an empty report and exit 0.
        "coverage" if attributes.contains("clover=") => Some(Ok("clover")),
        "coverage" => Some(Ok("cobertura")),
        "report" => Some(Ok("jacoco")),
        "testsuite" | "testsuites" => Some(Ok("junit")),
        "checkstyle" => Some(Ok("checkstyle")),
        "bom" => Some(Err(Planned {
            name: "CycloneDX XML",
            category: "sbom",
        })),
        "pmd" => Some(Err(Planned {
            name: "PMD XML",
            category: "quality",
        })),
        "BugCollection" => Some(Err(Planned {
            name: "SpotBugs XML",
            category: "quality",
        })),
        "coverage-report" | "CoverageSession" => Some(Err(Planned {
            name: "OpenCover XML",
            category: "coverage",
        })),
        "TestRun" => Some(Ok("trx")),
        _ => None,
    }
}

/// First real element, skipping the declaration, comments and the doctype,
/// returned as its local name plus the raw attribute text. Namespace prefixes
/// are stripped so `<ns:coverage>` still resolves.
///
/// The attributes are part of the answer because two formats can share a root
/// element name — see the `<coverage>` case in [`sniff_xml`].
fn xml_root_tag(text: &str) -> Option<(String, String)> {
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        let offset = text[index..].find('<')?;
        let start = index + offset + 1;
        let rest = text.get(start..)?;

        if let Some(after) = rest.strip_prefix('?') {
            index = start + after.find("?>").map_or(rest.len(), |i| i + 2);
        } else if rest.starts_with("!--") {
            index = start + rest.find("-->").map_or(rest.len(), |i| i + 3);
        } else if rest.starts_with('!') {
            // Doctype: an internal subset `[ … ]` may itself contain `>`.
            let end = match rest.find('[') {
                Some(open) if rest[..open].find('>').is_none() => rest[open..]
                    .find(']')
                    .and_then(|close| rest[open + close..].find('>').map(|i| open + close + i)),
                _ => rest.find('>'),
            };
            index = start + end.map_or(rest.len(), |i| i + 1);
        } else {
            let name: String = rest
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '>' && *c != '/')
                .collect();
            let local = name.rsplit(':').next().unwrap_or(&name);
            if local.is_empty() {
                return None;
            }
            let attributes: String = rest[name.len()..]
                .chars()
                .take_while(|c| *c != '>')
                .collect();
            return Some((local.to_string(), attributes));
        }
    }
    None
}

fn sniff_json(text: &str) -> Outcome {
    let has = |needle: &str| text.contains(needle);

    if text.starts_with('[') {
        // Refusing to guess does not mean refusing to look. ESLint's output is
        // an array like Code Climate's and pa11y's, but only its entries pair
        // `filePath` with `messages`, so the evidence is specific rather than
        // circumstantial.
        if has(r#""filePath""#) && has(r#""messages""#) {
            return Some(Ok("eslint"));
        }
        // Anything else array-shaped stays ambiguous: Code Climate and pa11y
        // are told apart only by fields either may legally omit.
        return None;
    }

    if has(r#""bomFormat""#) || has(r#""specVersion""#) && has(r#""components""#) {
        return Some(Err(Planned {
            name: "CycloneDX JSON",
            category: "sbom",
        }));
    }
    if has(r#""spdxVersion""#) || has(r#""SPDXID""#) {
        return Some(Err(Planned {
            name: "SPDX JSON",
            category: "sbom",
        }));
    }
    if has(r#""runs""#) && (has("sarif") || has(r#""tool""#)) {
        return Some(Ok("sarif"));
    }
    // `go test -json` is a *stream* of documents, so it never parses as one
    // JSON value; the pair of keys on its first line is what identifies it.
    if has(r#""Action""#) && has(r#""Package""#) {
        return Some(Ok("go-test-json"));
    }
    // An Istanbul coverage map is an object keyed by file path, which is no
    // fingerprint at all; `statementMap` is what every entry carries.
    if has(r#""statementMap""#) {
        return Some(Ok("istanbul"));
    }
    if has(r#""SchemaVersion""#) && has(r#""Results""#) {
        return Some(Err(Planned {
            name: "Trivy JSON",
            category: "security",
        }));
    }
    if has(r#""matches""#) && has(r#""vulnerability""#) {
        return Some(Err(Planned {
            name: "Grype JSON",
            category: "security",
        }));
    }
    None
}

/// `1..12` — a TAP plan, and nothing else looks like it.
fn is_tap_plan(line: &str) -> bool {
    match line
        .split('#')
        .next()
        .unwrap_or(line)
        .trim()
        .split_once("..")
    {
        Some((start, end)) => {
            !start.is_empty()
                && !end.is_empty()
                && start.chars().all(|c| c.is_ascii_digit())
                && end.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

fn sniff_lines(text: &str) -> Outcome {
    for line in text.lines().take(50) {
        let line = line.trim();
        if line.starts_with("SF:") || line.starts_with("TN:") || line == "end_of_record" {
            return Some(Ok("lcov"));
        }
        if line.starts_with("SPDXVersion:") {
            return Some(Err(Planned {
                name: "SPDX tag-value",
                category: "sbom",
            }));
        }
        if line.starts_with("mode: ") {
            return Some(Ok("go-coverprofile"));
        }
        // TAP: a version line, a plan, or an assertion — whichever comes first.
        if line.starts_with("TAP version")
            || line.starts_with("ok ")
            || line.starts_with("not ok ")
            || is_tap_plan(line)
        {
            return Some(Ok("tap"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_of(input: &str) -> String {
        detect(input.as_bytes(), "input").unwrap().id.to_string()
    }

    #[test]
    fn identifies_xml_formats_by_root_element() {
        assert_eq!(id_of("<coverage><packages/></coverage>"), "cobertura");
        assert_eq!(id_of("<report name=\"x\"/>"), "jacoco");
        assert_eq!(id_of("<testsuites/>"), "junit");
        assert_eq!(id_of("<testsuite name=\"a\"/>"), "junit");
        assert_eq!(id_of("<checkstyle version=\"8\"/>"), "checkstyle");
    }

    #[test]
    fn identifies_trx_by_its_test_run_root() {
        assert_eq!(
            id_of(
                r#"<TestRun id="x" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"/>"#
            ),
            "trx"
        );
    }

    #[test]
    fn skips_declaration_doctype_and_comments() {
        let input = "\u{feff}<?xml version=\"1.0\"?>\n\
                     <!-- generated <by> a tool -->\n\
                     <!DOCTYPE coverage SYSTEM \"http://x/coverage-04.dtd\">\n\
                     <coverage/>";
        assert_eq!(id_of(input), "cobertura");
    }

    #[test]
    fn handles_a_doctype_with_an_internal_subset() {
        let input = "<!DOCTYPE report [ <!ENTITY x \"y\"> ]>\n<report/>";
        assert_eq!(id_of(input), "jacoco");
    }

    #[test]
    fn tells_clover_from_cobertura_by_their_attributes() {
        // Both root at <coverage>; reading one as the other is silent, so the
        // discriminator has to be explicit.
        assert_eq!(
            id_of(r#"<coverage generated="1719410000" clover="3.2.0"><project/></coverage>"#),
            "clover"
        );
        assert_eq!(
            id_of(r#"<coverage line-rate="0.5" branch-rate="0"><packages/></coverage>"#),
            "cobertura"
        );
    }

    #[test]
    fn strips_namespace_prefixes() {
        assert_eq!(id_of("<ns:testsuites xmlns:ns=\"x\"/>"), "junit");
    }

    #[test]
    fn identifies_tap_by_its_version_plan_or_assertions() {
        assert_eq!(id_of("TAP version 13\n1..1\nok 1 - fine\n"), "tap");
        assert_eq!(id_of("1..2\nok 1\nnot ok 2\n"), "tap");
        assert_eq!(id_of("ok 1 - no header at all\n"), "tap");
    }

    #[test]
    fn identifies_lcov_by_its_record_prefixes() {
        assert_eq!(id_of("TN:\nSF:src/a.rs\nDA:1,1\nend_of_record\n"), "lcov");
    }

    #[test]
    fn identifies_a_go_coverage_profile_by_its_mode_header() {
        assert_eq!(
            id_of("mode: set\ngithub.com/acme/proj/main.go:12.13,15.2 2 1\n"),
            "go-coverprofile"
        );
    }

    #[test]
    fn identifies_sarif_by_its_runs_array() {
        assert_eq!(
            id_of(r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}}}]}"#),
            "sarif"
        );
    }

    #[test]
    fn identifies_a_go_test_event_stream() {
        assert_eq!(
            id_of(r#"{"Time":"2026-06-26T12:00:00Z","Action":"run","Package":"p","Test":"T"}"#),
            "go-test-json"
        );
    }

    #[test]
    fn identifies_an_istanbul_coverage_map_by_its_statement_map() {
        assert_eq!(
            id_of(r#"{"src/a.js":{"path":"src/a.js","statementMap":{},"s":{}}}"#),
            "istanbul"
        );
    }

    #[test]
    fn identifies_eslint_output_among_the_array_shaped_formats() {
        assert_eq!(
            id_of(r#"[{"filePath":"src/a.js","messages":[],"errorCount":0}]"#),
            "eslint"
        );
    }

    #[test]
    fn refuses_to_guess_between_array_shaped_formats() {
        let error = detect(br#"[{"check_name":"x"}]"#, "input").unwrap_err();
        assert!(matches!(error, Error::Detect(_)));
        assert!(error.to_string().contains("--input-format"));
    }

    #[test]
    fn names_recognized_but_unsupported_formats() {
        let error = detect(br#"{"bomFormat":"CycloneDX"}"#, "input").unwrap_err();
        assert!(error.to_string().contains("CycloneDX"));
        assert!(error.to_string().contains("not supported yet"));
    }

    #[test]
    fn gives_up_on_unrecognized_input() {
        assert!(detect(b"hello world", "input").is_err());
    }
}
