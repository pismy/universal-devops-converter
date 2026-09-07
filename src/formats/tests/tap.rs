//! TAP — the Test Anything Protocol, versions 12 through 14.
//!
//! ```text
//! TAP version 13
//! 1..3
//! ok 1 - adds numbers
//! not ok 2 - divides numbers
//!   ---
//!   message: 'expected 2, got 3'
//!   at: calc_test.js:23
//!   ...
//! ok 3 - later # SKIP needs network
//! ```
//!
//! The protocol is deliberately minimal, which pushes the work onto the reader:
//!
//! - **A directive changes what a result means.** `ok … # SKIP` did not run;
//!   `not ok … # TODO` is a known-pending test and not a failure, which is the
//!   one place where reading the `ok`/`not ok` alone gives the wrong answer.
//! - **The YAML diagnostic block is the only failure detail there is.** It is
//!   not parsed as YAML — TAP does not require the block to be valid YAML, and
//!   producers oblige — but its `message:` key is lifted when present, and the
//!   whole block kept.
//! - **Subtests are indentation.** A `# Subtest: name` comment introduces an
//!   indented block, and the un-indented `ok` that follows *summarizes* it.
//!   Each subtest becomes a suite and the summary line is dropped, because
//!   counting it as well would report every subtest group twice.
//! - **`Bail out!` means the run stopped.** Left alone it produces a report of
//!   whatever happened to run first, all green. It becomes a failing case.
//!
//! Read-only: TAP consumers are test harnesses and a handful of CI plugins, all
//! of which read JUnit too.

use crate::error::{Error, Result};
use crate::model::tests::{Outcome, Problem, TestCase, TestReport, TestSuite};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "tap";

/// Name of the suite holding assertions that sit outside any subtest.
const ROOT_SUITE: &str = "(root)";

/// One `ok` / `not ok` line, before its diagnostics arrive.
struct Assertion {
    ok: bool,
    description: String,
    directive: Option<Directive>,
}

enum Directive {
    Skip(Option<String>),
    Todo(Option<String>),
}

/// A suite being filled, and the indentation its lines sit at.
struct Frame {
    indent: usize,
    name: String,
    cases: Vec<TestCase>,
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let text = String::from_utf8_lossy(input);

    let mut report = TestReport::default();
    let mut stack: Vec<Frame> = vec![Frame {
        indent: 0,
        name: ROOT_SUITE.to_string(),
        cases: Vec::new(),
    }];
    // A `# Subtest: name` seen but whose indented block has not started yet.
    let mut announced: Option<String> = None;
    let mut diagnostics: Option<String> = None;
    let mut in_yaml = false;
    let mut saw_tap = false;
    let mut bailed: Option<String> = None;

    for raw in text.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        // The YAML block belongs to the assertion just read — and arrives after
        // it, so it is attached once the block closes rather than at build time.
        if in_yaml {
            if line == "..." {
                in_yaml = false;
                if let Some(block) = diagnostics.take() {
                    if let Some(case) = stack.last_mut().and_then(|f| f.cases.last_mut()) {
                        attach_diagnostics(case, block);
                    }
                }
            } else {
                let buffer = diagnostics.get_or_insert_with(String::new);
                buffer.push_str(raw.trim_start());
                buffer.push('\n');
            }
            continue;
        }
        if line == "---" {
            in_yaml = true;
            diagnostics = None;
            continue;
        }

        if let Some(reason) = line.strip_prefix("Bail out!") {
            saw_tap = true;
            bailed = Some(reason.trim().to_string());
            break;
        }
        if line.starts_with("TAP version") {
            saw_tap = true;
            continue;
        }
        // A plan (`1..3`) tells us nothing the assertions do not.
        if is_plan(line) {
            saw_tap = true;
            continue;
        }
        if let Some(name) = line.strip_prefix("# Subtest:") {
            announced = Some(name.trim().to_string());
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        let Some(assertion) = parse_assertion(line) else {
            log::debug!("tap: ignoring '{line}'");
            continue;
        };
        saw_tap = true;

        // Entering an indented block: it is the subtest just announced.
        if indent > stack.last().expect("never empty").indent {
            let name = announced
                .take()
                .unwrap_or_else(|| format!("subtest at column {indent}"));
            stack.push(Frame {
                indent,
                name,
                cases: Vec::new(),
            });
        }

        // Leaving one or more blocks: close them, and drop the line that only
        // summarizes the block we just closed.
        let mut summarized = false;
        while indent < stack.last().expect("never empty").indent {
            let frame = stack.pop().expect("never the root");
            summarized |= frame.name == assertion.description;
            close(&mut report, frame);
        }
        if summarized {
            continue;
        }

        let case = build_case(assertion);
        stack.last_mut().expect("never empty").cases.push(case);
    }

    while let Some(frame) = stack.pop() {
        close(&mut report, frame);
    }

    if let Some(reason) = bailed {
        // A bailed run stopped early; reporting only what happened to run first
        // would show a green report for an aborted suite.
        let message = if reason.is_empty() {
            "the run bailed out".to_string()
        } else {
            reason
        };
        ctx.lossy(format!(
            "tap: the run bailed out ({message}); everything after that point never ran"
        ));
        let mut suite = TestSuite::new("(bail out)");
        suite.cases.push(TestCase::new(
            "(bail out)",
            Outcome::Errored(Problem {
                message: Some(message),
                kind: Some("bail out".into()),
                detail: None,
            }),
        ));
        report.suites.push(suite);
    }

    if !saw_tap || report.suites.is_empty() {
        return Err(Error::parse(
            FORMAT,
            "no plan, version line or `ok`/`not ok` assertion — this does not look like TAP",
        ));
    }
    Ok(Doc::Tests(report))
}

fn close(report: &mut TestReport, frame: Frame) {
    if frame.cases.is_empty() {
        return;
    }
    let mut suite = TestSuite::new(frame.name);
    suite.cases = frame.cases;
    report.suites.push(suite);
}

/// `1..3`, or `1..0 # SKIP everything`.
fn is_plan(line: &str) -> bool {
    let head = line.split('#').next().unwrap_or(line).trim();
    match head.split_once("..") {
        Some((start, end)) => {
            !start.is_empty()
                && !end.is_empty()
                && start.chars().all(|c| c.is_ascii_digit())
                && end.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// `not ok 2 - divides numbers # TODO not implemented`
fn parse_assertion(line: &str) -> Option<Assertion> {
    let (ok, rest) = match line.strip_prefix("not ok") {
        Some(rest) => (false, rest),
        None => (true, line.strip_prefix("ok")?),
    };
    // `ok` must be a word of its own: `okay` is not an assertion.
    if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
        return None;
    }

    let rest = rest.trim_start();
    // Drop the test number, which the pivot does not model.
    let rest = match rest.split_once(char::is_whitespace) {
        Some((head, tail)) if head.chars().all(|c| c.is_ascii_digit()) && !head.is_empty() => tail,
        _ => rest.trim_start_matches(|c: char| c.is_ascii_digit()),
    };

    let (description, directive) = split_directive(rest.trim());
    Some(Assertion {
        ok,
        description: description
            .trim()
            .trim_start_matches('-')
            .trim()
            .to_string(),
        directive,
    })
}

/// Separate `# SKIP reason` / `# TODO reason` from the description. An escaped
/// `\#` is part of the description, not a directive.
fn split_directive(text: &str) -> (&str, Option<Directive>) {
    let mut search = 0;
    while let Some(offset) = text[search..].find('#') {
        let at = search + offset;
        if at > 0 && text.as_bytes()[at - 1] == b'\\' {
            search = at + 1;
            continue;
        }
        let (description, marker) = text.split_at(at);
        let marker = marker.trim_start_matches('#').trim();
        let (word, reason) = match marker.split_once(char::is_whitespace) {
            Some((word, reason)) => (word, reason.trim()),
            None => (marker, ""),
        };
        let reason = (!reason.is_empty()).then(|| reason.to_string());

        let directive =
            if word.eq_ignore_ascii_case("skip") || word.to_ascii_lowercase().starts_with("skip") {
                Some(Directive::Skip(reason))
            } else if word.eq_ignore_ascii_case("todo") {
                Some(Directive::Todo(reason))
            } else {
                None
            };
        return (description, directive);
    }
    (text, None)
}

/// Fold a diagnostic block into the assertion it followed.
fn attach_diagnostics(case: &mut TestCase, block: String) {
    match &mut case.outcome {
        Outcome::Failed(problem) | Outcome::Errored(problem) => {
            // The block is the only failure detail TAP offers, and its
            // `message:` beats the description as an explanation.
            if let Some(message) = yaml_message(&block) {
                problem.message = Some(message);
            }
            problem.detail = Some(block);
        }
        // A skip may explain itself in the block; a pass may carry timings.
        _ => case.system_out = Some(block),
    }
}

fn build_case(assertion: Assertion) -> TestCase {
    let outcome = match (&assertion.directive, assertion.ok) {
        // Explicitly not run.
        (Some(Directive::Skip(reason)), _) => Outcome::Skipped {
            message: reason.clone(),
        },
        // A failing TODO is the expected state of an unfinished test, not a
        // regression — reporting it as a failure would make every work in
        // progress break the build.
        (Some(Directive::Todo(reason)), false) => Outcome::Skipped {
            message: Some(match reason {
                Some(reason) => format!("TODO: {reason}"),
                None => "TODO".to_string(),
            }),
        },
        // A TODO that passed is worth surfacing, but it did pass.
        (Some(Directive::Todo(_)), true) | (None, true) => Outcome::Passed,
        // The description stands in until the diagnostic block, if any,
        // supplies something better.
        (None, false) => Outcome::Failed(Problem {
            message: Some(assertion.description.clone()),
            kind: None,
            detail: None,
        }),
    };

    TestCase::new(assertion.description, outcome)
}

/// Lift `message:` out of the diagnostic block.
///
/// Not parsed as YAML on purpose: TAP does not require the block to be valid
/// YAML and producers take the liberty, so a parser would fail on reports a
/// human reads fine.
fn yaml_message(block: &str) -> Option<String> {
    block.lines().find_map(|line| {
        let value = line.trim().strip_prefix("message:")?.trim();
        let value = value
            .trim_start_matches(['\'', '"'])
            .trim_end_matches(['\'', '"']);
        (!value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
TAP version 13
1..4
ok 1 - adds numbers
not ok 2 - divides numbers
  ---
  message: 'expected 2, got 3'
  at: calc_test.js:23
  ...
ok 3 - later # SKIP needs network
not ok 4 - streams # TODO not implemented yet
";

    const WITH_SUBTEST: &str = "\
TAP version 13
# Subtest: calculator
    ok 1 - adds
    not ok 2 - divides
    1..2
not ok 1 - calculator
ok 2 - standalone
1..2
";

    fn parse(input: &str) -> (TestReport, crate::warn::Warnings) {
        let mut ctx = FormatCtx::new(None);
        let report = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Tests(report) => report,
            _ => panic!("expected a test report"),
        };
        (report, ctx.into_warnings())
    }

    #[test]
    fn reads_assertions_and_their_descriptions() {
        let (report, _) = parse(SAMPLE);
        assert_eq!(report.total(), 4);
        let names: Vec<&str> = report.suites[0]
            .cases
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["adds numbers", "divides numbers", "later", "streams"]
        );
    }

    #[test]
    fn a_skip_directive_means_it_did_not_run() {
        let (report, _) = parse(SAMPLE);
        let case = &report.suites[0].cases[2];
        assert_eq!(
            case.outcome,
            Outcome::Skipped {
                message: Some("needs network".into())
            }
        );
    }

    #[test]
    fn a_failing_todo_is_not_a_failure() {
        // Otherwise every unfinished test breaks the build, which is the
        // opposite of what the directive is for.
        let (report, _) = parse(SAMPLE);
        let case = &report.suites[0].cases[3];
        assert_eq!(
            case.outcome,
            Outcome::Skipped {
                message: Some("TODO: not implemented yet".into())
            }
        );
        assert_eq!(report.failures(), 1);
    }

    #[test]
    fn lifts_the_message_out_of_the_diagnostic_block() {
        let (report, _) = parse(SAMPLE);
        match &report.suites[0].cases[1].outcome {
            Outcome::Failed(problem) => {
                assert_eq!(problem.message.as_deref(), Some("expected 2, got 3"));
                assert!(problem
                    .detail
                    .as_deref()
                    .unwrap()
                    .contains("calc_test.js:23"));
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn a_subtest_becomes_a_suite_and_its_summary_line_is_dropped() {
        let (report, _) = parse(WITH_SUBTEST);
        let names: Vec<&str> = report.suites.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["calculator", ROOT_SUITE]);

        // Two children and one standalone — not four, which is what counting
        // the summary line as well would give.
        assert_eq!(report.total(), 3);
        assert_eq!(report.failures(), 1);
    }

    #[test]
    fn a_bail_out_is_reported_rather_than_leaving_a_green_run() {
        let (report, warnings) =
            parse("TAP version 13\nok 1 - first\nBail out! database is down\n");
        assert_eq!(report.total(), 2);
        assert_eq!(report.errors(), 1);
        assert!(warnings.messages().any(|m| m.contains("database is down")));
    }

    #[test]
    fn accepts_tap_12_without_a_version_line() {
        let (report, _) = parse("ok 1 - first\nnot ok 2 - second\n1..2\n");
        assert_eq!(report.total(), 2);
        assert_eq!(report.failures(), 1);
    }

    #[test]
    fn a_word_starting_with_ok_is_not_an_assertion() {
        assert!(parse_assertion("okay then").is_none());
        assert!(parse_assertion("ok").is_some());
        assert!(parse_assertion("ok 1 - fine").is_some());
    }

    #[test]
    fn an_escaped_hash_stays_in_the_description() {
        let (report, _) = parse(r"ok 1 - issue \#42 is fixed");
        assert_eq!(report.suites[0].cases[0].name, r"issue \#42 is fixed");
        assert_eq!(report.suites[0].cases[0].outcome, Outcome::Passed);
    }

    #[test]
    fn rejects_input_that_is_not_tap() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"just some prose\nwith no assertions\n", &mut ctx).is_err());
    }
}
