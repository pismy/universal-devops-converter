//! `go test -json` — the NDJSON event stream Go's test runner emits.
//!
//! ```text
//! {"Action":"run","Package":"github.com/acme/proj/calc","Test":"TestAdds"}
//! {"Action":"output","Package":"…","Test":"TestAdds","Output":"=== RUN   TestAdds\n"}
//! {"Action":"pass","Package":"…","Test":"TestAdds","Elapsed":0.001}
//! {"Action":"fail","Package":"…","Elapsed":0.012}
//! ```
//!
//! One JSON document per line, not one document — so this is parsed line by
//! line and has no schema to validate against.
//!
//! Turning a stream of events into a report means reassembling state:
//!
//! - **A test is a package plus a name**, and its result arrives in a later
//!   event than its start. Suites are packages, in the order they first appear.
//! - **Go gives no structured failure message**, only the text the test wrote.
//!   The first line that is not `=== RUN` / `--- FAIL` scaffolding becomes the
//!   message — that is the assertion line, `calc_test.go:23: expected 2, got 3`
//!   — and the whole output is kept as the detail.
//! - **A package can fail without any test failing**: a build error, or a panic
//!   in `TestMain`. That would otherwise produce a report with no failures at
//!   all, which is the worst possible answer, so it becomes a synthetic case
//!   carrying the package's output.
//!
//! Subtests are emitted alongside their parent, as `go-junit-report` does. A
//! parent that only runs subtests reports the same failure twice, but a parent
//! may also assert outside of them, and dropping it would lose that.
//!
//! Read-only: the stream is a runner's log, and nothing replays one.

use std::collections::HashMap;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::model::tests::{Outcome, Problem, TestCase, TestReport, TestSuite};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "go-test-json";

/// Name given to the case that carries a package-level failure.
const PACKAGE_CASE: &str = "(package)";

#[derive(Debug, Deserialize)]
struct RawEvent {
    #[serde(default, rename = "Time")]
    time: Option<String>,
    #[serde(default, rename = "Action")]
    action: Option<String>,
    #[serde(default, rename = "Package")]
    package: Option<String>,
    #[serde(default, rename = "Test")]
    test: Option<String>,
    #[serde(default, rename = "Elapsed")]
    elapsed: Option<f64>,
    #[serde(default, rename = "Output")]
    output: Option<String>,
}

#[derive(Default)]
struct Accumulated {
    outcome: Option<String>,
    elapsed: Option<f64>,
    output: String,
}

#[derive(Default)]
struct Package {
    timestamp: Option<String>,
    /// Test name → accumulated state, plus the order they first appeared in.
    order: Vec<String>,
    tests: HashMap<String, Accumulated>,
    own: Accumulated,
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let text = String::from_utf8_lossy(input);

    let mut order: Vec<String> = Vec::new();
    let mut packages: HashMap<String, Package> = HashMap::new();
    let mut parsed = 0usize;
    let mut skipped_lines = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<RawEvent>(line) else {
            // `go build` failures reach the stream as plain text before the
            // JSON starts; they are not events and not an error either.
            skipped_lines += 1;
            log::debug!("go-test-json: ignoring non-JSON line '{line}'");
            continue;
        };
        parsed += 1;

        let Some(package_name) = event.package.clone() else {
            continue;
        };
        let package = packages.entry(package_name.clone()).or_insert_with(|| {
            order.push(package_name);
            Package::default()
        });
        if package.timestamp.is_none() {
            package.timestamp = event.time.clone();
        }

        let slot = match event.test.as_deref() {
            Some(name) => {
                if !package.tests.contains_key(name) {
                    package.order.push(name.to_string());
                    package
                        .tests
                        .insert(name.to_string(), Accumulated::default());
                }
                package.tests.get_mut(name).expect("just inserted")
            }
            None => &mut package.own,
        };

        match event.action.as_deref().unwrap_or("") {
            "output" => slot.output.push_str(event.output.as_deref().unwrap_or("")),
            action @ ("pass" | "fail" | "skip") => {
                slot.outcome = Some(action.to_string());
                slot.elapsed = event.elapsed.or(slot.elapsed);
            }
            _ => {}
        }
    }

    if parsed == 0 {
        return Err(Error::parse(
            FORMAT,
            "no JSON event on any line — this does not look like `go test -json` output",
        ));
    }
    if skipped_lines > 0 {
        ctx.lossy(format!(
            "go-test-json: {skipped_lines} line(s) were not JSON events and were ignored; a build \
             failure printed before the stream starts looks like this"
        ));
    }

    let mut report = TestReport::default();
    for name in order {
        let package = packages.remove(&name).expect("known package");
        if let Some(suite) = build_suite(name, package) {
            report.suites.push(suite);
        }
    }

    if report.suites.is_empty() {
        return Err(Error::parse(FORMAT, "no package reported any result"));
    }
    Ok(Doc::Tests(report))
}

fn build_suite(name: String, package: Package) -> Option<TestSuite> {
    let mut suite = TestSuite::new(name);
    suite.timestamp = package.timestamp;
    suite.time = package.own.elapsed;

    let mut any_failure = false;
    for test in &package.order {
        let state = package.tests.get(test).expect("known test");
        let outcome = outcome_of(state);
        any_failure |= matches!(outcome, Outcome::Failed(_));

        let mut case = TestCase::new(test.clone(), outcome);
        case.classname = Some(suite.name.clone());
        case.time = state.elapsed;
        case.system_out = surplus_output(&state.output, &case.outcome);
        suite.cases.push(case);
    }

    // A package that failed with no failing test failed to build, or panicked
    // outside a test. Reporting zero failures there would be the most damaging
    // answer available.
    if package.own.outcome.as_deref() == Some("fail") && !any_failure {
        let mut case = TestCase::new(
            PACKAGE_CASE,
            Outcome::Failed(Problem {
                message: Some(
                    first_meaningful_line(&package.own.output)
                        .unwrap_or_else(|| "the package failed with no failing test".into()),
                ),
                kind: Some("package".into()),
                detail: clean(&package.own.output),
            }),
        );
        case.classname = Some(suite.name.clone());
        suite.cases.push(case);
    }

    (!suite.cases.is_empty()).then_some(suite)
}

/// The captured output, unless the outcome already carries it.
///
/// Go has no failure message of its own, so the output *is* the failure
/// detail. Emitting it a second time as `system-out` would print every failing
/// test's log twice in the converted report.
fn surplus_output(output: &str, outcome: &Outcome) -> Option<String> {
    let trimmed = output.trim_end();
    if trimmed.trim().is_empty() {
        return None;
    }
    let already = match outcome {
        Outcome::Failed(problem) | Outcome::Errored(problem) => problem.detail.as_deref(),
        Outcome::Skipped { message } => message.as_deref(),
        Outcome::Passed => None,
    };
    (already != Some(trimmed) && already != Some(trimmed.trim())).then(|| trimmed.to_string())
}

fn outcome_of(state: &Accumulated) -> Outcome {
    match state.outcome.as_deref() {
        Some("pass") => Outcome::Passed,
        Some("skip") => Outcome::Skipped {
            message: first_meaningful_line(&state.output),
        },
        Some("fail") => Outcome::Failed(Problem {
            message: first_meaningful_line(&state.output),
            kind: None,
            detail: clean(&state.output),
        }),
        // No terminating event: the run was interrupted, and the test neither
        // passed nor failed.
        _ => Outcome::Skipped {
            message: Some("no result reported (the run did not finish)".into()),
        },
    }
}

/// The first line that says something, skipping `go test`'s own scaffolding.
/// For a failure that is the assertion line; for a skip, the reason.
fn first_meaningful_line(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !line.starts_with("=== ")
                && !line.starts_with("--- ")
                && *line != "FAIL"
                && *line != "PASS"
        })
        .map(str::to_string)
}

fn clean(output: &str) -> Option<String> {
    let trimmed = output.trim_end();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: &str = r##"{"Time":"2026-06-26T12:00:00.1Z","Action":"start","Package":"github.com/acme/proj/calc"}
{"Time":"2026-06-26T12:00:00.2Z","Action":"run","Package":"github.com/acme/proj/calc","Test":"TestAdds"}
{"Time":"2026-06-26T12:00:00.2Z","Action":"output","Package":"github.com/acme/proj/calc","Test":"TestAdds","Output":"=== RUN   TestAdds\n"}
{"Time":"2026-06-26T12:00:00.3Z","Action":"output","Package":"github.com/acme/proj/calc","Test":"TestAdds","Output":"--- PASS: TestAdds (0.00s)\n"}
{"Time":"2026-06-26T12:00:00.3Z","Action":"pass","Package":"github.com/acme/proj/calc","Test":"TestAdds","Elapsed":0.004}
{"Time":"2026-06-26T12:00:00.4Z","Action":"run","Package":"github.com/acme/proj/calc","Test":"TestDivides"}
{"Time":"2026-06-26T12:00:00.4Z","Action":"output","Package":"github.com/acme/proj/calc","Test":"TestDivides","Output":"=== RUN   TestDivides\n"}
{"Time":"2026-06-26T12:00:00.5Z","Action":"output","Package":"github.com/acme/proj/calc","Test":"TestDivides","Output":"    calc_test.go:23: expected 2, got 3\n"}
{"Time":"2026-06-26T12:00:00.5Z","Action":"output","Package":"github.com/acme/proj/calc","Test":"TestDivides","Output":"--- FAIL: TestDivides (0.00s)\n"}
{"Time":"2026-06-26T12:00:00.5Z","Action":"fail","Package":"github.com/acme/proj/calc","Test":"TestDivides","Elapsed":0.002}
{"Time":"2026-06-26T12:00:00.6Z","Action":"run","Package":"github.com/acme/proj/calc","Test":"TestLater"}
{"Time":"2026-06-26T12:00:00.6Z","Action":"output","Package":"github.com/acme/proj/calc","Test":"TestLater","Output":"    calc_test.go:31: needs network\n"}
{"Time":"2026-06-26T12:00:00.6Z","Action":"skip","Package":"github.com/acme/proj/calc","Test":"TestLater","Elapsed":0}
{"Time":"2026-06-26T12:00:00.7Z","Action":"fail","Package":"github.com/acme/proj/calc","Elapsed":0.021}
{"Time":"2026-06-26T12:00:01.0Z","Action":"output","Package":"github.com/acme/proj/broken","Output":"# github.com/acme/proj/broken\n"}
{"Time":"2026-06-26T12:00:01.0Z","Action":"output","Package":"github.com/acme/proj/broken","Output":"./main.go:7:2: undefined: missing\n"}
{"Time":"2026-06-26T12:00:01.0Z","Action":"fail","Package":"github.com/acme/proj/broken","Elapsed":0}
"##;

    fn parse(input: &str) -> (TestReport, crate::warn::Warnings) {
        let mut ctx = FormatCtx::new(None);
        let report = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Tests(report) => report,
            _ => panic!("expected a test report"),
        };
        (report, ctx.into_warnings())
    }

    #[test]
    fn packages_become_suites_in_the_order_they_appear() {
        let (report, _) = parse(STREAM);
        let names: Vec<&str> = report.suites.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["github.com/acme/proj/calc", "github.com/acme/proj/broken"]
        );
    }

    #[test]
    fn a_failure_message_is_the_assertion_line_not_the_scaffolding() {
        let (report, _) = parse(STREAM);
        let case = report.suites[0]
            .cases
            .iter()
            .find(|c| c.name == "TestDivides")
            .unwrap();

        match &case.outcome {
            Outcome::Failed(problem) => {
                assert_eq!(
                    problem.message.as_deref(),
                    Some("calc_test.go:23: expected 2, got 3")
                );
                // The whole output is still there for anyone who wants it.
                assert!(problem.detail.as_deref().unwrap().contains("=== RUN"));
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn a_failure_does_not_repeat_its_output_as_system_out() {
        let (report, _) = parse(STREAM);
        let case = report.suites[0]
            .cases
            .iter()
            .find(|c| c.name == "TestDivides")
            .unwrap();
        // The output is the failure detail; printing it twice would duplicate
        // every failing test's log in the converted report.
        assert!(case.system_out.is_none(), "{:?}", case.system_out);
    }

    #[test]
    fn a_passing_test_keeps_its_output() {
        let (report, _) = parse(STREAM);
        let case = report.suites[0]
            .cases
            .iter()
            .find(|c| c.name == "TestAdds")
            .unwrap();
        assert!(case.system_out.as_deref().unwrap().contains("=== RUN"));
    }

    #[test]
    fn a_skip_carries_its_reason() {
        let (report, _) = parse(STREAM);
        let case = report.suites[0]
            .cases
            .iter()
            .find(|c| c.name == "TestLater")
            .unwrap();
        assert_eq!(
            case.outcome,
            Outcome::Skipped {
                message: Some("calc_test.go:31: needs network".into())
            }
        );
    }

    #[test]
    fn a_package_that_fails_to_build_is_not_reported_as_zero_failures() {
        let (report, _) = parse(STREAM);
        let broken = report
            .suites
            .iter()
            .find(|s| s.name.ends_with("/broken"))
            .unwrap();

        assert_eq!(broken.cases.len(), 1);
        assert_eq!(broken.failures(), 1);
        assert_eq!(broken.cases[0].name, PACKAGE_CASE);
        match &broken.cases[0].outcome {
            Outcome::Failed(problem) => {
                assert_eq!(
                    problem.message.as_deref(),
                    Some("# github.com/acme/proj/broken")
                );
                assert!(problem
                    .detail
                    .as_deref()
                    .unwrap()
                    .contains("undefined: missing"));
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn a_package_failing_because_a_test_failed_gets_no_synthetic_case() {
        let (report, _) = parse(STREAM);
        let calc = &report.suites[0];
        assert!(!calc.cases.iter().any(|c| c.name == PACKAGE_CASE));
        assert_eq!(calc.cases.len(), 3);
    }

    #[test]
    fn subtests_are_kept_alongside_their_parent() {
        let (report, _) = parse(
            r#"{"Action":"run","Package":"p","Test":"TestTable"}
{"Action":"run","Package":"p","Test":"TestTable/case_one"}
{"Action":"fail","Package":"p","Test":"TestTable/case_one","Elapsed":0.001}
{"Action":"fail","Package":"p","Test":"TestTable","Elapsed":0.002}
"#,
        );
        let names: Vec<&str> = report.suites[0]
            .cases
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, ["TestTable", "TestTable/case_one"]);
    }

    #[test]
    fn a_test_with_no_terminating_event_is_not_a_pass() {
        let (report, _) = parse(r#"{"Action":"run","Package":"p","Test":"TestHangs"}"#);
        assert_eq!(report.suites[0].skipped(), 1);
        assert_eq!(
            report.suites[0].cases[0].outcome,
            Outcome::Skipped {
                message: Some("no result reported (the run did not finish)".into())
            }
        );
    }

    #[test]
    fn plain_text_before_the_stream_is_reported_not_swallowed() {
        let (_, warnings) = parse(
            "go: downloading example.com/dep v1.2.3\n{\"Action\":\"pass\",\"Package\":\"p\",\"Test\":\"T\"}\n",
        );
        assert!(warnings.messages().any(|m| m.contains("not JSON events")));
    }

    #[test]
    fn rejects_input_that_carries_no_event() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"just some text\nand more\n", &mut ctx).is_err());
    }
}
