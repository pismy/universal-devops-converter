//! TRX — the Visual Studio test result format, and what `dotnet test` writes by
//! default. Nothing outside the Microsoft toolchain ingests it, so a .NET
//! project that wants its results anywhere else needs this conversion.
//!
//! ```xml
//! <TestRun id="…" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
//!   <Times start="2026-06-26T12:00:00.0000000+00:00" finish="…"/>
//!   <Results>
//!     <UnitTestResult testId="…" testName="Acme.Tests.CalcTests.Divides"
//!                     duration="00:00:00.3010000" outcome="Failed">
//!       <Output>
//!         <StdOut>…</StdOut>
//!         <ErrorInfo><Message>…</Message><StackTrace>…</StackTrace></ErrorInfo>
//!       </Output>
//!     </UnitTestResult>
//!   </Results>
//!   <TestDefinitions>
//!     <UnitTest id="…"><TestMethod className="Acme.Tests.CalcTests" name="Divides"/></UnitTest>
//!   </TestDefinitions>
//! </TestRun>
//! ```
//!
//! Three things shape the reader:
//!
//! - **Results and their class names live apart.** A `UnitTestResult` carries a
//!   `testId`; the class it belongs to is in `TestDefinitions`, keyed by the
//!   same id. Suites are that class name, so the two sections have to be joined
//!   — and `TestDefinitions` may appear *after* `Results` in the file, so the
//!   join happens at the end rather than as results are read.
//! - **Data-driven tests nest.** A `[DataRow]` test emits a parent result whose
//!   `InnerResults` hold one child per row. Emitting both would count every row
//!   twice, so a parent with inner results is dropped in favour of its children.
//! - **TRX has a dozen outcomes** against the pivot's four. The mapping is in
//!   [`outcome_of`], and the ones that mean "did not run" become skipped rather
//!   than being invented as passes.
//!
//! Read-only: a TRX file is a web of GUID cross-references between `Results`,
//! `TestDefinitions`, `TestEntries` and `TestLists`, all of which would have to
//! be fabricated, and its consumers — Visual Studio and Azure DevOps — both
//! read JUnit too.

use std::collections::HashMap;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::error::{Error, Result};
use crate::model::tests::{Outcome, Problem, TestCase, TestReport, TestSuite};
use crate::registry::Doc;
use crate::warn::FormatCtx;
use crate::xml::{get_attr, local_name, xml_error};

const FORMAT: &str = "trx";

/// A result before its class name has been resolved from `TestDefinitions`.
struct PendingCase {
    test_id: Option<String>,
    case: TestCase,
    /// True when the result had `<InnerResults>`, i.e. it summarizes its
    /// children rather than being a test of its own.
    has_inner: bool,
}

/// Where character data currently being read should go.
#[derive(PartialEq)]
enum Sink {
    Discard,
    Message,
    StackTrace,
    StdOut,
    StdErr,
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);

    let mut buffer = Vec::new();
    let mut saw_root = false;
    let mut started: Option<String> = None;

    let mut pending: Vec<PendingCase> = Vec::new();
    // testId → class name, from TestDefinitions.
    let mut classes: HashMap<String, String> = HashMap::new();
    // Results nest for data-driven tests, so this is a stack, not a slot.
    let mut open: Vec<PendingCase> = Vec::new();
    // Id of the <UnitTest> currently being read, awaiting its <TestMethod>.
    let mut current_definition: Option<String> = None;
    let mut sink = Sink::Discard;
    let mut text = String::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|e| xml_error(FORMAT, e))?;

        match event {
            Event::Eof => break,
            Event::Start(ref element) | Event::Empty(ref element) => {
                let empty = matches!(event, Event::Empty(_));
                match local_name(element).as_str() {
                    "TestRun" => saw_root = true,
                    "Times" => started = get_attr(element, "start"),
                    "UnitTestResult" | "TestResult" => {
                        let case = start_case(element);
                        if empty {
                            pending.push(case);
                        } else {
                            open.push(case);
                        }
                    }
                    "InnerResults" => {
                        // The enclosing result is a summary of its rows.
                        if let Some(parent) = open.last_mut() {
                            parent.has_inner = true;
                        }
                    }
                    // <UnitTest id> holds the id, its child <TestMethod
                    // className> the class, so the id has to be carried from
                    // one to the other.
                    "UnitTest" => current_definition = get_attr(element, "id"),
                    "TestMethod" => {
                        if let (Some(id), Some(class)) =
                            (current_definition.as_ref(), get_attr(element, "className"))
                        {
                            classes.insert(id.clone(), class);
                        }
                    }
                    "Message" => text.clear_and_set(&mut sink, Sink::Message, empty),
                    "StackTrace" => text.clear_and_set(&mut sink, Sink::StackTrace, empty),
                    "StdOut" => text.clear_and_set(&mut sink, Sink::StdOut, empty),
                    "StdErr" => text.clear_and_set(&mut sink, Sink::StdErr, empty),
                    _ => {}
                }
            }
            Event::Text(ref chunk) => {
                if sink != Sink::Discard {
                    text.push_str(&chunk.unescape().map_err(|e| xml_error(FORMAT, e))?);
                }
            }
            Event::CData(ref chunk) => {
                if sink != Sink::Discard {
                    text.push_str(&String::from_utf8_lossy(chunk.as_ref()));
                }
            }
            Event::End(ref element) => match local_name(element).as_str() {
                "UnitTestResult" | "TestResult" => {
                    if let Some(case) = open.pop() {
                        pending.push(case);
                    }
                }
                "UnitTest" => current_definition = None,
                "Message" | "StackTrace" | "StdOut" | "StdErr" => {
                    let captured = take(&mut text);
                    if let Some(case) = open.last_mut() {
                        apply_text(&mut case.case, &sink, captured);
                    }
                    sink = Sink::Discard;
                }
                _ => {}
            },
            _ => {}
        }
        buffer.clear();
    }

    if !saw_root {
        return Err(Error::parse(
            FORMAT,
            "no <TestRun> root element — this does not look like a TRX file",
        ));
    }

    let rows = pending.iter().filter(|c| c.has_inner).count();
    if rows > 0 {
        log::debug!("trx: {rows} data-driven parent result(s) replaced by their rows");
    }

    let mut report = TestReport::default();
    let mut suites: Vec<TestSuite> = Vec::new();

    for entry in pending {
        // A parent that only summarizes its rows would double-count them.
        if entry.has_inner {
            continue;
        }
        let class = entry
            .test_id
            .as_deref()
            .and_then(|id| classes.get(id))
            .cloned()
            .or_else(|| class_from_name(&entry.case.name))
            .unwrap_or_else(|| "(unknown)".to_string());

        let mut case = entry.case;
        case.classname = Some(class.clone());

        match suites.iter_mut().find(|s| s.name == class) {
            Some(suite) => suite.cases.push(case),
            None => {
                let mut suite = TestSuite::new(class);
                suite.timestamp = started.clone();
                suite.cases.push(case);
                suites.push(suite);
            }
        }
    }

    if suites.is_empty() {
        return Err(Error::parse(FORMAT, "no test result in <Results>"));
    }
    if suites.iter().any(|s| s.name == "(unknown)") {
        ctx.lossy(
            "trx: some results had no matching <UnitTest> definition, so their class could not \
             be resolved and they were grouped under '(unknown)'",
        );
    }

    report.suites = suites;
    Ok(Doc::Tests(report))
}

fn start_case(element: &BytesStart) -> PendingCase {
    let name = get_attr(element, "testName").unwrap_or_else(|| "(unnamed)".into());
    let outcome = outcome_of(get_attr(element, "outcome").as_deref());

    let mut case = TestCase::new(name, outcome);
    case.time = get_attr(element, "duration")
        .as_deref()
        .and_then(parse_duration);

    PendingCase {
        test_id: get_attr(element, "testId"),
        case,
        has_inner: false,
    }
}

/// TRX's outcome vocabulary is much wider than the pivot's four states.
/// Everything that means "did not run" becomes skipped rather than being
/// silently promoted to a pass, and everything that means "the harness broke"
/// becomes an error rather than a failure.
fn outcome_of(raw: Option<&str>) -> Outcome {
    let raw = raw.unwrap_or("");
    // Keep the outcome name as the problem's kind. TRX distinguishes a timeout
    // from an abort from a disconnected agent, and a bare `<error/>` in the
    // JUnit output would throw away the only thing that says which happened.
    let problem = || Problem {
        kind: (!raw.is_empty()).then(|| raw.to_string()),
        ..Default::default()
    };

    match raw {
        "Passed" | "PassedButRunAborted" | "Completed" => Outcome::Passed,
        "Failed" => Outcome::Failed(problem()),
        "Timeout" | "Aborted" | "Error" | "Disconnected" => Outcome::Errored(problem()),
        other => Outcome::Skipped {
            message: (!other.is_empty() && other != "NotExecuted").then(|| other.to_string()),
        },
    }
}

/// `Acme.Tests.CalcTests.Divides` → `Acme.Tests.CalcTests`. Only used when
/// `TestDefinitions` did not resolve the class.
fn class_from_name(name: &str) -> Option<String> {
    // Drop a parameter list first: `Adds(a: 1)` must not have its dot eaten.
    let bare = name.split('(').next().unwrap_or(name);
    bare.rsplit_once('.').map(|(class, _)| class.to_string())
}

/// TRX durations are .NET `TimeSpan`s: `[d.]hh:mm:ss[.fffffff]`.
fn parse_duration(raw: &str) -> Option<f64> {
    let raw = raw.trim();
    let (days, rest) = match raw.split_once('.') {
        // A leading `d.` only exists when what precedes the dot is a plain day
        // count; `00:00:00.5` splits at the fractional seconds instead.
        Some((head, tail)) if !head.contains(':') => (head.parse::<f64>().ok()?, tail),
        _ => (0.0, raw),
    };

    let mut parts = rest.split(':');
    let hours: f64 = parts.next()?.parse().ok()?;
    let minutes: f64 = parts.next()?.parse().ok()?;
    let seconds: f64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }

    Some(days * 86_400.0 + hours * 3_600.0 + minutes * 60.0 + seconds)
}

fn apply_text(case: &mut TestCase, sink: &Sink, captured: Option<String>) {
    let Some(captured) = captured else { return };
    match sink {
        Sink::Message => with_problem(case, |p| p.message = Some(captured)),
        Sink::StackTrace => with_problem(case, |p| p.detail = Some(captured)),
        Sink::StdOut => case.system_out = Some(captured),
        Sink::StdErr => case.system_err = Some(captured),
        Sink::Discard => {}
    }
}

/// `<ErrorInfo>` may appear on a result whose outcome is not a failure — a
/// warning, say. Attach the detail without changing what the outcome says.
fn with_problem(case: &mut TestCase, edit: impl FnOnce(&mut Problem)) {
    match &mut case.outcome {
        Outcome::Failed(problem) | Outcome::Errored(problem) => edit(problem),
        _ => {
            let mut problem = Problem::default();
            edit(&mut problem);
            if problem.message.is_some() || problem.detail.is_some() {
                case.system_err = problem.message.or(problem.detail);
            }
        }
    }
}

fn take(text: &mut String) -> Option<String> {
    let captured = std::mem::take(text);
    let trimmed = captured.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Small helper so the four text elements read the same way at their start tag.
trait ClearAndSet {
    fn clear_and_set(&mut self, sink: &mut Sink, next: Sink, empty: bool);
}

impl ClearAndSet for String {
    fn clear_and_set(&mut self, sink: &mut Sink, next: Sink, empty: bool) {
        self.clear();
        *sink = if empty { Sink::Discard } else { next };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<TestRun id="7e4a8b21-0000-0000-0000-000000000001" name="runner 2026-06-26 12:00:00"
         xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
  <Times creation="2026-06-26T12:00:00.0000000+00:00" start="2026-06-26T12:00:01.0000000+00:00"
         finish="2026-06-26T12:00:03.0000000+00:00"/>
  <Results>
    <UnitTestResult executionId="e1" testId="t1" testName="Acme.Tests.CalcTests.Adds"
                    computerName="build-01" duration="00:00:00.5120000" outcome="Passed"/>
    <UnitTestResult executionId="e2" testId="t2" testName="Acme.Tests.CalcTests.Divides"
                    computerName="build-01" duration="00:00:00.3010000" outcome="Failed">
      <Output>
        <StdOut>dividing now</StdOut>
        <ErrorInfo>
          <Message>Assert.AreEqual failed. Expected:&lt;2&gt;. Actual:&lt;3&gt;.</Message>
          <StackTrace>   at Acme.Tests.CalcTests.Divides() in /src/CalcTests.cs:line 42</StackTrace>
        </ErrorInfo>
      </Output>
    </UnitTestResult>
    <UnitTestResult executionId="e3" testId="t3" testName="Acme.Tests.CalcTests.Later"
                    duration="00:00:00.0000000" outcome="NotExecuted"/>
    <UnitTestResult executionId="e4" testId="t4" testName="Acme.Tests.SlowTests.Waits"
                    duration="00:01:30.0000000" outcome="Timeout"/>
    <UnitTestResult executionId="e5" testId="t5" testName="Acme.Tests.DataTests.Rows"
                    outcome="Failed">
      <InnerResults>
        <UnitTestResult executionId="e5a" testId="t5" testName="Rows (a: 1)"
                        duration="00:00:00.0100000" outcome="Passed"/>
        <UnitTestResult executionId="e5b" testId="t5" testName="Rows (a: 2)"
                        duration="00:00:00.0200000" outcome="Failed">
          <Output><ErrorInfo><Message>row two failed</Message></ErrorInfo></Output>
        </UnitTestResult>
      </InnerResults>
    </UnitTestResult>
  </Results>
  <TestDefinitions>
    <UnitTest name="Adds" storage="acme.tests.dll" id="t1">
      <TestMethod codeBase="acme.tests.dll" className="Acme.Tests.CalcTests" name="Adds"/>
    </UnitTest>
    <UnitTest name="Divides" storage="acme.tests.dll" id="t2">
      <TestMethod codeBase="acme.tests.dll" className="Acme.Tests.CalcTests" name="Divides"/>
    </UnitTest>
    <UnitTest name="Later" storage="acme.tests.dll" id="t3">
      <TestMethod codeBase="acme.tests.dll" className="Acme.Tests.CalcTests" name="Later"/>
    </UnitTest>
    <UnitTest name="Waits" storage="acme.tests.dll" id="t4">
      <TestMethod codeBase="acme.tests.dll" className="Acme.Tests.SlowTests" name="Waits"/>
    </UnitTest>
    <UnitTest name="Rows" storage="acme.tests.dll" id="t5">
      <TestMethod codeBase="acme.tests.dll" className="Acme.Tests.DataTests" name="Rows"/>
    </UnitTest>
  </TestDefinitions>
  <ResultSummary outcome="Failed">
    <Counters total="5" executed="4" passed="2" failed="2" timeout="1"/>
  </ResultSummary>
</TestRun>
"#;

    fn parse(input: &str) -> (TestReport, crate::warn::Warnings) {
        let mut ctx = FormatCtx::new(None);
        let report = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Tests(report) => report,
            _ => panic!("expected a test report"),
        };
        (report, ctx.into_warnings())
    }

    #[test]
    fn groups_cases_into_suites_by_their_class() {
        let (report, _) = parse(SAMPLE);
        let names: Vec<&str> = report.suites.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"Acme.Tests.CalcTests"), "{names:?}");
        assert!(names.contains(&"Acme.Tests.SlowTests"), "{names:?}");
        assert!(names.contains(&"Acme.Tests.DataTests"), "{names:?}");
    }

    #[test]
    fn a_data_driven_parent_is_replaced_by_its_rows() {
        let (report, _) = parse(SAMPLE);
        let data = report
            .suites
            .iter()
            .find(|s| s.name == "Acme.Tests.DataTests")
            .unwrap();

        // Two rows, and not the parent as well: counting all three would report
        // one more test than ran.
        assert_eq!(data.cases.len(), 2);
        assert_eq!(data.failures(), 1);
        assert!(data.cases.iter().all(|c| c.name.starts_with("Rows (")));
    }

    #[test]
    fn maps_the_wider_trx_outcome_vocabulary() {
        let (report, _) = parse(SAMPLE);
        let calc = report
            .suites
            .iter()
            .find(|s| s.name == "Acme.Tests.CalcTests")
            .unwrap();
        assert_eq!(calc.failures(), 1);
        assert_eq!(calc.skipped(), 1);

        // A timeout is the harness giving up, not an assertion failing — and
        // which way it gave up is worth keeping.
        let slow = report
            .suites
            .iter()
            .find(|s| s.name == "Acme.Tests.SlowTests")
            .unwrap();
        assert_eq!(slow.errors(), 1);
        match &slow.cases[0].outcome {
            Outcome::Errored(problem) => assert_eq!(problem.kind.as_deref(), Some("Timeout")),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn keeps_the_failure_message_stack_trace_and_output() {
        let (report, _) = parse(SAMPLE);
        let case = report
            .suites
            .iter()
            .flat_map(|s| &s.cases)
            .find(|c| c.name.ends_with("Divides"))
            .unwrap();

        assert_eq!(case.system_out.as_deref(), Some("dividing now"));
        match &case.outcome {
            Outcome::Failed(problem) => {
                assert!(problem.message.as_deref().unwrap().contains("Expected:<2>"));
                assert!(problem
                    .detail
                    .as_deref()
                    .unwrap()
                    .contains("CalcTests.cs:line 42"));
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn parses_dotnet_timespans() {
        assert_eq!(parse_duration("00:00:00.5120000"), Some(0.512));
        assert_eq!(parse_duration("00:01:30.0000000"), Some(90.0));
        assert_eq!(parse_duration("01:00:00"), Some(3600.0));
        assert_eq!(parse_duration("2.03:00:00"), Some(2.0 * 86400.0 + 10800.0));
        assert_eq!(parse_duration("nonsense"), None);
    }

    #[test]
    fn falls_back_to_the_test_name_when_the_definition_is_missing() {
        let (report, warnings) = parse(
            r#"<TestRun><Results>
                 <UnitTestResult testId="zz" testName="Acme.Orphan.Test1" outcome="Passed"/>
               </Results></TestRun>"#,
        );
        // The fully-qualified name still yields a class, so no warning.
        assert_eq!(report.suites[0].name, "Acme.Orphan");
        assert!(!warnings.messages().any(|m| m.contains("(unknown)")));
    }

    #[test]
    fn reports_results_whose_class_cannot_be_resolved_at_all() {
        let (report, warnings) = parse(
            r#"<TestRun><Results>
                 <UnitTestResult testId="zz" testName="Bare" outcome="Passed"/>
               </Results></TestRun>"#,
        );
        assert_eq!(report.suites[0].name, "(unknown)");
        assert!(warnings.messages().any(|m| m.contains("(unknown)")));
    }

    #[test]
    fn rejects_input_that_is_not_a_test_run() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"<testsuite name=\"x\"/>", &mut ctx).is_err());
    }

    #[test]
    fn rejects_a_run_with_no_result() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"<TestRun><Results/></TestRun>", &mut ctx).is_err());
    }
}
