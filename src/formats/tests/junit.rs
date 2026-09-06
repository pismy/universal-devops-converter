//! JUnit XML.
//!
//! "JUnit XML" is not a specification but a family of dialects: Ant, Maven
//! Surefire, pytest, Jest, GoogleTest and a dozen others each emit their own
//! variation. The writer therefore targets the conservative common shape, while
//! the reader is deliberately permissive:
//!
//! - the root may be `<testsuites>` or a bare `<testsuite>`;
//! - suites may nest, and are flattened with a dotted name;
//! - counts declared on the elements are ignored and recomputed from the cases,
//!   because producers disagree on whether `tests` includes skipped ones.

use std::io::Write;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::{Error, Result};
use crate::model::tests::{Outcome, Problem, TestCase, TestReport, TestSuite};
use crate::registry::Doc;
use crate::warn::FormatCtx;
use crate::xml::{attr, get_attr, get_parsed, local_name, xml_error, Attrs, XmlWriter};

const FORMAT: &str = "junit";

/// Where character data currently being read should end up.
#[derive(Debug, PartialEq)]
enum Sink {
    Discard,
    Failure(Problem),
    Error(Problem),
    CaseOut,
    CaseErr,
    SuiteOut,
    SuiteErr,
}

pub fn read(input: &[u8], _ctx: &mut FormatCtx) -> Result<Doc> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);

    let mut report = TestReport::default();
    let mut buffer = Vec::new();
    // Stack, because suites may nest; entries are flattened on the way out.
    let mut suites: Vec<TestSuite> = Vec::new();
    let mut case: Option<TestCase> = None;
    let mut sink = Sink::Discard;
    let mut text = String::new();
    let mut saw_root = false;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|e| xml_error(FORMAT, e))?;

        match event {
            Event::Eof => break,
            Event::Start(ref element) | Event::Empty(ref element) => {
                let empty = matches!(event, Event::Empty(_));
                match local_name(element).as_str() {
                    "testsuites" => {
                        saw_root = true;
                        report.name = get_attr(element, "name").filter(|n| !n.is_empty());
                    }
                    "testsuite" => {
                        saw_root = true;
                        let mut suite = TestSuite::new(
                            get_attr(element, "name").unwrap_or_else(|| "(unnamed)".into()),
                        );
                        suite.timestamp = get_attr(element, "timestamp");
                        suite.hostname = get_attr(element, "hostname");
                        suite.file = get_attr(element, "file");
                        suite.time = get_parsed(element, "time");
                        suites.push(suite);
                        if empty {
                            flatten(&mut report, &mut suites);
                        }
                    }
                    "property" => {
                        if let (Some(suite), Some(name)) =
                            (suites.last_mut(), get_attr(element, "name"))
                        {
                            suite
                                .properties
                                .push((name, get_attr(element, "value").unwrap_or_default()));
                        }
                    }
                    "testcase" => {
                        let mut new_case = TestCase::new(
                            get_attr(element, "name").unwrap_or_else(|| "(unnamed)".into()),
                            Outcome::Passed,
                        );
                        new_case.classname = get_attr(element, "classname");
                        new_case.file = get_attr(element, "file");
                        new_case.line = get_parsed(element, "line");
                        new_case.time = get_parsed(element, "time");
                        if empty {
                            push_case(&mut suites, new_case);
                        } else {
                            case = Some(new_case);
                        }
                    }
                    "failure" | "error" => {
                        let problem = Problem {
                            message: get_attr(element, "message"),
                            kind: get_attr(element, "type"),
                            detail: None,
                        };
                        let failed = local_name(element) == "failure";
                        if empty {
                            if let Some(case) = case.as_mut() {
                                case.outcome = if failed {
                                    Outcome::Failed(problem)
                                } else {
                                    Outcome::Errored(problem)
                                };
                            }
                        } else {
                            text.clear();
                            sink = if failed {
                                Sink::Failure(problem)
                            } else {
                                Sink::Error(problem)
                            };
                        }
                    }
                    "skipped" => {
                        if let Some(case) = case.as_mut() {
                            case.outcome = Outcome::Skipped {
                                message: get_attr(element, "message"),
                            };
                        }
                    }
                    "system-out" | "system-err" => {
                        text.clear();
                        let is_out = local_name(element) == "system-out";
                        sink = match (case.is_some(), is_out) {
                            (true, true) => Sink::CaseOut,
                            (true, false) => Sink::CaseErr,
                            (false, true) => Sink::SuiteOut,
                            (false, false) => Sink::SuiteErr,
                        };
                        if empty {
                            sink = Sink::Discard;
                        }
                    }
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
                "failure" | "error" => {
                    let detail = take_text(&mut text);
                    let outcome = match std::mem::replace(&mut sink, Sink::Discard) {
                        Sink::Failure(problem) => {
                            Some(Outcome::Failed(Problem { detail, ..problem }))
                        }
                        Sink::Error(problem) => {
                            Some(Outcome::Errored(Problem { detail, ..problem }))
                        }
                        _ => None,
                    };
                    if let (Some(case), Some(outcome)) = (case.as_mut(), outcome) {
                        case.outcome = outcome;
                    }
                }
                "system-out" | "system-err" => {
                    let captured = take_text(&mut text);
                    match std::mem::replace(&mut sink, Sink::Discard) {
                        Sink::CaseOut => {
                            if let Some(case) = case.as_mut() {
                                case.system_out = captured;
                            }
                        }
                        Sink::CaseErr => {
                            if let Some(case) = case.as_mut() {
                                case.system_err = captured;
                            }
                        }
                        Sink::SuiteOut => {
                            if let Some(suite) = suites.last_mut() {
                                suite.system_out = captured;
                            }
                        }
                        Sink::SuiteErr => {
                            if let Some(suite) = suites.last_mut() {
                                suite.system_err = captured;
                            }
                        }
                        _ => {}
                    }
                }
                "testcase" => {
                    if let Some(case) = case.take() {
                        push_case(&mut suites, case);
                    }
                }
                "testsuite" => flatten(&mut report, &mut suites),
                _ => {}
            },
            _ => {}
        }
        buffer.clear();
    }

    if !saw_root {
        return Err(Error::parse(
            FORMAT,
            "no <testsuite>/<testsuites> element — this does not look like a JUnit report",
        ));
    }

    Ok(Doc::Tests(report))
}

fn take_text(text: &mut String) -> Option<String> {
    let captured = std::mem::take(text);
    let trimmed = captured.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn push_case(suites: &mut [TestSuite], case: TestCase) {
    if let Some(suite) = suites.last_mut() {
        suite.cases.push(case);
    }
}

/// Pop the innermost suite. Nested suites are flattened into a dotted name,
/// since the pivot (and JUnit consumers) only handle one level.
fn flatten(report: &mut TestReport, suites: &mut Vec<TestSuite>) {
    let Some(mut suite) = suites.pop() else {
        return;
    };
    if let Some(parent) = suites.last() {
        suite.name = format!("{}.{}", parent.name, suite.name);
    }
    report.suites.push(suite);
}

pub fn write(doc: &Doc, out: &mut dyn Write, _ctx: &mut FormatCtx) -> Result<()> {
    let report = doc.as_tests()?;

    let mut writer = XmlWriter::new(out);
    writer.declaration()?;

    let mut root_attrs = vec![
        attr("tests", report.total()),
        attr("failures", report.failures()),
        attr("errors", report.errors()),
        attr("skipped", report.skipped()),
        attr("time", fmt_time(report.duration())),
    ];
    if let Some(name) = &report.name {
        root_attrs.insert(0, attr("name", name));
    }
    writer.open("testsuites", &root_attrs)?;

    for suite in &report.suites {
        write_suite(&mut writer, suite)?;
    }

    writer.close("testsuites")?;
    writer.finish()
}

fn write_suite<W: Write>(writer: &mut XmlWriter<W>, suite: &TestSuite) -> Result<()> {
    let mut attrs = vec![
        attr("name", &suite.name),
        attr("tests", suite.cases.len()),
        attr("failures", suite.failures()),
        attr("errors", suite.errors()),
        attr("skipped", suite.skipped()),
        attr("time", fmt_time(suite.duration())),
    ];
    if let Some(timestamp) = &suite.timestamp {
        attrs.push(attr("timestamp", timestamp));
    }
    if let Some(hostname) = &suite.hostname {
        attrs.push(attr("hostname", hostname));
    }
    if let Some(file) = &suite.file {
        attrs.push(attr("file", file));
    }
    writer.open("testsuite", &attrs)?;

    if !suite.properties.is_empty() {
        writer.open("properties", &Attrs::new())?;
        for (name, value) in &suite.properties {
            writer.empty("property", &vec![attr("name", name), attr("value", value)])?;
        }
        writer.close("properties")?;
    }

    for case in &suite.cases {
        write_case(writer, case)?;
    }

    if let Some(out) = &suite.system_out {
        writer.text_element("system-out", &Attrs::new(), out)?;
    }
    if let Some(err) = &suite.system_err {
        writer.text_element("system-err", &Attrs::new(), err)?;
    }

    writer.close("testsuite")
}

fn write_case<W: Write>(writer: &mut XmlWriter<W>, case: &TestCase) -> Result<()> {
    let mut attrs = vec![attr("name", &case.name)];
    if let Some(classname) = &case.classname {
        attrs.push(attr("classname", classname));
    }
    if let Some(file) = &case.file {
        attrs.push(attr("file", file));
    }
    if let Some(line) = case.line {
        attrs.push(attr("line", line));
    }
    if let Some(time) = case.time {
        attrs.push(attr("time", fmt_time(time)));
    }

    let plain = matches!(case.outcome, Outcome::Passed)
        && case.system_out.is_none()
        && case.system_err.is_none();
    if plain {
        return writer.empty("testcase", &attrs);
    }

    writer.open("testcase", &attrs)?;
    match &case.outcome {
        Outcome::Passed => {}
        Outcome::Skipped { message } => {
            let attrs = message
                .as_ref()
                .map(|m| vec![attr("message", m)])
                .unwrap_or_default();
            writer.empty("skipped", &attrs)?;
        }
        Outcome::Failed(problem) => write_problem(writer, "failure", problem)?,
        Outcome::Errored(problem) => write_problem(writer, "error", problem)?,
    }
    if let Some(out) = &case.system_out {
        writer.text_element("system-out", &Attrs::new(), out)?;
    }
    if let Some(err) = &case.system_err {
        writer.text_element("system-err", &Attrs::new(), err)?;
    }
    writer.close("testcase")
}

fn write_problem<W: Write>(writer: &mut XmlWriter<W>, tag: &str, problem: &Problem) -> Result<()> {
    let mut attrs = Attrs::new();
    if let Some(message) = &problem.message {
        attrs.push(attr("message", message));
    }
    if let Some(kind) = &problem.kind {
        attrs.push(attr("type", kind));
    }
    match &problem.detail {
        Some(detail) => writer.text_element(tag, &attrs, detail),
        None => writer.empty(tag, &attrs),
    }
}

/// Three decimals, the de-facto convention across JUnit producers.
fn fmt_time(seconds: f64) -> String {
    // `Sum` for `f64` uses -0.0 as its identity, so a suite whose cases carry
    // no duration would otherwise render as `time="-0.000"`.
    let seconds = if seconds == 0.0 { 0.0 } else { seconds };
    format!("{seconds:.3}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="run">
  <testsuite name="acme.CalcTest" tests="4" time="1.25" timestamp="2026-01-02T03:04:05">
    <properties><property name="env" value="ci"/></properties>
    <testcase name="adds" classname="acme.CalcTest" time="0.5"/>
    <testcase name="divides" classname="acme.CalcTest" time="0.25">
      <failure message="expected 2 but was 3" type="AssertionError">at Calc.divide(Calc.java:12)</failure>
    </testcase>
    <testcase name="explodes" classname="acme.CalcTest" time="0.5">
      <error message="boom" type="RuntimeException"/>
    </testcase>
    <testcase name="later" classname="acme.CalcTest">
      <skipped message="not implemented"/>
    </testcase>
    <system-out>build log</system-out>
  </testsuite>
</testsuites>
"#;

    fn parse(input: &str) -> TestReport {
        let mut ctx = FormatCtx::new(None);
        match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Tests(report) => report,
            _ => panic!("expected a test report"),
        }
    }

    #[test]
    fn reads_every_outcome_kind() {
        let report = parse(SAMPLE);
        assert_eq!(report.name.as_deref(), Some("run"));
        assert_eq!(report.total(), 4);
        assert_eq!(report.failures(), 1);
        assert_eq!(report.errors(), 1);
        assert_eq!(report.skipped(), 1);

        let suite = &report.suites[0];
        assert_eq!(
            suite.properties,
            vec![("env".to_string(), "ci".to_string())]
        );
        assert_eq!(suite.system_out.as_deref(), Some("build log"));
        assert_eq!(suite.timestamp.as_deref(), Some("2026-01-02T03:04:05"));
    }

    #[test]
    fn keeps_failure_message_type_and_stack_trace() {
        let report = parse(SAMPLE);
        match &report.suites[0].cases[1].outcome {
            Outcome::Failed(problem) => {
                assert_eq!(problem.message.as_deref(), Some("expected 2 but was 3"));
                assert_eq!(problem.kind.as_deref(), Some("AssertionError"));
                assert_eq!(
                    problem.detail.as_deref(),
                    Some("at Calc.divide(Calc.java:12)")
                );
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn accepts_a_bare_testsuite_root() {
        let report = parse(r#"<testsuite name="solo"><testcase name="a"/></testsuite>"#);
        assert_eq!(report.suites.len(), 1);
        assert_eq!(report.total(), 1);
    }

    #[test]
    fn flattens_nested_suites_into_dotted_names() {
        let report = parse(
            r#"<testsuites><testsuite name="outer"><testsuite name="inner">
                 <testcase name="a"/>
               </testsuite></testsuite></testsuites>"#,
        );
        let names: Vec<&str> = report.suites.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"outer.inner"), "got {names:?}");
    }

    #[test]
    fn reads_cdata_wrapped_output() {
        let report = parse(
            r#"<testsuite name="s"><testcase name="a">
                 <system-out><![CDATA[raw <output>]]></system-out>
               </testcase></testsuite>"#,
        );
        assert_eq!(
            report.suites[0].cases[0].system_out.as_deref(),
            Some("raw <output>")
        );
    }

    #[test]
    fn rejects_input_that_is_not_a_test_report() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"<coverage/>", &mut ctx).is_err());
    }

    #[test]
    fn a_suite_without_timings_renders_as_positive_zero() {
        let report = parse(r#"<testsuite name="s"><testcase name="a"/></testsuite>"#);
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        write(&Doc::Tests(report), &mut buffer, &mut ctx).unwrap();

        let xml = String::from_utf8(buffer).unwrap();
        assert!(!xml.contains("-0.000"), "got {xml}");
        assert!(xml.contains(r#"time="0.000""#));
    }

    #[test]
    fn round_trips_through_the_writer() {
        let report = parse(SAMPLE);
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        write(&Doc::Tests(report.clone()), &mut buffer, &mut ctx).unwrap();

        let again = parse(&String::from_utf8(buffer).unwrap());
        assert_eq!(again.suites, report.suites);
    }
}
