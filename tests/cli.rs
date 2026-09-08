//! End-to-end tests over the real binary: they cover the wiring (argument
//! parsing, detection, merging, path normalization, exit codes) that unit tests
//! on the format modules cannot reach.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn udc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_udc"))
}

/// Run the binary with `input` on stdin and return the captured output.
fn run(args: &[&str], input: &str) -> Output {
    let mut child = udc()
        .args(args)
        .arg("--no-color")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn udc");
    // Take the handle so it is closed once written: a run that does read stdin
    // needs the EOF, and `wait_with_output` would otherwise be waiting on a
    // pipe this side still holds open.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    match stdin.write_all(input.as_bytes()) {
        Ok(()) => {}
        // Not a failure. `udc` validates its options before reading anything,
        // so a run that rejects a bad option exits before the input arrives and
        // the pipe closes under us. Which side wins that race depends on
        // machine load — treating it as an error made these tests pass locally
        // and fail in CI.
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to udc's stdin: {e}"),
    }
    drop(stdin);

    child.wait_with_output().expect("failed to wait for udc")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const LCOV: &str = "\
TN:
SF:/builds/acme/proj/src/main.rs
FN:10,main
FNDA:3,main
DA:10,3
DA:11,0
DA:12,3
BRDA:12,0,0,2
BRDA:12,0,1,-
end_of_record
";

const SARIF: &str = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "semgrep"}},
    "results": [{
      "ruleId": "R1",
      "level": "warning",
      "message": {"text": "Something to fix"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "src/app.py"},
        "region": {"startLine": 3}
      }}]
    }]
  }]
}"#;

const CHECKSTYLE: &str = r#"<?xml version="1.0"?>
<checkstyle version="8.36">
  <file name="/builds/acme/proj/src/app.js">
    <error line="12" column="5" severity="warning" message="Unexpected var" source="no-var"/>
  </file>
</checkstyle>
"#;

#[test]
fn converts_lcov_to_cobertura_from_stdin() {
    let output = run(&["-t", "cobertura"], LCOV);
    assert!(output.status.success(), "{}", stderr_of(&output));

    let xml = stdout_of(&output);
    assert!(xml.contains("<coverage"));
    assert!(xml.contains(r#"lines-valid="3""#));
    assert!(xml.contains(r#"condition-coverage="50% (1/2)""#));
}

#[test]
fn source_root_makes_build_paths_repository_relative() {
    let output = run(
        &["-t", "cobertura", "--source-root", "/builds/acme/proj"],
        LCOV,
    );
    assert!(output.status.success(), "{}", stderr_of(&output));

    let xml = stdout_of(&output);
    assert!(xml.contains(r#"filename="src/main.rs""#), "{xml}");
    assert!(!xml.contains("/builds/"), "{xml}");
}

#[test]
fn checkstyle_becomes_a_gitlab_code_quality_report() {
    let output = run(
        &["-f", "checkstyle", "-t", "codeclimate-gitlab"],
        CHECKSTYLE,
    );
    assert!(output.status.success(), "{}", stderr_of(&output));

    let json = stdout_of(&output);
    assert!(json.contains(r#""check_name": "no-var""#));
    assert!(json.contains(r#""fingerprint""#));
    // GitLab ignores columns, so they must not be emitted — and the loss must
    // be reported rather than silently swallowed.
    assert!(!json.contains("positions"));
    assert!(stderr_of(&output).contains("lossy:"));
}

#[test]
fn merges_repeated_inputs_into_one_report() {
    let dir = std::env::temp_dir().join(format!("udc-merge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let first = dir.join("a.xml");
    let second = dir.join("b.xml");
    std::fs::write(
        &first,
        r#"<testsuite name="a"><testcase name="t1"/></testsuite>"#,
    )
    .unwrap();
    std::fs::write(
        &second,
        r#"<testsuite name="b"><testcase name="t2"/><testcase name="t3"><failure message="x"/></testcase></testsuite>"#,
    )
    .unwrap();

    let output = run(
        &[
            "-i",
            first.to_str().unwrap(),
            "-i",
            second.to_str().unwrap(),
            "-t",
            "junit",
        ],
        "",
    );
    std::fs::remove_dir_all(&dir).ok();

    assert!(output.status.success(), "{}", stderr_of(&output));
    let xml = stdout_of(&output);
    assert!(xml.contains(r#"tests="3""#), "{xml}");
    assert!(xml.contains(r#"failures="1""#), "{xml}");
}

#[test]
fn refuses_to_convert_across_categories() {
    let output = run(&["-t", "cobertura"], CHECKSTYLE);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).contains("only defined within a category"));
}

#[test]
fn strict_turns_a_lossy_conversion_into_a_failure() {
    let output = run(&["-t", "jacoco", "--strict"], LCOV);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).contains("--strict"));
}

#[test]
fn the_same_conversion_without_strict_succeeds_and_only_warns() {
    let output = run(&["-t", "jacoco"], LCOV);
    assert!(output.status.success());
    // JaCoCo cannot express hit counts, so the values are rewritten rather
    // than dropped: that is a `degraded:` notice, not a `lossy:` one.
    assert!(stderr_of(&output).contains("degraded:"));
    assert!(stdout_of(&output).contains("<report"));
}

#[test]
fn both_notice_kinds_count_towards_strict() {
    for (args, expected) in [
        (["-t", "jacoco"], "degraded:"),
        (["-t", "codeclimate-gitlab"], "lossy:"),
    ] {
        let input = if expected == "degraded:" {
            LCOV
        } else {
            CHECKSTYLE
        };
        let lenient = run(&args, input);
        assert!(lenient.status.success());
        assert!(
            stderr_of(&lenient).contains(expected),
            "{}",
            stderr_of(&lenient)
        );

        let strict = run(&[args[0], args[1], "--strict"], input);
        assert_eq!(strict.status.code(), Some(1), "{}", stderr_of(&strict));
    }
}

#[test]
fn a_version_can_be_pinned_on_the_format() {
    let output = run(&["-f", "sarif@2.1.0", "-t", "codeclimate-gitlab"], SARIF);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert!(stdout_of(&output).contains(r#""check_name": "R1""#));
}

#[test]
fn an_unsupported_version_lists_the_supported_ones() {
    // Empty input on purpose: a bad selector is a usage error and must be
    // reported before anything is read.
    let output = run(&["-f", "sarif@1.0.0", "-t", "codeclimate-gitlab"], "");
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("does not support version '1.0.0'"),
        "{stderr}"
    );
    assert!(stderr.contains("2.1.0"), "{stderr}");
}

#[test]
fn a_version_on_an_unversioned_format_is_rejected() {
    let output = run(&["-t", "junit@1.0"], "");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).contains("is not versioned"));
}

#[test]
fn a_colon_separator_points_at_the_at_sign() {
    let output = run(&["-t", "sarif:2.1.0"], "");
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("sarif@2.1.0"), "{stderr}");
}

#[test]
fn formats_labels_notices_with_the_kind_the_writer_emits() {
    let listing = stdout_of(&run(&["formats", "--category", "coverage"], ""));
    // JaCoCo rewrites hit counts rather than dropping them; the listing must
    // say the same thing the conversion says on stderr.
    assert!(
        listing.contains("degraded: hit counts are flattened"),
        "{listing}"
    );
    assert!(
        listing.contains("lossy: JaCoCo instruction/complexity/method counters are dropped"),
        "{listing}"
    );
}

#[test]
fn a_format_in_two_categories_is_listed_under_each() {
    let quality = stdout_of(&run(&["formats", "--category", "quality"], ""));
    let security = stdout_of(&run(&["formats", "--category", "security"], ""));

    // SARIF describes both kinds of finding; the listing says so rather than
    // pretending it belongs to one.
    assert!(quality.contains("sarif"), "{quality}");
    assert!(security.contains("sarif"), "{security}");
    assert!(quality.contains("also a security format"), "{quality}");
}

#[test]
fn formats_advertises_the_version_syntax() {
    let output = run(&["formats", "--category", "quality"], "");
    assert!(output.status.success(), "{}", stderr_of(&output));
    let listing = stdout_of(&output);
    assert!(listing.contains("2.1.0 (default)"), "{listing}");
    assert!(listing.contains("sarif@<version>"), "{listing}");
}

#[test]
fn an_ambiguous_input_is_an_error_rather_than_a_guess() {
    let output = run(&["-t", "codeclimate"], r#"[{"check_name":"x"}]"#);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).contains("--input-format"));
}

#[test]
fn output_format_is_required() {
    let output = run(&[], LCOV);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).contains("--output-format is required"));
}

/// A failing run must not take the harness down with it.
///
/// `udc` rejects a bad option before reading stdin, so the pipe closes while
/// the test is still writing. With a small input that is a race — it passed
/// locally and failed in CI — so this sends more than a pipe buffer's worth,
/// which makes the broken pipe certain rather than likely.
#[test]
fn a_large_input_to_a_failing_run_does_not_break_the_harness() {
    let big = LCOV.repeat(4000);
    assert!(big.len() > 256 * 1024, "must exceed any pipe buffer");

    let output = run(&["-t", "auto"], &big);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).contains("cannot be 'auto'"));
}

#[test]
fn output_format_auto_is_rejected() {
    let output = run(&["-t", "auto"], LCOV);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr_of(&output).contains("cannot be 'auto'"));
}

#[test]
fn an_unknown_format_lists_the_known_ones() {
    let output = run(&["-t", "nope"], LCOV);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr_of(&output);
    assert!(stderr.contains("unknown format 'nope'"));
    assert!(stderr.contains("cobertura"));
}

#[test]
fn formats_lists_every_category() {
    let output = run(&["formats"], "");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let listing = stdout_of(&output);
    for expected in ["COVERAGE", "TESTS", "QUALITY", "lcov", "junit", "sarif"] {
        assert!(
            listing.contains(expected),
            "missing {expected} in {listing}"
        );
    }
}

#[test]
fn formats_can_be_filtered_by_category() {
    let output = run(&["formats", "--category", "coverage"], "");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let listing = stdout_of(&output);
    assert!(listing.contains("lcov"));
    assert!(!listing.contains("junit"));
}

#[test]
fn conversion_is_byte_stable_across_runs() {
    let first = run(&["-t", "cobertura"], LCOV);
    let second = run(&["-t", "cobertura"], LCOV);
    assert_eq!(first.stdout, second.stdout);
}
