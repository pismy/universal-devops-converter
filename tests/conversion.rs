//! Fixture-driven conversion matrix.
//!
//! Every sample report under `tests/fixtures/<format-id>/` is read with that
//! format's reader and then written out in **every** format of the same
//! category, and each output is validated against that format's schema.
//!
//! Nothing here enumerates formats or fixtures: both come from the registry and
//! from the directory tree. Adding a format to `FORMATS`, or dropping a report
//! into `tests/fixtures/<format-id>/`, extends the matrix on its own — which is
//! how a report that triggers a bug becomes a regression test: save it there and
//! the failure is reproduced.
//!
//! See `tests/fixtures/README.md`.

mod support;

use support::{fixtures, schema_for, validate, xmllint_available, Fixture, Schema};

use universal_devops_converter::registry::{Doc, FormatSpec, FORMATS};
use universal_devops_converter::warn::FormatCtx;

/// Read a fixture into the pivot, failing with a message that names the file.
fn parse(fixture: &Fixture) -> Doc {
    let mut ctx = FormatCtx::new(fixture.format.default_version);
    let reader = fixture
        .format
        .reader()
        .unwrap_or_else(|e| panic!("{}: {e}", fixture.label()));
    reader(&fixture.read(), &mut ctx).unwrap_or_else(|e| {
        panic!(
            "{} could not be read as '{}': {e}",
            fixture.label(),
            fixture.format.id
        )
    })
}

/// Write `doc` as `target`, returning the bytes.
fn render(doc: &Doc, target: &'static FormatSpec) -> Result<Vec<u8>, String> {
    let writer = target.writer().map_err(|e| e.to_string())?;
    let mut ctx = FormatCtx::new(target.default_version);
    let mut out = Vec::new();
    writer(doc, &mut out, &mut ctx).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Every format `source` can legally be converted into: a shared category, and
/// able to write. A format belonging to several categories reaches the writers
/// of all of them.
fn targets_for(source: &'static FormatSpec) -> Vec<&'static FormatSpec> {
    FORMATS
        .iter()
        .filter(|f| f.write.is_some() && f.shared_category(source).is_some())
        .collect()
}

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

#[test]
fn every_fixture_converts_to_every_format_of_its_category() {
    let mut failures = Vec::new();
    let mut conversions = 0;

    for fixture in fixtures().iter().filter(|f| !f.must_be_rejected) {
        let doc = parse(fixture);

        for target in targets_for(fixture.format) {
            conversions += 1;
            let label = format!("{} -> {}", fixture.label(), target.id);

            let rendered = match render(&doc, target) {
                Ok(bytes) => bytes,
                Err(e) => {
                    failures.push(format!("{label}: writing failed: {e}"));
                    continue;
                }
            };

            if rendered.is_empty() {
                failures.push(format!("{label}: produced no output"));
                continue;
            }

            if let Err(e) = validate(target.id, &rendered, &label) {
                failures.push(e);
            }
        }
    }

    assert!(conversions > 0, "no conversion was exercised");
    eprintln!("conversion matrix: {conversions} conversions exercised");
    assert!(
        failures.is_empty(),
        "{} of {conversions} conversions failed:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// Everything a writer produces must be readable again by the same format's
/// reader. This is the only end-to-end check LCOV gets, having no schema.
#[test]
fn every_written_format_can_be_read_back() {
    let mut failures = Vec::new();

    for fixture in fixtures().iter().filter(|f| !f.must_be_rejected) {
        let doc = parse(fixture);

        for target in targets_for(fixture.format) {
            let Some(reader) = target.read else { continue };
            let label = format!("{} -> {} -> {}", fixture.label(), target.id, target.id);

            let Ok(rendered) = render(&doc, target) else {
                continue; // reported by the matrix test
            };
            let mut ctx = FormatCtx::new(target.default_version);
            if let Err(e) = reader(&rendered, &mut ctx) {
                failures.push(format!("{label}: output is not readable back: {e}"));
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The same input must always produce the same bytes — reports land in caches
/// and diffs, and a converter that reorders its output on every run is noise.
#[test]
fn conversion_is_byte_stable() {
    for fixture in fixtures().iter().filter(|f| !f.must_be_rejected) {
        for target in targets_for(fixture.format) {
            let first = render(&parse(fixture), target);
            let second = render(&parse(fixture), target);
            assert_eq!(
                first,
                second,
                "{} -> {} is not deterministic",
                fixture.label(),
                target.id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The fixtures themselves
// ---------------------------------------------------------------------------

/// A fixture claiming to be format X must be a valid instance of X. Otherwise
/// the matrix proves nothing: it would be converting from something no real
/// tool emits.
#[test]
fn fixtures_are_valid_instances_of_the_format_they_claim() {
    let mut failures = Vec::new();

    for fixture in fixtures().iter().filter(|f| !f.must_be_rejected) {
        if let Err(e) = validate(fixture.format.id, &fixture.read(), &fixture.label()) {
            failures.push(e);
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// Files under `<format>/invalid/` document what the reader must refuse.
#[test]
fn invalid_fixtures_are_rejected() {
    for fixture in fixtures().iter().filter(|f| f.must_be_rejected) {
        let mut ctx = FormatCtx::new(fixture.format.default_version);
        let reader = fixture
            .format
            .reader()
            .expect("invalid fixtures target readers");
        assert!(
            reader(&fixture.read(), &mut ctx).is_err(),
            "{} was accepted as '{}' but lives under invalid/ and must be rejected",
            fixture.label(),
            fixture.format.id
        );
    }
}

// ---------------------------------------------------------------------------
// Coverage of the suite itself
// ---------------------------------------------------------------------------

/// Every readable format must ship at least one sample. This is what makes
/// "a new format comes with fixtures" a rule the build enforces rather than a
/// convention someone remembers.
#[test]
fn every_readable_format_has_a_fixture() {
    let all = fixtures();
    let missing: Vec<&str> = FORMATS
        .iter()
        .filter(|f| f.read.is_some())
        .filter(|f| {
            !all.iter()
                .any(|x| x.format.id == f.id && !x.must_be_rejected)
        })
        .map(|f| f.id)
        .collect();

    assert!(
        missing.is_empty(),
        "no fixture for: {}.\nAdd at least one real-world sample under tests/fixtures/<format-id>/.",
        missing.join(", ")
    );
}

/// Every format must have made a decision about schema validation — including
/// the decision that no schema exists, and why.
#[test]
fn every_format_declares_how_it_is_validated() {
    for format in FORMATS {
        // Panics if the format has no entry.
        let schema = schema_for(format.id);
        if let Schema::None(reason) = schema {
            assert!(
                !reason.is_empty(),
                "format '{}' declares no schema without saying why",
                format.id
            );
        }
    }
}

/// The harness must actually reject bad documents. Without this, a broken
/// validator — a schema that failed to load, an `xmllint` that silently exits 0
/// — would turn the whole matrix into a no-op that always passes.
#[test]
fn validation_rejects_documents_that_do_not_fit_the_schema() {
    // JSON: severity is not in the enum, and `location.path` is missing.
    let bad_json = br#"[{"type":"issue","check_name":"x","description":"y",
                         "fingerprint":"z","severity":"catastrophic","location":{}}]"#;
    assert!(
        validate("codeclimate-gitlab", bad_json, "deliberately bad JSON").is_err(),
        "the JSON Schema validator accepted an invalid document"
    );

    if xmllint_available() {
        // XML against a DTD: `coverage` is missing every required attribute.
        let bad_dtd = br#"<?xml version="1.0"?><coverage><packages/></coverage>"#;
        assert!(
            validate("cobertura", bad_dtd, "deliberately bad Cobertura").is_err(),
            "the DTD validator accepted an invalid document"
        );

        // XML against an XSD: <testcase> outside any <testsuite>.
        let bad_xsd = br#"<?xml version="1.0"?><testsuites><testcase name="stray"/></testsuites>"#;
        assert!(
            validate("junit", bad_xsd, "deliberately bad JUnit").is_err(),
            "the XSD validator accepted an invalid document"
        );
    }
}

/// XML validation is skipped when `xmllint` is missing, which is tolerable on a
/// developer machine and not in CI — otherwise the suite would quietly stop
/// checking half the formats.
#[test]
fn xmllint_is_available_in_ci() {
    if std::env::var_os("CI").is_none() {
        return;
    }
    assert!(
        xmllint_available(),
        "xmllint is required in CI for XML schema validation (Debian/Ubuntu: libxml2-utils)"
    );
}
