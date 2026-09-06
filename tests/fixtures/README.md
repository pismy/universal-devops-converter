# Fixtures

Sample reports, one directory per format. `tests/conversion.rs` discovers them:
**the directory layout is the registration mechanism**, so nothing needs editing
when a fixture is added.

```
tests/fixtures/<format-id>/<anything>.<ext>          must parse, and convert to
                                                     every format of its category
tests/fixtures/<format-id>/invalid/<anything>.<ext>  must be rejected by the reader
```

`<format-id>` is an id from `udc formats` — a directory naming something else
fails the suite rather than being ignored.

## Adding a report that triggers a bug

Drop it in `tests/fixtures/<format-id>/` and run `cargo test`. From that moment
it is read, converted to every format of its category, and each output is
validated against that format's schema — so the bug is reproduced, and stays
reproduced once fixed. Give it a name that says what is peculiar about it
(`nyc-istanbul.info`, `bare-testsuite-no-counts.xml`, `no-source-attribute.xml`)
rather than `bug-1234.xml`.

A report that *must not* be accepted goes in `invalid/` instead: that documents
the reader's boundary as precisely as a valid sample documents its reach.

## What is expected of a fixture

- **It must be a valid instance of its format.** The suite validates fixtures
  against the same schemas it validates output against. A fixture no real tool
  could emit proves nothing.
- **It should be representative of one producer or one edge case**, and say so
  in its name. The point of having several LCOV fixtures is that `nyc`,
  `cargo-llvm-cov` and `lcov 2.0` genuinely differ.
- **Keep it small.** These are read by people debugging; a 4 MB report from a
  real build helps nobody. Trim to the few files that carry the interesting
  case.
- **No real hostnames, tokens, internal paths or customer code.** Rewrite paths
  to something like `/home/runner/work/acme/acme`.

## Current fixtures

| Format | Fixture | What it covers |
|---|---|---|
| `lcov` | `cargo-llvm-cov.info` | Rust coverage: mangled function names, absolute build paths |
| | `nyc-istanbul.info` | JS coverage: `TN:`, anonymous functions, branch records |
| | `lcov-2.0-extended.info` | LCOV 2.x: `VER:`, three-field `FN:<start>,<end>,<name>`, an untaken branch |
| | `gcov-no-functions.info` | the minimum: `DA:` records only |
| | `invalid/not-a-tracefile.info` | no `SF:` record at all |
| `cobertura` | `coverage-py.xml` | the `coverage.py` dialect: ms timestamps, empty `<methods/>` |
| | `maven-cobertura.xml` | the Java dialect: methods with signatures, `<conditions>` |
| | `invalid/wrong-root.xml` | a JaCoCo report offered as Cobertura |
| `jacoco` | `jacoco-0.8.xml` | real JaCoCo shape: unindented with `standalone="yes"`, `<sessioninfo>`, every counter type |
| | `default-package.xml` | the empty package name, i.e. sources at the root |
| | `invalid/wrong-root.xml` | a Cobertura report offered as JaCoCo |
| `junit` | `maven-surefire.xml` | failure + error + skipped, properties, CDATA output |
| | `pytest.xml` | `<testsuites>` wrapper, `<skipped>` carrying text |
| | `bare-testsuite-no-counts.xml` | no root wrapper, no counts, no timings |
| | `nested-suites.xml` | suites nested inside suites |
| | `invalid/wrong-root.xml` | a coverage report offered as JUnit |
| `checkstyle` | `eslint.xml` | ESLint's reporter, including a file with no findings |
| | `golangci-lint.xml` | golangci-lint's reporter, attributes in a different order |
| | `no-source-attribute.xml` | no `source`, no `column`, no `severity` |
| | `invalid/wrong-root.xml` | a PMD report offered as Checkstyle |
| `sarif` | `semgrep.json` | rule metadata, `security-severity`, CWE tags, fingerprints, code flows |
| | `no-rules-metadata.json` | results with no `rules[]`, and a `file://` URI |
| | `invalid/sarif-1.0.json` | SARIF 1.0, a structurally different format |
| `codeclimate` | `full-spec.json` | categories, remediation `content`, `positions` |
| `codeclimate-gitlab` | `gitlab-subset.json` | exactly the subset GitLab reads |
| | `invalid/not-an-array.json` | an object where the format is an array |

## Provenance

These are **authored** for this project rather than captured from live runs, so
the repository carries no third-party licence obligations. Each one reproduces
the shape its producer actually emits, and the suite proves it: every fixture is
validated against the upstream schema for its format (see
`tests/schemas/README.md`). A fixture that did not match reality would fail that
check.
