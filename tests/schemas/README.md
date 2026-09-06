# Vendored schemas

These files are used **only by the test suite** (`tests/conversion.rs`) to check
that fixtures are valid instances of their format and that everything `udc`
writes is a valid instance of its target format. They are not compiled into the
binary and are not redistributed by it.

They are vendored rather than fetched at test time so the suite stays hermetic:
tests must not depend on network access, and a schema must not change under us
between two runs.

| File                    | Format                             | Source                                                                                                                            | Upstream licence                                                                                                   |
| ----------------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `sarif-2.1.0.json`      | SARIF 2.1.0 (JSON Schema draft-04) | [oasis-tcs/sarif-spec](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json)      | OASIS TC material                                                                                                  |
| `cobertura-04.dtd`      | Cobertura XML                      | [cobertura/cobertura](https://raw.githubusercontent.com/cobertura/cobertura/master/cobertura/src/site/htdocs/xml/coverage-04.dtd) | ISO 8879 notice: "Permission to copy in any form is granted for use with conforming SGML systems and applications" |
| `jacoco-report-1.1.dtd` | JaCoCo XML report 1.1              | [jacoco/jacoco](https://raw.githubusercontent.com/jacoco/jacoco/master/org.jacoco.report/src/org/jacoco/report/xml/report.dtd)    | EPL-2.0 (notice kept in the file)                                                                                  |
| `junit.xsd`             | JUnit / Ant JUnitReport XML        | [windyroad/JUnit-Schema](https://raw.githubusercontent.com/windyroad/JUnit-Schema/master/JUnit.xsd)                               | Apache-2.0 (notice kept in the file)                                                                               |

Files are kept **verbatim**, licence headers included. Update one by
re-downloading from the source above and re-running `cargo test`.

## Formats with no schema

- **LCOV** — a line-oriented text format with no formal grammar. Output is
  checked by re-reading it (round-trip) instead.
- **Code Climate / GitLab Code Quality** — no schema is published upstream; the
  contract is prose. `codeclimate-gitlab.schema.json` is **written by this
  project** from that documented contract, and is the one file here that is ours
  to change: tighten it whenever the writer's contract tightens.
- **Checkstyle** — read-only for now, and upstream publishes no schema.
