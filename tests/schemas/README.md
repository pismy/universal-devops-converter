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
| `gitlab-sast-15.2.5.json` | GitLab SAST security report | [security-report-schemas](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/sast-report-format.json) | MIT |

Files are kept **verbatim**, licence headers included. Update one by
re-downloading from the source above and re-running `cargo test`.

## Schemas written by this project

These are ours to change, and should be tightened whenever a writer's contract
tightens.

| File | Format | Why not upstream |
|---|---|---|
| `junit.xsd` | JUnit XML | There is no official schema. The Ant-era one ([windyroad/JUnit-Schema](https://github.com/windyroad/JUnit-Schema), Apache-2.0) describes a contract nothing honours any more: it forbids `tests`/`failures`/`time` on `<testsuites>`, which every modern producer emits, and requires `package`, `hostname` and a strictly-typed `timestamp`. It rejects pytest, Jest and our own output alike. Ours describes the consensus format instead. |
| `codeclimate.schema.json` | Code Climate | The analyzer specification is prose (codeclimate/platform, `spec/analyzers/SPEC.md`). |
| `codeclimate-gitlab.schema.json` | GitLab Code Quality | GitLab documents the contract in prose and publishes no schema. |
| `clover.xsd` | Clover XML | OpenClover ships a schema inside its distribution but publishes none at a stable URL a test suite can vendor from. Ours describes what PHPUnit and Jest actually emit. |

## Formats with no schema

- **LCOV** — a line-oriented text format with no formal grammar. Output is
  checked by re-reading it (round-trip) instead.
- **Checkstyle** — read-only, and upstream publishes no schema.
