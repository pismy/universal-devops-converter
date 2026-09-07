# Specification — `universal-devops-converter`

> The project's reference document. It describes **what the tool does**, **how it is structured**
> and **which formats it supports**. Every functional change starts with an update to this file.

## 1. Introduction

`universal-devops-converter` (binary: **`udc`**) converts DevOps tool reports between equivalent
formats.

This is a recurring problem: the ecosystem produces dozens of report formats (unit tests,
coverage, linters, SAST, DAST, SBOM, vulnerability scans, performance tests, accessibility…),
but the platforms that *consume* them generally support a single one per category. GitLab CI/CD
is the canonical example: one format and one only per report type
([`artifacts:reports`](https://docs.gitlab.com/ci/yaml/artifacts_reports/)).

The tool bridges that gap: use whichever tool you like, then project its report onto the format
the platform expects.

### What the tool is not

- It is **not a quality aggregator**: it computes no score, sets no threshold, fails no quality
  gate.
- It is **not a runner**: it never invokes an analysis tool, it consumes their output.
- It is **not a general-purpose transcoder**: conversion only makes sense within a single report
  **category**.

## 2. Constraints

- A **lightweight**, **runtime-free** executable (CLI), usable anywhere (developer machine, VM,
  container, minimal CI runner).
- A **static** binary wherever the platform allows it (Linux: `musl`).
- Language: **Rust**.
- `shell` / `PowerShell` install scripts detecting OS + architecture, downloading and installing
  the right executable (`latest` by default, overridable by option).
- Hosted on GitHub, with automated build and release. The tooling follows
  `/Users/pierre.smeyers/Dev/Misc/git-vbranch`: `semantic-release` + Conventional Commits,
  `ci.yml` / `release.yml` / `publish-assets.yml` workflows, floating `vX` / `vX.Y` tags.

## 3. Architecture principles

### 3.1 One pivot model per category

Conversion is **never** done format to format. Each report category owns a **canonical model**
(the pivot). Each format contributes a *reader* (format → pivot) and/or a *writer*
(pivot → format).

```
   lcov ─┐                                    ┌─→ cobertura
jacoco ──┼─→ [ CoverageDoc pivot ] ───────────┼─→ jacoco
 clover ─┘                                    └─→ lcov
```

Consequences:

- N formats ⇒ **2N** implementations instead of N² converters.
- Cross-category conversion is **impossible by construction** (explicit error).
- Adding a format means adding a reader and/or a writer, touching nothing else.

### 3.2 Conversion is *lossy*, and that must be visible

Projecting one model onto another loses information, **asymmetrically**:

| Conversion | Loss |
|---|---|
| Cobertura → JaCoCo | `INSTRUCTION`, `COMPLEXITY`, `METHOD` counters (not derivable) |
| JaCoCo → Cobertura | real *hit* counts (JaCoCo does not count executions) |
| SARIF → Code Climate | rules, `codeFlows`, levels, `relatedLocations` |
| Code Climate → SARIF | nothing blocking, but `rules[]` has to be reconstructed |
| CycloneDX → SPDX | VEX / vulnerabilities (absent from SPDX 2.x) |
| SPDX → CycloneDX | the fine semantics of `relationships` |
| LCOV → Cobertura | nothing significant (LCOV is a subset) |

Rules:

1. Every detected loss emits a **notice on stderr** (never on stdout, which may be carrying the
   converted report), in one of two forms:
   - `lossy:` — information the target cannot represent was **dropped**;
   - `degraded:` — a value was **rewritten** to stay valid (remapped enum member, approximated
     counter). The output remains schema-valid but no longer says exactly what the input said.
2. `--strict` turns any loss into an **error** (non-zero exit code).
3. The conversion matrix and its known losses are **documented and queryable** (`udc formats`).

### 3.3 Taxonomy by *format*, not by *tool*

"Trivy" and "pa11y" are not formats: they are tools that emit a format. A single tool often emits
several (Trivy natively produces SARIF, CycloneDX and the GitLab format). Format identifiers are
therefore named after the **format**, with its **version** when that is structural:

```
lcov  cobertura  jacoco  junit  checkstyle  sarif
codeclimate  codeclimate-gitlab
cyclonedx-json  cyclonedx-xml  spdx-json
trivy-json  grype-json          # a tool's proprietary format: prefixed with the tool
```

Format versioning is carried by an **optional suffix on the identifier**
(`cyclonedx-json@1.6`), not by an explosion of identifiers — see §3.4.

### 3.4 Format versioning

Several formats exist in multiple specification versions. They are not equivalent, and three
regimes must be told apart.

**A complete break — that is another format, not another version.** The data model changes and no
mechanical mapping exists. These cases get their own **format identifier**:

| Case | Nature of the break |
|---|---|
| SPDX 2.x → **3.0** | moves to an RDF graph model serialized as JSON-LD, split into profiles (Core, Software, Security, Licensing, Build, AI, Dataset). Nothing in common with the flat 2.x document. |
| SARIF 1.0 → 2.x | `files` (dictionary) → `artifacts` (array), `resultFile` → `physicalLocation.artifactLocation`, `formattedRuleMessage` → `message.id` + `arguments`. Dead format in practice. |
| SARIF 2.0 (drafts) → 2.1.0 | `resources.rules` → `tool.driver.rules`. |
| Trivy `SchemaVersion` 1 → 2 | restructuring; only 2 exists in practice. |

**Additive, with sharp edges.** CycloneDX claims backward compatibility (each version is a
superset), but a downgrade is not merely dropping fields:

- **JSON only exists from 1.2 onwards**: `cyclonedx-json@1.1` is structurally impossible, not
  merely degraded.
- **Vulnerabilities (VEX) arrive in 1.4**: going from 1.4+ down to 1.3 removes the document's
  *entire* security section.
- **Enumerations widen**: `component.type` gained `data`, `device-driver`, `platform`,
  `machine-learning-model` and `cryptographic-asset` over successive versions. Emitting
  `cryptographic-asset` in a document declared as 1.4 produces a **schema-invalid** file —
  rejected wholesale by the consumer, not merely impoverished.

SPDX 2.2 → 2.3, by contrast, is sensibly additive (`primaryPackagePurpose`, `releaseDate`,
`builtDate`, `validUntilDate`). With SPDX the **serialization** axis (tag-value, JSON, YAML,
RDF/XML) is in practice more structural than the version axis, and is orthogonal to it.

**No versions at all — dialects.** JUnit, Cobertura (DTD coverage-01→04, everyone is on 04),
JaCoCo (DTD 1.0/1.1), Code Climate. The answer here is not versioning but a tolerant reader and a
conservative writer. LCOV 1.x → 2.x (`FNL`, `BRL`, `VER`, the `FN:<start>,<end>,<name>` form) is
the only borderline case, absorbed by the reader.

#### Input and output are not handled alike

**On the input side this is not version support, it is tolerant reading.** The user does not
choose what their tool produced. A single lenient reader covers the union of shapes, since the
pivot only retains what is projectable anyway. The real input-side risk is not versioning but
**variance between producers at a constant version**: SARIF 2.1.0 makes almost everything
optional, and two conformant tools produce very different documents.

**On the output side the version matters.** The consumer (GitLab, GitHub, Dependency-Track, a
compliance portal) validates against a precise schema: a CycloneDX 1.6 document sent to a tool
expecting 1.4 is rejected in its entirety.

Three rules follow:

1. **The default is the most widely ingested version, not the newest one.** The newest version is
   the one the fewest consumers accept; a rejected report is worse than one missing a recent
   field. Hence `FormatSpec::default_version`, explicitly distinct from "the last one in the
   list".
2. **Converting to the same format ⇒ keep the input's version**, so as not to downgrade silently.
   *To be implemented with the first genuinely versioned format*: it requires the reader to carry
   the document's version into the pivot.
3. **A downgrade creates a distinct class of loss.** Dropping a field is one thing (`lossy`);
   rewriting a value to stay valid — remapping an enum member the target version does not know,
   approximating a counter — is another (`degraded`). Emitting the unknown value as-is is not an
   option: the document becomes invalid. Both count towards `--strict`, but they are displayed
   distinctly.

#### Syntax

The version is declared as a **suffix on the format identifier**, using `@`:

```
--output-format cyclonedx-json@1.6
--input-format sarif@2.1.0
-t spdx-json@2.3
```

- `@` rather than `:`: `@` is the ecosystem's "name at version" convention (npm, Go modules,
  GitHub Actions, Homebrew, purl). `format:version` is rejected with a pointer at `@`, since it
  is a natural guess.

> An earlier draft reserved `:` for a category qualifier (`security:sarif` vs `quality:sarif`).
> That turned out to be solving the wrong problem — see §3.5.
- An unversioned format rejects the suffix instead of ignoring it.
- With no suffix: the format's `default_version`.
- `udc formats` shows the supported versions and which one is the default.

### 3.5 A format may belong to several categories

SARIF describes code-quality findings and security findings with the same document shape. That
is not an ambiguity to be disambiguated, it is what the format *is*, and it is why SARIF is the
best universal input.

A format therefore declares a **set** of categories, and a conversion is legal when the source's
set and the target's set intersect:

| Conversion | Categories | Verdict |
|---|---|---|
| `checkstyle` → `codeclimate-gitlab` | {quality} ∩ {quality} | allowed |
| `sarif` → `codeclimate-gitlab` | {quality, security} ∩ {quality} | allowed |
| `sarif` → `gitlab-security` | {quality, security} ∩ {security} | allowed |
| `checkstyle` → `gitlab-security` | {quality} ∩ {security} = ∅ | refused |
| `checkstyle` → `cobertura` | {quality} ∩ {coverage} = ∅ | refused |

The alternative — two registry entries, `quality:sarif` and `security:sarif`, sharing the same
reader and writer — was rejected. It would duplicate an id, make a bare `-t sarif` ambiguous, and
require a qualifier syntax, all to express something the format already is. `udc formats` lists
such a format under each of its categories and says so.

## 4. CLI contract

```
udc [OPTIONS]                    # default mode: conversion
udc formats [--category <cat>]   # introspection: formats and conversion matrix
```

### 4.1 Conversion options

| Option | Default | Description |
|---|---|---|
| `-i`, `--input-file <PATH>` | `-` | Input file, or `-` for STDIN. **Repeatable** (merges). |
| `-o`, `--output-file <PATH>` | `-` | Output file, or `-` for STDOUT. |
| `-f`, `--input-format <FMT>[@<VER>]` | `auto` | Input format. `auto` = detection (see §4.3). |
| `-t`, `--output-format <FMT>[@<VER>]` | *(required)* | Output format. `auto` is **forbidden**. |
| `--source-root <PATH>` | — | Source root, used to normalize paths (see §4.4). |
| `--strip-prefix <P>` | — | Path prefix to strip. Repeatable. |
| `--strict` | `false` | Fail if the conversion loses information. |
| `-v`, `--verbose` | `false` | Debug-level logging. |
| `--no-color` | `false` | Disable colors (also honours `NO_COLOR`). |

Every option can also be driven by a `UDC_*` environment variable (`UDC_INPUT_FORMAT`,
`UDC_OUTPUT_FORMAT`, `UDC_SOURCE_ROOT`…).

`<FMT>` accepts an `@<VER>` version suffix for versioned formats (see §3.4) — e.g.
`-t cyclonedx-json@1.6`. The `:` separator is reserved and explicitly rejected.

### 4.2 Exit codes

| Code | Meaning |
|---|---|
| `0` | Conversion succeeded |
| `1` | Runtime error (parsing, I/O, impossible conversion, loss under `--strict`) |
| `2` | Usage error (invalid options — `clap`'s standard code) |

### 4.3 Automatic input format detection

`--input-format auto` (the default) inspects the beginning of the stream:

- **XML**: root element — `<coverage>` → Cobertura, `<report>` → JaCoCo,
  `<testsuite>`/`<testsuites>` → JUnit, `<checkstyle>` → Checkstyle, `<bom>` → CycloneDX XML,
  `<pmd>` → PMD, `<BugCollection>` → SpotBugs.
- **JSON**: discriminating keys — `$schema` (SARIF, SPDX), `bomFormat` (CycloneDX),
  `spdxVersion` (SPDX), `SchemaVersion` + `Results` (Trivy), `runs[].tool` (SARIF).
- **Line-oriented**: unambiguous prefixes — `TN:` / `SF:` → LCOV.

Two non-negotiable rules:

1. **`auto` only exists on the input side.** The output format is always explicit.
2. **Ambiguity is a failure.** A bare JSON array could be pa11y or Code Climate: the tool asks for
   `--input-format` instead of guessing.

Detection only inspects the **first 64 KiB** of the stream, which is enough to reach the
discriminating keys of every supported format.

> **Current limitation**: the *readers* work on the whole document in memory. On a
> several-hundred-megabyte SBOM that stays costly. Streaming parsing is an identified
> optimization, not an implemented one: the contract above only bounds detection.

### 4.4 Path normalization

This is a cross-cutting need and one of the tool's main values: GitLab requires paths **relative
to the repository root**, whereas LCOV carries the build machine's absolute paths and JaCoCo only
exposes `package` + `sourcefile`.

- `--source-root <PATH>`: absolute paths starting with this root are made relative.
- `--strip-prefix <P>`: strips a literal prefix (repeatable). Prefixes are tried in order and
  **the first match wins**; applying several in sequence would mangle a path that happens to
  start with a shorter, unrelated prefix.
- Stripping only happens on a **segment boundary**: the prefix `src/app` does not shorten
  `src/apple/main.rs`.
- By default, separators are normalized to `/` and `..` segments are resolved.

## 5. Categories and formats

Status: **✅ implemented** · **🔜 planned** · **💭 considered**

### 5.1 Code coverage — `CoverageDoc` pivot

Primary sink: **Cobertura** (historically the only format GitLab accepted; JaCoCo accepted since
GitLab 17).

| Format | Read | Write | Notes |
|---|---|---|---|
| LCOV | ✅ | ✅ | gcov, lcov, nyc/istanbul, `cargo llvm-cov`, tarpaulin, Swift |
| Cobertura | ✅ | ✅ | includes the `coverage.py` dialect |
| JaCoCo | ✅ | ✅ | no *hit* counter: covered = 1, uncovered = 0 |
| Clover | ✅ | ✅ | PHPUnit, Jest. Roots at `<coverage>` like Cobertura — see below |
| Istanbul JSON | 🔜 | — | `nyc` / `coverage-final.json` |
| Go `-coverprofile` | 🔜 | — | `go test`'s native format |
| OpenCover / dotCover | 💭 | — | .NET |
| Visual Studio `.coveragexml` | 💭 | — | .NET |
| SimpleCov JSON | 💭 | — | Ruby |

**Highest-ROI conversion of the project: LCOV → Cobertura.**

> **Clover and Cobertura share a root element.** Both documents start with
> `<coverage>`, and nothing else about the opening tag is common: Clover carries
> `clover` and `generated`, Cobertura carries `line-rate`. Detection keys on that,
> and each reader rejects the other's document outright — because the failure mode
> is silent. A Clover file read as Cobertura contains no `<class>` element, so it
> parses into an empty report and exits 0, handing the platform a file that says
> nobody covered anything.

### 5.2 Tests — `TestReport` pivot

Primary sink: **JUnit XML**.

Beware: "JUnit XML" is not a specification but a **family of dialects** (Ant, Maven Surefire,
pytest, Jest, GoogleTest…). The *writer* is simple; the *reader* must be tolerant (optional
attributes, optional `<testsuites>` root, `<skipped>` vs `status`).

| Format | Read | Write | Notes |
|---|---|---|---|
| JUnit XML | ✅ | ✅ | tolerant multi-dialect reader |
| TRX | 🔜 | — | MSTest / `dotnet test` |
| `go test -json` | 🔜 | — | NDJSON |
| TAP | 🔜 | — | Test Anything Protocol 13/14 |
| NUnit 2/3 | 💭 | — | |
| xUnit.net | 💭 | — | |
| Cucumber JSON / messages | 💭 | — | NDJSON for `messages` |
| Allure results | 💭 | — | one JSON file per test |
| TestNG / Robot Framework | 💭 | — | |

**Cross-cutting need**: merging several files into one report — hence the repeatable
`--input-file`.

### 5.3 Code quality — `FindingsDoc` pivot

Primary sink: **Code Climate JSON**, in its GitLab flavour
(`artifacts:reports:codequality`), which is a strict subset of the Code Climate format:
`description`, `check_name`, `fingerprint`, `severity`, `location.path`, `location.lines.begin`.

| Format | Read | Write | Notes |
|---|---|---|---|
| Checkstyle XML | ✅ | 💭 | ESLint, PHP_CodeSniffer, golangci-lint, ktlint, stylelint… — a *producer* format: nothing consumes it that does not also read something better |
| Code Climate | ✅ | ✅ | full specification |
| Code Climate (GitLab) | ✅ | ✅ | subset; `fingerprint` is mandatory |
| SARIF 2.1.0 | ✅ | ✅ | semgrep, CodeQL, gosec, bandit, Checkov…; writing it is what reaches GitHub code scanning |
| ESLint JSON | 🔜 | — | |
| PMD XML | 💭 | — | |
| SpotBugs XML | 💭 | — | |
| SonarQube Generic Issue | 💭 | 💭 | |
| Codacy | 💭 | — | |

**Highest-ROI conversions: Checkstyle → Code Climate (GitLab)** for GitLab, and
**Checkstyle → SARIF** for GitHub code scanning — the same need on the other platform.

> **Note on SARIF.** SARIF belongs to this category *and* to §5.4, and declares
> both (§3.5), so it reaches the writers of either.
>
> Rebuilding `tool.driver.rules[]` is the delicate part: the pivot carries rule
> metadata per finding, so the table is reconstructed by deduplicating on rule id
> and the first finding seen defines the rule. `security-severity` is emitted only
> for findings carrying a security identifier — it is GitHub's marker for "this
> belongs in the security tab", and putting it on a style lint would misfile it.
> The cost is that critical and blocker collapse into `error` for everything else,
> which is reported as `degraded:`.

### 5.4 Security — `FindingsDoc` pivot (vulnerability profile)

> **Decision**: security and code quality are **two distinct categories**. They share the notion
> of a "located finding" but neither their sink nor their semantics. A quality *issue* carries
> `check_name` / `categories` / `remediation_points`; a *vulnerability* carries `identifiers[]`
> (CVE, CWE, GHSA, OSV), a versioned component, a fixed version and a `solution`. The only format
> crossing both worlds is SARIF, which makes it the best universal input format.

> **Decision**: *dependency scanning* and *container scanning* share **the same data model** and
> differ only in their **location**:
> - dependencies → `location.file` + `location.dependency.package.name`
> - containers → `location.image` + `location.operating_system` + `location.dependency`
>
> One pivot, several **output formats** — not one writer with a switch. Reading the published
> schemas settles it: each profile has its own schema, its own `scan.type` enum, and different
> *required* location fields (SAST requires none, dependency scanning requires `file` +
> `dependency`, container scanning requires `dependency` + `operating_system` + `image`). They are
> separate formats of one family, which also gives each its own schema validation in the tests.

Primary sinks: **GitLab's security report schemas** (`sast`, `dependency_scanning`,
`container_scanning`, `secret_detection`, `dast`), and **SARIF** for GitHub code scanning.

Three constraints in those schemas shape the writers:

- `scan.start_time` / `scan.end_time` are **required**, with a fixed `yyyy-mm-ddThh:mm:ss` shape.
  Reading the clock would break the byte-stability the project guarantees, so the window comes
  from the source when it has one (SARIF's `invocations[]`) and otherwise falls back to a fixed
  epoch with a `degraded:` notice.
- `identifiers` needs **at least one entry**, while a linter finding has none. One is synthesized
  from the rule id; a finding with neither is dropped rather than making the whole document
  invalid.
- `id` is expected to be a UUID. The pivot's 128-bit fingerprint is formatted as one, and derived
  from the source fingerprint when there is one, so a finding keeps its identity across runs.

| Format | Read | Write | Notes |
|---|---|---|---|
| SARIF 2.1.0 | ✅ | ✅ | universal input; declares both categories (§3.5) |
| GitLab SAST | — | ✅ | `gitlab-sast`, schema 15.2.5 |
| GitLab Dependency Scanning | — | 🔜 | blocked on the pivot carrying a versioned component |
| GitLab Container Scanning | — | 🔜 | blocked on the pivot carrying an image and an OS |
| GitLab Secret Detection / DAST | — | 💭 | |
| Trivy JSON | 🔜 | — | dependencies + containers + IaC + secrets |
| Grype JSON | 🔜 | — | |
| OSV / osv-scanner | 💭 | — | |
| `npm audit` JSON | 💭 | — | |
| `pip-audit` JSON | 💭 | — | |
| OWASP Dependency-Check | 💭 | — | |
| Gitleaks / TruffleHog | 💭 | — | secrets |
| OWASP ZAP JSON/XML | 💭 | — | DAST |
| Snyk / Docker Scout | 💭 | — | |

### 5.5 SBOM — `SbomDoc` pivot

| Format | Read | Write | Notes |
|---|---|---|---|
| CycloneDX JSON | 🔜 | 🔜 | 1.4 → 1.6 |
| CycloneDX XML | 🔜 | 🔜 | |
| SPDX JSON | 🔜 | 🔜 | 2.2 / 2.3 |
| SPDX tag-value | 💭 | 💭 | |
| SPDX 3.0 | 💭 | 💭 | deeply reworked model |
| Syft JSON | 💭 | — | |
| SWID | 💭 | — | |

This is the **trickiest** category (component identity, `purl`, licenses, relationship graph).
To be tackled last, once the loss-reporting mechanism has matured.

### 5.6 Accessibility — `A11yDoc` pivot

Primary sink: **pa11y JSON** (`artifacts:reports:accessibility`).

| Format | Read | Write | Notes |
|---|---|---|---|
| pa11y JSON | 🔜 | 🔜 | |
| Pa11y CI JSON | 🔜 | — | a **different** shape from plain pa11y (map keyed by URL) |
| axe-core JSON | 🔜 | — | `@axe-core/cli`, axe DevTools |
| Lighthouse JSON | 💭 | — | extract the `accessibility` category |
| HTML_CodeSniffer | 💭 | — | |
| EARL (W3C, RDF) | ❌ | ❌ | out of scope |

### 5.7 Performance — `PerfDoc` pivot

> A category missing from the initial specification, added here.

GitLab sinks: **sitespeed.io JSON** (`browser_performance`) and the **k6 JSON summary**
(`load_performance`).

| Format | Read | Write | Notes |
|---|---|---|---|
| sitespeed.io JSON | 💭 | 💭 | |
| k6 summary JSON | 💭 | 💭 | |
| Lighthouse JSON | 💭 | — | → sitespeed.io |
| JMeter JTL/XML | 💭 | — | → k6 |
| Gatling | 💭 | — | |

## 6. Code layout

```
src/
  main.rs              — entry point, orchestration, `udc formats`, styling
  cli.rs               — clap definitions
  error.rs             — the single error type
  detect.rs            — input format sniffing
  registry.rs          — static format table + `Doc` pivot enum + `Category`
  paths.rs             — path normalization (--source-root, --strip-prefix)
  warn.rs              — conversion notices (`lossy`/`degraded`), `FormatCtx` (+ --strict mode)
  xml.rs               — XML read helpers + indenting writer
  hash.rs              — FNV-1a 128-bit fingerprints (Code Climate fingerprints)
  model/
    coverage.rs        — CoverageDoc pivot
    findings.rs        — FindingsDoc pivot (quality + security)
    tests.rs           — TestReport pivot
  formats/
    coverage/{lcov,cobertura,jacoco}.rs
    quality/{checkstyle,codeclimate,sarif}.rs
    tests/junit.rs
tests/
  cli.rs               — end-to-end tests against the real binary
  conversion.rs        — fixture-driven conversion matrix (see below)
  support/mod.rs       — fixture discovery + schema validation
  fixtures/<format>/   — sample reports; `invalid/` holds what must be refused
  schemas/             — vendored DTD / XSD / JSON Schema, with provenance
```

### Fixtures and schema validation

Every format ships with sample reports under `tests/fixtures/<format-id>/`, and
every document the tool writes is validated against a schema **in the tests**.
The binary itself does not validate: that would charge every user runtime for a
guarantee the build already provides.

`tests/conversion.rs` reads each fixture with its format's reader, writes it out
in *every* writable format of the same category, and validates each output. It
enumerates nothing: formats come from `FORMATS`, fixtures from the directory
tree. Consequences:

- dropping a report into `tests/fixtures/<format-id>/` extends the matrix on its
  own — which is how a report that triggers a bug becomes a regression test;
- a file under `<format-id>/invalid/` documents what the reader must refuse;
- fixtures are themselves validated against their format's schema, so a sample
  no real tool could emit cannot creep in;
- `every_readable_format_has_a_fixture` and the exhaustive `schema_for()` make
  "a new format comes with fixtures and a validation decision" a build failure
  rather than a convention;
- `validation_rejects_documents_that_do_not_fit_the_schema` guards the harness
  against decaying into a no-op that always passes.

Schemas are vendored so the suite stays hermetic. XML goes through `xmllint`
(`--nonet`, never fetching the doctype's SYSTEM id); JSON through the
`jsonschema` crate. Where no schema exists — LCOV, Code Climate — the reason is
recorded explicitly, and LCOV is covered by a read-back round trip instead.

The **registry** is a static table of `FormatSpec { id, aliases, category, description,
write_notes, versions, default_version, read, write }`, and `registry::resolve` resolves a
`<format>[@<version>]` selector against it. Adding a format comes down to writing its module and
adding one entry. Category consistency between input and output is checked before anything is
read.

## 7. Distribution

- Targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`,
  `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.
- `udc-<os>-<arch>.tar.gz` / `.zip` archives attached to the GitHub release.
- `install.sh` (POSIX) and `install.ps1` (PowerShell): OS/arch detection, version resolution
  (`latest` by default, `--version vX.Y.Z` to pin), download, checksum verification, installation
  into a directory on `PATH`.
- Release automated by `semantic-release` (Conventional Commits); the release is created as a
  *draft* and published once every binary has been uploaded; the floating `vX` and `vX.Y` tags
  are moved.

## 8. Phasing

1. ✅ **Foundation** — CLI, registry, detection, pivots, path normalization, loss collector,
   CI/release, install scripts.
2. ✅ **Coverage** — LCOV, Cobertura, JaCoCo (the LCOV → Cobertura conversion validates the design
   end to end).
3. 🔜 **Tests** — JUnit done (tolerant reader + writer); TRX / `go test -json` / TAP remain.
4. ✅ **Quality** — Checkstyle (read), SARIF (read + write) and Code Climate (read + write,
   GitLab flavour included). A Checkstyle *writer* is deliberately not planned: nothing consumes
   Checkstyle that does not also read a better format. ESLint JSON next, if asked for.
5. 🔜 **Security** — SARIF → GitLab SAST done. Dependency and container scanning need the pivot
   to carry a versioned component, an image and an OS; that arrives with the Trivy and Grype
   readers, which is the order to do them in.
6. **SBOM** — CycloneDX ↔ SPDX.
7. **Accessibility, performance** — on demand.
