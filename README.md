<img alt="universal-devops-converter logo" src="./logo.png" width="88" align="right">

# universal-devops-converter

[![CI](https://github.com/pismy/universal-devops-converter/actions/workflows/ci.yml/badge.svg)](https://github.com/pismy/universal-devops-converter/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/pismy/universal-devops-converter?sort=semver)](https://github.com/pismy/universal-devops-converter/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Convert DevOps tool reports between equivalent formats.** One small static
binary, `udc`.

## The problem

CI/CD platforms accept **one format per report type**. The ecosystem produces
dozens. So the tool you want and the platform you use routinely disagree:

| You run                                        | It emits       | Your platform wants                        |
| ---------------------------------------------- | -------------- | ------------------------------------------ |
| `cargo llvm-cov`, `nyc`, `gcov`, `pytest-cov`  | LCOV           | Cobertura                                  |
| JaCoCo, Gradle, Maven                          | JaCoCo XML     | Cobertura                                  |
| ESLint, golangci-lint, PHP_CodeSniffer, ktlint | Checkstyle XML | Code Climate JSON                          |
| semgrep, CodeQL, gosec, bandit, Checkov        | SARIF          | Code Climate JSON / GitLab Security Report |
| `dotnet test`, Cypress, Cucumber               | TRX, JSON, …   | JUnit XML                                  |

The usual workarounds are a fragile `sed` pipeline, a Python script nobody
maintains, or giving up on the report. `udc` is the boring alternative:

```console
$ cargo llvm-cov --lcov --output-path lcov.info
$ udc -i lcov.info -t cobertura -o coverage.xml --source-root "$PWD"
```

## Why this one

- **Single static binary.** No runtime, no interpreter, no dependency. `musl`
  on Linux, so it runs in `scratch`, `alpine` and every minimal runner image.
  Under 2 MB.
- **Honest about loss.** Formats do not carry the same information. Whatever
  the target cannot express is reported on stderr — `lossy:` when information
  is dropped, `degraded:` when a value had to be rewritten to stay
  schema-valid — and `--strict` turns either into a failed job.
- **Never guesses.** Format detection refuses ambiguous input rather than
  silently producing a wrong report.
- **Deterministic.** The same input always produces byte-identical output, so
  reports diff cleanly and caches stay warm.
- **Fixes paths.** The single most common reason a converted coverage report
  shows 0% — see [Troubleshooting](#troubleshooting).

## Install

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/pismy/universal-devops-converter/main/install.sh | sh
```

```powershell
# Windows
irm https://raw.githubusercontent.com/pismy/universal-devops-converter/main/install.ps1 | iex
```

Both scripts detect the OS and architecture, verify the published SHA-256
checksum and install the binary. Options:

```sh
curl -fsSL .../install.sh | sh -s -- --version v1.2.3 --install-dir ~/.local/bin
```

| Option                | Environment variable | Default                                           |
| --------------------- | -------------------- | ------------------------------------------------- |
| `--version <TAG>`     | `UDC_VERSION`        | `latest`                                          |
| `--install-dir <DIR>` | `UDC_INSTALL_DIR`    | `/usr/local/bin` if writable, else `~/.local/bin` |
| `--no-verify`         | —                    | checksum is verified                              |

Resolving `latest` reads GitHub's redirect rather than its API, so it does not
spend the unauthenticated rate limit. `GITHUB_TOKEN` is only consulted if that
lookup has to fall back to the API — which the PowerShell script always does.

Archives are attached to every
[release](https://github.com/pismy/universal-devops-converter/releases). From
source, all you need is a Rust toolchain:

```sh
cargo install --git https://github.com/pismy/universal-devops-converter
```

## Usage

```
udc [OPTIONS]                     # convert (the default mode)
udc formats [--category <CAT>]    # list formats and what each one loses
```

| Option                                | Default      | Description                                                           |
| ------------------------------------- | ------------ | --------------------------------------------------------------------- |
| `-i`, `--input-file <PATH>`           | `-` (stdin)  | Input file. **Repeatable** — see [Merging](#merging-several-reports). |
| `-o`, `--output-file <PATH>`          | `-` (stdout) | Output file.                                                          |
| `-f`, `--input-format <FMT>[@<VER>]`  | `auto`       | Input format, or `auto` to detect it.                                 |
| `-t`, `--output-format <FMT>[@<VER>]` | *required*   | Output format. `auto` is not accepted.                                |
| `--source-root <PATH>`                | —            | Make absolute paths under this root repository-relative.              |
| `--strip-prefix <PREFIX>`             | —            | Strip a literal path prefix. Repeatable.                              |
| `--strict`                            | off          | Fail instead of warning when the conversion loses information.        |
| `-v`, `--verbose`                     | off          | Debug logging. `RUST_LOG` overrides it.                               |
| `--no-color`                          | off          | Disable colors. `NO_COLOR` is honoured too.                           |

Every option can also be set through its `UDC_*` environment variable
(`UDC_INPUT_FILE`, `UDC_OUTPUT_FORMAT`, `UDC_SOURCE_ROOT`, `UDC_STRICT`, …),
which is often the tidier way to configure a CI job.

| Exit code | Meaning                                                                    |
| --------- | -------------------------------------------------------------------------- |
| `0`       | Conversion succeeded                                                       |
| `1`       | Runtime error: parse failure, impossible conversion, loss under `--strict` |
| `2`       | Usage error: unknown option, bad argument                                  |

### Examples

```sh
# LCOV from any language → the Cobertura report GitLab ingests
udc -i lcov.info -t cobertura -o coverage.xml --source-root "$PWD"

# JaCoCo → Cobertura, straight from a pipe
cat build/reports/jacoco.xml | udc -f jacoco -t cobertura -o coverage.xml

# Any linter with a Checkstyle reporter → GitLab Code Quality
eslint -f checkstyle . | udc -f checkstyle -t codeclimate-gitlab -o gl-code-quality.json

# SARIF (semgrep, CodeQL, gosec…) → GitLab Code Quality
semgrep --sarif | udc -f sarif -t codeclimate-gitlab -o gl-code-quality.json

# Merge sharded test runs into a single JUnit report
udc -i results/shard1.xml -i results/shard2.xml -t junit -o junit.xml

# Fail the job rather than hand the platform a degraded report
udc -i lcov.info -t jacoco --strict
```

### Merging several reports

`--input-file` is repeatable, and the merge follows each category's semantics:

- **Coverage** folds by file: hit counts are summed and line sets unioned, so a
  line uncovered in one shard and covered in another ends up covered. This is
  what you want for parallelised or matrix builds.
- **Tests** concatenates suites without folding them: two suites with the same
  name are two executions (shards, retries), and collapsing them would lose
  results.
- **Quality** concatenates findings and drops exact duplicates, which overlapping
  linter runs produce routinely.

Inputs may even be in **different formats** — detection runs per file, so they
only have to belong to the same category:

```sh
# a JaCoCo backend report and an LCOV frontend report, merged into one Cobertura file
udc -i backend/jacoco.xml -i frontend/lcov.info -t cobertura -o coverage.xml
```

That only works with `--input-format auto` (the default): an explicit `-f`
applies to every input.

### Spec versions

Formats that exist in several specification versions take an optional
`@<version>` suffix. Today SARIF is the only one; the syntax is in place for
CycloneDX and SPDX when SBOM support lands:

```sh
semgrep --sarif | udc -f sarif@2.1.0 -t codeclimate-gitlab -o gl-code-quality.json
```

Without a suffix the format's **default version** is used — deliberately the
most widely ingested one rather than the newest, because a report the platform
rejects is worse than one missing a recent field. An unversioned format rejects
the suffix instead of ignoring it, and `:` is reserved for a future category
qualifier (`security:sarif` vs `quality:sarif`):

```console
$ udc -t junit@1.0
error: format 'junit' is not versioned: drop the '@1.0' suffix

$ udc -t sarif:2.1.0
error: 'sarif:2.1.0': ':' is reserved for a future category qualifier.
       Use 'sarif@2.1.0' to pin a spec version.
```

Version breaks that are really *model* breaks — SPDX 3.0, SARIF 1.0 — get their
own format id rather than a version suffix. [SPECS.md §3.4](SPECS.md) explains
which is which and why.

## Supported formats

`udc formats` is the authoritative list, and it tells you what each writer
gives up:

```console
$ udc formats --category coverage
Any format readable in a category can be converted to any writable format of the same
category. `r` = can be read (input), `w` = can be written (output).
A versioned format accepts a `@<version>` suffix, e.g. `-t sarif@2.1.0`.

COVERAGE
  lcov       rw  LCOV tracefile (gcov, nyc/istanbul, cargo-llvm-cov, tarpaulin)
                 aliases: lcov-info
                 degraded: branch block/index identity is synthesized
                 lossy: JaCoCo instruction/complexity/method counters are dropped
  cobertura  rw  Cobertura XML — the coverage format GitLab CI ingests
                 aliases: coverage.py
                 lossy: JaCoCo instruction/complexity/method counters are dropped
  jacoco     rw  JaCoCo XML report
                 degraded: hit counts are flattened to covered/not-covered (JaCoCo has no hit counter)
                 degraded: instruction counters are approximated when the source has none
```

Today:

| Category     | Read                            | Write                               |
| ------------ | ------------------------------- | ----------------------------------- |
| **Coverage** | LCOV, Cobertura, JaCoCo         | LCOV, Cobertura, JaCoCo             |
| **Tests**    | JUnit XML                       | JUnit XML                           |
| **Quality**  | Checkstyle, SARIF, Code Climate | Code Climate, Code Climate (GitLab) |

Any readable format converts to any writable format **of the same category**.
Converting a Checkstyle report into Cobertura is an error, not a best-effort
guess. Security, SBOM, accessibility and performance are on the roadmap — see
[SPECS.md §5](SPECS.md).

## In CI

### GitLab

Convert in **`after_script`**, not in `script`. `after_script` runs whether the
job succeeded or failed, so the analysis tool keeps its normal exit code — a
failing lint or a failing test suite fails the job, as it should — while the
report still gets converted and published. `artifacts:when: always` is what
makes the report survive the failure.

```yaml
coverage:
  script:
    - cargo llvm-cov --lcov --output-path lcov.info
  after_script:
    - curl -fsSL https://raw.githubusercontent.com/pismy/universal-devops-converter/main/install.sh | sh -s -- --version v1.0.0
    - udc -i lcov.info -t cobertura -o coverage.xml --source-root "$CI_PROJECT_DIR"
  artifacts:
    when: always
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml

code_quality:
  script:
    # No `|| true`: ESLint fails the job on lint errors…
    - eslint -f checkstyle . > checkstyle.xml
  after_script:
    # …and the report is published either way, because the redirect above wrote
    # checkstyle.xml before ESLint exited non-zero.
    - curl -fsSL https://raw.githubusercontent.com/pismy/universal-devops-converter/main/install.sh | sh -s -- --version v1.0.0
    - udc -i checkstyle.xml -t codeclimate-gitlab -o gl-code-quality.json
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality.json
```

Three things worth knowing about this pattern:

- **`after_script` runs in a separate shell.** Anything `script` exported is
  gone; predefined variables such as `$CI_PROJECT_DIR` are still there, which is
  why the `--source-root` above works.
- **GitLab ignores the `after_script` exit code.** A failed install or a broken
  conversion leaves you with no report rather than a red job, so keep an eye on
  the job log — or move both back into `script` when you would rather they be
  blocking.
- **Pin the version.** It keeps the job reproducible: `latest` moves under you,
  and a pipeline that changes behaviour because a release happened is a pipeline
  you cannot bisect. Either the `--version` option or the `UDC_VERSION`
  environment variable. It also skips the release lookup entirely, which is one
  fewer network call that can fail.

### GitHub Actions

```yaml
- name: Install udc
  run: curl -fsSL https://raw.githubusercontent.com/pismy/universal-devops-converter/main/install.sh | sh
  env:
    GITHUB_TOKEN: ${{ github.token }}
    UDC_VERSION: v1.0.0

- name: Test with coverage
  run: cargo llvm-cov --lcov --output-path lcov.info

# Publish the report even when the previous step failed.
- name: Normalize the coverage report
  if: always()
  run: udc -i lcov.info -t cobertura -o coverage.xml --source-root "$GITHUB_WORKSPACE"
```

## Troubleshooting

### The converted coverage report shows 0%, or no annotations appear

Almost always a **path mismatch**, not a conversion bug. Platforms match a
report's file paths against the repository tree; LCOV records the build
machine's absolute paths (`/builds/acme/proj/src/main.rs`) and JaCoCo only
stores `package` + `sourcefile`. Neither is repository-relative.

Look at what came out:

```console
$ grep filename coverage.xml | head -1
<class name=".builds.acme.proj.src.main" filename="/builds/acme/proj/src/main.rs" …>
```

If the path is not what the platform would see from the repository root, fix it:

```sh
udc -i lcov.info -t cobertura -o coverage.xml --source-root "$CI_PROJECT_DIR"
```

`--strip-prefix` handles the cases `--source-root` cannot — a monorepo
sub-project, a container path that does not match the checkout:

```sh
udc -i lcov.info -t cobertura --strip-prefix /app --strip-prefix packages/api
```

Prefixes are tried in order and the first match wins; stripping only happens on
a path-segment boundary, so `--strip-prefix src/app` never mangles
`src/apple/main.rs`.

### `error: cannot detect the input format`

Detection found nothing conclusive, or the input is ambiguous — a bare JSON
array could be Code Climate or pa11y. Pass `-f` explicitly. This is by design:
guessing wrong produces a plausible-looking but incorrect report.

### `error: cannot convert a quality report into a coverage report`

Conversion only exists within a category. Check `udc formats` for the category
each format belongs to.

### The conversion warns and I want it to fail

```sh
udc -i lcov.info -t jacoco --strict
```

Both `lossy:` and `degraded:` notices count. Run without `--strict` first to see
what you would be enforcing.

## How it works

Formats never see each other. Each category has a **canonical pivot model**; a
format contributes a *reader* (format → pivot), a *writer* (pivot → format), or
both.

```
   lcov ─┐                                  ┌─→ cobertura
 jacoco ─┼─→ [ CoverageDoc ] ───────────────┼─→ jacoco
cobertura┘                                  └─→ lcov
```

That keeps the implementation at 2N instead of N², makes cross-category
conversion impossible by construction, and gives losses a single place to be
detected and reported.

Reading is done with a parser that does **not** resolve external DTDs or
entities. That is deliberate: Cobertura reports carry a `SYSTEM` doctype, and a
resolving parser would turn every conversion into a network call and every
untrusted report into an XXE vector.

[SPECS.md](SPECS.md) is the design document: category taxonomy, format roadmap
with per-format status, the CLI contract, and the reasoning behind each choice.

## Development

```sh
cargo test                                  # unit + end-to-end tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Adding a format means writing one module under `src/formats/<category>/` and
adding one entry to `FORMATS` in `src/registry.rs`. Nothing else in the codebase
enumerates formats. See [CLAUDE.md](CLAUDE.md) for the conventions.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/);
the release, changelog and binaries are produced by `semantic-release` on merge
to `main`.

## License

MIT — see [LICENSE](LICENSE).
