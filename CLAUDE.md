# universal-devops-converter

Rust CLI (`udc`) that converts DevOps tool reports between equivalent formats —
coverage, tests, code quality today; security, SBOM, accessibility and
performance planned.

**[SPECS.md](SPECS.md) is the reference document.** Any functional change starts
there: it holds the category taxonomy, the format roadmap with per-format status,
the CLI contract and the design decisions. Keep it in sync with the code.

The binary is named `udc`; the crate is `universal-devops-converter`. Keep both
names intact — the install scripts, workflows and `.releaserc.json` all key off
them.

## Build & test

- `cargo build --release` — binary at `target/release/udc`
- `cargo test` — unit tests per module, end-to-end CLI tests in `tests/cli.rs`,
  and the fixture-driven conversion matrix in `tests/conversion.rs`
- `xmllint` (Debian/Ubuntu: `libxml2-utils`) is needed for XML schema
  validation; without it those checks skip locally and fail in CI
- `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` — enforced by CI

## Architecture

Conversion **never** goes format-to-format. Each report category owns a canonical
pivot model; formats contribute a reader (format → pivot), a writer
(pivot → format), or both. N formats therefore cost 2N implementations instead
of N², and cross-category conversion is impossible by construction.

- `src/registry.rs` — the single enumeration of formats. `FormatSpec { id,
  aliases, category, description, write_notes, versions, default_version, read,
  write }` in a static `FORMATS` table, plus the `Doc` pivot enum, `Category`,
  and `resolve()` for `<format>[@<version>]` selectors.
- `src/model/{coverage,findings,tests}.rs` — the pivot models. `findings` backs
  both the `quality` and (future) `security` categories.
- `src/formats/<category>/<format>.rs` — one module per format, aware of nothing
  but its own format and the pivot.
- `src/detect.rs` — `--input-format auto`. Sniffs the first 64 KiB.
- `src/paths.rs` — `--source-root` / `--strip-prefix` normalization.
- `src/warn.rs` — conversion notices (`lossy` / `degraded`) and `FormatCtx`,
  the per-format context carrying the target version and the notices.
- `src/xml.rs` — shared XML read helpers and a small indenting writer.
- `src/hash.rs` — FNV-1a 128 fingerprints for formats that require one.
- `src/main.rs` — orchestration, `udc formats`, styling.
- `src/lib.rs` — the crate is a library plus a thin binary, so integration tests
  can enumerate `FORMATS` and drive readers and writers directly. That is what
  lets the conversion matrix discover formats instead of listing them.

## Key design choices

- **Losses are reported, never silent.** A reader or writer that cannot carry
  something calls `ctx.lossy` (information dropped) or `ctx.degraded` (a value
  *rewritten* to stay valid for the target — a remapped enum member, an
  approximated counter). Both go to **stderr** (stdout may carry the report) and
  both count towards `--strict`. When adding a format, populate `write_notes` in
  the registry too — that is what `udc formats` shows.
- **Versions live on the format id, not in a separate option.**
  `cyclonedx-json@1.6`. `@` is the separator; **`:` is reserved** for a future
  category qualifier (`security:sarif` vs `quality:sarif`) and is explicitly
  rejected with a pointer to `@`. A format that declares no `versions` rejects
  the suffix rather than ignoring it. `default_version` is deliberately *not*
  "the newest": pick the version most consumers actually ingest. See SPECS.md
  §3.4 for which formats have real version breaks — SPDX 3.0 and SARIF 1.0 are
  different formats and get their own ids, not a version suffix.
- **Detection never guesses.** An ambiguous input (two array-shaped JSON formats,
  say) is an error telling the user to pass `--input-format`. `auto` exists on
  the input side only.
- **Deterministic output.** `Doc::sort()` runs before writing so the same input
  always yields byte-identical output. Test suites are the exception: their
  execution order is meaningful, so they are not sorted.
- **Path normalization is central.** Readers store paths as they find them;
  only `CoverageDoc::normalize_paths` and friends rewrite them, driven by
  `PathMapper`. Prefix stripping respects path-segment boundaries.
- **Tolerant readers, conservative writers.** Real-world reports are malformed
  in small ways (`line="?"`, missing attributes, mixed dialects); a reader skips
  what it cannot parse and only fails when the document is clearly not the format
  it claims to be. Writers emit the conservative common shape.
- **No DTD resolution.** `quick-xml` does not fetch external entities. This is
  deliberate: Cobertura reports carry a `SYSTEM` doctype, and a resolving parser
  would turn every conversion into a network call and every untrusted report into
  an XXE vector.

## Fixtures and schema validation — project rule

**Every format ships with fixtures, and everything the tool writes is validated
against a schema in the tests.** This is not a convention to remember: the suite
enforces it, and a format that skips either step fails the build.

- `tests/fixtures/<format-id>/` holds sample reports; `invalid/` under it holds
  reports the reader must refuse. The directory layout *is* the registration —
  `tests/conversion.rs` discovers formats from `FORMATS` and fixtures from the
  tree, so neither is ever hard-coded.
- Each fixture is read, converted to **every** writable format of its category,
  and each output is validated. Fixtures are themselves validated against their
  own format's schema, so a fixture no real tool could emit cannot sneak in.
- `every_readable_format_has_a_fixture` fails when a format has no sample.
- `schema_for()` in `tests/support/mod.rs` is exhaustive: a format with no entry
  panics. Declaring `Schema::None(<why>)` is a valid answer, an omission is not.
- `validation_rejects_documents_that_do_not_fit_the_schema` guards the harness
  itself — it proves the validators still reject bad input, so the matrix cannot
  decay into a no-op that always passes.
- Validation lives **only in the tests**. The binary does not validate its
  output: that would cost every user runtime for a guarantee the build already
  gives.
- Schemas are vendored in `tests/schemas/` with their provenance and licence, so
  the suite is hermetic. XML goes through `xmllint` (`--nonet`, never fetching
  the doctype's SYSTEM id); JSON through the `jsonschema` crate. When `xmllint`
  is missing, XML validation is skipped locally but
  `xmllint_is_available_in_ci` fails the build in CI.

This is also the debugging workflow: a report that triggers a bug becomes a
regression test by being dropped into `tests/fixtures/<format-id>/`.

## Adding a format

1. Write `src/formats/<category>/<name>.rs` with a `read` and/or `write` function
   matching `ReadFn` / `WriteFn`. Both receive a `&mut FormatCtx`: read the
   target version with `ctx.version()`, report notices with `ctx.lossy` /
   `ctx.degraded`.
2. Register it in `FORMATS` (`src/registry.rs`), including `write_notes`,
   `versions` and `default_version` (leave the last two empty/`None` when the
   format is not versioned).
3. Teach `src/detect.rs` to recognize it, or add it to the "recognized but not
   supported" list there if it stays read-only for now.
4. **Add fixtures** under `tests/fixtures/<name>/` — at least one per producer
   dialect worth distinguishing, plus what the reader must refuse in `invalid/`.
5. **Add its `schema_for()` entry**, vendoring the schema into `tests/schemas/`
   with its source URL and licence in that directory's README.
6. Unit-test the module (a round-trip test plus the format's quirks) and update
   the status table in SPECS.md and the summary table in README.md.

## Release

`semantic-release` on merge to `main` (Conventional Commits):
`release.yml` bumps `Cargo.toml`/`Cargo.lock`, writes `CHANGELOG.md`, tags
`vX.Y.Z` and creates a **draft** release; `publish-assets.yml` (triggered by the
tag push, which needs the `RELEASE_TOKEN` PAT to cascade) cross-compiles every
target, uploads each archive with its `.sha256`, and un-drafts the release only
once every platform succeeded. `.github/scripts/update-floating-tags.sh` moves
the `vX` / `vX.Y` tags.

Linux targets use **musl** so the binary is fully static.
