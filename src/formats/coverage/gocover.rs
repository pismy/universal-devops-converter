//! Go coverage profile — what `go test -coverprofile=coverage.out` writes.
//!
//! ```text
//! mode: set
//! github.com/acme/proj/main.go:12.13,15.2 2 1
//! github.com/acme/proj/pkg/util.go:8.20,10.3 1 0
//! ```
//!
//! A header naming the counting mode, then one line per *basic block*:
//! `<file>:<startLine>.<startCol>,<endLine>.<endCol> <statements> <count>`.
//! In `set` mode the count is 0 or 1; in `count` and `atomic` it is the number
//! of executions.
//!
//! Two things make this format awkward, and both are handled explicitly rather
//! than quietly:
//!
//! - **Paths are import paths, not file paths.** `go test` writes
//!   `github.com/acme/proj/main.go`, which matches nothing in the repository
//!   tree. Platforms match report paths against that tree, so a conversion
//!   without `--strip-prefix github.com/acme/proj` produces a report showing no
//!   coverage at all. The reader cannot guess the module path — it is in
//!   `go.mod`, not in the profile — so it says so instead.
//! - **Blocks cover ranges, not lines.** A block spans `startLine..endLine`
//!   and counts *statements*, not lines. Without the Go source there is no way
//!   to tell which lines in that range are statements and which are blank
//!   lines, comments or closing braces, so every line in the range is marked
//!   and the approximation is reported.
//!
//! Read-only: writing a profile would mean inventing column positions and
//! statement counts, and the only consumer is `go tool cover`, which reads the
//! file Go itself just wrote.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::model::coverage::{CoverageDoc, FileCoverage, Line};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "go-coverprofile";

/// One parsed block line.
struct Block {
    file: String,
    start_line: u32,
    end_line: u32,
    count: u64,
}

pub fn read(input: &[u8], ctx: &mut FormatCtx) -> Result<Doc> {
    let text = String::from_utf8_lossy(input);
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"));

    let header = lines
        .next()
        .ok_or_else(|| Error::parse(FORMAT, "the profile is empty"))?;
    let mode = header.strip_prefix("mode:").map(str::trim).ok_or_else(|| {
        Error::parse(
            FORMAT,
            format!("expected a `mode:` header on the first line, found '{header}'"),
        )
    })?;
    if !matches!(mode, "set" | "count" | "atomic") {
        return Err(Error::parse(
            FORMAT,
            format!("unknown counting mode '{mode}' (expected set, count or atomic)"),
        ));
    }
    log::debug!("go coverage profile in '{mode}' mode");

    // `mode: set` records reached / not reached, so every covered line reports
    // exactly one hit. Downstream that reads as "ran once", which is all the
    // profile knows.
    if mode == "set" {
        ctx.degraded(
            "go-coverprofile: the profile was written in `set` mode, which records only whether \
             a block ran; every covered line reports a single hit",
        );
    }

    let mut files: BTreeMap<String, BTreeMap<u32, u64>> = BTreeMap::new();
    let mut spanned = false;

    for (number, line) in lines.enumerate() {
        let Some(block) = parse_block(line) else {
            log::debug!("go-coverprofile:{}: ignoring '{line}'", number + 2);
            continue;
        };
        spanned |= block.end_line > block.start_line;

        let entry = files.entry(block.file).or_default();
        for line_number in block.start_line..=block.end_line {
            // Two blocks can share a line — `} else {` ends one and starts
            // another. Keep the highest count rather than adding them, which
            // would report the line as running more often than it did.
            let slot = entry.entry(line_number).or_insert(0);
            *slot = (*slot).max(block.count);
        }
    }

    if files.is_empty() {
        return Err(Error::parse(
            FORMAT,
            "no coverage block after the `mode:` header",
        ));
    }
    if spanned {
        ctx.degraded(
            "go-coverprofile: blocks cover a line range and count statements, not lines; every \
             line of a block is marked, so blank lines, comments and closing braces inside it \
             are counted as executable",
        );
    }
    // Only worth saying when nothing will rewrite the paths: a run that already
    // passes --strip-prefix has addressed it, and warning anyway would fire on
    // correct usage — and fail it under --strict.
    if !ctx.path_rewriting_requested() && files.keys().any(|path| looks_like_import_path(path)) {
        ctx.lossy(
            "go-coverprofile: paths are Go import paths, not repository paths; pass \
             --strip-prefix <module path> or the platform will match none of them",
        );
    }

    let mut doc = CoverageDoc::default();
    for (path, hits) in files {
        let mut file = FileCoverage::new(crate::paths::normalize(&path));
        file.lines = hits
            .into_iter()
            .map(|(number, hits)| Line {
                number,
                hits,
                branch: None,
            })
            .collect();
        doc.files.push(file);
    }
    doc.sort();
    Ok(Doc::Coverage(doc))
}

/// A Go module path starts with a host, so its first segment carries a dot —
/// `github.com/acme/proj/main.go`. A repository-relative path does not.
fn looks_like_import_path(path: &str) -> bool {
    // More than one segment, and the first is a host. A bare `main.go` also has
    // a dot in its first (and only) segment, which is why the segment count
    // matters.
    let mut segments = path.split('/');
    let Some(first) = segments.next() else {
        return false;
    };
    segments.next().is_some() && first.contains('.')
}

/// `github.com/acme/proj/main.go:12.13,15.2 2 1`
fn parse_block(line: &str) -> Option<Block> {
    // From the right: the two trailing numbers are unambiguous, while the path
    // is whatever precedes them.
    let mut fields = line.rsplitn(3, char::is_whitespace);
    let count: u64 = fields.next()?.parse().ok()?;
    let _statements: u64 = fields.next()?.parse().ok()?;
    let located = fields.next()?;

    // Split at the last colon: an import path has none, but a Windows-style
    // absolute path would.
    let (file, span) = located.rsplit_once(':')?;
    let (start, end) = span.split_once(',')?;
    let start_line: u32 = start.split('.').next()?.parse().ok()?;
    let end_line: u32 = end.split('.').next()?.parse().ok()?;

    (!file.is_empty() && end_line >= start_line).then_some(Block {
        file: file.to_string(),
        start_line,
        end_line,
        count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "\
mode: set
github.com/acme/proj/main.go:12.13,15.2 2 1
github.com/acme/proj/main.go:18.2,18.16 1 0
github.com/acme/proj/pkg/util.go:8.20,10.3 1 1
";

    fn parse(input: &str) -> (CoverageDoc, crate::warn::Warnings) {
        let mut ctx = FormatCtx::new(None);
        let doc = match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Coverage(doc) => doc,
            _ => panic!("expected a coverage document"),
        };
        (doc, ctx.into_warnings())
    }

    #[test]
    fn expands_a_block_over_every_line_it_spans() {
        let (doc, _) = parse(PROFILE);
        assert_eq!(doc.files.len(), 2);

        let main = doc
            .files
            .iter()
            .find(|f| f.path.ends_with("main.go"))
            .unwrap();
        // 12..=15 covered, plus 18 uncovered.
        assert_eq!(main.lines_valid(), 5);
        assert_eq!(main.lines_covered(), 4);
        assert_eq!(main.lines.first().unwrap().number, 12);
        assert_eq!(main.lines.last().unwrap().number, 18);
    }

    #[test]
    fn overlapping_blocks_keep_the_highest_count() {
        // `} else {` ends one block and starts another on the same line.
        let (doc, _) = parse("mode: count\nx/a.go:5.2,7.3 2 4\nx/a.go:7.3,9.4 1 9\n");
        let line = doc.files[0].lines.iter().find(|l| l.number == 7).unwrap();
        assert_eq!(line.hits, 9);
    }

    #[test]
    fn says_that_import_paths_will_not_match_the_repository() {
        let (_, warnings) = parse(PROFILE);
        assert!(warnings.messages().any(|m| m.contains("--strip-prefix")));
    }

    #[test]
    fn stays_quiet_when_the_run_already_rewrites_paths() {
        let mut ctx = FormatCtx::new(None);
        ctx.set_path_rewriting(true);
        read(PROFILE.as_bytes(), &mut ctx).unwrap();
        assert!(
            !ctx.warnings()
                .messages()
                .any(|m| m.contains("--strip-prefix")),
            "warned about paths the user has already dealt with"
        );
    }

    #[test]
    fn a_relative_path_is_not_mistaken_for_an_import_path() {
        assert!(looks_like_import_path("github.com/acme/proj/main.go"));
        assert!(!looks_like_import_path("internal/engine/engine.go"));
        assert!(!looks_like_import_path("main.go"));
    }

    #[test]
    fn admits_the_range_approximation_and_the_set_mode() {
        let (_, warnings) = parse(PROFILE);
        assert!(warnings.messages().any(|m| m.contains("closing braces")));
        assert!(warnings.messages().any(|m| m.contains("`set` mode")));
    }

    #[test]
    fn count_mode_carries_real_execution_counts() {
        let (doc, warnings) = parse("mode: count\nx/a.go:1.1,1.10 1 37\n");
        assert_eq!(doc.files[0].lines[0].hits, 37);
        assert!(!warnings.messages().any(|m| m.contains("`set` mode")));
    }

    #[test]
    fn rejects_a_profile_without_a_mode_header() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"x/a.go:1.1,1.10 1 1\n", &mut ctx).is_err());
    }

    #[test]
    fn rejects_an_unknown_mode() {
        let mut ctx = FormatCtx::new(None);
        let error = read(b"mode: sideways\nx/a.go:1.1,1.2 1 1\n", &mut ctx)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown counting mode"), "{error}");
    }

    #[test]
    fn rejects_a_header_with_no_blocks() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"mode: set\n", &mut ctx).is_err());
    }
}
