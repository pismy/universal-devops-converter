//! Istanbul JSON — `coverage-final.json`, produced by `nyc` and by Jest's
//! `json` coverage reporter.
//!
//! ```json
//! {
//!   "/abs/src/index.js": {
//!     "path": "/abs/src/index.js",
//!     "statementMap": { "0": { "start": { "line": 1, "column": 0 }, "end": … } },
//!     "fnMap":        { "0": { "name": "handler", "decl": { "start": { "line": 3 } } } },
//!     "branchMap":    { "0": { "type": "if", "loc": { "start": { "line": 5 } },
//!                              "locations": [ … , … ] } },
//!     "s": { "0": 4 }, "f": { "0": 2 }, "b": { "0": [1, 0] }
//!   }
//! }
//! ```
//!
//! The model is position-based rather than line-based: statements, functions
//! and branches are ranges with columns, and their counters live in separate
//! maps keyed by the same ids. Projecting onto the pivot means collapsing those
//! ranges to lines, and the rule matters — `istanbul-lib-coverage`'s own
//! `getLineCoverage()` keys each statement by `start.line` and keeps the
//! **highest** count among the statements starting there, so that is what this
//! reader does. Summing instead would inflate any line holding several
//! statements, which is most one-liners.
//!
//! **Read-only on purpose.** The pivot has no columns, so writing this format
//! would mean fabricating every `start`/`end` position. Istanbul's HTML
//! reporter highlights source using exactly those columns, so the output would
//! be structurally valid and visibly wrong. Nothing consumes Istanbul JSON that
//! does not also read LCOV, which the pivot can express honestly.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::model::coverage::{Branch, CoverageDoc, FileCoverage, Function, Line};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "istanbul";

#[derive(Debug, Deserialize)]
struct RawFile {
    #[serde(default)]
    path: Option<String>,
    #[serde(default, rename = "statementMap")]
    statement_map: HashMap<String, RawRange>,
    #[serde(default, rename = "fnMap")]
    fn_map: HashMap<String, RawFunction>,
    #[serde(default, rename = "branchMap")]
    branch_map: HashMap<String, RawBranch>,
    #[serde(default)]
    s: HashMap<String, u64>,
    #[serde(default)]
    f: HashMap<String, u64>,
    #[serde(default)]
    b: HashMap<String, Vec<u64>>,
}

#[derive(Debug, Default, Deserialize)]
struct RawRange {
    #[serde(default)]
    start: RawPosition,
}

#[derive(Debug, Default, Deserialize)]
struct RawPosition {
    /// Absent in practice for synthetic ranges, which is why it is optional
    /// rather than a hard parse error.
    #[serde(default)]
    line: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawFunction {
    #[serde(default)]
    name: Option<String>,
    /// The declaration itself — where a reader expects the function to be.
    #[serde(default)]
    decl: Option<RawRange>,
    /// The whole body. Used only when `decl` is missing.
    #[serde(default)]
    loc: Option<RawRange>,
    /// Emitted by older istanbul versions instead of `decl`.
    #[serde(default)]
    line: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RawBranch {
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    loc: Option<RawRange>,
    #[serde(default)]
    locations: Vec<RawRange>,
}

impl RawFunction {
    fn line(&self) -> Option<u32> {
        self.decl
            .as_ref()
            .and_then(|r| r.start.line)
            .or_else(|| self.loc.as_ref().and_then(|r| r.start.line))
            .or(self.line)
    }
}

impl RawBranch {
    fn line(&self) -> Option<u32> {
        self.line
            .or_else(|| self.loc.as_ref().and_then(|r| r.start.line))
            .or_else(|| self.locations.first().and_then(|r| r.start.line))
    }
}

pub fn read(input: &[u8], _ctx: &mut FormatCtx) -> Result<Doc> {
    let files: HashMap<String, RawFile> =
        serde_json::from_slice(input).map_err(|e| Error::parse(FORMAT, e))?;

    if files.is_empty() {
        return Err(Error::parse(
            FORMAT,
            "no file entries — this does not look like an Istanbul coverage map",
        ));
    }
    // An object of objects is not much of a fingerprint; require the one key
    // every entry has, so a random JSON document is rejected rather than read
    // as a coverage report with nothing in it.
    if !files.values().any(|f| !f.statement_map.is_empty()) {
        return Err(Error::parse(
            FORMAT,
            "no entry carries a `statementMap` — this does not look like an Istanbul coverage map",
        ));
    }

    let mut doc = CoverageDoc::default();
    for (key, raw) in files {
        let path = raw.path.clone().unwrap_or(key);
        doc.files.push(build(crate::paths::normalize(&path), raw));
    }
    doc.sort();
    Ok(Doc::Coverage(doc))
}

fn build(path: String, raw: RawFile) -> FileCoverage {
    let mut file = FileCoverage::new(path);

    // Statements: keep the highest count among those starting on a line, which
    // is how istanbul itself derives line coverage.
    let mut hits: BTreeMap<u32, u64> = BTreeMap::new();
    for (id, count) in &raw.s {
        let Some(line) = raw.statement_map.get(id).and_then(|r| r.start.line) else {
            continue;
        };
        let slot = hits.entry(line).or_insert(0);
        *slot = (*slot).max(*count);
    }

    // Branches, folded per line: several `if`s on one line contribute to the
    // same total, which is all the pivot can express.
    let mut branches: BTreeMap<u32, Branch> = BTreeMap::new();
    for (id, counts) in &raw.b {
        let Some(line) = raw.branch_map.get(id).and_then(RawBranch::line) else {
            continue;
        };
        let entry = branches.entry(line).or_default();
        entry.total += counts.len() as u32;
        entry.covered += counts.iter().filter(|c| **c > 0).count() as u32;
    }

    // A branch may sit on a line no statement starts on; it is still
    // executable, so union the two sets rather than iterating statements alone.
    let numbers: BTreeSet<u32> = hits.keys().chain(branches.keys()).copied().collect();
    for number in numbers {
        file.lines.push(Line {
            number,
            hits: hits.get(&number).copied().unwrap_or(0),
            branch: branches.get(&number).copied(),
        });
    }

    for (id, count) in &raw.f {
        let Some(function) = raw.fn_map.get(id) else {
            continue;
        };
        file.functions.push(Function {
            name: function
                .name
                .clone()
                .unwrap_or_else(|| format!("(anonymous_{id})")),
            signature: None,
            line: function.line(),
            hits: *count,
        });
    }

    file
}

#[cfg(test)]
mod tests {
    use super::*;

    const NYC: &str = r#"{
      "/home/runner/work/acme/acme/src/index.js": {
        "path": "/home/runner/work/acme/acme/src/index.js",
        "statementMap": {
          "0": { "start": { "line": 1, "column": 0 }, "end": { "line": 1, "column": 24 } },
          "1": { "start": { "line": 4, "column": 2 }, "end": { "line": 4, "column": 30 } },
          "2": { "start": { "line": 4, "column": 32 }, "end": { "line": 4, "column": 48 } },
          "3": { "start": { "line": 8, "column": 2 }, "end": { "line": 8, "column": 12 } }
        },
        "fnMap": {
          "0": {
            "name": "handler",
            "decl": { "start": { "line": 3, "column": 9 }, "end": { "line": 3, "column": 16 } },
            "loc": { "start": { "line": 3, "column": 25 }, "end": { "line": 9, "column": 1 } }
          }
        },
        "branchMap": {
          "0": {
            "type": "if",
            "loc": { "start": { "line": 6, "column": 2 }, "end": { "line": 7, "column": 3 } },
            "locations": [
              { "start": { "line": 6, "column": 2 } },
              { "start": { "line": 6, "column": 2 } }
            ]
          }
        },
        "s": { "0": 4, "1": 2, "2": 7, "3": 0 },
        "f": { "0": 4 },
        "b": { "0": [3, 0] }
      }
    }"#;

    fn parse(input: &str) -> CoverageDoc {
        let mut ctx = FormatCtx::new(None);
        match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Coverage(doc) => doc,
            _ => panic!("expected a coverage document"),
        }
    }

    #[test]
    fn collapses_positions_onto_lines() {
        let doc = parse(NYC);
        assert_eq!(doc.files.len(), 1);

        let file = &doc.files[0];
        assert_eq!(file.path, "/home/runner/work/acme/acme/src/index.js");
        // Lines 1, 4, 8 from statements, plus line 6 from the branch.
        assert_eq!(file.lines_valid(), 4);
        assert_eq!(file.lines_covered(), 2);
    }

    #[test]
    fn several_statements_on_one_line_keep_the_highest_count() {
        // Statements 1 and 2 both start on line 4, with counts 2 and 7.
        // istanbul's own getLineCoverage keeps the maximum; summing would
        // report 9 executions of a line that ran 7 times.
        let doc = parse(NYC);
        let line = doc.files[0].lines.iter().find(|l| l.number == 4).unwrap();
        assert_eq!(line.hits, 7);
    }

    #[test]
    fn reads_functions_from_their_declaration() {
        let file = &parse(NYC).files[0];
        assert_eq!(file.functions.len(), 1);
        assert_eq!(file.functions[0].name, "handler");
        // `decl` wins over `loc`: 3, not the body's start.
        assert_eq!(file.functions[0].line, Some(3));
        assert_eq!(file.functions[0].hits, 4);
    }

    #[test]
    fn a_branch_line_is_executable_even_with_no_statement() {
        let file = &parse(NYC).files[0];
        let line = file.lines.iter().find(|l| l.number == 6).unwrap();
        assert_eq!(line.hits, 0);
        assert_eq!(
            line.branch,
            Some(Branch {
                covered: 1,
                total: 2
            })
        );
        assert_eq!(
            file.branches(),
            Branch {
                covered: 1,
                total: 2
            }
        );
    }

    #[test]
    fn falls_back_to_the_map_key_when_there_is_no_path_field() {
        let doc = parse(
            r#"{"src/a.js":{"statementMap":{"0":{"start":{"line":1}}},"s":{"0":1},
                 "fnMap":{},"branchMap":{},"f":{},"b":{}}}"#,
        );
        assert_eq!(doc.files[0].path, "src/a.js");
    }

    #[test]
    fn tolerates_the_older_shape_that_puts_line_on_the_function() {
        let doc = parse(
            r#"{"a.js":{"statementMap":{"0":{"start":{"line":2}}},"s":{"0":1},
                 "fnMap":{"0":{"name":"f","line":2}},"f":{"0":3},
                 "branchMap":{},"b":{}}}"#,
        );
        assert_eq!(doc.files[0].functions[0].line, Some(2));
    }

    #[test]
    fn rejects_json_that_is_not_a_coverage_map() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(br#"{"hello":{"world":1}}"#, &mut ctx).is_err());
        assert!(read(b"{}", &mut ctx).is_err());
    }
}
