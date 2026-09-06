//! LCOV tracefile — the lingua franca of native, JS, Rust and Swift coverage
//! tooling, and the single most valuable *source* format of the project.
//!
//! Line grammar (only the records carrying data are consumed; totals such as
//! `LF`/`LH`/`BRF`/`BRH` are recomputed rather than trusted):
//!
//! ```text
//! SF:<path>                              start of a file record
//! DA:<line>,<hits>[,<checksum>]          line hit count
//! FN:<line>,<name> | FN:<start>,<end>,<name>
//! FNDA:<hits>,<name>
//! BRDA:<line>,<block>,<branch>,<taken>   taken is a count or `-`
//! end_of_record
//! ```

use std::collections::BTreeMap;
use std::io::Write;

use crate::error::{Error, Result};
use crate::model::coverage::{Branch, CoverageDoc, FileCoverage, Function, Line};
use crate::registry::Doc;
use crate::warn::FormatCtx;

const FORMAT: &str = "lcov";

#[derive(Default)]
struct FileAcc {
    lines: BTreeMap<u32, u64>,
    /// line → (block, branch) → times taken. Keyed by identity so the same
    /// branch appearing in several records is counted once.
    branches: BTreeMap<u32, BTreeMap<(u32, String), u64>>,
    functions: BTreeMap<String, FunctionAcc>,
}

#[derive(Default)]
struct FunctionAcc {
    line: Option<u32>,
    hits: u64,
}

pub fn read(input: &[u8], _ctx: &mut FormatCtx) -> Result<Doc> {
    let text = String::from_utf8_lossy(input);
    let mut files: BTreeMap<String, FileAcc> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut saw_record = false;

    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "end_of_record" {
            current = None;
            continue;
        }

        let Some((tag, value)) = line.split_once(':') else {
            // `TN:` with no value, stray text… not worth failing over.
            log::debug!("lcov:{}: ignoring unrecognized line '{line}'", number + 1);
            continue;
        };

        if tag == "SF" {
            let path = crate::paths::normalize(value.trim());
            if path.is_empty() {
                return Err(Error::parse(
                    FORMAT,
                    format!("empty SF: path on line {}", number + 1),
                ));
            }
            files.entry(path.clone()).or_default();
            current = Some(path);
            saw_record = true;
            continue;
        }

        // Every remaining data record belongs to the open SF block.
        let Some(path) = current.as_deref() else {
            continue;
        };
        let acc = files.get_mut(path).expect("SF entry created above");

        match tag {
            "DA" => {
                if let Some((line_no, hits)) = parse_da(value) {
                    *acc.lines.entry(line_no).or_insert(0) += hits;
                }
            }
            "FN" => {
                if let Some((line_no, name)) = parse_fn(value) {
                    acc.functions.entry(name).or_default().line = Some(line_no);
                }
            }
            "FNDA" => {
                if let Some((hits, name)) = parse_fnda(value) {
                    acc.functions.entry(name).or_default().hits += hits;
                }
            }
            "BRDA" => {
                if let Some((line_no, block, branch, taken)) = parse_brda(value) {
                    *acc.branches
                        .entry(line_no)
                        .or_default()
                        .entry((block, branch))
                        .or_insert(0) += taken;
                }
            }
            // Totals and metadata: recomputed or irrelevant.
            "TN" | "LF" | "LH" | "BRF" | "BRH" | "FNF" | "FNH" | "VER" => {}
            _ => log::debug!("lcov:{}: ignoring '{tag}' record", number + 1),
        }
    }

    if !saw_record {
        return Err(Error::parse(
            FORMAT,
            "no `SF:` record found — this does not look like an LCOV tracefile",
        ));
    }

    let mut doc = CoverageDoc::default();
    for (path, acc) in files {
        doc.files.push(build_file(path, acc));
    }
    doc.sort();
    Ok(Doc::Coverage(doc))
}

fn build_file(path: String, acc: FileAcc) -> FileCoverage {
    let mut file = FileCoverage::new(path);

    // A `BRDA` line that never appears in `DA` still describes an executable
    // line, so union the two sets rather than iterating over `DA` alone.
    let numbers: std::collections::BTreeSet<u32> = acc
        .lines
        .keys()
        .chain(acc.branches.keys())
        .copied()
        .collect();

    for number in numbers {
        let hits = acc.lines.get(&number).copied().unwrap_or(0);
        let branch = acc.branches.get(&number).map(|entries| Branch {
            covered: entries.values().filter(|taken| **taken > 0).count() as u32,
            total: entries.len() as u32,
        });
        file.lines.push(Line {
            number,
            hits,
            branch,
        });
    }

    for (name, function) in acc.functions {
        file.functions.push(Function {
            name,
            signature: None,
            line: function.line,
            hits: function.hits,
        });
    }
    file
}

fn parse_da(value: &str) -> Option<(u32, u64)> {
    let mut parts = value.split(',');
    let line = parts.next()?.trim().parse().ok()?;
    // Some producers emit a float hit count (`DA:3,1.0`); accept it.
    let raw = parts.next()?.trim();
    let hits = raw
        .parse::<u64>()
        .ok()
        .or_else(|| raw.parse::<f64>().ok().map(|h| h.max(0.0) as u64))?;
    Some((line, hits))
}

fn parse_fn(value: &str) -> Option<(u32, String)> {
    let parts: Vec<&str> = value.splitn(3, ',').collect();
    match parts.as_slice() {
        // LCOV 1.x: FN:<line>,<name>
        [line, name] => Some((line.trim().parse().ok()?, (*name).to_string())),
        // LCOV 2.x: FN:<start>,<end>,<name>
        [start, _end, name] => Some((start.trim().parse().ok()?, (*name).to_string())),
        _ => None,
    }
}

fn parse_fnda(value: &str) -> Option<(u64, String)> {
    let (hits, name) = value.split_once(',')?;
    Some((hits.trim().parse().ok()?, name.to_string()))
}

fn parse_brda(value: &str) -> Option<(u32, u32, String, u64)> {
    let parts: Vec<&str> = value.splitn(4, ',').collect();
    let [line, block, branch, taken] = parts.as_slice() else {
        return None;
    };
    let taken = match taken.trim() {
        "-" => 0,
        other => other.parse().ok()?,
    };
    Some((
        line.trim().parse().ok()?,
        block.trim().parse().ok()?,
        (*branch).to_string(),
        taken,
    ))
}

pub fn write(doc: &Doc, out: &mut dyn Write, ctx: &mut FormatCtx) -> Result<()> {
    let doc = doc.as_coverage()?;

    if doc.has_extra_counters() {
        ctx.lossy(
            "lcov: JaCoCo instruction/complexity/method counters have no LCOV equivalent and were dropped",
        );
    }
    if doc.has_branches() {
        ctx.degraded(
            "lcov: branch block/index identifiers were synthesized (the pivot only keeps covered/total per line)",
        );
    }

    for file in &doc.files {
        writeln!(out, "TN:")?;
        writeln!(out, "SF:{}", file.path)?;

        for function in &file.functions {
            if let Some(line) = function.line {
                writeln!(out, "FN:{line},{}", function.name)?;
            }
        }
        for function in &file.functions {
            writeln!(out, "FNDA:{},{}", function.hits, function.name)?;
        }
        if !file.functions.is_empty() {
            writeln!(out, "FNF:{}", file.functions.len())?;
            writeln!(
                out,
                "FNH:{}",
                file.functions.iter().filter(|f| f.hits > 0).count()
            )?;
        }

        for line in &file.lines {
            let Some(branch) = line.branch else { continue };
            for index in 0..branch.total {
                let taken = if index < branch.covered { "1" } else { "-" };
                writeln!(out, "BRDA:{},0,{index},{taken}", line.number)?;
            }
        }
        let branches = file.branches();
        if branches.total > 0 {
            writeln!(out, "BRF:{}", branches.total)?;
            writeln!(out, "BRH:{}", branches.covered)?;
        }

        for line in &file.lines {
            writeln!(out, "DA:{},{}", line.number, line.hits)?;
        }
        writeln!(out, "LF:{}", file.lines_valid())?;
        writeln!(out, "LH:{}", file.lines_covered())?;
        writeln!(out, "end_of_record")?;
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
TN:
SF:/builds/acme/src/main.rs
FN:10,main
FNDA:3,main
FNF:1
FNH:1
BRDA:12,0,0,2
BRDA:12,0,1,-
BRF:2
BRH:1
DA:10,3
DA:11,0
DA:12,3
LF:3
LH:2
end_of_record
";

    fn parse(input: &str) -> CoverageDoc {
        let mut ctx = FormatCtx::new(None);
        match read(input.as_bytes(), &mut ctx).unwrap() {
            Doc::Coverage(doc) => doc,
            _ => panic!("expected a coverage document"),
        }
    }

    #[test]
    fn reads_lines_branches_and_functions() {
        let doc = parse(SAMPLE);
        assert_eq!(doc.files.len(), 1);

        let file = &doc.files[0];
        assert_eq!(file.path, "/builds/acme/src/main.rs");
        assert_eq!(file.lines_valid(), 3);
        assert_eq!(file.lines_covered(), 2);
        assert_eq!(
            file.branches(),
            Branch {
                covered: 1,
                total: 2
            }
        );
        assert_eq!(file.functions.len(), 1);
        assert_eq!(file.functions[0].name, "main");
        assert_eq!(file.functions[0].hits, 3);
        assert_eq!(file.functions[0].line, Some(10));
    }

    #[test]
    fn accepts_the_lcov_2_three_field_fn_record() {
        let doc = parse("SF:a.rs\nFN:4,9,helper\nFNDA:1,helper\nDA:4,1\nend_of_record\n");
        assert_eq!(doc.files[0].functions[0].line, Some(4));
    }

    #[test]
    fn a_branch_only_line_still_counts_as_executable() {
        let doc = parse("SF:a.rs\nBRDA:7,0,0,-\nend_of_record\n");
        let line = &doc.files[0].lines[0];
        assert_eq!(line.number, 7);
        assert_eq!(line.hits, 0);
        assert_eq!(
            line.branch,
            Some(Branch {
                covered: 0,
                total: 1
            })
        );
    }

    #[test]
    fn rejects_input_without_any_file_record() {
        let mut ctx = FormatCtx::new(None);
        assert!(read(b"hello world\n", &mut ctx).is_err());
    }

    #[test]
    fn round_trips_through_the_writer() {
        let doc = parse(SAMPLE);
        let mut buffer = Vec::new();
        let mut ctx = FormatCtx::new(None);
        write(&Doc::Coverage(doc.clone()), &mut buffer, &mut ctx).unwrap();

        let again = parse(&String::from_utf8(buffer).unwrap());
        assert_eq!(again.files[0].lines, doc.files[0].lines);
        assert_eq!(again.files[0].functions, doc.files[0].functions);
    }
}
