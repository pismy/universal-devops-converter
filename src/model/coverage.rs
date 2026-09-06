//! Pivot model for code coverage reports.
//!
//! Designed as the union of what LCOV, Cobertura and JaCoCo can express:
//!
//! - per-line **hit counts** (LCOV, Cobertura). JaCoCo has no hit counter, so
//!   it degrades to 0/1 and the writer reports the loss.
//! - per-line **branch coverage** as covered/total. LCOV additionally
//!   identifies each branch by block+index; that identity is not preserved,
//!   as neither Cobertura nor JaCoCo can express it.
//! - **functions/methods** with an optional hit count.
//! - JaCoCo's extra **counters** (instruction, complexity, method, class),
//!   carried through when present so a JaCoCo → JaCoCo round-trip is faithful.

use std::collections::BTreeMap;

use crate::paths::PathMapper;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Branch {
    pub covered: u32,
    pub total: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub number: u32,
    pub hits: u64,
    /// `None` when the line holds no branch (as opposed to a fully covered one).
    pub branch: Option<Branch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    /// JVM descriptor / language signature, when the source format has one.
    pub signature: Option<String>,
    pub line: Option<u32>,
    pub hits: u64,
}

/// A JaCoCo-style `missed`/`covered` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counter {
    pub missed: u64,
    pub covered: u64,
}

impl Counter {
    pub fn total(&self) -> u64 {
        self.missed + self.covered
    }
}

/// Counters that only JaCoCo carries. All optional: a writer that needs them
/// must either approximate (and warn) or drop them (and warn).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    pub instruction: Option<Counter>,
    pub complexity: Option<Counter>,
    pub method: Option<Counter>,
    pub class: Option<Counter>,
}

impl Counters {
    fn merge(&mut self, other: &Counters) {
        fn add(target: &mut Option<Counter>, extra: Option<Counter>) {
            if let Some(extra) = extra {
                let slot = target.get_or_insert(Counter::default());
                slot.missed += extra.missed;
                slot.covered += extra.covered;
            }
        }
        add(&mut self.instruction, other.instruction);
        add(&mut self.complexity, other.complexity);
        add(&mut self.method, other.method);
        add(&mut self.class, other.class);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileCoverage {
    /// Repository-relative path, `/`-separated. Normalization happens in
    /// [`CoverageDoc::normalize_paths`], never in the readers.
    pub path: String,
    pub lines: Vec<Line>,
    pub functions: Vec<Function>,
    pub counters: Counters,
}

impl FileCoverage {
    pub fn new(path: impl Into<String>) -> Self {
        FileCoverage {
            path: path.into(),
            ..Default::default()
        }
    }

    /// Dotted package name derived from the file's directory, e.g.
    /// `src/main/java/com/acme/App.java` → `src.main.java.com.acme`.
    /// Cobertura and JaCoCo both need a package grouping that LCOV lacks.
    pub fn package(&self) -> String {
        match self.path.rfind('/') {
            Some(idx) => self.path[..idx].replace('/', "."),
            None => String::new(),
        }
    }

    /// Directory part, `/`-separated (JaCoCo package naming).
    pub fn directory(&self) -> &str {
        match self.path.rfind('/') {
            Some(idx) => &self.path[..idx],
            None => "",
        }
    }

    pub fn file_name(&self) -> &str {
        match self.path.rfind('/') {
            Some(idx) => &self.path[idx + 1..],
            None => &self.path,
        }
    }

    /// File name without its extension — the closest thing to a class name
    /// available when converting from a file-oriented format.
    pub fn stem(&self) -> &str {
        let name = self.file_name();
        match name.rfind('.') {
            Some(idx) if idx > 0 => &name[..idx],
            _ => name,
        }
    }

    pub fn lines_valid(&self) -> u64 {
        self.lines.len() as u64
    }

    pub fn lines_covered(&self) -> u64 {
        self.lines.iter().filter(|l| l.hits > 0).count() as u64
    }

    pub fn branches(&self) -> Branch {
        self.lines
            .iter()
            .filter_map(|l| l.branch)
            .fold(Branch::default(), |mut acc, b| {
                acc.covered += b.covered;
                acc.total += b.total;
                acc
            })
    }

    pub fn has_branches(&self) -> bool {
        self.lines.iter().any(|l| l.branch.is_some())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageDoc {
    /// Unix timestamp of the run, when the source format records one.
    pub timestamp: Option<i64>,
    /// Source roots the paths are relative to (Cobertura `<sources>`).
    pub source_roots: Vec<String>,
    pub files: Vec<FileCoverage>,
}

impl CoverageDoc {
    pub fn lines_valid(&self) -> u64 {
        self.files.iter().map(FileCoverage::lines_valid).sum()
    }

    pub fn lines_covered(&self) -> u64 {
        self.files.iter().map(FileCoverage::lines_covered).sum()
    }

    pub fn branches(&self) -> Branch {
        self.files
            .iter()
            .map(FileCoverage::branches)
            .fold(Branch::default(), |mut acc, b| {
                acc.covered += b.covered;
                acc.total += b.total;
                acc
            })
    }

    pub fn line_rate(&self) -> f64 {
        rate(self.lines_covered(), self.lines_valid())
    }

    pub fn branch_rate(&self) -> f64 {
        let b = self.branches();
        rate(u64::from(b.covered), u64::from(b.total))
    }

    pub fn has_branches(&self) -> bool {
        self.files.iter().any(FileCoverage::has_branches)
    }

    /// Whether any file carries JaCoCo-only counters. Writers use this to
    /// decide whether they are dropping real data or merely not emitting
    /// something that never existed.
    pub fn has_extra_counters(&self) -> bool {
        self.files.iter().any(|f| {
            f.counters.instruction.is_some()
                || f.counters.complexity.is_some()
                || f.counters.method.is_some()
                || f.counters.class.is_some()
        })
    }

    /// Fold another document in, summing hit counts for files and lines seen
    /// twice. Backs the repeatable `--input-file`.
    pub fn merge(&mut self, other: CoverageDoc) {
        self.timestamp = self.timestamp.or(other.timestamp);
        for root in other.source_roots {
            if !self.source_roots.contains(&root) {
                self.source_roots.push(root);
            }
        }
        for incoming in other.files {
            match self.files.iter_mut().find(|f| f.path == incoming.path) {
                Some(existing) => merge_file(existing, incoming),
                None => self.files.push(incoming),
            }
        }
    }

    pub fn normalize_paths(&mut self, mapper: &PathMapper) {
        if mapper.is_noop() {
            return;
        }
        for file in &mut self.files {
            file.path = mapper.map(&file.path);
        }
        // Rewriting can make two entries collide (two absolute build paths
        // pointing at the same source): fold them instead of emitting the file
        // twice, which most consumers reject.
        let folded = std::mem::take(&mut self.files);
        for file in folded {
            match self.files.iter_mut().find(|f| f.path == file.path) {
                Some(existing) => merge_file(existing, file),
                None => self.files.push(file),
            }
        }
    }

    /// Deterministic ordering, so a conversion is byte-stable across runs.
    pub fn sort(&mut self) {
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
        for file in &mut self.files {
            file.lines.sort_by_key(|l| l.number);
            file.functions
                .sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.name.cmp(&b.name)));
        }
    }
}

fn merge_file(existing: &mut FileCoverage, incoming: FileCoverage) {
    let mut lines: BTreeMap<u32, Line> = existing.lines.drain(..).map(|l| (l.number, l)).collect();
    for line in incoming.lines {
        lines
            .entry(line.number)
            .and_modify(|slot| {
                slot.hits += line.hits;
                slot.branch = match (slot.branch, line.branch) {
                    (Some(a), Some(b)) => Some(Branch {
                        // Same line, same branch structure: keep the widest
                        // total and the best coverage seen.
                        covered: a.covered.max(b.covered),
                        total: a.total.max(b.total),
                    }),
                    (a, b) => a.or(b),
                };
            })
            .or_insert(line);
    }
    existing.lines = lines.into_values().collect();

    for function in incoming.functions {
        match existing
            .functions
            .iter_mut()
            .find(|f| f.name == function.name && f.line == function.line)
        {
            Some(slot) => slot.hits += function.hits,
            None => existing.functions.push(function),
        }
    }
    existing.counters.merge(&incoming.counters);
}

/// Coverage ratio in `[0, 1]`. An empty denominator is reported as fully
/// covered, matching what Cobertura and JaCoCo consumers expect for a file
/// with no executable line.
pub fn rate(covered: u64, valid: u64) -> f64 {
    if valid == 0 {
        1.0
    } else {
        covered as f64 / valid as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(number: u32, hits: u64) -> Line {
        Line {
            number,
            hits,
            branch: None,
        }
    }

    #[test]
    fn derives_package_and_stem_from_path() {
        let file = FileCoverage::new("src/main/java/com/acme/App.java");
        assert_eq!(file.package(), "src.main.java.com.acme");
        assert_eq!(file.directory(), "src/main/java/com/acme");
        assert_eq!(file.file_name(), "App.java");
        assert_eq!(file.stem(), "App");

        let root = FileCoverage::new("main.rs");
        assert_eq!(root.package(), "");
        assert_eq!(root.directory(), "");
        assert_eq!(root.stem(), "main");
    }

    #[test]
    fn merge_sums_hits_for_shared_lines() {
        let mut a = CoverageDoc::default();
        let mut fa = FileCoverage::new("a.rs");
        fa.lines = vec![line(1, 1), line(2, 0)];
        a.files.push(fa);

        let mut b = CoverageDoc::default();
        let mut fb = FileCoverage::new("a.rs");
        fb.lines = vec![line(2, 3), line(3, 1)];
        b.files.push(fb);

        a.merge(b);
        a.sort();

        assert_eq!(a.files.len(), 1);
        let lines = &a.files[0].lines;
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1].hits, 3);
        // Line 2 was uncovered in the first document and covered in the second:
        // merging makes it covered, which is the whole point of merging shards.
        assert_eq!(a.lines_covered(), 3);
        assert_eq!(a.lines_valid(), 3);
    }

    #[test]
    fn empty_denominator_rates_as_fully_covered() {
        assert_eq!(rate(0, 0), 1.0);
        assert_eq!(rate(1, 2), 0.5);
    }
}
