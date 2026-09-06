//! Pivot model for test reports.
//!
//! Shaped after the JUnit XML family, which is the only sink most platforms
//! accept — but deliberately kept a *superset* of the common denominator, so
//! richer sources (TRX, `go test -json`, Allure) can be added without
//! reshaping it.

use crate::paths::PathMapper;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Problem {
    pub message: Option<String>,
    /// Exception class or assertion type, when the source reports one.
    pub kind: Option<String>,
    /// Stack trace / long-form detail.
    pub detail: Option<String>,
}

/// A test case's result. `Failed` and `Errored` are kept distinct because
/// JUnit consumers treat them differently (assertion vs. crash).
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Passed,
    Skipped { message: Option<String> },
    Failed(Problem),
    Errored(Problem),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TestCase {
    pub name: String,
    pub classname: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub time: Option<f64>,
    pub outcome: Outcome,
    pub system_out: Option<String>,
    pub system_err: Option<String>,
}

impl TestCase {
    pub fn new(name: impl Into<String>, outcome: Outcome) -> Self {
        TestCase {
            name: name.into(),
            classname: None,
            file: None,
            line: None,
            time: None,
            outcome,
            system_out: None,
            system_err: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TestSuite {
    pub name: String,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub file: Option<String>,
    /// Wall-clock duration in seconds. `None` means "sum the cases".
    pub time: Option<f64>,
    pub properties: Vec<(String, String)>,
    pub cases: Vec<TestCase>,
    pub system_out: Option<String>,
    pub system_err: Option<String>,
}

impl TestSuite {
    pub fn new(name: impl Into<String>) -> Self {
        TestSuite {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn failures(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Failed(_)))
    }

    pub fn errors(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Errored(_)))
    }

    pub fn skipped(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Skipped { .. }))
    }

    fn count(&self, predicate: impl Fn(&Outcome) -> bool) -> usize {
        self.cases.iter().filter(|c| predicate(&c.outcome)).count()
    }

    /// Declared duration, or the sum of the cases when the suite has none.
    pub fn duration(&self) -> f64 {
        self.time
            .unwrap_or_else(|| self.cases.iter().filter_map(|c| c.time).sum())
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TestReport {
    pub name: Option<String>,
    pub suites: Vec<TestSuite>,
}

impl TestReport {
    pub fn total(&self) -> usize {
        self.suites.iter().map(|s| s.cases.len()).sum()
    }

    pub fn failures(&self) -> usize {
        self.suites.iter().map(TestSuite::failures).sum()
    }

    pub fn errors(&self) -> usize {
        self.suites.iter().map(TestSuite::errors).sum()
    }

    pub fn skipped(&self) -> usize {
        self.suites.iter().map(TestSuite::skipped).sum()
    }

    pub fn duration(&self) -> f64 {
        self.suites.iter().map(TestSuite::duration).sum()
    }

    /// Concatenate suites. Unlike coverage, test runs are not folded together:
    /// two suites with the same name are two distinct executions (sharded runs,
    /// retries) and collapsing them would lose results.
    pub fn merge(&mut self, other: TestReport) {
        self.name = self.name.take().or(other.name);
        self.suites.extend(other.suites);
    }

    pub fn normalize_paths(&mut self, mapper: &PathMapper) {
        if mapper.is_noop() {
            return;
        }
        for suite in &mut self.suites {
            suite.file = suite.file.as_deref().map(|p| mapper.map(p));
            for case in &mut suite.cases {
                case.file = case.file.as_deref().map(|p| mapper.map(p));
            }
        }
    }
}

#[cfg(test)]
// The pivot module is itself named `tests`; the inner module is the usual
// unit-test one, not a nesting mistake.
#[allow(clippy::module_inception)]
mod tests {
    use super::*;

    #[test]
    fn counts_outcomes_per_kind() {
        let mut suite = TestSuite::new("suite");
        suite.cases = vec![
            TestCase::new("ok", Outcome::Passed),
            TestCase::new("bad", Outcome::Failed(Problem::default())),
            TestCase::new("boom", Outcome::Errored(Problem::default())),
            TestCase::new("later", Outcome::Skipped { message: None }),
        ];
        assert_eq!(suite.failures(), 1);
        assert_eq!(suite.errors(), 1);
        assert_eq!(suite.skipped(), 1);
    }

    #[test]
    fn duration_falls_back_to_the_sum_of_cases() {
        let mut suite = TestSuite::new("suite");
        suite.cases = vec![
            TestCase {
                time: Some(1.5),
                ..TestCase::new("a", Outcome::Passed)
            },
            TestCase {
                time: Some(0.5),
                ..TestCase::new("b", Outcome::Passed)
            },
        ];
        assert_eq!(suite.duration(), 2.0);
        suite.time = Some(10.0);
        assert_eq!(suite.duration(), 10.0);
    }

    #[test]
    fn merge_keeps_same_named_suites_apart() {
        let mut a = TestReport {
            suites: vec![TestSuite::new("shard")],
            ..Default::default()
        };
        a.merge(TestReport {
            suites: vec![TestSuite::new("shard")],
            ..Default::default()
        });
        assert_eq!(a.suites.len(), 2);
    }
}
