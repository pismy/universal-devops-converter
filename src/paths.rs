//! Path normalization — one of the tool's main practical values.
//!
//! Report formats disagree on what a path is: LCOV records the build machine's
//! absolute path, JaCoCo only stores `package` + `sourcefile`, Cobertura splits
//! the root into `<sources>`. Platforms, on the other hand, want a single
//! thing: a path **relative to the repository root**, `/`-separated. Getting
//! this wrong is the classic reason a converted coverage report shows 0%.

/// Rewrites file paths according to `--source-root` and `--strip-prefix`.
#[derive(Debug, Default, Clone)]
pub struct PathMapper {
    source_root: Option<String>,
    strip_prefixes: Vec<String>,
}

impl PathMapper {
    pub fn new(source_root: Option<&str>, strip_prefixes: &[String]) -> Self {
        PathMapper {
            source_root: source_root.map(|r| trim_trailing_slash(&normalize(r))),
            strip_prefixes: strip_prefixes
                .iter()
                .map(|p| trim_trailing_slash(&normalize(p)))
                .filter(|p| !p.is_empty())
                .collect(),
        }
    }

    /// True when mapping would be the identity, letting callers skip the walk.
    pub fn is_noop(&self) -> bool {
        self.source_root.is_none() && self.strip_prefixes.is_empty()
    }

    pub fn map(&self, path: &str) -> String {
        let mut normalized = normalize(path);

        if let Some(root) = &self.source_root {
            if let Some(rest) = strip_dir_prefix(&normalized, root) {
                normalized = rest;
            }
        }

        // First matching prefix wins: applying several would silently mangle a
        // path that happens to start with a shorter, unrelated prefix.
        for prefix in &self.strip_prefixes {
            if let Some(rest) = strip_dir_prefix(&normalized, prefix) {
                normalized = rest;
                break;
            }
        }

        normalized
    }
}

/// `\` → `/`, drop `./` segments, resolve `..` lexically (never touching the
/// filesystem — the report may describe a machine we are not running on).
pub fn normalize(path: &str) -> String {
    let unified = path.replace('\\', "/");
    let absolute = unified.starts_with('/');

    let mut segments: Vec<&str> = Vec::new();
    for segment in unified.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                // A leading `..` in a relative path has no parent to pop, so it
                // must survive or the path would point somewhere else entirely.
                if matches!(segments.last(), Some(&last) if last != "..") {
                    segments.pop();
                } else if !absolute {
                    segments.push("..");
                }
            }
            other => segments.push(other),
        }
    }

    let joined = segments.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Strip `prefix` from `path`, but only on a segment boundary: `/src/apple`
/// must not be shortened by the prefix `/src/app`.
fn strip_dir_prefix(path: &str, prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    if path == prefix {
        return Some(String::new());
    }
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
        .map(str::to_string)
}

fn trim_trailing_slash(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() && path.starts_with('/') {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_separators_and_dot_segments() {
        assert_eq!(normalize("src\\main\\a.rs"), "src/main/a.rs");
        assert_eq!(normalize("./src/./a.rs"), "src/a.rs");
        assert_eq!(normalize("src/lib/../a.rs"), "src/a.rs");
        assert_eq!(
            normalize("/builds/proj/./src/a.rs"),
            "/builds/proj/src/a.rs"
        );
        assert_eq!(normalize("../shared/a.rs"), "../shared/a.rs");
    }

    #[test]
    fn source_root_makes_absolute_paths_relative() {
        let mapper = PathMapper::new(Some("/builds/acme/proj/"), &[]);
        assert_eq!(mapper.map("/builds/acme/proj/src/a.rs"), "src/a.rs");
        // Outside the root: left untouched rather than silently mangled.
        assert_eq!(mapper.map("/opt/vendor/b.rs"), "/opt/vendor/b.rs");
    }

    #[test]
    fn prefix_stripping_respects_segment_boundaries() {
        let mapper = PathMapper::new(None, &["src/app".to_string()]);
        assert_eq!(mapper.map("src/app/main.rs"), "main.rs");
        assert_eq!(mapper.map("src/apple/main.rs"), "src/apple/main.rs");
    }

    #[test]
    fn only_the_first_matching_prefix_is_stripped() {
        let mapper = PathMapper::new(None, &["a".to_string(), "b".to_string()]);
        assert_eq!(mapper.map("a/b/c.rs"), "b/c.rs");
    }

    #[test]
    fn noop_mapper_is_detected() {
        assert!(PathMapper::new(None, &[]).is_noop());
        assert!(!PathMapper::new(Some("/x"), &[]).is_noop());
    }
}
