//! Conversion notices — what a reader or a writer could not carry across.
//!
//! Losses are inherent to the pivot design (SPECS.md §3.2): a writer can only
//! emit what its target format and target *version* can express. Rather than
//! dropping data silently, every reader and writer reports what it gave up, and
//! the CLI either prints those on **stderr** (stdout may carry the report) or
//! turns them into a failure under `--strict`.

/// Why a notice was raised. The distinction matters when downgrading a format
/// to an older spec version: dropping a field is one thing, emitting a value
/// the target schema does not define is another — the consumer rejects the
/// whole document rather than ignoring one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteKind {
    /// Information the target cannot represent and that was dropped.
    Lossy,
    /// A value that had to be *rewritten* to stay valid for the target
    /// (an enum member the target version does not know, a field replaced by an
    /// approximation). The output stays schema-valid but no longer says exactly
    /// what the input said.
    Degraded,
}

impl NoteKind {
    /// Prefix used when the notice is printed.
    pub fn label(self) -> &'static str {
        match self {
            NoteKind::Lossy => "lossy:",
            NoteKind::Degraded => "degraded:",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub kind: NoteKind,
    pub message: String,
}

/// Accumulates conversion notices, deduplicated and order-preserving.
#[derive(Debug, Default)]
pub struct Warnings {
    items: Vec<Note>,
}

impl Warnings {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record dropped information. Repeated identical messages are collapsed,
    /// so a writer may call this per file without flooding the output.
    pub fn lossy(&mut self, message: impl Into<String>) {
        self.push(NoteKind::Lossy, message.into());
    }

    /// Record a value that had to be rewritten to stay valid for the target.
    pub fn degraded(&mut self, message: impl Into<String>) {
        self.push(NoteKind::Degraded, message.into());
    }

    fn push(&mut self, kind: NoteKind, message: String) {
        let note = Note { kind, message };
        if !self.items.contains(&note) {
            self.items.push(note);
        }
    }

    /// Fold another collection in, preserving order and deduplication. Used to
    /// gather the notices of each per-format context into a single run-level set.
    pub fn absorb(&mut self, other: Warnings) {
        for note in other.items {
            self.push(note.kind, note.message);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn notes(&self) -> impl Iterator<Item = &Note> {
        self.items.iter()
    }

    /// Messages only, without their kind — convenient in assertions.
    /// Test-only for now: the CLI prints the kind alongside the message.
    #[cfg(test)]
    pub fn messages(&self) -> impl Iterator<Item = &str> {
        self.items.iter().map(|n| n.message.as_str())
    }
}

/// What a reader or a writer is handed besides the bytes: the spec version it
/// must target, and somewhere to report what it could not carry.
///
/// It owns its notices rather than borrowing a shared collector, so that a
/// module's unit tests can inspect them without fighting the borrow checker;
/// the CLI folds each context's notices into a run-level [`Warnings`] with
/// [`Warnings::absorb`].
#[derive(Debug, Default)]
pub struct FormatCtx {
    version: Option<&'static str>,
    path_rewriting: bool,
    warnings: Warnings,
}

impl FormatCtx {
    /// `version` is already validated against the format's declared versions,
    /// and is `None` for formats that are not versioned.
    pub fn new(version: Option<&'static str>) -> Self {
        FormatCtx {
            version,
            path_rewriting: false,
            warnings: Warnings::new(),
        }
    }

    /// Tell the context that the run rewrites paths (`--source-root` or
    /// `--strip-prefix`).
    ///
    /// A reader for a format whose paths are known not to be
    /// repository-relative — Go import paths are the case in point — needs this
    /// to avoid warning about a problem the user has already addressed. A
    /// notice that fires on correct usage teaches people to ignore notices.
    pub fn set_path_rewriting(&mut self, requested: bool) {
        self.path_rewriting = requested;
    }

    /// Whether the run was asked to rewrite paths.
    pub fn path_rewriting_requested(&self) -> bool {
        self.path_rewriting
    }

    /// Spec version to target. A writer for an unversioned format ignores it.
    pub fn version(&self) -> Option<&'static str> {
        self.version
    }

    pub fn lossy(&mut self, message: impl Into<String>) {
        self.warnings.lossy(message);
    }

    pub fn degraded(&mut self, message: impl Into<String>) {
        self.warnings.degraded(message);
    }

    /// Test-only for now: the CLI consumes the notices through
    /// [`FormatCtx::into_warnings`] instead of borrowing them.
    #[cfg(test)]
    pub fn warnings(&self) -> &Warnings {
        &self.warnings
    }

    pub fn into_warnings(self) -> Warnings {
        self.warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_notices_are_collapsed() {
        let mut warnings = Warnings::new();
        warnings.lossy("dropped x");
        warnings.lossy("dropped x");
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn the_same_message_under_two_kinds_is_kept_twice() {
        let mut warnings = Warnings::new();
        warnings.lossy("x");
        warnings.degraded("x");
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn absorb_merges_and_deduplicates() {
        let mut ctx = FormatCtx::new(None);
        ctx.lossy("shared");
        ctx.degraded("only in ctx");

        let mut warnings = Warnings::new();
        warnings.lossy("shared");
        warnings.absorb(ctx.into_warnings());

        assert_eq!(warnings.len(), 2);
        assert!(warnings.messages().any(|m| m == "only in ctx"));
    }
}
