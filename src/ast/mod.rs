//! AST pass — tree-sitter-based semantic analysis.
//!
//! Per SPEC §ast, each language walker detects behavioral-obfuscation
//! patterns that require real parsing to identify (dynamic execution,
//! constructed imports, build-script shellouts, etc.). Tree-sitter is
//! deliberately tolerant of parse errors: we record the error on the
//! `FileAnalysis` and walk whatever tree is available.
//!
//! Python, Rust, TypeScript/JavaScript, and C walkers are all wired up.

use std::path::Path;

use crate::finding::Finding;
use crate::language::Language;

pub mod c;
pub mod python;
pub mod rust;
pub mod typescript;

/// File-level flags derived from the AST that the scorer uses to elevate
/// severities. These are metadata *about* the file, not findings in their
/// own right — presence of an `unsafe` block alone is not a finding, but
/// combined with a Warn elsewhere it is a Critical.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileFlags {
    /// Rust only: at least one `unsafe { ... }` block appears in the file.
    pub contains_unsafe: bool,
}

/// Output of the AST pass for a single file.
#[derive(Debug, Default)]
pub struct AstOutcome {
    pub findings: Vec<Finding>,
    pub parse_error: Option<String>,
    pub file_flags: FileFlags,
}

pub fn analyze(path: &Path, bytes: &[u8], lang: Language) -> AstOutcome {
    match lang {
        Language::C => c::analyze(path, bytes),
        Language::Python => python::analyze(path, bytes),
        Language::Rust => rust::analyze(path, bytes),
        Language::TypeScript | Language::JavaScript => typescript::analyze(path, bytes, lang),
    }
}
