//! AST pass — tree-sitter-based semantic analysis.
//!
//! Per SPEC §ast, each language walker detects behavioral-obfuscation
//! patterns that require real parsing to identify (dynamic execution,
//! constructed imports, build-script shellouts, etc.). Tree-sitter is
//! deliberately tolerant of parse errors: we record the error on the
//! `FileAnalysis` and walk whatever tree is available.
//!
//! Python, Rust, TypeScript/JavaScript, C, and Bash walkers are all wired up.

use std::path::Path;

use crate::finding::Finding;
use crate::language::Language;

pub mod bash;
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
    /// Byte ranges the analysis identified as data a known library parses
    /// and never runs (protobuf descriptors in generated `*_pb2.py`):
    /// encoding-shaped findings inside them are dropped (see
    /// [`is_data_shape_kind`]).
    pub data_spans: Vec<(usize, usize)>,
}

/// Signals about how bytes *look* (encoded, escaped, high-entropy), which a
/// [`AstOutcome::data_spans`] range explains. Anything about what code
/// *does* is never dropped this way.
pub fn is_data_shape_kind(kind: crate::finding::SignalKind) -> bool {
    use crate::finding::SignalKind::*;
    matches!(
        kind,
        EncodingBase64
            | EncodingHex
            | EncodingOctal
            | EncodingEscapeSoup
            | PayloadBytesLiteral
            | HighComplexity
    )
}

pub fn analyze(path: &Path, bytes: &[u8], lang: Language) -> AstOutcome {
    match lang {
        Language::Bash => bash::analyze(path, bytes),
        Language::C => c::analyze(path, bytes),
        Language::Python => python::analyze(path, bytes),
        Language::Rust => rust::analyze(path, bytes),
        Language::TypeScript | Language::JavaScript => typescript::analyze(path, bytes, lang),
        // Markup languages have no AST pass of their own; embedded code blocks
        // are analyzed under their resolved code language instead.
        Language::Text | Language::Markdown | Language::Yaml | Language::Rst => {
            AstOutcome::default()
        }
    }
}

/// Push `node`'s children onto a depth-first `stack` so they pop in source
/// order. Iterates with a cursor: `Node::child(i)` walks from the first
/// child on every call, so indexing through n children is O(n²), and
/// TypeScript's `reallyLargeFile.ts` (583,711 comment lines under one node)
/// took hours.
pub(crate) fn push_children<'a>(
    node: tree_sitter::Node<'a>,
    stack: &mut Vec<tree_sitter::Node<'a>>,
) {
    let start = stack.len();
    let mut cursor = node.walk();
    stack.extend(node.children(&mut cursor));
    stack[start..].reverse();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_are_linear_in_a_node_with_many_children() {
        // reallyLargeFile.ts in TypeScript's own tests: 583,711 comment lines,
        // all children of the root node. 100,000 here: the old indexed walk
        // needed minutes per language for this, a cursor walk milliseconds.
        let lines = 100_000;
        for (lang, line, ext) in [
            (Language::TypeScript, "////\n", "ts"),
            (Language::JavaScript, "////\n", "js"),
            (Language::Python, "#\n", "py"),
            (Language::Bash, "#\n", "sh"),
            (Language::C, "//\n", "c"),
            (Language::Rust, "//\n", "rs"),
        ] {
            let src = line.repeat(lines);
            let t = std::time::Instant::now();
            analyze(Path::new(&format!("big.{ext}")), src.as_bytes(), lang);
            assert!(
                t.elapsed() < std::time::Duration::from_secs(10),
                "{lang:?} took {:?}",
                t.elapsed()
            );
        }
    }
}
