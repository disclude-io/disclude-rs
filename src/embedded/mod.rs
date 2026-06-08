//! Embedded code-block extraction for markup files.
//!
//! Markup files (`.md`, `.yaml`, `.rst`) routinely carry executable code:
//! shell in GitHub Actions / GitLab CI / Ansible YAML scalars, language code
//! fences in Markdown docs, `code-block` directives in reStructuredText. Those
//! blocks are invisible to disclude's per-language scanners unless we first
//! isolate them.
//!
//! [`extract`] returns the byte ranges of each code block within the original
//! file plus the resolved [`Language`] to scan it as. The caller (`scan`) then
//! runs the normal token + AST passes over each slice and maps findings back to
//! the file's coordinates. Blocks whose language disclude does not scan are not
//! returned — they remain covered only by the language-agnostic raw pass.

use std::path::Path;

use crate::language::Language;

pub mod markdown;
pub mod rst;
pub mod yaml;

/// A run of embedded code within a markup file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeBlock {
    /// Byte offset of the block's content start in the original file.
    pub start: usize,
    /// Byte offset of the block's content end (exclusive).
    pub end: usize,
    /// Language to scan the block as.
    pub lang: Language,
}

impl CodeBlock {
    fn new(start: usize, end: usize, lang: Language) -> Option<Self> {
        if end > start {
            Some(CodeBlock { start, end, lang })
        } else {
            None
        }
    }
}

/// Extract embedded code blocks from a markup file. `lang` is the markup
/// language of the file itself. Returns an empty vec for `Text` (plain text has
/// no embedded-code structure) and for any parse that yields no blocks.
pub fn extract(_path: &Path, bytes: &[u8], lang: Language) -> Vec<CodeBlock> {
    match lang {
        Language::Markdown => markdown::extract(bytes),
        Language::Yaml => yaml::extract(bytes),
        Language::Rst => rst::extract(bytes),
        // Plain text and all code languages have nothing to extract here.
        _ => Vec::new(),
    }
}
