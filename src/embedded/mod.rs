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

/// A shell block written as a terminal session (`$ cmd`, then its output),
/// as documentation shows commands, rewritten as the commands a reader would
/// run: prompts become spaces, output lines are blanked, and lines continuing
/// a command (after a trailing `\`) are kept, less any `> ` prompt. The
/// result is the same length with the same line breaks, so findings keep
/// their positions. `None` when no line starts with a `$` prompt (a plain
/// script, scanned as written).
pub fn shell_session_commands(block: &[u8]) -> Option<Vec<u8>> {
    let is_prompt = |line: &[u8]| {
        let t = line.trim_ascii_start();
        t == b"$" || t.starts_with(b"$ ")
    };
    if !block.split(|&b| b == b'\n').any(is_prompt) {
        return None;
    }
    let mut out = Vec::with_capacity(block.len());
    let mut continues = false;
    for (i, line) in block.split(|&b| b == b'\n').enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        let indent = line.len() - line.trim_ascii_start().len();
        let rest = &line[indent..];
        let (marker, command) = if is_prompt(line) {
            (1, true)
        } else if continues {
            (if rest.starts_with(b"> ") { 1 } else { 0 }, true)
        } else {
            (0, false)
        };
        if command {
            out.extend(std::iter::repeat_n(b' ', indent + marker));
            out.extend_from_slice(&rest[marker..]);
            continues = line.trim_ascii_end().ends_with(b"\\");
        } else {
            // Output: blank it, keeping a `\r` so line endings are unchanged.
            out.extend(line.iter().map(|&b| if b == b'\r' { b } else { b' ' }));
            continues = false;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_sessions_become_their_commands() {
        let session = "$ pytest --version\npytest 9.1.1\n$ docker run \\\n> --rm img\n  $ cat failures\ntest_a.py::t1\n";
        let out = String::from_utf8(shell_session_commands(session.as_bytes()).unwrap()).unwrap();
        assert_eq!(out.len(), session.len());
        let lines: Vec<&str> = out.lines().map(str::trim_end).collect();
        assert_eq!(
            lines,
            [
                "  pytest --version",
                "",
                "  docker run \\",
                "  --rm img",
                "    cat failures",
                ""
            ]
        );
        // A script with `$VAR` in it is not a session.
        assert!(shell_session_commands(b"echo $HOME\n\"$CMD\" --flag\n").is_none());
    }
}
