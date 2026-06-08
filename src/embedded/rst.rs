//! reStructuredText code-block extraction (hand lexer).
//!
//! RST has no chosen tree-sitter grammar here, but its code directives are
//! simple and unambiguous. We recognize `.. code-block:: <lang>`,
//! `.. sourcecode:: <lang>`, and `.. code:: <lang>` directives and return the
//! byte range of the indented body that follows (skipping directive options
//! such as `:linenos:`). Plain literal blocks (`::`) carry no language and are
//! left to the global payload pass.

use super::CodeBlock;
use crate::language::Language;

pub fn extract(bytes: &[u8]) -> Vec<CodeBlock> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };

    // Line table: (start, end) with `end` exclusive of the newline.
    let mut lines: Vec<(usize, usize)> = Vec::new();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            lines.push((start, i));
            start = i + 1;
        }
    }
    if start < bytes.len() {
        lines.push((start, bytes.len()));
    }

    let mut out = Vec::new();
    let mut li = 0;
    while li < lines.len() {
        let (ls, le) = lines[li];
        if let Some((indent, lang)) = parse_directive(&text[ls..le]) {
            li += 1;
            let mut content_start: Option<usize> = None;
            let mut content_end = 0usize;
            while li < lines.len() {
                let (cls, cle) = lines[li];
                let line = &text[cls..cle];
                let trimmed = line.trim_start();
                if trimmed.is_empty() {
                    // Blank lines do not terminate an indented block.
                    li += 1;
                    continue;
                }
                let cur_indent = line.len() - trimmed.len();
                if cur_indent <= indent {
                    break; // dedent: block over
                }
                // Leading directive options (`:name: value`) precede content.
                if content_start.is_none() && trimmed.starts_with(':') && trimmed[1..].contains(':')
                {
                    li += 1;
                    continue;
                }
                if content_start.is_none() {
                    content_start = Some(cls);
                }
                content_end = cle;
                li += 1;
            }
            if let Some(cs) = content_start {
                if let Some(block) = CodeBlock::new(cs, content_end, lang) {
                    out.push(block);
                }
            }
        } else {
            li += 1;
        }
    }
    out
}

/// Parse an RST code directive line, returning its indent and resolved
/// language. Returns `None` for non-directives or unsupported/absent languages.
fn parse_directive(line: &str) -> Option<(usize, Language)> {
    let indent = line.len() - line.trim_start().len();
    let rest = line[indent..].trim_end();
    let body = rest.strip_prefix("..")?.trim_start();
    let sep = body.find("::")?;
    let name = body[..sep].trim().to_ascii_lowercase();
    if !matches!(name.as_str(), "code-block" | "sourcecode" | "code") {
        return None;
    }
    let arg = body[sep + 2..].trim();
    if arg.is_empty() {
        return None;
    }
    let lang = Language::from_fence_info(arg)?;
    Some((indent, lang))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(src: &str) -> Vec<(Language, String)> {
        extract(src.as_bytes())
            .into_iter()
            .map(|b| (b.lang, src[b.start..b.end].to_string()))
            .collect()
    }

    #[test]
    fn code_block_body_after_options_is_extracted() {
        let src = "intro\n\n.. code-block:: bash\n   :linenos:\n\n   eval \"$X\"\n   echo done\n\nafter\n";
        let blocks = texts(src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, Language::Bash);
        // Options are skipped; both code lines are captured; the trailing
        // dedented prose is not.
        assert!(blocks[0].1.contains("eval \"$X\""));
        assert!(blocks[0].1.contains("echo done"));
        assert!(!blocks[0].1.contains(":linenos:"));
        assert!(!blocks[0].1.contains("after"));
    }

    #[test]
    fn sourcecode_alias_and_python_language() {
        let src = ".. sourcecode:: python\n\n   exec(x)\n";
        let blocks = texts(src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, Language::Python);
    }

    #[test]
    fn directive_without_language_is_skipped() {
        let src = ".. code-block::\n\n   some text\n";
        assert!(extract(src.as_bytes()).is_empty());
    }

    #[test]
    fn plain_literal_block_is_not_a_directive() {
        let src = "Example::\n\n   not extracted\n";
        assert!(extract(src.as_bytes()).is_empty());
    }
}
