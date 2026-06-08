//! Markdown fenced-code-block extraction via tree-sitter-markdown.
//!
//! We use only the block grammar (`tree_sitter_md::LANGUAGE`); the inline
//! grammar is irrelevant for locating fenced code. For each `fenced_code_block`
//! we read the `info_string`'s `language` child to resolve the scan language
//! and return the `code_fence_content` byte range. Fences with no info string
//! (and indented code blocks) carry no language and are skipped.

use tree_sitter::{Node, Parser};

use super::CodeBlock;
use crate::language::Language;

pub fn extract(bytes: &[u8]) -> Vec<CodeBlock> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_md::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(bytes, None) else {
        return Vec::new();
    };
    let mut blocks = Vec::new();
    walk(tree.root_node(), bytes, &mut blocks);
    blocks
}

fn walk(node: Node, bytes: &[u8], out: &mut Vec<CodeBlock>) {
    if node.kind() == "fenced_code_block" {
        if let Some(block) = fenced_block(node, bytes) {
            out.push(block);
        }
        // Code blocks do not nest; no need to descend further.
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, bytes, out);
    }
}

fn fenced_block(node: Node, bytes: &[u8]) -> Option<CodeBlock> {
    let mut cursor = node.walk();
    let mut info: Option<String> = None;
    let mut content: Option<(usize, usize)> = None;
    for child in node.children(&mut cursor) {
        match child.kind() {
            "info_string" => {
                // The `language` child holds the bare language token; fall back
                // to the whole info string if the grammar did not split it.
                let mut ic = child.walk();
                let lang_node = child
                    .children(&mut ic)
                    .find(|n| n.kind() == "language")
                    .unwrap_or(child);
                info = std::str::from_utf8(&bytes[lang_node.byte_range()])
                    .ok()
                    .map(|s| s.to_string());
            }
            "code_fence_content" => {
                content = Some((child.start_byte(), child.end_byte()));
            }
            _ => {}
        }
    }
    let lang = Language::from_fence_info(info.as_deref()?)?;
    let (start, end) = content?;
    CodeBlock::new(start, end, lang)
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
    fn fenced_python_block_is_extracted() {
        let src = "intro\n\n```python\nexec(x)\n```\n";
        let blocks = texts(src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, Language::Python);
        assert!(blocks[0].1.contains("exec(x)"));
    }

    #[test]
    fn fences_without_known_language_are_skipped() {
        // No info string, and an unsupported language, both yield nothing.
        let src = "```\nplain\n```\n\n```json\n{\"a\":1}\n```\n";
        assert!(extract(src.as_bytes()).is_empty());
    }

    #[test]
    fn info_string_attributes_after_language_are_ignored() {
        let src = "```bash {.line-numbers}\nrm -rf /\n```\n";
        let blocks = texts(src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, Language::Bash);
    }
}
