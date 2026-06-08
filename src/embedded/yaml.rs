//! YAML embedded-shell extraction via tree-sitter-yaml.
//!
//! Targets CI/automation formats that store shell (or other) code in scalar
//! values keyed by a well-known name:
//!
//!   * GitHub Actions — `run:` step scalars, with an optional sibling `shell:`
//!     selecting the interpreter (`bash`, `python`, …).
//!   * GitLab CI — `script:`, `before_script:`, `after_script:` (each a scalar
//!     or a sequence of command scalars).
//!   * Ansible — `shell:` / `command:` modules, including the fully-qualified
//!     `ansible.builtin.shell` / `ansible.builtin.command` forms.
//!
//! For each matching key we resolve the language (default Bash) and return the
//! byte ranges of the scalar value(s). A bare `shell:` is treated as an Ansible
//! command *unless* the same mapping also has a `run:` key, in which case it is
//! a GitHub Actions interpreter selector and is consumed for the `run:` block's
//! language rather than scanned itself.

use tree_sitter::{Node, Parser};

use super::CodeBlock;
use crate::language::Language;

pub fn extract(bytes: &[u8]) -> Vec<CodeBlock> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
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
    if node.kind() == "block_mapping" || node.kind() == "flow_mapping" {
        handle_mapping(node, bytes, out);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, bytes, out);
    }
}

/// Normalize a key to its final dotted segment, lowercased
/// (`ansible.builtin.shell` → `shell`).
fn key_token(raw: &str) -> String {
    raw.trim()
        .rsplit('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn handle_mapping(mapping: Node, bytes: &[u8], out: &mut Vec<CodeBlock>) {
    // Gather direct (key, value) pairs of this mapping.
    let mut pairs: Vec<(String, Node)> = Vec::new();
    let mut cursor = mapping.walk();
    for child in mapping.children(&mut cursor) {
        if child.kind() != "block_mapping_pair" && child.kind() != "flow_pair" {
            continue;
        }
        let Some(key) = child.child_by_field_name("key") else {
            continue;
        };
        let Some(value) = child.child_by_field_name("value") else {
            continue;
        };
        if let Ok(k) = std::str::from_utf8(&bytes[key.byte_range()]) {
            pairs.push((key_token(k), value));
        }
    }

    let has_run = pairs.iter().any(|(k, _)| k == "run");
    // GHA interpreter selector: a sibling `shell:` next to a `run:`.
    let shell_lang = if has_run {
        pairs
            .iter()
            .find(|(k, _)| k == "shell")
            .and_then(|(_, v)| std::str::from_utf8(&bytes[v.byte_range()]).ok())
            .and_then(Language::from_fence_info)
    } else {
        None
    };

    for (key, value) in &pairs {
        let lang = match key.as_str() {
            "run" => shell_lang.unwrap_or(Language::Bash),
            "script" | "before_script" | "after_script" | "command" => Language::Bash,
            // `shell:` is an Ansible command key only when it is not acting as a
            // GitHub Actions selector for a sibling `run:`.
            "shell" if !has_run => Language::Bash,
            _ => continue,
        };
        for (start, end) in value_ranges(*value, bytes) {
            if let Some(block) = CodeBlock::new(start, end, lang) {
                out.push(block);
            }
        }
    }
}

/// Collect the byte ranges of the scannable scalar content within a value node.
/// Sequences (GitLab `script:` lists) yield one range per item; block scalars
/// drop the leading indicator line (`|`, `>`, with optional chomp/indent).
fn value_ranges(value: Node, bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    collect(value, bytes, &mut out);
    out
}

fn collect(node: Node, bytes: &[u8], out: &mut Vec<(usize, usize)>) {
    match node.kind() {
        "plain_scalar" | "single_quote_scalar" | "double_quote_scalar" | "string_scalar" => {
            out.push((node.start_byte(), node.end_byte()));
        }
        "block_scalar" => {
            // Skip the indicator line; content begins after the first newline.
            let start = node.start_byte();
            let end = node.end_byte();
            let body_start = bytes[start..end]
                .iter()
                .position(|&b| b == b'\n')
                .map(|i| start + i + 1)
                .unwrap_or(end);
            if end > body_start {
                out.push((body_start, end));
            }
        }
        // Descend through wrappers and sequences.
        "flow_node" | "block_node" | "block_sequence" | "block_sequence_item" | "flow_sequence" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                // Skip structural punctuation tokens (e.g. the `-` item marker).
                if child.is_named() {
                    collect(child, bytes, out);
                }
            }
        }
        _ => {}
    }
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
    fn gha_run_block_scalar_drops_indicator_line() {
        let src = "steps:\n  - run: |\n      echo hi\n      eval \"$X\"\n";
        let blocks = texts(src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, Language::Bash);
        // The `|` indicator line is excluded; body retained verbatim.
        assert!(blocks[0].1.contains("echo hi"));
        assert!(blocks[0].1.contains("eval \"$X\""));
        assert!(!blocks[0].1.contains('|'));
    }

    #[test]
    fn gha_shell_selector_picks_language_and_is_not_scanned_itself() {
        let src = "steps:\n  - run: print(1)\n    shell: python\n";
        let blocks = texts(src);
        // Only the `run:` value is scanned, as Python (per the `shell:` selector).
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, Language::Python);
        assert_eq!(blocks[0].1, "print(1)");
    }

    #[test]
    fn ansible_shell_and_command_are_scanned_as_bash() {
        // Without a sibling `run:`, `shell:`/`command:` are Ansible command keys.
        let src =
            "- name: x\n  ansible.builtin.shell: rm -rf /tmp/x\n- name: y\n  command: echo hi\n";
        let blocks = texts(src);
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|b| b.0 == Language::Bash));
        assert!(blocks.iter().any(|b| b.1 == "rm -rf /tmp/x"));
        assert!(blocks.iter().any(|b| b.1 == "echo hi"));
    }

    #[test]
    fn gitlab_script_sequence_yields_one_block_per_item() {
        let src = "job:\n  script:\n    - eval \"$A\"\n    - echo done\n";
        let blocks = texts(src);
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|b| b.0 == Language::Bash));
    }

    #[test]
    fn unrelated_keys_are_ignored() {
        let src = "name: build\ndescription: just metadata\n";
        assert!(extract(src.as_bytes()).is_empty());
    }
}
