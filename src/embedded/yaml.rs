//! YAML embedded-shell extraction via tree-sitter-yaml.
//!
//! Targets CI/automation formats that store shell (or other) code in scalar
//! values keyed by a well-known name:
//!
//!   * GitHub Actions — `run:` step scalars, with an optional sibling `shell:`
//!     selecting the interpreter (`bash`, `python`, …), and the `script:`
//!     input of `actions/github-script` (JavaScript). A step that runs under
//!     PowerShell or cmd is not scanned, since disclude has no passes for
//!     them: its `shell:`, the job's or workflow's `defaults.run.shell`, a
//!     Windows `runs-on` (whose default shell is PowerShell), or an `if:`
//!     limiting it to `runner.os == 'Windows'` says so.
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

/// The direct (key, value) pairs of a mapping, keys normalized.
fn pairs_of<'t>(mapping: Node<'t>, bytes: &[u8]) -> Vec<(String, Node<'t>)> {
    let mut pairs = Vec::new();
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
    pairs
}

/// A scalar value's text, unquoted.
fn scalar_text<'b>(value: Node, bytes: &'b [u8]) -> &'b str {
    std::str::from_utf8(&bytes[value.byte_range()])
        .unwrap_or("")
        .trim()
        .trim_matches(['"', '\''])
}

/// The mapping a value node holds, if it holds one.
fn mapping_in(value: Node) -> Option<Node> {
    let mut node = value;
    loop {
        if matches!(node.kind(), "block_mapping" | "flow_mapping") {
            return Some(node);
        }
        node = node.named_child(0)?;
    }
}

/// What a GitHub Actions shell runs a `run:` block as. `None` for a shell
/// disclude has no passes for (PowerShell, cmd).
fn gha_shell(value: &str) -> Option<Language> {
    // `bash -euo pipefail {0}`, `/usr/bin/python3 {0}`: the program decides.
    let program = value
        .split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match program.as_str() {
        "pwsh" | "powershell" | "cmd" => None,
        "python" | "python3" => Some(Language::Python),
        "node" => Some(Language::JavaScript),
        p => Some(Language::from_fence_info(p).unwrap_or(Language::Bash)),
    }
}

/// The language of the `run:` block in a step mapping, from the step's
/// `shell:`, else the nearest `defaults.run.shell`, else the runner: a
/// Windows `runs-on`, or an `if:` naming Windows, means PowerShell.
fn run_language(step: Node, pairs: &[(String, Node)], bytes: &[u8]) -> Option<Language> {
    if let Some((_, v)) = pairs.iter().find(|(k, _)| k == "shell") {
        return gha_shell(scalar_text(*v, bytes));
    }
    let windows = |text: &str| text.to_ascii_lowercase().contains("windows");
    if let Some((_, v)) = pairs.iter().find(|(k, _)| k == "if") {
        // Raw text: unquoting would also strip the quote ending `'Windows'`.
        let cond = std::str::from_utf8(&bytes[v.byte_range()])
            .unwrap_or("")
            .replace(' ', "")
            .to_ascii_lowercase();
        if cond.contains("runner.os=='windows'") || cond.contains("runner.os==\"windows\"") {
            return None;
        }
    }
    // Up through the job and the workflow: the nearest `defaults.run.shell`
    // wins; without one, the job's runner decides.
    let mut on_windows = false;
    let mut node = step.parent();
    while let Some(n) = node {
        if matches!(n.kind(), "block_mapping" | "flow_mapping") {
            let outer = pairs_of(n, bytes);
            let shell = outer
                .iter()
                .find(|(k, _)| k == "defaults")
                .and_then(|(_, v)| mapping_in(*v))
                .and_then(|m| pairs_of(m, bytes).into_iter().find(|(k, _)| k == "run"))
                .and_then(|(_, v)| mapping_in(v))
                .and_then(|m| pairs_of(m, bytes).into_iter().find(|(k, _)| k == "shell"));
            if let Some((_, v)) = shell {
                return gha_shell(scalar_text(v, bytes));
            }
            if let Some((_, v)) = outer.iter().find(|(k, _)| k == "runs-on") {
                on_windows |= windows(scalar_text(*v, bytes));
            }
        }
        node = n.parent();
    }
    (!on_windows).then_some(Language::Bash)
}

/// True if `mapping` is the `with:` of a step that uses
/// `actions/github-script`, whose `script:` input is JavaScript.
fn is_github_script_inputs(mapping: Node, bytes: &[u8]) -> bool {
    let mut node = mapping.parent();
    while let Some(n) = node {
        if matches!(n.kind(), "block_mapping_pair" | "flow_pair") {
            let key = n
                .child_by_field_name("key")
                .and_then(|k| std::str::from_utf8(&bytes[k.byte_range()]).ok())
                .map(key_token);
            if key.as_deref() != Some("with") {
                return false;
            }
            let Some(step) = n.parent() else { return false };
            return pairs_of(step, bytes).iter().any(|(k, v)| {
                k == "uses"
                    && scalar_text(*v, bytes)
                        .to_ascii_lowercase()
                        .starts_with("actions/github-script")
            });
        }
        node = n.parent();
    }
    false
}

/// True if `mapping` is the value of a pair keyed `key`.
fn is_value_of(mapping: Node, key: &str, bytes: &[u8]) -> bool {
    let mut node = mapping.parent();
    while let Some(n) = node {
        if matches!(n.kind(), "block_mapping_pair" | "flow_pair") {
            return n
                .child_by_field_name("key")
                .and_then(|k| std::str::from_utf8(&bytes[k.byte_range()]).ok())
                .is_some_and(|k| key_token(k) == key);
        }
        node = n.parent();
    }
    false
}

fn handle_mapping(mapping: Node, bytes: &[u8], out: &mut Vec<CodeBlock>) {
    let pairs = pairs_of(mapping, bytes);
    let has_run = pairs.iter().any(|(k, _)| k == "run");
    let run_lang = if has_run {
        run_language(mapping, &pairs, bytes)
    } else {
        None
    };
    let script_lang = if is_github_script_inputs(mapping, bytes) {
        Language::JavaScript
    } else {
        Language::Bash
    };

    for (key, value) in &pairs {
        let lang = match key.as_str() {
            "run" => match run_lang {
                Some(l) => l,
                None => continue,
            },
            "script" => script_lang,
            "before_script" | "after_script" | "command" => Language::Bash,
            // `shell:` is an Ansible command key only when it is not acting as a
            // GitHub Actions selector for a sibling `run:`.
            // Nor under `defaults: run:`, where it names the default shell.
            "shell" if !has_run && !is_value_of(mapping, "run", bytes) => Language::Bash,
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
    fn github_script_is_javascript() {
        let src = "steps:\n  - uses: actions/github-script@v7\n    with:\n      script: |\n        console.log(`hi ${user}`)\n";
        let blocks = texts(src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, Language::JavaScript);
        // Another action's `script:` input is still read as shell.
        let src =
            "steps:\n  - uses: appleboy/ssh-action@v1\n    with:\n      script: eval \"$X\"\n";
        assert_eq!(texts(src)[0].0, Language::Bash);
    }

    #[test]
    fn powershell_steps_are_not_read_as_bash() {
        // Explicit shell, Windows guard, Windows runner, and defaults.
        for src in [
            "steps:\n  - run: $env:X=\"$(a)\"\n    shell: pwsh\n",
            "steps:\n  - if: runner.os == 'Windows'\n    run: $env:X=\"$(a)\"\n",
            "jobs:\n  w:\n    runs-on: windows-latest\n    steps:\n      - run: $env:X=1\n",
            "defaults:\n  run:\n    shell: powershell\njobs:\n  w:\n    runs-on: ubuntu-latest\n    steps:\n      - run: $env:X=1\n",
        ] {
            assert!(texts(src).is_empty(), "{src}");
        }
        // A step's own shell beats the Windows runner; job defaults beat
        // workflow defaults.
        let src = "jobs:\n  w:\n    runs-on: windows-latest\n    steps:\n      - run: eval \"$X\"\n        shell: bash\n";
        assert_eq!(texts(src)[0].0, Language::Bash);
        let src = "defaults:\n  run:\n    shell: pwsh\njobs:\n  l:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: bash -e {0}\n    steps:\n      - run: eval \"$X\"\n";
        assert_eq!(texts(src)[0].0, Language::Bash);
        // Linux runners and matrices stay bash.
        let src =
            "jobs:\n  l:\n    runs-on: ${{ matrix.os }}\n    steps:\n      - run: eval \"$X\"\n";
        assert_eq!(texts(src)[0].0, Language::Bash);
    }

    #[test]
    fn unrelated_keys_are_ignored() {
        let src = "name: build\ndescription: just metadata\n";
        assert!(extract(src.as_bytes()).is_empty());
    }
}
