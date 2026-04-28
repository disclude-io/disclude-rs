//! C AST walker — tree-sitter-c based checks.
//!
//! The walker detects a small, high-signal set of dangerous call patterns
//! that are commonly used in supply-chain attacks or obfuscated C code:
//!
//!   * `system(x)` — spawns a shell command. Any argument triggers
//!     DynamicExecution: WARN for literal arguments, CRITICAL for non-literals.
//!   * `exec*(x, ...)` — execl, execlp, execle, execv, execvp, execve — direct
//!     process replacement. Non-literal first argument → DynamicExecution CRITICAL.
//!   * `popen(x, mode)` — opens a process via the shell. DynamicExecution WARN.
//!   * `dlopen(x, flags)` — dynamically loads a shared library. Non-literal
//!     path → DynamicImport WARN.
//!   * `dlsym(handle, name)` — resolves a symbol by name at runtime. Non-literal
//!     name → DynamicAttribute WARN.

use std::path::Path;

use tree_sitter::{Node, Parser};

use super::AstOutcome;
use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

const EXEC_FUNCTIONS: &[&str] = &["execl", "execlp", "execle", "execv", "execvp", "execve"];

pub fn analyze(path: &Path, bytes: &[u8]) -> AstOutcome {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
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
    let mut cursor = root.walk();
    walk(root, bytes, path, &index, &mut findings, &mut cursor);
    AstOutcome {
        findings,
        parse_error,
        file_flags: Default::default(),
    }
}

fn walk<'a>(
    node: Node<'a>,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    cursor: &mut tree_sitter::TreeCursor<'a>,
) {
    if node.kind() == "call_expression" {
        check_call(node, bytes, path, index, findings);
    }
    for child in node.children(cursor) {
        let mut sub = child.walk();
        walk(child, bytes, path, index, findings, &mut sub);
    }
}

// ---------------------------------------------------------------------------
// Call-expression analysis
// ---------------------------------------------------------------------------

fn check_call(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    // Only inspect direct identifier callees; function pointers and member
    // expressions are handled elsewhere or are out of scope.
    if func.kind() != "identifier" {
        return;
    }
    let name = node_text(func, bytes);

    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let positional = positional_args(args);

    match name {
        "system" => {
            check_system(node, positional.as_slice(), bytes, path, index, findings);
        }
        "popen" => {
            check_popen(node, positional.as_slice(), bytes, path, index, findings);
        }
        "dlopen" => {
            check_dlopen(node, positional.as_slice(), bytes, path, index, findings);
        }
        "dlsym" => {
            check_dlsym(node, positional.as_slice(), bytes, path, index, findings);
        }
        fn_name if EXEC_FUNCTIONS.contains(&fn_name) => {
            check_exec(node, fn_name, positional.as_slice(), bytes, path, index, findings);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/// `system(cmd)` — any argument triggers DynamicExecution.
/// Literal argument → WARN; non-literal → CRITICAL.
fn check_system(
    call: Node,
    args: &[Node],
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let (severity, confidence, message) = if let Some(first) = args.first() {
        if is_string_literal(*first) {
            (
                Severity::Warn,
                0.70,
                "`system` called with a string literal argument".to_string(),
            )
        } else {
            (
                Severity::Critical,
                0.90,
                "`system` called with a non-literal argument".to_string(),
            )
        }
    } else {
        // system() with no args is unusual; flag as Warn.
        (
            Severity::Warn,
            0.60,
            "`system` called".to_string(),
        )
    };
    push(findings, call, bytes, path, index, SignalKind::DynamicExecution, severity, confidence, message);
}

/// `exec*(path, ...)` — direct process replacement. Non-literal path → CRITICAL.
fn check_exec(
    call: Node,
    fn_name: &str,
    args: &[Node],
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let (severity, confidence, message) = if let Some(first) = args.first() {
        if is_string_literal(*first) {
            (
                Severity::Warn,
                0.70,
                format!("`{}` called with a string literal path", fn_name),
            )
        } else {
            (
                Severity::Critical,
                0.90,
                format!("`{}` called with a non-literal path", fn_name),
            )
        }
    } else {
        (
            Severity::Warn,
            0.60,
            format!("`{}` called", fn_name),
        )
    };
    push(findings, call, bytes, path, index, SignalKind::DynamicExecution, severity, confidence, message);
}

/// `popen(cmd, mode)` — runs a shell command. Always WARN.
fn check_popen(
    call: Node,
    args: &[Node],
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let (severity, confidence, message) = if let Some(first) = args.first() {
        if is_string_literal(*first) {
            (
                Severity::Warn,
                0.70,
                "`popen` called with a string literal command".to_string(),
            )
        } else {
            (
                Severity::Critical,
                0.85,
                "`popen` called with a non-literal command".to_string(),
            )
        }
    } else {
        (
            Severity::Warn,
            0.60,
            "`popen` called".to_string(),
        )
    };
    push(findings, call, bytes, path, index, SignalKind::DynamicExecution, severity, confidence, message);
}

/// `dlopen(path, flags)` — dynamically loads a library. Non-literal path → WARN.
fn check_dlopen(
    call: Node,
    args: &[Node],
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(first) = args.first() else { return };
    if is_string_literal(*first) {
        return;
    }
    push(
        findings,
        call,
        bytes,
        path,
        index,
        SignalKind::DynamicImport,
        Severity::Warn,
        0.75,
        "`dlopen` called with a non-literal path".to_string(),
    );
}

/// `dlsym(handle, name)` — resolves a symbol by name. Non-literal name → WARN.
fn check_dlsym(
    call: Node,
    args: &[Node],
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    // Second argument is the symbol name.
    let Some(name_arg) = args.get(1) else { return };
    if is_string_literal(*name_arg) {
        return;
    }
    push(
        findings,
        call,
        bytes,
        path,
        index,
        SignalKind::DynamicAttribute,
        Severity::Warn,
        0.75,
        "`dlsym` called with a non-literal symbol name".to_string(),
    );
}

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------

fn node_text<'a>(node: Node, bytes: &'a [u8]) -> &'a str {
    std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).unwrap_or("")
}

/// Collect positional argument expression nodes from an `argument_list` node,
/// skipping punctuation.
fn positional_args(args: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        match child.kind() {
            "(" | ")" | "," => {}
            _ => out.push(child),
        }
    }
    out
}

/// True if the node is a C string literal (`"..."` or `L"..."`).
fn is_string_literal(node: Node) -> bool {
    node.kind() == "string_literal" || node.kind() == "concatenated_string"
}

#[allow(clippy::too_many_arguments)]
fn push(
    findings: &mut Vec<Finding>,
    anchor: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    kind: SignalKind,
    severity: Severity,
    confidence: f32,
    message: String,
) {
    let off = anchor.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind,
        severity,
        confidence,
        message,
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(src: &[u8]) -> Vec<Finding> {
        analyze(&PathBuf::from("test.c"), src).findings
    }

    #[test]
    fn system_literal_is_warn() {
        let src = b"void f() { system(\"ls\"); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn system_variable_is_critical() {
        let src = b"void f(char *cmd) { system(cmd); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn popen_variable_is_critical() {
        let src = b"void f(char *cmd) { popen(cmd, \"r\"); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn popen_literal_is_warn() {
        let src = b"void f() { popen(\"ls\", \"r\"); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn exec_literal_is_warn() {
        let src = b"void f() { execl(\"/bin/ls\", \"ls\", (char*)0); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn exec_variable_is_critical() {
        let src = b"void f(char *prog) { execv(prog, NULL); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn dlopen_literal_is_ignored() {
        let src = b"void f() { dlopen(\"lib.so\", 1); }\n";
        let findings = run(src);
        assert!(findings.iter().all(|f| f.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn dlopen_variable_is_warn() {
        let src = b"void f(char *path) { dlopen(path, 1); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicImport)
            .expect("expected DynamicImport");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn dlsym_literal_is_ignored() {
        let src = b"void f(void *h) { dlsym(h, \"func\"); }\n";
        let findings = run(src);
        assert!(findings.iter().all(|f| f.kind != SignalKind::DynamicAttribute));
    }

    #[test]
    fn dlsym_variable_is_warn() {
        let src = b"void f(void *h, char *name) { dlsym(h, name); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicAttribute)
            .expect("expected DynamicAttribute");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn unrelated_call_is_ignored() {
        let src = b"int main() { printf(\"hello\\n\"); return 0; }\n";
        let findings = run(src);
        assert!(findings.is_empty(), "expected no findings, got: {:?}", findings);
    }

    #[test]
    fn parse_error_tolerated() {
        let result = analyze(&PathBuf::from("bad.c"), b"int x( {");
        let _ = result.parse_error;
    }
}
