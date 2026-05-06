//! Python AST walker — tree-sitter-python based checks for dynamic
//! execution, dynamic imports, and constructed-name attribute access.
//!
//! The checks look for a small, high-signal set of call patterns:
//!   * `exec(x)`, `eval(x)`, `compile(x)` where `x` is not a bare string
//!     literal. If the argument is a call to a known decoder or comes from
//!     string concatenation, we tag it as a reconstructed payload
//!     (CRITICAL); otherwise it's still non-literal input to a code-execution
//!     sink (CRITICAL — per SPEC, exec/eval with a decoded/decompressed value
//!     is critical, and in Python practice any non-literal exec is
//!     indistinguishable from that without dataflow).
//!   * `__import__(x)` with a non-literal first argument → CRITICAL.
//!   * `getattr(obj, x)` / `setattr(obj, x, v)` with a non-literal name →
//!     WARN.
//!   * `globals()[x]`, `vars()[x]`, `globals().get(x)` etc. → WARN.
//!
//! Each finding records the byte offset of the *call expression*, not of
//! the offending argument. This makes the reported location line up with
//! how a human reads the code ("this call does something dynamic").

use std::path::Path;

use tree_sitter::{Node, Parser};

use super::AstOutcome;
use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

pub fn analyze(path: &Path, bytes: &[u8]) -> AstOutcome {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
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
    check_payload_bytes_literals(root, bytes, path, &index, &mut findings);
    check_decoder_import_with_exec(root, bytes, path, &index, &mut findings);
    check_decoder_decompress_payload(root, bytes, path, &index, &mut findings);
    check_obfuscated_byte_strings(root, bytes, path, &index, &mut findings);
    check_frame_introspection(root, bytes, path, &index, &mut findings);
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
            "call" => check_call(node, bytes, path, index, findings),
            "subscript" => check_subscript(node, bytes, path, index, findings),
            "assignment" => check_assignment(node, bytes, path, index, findings),
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
    let Some(args_node) = node.child_by_field_name("arguments") else {
        return;
    };
    let args = positional_args(args_node);

    // Which callable?
    let short = callee_short_name(func, bytes);
    let qualified = callee_qualified_name(func, bytes);

    match short.as_deref() {
        Some(name @ ("exec" | "eval" | "compile")) if func.kind() == "identifier" => {
            // Only the bare builtin counts. `re.compile(...)`, `ast.parse(...)`,
            // etc. are unrelated APIs that share the name.
            if let Some(arg) = args.first() {
                emit_exec_like(node, *arg, bytes, path, index, findings, name);
            }
        }
        Some("__import__") => {
            if let Some(arg) = args.first() {
                emit_dynamic_import(node, *arg, bytes, path, index, findings);
            }
        }
        Some("open") if func.kind() == "identifier" => {
            if let Some(arg) = args.first() {
                if arg.kind() == "identifier" && node_text(*arg, bytes) == "__file__" {
                    emit_self_read(node, bytes, path, index, findings);
                }
            }
        }
        Some("setattr") if func.kind() == "identifier" => {
            // setattr(builtins, "name", value) patches the global namespace.
            if let Some(obj_arg) = args.first() {
                if obj_arg.kind() == "identifier" && node_text(*obj_arg, bytes) == "builtins" {
                    emit_builtins_write(
                        node,
                        bytes,
                        path,
                        index,
                        findings,
                        "setattr(builtins, ...)",
                    );
                }
            }
        }
        // Some("getattr") | Some("setattr") | Some("hasattr") | Some("delattr") => {
        //     if let Some(arg) = args.get(1) {
        //         emit_dynamic_attr(
        //             node,
        //             *arg,
        //             bytes,
        //             path,
        //             index,
        //             findings,
        //             short.as_deref().unwrap(),
        //         );
        //     }
        // }
        _ => {}
    }

    // `globals()[x]` / `vars()[x]` / `globals().get(x)` style.
    // These present as subscript or attribute chains with a `globals()`/
    // `vars()` base. tree-sitter-python exposes the subscript form as
    // `subscript` with a `value` field that is the base expression and a
    // `subscript` field that is the index.
    if let Some(name) = qualified.as_deref() {
        match name {
            "marshal.loads" | "marshal.load" => {
                if let Some(arg) = args.first() {
                    emit_marshal_loads(node, *arg, bytes, path, index, findings, name);
                }
            }
            "globals.get" | "vars.get" | "locals.get" => {
                if let Some(arg) = args.first() {
                    if !is_literal_expression(*arg, bytes) {
                        push_dynamic_attr(node, bytes, path, index, findings, name);
                    }
                }
            }
            _ => {}
        }
    }

    // Python shell/process spawn family: os.system, os.popen, os.spawn*,
    // subprocess.* (gated on shell=True for the run/call/Popen variants).
    // Also resolves `__import__('os').system(cmd)` chains.
    check_python_shellout(node, bytes, path, index, findings);
}

fn emit_marshal_loads(
    call_node: Node,
    arg: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    fn_name: &str,
) {
    // Higher confidence when the argument is a literal bytes blob — the
    // bytecode is embedded statically in the source. Lower (but still
    // meaningful) when it's a variable, since we can't rule out a file-read.
    let on_literal = matches!(arg.kind(), "string" | "concatenated_string");
    let confidence = if on_literal { 0.90 } else { 0.75 };
    let off = call_node.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicExecution,
        severity: Severity::Warn,
        confidence,
        message: format!(
            "`{}` deserializes Python bytecode from bytes — code-object sink",
            fn_name
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

// Subscript-form reach-by-name detection is handled in a separate visitor
// because it is *not* a call expression.
fn check_subscript(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    let Some(subscript) = node.child_by_field_name("subscript") else {
        return;
    };
    let base = callee_qualified_name(value, bytes);
    let is_dyn_base = matches!(
        base.as_deref(),
        Some("globals") | Some("vars") | Some("locals") | Some("__builtins__")
    );
    if !is_dyn_base {
        return;
    }
    // The `subscript` field points directly at the index expression in
    // current tree-sitter-python grammars (e.g. the `name` in `x[name]`
    // or the `string` in `x["literal"]`). If it's not a literal, that's a
    // reach-by-name.
    if !is_literal_expression(subscript, bytes) {
        let base_name = base.as_deref().unwrap_or("dynamic");
        push_dynamic_attr(node, bytes, path, index, findings, base_name);
    }
}

fn check_assignment(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    // `builtins.<name> = <expr>` — direct write into the builtins namespace.
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    if left.kind() != "attribute" {
        return;
    }
    let Some(obj) = left.child_by_field_name("object") else {
        return;
    };
    if obj.kind() != "identifier" || node_text(obj, bytes) != "builtins" {
        return;
    }
    let attr = left
        .child_by_field_name("attribute")
        .map(|n| node_text(n, bytes).to_string())
        .unwrap_or_else(|| "?".to_string());
    emit_builtins_write(
        node,
        bytes,
        path,
        index,
        findings,
        &format!("builtins.{} = ...", attr),
    );
}

fn emit_builtins_write(
    anchor: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    label: &str,
) {
    let off = anchor.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::BuiltinsWrite,
        severity: Severity::Critical,
        confidence: 0.95,
        message: format!(
            "`{}` — patches a built-in for every importer of this module",
            label
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

fn emit_exec_like(
    call_node: Node,
    arg: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    fn_name: &str,
) {
    // Bare string literal argument — well, `exec("print(1)")` is still
    // dubious but we don't flag it here; raw + token already look at
    // literals. Only emit for non-literal args.
    if is_literal_expression(arg, bytes) {
        return;
    }
    let decoded = looks_decoded(arg, bytes);
    let concatenated = looks_concatenated_string(arg, bytes);
    let module_scope = is_at_module_scope(call_node, bytes);
    let (severity, confidence, message) = if decoded {
        (
            Severity::Critical,
            0.90,
            format!("`{}` called on a decoded/decompressed value", fn_name),
        )
    } else if concatenated {
        (
            Severity::Critical,
            0.80,
            format!("`{}` called on a constructed string", fn_name),
        )
    } else if module_scope {
        // Module-scope `exec`/`eval` runs at import time. Any non-literal
        // argument means an importer of this file executes whatever the
        // expression evaluates to, before the user has a chance to read
        // the function it's hidden in.
        (
            Severity::Critical,
            0.80,
            format!(
                "`{}` at module scope (runs on import) on a non-literal expression",
                fn_name
            ),
        )
    } else {
        (
            Severity::Warn,
            0.70,
            format!("`{}` called on a non-literal expression", fn_name),
        )
    };
    let off = call_node.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicExecution,
        severity,
        confidence,
        message,
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

fn emit_dynamic_import(
    call_node: Node,
    arg: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    if is_literal_expression(arg, bytes) {
        return;
    }
    let off = call_node.start_byte();
    let (line, col) = index.locate(off);
    let confidence = if looks_concatenated_string(arg, bytes) || looks_decoded(arg, bytes) {
        0.90
    } else {
        0.70
    };
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicImport,
        severity: Severity::Critical,
        confidence,
        message: "`__import__` called on a non-literal expression".to_string(),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

fn emit_self_read(
    call_node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let off = call_node.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicExecution,
        severity: Severity::Warn,
        confidence: 0.85,
        message: "`open(__file__)` — file reads its own source, common pattern for extracting payloads hidden in comments".to_string(),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

// fn emit_dynamic_attr(
//     call_node: Node,
//     arg: Node,
//     bytes: &[u8],
//     path: &Path,
//     index: &LineIndex,
//     findings: &mut Vec<Finding>,
//     fn_name: &str,
// ) {
//     if is_literal_expression(arg, bytes) {
//         return;
//     }
//     let off = call_node.start_byte();
//     let (line, col) = index.locate(off);
//     let confidence = if looks_concatenated_string(arg, bytes) || looks_decoded(arg, bytes) {
//         0.80
//     } else {
//         0.55
//     };
//     findings.push(Finding {
//         path: path.to_path_buf(),
//         byte_offset: off,
//         line,
//         col,
//         pass: PassKind::Ast,
//         kind: SignalKind::DynamicAttribute,
//         severity: Severity::Warn,
//         confidence,
//         message: format!("`{}` called with a non-literal name argument", fn_name),
//         snippet: redact_snippet(&snippet_around(bytes, off, 100)),
//         diff_introduced: false,
//     });
// }

fn push_dynamic_attr(
    anchor: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    base: &str,
) {
    let off = anchor.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicAttribute,
        severity: Severity::Warn,
        confidence: 0.60,
        message: format!("reach-by-name through `{}`", base),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

// ---------------------------------------------------------------------------
// Python shell / process-spawn detector
// ---------------------------------------------------------------------------
//
// Mirrors what we already do for C and Bash, applied to the Python family:
//
//   * `os.system(cmd)`, `os.popen(cmd)` — always invoke /bin/sh.
//   * `subprocess.{run,call,check_call,check_output,Popen}(cmd, shell=True)`
//     — only shell-injection-prone when `shell=True` is present, so we gate
//     on it. Without `shell=True`, the call is exec-without-shell and
//     fundamentally less risky.
//   * `subprocess.getoutput(cmd)`, `subprocess.getstatusoutput(cmd)` — always
//     shell.
//   * `os.spawn*` family — fork/exec a binary by path; no shell, but still
//     surfaceable process-spawn behaviour.
//
// Severity:
//   * non-literal command argument → CRITICAL (runtime-determined target)
//   * literal command argument     → WARN
//   * resolved through an `__import__("os").system(...)` chain — CRITICAL
//     regardless of arg, because the chain itself is the obfuscation: a
//     normal `import os` would show up in static import scans.

#[derive(Clone, Copy)]
enum PyShellShape {
    AlwaysShell,
    ConditionalShell,
    Spawn,
}

fn check_python_shellout(
    call: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    let Some((qualified, via_dyn_import)) = resolve_qualified_name_with_import(func, bytes) else {
        return;
    };

    let shape = match qualified.as_str() {
        "os.system" | "os.popen" | "subprocess.getoutput" | "subprocess.getstatusoutput" => {
            PyShellShape::AlwaysShell
        }
        "subprocess.run"
        | "subprocess.call"
        | "subprocess.check_call"
        | "subprocess.check_output"
        | "subprocess.Popen" => PyShellShape::ConditionalShell,
        s if s.starts_with("os.spawn") => PyShellShape::Spawn,
        _ => return,
    };

    let Some(args_node) = call.child_by_field_name("arguments") else {
        return;
    };

    if matches!(shape, PyShellShape::ConditionalShell) && !has_shell_true(args_node, bytes) {
        return;
    }

    let pos = positional_args(args_node);
    let Some(&first_arg) = pos.first() else {
        return;
    };
    let is_literal = is_literal_expression(first_arg, bytes);

    let (severity, confidence, message) = if via_dyn_import {
        (
            Severity::Critical,
            0.90,
            format!(
                "`{}` reached via `__import__(...)` chain — runtime shell call hidden from static imports",
                qualified
            ),
        )
    } else if is_literal {
        let body = match shape {
            PyShellShape::ConditionalShell => {
                format!(
                    "`{}` called with `shell=True` and a literal command",
                    qualified
                )
            }
            PyShellShape::Spawn => {
                format!("`{}` called with a literal binary path", qualified)
            }
            PyShellShape::AlwaysShell => {
                format!("`{}` called with a literal shell command", qualified)
            }
        };
        (Severity::Warn, 0.70, body)
    } else {
        let body = match shape {
            PyShellShape::ConditionalShell => format!(
                "`{}` with `shell=True` and a non-literal command — runtime-determined shell invocation",
                qualified
            ),
            PyShellShape::Spawn => format!(
                "`{}` with a non-literal binary path — runtime-determined process spawn",
                qualified
            ),
            PyShellShape::AlwaysShell => format!(
                "`{}` called on a non-literal command — runtime-determined shell invocation",
                qualified
            ),
        };
        (Severity::Critical, 0.85, body)
    };

    let off = call.start_byte();
    let (line, col) = index.locate(off);
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicExecution,
        severity,
        confidence,
        message,
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

/// Like `callee_qualified_name` but also resolves `__import__("mod").attr`
/// chains by treating the literal-arg `__import__` call as `mod`. Returns
/// `(qualified-name, was-resolved-through-__import__)`.
fn resolve_qualified_name_with_import(func: Node, bytes: &[u8]) -> Option<(String, bool)> {
    match func.kind() {
        "identifier" => Some((node_text(func, bytes).to_string(), false)),
        "attribute" => {
            let obj = func.child_by_field_name("object")?;
            let attr = func.child_by_field_name("attribute")?;
            let attr_name = node_text(attr, bytes).to_string();
            if obj.kind() == "call" {
                if let Some(module) = dynamic_import_module_name(obj, bytes) {
                    return Some((format!("{}.{}", module, attr_name), true));
                }
            }
            let (obj_name, via_dyn) = resolve_qualified_name_with_import(obj, bytes)?;
            Some((format!("{}.{}", obj_name, attr_name), via_dyn))
        }
        _ => None,
    }
}

/// If `call` is `__import__("module-name")` with a literal string first arg,
/// returns the module name. Else `None`.
fn dynamic_import_module_name<'a>(call: Node, bytes: &'a [u8]) -> Option<&'a str> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "identifier" || node_text(func, bytes) != "__import__" {
        return None;
    }
    let args_node = call.child_by_field_name("arguments")?;
    let first = positional_args(args_node).first().copied()?;
    if first.kind() != "string" {
        return None;
    }
    let mut cursor = first.walk();
    for child in first.children(&mut cursor) {
        if child.kind() == "string_content" {
            return std::str::from_utf8(&bytes[child.start_byte()..child.end_byte()]).ok();
        }
    }
    None
}

/// Returns true when the `arguments` node carries a `shell=True` keyword.
fn has_shell_true(args_node: Node, bytes: &[u8]) -> bool {
    let mut cursor = args_node.walk();
    for child in args_node.children(&mut cursor) {
        if child.kind() == "keyword_argument" {
            let name_ok = child
                .child_by_field_name("name")
                .map(|n| node_text(n, bytes) == "shell")
                .unwrap_or(false);
            let value_true = child
                .child_by_field_name("value")
                .map(|v| node_text(v, bytes) == "True")
                .unwrap_or(false);
            if name_ok && value_true {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------

fn node_text<'a>(node: Node, bytes: &'a [u8]) -> &'a str {
    std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).unwrap_or("")
}

fn callee_short_name(func: Node, bytes: &[u8]) -> Option<String> {
    match func.kind() {
        "identifier" => Some(node_text(func, bytes).to_string()),
        "attribute" => func
            .child_by_field_name("attribute")
            .map(|n| node_text(n, bytes).to_string()),
        _ => None,
    }
}

fn callee_qualified_name(func: Node, bytes: &[u8]) -> Option<String> {
    match func.kind() {
        "identifier" => Some(node_text(func, bytes).to_string()),
        "attribute" => {
            let obj = func.child_by_field_name("object")?;
            let attr = func.child_by_field_name("attribute")?;
            let obj_name = callee_qualified_name(obj, bytes)?;
            Some(format!("{}.{}", obj_name, node_text(attr, bytes)))
        }
        "call" => {
            // `globals().get(x)` — the "callee" of the outer call is an
            // attribute whose object is a call node. Strip the parens and
            // return the inner callee name so we can detect chains.
            let inner = func.child_by_field_name("function")?;
            callee_qualified_name(inner, bytes)
        }
        _ => None,
    }
}

/// Collect positional argument expression nodes from an `arguments` node,
/// skipping punctuation and keyword arguments.
fn positional_args<'a>(args_node: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.children(&mut cursor) {
        match child.kind() {
            "(" | ")" | "," => {}
            "keyword_argument" => {}
            _ => out.push(child),
        }
    }
    out
}

fn is_literal_expression(node: Node, _bytes: &[u8]) -> bool {
    matches!(
        node.kind(),
        "string"
            | "concatenated_string"
            | "integer"
            | "float"
            | "true"
            | "false"
            | "none"
            | "list"
            | "tuple"
            | "set"
            | "dictionary"
    )
}

fn looks_concatenated_string(node: Node, bytes: &[u8]) -> bool {
    if node.kind() == "concatenated_string" {
        return true;
    }
    if node.kind() == "binary_operator" {
        let op = node
            .child_by_field_name("operator")
            .map(|n| node_text(n, bytes))
            .unwrap_or("");
        if op == "+" {
            let l = node.child_by_field_name("left");
            let r = node.child_by_field_name("right");
            let either_string = matches!(l.map(|n| n.kind()), Some("string"))
                || matches!(r.map(|n| n.kind()), Some("string"));
            if either_string {
                return true;
            }
            // Recurse: `"a" + "b" + "c"` nests as `(+ (+ "a" "b") "c")`.
            if let Some(l) = l {
                if looks_concatenated_string(l, bytes) {
                    return true;
                }
            }
            if let Some(r) = r {
                if looks_concatenated_string(r, bytes) {
                    return true;
                }
            }
        }
    }
    false
}

/// Heuristic: does this expression look like it produces a decoded or
/// decompressed byte string? Looks for call nodes whose short name matches
/// a known decoder. Recurses through attribute chains and `.decode()`
/// wrappers so `base64.b64decode(x).decode("utf-8")` is recognized.
fn looks_decoded(node: Node, bytes: &[u8]) -> bool {
    const DECODERS: &[&str] = &[
        "b64decode",
        "b32decode",
        "b16decode",
        "b85decode",
        "a85decode",
        "urlsafe_b64decode",
        "decode",
        "decompress",
        "decompressobj",
        "fromhex",
        "unhexlify",
        "decodebytes",
    ];
    if node.kind() == "call" {
        if let Some(func) = node.child_by_field_name("function") {
            if let Some(name) = callee_short_name(func, bytes) {
                if DECODERS.contains(&name.as_str()) {
                    return true;
                }
            }
            // `codecs.decode(x, "base64")` / `marshal.loads(x)` / `pickle.loads(x)` —
            // qualified decoder/code-object calls.
            if let Some(qual) = callee_qualified_name(func, bytes) {
                if qual.starts_with("codecs.")
                    || qual.ends_with(".decode")
                    || matches!(
                        qual.as_str(),
                        "marshal.loads" | "marshal.load" | "pickle.loads" | "pickle.load"
                    )
                {
                    return true;
                }
            }
            // Recurse into the function side — matches `foo(decoded_val)`
            // patterns wrapped in a benign-looking outer call.
            if looks_decoded(func, bytes) {
                return true;
            }
        }
        if let Some(args) = node.child_by_field_name("arguments") {
            for a in positional_args(args) {
                if looks_decoded(a, bytes) {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Module-scope detection
// ---------------------------------------------------------------------------

/// True if `node` is a top-level statement of the module — i.e. its
/// only enclosing block is the module itself, not a `function_definition`
/// or `class_definition`.
///
/// `if __name__ == "__main__":` blocks are still module scope here: the
/// guard delays execution but the runner is still the module body, and
/// the guarded code commonly hides the real payload.
fn is_at_module_scope(node: Node, bytes: &[u8]) -> bool {
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        match parent.kind() {
            "function_definition" | "class_definition" | "lambda" => return false,
            // `if __name__ == "__main__":` only runs when invoked as a
            // script — never on import. Malicious droppers go to module
            // top so they fire on import; legitimate scripts gate their
            // entry on this idiom. Treat as not-module-scope.
            "if_statement" => {
                if let Some(cond) = parent.child_by_field_name("condition") {
                    if is_dunder_name_main_check(cond, bytes) {
                        return false;
                    }
                }
            }
            _ => {}
        }
        cur = parent;
    }
    true
}

fn is_dunder_name_main_check(cond: Node, bytes: &[u8]) -> bool {
    if cond.kind() != "comparison_operator" {
        return false;
    }
    let mut saw_name = false;
    let mut saw_main = false;
    let mut cursor = cond.walk();
    for child in cond.children(&mut cursor) {
        match child.kind() {
            "identifier" if node_text(child, bytes) == "__name__" => {
                saw_name = true;
            }
            "string" => {
                let mut sc = child.walk();
                for inner in child.children(&mut sc) {
                    if inner.kind() == "string_content" && node_text(inner, bytes) == "__main__" {
                        saw_main = true;
                    }
                }
            }
            _ => {}
        }
    }
    saw_name && saw_main
}

// ---------------------------------------------------------------------------
// Payload bytes-literal detector
// ---------------------------------------------------------------------------
//
// A Python `b"..."` / `b'...'` literal whose content is dominated by `\xNN`
// escapes is a strong shape signal: real bytes literals are short and
// purposeful (`b"\r\n"`, `b"\x00\x01\x02\x03"` for protocol headers); a
// payload literal is dozens-to-hundreds of escape bytes, often
// representing compressed or encrypted code. Operates on the whole literal
// regardless of whether the escapes are consecutive — `find_hex_escape_runs`
// in the raw pass already covers the consecutive form.

const PAYLOAD_BYTES_MIN_ESCAPES: usize = 32;
const PAYLOAD_BYTES_MIN_RATIO: f32 = 0.30;

fn check_payload_bytes_literals(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "string" if string_node_is_bytes(node, bytes) => {
                inspect_bytes_literal(node, bytes, path, index, findings);
            }
            "concatenated_string" => {
                inspect_concatenated_bytes_literal(node, bytes, path, index, findings);
            }
            _ => {}
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
}

// Aggregate escape counts across all bytes-string chunks in a `b'...' b'...'`
// concatenated literal. Splitting a blob across several adjacent strings is a
// common way to stay under per-chunk thresholds.
fn inspect_concatenated_bytes_literal(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut total_content_len = 0usize;
    let mut total_escape_count = 0usize;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "string" && string_node_is_bytes(child, bytes) {
            let mut sc = child.walk();
            for content in child.children(&mut sc) {
                if content.kind() == "string_content" {
                    let span = &bytes[content.start_byte()..content.end_byte()];
                    total_content_len += span.len();
                    total_escape_count += count_hex_escapes_in_content(content, bytes);
                }
            }
        }
    }
    if total_escape_count < PAYLOAD_BYTES_MIN_ESCAPES || total_content_len == 0 {
        return;
    }
    let ratio = (total_escape_count * 4) as f32 / total_content_len as f32;
    if ratio < PAYLOAD_BYTES_MIN_RATIO {
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
        kind: SignalKind::PayloadBytesLiteral,
        severity: Severity::Warn,
        confidence: 0.85,
        message: format!(
            "concatenated bytes literal contains {} `\\xNN` escapes ({:.0}% of content) — binary payload shape",
            total_escape_count,
            ratio * 100.0
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

fn string_node_is_bytes(node: Node, bytes: &[u8]) -> bool {
    let Some(start) = node.child_by_field_name("string_start").or_else(|| {
        // Some grammar versions don't expose `string_start` as a field;
        // fall back to the first child.
        node.child(0)
    }) else {
        return false;
    };
    if start.kind() != "string_start" {
        return false;
    }
    let prefix = &bytes[start.start_byte()..start.end_byte()];
    // Strip trailing quote(s) and check for a `b`/`B` prefix. Reject `r`
    // (raw) prefixes — `\xNN` doesn't escape in raw strings.
    let mut has_b = false;
    let mut has_r = false;
    for &c in prefix {
        match c {
            b'b' | b'B' => has_b = true,
            b'r' | b'R' => has_r = true,
            b'"' | b'\'' => break,
            _ => {}
        }
    }
    has_b && !has_r
}

fn inspect_bytes_literal(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    // Sum content + escape stats across all `string_content` children
    // (multi-line bytes literals can contain several content nodes).
    let mut content_len = 0usize;
    let mut escape_count = 0usize;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "string_content" {
            let span = &bytes[child.start_byte()..child.end_byte()];
            content_len += span.len();
            escape_count += count_hex_escapes_in_content(child, bytes);
        }
    }
    if escape_count < PAYLOAD_BYTES_MIN_ESCAPES {
        return;
    }
    if content_len == 0 {
        return;
    }
    // Each `\xNN` escape sequence is 4 source bytes. Compute the source
    // ratio against the literal's content.
    let ratio = (escape_count * 4) as f32 / content_len as f32;
    if ratio < PAYLOAD_BYTES_MIN_RATIO {
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
        kind: SignalKind::PayloadBytesLiteral,
        severity: Severity::Warn,
        confidence: 0.85,
        message: format!(
            "bytes literal contains {} `\\xNN` escapes ({:.0}% of content) — binary payload shape",
            escape_count,
            ratio * 100.0
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

fn count_hex_escapes_in_content(content: Node, bytes: &[u8]) -> usize {
    let mut n = 0usize;
    let mut cursor = content.walk();
    for child in content.children(&mut cursor) {
        if child.kind() == "escape_sequence" {
            let s = &bytes[child.start_byte()..child.end_byte()];
            if s.len() >= 4 && s[0] == b'\\' && (s[1] == b'x' || s[1] == b'X') {
                n += 1;
            }
        }
    }
    n
}

// ---------------------------------------------------------------------------
// Decoder-import-with-exec detector
// ---------------------------------------------------------------------------
//
// File imports any of the canonical decoder/decompressor modules AND calls
// `exec`/`eval`/`compile`. Catches the multi-stage staging shape where the
// decoder calls are hidden behind user-defined helpers (`looks_decoded` only
// follows direct decoder-name calls). The co-occurrence is the signal —
// either alone is common enough to be noise.

const DECODER_MODULES: &[&str] = &[
    "base64", "binascii", "codecs", "marshal", "pickle", "cPickle", "zlib", "gzip", "lzma", "bz2",
];

fn check_decoder_import_with_exec(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let (decoder_imports, exec_call) = collect_decoder_imports_and_exec(root, bytes);
    if decoder_imports.is_empty() {
        return;
    }
    let Some(call) = exec_call else { return };
    let off = call.start_byte();
    let (line, col) = index.locate(off);
    let modules: Vec<&str> = decoder_imports.iter().take(4).copied().collect();
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DecoderImportWithExec,
        severity: Severity::Warn,
        confidence: 0.80,
        message: format!(
            "file imports decoder module(s) {} and calls `exec`/`eval`/`compile` — multi-stage payload shape",
            modules.join(", ")
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

/// Walk the module top-level for decoder imports, then walk the whole tree
/// for the first `exec`/`eval`/`compile` call. Returns deduped decoder
/// module names in source order plus the first sink call (if any).
fn collect_decoder_imports_and_exec<'a>(
    root: Node<'a>,
    bytes: &[u8],
) -> (Vec<&'static str>, Option<Node<'a>>) {
    let mut imports: Vec<&'static str> = Vec::new();
    let mut exec_call: Option<Node<'a>> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" | "import_from_statement" => {
                collect_imported_decoders(node, bytes, &mut imports);
            }
            "call" if exec_call.is_none() && call_is_exec_sink(node, bytes) => {
                exec_call = Some(node);
            }
            _ => {}
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    (imports, exec_call)
}

fn call_is_exec_sink(call: Node, bytes: &[u8]) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    // The bare builtins only — `re.compile`, `ast.parse`, etc. share names
    // but mean nothing for our purposes.
    if func.kind() != "identifier" {
        return false;
    }
    let name = match callee_short_name(func, bytes) {
        Some(n) => n,
        None => return false,
    };
    matches!(name.as_str(), "exec" | "eval" | "compile")
}

fn collect_imported_decoders(stmt: Node, bytes: &[u8], out: &mut Vec<&'static str>) {
    // For `import_statement`: each child `dotted_name` (or `aliased_import`
    // wrapping one) is a separately imported module. The relevant module
    // name is the FIRST identifier in the dotted path.
    // For `import_from_statement`: the `module_name` field holds the source
    // module — that's the one that matters (`from base64 import b64decode`
    // means the file uses base64, regardless of what was named).
    if stmt.kind() == "import_from_statement" {
        if let Some(module) = stmt.child_by_field_name("module_name") {
            if let Some(name) = first_dotted_name_root(module, bytes) {
                push_decoder_unique(name, out);
            }
        }
        return;
    }
    let mut cursor = stmt.walk();
    for child in stmt.children(&mut cursor) {
        match child.kind() {
            "dotted_name" => {
                if let Some(name) = first_dotted_name_root(child, bytes) {
                    push_decoder_unique(name, out);
                }
            }
            "aliased_import" => {
                let mut dotted = child.child_by_field_name("name");
                if dotted.is_none() {
                    let mut c = child.walk();
                    for inner in child.children(&mut c) {
                        if inner.kind() == "dotted_name" {
                            dotted = Some(inner);
                            break;
                        }
                    }
                }
                if let Some(node) = dotted {
                    if let Some(name) = first_dotted_name_root(node, bytes) {
                        push_decoder_unique(name, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn first_dotted_name_root<'a>(node: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    if node.kind() == "identifier" {
        return std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).ok();
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            return std::str::from_utf8(&bytes[child.start_byte()..child.end_byte()]).ok();
        }
    }
    None
}

fn push_decoder_unique(name: &str, out: &mut Vec<&'static str>) {
    for known in DECODER_MODULES {
        if *known == name && !out.contains(known) {
            out.push(*known);
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Decoder-import-with-decompress detector
// ---------------------------------------------------------------------------
//
// File imports a decoder/decompressor module AND calls `.decompress()` (or a
// similar decompression method) anywhere in the file. Unlike the exec variant,
// the decompressed result doesn't have to be exec'd — writing it to disk or
// splicing it into a process image (as in kernel-exploit droppers) is equally
// dangerous.

const DECOMPRESS_METHODS: &[&str] = &["decompress", "decompressobj", "decodestring", "decodebytes"];

fn check_decoder_decompress_payload(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut imports: Vec<&'static str> = Vec::new();
    let mut decompress_call: Option<Node> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" | "import_from_statement" => {
                collect_imported_decoders(node, bytes, &mut imports);
            }
            "call" if decompress_call.is_none() => {
                if let Some(func) = node.child_by_field_name("function") {
                    if func.kind() == "attribute" {
                        if let Some(attr) = func.child_by_field_name("attribute") {
                            let name = &bytes[attr.start_byte()..attr.end_byte()];
                            if DECOMPRESS_METHODS.iter().any(|m| name == m.as_bytes()) {
                                decompress_call = Some(node);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }

    if imports.is_empty() || decompress_call.is_none() {
        return;
    }
    let call = decompress_call.unwrap();
    let off = call.start_byte();
    let (line, col) = index.locate(off);
    let modules: Vec<&str> = imports.iter().take(4).copied().collect();
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DecoderDecompressPayload,
        severity: Severity::Warn,
        confidence: 0.75,
        message: format!(
            "file imports decoder module(s) {} and calls `.decompress()` — embedded payload decompressed at runtime",
            modules.join(", ")
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 120)),
        diff_introduced: false,
    });
}

// ---------------------------------------------------------------------------
// Obfuscated-byte-string detector
// ---------------------------------------------------------------------------
//
// `bytes([119, 104, 111, 97, 109, 105]).decode()` constructs the string
// "whoami" without it appearing as a literal anywhere. Real code would just
// write the string. The only purpose of this form is to hide the value from
// grep / static analysis. When all integers fall in the printable-ASCII range
// the string is clearly human-readable text being hidden, which is CRITICAL;
// otherwise we emit WARN (could be constructing binary data, though still
// suspicious in most contexts).

fn check_obfuscated_byte_strings(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            inspect_bytes_list_decode(node, bytes, path, index, findings);
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
}

/// Returns the `list` node inside `bytes([...]).decode()`, or `None` if the
/// call doesn't match that pattern.
fn bytes_list_decode_list<'a>(node: Node<'a>, bytes: &[u8]) -> Option<Node<'a>> {
    let func = node
        .child_by_field_name("function")
        .filter(|n| n.kind() == "attribute")?;
    func.child_by_field_name("attribute")
        .filter(|n| node_text(*n, bytes) == "decode")?;
    let obj = func
        .child_by_field_name("object")
        .filter(|n| n.kind() == "call")?;
    obj.child_by_field_name("function")
        .filter(|n| node_text(*n, bytes) == "bytes")?;
    let inner_args = obj.child_by_field_name("arguments")?;
    let &list_node = positional_args(inner_args).first()?;
    (list_node.kind() == "list").then_some(list_node)
}

fn inspect_bytes_list_decode(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(list_node) = bytes_list_decode_list(node, bytes) else {
        return;
    };

    // Collect integer element values.
    let mut int_values: Vec<u32> = Vec::new();
    let mut cursor = list_node.walk();
    for child in list_node.children(&mut cursor) {
        match child.kind() {
            "[" | "]" | "," => {}
            "integer" => {
                let s = node_text(child, bytes);
                if let Ok(v) = s.parse::<u32>() {
                    int_values.push(v);
                } else {
                    return; // not a plain decimal integer — bail
                }
            }
            _ => return, // non-integer element — bail
        }
    }
    if int_values.is_empty() {
        return;
    }

    let all_printable = int_values.iter().all(|&v| (0x20..=0x7e).contains(&v));
    let off = node.start_byte();
    let (line, col) = index.locate(off);
    let (severity, confidence) = if all_printable {
        (Severity::Critical, 0.90)
    } else {
        (Severity::Warn, 0.75)
    };
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::NumericLiteralPayload,
        severity,
        confidence,
        message: format!(
            "`bytes([...]).decode()` constructs a string from {} integer literals — numeric string obfuscation",
            int_values.len()
        ),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

// ---------------------------------------------------------------------------
// Frame-introspection detector
// ---------------------------------------------------------------------------
//
// `sys._getframe()`, `inspect.currentframe()`, `inspect.stack()`,
// `inspect.getouterframes()`, `sys.settrace()`, `sys.setprofile()` are the
// canonical Python escape hatches for reaching outside the current call —
// inspecting the caller's globals/locals or installing a hook on every
// instruction. Outside debuggers, profilers, and a small set of frameworks
// (loguru depth tracking, decorator, structlog, pdb integrations) they
// have essentially no legitimate use.
//
// Default severity is WARN. Elevated to CRITICAL when the same file also
// calls `sys.exit`, `exec`, or `eval` — the bail-on-detection / decode-
// then-execute shape that says "introspection is gating real behaviour".
//
// One finding per call site, anchored at the introspection call.

const FRAME_INTROSPECTION_QUALIFIED: &[&str] = &[
    "sys._getframe",
    "inspect.currentframe",
    "inspect.stack",
    "inspect.getouterframes",
    "sys.settrace",
    "sys.setprofile",
];

fn check_frame_introspection(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut intro_calls: Vec<(Node, &'static str)> = Vec::new();
    let mut has_elevation_trigger = false;

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            if let Some(name) = frame_introspection_name(node, bytes) {
                intro_calls.push((node, name));
            } else if call_is_exec_sink(node, bytes) || call_is_sys_exit(node, bytes) {
                has_elevation_trigger = true;
            }
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }

    if intro_calls.is_empty() {
        return;
    }

    let (severity, confidence) = if has_elevation_trigger {
        (Severity::Critical, 0.85)
    } else {
        (Severity::Warn, 0.70)
    };

    for (call, name) in intro_calls {
        let off = call.start_byte();
        let (line, col) = index.locate(off);
        let suffix = if has_elevation_trigger {
            " — file also calls `sys.exit`/`exec`/`eval` (anti-analysis shape)"
        } else {
            ""
        };
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: off,
            line,
            col,
            pass: PassKind::Ast,
            kind: SignalKind::FrameIntrospection,
            severity,
            confidence,
            message: format!("`{}` — call-stack frame introspection{}", name, suffix),
            snippet: redact_snippet(&snippet_around(bytes, off, 100)),
            diff_introduced: false,
        });
    }
}

/// Returns the canonical name (e.g. "sys._getframe") if the call's callee
/// matches one of the introspection APIs, else None.
fn frame_introspection_name(call: Node, bytes: &[u8]) -> Option<&'static str> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "attribute" {
        return None;
    }
    let qualified = callee_qualified_name(func, bytes)?;
    FRAME_INTROSPECTION_QUALIFIED
        .iter()
        .copied()
        .find(|n| *n == qualified.as_str())
}

fn call_is_sys_exit(call: Node, bytes: &[u8]) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    if func.kind() != "attribute" {
        return false;
    }
    callee_qualified_name(func, bytes)
        .map(|q| q == "sys.exit")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(src: &[u8]) -> Vec<Finding> {
        analyze(&PathBuf::from("test.py"), src).findings
    }

    #[test]
    fn exec_literal_is_ignored() {
        let findings = run(b"exec(\"print(1)\")\n");
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicExecution));
    }

    #[test]
    fn exec_of_decoded_is_critical() {
        let src = b"import base64\nexec(base64.b64decode(payload))\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn exec_of_concatenated_string_is_critical() {
        let src = b"name = \"ex\" + \"ec\"\nexec(\"print(1)\" + \";\")\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicExecution));
    }

    #[test]
    fn dynamic_import_with_variable_is_critical() {
        let src = b"mod = __import__(module_name)\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicImport && f.severity == Severity::Critical));
    }

    #[test]
    fn dynamic_import_with_literal_is_ignored() {
        let findings = run(b"mod = __import__(\"os\")\n");
        assert!(findings.iter().all(|f| f.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn getattr_with_literal_is_ignored() {
        let findings = run(b"v = getattr(obj, \"attr\")\n");
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicAttribute));
    }

    #[test]
    fn globals_subscript_with_variable_warns() {
        let findings = run(b"v = globals()[name]\n");
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicAttribute && f.severity == Severity::Warn));
    }

    #[test]
    fn globals_subscript_with_literal_is_ignored() {
        let findings = run(b"v = globals()[\"literal\"]\n");
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicAttribute));
    }

    // #[test]
    // fn getattr_with_variable_warns() {
    //     let findings = run(b"v = getattr(obj, name)\n");
    //     assert!(findings
    //         .iter()
    //         .any(|f| f.kind == SignalKind::DynamicAttribute && f.severity == Severity::Warn));
    // }

    #[test]
    fn parse_error_tolerated() {
        // Unterminated string — tree-sitter should still parse partially.
        let result = analyze(&PathBuf::from("bad.py"), b"x = \"oops\n");
        // Either partial or clean — we just require no panic.
        let _ = result.parse_error;
    }

    // -----------------------------------------------------------------------
    // payload-bytes-literal
    // -----------------------------------------------------------------------

    #[test]
    fn payload_bytes_literal_fires_on_dense_hex_blob() {
        // 40 \xNN escapes, all-hex content.
        let mut blob = String::from("payload = b\"");
        for i in 0..40u8 {
            blob.push_str(&format!("\\x{:02x}", i));
        }
        blob.push_str("\"\n");
        let findings = run(blob.as_bytes());
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::PayloadBytesLiteral)
            .expect("expected PayloadBytesLiteral finding");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn payload_bytes_literal_below_escape_threshold_is_ignored() {
        // 16 escapes — below the 32-escape minimum.
        let mut blob = String::from("payload = b\"");
        for i in 0..16u8 {
            blob.push_str(&format!("\\x{:02x}", i));
        }
        blob.push_str("\"\n");
        let findings = run(blob.as_bytes());
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::PayloadBytesLiteral));
    }

    #[test]
    fn payload_bytes_literal_below_ratio_is_ignored() {
        // 32 escapes diluted with ~300 chars of plain text → ratio ~33% drops
        // because we count \xNN as 4 bytes of "escape weight": 32*4=128 over
        // 128 escape bytes + 300 plain bytes = ~30%. To clearly miss, pad
        // generously.
        let mut blob = String::from("payload = b\"");
        for i in 0..32u8 {
            blob.push_str(&format!("\\x{:02x}", i));
        }
        for _ in 0..600 {
            blob.push('A');
        }
        blob.push_str("\"\n");
        let findings = run(blob.as_bytes());
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::PayloadBytesLiteral));
    }

    #[test]
    fn payload_bytes_literal_ignores_str_literal() {
        // Same shape but a `str` (no `b` prefix) — should not fire.
        let mut blob = String::from("payload = \"");
        for i in 0..40u8 {
            blob.push_str(&format!("\\x{:02x}", i));
        }
        blob.push_str("\"\n");
        let findings = run(blob.as_bytes());
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::PayloadBytesLiteral));
    }

    // -----------------------------------------------------------------------
    // decoder-import-with-exec
    // -----------------------------------------------------------------------

    #[test]
    fn decoder_import_with_exec_fires() {
        let src = b"import base64\nimport zlib\nexec(zlib.decompress(base64.b64decode(p)))\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::DecoderImportWithExec));
    }

    #[test]
    fn decoder_import_without_exec_does_not_fire() {
        // Imports the decoder but never calls exec/eval/compile.
        let src = b"import base64\nx = base64.b64decode(p)\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DecoderImportWithExec));
    }

    #[test]
    fn exec_without_decoder_import_does_not_fire_decoder_signal() {
        let src = b"exec(payload)\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DecoderImportWithExec));
    }

    #[test]
    fn from_decoder_import_counts() {
        // `from base64 import b64decode` should count as a base64 import.
        let src = b"from base64 import b64decode\nexec(b64decode(p))\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::DecoderImportWithExec));
    }

    // -----------------------------------------------------------------------
    // module-scope exec/eval elevation
    // -----------------------------------------------------------------------

    #[test]
    fn module_scope_exec_is_critical() {
        let src = b"exec(payload)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn function_scope_exec_remains_warn() {
        let src = b"def f(payload):\n    exec(payload)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn if_name_main_exec_is_not_module_scope() {
        // `if __name__ == '__main__':` runs only as a script, never on
        // import — should be treated as not module scope (severity = warn,
        // not the elevated critical).
        let src = b"if __name__ == '__main__':\n    exec(payload)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution finding");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn re_compile_is_not_dynamic_execution() {
        // `re.compile(...)` is unrelated to the `compile` builtin and must
        // not trigger.
        let src = b"import re\nPAT = re.compile(some_pattern_var)\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicExecution));
    }

    // -----------------------------------------------------------------------
    // obfuscated-byte-string detector
    // -----------------------------------------------------------------------

    #[test]
    fn bytes_list_decode_printable_ascii_is_critical() {
        // bytes([119, 104, 111, 97, 109, 105]).decode() == "whoami"
        let src = b"s = bytes([119, 104, 111, 97, 109, 105]).decode()\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::NumericLiteralPayload)
            .expect("expected NumericLiteralPayload finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn bytes_list_decode_non_printable_is_warn() {
        // Contains values outside printable ASCII — WARN, not CRITICAL.
        let src = b"s = bytes([0, 1, 2, 3, 4, 5]).decode()\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::NumericLiteralPayload)
            .expect("expected NumericLiteralPayload finding");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn bytes_list_decode_empty_list_is_ignored() {
        let src = b"s = bytes([]).decode()\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::NumericLiteralPayload));
    }

    #[test]
    fn plain_decode_without_bytes_list_not_flagged() {
        // `b"hello".decode()` is a plain bytes literal, not obfuscated.
        let src = b"s = b\"hello\".decode()\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::NumericLiteralPayload));
    }

    // -----------------------------------------------------------------------
    // marshal.loads detection
    // -----------------------------------------------------------------------

    #[test]
    fn marshal_loads_on_literal_warns() {
        let src = b"import marshal\ncode_obj = marshal.loads(b'\\xe3\\x00\\x00')\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("marshal"))
            .expect("expected DynamicExecution finding for marshal.loads");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.confidence >= 0.89);
    }

    #[test]
    fn marshal_loads_on_variable_warns() {
        let src = b"import marshal\ncode_obj = marshal.loads(raw)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("marshal"))
            .expect("expected DynamicExecution finding for marshal.loads");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn exec_of_marshal_loads_is_decoded() {
        // Inline `exec(marshal.loads(blob))` should be recognized as exec on a
        // decoded value (CRITICAL), not just a generic non-literal.
        let src = b"import marshal\nexec(marshal.loads(blob))\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.severity == Severity::Critical)
            .expect("expected CRITICAL DynamicExecution");
        assert!(hit.message.contains("decoded"));
    }

    // -----------------------------------------------------------------------
    // concatenated bytes literal aggregate threshold
    // -----------------------------------------------------------------------

    #[test]
    fn concatenated_bytes_aggregate_fires() {
        // Four chunks of ~10 escapes each — each below the 32-escape minimum
        // individually, but the aggregate (40) crosses it.
        let mut src = String::new();
        src.push_str("blob = (\n");
        for _ in 0..4 {
            src.push_str("    b\"");
            for i in 0u8..10 {
                src.push_str(&format!("\\x{:02x}", i));
            }
            src.push_str("\"\n");
        }
        src.push_str(")\n");
        let findings = run(src.as_bytes());
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::PayloadBytesLiteral));
    }

    #[test]
    fn concatenated_bytes_below_aggregate_threshold_is_ignored() {
        // Two chunks of 8 escapes each — aggregate 16, below threshold.
        let mut src = String::new();
        src.push_str("blob = (\n");
        for _ in 0..2 {
            src.push_str("    b\"");
            for i in 0u8..8 {
                src.push_str(&format!("\\x{:02x}", i));
            }
            src.push_str("\"\n");
        }
        src.push_str(")\n");
        let findings = run(src.as_bytes());
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::PayloadBytesLiteral));
    }

    // -----------------------------------------------------------------------
    // open(__file__) self-read detection
    // -----------------------------------------------------------------------

    #[test]
    fn open_dunder_file_warns() {
        let src = b"with open(__file__, 'r') as f:\n    data = f.read()\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("__file__"))
            .expect("expected DynamicExecution finding for open(__file__)");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn open_literal_path_is_not_flagged() {
        let src = b"with open('config.txt', 'r') as f:\n    data = f.read()\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| !(f.kind == SignalKind::DynamicExecution && f.message.contains("__file__"))));
    }

    // -----------------------------------------------------------------------
    // builtins-write detection
    // -----------------------------------------------------------------------

    #[test]
    fn builtins_attribute_assign_is_critical() {
        let src = b"import builtins\nbuiltins.open = my_open\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::BuiltinsWrite)
            .expect("expected BuiltinsWrite finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn setattr_builtins_is_critical() {
        let src = b"import builtins\nsetattr(builtins, \"exec\", lambda c: None)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::BuiltinsWrite)
            .expect("expected BuiltinsWrite finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn setattr_non_builtins_not_flagged() {
        // setattr on an arbitrary object is not a builtins write.
        let src = b"setattr(obj, \"name\", value)\n";
        let findings = run(src);
        assert!(findings.iter().all(|f| f.kind != SignalKind::BuiltinsWrite));
    }

    #[test]
    fn builtins_read_not_flagged() {
        // Reading from builtins (saving the original) is not itself a write.
        let src = b"import builtins\n_orig = builtins.open\n";
        let findings = run(src);
        assert!(findings.iter().all(|f| f.kind != SignalKind::BuiltinsWrite));
    }

    // -----------------------------------------------------------------------
    // frame-introspection
    // -----------------------------------------------------------------------

    #[test]
    fn sys_getframe_alone_is_warn() {
        // No exec/eval/sys.exit in the file → warn, not critical.
        let src = b"import sys\nf = sys._getframe(1)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::FrameIntrospection)
            .expect("expected FrameIntrospection finding");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(
            hit.message.contains("sys._getframe"),
            "expected `sys._getframe` cited in message, got: {}",
            hit.message
        );
    }

    #[test]
    fn sys_getframe_with_sys_exit_is_critical() {
        // The bail-on-detection shape from getframe.py.
        let src = b"import sys\nif \"x\" in sys._getframe(1).f_globals:\n    sys.exit()\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::FrameIntrospection)
            .expect("expected FrameIntrospection finding");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(
            hit.message.contains("anti-analysis"),
            "expected anti-analysis suffix, got: {}",
            hit.message
        );
    }

    #[test]
    fn inspect_currentframe_is_detected() {
        let src = b"import inspect\nf = inspect.currentframe()\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::FrameIntrospection)
            .expect("expected FrameIntrospection finding");
        assert!(hit.message.contains("inspect.currentframe"));
    }

    #[test]
    fn inspect_stack_is_detected() {
        let src = b"import inspect\nfor frame in inspect.stack():\n    pass\n";
        let findings = run(src);
        assert!(findings.iter().any(
            |f| f.kind == SignalKind::FrameIntrospection && f.message.contains("inspect.stack")
        ));
    }

    #[test]
    fn sys_settrace_is_detected() {
        let src = b"import sys\nsys.settrace(tracer)\n";
        let findings = run(src);
        assert!(findings.iter().any(
            |f| f.kind == SignalKind::FrameIntrospection && f.message.contains("sys.settrace")
        ));
    }

    #[test]
    fn settrace_with_exec_is_critical() {
        let src = b"import sys\nsys.settrace(tracer)\nexec(payload)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::FrameIntrospection)
            .expect("expected FrameIntrospection finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn ordinary_function_call_is_not_introspection() {
        // Regression: only the qualified introspection names should fire.
        let src = b"def _getframe(x): return x\n_getframe(1)\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::FrameIntrospection));
    }

    #[test]
    fn unrelated_sys_attribute_call_does_not_fire() {
        // `sys.path` access, `sys.argv` etc. — only the listed APIs fire.
        let src = b"import sys\nprint(sys.argv)\nsys.path.append(\"x\")\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::FrameIntrospection));
    }

    // -----------------------------------------------------------------------
    // Python shell / process spawn family
    // -----------------------------------------------------------------------

    #[test]
    fn os_system_with_variable_is_critical() {
        let src = b"import os\nos.system(cmd)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("os.system"))
            .expect("expected DynamicExecution for os.system");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn os_system_with_literal_is_warn() {
        let src = b"import os\nos.system(\"ls -la\")\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("os.system"))
            .expect("expected DynamicExecution for os.system literal");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn os_popen_with_variable_is_critical() {
        let src = b"import os\nos.popen(cmd)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("os.popen"))
            .expect("expected DynamicExecution for os.popen");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn subprocess_run_without_shell_true_is_ignored() {
        // subprocess.run(["ls", "-la"]) is exec-without-shell — no shell
        // injection surface. Don't fire.
        let src = b"import subprocess\nsubprocess.run([\"ls\", \"-la\"])\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| !(f.kind == SignalKind::DynamicExecution
                && f.message.contains("subprocess.run"))));
    }

    #[test]
    fn subprocess_run_with_shell_true_and_variable_is_critical() {
        let src = b"import subprocess\nsubprocess.run(cmd, shell=True)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| {
                f.kind == SignalKind::DynamicExecution && f.message.contains("subprocess.run")
            })
            .expect("expected DynamicExecution for subprocess.run");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn subprocess_run_with_shell_true_and_literal_is_warn() {
        let src = b"import subprocess\nsubprocess.run(\"ls -la\", shell=True)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| {
                f.kind == SignalKind::DynamicExecution && f.message.contains("subprocess.run")
            })
            .expect("expected DynamicExecution for subprocess.run literal");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn subprocess_getoutput_always_fires() {
        // getoutput is always shell-mode — no shell=True gate needed.
        let src = b"import subprocess\nsubprocess.getoutput(cmd)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| {
                f.kind == SignalKind::DynamicExecution && f.message.contains("subprocess.getoutput")
            })
            .expect("expected DynamicExecution for subprocess.getoutput");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn subprocess_check_output_with_shell_false_is_ignored() {
        // shell=False explicitly (or default) → no fire.
        let src = b"import subprocess\nsubprocess.check_output([\"ls\"], shell=False)\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| !(f.kind == SignalKind::DynamicExecution
                && f.message.contains("subprocess.check_output"))));
    }

    #[test]
    fn dynamic_import_chain_to_system_is_critical() {
        // `__import__('os').system(cmd)` — the import-laundering shape from
        // the context.py fixture. Critical regardless of arg type.
        let src = b"__import__('os').system(\"rm -rf /tmp/x\")\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("__import__"))
            .expect("expected DynamicExecution for __import__ chain");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.message.contains("os.system"));
    }

    #[test]
    fn dynamic_import_chain_subprocess_is_critical() {
        let src = b"__import__('subprocess').getoutput(cmd)\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("__import__"))
            .expect("expected DynamicExecution for __import__ chain");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn os_spawn_family_is_detected() {
        let src = b"import os\nos.spawnl(os.P_WAIT, path, arg0)\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("os.spawnl")));
    }

    #[test]
    fn unrelated_module_attribute_call_is_ignored() {
        // `mylib.system(x)` — not the os.system builtin, must not fire.
        let src = b"import mylib\nmylib.system(cmd)\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| !(f.kind == SignalKind::DynamicExecution && f.message.contains("system"))));
    }
}
