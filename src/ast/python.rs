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
    match node.kind() {
        "call" => check_call(node, bytes, path, index, findings),
        "subscript" => check_subscript(node, bytes, path, index, findings),
        _ => {}
    }
    for child in node.children(cursor) {
        // child iteration consumes the cursor; take a fresh one for recursion.
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
    let Some(args_node) = node.child_by_field_name("arguments") else {
        return;
    };
    let args = positional_args(args_node);

    // Which callable?
    let short = callee_short_name(func, bytes);
    let qualified = callee_qualified_name(func, bytes);

    match short.as_deref() {
        Some("exec") | Some("eval") | Some("compile") => {
            if let Some(arg) = args.first() {
                emit_exec_like(
                    node,
                    *arg,
                    bytes,
                    path,
                    index,
                    findings,
                    short.as_deref().unwrap(),
                );
            }
        }
        Some("__import__") => {
            if let Some(arg) = args.first() {
                emit_dynamic_import(node, *arg, bytes, path, index, findings);
            }
        }
        Some("getattr") | Some("setattr") | Some("hasattr") | Some("delattr") => {
            if let Some(arg) = args.get(1) {
                emit_dynamic_attr(
                    node,
                    *arg,
                    bytes,
                    path,
                    index,
                    findings,
                    short.as_deref().unwrap(),
                );
            }
        }
        _ => {}
    }

    // `globals()[x]` / `vars()[x]` / `globals().get(x)` style.
    // These present as subscript or attribute chains with a `globals()`/
    // `vars()` base. tree-sitter-python exposes the subscript form as
    // `subscript` with a `value` field that is the base expression and a
    // `subscript` field that is the index.
    if let Some(name) = qualified.as_deref() {
        if matches!(name, "globals.get" | "vars.get" | "locals.get") {
            if let Some(arg) = args.first() {
                if !is_literal_expression(*arg, bytes) {
                    push_dynamic_attr(node, bytes, path, index, findings, name);
                }
            }
        }
    }
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
    } else {
        (
            Severity::Critical,
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

fn emit_dynamic_attr(
    call_node: Node,
    arg: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    fn_name: &str,
) {
    if is_literal_expression(arg, bytes) {
        return;
    }
    let off = call_node.start_byte();
    let (line, col) = index.locate(off);
    let confidence = if looks_concatenated_string(arg, bytes) || looks_decoded(arg, bytes) {
        0.80
    } else {
        0.55
    };
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::DynamicAttribute,
        severity: Severity::Warn,
        confidence,
        message: format!("`{}` called with a non-literal name argument", fn_name),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

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
            // `codecs.decode(x, "base64")` — also decoder-shaped.
            if let Some(qual) = callee_qualified_name(func, bytes) {
                if qual.starts_with("codecs.") || qual.ends_with(".decode") {
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
        assert!(findings.iter().any(|f| f.kind == SignalKind::DynamicAttribute
            && f.severity == Severity::Warn));
    }

    #[test]
    fn globals_subscript_with_literal_is_ignored() {
        let findings = run(b"v = globals()[\"literal\"]\n");
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicAttribute));
    }

    #[test]
    fn getattr_with_variable_warns() {
        let findings = run(b"v = getattr(obj, name)\n");
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicAttribute && f.severity == Severity::Warn));
    }

    #[test]
    fn parse_error_tolerated() {
        // Unterminated string — tree-sitter should still parse partially.
        let result = analyze(&PathBuf::from("bad.py"), b"x = \"oops\n");
        // Either partial or clean — we just require no panic.
        let _ = result.parse_error;
    }
}
