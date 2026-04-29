//! TypeScript / JavaScript AST walker — tree-sitter-typescript based checks.
//!
//! The walker uses `LANGUAGE_TYPESCRIPT` for `.ts`/`.js`/`.mjs`/`.cjs` and
//! `LANGUAGE_TSX` for `.tsx`/`.jsx`, since the TS grammar alone does not
//! parse JSX syntax.
//!
//! Per SPEC §ast, the JS/TS checks are:
//!
//!   * `eval(x)` with non-literal `x` → DynamicExecution CRITICAL.
//!   * `Function(x)` or `new Function(x)` with non-literal `x` →
//!     DynamicExecution CRITICAL.
//!   * `require(x)` with non-literal `x` → DynamicImport WARN.
//!   * `import(x)` dynamic import with non-literal `x` → DynamicImport WARN.
//!   * `setTimeout(s, ...)` / `setInterval(s, ...)` where `s` is a string
//!     literal (string form of setTimeout is eval) → DynamicExecution WARN.
//!   * `process.binding(...)` (Node internal binding escape hatch) →
//!     DynamicAttribute WARN.
//!
//! Template strings with no `${}` substitution count as literals. Template
//! strings with substitutions are treated as constructed strings, as is
//! `a + b` binary-plus with any string operand.

use std::path::Path;

use tree_sitter::{Node, Parser};

use super::AstOutcome;
use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::language::Language;
use crate::util::{snippet_around, LineIndex};

pub fn analyze(path: &Path, bytes: &[u8], _lang: Language) -> AstOutcome {
    let use_tsx = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e, "tsx" | "jsx"))
        .unwrap_or(false);
    let grammar: tree_sitter::Language = if use_tsx {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
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
        "call_expression" => check_call(node, bytes, path, index, findings),
        "new_expression" => check_new(node, bytes, path, index, findings),
        _ => {}
    }
    for child in node.children(cursor) {
        let mut sub = child.walk();
        walk(child, bytes, path, index, findings, &mut sub);
    }
}

// ---------------------------------------------------------------------------
// call_expression
// ---------------------------------------------------------------------------

fn check_call(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(func) = call_function(node) else {
        return;
    };
    let Some(args) = call_arguments(node) else {
        return;
    };
    let positional: Vec<Node> = positional_args(args);

    // Dynamic `import(x)` — the callee is an `import` keyword node.
    if func.kind() == "import" {
        if let Some(first) = positional.first() {
            if !is_literal_expression(*first) {
                push(
                    findings,
                    node,
                    bytes,
                    path,
                    index,
                    SignalKind::DynamicImport,
                    Severity::Warn,
                    confidence_for_arg(*first, bytes, 0.80, 0.65),
                    "dynamic `import(...)` with a non-literal specifier".into(),
                );
            }
        }
        return;
    }

    // Simple identifier callees: eval / Function / require / setTimeout / setInterval
    if func.kind() == "identifier" {
        match node_text(func, bytes) {
            "eval" => {
                if let Some(first) = positional.first() {
                    if !is_literal_expression(*first) {
                        push(
                            findings,
                            node,
                            bytes,
                            path,
                            index,
                            SignalKind::DynamicExecution,
                            Severity::Critical,
                            confidence_for_arg(*first, bytes, 0.90, 0.75),
                            "`eval` called with a non-literal expression".into(),
                        );
                    }
                }
            }
            "Function" => {
                if let Some(first) = positional.first() {
                    emit_function_ctor(node, *first, bytes, path, index, findings);
                }
            }
            "require" => {
                if let Some(first) = positional.first() {
                    if !is_literal_expression(*first) {
                        push(
                            findings,
                            node,
                            bytes,
                            path,
                            index,
                            SignalKind::DynamicImport,
                            Severity::Warn,
                            confidence_for_arg(*first, bytes, 0.80, 0.60),
                            "`require` called with a non-literal specifier".into(),
                        );
                    }
                }
            }
            // `atob(x)` decodes base64 at runtime — the first step in the
            // classic "store payload as base64, decode and request/exec at
            // runtime" DPRK supply-chain pattern. Any call is suspicious since
            // legitimate uses are rare in library or server code. `btoa(x)`
            // encodes; less immediately dangerous but used for exfiltration.
            "atob" => {
                if let Some(first) = positional.first() {
                    let msg = if is_literal_expression(*first) {
                        "`atob` decodes a base64 literal — value is hidden in source".to_string()
                    } else {
                        "`atob` decodes a base64 value at runtime — common step before dynamic fetch or eval".to_string()
                    };
                    push(
                        findings,
                        node,
                        bytes,
                        path,
                        index,
                        SignalKind::DynamicExecution,
                        Severity::Warn,
                        0.75,
                        msg,
                    );
                }
            }
            "btoa" => {
                if !positional.is_empty() {
                    push(
                        findings,
                        node,
                        bytes,
                        path,
                        index,
                        SignalKind::DynamicExecution,
                        Severity::Info,
                        0.55,
                        "`btoa` encodes a value as base64 at runtime — used in exfiltration patterns".to_string(),
                    );
                }
            }
            "setTimeout" | "setInterval" => {
                if let Some(first) = positional.first() {
                    if is_string_literal(*first) {
                        let name = node_text(func, bytes);
                        push(
                            findings,
                            node,
                            bytes,
                            path,
                            index,
                            SignalKind::DynamicExecution,
                            Severity::Warn,
                            0.75,
                            format!(
                                "`{}` called with a string argument — string form evaluates as code",
                                name
                            ),
                        );
                    }
                }
            }
            _ => {}
        }
        return;
    }

    // Member-expression callees: process.binding(...)
    if func.kind() == "member_expression" {
        if let Some(qual) = member_qualified_name(func, bytes) {
            if qual == "process.binding" {
                push(
                    findings,
                    node,
                    bytes,
                    path,
                    index,
                    SignalKind::DynamicAttribute,
                    Severity::Warn,
                    0.80,
                    "`process.binding(...)` reaches Node internal bindings".into(),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// new_expression — `new Function(x)` is the constructor form of Function().
// ---------------------------------------------------------------------------

fn check_new(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(ctor) = new_constructor(node) else {
        return;
    };
    if ctor.kind() != "identifier" || node_text(ctor, bytes) != "Function" {
        return;
    }
    let Some(args) = new_arguments(node) else {
        return;
    };
    let Some(first) = positional_args(args).into_iter().next() else {
        return;
    };
    emit_function_ctor(node, first, bytes, path, index, findings);
}

fn emit_function_ctor(
    anchor: Node,
    first_arg: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    if is_literal_expression(first_arg) {
        // `new Function("return 1")` with a literal is still runtime code
        // generation, but the token pass already flags suspicious literals
        // and we reserve AST CRITICAL for the non-literal / constructed
        // shape per SPEC.
        return;
    }
    push(
        findings,
        anchor,
        bytes,
        path,
        index,
        SignalKind::DynamicExecution,
        Severity::Critical,
        confidence_for_arg(first_arg, bytes, 0.90, 0.75),
        "`Function(...)` called with a non-literal body".into(),
    );
}

// ---------------------------------------------------------------------------
// Node accessors
// ---------------------------------------------------------------------------

fn node_text<'a>(node: Node, bytes: &'a [u8]) -> &'a str {
    std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).unwrap_or("")
}

fn call_function(call: Node) -> Option<Node> {
    call.child_by_field_name("function")
        .or_else(|| call.child(0))
}

fn call_arguments(call: Node) -> Option<Node> {
    call.child_by_field_name("arguments")
        .or_else(|| find_child_by_kind(call, "arguments"))
}

fn new_constructor(new_expr: Node) -> Option<Node> {
    new_expr.child_by_field_name("constructor").or_else(|| {
        // Fallback: first child after the `new` keyword that is not `arguments`.
        let mut cursor = new_expr.walk();
        for child in new_expr.children(&mut cursor) {
            match child.kind() {
                "new" | "arguments" => continue,
                _ => return Some(child),
            }
        }
        None
    })
}

fn new_arguments(new_expr: Node) -> Option<Node> {
    new_expr
        .child_by_field_name("arguments")
        .or_else(|| find_child_by_kind(new_expr, "arguments"))
}

fn find_child_by_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).find(|c| c.kind() == kind);
    found
}

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

fn member_qualified_name(node: Node, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" => Some(node_text(node, bytes).to_string()),
        "member_expression" => {
            let obj = node.child_by_field_name("object")?;
            let prop = node.child_by_field_name("property")?;
            let obj_name = member_qualified_name(obj, bytes)?;
            Some(format!("{}.{}", obj_name, node_text(prop, bytes)))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Literal / construction classification
// ---------------------------------------------------------------------------

fn is_string_literal(node: Node) -> bool {
    match node.kind() {
        "string" => true,
        "template_string" => !template_has_substitution(node),
        _ => false,
    }
}

fn is_literal_expression(node: Node) -> bool {
    match node.kind() {
        "string" | "number" | "regex" | "true" | "false" | "null" | "undefined" => true,
        "template_string" => !template_has_substitution(node),
        _ => false,
    }
}

fn template_has_substitution(node: Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "template_substitution" {
            return true;
        }
    }
    false
}

fn looks_concatenated_string(node: Node, bytes: &[u8]) -> bool {
    if node.kind() == "template_string" && template_has_substitution(node) {
        return true;
    }
    if node.kind() == "binary_expression" {
        let op_text = node
            .child_by_field_name("operator")
            .map(|n| node_text(n, bytes))
            .unwrap_or_else(|| {
                // Fallback: second child is the operator token.
                node.child(1).map(|n| node_text(n, bytes)).unwrap_or("")
            });
        if op_text == "+" {
            let l = node.child_by_field_name("left").or_else(|| node.child(0));
            let r = node.child_by_field_name("right").or_else(|| node.child(2));
            if l.map(is_string_literal).unwrap_or(false)
                || r.map(is_string_literal).unwrap_or(false)
            {
                return true;
            }
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

/// Confidence for findings whose argument is non-literal: pick the higher
/// score if the argument is an obvious string construction (template with
/// `${}` or `+` concat), otherwise the lower score.
fn confidence_for_arg(arg: Node, bytes: &[u8], high: f32, low: f32) -> f32 {
    if looks_concatenated_string(arg, bytes) {
        high
    } else {
        low
    }
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
        analyze(&PathBuf::from("t.ts"), src, Language::TypeScript).findings
    }

    fn run_as(name: &str, lang: Language, src: &[u8]) -> Vec<Finding> {
        analyze(&PathBuf::from(name), src, lang).findings
    }

    #[test]
    fn eval_literal_is_ignored() {
        let f = run(b"eval(\"print(1)\");");
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicExecution));
    }

    #[test]
    fn eval_of_variable_is_critical() {
        let f = run(b"eval(payload);");
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn eval_of_concat_is_critical() {
        let f = run(b"eval('a' + b);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DynamicExecution && x.severity == Severity::Critical));
    }

    #[test]
    fn function_ctor_call_form_is_critical() {
        let f = run(b"const g = Function(body);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DynamicExecution && x.severity == Severity::Critical));
    }

    #[test]
    fn function_ctor_new_form_is_critical() {
        let f = run(b"const g = new Function(body);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DynamicExecution && x.severity == Severity::Critical));
    }

    #[test]
    fn function_ctor_literal_is_ignored() {
        // Literal body is still dubious, but AST layer defers to token/raw
        // flags on the literal itself.
        let f = run(b"const g = new Function(\"return 1\");");
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicExecution));
    }

    #[test]
    fn require_literal_is_ignored() {
        let f = run(b"const fs = require(\"fs\");");
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn require_variable_is_warn() {
        let f = run(b"const m = require(name);");
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::DynamicImport)
            .expect("expected DynamicImport");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn require_template_with_substitution_is_warn() {
        let f = run(b"const m = require(`pkg-${x}`);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DynamicImport && x.severity == Severity::Warn));
    }

    #[test]
    fn require_template_without_substitution_is_ignored() {
        let f = run(b"const m = require(`fs`);");
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn dynamic_import_variable_is_warn() {
        let f = run(b"const m = import(name);");
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::DynamicImport)
            .expect("expected DynamicImport");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn dynamic_import_literal_is_ignored() {
        let f = run(b"const m = import(\"./mod\");");
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn settimeout_string_is_warn() {
        let f = run(b"setTimeout('doThing()', 10);");
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::DynamicExecution)
            .expect("expected DynamicExecution");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn settimeout_function_is_ignored() {
        let f = run(b"setTimeout(() => {}, 10);");
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicExecution));
    }

    #[test]
    fn setinterval_string_is_warn() {
        let f = run(b"setInterval('doThing()', 10);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DynamicExecution && x.severity == Severity::Warn));
    }

    #[test]
    fn process_binding_is_warn() {
        let f = run(b"const b = process.binding(\"spawn\");");
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::DynamicAttribute)
            .expect("expected DynamicAttribute");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn process_something_else_is_ignored() {
        let f = run(b"const v = process.env.PATH;");
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicAttribute));
    }

    #[test]
    fn tsx_file_parses_under_tsx_grammar() {
        // Confirm the TSX grammar gets selected and doesn't error on JSX.
        let src = b"const App = () => <div onClick={() => eval(payload)}>hi</div>;";
        let f = run_as("t.tsx", Language::TypeScript, src);
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DynamicExecution && x.severity == Severity::Critical));
    }

    #[test]
    fn js_file_parses_under_ts_grammar() {
        let src = b"eval(payload);";
        let f = run_as("t.js", Language::JavaScript, src);
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DynamicExecution && x.severity == Severity::Critical));
    }

    #[test]
    fn parse_error_tolerated() {
        let result = analyze(
            &PathBuf::from("bad.ts"),
            b"const x = (",
            Language::TypeScript,
        );
        let _ = result.parse_error;
    }
}
