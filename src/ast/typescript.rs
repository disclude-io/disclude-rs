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

use std::collections::HashSet;
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
    let tag_deobfuscators = collect_tag_deobfuscators(root, bytes);
    let data_uri_vars = collect_data_uri_vars(root, bytes);
    let error_stack_vars = collect_error_stack_vars(root, bytes);
    let mut findings = Vec::new();
    walk(
        root,
        bytes,
        path,
        &index,
        &tag_deobfuscators,
        &data_uri_vars,
        &error_stack_vars,
        &mut findings,
    );
    AstOutcome {
        findings,
        parse_error,
        file_flags: Default::default(),
    }
}

#[allow(clippy::too_many_arguments)]
fn walk(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    tag_deobfuscators: &HashSet<String>,
    data_uri_vars: &HashSet<String>,
    error_stack_vars: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "call_expression" => check_call(
                node,
                bytes,
                path,
                index,
                tag_deobfuscators,
                data_uri_vars,
                error_stack_vars,
                findings,
            ),
            "new_expression" => check_new(node, bytes, path, index, findings),
            "yield_expression" => check_yield(node, bytes, path, index, findings),
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
// call_expression
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn check_call(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    tag_deobfuscators: &HashSet<String>,
    data_uri_vars: &HashSet<String>,
    error_stack_vars: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let Some(func) = call_function(node) else {
        return;
    };
    let Some(args) = call_arguments(node) else {
        return;
    };

    // `<obj>.<matchMethod>(...)` where <obj> is a stack string — direct
    // (`new Error().stack.includes(...)`) or via a const bound earlier in
    // the file (`const s = new Error().stack || ''; s.includes(...)`).
    // Reading `.stack` is fine on its own (loggers do it); the tell is
    // matching its content, which is how anti-analysis detects test or
    // tracing runners by their frames.
    if check_error_stack_match(node, func, bytes, path, index, error_stack_vars, findings) {
        return;
    }

    // Tagged template literal — `tag\`...\`` parses as a call_expression
    // whose arguments node is the template_string itself. Route those
    // separately; the rest of this function expects an argument list.
    if args.kind() == "template_string" {
        if func.kind() == "identifier" {
            let name = node_text(func, bytes);
            if tag_deobfuscators.contains(name) {
                push(
                    findings,
                    node,
                    bytes,
                    path,
                    index,
                    SignalKind::TagFunctionDeobfuscator,
                    Severity::Critical,
                    0.90,
                    format!(
                        "tagged template uses tag function `{}` whose body decodes its template strings — payload is hidden in the literal",
                        name
                    ),
                );
            }
        }
        return;
    }

    let positional: Vec<Node> = positional_args(args);

    // Dynamic `import(x)` — the callee is an `import` keyword node.
    if func.kind() == "import" {
        if let Some(first) = positional.first() {
            // `import("data:text/javascript;base64,...")` — and the
            // template-literal `\`data:...${x}\`` shape — execute arbitrary
            // code without ever touching disk. No legitimate use in app
            // or library code; emit a sharper signal in place of the
            // generic dynamic-import warn. Also flag the indirect form
            // `const m = \`data:...\`; await import(m);` by resolving the
            // identifier through the file's variable initializers.
            let arg_is_data_uri = specifier_starts_with_data_uri(*first, bytes)
                || (first.kind() == "identifier"
                    && data_uri_vars.contains(node_text(*first, bytes)));
            if arg_is_data_uri {
                push(
                    findings,
                    node,
                    bytes,
                    path,
                    index,
                    SignalKind::DataUriImport,
                    Severity::Critical,
                    0.95,
                    "`import(...)` specifier is a `data:` URI — executes arbitrary code without touching disk".into(),
                );
            } else if !is_literal_expression(*first) {
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
            "btoa" if !positional.is_empty() => {
                push(
                    findings,
                    node,
                    bytes,
                    path,
                    index,
                    SignalKind::DynamicExecution,
                    Severity::Info,
                    0.55,
                    "`btoa` encodes a value as base64 at runtime — used in exfiltration patterns"
                        .to_string(),
                );
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
    if ctor.kind() != "identifier" {
        return;
    }
    let name = node_text(ctor, bytes);
    let Some(args) = new_arguments(node) else {
        return;
    };
    let positional = positional_args(args);
    match name {
        "Function" => {
            if let Some(first) = positional.into_iter().next() {
                emit_function_ctor(node, first, bytes, path, index, findings);
            }
        }
        "Proxy" => {
            // `new Proxy(target, handler)` where `target` is one of the
            // documented globals lets the handler interpose on every
            // property access through that global — `'process' + 'env'`
            // never has to appear in source. Only fire on the small fixed
            // list of globals; legitimate uses (e.g. wrapping a plain
            // object or an instance) are out of scope.
            if let Some(first) = positional.first() {
                if let Some(target) = global_target_name(*first, bytes) {
                    push(
                        findings,
                        node,
                        bytes,
                        path,
                        index,
                        SignalKind::ProxyGlobalHijack,
                        Severity::Critical,
                        0.90,
                        format!(
                            "`new Proxy({}, ...)` interposes on a global object — every property read goes through the handler",
                            target
                        ),
                    );
                }
            }
        }
        _ => {}
    }
}

/// Return the canonical target name if `node` is one of the well-known
/// global objects whose interception via `Proxy` is a strong tell.
fn global_target_name(node: Node, bytes: &[u8]) -> Option<&'static str> {
    match node.kind() {
        "identifier" => match node_text(node, bytes) {
            "globalThis" => Some("globalThis"),
            "window" => Some("window"),
            "global" => Some("global"),
            "self" => Some("self"),
            "process" => Some("process"),
            "document" => Some("document"),
            _ => None,
        },
        "member_expression" => {
            let qual = member_qualified_name(node, bytes)?;
            match qual.as_str() {
                "Object.prototype" => Some("Object.prototype"),
                "Array.prototype" => Some("Array.prototype"),
                "Function.prototype" => Some("Function.prototype"),
                _ => None,
            }
        }
        _ => None,
    }
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

/// Returns true if `node` is a string literal whose content begins with
/// `data:`, or a template literal whose first literal segment begins with
/// `data:`. This is the shape `import("data:text/javascript;base64,...")` /
/// `` import(`data:...${x}`) `` — a JS module loaded from an inline data
/// URI, which executes arbitrary code without ever touching disk.
fn specifier_starts_with_data_uri(node: Node, bytes: &[u8]) -> bool {
    const PREFIX: &[u8] = b"data:";
    match node.kind() {
        "string" => {
            // Children are quote, string_fragment*, quote. Check the
            // first string_fragment.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "string_fragment" {
                    return bytes
                        .get(child.start_byte()..child.end_byte())
                        .is_some_and(|s| s.starts_with(PREFIX));
                }
            }
            false
        }
        "template_string" => {
            // Children: backtick, string_fragment*, template_substitution*,
            // backtick. The first string_fragment carries the literal
            // prefix; if it starts with `data:`, the import begins inside
            // a data URI regardless of what `${...}` interpolates.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "string_fragment" {
                    return bytes
                        .get(child.start_byte()..child.end_byte())
                        .is_some_and(|s| s.starts_with(PREFIX));
                }
            }
            false
        }
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
// Tag-function deobfuscator collection
// ---------------------------------------------------------------------------
//
// A tag function whose first parameter is `strings` (or typed
// `TemplateStringsArray`) and whose body applies a decoding op to that
// parameter is the classic "store payload in a tagged template literal,
// reverse/atob/fromCharCode it back at runtime" pattern. Legitimate tag
// functions — gql, css, sql, html, lit, styled — pass strings through or
// parse them; they do not reverse, base64-decode, or rebuild from char
// codes. The combination is highly specific to obfuscation.
//
// We collect such function names in a single pre-pass, then the main walk
// flags any tagged-template call whose tag identifier is in the set.

/// Collect variable names whose initializer is a string or template
/// literal beginning with `data:`. Used to resolve the indirect shape
/// `const m = \`data:...\`; await import(m);` — the call site sees only
/// the identifier, but the initializer pins the value's prefix.
fn collect_data_uri_vars(root: Node, bytes: &[u8]) -> HashSet<String> {
    let mut names: HashSet<String> = HashSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "variable_declarator" {
            if let (Some(name_node), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                if name_node.kind() == "identifier" && specifier_starts_with_data_uri(value, bytes)
                {
                    names.insert(node_text(name_node, bytes).to_string());
                }
            }
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    names
}

fn collect_tag_deobfuscators(root: Node, bytes: &[u8]) -> HashSet<String> {
    let mut names: HashSet<String> = HashSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_declaration" if is_tag_deobfuscator_fn(node, bytes) => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    names.insert(node_text(name_node, bytes).to_string());
                }
            }
            "variable_declarator" => {
                if let Some(value) = node.child_by_field_name("value") {
                    if matches!(
                        value.kind(),
                        "arrow_function" | "function_expression" | "function"
                    ) && is_tag_deobfuscator_fn(value, bytes)
                    {
                        if let Some(name_node) = node.child_by_field_name("name") {
                            if name_node.kind() == "identifier" {
                                names.insert(node_text(name_node, bytes).to_string());
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
    names
}

/// Returns true if `fn_node` (a `function_declaration`, `arrow_function`,
/// or `function_expression`) takes a `strings` / `TemplateStringsArray`
/// first parameter AND its body contains a string-decoding operation.
fn is_tag_deobfuscator_fn(fn_node: Node, bytes: &[u8]) -> bool {
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        // Arrow functions of the form `s => ...` use the `parameter` field
        // for a single identifier, not `parameters`. Check that path too.
        let Some(p) = fn_node.child_by_field_name("parameter") else {
            return false;
        };
        if p.kind() == "identifier" && node_text(p, bytes) == "strings" {
            if let Some(body) = fn_node.child_by_field_name("body") {
                return body_has_decode_op(body, bytes);
            }
        }
        return false;
    };
    if !first_param_is_template_strings(params, bytes) {
        return false;
    }
    let Some(body) = fn_node.child_by_field_name("body") else {
        return false;
    };
    body_has_decode_op(body, bytes)
}

fn first_param_is_template_strings(params: Node, bytes: &[u8]) -> bool {
    // `formal_parameters`: `(`, required_parameter*, `)`.
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        match child.kind() {
            "(" | ")" | "," => continue,
            "required_parameter" | "optional_parameter" => {
                return param_looks_like_template_strings(child, bytes);
            }
            // Single-identifier arrow-function param falls back here.
            "identifier" => {
                return node_text(child, bytes) == "strings";
            }
            _ => return false,
        }
    }
    false
}

fn param_looks_like_template_strings(param: Node, bytes: &[u8]) -> bool {
    // The pattern child is the parameter name; type_annotation child carries
    // the TS type. Either being a strings/TemplateStringsArray hint is enough.
    let mut cursor = param.walk();
    for child in param.children(&mut cursor) {
        match child.kind() {
            "identifier" if node_text(child, bytes) == "strings" => return true,
            "type_annotation" if node_text(child, bytes).contains("TemplateStringsArray") => {
                return true
            }
            _ => {}
        }
    }
    false
}

/// Walk `body` for any of the decoding operations a tag-function
/// deobfuscator applies to its template strings.
fn body_has_decode_op(body: Node, bytes: &[u8]) -> bool {
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.kind() == "member_expression" {
            if let Some(prop) = node.child_by_field_name("property") {
                let pname = node_text(prop, bytes);
                if matches!(pname, "reverse" | "fromCharCode") {
                    return true;
                }
            }
        }
        if node.kind() == "call_expression" {
            if let Some(f) = node.child_by_field_name("function") {
                match f.kind() {
                    "identifier" => {
                        if matches!(node_text(f, bytes), "atob" | "parseInt") {
                            return true;
                        }
                    }
                    "member_expression" => {
                        if let Some(qual) = member_qualified_name(f, bytes) {
                            if matches!(qual.as_str(), "Buffer.from" | "String.fromCharCode") {
                                return true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        for i in 0..node.child_count() as u32 {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// yield_expression — generator yielding a callable.
// ---------------------------------------------------------------------------
//
// `function* g() { yield () => os.read(...); yield m => m.run(); }` is the
// generator-as-state-machine deobfuscator: the dispatch function is split
// across multiple `yield` returns, each producing a callable. The driver
// pulls them out with `g.next().value` and invokes them. Reviewers see two
// short lambdas; the actual control flow is reconstructed at runtime by
// whoever owns the generator object. Yielding *data* values is fine; what
// makes the shape suspicious is that what comes out of `next().value` is
// itself a function to call.

fn check_yield(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(value) = yield_value(node) else {
        return;
    };
    if !matches!(value.kind(), "arrow_function" | "function_expression") {
        return;
    }
    let gen_name = enclosing_generator_name(node, bytes).unwrap_or_else(|| "<anonymous>".into());
    push(
        findings,
        node,
        bytes,
        path,
        index,
        SignalKind::GeneratorYieldCallable,
        Severity::Warn,
        0.80,
        format!(
            "generator `{}` yields a callable — `next().value()` invokes the yielded function (state-machine pattern)",
            gen_name
        ),
    );
}

/// Find the value expression of a `yield_expression`. Children are `yield`
/// (and optionally `*` for `yield*`) followed by the value, when present.
fn yield_value(node: Node) -> Option<Node> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "yield" | "*" => continue,
            _ => return Some(child),
        }
    }
    None
}

/// Walk parents to find the enclosing generator and return its name. For
/// anonymous generator expressions, fall back to the variable name when
/// the generator is the initializer of a `variable_declarator`.
fn enclosing_generator_name(node: Node, bytes: &[u8]) -> Option<String> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        match n.kind() {
            "generator_function_declaration" => {
                if let Some(name_node) = n.child_by_field_name("name") {
                    return Some(node_text(name_node, bytes).to_string());
                }
                return None;
            }
            "generator_function" => {
                if let Some(p) = n.parent() {
                    if p.kind() == "variable_declarator" {
                        if let Some(name_node) = p.child_by_field_name("name") {
                            return Some(node_text(name_node, bytes).to_string());
                        }
                    }
                }
                return None;
            }
            _ => {}
        }
        cur = n.parent();
    }
    None
}

// ---------------------------------------------------------------------------
// error-stack-inspection — `new Error().stack` is read and string-matched.
// ---------------------------------------------------------------------------
//
// The structural pattern: an Error stack is materialized (`new Error().stack`,
// either inline or bound through a `const`/`let` initializer that may include
// a `|| ''` / `?? ''` fallback) and then a string-match method is invoked on
// it. Reading the stack is benign on its own — loggers and error reporters
// all do it. The tell is the *match step*: anti-analysis code checks the
// stack for fingerprints of test runners, tracing tools, or sandboxes
// (`jest`, `mocha`, `ts-node`, `playwright`, `puppeteer`, `node_modules/...`)
// and gates the payload behind whether those frames are present. The shape
// is what's diagnostic; the matched literal can be anything.

fn check_error_stack_match(
    node: Node,
    func: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    error_stack_vars: &HashSet<String>,
    findings: &mut Vec<Finding>,
) -> bool {
    if func.kind() != "member_expression" {
        return false;
    }
    let Some(prop) = func.child_by_field_name("property") else {
        return false;
    };
    if !is_string_match_method(node_text(prop, bytes)) {
        return false;
    }
    let Some(obj) = func.child_by_field_name("object") else {
        return false;
    };
    let receiver_is_stack = match obj.kind() {
        "identifier" => error_stack_vars.contains(node_text(obj, bytes)),
        _ => expression_is_error_stack(obj, bytes),
    };
    if !receiver_is_stack {
        return false;
    }
    push(
        findings,
        node,
        bytes,
        path,
        index,
        SignalKind::ErrorStackInspection,
        Severity::Warn,
        0.85,
        format!(
            "`{}` called on `new Error().stack` — string-matching the call stack is the structural shape of sandbox/analyzer detection",
            node_text(prop, bytes)
        ),
    );
    true
}

fn is_string_match_method(name: &str) -> bool {
    matches!(
        name,
        "includes"
            | "indexOf"
            | "lastIndexOf"
            | "search"
            | "match"
            | "matchAll"
            | "startsWith"
            | "endsWith"
            | "test"
    )
}

/// Returns true if `node` is — or transparently wraps — a `.stack` access on
/// a freshly constructed `Error`. Walks through `||`/`??` fallbacks and
/// parenthesized expressions; does not follow identifiers (the caller
/// resolves those through `error_stack_vars`).
fn expression_is_error_stack(node: Node, bytes: &[u8]) -> bool {
    match node.kind() {
        "member_expression" => {
            let Some(prop) = node.child_by_field_name("property") else {
                return false;
            };
            if node_text(prop, bytes) != "stack" {
                return false;
            }
            let Some(obj) = node.child_by_field_name("object") else {
                return false;
            };
            is_new_error_expression(obj, bytes)
        }
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() != "(" && child.kind() != ")" {
                    return expression_is_error_stack(child, bytes);
                }
            }
            false
        }
        "binary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map(|n| node_text(n, bytes))
                .unwrap_or("");
            if op != "||" && op != "??" {
                return false;
            }
            let l = node.child_by_field_name("left");
            let r = node.child_by_field_name("right");
            l.map(|n| expression_is_error_stack(n, bytes))
                .unwrap_or(false)
                || r.map(|n| expression_is_error_stack(n, bytes))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// Returns true if `node` is `new Error()` or `new <SubclassOfError>()` —
/// detected by the constructor name ending in `Error`. This catches custom
/// error classes (`new MyError()`) without needing a class-graph walk.
fn is_new_error_expression(node: Node, bytes: &[u8]) -> bool {
    if node.kind() == "parenthesized_expression" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "(" && child.kind() != ")" {
                return is_new_error_expression(child, bytes);
            }
        }
        return false;
    }
    if node.kind() != "new_expression" {
        return false;
    }
    let Some(ctor) = new_constructor(node) else {
        return false;
    };
    match ctor.kind() {
        "identifier" => {
            let name = node_text(ctor, bytes);
            name == "Error" || name.ends_with("Error")
        }
        _ => false,
    }
}

/// Collect names of `const`/`let` bindings whose initializer resolves to a
/// `new Error().stack` access (possibly through a `||`/`??` fallback or a
/// parenthesized wrapping). Lets the call-site check resolve indirect uses
/// like `const s = new Error().stack || ''; s.includes('jest')`.
fn collect_error_stack_vars(root: Node, bytes: &[u8]) -> HashSet<String> {
    let mut names: HashSet<String> = HashSet::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "variable_declarator" {
            if let (Some(name_node), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                if name_node.kind() == "identifier" && expression_is_error_stack(value, bytes) {
                    names.insert(node_text(name_node, bytes).to_string());
                }
            }
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    names
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
    fn proxy_globalthis_is_critical() {
        let f = run(b"const p = new Proxy(globalThis, h);");
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::ProxyGlobalHijack)
            .expect("expected ProxyGlobalHijack");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.message.contains("globalThis"));
    }

    #[test]
    fn proxy_process_is_critical() {
        let f = run(b"const p = new Proxy(process, h);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::ProxyGlobalHijack && x.severity == Severity::Critical));
    }

    #[test]
    fn proxy_window_is_critical() {
        let f = run(b"const p = new Proxy(window, h);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::ProxyGlobalHijack && x.severity == Severity::Critical));
    }

    #[test]
    fn proxy_object_prototype_is_critical() {
        let f = run(b"const p = new Proxy(Object.prototype, h);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::ProxyGlobalHijack && x.severity == Severity::Critical));
    }

    #[test]
    fn proxy_plain_object_is_ignored() {
        let f = run(b"const p = new Proxy(target, h);");
        assert!(f.iter().all(|x| x.kind != SignalKind::ProxyGlobalHijack));
    }

    #[test]
    fn proxy_object_literal_is_ignored() {
        let f = run(b"const p = new Proxy({}, h);");
        assert!(f.iter().all(|x| x.kind != SignalKind::ProxyGlobalHijack));
    }

    #[test]
    fn tag_fn_with_reverse_is_critical() {
        let src = b"function r(strings: TemplateStringsArray) {\n\
            return strings.map(s => s.split('').reverse().join('')).join('');\n\
        }\n\
        const u = r`mc.revres-larrefe/moc.evil.ppa`;\n";
        let f = run(src);
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::TagFunctionDeobfuscator)
            .expect("expected TagFunctionDeobfuscator");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.message.contains("`r`"));
    }

    #[test]
    fn tag_fn_with_atob_is_critical() {
        let src = b"function t(strings: TemplateStringsArray) {\n\
            return atob(strings.join(''));\n\
        }\n\
        const v = t`SGVsbG8=`;\n";
        let f = run(src);
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::TagFunctionDeobfuscator
                && x.severity == Severity::Critical));
    }

    #[test]
    fn tag_fn_with_from_char_code_is_critical() {
        let src = b"function c(strings: TemplateStringsArray) {\n\
            return String.fromCharCode(...strings.map(s => parseInt(s, 16)));\n\
        }\n\
        const w = c`48 69`;\n";
        let f = run(src);
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::TagFunctionDeobfuscator
                && x.severity == Severity::Critical));
    }

    #[test]
    fn arrow_tag_fn_is_critical() {
        let src = b"const r = (strings: TemplateStringsArray) => \
            strings.map(s => s.split('').reverse().join('')).join('');\n\
        const u = r`abc`;\n";
        let f = run(src);
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::TagFunctionDeobfuscator
                && x.severity == Severity::Critical));
    }

    #[test]
    fn passthrough_tag_fn_is_ignored() {
        // Tag function that just stitches strings together — common shape
        // for gql/sql/css. No decode op in the body.
        let src = b"function gql(strings: TemplateStringsArray) {\n\
            return strings.join('');\n\
        }\n\
        const q = gql`query { a }`;\n";
        let f = run(src);
        assert!(f
            .iter()
            .all(|x| x.kind != SignalKind::TagFunctionDeobfuscator));
    }

    #[test]
    fn unrelated_function_not_used_as_tag_is_ignored() {
        // The function takes `strings` and reverses them, but is never
        // used as a template tag. Without a tagged-template usage we do
        // not fire — the deobfuscation is not actually wired up.
        let src = b"function r(strings: TemplateStringsArray) {\n\
            return strings.map(s => s.split('').reverse().join('')).join('');\n\
        }\n\
        const x = 1;\n";
        let f = run(src);
        assert!(f
            .iter()
            .all(|x| x.kind != SignalKind::TagFunctionDeobfuscator));
    }

    #[test]
    fn tag_fn_without_strings_param_is_ignored() {
        // First param is named `parts`, not `strings`, and lacks the
        // TemplateStringsArray type annotation. The body still reverses,
        // but the param-name gate keeps the rule from firing.
        let src = b"function r(parts: any) {\n\
            return parts.split('').reverse().join('');\n\
        }\n\
        const u = r('abc');\n";
        let f = run(src);
        assert!(f
            .iter()
            .all(|x| x.kind != SignalKind::TagFunctionDeobfuscator));
    }

    #[test]
    fn import_string_data_uri_is_critical() {
        let f = run(b"await import(\"data:text/javascript;base64,YWxlcnQoMSk=\");");
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::DataUriImport)
            .expect("expected DataUriImport");
        assert_eq!(hit.severity, Severity::Critical);
        // The generic dynamic-import warn must not double-fire on the same call.
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn import_template_data_uri_is_critical() {
        let f = run(b"await import(`data:text/javascript;base64,${blob}`);");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DataUriImport && x.severity == Severity::Critical));
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn import_indirect_data_uri_via_const_is_critical() {
        let src = b"const spec = `data:text/javascript;base64,${b}`;\n\
                    await import(spec);\n";
        let f = run(src);
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DataUriImport && x.severity == Severity::Critical));
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn import_non_data_uri_string_is_ignored_for_data_uri() {
        // Static specifier — neither dynamic-import nor data-uri-import.
        let f = run(b"await import(\"./mod\");");
        assert!(f.iter().all(|x| x.kind != SignalKind::DataUriImport));
        assert!(f.iter().all(|x| x.kind != SignalKind::DynamicImport));
    }

    #[test]
    fn import_dynamic_non_data_uri_stays_warn() {
        // Indirect import of a regular path — the existing dynamic-import
        // warn must still fire; data-uri-import must not.
        let f = run(b"await import(name);");
        assert!(f.iter().all(|x| x.kind != SignalKind::DataUriImport));
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::DynamicImport && x.severity == Severity::Warn));
    }

    #[test]
    fn generator_yields_arrow_is_warn() {
        let src = b"function* g() {\n    yield () => doThing();\n}\n";
        let f = run(src);
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::GeneratorYieldCallable)
            .expect("expected GeneratorYieldCallable");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.message.contains("`g`"));
    }

    #[test]
    fn generator_yields_function_expression_is_warn() {
        let src = b"function* g() {\n    yield function () { return 1; };\n}\n";
        let f = run(src);
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::GeneratorYieldCallable && x.severity == Severity::Warn));
    }

    #[test]
    fn generator_yields_data_is_ignored() {
        let src =
            b"function* g() {\n    yield 1;\n    yield { stage: 'a' };\n    yield 'literal';\n}\n";
        let f = run(src);
        assert!(f
            .iter()
            .all(|x| x.kind != SignalKind::GeneratorYieldCallable));
    }

    #[test]
    fn generator_yields_call_result_is_ignored() {
        // `yield call(fn, args)` (redux-saga shape) yields the *return value*
        // of `call`, not a function. Must not fire.
        let src = b"function* g() {\n    yield call(fn, x);\n}\n";
        let f = run(src);
        assert!(f
            .iter()
            .all(|x| x.kind != SignalKind::GeneratorYieldCallable));
    }

    #[test]
    fn generator_multiple_callable_yields_each_fire() {
        let src = b"function* g() {\n    yield () => a();\n    yield (m) => m.b();\n}\n";
        let f = run(src);
        let hits = f
            .iter()
            .filter(|x| x.kind == SignalKind::GeneratorYieldCallable)
            .count();
        assert_eq!(hits, 2);
    }

    #[test]
    fn generator_expression_via_const_uses_var_name() {
        let src = b"const dispatcher = function* () { yield () => x(); };\n";
        let f = run(src);
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::GeneratorYieldCallable)
            .expect("expected GeneratorYieldCallable");
        assert!(hit.message.contains("dispatcher"));
    }

    #[test]
    fn error_stack_inspection_via_const_includes_is_warn() {
        let src = b"function isAnalyzed() {\n    const stack = new Error().stack || '';\n    return stack.includes('jest');\n}\n";
        let f = run(src);
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::ErrorStackInspection)
            .expect("expected ErrorStackInspection");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.message.contains("includes"));
    }

    #[test]
    fn error_stack_inspection_direct_chain_is_warn() {
        let f = run(b"const hit = new Error().stack.includes('mocha');\n");
        assert!(f
            .iter()
            .any(|x| x.kind == SignalKind::ErrorStackInspection && x.severity == Severity::Warn));
    }

    #[test]
    fn error_stack_inspection_via_indexof_is_warn() {
        let src = b"const s = new Error().stack;\nif (s.indexOf('ts-node') !== -1) { /* ... */ }\n";
        let f = run(src);
        assert!(f.iter().any(|x| x.kind == SignalKind::ErrorStackInspection));
    }

    #[test]
    fn error_stack_inspection_subclass_constructor_is_warn() {
        // `new MyError().stack.includes(...)` — custom Error subclasses
        // expose the same `.stack` property and are equally diagnostic.
        let f = run(b"const hit = new MyError().stack.includes('cypress');\n");
        assert!(f.iter().any(|x| x.kind == SignalKind::ErrorStackInspection));
    }

    #[test]
    fn error_stack_read_without_match_is_ignored() {
        // Reading and forwarding the stack — what loggers and reporters do
        // — does not fire. Only the match step is diagnostic.
        let f = run(b"const stack = new Error().stack;\nreport(stack);\n");
        assert!(f.iter().all(|x| x.kind != SignalKind::ErrorStackInspection));
    }

    #[test]
    fn includes_on_unrelated_string_is_ignored() {
        // `.includes` on a regular string must not fire.
        let f = run(b"const s = 'hello world';\nreturn s.includes('world');\n");
        assert!(f.iter().all(|x| x.kind != SignalKind::ErrorStackInspection));
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
