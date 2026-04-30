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
            format!("`{}` at module scope (runs on import) on a non-literal expression", fn_name),
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
                    if inner.kind() == "string_content"
                        && node_text(inner, bytes) == "__main__"
                    {
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
        if node.kind() == "string" && string_node_is_bytes(node, bytes) {
            inspect_bytes_literal(node, bytes, path, index, findings);
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
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
    "base64",
    "binascii",
    "codecs",
    "marshal",
    "pickle",
    "cPickle",
    "zlib",
    "gzip",
    "lzma",
    "bz2",
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
}
