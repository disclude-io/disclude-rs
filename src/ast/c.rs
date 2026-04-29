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
//!   * Numeric-literal payload smuggling — a wide-numeric array (`double[]`,
//!     `long[]`, `uint64_t[]`, …) reinterpreted through a byte-pointer cast
//!     (`(char*)O`, `(unsigned char*)O`, `(uint8_t*)&O[i]`). This is the
//!     IOCCC / dropper trick of hiding bytes inside `double` literals so
//!     hex/base64 grep can't find them. NumericLiteralPayload CRITICAL.

use std::path::Path;

use tree_sitter::{Node, Parser};

use super::AstOutcome;
use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

const EXEC_FUNCTIONS: &[&str] = &["execl", "execlp", "execle", "execv", "execvp", "execve"];

/// printf-family functions and the 0-based positional index of their format
/// argument. The `v*` variants are intentionally excluded — they take a
/// `va_list` and exist precisely so that the format string can be forwarded
/// from a variadic wrapper, so a non-literal format is the norm rather than
/// the exception.
const PRINTF_FAMILY: &[(&str, usize)] = &[
    ("printf", 0),
    ("wprintf", 0),
    ("fprintf", 1),
    ("fwprintf", 1),
    ("dprintf", 1),
    ("sprintf", 1),
    ("asprintf", 1),
    ("snprintf", 2),
    ("swprintf", 2),
];

/// Localization wrappers whose return value, while not a literal at parse
/// time, resolves to a translated string-table entry at runtime. Excluded
/// from DynamicFormatString because the format itself is a literal in
/// some message catalog — not user-controlled data.
const I18N_WRAPPERS: &[&str] = &[
    "_",
    "N_",
    "Q_",
    "C_",
    "gettext",
    "dgettext",
    "dcgettext",
    "ngettext",
    "dngettext",
    "dcngettext",
    "pgettext",
    "dpgettext",
    "dcpgettext",
];

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
    walk(root, bytes, path, &index, &mut findings);
    let arrays = collect_numeric_arrays(root, bytes);
    if !arrays.is_empty() {
        check_numeric_payload_casts(root, bytes, path, &index, &mut findings, &arrays);
    }
    check_legacy_kr_main(root, bytes, path, &index, &mut findings);
    check_implicit_int_functions(root, bytes, path, &index, &mut findings);
    check_reverse_subscript_macros(root, bytes, path, &index, &mut findings);
    check_stringify_dereference_macros(root, bytes, path, &index, &mut findings);
    check_macro_keyword_overrides(root, bytes, path, &index, &mut findings);
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
            "call_expression" => {
                check_call(node, bytes, path, index, findings);
                check_recursive_main(node, bytes, path, index, findings);
            }
            "subscript_expression" => {
                check_reverse_subscript(node, bytes, path, index, findings);
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
            check_exec(
                node,
                fn_name,
                positional.as_slice(),
                bytes,
                path,
                index,
                findings,
            );
        }
        _ => {}
    }
    if let Some(&(_, fmt_idx)) = PRINTF_FAMILY.iter().find(|(n, _)| *n == name) {
        check_dynamic_format_string(
            node,
            name,
            fmt_idx,
            &positional,
            bytes,
            path,
            index,
            findings,
        );
    }
}

/// printf-family with a non-literal first format argument. We require that
/// the format argument is a *bare identifier that is not declared inside the
/// enclosing function* — i.e. a global or otherwise non-local. This is
/// precisely the IOCCC pattern (`F = "%c"; printf(F, x)`) and it suppresses
/// the legitimate-but-noisy cases:
///   * forwarding a parameter `fmt` through `vfprintf(stream, fmt, ap)` —
///     handled by excluding `v*` from PRINTF_FAMILY entirely;
///   * picking a local format string `const char *fmt = cond ? "a" : "b";
///     snprintf(buf, n, fmt, x)` — handled by the local-declaration scan.
#[allow(clippy::too_many_arguments)]
fn check_dynamic_format_string(
    call: Node,
    fn_name: &str,
    fmt_idx: usize,
    args: &[Node],
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(fmt_arg) = args.get(fmt_idx) else {
        return;
    };
    if is_string_literal(*fmt_arg) {
        return;
    }
    if call_to_i18n_wrapper(*fmt_arg, bytes) {
        return;
    }
    // Require the format arg to be a *bare identifier* — otherwise it is
    // likely an array index or struct field that we cannot reason about.
    if fmt_arg.kind() != "identifier" {
        return;
    }
    let Ok(arg_name) = std::str::from_utf8(&bytes[fmt_arg.start_byte()..fmt_arg.end_byte()]) else {
        return;
    };
    if is_likely_macro_name(arg_name) {
        // ALL_CAPS_WITH_UNDERSCORES is the universal C convention for
        // preprocessor macros — `printf(FMT_SHORT, x)` almost always
        // expands to a literal format string from a `#define`.
        return;
    }
    if name_is_local_to_enclosing_function(call, bytes, arg_name) {
        return;
    }
    push(
        findings,
        call,
        bytes,
        path,
        index,
        SignalKind::DynamicFormatString,
        Severity::Warn,
        0.80,
        format!(
            "`{}` called with a non-literal format string (format-string bug pattern)",
            fn_name
        ),
    );
}

/// True if `name` is declared as a parameter or local of the function that
/// contains `call`. Walks up to the enclosing `function_definition` and then
/// scans its declarator parameters and body for matching identifiers.
fn name_is_local_to_enclosing_function(call: Node, bytes: &[u8], name: &str) -> bool {
    let mut cursor = call;
    let func = loop {
        let Some(parent) = cursor.parent() else {
            return false;
        };
        if parent.kind() == "function_definition" {
            break parent;
        }
        cursor = parent;
    };
    // Parameters live inside the function_declarator child.
    let mut walker = func.walk();
    for child in func.children(&mut walker) {
        if child.kind() == "function_declarator"
            && declarator_has_parameter_named(child, bytes, name)
        {
            return true;
        }
        if child.kind() == "compound_statement" && body_declares_identifier(child, bytes, name) {
            return true;
        }
    }
    false
}

fn declarator_has_parameter_named(node: Node, bytes: &[u8], name: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "parameter_list" {
            let mut pl = child.walk();
            for param in child.children(&mut pl) {
                if param.kind() == "parameter_declaration"
                    && first_node_text_of_kind(param, bytes, "identifier") == Some(name)
                {
                    return true;
                }
            }
        }
    }
    false
}

fn body_declares_identifier(body: Node, bytes: &[u8], name: &str) -> bool {
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "declaration" && declaration_declares_identifier(child, bytes, name) {
            return true;
        }
        // Nested compound_statements (blocks) hide their own scope. We err
        // on the side of FN suppression: any inner declaration of the name
        // counts.
        if (child.kind() == "compound_statement"
            || child.kind() == "for_statement"
            || child.kind() == "if_statement"
            || child.kind() == "while_statement"
            || child.kind() == "do_statement")
            && body_declares_identifier(child, bytes, name)
        {
            return true;
        }
    }
    false
}

/// Walk a `declaration` node and check whether it declares a variable
/// named `name`. Handles multi-declarator forms like `char *a, *b, *c;`
/// where each declarator is a sibling of the type.
fn declaration_declares_identifier(decl: Node, bytes: &[u8], name: &str) -> bool {
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        match child.kind() {
            "init_declarator" | "pointer_declarator" | "array_declarator"
                if declarator_name(child, bytes) == Some(name) =>
            {
                return true;
            }
            "identifier" => {
                let Ok(text) = std::str::from_utf8(&bytes[child.start_byte()..child.end_byte()])
                else {
                    continue;
                };
                if text == name {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// The bound name of a declarator — the leaf identifier under any
/// `pointer_declarator` / `array_declarator` / `init_declarator` chain.
fn declarator_name<'a>(node: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                return std::str::from_utf8(&bytes[child.start_byte()..child.end_byte()]).ok();
            }
            "pointer_declarator" | "array_declarator" | "init_declarator" => {
                if let Some(s) = declarator_name(child, bytes) {
                    return Some(s);
                }
            }
            _ => {}
        }
    }
    None
}

fn is_likely_macro_name(name: &str) -> bool {
    // Match SCREAMING_SNAKE_CASE / FOOBAR style: all uppercase letters,
    // digits, or underscores, AND either contains an underscore or has
    // at least two alphabetic characters. Single-letter caps like `F`,
    // `M`, `S` are commonly user-defined globals — not macros.
    let mut alpha = 0usize;
    let mut has_underscore = false;
    for c in name.chars() {
        if c.is_ascii_alphabetic() {
            if !c.is_ascii_uppercase() {
                return false;
            }
            alpha += 1;
        } else if c == '_' {
            has_underscore = true;
        } else if !c.is_ascii_digit() {
            return false;
        }
    }
    alpha >= 1 && (has_underscore || alpha >= 2)
}

fn call_to_i18n_wrapper(node: Node, bytes: &[u8]) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    let Some(callee) = node.child(0) else {
        return false;
    };
    if callee.kind() != "identifier" {
        return false;
    }
    let Ok(name) = std::str::from_utf8(&bytes[callee.start_byte()..callee.end_byte()]) else {
        return false;
    };
    I18N_WRAPPERS.contains(&name)
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
        (Severity::Warn, 0.60, "`system` called".to_string())
    };
    push(
        findings,
        call,
        bytes,
        path,
        index,
        SignalKind::DynamicExecution,
        severity,
        confidence,
        message,
    );
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
        (Severity::Warn, 0.60, format!("`{}` called", fn_name))
    };
    push(
        findings,
        call,
        bytes,
        path,
        index,
        SignalKind::DynamicExecution,
        severity,
        confidence,
        message,
    );
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
        (Severity::Warn, 0.60, "`popen` called".to_string())
    };
    push(
        findings,
        call,
        bytes,
        path,
        index,
        SignalKind::DynamicExecution,
        severity,
        confidence,
        message,
    );
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
// Numeric-literal payload smuggling
// ---------------------------------------------------------------------------
//
// Two-pass: first collect "wide-numeric" arrays (≥ 8 numeric literals, element
// type ≥ 2 bytes), then look for byte-pointer casts whose operand references
// one of those array names. The combination is the fingerprint — either pass
// alone produces too many false positives (lookup tables, scientific data,
// generic void* casts).

const MIN_PAYLOAD_ELEMENTS: usize = 8;

#[derive(Debug)]
struct NumericArray {
    name: String,
    type_text: String,
    count: usize,
}

fn collect_numeric_arrays(root: Node, bytes: &[u8]) -> Vec<NumericArray> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "declaration" {
            if let Some(arr) = parse_numeric_array(node, bytes) {
                out.push(arr);
            }
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    out
}

fn parse_numeric_array(decl: Node, bytes: &[u8]) -> Option<NumericArray> {
    let type_node = first_child_of_kinds(
        decl,
        &["primitive_type", "type_identifier", "sized_type_specifier"],
    )?;
    let type_text = node_text(type_node, bytes).trim().to_string();
    if !is_wide_numeric_type(&type_text) {
        return None;
    }
    let init = first_child_of_kinds(decl, &["init_declarator"])?;
    let arr_decl = first_child_of_kinds(init, &["array_declarator"])?;
    let name_node = first_child_of_kinds(arr_decl, &["identifier"])?;
    let name = node_text(name_node, bytes).to_string();
    let init_list = first_child_of_kinds(init, &["initializer_list"])?;
    let mut cursor = init_list.walk();
    let count = init_list
        .children(&mut cursor)
        .filter(|c| c.kind() == "number_literal")
        .count();
    if count < MIN_PAYLOAD_ELEMENTS {
        return None;
    }
    Some(NumericArray {
        name,
        type_text,
        count,
    })
}

fn check_numeric_payload_casts(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
    arrays: &[NumericArray],
) {
    // (first_cast_offset, cast_count) keyed by array index.
    let mut hits: Vec<Option<(usize, usize)>> = vec![None; arrays.len()];
    walk_casts(root, bytes, arrays, &mut hits);
    for (i, hit) in hits.iter().enumerate() {
        let Some((offset, count)) = *hit else {
            continue;
        };
        let arr = &arrays[i];
        let (line, col) = index.locate(offset);
        let cast_clause = if count == 1 {
            "byte-pointer cast".to_string()
        } else {
            format!("{} byte-pointer casts", count)
        };
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: offset,
            line,
            col,
            pass: PassKind::Ast,
            kind: SignalKind::NumericLiteralPayload,
            severity: Severity::Critical,
            confidence: 0.85,
            message: format!(
                "{} of `{}` ({} array of {} elements) — payload smuggled in numeric literals",
                cast_clause, arr.name, arr.type_text, arr.count
            ),
            snippet: redact_snippet(&snippet_around(bytes, offset, 100)),
            diff_introduced: false,
        });
    }
}

fn walk_casts(
    root: Node,
    bytes: &[u8],
    arrays: &[NumericArray],
    hits: &mut [Option<(usize, usize)>],
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "cast_expression" {
            if let Some(idx) = matches_byte_cast_of_array(node, bytes, arrays) {
                let off = node.start_byte();
                match &mut hits[idx] {
                    slot @ None => *slot = Some((off, 1)),
                    Some((_, count)) => *count += 1,
                }
            }
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
}

fn matches_byte_cast_of_array(cast: Node, bytes: &[u8], arrays: &[NumericArray]) -> Option<usize> {
    let type_desc = first_child_of_kinds(cast, &["type_descriptor"])?;
    if !is_byte_pointer_type_descriptor(type_desc, bytes) {
        return None;
    }
    let mut names = Vec::new();
    collect_identifiers(cast, bytes, &mut names);
    arrays
        .iter()
        .position(|a| names.iter().any(|n| n == &a.name))
}

fn collect_identifiers(node: Node, bytes: &[u8], out: &mut Vec<String>) {
    if node.kind() == "type_descriptor" {
        return; // skip the cast's own type — that's not the operand
    }
    if node.kind() == "identifier" {
        out.push(node_text(node, bytes).to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_identifiers(child, bytes, out);
    }
}

fn first_child_of_kinds<'a>(node: Node<'a>, kinds: &[&str]) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .find(|c| kinds.contains(&c.kind()));
    found
}

fn is_wide_numeric_type(text: &str) -> bool {
    // Closed list of element types ≥ 2 bytes. Excludes `char`, `int8_t`,
    // `uint8_t` because byte arrays are already byte-indexable — the trick
    // we're catching is hiding bytes *inside* a non-byte-element array.
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    matches!(
        normalized.as_str(),
        "short"
            | "unsigned short"
            | "signed short"
            | "int"
            | "unsigned int"
            | "signed int"
            | "long"
            | "unsigned long"
            | "signed long"
            | "long long"
            | "unsigned long long"
            | "signed long long"
            | "long double"
            | "float"
            | "double"
            | "wchar_t"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
            | "intptr_t"
            | "uintptr_t"
    )
}

fn is_byte_pointer_type_descriptor(type_desc: Node, bytes: &[u8]) -> bool {
    // Must have at least one `abstract_pointer_declarator` to be a pointer.
    let mut cursor = type_desc.walk();
    let has_pointer = type_desc
        .children(&mut cursor)
        .any(|c| c.kind() == "abstract_pointer_declarator");
    if !has_pointer {
        return false;
    }
    let mut cursor = type_desc.walk();
    let type_part = type_desc
        .children(&mut cursor)
        .find(|c| {
            matches!(
                c.kind(),
                "primitive_type" | "type_identifier" | "sized_type_specifier"
            )
        })
        .map(|n| {
            node_text(n, bytes)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    matches!(
        type_part.as_str(),
        "char" | "unsigned char" | "signed char" | "int8_t" | "uint8_t" | "i8" | "u8"
    )
}

// ---------------------------------------------------------------------------
// Pre-ANSI K&R-style `main` declaration (no return type)
// ---------------------------------------------------------------------------
//
// `main(int c, char *C[]) { ... }` without a return type is pre-ANSI C
// (implicit-int return). Modern C compilers reject this; modern code never
// writes it. tree-sitter-c surfaces it as a top-level ERROR node followed by
// a `compound_statement` — the ERROR contains the malformed signature whose
// first deep `identifier` is `main`.

fn check_legacy_kr_main(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut cursor = root.walk();
    let children: Vec<Node> = root.children(&mut cursor).collect();
    for (idx, child) in children.iter().enumerate() {
        let kind = child.kind();
        let is_kr = match kind {
            // Pattern A: K&R `main() { ... }` — tree-sitter recovers the
            // signature as a top-level ERROR, followed by optional K&R
            // parameter declarations then a `compound_statement`. Both the
            // simple `main(){...}` and `main(v,c)char**c;{...}` forms land
            // here since the char**c declaration appears as a sibling of ERROR.
            "ERROR" => {
                followed_by_compound_after_decls(&children, idx)
                    && first_identifier_text(*child, bytes) == Some("main")
            }
            // Pattern B: heavy-recovery case (notation.c). The function body
            // gets folded into a top-level `declaration` whose first child is
            // `macro_type_specifier` (tree-sitter's recovery for `name(type)`
            // when no proper return-type precedes the function name).
            "declaration" => {
                child
                    .child(0)
                    .map(|c| c.kind() == "macro_type_specifier")
                    .unwrap_or(false)
                    && first_identifier_text(*child, bytes) == Some("main")
            }
            // Pattern C: classic K&R signature with explicit parameter
            // declarations between the signature and the body, e.g.
            // `main(argc, argv) int argc; char **argv; { ... }`. Here the
            // signature parses as an `expression_statement` whose call
            // expression's callee is `main`, followed by parameter
            // `declaration`s, followed by a top-level `compound_statement`.
            "expression_statement" => {
                expression_statement_calls_main(*child, bytes)
                    && followed_by_compound_after_decls(&children, idx)
            }
            _ => false,
        };
        if !is_kr {
            continue;
        }
        let offset = child.start_byte();
        let (line, col) = index.locate(offset);
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: offset,
            line,
            col,
            pass: PassKind::Ast,
            kind: SignalKind::LegacyKAndRMain,
            severity: Severity::Warn,
            confidence: 0.85,
            message: "main() defined without a return type (pre-ANSI K&R style)".to_string(),
            snippet: redact_snippet(&snippet_around(bytes, offset, 80)),
            diff_introduced: false,
        });
        return; // one finding per file
    }
}

// ---------------------------------------------------------------------------
// File-wide implicit-int / K&R style detection
// ---------------------------------------------------------------------------
//
// `f(a){ ... }` with no return type is pre-ANSI C — it has been undefined
// behaviour since C99. A *single* such function (typically `main`) is caught
// by check_legacy_kr_main above. When *many* functions in the same file lack
// a return type we have a much stronger signal: either pre-1989 source or
// IOCCC-style obfuscation that abuses implicit-int to compress declarations.
//
// Tree-sitter recovers implicit-int functions in three observable shapes:
//
//   * P1 (clean):    `function_definition` whose declarator child is a
//                    `parenthesized_declarator` rather than a
//                    `function_declarator`. The "return-type" slot has been
//                    filled by what is actually the function name parsed as a
//                    `type_identifier`.
//   * P2 (recovery): a top-level `expression_statement` containing a
//                    `call_expression` (the bare `name(args)` signature),
//                    followed by a `compound_statement` (the body).
//   * P3 (recovery): a top-level `ERROR` node followed by a
//                    `compound_statement` — the heaviest recovery, used when
//                    the parser couldn't even partially split the signature.
const IMPLICIT_INT_MIN_COUNT: usize = 3;

fn check_implicit_int_functions(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut cursor = root.walk();
    let children: Vec<Node> = root.children(&mut cursor).collect();
    let mut hits: Vec<(usize, &str)> = Vec::new();
    for (idx, child) in children.iter().enumerate() {
        let kind = child.kind();
        let matched_name: Option<&str> = match kind {
            "function_definition" => {
                if function_definition_is_implicit_int(*child) {
                    // The "type_identifier" slot in this recovered shape is
                    // actually the function name; the first plain identifier
                    // would be a parameter.
                    first_node_text_of_kind(*child, bytes, "type_identifier")
                } else {
                    None
                }
            }
            "expression_statement" => {
                if expression_statement_top_level_call(*child)
                    && children
                        .get(idx + 1)
                        .map(|n| n.kind() == "compound_statement")
                        .unwrap_or(false)
                {
                    first_node_text_of_kind(*child, bytes, "identifier")
                } else {
                    None
                }
            }
            "ERROR" => {
                if children
                    .get(idx + 1)
                    .map(|n| n.kind() == "compound_statement")
                    .unwrap_or(false)
                {
                    // Either the ERROR has a recovered macro_type_specifier
                    // (heavy recovery) or just a stray identifier.
                    first_node_text_of_kind(*child, bytes, "identifier")
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(name) = matched_name {
            hits.push((child.start_byte(), name));
        }
    }
    if hits.len() < IMPLICIT_INT_MIN_COUNT {
        return;
    }
    let (first_offset, _first_name) = hits[0];
    let (line, col) = index.locate(first_offset);
    let sample: Vec<&str> = hits.iter().take(6).map(|(_, n)| *n).collect();
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: first_offset,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::ImplicitIntFunction,
        severity: Severity::Warn,
        confidence: 0.85,
        message: format!(
            "{} functions in this file lack an explicit return type (pre-ANSI K&R style; e.g. {})",
            hits.len(),
            sample.join(", ")
        ),
        snippet: redact_snippet(&snippet_around(bytes, first_offset, 80)),
        diff_introduced: false,
    });
}

fn first_node_text_of_kind<'a>(node: Node<'a>, bytes: &'a [u8], kind: &str) -> Option<&'a str> {
    if node.kind() == kind {
        return std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).ok();
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(s) = first_node_text_of_kind(child, bytes, kind) {
            return Some(s);
        }
    }
    None
}

fn function_definition_is_implicit_int(node: Node) -> bool {
    let mut cursor = node.walk();
    let kids: Vec<Node> = node.children(&mut cursor).collect();
    // Implicit-int recovery: `f(a){...}` parses as
    // type_identifier + parenthesized_declarator + compound_statement.
    // A real definition has a function_declarator (or a pointer_declarator
    // wrapping one) instead.
    kids.iter().any(|n| n.kind() == "parenthesized_declarator")
}

fn expression_statement_top_level_call(node: Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            // Require the callee to be a bare identifier — otherwise this is
            // most likely a real expression statement, not a misparsed
            // function signature.
            if let Some(callee) = child.child(0) {
                if callee.kind() == "identifier" {
                    return true;
                }
            }
        }
    }
    false
}

fn expression_statement_calls_main(node: Node, bytes: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(callee) = child.child(0) {
                if callee.kind() == "identifier"
                    && std::str::from_utf8(&bytes[callee.start_byte()..callee.end_byte()]).ok()
                        == Some("main")
                {
                    return true;
                }
            }
        }
    }
    false
}

fn followed_by_compound_after_decls(children: &[Node], idx: usize) -> bool {
    for sibling in &children[idx + 1..] {
        match sibling.kind() {
            "declaration" => continue,
            "compound_statement" => return true,
            _ => return false,
        }
    }
    false
}

/// First identifier in a DFS traversal of `node`, or None if there isn't one.
fn first_identifier_text<'a>(root: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            return std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).ok();
        }
        for i in (0..node.child_count() as u32).rev() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Reverse subscript notation (`N[ptr]` form, equivalent to `ptr[N]`)
// ---------------------------------------------------------------------------
//
// In C, `a[b]` is defined as `*(a + b)`, so `2[arr]` and `arr[2]` are
// equivalent. Real code essentially never indexes a pointer with the integer
// on the left — it's a famous IOCCC trick.
//
// Two shapes:
//   * AST: `subscript_expression` whose `argument` field is a `number_literal`
//     — the direct `2[arr]` form that survives a clean parse.
//   * Macro: `#define <name> [<expr>]` where the body is a bare bracketed
//     expression. Used as `2 NAME` to construct a reverse subscript at the
//     call site (the rational.c trick: `#define q [v+a]` → `2 q` ⇒ `2[v+a]`).

fn check_reverse_subscript(
    node: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(arg) = node.child_by_field_name("argument") else {
        return;
    };
    if arg.kind() != "number_literal" {
        return;
    }
    // Suppress recovery artefacts: a subscript_expression nested in an
    // ERROR ancestor is most likely a misparse, not real source. A single
    // self-error (`node.is_error()`) is not enough — tree-sitter sometimes
    // wraps a half-recovered macro continuation in a parent ERROR that
    // joins the trailing `N` of one declaration with the `[expr]` of the
    // next.
    if has_error_ancestor(node) {
        return;
    }
    push(
        findings,
        node,
        bytes,
        path,
        index,
        SignalKind::ReverseSubscriptNotation,
        Severity::Warn,
        0.90,
        "subscript with integer literal on the left (`N[ptr]` is equivalent to `ptr[N]`)"
            .to_string(),
    );
}

fn has_error_ancestor(node: Node) -> bool {
    let mut cursor = node;
    while let Some(parent) = cursor.parent() {
        if parent.kind() == "ERROR" || parent.is_error() {
            return true;
        }
        cursor = parent;
    }
    false
}

fn check_reverse_subscript_macros(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut cursor = root.walk();
    for top in root.children(&mut cursor) {
        if top.kind() != "preproc_def" {
            continue;
        }
        let Some(arg) = preproc_arg_child(top) else {
            continue;
        };
        let body = match std::str::from_utf8(&bytes[arg.start_byte()..arg.end_byte()]) {
            Ok(s) => s.trim(),
            Err(_) => continue,
        };
        // `[...]` body: opens with `[`, closes with `]`, has at least one byte
        // of content between. Excludes `[]` placeholders.
        if body.len() < 3 || !body.starts_with('[') || !body.ends_with(']') {
            continue;
        }
        let Some(name) = first_node_text_of_kind(top, bytes, "identifier") else {
            continue;
        };
        push(
            findings,
            top,
            bytes,
            path,
            index,
            SignalKind::ReverseSubscriptNotation,
            Severity::Warn,
            0.90,
            format!(
                "`#define {} {}` — bracket-only macro body builds a reverse subscript at the call site (`N {}` ⇒ `N{}`)",
                name, body, name, body
            ),
        );
    }
}

#[allow(clippy::manual_find)]
fn preproc_arg_child(node: Node) -> Option<Node> {
    // The iterator's lifetime is tied to the cursor's stack frame, so we
    // can't return `find(...)` directly without collecting first.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "preproc_arg" {
            return Some(child);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Recursive `main()` call
// ---------------------------------------------------------------------------
//
// Real programs never call `main` from inside themselves — the runtime is the
// only legitimate caller. Calls to `main` from any function body in the same
// TU are an IOCCC pattern (loop using `main` as the recursion vehicle, often
// to thread state through `argc`/`argv`).

fn check_recursive_main(
    call: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    if func.kind() != "identifier" {
        return;
    }
    if &bytes[func.start_byte()..func.end_byte()] != b"main" {
        return;
    }
    // Suppress the K&R `main() { ... }` definition shape: tree-sitter
    // wraps the bare signature in an `ERROR` whose direct child is the
    // call_expression. A real recursive call sits inside a real expression
    // context (return_statement, argument_list, parenthesized_expression,
    // etc.), so its immediate parent will not be `ERROR`.
    if call.parent().map(|p| p.kind()) == Some("ERROR") {
        return;
    }
    // Also guard against a definition recovered as a top-level
    // `expression_statement` followed by optional K&R parameter declarations
    // then a `compound_statement` (Pattern C implicit-int recovery shape).
    if let Some(parent) = call.parent() {
        if parent.kind() == "expression_statement" {
            if let Some(gp) = parent.parent() {
                if gp.kind() == "translation_unit" {
                    let mut cur = gp.walk();
                    let kids: Vec<Node> = gp.children(&mut cur).collect();
                    if let Some(idx) = kids.iter().position(|n| n.id() == parent.id()) {
                        if followed_by_compound_after_decls(&kids, idx) {
                            return;
                        }
                    }
                }
            }
        }
    }
    push(
        findings,
        call,
        bytes,
        path,
        index,
        SignalKind::RecursiveMainCall,
        Severity::Warn,
        0.90,
        "`main` is called from within a function — recursion through main is an IOCCC pattern"
            .to_string(),
    );
}

// ---------------------------------------------------------------------------
// Stringify-and-dereference (`*#param` in a function-like macro body)
// ---------------------------------------------------------------------------
//
// In a `#define name(p) ...` body, the `#p` operator stringifies parameter
// `p` into a string literal at expansion time. Combining it with a leading
// `*` (`*#p`) dereferences the resulting literal to extract its first byte —
// a one-character literal extraction trick used in IOCCC code (e.g.
// `*c == *#v` to compare a runtime char against the first letter of a
// macro-arg token). Token paste `##` is excluded.

fn check_stringify_dereference_macros(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut cursor = root.walk();
    for top in root.children(&mut cursor) {
        if top.kind() != "preproc_function_def" {
            continue;
        }
        let Some(arg) = preproc_arg_child(top) else {
            continue;
        };
        let body = &bytes[arg.start_byte()..arg.end_byte()];
        if !body_has_stringify_deref(body) {
            continue;
        }
        let Some(name) = first_node_text_of_kind(top, bytes, "identifier") else {
            continue;
        };
        push(
            findings,
            top,
            bytes,
            path,
            index,
            SignalKind::StringifyDereference,
            Severity::Warn,
            0.90,
            format!(
                "macro `{}` body contains `*#param` — stringify-then-dereference extracts a single character from a macro argument",
                name
            ),
        );
    }
}

fn body_has_stringify_deref(body: &[u8]) -> bool {
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'*' {
            i += 1;
            continue;
        }
        // Skip any whitespace (incl. backslash-newline line continuations)
        // between `*` and `#`.
        let mut j = i + 1;
        while j < body.len() && is_macro_body_whitespace(body, j) {
            j = advance_whitespace(body, j);
        }
        if j >= body.len() || body[j] != b'#' {
            i += 1;
            continue;
        }
        // Reject token paste `##`.
        if j + 1 < body.len() && body[j + 1] == b'#' {
            i = j + 2;
            continue;
        }
        // Skip whitespace after `#`.
        let mut k = j + 1;
        while k < body.len() && is_macro_body_whitespace(body, k) {
            k = advance_whitespace(body, k);
        }
        if k < body.len() && (body[k].is_ascii_alphabetic() || body[k] == b'_') {
            return true;
        }
        i += 1;
    }
    false
}

fn is_macro_body_whitespace(body: &[u8], i: usize) -> bool {
    matches!(body[i], b' ' | b'\t' | b'\n' | b'\r')
        || (body[i] == b'\\'
            && i + 1 < body.len()
            && (body[i + 1] == b'\n' || body[i + 1] == b'\r'))
}

fn advance_whitespace(body: &[u8], i: usize) -> usize {
    if body[i] == b'\\' && i + 1 < body.len() && (body[i + 1] == b'\n' || body[i + 1] == b'\r') {
        i + 2
    } else {
        i + 1
    }
}

// ---------------------------------------------------------------------------
// Macro keyword override (`#define <keyword> <body>`)
// ---------------------------------------------------------------------------
//
// Rebinding a C reserved keyword silently changes the meaning of every later
// occurrence in the file. Empty-body shims (`#define inline`) are excluded —
// those are a legitimate portability pattern. C11+ pseudo-keywords
// (`_Static_assert`, `_Generic`, `_Atomic`, etc.) are also excluded because
// real codebases routinely polyfill them.

const C_KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
    "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
    "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
    "union", "unsigned", "void", "volatile", "while",
];

fn check_macro_keyword_overrides(
    root: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    findings: &mut Vec<Finding>,
) {
    let mut cursor = root.walk();
    for top in root.children(&mut cursor) {
        if top.kind() != "preproc_def" {
            continue;
        }
        let Some(name) = first_node_text_of_kind(top, bytes, "identifier") else {
            continue;
        };
        let body = preproc_arg_child(top)
            .map(|arg| {
                std::str::from_utf8(&bytes[arg.start_byte()..arg.end_byte()])
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
            .unwrap_or_default();
        if body.is_empty() {
            // Exclude empty-body shims (`#define inline`).
            continue;
        }
        if C_KEYWORDS.contains(&name) {
            // `#define for while` — rebinds the keyword itself.
            push(
                findings,
                top,
                bytes,
                path,
                index,
                SignalKind::MacroKeywordOverride,
                Severity::Warn,
                0.90,
                format!(
                    "`#define {} {}` rebinds a C reserved keyword — every later occurrence silently changes meaning",
                    name, body
                ),
            );
        } else if C_KEYWORDS.contains(&body.as_str()) {
            // `#define QO0 for` — hides a keyword behind an obfuscated alias.
            push(
                findings,
                top,
                bytes,
                path,
                index,
                SignalKind::MacroKeywordOverride,
                Severity::Warn,
                0.85,
                format!(
                    "`#define {} {}` aliases a C reserved keyword behind a non-keyword macro name",
                    name, body
                ),
            );
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
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicAttribute));
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
        assert!(
            findings.is_empty(),
            "expected no findings, got: {:?}",
            findings
        );
    }

    #[test]
    fn parse_error_tolerated() {
        let result = analyze(&PathBuf::from("bad.c"), b"int x( {");
        let _ = result.parse_error;
    }

    // --- numeric-literal payload smuggling ---

    #[test]
    fn double_array_with_byte_cast_is_critical() {
        let src = br#"double O[]={1.1,2.2,3.3,4.4,5.5,6.6,7.7,8.8,9.9};
void f(int i){ char *p = (char*)&O[i]; }
"#;
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::NumericLiteralPayload)
            .expect("expected NumericLiteralPayload");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.message.contains("`O`"));
        assert!(hit.message.contains("9 elements"));
    }

    #[test]
    fn unsigned_char_cast_of_uint64_array_is_critical() {
        let src = br#"uint64_t T[]={1,2,3,4,5,6,7,8,9,10};
void f(){ unsigned char *p = (unsigned char*)T; }
"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::NumericLiteralPayload),
            "expected NumericLiteralPayload, got: {:?}",
            findings
        );
    }

    #[test]
    fn uint8_t_cast_of_double_array_is_critical() {
        let src = br#"double O[]={1.1,2.2,3.3,4.4,5.5,6.6,7.7,8.8,9.9};
void f(){ uint8_t *p = (uint8_t*)O; }
"#;
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::NumericLiteralPayload));
    }

    #[test]
    fn multiple_casts_of_same_array_collapse_to_one_finding() {
        // Six casts → exactly one finding mentioning the count.
        let src = br#"double O[]={1.1,2.2,3.3,4.4,5.5,6.6,7.7,8.8,9.9};
void f(int i){
    char *a=(char*)O;
    char *b=(char*)&O[1];
    char *c=(char*)&O[i];
    char *d=(char*)(O+1);
    unsigned char *e=(unsigned char*)O;
    uint8_t *g=(uint8_t*)&O[2];
}
"#;
        let findings = run(src);
        let payload: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == SignalKind::NumericLiteralPayload)
            .collect();
        assert_eq!(payload.len(), 1, "expected 1 finding, got: {:?}", payload);
        assert!(
            payload[0].message.contains("6 byte-pointer casts"),
            "expected count, got: {}",
            payload[0].message
        );
    }

    #[test]
    fn double_array_without_cast_does_not_fire() {
        let src = br#"double C[]={1.1,2.2,3.3,4.4,5.5,6.6,7.7,8.8,9.9};
double sum(int n){ double s=0; for(int i=0;i<n;i++) s+=C[i]; return s; }
"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::NumericLiteralPayload),
            "no NumericLiteralPayload expected without a byte cast, got: {:?}",
            findings
        );
    }

    #[test]
    fn small_double_array_does_not_fire() {
        // Below the MIN_PAYLOAD_ELEMENTS threshold (8): a 4-element matrix
        // row legitimately cast for memcpy is too small to carry a payload.
        let src = br#"double M[]={1.0,2.0,3.0,4.0};
void f(){ char *p=(char*)M; }
"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::NumericLiteralPayload),
            "small array should not fire, got: {:?}",
            findings
        );
    }

    #[test]
    fn byte_array_does_not_fire_even_with_cast() {
        // Already-byte arrays aren't smuggling — they're just byte buffers.
        let src = br#"unsigned char K[]={1,2,3,4,5,6,7,8,9,10};
void f(){ char *p=(char*)K; }
"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::NumericLiteralPayload),
            "byte-element array should not fire, got: {:?}",
            findings
        );
    }

    #[test]
    fn void_pointer_cast_does_not_fire() {
        // Generic void* casts (memcpy/memcmp args) are too common to flag.
        let src = br#"double O[]={1.1,2.2,3.3,4.4,5.5,6.6,7.7,8.8,9.9};
void f(){ void *p=(void*)O; }
"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::NumericLiteralPayload),
            "void* cast should not fire, got: {:?}",
            findings
        );
    }

    // --- K&R legacy main detection ---

    #[test]
    fn kr_main_simple_form_is_warn() {
        // Pattern A: tree-sitter parses this as ERROR + compound_statement.
        let src = b"main() { return 0; }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::LegacyKAndRMain)
            .expect("expected LegacyKAndRMain for `main() { ... }`");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.message.contains("K&R"));
    }

    #[test]
    fn kr_main_with_argv_argc_is_warn() {
        // Pattern A: ERROR + compound_statement, but with K&R argv/argc.
        let src = b"main(argc, argv) int argc; char **argv; { return 0; }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::LegacyKAndRMain));
    }

    #[test]
    fn kr_main_heavy_recovery_form_fires() {
        // Pattern B: notation.c-style — function body is heavy enough that
        // tree-sitter folds the whole thing into a `declaration` with
        // `macro_type_specifier` as the first child.
        // Use the actual notation.c head to ensure heavy recovery triggers.
        let src = br#"#include<stdio.h>
#define c(C) printf("%c",C)
#define C(c) ((int*)(C[1]+6))[c]
main(int c,char *C[]) {
  int a, b, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z;
  for (a=0; a<10; a++) { for (b=0; b<10; b++) { d = a + b; } }
  return 0;
}
"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::LegacyKAndRMain),
            "expected LegacyKAndRMain for heavy-recovery main, got: {:?}",
            findings
        );
    }

    #[test]
    fn explicit_int_main_does_not_fire() {
        let src = b"int main(int argc, char **argv) { return 0; }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::LegacyKAndRMain));
    }

    #[test]
    fn explicit_void_main_does_not_fire() {
        let src = b"void main(void) { return; }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::LegacyKAndRMain));
    }

    #[test]
    fn function_named_other_than_main_does_not_fire() {
        // K&R-style function but not `main` — out of scope for this signal.
        let src = b"foo() { return 0; }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::LegacyKAndRMain));
    }

    #[test]
    fn one_finding_per_file_only() {
        // Even if the file has multiple anomalies that could match, we emit at
        // most one LegacyKAndRMain finding.
        let src = b"main() { return 0; }\nmain() { return 1; }\n";
        let findings = run(src);
        let hits = findings
            .iter()
            .filter(|f| f.kind == SignalKind::LegacyKAndRMain)
            .count();
        assert_eq!(
            hits, 1,
            "expected one finding, got {} in {:?}",
            hits, findings
        );
    }

    // --- file-wide implicit-int / K&R style detection ---

    #[test]
    fn implicit_int_three_functions_fires() {
        // K&R-style implicit-int: parameters listed without types. This is
        // what tree-sitter recovers as `parenthesized_declarator`, the
        // pattern our detector keys off.
        let src = b"Q(a){return a;}\nW(b){return b;}\nE(c){return c;}\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::ImplicitIntFunction)
            .expect("expected ImplicitIntFunction for 3+ implicit-int functions");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.message.contains("3"));
    }

    #[test]
    fn implicit_int_two_functions_does_not_fire() {
        // Threshold is 3. K&R main alone is caught by LegacyKAndRMain.
        let src = b"Q(a){return a;}\nmain(){}\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::ImplicitIntFunction));
    }

    #[test]
    fn implicit_int_modern_c_does_not_fire() {
        let src =
            b"int f(void) { return 0; }\nvoid g(void) {}\nstatic int h(int x) { return x; }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::ImplicitIntFunction));
    }

    // --- dynamic format string ---

    #[test]
    fn dynamic_format_string_global_format_fires() {
        let src = b"const char *F = \"%c\";\nvoid emit(int c) { printf(F, c); }\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::DynamicFormatString)
            .expect("expected DynamicFormatString for global format var");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn dynamic_format_string_local_var_does_not_fire() {
        // Local variable holding a literal — common pattern, suppress.
        let src = b"void f(int x) { const char *fmt = \"%d\"; printf(fmt, x); }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicFormatString));
    }

    #[test]
    fn dynamic_format_string_parameter_does_not_fire() {
        // Wrapper functions that forward a format-string parameter.
        let src = b"void wrap(const char *fmt, int x) { printf(fmt, x); }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicFormatString));
    }

    #[test]
    fn dynamic_format_string_v_family_does_not_fire() {
        // v* family is excluded entirely — they exist to forward formats.
        let src = b"#include <stdarg.h>\nvoid wrap(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicFormatString));
    }

    #[test]
    fn dynamic_format_string_macro_does_not_fire() {
        // ALL_CAPS identifier is treated as a likely macro.
        let src = b"#define FMT \"%d\\n\"\nvoid f(int x) { printf(FMT, x); }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicFormatString));
    }

    #[test]
    fn dynamic_format_string_i18n_wrapper_does_not_fire() {
        let src = b"const char *_(const char *s);\nvoid f(int x) { printf(_(\"hello %d\"), x); }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicFormatString));
    }

    #[test]
    fn dynamic_format_string_string_literal_does_not_fire() {
        let src = b"void f(int x) { printf(\"%d\\n\", x); }\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicFormatString));
    }

    #[test]
    fn reverse_subscript_direct_fires() {
        let src = b"int f(int *a){return 2[a];}\n";
        let findings = run(src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::ReverseSubscriptNotation)
            .expect("expected ReverseSubscriptNotation");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn reverse_subscript_normal_does_not_fire() {
        let src = b"int f(int *a){return a[2];}\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::ReverseSubscriptNotation));
    }

    #[test]
    fn reverse_subscript_macro_bracket_body_fires() {
        let src = b"#define q [v+a]\nint v[10]; int f(int a){return 2[v+a];}\n";
        let findings: Vec<_> = run(src)
            .into_iter()
            .filter(|f| f.kind == SignalKind::ReverseSubscriptNotation)
            .collect();
        // One from the macro definition, one from the direct subscript.
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("#define q")));
    }

    #[test]
    fn reverse_subscript_normal_macro_body_does_not_fire() {
        // A macro body that contains brackets but isn't a bare bracket
        // expression — `b[1]` is the value, not a subscript fragment to
        // splice onto an integer.
        let src = b"#define c b[1]\nint b[3]; int f(){return c;}\n";
        let findings: Vec<_> = run(src)
            .into_iter()
            .filter(|f| f.kind == SignalKind::ReverseSubscriptNotation)
            .collect();
        assert!(findings.is_empty());
    }

    #[test]
    fn recursive_main_call_fires() {
        let src = b"int main(int a, char**b){if(a) return main(a-1,b); return 0;}\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::RecursiveMainCall)
            .expect("expected RecursiveMainCall");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn recursive_main_kr_definition_does_not_fire() {
        // K&R `main()` definition parses as ERROR + compound_statement —
        // the call_expression has no function_definition ancestor, so we
        // must NOT fire (it's a definition, not a recursive call).
        let src = b"main()\n{\nreturn 0;\n}\n";
        let findings: Vec<_> = run(src)
            .into_iter()
            .filter(|f| f.kind == SignalKind::RecursiveMainCall)
            .collect();
        assert!(findings.is_empty());
    }

    #[test]
    fn recursive_main_other_function_calling_main_fires() {
        let src = b"int main(int a, char**b){return a;}\nvoid g(int a, char**b){main(a,b);}\n";
        let findings: Vec<_> = run(src)
            .into_iter()
            .filter(|f| f.kind == SignalKind::RecursiveMainCall)
            .collect();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn stringify_dereference_fires() {
        let src = b"#define p(v) *#v\nint f(){return p(x);}\n";
        let hit = run(src)
            .into_iter()
            .find(|f| f.kind == SignalKind::StringifyDereference)
            .expect("expected StringifyDereference");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.message.contains("`p`"));
    }

    #[test]
    fn stringify_dereference_token_paste_does_not_fire() {
        // `##` is token paste, not stringify; should not fire.
        let src = b"#define cat(a,b) *##a##b\nint f(){return 0;}\n";
        let findings: Vec<_> = run(src)
            .into_iter()
            .filter(|f| f.kind == SignalKind::StringifyDereference)
            .collect();
        assert!(findings.is_empty());
    }

    #[test]
    fn stringify_dereference_plain_stringify_does_not_fire() {
        // `#x` alone (not preceded by `*`) is a normal stringify use.
        let src = b"#define dump(x) printf(\"%s=%d\\n\", #x, x)\n";
        let findings: Vec<_> = run(src)
            .into_iter()
            .filter(|f| f.kind == SignalKind::StringifyDereference)
            .collect();
        assert!(findings.is_empty());
    }

    #[test]
    fn execlp_kr_main_oneliner_fires() {
        let src = b"main(v,c)char**c;{for(;;){}}";
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::LegacyKAndRMain),
            "K&R main on one line should fire: {:?}",
            findings
        );
    }
}
