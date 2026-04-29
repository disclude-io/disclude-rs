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
    let arrays = collect_numeric_arrays(root, bytes);
    if !arrays.is_empty() {
        check_numeric_payload_casts(root, bytes, path, &index, &mut findings, &arrays);
    }
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
    let mut cursor = root.walk();
    walk_for_arrays(root, bytes, &mut out, &mut cursor);
    out
}

fn walk_for_arrays<'a>(
    node: Node<'a>,
    bytes: &[u8],
    out: &mut Vec<NumericArray>,
    cursor: &mut tree_sitter::TreeCursor<'a>,
) {
    if node.kind() == "declaration" {
        if let Some(arr) = parse_numeric_array(node, bytes) {
            out.push(arr);
        }
    }
    for child in node.children(cursor) {
        let mut sub = child.walk();
        walk_for_arrays(child, bytes, out, &mut sub);
    }
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
    let mut cursor = root.walk();
    walk_casts(root, bytes, arrays, &mut hits, &mut cursor);
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

fn walk_casts<'a>(
    node: Node<'a>,
    bytes: &[u8],
    arrays: &[NumericArray],
    hits: &mut [Option<(usize, usize)>],
    cursor: &mut tree_sitter::TreeCursor<'a>,
) {
    if node.kind() == "cast_expression" {
        if let Some(idx) = matches_byte_cast_of_array(node, bytes, arrays) {
            let off = node.start_byte();
            match &mut hits[idx] {
                slot @ None => *slot = Some((off, 1)),
                Some((_, count)) => *count += 1,
            }
        }
    }
    for child in node.children(cursor) {
        let mut sub = child.walk();
        walk_casts(child, bytes, arrays, hits, &mut sub);
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
}
