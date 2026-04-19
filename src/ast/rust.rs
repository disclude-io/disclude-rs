//! Rust AST walker — tree-sitter-rust based checks.
//!
//! Per SPEC §ast, the Rust walker flags two things:
//!
//!   * `BuildScriptShellout` (CRITICAL): a `std::process::Command::new(x)`
//!     inside a file named `build.rs`, where the program argument is a shell
//!     or network client (`sh`, `bash`, `zsh`, `curl`, `wget`, `python`). A
//!     build script reaching out to the network or spawning a shell at
//!     compile time is a classic supply-chain-attack shape.
//!   * `ProcMacroPresence` (INFO): the file uses `#[proc_macro]`,
//!     `#[proc_macro_derive]`, or `#[proc_macro_attribute]`. Proc macros run
//!     arbitrary Rust at compile time; presence alone is not malicious, but
//!     it should surface for review.
//!
//! The walker intentionally does not flag `include_str!` / `include_bytes!`
//! with relative-escape paths — the public `SignalKind` enum has no slot
//! for that check, and the SPEC leaves a gap there. Landing it would
//! require extending the enum.

use std::path::Path;

use tree_sitter::{Node, Parser};

use super::{AstOutcome, FileFlags};
use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

const SHELL_INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "curl", "wget", "python", "python3",
];

pub fn analyze(path: &Path, bytes: &[u8]) -> AstOutcome {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return AstOutcome {
            findings: Vec::new(),
            parse_error: Some("tree-sitter: set_language failed".into()),
            file_flags: FileFlags::default(),
        };
    }
    let Some(tree) = parser.parse(bytes, None) else {
        return AstOutcome {
            findings: Vec::new(),
            parse_error: Some("tree-sitter: parse returned None".into()),
            file_flags: FileFlags::default(),
        };
    };
    let root = tree.root_node();
    let parse_error = if root.has_error() {
        Some("tree-sitter: partial parse (errors present)".into())
    } else {
        None
    };
    let index = LineIndex::new(bytes);
    let is_build_rs = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == "build.rs")
        .unwrap_or(false);

    let mut state = State {
        findings: Vec::new(),
        proc_macro_emitted: false,
        contains_unsafe: false,
        is_build_rs,
    };
    let mut cursor = root.walk();
    walk(root, bytes, path, &index, &mut state, &mut cursor);
    AstOutcome {
        findings: state.findings,
        parse_error,
        file_flags: FileFlags {
            contains_unsafe: state.contains_unsafe,
        },
    }
}

struct State {
    findings: Vec<Finding>,
    proc_macro_emitted: bool,
    contains_unsafe: bool,
    is_build_rs: bool,
}

fn walk<'a>(
    node: Node<'a>,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    state: &mut State,
    cursor: &mut tree_sitter::TreeCursor<'a>,
) {
    match node.kind() {
        "call_expression" if state.is_build_rs => check_shellout(node, bytes, path, index, state),
        "attribute_item" | "inner_attribute_item" => {
            if !state.proc_macro_emitted {
                check_proc_macro(node, bytes, path, index, state);
            }
        }
        "unsafe_block" => state.contains_unsafe = true,
        _ => {}
    }
    for child in node.children(cursor) {
        let mut sub = child.walk();
        walk(child, bytes, path, index, state, &mut sub);
    }
}

// ---------------------------------------------------------------------------
// BuildScriptShellout
// ---------------------------------------------------------------------------

fn check_shellout(call: Node, bytes: &[u8], path: &Path, index: &LineIndex, state: &mut State) {
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    let func = unwrap_generic(func);
    if !callee_ends_with(func, bytes, "Command", "new") {
        return;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };
    let Some(first) = first_positional_arg(args) else {
        return;
    };
    let Some(lit) = string_literal_value(first, bytes) else {
        return;
    };
    let Some(interp) = shell_interpreter(&lit) else {
        return;
    };
    let off = call.start_byte();
    let (line, col) = index.locate(off);
    state.findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::BuildScriptShellout,
        severity: Severity::Critical,
        confidence: 0.90,
        message: format!("build.rs spawns `{}` via std::process::Command", interp),
        snippet: redact_snippet(&snippet_around(bytes, off, 100)),
        diff_introduced: false,
    });
}

// ---------------------------------------------------------------------------
// ProcMacroPresence
// ---------------------------------------------------------------------------

fn check_proc_macro(
    attr_item: Node,
    bytes: &[u8],
    path: &Path,
    index: &LineIndex,
    state: &mut State,
) {
    // attribute_item contains exactly one `attribute` node; that attribute's
    // first identifier-shaped child is the attribute path.
    let Some(attr) = find_child_by_kind(attr_item, "attribute") else {
        return;
    };
    let Some(name) = attribute_name(attr, bytes) else {
        return;
    };
    if !matches!(
        name.as_str(),
        "proc_macro" | "proc_macro_derive" | "proc_macro_attribute"
    ) {
        return;
    }
    let off = attr_item.start_byte();
    let (line, col) = index.locate(off);
    state.findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: off,
        line,
        col,
        pass: PassKind::Ast,
        kind: SignalKind::ProcMacroPresence,
        severity: Severity::Info,
        confidence: 0.95,
        message: format!("proc-macro attribute `#[{}]` present", name),
        snippet: redact_snippet(&snippet_around(bytes, off, 80)),
        diff_introduced: false,
    });
    state.proc_macro_emitted = true;
}

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------

fn node_text<'a>(node: Node, bytes: &'a [u8]) -> &'a str {
    std::str::from_utf8(&bytes[node.start_byte()..node.end_byte()]).unwrap_or("")
}

fn find_child_by_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            return Some(child);
        }
    }
    None
}

/// If the callee is a `generic_function` (`foo::<T>()`), return the underlying
/// function path; otherwise return the node as-is.
fn unwrap_generic(func: Node) -> Node {
    if func.kind() == "generic_function" {
        func.child_by_field_name("function").unwrap_or(func)
    } else {
        func
    }
}

/// True if `func` is `...::a::b` — used to match `...::Command::new` without
/// binding to a specific import path (handles bare `Command::new` and
/// `std::process::Command::new` alike).
fn callee_ends_with(func: Node, bytes: &[u8], second_to_last: &str, last: &str) -> bool {
    // Flatten a scoped_identifier chain into its segment identifiers.
    let segs = scoped_segments(func, bytes);
    let n = segs.len();
    n >= 2 && segs[n - 1] == last && segs[n - 2] == second_to_last
}

fn scoped_segments(node: Node, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    collect_segments(node, bytes, &mut out);
    out
}

fn collect_segments(node: Node, bytes: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "identifier" => out.push(node_text(node, bytes).to_string()),
        "scoped_identifier" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "::" => {}
                    _ => collect_segments(child, bytes, out),
                }
            }
        }
        _ => {}
    }
}

/// Return the first positional argument expression, skipping punctuation.
/// tree-sitter-rust `arguments` children: `(`, expressions separated by `,`, `)`.
fn first_positional_arg(args: Node) -> Option<Node> {
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        match child.kind() {
            "(" | ")" | "," => continue,
            _ => return Some(child),
        }
    }
    None
}

/// Extract the text content of a `string_literal` or `raw_string_literal`.
/// Returns `None` for any other node kind (including non-literal expressions).
fn string_literal_value(node: Node, bytes: &[u8]) -> Option<String> {
    match node.kind() {
        "string_literal" => {
            if let Some(content) = find_child_by_kind(node, "string_content") {
                return Some(node_text(content, bytes).to_string());
            }
            // Empty string "": no content node. Return empty.
            Some(String::new())
        }
        "raw_string_literal" => {
            // tree-sitter-rust exposes raw string content as the node text
            // minus the `r#"..."#` wrapping. We strip symmetric leading `r`,
            // `#`, `"` and matching trailing `#`, `"`.
            let raw = node_text(node, bytes);
            strip_raw_string(raw).map(|s| s.to_string())
        }
        _ => None,
    }
}

fn strip_raw_string(raw: &str) -> Option<&str> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    if bytes.first() != Some(&b'r') {
        return None;
    }
    i += 1;
    let mut hashes = 0;
    while i < bytes.len() && bytes[i] == b'#' {
        hashes += 1;
        i += 1;
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    let start = i;
    let end = raw.len().checked_sub(1 + hashes)?;
    if end < start {
        return None;
    }
    if bytes[end] != b'"' {
        return None;
    }
    Some(&raw[start..end])
}

/// Map a string value to a shell-interpreter name, matching by basename so
/// both `"curl"` and `"/usr/bin/curl"` normalize to `curl`.
fn shell_interpreter(s: &str) -> Option<&'static str> {
    let basename = s.rsplit_once('/').map(|(_, b)| b).unwrap_or(s);
    for &name in SHELL_INTERPRETERS {
        if basename == name {
            return Some(name);
        }
    }
    None
}

/// Pull the attribute path out of an `attribute` node. Accepts both
/// `#[proc_macro]` (identifier) and `#[proc_macro_derive(...)]` (identifier
/// followed by token_tree). Scoped attribute paths return the full dotted
/// path with `::` preserved.
fn attribute_name(attr: Node, bytes: &[u8]) -> Option<String> {
    let mut cursor = attr.walk();
    for child in attr.children(&mut cursor) {
        match child.kind() {
            "identifier" | "scoped_identifier" => {
                return Some(node_text(child, bytes).to_string());
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(name: &str, src: &[u8]) -> Vec<Finding> {
        analyze(&PathBuf::from(name), src).findings
    }

    fn run_flags(name: &str, src: &[u8]) -> FileFlags {
        analyze(&PathBuf::from(name), src).file_flags
    }

    #[test]
    fn build_rs_command_curl_is_critical() {
        let src = br#"
fn main() {
    std::process::Command::new("curl").arg("http://x").status().unwrap();
}
"#;
        let findings = run("build.rs", src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::BuildScriptShellout)
            .expect("expected BuildScriptShellout");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn build_rs_command_sh_is_critical() {
        let src = br#"
use std::process::Command;
fn main() { Command::new("sh").arg("-c").arg("...").status().unwrap(); }
"#;
        let findings = run("build.rs", src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::BuildScriptShellout));
    }

    #[test]
    fn build_rs_command_abspath_curl_is_critical() {
        let src = br#"
fn main() { std::process::Command::new("/usr/bin/curl").status().unwrap(); }
"#;
        let findings = run("build.rs", src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::BuildScriptShellout));
    }

    #[test]
    fn build_rs_command_cargo_is_ignored() {
        let src = br#"
fn main() { std::process::Command::new("cargo").arg("--version").status().unwrap(); }
"#;
        let findings = run("build.rs", src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::BuildScriptShellout));
    }

    #[test]
    fn non_build_rs_command_is_ignored() {
        // Same shellout pattern, but in a regular source file: no finding.
        let src = br#"
fn main() { std::process::Command::new("curl").status().unwrap(); }
"#;
        let findings = run("src/main.rs", src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::BuildScriptShellout));
    }

    #[test]
    fn build_rs_dynamic_program_is_ignored() {
        // Program argument is a variable, not a string literal. We intentionally
        // do not flag this in the AST pass — string-construction heuristics are
        // a token-pass concern and would produce too many false positives on
        // bare `Command::new(prog)`.
        let src = br#"
fn run(prog: &str) { std::process::Command::new(prog).status().unwrap(); }
"#;
        let findings = run("build.rs", src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::BuildScriptShellout));
    }

    #[test]
    fn proc_macro_attribute_is_info() {
        let src = br#"
#[proc_macro]
pub fn my_macro(input: proc_macro::TokenStream) -> proc_macro::TokenStream { input }
"#;
        let findings = run("src/lib.rs", src);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::ProcMacroPresence)
            .expect("expected ProcMacroPresence");
        assert_eq!(hit.severity, Severity::Info);
    }

    #[test]
    fn proc_macro_derive_detected() {
        let src = br#"
#[proc_macro_derive(Foo)]
pub fn derive_foo(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    unimplemented!()
}
"#;
        let findings = run("src/lib.rs", src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::ProcMacroPresence));
    }

    #[test]
    fn proc_macro_emitted_once_per_file() {
        let src = br#"
#[proc_macro] pub fn a(x: T) -> T { x }
#[proc_macro_attribute] pub fn b(_: T, x: T) -> T { x }
#[proc_macro_derive(Foo)] pub fn c(_: T) -> T { unimplemented!() }
"#;
        let findings = run("src/lib.rs", src);
        let count = findings
            .iter()
            .filter(|f| f.kind == SignalKind::ProcMacroPresence)
            .count();
        assert_eq!(count, 1, "expected exactly one proc-macro finding per file");
    }

    #[test]
    fn ordinary_attribute_is_not_proc_macro() {
        let src = br#"
#[derive(Debug, Clone)]
#[serde(rename = "x")]
pub struct S;
"#;
        let findings = run("src/lib.rs", src);
        assert!(findings
            .iter()
            .all(|f| f.kind != SignalKind::ProcMacroPresence));
    }

    #[test]
    fn parse_error_tolerated() {
        let result = analyze(&PathBuf::from("bad.rs"), b"fn x( {");
        let _ = result.parse_error;
    }

    #[test]
    fn unsafe_block_sets_file_flag() {
        let src = br#"
fn main() {
    unsafe { *(0 as *const u8) };
}
"#;
        let flags = run_flags("src/lib.rs", src);
        assert!(flags.contains_unsafe);
    }

    #[test]
    fn no_unsafe_leaves_flag_unset() {
        let src = b"fn main() { println!(\"safe\"); }";
        let flags = run_flags("src/lib.rs", src);
        assert!(!flags.contains_unsafe);
    }

    #[test]
    fn unsafe_in_string_literal_does_not_set_flag() {
        let src = b"fn main() { let s = \"unsafe block\"; }";
        let flags = run_flags("src/lib.rs", src);
        assert!(!flags.contains_unsafe);
    }

    #[test]
    fn strip_raw_string_roundtrip() {
        assert_eq!(strip_raw_string(r#"r"curl""#), Some("curl"));
        assert_eq!(strip_raw_string(r###"r##"a"b"##"###), Some("a\"b"));
    }
}
