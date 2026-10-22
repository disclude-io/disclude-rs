//! Python path configuration files (`.pth`).
//!
//! At every interpreter start, `site` reads each `.pth` file in a
//! site-packages directory. A line that starts with `import ` or `import\t`
//! is executed as Python; every other line is a path to add to `sys.path`
//! (or, starting with `#`, a comment). An executable line runs before any of
//! the program's own code, whether or not its package is ever imported:
//! malware uses it to persist. Editable installs, coverage, setuptools'
//! distutils shim, and namespace packages use it legitimately.
//!
//! [`extract`] returns each executable line as a Python block, and
//! [`findings`] reports each as `pth-executable-line`: warn, or critical
//! when the line runs code from data, decodes or decompresses, starts a
//! process, loads native code, or uses the network.

use std::path::Path;

use super::CodeBlock;
use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::language::Language;
use crate::util::LineIndex;
use tree_sitter::{Node, Parser};

/// Names whose use on an executable `.pth` line makes it critical, with what
/// they do. Words are matched in identifiers and in strings alike
/// (`__import__('zlib')` names its module in a string).
const CRITICAL_WORDS: &[(&str, &[&str])] = &[
    ("runs code from data", &["exec", "eval", "compile"]),
    (
        "decodes or decompresses data",
        &[
            "base64",
            "b64decode",
            "b32decode",
            "b16decode",
            "b85decode",
            "a85decode",
            "binascii",
            "unhexlify",
            "a2b_base64",
            "fromhex",
            "codecs",
            "zlib",
            "bz2",
            "lzma",
            "gzip",
            "decompress",
            "marshal",
            "pickle",
        ],
    ),
    (
        "starts a process",
        &[
            "subprocess",
            "system",
            "popen",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "execl",
            "execle",
            "execlp",
            "execlpe",
            "spawnv",
            "spawnve",
            "spawnl",
            "spawnle",
            "posix_spawn",
            "startfile",
            "pty",
        ],
    ),
    ("loads native code", &["ctypes", "cffi"]),
    (
        "uses the network",
        &[
            "socket",
            "urllib",
            "urlopen",
            "urlretrieve",
            "http",
            "requests",
            "httpx",
            "ftplib",
        ],
    ),
];

/// Each line `site` executes, as a Python block (the line, less its line
/// ending).
pub fn extract(bytes: &[u8]) -> Vec<CodeBlock> {
    executable_lines(bytes)
        .filter_map(|(start, end)| CodeBlock::new(start, end, Language::Python))
        .collect()
}

pub fn findings(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    executable_lines(bytes)
        .map(|(start, end)| {
            let line = String::from_utf8_lossy(&bytes[start..end]);
            let hit = critical_word(&line);
            let (l, col) = index.locate(start);
            let mut message =
                "`.pth` line that Python's `site` executes at every interpreter start".to_string();
            if let Some((what, word)) = hit {
                message.push_str(&format!(", and it {what} (`{word}`)"));
            }
            Finding {
                path: path.to_path_buf(),
                byte_offset: start,
                line: l,
                col,
                pass: PassKind::Ast,
                kind: SignalKind::PthExecutableLine,
                severity: if hit.is_some() {
                    Severity::Critical
                } else {
                    Severity::Warn
                },
                confidence: if hit.is_some() { 0.9 } else { 0.7 },
                message,
                snippet: redact_snippet(line.trim_end()),
                diff_introduced: false,
            }
        })
        .collect()
}

/// `(start, end)` of each line starting `import ` or `import\t`, as `site`
/// tests it: no leading whitespace, after a UTF-8 BOM on the first line.
fn executable_lines(bytes: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut start = 0;
    std::iter::from_fn(move || {
        while start < bytes.len() {
            let end = bytes[start..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(bytes.len(), |i| start + i);
            let mut s = start;
            if s == 0 && bytes.starts_with(b"\xef\xbb\xbf") {
                s = 3;
            }
            start = end + 1;
            let line = &bytes[s..end];
            if line.starts_with(b"import ") || line.starts_with(b"import\t") {
                let e = if line.ends_with(b"\r") { end - 1 } else { end };
                return Some((s, e));
            }
        }
        None
    })
}

/// How deep code in `exec('…')` literals is followed.
const MAX_LITERAL_DEPTH: usize = 3;

/// The first name on the line that makes it critical, with what it does.
/// Names are identifiers, and strings that are only a dotted name
/// (`__import__('zlib')`, `getattr(os, 'system')`); prose in strings is
/// not. `exec('…')` on a plain string literal is how a `.pth` line holds
/// more than one statement (coverage, pytest-cov): the literal's code is
/// checked in its place.
fn critical_word(line: &str) -> Option<(&'static str, &'static str)> {
    critical_in(line, 0)
}

fn critical_in(src: &str, depth: usize) -> Option<(&'static str, &'static str)> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(src, None)?;
    let mut hit = None;
    walk(tree.root_node(), src, depth, &mut hit);
    hit
}

fn walk(node: Node, src: &str, depth: usize, hit: &mut Option<(&'static str, &'static str)>) {
    if hit.is_some() {
        return;
    }
    match node.kind() {
        "identifier" => {
            let name = &src[node.byte_range()];
            if matches!(name, "exec" | "eval" | "compile") {
                if let Some(code) = plain_literal_argument(node, src) {
                    if depth < MAX_LITERAL_DEPTH {
                        *hit = critical_in(&code, depth + 1);
                    }
                    return;
                }
            }
            // `platform.system()` is not `os.system()`.
            if matches!(name, "system" | "popen") && !on_os_module(node, src) {
                return;
            }
            *hit = critical_name(name);
            return;
        }
        "string" => {
            if let Some(text) = string_text(node, src) {
                if !text.is_empty()
                    && text.split('.').all(|w| {
                        !w.is_empty() && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    })
                {
                    *hit = text.split('.').find_map(critical_name);
                }
            }
            return;
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, src, depth, hit);
    }
}

/// Whether an attribute name is read from `os`, `posix`, or `nt`.
fn on_os_module(name: Node, src: &str) -> bool {
    name.parent()
        .filter(|p| p.kind() == "attribute" && p.child_by_field_name("attribute") == Some(name))
        .and_then(|p| p.child_by_field_name("object"))
        .is_some_and(|o| matches!(&src[o.byte_range()], "os" | "posix" | "nt"))
}

fn critical_name(name: &str) -> Option<(&'static str, &'static str)> {
    CRITICAL_WORDS
        .iter()
        .find_map(|(what, words)| words.iter().find(|w| **w == name).map(|w| (*what, *w)))
}

/// The code in `exec('…')`, when the callee's only argument (or, for
/// `compile`, its first) is a plain string literal.
fn plain_literal_argument(callee: Node, src: &str) -> Option<String> {
    let call = callee.parent().filter(|p| p.kind() == "call")?;
    if call.child_by_field_name("function") != Some(callee) {
        return None;
    }
    let args = call.child_by_field_name("arguments")?;
    let first = args.named_child(0).filter(|a| a.kind() == "string")?;
    string_text(first, src)
}

/// A string literal's text, when it is plain: no prefix but `u`, no
/// interpolation, and no escapes that hide its text (`\x`, `\u`, `\N`,
/// octal). Allowed escapes are decoded.
fn string_text(node: Node, src: &str) -> Option<String> {
    let raw = &src[node.byte_range()];
    let body = raw.strip_prefix(['u', 'U']).unwrap_or(raw);
    let quote = ["\"\"\"", "'''", "\"", "'"]
        .into_iter()
        .find(|q| body.starts_with(q) && body.len() >= 2 * q.len() && body.ends_with(q))?;
    let inner = &body[quote.len()..body.len() - quote.len()];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            c @ ('\\' | '\'' | '"') => out.push(c),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(src: &str) -> Vec<&str> {
        extract(src.as_bytes())
            .iter()
            .map(|b| &src[b.start..b.end])
            .collect()
    }

    #[test]
    fn only_lines_site_executes_are_extracted() {
        let src = "\u{feff}import a; a.go()\r\n# import b\n/opt/lib\n  import c\nimportd\nimport\te\nimport";
        assert_eq!(lines(src), ["import a; a.go()", "import\te"]);
        assert!(lines("/usr/lib/python3/dist-packages\n").is_empty());
    }

    #[test]
    fn legitimate_lines_warn_and_payloads_are_critical() {
        let index = |s: &str| LineIndex::new(s.as_bytes());
        let severity = |s: &str| {
            let f = findings(Path::new("x.pth"), s.as_bytes(), &index(s));
            assert_eq!(f.len(), 1, "{s}");
            (f[0].severity, f[0].message.clone())
        };
        for benign in [
            "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); ",
            "import __editable___mypkg_1_0_finder; __editable___mypkg_1_0_finder.install()",
            "import coverage; coverage.process_startup()",
            "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('google',));importlib = has_mfs and __import__('importlib.util')",
        ] {
            assert_eq!(severity(benign).0, Severity::Warn, "{benign}");
        }
        let (s, m) = severity("import os;exec(__import__('zlib').decompress(b'x'))");
        assert_eq!(s, Severity::Critical);
        assert!(m.ends_with("runs code from data (`exec`)"), "{m}");
        // A plain literal is how one line holds several statements; its
        // words are checked, and escapes that hide them are not plain.
        let coverage = r#"import os, sys;exec('if \'COV_CORE_SOURCE\' in os.environ:\n try:\n  from pytest_cov.embed import init\n  init()\n except Exception:\n  sys.stderr.write("Failed to setup subprocess coverage.")\n')"#;
        assert_eq!(severity(coverage).0, Severity::Warn);
        let (s, m) = severity("import sys;exec('import socket\\nsocket.create_connection(1)')");
        assert_eq!(s, Severity::Critical);
        assert!(m.ends_with("uses the network (`socket`)"), "{m}");
        let (s, m) = severity(r"import sys;exec('\x69\x6d\x70')");
        assert_eq!(s, Severity::Critical);
        assert!(m.ends_with("(`exec`)"), "{m}");
        assert_eq!(severity("import x;exec(x.y)").0, Severity::Critical);
        assert_eq!(
            severity("import platform; platform.system() == 'Linux' and None").0,
            Severity::Warn
        );
        assert!(severity("import os; os.system('id')")
            .1
            .ends_with("(`system`)"));
        assert!(severity("import os; getattr(os, 'system')('id')")
            .1
            .ends_with("(`system`)"));
        let (s, m) = severity("import subprocess,sys;subprocess.Popen([sys.executable])");
        assert_eq!(s, Severity::Critical);
        assert!(m.ends_with("starts a process (`subprocess`)"), "{m}");
    }
}
