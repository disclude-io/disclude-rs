//! HTML code extraction via tree-sitter-html.
//!
//! Three places in a page hold JavaScript a browser runs:
//!
//! * `<script>` bodies whose `type` is absent or a JavaScript type (JSON data
//!   islands are not code; `crate::hidden` reads those);
//! * event-handler attributes (`onclick`, `onload`, …);
//! * `javascript:` URLs in `href`, `src`, `action`, and `formaction`.
//!
//! A browser decodes character references in attribute values before running
//! them (`onclick="&#101;val(…)"` runs `eval(…)`); a script body is raw text
//! and is not decoded. [`decode_block`] gives the scanner what the browser
//! runs, at the block's original length, so findings keep their lines.

use std::path::Path;

use tree_sitter::{Node, Parser, Tree};

use super::CodeBlock;
use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::language::Language;
use crate::util::{snippet_around, LineIndex};

/// Attributes whose value is a URL that may use the `javascript:` scheme.
const URL_ATTRIBUTES: &[&str] = &["href", "src", "action", "formaction", "xlink:href"];

/// Character references spelling letters or digits, in one attribute value,
/// at or above which the spelling is concealment: nothing in a handler or URL
/// needs `&#101;` for `e`. Entities for markup characters (`&amp;`, `&quot;`)
/// are ordinary and not counted.
const NEEDLESS_REFERENCES_MIN: usize = 3;

pub(crate) fn parse(bytes: &[u8]) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_html::LANGUAGE.into())
        .ok()?;
    parser.parse(bytes, None)
}

pub fn extract(bytes: &[u8]) -> Vec<CodeBlock> {
    let Some(tree) = parse(bytes) else {
        return Vec::new();
    };
    let mut blocks = Vec::new();
    walk(tree.root_node(), bytes, &mut blocks);
    blocks
}

fn walk(node: Node, bytes: &[u8], out: &mut Vec<CodeBlock>) {
    match node.kind() {
        "script_element" => {
            let mut cursor = node.walk();
            let mut is_js = true;
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "start_tag" => {
                        attributes(child, bytes, |name, value| {
                            if name == "type" {
                                is_js = is_javascript_type(&text_of(bytes, value));
                            }
                        });
                        handler_blocks(child, bytes, out);
                    }
                    "raw_text" if is_js => {
                        out.extend(CodeBlock::new(
                            child.start_byte(),
                            child.end_byte(),
                            Language::JavaScript,
                        ));
                    }
                    _ => {}
                }
            }
            return;
        }
        "start_tag" | "self_closing_tag" => {
            handler_blocks(node, bytes, out);
            return;
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, bytes, out);
    }
}

/// Event handlers and `javascript:` URLs among a tag's attributes.
fn handler_blocks(tag: Node, bytes: &[u8], out: &mut Vec<CodeBlock>) {
    attributes(tag, bytes, |name, value| {
        if is_runnable_attribute(&name, bytes, value) {
            out.extend(CodeBlock::new(
                value.start_byte(),
                value.end_byte(),
                Language::JavaScript,
            ));
        }
    });
}

fn is_runnable_attribute(name: &str, bytes: &[u8], value: Node) -> bool {
    is_event_handler(name)
        || (URL_ATTRIBUTES.contains(&name)
            && javascript_scheme_len(&decode_references(&bytes[value.byte_range()]).0).is_some())
}

/// `on` and a lowercase event name: `onclick`, `onerror`, `onpointerdown`.
fn is_event_handler(name: &str) -> bool {
    name.len() > 2 && name.starts_with("on") && name[2..].bytes().all(|b| b.is_ascii_lowercase())
}

fn is_javascript_type(t: &str) -> bool {
    matches!(
        t.trim().to_ascii_lowercase().as_str(),
        "" | "module"
            | "text/javascript"
            | "application/javascript"
            | "text/ecmascript"
            | "application/ecmascript"
            | "application/x-javascript"
    )
}

/// Calls `f(name, value)` for each attribute of a `start_tag` or
/// `self_closing_tag` that has a value. `name` is lowercased; `value` is the
/// `attribute_value` node, inside any quotes.
pub(crate) fn attributes(tag: Node, bytes: &[u8], mut f: impl FnMut(String, Node)) {
    let mut cursor = tag.walk();
    for attr in tag.children(&mut cursor) {
        if attr.kind() != "attribute" {
            continue;
        }
        let mut name = None;
        let mut value = None;
        let mut ac = attr.walk();
        for part in attr.children(&mut ac) {
            match part.kind() {
                "attribute_name" => name = Some(text_of(bytes, part).to_ascii_lowercase()),
                "attribute_value" => value = Some(part),
                "quoted_attribute_value" => {
                    let mut qc = part.walk();
                    value = part
                        .children(&mut qc)
                        .find(|n| n.kind() == "attribute_value");
                }
                _ => {}
            }
        }
        if let (Some(name), Some(value)) = (name, value) {
            f(name, value);
        }
    }
}

pub(crate) fn text_of(bytes: &[u8], node: Node) -> String {
    String::from_utf8_lossy(&bytes[node.byte_range()]).into_owned()
}

/// The length of a leading `javascript:` scheme, after the whitespace a
/// browser strips, or `None` when the value has no such scheme.
fn javascript_scheme_len(value: &[u8]) -> Option<usize> {
    const SCHEME: &[u8] = b"javascript:";
    let lead = value
        .iter()
        .take_while(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        .count();
    let rest = &value[lead..];
    (rest.len() >= SCHEME.len() && rest[..SCHEME.len()].eq_ignore_ascii_case(SCHEME))
        .then_some(lead + SCHEME.len())
}

/// Decodes character references (`&#101;`, `&#x65;`, and `amp lt gt quot apos
/// nbsp`), returning the text and how many references spelled an ASCII
/// letter or digit. A reference is never shorter than what it stands for, so
/// the result is never longer than `value`.
pub(crate) fn decode_references(value: &[u8]) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(value.len());
    let mut needless = 0;
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'&' {
            if let Some((c, len)) = reference_at(&value[i..]) {
                if c.is_ascii_alphanumeric() {
                    needless += 1;
                }
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                i += len;
                continue;
            }
        }
        out.push(value[i]);
        i += 1;
    }
    (out, needless)
}

/// The character a reference at the start of `s` stands for, and the
/// reference's length (its `;` included when present).
fn reference_at(s: &[u8]) -> Option<(char, usize)> {
    let body = &s[1..];
    let (digits, radix, skip) = match body {
        [b'#', b'x' | b'X', ..] => (&body[2..], 16, 3),
        [b'#', ..] => (&body[1..], 10, 2),
        _ => {
            const NAMED: &[(&[u8], char)] = &[
                (b"amp", '&'),
                (b"lt", '<'),
                (b"gt", '>'),
                (b"quot", '"'),
                (b"apos", '\''),
                (b"nbsp", '\u{a0}'),
            ];
            return NAMED.iter().find_map(|&(name, c)| {
                (body.len() > name.len() && body.starts_with(name) && body[name.len()] == b';')
                    .then_some((c, name.len() + 2))
            });
        }
    };
    let n = digits
        .iter()
        .take_while(|b| b.is_ascii_digit() || (radix == 16 && b.is_ascii_hexdigit()))
        .count()
        .min(8);
    if n == 0 {
        return None;
    }
    let code = u32::from_str_radix(std::str::from_utf8(&digits[..n]).ok()?, radix).ok()?;
    let c = char::from_u32(code)?;
    let semi = usize::from(digits.get(n) == Some(&b';'));
    Some((c, skip + n + semi))
}

/// What a browser runs for an attribute block (an event handler or a
/// `javascript:` URL): references decoded and the scheme blanked, padded
/// with spaces to the block's length. `None` for a `<script>` body, which a
/// browser runs as written. A script body follows its start tag's `>`; an
/// attribute value follows a quote, `=`, or nothing else.
pub fn decode_block(bytes: &[u8], block: &CodeBlock) -> Option<Vec<u8>> {
    if block.start == 0 || bytes[block.start - 1] == b'>' {
        return None;
    }
    let raw = &bytes[block.start..block.end];
    let (mut decoded, _) = decode_references(raw);
    if let Some(n) = javascript_scheme_len(&decoded) {
        decoded[..n].fill(b' ');
    }
    decoded.resize(raw.len(), b' ');
    Some(decoded)
}

/// `encoding-escape-soup` for event handlers and `javascript:` URLs that
/// spell letters or digits as character references.
pub fn reference_findings(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    for block in extract(bytes) {
        if decode_block(bytes, &block).is_none() {
            continue;
        }
        let (_, needless) = decode_references(&bytes[block.start..block.end]);
        if needless < NEEDLESS_REFERENCES_MIN {
            continue;
        }
        let (line, col) = index.locate(block.start);
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: block.start,
            line,
            col,
            pass: PassKind::Ast,
            kind: SignalKind::EncodingEscapeSoup,
            severity: Severity::Warn,
            confidence: 0.8,
            message: format!(
                "[embedded javascript] {needless} letters or digits written as HTML character references in code a browser runs"
            ),
            snippet: redact_snippet(&snippet_around(bytes, block.start, 120)),
            diff_introduced: false,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(src: &str) -> Vec<String> {
        extract(src.as_bytes())
            .iter()
            .map(|b| {
                assert_eq!(b.lang, Language::JavaScript);
                src[b.start..b.end].to_string()
            })
            .collect()
    }

    #[test]
    fn scripts_handlers_and_javascript_urls_are_extracted() {
        let src = r#"<html><head>
<script>var a = 1;</script>
<script type="module">import x from "./x.js";</script>
<script type="application/json">{"not": "code"}</script>
<script type="application/ld+json">{"@type": "Product"}</script>
</head><body onload="init()">
<a href="javascript:void(0)">x</a> <a href="/plain">y</a>
<img src=x onerror=alert(1)>
<button data-onclick="nope" onclick='go("a")'>b</button>
</body></html>"#;
        assert_eq!(
            texts(src),
            [
                "var a = 1;",
                "import x from \"./x.js\";",
                "init()",
                "javascript:void(0)",
                "alert(1)",
                "go(\"a\")",
            ]
        );
    }

    #[test]
    fn comments_are_not_code() {
        assert!(texts("<!-- <script>evil()</script> --><p>hi</p>").is_empty());
    }

    #[test]
    fn references_decode_to_what_a_browser_runs() {
        let src = r#"<a href="  JavaScr&#105;pt:&#x65;val(1)">x</a><p onclick="a&amp;&amp;b()">"#;
        let blocks = extract(src.as_bytes());
        assert_eq!(blocks.len(), 2);
        let run = |i: usize| {
            let d = decode_block(src.as_bytes(), &blocks[i]).unwrap();
            assert_eq!(d.len(), blocks[i].end - blocks[i].start);
            String::from_utf8(d).unwrap().trim().to_string()
        };
        assert_eq!(run(0), "eval(1)");
        assert_eq!(run(1), "a&&b()");
        // A script body is run as written.
        let src = "<script>a = '&#101;';</script>";
        let b = extract(src.as_bytes());
        assert!(decode_block(src.as_bytes(), &b[0]).is_none());
    }

    #[test]
    fn needless_references_are_reported() {
        let src = r#"<p onclick="&#101;&#118;&#97;l(x)">a</p><p onclick="a &amp;&amp; b()">b</p>"#;
        let f = reference_findings(
            Path::new("a.html"),
            src.as_bytes(),
            &LineIndex::new(src.as_bytes()),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, SignalKind::EncodingEscapeSoup);
    }
}
