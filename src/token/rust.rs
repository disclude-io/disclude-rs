//! Rust tokenizer — line/block (nestable) comments, strings (with `b`, `r`,
//! `br` prefixes and `#`-delimited raw forms), identifiers, and the `+`
//! operator. Char literals are recognized so we don't confuse them with
//! lifetimes, but we emit them as `Other` because their one-or-two byte
//! content is never interesting to downstream checks.

use super::{Token, TokenKind};
use crate::util::utf8_len;

pub fn tokenize(bytes: &[u8]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let b = bytes[i];
        // Line comment
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            let start = i;
            let content_start = i + 2;
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            out.push(Token {
                kind: TokenKind::Comment,
                start,
                end: i,
                content_start,
                content_end: i,
            });
            continue;
        }
        // Block comment (nestable)
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            let start = i;
            let content_start = i + 2;
            let mut depth = 1usize;
            i += 2;
            while i + 1 < n && depth > 0 {
                if bytes[i] == b'/' && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if depth != 0 {
                // Unterminated — swallow to EOF.
                i = n;
            }
            out.push(Token {
                kind: TokenKind::Comment,
                start,
                end: i,
                content_start,
                content_end: i.saturating_sub(2).max(content_start),
            });
            continue;
        }
        // String / byte string / raw string
        if let Some((prefix_len, raw, hashes)) = rust_string_prefix(bytes, i) {
            if let Some(tok) = lex_string(bytes, i, prefix_len, raw, hashes) {
                i = tok.end;
                out.push(tok);
                continue;
            }
        }
        if b == b'"' {
            if let Some(tok) = lex_string(bytes, i, 0, false, 0) {
                i = tok.end;
                out.push(tok);
                continue;
            }
        }
        // Char literal vs lifetime — both start with `'`. Disambiguate by
        // looking past the apostrophe. `'\...'` is always a char; `'x'` with
        // closing quote within 1-4 bytes is a char; otherwise it's a lifetime
        // label and we fall through to identifier lexing.
        if b == b'\'' {
            if let Some(end) = try_lex_char(bytes, i) {
                out.push(Token {
                    kind: TokenKind::Other,
                    start: i,
                    end,
                    content_start: i + 1,
                    content_end: end.saturating_sub(1),
                });
                i = end;
                continue;
            }
            // Not a char literal — skip the apostrophe and let the next
            // iteration pick up the lifetime identifier.
            i += 1;
            continue;
        }
        // Identifier
        if is_rust_ident_start(bytes, i) {
            let start = i;
            i += utf8_len(bytes[i]);
            while i < n && is_rust_ident_cont(bytes, i) {
                i += utf8_len(bytes[i]);
            }
            out.push(Token {
                kind: TokenKind::Identifier,
                start,
                end: i,
                content_start: start,
                content_end: i,
            });
            continue;
        }
        if b == b'+' {
            out.push(Token {
                kind: TokenKind::Operator,
                start: i,
                end: i + 1,
                content_start: i,
                content_end: i + 1,
            });
            i += 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Detect a Rust string prefix at `pos`. Returns (prefix_len, is_raw, hashes)
/// where `hashes` is the number of `#` between the `r` and the opening quote
/// of a raw string. Supported: `"`, `b"`, `r"`, `r#"`, `r##"`..., `br"`,
/// `br#"`, etc.
fn rust_string_prefix(bytes: &[u8], pos: usize) -> Option<(usize, bool, usize)> {
    let n = bytes.len();
    let mut i = pos;
    let mut has_b = false;
    let mut has_r = false;
    if i < n && bytes[i] == b'b' {
        has_b = true;
        i += 1;
    }
    if i < n && bytes[i] == b'r' {
        has_r = true;
        i += 1;
    }
    let mut hashes = 0;
    if has_r {
        while i < n && bytes[i] == b'#' {
            hashes += 1;
            i += 1;
        }
    }
    if i >= n || bytes[i] != b'"' {
        return None;
    }
    if !has_b && !has_r {
        return None;
    }
    // Prefix must be followed by the quote — ensure the prefix chars form a
    // recognizable token boundary (i.e. the char before `pos` is not
    // identifier-continuing). This prevents `fooBr"..."` from being misread.
    if pos > 0 && is_rust_ident_cont(bytes, pos - 1) {
        return None;
    }
    Some((i - pos, has_r, hashes))
}

fn lex_string(
    bytes: &[u8],
    start: usize,
    prefix_len: usize,
    raw: bool,
    hashes: usize,
) -> Option<Token> {
    let body_start = start + prefix_len + 1;
    let n = bytes.len();
    let mut i = body_start;
    if raw {
        while i < n {
            if bytes[i] == b'"' {
                let mut k = 0;
                while k < hashes && i + 1 + k < n && bytes[i + 1 + k] == b'#' {
                    k += 1;
                }
                if k == hashes {
                    return Some(Token {
                        kind: TokenKind::StringLiteral,
                        start,
                        end: i + 1 + hashes,
                        content_start: body_start,
                        content_end: i,
                    });
                }
            }
            i += 1;
        }
        // Unterminated — end at EOF.
        return Some(Token {
            kind: TokenKind::StringLiteral,
            start,
            end: n,
            content_start: body_start,
            content_end: n,
        });
    }
    while i < n {
        let c = bytes[i];
        if c == b'\\' && i + 1 < n {
            i += 2;
            continue;
        }
        if c == b'"' {
            return Some(Token {
                kind: TokenKind::StringLiteral,
                start,
                end: i + 1,
                content_start: body_start,
                content_end: i,
            });
        }
        i += 1;
    }
    None
}

/// Try to lex a Rust char literal starting at `pos`. Returns the end offset
/// (exclusive) on success, or None if it looks like a lifetime.
fn try_lex_char(bytes: &[u8], pos: usize) -> Option<usize> {
    let n = bytes.len();
    if pos + 1 >= n {
        return None;
    }
    let after = bytes[pos + 1];
    if after == b'\\' {
        // Escape — scan until closing quote, max 10 bytes for `\u{XXXXXX}`.
        let mut i = pos + 2;
        while i < n && i < pos + 12 {
            if bytes[i] == b'\'' {
                return Some(i + 1);
            }
            i += 1;
        }
        return None;
    }
    // Single-byte ASCII char: `'x'`
    if pos + 2 < n && bytes[pos + 2] == b'\'' {
        return Some(pos + 3);
    }
    // UTF-8 multi-byte char: `'é'`
    if after >= 0x80 {
        let len = utf8_len(after);
        if pos + 1 + len < n && bytes[pos + 1 + len] == b'\'' {
            return Some(pos + 2 + len);
        }
    }
    None
}

fn is_rust_ident_start(bytes: &[u8], pos: usize) -> bool {
    let b = bytes[pos];
    if b == b'_' || b.is_ascii_alphabetic() {
        return true;
    }
    if b < 0x80 {
        return false;
    }
    let end = (pos + utf8_len(b)).min(bytes.len());
    std::str::from_utf8(&bytes[pos..end])
        .ok()
        .and_then(|s| s.chars().next())
        .map(|c| c.is_alphabetic() || c == '_')
        .unwrap_or(false)
}

fn is_rust_ident_cont(bytes: &[u8], pos: usize) -> bool {
    let b = bytes[pos];
    if b == b'_' || b.is_ascii_alphanumeric() {
        return true;
    }
    if b < 0x80 {
        return false;
    }
    let end = (pos + utf8_len(b)).min(bytes.len());
    std::str::from_utf8(&bytes[pos..end])
        .ok()
        .and_then(|s| s.chars().next())
        .map(|c| c.is_alphanumeric() || c == '_')
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_comment() {
        let toks = tokenize(b"let x = 1; // hello\n");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Comment));
    }

    #[test]
    fn block_comment_nestable() {
        let src = b"/* outer /* inner */ still outer */ x\n";
        let toks = tokenize(src);
        let c = toks.iter().find(|t| t.kind == TokenKind::Comment).unwrap();
        // Comment span covers both `*/` closers of the nested pair.
        assert_eq!(&src[c.start..c.end], b"/* outer /* inner */ still outer */");
    }

    #[test]
    fn string_literal_regular() {
        let toks = tokenize(br#"let s = "hello";"#);
        let s = toks
            .iter()
            .find(|t| t.kind == TokenKind::StringLiteral)
            .unwrap();
        assert_eq!(s.content_end - s.content_start, 5);
    }

    #[test]
    fn raw_string_with_hashes() {
        let src = br####"let s = r##"a"#b"##;"####;
        let toks = tokenize(src);
        let s = toks
            .iter()
            .find(|t| t.kind == TokenKind::StringLiteral)
            .unwrap();
        assert_eq!(&src[s.content_start..s.content_end], br##"a"#b"##);
    }

    #[test]
    fn byte_string() {
        let toks = tokenize(br#"let s = b"\xde\xad";"#);
        assert!(toks.iter().any(|t| t.kind == TokenKind::StringLiteral));
    }

    #[test]
    fn lifetime_is_not_a_char_literal() {
        let toks = tokenize(b"fn f<'a>(x: &'a str) -> &'static str { x }\n");
        // No Other tokens should appear for the apostrophes — they're all
        // lifetime labels, not chars.
        assert!(toks.iter().all(|t| t.kind != TokenKind::Other));
        // `a`, `static`, `x`, `str`, `f`, `x` — identifiers present.
        assert!(toks.iter().any(|t| t.kind == TokenKind::Identifier
            && b"a" == &b"fn f<'a>(x: &'a str) -> &'static str { x }\n"[t.start..t.end]));
    }

    #[test]
    fn char_literal_is_not_a_lifetime() {
        let toks = tokenize(b"let c = 'x';\n");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Other));
    }

    #[test]
    fn escaped_char_literal() {
        let toks = tokenize(b"let c = '\\n';\n");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Other));
    }
}
