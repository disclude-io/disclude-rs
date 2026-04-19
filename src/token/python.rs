//! Python tokenizer — comments, strings (with b/r/f/u prefix combos and
//! triple-quoted forms), identifiers, and the `+` operator needed for
//! concatenation detection.
//!
//! This is not a full Python lexer. It recognizes what the token pass needs
//! and treats everything else as `Other`. In particular it does not:
//!   * expand f-string `{expr}` placeholders into sub-tokens
//!   * handle `\` line continuation
//!   * recognize numeric literals as anything special
//!   * reject lexically-invalid identifier characters
//!
//! These omissions are acceptable because the downstream checks only care
//! about where comments, strings, and identifier spans are.

use super::{Token, TokenKind};
use crate::util::utf8_len;

pub fn tokenize(bytes: &[u8]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let b = bytes[i];
        if b == b'#' {
            let start = i;
            let content_start = i + 1;
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
        // String prefix + quote. Accept any ordering of b/B/r/R/f/F/u/U up
        // to 2 prefix bytes followed by a quote.
        if let Some((prefix_len, raw)) = python_string_prefix(bytes, i) {
            if let Some(tok) = lex_string(bytes, i, prefix_len, raw) {
                i = tok.end;
                out.push(tok);
                continue;
            }
        }
        // Bare quote — no prefix — is still a string.
        if (b == b'"' || b == b'\'') && python_string_prefix(bytes, i).is_none() {
            if let Some(tok) = lex_string(bytes, i, 0, false) {
                i = tok.end;
                out.push(tok);
                continue;
            }
        }
        // Identifier
        if is_py_ident_start(bytes, i) {
            let start = i;
            i += utf8_len(bytes[i]);
            while i < n && is_py_ident_cont(bytes, i) {
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
        // `+` is the only operator we care about (for concat detection).
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

/// Returns (prefix_len, is_raw) if the bytes at `pos` are a Python string
/// prefix followed by a quote. Accepts 1-2 byte prefixes from {b,B,r,R,f,F,u,U}.
fn python_string_prefix(bytes: &[u8], pos: usize) -> Option<(usize, bool)> {
    const PREFIX: &[u8] = b"bBrRfFuU";
    let mut n = 0;
    let mut raw = false;
    while n < 2 && pos + n < bytes.len() && PREFIX.contains(&bytes[pos + n]) {
        if bytes[pos + n] == b'r' || bytes[pos + n] == b'R' {
            raw = true;
        }
        n += 1;
    }
    if n == 0 {
        return None;
    }
    if pos + n >= bytes.len() {
        return None;
    }
    let q = bytes[pos + n];
    if q != b'"' && q != b'\'' {
        return None;
    }
    Some((n, raw))
}

fn lex_string(bytes: &[u8], start: usize, prefix_len: usize, raw: bool) -> Option<Token> {
    let q = bytes[start + prefix_len];
    let triple = start + prefix_len + 2 < bytes.len()
        && bytes[start + prefix_len + 1] == q
        && bytes[start + prefix_len + 2] == q;
    let (body_start, end) = if triple {
        let body = start + prefix_len + 3;
        let mut i = body;
        while i + 2 < bytes.len() {
            if !raw && bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == q && bytes[i + 1] == q && bytes[i + 2] == q {
                return Some(Token {
                    kind: TokenKind::StringLiteral,
                    start,
                    end: i + 3,
                    content_start: body,
                    content_end: i,
                });
            }
            i += 1;
        }
        // Unterminated triple-quoted string — treat as running to EOF.
        (body, bytes.len())
    } else {
        let body = start + prefix_len + 1;
        let mut i = body;
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'\n' {
                return None; // unterminated single-line string
            }
            if !raw && c == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == q {
                return Some(Token {
                    kind: TokenKind::StringLiteral,
                    start,
                    end: i + 1,
                    content_start: body,
                    content_end: i,
                });
            }
            i += 1;
        }
        return None;
    };
    Some(Token {
        kind: TokenKind::StringLiteral,
        start,
        end,
        content_start: body_start,
        content_end: end,
    })
}

fn is_py_ident_start(bytes: &[u8], pos: usize) -> bool {
    let b = bytes[pos];
    if b == b'_' || b.is_ascii_alphabetic() {
        return true;
    }
    if b < 0x80 {
        return false;
    }
    // Non-ASCII — decode one codepoint and ask.
    let end = (pos + utf8_len(b)).min(bytes.len());
    std::str::from_utf8(&bytes[pos..end])
        .ok()
        .and_then(|s| s.chars().next())
        .map(|c| c.is_alphabetic() || c == '_')
        .unwrap_or(false)
}

fn is_py_ident_cont(bytes: &[u8], pos: usize) -> bool {
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
    fn tokenizes_comment() {
        let toks = tokenize(b"x = 1  # hello\n");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Comment));
    }

    #[test]
    fn tokenizes_single_quoted_string() {
        let toks = tokenize(b"s = \"hello\"\n");
        let s = toks
            .iter()
            .find(|t| t.kind == TokenKind::StringLiteral)
            .unwrap();
        assert_eq!(s.content_end - s.content_start, 5);
    }

    #[test]
    fn tokenizes_triple_quoted_string() {
        let toks = tokenize(b"s = \"\"\"multi\nline\"\"\"\n");
        let s = toks
            .iter()
            .find(|t| t.kind == TokenKind::StringLiteral)
            .unwrap();
        assert_eq!(
            &b"s = \"\"\"multi\nline\"\"\"\n"[s.content_start..s.content_end],
            b"multi\nline"
        );
    }

    #[test]
    fn tokenizes_b_prefixed_string() {
        let toks = tokenize(b"p = b\"\\xde\\xad\"\n");
        assert!(toks.iter().any(|t| t.kind == TokenKind::StringLiteral));
    }

    #[test]
    fn tokenizes_raw_string_keeps_backslash_literal() {
        // In a raw string the `\"` should not close the string early.
        let toks = tokenize(b"p = r\"a\\nb\"\n");
        let s = toks
            .iter()
            .find(|t| t.kind == TokenKind::StringLiteral)
            .unwrap();
        // Raw strings: `r"a\nb"` — body is `a\nb` (4 bytes).
        assert_eq!(s.content_end - s.content_start, 4);
    }

    #[test]
    fn identifier_with_unicode() {
        let src = "café = 1\n".as_bytes();
        let toks = tokenize(src);
        let id = toks
            .iter()
            .find(|t| t.kind == TokenKind::Identifier)
            .unwrap();
        assert_eq!(&src[id.start..id.end], "café".as_bytes());
    }

    #[test]
    fn unterminated_single_line_string_is_not_emitted() {
        let toks = tokenize(b"s = \"oops\n");
        assert!(toks.iter().all(|t| t.kind != TokenKind::StringLiteral));
    }

    #[test]
    fn plus_operator_is_tokenized() {
        let toks = tokenize(b"s = \"a\" + \"b\"\n");
        assert_eq!(
            toks.iter()
                .filter(|t| t.kind == TokenKind::Operator)
                .count(),
            1
        );
    }
}
