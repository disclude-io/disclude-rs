//! C tokenizer — line/block comments, string and character literals,
//! identifiers, and the `+` operator.
//!
//! C string literals may carry optional prefixes (`L`, `u8`, `u`, `U`).
//! Character literals (`'x'`, `'\n'`, `'\xNN'`) are emitted as `Other`
//! because their short content is never interesting for downstream checks.
//! Adjacent string literals ("a" "b") are separate tokens here; the concat
//! finder in the token pass joins them when both are StringLiteral.

use super::{Token, TokenKind};
use crate::util::utf8_len;

pub fn tokenize(bytes: &[u8]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let b = bytes[i];
        // Whitespace
        if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
            i += 1;
            continue;
        }
        // Preprocessor directives — treat as a comment for token purposes.
        if b == b'#' {
            let start = i;
            let content_start = i + 1;
            // Read to end of logical line (handle line continuations).
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n && bytes[i + 1] == b'\n' {
                    i += 2;
                } else if bytes[i] == b'\n' {
                    break;
                } else {
                    i += 1;
                }
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
        // Block comment (not nestable in C)
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            let start = i;
            let content_start = i + 2;
            i += 2;
            while i + 1 < n {
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            if i + 1 >= n && !(i > 0 && bytes[i - 1] == b'/' && i >= 2 && bytes[i - 2] == b'*') {
                i = n; // unterminated
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
        // String literals — optional prefix (L, u8, u, U) then `"`.
        // Wide / Unicode prefixes: skip the prefix bytes before the quote.
        let str_prefix_len = string_prefix_len(bytes, i);
        if str_prefix_len > 0
            || (b == b'"')
        {
            if b == b'"' || (str_prefix_len > 0 && bytes.get(i + str_prefix_len) == Some(&b'"')) {
                let start = i;
                let quote_pos = i + str_prefix_len;
                let content_start = quote_pos + 1;
                i = content_start;
                while i < n && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1; // skip escaped char
                    }
                    i += 1;
                }
                let content_end = i;
                if i < n {
                    i += 1; // closing "
                }
                out.push(Token {
                    kind: TokenKind::StringLiteral,
                    start,
                    end: i,
                    content_start,
                    content_end,
                });
                continue;
            }
        }
        // Character literals — emit as Other.
        if b == b'\'' {
            let start = i;
            i += 1;
            while i < n && bytes[i] != b'\'' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i < n {
                i += 1;
            }
            out.push(Token {
                kind: TokenKind::Other,
                start,
                end: i,
                content_start: start,
                content_end: i,
            });
            continue;
        }
        // + operator (for string concat detection)
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
        // Identifiers
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
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
        // Anything else
        i += utf8_len(b);
    }
    out
}

/// Returns the length (in bytes) of a C string literal prefix (`L`, `u8`,
/// `u`, `U`) if one precedes a `"` at `bytes[i..]`, otherwise 0.
fn string_prefix_len(bytes: &[u8], i: usize) -> usize {
    let n = bytes.len();
    match bytes.get(i) {
        Some(&b'L') | Some(&b'u') | Some(&b'U') => {
            if bytes.get(i + 1) == Some(&b'"') {
                1
            } else if bytes.get(i) == Some(&b'u')
                && bytes.get(i + 1) == Some(&b'8')
                && i + 2 < n
                && bytes[i + 2] == b'"'
            {
                2
            } else {
                0
            }
        }
        _ => 0,
    }
}
