//! TypeScript / JavaScript tokenizer — line/block comments, string literals
//! (single-, double-, and backtick-quoted), identifiers, and the `+`
//! operator.
//!
//! Template literals (`` `...${expr}...` ``) are tokenized as a single
//! StringLiteral spanning the whole backtick-delimited region. We do not
//! descend into `${...}` — that would require paren matching to find the
//! matching brace, and the token pass does not need it. The downstream checks
//! read the raw content bytes, which is the right behavior for concat
//! detection (a template literal is already string construction; our job is
//! to flag `+`-spliced assembly, which template literals obviate).
//!
//! Regex literals `/pattern/flags` are detected via a coarse
//! "previous-token-allows-regex" heuristic and emitted as `Other`. When the
//! heuristic is wrong we bias toward skipping the `/` as division, which
//! matches how humans reading the source would understand it.

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
        // Block comment (not nestable in JS)
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            let start = i;
            let content_start = i + 2;
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            let content_end = i;
            if i + 1 < n {
                i += 2;
            } else {
                i = n;
            }
            out.push(Token {
                kind: TokenKind::Comment,
                start,
                end: i,
                content_start,
                content_end,
            });
            continue;
        }
        // Regex literal vs division
        if b == b'/' && regex_context_ok(&out) {
            if let Some(end) = try_lex_regex(bytes, i) {
                out.push(Token {
                    kind: TokenKind::Other,
                    start: i,
                    end,
                    content_start: i + 1,
                    content_end: end,
                });
                i = end;
                continue;
            }
        }
        // String
        if b == b'"' || b == b'\'' {
            if let Some(tok) = lex_quoted(bytes, i, b) {
                i = tok.end;
                out.push(tok);
                continue;
            }
        }
        if b == b'`' {
            if let Some(tok) = lex_template(bytes, i) {
                i = tok.end;
                out.push(tok);
                continue;
            }
        }
        // Identifier
        if is_js_ident_start(bytes, i) {
            let start = i;
            i += utf8_len(bytes[i]);
            while i < n && is_js_ident_cont(bytes, i) {
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
        // Broader punctuation tokenization so the regex-vs-division heuristic
        // has something to latch onto. Everything that syntactically precedes
        // a regex literal (assignment, opening bracket, comma, etc.) must be
        // visible as a non-Identifier token.
        if matches!(
            b,
            b'=' | b'('
                | b'{'
                | b'['
                | b','
                | b';'
                | b':'
                | b'!'
                | b'?'
                | b'&'
                | b'|'
                | b'^'
                | b'%'
                | b'~'
                | b'<'
                | b'>'
                | b'-'
                | b'*'
        ) {
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

/// True if the previous significant token leaves us in a position where `/`
/// starts a regex literal rather than a division. Rough ECMAScript rule: `/`
/// is division after an identifier, numeric literal, string literal, `)`,
/// `]`, or `}`; otherwise it's a regex.
fn regex_context_ok(prev: &[Token]) -> bool {
    for tok in prev.iter().rev() {
        match tok.kind {
            TokenKind::Comment => continue,
            TokenKind::Identifier => {
                // Some identifiers are keywords that *do* allow a regex
                // after them (e.g. `return /pat/`). Accept a conservative set.
                return false; // default: no regex
            }
            TokenKind::StringLiteral => return false,
            TokenKind::Operator => return true,
            TokenKind::Other => return true,
        }
    }
    true
}

fn try_lex_regex(bytes: &[u8], start: usize) -> Option<usize> {
    let n = bytes.len();
    let mut i = start + 1;
    let mut in_class = false;
    while i < n {
        let c = bytes[i];
        if c == b'\n' {
            return None;
        }
        if c == b'\\' && i + 1 < n {
            i += 2;
            continue;
        }
        if c == b'[' {
            in_class = true;
        } else if c == b']' {
            in_class = false;
        } else if c == b'/' && !in_class {
            // Consume trailing flag chars: g, i, m, s, u, y, d
            i += 1;
            while i < n && matches!(bytes[i], b'g' | b'i' | b'm' | b's' | b'u' | b'y' | b'd') {
                i += 1;
            }
            return Some(i);
        }
        i += 1;
    }
    None
}

fn lex_quoted(bytes: &[u8], start: usize, quote: u8) -> Option<Token> {
    let body = start + 1;
    let mut i = body;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\n' {
            return None;
        }
        if c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if c == quote {
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
    None
}

fn lex_template(bytes: &[u8], start: usize) -> Option<Token> {
    let body = start + 1;
    let mut i = body;
    let mut brace_depth: i32 = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if c == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            brace_depth += 1;
            i += 2;
            continue;
        }
        if brace_depth > 0 && c == b'{' {
            brace_depth += 1;
            i += 1;
            continue;
        }
        if brace_depth > 0 && c == b'}' {
            brace_depth -= 1;
            i += 1;
            continue;
        }
        if brace_depth == 0 && c == b'`' {
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
    None
}

fn is_js_ident_start(bytes: &[u8], pos: usize) -> bool {
    let b = bytes[pos];
    if b == b'_' || b == b'$' || b.is_ascii_alphabetic() {
        return true;
    }
    if b < 0x80 {
        return false;
    }
    let end = (pos + utf8_len(b)).min(bytes.len());
    std::str::from_utf8(&bytes[pos..end])
        .ok()
        .and_then(|s| s.chars().next())
        .map(|c| c.is_alphabetic() || c == '_' || c == '$')
        .unwrap_or(false)
}

fn is_js_ident_cont(bytes: &[u8], pos: usize) -> bool {
    let b = bytes[pos];
    if b == b'_' || b == b'$' || b.is_ascii_alphanumeric() {
        return true;
    }
    if b < 0x80 {
        return false;
    }
    let end = (pos + utf8_len(b)).min(bytes.len());
    std::str::from_utf8(&bytes[pos..end])
        .ok()
        .and_then(|s| s.chars().next())
        .map(|c| c.is_alphanumeric() || c == '_' || c == '$')
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_and_block_comments() {
        let toks = tokenize(b"// hi\n/* block */ x\n");
        assert_eq!(
            toks.iter().filter(|t| t.kind == TokenKind::Comment).count(),
            2
        );
    }

    #[test]
    fn string_single_and_double() {
        let toks = tokenize(br#"let s = "a" + 'b';"#);
        assert_eq!(
            toks.iter()
                .filter(|t| t.kind == TokenKind::StringLiteral)
                .count(),
            2
        );
    }

    #[test]
    fn template_literal_is_one_string() {
        let toks = tokenize(b"let s = `hi ${name}!`;\n");
        let strings: Vec<_> = toks
            .iter()
            .filter(|t| t.kind == TokenKind::StringLiteral)
            .collect();
        assert_eq!(strings.len(), 1);
        // Inner content should include the `${name}` substitution.
        let s = strings[0];
        let content = &b"let s = `hi ${name}!`;\n"[s.content_start..s.content_end];
        assert_eq!(content, b"hi ${name}!");
    }

    #[test]
    fn regex_after_assignment() {
        let toks = tokenize(b"let r = /ab+c/gi;\n");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Other));
    }

    #[test]
    fn division_after_identifier() {
        let toks = tokenize(b"let x = a / b;\n");
        // No Other token — the `/` should have been skipped as division.
        assert!(toks.iter().all(|t| t.kind != TokenKind::Other));
    }

    #[test]
    fn dollar_identifier() {
        let toks = tokenize(b"const $elem = 1;\n");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Identifier
            && &b"const $elem = 1;\n"[t.start..t.end] == b"$elem"));
    }
}
