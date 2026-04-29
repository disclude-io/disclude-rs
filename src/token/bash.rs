//! Bash tokenizer — `#`-line comments, single-quoted, double-quoted, and
//! ANSI-C-quoted (`$'...'`) string literals, heredoc bodies, and identifiers.
//!
//! This is not a full shell lexer. It recognizes what the token pass needs
//! and treats everything else as `Other`. In particular it does not:
//!   * handle arithmetic expansion `$((...))` specially
//!   * track command substitution nesting `$(...)`
//!   * recognize numeric literals as anything special
//!   * validate identifier names against POSIX rules
//!
//! Key shell-specific rules implemented here:
//!   * Single-quoted strings `'...'` are always raw — no backslash escaping.
//!   * Double-quoted strings `"..."` allow `\"` and `\\` escapes, but we
//!     treat the whole thing as one string literal for classification purposes.
//!   * `$'...'` ANSI-C quoting supports `\n`, `\xHH`, etc. and is emitted as
//!     a string literal.
//!   * Heredocs `<<WORD ... WORD` have their body treated as a string literal.
//!   * Identifiers are sequences of `[A-Za-z0-9_]` starting with `[A-Za-z_]`.
//!     The leading `$` of variable references (`$VAR`) is not included.

use super::{Token, TokenKind};

pub fn tokenize(bytes: &[u8]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let b = bytes[i];
        // Single-line comment: `#` to end of line.
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
        // ANSI-C quoted string: `$'...'` — backslash-escape sequences allowed.
        if b == b'$' && i + 1 < n && bytes[i + 1] == b'\'' {
            let start = i;
            let body_start = i + 2;
            i += 2; // skip `$'`
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n {
                    i += 2; // skip escape pair
                } else if bytes[i] == b'\'' {
                    i += 1; // skip closing quote
                    break;
                } else {
                    i += 1;
                }
            }
            out.push(Token {
                kind: TokenKind::StringLiteral,
                start,
                end: i,
                content_start: body_start,
                content_end: i.saturating_sub(1), // exclude closing `'`
            });
            continue;
        }
        // Single-quoted string `'...'` — truly raw; no escapes whatsoever.
        if b == b'\'' {
            let start = i;
            let body_start = i + 1;
            i += 1; // skip opening `'`
            while i < n && bytes[i] != b'\'' {
                i += 1;
            }
            let body_end = i;
            if i < n {
                i += 1; // skip closing `'`
            }
            out.push(Token {
                kind: TokenKind::StringLiteral,
                start,
                end: i,
                content_start: body_start,
                content_end: body_end,
            });
            continue;
        }
        // Double-quoted string `"..."` — allows `\"`, `\\`, `\$`, etc.
        if b == b'"' {
            let start = i;
            let body_start = i + 1;
            i += 1; // skip opening `"`
            while i < n {
                if bytes[i] == b'\\' && i + 1 < n {
                    i += 2; // skip escape pair
                } else if bytes[i] == b'"' {
                    i += 1; // skip closing `"`
                    break;
                } else {
                    i += 1;
                }
            }
            out.push(Token {
                kind: TokenKind::StringLiteral,
                start,
                end: i,
                content_start: body_start,
                content_end: i.saturating_sub(1), // exclude closing `"`
            });
            continue;
        }
        // Heredoc: `<<[-]WORD` optionally followed by spaces, then a newline.
        // The body runs until a line that is exactly `WORD` (with optional
        // leading tabs for `<<-`).
        if b == b'<' && i + 1 < n && bytes[i + 1] == b'<' {
            let heredoc_start = i;
            i += 2; // skip `<<`
            let strip_tabs = i < n && bytes[i] == b'-';
            if strip_tabs {
                i += 1;
            }
            // Skip optional spaces before the delimiter word.
            while i < n && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
            // The delimiter may be quoted (`<<"EOF"`, `<<'EOF'`, `<<\EOF`).
            // We strip quotes/backslash and record the raw delimiter.
            let delim_quoted = i < n && matches!(bytes[i], b'\'' | b'"');
            let delim_quote_char = if delim_quoted { bytes[i] } else { 0 };
            if delim_quoted {
                i += 1; // skip opening quote
            }
            let delim_start = i;
            while i < n && bytes[i] != b'\n' {
                if delim_quoted && bytes[i] == delim_quote_char {
                    break;
                }
                if !delim_quoted && (bytes[i] == b' ' || bytes[i] == b'\t') {
                    break;
                }
                i += 1;
            }
            let delim = bytes[delim_start..i].to_vec();
            if delim_quoted && i < n && bytes[i] == delim_quote_char {
                i += 1; // skip closing quote
            }
            // Skip to end of the heredoc-start line.
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            if i < n {
                i += 1; // skip the newline
            }
            // Scan for the terminating line.
            let body_start = i;
            loop {
                if i >= n {
                    break;
                }
                let line_start = i;
                // Optionally strip leading tabs (for `<<-`).
                if strip_tabs {
                    while i < n && bytes[i] == b'\t' {
                        i += 1;
                    }
                }
                // Check if this line equals the delimiter.
                let remaining = &bytes[i..];
                if remaining.starts_with(&delim) {
                    let after = i + delim.len();
                    if after >= n || bytes[after] == b'\n' || bytes[after] == b'\r' {
                        // Found the terminator line; body ends at line_start.
                        let body_end = line_start;
                        // Advance past the terminator line.
                        i = after;
                        while i < n && bytes[i] != b'\n' {
                            i += 1;
                        }
                        if i < n {
                            i += 1;
                        }
                        out.push(Token {
                            kind: TokenKind::StringLiteral,
                            start: heredoc_start,
                            end: i,
                            content_start: body_start,
                            content_end: body_end,
                        });
                        break;
                    }
                }
                // Advance to end of current line.
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
                if i < n {
                    i += 1;
                }
            }
            continue;
        }
        // Identifier: `[A-Za-z_][A-Za-z0-9_]*`
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            i += 1;
            while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
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
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_comment() {
        let toks = tokenize(b"# this is a comment\necho hi\n");
        assert!(toks.iter().any(|t| t.kind == TokenKind::Comment));
        let c = toks.iter().find(|t| t.kind == TokenKind::Comment).unwrap();
        assert_eq!(
            &b"# this is a comment\necho hi\n"[c.start..c.end],
            b"# this is a comment"
        );
    }

    #[test]
    fn tokenizes_double_quoted_string() {
        let toks = tokenize(b"echo \"hello world\"\n");
        let s = toks
            .iter()
            .find(|t| t.kind == TokenKind::StringLiteral)
            .unwrap();
        let src = b"echo \"hello world\"\n";
        assert_eq!(&src[s.content_start..s.content_end], b"hello world");
    }

    #[test]
    fn tokenizes_single_quoted_string_raw() {
        // Single-quoted: backslash is NOT an escape — `\n` is literal backslash + n.
        let src = b"echo 'hello\\nworld'\n";
        let toks = tokenize(src);
        let s = toks
            .iter()
            .find(|t| t.kind == TokenKind::StringLiteral)
            .unwrap();
        assert_eq!(&src[s.content_start..s.content_end], b"hello\\nworld");
    }

    #[test]
    fn tokenizes_ansi_c_quoted_string() {
        let src = b"echo $'hello\\n'\n";
        let toks = tokenize(src);
        assert!(toks.iter().any(|t| t.kind == TokenKind::StringLiteral));
    }

    #[test]
    fn tokenizes_heredoc() {
        let src = b"cat <<EOF\nhello world\nEOF\n";
        let toks = tokenize(src);
        let s = toks
            .iter()
            .find(|t| t.kind == TokenKind::StringLiteral)
            .unwrap();
        assert_eq!(&src[s.content_start..s.content_end], b"hello world\n");
    }

    #[test]
    fn tokenizes_heredoc_quoted_delimiter() {
        // Quoted delimiter means no variable expansion in body — doesn't affect
        // tokenization result but we should handle the syntax without panicking.
        let src = b"cat <<'EOF'\nhello $WORLD\nEOF\n";
        let toks = tokenize(src);
        assert!(toks.iter().any(|t| t.kind == TokenKind::StringLiteral));
    }

    #[test]
    fn tokenizes_identifier() {
        let toks = tokenize(b"my_var=1\n");
        let id = toks
            .iter()
            .find(|t| t.kind == TokenKind::Identifier)
            .unwrap();
        assert_eq!(&b"my_var=1\n"[id.start..id.end], b"my_var");
    }

    #[test]
    fn dollar_sign_does_not_start_identifier() {
        // `$VAR` — the `$` is skipped, `VAR` is the identifier.
        let toks = tokenize(b"echo $VAR\n");
        let ids: Vec<_> = toks
            .iter()
            .filter(|t| t.kind == TokenKind::Identifier)
            .collect();
        let src = b"echo $VAR\n";
        let names: Vec<_> = ids.iter().map(|t| &src[t.start..t.end]).collect();
        assert!(names.contains(&b"echo".as_slice()));
        assert!(names.contains(&b"VAR".as_slice()));
    }

    #[test]
    fn double_quoted_with_backslash_escape() {
        // `\"` inside a double-quoted string should not end the string.
        let src = b"echo \"say \\\"hi\\\"\"\n";
        let toks = tokenize(src);
        assert!(toks.iter().any(|t| t.kind == TokenKind::StringLiteral));
    }
}
