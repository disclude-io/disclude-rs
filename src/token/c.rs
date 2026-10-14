//! C and C++ tokenizer — line/block comments, string and character
//! literals, identifiers, and the `+` operator.
//!
//! C++ adds raw string literals (`R"d(...)d"`, optionally prefixed `L`,
//! `u8`, `u` or `U`), whose content runs to `)d"` with no escapes. Number
//! literals are skipped whole in both, so a digit separator (`1'000'000`,
//! C++14 and C23) is not read as the start of a character literal.
//!
//! C string literals may carry optional prefixes (`L`, `u8`, `u`, `U`).
//! Character literals (`'x'`, `'\n'`, `'\xNN'`) are emitted as `Other`
//! because their short content is never interesting for downstream checks.
//! Adjacent string literals ("a" "b") are separate tokens here; the concat
//! finder in the token pass joins them when both are StringLiteral.

use super::{Token, TokenKind};
use crate::util::utf8_len;

pub fn tokenize(bytes: &[u8]) -> Vec<Token> {
    tokenize_with(bytes, false)
}

/// Tokenizes C++: C plus raw string literals.
pub fn tokenize_cpp(bytes: &[u8]) -> Vec<Token> {
    tokenize_with(bytes, true)
}

/// True when the code (outside comments, strings and preprocessor lines)
/// has a construct C lacks: `template <`, `namespace x {` or `namespace {`,
/// `class X {` or `class X :`, or a scope operator `a::b`. Used to tell C++
/// `.h` headers from C ones.
pub fn looks_like_cpp(bytes: &[u8]) -> bool {
    let next = |mut i: usize| {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    let tokens = tokenize(bytes);
    tokens.iter().enumerate().any(|(k, t)| {
        if t.kind != TokenKind::Identifier {
            return false;
        }
        let word = &bytes[t.start..t.end];
        let after = next(t.end);
        match word {
            b"template" => bytes.get(after) == Some(&b'<'),
            b"namespace" => {
                bytes.get(after) == Some(&b'{')
                    || tokens.get(k + 1).is_some_and(|n| {
                        n.kind == TokenKind::Identifier
                            && n.start == after
                            && bytes.get(next(n.end)) == Some(&b'{')
                    })
            }
            b"class" => tokens.get(k + 1).is_some_and(|n| {
                let after_name = next(n.end);
                n.kind == TokenKind::Identifier
                    && n.start == after
                    && (bytes.get(after_name) == Some(&b'{')
                        || (bytes.get(after_name) == Some(&b':')
                            && bytes.get(after_name + 1) != Some(&b':')))
            }),
            _ => {
                bytes[t.end..].starts_with(b"::")
                    && tokens
                        .get(k + 1)
                        .is_some_and(|n| n.kind == TokenKind::Identifier && n.start == t.end + 2)
            }
        }
    })
}

fn tokenize_with(bytes: &[u8], cpp: bool) -> Vec<Token> {
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
            let mut closed = false;
            while i + 1 < n {
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    i += 2;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                i = n; // unterminated — swallow to EOF
            }
            out.push(Token {
                kind: TokenKind::Comment,
                start,
                end: i,
                content_start,
                content_end: if closed { i - 2 } else { i },
            });
            continue;
        }
        // C++ raw string literals: `R"delim(` … `)delim"`, no escapes.
        if cpp {
            if let Some(tok) = raw_string(bytes, i) {
                i = tok.end;
                out.push(tok);
                continue;
            }
        }
        // Number literals, digit separators included: `0x1F`, `1'000`, `1e-3`.
        if b.is_ascii_digit() || (b == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            i = number_end(bytes, i);
            continue;
        }
        // String literals — optional prefix (L, u8, u, U) then `"`.
        // Wide / Unicode prefixes: skip the prefix bytes before the quote.
        let str_prefix_len = string_prefix_len(bytes, i);
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
        // Character literals.
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
                kind: TokenKind::CharLiteral,
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

/// The end of the number literal starting at `i` (a C/C++ pp-number):
/// digits, letters, `_` and `.`, a sign after an exponent (`e`, `E`, `p`,
/// `P`), and `'` between digits.
fn number_end(bytes: &[u8], mut i: usize) -> usize {
    while let Some(&b) = bytes.get(i) {
        let part = b.is_ascii_alphanumeric()
            || b == b'_'
            || b == b'.'
            || ((b == b'+' || b == b'-') && matches!(bytes[i - 1], b'e' | b'E' | b'p' | b'P'))
            || (b == b'\'' && bytes.get(i + 1).is_some_and(u8::is_ascii_alphanumeric));
        if !part {
            break;
        }
        i += 1;
    }
    i
}

/// A C++ raw string literal starting at `i`, if there is one: an optional
/// encoding prefix, `R"`, a delimiter of up to 16 characters, `(`, the
/// content, then `)delimiter"`. Unterminated, it runs to the end of input.
fn raw_string(bytes: &[u8], i: usize) -> Option<Token> {
    if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
        return None;
    }
    let prefix = [&b"u8R\""[..], b"uR\"", b"UR\"", b"LR\"", b"R\""]
        .into_iter()
        .find(|p| bytes[i..].starts_with(p))?;
    let delim_start = i + prefix.len();
    let open = delim_start
        + bytes[delim_start..]
            .iter()
            .take(17)
            .position(|&c| c == b'(')?;
    let delim = &bytes[delim_start..open];
    if delim
        .iter()
        .any(|&c| c.is_ascii_whitespace() || matches!(c, b'\\' | b')' | b'"'))
    {
        return None;
    }
    let content_start = open + 1;
    let mut close = Vec::with_capacity(delim.len() + 2);
    close.push(b')');
    close.extend_from_slice(delim);
    close.push(b'"');
    let (content_end, end) = match bytes[content_start..]
        .windows(close.len())
        .position(|w| w == close.as_slice())
    {
        Some(p) => (content_start + p, content_start + p + close.len()),
        None => (bytes.len(), bytes.len()),
    };
    Some(Token {
        kind: TokenKind::StringLiteral,
        start: i,
        end,
        content_start,
        content_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(src: &[u8], cpp: bool) -> Vec<String> {
        tokenize_with(src, cpp)
            .iter()
            .filter(|t| t.kind == TokenKind::StringLiteral)
            .map(|t| String::from_utf8_lossy(&src[t.content_start..t.content_end]).into_owned())
            .collect()
    }

    #[test]
    fn cpp_raw_strings_are_one_literal() {
        let src = br#"auto a = R"(say "hi" // \n)"; auto b = u8R"xy(a)"b)xy"; f("c");"#;
        assert_eq!(strings(src, true), [r#"say "hi" // \n"#, r#"a)"b"#, "c"]);
        // `R` that ends an identifier is not a raw-string prefix.
        assert_eq!(strings(br#"FOOR"(x)""#, true), ["(x)"]);
        // C has no raw strings: `R` is an identifier, then a plain string.
        assert_eq!(strings(br#"R"(a)""#, false), ["(a)"]);
        // Unterminated: to the end of input.
        assert_eq!(strings(br#"R"(open"#, true), ["open"]);
    }

    #[test]
    fn digit_separators_do_not_open_char_literals() {
        let src = b"int n = 1'000'000; char q = '\"'; const char* s = \"x\";";
        assert_eq!(strings(src, false), ["x"]);
        let chars = tokenize(src)
            .iter()
            .filter(|t| t.kind == TokenKind::CharLiteral)
            .count();
        assert_eq!(chars, 1);
        // Numbers are not identifiers: no `x1F` from `0x1F`, no `e` from `1e-3`.
        let idents: Vec<&[u8]> = tokenize(b"a = 0x1F + 1e-3 + .5f;")
            .iter()
            .filter(|t| t.kind == TokenKind::Identifier)
            .map(|t| &b"a = 0x1F + 1e-3 + .5f;"[t.start..t.end])
            .collect();
        assert_eq!(idents, [&b"a"[..]]);
    }

    #[test]
    fn cpp_headers_are_told_from_c_headers() {
        for cpp in [
            &b"template <typename T> T id(T x);"[..],
            b"namespace arrow {\nint f();\n}",
            b"namespace {\nint f();\n}",
            b"class Widget {\n public:\n  int n;\n};",
            b"class Derived : public Base {};",
            b"inline int f() { return std::max(1, 2); }",
        ] {
            assert!(looks_like_cpp(cpp), "{}", String::from_utf8_lossy(cpp));
        }
        for c in [
            &b"struct point { int x, y; };\nint class_count;"[..],
            // The usual guards around a C header.
            b"#ifdef __cplusplus\nextern \"C\" {\n#endif\nint f(void);\n#ifdef __cplusplus\n}\n#endif",
            // C++ only in comments and strings.
            b"// template <class T>, std::vector\nconst char* s = \"a::b\";",
            b"/* class Foo { }; namespace x { } */ int f(void);",
        ] {
            assert!(!looks_like_cpp(c), "{}", String::from_utf8_lossy(c));
        }
    }
}
