//! Token pass — language-aware but lighter than full AST.
//!
//! The per-language tokenizers here are deliberately minimal. They recognize
//! the handful of constructs needed to reclassify raw findings (strings,
//! comments, identifiers) and to emit the token-pass signals defined in
//! SPEC.md. They do not build a full AST — that is the job of the `ast` pass.
//!
//! All tokenizers return tokens with byte offsets into the original file.
//! `content` carries the inner byte range of the string or comment body
//! (excluding quotes, prefix bytes, and comment markers); for identifiers it
//! is the whole identifier span; for operators/other it is unset.

use std::path::Path;

use crate::finding::{Finding, PassKind, Severity, SignalKind};
use crate::language::Language;
use crate::util::{snippet_around, LineIndex};

pub mod c;
pub mod python;
pub mod rust;
pub mod typescript;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Comment,
    StringLiteral,
    Identifier,
    Operator,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub struct Token {
    pub kind: TokenKind,
    pub start: usize,
    pub end: usize,
    /// Inner content range (for strings: between the quotes; for comments:
    /// after the comment marker; for identifiers: same as start..end).
    pub content_start: usize,
    pub content_end: usize,
}

impl Token {
    pub fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end
    }
}

/// Run the token pass: tokenize, reclassify raw findings, and emit new
/// token-level signals. Returns the combined finding set.
pub fn analyze(
    path: &Path,
    bytes: &[u8],
    lang: Language,
    index: &LineIndex,
    raw_findings: Vec<Finding>,
) -> Vec<Finding> {
    let tokens = tokenize(bytes, lang);
    let mut findings = reclassify(bytes, raw_findings, &tokens);
    findings.extend(emit_identifier_findings(path, bytes, index, lang, &tokens));
    findings.extend(emit_concat_findings(path, bytes, index, lang, &tokens));
    findings.extend(emit_surrogate_escape_findings(
        path, bytes, index, lang, &tokens,
    ));
    findings.extend(emit_macro_alias_findings(path, bytes, index, lang, &tokens));
    findings.extend(emit_format_string_write_findings(
        path, bytes, index, lang, &tokens,
    ));
    findings.extend(emit_decorative_whitespace_findings(
        path, bytes, index, lang, &tokens,
    ));
    findings.extend(emit_line_continuation_findings(
        path, bytes, index, lang, &tokens,
    ));
    findings
}

fn tokenize(bytes: &[u8], lang: Language) -> Vec<Token> {
    match lang {
        Language::C => c::tokenize(bytes),
        Language::Python => python::tokenize(bytes),
        Language::Rust => rust::tokenize(bytes),
        Language::TypeScript | Language::JavaScript => typescript::tokenize(bytes),
    }
}

/// Binary-search the token list for the token whose span covers `offset`.
/// Tokens are expected to be sorted by `start` and non-overlapping.
fn token_at(tokens: &[Token], offset: usize) -> Option<&Token> {
    let idx = match tokens.binary_search_by_key(&offset, |t| t.start) {
        Ok(i) => i,
        Err(0) => return None,
        Err(i) => i - 1,
    };
    let t = &tokens[idx];
    if t.contains(offset) {
        Some(t)
    } else {
        None
    }
}

/// Byte offset of the newline terminating the line containing `start`, or
/// `bytes.len()` if the line is the last and unterminated.
fn line_end_from(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| start + i)
        .unwrap_or(bytes.len())
}

/// Sum the bytes of `[line_start, line_end)` that lie inside a string
/// literal or comment token. Used to decide whether a long line is
/// actually a long code line vs. a long-string-literal fixture.
fn string_comment_coverage(tokens: &[Token], line_start: usize, line_end: usize) -> usize {
    let mut idx = match tokens.binary_search_by_key(&line_start, |t| t.start) {
        Ok(i) => i,
        Err(0) => 0,
        Err(i) => i - 1, // preceding token may extend into the line
    };
    let mut total = 0usize;
    while idx < tokens.len() {
        let t = &tokens[idx];
        if t.start >= line_end {
            break;
        }
        if matches!(t.kind, TokenKind::StringLiteral | TokenKind::Comment) {
            let overlap_start = t.start.max(line_start);
            let overlap_end = t.end.min(line_end);
            if overlap_end > overlap_start {
                total += overlap_end - overlap_start;
            }
        }
        idx += 1;
    }
    total
}

// ---------------------------------------------------------------------------
// Reclassification of raw findings
// ---------------------------------------------------------------------------

/// Adjust severity/confidence of raw findings based on what token type (if any)
/// they sit inside. Per SPEC §Token:
///   * High-complexity / encoding findings in a comment → demote to INFO.
///   * Encoding findings outside any string or comment → demote to INFO
///     (likely a false positive — base64/hex runs in bare code are almost
///     always identifiers or numeric literals the raw pass misclassified).
///   * UnicodeHomoglyph / UnicodeMixedScript inside a string or comment →
///     demote to INFO (Cyrillic in a translation string is not an attack).
///   * UnicodeBidi stays CRITICAL everywhere — bidi overrides are the one
///     attack where location does not mitigate.
fn reclassify(bytes: &[u8], findings: Vec<Finding>, tokens: &[Token]) -> Vec<Finding> {
    findings
        .into_iter()
        .filter_map(|mut f| {
            let ctx = token_at(tokens, f.byte_offset).map(|t| t.kind);
            match f.kind {
                SignalKind::HighComplexity
                | SignalKind::EncodingBase64
                | SignalKind::EncodingHex
                | SignalKind::EncodingEscapeSoup => match ctx {
                    Some(TokenKind::Comment) => {
                        f.severity = Severity::Info;
                        f.confidence = (f.confidence * 0.6).max(0.20);
                        f.message = format!("{} (in comment)", f.message);
                    }
                    Some(TokenKind::StringLiteral) => {
                        // Expected location for encoded payloads — leave as-is.
                    }
                    _ => {
                        f.severity = Severity::Info;
                        f.confidence = (f.confidence * 0.5).max(0.20);
                        f.message = format!("{} (outside string/comment)", f.message);
                    }
                },
                SignalKind::UnicodeHomoglyph | SignalKind::UnicodeMixedScript => {
                    if matches!(
                        ctx,
                        Some(TokenKind::Comment) | Some(TokenKind::StringLiteral)
                    ) {
                        f.severity = Severity::Info;
                        f.confidence = (f.confidence * 0.5).max(0.20);
                        f.message = format!("{} (in string/comment)", f.message);
                    }
                }
                SignalKind::UnicodeZeroWidth | SignalKind::UnicodeInvisible => {
                    if matches!(
                        ctx,
                        Some(TokenKind::Comment) | Some(TokenKind::StringLiteral)
                    ) {
                        f.severity = Severity::Info;
                        f.confidence = (f.confidence * 0.6).max(0.20);
                        f.message = format!("{} (in string/comment)", f.message);
                    }
                }
                SignalKind::LongLine => {
                    // The raw pass anchors the finding at the start of the
                    // line, so we can measure the whole line's token coverage
                    // directly from byte_offset.
                    let line_start = f.byte_offset;
                    let line_end = line_end_from(bytes, line_start);
                    let line_len = line_end.saturating_sub(line_start);
                    if line_len > 0 {
                        let coverage = string_comment_coverage(tokens, line_start, line_end);
                        let fraction = coverage as f32 / line_len as f32;
                        if fraction > 0.8 {
                            // Mostly a string literal or comment — almost
                            // always a test fixture or embedded data blob.
                            return None;
                        }
                        if fraction > 0.5 && f.severity == Severity::Warn {
                            f.severity = Severity::Info;
                            f.confidence = (f.confidence * 0.6).max(0.20);
                            f.message = format!("{} (mostly string/comment)", f.message);
                        }
                    }
                }
                _ => {}
            }
            Some(f)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Identifier analysis — narrow charset + per-file low-length outliers
// ---------------------------------------------------------------------------

fn is_conventional_short(ident: &str, lang: Language) -> bool {
    // Per-language "this is fine even though it's tiny" list. Matches SPEC
    // §Per-language calibration.
    let base: &[&str] = &[
        "i", "j", "k", "x", "y", "z", "n", "m", "_", "it", "id", "fn",
    ];
    if base.contains(&ident) {
        return true;
    }
    match lang {
        Language::C => false,
        Language::Python => ident.starts_with("__") && ident.ends_with("__"),
        Language::Rust => ident.starts_with('_'),
        Language::TypeScript | Language::JavaScript => ident.starts_with('$'),
    }
}

fn is_narrow_charset(ident: &str) -> bool {
    // SPEC: identifier using only characters from a visually confusable set
    // (e.g. l, I, 1, O, 0). Require length ≥ 4 to avoid flagging single-letter
    // names like `l` or `I` used as loop variables.
    if ident.len() < 4 {
        return false;
    }
    ident
        .chars()
        .all(|c| matches!(c, 'l' | 'I' | '1' | 'O' | '0'))
}

fn emit_identifier_findings(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Language,
    tokens: &[Token],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut ident_lengths: Vec<usize> = Vec::new();
    for tok in tokens.iter().filter(|t| t.kind == TokenKind::Identifier) {
        let Ok(ident) = std::str::from_utf8(&bytes[tok.start..tok.end]) else {
            continue;
        };
        if !is_conventional_short(ident, lang) {
            ident_lengths.push(ident.chars().count());
        }
        if is_narrow_charset(ident) {
            let (line, col) = index.locate(tok.start);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: tok.start,
                line,
                col,
                pass: PassKind::Token,
                kind: SignalKind::IdentifierNarrowCharset,
                severity: Severity::Warn,
                confidence: 0.55,
                message: format!("identifier `{}` uses only visually confusable chars", ident),
                snippet: crate::finding::redact_snippet(&snippet_around(bytes, tok.start, 60)),
                diff_introduced: false,
            });
        }
    }

    // File-level naming-shape signals. Two complementary triggers:
    //   (a) Mean non-conventional identifier length < 2.0 — catches files
    //       where almost every name is 1-2 chars on average.
    //   (b) ≥ 40% of non-conventional identifiers are exactly one character
    //       — catches IOCCC-style obfuscation where many globals/functions
    //       are single letters but a handful of keywords (`extern`, `void`,
    //       `nanosleep`, `TIOCGWINSZ`, …) inflate the mean above 2.0.
    if ident_lengths.len() >= 20 {
        let total = ident_lengths.len();
        let mean = ident_lengths.iter().sum::<usize>() as f32 / total as f32;
        let single_char = ident_lengths.iter().filter(|&&n| n == 1).count();
        let single_frac = single_char as f32 / total as f32;
        let message = if mean < 2.0 {
            Some(format!(
                "mean non-conventional identifier length {:.2} over {} names",
                mean, total
            ))
        } else if total >= 30 && single_frac >= 0.4 {
            Some(format!(
                "{} of {} non-conventional identifiers are single-character ({:.0}%)",
                single_char,
                total,
                single_frac * 100.0
            ))
        } else {
            None
        };
        if let Some(message) = message {
            // Anchor the finding at the start of the file — this is a
            // file-level observation, not a per-identifier one.
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: 0,
                line: 1,
                col: 1,
                pass: PassKind::Token,
                kind: SignalKind::IdentifierLowLength,
                severity: Severity::Info,
                confidence: 0.50,
                message,
                snippet: String::new(),
                diff_introduced: false,
            });
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// String concatenation reconstruction — `"im" + "port"` patterns
// ---------------------------------------------------------------------------

/// Substrings that, if they appear inside a concatenated-string reconstruction,
/// flip the finding to Warn. The list is intentionally short and conservative:
/// each entry is a name that obfuscation payloads famously reassemble to
/// dodge static greps (exec/eval/import/getattr/etc.).
const DANGEROUS_NAMES: &[&str] = &[
    "exec",
    "eval",
    "compile",
    "__import__",
    "import",
    "getattr",
    "setattr",
    "globals",
    "locals",
    "vars",
    "__builtins__",
    "system",
    "subprocess",
    "popen",
    "Function",
    "require",
    "child_process",
    "include_str",
    "include_bytes",
];

fn emit_concat_findings(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Language,
    tokens: &[Token],
) -> Vec<Finding> {
    let _ = lang;
    let mut findings = Vec::new();
    let n = tokens.len();
    let mut i = 0;
    while i < n {
        if tokens[i].kind != TokenKind::StringLiteral {
            i += 1;
            continue;
        }
        // Greedy: find the longest run `StringLit (Plus StringLit)+`.
        let start_idx = i;
        let mut last_string_idx = i;
        let mut j = i + 1;
        while j + 1 < n
            && tokens[j].kind == TokenKind::Operator
            && &bytes[tokens[j].start..tokens[j].end] == b"+"
            && tokens[j + 1].kind == TokenKind::StringLiteral
        {
            last_string_idx = j + 1;
            j += 2;
        }
        if last_string_idx > start_idx {
            // Concatenate the string contents.
            let mut concat = Vec::new();
            let mut k = start_idx;
            while k <= last_string_idx {
                if tokens[k].kind == TokenKind::StringLiteral {
                    concat
                        .extend_from_slice(&bytes[tokens[k].content_start..tokens[k].content_end]);
                }
                k += 1;
            }
            if let Ok(text) = std::str::from_utf8(&concat) {
                if let Some(hit) = DANGEROUS_NAMES.iter().find(|name| text.contains(*name)) {
                    let anchor = tokens[start_idx].start;
                    let (line, col) = index.locate(anchor);
                    findings.push(Finding {
                        path: path.to_path_buf(),
                        byte_offset: anchor,
                        line,
                        col,
                        pass: PassKind::Token,
                        kind: SignalKind::StringConcatConstruction,
                        severity: Severity::Warn,
                        confidence: 0.65,
                        message: format!(
                            "concatenated string reconstructs `{}`: {:?}",
                            hit,
                            if text.len() > 60 {
                                format!("{}…", &text[..60])
                            } else {
                                text.to_string()
                            }
                        ),
                        snippet: crate::finding::redact_snippet(&snippet_around(bytes, anchor, 80)),
                        diff_introduced: false,
                    });
                }
            }
            i = last_string_idx + 1;
        } else {
            i += 1;
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Surrogate-pair escape sequence detection
// ---------------------------------------------------------------------------
//
// JavaScript/TypeScript runtimes recombine adjacent \uHHHH escape sequences
// for surrogate pairs into a single supplementary codepoint. The pair
// \uDB40\uDCxx decodes to a Unicode Tags block character (U+E0000–U+E007F),
// which is invisible and has no legitimate use in source code.
//
// This check only applies to JS/TS; other languages either reject lone
// surrogates at compile time (Rust) or do not recombine them (Python 3).

fn is_tag_codepoint(cp: u32) -> bool {
    cp == 0xE0001 || matches!(cp, 0xE0020..=0xE007F)
}

/// Scan `content` (raw bytes of a string literal, between the quotes) for
/// `\uHHHH` escape sequences. Returns `(offset_in_content, codepoint)` for
/// each one found. The offset points at the leading `\`.
fn scan_u4_escapes(content: &[u8]) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    let n = content.len();
    let mut i = 0;
    while i + 6 <= n {
        if content[i] == b'\\'
            && content[i + 1] == b'u'
            && content[i + 2] != b'{'
            && content[i + 2..i + 6].iter().all(|b| b.is_ascii_hexdigit())
        {
            let hex = std::str::from_utf8(&content[i + 2..i + 6]).unwrap_or("");
            if let Ok(cp) = u32::from_str_radix(hex, 16) {
                out.push((i, cp));
                i += 6;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn emit_surrogate_escape_findings(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Language,
    tokens: &[Token],
) -> Vec<Finding> {
    if !matches!(lang, Language::TypeScript | Language::JavaScript) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for tok in tokens.iter().filter(|t| t.kind == TokenKind::StringLiteral) {
        let content = &bytes[tok.content_start..tok.content_end];
        let escapes = scan_u4_escapes(content);
        let mut i = 0;
        while i < escapes.len() {
            let (off, cp) = escapes[i];
            let abs = tok.content_start + off;

            if (0xD800..=0xDBFF).contains(&cp) {
                // High surrogate — look for an immediately adjacent low surrogate.
                // The \uHHHH escape is 6 bytes, so the next one must be at off+6.
                let paired = escapes
                    .get(i + 1)
                    .filter(|&&(lo, lcp)| lo == off + 6 && (0xDC00..=0xDFFF).contains(&lcp));

                if let Some(&(_, low_cp)) = paired {
                    let combined = 0x10000 + (cp - 0xD800) * 0x400 + (low_cp - 0xDC00);
                    let (line, col) = index.locate(abs);
                    let (severity, confidence, message) = if is_tag_codepoint(combined) {
                        (
                            Severity::Warn,
                            0.92,
                            format!(
                                "surrogate pair \\u{:04X}\\u{:04X} decodes to \
                                 U+{:05X} (invisible tag character)",
                                cp, low_cp, combined
                            ),
                        )
                    } else {
                        (
                            Severity::Info,
                            0.70,
                            format!(
                                "surrogate pair \\u{:04X}\\u{:04X} (non-scalar \
                                 Unicode codepoints in string literal)",
                                cp, low_cp
                            ),
                        )
                    };
                    findings.push(Finding {
                        path: path.to_path_buf(),
                        byte_offset: abs,
                        line,
                        col,
                        pass: PassKind::Token,
                        kind: SignalKind::UnicodeSurrogate,
                        severity,
                        confidence,
                        message,
                        snippet: crate::finding::redact_snippet(&snippet_around(bytes, abs, 80)),
                        diff_introduced: false,
                    });
                    i += 2;
                    continue;
                }

                // Orphaned high surrogate.
                let (line, col) = index.locate(abs);
                findings.push(Finding {
                    path: path.to_path_buf(),
                    byte_offset: abs,
                    line,
                    col,
                    pass: PassKind::Token,
                    kind: SignalKind::UnicodeSurrogate,
                    severity: Severity::Info,
                    confidence: 0.65,
                    message: format!(
                        "orphaned high surrogate \\u{:04X} (no matching low surrogate)",
                        cp
                    ),
                    snippet: crate::finding::redact_snippet(&snippet_around(bytes, abs, 80)),
                    diff_introduced: false,
                });
            } else if (0xDC00..=0xDFFF).contains(&cp) {
                // Orphaned low surrogate (no preceding high).
                let (line, col) = index.locate(abs);
                findings.push(Finding {
                    path: path.to_path_buf(),
                    byte_offset: abs,
                    line,
                    col,
                    pass: PassKind::Token,
                    kind: SignalKind::UnicodeSurrogate,
                    severity: Severity::Info,
                    confidence: 0.65,
                    message: format!(
                        "orphaned low surrogate \\u{:04X} (no preceding high surrogate)",
                        cp
                    ),
                    snippet: crate::finding::redact_snippet(&snippet_around(bytes, abs, 80)),
                    diff_introduced: false,
                });
            }
            i += 1;
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// C macro aliasing — `#define <short> <sensitive>`
// ---------------------------------------------------------------------------
//
// Obfuscated C frequently aliases system calls or libc functions to one- or
// two-character macro names (`#define A write`) so static greps for
// `system(`, `exec(`, etc. miss the call site. The C tokenizer emits each
// preprocessor directive as a single Comment token whose content starts at
// the byte after `#`, so we just scan those.

const MACRO_SENSITIVE_NAMES: &[&str] = &[
    // process spawn / replacement
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve", "fork", "vfork",
    "kill", "raise", // dynamic loading
    "dlopen", "dlsym", "dlmopen", "dlclose",
    // direct syscalls (bonsai uses `#define A write`)
    "write", "read", "open", "openat", "close", // memory protection
    "mmap", "mprotect", "munmap", // network
    "socket", "connect", "bind", "accept", "listen", "send", "sendto", "sendmsg", "recv",
    "recvfrom", "recvmsg", // generic but useful when aliased to a 1-char name
    "ptrace", "syscall",
];

const MACRO_NAME_MAX_LEN: usize = 2;

fn emit_macro_alias_findings(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Language,
    tokens: &[Token],
) -> Vec<Finding> {
    if !matches!(lang, Language::C) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for tok in tokens.iter().filter(|t| t.kind == TokenKind::Comment) {
        let Ok(content) = std::str::from_utf8(&bytes[tok.content_start..tok.content_end]) else {
            continue;
        };
        let Some((name, replacement)) = parse_define(content) else {
            continue;
        };
        if name.len() > MACRO_NAME_MAX_LEN {
            continue;
        }
        if !MACRO_SENSITIVE_NAMES.contains(&replacement) {
            continue;
        }
        let (line, col) = index.locate(tok.start);
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: tok.start,
            line,
            col,
            pass: PassKind::Token,
            kind: SignalKind::MacroAlias,
            severity: Severity::Warn,
            confidence: 0.65,
            message: format!(
                "{}-char macro `{}` aliases sensitive name `{}`",
                name.len(),
                name,
                replacement
            ),
            snippet: crate::finding::redact_snippet(&snippet_around(bytes, tok.start, 80)),
            diff_introduced: false,
        });
    }
    findings
}

/// Given a preprocessor directive body (the bytes after `#`), return
/// `(macro_name, replacement_identifier)` if the directive is a simple
/// object-like `#define NAME REPLACEMENT` where REPLACEMENT is a single
/// identifier. Function-like macros (`NAME(args)`) and multi-token bodies
/// return `None` so the caller can skip them.
fn parse_define(content: &str) -> Option<(&str, &str)> {
    let body = content.trim_start();
    let body = body.strip_prefix("define")?;
    // Require whitespace after `define` so we don't match `defined(X)`.
    if !body.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let mut parts = body.split_whitespace();
    let name = parts.next()?;
    if !is_simple_identifier(name) {
        // Function-like macros (`NAME(x)`) and anything containing punctuation.
        return None;
    }
    let replacement = parts.next()?;
    if parts.next().is_some() {
        // Multi-token replacement is not a simple alias.
        return None;
    }
    if !is_simple_identifier(replacement) {
        return None;
    }
    Some((name, replacement))
}

// ---------------------------------------------------------------------------
// printf format-string write directive (`%n` family)
// ---------------------------------------------------------------------------
//
// The `%n` conversion writes the count of bytes printed so far into an int*
// argument — a memory write primitive, virtually always seen in CTF/exploit
// code. Variants: `%n`, `%hhn` (signed char*), `%hn` (short*), `%ln` (long*),
// `%lln` (long long*). POSIX positional form: `%<digit>$<length>n`.
//
// Bonsai-style obfuscation splits the directive across stringification:
//   `#define N(a) "%"#a"$hhn"` — the literal `$hhn` appears alone.
// We catch both the assembled directive and the orphan tail.

fn emit_format_string_write_findings(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Language,
    tokens: &[Token],
) -> Vec<Finding> {
    if !matches!(lang, Language::C) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for tok in tokens {
        let (text, abs_offset, in_macro) = match tok.kind {
            TokenKind::StringLiteral => (
                &bytes[tok.content_start..tok.content_end],
                tok.content_start,
                false,
            ),
            TokenKind::Comment => {
                // Only preprocessor `#define` directives — line/block comments
                // mentioning %n are human discussion, not code.
                if bytes.get(tok.start) != Some(&b'#') {
                    continue;
                }
                let body = &bytes[tok.content_start..tok.content_end];
                let Ok(body_str) = std::str::from_utf8(body) else {
                    continue;
                };
                let trimmed = body_str.trim_start();
                if !(trimmed.starts_with("define ") || trimmed.starts_with("define\t")) {
                    continue;
                }
                (body, tok.content_start, true)
            }
            _ => continue,
        };
        // For #define directives, strip embedded C comments — `%n` inside a
        // `/* ... */` or `// ...` is documentation, not code.
        let scratch: Vec<u8>;
        let scan_text: &[u8] = if matches!(tok.kind, TokenKind::Comment) {
            scratch = mask_c_comments(text);
            &scratch
        } else {
            text
        };
        for (off, dir) in scan_format_n_directives(scan_text) {
            let abs = abs_offset + off;
            let (line, col) = index.locate(abs);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: abs,
                line,
                col,
                pass: PassKind::Token,
                kind: SignalKind::FormatStringWrite,
                severity: Severity::Critical,
                confidence: 0.90,
                message: format!(
                    "printf format directive `{}` writes to memory ({})",
                    dir,
                    if in_macro {
                        "in macro definition"
                    } else {
                        "in string literal"
                    }
                ),
                snippet: crate::finding::redact_snippet(&snippet_around(bytes, abs, 80)),
                diff_introduced: false,
            });
        }
    }
    findings
}

/// Replace `/* ... */` and `// ...` comment regions in `text` with spaces,
/// preserving byte offsets. Used to avoid matching `%n` inside an embedded
/// comment of a `#define` line.
fn mask_c_comments(text: &[u8]) -> Vec<u8> {
    let mut out = text.to_vec();
    let n = out.len();
    let mut i = 0;
    while i + 1 < n {
        if out[i] == b'/' && out[i + 1] == b'*' {
            let mut j = i + 2;
            while j + 1 < n && !(out[j] == b'*' && out[j + 1] == b'/') {
                j += 1;
            }
            let end = (j + 2).min(n);
            for k in i..end {
                out[k] = b' ';
            }
            i = end;
            continue;
        }
        if out[i] == b'/' && out[i + 1] == b'/' {
            let mut j = i + 2;
            while j < n && out[j] != b'\n' {
                j += 1;
            }
            for k in i..j {
                out[k] = b' ';
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// Scan `text` for printf write directives. Returns `(offset, directive_text)`
/// for each hit. Catches both assembled `%[...]n` directives and the
/// orphan-tail form `$[hl]+n` produced by stringification splits.
fn scan_format_n_directives(text: &[u8]) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    let n = text.len();
    let mut i = 0;
    while i < n {
        // Skip `%%` literal percent.
        if text[i] == b'%' && i + 1 < n && text[i + 1] == b'%' {
            i += 2;
            continue;
        }
        if text[i] == b'%' {
            if let Some((dir_len, is_n)) = parse_printf_directive(&text[i..]) {
                if is_n {
                    let dir = std::str::from_utf8(&text[i..i + dir_len])
                        .unwrap_or("?")
                        .to_string();
                    hits.push((i, dir));
                }
                i += dir_len.max(1);
                continue;
            }
        }
        // Orphan tail: `$[hl]+n` — fragment of a positional `%<d>$<len>n`
        // directive stranded by macro stringification splits.
        if text[i] == b'$' {
            let len_start = i + 1;
            let mut j = len_start;
            while j < n && (text[j] == b'h' || text[j] == b'l') {
                j += 1;
            }
            if j > len_start && j < n && text[j] == b'n' {
                let dir = std::str::from_utf8(&text[i..=j]).unwrap_or("?").to_string();
                hits.push((i, dir));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    hits
}

/// Parse a printf format directive starting at byte 0 of `tail` (which must
/// begin with `%`). Returns `(directive_byte_length, conversion_is_n)` if a
/// complete directive parses, else None.
fn parse_printf_directive(tail: &[u8]) -> Option<(usize, bool)> {
    let n = tail.len();
    if n < 2 || tail[0] != b'%' {
        return None;
    }
    let mut i = 1;
    // Optional positional argument: [0-9]+\$
    let mark = i;
    while i < n && tail[i].is_ascii_digit() {
        i += 1;
    }
    if i > mark && i < n && tail[i] == b'$' {
        i += 1;
    } else {
        i = mark;
    }
    // Flags
    while i < n && matches!(tail[i], b'-' | b'+' | b' ' | b'#' | b'0' | b'\'') {
        i += 1;
    }
    // Width
    if i < n && tail[i] == b'*' {
        i += 1;
        let m = i;
        while i < n && tail[i].is_ascii_digit() {
            i += 1;
        }
        if i > m && i < n && tail[i] == b'$' {
            i += 1;
        } else {
            i = m;
        }
    } else {
        while i < n && tail[i].is_ascii_digit() {
            i += 1;
        }
    }
    // Precision
    if i < n && tail[i] == b'.' {
        i += 1;
        if i < n && tail[i] == b'*' {
            i += 1;
            let m = i;
            while i < n && tail[i].is_ascii_digit() {
                i += 1;
            }
            if i > m && i < n && tail[i] == b'$' {
                i += 1;
            } else {
                i = m;
            }
        } else {
            while i < n && tail[i].is_ascii_digit() {
                i += 1;
            }
        }
    }
    // Length modifier
    while i < n && matches!(tail[i], b'h' | b'l' | b'j' | b'z' | b't' | b'L' | b'q') {
        i += 1;
    }
    if i >= n {
        return None;
    }
    let conv = tail[i];
    if !matches!(
        conv,
        b'd' | b'i'
            | b'u'
            | b'o'
            | b'x'
            | b'X'
            | b'e'
            | b'E'
            | b'f'
            | b'F'
            | b'g'
            | b'G'
            | b'a'
            | b'A'
            | b'c'
            | b's'
            | b'p'
            | b'n'
            | b'C'
            | b'S'
            | b'm'
    ) {
        return None;
    }
    Some((i + 1, conv == b'n'))
}

// ---------------------------------------------------------------------------
// Decorative internal whitespace layout
// ---------------------------------------------------------------------------
//
// IOCCC-style obfuscation shapes code into rectangles, diamonds, and other
// visual forms by padding internal whitespace between tokens. The hallmark:
// many lines have multiple multi-character whitespace runs *between* code
// tokens (not just leading indent). Real code rarely does this — at most one
// internal alignment run per line for end-of-line comments, never several.

const DECORATIVE_MIN_RUN_LEN: usize = 4;
const DECORATIVE_MIN_RUNS_PER_LINE: usize = 2;
const DECORATIVE_MIN_FILE_LINES: usize = 20;
const DECORATIVE_MIN_FRACTION: f32 = 0.30;
const DECORATIVE_MIN_LINES: usize = 5;
// Suppress if a single first-non-ws byte dominates decorative lines —
// this catches `switch/case` tables where every line starts with `case`.
const DECORATIVE_MAX_FIRST_BYTE_DOMINANCE: f32 = 0.70;
// Suppress if run-start columns are highly clustered (column-aligned) —
// this catches data arrays where each row aligns its literals to fixed
// columns. Snapped distinct-columns / total-runs below this threshold
// indicates structural alignment, not free-form decorative shaping.
const DECORATIVE_MIN_DISTINCT_COL_RATIO: f32 = 0.10;

fn emit_decorative_whitespace_findings(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Language,
    tokens: &[Token],
) -> Vec<Finding> {
    if !matches!(lang, Language::C) {
        return Vec::new();
    }
    let mut total_lines = 0usize;
    let mut decorative_lines = 0usize;
    let mut first_decorative_offset: Option<usize> = None;
    let mut total_runs = 0usize;
    let mut snapped_col_counts: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();
    let mut first_byte_counts: std::collections::HashMap<u8, usize> =
        std::collections::HashMap::new();

    let n = bytes.len();
    let mut line_start = 0usize;
    for i in 0..=n {
        if i != n && bytes[i] != b'\n' {
            continue;
        }
        let line_end = i;
        let line = &bytes[line_start..line_end];
        if let (Some(first_nws), Some(last_nws)) = (
            line.iter().position(|&b| !is_layout_ws(b)),
            line.iter().rposition(|&b| !is_layout_ws(b)),
        ) {
            total_lines += 1;
            let mut runs: Vec<usize> = Vec::new();
            collect_internal_ws_runs(
                line,
                first_nws,
                last_nws,
                line_start,
                tokens,
                DECORATIVE_MIN_RUN_LEN,
                &mut runs,
            );
            if runs.len() >= DECORATIVE_MIN_RUNS_PER_LINE {
                decorative_lines += 1;
                first_decorative_offset.get_or_insert(line_start);
                total_runs += runs.len();
                for r in &runs {
                    *snapped_col_counts.entry((r / 2) * 2).or_insert(0) += 1;
                }
                *first_byte_counts.entry(line[first_nws]).or_insert(0) += 1;
            }
        }
        line_start = i + 1;
    }

    if total_lines < DECORATIVE_MIN_FILE_LINES || decorative_lines < DECORATIVE_MIN_LINES {
        return Vec::new();
    }
    let fraction = decorative_lines as f32 / total_lines as f32;
    if fraction < DECORATIVE_MIN_FRACTION {
        return Vec::new();
    }
    // Filter: structural alignment via single-keyword tables.
    let dominant_first_byte = first_byte_counts.values().copied().max().unwrap_or(0);
    if (dominant_first_byte as f32 / decorative_lines as f32) >= DECORATIVE_MAX_FIRST_BYTE_DOMINANCE
    {
        return Vec::new();
    }
    // Filter: structural alignment via column-aligned data tables.
    if total_runs > 0 {
        let distinct_cols = snapped_col_counts.len();
        if (distinct_cols as f32 / total_runs as f32) < DECORATIVE_MIN_DISTINCT_COL_RATIO {
            return Vec::new();
        }
    }
    let offset = first_decorative_offset.unwrap_or(0);
    let (line, col) = index.locate(offset);
    vec![Finding {
        path: path.to_path_buf(),
        byte_offset: offset,
        line,
        col,
        pass: PassKind::Token,
        kind: SignalKind::WhitespaceAnomaly,
        severity: Severity::Warn,
        confidence: 0.70,
        message: format!(
            "{}/{} lines ({:.0}%) have decorative internal whitespace layout (≥{} runs of ≥{} spaces between code tokens)",
            decorative_lines,
            total_lines,
            fraction * 100.0,
            DECORATIVE_MIN_RUNS_PER_LINE,
            DECORATIVE_MIN_RUN_LEN,
        ),
        snippet: crate::finding::redact_snippet(&snippet_around(bytes, offset, 80)),
        diff_introduced: false,
    }]
}

fn is_layout_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Append run-start columns of maximal runs of ≥`min_len` whitespace bytes
/// inside `line[first..=last]` that are not covered by a string-literal or
/// comment token. Each appended value is the column (line-relative byte index)
/// at which a qualifying run begins.
fn collect_internal_ws_runs(
    line: &[u8],
    first: usize,
    last: usize,
    line_offset: usize,
    tokens: &[Token],
    min_len: usize,
    out: &mut Vec<usize>,
) {
    let mut run_start: Option<usize> = None;
    let mut k = first;
    while k <= last {
        let abs = line_offset + k;
        let in_string_or_comment = token_at(tokens, abs)
            .map(|t| matches!(t.kind, TokenKind::StringLiteral | TokenKind::Comment))
            .unwrap_or(false);
        let counts = is_layout_ws(line[k]) && !in_string_or_comment;
        if counts {
            if run_start.is_none() {
                run_start = Some(k);
            }
        } else if let Some(s) = run_start.take() {
            if k - s >= min_len {
                out.push(s);
            }
        }
        k += 1;
    }
}

// ---------------------------------------------------------------------------
// Backslash line continuation outside `#` directives and string literals
// ---------------------------------------------------------------------------
//
// `\<newline>` is the preprocessor line-continuation marker. Real code uses
// it inside `#define` macros and (rarely) inside long string literals. Using
// it inside a function body or expression is a strong obfuscation signal —
// IOCCC entries break expressions across line boundaries to fit a visual
// shape.

fn emit_line_continuation_findings(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Language,
    tokens: &[Token],
) -> Vec<Finding> {
    if !matches!(lang, Language::C) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let n = bytes.len();
    let mut i = 0;
    while i + 1 < n {
        if bytes[i] == b'\\' && bytes[i + 1] == b'\n' {
            // Skip if the `\` is inside a comment (which covers `#` directives
            // in our C tokenizer) or string literal.
            let inside = token_at(tokens, i).map(|t| t.kind);
            if !matches!(
                inside,
                Some(TokenKind::Comment) | Some(TokenKind::StringLiteral)
            ) {
                let (line, col) = index.locate(i);
                findings.push(Finding {
                    path: path.to_path_buf(),
                    byte_offset: i,
                    line,
                    col,
                    pass: PassKind::Token,
                    kind: SignalKind::LineContinuationInCode,
                    severity: Severity::Warn,
                    confidence: 0.75,
                    message:
                        "backslash line continuation in code (not a `#define` or string literal)"
                            .to_string(),
                    snippet: crate::finding::redact_snippet(&snippet_around(bytes, i, 60)),
                    diff_introduced: false,
                });
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    findings
}

fn is_simple_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{PassKind, SignalKind};
    use std::path::PathBuf;

    fn make_long_line_finding(byte_offset: usize, severity: Severity) -> Finding {
        Finding {
            path: PathBuf::from("fixture.py"),
            byte_offset,
            line: 1,
            col: 1,
            pass: PassKind::Raw,
            kind: SignalKind::LongLine,
            severity,
            confidence: 0.5,
            message: "line length N bytes".to_string(),
            snippet: String::new(),
            diff_introduced: false,
        }
    }

    // --- surrogate escape detection ---

    fn run_surrogate(src: &[u8], lang: Language) -> Vec<Finding> {
        let idx = LineIndex::new(src);
        let tokens = tokenize(src, lang);
        emit_surrogate_escape_findings(&PathBuf::from("test.js"), src, &idx, lang, &tokens)
    }

    #[test]
    fn surrogate_pair_decoding_to_tag_char_is_warn() {
        // 󠁁 is the JS escape sequence for U+E0041
        // (TAG LATIN CAPITAL LETTER A — invisible).
        let src = b"const x = \"\\uDB40\\uDC41\";";
        let findings = run_surrogate(src, Language::JavaScript);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::UnicodeSurrogate && f.severity == Severity::Warn)
            .expect("expected Warn UnicodeSurrogate for tag-char pair");
        assert!(
            hit.message.contains("E0041"),
            "message should cite U+E0041, got: {}",
            hit.message
        );
    }

    #[test]
    fn surrogate_pair_not_tag_char_is_info() {
        // 😀 decodes to U+1F600 GRINNING FACE (emoji, not a tag char).
        let src = b"const x = \"\\uD83D\\uDE00\";";
        let findings = run_surrogate(src, Language::JavaScript);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::UnicodeSurrogate)
            .expect("expected UnicodeSurrogate for emoji surrogate pair");
        assert_eq!(hit.severity, Severity::Info);
    }

    #[test]
    fn orphaned_high_surrogate_is_info() {
        let src = b"const x = \"\\uDB40\";";
        let findings = run_surrogate(src, Language::JavaScript);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::UnicodeSurrogate)
            .expect("expected UnicodeSurrogate for orphaned high surrogate");
        assert_eq!(hit.severity, Severity::Info);
        assert!(hit.message.contains("orphaned high"));
    }

    #[test]
    fn orphaned_low_surrogate_is_info() {
        let src = b"const x = \"\\uDC41\";";
        let findings = run_surrogate(src, Language::JavaScript);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::UnicodeSurrogate)
            .expect("expected UnicodeSurrogate for orphaned low surrogate");
        assert_eq!(hit.severity, Severity::Info);
        assert!(hit.message.contains("orphaned low"));
    }

    #[test]
    fn clean_string_emits_no_surrogate_findings() {
        let src = b"const x = \"hello world\";";
        let findings = run_surrogate(src, Language::JavaScript);
        assert!(findings.is_empty());
    }

    #[test]
    fn surrogate_check_skipped_for_python() {
        let src = b"x = \"\\uDB40\\uDC41\"";
        let findings = run_surrogate(src, Language::Python);
        assert!(findings.is_empty());
    }

    #[test]
    fn long_line_is_suppressed_when_mostly_string_literal() {
        // One long line: `x = "..................."` — quotes cover > 80%.
        let bytes = b"x = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";
        let tokens = vec![Token {
            kind: TokenKind::StringLiteral,
            start: 4,
            end: bytes.len() - 1,
            content_start: 5,
            content_end: bytes.len() - 2,
        }];
        let f = make_long_line_finding(0, Severity::Info);
        let out = reclassify(bytes, vec![f], &tokens);
        assert!(out.is_empty(), "expected LongLine to be suppressed");
    }

    #[test]
    fn long_line_warn_demoted_to_info_when_half_string() {
        // Line is "abcdefghij" + "STRINGSTRI" (half code, half string literal).
        let bytes = b"abcdefghij\"STRINGSTR\"\n";
        let tokens = vec![Token {
            kind: TokenKind::StringLiteral,
            start: 10,
            end: 21,
            content_start: 11,
            content_end: 20,
        }];
        let f = make_long_line_finding(0, Severity::Warn);
        let out = reclassify(bytes, vec![f], &tokens);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Info);
        assert!(out[0].message.contains("mostly string/comment"));
    }

    #[test]
    fn long_line_preserved_when_code_dominates() {
        // Mostly bare code, no tokens covering most of the line.
        let bytes = b"let a = 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10;\n";
        let tokens: Vec<Token> = Vec::new();
        let f = make_long_line_finding(0, Severity::Info);
        let out = reclassify(bytes, vec![f], &tokens);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Info);
        assert!(!out[0].message.contains("mostly string/comment"));
    }

    fn run_emit_idents(src: &[u8], lang: Language) -> Vec<Finding> {
        let idx = LineIndex::new(src);
        let tokens = tokenize(src, lang);
        emit_identifier_findings(&PathBuf::from("test.c"), src, &idx, lang, &tokens)
    }

    #[test]
    fn high_single_char_fraction_fires_low_length_signal() {
        // 30 1-letter non-conventional names + a sprinkling of keywords.
        // The mean stays above 2.0 but the single-char fraction does not.
        let mut src = String::new();
        for ch in b'a'..=b'z' {
            // skip the conventional shorts (i, j, k, m, n, x, y, z)
            if matches!(ch, b'i' | b'j' | b'k' | b'm' | b'n' | b'x' | b'y' | b'z') {
                continue;
            }
            src.push_str(&format!("int {}=0;", ch as char));
        }
        // 4 distinct uppercase singles → push the count past 30.
        for ch in [b'A', b'B', b'C', b'D'] {
            src.push_str(&format!("int {}=0;", ch as char));
        }
        let findings = run_emit_idents(src.as_bytes(), Language::C);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::IdentifierLowLength)
            .expect("expected IdentifierLowLength for high single-char fraction");
        assert!(
            hit.message.contains("single-character"),
            "message should describe the single-char trigger, got: {}",
            hit.message
        );
    }

    #[test]
    fn ordinary_identifiers_do_not_fire_low_length() {
        // 30 well-formed identifiers, no single-char ones.
        let names = [
            "config", "parser", "result", "count", "buffer", "writer", "reader", "stream",
            "source", "target", "value", "index", "limit", "offset", "length", "header", "footer",
            "client", "server", "request", "response", "context", "session", "manager", "handler",
            "queue", "worker", "logger", "filter", "encoder",
        ];
        let src = names
            .iter()
            .map(|n| format!("int {}=0;", n))
            .collect::<String>();
        let findings = run_emit_idents(src.as_bytes(), Language::C);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::IdentifierLowLength),
            "no IdentifierLowLength expected, got: {:?}",
            findings
        );
    }

    // --- macro alias detection ---

    fn run_macro_alias(src: &[u8], lang: Language) -> Vec<Finding> {
        let idx = LineIndex::new(src);
        let tokens = tokenize(src, lang);
        emit_macro_alias_findings(&PathBuf::from("test.c"), src, &idx, lang, &tokens)
    }

    #[test]
    fn one_char_macro_aliasing_write_is_warn() {
        let src = b"#define A write\nint main(){return 0;}\n";
        let findings = run_macro_alias(src, Language::C);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::MacroAlias)
            .expect("expected MacroAlias for `#define A write`");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.message.contains("`A`"));
        assert!(hit.message.contains("`write`"));
    }

    #[test]
    fn two_char_macro_aliasing_system_is_warn() {
        let src = b"#define SY system\n";
        let findings = run_macro_alias(src, Language::C);
        assert!(findings.iter().any(|f| f.kind == SignalKind::MacroAlias));
    }

    #[test]
    fn long_macro_name_does_not_fire() {
        let src = b"#define WRAPPER write\n";
        let findings = run_macro_alias(src, Language::C);
        assert!(findings.iter().all(|f| f.kind != SignalKind::MacroAlias));
    }

    #[test]
    fn non_sensitive_replacement_does_not_fire() {
        let src = b"#define N 100\n#define X y\n";
        let findings = run_macro_alias(src, Language::C);
        assert!(findings.iter().all(|f| f.kind != SignalKind::MacroAlias));
    }

    #[test]
    fn function_like_macro_does_not_fire() {
        // `#define A(x)` looks like an alias of `(x)`, but it's a function-like
        // macro — name has a `(` immediately after, so we skip it.
        let src = b"#define A(x) write(1, x, 1)\n";
        let findings = run_macro_alias(src, Language::C);
        assert!(findings.iter().all(|f| f.kind != SignalKind::MacroAlias));
    }

    #[test]
    fn multi_token_replacement_does_not_fire() {
        let src = b"#define A write_once\n#define B (write)\n";
        let findings = run_macro_alias(src, Language::C);
        assert!(findings.iter().all(|f| f.kind != SignalKind::MacroAlias));
    }

    #[test]
    fn macro_alias_skipped_for_non_c_languages() {
        let src = b"#define A write\n";
        for lang in [Language::Python, Language::Rust, Language::JavaScript] {
            let findings = run_macro_alias(src, lang);
            assert!(
                findings.iter().all(|f| f.kind != SignalKind::MacroAlias),
                "MacroAlias should only fire for C, fired for {:?}",
                lang
            );
        }
    }

    #[test]
    fn defined_pseudo_function_is_not_an_alias() {
        // `#if defined(write)` — the `defined` keyword should not be parsed as
        // `define` by parse_define.
        let src = b"#if defined(write)\n#endif\n";
        let findings = run_macro_alias(src, Language::C);
        assert!(findings.iter().all(|f| f.kind != SignalKind::MacroAlias));
    }

    // --- format-string write directive detection ---

    fn run_fmt_write(src: &[u8], lang: Language) -> Vec<Finding> {
        let idx = LineIndex::new(src);
        let tokens = tokenize(src, lang);
        emit_format_string_write_findings(&PathBuf::from("test.c"), src, &idx, lang, &tokens)
    }

    #[test]
    fn percent_n_in_string_literal_is_critical() {
        let src = br#"int x; printf("hello%n", &x);"#;
        let findings = run_fmt_write(src, Language::C);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::FormatStringWrite)
            .expect("expected FormatStringWrite for %n");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.message.contains("`%n`"));
        assert!(hit.message.contains("string literal"));
    }

    #[test]
    fn percent_hhn_with_positional_is_critical() {
        let src = br#"printf("%12$hhn", &c);"#;
        let findings = run_fmt_write(src, Language::C);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::FormatStringWrite)
            .expect("expected FormatStringWrite for %12$hhn");
        assert!(hit.message.contains("`%12$hhn`"));
    }

    #[test]
    fn percent_lln_is_critical() {
        let src = br#"printf("%lln", &n);"#;
        assert!(run_fmt_write(src, Language::C)
            .iter()
            .any(|f| f.kind == SignalKind::FormatStringWrite));
    }

    #[test]
    fn ordinary_format_directives_do_not_fire() {
        let src = br#"printf("%d %s %5.2f %p %x %ld %hhd %12$s\n", a, b, c, d);"#;
        let findings = run_fmt_write(src, Language::C);
        assert!(
            findings.is_empty(),
            "ordinary directives must not fire: {:?}",
            findings
        );
    }

    #[test]
    fn double_percent_does_not_fire() {
        let src = br#"printf("100%% done, n=%d\n", n);"#;
        assert!(run_fmt_write(src, Language::C).is_empty());
    }

    #[test]
    fn orphan_tail_in_define_macro_is_critical() {
        // Bonsai/IOCCC printf style — `$hhn` lives alone inside the macro,
        // assembled into a `%n` directive after preprocessor stringification.
        let src = b"#define N(a) \"%\"#a\"$hhn\"\n";
        let findings = run_fmt_write(src, Language::C);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::FormatStringWrite)
            .expect("expected FormatStringWrite for orphan $hhn");
        assert!(hit.message.contains("`$hhn`"));
        assert!(hit.message.contains("macro definition"));
    }

    #[test]
    fn plain_dollar_n_does_not_fire() {
        // Without a length modifier, `$n` is too common — it's a shell-var
        // reference in many strings. Require at least one h/l before n.
        let src = br#"system("echo $name $n");"#;
        let findings = run_fmt_write(src, Language::C);
        assert!(findings.is_empty(), "$n must not fire: {:?}", findings);
    }

    #[test]
    fn line_comment_mentioning_percent_n_does_not_fire() {
        let src = b"// printf(\"%n\") writes to memory - never use this\nint x;\n";
        let findings = run_fmt_write(src, Language::C);
        assert!(findings.is_empty(), "comment must not fire: {:?}", findings);
    }

    #[test]
    fn block_comment_mentioning_percent_n_does_not_fire() {
        let src = b"/* %n is a memory write directive */\nint x;\n";
        let findings = run_fmt_write(src, Language::C);
        assert!(findings.is_empty(), "comment must not fire: {:?}", findings);
    }

    #[test]
    fn percent_n_inside_define_block_comment_does_not_fire() {
        // SQLite-style: `#define SIZE 4 /* ... %n */` — the %n is in a
        // documentation comment within the directive line, not in the
        // macro replacement.
        let src = b"#define SIZE 4 /* Number of chars processed. %n */\n";
        let findings = run_fmt_write(src, Language::C);
        assert!(
            findings.is_empty(),
            "%n in /* */ inside #define must not fire: {:?}",
            findings
        );
    }

    #[test]
    fn percent_n_inside_define_line_comment_does_not_fire() {
        let src = b"#define SIZE 4 // size; %n means write\n";
        let findings = run_fmt_write(src, Language::C);
        assert!(
            findings.is_empty(),
            "%n in // inside #define must not fire: {:?}",
            findings
        );
    }

    #[test]
    fn format_string_write_skipped_for_non_c() {
        let src = br#"printf("%n", &x)"#;
        for lang in [Language::Python, Language::Rust, Language::JavaScript] {
            let findings = run_fmt_write(src, lang);
            assert!(
                findings.is_empty(),
                "FormatStringWrite must only fire for C, fired for {:?}",
                lang
            );
        }
    }

    #[test]
    fn parse_directive_accepts_full_grammar() {
        // Width with star-positional, precision with star-positional,
        // length modifier, n conversion.
        let r = parse_printf_directive(b"%1$*2$.*3$lln,");
        assert_eq!(r, Some((13, true)));
    }

    // --- decorative whitespace layout detection ---

    fn run_decorative(src: &[u8], lang: Language) -> Vec<Finding> {
        let idx = LineIndex::new(src);
        let tokens = tokenize(src, lang);
        emit_decorative_whitespace_findings(&PathBuf::from("test.c"), src, &idx, lang, &tokens)
    }

    #[test]
    fn decorative_layout_fires_when_threshold_met() {
        // 25 lines with internal whitespace runs at *varying* columns and
        // *varying* leading characters — the IOCCC shape signature, not an
        // aligned-table signature. Each line starts with a different byte
        // and its runs sit at different offsets.
        let lines = [
            "(   a    +    1)",
            "+    b   *    2",
            "[c    -    3]",
            "*d    +    4",
            "/   e    %    5",
            "{f    >>    6}",
            "<g    <<    7>",
            "&   h    |    8",
            "^i    !    9",
            "%j    ~    a",
        ];
        let mut src = String::new();
        // 30 lines: cycle through 10 patterns 3 times to keep first-byte
        // dominance below 70% and run-start columns well-distributed.
        for cycle in 0..3 {
            for line in &lines {
                src.push_str(&format!("{}{};\n", line, cycle));
            }
        }
        let findings = run_decorative(src.as_bytes(), Language::C);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::WhitespaceAnomaly)
            .expect("expected WhitespaceAnomaly for decorative layout");
        assert_eq!(hit.severity, Severity::Warn);
        assert!(hit.message.contains("decorative"));
    }

    #[test]
    fn decorative_layout_suppressed_for_case_table() {
        // switch/case alignment table: every decorative line begins with
        // `case` — first-byte dominance hits 100%, so the heuristic must
        // back off.
        let mut src = String::from("switch (op) {\n");
        for n in 0..30 {
            src.push_str(&format!(
                "  case OP_{:02}:        zOp = \"OP_{:02}\";        break;\n",
                n, n
            ));
        }
        src.push_str("}\n");
        let findings = run_decorative(src.as_bytes(), Language::C);
        assert!(
            findings.is_empty(),
            "switch/case table must not fire: {:?}",
            findings
        );
    }

    #[test]
    fn decorative_layout_suppressed_for_aligned_data_table() {
        // Char-literal data array with rows column-aligned at the same
        // offsets — distinct-snapped-cols / total-runs is tiny.
        let row = "    'a',       'b',       'c',       'd',       'e',       'f',       'g',\n";
        let mut src = String::from("char arr[] = {\n");
        for _ in 0..40 {
            src.push_str(row);
        }
        src.push_str("};\n");
        let findings = run_decorative(src.as_bytes(), Language::C);
        assert!(
            findings.is_empty(),
            "column-aligned data table must not fire: {:?}",
            findings
        );
    }

    #[test]
    fn decorative_layout_skipped_below_min_lines() {
        // Only 10 lines — below DECORATIVE_MIN_FILE_LINES (20).
        let mut src = String::new();
        for _ in 0..10 {
            src.push_str("x    =    1;\n");
        }
        let findings = run_decorative(src.as_bytes(), Language::C);
        assert!(findings.is_empty());
    }

    #[test]
    fn decorative_layout_skipped_at_low_fraction() {
        // 30 lines but only 4 decorative — under 30%.
        let mut src = String::new();
        for _ in 0..4 {
            src.push_str("x    =    1;\n");
        }
        for _ in 0..26 {
            src.push_str("int a = 0;\n");
        }
        let findings = run_decorative(src.as_bytes(), Language::C);
        assert!(findings.is_empty());
    }

    #[test]
    fn decorative_layout_ignores_runs_inside_string_literals() {
        // 25 lines whose ≥4-space runs lie entirely inside string literals.
        let mut src = String::new();
        for _ in 0..25 {
            src.push_str("char *s = \"a    b    c\";\n");
        }
        let findings = run_decorative(src.as_bytes(), Language::C);
        assert!(
            findings.is_empty(),
            "string-literal whitespace must not count: {:?}",
            findings
        );
    }

    #[test]
    fn decorative_layout_ignores_leading_indent() {
        // 25 lines with deep leading indent but no internal runs.
        let mut src = String::new();
        for _ in 0..25 {
            src.push_str("                int a = 0;\n");
        }
        let findings = run_decorative(src.as_bytes(), Language::C);
        assert!(findings.is_empty());
    }

    #[test]
    fn decorative_layout_skipped_for_non_c() {
        let mut src = String::new();
        for _ in 0..25 {
            src.push_str("x    =    1\n");
        }
        for lang in [Language::Python, Language::Rust, Language::JavaScript] {
            let findings = run_decorative(src.as_bytes(), lang);
            assert!(
                findings.is_empty(),
                "WhitespaceAnomaly (decorative) must only fire for C, fired for {:?}",
                lang
            );
        }
    }

    // --- line continuation in code detection ---

    fn run_line_cont(src: &[u8], lang: Language) -> Vec<Finding> {
        let idx = LineIndex::new(src);
        let tokens = tokenize(src, lang);
        emit_line_continuation_findings(&PathBuf::from("test.c"), src, &idx, lang, &tokens)
    }

    #[test]
    fn line_continuation_in_expression_is_warn() {
        let src = b"int main(){int x = 1 + \\\n2; return x;}\n";
        let findings = run_line_cont(src, Language::C);
        let hit = findings
            .iter()
            .find(|f| f.kind == SignalKind::LineContinuationInCode)
            .expect("expected LineContinuationInCode for `\\<nl>` in expression");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn line_continuation_inside_define_does_not_fire() {
        let src = b"#define FOO(x) \\\n  ((x) + 1)\nint y;\n";
        let findings = run_line_cont(src, Language::C);
        assert!(
            findings.is_empty(),
            "`\\<nl>` inside #define must not fire: {:?}",
            findings
        );
    }

    #[test]
    fn line_continuation_inside_string_does_not_fire() {
        let src = b"const char *s = \"line1 \\\nline2\";\n";
        let findings = run_line_cont(src, Language::C);
        assert!(
            findings.is_empty(),
            "`\\<nl>` inside string literal must not fire: {:?}",
            findings
        );
    }

    #[test]
    fn line_continuation_skipped_for_non_c() {
        let src = b"x = 1 + \\\n2\n";
        for lang in [Language::Python, Language::Rust, Language::JavaScript] {
            let findings = run_line_cont(src, lang);
            assert!(
                findings.is_empty(),
                "LineContinuationInCode must only fire for C, fired for {:?}",
                lang
            );
        }
    }

    #[test]
    fn token_at_finds_enclosing_span() {
        let toks = vec![
            Token {
                kind: TokenKind::Identifier,
                start: 0,
                end: 3,
                content_start: 0,
                content_end: 3,
            },
            Token {
                kind: TokenKind::StringLiteral,
                start: 6,
                end: 15,
                content_start: 7,
                content_end: 14,
            },
        ];
        assert_eq!(
            token_at(&toks, 1).map(|t| t.kind),
            Some(TokenKind::Identifier)
        );
        assert!(token_at(&toks, 3).is_none());
        assert_eq!(
            token_at(&toks, 10).map(|t| t.kind),
            Some(TokenKind::StringLiteral)
        );
        assert!(token_at(&toks, 100).is_none());
    }
}
