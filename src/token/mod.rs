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
    findings
}

fn tokenize(bytes: &[u8], lang: Language) -> Vec<Token> {
    match lang {
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
                SignalKind::UnicodeZeroWidth => {
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

    // File-level low-mean-length signal. Require a minimum sample size so we
    // don't flag small one-off scripts.
    if ident_lengths.len() >= 20 {
        let mean = ident_lengths.iter().sum::<usize>() as f32 / ident_lengths.len() as f32;
        if mean < 2.0 {
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
                message: format!(
                    "mean non-conventional identifier length {:.2} over {} names",
                    mean,
                    ident_lengths.len()
                ),
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
