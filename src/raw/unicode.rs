//! Unicode-level anomalies detected on raw source bytes.
//!
//! Operates on decoded UTF-8 codepoints but records *byte* offsets into the
//! original file, never char offsets. The file is decoded once; byte offsets
//! come straight from `char_indices`.

use std::path::Path;

use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

pub fn analyze(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    findings.extend(scan_bidi_and_zero_width(path, bytes, text, index));
    findings.extend(scan_identifiers(path, bytes, text, index));
    findings
}

// ---------------------------------------------------------------------------
// Bidi and zero-width scan (per codepoint)
// ---------------------------------------------------------------------------

fn is_bidi_control(c: char) -> bool {
    matches!(
        c as u32,
        0x202A | 0x202B | 0x202C | 0x202D | 0x202E | 0x2066 | 0x2067 | 0x2068 | 0x2069
    )
}

fn is_zero_width(c: char) -> bool {
    matches!(c as u32, 0x200B | 0x200C | 0x200D | 0xFEFF | 0x00AD)
}

fn bidi_name(c: char) -> &'static str {
    match c as u32 {
        0x202A => "U+202A LEFT-TO-RIGHT EMBEDDING",
        0x202B => "U+202B RIGHT-TO-LEFT EMBEDDING",
        0x202C => "U+202C POP DIRECTIONAL FORMATTING",
        0x202D => "U+202D LEFT-TO-RIGHT OVERRIDE",
        0x202E => "U+202E RIGHT-TO-LEFT OVERRIDE",
        0x2066 => "U+2066 LEFT-TO-RIGHT ISOLATE",
        0x2067 => "U+2067 RIGHT-TO-LEFT ISOLATE",
        0x2068 => "U+2068 FIRST STRONG ISOLATE",
        0x2069 => "U+2069 POP DIRECTIONAL ISOLATE",
        _ => "bidi control",
    }
}

fn zero_width_name(c: char) -> &'static str {
    match c as u32 {
        0x200B => "U+200B ZERO WIDTH SPACE",
        0x200C => "U+200C ZERO WIDTH NON-JOINER",
        0x200D => "U+200D ZERO WIDTH JOINER",
        0xFEFF => "U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)",
        0x00AD => "U+00AD SOFT HYPHEN",
        _ => "zero-width",
    }
}

fn scan_bidi_and_zero_width(
    path: &Path,
    bytes: &[u8],
    text: &str,
    index: &LineIndex,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (offset, c) in text.char_indices() {
        // BOM at start of file is common and not worth flagging on its own.
        if c as u32 == 0xFEFF && offset == 0 {
            continue;
        }
        if is_bidi_control(c) {
            let (line, col) = index.locate(offset);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: offset,
                line,
                col,
                pass: PassKind::Raw,
                kind: SignalKind::UnicodeBidi,
                severity: Severity::Critical,
                confidence: 0.98,
                message: format!("{} in source", bidi_name(c)),
                snippet: redact_snippet(&snippet_around(bytes, offset, 80)),
                diff_introduced: false,
            });
        } else if is_zero_width(c) {
            let (line, col) = index.locate(offset);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: offset,
                line,
                col,
                pass: PassKind::Raw,
                kind: SignalKind::UnicodeZeroWidth,
                severity: Severity::Warn,
                confidence: 0.75,
                message: format!("{} in source", zero_width_name(c)),
                snippet: redact_snippet(&snippet_around(bytes, offset, 80)),
                diff_introduced: false,
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Identifier-level checks: mixed-script and homoglyph candidates
// ---------------------------------------------------------------------------

/// Coarse Unicode-script bucketing for the letter categories that actually
/// appear in source-code identifiers. Deliberately narrow: we care about
/// spotting mixed-script identifiers in programming contexts, not faithful
/// ISO 15924 coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Armenian,
    Hebrew,
    Arabic,
    Han,
    Hiragana,
    Katakana,
    Hangul,
    Other,
}

fn script_of(c: char) -> Option<Script> {
    if !c.is_alphabetic() {
        return None;
    }
    let cp = c as u32;
    let s = match cp {
        0x0041..=0x005A | 0x0061..=0x007A => Script::Latin,
        0x00C0..=0x024F | 0x1E00..=0x1EFF => Script::Latin, // Latin Supplement + Extended
        0x0370..=0x03FF | 0x1F00..=0x1FFF => Script::Greek,
        0x0400..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => Script::Cyrillic,
        0x0530..=0x058F => Script::Armenian,
        0x0590..=0x05FF => Script::Hebrew,
        0x0600..=0x06FF | 0x0750..=0x077F => Script::Arabic,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF => Script::Han,
        0x3040..=0x309F => Script::Hiragana,
        0x30A0..=0x30FF => Script::Katakana,
        0xAC00..=0xD7AF | 0x1100..=0x11FF => Script::Hangul,
        _ => Script::Other,
    };
    Some(s)
}

/// Small hand-curated table of the homoglyphs most commonly abused in
/// identifier spoofing attacks. Each entry: `(confusing codepoint, ASCII it
/// mimics)`.
const HOMOGLYPHS: &[(u32, char)] = &[
    // Cyrillic lowercase
    (0x0430, 'a'),
    (0x0435, 'e'),
    (0x043E, 'o'),
    (0x0440, 'p'),
    (0x0441, 'c'),
    (0x0443, 'y'),
    (0x0445, 'x'),
    (0x0456, 'i'),
    // Cyrillic uppercase
    (0x0410, 'A'),
    (0x0415, 'E'),
    (0x041E, 'O'),
    (0x0420, 'P'),
    (0x0421, 'C'),
    (0x0422, 'T'),
    (0x0425, 'X'),
    (0x041A, 'K'),
    (0x041C, 'M'),
    (0x041D, 'H'),
    (0x0412, 'B'),
    // Greek
    (0x03BF, 'o'),
    (0x03B1, 'a'),
    (0x03C1, 'p'),
    (0x03BD, 'v'),
    (0x03BA, 'k'),
    (0x03B7, 'n'),
    (0x0391, 'A'),
    (0x0392, 'B'),
    (0x0395, 'E'),
    (0x0397, 'H'),
    (0x039A, 'K'),
    (0x039C, 'M'),
    (0x039D, 'N'),
    (0x039F, 'O'),
    (0x03A1, 'P'),
    (0x03A4, 'T'),
    (0x03A7, 'X'),
    (0x03A5, 'Y'),
    (0x03A2, 'Z'),
];

fn homoglyph_of(c: char) -> Option<char> {
    let cp = c as u32;
    HOMOGLYPHS
        .iter()
        .find_map(|&(src, dst)| if src == cp { Some(dst) } else { None })
}

/// An identifier-like run in raw bytes: a maximal sequence of letters, digits,
/// and underscores starting with a letter or underscore. This is a coarse
/// approximation used for raw-pass script/homoglyph checks; the token pass
/// will eventually refine with per-language tokenizers.
fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn is_ident_cont(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

fn scan_identifiers(path: &Path, bytes: &[u8], text: &str, index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut chars = text.char_indices().peekable();

    while let Some(&(offset, c)) = chars.peek() {
        if !is_ident_start(c) {
            chars.next();
            continue;
        }
        let start = offset;
        let mut last_end = offset + c.len_utf8();
        chars.next();
        while let Some(&(o, nc)) = chars.peek() {
            if is_ident_cont(nc) {
                last_end = o + nc.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        let ident = &text[start..last_end];
        // Skip pure-ASCII identifiers — vast majority of source — early out.
        if ident.is_ascii() {
            continue;
        }
        findings.extend(check_identifier(path, bytes, index, ident, start));
    }

    findings
}

fn check_identifier(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    ident: &str,
    start: usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Mixed script
    let mut scripts = std::collections::HashSet::new();
    for c in ident.chars() {
        if let Some(s) = script_of(c) {
            scripts.insert(s);
        }
    }
    if scripts.len() > 1 {
        let (line, col) = index.locate(start);
        let scripts_list: Vec<_> = scripts.iter().map(|s| format!("{:?}", s)).collect();
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: start,
            line,
            col,
            pass: PassKind::Raw,
            kind: SignalKind::UnicodeMixedScript,
            severity: Severity::Warn,
            confidence: 0.80,
            message: format!(
                "identifier `{}` mixes scripts: {}",
                ident,
                scripts_list.join(" + ")
            ),
            snippet: redact_snippet(&snippet_around(bytes, start, 80)),
            diff_introduced: false,
        });
    }

    // Homoglyph candidates
    let mut hits: Vec<(char, char)> = Vec::new();
    for c in ident.chars() {
        if let Some(ascii) = homoglyph_of(c) {
            hits.push((c, ascii));
        }
    }
    if !hits.is_empty() {
        let (line, col) = index.locate(start);
        let shown: Vec<_> = hits
            .iter()
            .take(4)
            .map(|(c, ascii)| format!("{} ({:04X})→{}", c, *c as u32, ascii))
            .collect();
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: start,
            line,
            col,
            pass: PassKind::Raw,
            kind: SignalKind::UnicodeHomoglyph,
            severity: Severity::Warn,
            confidence: 0.70,
            message: format!(
                "identifier `{}` contains homoglyph candidates: {}",
                ident,
                shown.join(", ")
            ),
            snippet: redact_snippet(&snippet_around(bytes, start, 80)),
            diff_introduced: false,
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(src: &[u8]) -> Vec<Finding> {
        let idx = LineIndex::new(src);
        analyze(&PathBuf::from("test.py"), src, &idx)
    }

    #[test]
    fn flags_bidi_override() {
        let src = "x = 1  # \u{202E}override\n".as_bytes();
        let findings = run(src);
        assert!(findings.iter().any(|f| f.kind == SignalKind::UnicodeBidi));
    }

    #[test]
    fn flags_zero_width_space() {
        let src = "var\u{200B}able = 1\n".as_bytes();
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::UnicodeZeroWidth));
    }

    #[test]
    fn flags_cyrillic_homoglyph_in_identifier() {
        // "раssword" where р is Cyrillic (U+0440) and а is Cyrillic (U+0430)
        let src = "\u{0440}\u{0430}ssword = 1\n".as_bytes();
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::UnicodeHomoglyph));
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::UnicodeMixedScript));
    }

    #[test]
    fn ignores_pure_ascii_identifiers() {
        let src = b"password = 1\n";
        let findings = run(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn skips_leading_bom() {
        let src = "\u{FEFF}x = 1\n".as_bytes();
        let findings = run(src);
        assert!(findings.is_empty());
    }
}
