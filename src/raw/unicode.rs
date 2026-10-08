//! Unicode-level anomalies detected on raw source bytes.
//!
//! Operates on decoded UTF-8 codepoints but records *byte* offsets into the
//! original file, never char offsets. The file is decoded once; byte offsets
//! come straight from `char_indices`.

use std::collections::HashMap;
use std::path::Path;

use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

pub fn analyze(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    findings.extend(scan_bidi_and_zero_width(path, bytes, text, index));
    findings.extend(scan_tag_chars(path, bytes, text, index));
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

/// Emoji and pictographs, the parts a ZWJ joins into one emoji (an
/// approximation of `Extended_Pictographic`, which includes the skin-tone
/// modifiers U+1F3FB–1F3FF).
fn is_pictographic(c: char) -> bool {
    matches!(
        c as u32,
        0x00A9 | 0x00AE | 0x203C | 0x2049 | 0x2122 | 0x2139
            | 0x2194..=0x21AA | 0x231A..=0x23FF | 0x24C2 | 0x25AA..=0x25FE
            | 0x2600..=0x27BF | 0x2934 | 0x2935 | 0x2B05..=0x2B55
            | 0x3030 | 0x303D | 0x3297 | 0x3299 | 0x1F000..=0x1FAFF
    )
}

/// A ZWJ between two pictographs (after an optional U+FE0F emoji-style
/// selector): an emoji ZWJ sequence such as 👨‍👩‍👧‍👦 or 👩‍💻, where the joiner is
/// how the emoji is written, not something hidden.
fn is_emoji_zwj(text: &str, offset: usize) -> bool {
    let before = text[..offset].chars().rev().find(|&c| c != '\u{FE0F}');
    let after = text[offset + '\u{200D}'.len_utf8()..].chars().next();
    before.is_some_and(is_pictographic) && after.is_some_and(is_pictographic)
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
        } else if is_zero_width(c) && !(c == '\u{200D}' && is_emoji_zwj(text, offset)) {
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
// Invisible Unicode character scan
// ---------------------------------------------------------------------------
//
// Three related families of invisible characters are used for payload smuggling
// in source code:
//
//   * Tags block (U+E0001, U+E0020–U+E007F) — invisible tag variants of ASCII.
//     Used in IOCCC 2024 "salmon" and similar obfuscations.
//
//   * Variation Selectors (U+FE00–U+FE0F) — 16 selectors for glyph variants.
//     No visual rendering in source; exploited by glassworm-style attacks to
//     encode nibbles 0–15.
//
//   * Variation Selectors Supplement (U+E0100–U+E01EF) — 240 selectors.
//     Each encodes one byte (value = cp − 0xE0100 + 16) in the glassworm
//     technique, making an entirely invisible payload inside a string literal.

fn is_tag_char(c: char) -> bool {
    let cp = c as u32;
    // Tags block
    cp == 0xE0001
        || matches!(cp, 0xE0020..=0xE007F)
        // Variation Selectors (FE00-FE0F): no legitimate use in source code
        || matches!(cp, 0xFE00..=0xFE0F)
        // Variation Selectors Supplement (E0100-E01EF): glassworm payload carriers
        || matches!(cp, 0xE0100..=0xE01EF)
}

fn tag_char_name(c: char) -> String {
    let cp = c as u32;
    match cp {
        0xE0001 => "U+E0001 LANGUAGE TAG".to_string(),
        0xE007F => "U+E007F CANCEL TAG".to_string(),
        0xE0020..=0xE007E => {
            let ascii = (cp - 0xE0000) as u8 as char;
            format!("U+{:05X} TAG {:?}", cp, ascii)
        }
        0xFE00..=0xFE0F => {
            format!(
                "U+{:04X} VARIATION SELECTOR-{} (invisible payload carrier)",
                cp,
                cp - 0xFE00 + 1
            )
        }
        0xE0100..=0xE01EF => {
            format!("U+{:05X} VARIATION SELECTOR SUPPLEMENT (invisible payload carrier, encodes byte 0x{:02X})", cp, cp - 0xE0100 + 16)
        }
        _ => format!("U+{:05X} invisible tag character", cp),
    }
}

/// Attempt to decode a sequence of invisible tag/VS codepoints back to bytes.
///
/// * Tags block (E0020-E007F): byte = cp - 0xE0000
/// * Variation Selectors (FE00-FE0F): byte = cp - 0xFE00 (nibbles 0-15)
/// * Variation Selectors Supplement (E0100-E01EF): byte = cp - 0xE0100 + 16
///
/// Returns the decoded UTF-8 string if all codepoints are decodable and the
/// result is valid UTF-8; otherwise returns None.
fn try_decode_invisible_payload(chars: &[char]) -> Option<String> {
    let mut bytes = Vec::with_capacity(chars.len());
    for &c in chars {
        let cp = c as u32;
        if matches!(cp, 0xFE00..=0xFE0F) {
            bytes.push((cp - 0xFE00) as u8);
        } else if matches!(cp, 0xE0100..=0xE01EF) {
            bytes.push((cp - 0xE0100 + 16) as u8);
        } else if matches!(cp, 0xE0020..=0xE007F) {
            bytes.push((cp - 0xE0000) as u8);
        } else {
            return None;
        }
    }
    String::from_utf8(bytes).ok()
}

/// When ≥ this many invisible tag characters appear on the same source line,
/// aggregate them into a single CRITICAL finding instead of per-char warnings.
const INVISIBLE_CLUSTER_THRESHOLD: usize = 4;

fn scan_tag_chars(path: &Path, bytes: &[u8], text: &str, index: &LineIndex) -> Vec<Finding> {
    // Group (offset, col, char) tuples by line.
    let mut by_line: HashMap<usize, Vec<(usize, usize, char)>> = HashMap::new();
    for (offset, c) in text.char_indices() {
        if is_tag_char(c) {
            let (line, col) = index.locate(offset);
            by_line.entry(line).or_default().push((offset, col, c));
        }
    }

    let mut lines: Vec<usize> = by_line.keys().copied().collect();
    lines.sort_unstable();

    let mut findings = Vec::new();
    for line in lines {
        let chars = &by_line[&line];
        if chars.len() >= INVISIBLE_CLUSTER_THRESHOLD {
            // Aggregate into one CRITICAL finding, decoding the payload if possible.
            let (first_offset, first_col, _) = chars[0];
            let raw_chars: Vec<char> = chars.iter().map(|(_, _, c)| *c).collect();
            let message = match try_decode_invisible_payload(&raw_chars) {
                Some(decoded) => format!(
                    "{} invisible characters encode hidden payload: {:?}",
                    chars.len(),
                    decoded
                ),
                None => format!(
                    "{} invisible tag characters on this line (possible encoded payload)",
                    chars.len()
                ),
            };
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: first_offset,
                line,
                col: first_col,
                pass: PassKind::Raw,
                kind: SignalKind::UnicodeInvisible,
                severity: Severity::Critical,
                confidence: 0.99,
                message,
                snippet: redact_snippet(&snippet_around(bytes, first_offset, 80)),
                diff_introduced: false,
            });
        } else {
            for (offset, col, c) in chars {
                findings.push(Finding {
                    path: path.to_path_buf(),
                    byte_offset: *offset,
                    line,
                    col: *col,
                    pass: PassKind::Raw,
                    kind: SignalKind::UnicodeInvisible,
                    severity: Severity::Warn,
                    confidence: 0.90,
                    message: format!("{} in source", tag_char_name(*c)),
                    snippet: redact_snippet(&snippet_around(bytes, *offset, 80)),
                    diff_introduced: false,
                });
            }
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
        // Latin-1 Supplement letter-property stragglers that sit below the
        // main accented range: U+00AA (feminine ordinal), U+00B5 (micro
        // sign — universally used in scientific code as µs / µm / µF),
        // U+00BA (masculine ordinal). All are Latin-context.
        0x00AA | 0x00B5 | 0x00BA => Script::Latin,
        0x00C0..=0x024F | 0x1E00..=0x1EFF => Script::Latin, // Latin Supplement + Extended
        // U+03BC GREEK SMALL LETTER MU is overwhelmingly used as the
        // scientific "micro" prefix (numpy dtypes like `timedelta64[μs]`,
        // units like `μm`, `μg`). No Latin homoglyph partner, so not a
        // spoofing risk. Classify as Latin for script-mixing purposes.
        0x03BC => Script::Latin,
        0x0370..=0x03FF | 0x1F00..=0x1FFF => Script::Greek,
        0x0400..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => Script::Cyrillic,
        0x0530..=0x058F => Script::Armenian,
        0x0590..=0x05FF => Script::Hebrew,
        0x0600..=0x06FF | 0x0750..=0x077F => Script::Arabic,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF => Script::Han,
        0x3040..=0x309F => Script::Hiragana,
        0x30A0..=0x30FF => Script::Katakana,
        // Fullwidth Latin letters and halfwidth katakana, as typed in
        // Chinese and Japanese text (`你的ＧＵＴＳ`).
        0xFF21..=0xFF3A | 0xFF41..=0xFF5A => Script::Latin,
        0xFF66..=0xFF9F => Script::Katakana,
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

/// Script mixes that are ordinary writing, per UTS #39's "Highly
/// Restrictive" level: Chinese and Japanese (Han with kana, and Latin for
/// acronyms and brand names, as in `你当选MVP了`) and Korean (Han, Hangul,
/// Latin). None of those scripts has Latin lookalikes. Every other mix,
/// Latin with Cyrillic or Greek above all, is reported.
fn is_customary_script_mix(scripts: &[Script]) -> bool {
    use Script::*;
    let within = |set: &[Script]| scripts.iter().all(|s| set.contains(s));
    within(&[Latin, Han, Hiragana, Katakana]) || within(&[Latin, Han, Hangul])
}

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

/// A script making up at least this share of a file's letters means the file
/// is substantially written in it (a Russian document, a Greek locale file):
/// words wholly in that script are its language, not lookalike spoofs.
const WRITTEN_IN_SCRIPT_SHARE: f32 = 0.30;

/// Letters per script across a file, for judging whether a word in some
/// script is ordinary text or stands out.
struct ScriptShares {
    counts: std::collections::HashMap<Script, usize>,
    total: usize,
}

impl ScriptShares {
    fn of(text: &str) -> Self {
        let mut counts = std::collections::HashMap::new();
        let mut total = 0;
        for s in text.chars().filter_map(script_of) {
            *counts.entry(s).or_insert(0) += 1;
            total += 1;
        }
        ScriptShares { counts, total }
    }

    fn share(&self, s: Script) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        *self.counts.get(&s).unwrap_or(&0) as f32 / self.total as f32
    }
}

/// True if the byte at `offset` follows an odd run of backslashes: escaped,
/// as in `\n`, but not in `\\n` (an escaped backslash, then `n`).
fn is_escaped(bytes: &[u8], offset: usize) -> bool {
    bytes[..offset]
        .iter()
        .rev()
        .take_while(|&&b| b == b'\\')
        .count()
        % 2
        == 1
}

fn scan_identifiers(path: &Path, bytes: &[u8], text: &str, index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Counted lazily: only files with a non-ASCII identifier need it.
    let mut shares: Option<ScriptShares> = None;
    let mut chars = text.char_indices().peekable();

    while let Some(&(offset, c)) = chars.peek() {
        if !is_ident_start(c) {
            chars.next();
            continue;
        }
        // The letter of an escape (`\n`, `\t`, `\u…`) is not the start of a
        // word: in `'நி\nநி'` the `n` would otherwise join the Tamil after it
        // as a Latin + Tamil "identifier".
        if c.is_ascii_alphabetic() && is_escaped(text.as_bytes(), offset) {
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
        let shares = shares.get_or_insert_with(|| ScriptShares::of(text));
        findings.extend(check_identifier(path, bytes, index, ident, start, shares));
    }

    findings
}

fn check_identifier(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    ident: &str,
    start: usize,
    shares: &ScriptShares,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Mixed script
    // In order of first appearance, so the message is the same every run.
    let mut scripts: Vec<Script> = Vec::new();
    for c in ident.chars() {
        if let Some(s) = script_of(c) {
            if !scripts.contains(&s) {
                scripts.push(s);
            }
        }
    }
    if scripts.len() > 1 && !is_customary_script_mix(&scripts) {
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

    // Homoglyph candidates. A lookalike letter alone is not a spoof: most
    // Russian words contain `о` or `е`. It is one when the word could be
    // mistaken for a Latin one, either
    //   * mixed: Latin letters with lookalikes swapped in (`pаypal`), or
    //   * whole-script: every letter has a Latin lookalike (`сор`, a lone
    //     Cyrillic `с`), in a file not itself written in that script, so the
    //     word stands out (a Cyrillic `с` as a variable in Python code, not
    //     the word "с" in Russian prose).
    let mut hits: Vec<(char, char)> = Vec::new();
    for c in ident.chars() {
        if let Some(ascii) = homoglyph_of(c) {
            hits.push((c, ascii));
        }
    }
    let letters: Vec<char> = ident.chars().filter(|c| c.is_alphabetic()).collect();
    let has_latin = letters.iter().any(|&c| script_of(c) == Some(Script::Latin));
    let whole_script = !letters.is_empty() && letters.iter().all(|&c| homoglyph_of(c).is_some());
    let stands_out = hits
        .first()
        .and_then(|&(c, _)| script_of(c))
        .is_some_and(|s| shares.share(s) < WRITTEN_IN_SCRIPT_SHARE);
    let spoof = !hits.is_empty() && (has_latin || (whole_script && stands_out));
    if spoof {
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
    fn flags_tag_char_in_code() {
        // U+E0041 TAG LATIN CAPITAL LETTER A embedded in an identifier.
        let src = "let x\u{E0041} = 1;\n".as_bytes();
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::UnicodeInvisible),
            "expected UnicodeInvisible for tag char in identifier"
        );
    }

    #[test]
    fn flags_language_tag_char() {
        // U+E0001 LANGUAGE TAG.
        let src = "fn foo\u{E0001}() {}\n".as_bytes();
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::UnicodeInvisible),
            "expected UnicodeInvisible for U+E0001 language tag"
        );
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
    fn ordinary_words_in_another_script_are_not_homoglyphs() {
        let homoglyphs = |src: &str| {
            run(src.as_bytes())
                .into_iter()
                .filter(|f| f.kind == SignalKind::UnicodeHomoglyph)
                .map(|f| f.message)
                .collect::<Vec<_>>()
        };
        // memchr's Russian subtitle corpus: words with non-lookalike letters
        // (`было`, `не`) are just Russian, and in a Russian document even
        // all-lookalike words (`с`, `А`, `сор`) are its language.
        assert!(homoglyphs("Было не так. А что с ним? Сор и пыль.\n").is_empty());
        // In Latin code, a variable written entirely in lookalikes stands out.
        let code = "def total(items):\n    \u{0441} = 0\n    for item in items:\n        \u{0441} += item.price\n    return \u{0441}\n";
        assert_eq!(homoglyphs(code).len(), 3, "{:?}", homoglyphs(code));
        // A Russian comment in Latin code: ordinary words still aren't spoofs.
        assert!(homoglyphs("x = compute(values)  # было много значений\n").is_empty());
    }

    #[test]
    fn cjk_writing_with_latin_is_not_mixed_script() {
        let mixed = |src: &str| {
            run(src.as_bytes())
                .into_iter()
                .filter(|f| f.kind == SignalKind::UnicodeMixedScript)
                .map(|f| f.message)
                .collect::<Vec<_>>()
        };
        // memchr's Chinese subtitles, Japanese, Korean: ordinary writing.
        for ok in [
            "你当选MVP了\n",
            "你的ＧＵＴＳ去哪里了\n",
            "日本語のテキストとAPI\n",
            "한국어API문서\n",
        ] {
            assert!(mixed(ok).is_empty(), "{ok}: {:?}", mixed(ok));
        }
        // Lookalike-bearing mixes, and mixes outside one writing system.
        for (bad, scripts) in [
            ("\u{0440}\u{0430}ssword = 1\n", "Cyrillic + Latin"),
            ("abcd\u{03B1}\u{03B2}\n", "Latin + Greek"),
            ("\u{0411}\u{043E}r\n", "Cyrillic + Latin"),
            ("\u{4E2D}\u{D55C}\u{306E}\n", "Han + Hangul + Hiragana"),
            ("\u{0E44}\u{0E17}\u{4E2D}\n", "Other + Han"),
        ] {
            assert_eq!(mixed(bad).len(), 1, "{bad}");
            assert!(mixed(bad)[0].ends_with(scripts), "{:?}", mixed(bad));
        }
    }

    #[test]
    fn mixed_script_message_is_stable() {
        let src = "let s = \"ศไทย中华Việt\";\n";
        let messages: std::collections::HashSet<String> = (0..20)
            .flat_map(|_| run(src.as_bytes()))
            .filter(|f| f.kind == SignalKind::UnicodeMixedScript)
            .map(|f| f.message)
            .collect();
        assert_eq!(
            messages.into_iter().collect::<Vec<_>>(),
            ["identifier `ศไทย中华Việt` mixes scripts: Other + Han + Latin"]
        );
    }

    #[test]
    fn zwj_inside_an_emoji_sequence_is_not_hidden() {
        let zero_width = |src: &str| {
            run(src.as_bytes())
                .into_iter()
                .filter(|f| f.kind == SignalKind::UnicodeZeroWidth)
                .count()
        };
        // wrap-ansi's test: family, plus a profession and a flag (🏳️‍🌈 has
        // U+FE0F before its joiner).
        for emoji in [
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}",
            "\u{1F469}\u{1F3FD}\u{200D}\u{1F4BB}",
            "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}",
        ] {
            assert_eq!(zero_width(&format!("s = '{emoji}'\n")), 0, "{emoji:?}");
        }
        // A joiner between letters, or at an emoji's edge, is still hidden.
        assert_eq!(zero_width("pass\u{200D}word = 1\n"), 1);
        assert_eq!(zero_width("s = '\u{1F600}\u{200D}a'\n"), 1);
        assert_eq!(zero_width("s = 'a\u{200D}\u{1F600}'\n"), 1);
    }

    #[test]
    fn escape_letters_do_not_join_the_next_word() {
        let mixed = |src: &str| {
            run(src.as_bytes())
                .into_iter()
                .filter(|f| f.kind == SignalKind::UnicodeMixedScript)
                .map(|f| f.message)
                .collect::<Vec<_>>()
        };
        // wrap-ansi: Tamil around a `\n` escape.
        assert!(mixed("s = '\u{0BA8}\u{0BBF}\\n\u{0BA8}\u{0BBF}'\n").is_empty());
        assert!(mixed("s = '\\t\u{0430}\u{0431}'\n").is_empty());
        // After an escaped backslash, `n` is a real letter again.
        assert_eq!(mixed("s = '\\\\n\u{0430}\u{0431}'\n").len(), 1);
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

    #[test]
    fn micro_sign_is_latin_not_mixed_script() {
        // `µs` (U+00B5 + s) — scientific "microseconds" shorthand.
        let src = "label = \"\u{00B5}s\"\n".as_bytes();
        let findings = run(src);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::UnicodeMixedScript),
            "µs should not be mixed-script: {:?}",
            findings
        );
    }

    #[test]
    fn greek_mu_is_latin_not_mixed_script() {
        // `μs` with U+03BC — numpy-style dtype `timedelta64[μs]`.
        let src = "dt = \"\u{03BC}s\"\n".as_bytes();
        let findings = run(src);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::UnicodeMixedScript),
            "Greek mu as micro prefix should not be mixed-script: {:?}",
            findings
        );
    }

    #[test]
    fn other_greek_letters_still_mix() {
        // Real Greek-plus-Latin should still trigger — only μ is exempted.
        let src = "var\u{03B1}lpha = 1\n".as_bytes();
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::UnicodeMixedScript),
            "Greek alpha + Latin should still be mixed-script: {:?}",
            findings
        );
    }

    #[test]
    fn ordinal_indicators_are_latin() {
        // U+00AA + U+00BA — feminine/masculine ordinals used alongside Latin.
        let src = "x = \"1\u{00AA} y 2\u{00BA}z\"\n".as_bytes();
        let findings = run(src);
        assert!(
            findings
                .iter()
                .all(|f| f.kind != SignalKind::UnicodeMixedScript),
            "ordinal indicators should not be mixed-script: {:?}",
            findings
        );
    }
}
