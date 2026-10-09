//! Structural anomalies — line length, indentation whitespace, tab/space mix.

use std::path::Path;

use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::language::Language;
use crate::util::{snippet_around, LineIndex};

const LONG_LINE_INFO: usize = 500;
const LONG_LINE_WARN: usize = 2000;

pub fn analyze(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    analyze_lang(path, bytes, index, None)
}

/// [`analyze`] for a file of known language. Mixed tab/space indentation is
/// reported where indentation is syntax ([`indentation_is_syntax`]) or where
/// one style is near-universal ([`indentation_has_one_convention`]); with
/// `None` (language unknown) it is always reported.
pub fn analyze_lang(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Option<Language>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(scan_long_lines(path, bytes, index));
    findings.extend(scan_indent_whitespace(path, bytes, index));
    match lang {
        None => findings.extend(scan_mixed_indent(path, bytes, index, false)),
        Some(l) if indentation_is_syntax(l) => {
            findings.extend(scan_mixed_indent(path, bytes, index, false))
        }
        Some(l) if indentation_has_one_convention(l) => {
            findings.extend(scan_mixed_indent(path, bytes, index, true))
        }
        Some(_) => {}
    }
    findings.extend(scan_narrow_charset(path, bytes));
    findings
}

/// Languages where mixing tabs and spaces in indentation can change meaning:
/// Python (a block can look nested differently from how it runs) and YAML
/// (tabs are not valid indentation). Elsewhere it is a style choice: tabs to
/// indent and spaces to align in C, prose layout in reStructuredText and
/// Markdown, `<<-` heredocs in shell.
pub fn indentation_is_syntax(lang: Language) -> bool {
    matches!(lang, Language::Python | Language::Yaml)
}

/// Languages whose formatters make one indentation style near-universal
/// (rustfmt for Rust, Prettier for JavaScript and TypeScript, both spaces),
/// so a file that mixes styles may hold code edited apart from the rest. A
/// weaker signal than in Python; C is excluded, where tabs to indent and
/// spaces to align is a common deliberate style.
pub fn indentation_has_one_convention(lang: Language) -> bool {
    matches!(
        lang,
        Language::Rust | Language::JavaScript | Language::TypeScript
    )
}

// ---------------------------------------------------------------------------
// Long lines
// ---------------------------------------------------------------------------

/// Lines within this many of a long line are its neighbourhood: wide enough
/// for records that alternate long and short lines (NIST test vectors:
/// `P = <hex>` then `counter = 1`).
const TABLE_NEIGHBOURS: usize = 10;
/// How many neighbours at least [`TABLE_SIMILAR`] as long make a long line
/// part of a layout or data block (a table's rows, a file of records), not
/// a line that stands out.
const TABLE_MIN_SIMILAR: usize = 3;
const TABLE_SIMILAR: f32 = 0.8;
/// A long line is ordinary for its file when other lines at least this share
/// of its length make up [`FILE_TYPICAL_FRACTION`] of the file's non-blank
/// lines (and number at least [`TABLE_MIN_SIMILAR`]): data files such as RSA
/// test vectors, where long hex lines are a tenth or more of the file. In
/// code a long line still stands out.
const FILE_TYPICAL_SHARE: f32 = 0.5;
const FILE_TYPICAL_FRACTION: f32 = 0.1;

fn scan_long_lines(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let _ = index; // long-line location is always (line_num, 1), don't need the index

    // (start byte, length in characters) per line. Characters, not bytes:
    // the signal is about width on screen, and Cyrillic or CJK text takes
    // two or three bytes a character.
    let mut lines = Vec::new();
    let mut texts: Vec<&[u8]> = Vec::new();
    let mut offset = 0usize;
    for line in bytes.split(|&b| b == b'\n') {
        let chars = match std::str::from_utf8(line) {
            Ok(text) => text.chars().count(),
            Err(_) => line.len(),
        };
        lines.push((offset, chars));
        texts.push(line);
        offset += line.len() + 1;
    }
    // Non-blank line lengths, sorted, to count lines at least so long.
    let mut sorted: Vec<usize> = lines.iter().map(|&(_, n)| n).filter(|&n| n > 0).collect();
    sorted.sort_unstable();
    let mut findings = Vec::new();
    for (i, &(line_start, len)) in lines.iter().enumerate() {
        if len > LONG_LINE_INFO
            && len <= LONG_LINE_WARN
            && (in_layout_block(&lines, i)
                || typical_for_file(&sorted, len)
                || (in_declaration_run(&texts, i) && !has_whitespace_gap(texts[i])))
        {
            continue;
        }
        emit_long_line(&mut findings, path, bytes, line_start, i + 1, len);
    }
    findings
}

/// Bytes two lines must share at their start to count as the same kind of
/// line: `windows_link::link!(`, whichever DLL follows.
const RUN_PREFIX: usize = 20;
/// A gap this wide after a line's first non-blank character is how code is
/// pushed past the right edge of the screen.
const WHITESPACE_GAP: usize = 16;

/// True if at least [`TABLE_MIN_SIMILAR`] lines within [`TABLE_NEIGHBOURS`]
/// start with the same [`RUN_PREFIX`] bytes as line `i`: one of a run of
/// generated declarations (windows-sys bindings), long because its
/// parameter list is, not because it hides something.
fn in_declaration_run(texts: &[&[u8]], i: usize) -> bool {
    let Some(prefix) = texts[i].get(..RUN_PREFIX) else {
        return false;
    };
    let lo = i.saturating_sub(TABLE_NEIGHBOURS);
    let hi = (i + TABLE_NEIGHBOURS).min(texts.len() - 1);
    (lo..=hi)
        .filter(|&j| j != i && texts[j].get(..RUN_PREFIX) == Some(prefix))
        .count()
        >= TABLE_MIN_SIMILAR
}

/// True if `line` has a run of [`WHITESPACE_GAP`] or more spaces or tabs
/// after its first non-blank character.
fn has_whitespace_gap(line: &[u8]) -> bool {
    let Some(start) = line.iter().position(|b| !matches!(b, b' ' | b'\t')) else {
        return false;
    };
    let mut run = 0;
    for &b in &line[start..] {
        run = if matches!(b, b' ' | b'\t') {
            run + 1
        } else {
            0
        };
        if run >= WHITESPACE_GAP {
            return true;
        }
    }
    false
}

/// True if enough of the file's other lines (`sorted`: non-blank lengths,
/// ascending, including this one) are at least half as long as `len`.
fn typical_for_file(sorted: &[usize], len: usize) -> bool {
    let floor = (FILE_TYPICAL_SHARE * len as f32).ceil() as usize;
    let others = sorted.len() - sorted.partition_point(|&n| n < floor) - 1;
    others >= TABLE_MIN_SIMILAR && others as f32 >= FILE_TYPICAL_FRACTION * sorted.len() as f32
}

/// True if enough lines around line `i` are nearly as long: the rows of a
/// padded table (pytest's plugin list) or a data file's records
/// (cryptography's test vectors) rather than one line that runs far past
/// the rest, as code hidden off the right edge of the screen does.
fn in_layout_block(lines: &[(usize, usize)], i: usize) -> bool {
    let len = lines[i].1 as f32;
    let lo = i.saturating_sub(TABLE_NEIGHBOURS);
    let hi = (i + TABLE_NEIGHBOURS).min(lines.len() - 1);
    (lo..=hi)
        .filter(|&j| j != i && lines[j].1 as f32 >= TABLE_SIMILAR * len)
        .count()
        >= TABLE_MIN_SIMILAR
}

fn emit_long_line(
    findings: &mut Vec<Finding>,
    path: &Path,
    bytes: &[u8],
    line_start: usize,
    line_num: usize,
    len: usize,
) {
    let (severity, confidence) = if len > LONG_LINE_WARN {
        (Severity::Warn, 0.65)
    } else if len > LONG_LINE_INFO {
        (Severity::Info, 0.50)
    } else {
        return;
    };
    findings.push(Finding {
        path: path.to_path_buf(),
        byte_offset: line_start,
        line: line_num,
        col: 1,
        pass: PassKind::Raw,
        kind: SignalKind::LongLine,
        severity,
        confidence,
        message: format!("line length {} characters", len),
        snippet: redact_snippet(&snippet_around(bytes, line_start, 80)),
        diff_introduced: false,
    });
}

// ---------------------------------------------------------------------------
// Invisible whitespace in indentation
// ---------------------------------------------------------------------------

fn is_invisible_indent(c: char) -> bool {
    // NBSP, EN QUAD .. HAIR SPACE, NARROW NBSP, MEDIUM MATH SPACE, IDEOGRAPHIC SPACE
    let cp = c as u32;
    cp == 0x00A0 || (0x2000..=0x200A).contains(&cp) || cp == 0x202F || cp == 0x205F || cp == 0x3000
}

fn scan_indent_whitespace(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let mut line_start = 0usize;
    for (byte_idx, c) in text.char_indices() {
        if c == '\n' {
            line_start = byte_idx + 1;
            continue;
        }
        if byte_idx < line_start {
            continue;
        }
        // Only examine the leading whitespace run of each line.
        if c == ' ' || c == '\t' {
            continue;
        }
        if is_invisible_indent(c) {
            let (line, col) = index.locate(byte_idx);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: byte_idx,
                line,
                col,
                pass: PassKind::Raw,
                kind: SignalKind::WhitespaceAnomaly,
                severity: Severity::Warn,
                confidence: 0.80,
                message: format!("invisible whitespace U+{:04X} in indentation", c as u32),
                snippet: redact_snippet(&snippet_around(bytes, byte_idx, 60)),
                diff_introduced: false,
            });
            // Keep scanning the rest of the indent of this line: another
            // suspicious char could follow the first.
            line_start = byte_idx + c.len_utf8();
        } else {
            // First non-whitespace char: stop examining this line's indent.
            line_start = usize::MAX; // sentinel: nothing matches `byte_idx < line_start`
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Mixed tabs and spaces in indentation (single file-level INFO)
// ---------------------------------------------------------------------------

fn scan_mixed_indent(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    skip_comment_continuations: bool,
) -> Vec<Finding> {
    let mut tab_lines = 0usize;
    let mut space_lines = 0usize;
    let mut first_tab = None;
    let mut first_space = None;
    let mut offset = 0usize;
    for line in bytes.split(|&b| b == b'\n') {
        let start = offset;
        offset += line.len() + 1;
        let Some(&first) = line.first() else { continue };
        // Only lines with code after their indentation count: a blank line
        // holding stray spaces is not an indentation style.
        let Some(content) = line.iter().position(|b| !matches!(b, b' ' | b'\t' | b'\r')) else {
            continue;
        };
        // ` * @param …` continuation lines of block comments (JSDoc, Rust
        // `/* */`) start with a space even in a tab-indented file.
        if skip_comment_continuations && line[content] == b'*' {
            continue;
        }
        if first == b'\t' {
            tab_lines += 1;
            first_tab.get_or_insert(start);
        } else if first == b' ' {
            space_lines += 1;
            first_space.get_or_insert(start);
        }
    }
    if tab_lines > 0 && space_lines > 0 {
        // Anchor the finding at whichever offending style appears first.
        let offset = first_tab.into_iter().chain(first_space).min().unwrap_or(0);
        let (line, col) = index.locate(offset);
        return vec![Finding {
            path: path.to_path_buf(),
            byte_offset: offset,
            line,
            col,
            pass: PassKind::Raw,
            kind: SignalKind::WhitespaceAnomaly,
            severity: Severity::Info,
            confidence: 0.40,
            message: format!(
                "file mixes tab and space indentation ({tab_lines} tab-indented and {space_lines} space-indented {})",
                if tab_lines + space_lines == 1 { "line" } else { "lines" }
            ),
            snippet: redact_snippet(&snippet_around(bytes, offset, 60)),
            diff_introduced: false,
        }];
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// Narrow character-set file
// ---------------------------------------------------------------------------
//
// JSF*ck and similar esoteric-JS encodings use only 6 characters: `[]()!+`.
// No legitimate source file (even minified) comes close to that restriction —
// normal minified JS uses 30+ distinct printable characters. When the entire
// printable-non-whitespace vocabulary of a file fits within a tiny set we have
// a strong indicator of deliberate character-set-constrained obfuscation.

/// Maximum distinct printable ASCII (0x21..=0x7e) characters for the signal
/// to fire. JSF*ck uses 6; a threshold of 12 gives comfortable headroom for
/// minor variants while staying far below any legitimate code.
const NARROW_CHARSET_MAX_DISTINCT: usize = 12;

/// Minimum printable non-whitespace bytes before checking. Prevents false
/// positives on stub files or files that are almost entirely comments.
const NARROW_CHARSET_MIN_CONTENT: usize = 200;

fn scan_narrow_charset(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let mut present = [false; 128];
    let mut content = 0usize;
    for &b in bytes {
        if (0x21..=0x7e).contains(&b) {
            present[b as usize] = true;
            content += 1;
        }
    }
    if content < NARROW_CHARSET_MIN_CONTENT {
        return Vec::new();
    }
    let distinct = present[0x21..=0x7e].iter().filter(|&&p| p).count();
    if distinct > NARROW_CHARSET_MAX_DISTINCT {
        return Vec::new();
    }
    let chars: String = (0x21u8..=0x7eu8)
        .filter(|&b| present[b as usize])
        .map(|b| b as char)
        .collect();
    let snippet = redact_snippet(&snippet_around(bytes, 0, 80));
    vec![Finding {
        path: path.to_path_buf(),
        byte_offset: 0,
        line: 1,
        col: 1,
        pass: PassKind::Raw,
        kind: SignalKind::NarrowFileCharset,
        severity: Severity::Warn,
        confidence: 0.90,
        message: format!(
            "file uses only {} distinct printable characters ({:?}) — JSF*ck-style or character-constrained obfuscation",
            distinct, chars
        ),
        snippet,
        diff_introduced: false,
    }]
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
    fn flags_long_line_info() {
        let mut src = b"x = ".to_vec();
        src.extend(std::iter::repeat_n(b'a', 600));
        src.push(b'\n');
        let findings = run(&src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::LongLine && f.severity == Severity::Info));
    }

    #[test]
    fn flags_long_line_warn() {
        let mut src = b"x = ".to_vec();
        src.extend(std::iter::repeat_n(b'a', 2100));
        src.push(b'\n');
        let findings = run(&src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::LongLine && f.severity == Severity::Warn));
    }

    #[test]
    fn flags_nbsp_in_indent() {
        let src = "def f():\n\u{00A0}   return 1\n".as_bytes();
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::WhitespaceAnomaly && f.severity == Severity::Warn));
    }

    #[test]
    fn flags_mixed_tab_space_indent() {
        let src = b"def f():\n\treturn 1\ndef g():\n    return 2\n";
        let findings = run(src);
        assert!(findings
            .iter()
            .any(|f| f.kind == SignalKind::WhitespaceAnomaly && f.severity == Severity::Info));
    }

    #[test]
    fn mixed_indent_reported_where_indentation_matters() {
        let src = b"def f():\n\treturn 1\n\ndef g():\n    return 2\n    pass\n";
        let idx = LineIndex::new(src);
        let mixed = |lang: Option<Language>| {
            analyze_lang(Path::new("f"), src, &idx, lang)
                .into_iter()
                .filter(|f| f.message.starts_with("file mixes tab and space"))
                .map(|f| f.message)
                .collect::<Vec<_>>()
        };
        for lang in [
            Language::Python,
            Language::Yaml,
            Language::Rust,
            Language::JavaScript,
            Language::TypeScript,
        ] {
            assert_eq!(
                mixed(Some(lang)),
                ["file mixes tab and space indentation (1 tab-indented and 2 space-indented lines)"],
                "{lang:?}"
            );
        }
        for lang in [
            Language::C,
            Language::Rst,
            Language::Markdown,
            Language::Bash,
        ] {
            assert!(mixed(Some(lang)).is_empty(), "{lang:?}");
        }
        assert_eq!(
            mixed(None).len(),
            1,
            "unknown language: unchanged behaviour"
        );
        assert_eq!(
            analyze(Path::new("f"), src, &idx)
                .iter()
                .filter(|f| f.message.starts_with("file mixes"))
                .count(),
            1
        );
    }

    #[test]
    fn jsdoc_continuations_and_blank_lines_are_not_an_indent_style() {
        let count = |src: &[u8]| {
            let idx = LineIndex::new(src);
            analyze_lang(Path::new("a.js"), src, &idx, Some(Language::JavaScript))
                .into_iter()
                .filter(|f| f.message.starts_with("file mixes"))
                .count()
        };
        // Tab-indented JS with top-level JSDoc (` * …` lines start with a
        // space) and a blank line holding stray spaces: one style, not two.
        assert_eq!(
            count(b"/**\n * Adds.\n * @param {number} a\n */\nfunction add(a, b) {\n\treturn a + b;\n    \n}\n"),
            0
        );
        // A space-indented code line among tab-indented ones still counts.
        assert_eq!(count(b"function f() {\n\tlet a = 1;\n  let b = 2;\n}\n"), 1);
    }

    #[test]
    fn long_lines_count_characters_and_skip_table_rows() {
        let long = |src: String| {
            let idx = LineIndex::new(src.as_bytes());
            scan_long_lines(Path::new("t.rst"), src.as_bytes(), &idx)
                .into_iter()
                .map(|f| (f.line, f.message))
                .collect::<Vec<_>>()
        };
        // 300 Cyrillic characters are 600 bytes but not a long line.
        assert!(long(format!("{}\n", "\u{0436}".repeat(300))).is_empty());
        // Records alternating long and short lines (cryptography's vectors).
        let records: String = (0..8)
            .map(|i| format!("counter = {i}\nP = {}\n", "c".repeat(514)))
            .collect();
        assert!(long(records).is_empty());
        // A key file: a few 512-character moduli among 256-character primes
        // and short labels, too sparse for any neighbourhood.
        let mut key = String::new();
        for _ in 0..4 {
            key.push_str(&format!(
                "# Modulus:\n{}\n# Exponent:\n10001\n",
                "b".repeat(512)
            ));
            for label in ["Prime 1", "Prime 2", "Coefficient"] {
                key.push_str(&format!("# {label}:\n{}\n", "d".repeat(256)));
            }
            key.push_str(&"# a comment line\n".repeat(12));
        }
        assert!(long(key).is_empty());
        // Generated declarations (windows-sys): one long signature among
        // shorter ones of the same shape.
        let decl = |args: usize| {
            format!(
                "windows_link::link!(\"iphlpapi.dll\" \"system\" fn F({}) -> u32);\n",
                "a : u32, ".repeat(args)
            )
        };
        let bindings: String = [3, 5, 2, 60, 4, 3].iter().map(|&n| decl(n)).collect();
        assert!(long(bindings).is_empty());
        // ... unless that line pushes code past the screen's edge.
        let mut hidden: String = [3, 5, 2].iter().map(|&n| decl(n)).collect();
        hidden.push_str(&format!(
            "windows_link::link!(\"iphlpapi.dll\" \"system\" fn F() -> u32);{}std::process::exit(0);\n",
            " ".repeat(500)
        ));
        hidden.push_str(&decl(4));
        assert_eq!(long(hidden).len(), 1);
        // A padded table: rows of 480–510 characters together.
        let row = |n: usize| format!("   :pypi:`p`   {}\n", "d".repeat(n));
        let table: String = [480, 470, 495, 510, 475, 490, 485]
            .iter()
            .map(|&n| row(n))
            .collect();
        assert!(long(table).is_empty());
        // One line that runs far past short neighbours still stands out.
        let src = format!("a = 1\nb = 2\n{}x = 1\nc = 3\n", " ".repeat(600));
        assert_eq!(long(src), [(3, "line length 605 characters".to_string())]);
        // Over the warn threshold, a line is reported even among others.
        let big: String = (0..5).map(|_| format!("{}\n", "z".repeat(2100))).collect();
        assert_eq!(long(big).len(), 5);
    }

    #[test]
    fn flags_jsfuck_style_narrow_charset() {
        // 6-character JSF*ck alphabet repeated to exceed the content threshold.
        let src = b"[]()+!\n".repeat(40);
        let findings = run(&src);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::NarrowFileCharset),
            "JSFuck-alphabet file should fire NarrowFileCharset: {:?}",
            findings
        );
    }

    #[test]
    fn does_not_flag_normal_js() {
        // A normal JS snippet has far more than 12 distinct chars.
        let src = b"const x = require('path').join(__dirname, 'dist');\nmodule.exports = x;\n";
        let findings = run(src);
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SignalKind::NarrowFileCharset),
            "normal JS must not fire NarrowFileCharset: {:?}",
            findings
        );
    }

    #[test]
    fn does_not_flag_short_file_below_content_threshold() {
        // Under 200 printable bytes — not enough content to judge.
        let src = b"[]()+!\n".repeat(5);
        let findings = run(&src);
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SignalKind::NarrowFileCharset),
            "short file must not fire NarrowFileCharset: {:?}",
            findings
        );
    }
}
