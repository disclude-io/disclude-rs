//! Structural anomalies — line length, indentation whitespace, tab/space mix.

use std::path::Path;

use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

const LONG_LINE_INFO: usize = 500;
const LONG_LINE_WARN: usize = 2000;

pub fn analyze(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(scan_long_lines(path, bytes, index));
    findings.extend(scan_indent_whitespace(path, bytes, index));
    findings.extend(scan_mixed_indent(path, bytes, index));
    findings
}

// ---------------------------------------------------------------------------
// Long lines
// ---------------------------------------------------------------------------

fn scan_long_lines(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut line_start = 0usize;
    let mut line_num = 1usize;
    let _ = index; // long-line location is always (line_num, 1), don't need the index
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            let len = i - line_start;
            emit_long_line(&mut findings, path, bytes, line_start, line_num, len);
            line_start = i + 1;
            line_num += 1;
        }
    }
    // trailing line (no terminating newline)
    if line_start < bytes.len() {
        let len = bytes.len() - line_start;
        emit_long_line(&mut findings, path, bytes, line_start, line_num, len);
    }
    findings
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
        message: format!("line length {} bytes", len),
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

fn scan_mixed_indent(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let mut has_tab_indent = false;
    let mut has_space_indent = false;
    let mut first_tab = None;
    let mut first_space = None;
    let mut line_start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            line_start = i + 1;
            continue;
        }
        if i == line_start {
            if b == b'\t' {
                has_tab_indent = true;
                first_tab.get_or_insert(i);
            } else if b == b' ' {
                has_space_indent = true;
                first_space.get_or_insert(i);
            }
            // Once the first byte of a line is examined we stop examining
            // that line — advance the sentinel so the `i == line_start` check
            // misses until the next `\n`.
            line_start = usize::MAX;
        }
    }
    if has_tab_indent && has_space_indent {
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
            message: "file mixes tab and space indentation".to_string(),
            snippet: redact_snippet(&snippet_around(bytes, offset, 60)),
            diff_introduced: false,
        }];
    }
    Vec::new()
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
}
