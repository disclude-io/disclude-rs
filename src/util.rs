//! Byte-offset utilities. All analysis in `disclude` tracks positions in the
//! original file bytes; this module is the single source of truth for converting
//! those offsets into (line, col) for user-facing reports.

/// Pre-computed line-start byte offsets for fast offset → (line, col) lookup.
pub struct LineIndex {
    /// `line_starts[i]` is the byte offset of the first byte of line i+1.
    /// Always begins with 0.
    line_starts: Vec<usize>,
    total_len: usize,
}

impl LineIndex {
    pub fn new(bytes: &[u8]) -> Self {
        let mut line_starts = Vec::with_capacity(bytes.len() / 40 + 1);
        line_starts.push(0);
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        LineIndex {
            line_starts,
            total_len: bytes.len(),
        }
    }

    /// Convert a byte offset into (line, col), both 1-indexed. `col` is a byte
    /// offset from the start of the line (not a grapheme cluster column).
    pub fn locate(&self, offset: usize) -> (usize, usize) {
        let offset = offset.min(self.total_len);
        let line_idx = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let col = offset - self.line_starts[line_idx] + 1;
        (line_idx + 1, col)
    }

    /// The byte range of a given 1-indexed line, excluding the trailing newline.
    pub fn line_range(&self, line: usize) -> Option<(usize, usize)> {
        if line == 0 || line > self.line_starts.len() {
            return None;
        }
        let start = self.line_starts[line - 1];
        let end = self
            .line_starts
            .get(line)
            .map(|&e| e.saturating_sub(1))
            .unwrap_or(self.total_len);
        Some((start, end))
    }
}

/// Extract a short byte-accurate snippet around an offset for reporting.
/// Never panics on multi-byte boundaries: falls back to raw-byte slicing and
/// replaces invalid UTF-8 with the replacement character.
pub fn snippet_around(bytes: &[u8], offset: usize, span: usize) -> String {
    let lo = offset.saturating_sub(span / 2);
    let hi = (offset + span / 2).min(bytes.len());
    String::from_utf8_lossy(&bytes[lo..hi]).into_owned()
}

/// Return the slice of bytes for the line containing `offset`, without the
/// trailing newline.
pub fn line_slice<'a>(bytes: &'a [u8], index: &LineIndex, offset: usize) -> &'a [u8] {
    let (line, _col) = index.locate(offset);
    if let Some((start, end)) = index.line_range(line) {
        &bytes[start..end]
    } else {
        &[]
    }
}

/// Length in bytes of the UTF-8 sequence starting with `b`. Returns 1 for
/// continuation bytes and ASCII — safe to use when walking a validated UTF-8
/// slice byte by byte.
pub fn utf8_len(b: u8) -> usize {
    if b < 0xC0 {
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_basic() {
        let idx = LineIndex::new(b"abc\ndef\nghi");
        assert_eq!(idx.locate(0), (1, 1));
        assert_eq!(idx.locate(2), (1, 3));
        assert_eq!(idx.locate(3), (1, 4)); // newline itself is still line 1
        assert_eq!(idx.locate(4), (2, 1));
        assert_eq!(idx.locate(10), (3, 3));
    }

    #[test]
    fn locate_past_end_clamps() {
        let idx = LineIndex::new(b"abc");
        assert_eq!(idx.locate(100), (1, 4));
    }

    #[test]
    fn line_range_returns_line_without_newline() {
        let bytes = b"abc\ndef\nghi";
        let idx = LineIndex::new(bytes);
        assert_eq!(idx.line_range(1), Some((0, 3)));
        assert_eq!(idx.line_range(2), Some((4, 7)));
        assert_eq!(idx.line_range(3), Some((8, 11)));
    }
}
