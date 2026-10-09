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

/// Lines of context a snippet keeps before and after the finding's line.
const SNIPPET_LINES_BEFORE: usize = 1;
const SNIPPET_LINES_AFTER: usize = 2;

/// Extract a snippet around an offset for reporting: whole lines, the
/// finding's line with [`SNIPPET_LINES_BEFORE`] before and
/// [`SNIPPET_LINES_AFTER`] after, within [`crate::finding::SNIPPET_MAX`]
/// bytes. Context lines go first when that is too long; a single line longer
/// than that is cut to a window starting `span / 2` bytes before the offset.
/// Never panics on multi-byte boundaries: invalid UTF-8 is replaced with the
/// replacement character.
pub fn snippet_around(bytes: &[u8], offset: usize, span: usize) -> String {
    let max = crate::finding::SNIPPET_MAX;
    let offset = offset.min(bytes.len());
    let line_start = |at: usize| {
        bytes[..at]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1)
    };
    let line_end = |at: usize| {
        bytes[at..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |i| at + i)
    };
    let (first, last) = (line_start(offset), line_end(offset));
    if last - first > max {
        // One long line: a window that starts a little before the finding.
        let lo = offset.saturating_sub(span / 2).max(first);
        let hi = (lo + max).min(last);
        return String::from_utf8_lossy(&bytes[lo..hi]).into_owned();
    }
    let (mut lo, mut hi) = (first, last);
    // Widen by whole lines, after first (what follows a finding usually
    // completes it: the rest of a pipeline, a call's arguments), while it fits.
    let mut before = 0;
    let mut after = 0;
    loop {
        let mut grew = false;
        if after < SNIPPET_LINES_AFTER && hi < bytes.len() {
            let next = line_end(hi + 1);
            if next - lo <= max {
                hi = next;
                after += 1;
                grew = true;
            }
        }
        if before < SNIPPET_LINES_BEFORE && lo > 0 {
            let prev = line_start(lo - 1);
            if hi - prev <= max {
                lo = prev;
                before += 1;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    while hi > first.max(lo) && matches!(bytes[hi - 1], b'\n' | b'\r') {
        hi -= 1;
    }
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

    #[test]
    fn snippets_are_whole_lines_around_the_finding() {
        // libc's ci/bsd-prepare.sh: the finding is a curl | sh pipeline.
        let src = b"if ! pkg install -y curl; then\n    echo \"failed to install dependencies\"\n    exit 1\nfi\n\ncurl --proto '=https' --tlsv1.2 -sSf --retry 5 https://sh.rustup.rs | sh -s -- -y --profile minimal\n. \"$HOME/.cargo/env\"\nrustc -V\nmore\n";
        let off = src.windows(4).position(|w| w == b"curl").unwrap();
        let off = src[off + 4..]
            .windows(4)
            .position(|w| w == b"curl")
            .unwrap()
            + off
            + 4;
        let snip = snippet_around(src, off, 100);
        assert_eq!(
            snip,
            "\ncurl --proto '=https' --tlsv1.2 -sSf --retry 5 https://sh.rustup.rs | sh -s -- -y --profile minimal\n. \"$HOME/.cargo/env\"\nrustc -V"
        );
        // A line longer than the cap: a window from a little before the finding.
        let long = format!("x = \"{}PAYLOAD{}\"\n", "a".repeat(1000), "b".repeat(1000));
        let at = long.find("PAYLOAD").unwrap();
        let snip = snippet_around(long.as_bytes(), at, 100);
        assert!(snip.len() <= crate::finding::SNIPPET_MAX && snip.contains("PAYLOAD"));
        // Context lines are dropped before the finding's line is cut.
        let wide = format!("{}\nfinding here\n{}\n", "c".repeat(400), "d".repeat(400));
        assert_eq!(snippet_around(wide.as_bytes(), 402, 100), "finding here");
    }

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
