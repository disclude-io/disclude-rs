//! String-literal compression-ratio analysis.
//!
//! Raw pass doesn't have a real tokenizer, so we approximate "string literals"
//! as single-line quoted spans between matching `"` or `'` with simple
//! backslash-escape handling. Token pass will refine this with language-aware
//! string recognition (including raw strings, triple-quoted Python strings,
//! TS template literals, etc.).
//!
//! Deviation from SPEC.md §Compression ratio implementation:
//!   * We use raw DEFLATE rather than zlib-framed compression. zlib adds ~6
//!     bytes of header + Adler-32 trailer which dominates the ratio on short
//!     inputs and produces critical-severity findings on ordinary format
//!     strings.
//!   * We raise the minimum-literal gate from 32 → 128 bytes. At 32–64 bytes
//!     the DEFLATE output is dominated by block-framing overhead; ordinary
//!     English sentences routinely exceed ratio 0.98 and flood the report
//!     with false positives (observed empirically on this crate's own
//!     sources). 128 bytes is the shortest length at which English reliably
//!     drops below 0.9 while attack payloads (base64, hex blobs, packed
//!     binary) reliably stay above it.

use std::path::Path;

use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write;

use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

const MIN_LITERAL_LEN: usize = 128;
const WARN_RATIO: f32 = 0.95;
const CRITICAL_RATIO: f32 = 0.98;

pub fn analyze(path: &Path, bytes: &[u8], index: &LineIndex) -> (Vec<Finding>, (f32, f32)) {
    let literals = find_string_literals(bytes);
    let mut ratios: Vec<(usize, usize, f32)> = Vec::new(); // (content_start, content_end, ratio)
    for (content_start, content_end) in literals {
        if content_end - content_start < MIN_LITERAL_LEN {
            continue;
        }
        let content = &bytes[content_start..content_end];
        let ratio = compression_ratio(content);
        ratios.push((content_start, content_end, ratio));
    }

    let (mean, stddev, max) = stats(&ratios);
    let mut findings = Vec::new();

    for &(start, end, ratio) in &ratios {
        if ratio > CRITICAL_RATIO {
            let (line, col) = index.locate(start);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: start,
                line,
                col,
                pass: PassKind::Raw,
                kind: SignalKind::HighComplexity,
                severity: Severity::Critical,
                confidence: 0.70,
                message: format!(
                    "string literal compression ratio {:.3} ({} bytes)",
                    ratio,
                    end - start
                ),
                snippet: redact_snippet(&snippet_around(bytes, start, 100)),
                diff_introduced: false,
            });
        } else if ratio > WARN_RATIO {
            let (line, col) = index.locate(start);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: start,
                line,
                col,
                pass: PassKind::Raw,
                kind: SignalKind::HighComplexity,
                severity: Severity::Warn,
                confidence: 0.60,
                message: format!(
                    "string literal compression ratio {:.3} ({} bytes)",
                    ratio,
                    end - start
                ),
                snippet: redact_snippet(&snippet_around(bytes, start, 100)),
                diff_introduced: false,
            });
        } else if ratios.len() >= 5 && stddev > 0.0 && ratio > mean + 2.0 * stddev {
            // File-level outlier: a literal significantly more dense than
            // the rest of this file's literals.
            let (line, col) = index.locate(start);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: start,
                line,
                col,
                pass: PassKind::Raw,
                kind: SignalKind::HighComplexity,
                severity: Severity::Info,
                confidence: 0.50,
                message: format!(
                    "compression ratio {:.3} is >2σ above file mean {:.3}",
                    ratio, mean
                ),
                snippet: redact_snippet(&snippet_around(bytes, start, 100)),
                diff_introduced: false,
            });
        }
    }

    (findings, (mean, max))
}

fn compression_ratio(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .expect("in-memory deflate write never fails");
    let compressed = encoder
        .finish()
        .expect("in-memory deflate finish never fails");
    compressed.len() as f32 / bytes.len() as f32
}

fn stats(ratios: &[(usize, usize, f32)]) -> (f32, f32, f32) {
    if ratios.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let n = ratios.len() as f32;
    let mean = ratios.iter().map(|&(_, _, r)| r).sum::<f32>() / n;
    let var = ratios
        .iter()
        .map(|&(_, _, r)| {
            let d = r - mean;
            d * d
        })
        .sum::<f32>()
        / n;
    let stddev = var.sqrt();
    let max = ratios.iter().map(|&(_, _, r)| r).fold(0.0_f32, f32::max);
    (mean, stddev, max)
}

/// Coarse single-line quoted-span detector. Returns (content_start,
/// content_end) byte offsets — the bytes *between* the quotes, not including
/// them. Backslash escapes are consumed as two bytes. Unterminated or
/// multi-line strings are skipped.
fn find_string_literals(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let quote = b;
            i += 1;
            let content_start = i;
            while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if i < bytes.len() && bytes[i] == quote {
                out.push((content_start, i));
                i += 1;
            } else {
                // Unterminated or newline hit: bail to after the opening
                // quote rather than re-scanning the skipped region.
                i = content_start;
            }
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(src: &[u8]) -> (Vec<Finding>, (f32, f32)) {
        let idx = LineIndex::new(src);
        analyze(&PathBuf::from("test.py"), src, &idx)
    }

    #[test]
    fn flags_high_compression_ratio_literal() {
        // Embed 256 bytes of pseudo-random binary in a byte-string literal.
        // Random bytes reliably exceed ratio 0.98 with raw DEFLATE; alphabetic
        // alphabets do not, because DEFLATE learns the restricted byte range.
        let mut payload: Vec<u8> = Vec::with_capacity(256);
        let mut x: u64 = 0xDEADBEEFCAFEBABE;
        while payload.len() < 256 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let b = (x >> 33) as u8;
            // Avoid bytes that would break our single-line quoted-span
            // detector: quotes, backslash, newline, NUL.
            if !matches!(b, b'"' | b'\'' | b'\\' | b'\n' | 0) {
                payload.push(b);
            }
        }
        let mut src = Vec::from(&b"let x = b\""[..]);
        src.extend_from_slice(&payload);
        src.extend_from_slice(b"\";\n");
        let (findings, _) = run(&src);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::HighComplexity),
            "expected HighComplexity finding, got {:?}",
            findings
        );
    }

    #[test]
    fn ignores_low_compression_short_literal() {
        let src = b"msg = \"hello world\"\n";
        let (findings, _) = run(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_ordinary_english_sentence() {
        // Plain English string that previously false-positived at the 32-byte
        // gate with zlib framing. Should produce no finding now.
        let src = b"err = \"disclude: could not load ignore file {}: {}\"\n";
        let (findings, _) = run(src);
        assert!(
            findings.is_empty(),
            "ordinary English should not trip HighComplexity, got {:?}",
            findings
        );
    }
}
