//! Encoding-pattern detection on raw source bytes.
//!
//! All heuristics here deliberately over-trigger; the token pass refines them
//! by distinguishing code from comment context.

use std::path::Path;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

pub fn analyze(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(find_base64_blobs(path, bytes, index));
    findings.extend(find_hex_escape_runs(path, bytes, index));
    findings.extend(find_octal_escape_runs(path, bytes, index));
    findings
}

// ---------------------------------------------------------------------------
// Base64 blobs
// ---------------------------------------------------------------------------

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

fn compress(bytes: &[u8]) -> usize {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .expect("in-memory zlib write never fails");
    encoder
        .finish()
        .expect("in-memory zlib finish never fails")
        .len()
}

fn compression_ratio(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    compress(bytes) as f32 / bytes.len() as f32
}

fn find_base64_blobs(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_base64_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_base64_byte(bytes[i]) {
            i += 1;
        }
        let end = i;
        let len = end - start;
        // Minimum length: 64 for unpadded blobs (avoids git SHAs, session
        // IDs, cache keys); 40 for blobs ending with `=` or `==` padding.
        // Base64 padding is definitive proof the blob is encoded data, so we
        // can safely lower the threshold — the dominant false-positive class
        // (hex digests, identifiers) never carries padding.
        let is_padded = bytes.get(end.saturating_sub(1)) == Some(&b'=');
        let min_len = if is_padded { 40 } else { 64 };
        if len < min_len {
            continue;
        }

        let span = &bytes[start..end];
        // Require BOTH uppercase AND lowercase letters. Hex digests
        // (sha1/sha256) and git refs are the dominant false-positive class
        // and are always single-case; real base64 of ≥32 random bytes
        // contains both cases with probability ≈ 1. Also ensures a digit
        // is present, which rules out long identifiers.
        let has_upper = span.iter().any(|b| b.is_ascii_uppercase());
        let has_lower = span.iter().any(|b| b.is_ascii_lowercase());
        let has_digit = span.iter().any(|b| b.is_ascii_digit());
        if !(has_upper && has_lower && has_digit) {
            continue;
        }
        let ratio = compression_ratio(span);
        if ratio < 0.85 {
            continue;
        }

        let (line, col) = index.locate(start);
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: start,
            line,
            col,
            pass: PassKind::Raw,
            kind: SignalKind::EncodingBase64,
            severity: Severity::Warn,
            confidence: 0.60,
            message: format!(
                "base64-like blob ({} bytes, compression ratio {:.2})",
                len, ratio
            ),
            snippet: redact_snippet(&snippet_around(bytes, start, 100)),
            diff_introduced: false,
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// Hex escape runs (`\xNN\xNN...`) — canonical "escape soup"
// ---------------------------------------------------------------------------

/// Minimum consecutive `\xNN` escapes before we emit any signal. Was 8;
/// raised to 16 because short runs collide with binary-format fixtures
/// (length prefixes, serialized records) that interleave escapes with
/// ASCII field names and look nothing like encoded payloads.
const HEX_ESCAPE_THRESHOLD: usize = 16;

/// Minimum Shannon entropy (bits/byte) of the decoded escape bytes before
/// we emit a finding. Real shellcode and encoded payloads sit at ~7–8
/// bits/byte. Serialization padding (length prefixes, alignment) and
/// other structured binary formats sit well below 4. A floor of 3.5
/// cleanly separates the two without risking true positives.
const HEX_MIN_ENTROPY_BITS: f32 = 3.5;

fn hex_pair_value(b0: u8, b1: u8) -> u8 {
    fn nib(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0,
        }
    }
    (nib(b0) << 4) | nib(b1)
}

/// Shannon entropy of a byte histogram, in bits/byte. `total` is the sum
/// of `hist`. Returns 0 for empty input.
fn shannon_entropy(hist: &[u32; 256], total: u32) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f32;
    let mut h = 0.0_f32;
    for &c in hist.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f32 / total_f;
        h -= p * p.log2();
    }
    h
}

fn find_hex_escape_runs(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'\\'
            && bytes[i + 1] == b'x'
            && bytes[i + 2].is_ascii_hexdigit()
            && bytes[i + 3].is_ascii_hexdigit()
        {
            let start = i;
            let mut count = 0u32;
            let mut hist = [0u32; 256];
            while i + 3 < bytes.len()
                && bytes[i] == b'\\'
                && bytes[i + 1] == b'x'
                && bytes[i + 2].is_ascii_hexdigit()
                && bytes[i + 3].is_ascii_hexdigit()
            {
                let v = hex_pair_value(bytes[i + 2], bytes[i + 3]);
                hist[v as usize] += 1;
                i += 4;
                count += 1;
            }
            if count as usize >= HEX_ESCAPE_THRESHOLD {
                let entropy = shannon_entropy(&hist, count);
                if entropy < HEX_MIN_ENTROPY_BITS {
                    continue;
                }
                let (line, col) = index.locate(start);
                // Separate signal for the "encoding-soup" sense — we only
                // emit one Finding per run; pick the escape-soup kind for
                // long runs, hex for anything above threshold.
                let (kind, severity, confidence) = if count >= 24 {
                    (SignalKind::EncodingEscapeSoup, Severity::Warn, 0.80)
                } else {
                    (SignalKind::EncodingHex, Severity::Warn, 0.65)
                };
                let message = format!(
                    "{} consecutive `\\xNN` escapes (entropy {:.1} bits/byte)",
                    count, entropy
                );
                findings.push(Finding {
                    path: path.to_path_buf(),
                    byte_offset: start,
                    line,
                    col,
                    pass: PassKind::Raw,
                    kind,
                    severity,
                    confidence,
                    message,
                    snippet: redact_snippet(&snippet_around(bytes, start, 100)),
                    diff_introduced: false,
                });
            }
        } else {
            i += 1;
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Octal escape runs (`\NNN\NNN...`) — same obfuscation class as hex escapes
// but less recognizable, valid in C, Python, and JavaScript.
// ---------------------------------------------------------------------------

/// Minimum consecutive `\NNN` octal escapes before emitting a signal.
/// Lower than the hex threshold because octal is rarely used in legitimate
/// code — a run of 6+ is almost never accidental.
const OCTAL_ESCAPE_THRESHOLD: usize = 6;

/// Minimum Shannon entropy (bits/byte) of the decoded octal bytes. Filters
/// out null-padding and other low-entropy repetitive patterns.
const OCTAL_MIN_ENTROPY_BITS: f32 = 2.5;

fn parse_octal_escape(bytes: &[u8], i: usize) -> Option<(u8, usize)> {
    if bytes.get(i) != Some(&b'\\') {
        return None;
    }
    let d0 = bytes.get(i + 1)?;
    if !matches!(d0, b'0'..=b'7') {
        return None;
    }
    let mut val = (d0 - b'0') as u32;
    let mut len = 1usize;
    for k in 2..=3usize {
        match bytes.get(i + k) {
            Some(&d) if matches!(d, b'0'..=b'7') => {
                val = val * 8 + (d - b'0') as u32;
                len += 1;
            }
            _ => break,
        }
    }
    Some(((val & 0xFF) as u8, i + 1 + len))
}

fn find_octal_escape_runs(path: &Path, bytes: &[u8], index: &LineIndex) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || !matches!(bytes.get(i + 1), Some(b'0'..=b'7')) {
            i += 1;
            continue;
        }
        let start = i;
        let mut count = 0usize;
        let mut hist = [0u32; 256];
        while let Some((v, next)) = parse_octal_escape(bytes, i) {
            hist[v as usize] += 1;
            count += 1;
            i = next;
        }
        if count >= OCTAL_ESCAPE_THRESHOLD {
            let entropy = shannon_entropy(&hist, count as u32);
            if entropy < OCTAL_MIN_ENTROPY_BITS {
                continue;
            }
            let (line, col) = index.locate(start);
            findings.push(Finding {
                path: path.to_path_buf(),
                byte_offset: start,
                line,
                col,
                pass: PassKind::Raw,
                kind: SignalKind::EncodingOctal,
                severity: Severity::Warn,
                confidence: 0.65,
                message: format!(
                    "{} consecutive `\\NNN` octal escapes (entropy {:.1} bits/byte)",
                    count, entropy
                ),
                snippet: redact_snippet(&snippet_around(bytes, start, 100)),
                diff_introduced: false,
            });
        }
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
    fn flags_long_base64_blob() {
        // 88-char blob (mixed case, digits) — realistic payload length.
        let blob =
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
        let src = format!("data = \"{}\"\n", blob);
        let findings = run(src.as_bytes());
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::EncodingBase64),
            "expected base64 finding, got {:?}",
            findings
        );
    }

    #[test]
    fn ignores_short_base64_like_metadata() {
        // 50-char wheel-RECORD style hash — too short to be a real obfuscated payload.
        let src = b"record = \"WHEEL,sha256=G16H4A3IeoQmnOrYV4ueZGKSjhipXx8zc8nu9FGlvMA\"\n";
        let findings = run(src);
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SignalKind::EncodingBase64),
            "short base64-like metadata must not trigger: {:?}",
            findings
        );
    }

    #[test]
    fn flags_hex_escape_run() {
        // 16 high-entropy escapes — at threshold, no null dominance.
        let src =
            br#"payload = b"\xde\xad\xbe\xef\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c""#;
        let findings = run(src);
        assert!(findings.iter().any(|f| f.kind == SignalKind::EncodingHex));
    }

    #[test]
    fn ignores_short_hex_run() {
        let src = br#"x = b"\xde\xad""#;
        let findings = run(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_sub_threshold_hex_run() {
        // 10 escapes — above the old threshold of 8, below the new 16.
        let src = br#"x = b"\xde\xad\xbe\xef\x01\x02\x03\x04\x05\x06""#;
        let findings = run(src);
        assert!(
            findings.is_empty(),
            "10-escape run should be below threshold: {:?}",
            findings
        );
    }

    #[test]
    fn ignores_low_entropy_run_of_repeated_byte() {
        // 20 escapes, all \x00 — pure padding. Entropy = 0.
        let src = br#"b = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00""#;
        let findings = run(src);
        assert!(
            !findings.iter().any(|f| matches!(
                f.kind,
                SignalKind::EncodingHex | SignalKind::EncodingEscapeSoup
            )),
            "zero-entropy run must not trigger: {:?}",
            findings
        );
    }

    #[test]
    fn ignores_low_entropy_run_of_two_values() {
        // 20 escapes alternating between two values — entropy ≈ 1 bit/byte.
        let src = br#"b = b"\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01""#;
        let findings = run(src);
        assert!(
            !findings.iter().any(|f| matches!(
                f.kind,
                SignalKind::EncodingHex | SignalKind::EncodingEscapeSoup
            )),
            "low-entropy alternation must not trigger: {:?}",
            findings
        );
    }

    #[test]
    fn high_entropy_run_triggers_finding() {
        // 16 distinct escape values — entropy = 4.0 bits/byte, above the floor.
        let src = br#"b = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff""#;
        let findings = run(src);
        assert!(
            findings.iter().any(|f| f.kind == SignalKind::EncodingHex),
            "high-entropy run should trigger: {:?}",
            findings
        );
    }

    #[test]
    fn shannon_entropy_is_zero_for_single_value() {
        let mut hist = [0u32; 256];
        hist[0] = 20;
        assert_eq!(shannon_entropy(&hist, 20), 0.0);
    }

    #[test]
    fn shannon_entropy_is_max_for_uniform_distribution() {
        let mut hist = [0u32; 256];
        for slot in hist.iter_mut().take(16) {
            *slot = 1;
        }
        let h = shannon_entropy(&hist, 16);
        assert!((h - 4.0).abs() < 0.01, "expected ~4.0 bits, got {}", h);
    }

    #[test]
    fn sha256_hex_digest_is_not_base64() {
        // 64-char lowercase hex digest — the dominant false-positive class.
        let src = b"hash = \"a9be99c9d2ab6f60294f2931bc875833993ce3f4d41d8da1684d4c27aa7c8e4\"\n";
        let findings = run(src);
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SignalKind::EncodingBase64),
            "hex digest must not trigger base64: {:?}",
            findings
        );
    }

    #[test]
    fn sha1_git_ref_is_not_base64() {
        let src = b"rev = \"cf2cbe2aec28f87c6228a6fb136c27931c9af407\"\n";
        let findings = run(src);
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SignalKind::EncodingBase64),
            "git sha1 must not trigger base64: {:?}",
            findings
        );
    }

    #[test]
    fn uppercase_only_hex_is_not_base64() {
        let src = b"x = \"A9BE99C9D2AB6F60294F2931BC875833993CE3F4D41D8DA1684D4C27AA7C8E4\"\n";
        let findings = run(src);
        assert!(!findings
            .iter()
            .any(|f| f.kind == SignalKind::EncodingBase64));
    }

    #[test]
    fn flags_octal_escape_run() {
        // 8 distinct octal escapes — above threshold, sufficient entropy.
        // \101\102\103\104\105\106\107\110 = ABCDEFGH
        let src = br#"x = "\101\102\103\104\105\106\107\110""#;
        let findings = run(src);
        assert!(
            findings.iter().any(|f| f.kind == SignalKind::EncodingOctal),
            "expected octal finding: {:?}",
            findings
        );
    }

    #[test]
    fn ignores_short_octal_run() {
        // 3 octal escapes — well below the threshold of 6.
        let src = br#"x = "\012\011\012""#;
        let findings = run(src);
        assert!(
            !findings.iter().any(|f| f.kind == SignalKind::EncodingOctal),
            "short octal run must not trigger: {:?}",
            findings
        );
    }

    #[test]
    fn ignores_low_entropy_octal_run() {
        // 8 identical null escapes — entropy 0, must be suppressed.
        let src = br#"x = "\000\000\000\000\000\000\000\000""#;
        let findings = run(src);
        assert!(
            !findings.iter().any(|f| f.kind == SignalKind::EncodingOctal),
            "zero-entropy octal run must not trigger: {:?}",
            findings
        );
    }
}
