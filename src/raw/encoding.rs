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
        // Minimum length 64: below this we hit mostly hashes, session IDs,
        // wheel-RECORD sha256 tags, cache keys. A real obfuscated-code
        // payload is hundreds of bytes. Anything entropic that slips
        // through here is still caught by the HighComplexity pass.
        if len < 64 {
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

const HEX_ESCAPE_THRESHOLD: usize = 8;

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
            let mut count = 0;
            while i + 3 < bytes.len()
                && bytes[i] == b'\\'
                && bytes[i + 1] == b'x'
                && bytes[i + 2].is_ascii_hexdigit()
                && bytes[i + 3].is_ascii_hexdigit()
            {
                i += 4;
                count += 1;
            }
            if count >= HEX_ESCAPE_THRESHOLD {
                let (line, col) = index.locate(start);
                // Separate signal for the "encoding-soup" sense — we only
                // emit one Finding per run; pick the escape-soup kind for
                // long runs, hex for anything above threshold.
                let (kind, severity, confidence, message) = if count >= 24 {
                    (
                        SignalKind::EncodingEscapeSoup,
                        Severity::Warn,
                        0.80,
                        format!("{} consecutive `\\xNN` escapes", count),
                    )
                } else {
                    (
                        SignalKind::EncodingHex,
                        Severity::Warn,
                        0.65,
                        format!("{} consecutive `\\xNN` escapes", count),
                    )
                };
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
        let blob = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
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
        let src = br#"payload = b"\xde\xad\xbe\xef\x01\x02\x03\x04\x05\x06""#;
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
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SignalKind::EncodingBase64)
        );
    }
}
