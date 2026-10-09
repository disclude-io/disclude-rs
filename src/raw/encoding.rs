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

/// Share of adjacent character pairs that are neighbours (`A→B`, `z→y`) at or
/// above which a span is an alphabet table, not data: `ABCD…xyz0123…+/`
/// scores 0.94, and the mutated alphabets in a base64 library's tests
/// (`AACDEF…`, `…YZZbc…`) stay above 0.8. Encoded random bytes score about
/// 1/64. High enough that disguising a payload as an alphabet would take
/// three times its length in ordered padding.
const ALPHABET_MIN_SEQUENTIAL: f32 = 0.75;

/// Subresource Integrity hash prefixes and the base64 length of each digest:
/// `sha512-<88 chars>` in `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
/// and HTML `integrity` attributes.
const SRI_DIGESTS: &[(&[u8], usize)] = &[(b"sha256-", 44), (b"sha384-", 64), (b"sha512-", 88)];

/// True if `bytes[start..end]` is the digest of an SRI hash: preceded by its
/// algorithm prefix and exactly that digest's base64 length. A hash, not
/// encoded content; it decodes to nothing that could run.
fn is_sri_digest(bytes: &[u8], start: usize, end: usize) -> bool {
    SRI_DIGESTS.iter().any(|&(prefix, len)| {
        end - start == len && start >= prefix.len() && &bytes[start - prefix.len()..start] == prefix
    })
}

/// A path, not data: `//vda1cs4850/workspaces/folderAtRoot/folder1/…` (TypeScript's
/// test baselines). `/` is a base64 character, so an all-alphanumeric path
/// is one long base64-shaped run; but encoded data has `/` and `+` each about
/// once in 64 characters, where a path has a slash every few characters and
/// no `+`. At least 4 slashes, one per 24 characters or more, and no `+` or
/// `=`: about a 1% chance for a random 73-character blob, far less longer.
fn is_path_like(span: &[u8]) -> bool {
    let slashes = span.iter().filter(|&&b| b == b'/').count();
    slashes >= 4 && slashes * 24 >= span.len() && !span.contains(&b'+') && !span.contains(&b'=')
}

/// Share of a span's letters in same-case runs of [`WORD_RUN`] or more at or
/// above which it is words, not encoding: `ClassDeclarationWithInvalidConst…`
/// (a TypeScript test path) scores near 1. In base64, of random bytes or of
/// text, upper and lower case alternate almost at random: measured, no 64-,
/// 100-, or 256-character sample of random data reached 0.7, and about 1 in
/// 20,000 of base64-encoded source code did.
const WORDY_MIN_SHARE: f32 = 0.7;
const WORD_RUN: usize = 4;

/// The share of `span`'s letters that sit in runs of at least [`WORD_RUN`]
/// letters of the same case.
fn wordy_share(span: &[u8]) -> f32 {
    let (mut letters, mut in_words, mut run, mut upper) = (0usize, 0usize, 0usize, false);
    let mut close = |run: usize| {
        if run >= WORD_RUN {
            in_words += run;
        }
    };
    for &b in span {
        if b.is_ascii_alphabetic() {
            letters += 1;
            if run > 0 && b.is_ascii_uppercase() == upper {
                run += 1;
            } else {
                close(run);
                run = 1;
                upper = b.is_ascii_uppercase();
            }
        } else {
            close(run);
            run = 0;
        }
    }
    close(run);
    if letters == 0 {
        return 0.0;
    }
    in_words as f32 / letters as f32
}

/// The shortest base64 line taken as part of a wrapped blob. Wrapped base64
/// uses 60, 64, or 76 characters a line; ordinary words and identifiers
/// that happen to end and start lines are far shorter.
const WRAPPED_MIN_LINE: usize = 40;

/// The lines of a base64 blob that starts with the run `bytes[start..end]`:
/// while a run of at least [`WRAPPED_MIN_LINE`] ends its line and the next
/// line, after any indentation, is another such run, they continue one
/// blob. Returns each line's run; a single entry when the blob is one line.
fn wrapped_lines(bytes: &[u8], start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut lines = vec![(start, end)];
    let (mut s, mut e) = (start, end);
    while e - s >= WRAPPED_MIN_LINE {
        let next = match (bytes.get(e), bytes.get(e + 1)) {
            (Some(b'\n'), _) => e + 1,
            (Some(b'\r'), Some(b'\n')) => e + 2,
            _ => break,
        };
        let mut k = next;
        while k < bytes.len() && matches!(bytes[k], b' ' | b'\t') {
            k += 1;
        }
        let run_start = k;
        while k < bytes.len() && is_base64_byte(bytes[k]) {
            k += 1;
        }
        // The last line of a wrapped blob is often short; take it if the
        // blob already spans a full line before it.
        if k == run_start {
            break;
        }
        lines.push((run_start, k));
        (s, e) = (run_start, k);
    }
    // A short run that only starts the next line (`abc` in `…\nabc def`)
    // is not a continuation unless it ends its own line or the blob there.
    if lines.len() > 1 {
        let &(ls, le) = lines.last().unwrap();
        let ends_line = matches!(bytes.get(le), None | Some(b'\n' | b'\r'));
        let ends_blob = matches!(bytes.get(le), Some(b'"' | b'\'' | b'`'));
        if le - ls < WRAPPED_MIN_LINE && !ends_line && !ends_blob {
            lines.pop();
        }
    }
    lines
}

/// The share of adjacent byte pairs in `span` that differ by exactly one.
fn sequential_share(span: &[u8]) -> f32 {
    if span.len() < 2 {
        return 0.0;
    }
    let seq = span.windows(2).filter(|w| w[0].abs_diff(w[1]) == 1).count();
    seq as f32 / (span.len() - 1) as f32
}

const BASE64_LONG_SPAN: usize = 256;
const BASE64_SHORT_MIN_RATIO: f32 = 0.85;
const BASE64_LONG_MIN_RATIO: f32 = 0.70;

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
        // Base64 wrapped over lines (60, 64, or 76 characters each, as
        // `base64` and MIME write it) is one blob: join its lines and judge
        // it once, rather than as a scatter of per-line findings.
        let lines = wrapped_lines(bytes, start, i);
        i = lines.last().map_or(i, |&(_, e)| e);
        let end = i;
        let joined: Vec<u8>;
        let span: &[u8] = if lines.len() > 1 {
            joined = lines
                .iter()
                .flat_map(|&(s, e)| bytes[s..e].iter().copied())
                .collect();
            &joined
        } else {
            &bytes[start..end]
        };
        let len = span.len();
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

        if lines.len() == 1 && is_sri_digest(bytes, start, end) {
            continue;
        }
        if is_path_like(span) || wordy_share(span) >= WORDY_MIN_SHARE {
            continue;
        }
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
        // Reject repetitive spans that zlib squeezes well. Random base64
        // carries 6 bits per 8-bit char, so long blobs converge on a ratio
        // of ~0.75; the floor for those must sit below that asymptote or
        // large payloads go unseen. Short spans keep a stricter floor, since
        // zlib's fixed overhead inflates their ratio (random 64-char base64
        // sits near 1.1) and a lenient floor admits repetitive identifiers.
        // An alphabet (base64's own, Base32's, a custom one), written out in
        // order: incompressible to zlib at this length, but not data.
        if sequential_share(span) >= ALPHABET_MIN_SEQUENTIAL {
            continue;
        }
        let ratio = compression_ratio(span);
        let min_ratio = if len >= BASE64_LONG_SPAN {
            BASE64_LONG_MIN_RATIO
        } else {
            BASE64_SHORT_MIN_RATIO
        };
        if ratio < min_ratio {
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
            message: if lines.len() > 1 {
                format!(
                    "base64-like blob ({} bytes over {} lines, compression ratio {:.2})",
                    len,
                    lines.len(),
                    ratio
                )
            } else {
                format!(
                    "base64-like blob ({} bytes, compression ratio {:.2})",
                    len, ratio
                )
            },
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
    fn file_paths_are_not_base64_blobs() {
        let blobs = |src: &str| {
            let idx = LineIndex::new(src.as_bytes());
            find_base64_blobs(Path::new("x.md"), src.as_bytes(), &idx).len()
        };
        // TypeScript's canWatch baselines.
        for path in [
            "//vda1cs4850/workspaces/folderAtRoot/folder1/folder2/folder3/folder4/node_modules",
            "/home/src/workspaces/project/node_modules/typescript/lib/lib2d3dts/Foo99",
            "c:/Users/username1/AppData/Local/Temp/folder1/folder2/folder3/file4dts",
        ] {
            assert_eq!(blobs(&format!("| true | {path} |\n")), 0, "{path}");
        }
        // Encoded data that happens to contain slashes still is.
        let data = "ms1gomXicKOD6eCkaq5wpTWnYKZTyvCnFYlgqDOs8Kj+peCqE47wqt6H4KvzcPCsvmngrdNS8K6e";
        assert_eq!(blobs(&format!("x = \"{data}\"\n")), 1);
        let slashy =
            "YLzk1/C9r9DgvsS58L/PsuDApJvwwW/U4MKEffDDT3bg/xGRf8MUvWODGTXxwxw864MgtXnDIFdg==";
        assert_eq!(blobs(&format!("x = \"{slashy}\"\n")), 1);
    }

    #[test]
    fn words_are_not_base64_blobs() {
        let blobs = |src: &str| {
            let idx = LineIndex::new(src.as_bytes());
            find_base64_blobs(Path::new("x.js"), src.as_bytes(), &idx).len()
        };
        // TypeScript's baseline headers: sparse slashes, but words.
        let header = "//// [tests/cases/compiler/ClassDeclarationWithInvalidConstOnPropertyDeclaration2.ts]\n";
        assert_eq!(blobs(header), 0);
        assert!(
            wordy_share(b"tests/cases/compiler/ClassDeclarationWithInvalidConst")
                >= WORDY_MIN_SHARE
        );
        // Base64, of JSON (an inline source map) or of random bytes, is not.
        let map = "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib3V0ZmlsZS5qcyIsInNvdXJjZVJvb3QiOiIifQ==\n";
        assert_eq!(blobs(map), 1);
        assert!(
            wordy_share(
                b"ms1gomXicKOD6eCkaq5wpTWnYKZTyvCnFYlgqDOs8Kj+peCqE47wqt6H4KvzcPCsvmngrdNS8K6e"
            ) < 0.3
        );
    }

    #[test]
    fn wrapped_base64_is_one_blob() {
        let find = |src: &str| {
            let idx = LineIndex::new(src.as_bytes());
            find_base64_blobs(Path::new("test_tz.py"), src.as_bytes(), &idx)
                .into_iter()
                .map(|f| (f.line, f.message))
                .collect::<Vec<_>>()
        };
        // python-dateutil's tests: a TZif file as base64 wrapped at 76.
        let blob = "VFppZgAAAAAAAAAAAAAAAAAAAAAAAAAEAAAABAAAABcAAADrAAAABAAAABCeph5wn7rrYKCGAHCh\n\
                    ms1gomXicKOD6eCkaq5wpTWnYKZTyvCnFYlgqDOs8Kj+peCqE47wqt6H4KvzcPCsvmngrdNS8K6e\n\
                    S+CvszTwsH4t4LGcUXCyZ0pgs3wzcLRHLGC1XBVwticOYLc793C4BvBguRvZcLnm0mC7BPXwu8a0\n\
                    YLzk1/C9r9DgvsS58L+PsuDApJvwwW+U4MKEffDDT3bgxGRf8MUvWODGTXxwxw864MgtXnDI+Fdg\n\
                    yg1AcMrYOWDLiPBw0iP0cNJg++DTdeTw1EDd4NVVxvDWIL/g1zWo8NgAoeDZ\n";
        let got = find(&format!("TZFILE = b\"\"\"\n{blob}\"\"\"\n"));
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, 2);
        assert!(got[0].1.contains("over 5 lines"), "{}", got[0].1);
        // Indented continuation lines (a PEM body in YAML) join too.
        let indented = blob
            .lines()
            .map(|l| format!("    {l}\n"))
            .collect::<String>();
        assert_eq!(find(&format!("key: |\n{indented}")).len(), 1);
        // A single long line is reported as before, without a line count.
        let one = find(&format!("x = \"{}\"\n", blob.lines().nth(1).unwrap()));
        assert_eq!(one.len(), 1);
        assert!(!one[0].1.contains("lines"), "{}", one[0].1);
    }

    #[test]
    fn sri_integrity_hashes_are_not_base64_blobs() {
        let blobs = |src: &str| {
            let idx = LineIndex::new(src.as_bytes());
            find_base64_blobs(Path::new("pnpm-lock.yaml"), src.as_bytes(), &idx).len()
        };
        let sha512 = "Ttkx4a7Y1z9QmB2rC3sD4tE5uF6vG7wH8xI9yJ0zK1aL2bM3cN4dO5eP6fQ7gR8hS9iT0jU1kV2lW3mX4n+Yvq==";
        let sha384 = "oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC";
        let sha256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        assert_eq!(sha512.len(), 88);
        for (alg, digest) in [("sha512", sha512), ("sha384", sha384), ("sha256", sha256)] {
            assert_eq!(
                blobs(&format!("  resolution: {{integrity: {alg}-{digest}}}\n")),
                0,
                "{alg}"
            );
        }
        assert_eq!(
            blobs(&format!(
                "<script integrity=\"sha384-{sha384}\"></script>\n"
            )),
            0
        );
        // The same characters without the prefix, or with a digest of the
        // wrong length behind it, are still base64.
        assert_eq!(blobs(&format!("data = \"{sha512}\"\n")), 1);
        assert_eq!(blobs(&format!("x: sha512-{sha512}{sha384}\n")), 1);
    }

    #[test]
    fn alphabet_tables_are_not_base64_blobs() {
        let blobs = |src: &str| {
            let idx = LineIndex::new(src.as_bytes());
            find_base64_blobs(Path::new("a.rs"), src.as_bytes(), &idx).len()
        };
        // The base64 crate's alphabets, including its deliberately broken
        // test alphabets, reversed, and Base32.
        for alphabet in [
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "AACDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZZbcdefghijklmnopqrstuvwxyz0123456789-_",
            "xxxxxxxxxABCDEFGHIJKLMNOPQRSTUVWXYZZbcdefghijklmnopqrstuvwxyz0123456789+/",
            "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA",
        ] {
            assert_eq!(
                blobs(&format!("let a = \"{alphabet}\";\n")),
                0,
                "{alphabet}"
            );
        }
        // Real encoded data still is (from the crate's own tests).
        let data = "z3Uuv7+Xsn+acg0ZNRsw1/ZEl1FJEMw3kV0N0MaAWbPeUBTyvyVgWiUemvU6kIFqi0RqNs7Fo8IuBCYW7bZq3Q==";
        assert_eq!(blobs(&format!("let b = \"{data}\";\n")), 1);
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

    /// Deterministic pseudo-random base64 text (LCG over the alphabet), so
    /// the test exercises an incompressible blob without a `rand` dependency.
    fn pseudo_random_base64(len: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                ALPHABET[(state >> 58) as usize] as char
            })
            .collect()
    }

    #[test]
    fn flags_large_base64_blob() {
        // Random base64 compresses to ~0.75 once zlib's fixed overhead is
        // amortized; a multi-KB payload must not slip under the ratio floor.
        let src = format!("data = b'{}'\n", pseudo_random_base64(4096));
        let findings = run(src.as_bytes());
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SignalKind::EncodingBase64),
            "expected base64 finding on 4 KB blob, got {:?}",
            findings
        );
    }

    #[test]
    fn short_low_ratio_span_is_ignored() {
        // Hex-like identifier with a stray capital: mixed case and digits,
        // but repetitive enough to compress to ~0.71.
        let span = "Ree183a1e18390e183ade1839be18394e1839ae18390e183935fe18392e18394e1839b";
        let src = format!("s = \"{}\"\n", span);
        let findings = run(src.as_bytes());
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SignalKind::EncodingBase64),
            "short repetitive span must not trigger base64: {:?}",
            findings
        );
    }

    #[test]
    fn repetitive_base64_alphabet_span_is_ignored() {
        let src = format!("data = \"{}\"\n", "Ab1Cd2Ef3Gh4".repeat(64));
        let findings = run(src.as_bytes());
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SignalKind::EncodingBase64),
            "repetitive span must not trigger base64: {:?}",
            findings
        );
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
