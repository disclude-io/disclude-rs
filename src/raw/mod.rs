//! Language-agnostic raw-byte analyses. Operates on original source bytes;
//! never normalizes, never converts to `String` or `&str` before preserving
//! byte offsets.

use std::path::Path;

use crate::finding::Finding;
use crate::util::LineIndex;

pub mod complexity;
pub mod encoding;
pub mod structural;
pub mod unicode;

/// Run every raw-pass analyzer and return the combined findings plus per-file
/// compression-ratio stats (mean, max) for downstream use.
pub fn analyze(path: &Path, bytes: &[u8], index: &LineIndex) -> (Vec<Finding>, (f32, f32)) {
    analyze_lang(path, bytes, index, None)
}

/// [`analyze`] for a file of known language, which lets language-dependent
/// raw signals (mixed indentation) apply only where they mean something.
pub fn analyze_lang(
    path: &Path,
    bytes: &[u8],
    index: &LineIndex,
    lang: Option<crate::language::Language>,
) -> (Vec<Finding>, (f32, f32)) {
    let mut findings = Vec::new();

    findings.extend(unicode::analyze(path, bytes, index));
    findings.extend(encoding::analyze(path, bytes, index));
    findings.extend(structural::analyze_lang(path, bytes, index, lang));
    let (complexity_findings, stats) = complexity::analyze(path, bytes, index);
    findings.extend(complexity_findings);

    (findings, stats)
}
