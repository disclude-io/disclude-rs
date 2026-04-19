//! Scan orchestration: file resolution, per-file analysis, result aggregation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::ast;
use crate::ast::FileFlags;
use crate::diff;
use crate::finding::{FileAnalysis, ScanResult, Severity};
use crate::ignore::walk;
use crate::language::Language;
use crate::package_json;
use crate::raw;
use crate::scorer;
use crate::token;
use crate::util::LineIndex;

/// File-size ceiling: files larger than this are skipped. Pragmatic guard
/// against accidentally scanning large data files.
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Null-byte probe size for binary detection.
const BINARY_PROBE_BYTES: usize = 8192;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub lang_override: Option<Language>,
    pub run_raw: bool,
    pub run_token: bool,
    pub run_ast: bool,
    pub ignore_path: Option<PathBuf>,
    pub diff_ref: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            lang_override: None,
            run_raw: true,
            run_token: true,
            run_ast: true,
            ignore_path: None,
            diff_ref: None,
        }
    }
}

pub fn scan(root: &Path, opts: &ScanOptions) -> Result<ScanResult> {
    let files = walk(root, opts.ignore_path.as_deref());

    let mut analyses: Vec<FileAnalysis> = files
        .par_iter()
        .filter_map(|path| match analyze_file(path, opts) {
            Ok(Some(fa)) => Some(fa),
            Ok(None) => None,
            Err(err) => {
                eprintln!("disclude: {}: {}", path.display(), err);
                None
            }
        })
        .collect();

    if let Some(git_ref) = opts.diff_ref.as_deref() {
        match diff::compute_added_lines(root, git_ref) {
            Ok(added) => {
                for fa in analyses.iter_mut() {
                    if let Some(lines) = added.get(&fa.path) {
                        for f in fa.findings.iter_mut() {
                            if lines.contains(&f.line) {
                                f.diff_introduced = true;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "disclude: --diff annotation skipped: {:#}; continuing without diff info",
                    e
                );
            }
        }
    }

    let mut findings_by_severity: HashMap<Severity, usize> = HashMap::new();
    let mut findings_total = 0usize;
    let mut files_with_findings = 0usize;
    for fa in &analyses {
        if !fa.findings.is_empty() {
            files_with_findings += 1;
        }
        findings_total += fa.findings.len();
        for f in &fa.findings {
            *findings_by_severity.entry(f.severity).or_insert(0) += 1;
        }
    }

    Ok(ScanResult {
        root: root.to_path_buf(),
        files_scanned: analyses.len(),
        files_with_findings,
        findings_total,
        findings_by_severity,
        files: analyses,
        diff_ref: opts.diff_ref.clone(),
    })
}

fn analyze_file(path: &Path, opts: &ScanOptions) -> Result<Option<FileAnalysis>> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("stat failed for {}", path.display()))?;
    if metadata.len() > MAX_FILE_BYTES {
        return Ok(None);
    }

    let bytes =
        std::fs::read(path).with_context(|| format!("read failed for {}", path.display()))?;

    // Binary detection: any NUL in the probe window disqualifies.
    let probe = &bytes[..bytes.len().min(BINARY_PROBE_BYTES)];
    if probe.contains(&0) {
        return Ok(None);
    }

    // Special-case: package.json gets its own JSON-structured analyzer
    // (install-hook shellout detection) instead of the raw/token/ast flow,
    // which expects a source-code file.
    if path.file_name().and_then(|n| n.to_str()) == Some("package.json") {
        let findings = package_json::analyze(path, &bytes);
        return Ok(Some(FileAnalysis {
            path: path.to_path_buf(),
            language: Language::JavaScript,
            findings,
            file_complexity_mean: 0.0,
            file_complexity_max: 0.0,
            parse_error: None,
        }));
    }

    let language = match opts.lang_override {
        Some(l) => l,
        None => match Language::detect(path, &bytes) {
            Some(l) => l,
            None => return Ok(None),
        },
    };

    let index = LineIndex::new(&bytes);
    let mut findings = Vec::new();
    let mut complexity_mean = 0.0_f32;
    let mut complexity_max = 0.0_f32;
    let mut parse_error: Option<String> = None;
    let mut file_flags = FileFlags::default();

    if opts.run_raw {
        let (raw_findings, (mean, max)) = raw::analyze(path, &bytes, &index);
        findings.extend(raw_findings);
        complexity_mean = mean;
        complexity_max = max;
    }

    if opts.run_token {
        findings = token::analyze(path, &bytes, language, &index, findings);
    }

    if opts.run_ast {
        let outcome = ast::analyze(path, &bytes, language);
        findings.extend(outcome.findings);
        parse_error = outcome.parse_error;
        file_flags = outcome.file_flags;
    }

    scorer::elevate(&mut findings, language, file_flags);

    findings.sort_by_key(|f| (f.byte_offset, f.kind.as_str()));

    Ok(Some(FileAnalysis {
        path: path.to_path_buf(),
        language,
        findings,
        file_complexity_mean: complexity_mean,
        file_complexity_max: complexity_max,
        parse_error,
    }))
}
