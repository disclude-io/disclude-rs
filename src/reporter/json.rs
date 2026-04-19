//! JSON reporter — pretty-prints the filtered `ScanResult`.
//!
//! Threshold filtering applies to individual findings but per-file metadata
//! (path, language, complexity stats) is always preserved so downstream
//! consumers can see which files were scanned even if they produced nothing.

use std::io::{self, Write};

use crate::finding::{FileAnalysis, ScanResult, Severity};

pub fn render(result: &ScanResult, threshold: Severity, writer: &mut dyn Write) -> io::Result<()> {
    let filtered_files: Vec<FileAnalysis> = result
        .files
        .iter()
        .map(|fa| FileAnalysis {
            path: fa.path.clone(),
            language: fa.language,
            findings: fa
                .findings
                .iter()
                .filter(|f| f.severity >= threshold)
                .cloned()
                .collect(),
            file_complexity_mean: fa.file_complexity_mean,
            file_complexity_max: fa.file_complexity_max,
            parse_error: fa.parse_error.clone(),
        })
        .collect();

    let filtered = ScanResult {
        root: result.root.clone(),
        files_scanned: result.files_scanned,
        files_with_findings: filtered_files
            .iter()
            .filter(|fa| !fa.findings.is_empty())
            .count(),
        findings_total: filtered_files.iter().map(|fa| fa.findings.len()).sum(),
        findings_by_severity: result.findings_by_severity.clone(),
        files: filtered_files,
        diff_ref: result.diff_ref.clone(),
    };

    serde_json::to_writer_pretty(&mut *writer, &filtered).map_err(io::Error::other)?;
    writeln!(writer)?;
    Ok(())
}
