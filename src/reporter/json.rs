//! JSON reporter — pretty-prints the filtered `ScanResult`.
//!
//! Threshold filtering applies to individual findings but per-file metadata
//! (path, language, complexity stats) is always preserved so downstream
//! consumers can see which files were scanned even if they produced nothing.

use std::io::{self, Write};

use serde::Serialize;
use serde_json::Value;

use crate::finding::{FileAnalysis, Finding, ScanResult, Severity};
use crate::llm::{LLMReview, LLMVerdict, finding_key};

pub fn render(
    result: &ScanResult,
    threshold: Severity,
    llm_review: Option<&LLMReview>,
    writer: &mut dyn Write,
) -> io::Result<()> {
    if llm_review.is_none() {
        return render_plain(result, threshold, writer);
    }
    render_enriched(result, threshold, llm_review.unwrap(), writer)
}

fn render_plain(
    result: &ScanResult,
    threshold: Severity,
    writer: &mut dyn Write,
) -> io::Result<()> {
    let filtered = filter_result(result, threshold);
    serde_json::to_writer_pretty(&mut *writer, &filtered).map_err(io::Error::other)?;
    writeln!(writer)
}

fn render_enriched(
    result: &ScanResult,
    threshold: Severity,
    llm_review: &LLMReview,
    writer: &mut dyn Write,
) -> io::Result<()> {
    #[derive(Serialize)]
    struct FindingWithVerdict<'a> {
        #[serde(flatten)]
        finding: &'a Finding,
        llm_verdict: Option<&'a LLMVerdict>,
    }

    #[derive(Serialize)]
    struct FileWithVerdicts<'a> {
        #[serde(flatten)]
        meta: FileAnalysisMeta<'a>,
        findings: Vec<FindingWithVerdict<'a>>,
    }

    #[derive(Serialize)]
    struct FileAnalysisMeta<'a> {
        path: &'a std::path::PathBuf,
        language: crate::language::Language,
        file_complexity_mean: f32,
        file_complexity_max: f32,
        parse_error: &'a Option<String>,
    }

    let files: Vec<FileWithVerdicts<'_>> = result
        .files
        .iter()
        .map(|fa| {
            let findings: Vec<FindingWithVerdict<'_>> = fa
                .findings
                .iter()
                .filter(|f| f.severity >= threshold)
                .map(|f| FindingWithVerdict {
                    llm_verdict: llm_review.get(&finding_key(f)),
                    finding: f,
                })
                .collect();
            FileWithVerdicts {
                meta: FileAnalysisMeta {
                    path: &fa.path,
                    language: fa.language,
                    file_complexity_mean: fa.file_complexity_mean,
                    file_complexity_max: fa.file_complexity_max,
                    parse_error: &fa.parse_error,
                },
                findings,
            }
        })
        .collect();

    let findings_total: usize = files.iter().map(|f| f.findings.len()).sum();
    let files_with_findings = files.iter().filter(|f| !f.findings.is_empty()).count();

    let doc: Value = serde_json::json!({
        "root": result.root,
        "files_scanned": result.files_scanned,
        "files_with_findings": files_with_findings,
        "findings_total": findings_total,
        "findings_by_severity": result.findings_by_severity,
        "diff_ref": result.diff_ref,
        "files": files,
    });

    serde_json::to_writer_pretty(&mut *writer, &doc).map_err(io::Error::other)?;
    writeln!(writer)
}

fn filter_result(result: &ScanResult, threshold: Severity) -> ScanResult {
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

    ScanResult {
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
    }
}
