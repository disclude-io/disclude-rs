//! Human-readable reporter — columnar per-finding lines, followed by a summary.

use std::io::{self, Write};

use crate::finding::{Finding, ScanResult, Severity};
use crate::llm::{finding_key, LLMReview, Verdict};

pub fn render(
    result: &ScanResult,
    threshold: Severity,
    llm_review: Option<&LLMReview>,
    writer: &mut dyn Write,
) -> io::Result<()> {
    let mut shown: Vec<&Finding> = result
        .files
        .iter()
        .flat_map(|fa| fa.findings.iter())
        .filter(|f| f.severity >= threshold)
        .collect();
    shown.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.byte_offset.cmp(&b.byte_offset))
    });

    if shown.is_empty() {
        writeln!(
            writer,
            "disclude: scanned {} files, no findings at or above {} threshold",
            result.files_scanned,
            threshold.as_str()
        )?;
    } else {
        for f in &shown {
            let location = format!("{}:{}", f.path.display(), f.line);
            let severity = sev_label(f.severity);
            let new_marker = if f.diff_introduced { "[NEW] " } else { "" };
            writeln!(
                writer,
                "{:<9} {:<32}:\n{:<10}{} {}{}",
                severity,
                location,
                "",
                f.kind.as_str(),
                new_marker,
                f.message,
            )?;
            if let Some(review) = llm_review {
                if let Some(v) = review.get(&finding_key(f)) {
                    let label = verdict_label(v.verdict);
                    writeln!(
                        writer,
                        "{:<10}llm [{}/{}  {:.0}%] {}",
                        "",
                        v.score,
                        label,
                        v.confidence * 100.0,
                        v.summary,
                    )?;
                }
            }
        }
        writeln!(writer)?;
    }

    // Summary of full finding set (not threshold-filtered), matching the
    // spec's example output.
    let total = result.findings_total;
    let by_sev = &result.findings_by_severity;
    let critical = by_sev.get(&Severity::Critical).copied().unwrap_or(0);
    let warn = by_sev.get(&Severity::Warn).copied().unwrap_or(0);
    let info = by_sev.get(&Severity::Info).copied().unwrap_or(0);
    writeln!(
        writer,
        "{} findings ({} critical, {} warn, {} info) in {} files",
        total, critical, warn, info, result.files_scanned
    )?;
    if let Some(dref) = &result.diff_ref {
        writeln!(writer, "diff base: {}", dref)?;
    }
    Ok(())
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Dismissed => "dismissed",
        Verdict::LikelyBenign => "likely_benign",
        Verdict::Inconclusive => "inconclusive",
        Verdict::Suspicious => "suspicious",
        Verdict::Confirmed => "confirmed",
    }
}
