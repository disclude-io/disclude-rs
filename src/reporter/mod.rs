//! Output reporters: render a `ScanResult` to stdout in the requested format.

use std::io::{self, Write};

use crate::finding::{ScanResult, Severity};
use crate::llm::LLMReview;

pub mod human;
pub mod json;
pub mod sarif;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "human" | "text" => Some(OutputFormat::Human),
            "json" => Some(OutputFormat::Json),
            "sarif" => Some(OutputFormat::Sarif),
            _ => None,
        }
    }
}

pub fn report(
    result: &ScanResult,
    threshold: Severity,
    format: OutputFormat,
    llm_review: Option<&LLMReview>,
    writer: &mut dyn Write,
) -> io::Result<()> {
    match format {
        OutputFormat::Human => human::render(result, threshold, llm_review, writer),
        OutputFormat::Json => json::render(result, threshold, llm_review, writer),
        OutputFormat::Sarif => sarif::render(result, threshold, llm_review, writer),
    }
}
