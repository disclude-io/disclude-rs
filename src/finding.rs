use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::language::Language;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum PassKind {
    Raw,
    Token,
    Ast,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum SignalKind {
    // raw
    UnicodeBidi,
    UnicodeZeroWidth,
    UnicodeInvisible,
    UnicodeSurrogate,
    UnicodeMixedScript,
    UnicodeHomoglyph,
    EncodingBase64,
    EncodingHex,
    EncodingOctal,
    EncodingEscapeSoup,
    HighComplexity,
    LongLine,
    WhitespaceAnomaly,
    NarrowFileCharset,
    // token
    IdentifierNarrowCharset,
    IdentifierLowLength,
    IdentifierConfusableCollision,
    StringConcatConstruction,
    MacroAlias,
    MacroKeywordOverride,
    // ast
    DynamicExecution,
    DynamicImport,
    DynamicAttribute,
    BuildScriptShellout,
    ProcMacroPresence,
    InstallHookShellout,
    NumericLiteralPayload,
    FormatStringWrite,
    LegacyKAndRMain,
    LineContinuationInCode,
    ImplicitIntFunction,
    DynamicFormatString,
    EmbeddedNulInString,
    ReverseSubscriptNotation,
    RecursiveMainCall,
    StringifyDereference,
    PayloadBytesLiteral,
    DecoderImportWithExec,
}

impl SignalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignalKind::UnicodeBidi => "unicode-bidi",
            SignalKind::UnicodeZeroWidth => "unicode-zero-width",
            SignalKind::UnicodeInvisible => "unicode-invisible",
            SignalKind::UnicodeSurrogate => "unicode-surrogate",
            SignalKind::UnicodeMixedScript => "unicode-mixed-script",
            SignalKind::UnicodeHomoglyph => "unicode-homoglyph",
            SignalKind::EncodingBase64 => "encoding-base64",
            SignalKind::EncodingHex => "encoding-hex",
            SignalKind::EncodingOctal => "encoding-octal",
            SignalKind::EncodingEscapeSoup => "encoding-escape-soup",
            SignalKind::HighComplexity => "high-complexity",
            SignalKind::LongLine => "long-line",
            SignalKind::WhitespaceAnomaly => "whitespace-anomaly",
            SignalKind::NarrowFileCharset => "narrow-file-charset",
            SignalKind::IdentifierNarrowCharset => "identifier-narrow-charset",
            SignalKind::IdentifierLowLength => "identifier-low-length",
            SignalKind::IdentifierConfusableCollision => "identifier-confusable-collision",
            SignalKind::StringConcatConstruction => "string-concat-construction",
            SignalKind::MacroAlias => "macro-alias",
            SignalKind::MacroKeywordOverride => "macro-keyword-override",
            SignalKind::DynamicExecution => "dynamic-execution",
            SignalKind::DynamicImport => "dynamic-import",
            SignalKind::DynamicAttribute => "dynamic-attribute",
            SignalKind::BuildScriptShellout => "build-script-shellout",
            SignalKind::ProcMacroPresence => "proc-macro-presence",
            SignalKind::InstallHookShellout => "install-hook-shellout",
            SignalKind::NumericLiteralPayload => "numeric-literal-payload",
            SignalKind::FormatStringWrite => "format-string-write",
            SignalKind::LegacyKAndRMain => "legacy-k-and-r-main",
            SignalKind::LineContinuationInCode => "line-continuation-in-code",
            SignalKind::ImplicitIntFunction => "implicit-int-function",
            SignalKind::DynamicFormatString => "dynamic-format-string",
            SignalKind::EmbeddedNulInString => "embedded-nul-in-string",
            SignalKind::ReverseSubscriptNotation => "reverse-subscript-notation",
            SignalKind::RecursiveMainCall => "recursive-main-call",
            SignalKind::StringifyDereference => "stringify-dereference",
            SignalKind::PayloadBytesLiteral => "payload-bytes-literal",
            SignalKind::DecoderImportWithExec => "decoder-import-with-exec",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "warn" | "warning" => Some(Severity::Warn),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub path: PathBuf,
    pub byte_offset: usize,
    pub line: usize,
    pub col: usize,
    pub pass: PassKind,
    pub kind: SignalKind,
    pub severity: Severity,
    pub confidence: f32,
    pub message: String,
    pub snippet: String,
    pub diff_introduced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysis {
    pub path: PathBuf,
    pub language: Language,
    pub findings: Vec<Finding>,
    pub file_complexity_mean: f32,
    pub file_complexity_max: f32,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub root: PathBuf,
    pub files_scanned: usize,
    pub files_with_findings: usize,
    pub findings_total: usize,
    pub findings_by_severity: HashMap<Severity, usize>,
    pub files: Vec<FileAnalysis>,
    pub diff_ref: Option<String>,
}

/// Truncate a snippet to a reasonable context length for reporting.
/// Per spec: redact if > 120 chars.
pub fn redact_snippet(s: &str) -> String {
    const MAX: usize = 120;
    if s.len() <= MAX {
        s.to_string()
    } else {
        let mut end = MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}… ({} bytes total)", &s[..end], s.len())
    }
}
