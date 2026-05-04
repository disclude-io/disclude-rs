//! SARIF 2.1.0 reporter — standard format for CI integration.
//!
//! Per SPEC §output: each `Finding` maps to a SARIF `result` with `ruleId`
//! from `SignalKind`, `level` from `Severity`, and `physicalLocation` from
//! `path` + `byte_offset`. Findings below the threshold are filtered out;
//! the rules list always contains every `SignalKind` so consumers can
//! deduplicate against a stable rule catalog.

use std::io::{self, Write};

use serde_json::{json, Map, Value};

use crate::finding::{Finding, ScanResult, Severity, SignalKind};

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_NAME: &str = "disclude";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const TOOL_URI: &str = "https://github.com/disclude-io/disclude-rs";

pub fn render(result: &ScanResult, threshold: Severity, writer: &mut dyn Write) -> io::Result<()> {
    let rules = build_rules();
    let results = build_results(result, threshold);

    let doc = json!({
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": { "uri": uri_from_root(result) }
                },
                "results": results,
            }
        ]
    });

    serde_json::to_writer_pretty(&mut *writer, &doc).map_err(io::Error::other)?;
    writeln!(writer)?;
    Ok(())
}

fn build_rules() -> Vec<Value> {
    ALL_KINDS
        .iter()
        .map(|kind| {
            json!({
                "id": kind.as_str(),
                "name": kind_pascal_name(*kind),
                "shortDescription": { "text": kind_short_description(*kind) },
                "defaultConfiguration": {
                    "level": sarif_level(kind_default_severity(*kind)),
                },
            })
        })
        .collect()
}

fn build_results(result: &ScanResult, threshold: Severity) -> Vec<Value> {
    let mut out = Vec::new();
    for fa in &result.files {
        let uri = relative_uri(&result.root, &fa.path);
        for f in &fa.findings {
            if f.severity < threshold {
                continue;
            }
            out.push(finding_to_result(f, &uri));
        }
    }
    out
}

fn finding_to_result(f: &Finding, uri: &str) -> Value {
    let mut properties = Map::new();
    properties.insert("confidence".into(), Value::from(f64::from(f.confidence)));
    properties.insert("pass".into(), Value::from(pass_str(f.pass)));
    properties.insert("diffIntroduced".into(), Value::from(f.diff_introduced));
    if !f.snippet.is_empty() {
        properties.insert("snippet".into(), Value::from(f.snippet.clone()));
    }

    json!({
        "ruleId": f.kind.as_str(),
        "level": sarif_level(f.severity),
        "message": { "text": f.message.clone() },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "SRCROOT",
                    },
                    "region": {
                        "startLine": f.line,
                        "startColumn": f.col,
                        "byteOffset": f.byte_offset,
                    }
                }
            }
        ],
        "properties": Value::Object(properties),
    })
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "error",
        Severity::Warn => "warning",
        Severity::Info => "note",
    }
}

fn pass_str(pass: crate::finding::PassKind) -> &'static str {
    match pass {
        crate::finding::PassKind::Raw => "raw",
        crate::finding::PassKind::Token => "token",
        crate::finding::PassKind::Ast => "ast",
    }
}

fn relative_uri(root: &std::path::Path, path: &std::path::Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn uri_from_root(result: &ScanResult) -> String {
    // SARIF URI base; use file:// if we have an absolute path, otherwise a
    // relative form. Consumers that don't need the base can ignore it.
    let s = result.root.to_string_lossy();
    if result.root.is_absolute() {
        format!("file://{}", s)
    } else {
        s.into_owned()
    }
}

/// Canonical list of rule IDs exposed in the SARIF rules array. Kept in
/// sync with `SignalKind` so every signal has a corresponding rule even
/// if no findings for that rule occurred in this run.
const ALL_KINDS: &[SignalKind] = &[
    SignalKind::UnicodeBidi,
    SignalKind::UnicodeZeroWidth,
    SignalKind::UnicodeInvisible,
    SignalKind::UnicodeSurrogate,
    SignalKind::UnicodeMixedScript,
    SignalKind::UnicodeHomoglyph,
    SignalKind::EncodingBase64,
    SignalKind::EncodingHex,
    SignalKind::EncodingOctal,
    SignalKind::EncodingEscapeSoup,
    SignalKind::HighComplexity,
    SignalKind::LongLine,
    SignalKind::WhitespaceAnomaly,
    SignalKind::NarrowFileCharset,
    SignalKind::IdentifierNarrowCharset,
    SignalKind::IdentifierLowLength,
    SignalKind::IdentifierConfusableCollision,
    SignalKind::StringConcatConstruction,
    SignalKind::MacroAlias,
    SignalKind::MacroKeywordOverride,
    SignalKind::DynamicExecution,
    SignalKind::DynamicImport,
    SignalKind::DynamicAttribute,
    SignalKind::BuildScriptShellout,
    SignalKind::ProcMacroPresence,
    SignalKind::InstallHookShellout,
    SignalKind::NumericLiteralPayload,
    SignalKind::FormatStringWrite,
    SignalKind::LegacyKAndRMain,
    SignalKind::LineContinuationInCode,
    SignalKind::ImplicitIntFunction,
    SignalKind::DynamicFormatString,
    SignalKind::EmbeddedNulInString,
    SignalKind::ReverseSubscriptNotation,
    SignalKind::RecursiveMainCall,
    SignalKind::StringifyDereference,
    SignalKind::PayloadBytesLiteral,
    SignalKind::DecoderImportWithExec,
    SignalKind::BuiltinsWrite,
    SignalKind::FrameIntrospection,
    SignalKind::ProxyGlobalHijack,
    SignalKind::TagFunctionDeobfuscator,
    SignalKind::DataUriImport,
    SignalKind::GeneratorYieldCallable,
    SignalKind::ErrorStackInspection,
    SignalKind::FunctionShadowing,
    SignalKind::ObfuscatedCommandName,
    SignalKind::IfsManipulation,
];

fn kind_pascal_name(k: SignalKind) -> &'static str {
    match k {
        SignalKind::UnicodeBidi => "UnicodeBidi",
        SignalKind::UnicodeZeroWidth => "UnicodeZeroWidth",
        SignalKind::UnicodeInvisible => "UnicodeInvisible",
        SignalKind::UnicodeSurrogate => "UnicodeSurrogate",
        SignalKind::UnicodeMixedScript => "UnicodeMixedScript",
        SignalKind::UnicodeHomoglyph => "UnicodeHomoglyph",
        SignalKind::EncodingBase64 => "EncodingBase64",
        SignalKind::EncodingHex => "EncodingHex",
        SignalKind::EncodingOctal => "EncodingOctal",
        SignalKind::EncodingEscapeSoup => "EncodingEscapeSoup",
        SignalKind::HighComplexity => "HighComplexity",
        SignalKind::LongLine => "LongLine",
        SignalKind::WhitespaceAnomaly => "WhitespaceAnomaly",
        SignalKind::NarrowFileCharset => "NarrowFileCharset",
        SignalKind::IdentifierNarrowCharset => "IdentifierNarrowCharset",
        SignalKind::IdentifierLowLength => "IdentifierLowLength",
        SignalKind::IdentifierConfusableCollision => "IdentifierConfusableCollision",
        SignalKind::StringConcatConstruction => "StringConcatConstruction",
        SignalKind::MacroAlias => "MacroAlias",
        SignalKind::MacroKeywordOverride => "MacroKeywordOverride",
        SignalKind::DynamicExecution => "DynamicExecution",
        SignalKind::DynamicImport => "DynamicImport",
        SignalKind::DynamicAttribute => "DynamicAttribute",
        SignalKind::BuildScriptShellout => "BuildScriptShellout",
        SignalKind::ProcMacroPresence => "ProcMacroPresence",
        SignalKind::InstallHookShellout => "InstallHookShellout",
        SignalKind::NumericLiteralPayload => "NumericLiteralPayload",
        SignalKind::FormatStringWrite => "FormatStringWrite",
        SignalKind::LegacyKAndRMain => "LegacyKAndRMain",
        SignalKind::LineContinuationInCode => "LineContinuationInCode",
        SignalKind::ImplicitIntFunction => "ImplicitIntFunction",
        SignalKind::DynamicFormatString => "DynamicFormatString",
        SignalKind::EmbeddedNulInString => "EmbeddedNulInString",
        SignalKind::ReverseSubscriptNotation => "ReverseSubscriptNotation",
        SignalKind::RecursiveMainCall => "RecursiveMainCall",
        SignalKind::StringifyDereference => "StringifyDereference",
        SignalKind::PayloadBytesLiteral => "PayloadBytesLiteral",
        SignalKind::DecoderImportWithExec => "DecoderImportWithExec",
        SignalKind::BuiltinsWrite => "BuiltinsWrite",
        SignalKind::FrameIntrospection => "FrameIntrospection",
        SignalKind::ProxyGlobalHijack => "ProxyGlobalHijack",
        SignalKind::TagFunctionDeobfuscator => "TagFunctionDeobfuscator",
        SignalKind::DataUriImport => "DataUriImport",
        SignalKind::GeneratorYieldCallable => "GeneratorYieldCallable",
        SignalKind::ErrorStackInspection => "ErrorStackInspection",
        SignalKind::FunctionShadowing => "FunctionShadowing",
        SignalKind::ObfuscatedCommandName => "ObfuscatedCommandName",
        SignalKind::IfsManipulation => "IfsManipulation",
    }
}

fn kind_short_description(k: SignalKind) -> &'static str {
    match k {
        SignalKind::UnicodeBidi => "Bidirectional control character (Trojan Source class)",
        SignalKind::UnicodeZeroWidth => "Zero-width character in identifier or string",
        SignalKind::UnicodeInvisible => {
            "Unicode Tags block character used as invisible identifier or hidden content"
        }
        SignalKind::UnicodeSurrogate => {
            "Surrogate pair escape sequence that decodes to an invisible tag character"
        }
        SignalKind::UnicodeMixedScript => {
            "Identifier mixes characters from multiple Unicode scripts"
        }
        SignalKind::UnicodeHomoglyph => "Identifier contains confusable homoglyph characters",
        SignalKind::EncodingBase64 => "Base64-shaped blob in a string literal",
        SignalKind::EncodingHex => "Long run of hex-escape sequences in a string literal",
        SignalKind::EncodingOctal => "Long run of octal-escape sequences in a string literal",
        SignalKind::EncodingEscapeSoup => "Dense run of arbitrary escape sequences",
        SignalKind::HighComplexity => "String literal with high entropy (high compression ratio)",
        SignalKind::LongLine => "Line length in a non-minified file exceeds threshold",
        SignalKind::WhitespaceAnomaly => "Unusual whitespace in indentation",
        SignalKind::NarrowFileCharset => "File uses a very small printable character vocabulary",
        SignalKind::IdentifierNarrowCharset => {
            "Identifier uses only visually confusable characters"
        }
        SignalKind::IdentifierLowLength => "File-wide mean identifier length is unusually short",
        SignalKind::IdentifierConfusableCollision => {
            "Two distinct identifiers in the same file collapse to the same visual skeleton"
        }
        SignalKind::StringConcatConstruction => {
            "String concatenation reconstructs a sensitive identifier"
        }
        SignalKind::MacroAlias => "Short C macro name aliases a sensitive function or syscall",
        SignalKind::MacroKeywordOverride => "C `#define` rebinds a reserved keyword",
        SignalKind::DynamicExecution => "exec/eval/Function/setTimeout invoked on a non-literal",
        SignalKind::DynamicImport => "Import or require with a constructed specifier",
        SignalKind::DynamicAttribute => "Attribute access by runtime-constructed name",
        SignalKind::BuildScriptShellout => {
            "build.rs spawns a shell or network client at compile time"
        }
        SignalKind::ProcMacroPresence => "Crate defines a proc-macro (runs at compile time)",
        SignalKind::InstallHookShellout => "package.json install hook shells out",
        SignalKind::NumericLiteralPayload => {
            "Wide-numeric array reinterpreted via byte-pointer cast (data smuggling)"
        }
        SignalKind::FormatStringWrite => {
            "printf format string contains %n write directive (memory write primitive)"
        }
        SignalKind::LegacyKAndRMain => "main() defined without a return type (pre-ANSI K&R style)",
        SignalKind::LineContinuationInCode => {
            "Backslash line continuation mid-expression (IOCCC-style obfuscation)"
        }
        SignalKind::ImplicitIntFunction => {
            "Many functions in this file lack an explicit return type (pre-ANSI K&R style)"
        }
        SignalKind::DynamicFormatString => "printf-family call uses a non-literal format string",
        SignalKind::EmbeddedNulInString => {
            "String literal contains an embedded NUL byte followed by more data"
        }
        SignalKind::ReverseSubscriptNotation => {
            "Array indexed with the integer on the left (`N[ptr]` form)"
        }
        SignalKind::RecursiveMainCall => "main() is called from within a function in this TU",
        SignalKind::StringifyDereference => {
            "`*#param` pattern in a #define body — stringify-then-dereference"
        }
        SignalKind::PayloadBytesLiteral => {
            "Bytes literal is dominated by `\\xNN` escapes (binary payload shape)"
        }
        SignalKind::DecoderImportWithExec => {
            "Decoder module import co-occurs with exec/eval/compile (multi-stage payload shape)"
        }
        SignalKind::BuiltinsWrite => {
            "Direct write to the builtins namespace — patches a built-in for every importer"
        }
        SignalKind::FrameIntrospection => {
            "Call-stack frame introspection (sys._getframe / inspect.* / settrace) — anti-analysis tell"
        }
        SignalKind::ProxyGlobalHijack => {
            "`new Proxy(...)` wraps a global object — interposes on every property access"
        }
        SignalKind::TagFunctionDeobfuscator => {
            "Tagged-template tag function decodes its template strings (reverse / atob / fromCharCode)"
        }
        SignalKind::DataUriImport => {
            "`import()` specifier is a `data:` URI — executes arbitrary code without touching disk"
        }
        SignalKind::GeneratorYieldCallable => {
            "Generator (`function*`) yields callables — state-machine deobfuscator pattern"
        }
        SignalKind::ErrorStackInspection => {
            "`new Error().stack` is read and string-matched — sandbox/analyzer detection"
        }
        SignalKind::FunctionShadowing => {
            "Shell function shadows a sensitive command — intercepts calls and may steal credentials"
        }
        SignalKind::ObfuscatedCommandName => {
            "Command name uses many backslash-escape sequences — hides the true command from static analysis"
        }
        SignalKind::IfsManipulation => {
            "`IFS` set to a non-whitespace separator — enables word-splitting of variable expansions into command arguments"
        }
    }
}

fn kind_default_severity(k: SignalKind) -> Severity {
    match k {
        SignalKind::UnicodeBidi
        | SignalKind::DynamicExecution
        | SignalKind::DynamicImport
        | SignalKind::BuildScriptShellout
        | SignalKind::NumericLiteralPayload
        | SignalKind::FormatStringWrite
        | SignalKind::BuiltinsWrite
        | SignalKind::ProxyGlobalHijack
        | SignalKind::TagFunctionDeobfuscator
        | SignalKind::DataUriImport
        | SignalKind::FunctionShadowing => Severity::Critical,
        SignalKind::LongLine | SignalKind::ProcMacroPresence => Severity::Info,
        _ => Severity::Warn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FileAnalysis, Finding, PassKind, SignalKind};
    use crate::language::Language;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn mk_finding() -> Finding {
        Finding {
            path: PathBuf::from("/tmp/root/src/a.py"),
            byte_offset: 42,
            line: 3,
            col: 7,
            pass: PassKind::Raw,
            kind: SignalKind::UnicodeBidi,
            severity: Severity::Critical,
            confidence: 0.95,
            message: "bidi control".into(),
            snippet: "x = '\u{202e}'".into(),
            diff_introduced: false,
        }
    }

    fn scan_with(f: Finding) -> ScanResult {
        ScanResult {
            root: PathBuf::from("/tmp/root"),
            files_scanned: 1,
            files_with_findings: 1,
            findings_total: 1,
            findings_by_severity: HashMap::new(),
            files: vec![FileAnalysis {
                path: f.path.clone(),
                language: Language::Python,
                findings: vec![f],
                file_complexity_mean: 0.0,
                file_complexity_max: 0.0,
                parse_error: None,
            }],
            diff_ref: None,
        }
    }

    fn render_to_value(result: &ScanResult, threshold: Severity) -> Value {
        let mut buf = Vec::new();
        render(result, threshold, &mut buf).expect("render ok");
        serde_json::from_slice(&buf).expect("valid json")
    }

    #[test]
    fn sarif_has_version_and_schema() {
        let r = scan_with(mk_finding());
        let v = render_to_value(&r, Severity::Warn);
        assert_eq!(v["version"], SARIF_VERSION);
        assert!(v["$schema"].is_string());
        assert!(v["runs"].is_array());
    }

    #[test]
    fn sarif_exposes_all_rule_ids() {
        let r = scan_with(mk_finding());
        let v = render_to_value(&r, Severity::Info);
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), ALL_KINDS.len());
    }

    #[test]
    fn critical_maps_to_error_level() {
        let r = scan_with(mk_finding());
        let v = render_to_value(&r, Severity::Warn);
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "error");
    }

    #[test]
    fn result_uri_is_relative_to_root() {
        let r = scan_with(mk_finding());
        let v = render_to_value(&r, Severity::Warn);
        let uri = v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(uri, "src/a.py");
    }

    #[test]
    fn below_threshold_findings_are_excluded() {
        let mut f = mk_finding();
        f.severity = Severity::Info;
        let r = scan_with(f);
        let v = render_to_value(&r, Severity::Warn);
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn region_carries_byte_offset() {
        let r = scan_with(mk_finding());
        let v = render_to_value(&r, Severity::Warn);
        let region = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["byteOffset"], 42);
        assert_eq!(region["startLine"], 3);
        assert_eq!(region["startColumn"], 7);
    }

    #[test]
    fn properties_include_confidence_pass_diff() {
        let r = scan_with(mk_finding());
        let v = render_to_value(&r, Severity::Warn);
        let props = &v["runs"][0]["results"][0]["properties"];
        assert!((props["confidence"].as_f64().unwrap() - 0.95).abs() < 1e-6);
        assert_eq!(props["pass"], "raw");
        assert_eq!(props["diffIntroduced"], false);
    }
}
