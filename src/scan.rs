//! Scan orchestration: file resolution, per-file analysis, result aggregation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::ast;
use crate::ast::FileFlags;
use crate::diff;
use crate::embedded;
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
    analyses.sort_by(|a, b| a.path.cmp(&b.path));

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

    if language.is_markup() {
        // Markup files have no token/AST pass of their own. Extract embedded
        // code blocks and run the per-language passes over each slice, mapping
        // findings back to file coordinates. Raw-pass findings outside any
        // block are kept as-is — the global payload scan.
        findings = analyze_markup_blocks(path, &bytes, language, &index, findings, opts);
    } else {
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
    }

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

/// Token/AST analysis for markup files: extract embedded code blocks, scan each
/// under its own language, and merge results back into file coordinates.
///
/// `raw_findings` are the whole-file raw-pass findings. Those falling inside a
/// block are handed to that block's token pass (so they get real code-context
/// reclassification); those outside every block are kept verbatim as the file's
/// payload-scan findings. Findings emitted from a block are shifted from
/// block-local offsets back to file offsets and re-located via `file_index`.
fn analyze_markup_blocks(
    path: &Path,
    bytes: &[u8],
    language: Language,
    file_index: &LineIndex,
    raw_findings: Vec<crate::finding::Finding>,
    opts: &ScanOptions,
) -> Vec<crate::finding::Finding> {
    let blocks = embedded::extract(path, bytes, language);

    // Partition raw findings: inside a block (by byte offset) vs. file-level.
    let mut per_block: Vec<Vec<crate::finding::Finding>> = vec![Vec::new(); blocks.len()];
    let mut findings: Vec<crate::finding::Finding> = Vec::new();
    for f in raw_findings {
        match blocks
            .iter()
            .position(|b| f.byte_offset >= b.start && f.byte_offset < b.end)
        {
            Some(bi) => per_block[bi].push(f),
            None => findings.push(f),
        }
    }

    for (bi, block) in blocks.iter().enumerate() {
        let slice = &bytes[block.start..block.end];
        let local_index = LineIndex::new(slice);

        // Re-anchor the block's raw findings to block-local offsets so the
        // token pass can reclassify them against the real code structure.
        let mut block_findings = std::mem::take(&mut per_block[bi]);
        for f in &mut block_findings {
            f.byte_offset -= block.start;
            let (line, col) = local_index.locate(f.byte_offset);
            f.line = line;
            f.col = col;
        }

        if opts.run_token {
            block_findings = token::analyze(path, slice, block.lang, &local_index, block_findings);
        }

        let mut file_flags = FileFlags::default();
        if opts.run_ast {
            let outcome = ast::analyze(path, slice, block.lang);
            block_findings.extend(outcome.findings);
            file_flags = outcome.file_flags;
        }
        scorer::elevate(&mut block_findings, block.lang, file_flags);

        // Shift back to file coordinates, re-locate, and tag the origin.
        let tag = format!("[embedded {}] ", block.lang.as_str());
        for f in &mut block_findings {
            f.byte_offset += block.start;
            let (line, col) = file_index.locate(f.byte_offset);
            f.line = line;
            f.col = col;
            f.message = format!("{}{}", tag, f.message);
        }
        findings.extend(block_findings);
    }

    // Prose scan: malicious instructions in docs are often left *unfenced* to
    // dodge code-block extraction. For prose-bearing markup (Markdown, RST,
    // plain text — not YAML, whose shell lives in structured keys we already
    // extract), run the bash AST over the whole file and keep only high-signal
    // findings, skipping anything already covered by an extracted block.
    if opts.run_ast && matches!(language, Language::Markdown | Language::Rst | Language::Text) {
        findings.extend(prose_high_signal_findings(path, bytes, &blocks));
    }

    findings
}

/// Whether a bash-AST finding is worth surfacing from free-form markup prose.
/// Restricted to the highest-signal shell behaviors — those that require a
/// literal dangerous keyword (`eval`, `| bash`, `rm -rf /`, `unzip -P`) — so
/// that parsing English text and Markdown tables as shell does not generate
/// noise. In particular the "dynamic command name" form of `DynamicExecution`
/// (a bare `$VAR` in command position) is excluded: `$`-sigils are pervasive
/// in prose and would fire constantly.
fn is_prose_high_signal(f: &crate::finding::Finding) -> bool {
    use crate::finding::SignalKind::*;
    match f.kind {
        DestructiveCommandPayload | EncryptedArchiveExtraction => true,
        DynamicExecution => !f.message.contains("command name is a variable"),
        _ => false,
    }
}

/// Run the bash AST over an entire markup file and return its high-signal
/// findings that fall outside any already-extracted code block. Offsets are
/// file-relative (the whole file is parsed), so no remapping is needed.
fn prose_high_signal_findings(
    path: &Path,
    bytes: &[u8],
    blocks: &[embedded::CodeBlock],
) -> Vec<crate::finding::Finding> {
    ast::bash::analyze(path, bytes)
        .findings
        .into_iter()
        .filter(is_prose_high_signal)
        .filter(|f| {
            !blocks
                .iter()
                .any(|b| f.byte_offset >= b.start && f.byte_offset < b.end)
        })
        .filter(|f| !is_doc_reference(bytes, f.byte_offset))
        .map(|mut f| {
            f.message = format!("[markup prose] {}", f.message);
            f
        })
        .collect()
}

/// Heuristic: is the command at `offset` a documentation *reference* rather than
/// an executable *instruction*? Docs cite commands inside `` `inline code` ``
/// spans and Markdown table cells; malicious instructions are typically bare,
/// copy-pasteable prose. Excluding code spans and table rows removes the common
/// false positive of a README that documents a dangerous command as an example.
fn is_doc_reference(bytes: &[u8], offset: usize) -> bool {
    let line_start = bytes[..offset]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    // Markdown table row: the line's first non-space byte is a pipe.
    let first = bytes[line_start..offset]
        .iter()
        .find(|&&b| !b.is_ascii_whitespace());
    if first == Some(&b'|') {
        return true;
    }
    // Inline code span: an odd number of backticks precede the offset on this
    // line, so the offset sits between an opening and closing backtick.
    let backticks = bytes[line_start..offset]
        .iter()
        .filter(|&&b| b == b'`')
        .count();
    backticks % 2 == 1
}
