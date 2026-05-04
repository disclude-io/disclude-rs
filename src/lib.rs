//! disclude — detect obfuscation in source code packages.
//!
//! This is a source-tree scanner. It is not a vulnerability scanner, not a secrets
//! detector, and not a SAST engine. Its single question is: does this source appear
//! to hide its intent from a human reader?

pub mod ast;
pub mod diff;
pub mod finding;
pub mod ignore;
pub mod language;
pub mod llm;
pub mod package_json;
pub mod raw;
pub mod reporter;
pub mod scan;
pub mod scorer;
pub mod token;
pub mod util;

pub use finding::{FileAnalysis, Finding, PassKind, ScanResult, Severity, SignalKind};
pub use language::Language;
pub use scan::{scan, ScanOptions};

use clap::{Parser, Subcommand};
use reporter::OutputFormat;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "disclude",
    version,
    about = "Detect obfuscation in source code packages",
    long_about = "Scan a source tree for signs that the code is hiding its intent from a human \
                  reader (unicode attacks, encoded payloads, dynamic execution, etc.). \
                  Not a vulnerability scanner, not a secrets detector."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Recursively scan a source tree.
    Scan(ScanArgs),
}

#[derive(clap::Args, Debug)]
struct ScanArgs {
    /// Path to the source tree root.
    path: PathBuf,

    /// Override language detection (python|rust|ts|js).
    #[arg(long)]
    lang: Option<String>,

    /// Output format: human (default), json, sarif.
    #[arg(long, default_value = "human")]
    format: String,

    /// Minimum severity to report: info|warn|critical.
    #[arg(long, default_value = "warn")]
    severity: String,

    /// Exit non-zero if any findings at or above --severity threshold.
    #[arg(long)]
    exit_code: bool,

    /// Path to an additional ignore file (gitignore syntax).
    #[arg(long)]
    ignore: Option<PathBuf>,

    /// Annotate findings with recency against a git ref (e.g. `main`, a tag, a SHA).
    #[arg(long)]
    diff: Option<String>,

    /// Skip raw byte analysis (not recommended).
    #[arg(long)]
    no_raw: bool,

    /// Skip token-level analysis.
    #[arg(long)]
    no_token: bool,

    /// Skip AST analysis (faster, less accurate).
    #[arg(long)]
    no_ast: bool,

    /// Send findings to an LLM for validation (requires an API key in env).
    #[arg(long)]
    llm: bool,

    /// LLM provider: anthropic|openai|ollama (auto-detected from env if omitted).
    #[arg(long)]
    llm_provider: Option<String>,

    /// Override the default model for the selected provider.
    #[arg(long)]
    llm_model: Option<String>,

    /// Override the API base URL (e.g. a custom Ollama endpoint).
    #[arg(long)]
    llm_base_url: Option<String>,
}

/// Run the disclude CLI. `args[0]` should be the binary name (passed to clap as the program name).
/// Returns Ok(0) for success, Ok(1) for findings (with --exit-code), or Err on failure.
pub fn run_cli(args: Vec<String>) -> anyhow::Result<u8> {
    let cli = match Cli::try_parse_from(&args) {
        Ok(c) => c,
        Err(e) => {
            let code = e.exit_code() as u8;
            let _ = e.print();
            return Ok(code);
        }
    };

    match cli.command {
        Command::Scan(args) => run_scan_cli(args),
    }
}

fn run_scan_cli(args: ScanArgs) -> anyhow::Result<u8> {
    let format = OutputFormat::parse(&args.format)
        .ok_or_else(|| anyhow::anyhow!("unknown format '{}'", args.format))?;
    let threshold = Severity::parse(&args.severity)
        .ok_or_else(|| anyhow::anyhow!("unknown severity '{}'", args.severity))?;
    let lang_override = if let Some(ref lang) = args.lang {
        Some(
            Language::parse_flag(lang)
                .ok_or_else(|| anyhow::anyhow!("unknown language '{}'", lang))?,
        )
    } else {
        None
    };

    let opts = ScanOptions {
        lang_override,
        run_raw: !args.no_raw,
        run_token: !args.no_token,
        run_ast: !args.no_ast,
        ignore_path: args.ignore,
        diff_ref: args.diff,
    };

    let result = scan::scan(&args.path, &opts)?;

    let llm_review: Option<llm::LLMReview> = if args.llm {
        let config = llm::detect_provider(
            args.llm_provider.as_deref(),
            args.llm_model.as_deref(),
            args.llm_base_url.as_deref(),
        )?;
        eprintln!(
            "disclude: sending findings to {} for review…",
            config.provider_name()
        );
        Some(llm::review_scan(&result, &config)?)
    } else {
        None
    };

    let mut stdout = std::io::stdout().lock();
    reporter::report(&result, threshold, format, llm_review.as_ref(), &mut stdout)?;

    if args.exit_code {
        let hit = result
            .files
            .iter()
            .flat_map(|fa| fa.findings.iter())
            .any(|f| f.severity >= threshold);
        if hit {
            return Ok(1);
        }
    }
    Ok(0)
}
