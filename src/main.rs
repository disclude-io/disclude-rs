use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use disclude::finding::Severity;
use disclude::language::Language;
use disclude::reporter::{self, OutputFormat};
use disclude::scan::{self, ScanOptions};

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args),
    }
}

fn run_scan(args: ScanArgs) -> ExitCode {
    let format = match OutputFormat::parse(&args.format) {
        Some(f) => f,
        None => {
            eprintln!("disclude: unknown format '{}'", args.format);
            return ExitCode::from(2);
        }
    };
    let threshold = match Severity::parse(&args.severity) {
        Some(s) => s,
        None => {
            eprintln!("disclude: unknown severity '{}'", args.severity);
            return ExitCode::from(2);
        }
    };
    let lang_override = if let Some(lang) = &args.lang {
        match Language::parse_flag(lang) {
            Some(l) => Some(l),
            None => {
                eprintln!("disclude: unknown language '{}'", lang);
                return ExitCode::from(2);
            }
        }
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

    let result = match scan::scan(&args.path, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("disclude: scan failed: {:#}", e);
            return ExitCode::from(2);
        }
    };

    let mut stdout = std::io::stdout().lock();
    if let Err(e) = reporter::report(&result, threshold, format, &mut stdout) {
        eprintln!("disclude: report failed: {}", e);
        return ExitCode::from(2);
    }

    if args.exit_code {
        let hit = result
            .files
            .iter()
            .flat_map(|fa| fa.findings.iter())
            .any(|f| f.severity >= threshold);
        if hit {
            return ExitCode::from(1);
        }
    }
    ExitCode::from(0)
}
