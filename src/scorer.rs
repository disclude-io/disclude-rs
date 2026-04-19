//! Severity elevation — post-pass scoring adjustments.
//!
//! Passes emit findings with a base severity. The scorer applies SPEC §scoring
//! elevation rules that depend on *combinations* of findings or file-level
//! context (e.g. presence of an `unsafe` block). It runs once per file after
//! raw + token + ast are done.
//!
//! Currently implements:
//!
//!   * **Rust `unsafe` + any Warn → Critical** (file scope). When a Rust
//!     file contains both an `unsafe { ... }` block (tracked as a
//!     `FileFlags.contains_unsafe` marker by the AST pass) and at least one
//!     Warn finding from any pass, every Warn finding in that file is
//!     elevated to Critical. The elevation is noted in the finding's
//!     `message` so the human reading the report understands why.
//!
//! Deferred to a later phase:
//!
//!   * Function-scope elevation ("two or more Warn findings of different
//!     `raw`/`token` kinds in the same function scope → Critical"). This
//!     needs a per-function range index from the AST, which is not yet
//!     built.

use crate::ast::FileFlags;
use crate::finding::{Finding, Severity};
use crate::language::Language;

/// Apply elevation rules to a file's findings in place. `lang` and `flags`
/// come from the file-level context; passing them in keeps the scorer
/// decoupled from `FileAnalysis` so it's easy to unit test.
pub fn elevate(findings: &mut [Finding], lang: Language, flags: FileFlags) {
    if matches!(lang, Language::Rust) && flags.contains_unsafe {
        let has_warn = findings.iter().any(|f| f.severity == Severity::Warn);
        if has_warn {
            for f in findings.iter_mut() {
                if f.severity == Severity::Warn {
                    f.severity = Severity::Critical;
                    f.message = format!("{} [elevated: unsafe block in same file]", f.message);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{PassKind, SignalKind};
    use std::path::PathBuf;

    fn finding(severity: Severity) -> Finding {
        Finding {
            path: PathBuf::from("lib.rs"),
            byte_offset: 0,
            line: 1,
            col: 1,
            pass: PassKind::Raw,
            kind: SignalKind::EncodingBase64,
            severity,
            confidence: 0.5,
            message: "base64 blob".into(),
            snippet: String::new(),
            diff_introduced: false,
        }
    }

    #[test]
    fn rust_unsafe_plus_warn_elevates_to_critical() {
        let mut fs = vec![finding(Severity::Warn)];
        elevate(
            &mut fs,
            Language::Rust,
            FileFlags {
                contains_unsafe: true,
            },
        );
        assert_eq!(fs[0].severity, Severity::Critical);
        assert!(fs[0].message.contains("elevated"));
    }

    #[test]
    fn rust_without_unsafe_does_not_elevate() {
        let mut fs = vec![finding(Severity::Warn)];
        elevate(
            &mut fs,
            Language::Rust,
            FileFlags {
                contains_unsafe: false,
            },
        );
        assert_eq!(fs[0].severity, Severity::Warn);
    }

    #[test]
    fn non_rust_with_unsafe_flag_does_not_elevate() {
        // Defensive: the unsafe flag is Rust-only, but a future caller could
        // fabricate one. Python/TS must remain unaffected.
        let mut fs = vec![finding(Severity::Warn)];
        elevate(
            &mut fs,
            Language::Python,
            FileFlags {
                contains_unsafe: true,
            },
        );
        assert_eq!(fs[0].severity, Severity::Warn);
    }

    #[test]
    fn info_and_critical_findings_pass_through_unchanged() {
        let mut fs = vec![
            finding(Severity::Info),
            finding(Severity::Warn),
            finding(Severity::Critical),
        ];
        elevate(
            &mut fs,
            Language::Rust,
            FileFlags {
                contains_unsafe: true,
            },
        );
        assert_eq!(fs[0].severity, Severity::Info);
        assert_eq!(fs[1].severity, Severity::Critical);
        assert_eq!(fs[2].severity, Severity::Critical);
    }
}
