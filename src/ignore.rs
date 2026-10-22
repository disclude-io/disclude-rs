//! Filesystem walking with `.discludeignore` support and built-in skips.

use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

use crate::finding::{DiagnosticKind, ScanDiagnostic};

const ALWAYS_SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "__pycache__"];
const ALWAYS_SKIP_SUFFIXES: &[&str] = &[".min.js", ".min.css", ".pyc"];

/// Walk `root` and return the set of candidate file paths.
///
/// Applies, in order: built-in always-skip rules (`.git/`, `node_modules/`,
/// `target/`, `__pycache__/`, `*.min.js`, `*.min.css`, `*.pyc`); standard
/// `.gitignore` / hidden-file rules from the `ignore` crate; any
/// `.discludeignore` files found in the tree; and, if provided, an external
/// ignore file (`--ignore <path>`).
///
/// Problems (an unloadable ignore file, unreadable directories) are returned
/// as diagnostics alongside the paths rather than written to stderr.
pub fn walk(root: &Path, extra_ignore: Option<&Path>) -> (Vec<PathBuf>, Vec<ScanDiagnostic>) {
    walk_with(root, extra_ignore, false)
}

/// [`walk`], or with `untrusted`, a walk of a tree whose contents may be
/// hostile (a downloaded package, someone else's repository). Then nothing
/// in the tree decides what is scanned: `.gitignore`, `.ignore`,
/// `.discludeignore`, and git's exclude files are not read, nor ignore files
/// in the root's parents, and hidden files and directories are walked.
/// Otherwise a package could hide a file by listing it in an ignore file it
/// ships, or by giving it a leading dot. The built-in skips and
/// `extra_ignore` (the caller's own file) still apply.
pub fn walk_with(
    root: &Path,
    extra_ignore: Option<&Path>,
    untrusted: bool,
) -> (Vec<PathBuf>, Vec<ScanDiagnostic>) {
    let mut diagnostics = Vec::new();
    let mut builder = WalkBuilder::new(root);
    builder.standard_filters(!untrusted);
    if !untrusted {
        builder.add_custom_ignore_filename(".discludeignore");
    }
    builder.filter_entry(|entry| {
        let name = entry.file_name().to_string_lossy();
        if ALWAYS_SKIP_DIRS.iter().any(|d| name.as_ref() == *d) {
            return false;
        }
        if ALWAYS_SKIP_SUFFIXES
            .iter()
            .any(|s| name.as_ref().ends_with(s))
        {
            return false;
        }
        true
    });

    if let Some(path) = extra_ignore {
        if let Some(err) = builder.add_ignore(path) {
            diagnostics.push(ScanDiagnostic::new(
                Some(path.to_path_buf()),
                DiagnosticKind::IgnoreFileError,
                format!("could not load ignore file: {}", err),
            ));
        }
    }

    let mut paths = Vec::new();
    for result in builder.build() {
        match result {
            Ok(entry) => {
                if entry.file_type().is_some_and(|t| t.is_file()) {
                    paths.push(entry.into_path());
                }
            }
            Err(err) => {
                diagnostics.push(ScanDiagnostic::new(
                    error_path(&err),
                    DiagnosticKind::WalkError,
                    err.to_string(),
                ));
            }
        }
    }
    (paths, diagnostics)
}

/// The path an `ignore` walk error refers to, if it carries one.
fn error_path(err: &ignore::Error) -> Option<PathBuf> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path.clone()),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            error_path(err)
        }
        _ => None,
    }
}
