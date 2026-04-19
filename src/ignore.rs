//! Filesystem walking with `.discludeignore` support and built-in skips.

use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

const ALWAYS_SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "__pycache__"];
const ALWAYS_SKIP_SUFFIXES: &[&str] = &[".min.js", ".min.css", ".pyc"];

/// Walk `root` and return the set of candidate file paths.
///
/// Applies, in order: built-in always-skip rules (`.git/`, `node_modules/`,
/// `target/`, `__pycache__/`, `*.min.js`, `*.min.css`, `*.pyc`); standard
/// `.gitignore` / hidden-file rules from the `ignore` crate; any
/// `.discludeignore` files found in the tree; and, if provided, an external
/// ignore file (`--ignore <path>`).
pub fn walk(root: &Path, extra_ignore: Option<&Path>) -> Vec<PathBuf> {
    let mut builder = WalkBuilder::new(root);
    builder
        .standard_filters(true)
        .add_custom_ignore_filename(".discludeignore")
        .filter_entry(|entry| {
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
            eprintln!(
                "disclude: could not load ignore file {}: {}",
                path.display(),
                err
            );
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
                eprintln!("disclude: walk error: {}", err);
            }
        }
    }
    paths
}
