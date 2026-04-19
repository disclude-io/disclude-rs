//! Git diff annotation — map each finding to "was this introduced since
//! `<ref>`?" by parsing `git diff <ref> HEAD --unified=0`.
//!
//! `diff_introduced` is purely informational — it does not change a
//! finding's `severity` or `confidence`. The human reporter uses it to
//! prefix `[NEW]`; JSON and SARIF carry it as a boolean field.
//!
//! The parser works at line granularity: if a finding's `line` falls
//! within an added hunk for that file, we mark it. We do not try to
//! reason about byte-level edits within a line, because findings always
//! carry a `line` derived from `byte_offset` via `LineIndex` and the
//! unified diff granularity is the line.
//!
//! If `git` is unavailable or the scan root is not a git repository, a
//! warning goes to stderr and annotation is simply skipped; the scan
//! still completes normally.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

/// Line numbers added in each file, keyed by the absolute path that the
/// scanner sees. Look up a finding's `(path, line)` to decide whether it
/// was introduced since `<ref>`.
pub type AddedLines = HashMap<PathBuf, HashSet<usize>>;

pub fn compute_added_lines(root: &Path, git_ref: &str) -> Result<AddedLines> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("diff")
        .arg("--no-color")
        .arg("--unified=0")
        .arg("--relative")
        .arg(git_ref)
        .arg("HEAD")
        .output()
        .context("failed to exec git — is git installed?")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "git diff {}..HEAD failed: {}",
            git_ref,
            stderr.trim()
        ));
    }
    Ok(parse_unified_diff(&out.stdout, root))
}

fn parse_unified_diff(stdout: &[u8], root: &Path) -> AddedLines {
    let text = String::from_utf8_lossy(stdout);
    let mut map: AddedLines = HashMap::new();
    let mut current: Option<PathBuf> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("+++ ") {
            current = resolve_new_side(rest, root);
        } else if line.starts_with("@@ ") {
            let (Some(path), Some((start, count))) = (current.as_ref(), parse_hunk_header(line))
            else {
                continue;
            };
            if count == 0 {
                continue; // pure-deletion hunk — nothing added
            }
            let set = map.entry(path.clone()).or_default();
            for l in start..start + count {
                set.insert(l);
            }
        }
    }
    map
}

/// Resolve the `+++ b/<path>` side of a unified diff header to an absolute
/// path rooted at the scan root. `+++ /dev/null` means the file was
/// deleted on the new side, so no added lines to track.
fn resolve_new_side(rest: &str, root: &Path) -> Option<PathBuf> {
    if rest == "/dev/null" {
        return None;
    }
    let stripped = rest.strip_prefix("b/").unwrap_or(rest);
    Some(root.join(stripped))
}

/// Parse `@@ -old,oldcount +new,newcount @@`. Returns `(new_start, new_count)`.
/// Count defaults to 1 when omitted (e.g. `@@ -10 +11 @@`).
fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    let s = line.strip_prefix("@@ ")?;
    let plus_tok = s.split_whitespace().find(|t| t.starts_with('+'))?;
    let body = plus_tok.strip_prefix('+')?;
    match body.split_once(',') {
        Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
        None => Some((body.parse().ok()?, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from("/tmp/repo")
    }

    #[test]
    fn parse_hunk_header_with_count() {
        assert_eq!(parse_hunk_header("@@ -10,2 +11,3 @@"), Some((11, 3)));
    }

    #[test]
    fn parse_hunk_header_without_count_defaults_to_one() {
        assert_eq!(parse_hunk_header("@@ -10 +11 @@"), Some((11, 1)));
    }

    #[test]
    fn parse_hunk_header_with_trailing_context() {
        assert_eq!(
            parse_hunk_header("@@ -10,2 +11,3 @@ fn example() {"),
            Some((11, 3))
        );
    }

    #[test]
    fn pure_deletion_hunk_adds_no_lines() {
        let diff = "\
diff --git a/x.rs b/x.rs
--- a/x.rs
+++ b/x.rs
@@ -10,2 +10,0 @@
-old line 1
-old line 2
";
        let map = parse_unified_diff(diff.as_bytes(), &root());
        assert!(map.get(&root().join("x.rs")).is_none());
    }

    #[test]
    fn added_lines_extracted_per_file() {
        let diff = "\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -0,0 +5,3 @@
+line 5
+line 6
+line 7
diff --git a/b.rs b/b.rs
--- a/b.rs
+++ b/b.rs
@@ -2 +2 @@
-old
+new
";
        let map = parse_unified_diff(diff.as_bytes(), &root());
        let a = map.get(&root().join("a.py")).unwrap();
        assert!(a.contains(&5) && a.contains(&6) && a.contains(&7));
        let b = map.get(&root().join("b.rs")).unwrap();
        assert!(b.contains(&2));
    }

    #[test]
    fn new_file_addition_tracked() {
        let diff = "\
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+hello
+world
";
        let map = parse_unified_diff(diff.as_bytes(), &root());
        let s = map.get(&root().join("new.py")).unwrap();
        assert!(s.contains(&1) && s.contains(&2));
    }

    #[test]
    fn deleted_file_produces_no_entry() {
        let diff = "\
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-line 1
-line 2
";
        let map = parse_unified_diff(diff.as_bytes(), &root());
        assert!(map.is_empty());
    }

    #[test]
    fn multiple_hunks_in_one_file_merged() {
        let diff = "\
diff --git a/m.rs b/m.rs
--- a/m.rs
+++ b/m.rs
@@ -0,0 +3,1 @@
+three
@@ -0,0 +10,2 @@
+ten
+eleven
";
        let map = parse_unified_diff(diff.as_bytes(), &root());
        let s = map.get(&root().join("m.rs")).unwrap();
        assert!(s.contains(&3));
        assert!(s.contains(&10) && s.contains(&11));
        assert!(!s.contains(&4));
    }
}
