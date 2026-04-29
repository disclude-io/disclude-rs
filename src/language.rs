use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Bash,
    C,
    Python,
    Rust,
    TypeScript,
    JavaScript,
}

impl Language {
    pub fn from_extension(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        match ext {
            "sh" | "bash" | "bsh" | "ksh" | "zsh" => Some(Language::Bash),
            "c" | "h" => Some(Language::C),
            "py" | "pyi" => Some(Language::Python),
            "rs" => Some(Language::Rust),
            "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            _ => None,
        }
    }

    pub fn from_shebang(bytes: &[u8]) -> Option<Self> {
        if !bytes.starts_with(b"#!") {
            return None;
        }
        let end = bytes
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(bytes.len());
        let line = std::str::from_utf8(&bytes[..end]).ok()?;
        if line.contains("python") {
            Some(Language::Python)
        } else if line.contains("node") || line.contains("deno") || line.contains("bun") {
            Some(Language::JavaScript)
        } else if line.contains("bash")
            || line.contains("/sh")
            || line.contains("ksh")
            || line.contains("zsh")
        {
            Some(Language::Bash)
        } else {
            None
        }
    }

    pub fn detect(path: &Path, bytes: &[u8]) -> Option<Self> {
        Language::from_extension(path).or_else(|| Language::from_shebang(bytes))
    }

    pub fn parse_flag(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "bash" | "sh" | "shell" => Some(Language::Bash),
            "c" => Some(Language::C),
            "python" | "py" => Some(Language::Python),
            "rust" | "rs" => Some(Language::Rust),
            "ts" | "typescript" => Some(Language::TypeScript),
            "js" | "javascript" => Some(Language::JavaScript),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Bash => "bash",
            Language::C => "c",
            Language::Python => "python",
            Language::Rust => "rust",
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
        }
    }
}
