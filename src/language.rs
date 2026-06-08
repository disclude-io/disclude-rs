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
    /// Plain text: payload-scanned (raw pass) only, no embedded-code extraction.
    Text,
    /// Markdown: prose payload-scanned; fenced code blocks extracted and scanned
    /// with the per-language token/AST passes.
    Markdown,
    /// YAML: payload-scanned; CI/automation shell scalars (GHA `run:`, GitLab
    /// `script:`, Ansible shell/command) extracted and scanned as their language.
    Yaml,
    /// reStructuredText: payload-scanned; `code-block`/`sourcecode` directive
    /// bodies extracted and scanned with the per-language passes.
    Rst,
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
            "txt" | "text" => Some(Language::Text),
            "md" | "markdown" => Some(Language::Markdown),
            "yaml" | "yml" => Some(Language::Yaml),
            "rst" => Some(Language::Rst),
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
            "text" | "txt" => Some(Language::Text),
            "md" | "markdown" => Some(Language::Markdown),
            "yaml" | "yml" => Some(Language::Yaml),
            "rst" => Some(Language::Rst),
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
            Language::Text => "text",
            Language::Markdown => "markdown",
            Language::Yaml => "yaml",
            Language::Rst => "rst",
        }
    }

    /// Markup/text languages: payload-scanned globally, with embedded code
    /// blocks (if any) extracted and routed to the matching code scanner.
    /// These do not have token/AST passes of their own.
    pub fn is_markup(&self) -> bool {
        matches!(
            self,
            Language::Text | Language::Markdown | Language::Yaml | Language::Rst
        )
    }

    /// Source-code languages that have token + AST passes.
    pub fn is_code(&self) -> bool {
        !self.is_markup()
    }

    /// Resolve a code-fence info string or CI `shell:` selector to a scannable
    /// language. Returns `None` for languages disclude does not scan (the block
    /// is then left to the global payload pass only).
    pub fn from_fence_info(info: &str) -> Option<Self> {
        // Info strings can carry attributes after the language token
        // (e.g. "python {.line-numbers}"); take the first whitespace- or
        // comma-delimited token.
        let token = info
            .trim()
            .split(|c: char| c.is_whitespace() || c == ',')
            .next()
            .unwrap_or("")
            .trim();
        match token.to_ascii_lowercase().as_str() {
            "bash" | "sh" | "shell" | "zsh" | "ksh" | "console" | "shell-session" => {
                Some(Language::Bash)
            }
            "c" | "h" => Some(Language::C),
            "python" | "py" | "py3" | "python3" => Some(Language::Python),
            "rust" | "rs" => Some(Language::Rust),
            "typescript" | "ts" | "tsx" => Some(Language::TypeScript),
            "javascript" | "js" | "jsx" | "node" => Some(Language::JavaScript),
            _ => None,
        }
    }
}
