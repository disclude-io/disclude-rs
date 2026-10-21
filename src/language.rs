use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Language {
    Bash,
    C,
    /// C++: `.cc`, `.cpp`, `.hpp` and the like, and `.h` headers whose code
    /// is C++ (`template <`, `namespace x {`, `a::b`).
    Cpp,
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
    /// HTML: payload-scanned; `<script>` bodies, event-handler attributes, and
    /// `javascript:` URLs extracted and scanned as JavaScript.
    Html,
}

impl Language {
    pub fn from_extension(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        match ext {
            "sh" | "bash" | "bsh" | "ksh" | "zsh" => Some(Language::Bash),
            "c" | "h" => Some(Language::C),
            "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" | "ipp" | "tpp" | "inl" => {
                Some(Language::Cpp)
            }
            "py" | "pyi" => Some(Language::Python),
            "rs" => Some(Language::Rust),
            "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "txt" | "text" => Some(Language::Text),
            "md" | "markdown" => Some(Language::Markdown),
            "yaml" | "yml" => Some(Language::Yaml),
            "rst" => Some(Language::Rst),
            "html" | "htm" | "xhtml" => Some(Language::Html),
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
        match Language::from_extension(path) {
            // `.h` is shared by C and C++: Arrow, Abseil and gRPC write C++
            // in `.h` files, which the C grammar misreads.
            Some(Language::C)
                if path.extension().is_some_and(|e| e == "h")
                    && crate::token::looks_like_cpp(bytes) =>
            {
                Some(Language::Cpp)
            }
            Some(l) => Some(l),
            None => Language::from_shebang(bytes),
        }
    }

    pub fn parse_flag(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "bash" | "sh" | "shell" => Some(Language::Bash),
            "c" => Some(Language::C),
            "cpp" | "c++" | "cxx" => Some(Language::Cpp),
            "python" | "py" => Some(Language::Python),
            "rust" | "rs" => Some(Language::Rust),
            "ts" | "typescript" => Some(Language::TypeScript),
            "js" | "javascript" => Some(Language::JavaScript),
            "text" | "txt" => Some(Language::Text),
            "md" | "markdown" => Some(Language::Markdown),
            "yaml" | "yml" => Some(Language::Yaml),
            "rst" => Some(Language::Rst),
            "html" | "htm" => Some(Language::Html),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Bash => "bash",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Python => "python",
            Language::Rust => "rust",
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
            Language::Text => "text",
            Language::Markdown => "markdown",
            Language::Yaml => "yaml",
            Language::Rst => "rst",
            Language::Html => "html",
        }
    }

    /// Markup/text languages: payload-scanned globally, with embedded code
    /// blocks (if any) extracted and routed to the matching code scanner.
    /// These do not have token/AST passes of their own.
    pub fn is_markup(&self) -> bool {
        matches!(
            self,
            Language::Text | Language::Markdown | Language::Yaml | Language::Rst | Language::Html
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
            "cpp" | "c++" | "cc" | "cxx" | "hpp" => Some(Language::Cpp),
            "python" | "py" | "py3" | "python3" => Some(Language::Python),
            "rust" | "rs" => Some(Language::Rust),
            "typescript" | "ts" | "tsx" => Some(Language::TypeScript),
            "javascript" | "js" | "jsx" | "node" => Some(Language::JavaScript),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpp_by_extension_and_by_header_content() {
        for name in [
            "a.cc", "a.cpp", "a.cxx", "a.hpp", "a.hh", "a.hxx", "a.ipp", "a.tpp", "a.inl",
        ] {
            assert_eq!(
                Language::detect(Path::new(name), b""),
                Some(Language::Cpp),
                "{name}"
            );
        }
        // `.c++` is rare for sources and also names Doxygen configs.
        assert_eq!(Language::detect(Path::new("Doxyfile.c++"), b""), None);
        let h = Path::new("widget.h");
        assert_eq!(
            Language::detect(h, b"class Widget {};"),
            Some(Language::Cpp)
        );
        assert_eq!(Language::detect(h, b"struct widget;"), Some(Language::C));
        assert_eq!(
            Language::detect(Path::new("w.c"), b"class Widget {};"),
            Some(Language::C)
        );
        assert_eq!(Language::parse_flag("c++"), Some(Language::Cpp));
        assert_eq!(Language::from_fence_info("cpp"), Some(Language::Cpp));
        assert_eq!(Language::Cpp.as_str(), "cpp");
    }
}
