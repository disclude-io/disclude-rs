# disclude — Claude Code Specification

## Project Identity

**Name:** `disclude`
**Language:** Rust
**Purpose:** Detect obfuscation in source code packages — not a general security scanner, not a vulnerability checker, not a secrets detector. Specifically and only: does this code appear to hide its intent from human readers?
**Scope:** Source trees (Python, Rust, TypeScript/JavaScript). Not binaries, not minified JS, not compiled artifacts.
**Sibling tool:** `fetter` (package discovery and vulnerability auditing)

---

## What Disclude Is Not

These are explicit non-goals and should not appear in findings or documentation:
- CVE / vulnerability matching
- Credential or secrets detection
- License checking
- Dependency auditing
- General SAST / taint analysis
- Binary analysis
- Minified JS analysis

---

## CLI Interface

### Primary Command

```
disclude scan <path> [OPTIONS]
```

Recursively scans a source tree rooted at `<path>`.

### Options

```
--lang <lang>          Override language detection (python|rust|ts|js)
--format <fmt>         Output format: human (default), json, sarif
--severity <level>     Minimum severity to report: info|warn|critical (default: warn)
--exit-code            Exit non-zero if any findings at or above --severity threshold
--ignore <path>        Path to .discludeignore file (default: .discludeignore in tree root)
--diff <git-ref>       Annotate findings with recency — was this introduced since <git-ref>?
                       Does not affect scoring or severity. Purely informational.
--no-raw               Skip raw byte analysis (not recommended)
--no-ast               Skip AST analysis (faster, less accurate)
```

### Exit Codes

```
0    Clean — no findings at or above threshold
1    Findings found at or above threshold
2    Error — could not complete analysis (parse failure, IO error, etc.)
```

### Output Formats

**Human (default):**
```
disclude scan ./mypackage

CRITICAL  src/utils.py:142   encoding-chain    base64 literal fed to exec()
WARN      src/utils.py:89    high-complexity   string literal compression ratio 0.97
WARN      src/auth.rs:12     unicode-bidi      U+202E RIGHT-TO-LEFT OVERRIDE in identifier
INFO      src/index.ts:201   long-line         line length 1842 in non-minified context

4 findings (1 critical, 2 warn, 1 info)
```

**JSON:** Structured array of `Finding` objects (schema below).
**SARIF:** Standard Static Analysis Results Interchange Format for CI integration.

---

## Architecture

Three sequential passes per file. All passes produce `Finding` objects with byte offsets. Findings from all passes feed into a unified result.

```
Input: source tree path
  └─> File resolver (language detection, ignore rules)
        └─> Per file:
              ├─> raw:   Raw byte / text analysis
              ├─> token: Tokenizer-level analysis
              └─> ast:   AST / semantic analysis (tree-sitter)
                    └─> Finding aggregator
                          └─> Scorer
                                └─> Reporter
```

### raw: Raw Byte / Text Analysis

Language agnostic. Operates on original source bytes with no normalization. Must preserve byte offsets throughout.

**Unicode checks:**
- Bidirectional control characters: U+202A, U+202B, U+202C, U+202D, U+202E, U+2066, U+2067, U+2068, U+2069 (Trojan Source class) → CRITICAL
- Zero-width characters in identifiers or string literals: U+200B, U+200C, U+200D, U+FEFF, U+00AD → WARN
- Mixed-script identifiers: identifier contains characters from more than one Unicode script (e.g. Latin + Cyrillic) → WARN
- Homoglyph candidates: identifier characters with confusable mappings per Unicode confusables.txt → WARN

**Encoding pattern checks:**
- Base64 blob detection: string literal matching base64 alphabet, length > 32, compression ratio > 0.9 → WARN
- Hex-encoded string detection: string literal of form `\x41\x42...` with 8+ escape sequences → WARN
- Escape sequence soup: more than N consecutive `\xNN` escapes in a single literal → WARN

**Complexity checks (compression ratio):**
- Compute `zlib_compressed_len / original_len` for each string literal above a minimum length threshold (e.g. 32 bytes)
- Ratio > 0.95: high complexity → WARN
- Ratio > 0.98: very high complexity → CRITICAL
- Also compute per-file mean complexity across all string literals; flag files where one literal is > 2 standard deviations above the mean → INFO

**Structural checks:**
- Line length > 500 characters in a non-minified file → INFO
- Line length > 2000 characters → WARN
- Invisible whitespace characters in indentation (not standard space/tab): U+00A0, U+2000–U+200A, U+3000 → WARN
- Mixed tab and space indentation within the same file in a way that changes parse behavior → INFO

### token: Tokenizer-Level Analysis

Language-aware but lighter than full AST. Uses a simple per-language tokenizer to distinguish string literals, comments, identifiers, and code regions. Refines and contextualizes `raw` findings.

**String literal contextualization:**
- Re-run complexity analysis with string vs comment distinction
- A high-complexity string in a comment is INFO; in an assignment fed to a function call is WARN
- Base64 blob in a comment → INFO; in a variable assignment → WARN

**Identifier analysis:**
- Identifier character set narrowness: identifier using only characters from a visually confusable set (e.g. l, I, 1, O, 0) → WARN
- Identifier length distribution: file where mean identifier length < 2 characters (excluding conventional short names: i, j, k, x, y, n) → INFO
- String concatenation reconstructing identifiers: `"im" + "port"`, `"ex" + "ec"` patterns → WARN

**Per-language calibration of "normal":**
- Python: dunder identifiers (`__x__`) are normal; single underscore `_` is normal
- Rust: `_` prefix for intentionally unused is normal; short lifetimes (`'a`) are normal
- JS/TS: `$` prefix is normal; short callback args are normal
- These calibrations prevent false positives on idiomatic code

### ast: AST / Semantic Analysis

Full tree-sitter parse per language. Walk the AST to detect behavioral obfuscation patterns. Requires a tree-sitter grammar per language.

**Tree-sitter grammars:**
- `tree-sitter-python`
- `tree-sitter-rust`
- `tree-sitter-typescript` (covers both TS and JS)

**Python-specific checks:**
- `exec(...)` or `eval(...)` receiving a decoded/decompressed value → CRITICAL
- `__import__(constructed_string)` → CRITICAL
- `getattr(obj, constructed_string)` where string is concatenated or decoded → WARN
- `globals()` / `vars()` / `__builtins__` used to reach symbols by constructed string → WARN
- `compile(...)` fed to `exec` → CRITICAL
- Decorator used to wrap and re-execute function body → WARN

**Rust-specific checks:**
- `build.rs` present: flag for manual review → INFO
- `build.rs` containing `std::process::Command` invoking curl, wget, sh, bash, python → CRITICAL
- `include_str!` or `include_bytes!` pulling from outside the package tree → WARN
- Proc macro crate: flag presence → INFO (proc macros execute arbitrary code at compile time)
- `unsafe` block combined with other `raw` or `token` signals in the same file → elevates severity

**JS/TS-specific checks:**
- `eval(...)` receiving any non-literal argument → CRITICAL
- `Function(constructed_string)` → CRITICAL
- `require(constructed_string)` where string is not a literal → WARN
- `process.binding(...)` → WARN
- `setTimeout(string_arg, ...)` — string form of setTimeout is eval → WARN
- `postinstall` script in `package.json` that shells out → WARN
- Dynamic `import(constructed_string)` → WARN

---

## Data Structures

```rust
pub enum PassKind {
    Raw,
    Token,
    Ast,
}

pub enum SignalKind {
    // raw
    UnicodeBidi,
    UnicodeZeroWidth,
    UnicodeMixedScript,
    UnicodeHomoglyph,
    EncodingBase64,
    EncodingHex,
    EncodingEscapeSoup,
    HighComplexity,
    LongLine,
    WhitespaceAnomaly,
    // token
    IdentifierNarrowCharset,
    IdentifierLowLength,
    StringConcatConstruction,
    // ast
    DynamicExecution,
    DynamicImport,
    DynamicAttribute,
    BuildScriptShellout,
    ProcMacroPresence,
    InstallHookShellout,
}

pub enum Severity {
    Info,
    Warn,
    Critical,
}

pub struct Finding {
    pub path: PathBuf,
    pub byte_offset: usize,
    pub line: usize,
    pub col: usize,
    pub pass: PassKind,
    pub kind: SignalKind,
    pub severity: Severity,
    pub confidence: f32,       // 0.0–1.0
    pub message: String,       // human-readable description
    pub snippet: String,       // source context (redacted if > 120 chars)
    pub diff_introduced: bool, // true if byte_offset falls within --diff hunk
}

pub struct FileAnalysis {
    pub path: PathBuf,
    pub language: Language,
    pub findings: Vec<Finding>,
    pub file_complexity_mean: f32,   // mean compression ratio across string literals
    pub file_complexity_max: f32,    // max compression ratio
    pub parse_error: Option<String>, // if AST pass failed
}

pub struct ScanResult {
    pub root: PathBuf,
    pub files_scanned: usize,
    pub files_with_findings: usize,
    pub findings_total: usize,
    pub findings_by_severity: HashMap<Severity, usize>,
    pub files: Vec<FileAnalysis>,
    pub diff_ref: Option<String>,
}
```

---

## Scoring Model

Severity is assigned per finding kind with confidence modulation:

| Kind | Base Severity | Confidence notes |
|---|---|---|
| UnicodeBidi | Critical | Near 1.0 — almost never legitimate |
| DynamicExecution (exec/eval + decoded arg) | Critical | High — combination required |
| BuildScriptShellout (curl/wget/sh) | Critical | High |
| UnicodeZeroWidth | Warn | Medium — could be legitimate in some encodings |
| EncodingBase64 (in assignment) | Warn | Medium — context-dependent |
| HighComplexity (ratio > 0.98) | Critical | Medium — length-gated |
| HighComplexity (ratio > 0.95) | Warn | Medium |
| StringConcatConstruction | Warn | Medium |
| UnicodeMixedScript | Warn | Medium |
| UnicodeHomoglyph | Warn | Medium — false positives possible |
| IdentifierNarrowCharset | Warn | Lower — needs corroboration |
| LongLine (> 2000) | Warn | Lower |
| ProcMacroPresence | Info | Informational only |
| BuildScriptPresence | Info | Informational only |
| LongLine (> 500) | Info | Lower |

**Severity elevation rules:**
- Any `unsafe` block in Rust + any Warn finding in the same file → elevate to Critical
- Two or more Warn findings of different `raw` or `token` kinds in the same function scope → elevate to Critical
- `diff_introduced: true` on any Critical finding → prepend `[NEW]` in human output

---

## File Resolution

**Language detection** (in priority order):
1. `--lang` flag override
2. File extension: `.py` → Python, `.rs` → Rust, `.ts`/`.tsx` → TypeScript, `.js`/`.jsx`/`.mjs` → JavaScript
3. Shebang line: `#!/usr/bin/env python3` etc.
4. Skip if unrecognized

**Files always skipped:**
- `.git/` directory contents
- Binary files (detected by null byte presence in first 8KB)
- Files matching `.discludeignore` patterns (gitignore syntax)
- Files > 10MB
- `*.min.js`, `*.min.css` — declared minified
- `node_modules/` — use `disclude scan` on individual packages, not consuming projects
- `target/` (Rust build output)
- `__pycache__/`, `*.pyc`

**Default `.discludeignore`:**
```
*.min.js
*.min.css
node_modules/
target/
__pycache__/
*.pyc
.git/
```

---

## Diff Annotation

When `--diff <git-ref>` is provided:

1. Run `git diff <git-ref> HEAD -- <path>` to obtain unified diff
2. Parse `+` hunks to extract byte ranges of added/modified lines per file
3. After all passes complete, for each `Finding`, set `diff_introduced: true` if `finding.byte_offset` falls within any added hunk range
4. `diff_introduced` is purely informational — it does not change `severity` or `confidence`
5. In human output, prefix `[NEW]` to findings where `diff_introduced: true`
6. In JSON/SARIF output, `diff_introduced` is a boolean field on each finding

If `git` is not available or `<path>` is not a git repository, emit a warning and continue without diff annotation.

---

## Rust Crate Dependencies

```toml
[dependencies]
# AST parsing
tree-sitter = "0.22"
tree-sitter-python = "0.21"
tree-sitter-rust = "0.21"
tree-sitter-typescript = "0.21"

# Compression (compression ratio complexity metric + archive unpacking)
flate2 = "1.0"

# Unicode
unicode-normalization = "0.1"
unicode-general-category = "0.6"

# CLI
clap = { version = "4", features = ["derive"] }

# Output
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
anyhow = "1"
thiserror = "1"

# Filesystem walking
ignore = "0.4"   # respects .gitignore / .discludeignore, handles ignore rules
walkdir = "2"

# Parallelism
rayon = "1"
```

---

## Project Structure

```
disclude/
├── Cargo.toml
├── README.md
├── .discludeignore
├── src/
│   ├── main.rs              # CLI entry point, clap definitions
│   ├── lib.rs               # public API
│   ├── scan.rs              # orchestration: file resolution, pass sequencing
│   ├── finding.rs           # Finding, FileAnalysis, ScanResult types
│   ├── language.rs          # Language enum, detection logic
│   ├── raw/
│   │   ├── mod.rs
│   │   ├── unicode.rs       # bidi, zero-width, homoglyph, mixed-script
│   │   ├── encoding.rs      # base64, hex, escape soup detection
│   │   ├── complexity.rs    # compression ratio, per-file statistics
│   │   └── structural.rs    # long lines, whitespace anomalies
│   ├── token/
│   │   ├── mod.rs
│   │   ├── python.rs        # Python tokenizer-level analysis
│   │   ├── rust.rs          # Rust tokenizer-level analysis
│   │   └── typescript.rs    # TS/JS tokenizer-level analysis
│   ├── ast/
│   │   ├── mod.rs
│   │   ├── python.rs        # Python AST rules
│   │   ├── rust.rs          # Rust AST rules
│   │   └── typescript.rs    # TS/JS AST rules
│   ├── diff.rs              # git diff parsing, byte offset annotation
│   ├── scorer.rs            # severity elevation rules
│   ├── ignore.rs            # .discludeignore handling
│   └── reporter/
│       ├── mod.rs
│       ├── human.rs         # human-readable output
│       ├── json.rs          # JSON output
│       └── sarif.rs         # SARIF output
└── tests/
    ├── fixtures/            # per-language obfuscation samples for testing
    │   ├── python/
    │   ├── rust/
    │   └── typescript/
    └── integration/
```

---

## Implementation Notes for Claude Code

1. **Byte offset discipline:** `raw` must track byte offsets precisely throughout. All findings must carry a `byte_offset` into the original file bytes. Do not use char offsets — they diverge on multi-byte unicode, which is exactly the attack surface.

2. **`raw` operates on `&[u8]`:** Never convert to `String` or `&str` before `raw` completes. The raw bytes are the evidence.

3. **Compression ratio implementation:** Use `flate2` zlib compression at default level. Compute on the raw bytes of the string literal value (not the source representation including quotes). Gate on minimum length of 32 bytes to avoid noisy results on short strings.

4. **Tree-sitter error tolerance:** Tree-sitter produces partial ASTs on parse errors. Do not abort `ast` on parse failure — record the error in `FileAnalysis.parse_error` and continue with whatever nodes are available.

5. **Rayon parallelism:** File analysis is embarrassingly parallel. Use `rayon::par_iter()` over the file list. Each `FileAnalysis` is independent.

6. **Unicode confusables:** The Unicode consortium publishes `confusables.txt`. Embed a minimal subset covering the most common homoglyph attacks as a static lookup table rather than shipping the full file.

7. **Base64 detection heuristic:** A string literal qualifies as a base64 candidate if: length > 32, character set is subset of `[A-Za-z0-9+/=]`, length is a multiple of 4 (or close), AND compression ratio > 0.85. All conditions required to reduce false positives on short alphanumeric strings.

8. **The `ignore` crate:** Use the `ignore` crate for filesystem walking — it handles `.gitignore`, `.discludeignore`, hidden files, and binary detection efficiently and correctly.

9. **SARIF output:** Target SARIF 2.1.0. Each `Finding` maps to a SARIF `result` with `ruleId` from `SignalKind`, `level` from `Severity`, and `physicalLocation` from `path` + `byte_offset`.

10. **Testing fixtures:** The `tests/fixtures/` directory should contain small, self-contained source files that exercise each signal kind. Each fixture should have a corresponding expected findings JSON. Use these as integration tests.
