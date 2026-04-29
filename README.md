# disclude

Scan a (C, Rust, Python, Typescript) source tree for signs that code is hiding its intent from a human reader: Unicode attacks, encoded payloads, dynamic execution patterns, and build-time escape hatches. This is not a general purpose vulnerability scanner. This is a tool to surface the techniques used to make malicious code look benign on review.

## Install

```
cargo build --release
# binary at target/release/disclude
```

## Usage

```
disclude scan <path> [options]
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `human` | Output format: `human`, `json`, `sarif` |
| `--severity` | `warn` | Minimum severity to report: `info`, `warn`, `critical` |
| `--exit-code` | off | Exit 1 if any findings at or above threshold |
| `--diff <ref>` | — | Annotate findings introduced since a git ref (`main`, a tag, a SHA) |
| `--lang <lang>` | auto | Override language detection: `python`, `rust`, `ts`, `js`, `c` |
| `--ignore <file>` | — | Additional ignore file (gitignore syntax) |
| `--no-raw` | — | Skip raw byte analysis |
| `--no-token` | — | Skip token-level analysis |
| `--no-ast` | — | Skip AST analysis (faster, less precise) |

### Examples

```sh
# Human-readable report, warn and above
disclude scan ./my-package

# SARIF output for GitHub Code Scanning
disclude scan ./my-package --format sarif > results.sarif

# CI gate: fail if any critical finding
disclude scan ./my-package --severity critical --exit-code

# Review only what a PR introduced
disclude scan ./my-package --diff main --exit-code
```

## Languages

Language is detected from file extension or shebang line.

| Language | Extensions | Shebang |
|---|---|---|
| C | `.c`, `.h` | — |
| Python | `.py`, `.pyi` | `python` |
| Rust | `.rs` | — |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` | — |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | `node`, `deno`, `bun` |

## How it works

Each file passes through up to three analysis layers. Later layers refine earlier ones — for example, a base64 blob found in a comment is demoted to `info` by the token pass because encoded text in comments is common and low-risk.

```
Raw pass   → byte-level: Unicode codepoints, encoded strings, entropy, line length
Token pass → language-aware: reclassify raw findings by context (identifier / string / comment),
             emit identifier anomalies and string-concat patterns
AST pass   → tree-sitter: function call patterns, build scripts, install hooks
```

Severity levels: **critical** (high confidence attack signal), **warn** (suspicious, review recommended), **info** (low confidence or expected in some legitimate code).

## Checks

### Unicode obfuscation

These run on every file regardless of language.

| Signal | Severity | Description |
|---|---|---|
| `unicode-bidi` | critical | Bidirectional control characters (U+202A–U+202E, U+2066–U+2069). The [Trojan Source](https://trojansource.codes/) attack class — bidi overrides make code appear to do something different from what it compiles to. |
| `unicode-zero-width` | warn | Zero-width characters (U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+00AD soft hyphen, U+FEFF BOM outside file start). Can silently change identifier names or inject hidden content. |
| `unicode-invisible` | warn | Characters from the Unicode Tags block (U+E0001 LANGUAGE TAG; U+E0020–U+E007F). These are invisible in all common renderers and have no legitimate use in source code. Used in [IOCCC 2024 "salmon"](https://www.ioccc.org/2024/cable2/index.html) to attach invisible suffixes to macro names, making identifiers silently different from what they appear. Demoted to `info` when found inside string literals or comments. |
| `unicode-mixed-script` | warn | Identifier contains characters from more than one Unicode script (e.g. Cyrillic + Latin). Demoted to `info` inside strings/comments. |
| `unicode-homoglyph` | warn | Identifier contains characters that are visually indistinguishable from a different ASCII character (e.g. Cyrillic `а` vs Latin `a`). Demoted to `info` inside strings/comments. |

### Surrogate escape sequences

Applies to JavaScript and TypeScript string literals only.

| Signal | Severity | Description |
|---|---|---|
| `unicode-surrogate` | warn / info | `\uHHHH` escape sequences forming UTF-16 surrogate pairs. JavaScript runtimes recombine adjacent surrogate pairs at runtime — a pair such as `󠁁` evaluates to U+E0041 (TAG LATIN CAPITAL LETTER A), an invisible tag character. **Warn** when the decoded codepoint is a Tags block character; **info** for other surrogate pairs (e.g. emoji written as `😀`) or orphaned surrogates. |

### Encoded payloads

These run on every file regardless of language.

| Signal | Severity | Description |
|---|---|---|
| `encoding-base64` | warn | Base64-shaped blob in a string literal (≥64 chars matching the base64 alphabet). Often used to embed payloads that are decoded and executed at runtime. Demoted to `info` outside string literals. |
| `encoding-hex` | warn | Long run of `\xNN` hex escape sequences in a string literal. A common way to embed shellcode or obfuscated text. Demoted to `info` outside string literals. |
| `encoding-escape-soup` | warn | Dense mix of arbitrary escape sequences. Indicates content that has been serialized or obfuscated to avoid plain-text grep. |

### Code structure anomalies

These run on every file regardless of language.

| Signal | Severity | Description |
|---|---|---|
| `high-complexity` | warn | String literal with unusually high Shannon entropy (high compression ratio). Raw high-entropy data in source is often an encoded payload or embedded binary. |
| `long-line` | info | Line length exceeds threshold in a file that is not a minified bundle. Lines dominated (>80%) by string/comment content are suppressed — the signal targets long *code* lines, which are a common obfuscation tactic. |
| `whitespace-anomaly` | warn | Unusual whitespace in indentation (e.g. mixed tabs/spaces, non-standard whitespace characters). |

### Identifier anomalies

Token pass; language-aware.

| Signal | Severity | Description |
|---|---|---|
| `identifier-narrow-charset` | warn | Identifier composed entirely of visually confusable characters (`l`, `I`, `1`, `O`, `0`). Names like `lI1O0lI` are unreadable by design. |
| `identifier-low-length` | info | File-wide naming-shape signal. Fires when the mean non-conventional identifier length is below 2.0 over at least 20 identifiers, **or** when ≥ 40 % of non-conventional identifiers are exactly one character (over at least 30 identifiers). The second trigger catches IOCCC-style obfuscation where a sprinkling of long keywords (`extern`, `nanosleep`, `TIOCGWINSZ`) inflates the mean above 2.0 even though most globals and functions are single letters. |
| `string-concat-construction` | warn | String concatenation that reconstructs a sensitive identifier (`exec`, `eval`, `import`, `getattr`, `system`, `require`, etc.). A common pattern to dodge static keyword grep. |

### Dynamic execution — Python

AST pass; tree-sitter.

| Signal | Severity | Description |
|---|---|---|
| `dynamic-execution` | critical / warn | `exec()` or `eval()` called with a non-literal argument (critical), or with a literal (warn). Also fires when `compile()` is reached by a decoded value. |
| `dynamic-import` | warn | `__import__()` or `importlib.import_module()` called with a non-literal specifier. |
| `dynamic-attribute` | warn | `getattr(obj, name)` where `name` is not a string literal — runtime-resolved attribute lookup. |

### Dynamic execution — TypeScript / JavaScript

AST pass; tree-sitter.

| Signal | Severity | Description |
|---|---|---|
| `dynamic-execution` | critical / warn | `eval()`, `new Function()`, or `setTimeout`/`setInterval` called with a string argument. |
| `dynamic-import` | warn | `require(expr)` where `expr` is not a string literal, or `` import(`...${expr}...`) `` template. |
| `dynamic-attribute` | warn | `process.binding(name)` — Node.js internal binding escape hatch, reaches C++ internals not exposed through the public API. |

### Dynamic execution — C

AST pass; tree-sitter.

| Signal | Severity | Description |
|---|---|---|
| `dynamic-execution` | critical / warn | `system(cmd)` or `exec*(path, ...)` (`execl`, `execlp`, `execle`, `execv`, `execvp`, `execve`) or `popen(cmd, mode)`. Critical when the argument is a variable; warn when it is a string literal. |
| `dynamic-import` | warn | `dlopen(path, flags)` with a non-literal path — dynamically loads a shared library. |
| `dynamic-attribute` | warn | `dlsym(handle, name)` with a non-literal symbol name — resolves a function pointer by name at runtime. |

### C-specific obfuscation

| Signal | Severity | Description |
|---|---|---|
| `macro-alias` | warn | Token pass. `#define <name> <replacement>` where the macro name is 1–2 characters and the replacement is a sensitive identifier (`write`, `read`, `open`, `system`, `exec*`, `popen`, `fork`, `kill`, `ptrace`, `syscall`, `dlopen`, `dlsym`, `mmap`, `mprotect`, `socket`, `connect`, `send`, `recv`, …). A common dropper trick: the syscall is renamed to a single letter so that simple keyword grep over the source misses it. Function-like macros and multi-token bodies are excluded. |
| `numeric-literal-payload` | critical | AST pass. A wide-numeric array (≥ 8 elements of `short`, `int`, `long`, `long long`, `float`, `double`, `long double`, `wchar_t`, `size_t`, `int16_t`/`int32_t`/`int64_t`, `uint16_t`/`uint32_t`/`uint64_t`, `intptr_t`, `uintptr_t`, …) that is later reinterpreted through a byte-pointer cast (`char *`, `unsigned char *`, `signed char *`, `int8_t *`, `uint8_t *`). Hides arbitrary bytes inside what looks like a table of floating-point or integer constants. Findings are deduped per array — one report per array citing the cast count. |
| `format-string-write` | critical | Token pass. `printf`-family format string contains a `%n` write directive (`%n`, `%hhn`, `%hn`, `%ln`, `%lln`, with optional positional `%<digit>$…n`). The `n` conversion writes the byte-count-so-far into an `int *` argument — a memory write primitive seen almost exclusively in CTF/exploit code and IOCCC entries. Detected inside string literals and inside `#define` macro bodies (catches the IOCCC stringification trick `#define N(a) "%"#a"$hhn"`, where the `$hhn` directive tail is split across stringification). Comments mentioning `%n` are excluded. |

### Build-time and install-time

AST pass; language-specific.

| Signal | Severity | Description |
|---|---|---|
| `build-script-shellout` | critical | Rust `build.rs` spawns a shell command or makes a network request at compile time. Malicious build scripts are a known supply-chain vector — they run automatically during `cargo build`. Also elevated to critical when found alongside `unsafe` code in the same file. |
| `proc-macro-presence` | info | Rust crate defines a procedural macro (`proc-macro = true`). Proc-macros run arbitrary code at compile time with full access to the compiler. Informational — legitimate proc-macros are common, but they warrant extra scrutiny in untrusted dependencies. |
| `install-hook-shellout` | warn | `package.json` `preinstall`/`postinstall`/`install` script shells out to a non-trivial command. Runs automatically on `npm install`. |

## Output formats

**`human`** — coloured terminal output grouped by file.

**`json`** — newline-delimited JSON, one object per file. Suitable for further processing.

**`sarif`** — [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), compatible with GitHub Code Scanning, VS Code SARIF viewer, and most CI platforms. Every signal kind appears in the rules catalog even if no findings were produced.
