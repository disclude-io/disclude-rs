# Spec: disclude-rs embedding-ready public API

Status: draft · Target crate: `disclude` (currently `3.0.0`) · Consumer: `disclude-daemon` in `disclude-platform` (the `disclude-www` web server does not link disclude)

## 1. Summary

The library API is already public and largely sufficient. `src/lib.rs` exports
`scan(&Path, &ScanOptions) -> anyhow::Result<ScanResult>` plus fully-`pub`,
serde-derived result types (`ScanResult`, `FileAnalysis`, `Finding`, `SignalKind`,
`Severity`, `PassKind`, `Language`), and `--diff` support already lives in the
library via `ScanOptions::diff_ref`.

So this is **not** a "build an API" effort. It is a small set of changes to make
the existing API safe to embed in a long-running host that feeds it adversarial
input and needs structured output. The changes are grouped into **blockers**
(required before linking) and **recommended** (quality-of-life / future-proofing).

## 2. What already works (no change needed)

- `disclude::scan(root, &opts)` — offline, pure (reads files, optionally shells
  `git` for diff). No network, no LLM inside `scan()`; the LLM pass is orchestrated
  by the CLI *after* `scan()`, so embedding `scan()` gives a clean offline call.
- `ScanOptions { lang_override, run_raw, run_token, run_ast, ignore_path, diff_ref }`
  with a `Default` impl.
- `ScanResult` and all nested types derive `Serialize`/`Deserialize` and expose
  public fields. `Severity` is `Ord` (so `>= threshold` filtering works).
- The platform does not use the reporter or SARIF. It maps `ScanResult`
  directly to its own stored JSON; anyone wanting SARIF reruns the scan with the
  disclude CLI (platform spec §5.3).

## 3. Blockers (required for embedding)

### B1 — Cooperative cancellation

`scan()` is a blocking `rayon` `par_iter` with no cancellation hook. The daemon
needs to abandon an in-progress scan on a wall-clock deadline.

Add an optional cancellation flag checked before each file is analysed:

```rust
pub struct ScanOptions {
    // ...existing fields...
    /// If set, checked before each file; when true, scan returns early
    /// with whatever has completed so far (result marked partial).
    pub cancel: Option<Arc<AtomicBool>>,
}
```

In the `par_iter().filter_map` closure, short-circuit when the flag is set. Mark
the returned `ScanResult` as partial (see B2's `truncated` flag) so the caller
knows coverage was cut short.

Scope note: this gives **between-files** cancellation only. A single pathological
file inside `analyze_file` (tree-sitter parse, entropy loop) is not interruptible
this way. That residual risk is owned by the daemon's process boundary (hard
wall-clock kill of the scan-worker child), **not** by this library. The existing
`MAX_FILE_BYTES = 10 MiB` guard bounds the per-file blast radius; keep it.

### B2 — Structured diagnostics instead of stderr

Library code writes directly to stderr on the pure `scan()` path, which is
unacceptable for an embedded host that owns its own logging:

- `src/scan.rs:61` — per-file analyze error → file silently dropped + stderr line
- `src/scan.rs:82` — diff annotation skipped → stderr line
- `src/ignore.rs:37,54` — directory-walk errors → stderr

Replace these with data on the result. Add a diagnostics channel so the daemon
can record coverage gaps (which feed the scan summary and the "N files skipped"
UI):

```rust
pub struct ScanDiagnostic {
    pub path: Option<PathBuf>,
    pub kind: DiagnosticKind,   // ReadError | WalkError | DiffSkipped | Skipped...
    pub detail: String,
}

pub struct ScanResult {
    // ...existing fields...
    pub diagnostics: Vec<ScanDiagnostic>,
    pub truncated: bool,        // set by B1 on early cancel
}
```

Route any genuinely incidental messages through the `log` facade rather than
`eprintln!`, so the host chooses the sink. Files dropped for benign reasons
(binary, oversized, undetected language) should be counted (a `files_skipped`
tally is enough) rather than emitted per-line.

### B3 — Exported version constant

The daemon stamps `disclude_version` into every stored result — it is how a
finding's absence is interpreted ("not flagged by ruleset X," not "clean") and
how re-scan campaigns are scoped. Version is currently only wired into clap.

```rust
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

If signal definitions ever version independently of the crate, add a separate
`pub const RULESET_VERSION`; crate version is an acceptable proxy to start.

### B4 — `#[non_exhaustive]` on open enums

`SignalKind` demonstrably grows over time (the 2.0 set is much larger than the
1.2 README set). Any downstream exhaustive `match` on it breaks on every disclude
upgrade. Mark the open enums so adding a variant is a non-breaking change and
consumers are forced to carry a `_ =>` arm:

```rust
#[non_exhaustive]
pub enum SignalKind { /* ... */ }

#[non_exhaustive]
pub enum Language { /* ... */ }
```

Leave `Severity` and `PassKind` exhaustive — they are genuinely closed sets.

## 4. Recommended (non-blocking)

### R1 — Thread-pool scoping

`scan()` uses the global `rayon` pool. This only matters if the host runs
**multiple concurrent scans in one process** — they would contend on one pool
with no per-scan bound. The daemon's subprocess-per-scan model sidesteps this
entirely (each child has its own global pool), so treat R1 as optional. If an
in-process multi-scan mode is ever wanted, accept an optional thread budget and
run the walk under a scoped `ThreadPoolBuilder::install`.

### R2 — Snippet handling stays the caller's choice

`Finding.snippet` can contain the very adversarial bytes that triggered the
finding (bidi controls, invisible tags, high-entropy blobs). `redact_snippet`
(120-char cap) is applied by reporters, not by `scan()`, so raw `Finding.snippet`
reaches an embedder unredacted. That's fine — but it must be documented, because
the consumer is responsible for defusing snippets before storage/display (the
platform redacts at write time and its templates render control characters as
visible markers, never raw).

### R3 — Document the `git` dependency of `diff_ref`

`diff::compute_added_lines` shells `git -C <root> diff <ref> HEAD`. Document that
setting `ScanOptions::diff_ref` requires (a) a `git` binary on `PATH` and (b) the
scan root being a real checkout whose history contains **both** `<ref>` and
`HEAD`. This constrains how the daemon clones (see the platform spec: treeless
partial clone, not `--depth 1`, so the previous tag resolves).

## 5. Compatibility and process

- B1/B2 add fields to `ScanOptions` and `ScanResult`. Adding fields to a struct
  with public fields is a breaking change in Rust; bundle B1–B4 into a single
  minor/major bump (e.g. `2.1.0` if you accept the struct-literal break, or gate
  behind `#[non_exhaustive]` on the structs too if you want additive-only going
  forward — recommended for `ScanResult`).
- Add a snapshot/round-trip test asserting `ScanResult` serde output is stable,
  so schema drift is caught even though the daemon maps to its own DTO.
- Keep the CLI (`run_cli`) as a thin wrapper over the same `scan()` +
  `reporter::report` path so the two never diverge and the CLI stays the
  integration-test surface.

## 6. Explicitly out of scope for disclude-rs

- **Panic / segfault / OOM containment.** disclude is not required to be
  crash-proof on hostile input. The daemon owns process isolation (worker child +
  rlimits + wall-clock kill). Do not add in-library sandboxing.
- **Storage schema.** The daemon maps `ScanResult` → its own `ScanReport` DTO;
  disclude need not freeze its serde JSON as a storage contract. Keeping fields
  public and typed is sufficient.
