//! End-to-end sanity test: run the scanner against the bundled fixture tree
//! and verify every expected signal fires.

use std::path::PathBuf;

use disclude::finding::SignalKind;
use disclude::scan::{scan, ScanOptions};

fn fixture_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("tests/fixtures")
}

fn run() -> disclude::finding::ScanResult {
    scan(&fixture_root(), &ScanOptions::default()).expect("scan failed")
}

fn has_kind_in(
    result: &disclude::finding::ScanResult,
    file_ends_with: &str,
    kind: SignalKind,
) -> bool {
    result.files.iter().any(|fa| {
        fa.path.to_string_lossy().ends_with(file_ends_with)
            && fa.findings.iter().any(|f| f.kind == kind)
    })
}

#[test]
fn unicode_bidi_fixture_emits_bidi_finding() {
    let r = run();
    assert!(has_kind_in(&r, "unicode_bidi.py", SignalKind::UnicodeBidi));
}

#[test]
fn homoglyph_fixture_emits_homoglyph_and_mixed_script() {
    let r = run();
    assert!(has_kind_in(
        &r,
        "homoglyph.py",
        SignalKind::UnicodeHomoglyph
    ));
    assert!(has_kind_in(
        &r,
        "homoglyph.py",
        SignalKind::UnicodeMixedScript
    ));
}

#[test]
fn base64_fixture_emits_base64_finding() {
    let r = run();
    assert!(has_kind_in(
        &r,
        "base64_blob.py",
        SignalKind::EncodingBase64
    ));
}

#[test]
fn hex_fixture_emits_hex_finding() {
    let r = run();
    assert!(has_kind_in(&r, "hex_escapes.py", SignalKind::EncodingHex));
}

#[test]
fn long_line_fixture_emits_long_line_finding() {
    let r = run();
    assert!(has_kind_in(&r, "long_line.ts", SignalKind::LongLine));
}

#[test]
fn clean_fixture_emits_no_findings() {
    let r = run();
    let clean = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("clean.py"))
        .expect("clean fixture was scanned");
    assert!(
        clean.findings.is_empty(),
        "clean fixture produced findings: {:?}",
        clean.findings
    );
}

#[test]
fn total_files_scanned_matches_fixture_count() {
    let r = run();
    assert!(
        r.files_scanned >= 26,
        "expected at least 26 fixture files, got {} — files: {:?}",
        r.files_scanned,
        r.files.iter().map(|fa| &fa.path).collect::<Vec<_>>()
    );
}

#[test]
fn base64_fixture_emits_dynamic_execution_critical() {
    // exec(base64.b64decode(payload)) — the AST pass must catch the decoded
    // arg reaching exec and flag it CRITICAL, independent of the earlier
    // base64-blob WARN.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("base64_blob.py"))
        .expect("base64 fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicExecution)
        .expect("DynamicExecution finding present");
    assert_eq!(hit.severity, disclude::finding::Severity::Critical);
}

#[test]
fn dynamic_import_fixture_emits_finding() {
    let r = run();
    assert!(has_kind_in(
        &r,
        "dynamic_import.py",
        SignalKind::DynamicImport
    ));
}

#[test]
fn dynamic_attribute_fixture_emits_finding() {
    let r = run();
    assert!(has_kind_in(
        &r,
        "dynamic_attribute.py",
        SignalKind::DynamicAttribute
    ));
}

#[test]
fn concat_fixture_emits_string_concat_finding() {
    let r = run();
    assert!(has_kind_in(
        &r,
        "concat_construction.py",
        SignalKind::StringConcatConstruction
    ));
}

#[test]
fn rust_build_rs_fixture_emits_shellout_critical() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("rust/build.rs"))
        .expect("rust/build.rs fixture was scanned");
    let hits: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::BuildScriptShellout)
        .collect();
    assert!(
        !hits.is_empty(),
        "expected BuildScriptShellout finding on rust/build.rs"
    );
    assert!(
        hits.iter()
            .all(|f| f.severity == disclude::finding::Severity::Critical),
        "BuildScriptShellout must be Critical"
    );
}

#[test]
fn rust_proc_macro_fixture_emits_proc_macro_info() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("rust/proc_macro.rs"))
        .expect("rust/proc_macro.rs fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::ProcMacroPresence)
        .expect("expected ProcMacroPresence finding");
    assert_eq!(hit.severity, disclude::finding::Severity::Info);
    let count = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::ProcMacroPresence)
        .count();
    assert_eq!(count, 1, "proc-macro finding should fire once per file");
}

#[test]
fn ts_eval_dynamic_fixture_emits_dynamic_execution_critical() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/eval_dynamic.ts")
        })
        .expect("typescript/eval_dynamic.ts fixture was scanned");
    let hits: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::DynamicExecution)
        .collect();
    assert!(
        hits.iter()
            .any(|f| f.severity == disclude::finding::Severity::Critical),
        "expected at least one CRITICAL DynamicExecution finding, got: {:?}",
        hits
    );
    // eval_dynamic.ts also contains a dynamic `import(`pkg-${name}`)`.
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicImport),
        "expected DynamicImport from the import() call"
    );
}

#[test]
fn ts_require_dynamic_fixture_emits_findings() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/require_dynamic.js")
        })
        .expect("typescript/require_dynamic.js fixture was scanned");
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicImport),
        "expected DynamicImport from require(name)"
    );
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicExecution),
        "expected DynamicExecution from setTimeout(string)"
    );
}

#[test]
fn ts_process_binding_fixture_emits_dynamic_attribute() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/process_binding.js")
        })
        .expect("typescript/process_binding.js fixture was scanned");
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicAttribute),
        "expected DynamicAttribute from process.binding"
    );
}

#[test]
fn ts_tag_smuggling_fixture_emits_unicode_surrogate() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/tag_smuggling.js")
        })
        .expect("typescript/tag_smuggling.js fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::UnicodeSurrogate
                && f.severity >= disclude::finding::Severity::Warn
        })
        .expect("expected Warn UnicodeSurrogate from surrogate pair decoding to tag char");
    assert!(
        hit.message.contains("E0041"),
        "finding should identify U+E0041, got: {}",
        hit.message
    );
}

#[test]
fn c_bonsai_fixture_emits_numeric_literal_payload() {
    // bonsai.c hides bytes inside a `double O[19]` array and reads them via
    // `((char*)&O[_])[r()]` and `((char*)(O+14))`. The C AST pass should fire
    // a single NumericLiteralPayload (CRITICAL) covering all cast sites.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/bonsai.c"))
        .expect("c/bonsai.c fixture was scanned");
    let hits: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::NumericLiteralPayload)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one NumericLiteralPayload (deduped per array), got: {:?}",
        hits
    );
    assert_eq!(hits[0].severity, disclude::finding::Severity::Critical);
    assert!(
        hits[0].message.contains("`O`"),
        "expected message to cite array name, got: {}",
        hits[0].message
    );
    assert!(
        hits[0].message.contains("byte-pointer cast"),
        "expected cast clause, got: {}",
        hits[0].message
    );
}

#[test]
fn c_bonsai_fixture_emits_macro_alias_for_write() {
    // bonsai.c starts with `#define A write` — a 1-char macro aliasing the
    // write(2) syscall. The token pass should fire MacroAlias WARN.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/bonsai.c"))
        .expect("c/bonsai.c fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::MacroAlias)
        .expect("expected MacroAlias finding");
    assert_eq!(hit.severity, disclude::finding::Severity::Warn);
    assert!(
        hit.message.contains("`A`") && hit.message.contains("`write`"),
        "expected message to cite the alias and target, got: {}",
        hit.message
    );
}

#[test]
fn c_bonsai_fixture_emits_identifier_low_length() {
    // bonsai.c is IOCCC-style: many single-letter globals/functions
    // (`A`, `O`, `w`, `r`, `L`, `P`, `S`, `Q`, …) but with system-call
    // keywords (`extern`, `nanosleep`, `gettimeofday`, `TIOCGWINSZ`) that
    // pull the mean identifier length above 2.0. The single-char-fraction
    // trigger should still fire it.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/bonsai.c"))
        .expect("c/bonsai.c fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::IdentifierLowLength)
        .expect("expected IdentifierLowLength on bonsai.c");
    assert_eq!(hit.severity, disclude::finding::Severity::Info);
    assert!(
        hit.message.contains("single-character"),
        "expected single-char-trigger message, got: {}",
        hit.message
    );
}

#[test]
fn c_printf_fixture_emits_format_string_write() {
    // IOCCC printf.c builds %n write directives via macro stringification:
    // `#define N(a) "%"#a"$hhn"` leaves the literal `$hhn` substring in the
    // source. The C token pass should flag it CRITICAL.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/printf.c"))
        .expect("c/printf.c fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::FormatStringWrite)
        .expect("expected FormatStringWrite finding on printf.c");
    assert_eq!(hit.severity, disclude::finding::Severity::Critical);
    assert!(
        hit.message.contains("$hhn"),
        "expected message to cite the directive, got: {}",
        hit.message
    );
    assert!(
        hit.message.contains("macro"),
        "expected message to cite macro context, got: {}",
        hit.message
    );
}

#[test]
fn c_notation_fixture_emits_kr_main_decorative_and_line_continuation() {
    // IOCCC notation.c is shaped like a chess board: K&R-style main with no
    // return type, decorative internal whitespace forming the visual layout,
    // and `\<nl>` continuations splitting expressions across line breaks.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/notation.c"))
        .expect("c/notation.c fixture was scanned");

    let kr = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::LegacyKAndRMain)
        .expect("expected LegacyKAndRMain on notation.c");
    assert_eq!(kr.severity, disclude::finding::Severity::Warn);
    assert!(kr.message.contains("K&R"));

    let deco = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::WhitespaceAnomaly)
        .expect("expected decorative WhitespaceAnomaly on notation.c");
    assert_eq!(deco.severity, disclude::finding::Severity::Warn);
    assert!(
        deco.message.contains("decorative"),
        "expected decorative message, got: {}",
        deco.message
    );

    let cont = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::LineContinuationInCode)
        .expect("expected LineContinuationInCode on notation.c");
    assert_eq!(cont.severity, disclude::finding::Severity::Warn);
}

#[test]
fn c_magritte_fixture_emits_implicit_int_dynamic_format_and_embedded_nul() {
    // IOCCC magritte.c packs three signals worth surfacing:
    //   * 19 functions defined without an explicit return type
    //   * `printf(F, ...)` with a global (non-literal) format string
    //   * `"|\\/=_ \n](.\0(...)..."` — an embedded NUL with trailing payload
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/magritte.c"))
        .expect("c/magritte.c fixture was scanned");

    let implicit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::ImplicitIntFunction)
        .expect("expected ImplicitIntFunction on magritte.c");
    assert_eq!(implicit.severity, disclude::finding::Severity::Warn);
    assert!(
        implicit.message.contains("functions"),
        "expected count-bearing message, got: {}",
        implicit.message
    );

    let dyn_fmt = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicFormatString)
        .expect("expected DynamicFormatString on magritte.c");
    assert_eq!(dyn_fmt.severity, disclude::finding::Severity::Warn);
    assert!(
        dyn_fmt.message.contains("printf"),
        "expected printf in message, got: {}",
        dyn_fmt.message
    );

    let nul = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::EmbeddedNulInString)
        .expect("expected EmbeddedNulInString on magritte.c");
    assert_eq!(nul.severity, disclude::finding::Severity::Warn);
}

#[test]
fn c_rational_fixture_emits_reverse_subscript_recursive_main_and_stringify() {
    // IOCCC rational.c packs three obfuscation signals:
    //   * `#define q [v+a]` — bracket-only macro body forming `2 q` ⇒ `2[v+a]`
    //   * `main(d, b)` recursive call from inside main()
    //   * `*#v` stringify-then-dereference inside the `p` macro body
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/rational.c"))
        .expect("c/rational.c fixture was scanned");

    let rev = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::ReverseSubscriptNotation)
        .expect("expected ReverseSubscriptNotation on rational.c");
    assert_eq!(rev.severity, disclude::finding::Severity::Warn);
    assert!(
        rev.message.contains("#define q") || rev.message.contains("integer literal"),
        "unexpected message: {}",
        rev.message
    );

    let rec = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::RecursiveMainCall)
        .expect("expected RecursiveMainCall on rational.c");
    assert_eq!(rec.severity, disclude::finding::Severity::Warn);

    let strg = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::StringifyDereference)
        .expect("expected StringifyDereference on rational.c");
    assert_eq!(strg.severity, disclude::finding::Severity::Warn);
    assert!(
        strg.message.contains("`p`"),
        "expected macro name `p` in message, got: {}",
        strg.message
    );
}

#[test]
fn python_multi_stage_fixture_emits_three_signals() {
    // multi_stage.py is a malware-shape Python module:
    //   * a 33-escape `b"..."` payload literal
    //   * imports of zlib + base64 + codecs (decoder modules)
    //   * a top-level `exec(...)` chain that runs on import
    // We expect: payload-bytes-literal (warn), decoder-import-with-exec
    // (warn), and the dynamic-execution finding elevated to CRITICAL because
    // the call sits at module scope.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("python/multi_stage.py"))
        .expect("python/multi_stage.py fixture was scanned");

    let payload = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::PayloadBytesLiteral)
        .expect("expected PayloadBytesLiteral on multi_stage.py");
    assert_eq!(payload.severity, disclude::finding::Severity::Warn);
    assert!(
        payload.message.contains("\\xNN"),
        "unexpected message: {}",
        payload.message
    );

    let dec = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DecoderImportWithExec)
        .expect("expected DecoderImportWithExec on multi_stage.py");
    assert_eq!(dec.severity, disclude::finding::Severity::Warn);
    for module in ["base64", "zlib", "codecs"] {
        assert!(
            dec.message.contains(module),
            "expected `{}` cited in decoder-import-with-exec message, got: {}",
            module,
            dec.message
        );
    }

    let dynx = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicExecution)
        .expect("expected DynamicExecution on multi_stage.py");
    assert_eq!(
        dynx.severity,
        disclude::finding::Severity::Critical,
        "module-scope exec must elevate to CRITICAL, got: {:?}",
        dynx
    );
    assert!(
        dynx.message.contains("module scope"),
        "expected module-scope wording in message, got: {}",
        dynx.message
    );
}

#[test]
fn python_getframe_fixture_emits_critical_frame_introspection() {
    // getframe.py uses `sys._getframe(1).f_globals` to snoop on the caller
    // and then bails with `sys.exit()` if it sees an analyzer in the stack.
    // The introspection signal should fire and elevate to CRITICAL because
    // the file also contains an exec/eval/sys.exit elevation trigger.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("python/getframe.py"))
        .expect("python/getframe.py fixture was scanned");

    let intro = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::FrameIntrospection)
        .expect("expected FrameIntrospection on getframe.py");
    assert_eq!(
        intro.severity,
        disclude::finding::Severity::Critical,
        "_getframe + sys.exit must elevate to CRITICAL, got: {:?}",
        intro
    );
    assert!(
        intro.message.contains("sys._getframe"),
        "expected `sys._getframe` cited in message, got: {}",
        intro.message
    );
    assert!(
        intro.message.contains("anti-analysis"),
        "expected anti-analysis suffix, got: {}",
        intro.message
    );
}

#[test]
fn python_context_fixture_emits_dynamic_import_shellout_chain() {
    // context.py hides destructive shell behaviour inside a context
    // manager's __exit__ via `__import__('os').system('rm -rf /tmp/...')`.
    // The detector must resolve the __import__ chain to os.system and
    // emit CRITICAL because reaching shell-call APIs through __import__
    // is itself the obfuscation tell.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("python/context.py"))
        .expect("python/context.py fixture was scanned");

    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicExecution && f.message.contains("__import__"))
        .expect("expected DynamicExecution finding for __import__ chain on context.py");
    assert_eq!(
        hit.severity,
        disclude::finding::Severity::Critical,
        "__import__('os').system(...) must be CRITICAL, got: {:?}",
        hit
    );
    assert!(
        hit.message.contains("os.system"),
        "expected `os.system` resolved through chain, got: {}",
        hit.message
    );
    assert_eq!(
        hit.line, 6,
        "finding should anchor on the line with the __import__ call"
    );
}

#[test]
fn typescript_proxy_gate_fixture_emits_proxy_global_hijack() {
    // proxy_gate.ts wraps `globalThis` in a Proxy whose `get` handler
    // reassembles "process" from a small map and returns the value
    // through bracket subscript. The string literals never appear in
    // direct form, so the AST signal that anchors detection is
    // ProxyGlobalHijack on `new Proxy(globalThis, ...)`.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/proxy_gate.ts")
        })
        .expect("typescript/proxy_gate.ts fixture was scanned");

    let hijack = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::ProxyGlobalHijack)
        .expect("expected ProxyGlobalHijack on proxy_gate.ts");
    assert_eq!(hijack.severity, disclude::finding::Severity::Critical);
    assert!(
        hijack.message.contains("globalThis"),
        "expected message to name the global target, got: {}",
        hijack.message
    );
    assert_eq!(
        hijack.line, 10,
        "finding should anchor on the `new Proxy(globalThis, handler)` line"
    );
}

#[test]
fn typescript_intl_fixture_surfaces_payload_via_existing_detectors() {
    // intl.ts demonstrates the "stash a payload in a free-form Intl
    // string field" pattern (timeZone, locale tags, etc.). The receiver
    // looks innocuous — `Intl.DateTimeFormat`, `Intl.NumberFormat` — but
    // the string handed in is the real cargo. The point of pinning this
    // fixture is to confirm that payload-shape detectors fire regardless
    // of which API wraps the literal: they key off the string bytes, not
    // the call surface.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("typescript/intl.ts"))
        .expect("typescript/intl.ts fixture was scanned");

    let b64 = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::EncodingBase64)
        .expect("expected EncodingBase64 on the timeZone payload");
    assert_eq!(b64.severity, disclude::finding::Severity::Warn);
    assert_eq!(
        b64.line, 15,
        "base64 payload should anchor on the timeZone literal"
    );

    let soup = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::EncodingEscapeSoup)
        .expect("expected EncodingEscapeSoup on the hex locale literal");
    assert_eq!(soup.severity, disclude::finding::Severity::Warn);
    assert_eq!(
        soup.line, 22,
        "hex-escape soup should anchor on the locale literal"
    );
}

#[test]
fn typescript_dynamic_import_fixture_emits_data_uri_import_critical() {
    // dynamic_import.ts builds a `data:text/javascript;base64,${...}`
    // template into a `const`, then calls `import(spec)`. Detection must
    // resolve the identifier through the variable initializer and flip
    // the generic dynamic-import warn to data-uri-import critical.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/dynamic_import.ts")
        })
        .expect("typescript/dynamic_import.ts fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DataUriImport)
        .expect("expected DataUriImport on dynamic_import.ts");
    assert_eq!(hit.severity, disclude::finding::Severity::Critical);
    assert_eq!(hit.line, 6);
    // The sharper signal replaces the generic dynamic-import warn —
    // this fixture must not double-emit both.
    assert!(
        file.findings
            .iter()
            .all(|f| f.kind != SignalKind::DynamicImport),
        "expected dynamic-import to NOT also fire when data-uri-import does, got: {:?}",
        file.findings
    );
}

#[test]
fn typescript_error_stack_fixture_emits_error_stack_inspection() {
    // error_stack.ts binds `const stack = new Error().stack || ''` and then
    // calls `stack.includes(...)` twice to fingerprint analysis runners.
    // Detection must resolve the variable through the `||` fallback and
    // fire on each match call.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/error_stack.ts")
        })
        .expect("typescript/error_stack.ts fixture was scanned");
    let hits: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::ErrorStackInspection)
        .collect();
    assert_eq!(
        hits.len(),
        2,
        "expected 2 ErrorStackInspection findings (one per .includes call), got {:?}",
        file.findings
    );
    for h in &hits {
        assert_eq!(h.severity, disclude::finding::Severity::Warn);
        assert_eq!(
            h.line, 5,
            "both match calls live on line 5 (the return expression)"
        );
    }
}

#[test]
fn typescript_generators_fixture_emits_generator_yield_callable() {
    // generators.ts defines `function* dispatcher()` that yields two
    // arrow functions; the driver pulls each out with `g.next().value!()`
    // to invoke them. Detection must fire on each callable yield and
    // name the enclosing generator in the message.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/generators.ts")
        })
        .expect("typescript/generators.ts fixture was scanned");
    let hits: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::GeneratorYieldCallable)
        .collect();
    assert_eq!(
        hits.len(),
        2,
        "expected 2 GeneratorYieldCallable findings (one per yield), got {:?}",
        file.findings
    );
    for h in &hits {
        assert_eq!(h.severity, disclude::finding::Severity::Warn);
        assert!(
            h.message.contains("dispatcher"),
            "expected message to name the generator, got: {}",
            h.message
        );
    }
    let lines: Vec<usize> = hits.iter().map(|h| h.line).collect();
    assert!(
        lines.contains(&5),
        "expected hit on yield line 5, got {:?}",
        lines
    );
    assert!(
        lines.contains(&10),
        "expected hit on yield line 10, got {:?}",
        lines
    );
}

#[test]
fn typescript_template_fixture_emits_tag_function_deobfuscator() {
    // template.ts defines a tag function `r` that reverses each
    // template-string segment, then uses `` r`...` `` to materialize the
    // real C2 URL at runtime. Detection requires resolving the tag
    // identifier back to a function whose body applies a decoding op.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/template.ts")
        })
        .expect("typescript/template.ts fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::TagFunctionDeobfuscator)
        .expect("expected TagFunctionDeobfuscator on template.ts");
    assert_eq!(hit.severity, disclude::finding::Severity::Critical);
    assert!(
        hit.message.contains("`r`"),
        "expected message to name the tag function, got: {}",
        hit.message
    );
    assert_eq!(
        hit.line, 7,
        "finding should anchor on the `r\\`...\\`` use, not the function declaration"
    );
}

#[test]
fn typescript_string_concat_watchlist_includes_process() {
    // Cross-cutting check on the token-pass watchlist — concatenated
    // string literals that reconstruct `process` should fire
    // StringConcatConstruction. We exercise the rule directly with a
    // synthetic source to avoid coupling to an existing fixture.
    use disclude::language::Language;
    use disclude::util::LineIndex;
    use std::path::PathBuf;
    let src = b"const a = 'proc' + 'ess';\n";
    let index = LineIndex::new(src);
    let findings = disclude::token::analyze(
        &PathBuf::from("synth.ts"),
        src,
        Language::TypeScript,
        &index,
        Vec::new(),
    );
    let process_hit = findings
        .iter()
        .find(|f| f.kind == SignalKind::StringConcatConstruction && f.message.contains("process"));
    assert!(
        process_hit.is_some(),
        "expected `process` concat to fire StringConcatConstruction, got: {:?}",
        findings
    );
}

#[test]
fn c_defines_fixture_emits_macro_keyword_override_and_collision() {
    // IOCCC defines.c rebinds reserved C keywords via `#define` and packs
    // distinct identifiers that collapse to the same visual skeleton.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/defines.c"))
        .expect("c/defines.c fixture was scanned");

    let overrides: Vec<&disclude::finding::Finding> = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::MacroKeywordOverride)
        .collect();
    assert!(
        overrides.len() >= 3,
        "expected ≥3 MacroKeywordOverride findings on defines.c, got {}: {:?}",
        overrides.len(),
        overrides
    );
    for f in &overrides {
        assert_eq!(f.severity, disclude::finding::Severity::Warn);
    }
    let names: Vec<&str> = overrides
        .iter()
        .filter_map(|f| {
            ["double", "char", "union"]
                .iter()
                .copied()
                .find(|k| f.message.contains(*k))
        })
        .collect();
    for kw in ["double", "char", "union"] {
        assert!(
            names.contains(&kw),
            "expected `#define {}` override, got messages: {:?}",
            kw,
            overrides.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
    }

    let collisions: Vec<&disclude::finding::Finding> = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::IdentifierConfusableCollision)
        .collect();
    assert!(
        collisions.len() >= 2,
        "expected ≥2 IdentifierConfusableCollision findings on defines.c, got {}: {:?}",
        collisions.len(),
        collisions
    );
    for f in &collisions {
        assert_eq!(f.severity, disclude::finding::Severity::Warn);
        assert!(
            f.message.contains("skeleton"),
            "expected skeleton message, got: {}",
            f.message
        );
    }
}

#[test]
fn ts_clean_fixture_emits_no_findings() {
    let r = run();
    let clean = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("typescript/clean.ts"))
        .expect("typescript/clean.ts fixture was scanned");
    assert!(
        clean.findings.is_empty(),
        "ts clean fixture produced findings: {:?}",
        clean.findings
    );
}

#[test]
fn evil_package_json_emits_install_hook_shellout() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("evil_pkg/package.json"))
        .expect("evil_pkg/package.json fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::InstallHookShellout)
        .expect("expected InstallHookShellout on evil postinstall");
    assert_eq!(hit.severity, disclude::finding::Severity::Warn);
    assert!(hit.message.contains("postinstall"));
}

#[test]
fn clean_package_json_emits_no_install_hook_findings() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("clean_pkg/package.json")
        })
        .expect("clean_pkg/package.json fixture was scanned");
    assert!(
        file.findings
            .iter()
            .all(|f| f.kind != SignalKind::InstallHookShellout),
        "clean postinstall (node script) should not fire a shellout finding: {:?}",
        file.findings
    );
}

#[test]
fn rust_unsafe_plus_warn_is_elevated_to_critical() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("rust/unsafe_with_warn.rs")
        })
        .expect("rust/unsafe_with_warn.rs fixture was scanned");
    // Without elevation, the base64 blob would be Warn. The scorer must
    // flip it to Critical because the same file contains an unsafe block.
    let b64 = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::EncodingBase64)
        .expect("expected base64 finding");
    assert_eq!(b64.severity, disclude::finding::Severity::Critical);
    assert!(
        b64.message.contains("elevated"),
        "elevation should be noted in message, got: {}",
        b64.message
    );
}

#[test]
fn rust_clean_fixture_emits_no_findings() {
    let r = run();
    let clean = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("rust/clean.rs"))
        .expect("rust/clean.rs fixture was scanned");
    assert!(
        clean.findings.is_empty(),
        "rust clean fixture produced findings: {:?}",
        clean.findings
    );
}

#[test]
fn base64_eval_compile_fixture_emits_expected_findings() {
    // Obfuscation pattern from a real dropper: base64 strings stitched together
    // through `\xNN`-escaped identifiers, then fed to eval(compile(b64decode(...))).
    // The scanner should catch both the escape-soup payload construction (raw)
    // and the decoded value reaching eval/compile (ast).
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("base64_eval_compile.py")
        })
        .expect("base64_eval_compile fixture was scanned");

    use disclude::finding::Severity;
    let by_kind_sev: Vec<(SignalKind, Severity, usize)> = {
        let mut v: Vec<(SignalKind, Severity, usize)> = Vec::new();
        for f in &file.findings {
            match v.iter_mut().find(|e| e.0 == f.kind && e.1 == f.severity) {
                Some(e) => e.2 += 1,
                None => v.push((f.kind, f.severity, 1)),
            }
        }
        v.sort_by_key(|e| (e.0 as u8, e.1 as u8));
        v
    };

    // Two escape-soup runs on line 7 (the `trust = eval(...) + eval(...) + ...`
    // chain) and two dynamic-execution hits on line 8 (eval + compile reached
    // by a decoded value).
    assert_eq!(
        file.findings
            .iter()
            .filter(|f| f.kind == SignalKind::EncodingEscapeSoup
                && f.severity == Severity::Warn
                && f.line == 7)
            .count(),
        2,
        "expected 2 WARN escape-soup findings on line 7, got: {:?}",
        by_kind_sev
    );
    let dyn_exec: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.kind == SignalKind::DynamicExecution)
        .collect();
    assert_eq!(
        dyn_exec.len(),
        2,
        "expected 2 dynamic-execution findings (eval + compile), got: {:?}",
        dyn_exec
    );
    assert!(
        dyn_exec.iter().all(|f| f.severity == Severity::Critical),
        "both dynamic-execution findings must be CRITICAL, got: {:?}",
        dyn_exec
    );
    assert!(
        dyn_exec.iter().all(|f| f.line == 8),
        "dynamic-execution findings should anchor on line 8 (the eval(compile(...)) call)"
    );
    assert!(
        dyn_exec.iter().any(|f| f.message.contains("`eval`")),
        "expected a finding citing `eval`"
    );
    assert!(
        dyn_exec.iter().any(|f| f.message.contains("`compile`")),
        "expected a finding citing `compile`"
    );

    // Full finding set: 2 EncodingEscapeSoup + 2 DynamicExecution +
    // 1 DecoderImportWithExec = 5 total. Short b64-looking strings
    // (`cHJpbnQ`, `bVxuyoT`, ...) are below the base64 detector's 64-char
    // threshold and must not trigger.
    assert_eq!(
        file.findings.len(),
        5,
        "expected exactly 5 findings, got: {:?}",
        file.findings
    );
    assert!(
        !file
            .findings
            .iter()
            .any(|f| f.kind == SignalKind::EncodingBase64),
        "short base64-like literals must not trigger the base64 detector"
    );
    assert_eq!(
        file.findings
            .iter()
            .filter(|f| f.kind == SignalKind::DecoderImportWithExec)
            .count(),
        1,
        "expected one decoder-import-with-exec finding (base64 + codecs imported, eval/compile present)"
    );
}

#[test]
fn base64_fixture_finding_stays_warn_inside_string() {
    // Token pass must NOT demote the base64 finding: the blob lives inside a
    // string literal, which is exactly where we expect encoded payloads.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("base64_blob.py"))
        .expect("base64 fixture was scanned");
    let b64 = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::EncodingBase64)
        .expect("base64 finding present");
    assert_eq!(b64.severity, disclude::finding::Severity::Warn);
}

#[test]
fn c_shellout_fixture_emits_dynamic_execution_critical() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/shellout.c"))
        .expect("c/shellout.c fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicExecution)
        .expect("expected DynamicExecution finding on c/shellout.c");
    assert_eq!(hit.severity, disclude::finding::Severity::Critical);
}

#[test]
fn c_dlopen_fixture_emits_dynamic_import_and_attribute() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/dlopen_dlsym.c"))
        .expect("c/dlopen_dlsym.c fixture was scanned");
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicImport),
        "expected DynamicImport from dlopen(path, ...) call"
    );
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicAttribute),
        "expected DynamicAttribute from dlsym(h, name) call"
    );
}

#[test]
fn c_salmon_fixture_emits_unicode_invisible() {
    // IOCCC 2024 "cable2/salmon": invisible Unicode Tag characters embedded in
    // macro names and inline code make the program behave differently from what
    // it visually appears to do.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/salmon.c"))
        .expect("c/salmon.c fixture was scanned");
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::UnicodeInvisible),
        "expected UnicodeInvisible findings in salmon.c, got: {:?}",
        file.findings
    );
    // The tag chars embedded directly in code (not inside string/comment tokens)
    // must remain at Warn or higher.
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::UnicodeInvisible
                && f.severity >= disclude::finding::Severity::Warn),
        "expected at least one Warn-level UnicodeInvisible finding"
    );
}

#[test]
fn c_clean_fixture_emits_no_findings() {
    let r = run();
    let clean = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("c/clean.c"))
        .expect("c/clean.c fixture was scanned");
    assert!(
        clean.findings.is_empty(),
        "c clean fixture produced findings: {:?}",
        clean.findings
    );
}

#[test]
fn ts_recruiter_attack_fixture_emits_base64_and_atob() {
    // Replicates the DPRK-linked supply-chain attack described at
    // https://dev.to/mighty840/i-was-targeted-by-a-dprk-linked-supply-chain-attack-via-linkedin-heres-exactly-how-it-worked-21kp
    // The attack stores a C2 URL as a padded base64 literal then decodes it
    // with `atob()` at runtime. Both signals must fire.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/recruiter_attack.js")
        })
        .expect("typescript/recruiter_attack.js fixture was scanned");
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::EncodingBase64),
        "expected EncodingBase64 from padded base64 C2 URL: {:?}",
        file.findings
    );
    assert!(
        file.findings
            .iter()
            .any(|f| f.kind == SignalKind::DynamicExecution),
        "expected DynamicExecution from atob() call: {:?}",
        file.findings
    );
}

#[test]
fn ts_jsfuck_fixture_emits_narrow_file_charset() {
    // JSF*ck encodes arbitrary JS using only 6 characters: `!()+[]`.
    // The narrow-file-charset signal must fire at Warn.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("typescript/jsfuck.js"))
        .expect("typescript/jsfuck.js fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::NarrowFileCharset)
        .expect("expected NarrowFileCharset finding");
    assert_eq!(hit.severity, disclude::finding::Severity::Warn);
    assert!(
        hit.message.contains('6'),
        "message should report 6 distinct characters, got: {}",
        hit.message
    );
}

#[test]
fn bash_eval_dynamic_fixture_emits_dynamic_execution_critical() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/eval_dynamic.sh"))
        .expect("bash/eval_dynamic.sh fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL DynamicExecution finding on bash/eval_dynamic.sh");
    assert!(
        hit.message.contains("eval"),
        "expected message to cite `eval`, got: {}",
        hit.message
    );
}

#[test]
fn bash_pipe_to_shell_fixture_emits_dynamic_execution_warn() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/pipe_to_shell.sh"))
        .expect("bash/pipe_to_shell.sh fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Warn
        })
        .expect("expected Warn DynamicExecution finding on bash/pipe_to_shell.sh");
    assert!(
        hit.message.contains("bash"),
        "expected message to cite `bash`, got: {}",
        hit.message
    );
}

#[test]
fn bash_clean_fixture_emits_no_findings() {
    let r = run();
    let clean = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/clean.sh"))
        .expect("bash/clean.sh fixture was scanned");
    assert!(
        clean.findings.is_empty(),
        "bash clean fixture produced findings: {:?}",
        clean.findings
    );
}

#[test]
fn bash_b64_dropper_fixture_emits_base64_and_pipe_to_shell() {
    // Synthetic dropper based on the Linux malware pattern described in
    // "Analysis of a Malicious Linux Script" (Medium, Shubh Andrew):
    // a base64-encoded second-stage script is embedded in the file, decoded
    // at runtime, and piped directly into bash — no disk write.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/b64_dropper.sh"))
        .expect("bash/b64_dropper.sh fixture was scanned");

    // Raw pass: the embedded base64 literal should be flagged.
    file.findings
        .iter()
        .find(|f| f.kind == SignalKind::EncodingBase64)
        .expect("expected EncodingBase64 finding on bash/b64_dropper.sh");

    // AST pass: the `base64 -d | bash` pipeline is an encoded dropper —
    // elevated to CRITICAL.
    let pipe_hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected Critical DynamicExecution (encoded dropper) on bash/b64_dropper.sh");
    assert!(
        pipe_hit.message.contains("base64"),
        "expected pipe message to cite `base64`, got: {}",
        pipe_hit.message
    );
}

#[test]
fn bash_wget_exec_fixture_emits_dynamic_exec_critical() {
    // Synthetic dropper based on the Linux malware pattern: fetches a binary
    // disguised as a PNG image, stages it in a hidden /var/tmp directory,
    // and replaces the current process via exec with a dynamic path.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/wget_exec.sh"))
        .expect("bash/wget_exec.sh fixture was scanned");

    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL DynamicExecution on bash/wget_exec.sh");
    assert!(
        hit.message.contains("exec"),
        "expected message to cite `exec`, got: {}",
        hit.message
    );
}

#[test]
fn bash_env_var_fixture_emits_destructive_payload_and_eval() {
    // env_var.sh stores "rm -rf /" in an env var, then eval's it.
    // Two CRITICAL findings must fire:
    //   1. DestructiveCommandPayload on the string literal (line 2)
    //   2. DynamicExecution on the eval (line 4)
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/env_var.sh"))
        .expect("bash/env_var.sh fixture was scanned");

    let payload = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DestructiveCommandPayload)
        .expect("expected DestructiveCommandPayload on bash/env_var.sh");
    assert_eq!(payload.severity, disclude::finding::Severity::Critical);
    assert_eq!(
        payload.line, 2,
        "finding should anchor on the string literal"
    );

    let dynx = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicExecution)
        .expect("expected DynamicExecution on bash/env_var.sh");
    assert_eq!(dynx.severity, disclude::finding::Severity::Critical);
    assert_eq!(dynx.line, 4, "finding should anchor on the eval call");
}

#[test]
fn bash_ifs_escapes_fixture_emits_obfuscated_command_and_ifs() {
    // ifs_escapes.sh demonstrates two obfuscation techniques:
    //   1. `\b\i\n/\n\c -e /\b\i\n/s\h` — every char backslash-quoted to hide /bin/nc
    //   2. `IFS=,; cmd=/bin/bash,-c,whoami; $cmd` — comma separator splits on expand
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/ifs_escapes.sh"))
        .expect("bash/ifs_escapes.sh fixture was scanned");

    let obf = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::ObfuscatedCommandName)
        .expect("expected ObfuscatedCommandName on bash/ifs_escapes.sh");
    assert_eq!(obf.severity, disclude::finding::Severity::Warn);

    let ifs = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::IfsManipulation)
        .expect("expected IfsManipulation on bash/ifs_escapes.sh");
    assert_eq!(ifs.severity, disclude::finding::Severity::Warn);
    assert!(
        ifs.message.contains(','),
        "expected message to cite the comma separator, got: {}",
        ifs.message
    );
}

#[test]
fn bash_function_shadowing_fixture_emits_critical() {
    // function_shadowing.sh defines `sudo()` to capture the typed password
    // before forwarding to the real sudo — a classic credential-theft pattern.
    // The FunctionShadowing signal must fire CRITICAL and name the shadowed command.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("bash/function_shadowing.sh")
        })
        .expect("bash/function_shadowing.sh fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::FunctionShadowing)
        .expect("expected FunctionShadowing on bash/function_shadowing.sh");
    assert_eq!(hit.severity, disclude::finding::Severity::Critical);
    assert!(
        hit.message.contains("sudo"),
        "expected message to name the shadowed command, got: {}",
        hit.message
    );
}

#[test]
fn bash_b64_source_fixture_emits_base64_and_dynamic_import() {
    // b64_source.sh stores a base64-encoded payload in a variable, then decodes
    // and sources it via `source <(echo $PAYLOAD | base64 -d)`.  Two signals
    // must fire: the raw-pass base64 blob and the AST-pass dynamic import from
    // the process substitution passed to `source`.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/b64_source.sh"))
        .expect("bash/b64_source.sh fixture was scanned");

    file.findings
        .iter()
        .find(|f| f.kind == SignalKind::EncodingBase64)
        .expect("expected EncodingBase64 on bash/b64_source.sh");

    let import_hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicImport)
        .expect("expected DynamicImport from source <(…) on bash/b64_source.sh");
    assert_eq!(import_hit.severity, disclude::finding::Severity::Warn);
    assert!(
        import_hit.message.contains("source"),
        "expected message to cite `source`, got: {}",
        import_hit.message
    );
}

#[test]
fn bash_variable_expansion_fixture_emits_dynamic_execution_critical() {
    // variable_expansion.sh reconstructs "bash" and "curl" from substrings of
    // a string variable, then passes the assembled command through `eval`.
    // The eval-of-variable path must catch this even though neither "curl" nor
    // "bash" appears as a literal token in the source.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("bash/variable_expansion.sh")
        })
        .expect("bash/variable_expansion.sh fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL DynamicExecution on bash/variable_expansion.sh");
    assert!(
        hit.message.contains("eval"),
        "expected message to cite `eval`, got: {}",
        hit.message
    );
}

#[test]
fn bash_c_flag_fixture_emits_dynamic_execution_critical() {
    // bash_c_flag.sh fetches a payload via command substitution and passes it
    // to `bash -c`, which is semantically equivalent to eval but avoids the
    // eval keyword.  Detection must fire CRITICAL DynamicExecution.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/bash_c_flag.sh"))
        .expect("bash/bash_c_flag.sh fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL DynamicExecution on bash/bash_c_flag.sh");
    assert!(
        hit.message.contains("bash -c"),
        "expected message to cite `bash -c`, got: {}",
        hit.message
    );
}

#[test]
fn bash_obfuscate_fixture_emits_single_critical_eval() {
    // Output of the `bash-obfuscate` npm tool: the original script is split
    // into fragments stored in short variables (Az, Bz, …), then reassembled
    // and executed via `eval "$Az$Bz$Cz…"`. The only signal should be the
    // CRITICAL DynamicExecution on the eval line; the variable assignments on
    // the preceding line are individually benign and should not fire.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("bash/bash-obfuscate.sh")
        })
        .expect("bash/bash-obfuscate.sh fixture was scanned");

    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL DynamicExecution on bash/bash-obfuscate.sh");
    assert!(
        hit.message.contains("eval"),
        "expected message to cite `eval`, got: {}",
        hit.message
    );
    assert_eq!(
        file.findings.len(),
        1,
        "expected exactly 1 finding (the eval), got: {:?}",
        file.findings
    );
}

#[test]
fn js_glassworm_fixture_emits_invisible_and_dynamic_execution() {
    // glassworm-style attack: a JS template literal contains 38 invisible
    // Variation Selector Supplement codepoints (U+E0100-E01EF) that encode a
    // hidden payload; at runtime `new Function(...)` executes it.
    // We expect UnicodeInvisible findings for each encoded byte plus a
    // CRITICAL DynamicExecution for the `new Function(...)` call.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("typescript/hidden_payload.js")
        })
        .expect("typescript/hidden_payload.js fixture was scanned");

    // The 38 VSS codepoints should be collapsed into one CRITICAL aggregate
    // finding whose message includes the decoded payload string.
    let aggregate = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::UnicodeInvisible
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL UnicodeInvisible aggregate for glassworm VSS payload");
    assert!(
        aggregate.message.contains("38"),
        "expected aggregate message to report 38 chars, got: {}",
        aggregate.message
    );
    assert!(
        aggregate.message.contains("console.log"),
        "expected decoded payload in aggregate message, got: {}",
        aggregate.message
    );

    file.findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL DynamicExecution for new Function(...) in hidden_payload.js");
}

#[test]
fn bash_tcp_exfil_fixture_emits_dev_tcp_socket_critical() {
    // Uses bash's /dev/tcp/ pseudo-device to open a TCP connection and exfiltrate
    // /etc/passwd without any external binary (nc, curl, etc.).
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/tcp_exfil.sh"))
        .expect("bash/tcp_exfil.sh fixture was scanned");
    file.findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::BashDevTcpSocket
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL BashDevTcpSocket on bash/tcp_exfil.sh");
}

#[test]
fn bash_arithmetic_char_fixture_emits_dynamic_execution_critical() {
    // Assembles a command name from ASCII character codes via arithmetic
    // expansion (`printf "\\$((105))\\$((100))"` → `id`), stores it in
    // a variable, then executes `$cmd` — using a variable as the command
    // name, which is equivalent to eval.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("bash/arithmetic_char.sh")
        })
        .expect("bash/arithmetic_char.sh fixture was scanned");
    file.findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL DynamicExecution on bash/arithmetic_char.sh");
}

#[test]
fn bash_path_hijack_fixture_emits_path_command_shadow_critical() {
    // Prepends /tmp to PATH and writes a fake `ls` binary there, so that
    // running `ls` triggers the attacker-controlled payload.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/path_hijack.sh"))
        .expect("bash/path_hijack.sh fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::PathCommandShadow
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL PathCommandShadow on bash/path_hijack.sh");
    assert!(
        hit.message.contains("ls"),
        "expected message to identify `ls` as the shadowed command, got: {}",
        hit.message
    );
}

#[test]
fn bash_read_sink_fixture_emits_encoded_dropper_critical() {
    // Loads a base64 payload via `read -r` heredoc, then runs
    // `echo $payload | base64 -d | bash` — the decoder-in-pipeline
    // pattern should be elevated to CRITICAL.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("bash/read_sink.sh"))
        .expect("bash/read_sink.sh fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution
                && f.severity == disclude::finding::Severity::Critical
        })
        .expect("expected CRITICAL DynamicExecution (encoded dropper) on bash/read_sink.sh");
    assert!(
        hit.message.contains("base64"),
        "expected message to name the decoder, got: {}",
        hit.message
    );
}

// ---------------------------------------------------------------------------
// Markup / text file types — embedded code extraction + global payload scan.
// ---------------------------------------------------------------------------

#[test]
fn gha_yaml_run_emits_embedded_bash_finding() {
    // GitHub Actions `run:` scalars (inline and block) are scanned as Bash:
    // `curl | bash` (pipe-to-shell) and `eval "$INJECTED"` (dynamic eval).
    let r = run();
    assert!(has_kind_in(
        &r,
        "yaml/gha_curl_pipe.yml",
        SignalKind::DynamicExecution
    ));
}

#[test]
fn gitlab_yaml_script_emits_embedded_bash_finding() {
    // GitLab `script:` sequence items are scanned as Bash; `eval "$CMD"` fires.
    let r = run();
    assert!(has_kind_in(
        &r,
        "yaml/gitlab_script_eval.yml",
        SignalKind::DynamicExecution
    ));
}

#[test]
fn markdown_python_fence_emits_dynamic_execution() {
    // A ```python fence containing exec(<non-literal>) is scanned as Python.
    let r = run();
    assert!(has_kind_in(
        &r,
        "markdown/skill_exec.md",
        SignalKind::DynamicExecution
    ));
}

#[test]
fn markdown_embedded_finding_maps_to_real_line() {
    // The embedded-block finding must report its location in the *markdown*
    // file. `exec(data)` sits on line 7 of skill_exec.md.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("markdown/skill_exec.md")
        })
        .expect("skill_exec.md fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicExecution)
        .expect("DynamicExecution finding present");
    assert_eq!(hit.line, 7, "expected exec() on line 7, got {}", hit.line);
    assert!(
        hit.message.contains("[embedded python]"),
        "expected embedded-origin tag, got: {}",
        hit.message
    );
}

#[test]
fn markdown_clean_emits_no_findings() {
    // Prose plus a non-code ```text fence must not produce findings.
    let r = run();
    let clean = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("markdown/clean.md"))
        .expect("clean.md fixture was scanned");
    assert!(
        clean.findings.is_empty(),
        "clean markdown produced findings: {:?}",
        clean.findings
    );
}

#[test]
fn rst_code_block_emits_embedded_bash_finding() {
    // `.. code-block:: bash` body (after a `:linenos:` option) is scanned as
    // Bash; `eval "$REMOTE_CMD"` fires.
    let r = run();
    assert!(has_kind_in(
        &r,
        "rst/code_block.rst",
        SignalKind::DynamicExecution
    ));
}

#[test]
fn text_file_bidi_payload_is_scanned() {
    // Plain .txt gets the global raw payload pass: a bidi override is flagged.
    let r = run();
    assert!(has_kind_in(&r, "text/bidi.txt", SignalKind::UnicodeBidi));
}

#[test]
fn encrypted_archive_with_inline_password_is_flagged_in_shell() {
    // `unzip -P "<pw>"` — a password-protected payload that evades inspection.
    let r = run();
    assert!(has_kind_in(
        &r,
        "bash/encrypted_archive.sh",
        SignalKind::EncryptedArchiveExtraction
    ));
}

#[test]
fn markdown_obfuscated_eval_base64_flags_both_signals() {
    // obfuscated.md hides `eval $(echo "<base64>" | base64 -d)` as bare prose.
    // The prose scan flags the eval-on-substitution (dynamic execution) and the
    // raw pass independently flags the base64 blob — two complementary signals.
    let r = run();
    assert!(has_kind_in(
        &r,
        "markdown/obfuscated.md",
        SignalKind::DynamicExecution
    ));
    assert!(has_kind_in(
        &r,
        "markdown/obfuscated.md",
        SignalKind::EncodingBase64
    ));
}

#[test]
fn markdown_obfuscated_eval_is_prose_tagged_and_critical() {
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| {
            fa.path
                .to_string_lossy()
                .ends_with("markdown/obfuscated.md")
        })
        .expect("obfuscated.md fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::DynamicExecution)
        .expect("expected DynamicExecution from prose scan");
    assert_eq!(hit.severity, disclude::finding::Severity::Critical);
    assert!(
        hit.message.contains("[markup prose]"),
        "expected prose-origin tag, got: {}",
        hit.message
    );
}

#[test]
fn markdown_wild_skill_dropper_in_backticks_is_flagged() {
    // twitter.md is a real-world malicious skill file: its macOS step hides a
    // `echo '<base64>' | base64 -D | bash` dropper inside backticks under "copy
    // the command and run it". The pipe-to-shell must fire even though quoted
    // (it is a dropper, not a documentation example), alongside the base64 blob.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("markdown/twitter.md"))
        .expect("twitter.md fixture was scanned");
    let pipe = file
        .findings
        .iter()
        .find(|f| {
            f.kind == SignalKind::DynamicExecution && f.message.contains("pipeline feeds into")
        })
        .expect("expected pipe-to-shell finding from prose scan");
    assert!(pipe.message.contains("[markup prose]"));
    assert!(file
        .findings
        .iter()
        .any(|f| f.kind == SignalKind::EncodingBase64));
}

#[test]
fn markdown_backticked_command_examples_do_not_false_positive() {
    // Commands cited as documentation examples inside inline-code spans or table
    // cells (e.g. `eval "$VAR"`, `unzip -P <pw>`) must NOT be flagged — only
    // bare instructions and pipe-to-shell droppers are. The project README is a
    // worst case: it documents many dangerous commands in backticks and tables.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let readme = PathBuf::from(manifest).join("README.md");
    let r = scan(&readme, &ScanOptions::default()).expect("scan failed");
    let prose: Vec<_> = r
        .files
        .iter()
        .flat_map(|fa| &fa.findings)
        .filter(|f| f.message.contains("[markup prose]"))
        .collect();
    assert!(
        prose.is_empty(),
        "README documentation examples produced prose findings: {:?}",
        prose
            .iter()
            .map(|f| (f.line, &f.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn markdown_unfenced_command_flagged_via_prose_scan() {
    // external.md hides its dangerous commands as bare prose (no code fence) to
    // dodge block extraction. The prose scan must still flag the `unzip -P`.
    let r = run();
    let file = r
        .files
        .iter()
        .find(|fa| fa.path.to_string_lossy().ends_with("markdown/external.md"))
        .expect("external.md fixture was scanned");
    let hit = file
        .findings
        .iter()
        .find(|f| f.kind == SignalKind::EncryptedArchiveExtraction)
        .expect("expected EncryptedArchiveExtraction from prose scan");
    assert!(
        hit.message.contains("[markup prose]"),
        "expected prose-origin tag, got: {}",
        hit.message
    );
}
