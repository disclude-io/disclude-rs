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
        r.files_scanned >= 21,
        "expected at least 21 fixture files, got {} — files: {:?}",
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

    // Full finding set: no other kinds should fire on this fixture. In
    // particular, the short b64-looking strings (`cHJpbnQ`, `bVxuyoT`, ...)
    // are below the base64 detector's 64-char threshold and must not trigger.
    assert_eq!(
        file.findings.len(),
        4,
        "expected exactly 4 findings, got: {:?}",
        file.findings
    );
    assert!(
        !file
            .findings
            .iter()
            .any(|f| f.kind == SignalKind::EncodingBase64),
        "short base64-like literals must not trigger the base64 detector"
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
