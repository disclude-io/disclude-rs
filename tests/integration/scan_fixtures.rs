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
    assert_eq!(
        r.files_scanned,
        19,
        "expected 19 fixture files, got {} — files: {:?}",
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
