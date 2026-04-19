//! disclude — detect obfuscation in source code packages.
//!
//! This is a source-tree scanner. It is not a vulnerability scanner, not a secrets
//! detector, and not a SAST engine. Its single question is: does this source appear
//! to hide its intent from a human reader?

pub mod ast;
pub mod diff;
pub mod finding;
pub mod ignore;
pub mod language;
pub mod package_json;
pub mod raw;
pub mod reporter;
pub mod scan;
pub mod scorer;
pub mod token;
pub mod util;

pub use finding::{FileAnalysis, Finding, PassKind, ScanResult, Severity, SignalKind};
pub use language::Language;
pub use scan::{scan, ScanOptions};
