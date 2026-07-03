//! Fuzz target for the governance-doc classification oracle
//! (`classify_governance_doc`, Governance Intake Component A).
//!
//! Unlike the adapter targets (which fuzz a `TranscriptAdapter::parse` over
//! `RawRecord` bytes), `classify_governance_doc` takes `(path, content,
//! sidecars)` — a pure, total, never-panics function of a string, not a byte
//! parser with its own error type. This target splits the fuzz input into a
//! short path-like prefix and a content suffix (byte 0 also seeds the sidecar
//! flags), lossily converts both to UTF-8 the way a real file-read boundary
//! would, and asserts the oracle never panics and terminates. The libFuzzer
//! harness turns any panic into a crash artifact.
#![cfg_attr(fuzzing, no_main)]

use memscribe_core::governance_doc::{classify_governance_doc, SidecarSignals};

/// Drive one fuzz input through the oracle. `classify_governance_doc` is
/// allowed to return `Some(_)` or `None`; the only contract a fuzz run
/// enforces is that it neither panics nor diverges. We deliberately ignore
/// the result.
#[inline]
fn run(data: &[u8]) {
    if data.is_empty() {
        let sidecars = SidecarSignals::default();
        let _ = classify_governance_doc("", "", &sidecars);
        return;
    }

    // First byte seeds the three sidecar booleans (cheap, deterministic, no
    // extra `arbitrary` plumbing needed for three bits).
    let flags = data[0];
    let sidecars = SidecarSignals {
        kep_yaml_sidecar: flags & 0b001 != 0,
        adr_dir_marker: flags & 0b010 != 0,
        log4brains_marker: flags & 0b100 != 0,
    };

    // Split the remaining bytes into a short "path" slice and a "content"
    // slice, so both the filename-keyed gates and the body-scanning gates get
    // fuzzed inputs, not just one or the other.
    let rest = &data[1..];
    let split = rest.len().min(32);
    let (path_bytes, content_bytes) = rest.split_at(split);
    let path = String::from_utf8_lossy(path_bytes);
    let content = String::from_utf8_lossy(content_bytes);

    let _ = classify_governance_doc(&path, &content, &sidecars);
}

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    run(data);
});

// Plain `cargo build` (no `--cfg fuzzing`): a tiny stub `main` so the target
// compiles and links on stable without the libFuzzer runtime, and exercises the
// same code path once on an empty input.
#[cfg(not(fuzzing))]
fn main() {
    run(b"");
}
