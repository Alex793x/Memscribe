//! Property tests (`proptest`) for `classify_governance_doc` (Governance
//! Intake, Component A), proving the same two guarantees `gitcommit`'s
//! `classify_commit` and the pipeline carry (see `pipeline_properties.rs`):
//!
//! - **Totality** — never panics on arbitrary strings, including byte
//!   sequences that are not valid UTF-8 (lossily converted, the way a real
//!   file read would be handled upstream).
//! - **Determinism** — the same `(path, content, sidecars)` input always
//!   produces a byte-identical (via `Debug`, since `GovernanceDoc` has no
//!   serde impl) result on repeated calls.

use memscribe_core::governance_doc::{classify_governance_doc, SidecarSignals};
use proptest::prelude::*;

/// A mix of fully-arbitrary unicode text and structured governance-doc-shaped
/// fragments (headings, front matter, bullet status lines, table rows), so the
/// properties are exercised on both noise and near-miss realistic shapes that
/// stress the gates rather than only ever hitting the early template/lookalike
/// rejects.
fn arbitrary_content() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        ".{0,300}",
        proptest::collection::vec(
            prop_oneof![
                Just("# 9. Use Postgres for the orders service".to_string()),
                Just("## Status".to_string()),
                Just("Accepted".to_string()),
                Just("Superceded by [5. New](0005-new.md)".to_string()),
                Just("* Status: Accepted".to_string()),
                Just("- Status: draft".to_string()),
                Just("---".to_string()),
                Just("status: accepted".to_string()),
                Just("status: \"{proposed | rejected | accepted}\"".to_string()),
                Just("## Context and Problem Statement".to_string()),
                Just("Chosen option: \"X\", because Y.".to_string()),
                Just("| Date | Decision | Status | Rationale |".to_string()),
                Just("|------|----------|--------|-----------|".to_string()),
                Just("| 2024-01-01 | Use Postgres | Accepted | Familiarity |".to_string()),
                Just("TBD".to_string()),
                Just("fill me in".to_string()),
                "[a-zA-Z0-9 ,.:`/_?!#*|=-]{0,64}".prop_map(|s| s),
            ],
            0..12
        )
        .prop_map(|lines| lines.join("\n")),
    ]
}

/// Plausible file paths, including well-known lookalike filenames and
/// ADR-shaped numeric-prefixed names, so the filename-keyed gates are
/// exercised as part of the property, not just the body-scanning gates.
fn arbitrary_path() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("README.md".to_string()),
        Just("CONTRIBUTING.md".to_string()),
        Just("CHANGELOG.md".to_string()),
        Just("doc/adr/0001-title.md".to_string()),
        Just("doc/adr/0000-template.md".to_string()),
        Just("docs/decisions/0004-title.md".to_string()),
        Just(".github/ISSUE_TEMPLATE/bug_report.md".to_string()),
        "[a-zA-Z0-9/_.-]{0,40}".prop_map(|s| s),
    ]
}

fn arbitrary_sidecars() -> impl Strategy<Value = SidecarSignals> {
    (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
        |(kep_yaml_sidecar, adr_dir_marker, log4brains_marker)| SidecarSignals {
            kep_yaml_sidecar,
            adr_dir_marker,
            log4brains_marker,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Totality: `classify_governance_doc` never panics on arbitrary
    /// (path, content, sidecars) triples.
    #[test]
    fn classify_governance_doc_never_panics(
        path in arbitrary_path(),
        content in arbitrary_content(),
        sidecars in arbitrary_sidecars(),
    ) {
        let _ = classify_governance_doc(&path, &content, &sidecars);
    }

    /// Totality on raw bytes: content that is not valid UTF-8, lossily
    /// converted the way a real file-read boundary would hand it to the
    /// classifier, must never panic either.
    #[test]
    fn classify_governance_doc_never_panics_on_lossy_utf8(
        path in arbitrary_path(),
        raw_bytes in proptest::collection::vec(any::<u8>(), 0..200),
        sidecars in arbitrary_sidecars(),
    ) {
        let content = String::from_utf8_lossy(&raw_bytes).to_string();
        let _ = classify_governance_doc(&path, &content, &sidecars);
    }

    /// Determinism: the same input classified twice yields an identical
    /// result (compared via `Debug`, since `GovernanceDoc` intentionally has
    /// no serde impl — it is an in-process contract for downstream Rust
    /// components, not a wire format).
    #[test]
    fn classify_governance_doc_is_deterministic(
        path in arbitrary_path(),
        content in arbitrary_content(),
        sidecars in arbitrary_sidecars(),
    ) {
        let a = classify_governance_doc(&path, &content, &sidecars);
        let b = classify_governance_doc(&path, &content, &sidecars);
        prop_assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    /// Determinism holds under the lossy-UTF8 boundary too.
    #[test]
    fn classify_governance_doc_is_deterministic_on_lossy_utf8(
        path in arbitrary_path(),
        raw_bytes in proptest::collection::vec(any::<u8>(), 0..200),
        sidecars in arbitrary_sidecars(),
    ) {
        let content = String::from_utf8_lossy(&raw_bytes).to_string();
        let a = classify_governance_doc(&path, &content, &sidecars);
        let b = classify_governance_doc(&path, &content, &sidecars);
        prop_assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    /// A conservative invariant the whole design hinges on (V1 contract §2):
    /// `governance_effective` is never true unless `doc_state == "accepted"`.
    #[test]
    fn governance_effective_implies_accepted_state(
        path in arbitrary_path(),
        content in arbitrary_content(),
        sidecars in arbitrary_sidecars(),
    ) {
        if let Some(doc) = classify_governance_doc(&path, &content, &sidecars) {
            if doc.governance_effective {
                prop_assert_eq!(doc.doc_state.as_str(), "accepted");
            }
        }
    }
}
