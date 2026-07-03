//! Golden corpus for `classify_governance_doc` (Governance Intake, Component A).
//!
//! Layout mirrors the transcript golden corpus (`golden.rs`), swapping the
//! `.jsonl` transcript extension for `.md`:
//! ```text
//! fixtures/governance_doc/v1/<case>.md                    # input document
//! fixtures-expected/governance_doc/v1/<case>.expected.json # expected classification
//! ```
//!
//! Each case covers one of: the four in-v1-scope formats (Nygard/adr-tools,
//! MADR 2.x/3.x/4.x, log4brains, DECISIONS.md) crossed with status values, the
//! named traps (the adr-tools "Superceded" misspelling, multi-line `## Status`
//! accretion, MADR absent-status-implies-accepted, the H1-suffix status shape,
//! the bold-bullet status shape), or one of the anti-lookalike rejection
//! classes (template, generated index/TOC, numbered tutorial, Jekyll blog post,
//! README, CONTRIBUTING, CHANGELOG, issue template, KEP-without-sidecar,
//! status-less-with-no-fingerprint).
//!
//! An expected file with `"not_governance": true` asserts
//! `classify_governance_doc` returns `None` for that case; otherwise it names
//! the expected `(doc_class, doc_state, governance_effective, parse_quality)`
//! tuple. Fixtures whose case name starts with `log4brains_` are classified
//! with the log4brains sidecar signal set, matching how the (out-of-band)
//! `adr_mine` capture pass would have detected the sidecar on disk before
//! calling the pure oracle.

use memscribe_core::governance_doc::{
    classify_governance_doc, DocClass, ParseQuality, SidecarSignals,
};
use memscribe_testkit::golden::{discover_cases_with_ext, fixtures_dir, GoldenCase};
use serde::Deserialize;

/// The expected-output shape for one golden case. `not_governance: true` means
/// `classify_governance_doc` must return `None`; otherwise the four fields are
/// asserted against `Some(GovernanceDoc)`.
#[derive(Debug, Deserialize)]
struct Expected {
    #[serde(default)]
    not_governance: bool,
    #[serde(default)]
    doc_class: Option<String>,
    #[serde(default)]
    doc_state: Option<String>,
    #[serde(default)]
    governance_effective: Option<bool>,
    #[serde(default)]
    parse_quality: Option<String>,
}

fn doc_class_slug(c: DocClass) -> &'static str {
    match c {
        DocClass::DecisionRecord => "decision_record",
        DocClass::ProposalInFlight => "proposal_in_flight",
        DocClass::StandingRule => "standing_rule",
        DocClass::Procedure => "procedure",
    }
}

fn parse_quality_slug(q: ParseQuality) -> &'static str {
    match q {
        ParseQuality::FullParse => "full_parse",
        ParseQuality::RecallOnly => "recall_only",
    }
}

/// Fixture cases whose sidecar-marker behavior the (out-of-band) `adr_mine`
/// capture pass would have supplied. The pure oracle takes this as a plain
/// parameter (see `SidecarSignals`), so the golden test reconstructs it from
/// the case name rather than doing any filesystem probing of its own.
fn sidecars_for_case(case: &GoldenCase) -> SidecarSignals {
    SidecarSignals {
        kep_yaml_sidecar: false,
        adr_dir_marker: false,
        log4brains_marker: case.case.starts_with("log4brains_"),
    }
}

#[test]
fn governance_doc_golden_corpus() {
    let cases = discover_cases_with_ext("md");
    let governance_cases: Vec<_> = cases
        .into_iter()
        .filter(|c| c.tool == "governance_doc")
        .collect();

    assert!(
        !governance_cases.is_empty(),
        "no governance_doc fixtures discovered under {}",
        fixtures_dir().display()
    );

    let mut checked = 0;
    for case in &governance_cases {
        let input_path = case.input_path_ext("md");
        let content = std::fs::read_to_string(&input_path)
            .unwrap_or_else(|e| panic!("read fixture {}: {e}", input_path.display()));

        let expected_path = case.expected_path_suffix("expected.json");
        let expected_raw = std::fs::read_to_string(&expected_path)
            .unwrap_or_else(|e| panic!("read expected {}: {e}", expected_path.display()));
        let expected: Expected = serde_json::from_str(&expected_raw)
            .unwrap_or_else(|e| panic!("parse expected {}: {e}", expected_path.display()));

        // The fixture's own relative filename stands in for the repo path the
        // real `adr_mine` pass would pass — case names encode the directory
        // conventions the classifier's filename/lookalike gates key on
        // (e.g. `lookalike_readme` -> a path ending in `readme.md`).
        let path = fixture_relative_path(&case.case);
        let sidecars = sidecars_for_case(case);

        let actual = classify_governance_doc(&path, &content, &sidecars);

        if expected.not_governance {
            assert!(
                actual.is_none(),
                "case {:?}: expected NOT governance, got {:?}",
                case.case,
                actual
            );
        } else {
            let doc = actual
                .unwrap_or_else(|| panic!("case {:?}: expected governance, got None", case.case));
            if let Some(want) = &expected.doc_class {
                assert_eq!(
                    doc_class_slug(doc.doc_class),
                    want,
                    "case {:?}: doc_class mismatch",
                    case.case
                );
            }
            if let Some(want) = &expected.doc_state {
                assert_eq!(
                    &doc.doc_state, want,
                    "case {:?}: doc_state mismatch",
                    case.case
                );
            }
            if let Some(want) = expected.governance_effective {
                assert_eq!(
                    doc.governance_effective, want,
                    "case {:?}: governance_effective mismatch",
                    case.case
                );
            }
            if let Some(want) = &expected.parse_quality {
                assert_eq!(
                    parse_quality_slug(doc.parse_quality),
                    want,
                    "case {:?}: parse_quality mismatch",
                    case.case
                );
            }
        }
        checked += 1;
    }

    assert_eq!(
        checked,
        governance_cases.len(),
        "every discovered governance_doc fixture must be checked"
    );
}

/// Map a case name to a plausible repo-relative path so the classifier's
/// filename-keyed gates (README/CONTRIBUTING/CHANGELOG/numbered-tutorial/
/// template) see the same signal a real sweep would provide.
fn fixture_relative_path(case: &str) -> String {
    match case {
        "lookalike_readme" => "README.md".to_string(),
        "lookalike_contributing" => "CONTRIBUTING.md".to_string(),
        "lookalike_changelog" => "CHANGELOG.md".to_string(),
        "lookalike_generated_index" => "doc/adr/index.md".to_string(),
        "lookalike_adr_template" => "doc/adr/0000-template.md".to_string(),
        "lookalike_numbered_tutorial" => "docs/0001-getting-started.md".to_string(),
        "lookalike_jekyll_blog_post" => "_posts/2024-05-01-our-new-architecture.md".to_string(),
        "lookalike_issue_template" => ".github/ISSUE_TEMPLATE/bug_report.md".to_string(),
        "lookalike_kep_readme_no_sidecar" => "keps/sig-node/2400-node-swap/README.md".to_string(),
        _ => format!("doc/adr/{case}.md"),
    }
}
