//! The governance-doc classification oracle (Governance Intake, Component A).
//!
//! A repo's markdown often carries decisions (ADRs), proposals (RFCs/PEPs/KEPs),
//! standing rules (CONTRIBUTING/CLAUDE.md/style guides), and procedures
//! (runbooks) — none of which git-mine or transcript-mine ever sees, because
//! `CommitInput` has no blob field and conversation capture never reads
//! arbitrary files. This module is the doc-side analog of [`crate::gitcommit`]:
//! a total, pure, never-panics classifier over `(path, content)`, spec'd by the
//! researched detection catalog (`governance-intake-catalog.md`) and narrowed to
//! a v1 scope by `governance-intake-design.md`'s V1 contract (§8a):
//!
//! - Formats: Nygard-style ADRs (adr-tools), MADR 2.x (bold-bullet status), MADR
//!   3.x/4.x (YAML front matter, absent-status-implies-accepted), log4brains
//!   (sidecar-marked), and DECISIONS.md (table-row-is-the-record).
//! - Everything else in the 39-format catalog is out of v1 scope; an
//!   unrecognized-but-plausible doc lands in [`ParseQuality::RecallOnly`] rather
//!   than being invented a status, or is rejected outright as not-governance.
//!
//! Decision order (mirrors the design doc): template/placeholder gate → sidecar
//! check → metadata-position scan (front matter, bold/plain bullet list, `##
//! Status` section, H1 suffix) → vocab + section-heading fingerprint → doc-class
//! assignment → anti-lookalike gates.
//!
//! `doc_state` and `governance_effective` are deliberately two different fields
//! (V1 contract §2): `doc_state` is the canonicalized-but-honest verbatim
//! status (recall/display); `governance_effective` is a conservative derivation
//! that ONLY `accepted` (or MADR's implicit accepted-when-absent) ever sets true
//! — `implemented`/`published`/`stage 3`/`final` are NOT authority-equivalent to
//! `accepted` in this scope. This function never mints edges; it only classifies.

use regex::Regex;
use std::sync::OnceLock;

/// Sidecar/filesystem signals the caller observed for the file being
/// classified. The classifier itself does no I/O (it stays pure and
/// unit-testable exactly like [`crate::gitcommit::classify_commit`]); the
/// caller (the `adr_mine` capture pass) is responsible for checking for these
/// on disk and passing the result in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SidecarSignals {
    /// A sibling `kep.yaml` exists next to this file (Kubernetes KEP positive
    /// signal — out of v1 format scope, but recognizing the sidecar lets the
    /// classifier route a KEP `README.md` to recall-only instead of silently
    /// misreading it as a plain doc via ADR heuristics).
    pub kep_yaml_sidecar: bool,
    /// An `.adr-dir` file at the repo root names this file's directory as the
    /// ADR directory (adr-tools convention). Location-as-confidence-hint only.
    pub adr_dir_marker: bool,
    /// A `.log4brains.yml` config names this file's directory as an ADR
    /// folder — the positive discriminator for the log4brains format.
    pub log4brains_marker: bool,
}

/// The four doc-classes from the design doc's taxonomy (§1b). v1 format
/// coverage (Nygard/adr-tools/MADR/log4brains/DECISIONS.md) is entirely within
/// `DecisionRecord`; the other three variants are defined now so downstream
/// components (and later v2 format coverage) have a stable target, but v1
/// itself never chooses them for accepted parses — see `parse_quality` for how
/// out-of-scope-but-plausible docs are still surfaced without inventing a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocClass {
    /// A record of a decision already made: ADRs, MADR, log4brains,
    /// DECISIONS.md, AWS/Azure ADRs, arc42 §9, Y-statements.
    DecisionRecord,
    /// A proposal that is not yet a decision until terminal-accept: Rust RFC,
    /// PEP, JEP, KEP, RFD, company RFCs. Out of v1 format scope.
    ProposalInFlight,
    /// A standing rule, in force while present, no status vocabulary:
    /// CONTRIBUTING, style guides, CLAUDE.md/AGENTS.md/.cursor/rules. Out of
    /// v1 format scope.
    StandingRule,
    /// A runbook/playbook; only embedded invariants govern, never step lists.
    /// Out of v1 format scope.
    Procedure,
}

/// The three-way degradation ladder (design doc: "full parse → recall-only
/// node → skip"). `classify_governance_doc` returning `None` IS the skip rung;
/// this enum distinguishes the other two so a caller building a recall-only
/// node knows to render it that way (e.g. status-mangled-but-in-a-conventional-
/// ADR-directory, or a format the v1 parser recognizes as governance-shaped but
/// cannot fully fingerprint).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseQuality {
    /// Every metadata position resolved cleanly: status, section fingerprint,
    /// and (for formats that have one) identity all matched a known shape.
    FullParse,
    /// Governance-shaped (title + at least one section-fingerprint hit, or a
    /// location/sidecar hint) but the status could not be resolved with
    /// confidence. Never invents a status — `doc_state` is `"unknown"` and
    /// `governance_effective` is always `false` at this quality.
    RecallOnly,
}

/// The deterministic classification of a markdown file as a governance
/// document, or `None` when it is not governance at all (the design doc's
/// "skip" rung of the degradation ladder).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceDoc {
    /// Which of the four doc-classes this document is.
    pub doc_class: DocClass,
    /// The canonicalized-but-honest verbatim status: case/whitespace
    /// normalized, the adr-tools "Superceded" misspelling folded to
    /// "superseded", but never invented. `"unknown"` at
    /// [`ParseQuality::RecallOnly`].
    pub doc_state: String,
    /// Conservative, separate from `doc_state` (V1 contract §2): true only for
    /// `accepted` (verbatim or MADR-implicit-when-absent). Always `false` at
    /// `ParseQuality::RecallOnly` and false for every other status, including
    /// process near-synonyms like "implemented"/"published"/"final".
    pub governance_effective: bool,
    /// How complete the parse is — the recall-only-vs-full-parse rung of the
    /// degradation ladder. (The "skip" rung is `classify_governance_doc`
    /// returning `None`.)
    pub parse_quality: ParseQuality,
    /// The document's title/epitome — the H1, or (DECISIONS.md) the row's
    /// decision text, verbatim and whitespace-collapsed.
    pub title: String,
    /// The raw ADR number/slug, when the format has one (adr-tools/MADR/
    /// log4brains filename or H1 prefix). Plain string, no cross-repo identity
    /// scheme attached here — that is a separate component's job.
    pub doc_id: Option<String>,
    /// V1 contract, explicit-only (design doc "Anchoring" section, last
    /// bullet): `true` only when the front matter carries an explicit
    /// `ban:`/`policy:` key with a non-falsy value. NEVER inferred from
    /// prose/polarity — this is the sole place v1 sets a ban true. Always
    /// `false` when no front matter is present or the doc is not a
    /// `DecisionRecord`.
    pub ban: bool,
    /// Tier 0 author-declared scope selectors (design doc "How a scope gets
    /// attached", Tier 0): the raw `governs: [...]` front-matter list,
    /// verbatim, unparsed/unvalidated (Component F's `scope_parse` resolves
    /// these against the closed selector vocabulary). Empty when absent.
    pub governs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Template / placeholder gate
// ---------------------------------------------------------------------------

/// Filename/path fragments that mark a file as a template, never a real record.
const TEMPLATE_PATH_MARKERS: &[&str] = &["template", "kep-template", "swift-template"];

/// Literal placeholder PHRASES (safe as substring matches — multi-word, so
/// they cannot collide with an unrelated word that merely contains one as a
/// fragment).
const PLACEHOLDER_PHRASES: &[&str] = &[
    "fill me in",
    "fill this in",
    "leave this empty",
    "0000-my-feature",
];

/// Literal placeholder WORD tokens that must match as a whole word — "tbd" as
/// a naive substring would also fire on an unrelated word like "TBD-free" or
/// "tbdomain"; matched via `is_whole_word_match` instead.
const PLACEHOLDER_WORDS: &[&str] = &["tbd"];

/// Whether `path` or `content` mark the file as a template/placeholder rather
/// than a real record. Checked first, per the design doc's decision order.
fn is_template_or_placeholder(path: &str, content: &str) -> bool {
    let path_lc = path.to_ascii_lowercase();
    if TEMPLATE_PATH_MARKERS.iter().any(|m| path_lc.contains(m)) {
        return true;
    }
    // A bare numeric-placeholder id: "0000-" prefix on the filename.
    if let Some(name) = path_lc.rsplit('/').next() {
        if name.starts_with("0000-") || name == "0000.md" {
            return true;
        }
    }
    let content_lc = content.to_ascii_lowercase();
    if PLACEHOLDER_PHRASES.iter().any(|t| content_lc.contains(t)) {
        return true;
    }
    if PLACEHOLDER_WORDS
        .iter()
        .any(|w| is_whole_word_match(&content_lc, w))
    {
        return true;
    }
    // The literal pipe-separated status-options-as-text a template ships
    // verbatim, e.g. "{proposed | rejected | accepted | deprecated | ...}" or
    // "[draft | proposed | rejected | accepted | ...]".
    if has_pipe_separated_status_literal(content) {
        return true;
    }
    // Curly/square/angle placeholder braces around a short token, a strong
    // template signal in a status-bearing line.
    if content.contains("{status}") || content.contains("<status>") || content.contains("[status]")
    {
        return true;
    }
    false
}

/// Whether `word` occurs in `haystack_lc` as a whole word — i.e. not
/// immediately preceded/followed by an alphanumeric character. Both inputs are
/// plain ASCII-lowercase text (callers already lowercase); avoids a naive
/// `contains` false-positive like "tbd" matching inside "TBD-free" or
/// "tbdomain".
fn is_whole_word_match(haystack_lc: &str, word: &str) -> bool {
    let bytes = haystack_lc.as_bytes();
    let wlen = word.len();
    if wlen == 0 {
        return false;
    }
    let mut start = 0;
    while let Some(rel) = haystack_lc[start..].find(word) {
        let idx = start + rel;
        let before_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
        let after_idx = idx + wlen;
        let after_ok = after_idx >= bytes.len() || !bytes[after_idx].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = idx + 1;
        if start >= haystack_lc.len() {
            break;
        }
    }
    false
}

fn pipe_status_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)[\{\[]\s*(?:draft|proposed)\s*\|\s*\w[\w -]*\s*\|\s*\w[\w -]*")
            .expect("pipe-status pattern must compile")
    })
}

fn has_pipe_separated_status_literal(content: &str) -> bool {
    pipe_status_re().is_match(content)
}

// ---------------------------------------------------------------------------
// Status vocabulary → canonical mapping
// ---------------------------------------------------------------------------

/// Canonicalize a raw status token/phrase to the closed vocabulary the design
/// doc specifies: `proposed`, `accepted`, `rejected`, `deprecated`,
/// `superseded`, `amended`. Returns `None` when the token does not resolve to
/// any decision-vocab member (the vocab-domain gate: publishing/work/incident
/// vocab never maps here).
///
/// Case-insensitive; strips trailing markdown links/parens/version
/// annotations first (e.g. "Implemented (Swift 5.0)" → "implemented",
/// "superseded by [xxx](yyyymmdd-xxx.md)" → "superseded by").
#[must_use]
fn canonicalize_status(raw: &str) -> Option<&'static str> {
    let cleaned = strip_trailing_annotation(raw);
    let lc_owned = cleaned.trim().to_ascii_lowercase();
    let lc: &str = lc_owned.trim_matches(|c: char| c == '*' || c == '`' || c.is_whitespace());

    // Supersession: check first because "superseded by X" / the historic
    // "superceded" misspelling both carry a relation but canonicalize to the
    // same status. adr-tools generated "Superceded by [...]" for years before
    // PR #111 fixed the tool; both spellings must parse identically.
    if lc.starts_with("superseded") || lc.starts_with("superceded") || lc.starts_with("replaced") {
        return Some("superseded");
    }
    if lc.starts_with("amended") {
        return Some("amended");
    }

    match lc {
        "proposed"
        | "draft"
        | "predraft"
        | "prediscussion"
        | "ideation"
        | "discussion"
        | "in review"
        | "open for comments"
        | "awaiting review"
        | "scheduled for review"
        | "active review"
        | "submitted"
        | "candidate"
        | "exploring"
        | "provisional"
        | "proposed to target"
        | "proposed to drop"
        | "returned for revision" => Some("proposed"),
        "accepted"
        | "approved"
        | "agreed"
        | "decided"
        | "active"
        | "final"
        | "accepted with revisions"
        | "accepted with reservations"
        | "previewing"
        | "implemented"
        | "done"
        | "complete"
        | "targeted"
        | "integrated"
        | "closed / delivered"
        | "published"
        | "committed"
        | "publish"
        | "implementable"
        | "ready-for-release"
        | "released"
        | "recommended" => Some("accepted"),
        "rejected" | "withdrawn" | "abandoned" | "closed" | "closed / rejected"
        | "closed / withdrawn" => Some("rejected"),
        "deprecated" | "obsolete" | "historic" | "discontinued" => Some("deprecated"),
        _ => None,
    }
}

/// Strip a trailing markdown link/reference, parenthetical version note, or
/// bracket after the leading status word — e.g. "Implemented (Swift 5.0)",
/// "superseded by [xxx](yyyymmdd-xxx.md)" keeps its lead word for the
/// startswith checks above but this trims pure decoration for exact matches.
fn strip_trailing_annotation(raw: &str) -> String {
    let mut s = raw.trim();
    // Drop a trailing "(...)" annotation.
    if let Some(idx) = s.find(" (") {
        if s.ends_with(')') {
            s = &s[..idx];
        }
    }
    s.trim().to_string()
}

// ---------------------------------------------------------------------------
// Section / metadata-position scanning
// ---------------------------------------------------------------------------

/// The result of scanning a document body for a status value, before
/// canonicalization: the raw text plus which metadata position produced it (so
/// the doc-class fingerprint below can use position as a signal too).
struct StatusHit {
    raw: String,
}

/// P1: YAML front matter (`---` fenced at byte 0). Returns the `status:` value
/// when present. Absence is meaningful for MADR 3.x/4.x (implicit accepted) —
/// callers distinguish "front matter present, no status key" from "no front
/// matter at all" via `front_matter_present`.
struct FrontMatter {
    present: bool,
    status: Option<String>,
    /// True when the ONLY keys present are scope/publishing keys that never
    /// carry decision status (used by the standing-rule / lookalike gates).
    only_scope_or_publishing_keys: bool,
    has_publishing_keys: bool,
    has_issue_template_keys: bool,
    /// V1 contract explicit-only ban/policy field (design doc "Anchoring"
    /// section: "Ban/Contract minting is explicit-only in v1: front-matter
    /// `ban:`/`policy:` field"). `true` when the raw value is YAML-ish
    /// truthy (`true`/`yes`/`1`) OR the key is present with any non-empty,
    /// non-falsy value (a `policy: "no committing secrets"` style string
    /// value is ALSO a ban assertion — only explicit `false`/`no`/`0`/empty
    /// opts out). Never inferred from prose — this is the one place v1 ever
    /// sets a ban true, per the design doc's explicit-only mandate.
    ban: bool,
    /// The raw `governs: [...]` selector strings, in file order, when
    /// present (Tier 0 anchoring — design doc "How a scope gets attached").
    /// Supports both a flow-style list (`governs: [a, b]`) and a block-style
    /// YAML list (`governs:` followed by indented `- a` / `- b` lines).
    governs: Vec<String>,
}

fn empty_front_matter(present: bool) -> FrontMatter {
    FrontMatter {
        present,
        status: None,
        only_scope_or_publishing_keys: false,
        has_publishing_keys: false,
        has_issue_template_keys: false,
        ban: false,
        governs: Vec::new(),
    }
}

/// Whether a raw front-matter scalar value reads as YAML-truthy
/// (`true`/`yes`/`on`/`1`, case-insensitive) — used only for the explicit
/// `ban:` boolean gate.
fn is_yaml_truthy(val: &str) -> bool {
    matches!(
        val.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

/// Whether a raw front-matter scalar value reads as YAML-falsy
/// (`false`/`no`/`off`/`0`, case-insensitive, or empty).
fn is_yaml_falsy(val: &str) -> bool {
    let lc = val.trim().to_ascii_lowercase();
    lc.is_empty() || matches!(lc.as_str(), "false" | "no" | "off" | "0")
}

/// Parse a flow-style YAML list value (`[a, b, "c"]`) into its element
/// strings. Returns `None` if `val` is not bracket-delimited (the caller then
/// tries the block-style list form instead). Total: malformed brackets/empty
/// list yield `Some(vec![])` rather than panicking or erroring.
fn parse_flow_list(val: &str) -> Option<Vec<String>> {
    let t = val.trim();
    let inner = t.strip_prefix('[')?.strip_suffix(']')?;
    Some(
        inner
            .split(',')
            .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

fn parse_front_matter(content: &str) -> FrontMatter {
    let trimmed = content.trim_start_matches(['\u{feff}']);
    if !trimmed.starts_with("---") {
        return empty_front_matter(false);
    }
    let lines: Vec<&str> = trimmed.lines().collect();
    let mut status = None;
    let mut keys: Vec<String> = Vec::new();
    let mut closed = false;
    let mut ban = false;
    let mut governs: Vec<String> = Vec::new();
    let mut i = 1; // skip the opening '---'
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim_end();
        if t.trim() == "---" || t.trim() == "..." {
            closed = true;
            break;
        }
        if let Some(colon) = t.find(':') {
            // Only a top-level (non-indented) key participates in the key set /
            // status extraction — nested list items indent past column 0.
            if t.starts_with(|c: char| c.is_whitespace()) {
                i += 1;
                continue;
            }
            let key = t[..colon].trim().to_ascii_lowercase();
            let val = t[colon + 1..].trim().trim_matches('"').trim_matches('\'');
            if !key.is_empty() {
                keys.push(key.clone());
            }
            if key == "status" && !val.is_empty() {
                status = Some(val.to_string());
            }
            if key == "ban" || key == "policy" {
                // Explicit-only (V1 contract): a present key with a
                // non-falsy value is a ban assertion, whether it is the
                // literal boolean `true` or a free-text policy string.
                ban = ban || !is_yaml_falsy(val) || is_yaml_truthy(val);
            }
            if key == "governs" {
                if let Some(flow) = parse_flow_list(val) {
                    governs = flow;
                } else if val.is_empty() {
                    // Block-style list: collect indented `- item` lines
                    // immediately following this key.
                    let mut j = i + 1;
                    while j < lines.len() {
                        let item_line = lines[j];
                        if !item_line.starts_with(|c: char| c.is_whitespace()) {
                            break;
                        }
                        let item_t = item_line.trim();
                        if let Some(rest) = item_t.strip_prefix("- ") {
                            let cleaned = rest.trim().trim_matches('"').trim_matches('\'');
                            if !cleaned.is_empty() {
                                governs.push(cleaned.to_string());
                            }
                            j += 1;
                        } else if item_t == "-" {
                            j += 1;
                        } else {
                            break;
                        }
                    }
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    if !closed {
        // Unterminated fence: not real front matter (a stray "---" divider).
        return empty_front_matter(false);
    }
    const SCOPE_KEYS: &[&str] = &[
        "paths",
        "globs",
        "applyto",
        "trigger",
        "alwaysapply",
        "description",
        "governs",
    ];
    const PUBLISHING_KEYS: &[&str] = &[
        "layout",
        "permalink",
        "slug",
        "sidebar_position",
        "categories",
        "author",
    ];
    const ISSUE_TEMPLATE_KEYS: &[&str] = &["about", "labels", "assignees"];
    let has_publishing_keys = keys.iter().any(|k| PUBLISHING_KEYS.contains(&k.as_str()));
    let has_issue_template_keys = keys
        .iter()
        .any(|k| ISSUE_TEMPLATE_KEYS.contains(&k.as_str()));
    let only_scope_or_publishing_keys = !keys.is_empty()
        && keys
            .iter()
            .all(|k| SCOPE_KEYS.contains(&k.as_str()) || PUBLISHING_KEYS.contains(&k.as_str()));
    FrontMatter {
        present: true,
        status,
        only_scope_or_publishing_keys,
        has_publishing_keys,
        has_issue_template_keys,
        ban,
        governs,
    }
}

/// P2: a bold or plain bullet list item `* Status: value` / `- Status: value`
/// / `**Status:** value` between the H1 and the first `##` heading.
fn find_bullet_status(content: &str) -> Option<StatusHit> {
    let body_before_h2 = body_before_first_h2(content);
    for raw in body_before_h2.lines() {
        let line = raw.trim();
        let stripped = line
            .trim_start_matches(['*', '-'])
            .trim_start_matches(['*'])
            .trim();
        let lc = stripped.to_ascii_lowercase();
        if let Some(rest) = lc
            .strip_prefix("status:")
            .or_else(|| lc.strip_prefix("**status:**"))
            .or_else(|| lc.strip_prefix("status**:"))
        {
            // Re-slice the ORIGINAL (not lowercased) string for the same byte
            // length so case is preserved for canonicalization.
            let start = stripped.len() - rest.len();
            let value = stripped[start..]
                .trim()
                .trim_matches('*')
                .trim_matches('`')
                .trim();
            if !value.is_empty() {
                return Some(StatusHit {
                    raw: value.to_string(),
                });
            }
        }
    }
    None
}

/// Slice the document from just after the H1 line up to (excluding) the first
/// `##` heading — this is where P2 bullet metadata and Rust/React/Swift-style
/// plain bullet lists live.
fn body_before_first_h2(content: &str) -> String {
    let mut seen_h1 = false;
    let mut out_lines: Vec<&str> = Vec::new();
    for line in content.lines() {
        if !seen_h1 {
            if line.trim_start().starts_with('#') {
                seen_h1 = true;
            }
            continue;
        }
        let t = line.trim_start();
        if t.starts_with("## ") || t == "##" {
            break;
        }
        out_lines.push(line);
    }
    out_lines.join("\n")
}

/// P3: a `## Status` section body. Nygard/adr-tools/AWS/MS-playbook accrete
/// multiple lines under this heading over the doc's lifetime (edit history of
/// "adr link" commands appending relation lines) — the LAST non-empty line is
/// the effective status, per the design doc's explicit trap.
fn find_status_section(content: &str) -> Option<StatusHit> {
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let heading = lines[i].trim();
        if heading.eq_ignore_ascii_case("## status") || heading.eq_ignore_ascii_case("# status") {
            let mut last_nonempty: Option<String> = None;
            let mut j = i + 1;
            while j < lines.len() {
                let l = lines[j];
                if l.trim_start().starts_with('#') {
                    break;
                }
                let t = l.trim();
                if !t.is_empty() {
                    last_nonempty = Some(t.to_string());
                }
                j += 1;
            }
            return last_nonempty.map(|raw| StatusHit { raw });
        }
        i += 1;
    }
    None
}

/// P4: an H1 suffix status, e.g. `# 857. Capability system [Proposed]` or
/// `# ADR-012: Title [Accepted]`. Fallback position — only consulted when no
/// stronger position produced a hit.
fn find_h1_suffix_status(content: &str) -> Option<StatusHit> {
    let h1 = find_h1(content)?;
    let re = h1_suffix_re();
    let caps = re.captures(&h1)?;
    Some(StatusHit {
        raw: caps.get(1)?.as_str().to_string(),
    })
}

fn h1_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\[\s*([A-Za-z][A-Za-z /-]*)\s*\]\s*$").expect("h1 suffix pattern must compile")
    })
}

/// P10: DECISIONS.md-style markdown table where the row IS the record. Finds
/// a `Status` column and returns each row's status cell alongside the row's
/// `Decision`-ish cell for the title/epitome. A genuinely different parsing
/// strategy from the other three (table structure, not headings/front matter).
struct TableRow {
    status_raw: Option<String>,
    epitome: String,
}

fn parse_decisions_table(content: &str) -> Option<Vec<TableRow>> {
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if line.starts_with('|') && line.ends_with('|') && line.matches('|').count() >= 3 {
            let header_cells = split_table_row(line);
            // The separator row ("|---|---|") must follow immediately.
            if i + 1 < lines.len() && is_table_separator(lines[i + 1]) {
                let status_col = header_cells
                    .iter()
                    .position(|c| c.trim().eq_ignore_ascii_case("status"));
                let decision_col = header_cells.iter().position(|c| {
                    let lc = c.trim().to_ascii_lowercase();
                    lc == "decision" || lc == "title" || lc == "summary"
                });
                let date_col = header_cells
                    .iter()
                    .position(|c| c.trim().eq_ignore_ascii_case("date"));
                let mut rows = Vec::new();
                let mut j = i + 2;
                while j < lines.len() {
                    let row_line = lines[j].trim();
                    if !row_line.starts_with('|') {
                        break;
                    }
                    let cells = split_table_row(row_line);
                    if cells.is_empty() {
                        break;
                    }
                    let epitome = decision_col
                        .and_then(|c| cells.get(c))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .or_else(|| {
                            date_col
                                .and_then(|c| cells.get(c))
                                .map(|s| s.trim().to_string())
                        })
                        .unwrap_or_default();
                    let status_raw = status_col
                        .and_then(|c| cells.get(c))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    if !epitome.is_empty() {
                        rows.push(TableRow {
                            status_raw,
                            epitome,
                        });
                    }
                    j += 1;
                }
                if !rows.is_empty() {
                    return Some(rows);
                }
            }
        }
        i += 1;
    }
    None
}

fn split_table_row(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    inner.split('|').map(|s| s.trim().to_string()).collect()
}

fn is_table_separator(line: &str) -> bool {
    let t = line.trim();
    t.starts_with('|')
        && t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ' | '\t'))
        && t.contains('-')
}

/// The first H1 heading (`# ...`), verbatim after the `# ` marker.
fn find_h1(content: &str) -> Option<String> {
    for line in content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("# ") {
            return Some(rest.trim().to_string());
        }
        if t == "#" {
            return Some(String::new());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Section-heading fingerprint (Nygard/MADR family detection)
// ---------------------------------------------------------------------------

/// Whether the body carries the Nygard/adr-tools family fingerprint:
/// `Context`, `Decision`, `Consequences` headings (any subset of 2+ is a solid
/// signal; all three is definitive).
fn has_nygard_fingerprint(content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    let hits = ["## context", "## decision", "## consequences"]
        .iter()
        .filter(|h| lc.contains(*h))
        .count();
    hits >= 2
}

/// Whether the body carries the MADR family fingerprint: "Context and Problem
/// Statement", "Considered Options", "Decision Outcome" / "Chosen option:".
fn has_madr_fingerprint(content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("context and problem statement")
        || lc.contains("considered options")
        || lc.contains("decision outcome")
        || lc.contains("chosen option:")
}

// ---------------------------------------------------------------------------
// Anti-lookalike gates
// ---------------------------------------------------------------------------

/// Well-known standing-rule / non-governance filenames that must never be
/// classified as a decision-record no matter what prose they contain (the
/// README/CONTRIBUTING/CHANGELOG/CODE_OF_CONDUCT lookalike gate).
const NEVER_DECISION_FILENAMES: &[&str] = &[
    "readme.md",
    "contributing.md",
    "changelog.md",
    "history.md",
    "releases.md",
    "code_of_conduct.md",
    "support.md",
    "security.md",
    "index.md",
];

fn file_name_lc(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase()
}

/// The index/TOC lookalike: body is only links/table-rows pointing at other
/// ADR files, with no Context/Decision sections of its own.
fn looks_like_index_or_toc(content: &str) -> bool {
    let non_blank: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if non_blank.is_empty() {
        return false;
    }
    let link_or_heading_lines = non_blank
        .iter()
        .filter(|l| {
            l.starts_with('#')
                || l.starts_with('-')
                || l.starts_with('*')
                || (l.starts_with('[') && l.contains("]("))
        })
        .count();
    // Every non-blank line is a heading/bullet/link, AND no Context/Decision
    // fingerprint — a real ADR always has prose paragraphs in its sections.
    link_or_heading_lines == non_blank.len()
        && !has_nygard_fingerprint(content)
        && !has_madr_fingerprint(content)
}

/// A numbered tutorial: filename numeric-prefixed like an ADR but no status
/// anywhere and no decision fingerprint — imperative how-to headings instead.
fn looks_like_numbered_tutorial(path: &str, content: &str) -> bool {
    let name = file_name_lc(path);
    let numeric_prefixed = name
        .split(['-', '_'])
        .next()
        .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if !numeric_prefixed {
        return false;
    }
    let has_any_status = find_bullet_status(content).is_some()
        || find_status_section(content).is_some()
        || parse_front_matter(content).status.is_some();
    !has_any_status && !has_nygard_fingerprint(content) && !has_madr_fingerprint(content)
}

/// Jekyll/Hugo/Docusaurus publishing front matter — `status: published`/
/// `draft: true` alongside layout/permalink/slug keys is a blog post, not a
/// decision, even though "published" superficially resembles accepted-ish
/// vocab.
fn looks_like_publishing_front_matter(content: &str) -> bool {
    let fm = parse_front_matter(content);
    fm.present && (fm.has_publishing_keys || fm.only_scope_or_publishing_keys)
}

/// GitHub issue/PR template front matter (name/about/labels/assignees).
fn looks_like_issue_template(content: &str) -> bool {
    parse_front_matter(content).has_issue_template_keys
}

// ---------------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------------

/// Classify a markdown-ish file as a governance document, or `None` when it is
/// not governance at all.
///
/// Pure: the result depends only on `(path, content, sidecars)`. Never panics
/// on any input, including non-UTF8-looking or empty content.
#[must_use]
pub fn classify_governance_doc(
    path: &str,
    content: &str,
    sidecars: &SidecarSignals,
) -> Option<GovernanceDoc> {
    // 1. Template/placeholder gate.
    if is_template_or_placeholder(path, content) {
        return None;
    }

    // 2. Sidecar check (kep.yaml / .adr-dir / .log4brains.yml), per the design
    //    doc's decision order (template gate → sidecar check → metadata-position
    //    scan → ... → anti-lookalike gates). This MUST run before the filename
    //    lookalike gates below: a kep.yaml sidecar is the positive signal that
    //    rescues an otherwise-generic `README.md` from the blanket
    //    README-is-never-a-decision gate ("never ingest KEP trees via ADR
    //    heuristics", but a README WITH its sidecar present is a real KEP).
    //    `.adr-dir`/`.log4brains.yml` are location-as-confidence hints for the
    //    Nygard/log4brains formats we DO parse, handled inline further down via
    //    the normal position scan (they raise a status-mangled file to
    //    recall-only instead of skip).
    if sidecars.kep_yaml_sidecar {
        return Some(GovernanceDoc {
            doc_class: DocClass::ProposalInFlight,
            doc_state: "unknown".to_string(),
            governance_effective: false,
            parse_quality: ParseQuality::RecallOnly,
            title: find_h1(content).unwrap_or_default(),
            doc_id: None,
            ban: false,
            governs: Vec::new(),
        });
    }

    // 3. Anti-lookalike gates that must run before the position scan, because
    //    their signals (filename, front-matter key set) would otherwise be
    //    mistaken for real metadata by the position scan below.
    let name = file_name_lc(path);
    if NEVER_DECISION_FILENAMES.contains(&name.as_str()) {
        return None;
    }
    if looks_like_publishing_front_matter(content) {
        return None;
    }
    if looks_like_issue_template(content) {
        return None;
    }
    if looks_like_index_or_toc(content) {
        return None;
    }
    if looks_like_numbered_tutorial(path, content) {
        return None;
    }

    // 4. DECISIONS.md table strategy — structurally different from the other
    //    three formats, checked ahead of the heading/front-matter scan because
    //    a table-shaped doc rarely also has a `## Status` section of its own.
    if let Some(rows) = parse_decisions_table(content) {
        return classify_decisions_table(&rows);
    }

    // 5. Metadata-position scan, in the design doc's stated order: front
    //    matter (P1) → bullet list (P2) → `## Status` section (P3) → H1
    //    suffix (P4, fallback only).
    let front_matter = parse_front_matter(content);
    let bullet_status = find_bullet_status(content);
    let section_status = find_status_section(content);
    let h1_suffix_status = find_h1_suffix_status(content);

    let has_yaml_front_matter_with_decision_shape =
        front_matter.present && !front_matter.only_scope_or_publishing_keys;

    // 6. Vocab + section-heading fingerprint decides Nygard-family vs
    //    MADR-family vs "no recognized fingerprint at all".
    let nygard_fp = has_nygard_fingerprint(content);
    let madr_fp = has_madr_fingerprint(content);

    if !nygard_fp && !madr_fp && !has_yaml_front_matter_with_decision_shape {
        // No section fingerprint AND no decision-shaped front matter: nothing
        // in the v1 format family recognizes this doc. Not governance.
        return None;
    }

    // Resolve the raw status hit, position-scan order, with the P3
    // last-non-empty-line trap already applied inside `find_status_section`.
    let raw_hit: Option<String> = front_matter
        .status
        .clone()
        .or_else(|| bullet_status.map(|h| h.raw))
        .or_else(|| section_status.map(|h| h.raw))
        .or_else(|| h1_suffix_status.map(|h| h.raw));

    let title = find_h1(content).unwrap_or_default();
    let doc_id = extract_doc_id(path, &title);

    // V1 contract, explicit-only: `ban:`/`policy:` and `governs:` are read
    // straight from front matter, never inferred from prose — carried
    // through on every DecisionRecord branch below regardless of parse
    // quality/status (an author can declare scope/ban on a doc this pass
    // only manages to recall-only-parse; the fields are still honest, just
    // not eligible to mint edges until `governance_effective` is also true —
    // that gate lives downstream in the reconciler, not here).
    let ban = front_matter.ban;
    let governs = front_matter.governs.clone();

    match raw_hit {
        Some(raw) => {
            if let Some(canon) = canonicalize_status(&raw) {
                let effective = canon == "accepted";
                Some(GovernanceDoc {
                    doc_class: DocClass::DecisionRecord,
                    doc_state: canon.to_string(),
                    governance_effective: effective,
                    parse_quality: ParseQuality::FullParse,
                    title,
                    doc_id,
                    ban,
                    governs,
                })
            } else {
                // A status-shaped value that isn't in our closed vocabulary
                // (e.g. an ad-hoc org-specific word). Never guess — recall
                // only, honestly labeled unknown.
                Some(GovernanceDoc {
                    doc_class: DocClass::DecisionRecord,
                    doc_state: "unknown".to_string(),
                    governance_effective: false,
                    parse_quality: ParseQuality::RecallOnly,
                    title,
                    doc_id,
                    ban,
                    governs,
                })
            }
        }
        None => {
            // No status found anywhere. MADR 3.x/4.x defines absent status as
            // implicit-accepted, but ONLY when the section fingerprint
            // actually matches MADR — never default a random status-less doc
            // (e.g. a plain fingerprint-free file that slipped past the gates
            // above) to accepted. A Nygard-fingerprint doc with no status
            // section is degraded to recall-only instead: Nygard's own spec
            // requires a `## Status` section, so its absence is a genuine
            // parse gap, not "in force by convention" like MADR 3/4.
            if madr_fp {
                Some(GovernanceDoc {
                    doc_class: DocClass::DecisionRecord,
                    doc_state: "accepted".to_string(),
                    governance_effective: true,
                    parse_quality: ParseQuality::FullParse,
                    title,
                    doc_id,
                    ban,
                    governs,
                })
            } else if nygard_fp || sidecars.adr_dir_marker || sidecars.log4brains_marker {
                Some(GovernanceDoc {
                    doc_class: DocClass::DecisionRecord,
                    doc_state: "unknown".to_string(),
                    governance_effective: false,
                    parse_quality: ParseQuality::RecallOnly,
                    title,
                    doc_id,
                    ban,
                    governs,
                })
            } else {
                None
            }
        }
    }
}

/// Classify a parsed DECISIONS.md-style table into the first row (v1 scope:
/// one file → one representative record; multi-row identity is a later
/// component's concern — see the "known gaps" note in the module docs). A
/// table with rows but no status column at all is recall-only (status column
/// frequently absent in the wild — presence-in-the-table implies in force,
/// but we do not invent "accepted" without at least an explicit column).
fn classify_decisions_table(rows: &[TableRow]) -> Option<GovernanceDoc> {
    let row = rows.first()?;
    let title = row.epitome.clone();
    match &row.status_raw {
        Some(raw) => match canonicalize_status(raw) {
            Some(canon) => Some(GovernanceDoc {
                doc_class: DocClass::DecisionRecord,
                doc_state: canon.to_string(),
                governance_effective: canon == "accepted",
                parse_quality: ParseQuality::FullParse,
                title,
                doc_id: None,
                ban: false,
                governs: Vec::new(),
            }),
            None => Some(GovernanceDoc {
                doc_class: DocClass::DecisionRecord,
                doc_state: "unknown".to_string(),
                governance_effective: false,
                parse_quality: ParseQuality::RecallOnly,
                title,
                doc_id: None,
                ban: false,
                governs: Vec::new(),
            }),
        },
        None => Some(GovernanceDoc {
            doc_class: DocClass::DecisionRecord,
            doc_state: "unknown".to_string(),
            governance_effective: false,
            parse_quality: ParseQuality::RecallOnly,
            title,
            doc_id: None,
            ban: false,
            governs: Vec::new(),
        }),
    }
}

/// The raw ADR number/slug from the filename (`0001-...`, `20240501-...`) or
/// the H1 prefix (`# 857. Title`, `# ADR-012: Title`), when present.
fn extract_doc_id(path: &str, title: &str) -> Option<String> {
    let name = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .trim_end_matches(".md");
    if let Some(hit) = doc_id_from_filename_re().captures(name) {
        return hit.get(1).map(|m| m.as_str().to_string());
    }
    if let Some(hit) = doc_id_from_title_re().captures(title) {
        return hit.get(1).map(|m| m.as_str().to_string());
    }
    None
}

fn doc_id_from_filename_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\d{4,8})-").expect("doc id filename pattern must compile"))
}

fn doc_id_from_title_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:adr-?)?(\d+)[.:]").expect("doc id title pattern must compile")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(path: &str, content: &str) -> Option<GovernanceDoc> {
        classify_governance_doc(path, content, &SidecarSignals::default())
    }

    // -- Nygard-style ADR (adr-tools) -----------------------------------

    #[test]
    fn nygard_accepted_is_full_parse_and_effective() {
        let content = "\
# 9. Use Postgres for the orders service

Date: 2024-01-05

## Status

Accepted

## Context

We need a relational store for the orders service.

## Decision

We will use Postgres.

## Consequences

Operational familiarity across the team.
";
        let d = classify("doc/adr/0009-use-postgres.md", content).unwrap();
        assert_eq!(d.doc_class, DocClass::DecisionRecord);
        assert_eq!(d.doc_state, "accepted");
        assert!(d.governance_effective);
        assert_eq!(d.parse_quality, ParseQuality::FullParse);
        assert_eq!(d.doc_id.as_deref(), Some("0009"));
    }

    /// NAMED TRAP: adr-tools' historical "Superceded" (sic) misspelling.
    #[test]
    fn adr_tools_superceded_misspelling_normalizes() {
        let content = "\
# 3. Old choice

## Status

Superceded by [5. New choice](0005-new-choice.md)

## Context

Ctx.

## Decision

Old decision.

## Consequences

None.
";
        let d = classify("doc/adr/0003-old-choice.md", content).unwrap();
        assert_eq!(d.doc_state, "superseded");
        assert!(!d.governance_effective);
    }

    #[test]
    fn adr_tools_correctly_spelled_superseded_also_normalizes() {
        let content = "\
# 3. Old choice

## Status

Superseded by [5. New choice](0005-new-choice.md)

## Context

Ctx.

## Decision

Old decision.

## Consequences

None.
";
        let d = classify("doc/adr/0003-old-choice.md", content).unwrap();
        assert_eq!(d.doc_state, "superseded");
    }

    /// NAMED TRAP: multi-line "## Status" section — only the LAST non-empty
    /// line is authoritative (accretion via `adr link`-style edits).
    #[test]
    fn multiline_status_section_last_line_wins() {
        let content = "\
# 12. Choose a diff algorithm

## Status

Accepted

Amended by [15. Refine diff algorithm](0015-refine-diff.md)

## Context

Ctx.

## Decision

Use histogram diff.

## Consequences

Faster diffs.
";
        let d = classify("doc/adr/0012-diff-algo.md", content).unwrap();
        assert_eq!(d.doc_state, "amended");
    }

    /// NAMED TRAP: status expressed as an H1 suffix, exactly the founder's
    /// ADR-857 example from the design doc.
    #[test]
    fn h1_suffix_status_is_recognized() {
        let content = "\
# 857. Capability system [Proposed]

## Context

We need a capability system.

## Decision

Introduce a CapabilityRegistry.

## Consequences

New abstraction to maintain.
";
        let d = classify("docs/adr/857-capability-system.md", content).unwrap();
        assert_eq!(d.doc_state, "proposed");
        assert!(!d.governance_effective);
        assert_eq!(d.doc_id.as_deref(), Some("857"));
    }

    #[test]
    fn nygard_without_status_section_is_recall_only() {
        let content = "\
# 20. Some old decision

## Context

Ctx.

## Decision

Did the thing.

## Consequences

Some.
";
        let d = classify("doc/adr/0020-some-old-decision.md", content).unwrap();
        assert_eq!(d.parse_quality, ParseQuality::RecallOnly);
        assert_eq!(d.doc_state, "unknown");
        assert!(!d.governance_effective);
    }

    // -- MADR 2.x (bold-bullet status) ----------------------------------

    /// NAMED TRAP: status expressed as a bold-bullet list item.
    #[test]
    fn madr_2x_bold_bullet_status_accepted() {
        let content = "\
# Use Redis for session storage

* Status: Accepted
* Deciders: alice, bob
* Date: 2024-02-01

## Context and Problem Statement

We need shared session storage across instances.

## Considered Options

* Redis
* In-memory

## Decision Outcome

Chosen option: \"Redis\", because it is already in our stack.
";
        let d = classify("docs/adr/0001-redis-sessions.md", content).unwrap();
        assert_eq!(d.doc_class, DocClass::DecisionRecord);
        assert_eq!(d.doc_state, "accepted");
        assert!(d.governance_effective);
    }

    #[test]
    fn madr_2x_status_rejected() {
        let content = "\
# Use GraphQL for the public API

- Status: Rejected
- Deciders: team

## Context and Problem Statement

Should we expose GraphQL?

## Considered Options

* GraphQL
* REST

## Decision Outcome

Chosen option: \"REST\", because simpler operationally.
";
        let d = classify("docs/adr/0002-graphql.md", content).unwrap();
        assert_eq!(d.doc_state, "rejected");
        assert!(!d.governance_effective);
    }

    // -- MADR 3.x/4.x (YAML front matter) -------------------------------

    #[test]
    fn madr_3x_yaml_status_accepted() {
        let content = "\
---
status: accepted
date: 2024-03-01
deciders: alice, bob
---

# Use RaBitQ for vector compression

## Context and Problem Statement

We need cheaper vector storage.

## Considered Options

* RaBitQ
* int8

## Decision Outcome

Chosen option: \"RaBitQ\", because of the compression ratio.
";
        let d = classify("docs/decisions/0007-rabitq.md", content).unwrap();
        assert_eq!(d.doc_state, "accepted");
        assert!(d.governance_effective);
    }

    #[test]
    fn madr_4x_decision_makers_key_status_proposed() {
        let content = "\
---
status: proposed
decision-makers: alice, bob
---

# Adopt a new retry policy

## Context and Problem Statement

Retries are ad hoc today.

## Considered Options

* Exponential backoff
* Fixed delay

## Decision Outcome

Chosen option: \"Exponential backoff\".
";
        let d = classify("docs/decisions/0011-retry-policy.md", content).unwrap();
        assert_eq!(d.doc_state, "proposed");
        assert!(!d.governance_effective);
    }

    /// NAMED TRAP: MADR 3.x/4.x with no status field present defaults to
    /// Accepted — but ONLY because the section fingerprint matches MADR.
    #[test]
    fn madr_absent_status_defaults_to_accepted_when_fingerprint_matches() {
        let content = "\
# Use trunk-based development

## Context and Problem Statement

We need a branching strategy.

## Considered Options

* Trunk-based
* GitFlow

## Decision Outcome

Chosen option: \"Trunk-based\", because it minimizes merge pain.
";
        let d = classify("docs/decisions/0004-trunk-based.md", content).unwrap();
        assert_eq!(d.doc_state, "accepted");
        assert!(d.governance_effective);
        assert_eq!(d.parse_quality, ParseQuality::FullParse);
    }

    /// The flip side of the trap above: a random status-less doc that does
    /// NOT match the MADR fingerprint must NOT be defaulted to accepted.
    #[test]
    fn status_less_doc_without_madr_fingerprint_is_not_defaulted() {
        let content = "\
# Some notes

Just some prose about the system with no decision structure at all,
no Context/Decision/Consequences headings, nothing MADR-shaped.
";
        assert!(classify("docs/notes.md", content).is_none());
    }

    // -- log4brains (sidecar-marked) -------------------------------------

    #[test]
    fn log4brains_status_accepted() {
        let content = "\
# Use event sourcing for the ledger

- Status: accepted
- Date: 2024-04-10
- Tags: ledger

Technical Story: LEDGER-42

## Context and Problem Statement

We need an auditable ledger.

## Decision Outcome

Chosen option: \"Event sourcing\".
";
        let sidecars = SidecarSignals {
            log4brains_marker: true,
            ..Default::default()
        };
        let d = classify_governance_doc("docs/adr/20240410-event-sourcing.md", content, &sidecars)
            .unwrap();
        assert_eq!(d.doc_state, "accepted");
        assert!(d.governance_effective);
    }

    #[test]
    fn log4brains_draft_is_proposed_family_not_effective() {
        let content = "\
# Draft idea

- Status: draft
- Date: 2024-04-11

## Context and Problem Statement

Early idea, not yet settled.

## Decision Outcome

Chosen option: \"early sketch, revisit later\".
";
        let sidecars = SidecarSignals {
            log4brains_marker: true,
            ..Default::default()
        };
        let d =
            classify_governance_doc("docs/adr/20240411-draft-idea.md", content, &sidecars).unwrap();
        assert_eq!(d.doc_state, "proposed");
        assert!(!d.governance_effective);
    }

    // -- DECISIONS.md (table-row-is-the-record) --------------------------

    #[test]
    fn decisions_md_table_row_is_the_record() {
        let content = "\
# Decisions

| Date | Decision | Status | Rationale |
|------|----------|--------|-----------|
| 2024-01-01 | Use Postgres for orders | Accepted | Team familiarity |
| 2024-02-01 | Use GraphQL for public API | Rejected | Too complex ops |
";
        let d = classify("DECISIONS.md", content).unwrap();
        assert_eq!(d.doc_class, DocClass::DecisionRecord);
        assert_eq!(d.title, "Use Postgres for orders");
        assert_eq!(d.doc_state, "accepted");
        assert!(d.governance_effective);
    }

    #[test]
    fn decisions_md_table_without_status_column_is_recall_only() {
        let content = "\
# Decision Log

| Date | Decision |
|------|----------|
| 2024-01-01 | Use Postgres for orders |
";
        let d = classify("DECISIONS.md", content).unwrap();
        assert_eq!(d.parse_quality, ParseQuality::RecallOnly);
        assert!(!d.governance_effective);
    }

    // -- kep.yaml sidecar --------------------------------------------------

    #[test]
    fn kep_yaml_sidecar_routes_to_recall_only_proposal() {
        let content = "\
# Node swap KEP

## Summary

Add swap support to kubelet.
";
        let sidecars = SidecarSignals {
            kep_yaml_sidecar: true,
            ..Default::default()
        };
        let d =
            classify_governance_doc("keps/sig-node/2400-node-swap/README.md", content, &sidecars)
                .unwrap();
        assert_eq!(d.doc_class, DocClass::ProposalInFlight);
        assert_eq!(d.parse_quality, ParseQuality::RecallOnly);
        assert!(!d.governance_effective);
    }

    // -- Anti-lookalike gates --------------------------------------------

    /// REJECTION: template file with placeholder id + pipe-separated status.
    #[test]
    fn rejects_adr_template() {
        let content = "\
# NNNN. Title of the ADR

## Status

{proposed | rejected | accepted | deprecated | superseded}

## Context

TBD

## Decision

Fill me in.

## Consequences

TBD
";
        assert!(classify("doc/adr/0000-template.md", content).is_none());
    }

    /// REJECTION: generated table-of-contents / index.md.
    #[test]
    fn rejects_generated_toc_index() {
        let content = "\
# Architecture Decision Records

- [1. Record architecture decisions](0001-record-architecture-decisions.md)
- [2. Use Postgres](0002-use-postgres.md)
- [3. Use Redis](0003-use-redis.md)
";
        assert!(classify("doc/adr/index.md", content).is_none());
    }

    /// REJECTION: a numbered tutorial with no status field.
    #[test]
    fn rejects_numbered_tutorial_without_status() {
        let content = "\
# Getting started

## Step 1: install

Run the installer.

## Step 2: configure

Edit the config file.

## Step 3: run

Start the service.
";
        assert!(classify("docs/0001-getting-started.md", content).is_none());
    }

    /// REJECTION: Jekyll blog post with `status: published` front matter.
    #[test]
    fn rejects_jekyll_blog_post_with_status_published() {
        let content = "\
---
layout: post
title: \"Our new architecture\"
status: published
permalink: /blog/our-new-architecture/
---

# Our new architecture

We rebuilt the whole thing and here is a narrative about it, written for
a general audience, not a decision record.
";
        assert!(classify("_posts/2024-05-01-our-new-architecture.md", content).is_none());
    }

    /// REJECTION: plain README.md, no matter what it contains.
    #[test]
    fn rejects_readme() {
        let content = "\
# My Project

## Status

Accepted

## Context

Some context that happens to use ADR-shaped words.

## Decision

We decided this.

## Consequences

None.
";
        assert!(classify("README.md", content).is_none());
    }

    /// REJECTION: CONTRIBUTING.md.
    #[test]
    fn rejects_contributing_md() {
        let content = "\
# Contributing

## Status

Please read this before contributing.

Run the tests before opening a PR. Follow the style guide.
";
        assert!(classify("CONTRIBUTING.md", content).is_none());
    }

    /// REJECTION: CHANGELOG.md — "Deprecated" is a section name, not a status.
    #[test]
    fn rejects_changelog_md() {
        let content = "\
# Changelog

## [1.2.0] - 2024-06-01

### Added

- New endpoint.

### Deprecated

- Old endpoint.

### Fixed

- Off-by-one bug.
";
        assert!(classify("CHANGELOG.md", content).is_none());
    }

    /// REJECTION: GitHub issue template front matter.
    #[test]
    fn rejects_issue_template() {
        let content = "\
---
name: Bug report
about: Create a report to help us improve
labels: bug
assignees: octocat
---

# Bug report

**Describe the bug**
A clear description.
";
        assert!(classify(".github/ISSUE_TEMPLATE/bug_report.md", content).is_none());
    }

    /// REJECTION: KEP-shaped README without the sibling kep.yaml sidecar —
    /// never ingest KEP trees via ADR heuristics.
    #[test]
    fn rejects_kep_shaped_readme_without_sidecar() {
        let content = "\
# Node swap KEP

## Summary

Add swap support to kubelet.

## Motivation

Some workloads need swap.
";
        assert!(classify("keps/sig-node/2400-node-swap/README.md", content).is_none());
    }

    // -- Totality / never-panics smoke ------------------------------------

    #[test]
    fn empty_input_does_not_panic_and_is_not_governance() {
        assert!(classify("", "").is_none());
        assert!(classify("adr/0001-x.md", "").is_none());
    }

    #[test]
    fn garbage_bytes_as_lossy_utf8_do_not_panic() {
        let bytes: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x01, b'#', b' ', 0x80, 0x81];
        let s = String::from_utf8_lossy(&bytes).to_string();
        let _ = classify("weird.md", &s);
    }

    #[test]
    fn deterministic_repeated_calls() {
        let content = "\
# 1. Record architecture decisions

## Status

Accepted

## Context

Ctx.

## Decision

Use ADRs.

## Consequences

None.
";
        let a = classify("doc/adr/0001-record-architecture-decisions.md", content);
        let b = classify("doc/adr/0001-record-architecture-decisions.md", content);
        assert_eq!(a, b);
    }

    // -- V1 contract: explicit-only `ban:`/`policy:` front matter ----------

    /// An accepted ADR with `ban: true` front matter surfaces `ban: true` —
    /// the ONLY v1 mechanism that ever sets it (never inferred from prose).
    #[test]
    fn front_matter_ban_true_is_honored() {
        let content = "\
---
status: accepted
ban: true
---

# Never commit secrets to the repo

## Context

We had an incident.

## Decision

Secrets must never be committed.

## Consequences

CI scans for them.
";
        let d = classify("docs/adr/0005-no-secrets.md", content).unwrap();
        assert!(d.ban, "explicit ban: true front matter must set GovernanceDoc::ban");
        assert!(d.governance_effective);
    }

    /// `policy:` is an accepted synonym for `ban:`, and a non-empty string
    /// value (not just literal `true`) still counts as an assertion.
    #[test]
    fn front_matter_policy_string_value_is_honored_as_a_ban() {
        let content = "\
---
status: accepted
policy: no disabling TLS verification
---

# Never disable TLS verification

## Context

An incident happened.

## Decision

TLS verification must always be on.

## Consequences

None.
";
        let d = classify("docs/adr/0006-tls-verification.md", content).unwrap();
        assert!(d.ban, "a non-falsy policy: value must be honored as a ban assertion");
    }

    /// Absence of `ban:`/`policy:` must never be inferred true from ban-shaped
    /// prose — explicit-only per the V1 contract.
    #[test]
    fn ban_is_false_when_front_matter_omits_it_even_with_ban_shaped_prose() {
        let content = "\
# 7. Never use raw SQL string concatenation

## Status

Accepted

## Context

SQL injection risk.

## Decision

We will never allow raw string-concatenated SQL.

## Consequences

Use the query builder everywhere.
";
        let d = classify("docs/adr/0007-no-raw-sql.md", content).unwrap();
        assert!(
            !d.ban,
            "ban-shaped prose without an explicit ban:/policy: field must never set ban=true"
        );
    }

    /// Explicit `ban: false` (or falsy variants) never sets the flag.
    #[test]
    fn front_matter_ban_false_is_honored_as_no_ban() {
        let content = "\
---
status: accepted
ban: false
---

# Use Postgres for the orders service

## Context

Ctx.

## Decision

Use Postgres.

## Consequences

None.
";
        let d = classify("docs/adr/0008-use-postgres.md", content).unwrap();
        assert!(!d.ban);
    }

    // -- V1 contract / Tier 0: explicit `governs:` front matter -------------

    /// A flow-style `governs: [a, b]` list is carried through verbatim.
    #[test]
    fn front_matter_governs_flow_list_is_carried_through() {
        let content = "\
---
status: accepted
governs: [lang:ts, path:apps/web/**]
---

# Use strict null checks in the frontend

## Context

Ctx.

## Decision

Enable strict null checks.

## Consequences

Fewer null-pointer bugs.
";
        let d = classify("docs/adr/0009-strict-null-checks.md", content).unwrap();
        assert_eq!(
            d.governs,
            vec!["lang:ts".to_string(), "path:apps/web/**".to_string()]
        );
    }

    /// A block-style YAML list under `governs:` is also carried through.
    #[test]
    fn front_matter_governs_block_list_is_carried_through() {
        let content = "\
---
status: accepted
governs:
  - service:billing-api
  - path:services/billing/**
---

# Billing must use idempotency keys

## Context

Ctx.

## Decision

All billing writes require an idempotency key.

## Consequences

None.
";
        let d = classify("docs/adr/0010-billing-idempotency.md", content).unwrap();
        assert_eq!(
            d.governs,
            vec![
                "service:billing-api".to_string(),
                "path:services/billing/**".to_string()
            ]
        );
    }

    /// No `governs:` key at all ⇒ empty, never invented.
    #[test]
    fn governs_is_empty_when_front_matter_omits_it() {
        let content = "\
---
status: accepted
---

# Use Postgres for the orders service

## Context

Ctx.

## Decision

Use Postgres.

## Consequences

None.
";
        let d = classify("docs/adr/0011-use-postgres.md", content).unwrap();
        assert!(d.governs.is_empty());
    }
}
