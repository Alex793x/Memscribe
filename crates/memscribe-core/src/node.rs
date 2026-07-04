//! The output contract: prepared nodes (whitepaper §6).
//!
//! Memscribe only ever produces nodes with `Observed` or
//! `DeterministicallyDerived` fact-status. It does the deterministic
//! preparation and *flags* everything that would require inference
//! (fine-grained decision typing, concept naming) for the consumer to handle
//! later. That is what keeps the module zero-LLM and its output golden-testable.

use crate::model::{Diff, GitRef, SourceLocation};
use serde::{Deserialize, Serialize};
use std::ops::Range;
use std::path::PathBuf;
use time::OffsetDateTime;

/// A stable id for a prepared node. Derived deterministically from the source
/// (session id + span), so the same input always yields the same id.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub String);

impl NodeId {
    /// Construct a node id.
    pub fn new(s: impl Into<String>) -> Self {
        NodeId(s.into())
    }
    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The epistemic status of a node or edge. Memscribe emits only the first two;
/// the latter two are *flags* for a downstream inference layer, never values
/// Memscribe itself computes by guessing.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactStatus {
    /// Verbatim from the source.
    Observed,
    /// Computed by a deterministic function of observed data.
    DeterministicallyDerived,
    /// Ranked by a statistical measure (downstream).
    StatisticallyRanked,
    /// An LLM hypothesis (downstream); Memscribe only ever *flags* this.
    LlmHypothesis,
}

/// The category of a deterministic commitment marker.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MarkerCategory {
    /// Explicit decision verb ("use", "let's go with", "decide").
    DecisionVerb,
    /// A rejected alternative ("instead of X", "rather than").
    Rejection,
    /// A ban ("we will NOT / never use X") — Kruchten anticrisis.
    Ban,
    /// An imperative ("must", "always", "never", "shall").
    Imperative,
    /// A memory directive ("remember that", "keep in mind").
    Memory,
    /// Assistant-proposal-then-user-confirmation.
    Confirmation,
    /// An imperative request to change code ("fix", "add", "refactor",
    /// "remove", "optimize"). Distinct from [`Self::Imperative`] (modal
    /// obligation: must/always/never) — an action request should bind to an
    /// edit, not state a standing rule. Additive variant (serde snake_case →
    /// `action_request`); existing serialization is unchanged.
    ActionRequest,
}

/// Which deterministic commitment marker fired on a turn, and where.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitmentMarker {
    /// The rule id that matched (e.g. `decision_verb.use`).
    pub rule_id: String,
    /// The marker category.
    pub category: MarkerCategory,
    /// The verbatim text span that matched.
    pub matched_text: String,
    /// Byte offset of the match within the turn text.
    pub offset: usize,
}

/// A gated, verbatim dialogue span (always `Observed`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversationSpan {
    /// The session the span belongs to.
    pub session_id: String,
    /// The (inclusive-start, exclusive-end) turn-seq range.
    pub turn_range: Range<u64>,
    /// The verbatim dialogue text.
    pub text: String,
    /// Which deterministic markers fired.
    pub markers: Vec<CommitmentMarker>,
    /// Always [`FactStatus::Observed`].
    pub fact_status: FactStatus,
    /// Provenance pointers for replay & audit.
    pub provenance: Vec<SourceLocation>,
}

/// Which pipeline produced a [`DecisionRecord`] — conversation-mined,
/// git-mined, or governance-doc-ingested (ADR/MADR/log4brains/DECISIONS.md,
/// Component A's `classify_governance_doc`). Distinct from [`crate::model::SourceKind`],
/// which names the *agent/tool* a conversation came from (Claude Code, Codex,
/// …) — this is the *decision-provenance* axis MemCortex's identity scheme
/// (Component G) keys on to route ADR-sourced records through a disjoint id
/// space from conversation/git-mined ones. Defaults to `Conversation` (the
/// original, only origin that existed before this field), so every prior
/// `DecisionRecord` construction site (git-mine included) keeps compiling and
/// keeps its historical meaning without an explicit update.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOrigin {
    /// Deterministically parsed from a gated conversation turn.
    #[default]
    Conversation,
    /// Mined from a git commit subject/body (`gitcommit::mine_commit_nodes`).
    GitCommit,
    /// Ingested from a classified governance document (ADR/MADR/log4brains/
    /// DECISIONS.md) via `classify_governance_doc` (Component A).
    Governance,
}

impl DecisionOrigin {
    /// Whether this is the default ([`DecisionOrigin::Conversation`]) — used as
    /// the `serde(skip_serializing_if)` predicate on [`DecisionRecord::origin`]
    /// so pre-Component-G serialized shapes are unaffected.
    #[must_use]
    fn is_default(&self) -> bool {
        matches!(self, DecisionOrigin::Conversation)
    }
}

/// A considered option within a decision.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Opt {
    /// The option text (verbatim span).
    pub text: String,
    /// Whether this option was the one chosen.
    pub chosen: bool,
}

/// A pointer to a confirmation check (an ArchUnit rule, test, or schema check)
/// named in a decision.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckRef {
    /// The kind of check (`archunit` | `test` | `schema`).
    pub kind: String,
    /// The named target.
    pub target: String,
}

/// A decision parsed deterministically from a gated turn. The schema follows
/// IBIS / QOC / MADR / Kruchten. Prose typing that requires inference is left to
/// the consumer; only verbatim spans and structural flags are populated here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRecord {
    /// The decision sentence (a verbatim span).
    pub epitome: String,
    /// Options parsed from "instead of X", "vs", or explicit lists.
    pub considered_options: Vec<Opt>,
    /// True for a ban ("we will NOT / never use X").
    pub is_ban: bool,
    /// A pointer to a node that supersedes this decision, if known.
    pub superseded_by: Option<NodeId>,
    /// A named confirmation check, if the decision references one.
    pub confirmation: Option<CheckRef>,
    /// The exact turn span (no accreted context).
    pub source_span: Range<u64>,
    /// `Observed` for the verbatim text. Element-typing uncertainty is flagged
    /// downstream as [`FactStatus::LlmHypothesis`], never guessed here.
    pub fact_status: FactStatus,
    /// When the decision was made: the originating gated turn's wall-clock time.
    /// Lives on the record (not a sidecar) so each decision carries its own real
    /// time across `nodeprep`'s `.record.clone()` and the NDJSON round-trip —
    /// without it, ingest stamps every node with the batch default (epoch 1000).
    #[serde(with = "time::serde::rfc3339", default = "epoch_fallback")]
    pub timestamp: OffsetDateTime,
    /// Who made the decision, when known — the authoritative per-engineer
    /// attribution (Teams). Git-mined decisions set this to the commit author
    /// ("Name <email>"); conversation-captured decisions leave it `None` (the read
    /// layer falls back to the store owner). Additive + `serde(default)`, so older
    /// NDJSON corpora and the conversation path deserialize/serialize unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// Which pipeline produced this record (Governance Intake, Component G).
    /// Additive + `serde(default)` (defaults to [`DecisionOrigin::Conversation`]).
    /// Also `skip_serializing_if` at the default: existing NDJSON corpora and
    /// every golden snapshot fixture built before this field existed (the
    /// conversation-adapter-driven ones, which are all `Conversation`-origin)
    /// keep serializing byte-identically. It becomes visible in the output
    /// only when it carries information a pre-Component-G reader didn't have
    /// (`GitCommit`/`Governance`).
    #[serde(default, skip_serializing_if = "DecisionOrigin::is_default")]
    pub origin: DecisionOrigin,
    /// A stable repo identifier the decision was ingested against — e.g. the
    /// repo's root-relative canonical name (design decision: NOT a filesystem
    /// absolute path, which is machine-specific; a short name/slug the indexer
    /// already has for the repo, matching the `repo:` scope selector in the
    /// governance-intake design doc). `None` for conversation/git-mined
    /// decisions today (no caller sets it); ADR ingestion (a later component,
    /// downstream of Component A's `classify_governance_doc`) is expected to
    /// populate it. Additive + `serde(default)`, so nothing existing changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_identity: Option<String>,
    /// The ADR number (from `GovernanceDoc.doc_id`) or, when the doc has no
    /// numeric/slug id (MADR/log4brains/Y-statement docs with `doc_id: None`),
    /// a stable hash of the doc's repo-relative file path (see
    /// `memcortex_ingest::adr_fallback_key` in MemCortex, which is what
    /// actually computes that hash — this field just carries whichever string
    /// the caller decided is the ADR-or-fallback key). `None` unless
    /// `origin == Governance`. Additive + `serde(default)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adr_key: Option<String>,
    /// The classified governance-doc facts (Component A's `classify_governance_doc`
    /// output, minus its `title`/`doc_id` which already have a home on this
    /// record via `epitome`/`adr_key`), when this record was ingested via the
    /// Governance Intake doc path (`origin == Governance`). `None` for every
    /// conversation/git-mined record (no caller sets it).
    ///
    /// Design note (Component D): this is a **typed sidecar field on
    /// `DecisionRecord`**, not a separate `PreparedNode` variant — a classified
    /// ADR/MADR/log4brains/DECISIONS.md fact is still exactly a `Decision`
    /// (IBIS/MADR-shaped: an epitome, a status, a lifecycle), so it round-trips
    /// through the existing `PreparedNode::Decision` arm rather than forcing
    /// every downstream consumer (ingest, redaction, NDJSON tail, corpusgen) to
    /// learn a fifth `PreparedNode` shape for what is semantically the same
    /// node kind. Additive + `serde(default)`, so every pre-Component-D
    /// producer/consumer (conversation/git-mined records, and any capture pass
    /// — e.g. a sibling worktree's `governance_doc_to_prepared_node` — that
    /// already emits a `PreparedNode::Decision` without this field) keeps
    /// (de)serializing unchanged; a reader that sets this field via its own
    /// "governance" JSON sidecar convention still deserializes correctly as
    /// long as the field name matches (`governance`), since serde ignores
    /// unknown-shaped `None` the same way either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<GovernanceFacts>,
}

/// The classified governance-doc facts a `DecisionRecord` carries when
/// `origin == DecisionOrigin::Governance` (Component D). Mirrors
/// `memscribe_core::governance_doc::GovernanceDoc` (Component A) minus
/// `title`/`doc_id`, which already have a home on `DecisionRecord` itself
/// (`epitome`/`adr_key`) — this type exists so `memcortex-ingest` (which
/// cannot depend on `governance_doc`'s classifier internals, only its output
/// shape) has a plain, serializable carrier for the two-field V1-contract
/// split (`doc_state` vs `governance_effective`, design doc item 2) plus the
/// doc-class and parse-quality labels needed for honest recall/display.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceFacts {
    /// The doc-class slug (`"decision_record"` / `"proposal_in_flight"` /
    /// `"standing_rule"` / `"procedure"`) — a plain string, not
    /// `governance_doc::DocClass` itself, so this type has no dependency on
    /// that module (kept here, alongside `PreparedNode`, so a consumer crate
    /// that only needs the *shape* of governance facts, not the classifier,
    /// avoids pulling in `classify_governance_doc`'s parsing internals).
    pub doc_class: String,
    /// The canonicalized-but-honest verbatim status (`GovernanceDoc::doc_state`).
    /// Never invented; `"unknown"` at recall-only parse quality.
    pub doc_state: String,
    /// Conservatively derived (`GovernanceDoc::governance_effective`): true only
    /// for `accepted` (verbatim or MADR-implicit). Gates edge-minting eligibility
    /// downstream (Component E) — this field only ever *carries* the value
    /// honestly; it never decides anything on its own.
    pub governance_effective: bool,
    /// The parse-quality slug (`"full_parse"` / `"recall_only"`) —
    /// `GovernanceDoc::parse_quality` as a plain string, same rationale as
    /// `doc_class`.
    pub parse_quality: String,
    /// A Tier-0 author-declared scope (`governs: [...]` front matter), when
    /// present. `None` when the doc carries no scope metadata — Tier 1/2
    /// scope derivation (prose extraction, mined suggestions) is Component F's
    /// concern and is never populated here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeNode>,
}

/// A minimal scope-node shape (design doc "Anchoring" section, Tier 0):
/// the closed-vocabulary selector strings straight from a `governs:`
/// front-matter line (e.g. `["lang:ts", "path:apps/web/**"]`), carried
/// verbatim. **Not evaluated here** — resolving a selector against a
/// repo/path/lang/service/symbol at query time is Component F's scope
/// predicate evaluator; this type only makes sure the raw selectors survive
/// the NDJSON round-trip so a scope node CAN be represented and stored today.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeNode {
    /// The raw selector strings, in file order, verbatim from front matter
    /// (e.g. `"repo:memtrace-ui"`, `"path:apps/web/**"`, `"lang:typescript"`,
    /// `"ext:.sql"`, `"service:billing-api"`, `"symbol:CapabilityRegistry"`).
    /// Unparsed/unvalidated here — the closed-vocabulary selector grammar
    /// (design doc's "Scope selector vocabulary" table) is Component F's
    /// concern; this is a lossless carrier only.
    pub selectors: Vec<String>,
}

/// Backward-compat default for `DecisionRecord.timestamp` when reading NDJSON
/// produced before the field existed (e.g. a committed benchmark corpus): the
/// record deserializes with an epoch timestamp instead of failing the whole line.
fn epoch_fallback() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

/// A code edit episode: the path, the diff, and the git sha
/// (`DeterministicallyDerived`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeEpisode {
    /// The edited path.
    pub path: PathBuf,
    /// The normalized diff.
    pub diff: Diff,
    /// The git ref at edit time, if known.
    pub git: Option<GitRef>,
    /// A deterministic id for the episode.
    pub episode_id: String,
}

/// The relation a binding edge expresses.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// A decision/conversation produced an episode.
    Produced,
    /// A decision governs an episode.
    Governs,
    /// An episode is derived from a decision/conversation.
    DerivedFrom,
    /// Two nodes are statistically correlated.
    CorrelatedWith,
}

/// A PROV record: `used(session, decision)` + `wasGeneratedBy(diff, session)`
/// with the temporal invariant `t_use ≤ t_gen`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvRecord {
    /// The session that used the decision.
    pub used_session: String,
    /// The decision node that was used, if any.
    pub used_decision: Option<NodeId>,
    /// The session that generated the edit.
    pub was_generated_by_session: String,
    /// When the decision was used.
    #[serde(with = "time::serde::rfc3339")]
    pub t_use: OffsetDateTime,
    /// When the edit was generated. Invariant: `t_use ≤ t_gen`.
    #[serde(with = "time::serde::rfc3339")]
    pub t_gen: OffsetDateTime,
}

impl ProvRecord {
    /// Whether the temporal invariant `t_use ≤ t_gen` holds.
    #[must_use]
    pub fn is_temporally_valid(&self) -> bool {
        self.t_use <= self.t_gen
    }
}

/// A correlation measure between two nodes, when computable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CorrelationTuple {
    /// Support.
    pub support: f64,
    /// Confidence.
    pub confidence: f64,
    /// Lift.
    pub lift: f64,
    /// Phi coefficient.
    pub phi: f64,
    /// p-value.
    pub p: f64,
}

/// A binding edge: decision/conversation → episode, with PROV, fact-status, and
/// (optional) correlation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BindingEdge {
    /// The source node.
    pub from: NodeId,
    /// The target node.
    pub to: NodeId,
    /// The relation.
    pub relation: Relation,
    /// The PROV record.
    pub prov: ProvRecord,
    /// `DeterministicallyDerived` when recorded live; else downgraded.
    pub fact_status: FactStatus,
    /// A correlation tuple, when computable.
    pub correlation: Option<CorrelationTuple>,
}

/// The typed data the consumer layer (MemCortex) ingests.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "node", rename_all = "snake_case")]
pub enum PreparedNode {
    /// A gated, verbatim dialogue span.
    Conversation(ConversationSpan),
    /// A deterministically-parsed decision.
    Decision(DecisionRecord),
    /// A code edit episode.
    Episode(CodeEpisode),
    /// A decision/conversation → episode binding.
    Binding(BindingEdge),
}

impl PreparedNode {
    /// A stable tag for the node variant — used in tests and ordering.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            PreparedNode::Conversation(_) => "conversation",
            PreparedNode::Decision(_) => "decision",
            PreparedNode::Episode(_) => "episode",
            PreparedNode::Binding(_) => "binding",
        }
    }

    /// The node's fact-status.
    #[must_use]
    pub fn fact_status(&self) -> FactStatus {
        match self {
            PreparedNode::Conversation(c) => c.fact_status,
            PreparedNode::Decision(d) => d.fact_status,
            PreparedNode::Episode(_) => FactStatus::DeterministicallyDerived,
            PreparedNode::Binding(b) => b.fact_status,
        }
    }
}
