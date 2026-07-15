//! Section I — Federation observability bulk primitives.
//!
//! Moved from `src/read/federation.rs` in v4.0 (FSD §3.3).
//!
//! The existing federation directory primitives (`lookup_public_key`,
//! `list_attestations_for`, `revocations_for`) are point-lookup
//! shaped — keyed on a single identity or key_id. Monitoring dashboards
//! need bulk-list primitives that page through the whole directory
//! with multi-field filters.
//!
//! Three list primitives, each cursor-paged newest-first:
//!
//! - [`crate::ceg::ReadEngine::list_federation_keys`] — over
//!   `cirislens.federation_keys`.
//! - [`crate::ceg::ReadEngine::list_attestations`] — over
//!   `cirislens.federation_attestations`.
//! - [`crate::ceg::ReadEngine::list_revocations`] — over
//!   `cirislens.federation_revocations`.
//!
//! Item types reuse the existing [`crate::federation::KeyRecord`],
//! [`crate::federation::Attestation`], [`crate::federation::Revocation`]
//! shapes — no duplicate types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::federation::{Attestation, KeyRecord, Revocation};

// ─── Federation keys ───────────────────────────────────────────────

/// Filter for [`crate::ceg::ReadEngine::list_federation_keys`]. Composes
/// AND-style; every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationKeyFilter {
    /// Filter by agent identity (matches `identity_ref` when
    /// `identity_type = 'agent'`).
    pub agent_id_hash: Option<String>,

    /// Filter by algorithm (`"ed25519"` / `"ml_dsa_65"` / hybrid).
    pub algorithm: Option<String>,

    /// Filter by revocation status. `Some(true)` returns only keys
    /// that appear in `cirislens.federation_revocations`;
    /// `Some(false)` returns only un-revoked keys. `None` returns
    /// both.
    pub revoked: Option<bool>,

    /// Filter by PQC completion. `Some(true)` returns keys whose
    /// `pqc_completed_at IS NOT NULL`; `Some(false)` returns only
    /// hybrid-pending keys.
    pub pqc_completed: Option<bool>,

    /// v3.9.3 (CIRISPersist#151) — filter to keys whose **peer**
    /// declares this `cohort_scope` in its
    /// `federation_peer_metadata.policy_blob` (the peer-level
    /// membership slot, e.g. `"family-acme"` — distinct from the
    /// envelope-level closed-set `cohort_scope` on
    /// `federation_attestations`).
    ///
    /// Answers "which key_ids belong to cohort X?" in one indexed
    /// query instead of an O(N) per-key `peer_metadata_for` fan-out.
    /// Matches via an `EXISTS` join against
    /// `federation_peer_metadata` (Postgres `policy_blob->>'cohort_scope'`,
    /// SQLite `json_extract(policy_blob, '$.cohort_scope')`), and —
    /// because membership is a *live* property — **excludes
    /// soft-removed peers** (`removed_at IS NULL`). A V057 functional
    /// index over the JSON path keeps it O(log N).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort_scope: Option<String>,
}

/// Opaque cursor for [`crate::ceg::ReadEngine::list_federation_keys`].
///
/// Ordered by `(valid_from DESC, key_id DESC)` — newest-registered
/// first. Tuple cursor for unique tiebreak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationKeyCursor {
    /// Cursor format version. v0.5.5 ships `"v1"`.
    pub version: String,
    /// `valid_from` of the trailing row.
    pub last_valid_from: DateTime<Utc>,
    /// `key_id` of the trailing row.
    pub last_key_id: String,
}

impl FederationKeyCursor {
    /// Construct a v1 cursor.
    pub fn from_trailing(last_valid_from: DateTime<Utc>, last_key_id: String) -> Self {
        FederationKeyCursor {
            version: "v1".to_owned(),
            last_valid_from,
            last_key_id,
        }
    }
}

/// One page of [`KeyRecord`]s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationKeyListPage {
    /// Key records in `(valid_from DESC, key_id DESC)` order.
    pub items: Vec<KeyRecord>,
    /// Cursor for the next page; `None` at end of stream.
    pub next_cursor: Option<FederationKeyCursor>,
}

// ─── Attestations ──────────────────────────────────────────────────

/// v17.4.0 (FSD-005 Appendix C.2) — the row-tier axis of a `scores`
/// query. `None` on [`AttestationFilter::tier`] preserves the pre-v17.4.0
/// `list_attestations` behavior (federation-tier-only). Made a first-class
/// axis (C.4 rule 5) so drafts (`Local`) never need a second handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// Producer-only-authority, signature-deferred, self-visible-only rows.
    Local,
    /// Hybrid-signed, federation-visible rows (the default read tier).
    Federation,
    /// Both tiers (the caller opts into seeing its own drafts alongside
    /// federation rows).
    Any,
}

/// v17.4.0 (FSD-005 Appendix C.2) — lifecycle visibility. `Live` (the
/// serde default) hides rows retracted by a `supersedes` / `withdraws` /
/// `recants` composer; the `Include*` variants opt specific retracted
/// classes back in; `All` shows everything. Made a first-class axis (C.4
/// rule 5) so "I need retracted history" never forces a new API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleView {
    /// Only the precedence-live head per attester chain (default).
    #[default]
    Live,
    /// Live rows plus rows retracted by a `supersedes`.
    IncludeSuperseded,
    /// Live rows plus rows retracted by a `withdraws`.
    IncludeWithdrawn,
    /// Live rows plus rows retracted by a `recants`.
    IncludeRecanted,
    /// Every row, retracted or not.
    All,
}

/// v17.4.0 (FSD-005 Appendix C.2) — trust-perspective attester filter.
/// The v17.4.0 substrate honors ONLY set membership (`All` / `Explicit`);
/// the DERIVED predicates (`holders_of` / `reachable_from` / `licensed_by`)
/// resolve to an `Explicit` set SERVER-SIDE and are intentionally absent
/// here. `#[non_exhaustive]` keeps adding them later additive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttesterSet {
    /// No attester restriction.
    All,
    /// Keep only rows whose `attesting_key_id` is in this set.
    Explicit(Vec<String>),
}

/// Filter for [`crate::ceg::ReadEngine::list_attestations`] and the
/// v17.4.0 `scores` read handles. Composes AND-style.
///
/// v17.4.0 (FSD-005 Appendix C.2): this is the ONE `ScoresQuery` — extended
/// in place (never forked) so `list_scores` and `resolve_scores` share it
/// and a consumer builds a filter once for both the timeline and the verdict.
/// Every field is `Option`/additive and the struct is `#[non_exhaustive]`, so
/// a new query axis is a new optional field defaulting to today's behavior —
/// old consumers keep compiling and deserializing (C.4 rule 2).
// `Eq` dropped in v4.5 — `confidence_floor: Option<f64>` is not `Eq`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AttestationFilter {
    /// Filter by the key id that DID the attesting.
    pub attesting_key_id: Option<String>,

    /// Filter by the key id that WAS attested.
    pub attested_key_id: Option<String>,

    /// Filter by attestation_type token (e.g. `"identity"`,
    /// `"capability"`).
    pub attestation_type: Option<String>,

    /// Filter by PQC completion.
    pub pqc_completed: Option<bool>,

    /// v4.5 (CIRISPersist#171, CEG §10.1.5.4) — **open-vocabulary**
    /// dimension-prefix filter. Matches rows whose envelope `dimension`
    /// (`attestation_envelope->>'dimension'`) starts with ANY of these
    /// prefixes (hierarchical-prefix-matched, OR-combined). Empty = no
    /// dimension filter. The `attestation_query` axis; validated
    /// structurally, NOT against a closed enum.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dimension_prefixes: Vec<String>,

    /// v4.5 — point-in-time validity: keep rows with
    /// `asserted_at <= valid_at < COALESCE(expires_at, +inf)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_at: Option<DateTime<Utc>>,

    /// v4.5 — minimum `weight` (confidence floor): keep rows with
    /// `weight >= confidence_floor`. Rows with NULL weight are excluded
    /// when a floor is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_floor: Option<f64>,

    /// v4.5 — narrow to attestations naming this subject (the key id is
    /// a member of `subject_key_ids`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key_id: Option<String>,

    /// v17.4.0 (Appendix C.2) — EXACT dimension match (the axis today's
    /// prefix-only `dimension_prefixes` lacks; `attestation_type` is exact
    /// but `dimension` was prefix-only). AND-composed with any prefix set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimension_exact: Option<String>,

    /// v17.4.0 (Appendix C.2) — half-open time window `[start, end)` on
    /// `asserted_at`, for the timeline read. Distinct from `valid_at`
    /// (point-in-time validity incl. expiry); this is a range on when the
    /// attestation was asserted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<(DateTime<Utc>, DateTime<Utc>)>,

    /// v17.4.0 (Appendix C.2) — row-tier axis. `None` = federation-only
    /// (preserves `list_attestations`' pre-v17.4.0 behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,

    /// v17.4.0 (Appendix C.2) — lifecycle visibility. Default `Live`.
    #[serde(default, skip_serializing_if = "is_default_lifecycle")]
    pub lifecycle: LifecycleView,

    /// v17.4.0 (Appendix C.2) — trust-perspective attester filter. `None`
    /// = no restriction (equivalent to `AttesterSet::All`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attester_filter: Option<AttesterSet>,
}

/// serde `skip_serializing_if` for the default `LifecycleView::Live` — keeps
/// pre-v17.4.0 filter JSON byte-stable across the schema extension.
fn is_default_lifecycle(v: &LifecycleView) -> bool {
    matches!(v, LifecycleView::Live)
}

/// Opaque cursor for [`crate::ceg::ReadEngine::list_attestations`].
///
/// Ordered by `(asserted_at DESC, attestation_id DESC)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationCursor {
    /// Cursor format version. v0.5.5 ships `"v1"`.
    pub version: String,
    /// `asserted_at` of the trailing row.
    pub last_asserted_at: DateTime<Utc>,
    /// `attestation_id` of the trailing row.
    pub last_attestation_id: String,
}

impl AttestationCursor {
    /// Construct a v1 cursor.
    pub fn from_trailing(last_asserted_at: DateTime<Utc>, last_attestation_id: String) -> Self {
        AttestationCursor {
            version: "v1".to_owned(),
            last_asserted_at,
            last_attestation_id,
        }
    }
}

/// One page of [`Attestation`]s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationListPage {
    /// Attestations in `(asserted_at DESC, attestation_id DESC)` order.
    pub items: Vec<Attestation>,
    /// Cursor for the next page.
    pub next_cursor: Option<AttestationCursor>,
}

// ─── v17.4.0 scores read surface (FSD-005 Appendix C) ──────────────

/// One page of `list_scores` rows. Mirrors [`AttestationListPage`]; reuses
/// the [`AttestationCursor`] `(asserted_at, attestation_id)` shape. Each item
/// is a full [`Attestation`] (the `ScoredRow`) so the timeline consumer has
/// the raw signed row, not a lossy projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoresPage {
    /// Scored rows in `(asserted_at DESC, attestation_id DESC)` order.
    pub items: Vec<Attestation>,
    /// Cursor for the next page; `None` at end of stream.
    pub next_cursor: Option<AttestationCursor>,
}

/// v17.4.0 (FSD-005 Appendix C.3) — the composed verdict as a QUALITATIVE
/// band, never a bare float. `#[non_exhaustive]` so a future band does not
/// break a consumer `match`. Keeping the float scale out of the wire lets the
/// composition math evolve forever without a break (C.4 rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConfidenceBand {
    /// The live head is a negative-polarity claim (refuted).
    Refuted,
    /// Live rows disagree in sign (open contradiction dominates).
    Contested,
    /// Supported by few / low-confidence contributors.
    Weak,
    /// Supported by a healthy set of contributors.
    Supported,
    /// Strongly supported (high aggregate + contributor count).
    WellEstablished,
    /// Not enough distinct witnesses to render a verdict.
    InsufficientWitnesses,
}

/// v17.4.0 (FSD-005 Appendix C.3) — the `resolve_scores` fold result.
/// `#[non_exhaustive]`; the `trace` is the OPEN extensibility escape hatch
/// (`serde_json::Value` at the FFI seam) — any future fold input (a
/// witness-diversity discount, a bond weighting, a new gate) appears as a new
/// trace field, reflected in `band`, invisible to consumers that ignore it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ComposedVerdict {
    /// The qualitative confidence band.
    pub band: ConfidenceBand,
    /// Distinct attesting keys among the live (post-precedence) rows.
    pub contributor_count: u32,
    /// The anti-collusion witness-diversity n (NOT n_eff). `None` until the
    /// server-tier diversity policy lands (Appendix C.5 out-of-scope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_diversity: Option<f64>,
    /// Count of live rows whose sign opposes the head (open contradictions).
    pub open_contradictions: u32,
    /// Age of the precedence head (`now − head.asserted_at`). `None` when
    /// there is no live head (empty fold).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_of_head: Option<std::time::Duration>,
    /// Which composition policy produced this verdict (the `PolicyId`).
    pub policy_applied: String,
    /// The derivation trace, populated only when the caller asks for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<serde_json::Value>,
}

// ─── Revocations ───────────────────────────────────────────────────

/// Filter for [`crate::ceg::ReadEngine::list_revocations`]. Composes
/// AND-style.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationFilter {
    /// Filter by the key id that WAS revoked.
    pub revoked_key_id: Option<String>,

    /// Filter by the key id that DID the revoking.
    pub revoking_key_id: Option<String>,

    /// Filter by PQC completion.
    pub pqc_completed: Option<bool>,
}

/// Opaque cursor for [`crate::ceg::ReadEngine::list_revocations`].
///
/// Ordered by `(revoked_at DESC, revocation_id DESC)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationCursor {
    /// Cursor format version. v0.5.5 ships `"v1"`.
    pub version: String,
    /// `revoked_at` of the trailing row.
    pub last_revoked_at: DateTime<Utc>,
    /// `revocation_id` of the trailing row.
    pub last_revocation_id: String,
}

impl RevocationCursor {
    /// Construct a v1 cursor.
    pub fn from_trailing(last_revoked_at: DateTime<Utc>, last_revocation_id: String) -> Self {
        RevocationCursor {
            version: "v1".to_owned(),
            last_revoked_at,
            last_revocation_id,
        }
    }
}

/// One page of [`Revocation`]s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevocationListPage {
    /// Revocations in `(revoked_at DESC, revocation_id DESC)` order.
    pub items: Vec<Revocation>,
    /// Cursor for the next page.
    pub next_cursor: Option<RevocationCursor>,
}
