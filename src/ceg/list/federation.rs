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

/// v30.9.0 (CIRISPersist#627) — fold a singular convenience field and its
/// set-valued twin into ONE effective OR-list.
///
/// Every backend's query builder calls this so the singular/plural combination
/// has a single definition. Two builders deriving "OR them together" separately
/// is how they drift, and this struct already carries the scar (`#596 item 2`:
/// three axes silently ignored by one backend).
///
/// Empty result ⇒ the caller emits NO predicate, which is "match anything" —
/// not "match nothing". That is the existing meaning of an unset filter field
/// and changing it here would silently empty every unfiltered listing.
#[must_use]
pub fn merge_key_predicate(one: Option<&String>, many: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(many.len() + 1);
    if let Some(k) = one {
        out.push(k.clone());
    }
    for k in many {
        if !out.contains(k) {
            out.push(k.clone());
        }
    }
    out
}

/// v32.2.0 (CIRISPersist#605) — **the supported open-ended upper bound** for
/// [`AttestationFilter::window`].
///
/// `9999-12-31T23:59:59.999999999Z`. Chosen because the window predicate is a
/// LEXICOGRAPHIC comparison over RFC-3339 text, so the bound must both be later
/// than any real row AND sort above it as a string. `9999` is the largest
/// four-digit year, and four digits is exactly the range over which
/// `chrono`'s RFC-3339 rendering keeps text order and time order agreeing.
///
/// The intuitive choice, `DateTime::<Utc>::MAX_UTC`, is the trap: it renders as
/// `+262143-12-31T…`, leading with `'+'` (0x2B) where every ordinary row leads
/// with a digit — so it sorts BELOW every four-digit-year row and selects
/// nothing. A consumer measured an `after:`-only selection going 2 rows to 0
/// the moment the push-down began binding.
pub const OPEN_ENDED_WINDOW_END: &str = "9999-12-31T23:59:59.999999999Z";

/// The inclusive text-orderable range for a window bound: `[1000-01-01,
/// 9999-12-31]`. Outside it, RFC-3339 rendering stops agreeing with time order
/// — below year 1000 the year is zero-padded to four digits by `chrono` but a
/// negative year renders with `'-'`, and above 9999 with `'+'`; both sort
/// outside the digit range `'0'..='9'`.
const WINDOW_BOUND_MIN_YEAR: i32 = 1000;
const WINDOW_BOUND_MAX_YEAR: i32 = 9999;

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
    ///
    /// Convenience alias for a one-element [`Self::attesting_key_ids`]. When both
    /// are set they are OR-combined, matching how `dimension_prefixes` behaves.
    pub attesting_key_id: Option<String>,

    /// Filter by the key id that WAS attested.
    ///
    /// Convenience alias for a one-element [`Self::attested_key_ids`]; see that
    /// field.
    pub attested_key_id: Option<String>,

    /// v30.9.0 (CIRISPersist#627) — filter by a SET of attesting key ids,
    /// OR-combined and pushed into the query as `IN (…)`.
    ///
    /// # Why the set form exists
    ///
    /// Every graded moderation act (`refuse-writes`, `deadmit`, `quarantine`,
    /// `descend`) addresses the subjects this filter names. With only the
    /// singular field, de-admitting 61 leaked keys is 61 preview→commit pairs,
    /// each with its own hash, reason and authority walk — and the operator's
    /// alternative is a script hammering a tier-4 door in a loop, which is worse
    /// than what the tiering exists to prevent. At mesh scale it is not slow, it
    /// is unusable: no predicate over a population is expressible at all.
    ///
    /// **The ladder's safety property does not require the singular form.** Its
    /// guarantee is preview-hash commit — *what was previewed is what executes* —
    /// which is a property of the HASH, not of cardinality. A preview over 61
    /// keys produces one hash over that row set and is exactly as TOCTOU-closed
    /// as a preview over one. It also audits better: one decision, one stated
    /// reason, one ledger entry naming the whole set, instead of 61 rows a reader
    /// must infer were a single act.
    ///
    /// Pushed into the QUERY, never an application-side loop — the CIRISServer#343
    /// lesson this module's own doc already states. `dimension_prefixes` is the
    /// precedent: same struct, already `Vec<String>`, already OR-combined,
    /// already pushed down.
    ///
    /// # `#[serde(default)]` is REQUIRED, not decoration
    ///
    /// `AttestationFilter` is `Serialize`/`Deserialize`, and filters are
    /// persisted and sent over the wire. A bare new field is MANDATORY on
    /// deserialize, so every filter written before this release fails to load
    /// with `missing field ...`. That is not hypothetical — three trace-plane
    /// tests went red on stored filters the moment these fields landed
    /// (`backfill_trace_attestations_478`, and the two ingest replays).
    ///
    /// `#[serde(default)]` makes an absent field the empty set, which is exactly
    /// "no additional key predicate" and preserves every existing document. Any
    /// future field on this struct needs the same treatment.
    #[serde(default)]
    pub attesting_key_ids: Vec<String>,

    /// v30.9.0 (CIRISPersist#627) — filter by a SET of attested key ids.
    /// See [`Self::attesting_key_ids`].
    #[serde(default)]
    pub attested_key_ids: Vec<String>,

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
    ///
    /// # Both bounds are compared as RFC-3339 **TEXT** (v32.2.0, #605)
    ///
    /// `asserted_at` is stored and bound as text, so this predicate is a
    /// LEXICOGRAPHIC comparison, not a temporal one. That is fine for ordinary
    /// four-digit years and catastrophic outside them:
    ///
    /// ```text
    /// DateTime::<Utc>::MAX_UTC  ->  "+262143-12-31T23:59:59.999999999+00:00"
    /// ```
    ///
    /// It leads with `'+'` (0x2B); every ordinary row leads with a digit
    /// (`'2'`, 0x32). So `"2026-08-05T…" < "+262143-…"` is **false**, and the
    /// sentinel meaning "no upper bound" is the one value that excludes every
    /// row in the table.
    ///
    /// Use [`OPEN_ENDED_WINDOW_END`] for an open-ended window. Out-of-range
    /// bounds are REFUSED by [`Self::validate`] rather than silently returning
    /// nothing — an empty result set reads as a legitimate answer everywhere,
    /// which is what made this invisible until a consumer measured which layer
    /// had actually applied the predicate.
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

impl AttestationFilter {
    /// v32.2.0 (CIRISPersist#605) — **refuse a window bound that does not sort
    /// the way it reads.**
    ///
    /// [`Self::window`] is pushed down as a comparison over RFC-3339 TEXT, so
    /// its correctness depends on the rendered string ordering the same way the
    /// instant does. That holds for four-digit years and fails outside them:
    /// `DateTime::<Utc>::MAX_UTC` renders as `+262143-12-31T…`, leading with
    /// `'+'` (0x2B) where every ordinary row leads with a digit, so it sorts
    /// BELOW every real row. `asserted_at < MAX_UTC` is false for the entire
    /// table.
    ///
    /// **Refusing beats returning nothing**, which is the entire point. An
    /// empty result set is a legitimate answer everywhere, so the failure is
    /// invisible: a consumer's `after:`-only selection went 2 rows to 0 the
    /// moment the push-down began binding, and nothing in the stack could tell
    /// "filtered correctly" from "filtered everything out". A loud refusal
    /// naming the bound converts a silent wrong answer into a fixable one.
    ///
    /// Callers wanting an open-ended window should use
    /// [`OPEN_ENDED_WINDOW_END`].
    ///
    /// Also rejects an inverted window (`start >= end`), which would select
    /// nothing for the same reason and be equally silent.
    pub fn validate(&self) -> Result<(), crate::ceg::Error> {
        let Some((start, end)) = self.window else {
            return Ok(());
        };
        for (label, bound) in [("start", start), ("end", end)] {
            let year = chrono::Datelike::year(&bound);
            if !(WINDOW_BOUND_MIN_YEAR..=WINDOW_BOUND_MAX_YEAR).contains(&year) {
                return Err(crate::ceg::Error::InvalidArgument(format!(
                    "window {label} bound has year {year}, outside the \
                     text-orderable range {WINDOW_BOUND_MIN_YEAR}..={WINDOW_BOUND_MAX_YEAR}. \
                     `asserted_at` is compared as RFC-3339 TEXT, so a bound outside \
                     four-digit years does not sort the way it reads and would select \
                     ZERO rows rather than the range you asked for (this is what \
                     `DateTime::MAX_UTC` does — it renders as `+262143-…`, which sorts \
                     below every ordinary row). For an open-ended window use \
                     `{OPEN_ENDED_WINDOW_END}`."
                )));
            }
        }
        if start >= end {
            return Err(crate::ceg::Error::InvalidArgument(format!(
                "window is empty or inverted: start {start} is not before end {end}; \
                 the window is half-open [start, end), so this selects zero rows"
            )));
        }
        Ok(())
    }
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

#[cfg(test)]
mod window_bound_tests_605 {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn with_window(start: DateTime<Utc>, end: DateTime<Utc>) -> AttestationFilter {
        AttestationFilter {
            window: Some((start, end)),
            ..Default::default()
        }
    }

    /// **THE DEFECT ITSELF, as a property of the rendered text.**
    ///
    /// This asserts the thing that makes the issue real: `MAX_UTC` sorts BELOW
    /// an ordinary row when compared as RFC-3339 text, which is exactly how the
    /// predicate compares it. Without this, the validator below is an arbitrary
    /// range check whose motivation lives only in a comment — and a comment
    /// cannot fail.
    #[test]
    fn max_utc_sorts_below_every_ordinary_row_as_text_605() {
        let sentinel = DateTime::<Utc>::MAX_UTC.to_rfc3339();
        let ordinary = t("2026-08-15T12:00:00Z").to_rfc3339();

        assert!(
            sentinel.starts_with('+'),
            "the trap depends on the leading '+': {sentinel}"
        );
        assert!(
            ordinary.as_str() > sentinel.as_str(),
            "a 2026 row must sort ABOVE MAX_UTC as text — this inversion IS the \
             bug: `asserted_at < MAX_UTC` is FALSE for every four-digit-year \
             row, so the sentinel meaning 'no upper bound' excludes everything. \
             ordinary={ordinary} sentinel={sentinel}"
        );
    }

    /// The recommended sentinel must NOT have that property, or the fix hands
    /// callers a second trap.
    #[test]
    fn the_recommended_sentinel_sorts_above_every_ordinary_row_605() {
        let ordinary = t("2026-08-15T12:00:00Z").to_rfc3339();
        assert!(
            OPEN_ENDED_WINDOW_END > ordinary.as_str(),
            "OPEN_ENDED_WINDOW_END must sort above real rows as TEXT, or it is \
             the same defect with a different literal"
        );
        let parsed: DateTime<Utc> = OPEN_ENDED_WINDOW_END.parse().expect("parses");
        assert!(with_window(t("2026-01-01T00:00:00Z"), parsed)
            .validate()
            .is_ok());
    }

    /// The refusal fires, and names the remedy rather than just saying no.
    #[test]
    fn max_utc_as_a_bound_is_refused_not_silently_empty_605() {
        let f = with_window(t("2026-01-01T00:00:00Z"), DateTime::<Utc>::MAX_UTC);
        let err = f.validate().expect_err("MAX_UTC must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("262143") || msg.contains("year"),
            "the refusal must name what is wrong with the bound: {msg}"
        );
        assert!(
            msg.contains(OPEN_ENDED_WINDOW_END),
            "the refusal must name the SUPPORTED sentinel, so the caller's next \
             step is in the error rather than in an issue thread: {msg}"
        );
    }

    /// An ordinary window is untouched — a validator that refused real queries
    /// would be worse than the bug.
    #[test]
    fn an_ordinary_window_still_passes_605() {
        assert!(
            with_window(t("2026-01-01T00:00:00Z"), t("2026-12-31T00:00:00Z"))
                .validate()
                .is_ok()
        );
        assert!(AttestationFilter::default().validate().is_ok());
    }

    /// An inverted window selects nothing for the same silent reason, so the
    /// same door refuses it.
    #[test]
    fn an_inverted_window_is_refused_605() {
        let f = with_window(t("2026-12-31T00:00:00Z"), t("2026-01-01T00:00:00Z"));
        let msg = format!("{}", f.validate().expect_err("inverted must be refused"));
        assert!(
            msg.contains("inverted") || msg.contains("zero rows"),
            "{msg}"
        );
        let eq = t("2026-06-01T00:00:00Z");
        assert!(with_window(eq, eq).validate().is_err());
    }
}
