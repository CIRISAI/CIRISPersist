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

/// Filter for [`crate::ceg::ReadEngine::list_attestations`]. Composes
/// AND-style.
// `Eq` dropped in v4.5 — `confidence_floor: Option<f64>` is not `Eq`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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
