//! Per-identity Reticulum blackhole substrate (v3.2.0, CIRISPersist#120).
//!
//! # Mission alignment (MISSION.md §2 — `federation/`)
//!
//! The federation directory names what cryptographic identities exist;
//! [`BlobStorage`](crate::federation::BlobStorage) names what bytes
//! exist. This module names what *Reticulum transport identities* the
//! operator has chosen to deny.
//!
//! [`BlackholeRules`] is a sibling trait to
//! [`FederationDirectory`](crate::federation::FederationDirectory) —
//! same shape, same connection pool, distinct surface. The decision to
//! split is identical to the [`BlobStorage`](crate::federation::BlobStorage)
//! split: directory is about *identities + trust statements*, blob is
//! about *bytes*, and blackhole is about *operator-driven transport-
//! address denials*. Keeping them separate lets the trait doc-comments
//! scope cleanly and lets a caller mock one without the others.
//!
//! # The five operations (per CIRISPersist#120)
//!
//! 1. [`blackhole_list`](BlackholeRules::blackhole_list) — operator
//!    UX: "show me my deny-list".
//! 2. [`blackhole_upsert`](BlackholeRules::blackhole_upsert) — add a
//!    rule or revise an existing one. Re-upsert preserves `hits` (an
//!    operator changing the reason / expiry is NOT a counter reset)
//!    and preserves `added_at` (the first-banned-at forensic marker).
//! 3. [`blackhole_remove`](BlackholeRules::blackhole_remove) — drop
//!    a rule. Silent no-op when the identity isn't in the table —
//!    mirrors POSIX `rm -f` ergonomics for operator scripting.
//! 4. [`blackhole_record_hit`](BlackholeRules::blackhole_record_hit) —
//!    hot-path observation: "I just dropped an envelope addressed to
//!    this identity, bump the counter". Race-tolerant: silent no-op
//!    when the rule was removed between the send-path check and the
//!    increment.
//! 5. [`blackhole_prune_expired`](BlackholeRules::blackhole_prune_expired) —
//!    background-task hot path: drop rules whose `until` is in the
//!    past. Permanent rules (`until IS NULL`) are NEVER pruned — the
//!    NULL is the operator's "this rule lives until I say otherwise"
//!    signal.
//!
//! # `identity_hash` shape — 16 bytes, validated at the API surface
//!
//! Reticulum's destination hash is 16 bytes today. The trait validates
//! `identity_hash.len() == 16` at the call boundary, raising
//! [`Error::InvalidArgument`](crate::federation::Error::InvalidArgument)
//! on mismatch. There is **no SQL-side CHECK constraint** — if
//! Reticulum widens the hash format in a future version, the API
//! guard relaxes without a schema rewrite. The SQL column is BYTEA on
//! Postgres / BLOB on SQLite (untyped-width container).
//!
//! # `hits` is commutative, not transactional
//!
//! [`blackhole_record_hit`](BlackholeRules::blackhole_record_hit) is a
//! single-statement `UPDATE … SET hits = hits + 1` — no transaction
//! wrap, no read-modify-write race. The counter is an observation
//! field, not a consensus value; two writers double-incrementing is
//! the desired behavior for the operator's "how noisy is this
//! identity?" question.
//!
//! Callers on the hottest send paths (CIRISEdge `ReticulumTransport`'s
//! per-envelope check) may want to batch hits client-side to avoid the
//! round-trip per send. Persist deliberately does NOT batch — that's
//! the caller's policy choice; a `HashMap<Vec<u8>, u64>` accumulator
//! with a periodic flush is the recommended shape.
//!
//! # `record_hit` does NOT recompute `persist_row_hash`
//!
//! The `persist_row_hash` field is server-computed via
//! [`compute_persist_row_hash`](crate::federation::types::compute_persist_row_hash)
//! on the canonical bytes of the row (excluding the hash itself). The
//! `hits` counter is intentionally excluded from the hash input — a
//! re-hash on every send would force the canonicalizer to run inside
//! the hot path. The operator-meaningful fields (`until`, `reason`)
//! ARE part of the hash; the observation counter is not.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// v3.2.0 (CIRISPersist#120) — durable per-identity blackhole rule
/// row. Returned by [`BlackholeRules::blackhole_list`] with
/// `persist_row_hash` populated server-side over the canonical bytes
/// of the row (excluding the hash itself + excluding `hits`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlackholeRecord {
    /// 16-byte Reticulum identity hash. The transport-layer address
    /// the operator denied. Length-validated at the API surface (no
    /// SQL-side CHECK).
    #[serde(with = "crate::federation::serde_bytes_b64")]
    pub identity_hash: Vec<u8>,
    /// Soft-expiry. `None` = permanent rule (the operator must remove
    /// it explicitly). `Some(ts)` = expire at this wall-clock; rows
    /// whose `until` is in the past are eligible for
    /// [`blackhole_prune_expired`](BlackholeRules::blackhole_prune_expired).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
    /// Operator-readable reason. Free-form; persist does not parse.
    /// `None` when the operator added the rule without annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// First-banned-at wall-clock. Preserved across `upsert` so
    /// operators can ask "how long has this rule been in effect?".
    pub added_at: DateTime<Utc>,
    /// Hot-path observation counter (incremented by
    /// [`blackhole_record_hit`](BlackholeRules::blackhole_record_hit)).
    /// Not part of the [`persist_row_hash`](Self::persist_row_hash)
    /// input — the counter is observation, not operator-intent.
    pub hits: i64,
    /// Server-computed AV-row-hash. SHA-256 of the canonical bytes of
    /// the row with `persist_row_hash` itself and `hits` removed
    /// (the latter so hot-path hit-records don't force a re-hash).
    pub persist_row_hash: String,
}

/// v3.2.0 (CIRISPersist#120) — operator-driven blackhole CRUD trait.
///
/// Sibling to [`FederationDirectory`](crate::federation::FederationDirectory)
/// and [`BlobStorage`](crate::federation::BlobStorage). The same
/// backends implement all three — they share the federation
/// connection pool — but the trait surfaces are kept distinct so each
/// can be implemented / mocked independently.
///
/// # Object-safety
///
/// The trait is annotated with [`#[async_trait]`](async_trait::async_trait)
/// — every method returns `Pin<Box<dyn Future<Output = …> + Send + '_>>`
/// rather than a per-method RPITIT — so consumers can build
/// `Arc<dyn BlackholeRules>`. Matches the
/// [`FederationDirectory`](crate::federation::FederationDirectory)
/// shape (which CIRISEdge's `current_rust_engine()` consumer will reach
/// for).
///
/// # Errors
///
/// All methods route through the existing
/// [`federation::Error`](crate::federation::Error) tree — no new error
/// variants. The operator-CRUD surface uses:
///
/// - [`Error::InvalidArgument`](crate::federation::Error::InvalidArgument)
///   for length-mismatched `identity_hash` (must be 16 bytes).
/// - [`Error::Backend`](crate::federation::Error::Backend) for any DB-
///   level failure.
///
/// `remove` and `record_hit` are silent no-ops when the identity is
/// not present — neither raises [`Error::PeerNotFound`]
/// (a `BlackholeRecord` is not a peer) nor a hypothetical
/// `Error::BlackholeNotFound` (the ergonomic contract is "operator
/// addresses an identity; persist either has a rule or it doesn't;
/// caller does not need to special-case missing").
#[async_trait::async_trait]
pub trait BlackholeRules: Send + Sync {
    /// Enumerate every blackhole rule. Ordered ascending by
    /// `added_at` so callers can paginate / diff deterministically.
    /// Returns an empty `Vec` when no rules exist.
    async fn blackhole_list(&self) -> Result<Vec<BlackholeRecord>, crate::federation::Error>;

    /// Insert a new rule or revise an existing one.
    ///
    /// On conflict (`identity_hash` already present):
    /// - `until` and `reason` are OVERWRITTEN with the new values.
    /// - `hits` is PRESERVED — a re-upsert is an operator-intent
    ///   change, not a counter reset.
    /// - `added_at` is PRESERVED — the first-banned-at wall-clock is
    ///   a forensic marker; operators want it stable across edits.
    ///
    /// `identity_hash.len()` MUST equal 16; non-conforming inputs
    /// return [`Error::InvalidArgument`](crate::federation::Error::InvalidArgument)
    /// before any DB interaction.
    async fn blackhole_upsert(
        &self,
        identity_hash: &[u8],
        until: Option<DateTime<Utc>>,
        reason: Option<&str>,
    ) -> Result<(), crate::federation::Error>;

    /// Drop a rule. Silent no-op when no rule exists for
    /// `identity_hash` — POSIX `rm -f` ergonomics for operator
    /// scripts that want to call without a preceding lookup.
    ///
    /// `identity_hash.len()` MUST equal 16; non-conforming inputs
    /// return [`Error::InvalidArgument`](crate::federation::Error::InvalidArgument).
    async fn blackhole_remove(&self, identity_hash: &[u8]) -> Result<(), crate::federation::Error>;

    /// Increment `hits` for the rule. Hot-path send-side counter
    /// bump.
    ///
    /// Silent no-op when no rule exists for `identity_hash` (race-
    /// tolerant: the operator may have removed the rule between the
    /// send-path check and this call).
    ///
    /// Does NOT recompute `persist_row_hash` — the counter is
    /// observation, not operator-intent. Callers concerned about
    /// hot-path latency should batch hits client-side
    /// (`HashMap<Vec<u8>, u64>` + periodic flush) and call this with
    /// the accumulated count via N sequential calls; persist
    /// deliberately does not surface a batched increment.
    ///
    /// `identity_hash.len()` MUST equal 16; non-conforming inputs
    /// return [`Error::InvalidArgument`](crate::federation::Error::InvalidArgument).
    async fn blackhole_record_hit(
        &self,
        identity_hash: &[u8],
    ) -> Result<(), crate::federation::Error>;

    /// Delete every rule whose `until` is in the past relative to
    /// `now`. Returns the number of rows deleted.
    ///
    /// Permanent rules (`until IS NULL`) are NEVER pruned — the
    /// NULL is the operator's "this rule lives until I say
    /// otherwise" signal. Operators wanting to drop a permanent
    /// rule MUST call [`blackhole_remove`](Self::blackhole_remove).
    ///
    /// Returns `0` when no rules are expired.
    async fn blackhole_prune_expired(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, crate::federation::Error>;
}

/// v3.2.0 (CIRISPersist#120) — fixed Reticulum identity hash length
/// (16 bytes). Validation constant for the four
/// `identity_hash`-taking trait methods.
pub const RETICULUM_IDENTITY_HASH_LEN: usize = 16;

/// Validate that an `identity_hash` argument is exactly the expected
/// length. Used by every trait method that takes one. Returns
/// [`Error::InvalidArgument`](crate::federation::Error::InvalidArgument)
/// on mismatch with a stable message format the kind-token mapping
/// can pattern-match.
pub fn validate_identity_hash_len(identity_hash: &[u8]) -> Result<(), crate::federation::Error> {
    if identity_hash.len() != RETICULUM_IDENTITY_HASH_LEN {
        return Err(crate::federation::Error::InvalidArgument(format!(
            "identity_hash must be {} bytes, got {}",
            RETICULUM_IDENTITY_HASH_LEN,
            identity_hash.len()
        )));
    }
    Ok(())
}

/// Canonical-bytes shape used by [`compute_blackhole_row_hash`].
///
/// Mirrors the on-disk [`BlackholeRecord`] but EXCLUDES the `hits`
/// counter — see the [`BlackholeRecord::persist_row_hash`] doc for the
/// rationale (hot-path hit-recording must not force a re-canonicalize).
#[derive(Serialize)]
struct BlackholeHashShape<'a> {
    #[serde(with = "crate::federation::serde_bytes_b64")]
    identity_hash: &'a [u8],
    #[serde(skip_serializing_if = "Option::is_none")]
    until: &'a Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: &'a Option<String>,
    added_at: &'a DateTime<Utc>,
}

/// Compute the `persist_row_hash` for a blackhole rule from its
/// operator-intent fields. The `hits` counter is intentionally
/// excluded — see the [`BlackholeRecord::persist_row_hash`] doc.
pub(crate) fn compute_blackhole_row_hash(
    identity_hash: &[u8],
    until: &Option<DateTime<Utc>>,
    reason: &Option<String>,
    added_at: &DateTime<Utc>,
) -> Result<String, crate::federation::Error> {
    let shape = BlackholeHashShape {
        identity_hash,
        until,
        reason,
        added_at,
    };
    crate::federation::types::compute_persist_row_hash(&shape)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_identity_hash_len_accepts_16() {
        assert!(validate_identity_hash_len(&[0u8; 16]).is_ok());
    }

    #[test]
    fn validate_identity_hash_len_rejects_other_lengths() {
        for n in [0usize, 1, 8, 15, 17, 32, 64] {
            let bytes = vec![0u8; n];
            let err = validate_identity_hash_len(&bytes).unwrap_err();
            assert!(
                matches!(err, crate::federation::Error::InvalidArgument(_)),
                "len {n} should reject: got {err:?}"
            );
        }
    }

    #[test]
    fn compute_blackhole_row_hash_excludes_hits_field() {
        // The hash MUST be stable across hit-record bumps — the
        // canonical-bytes shape does not include hits, so the hash
        // is the same regardless of any (unhashed) counter state.
        let id = vec![0xABu8; 16];
        let added_at = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let until =
            Some(chrono::DateTime::<chrono::Utc>::from_timestamp(1_800_000_000, 0).unwrap());
        let reason = Some("noise".to_string());
        let h1 = compute_blackhole_row_hash(&id, &until, &reason, &added_at).unwrap();
        let h2 = compute_blackhole_row_hash(&id, &until, &reason, &added_at).unwrap();
        assert_eq!(h1, h2);

        // Mutating reason changes the hash.
        let other = Some("other".to_string());
        let h3 = compute_blackhole_row_hash(&id, &until, &other, &added_at).unwrap();
        assert_ne!(h1, h3);
    }
}
