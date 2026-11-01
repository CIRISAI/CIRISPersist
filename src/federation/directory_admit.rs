//! v61 (CIRISPersist#934, S4a) — **the operator peer add, the known-hash
//! sighting and the steward purge's record write, decided once.**
//!
//! `add_peer_record`, `insert_known_wire_hash` and `purge_put_execution` were
//! written twice, in `store/{sqlite,postgres}.rs`, with the same gates in the
//! same order. Each door is now one function here; a backend implements
//! [`DirectoryStore`]: the SQL, the serve position, the transaction. It
//! decides nothing. The peer add's held-row verdict runs INSIDE the
//! executor's transaction (a conflict rolls the key row back with it), so it
//! is a shared plan the executor re-asks ([`peer_record_held_verdict`]), the
//! `recheck_cycle_under_lock` shape.
//!
//! # Which instant each plan reads
//!
//! The peer add stamps `valid_from`, `scrub_timestamp`, `inserted_at` and
//! `updated_at` with its one clock read. The sighting's instant is the
//! caller's `now`. The purge write reads none (its instants are the
//! execution's).

use chrono::{DateTime, Utc};

use super::steward_purge::{PurgeExecution, PurgePutOutcome, PurgeTombstone};
use super::{Error, FederationDirectory};
use super::{KeyRecord, PeerMetadataRow};

/// An operator-added peer the plan admitted: its `federation_keys` row and
/// its `federation_peer_metadata` row, each with its `persist_row_hash`.
#[derive(Debug, Clone)]
pub(crate) struct PlannedPeerRecord {
    /// The key row (no signed envelope: operator-authorised).
    pub(crate) key: KeyRecord,
    /// `original_content_hash`, decoded.
    pub(crate) original_content_hash: Vec<u8>,
    /// The metadata row.
    pub(crate) meta: PeerMetadataRow,
}

/// What the peer add does to a held metadata row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerMetaWrite {
    /// No row is held: insert it.
    Insert,
    /// A soft-removed row is held: re-add it (replace with the new row).
    ReAdd,
    /// A live row with the same transport is held: an idempotent no-op.
    Keep,
}

/// The metadata row the peer add found held under the key, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldPeerMeta {
    /// Its `transport_identity`.
    pub(crate) transport_identity: Option<String>,
    /// Whether `removed_at` is set.
    pub(crate) removed: bool,
}

/// The directory executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait DirectoryStore: FederationDirectory + Sized {
    /// In ONE transaction: insert the key row at a fresh admission position
    /// (`ON CONFLICT (key_id) DO NOTHING`), read the held pubkey and the held
    /// metadata row, ask [`peer_record_held_verdict`], and write the
    /// metadata row as it says. Its refusal rolls the transaction back.
    async fn store_planned_peer_record(&self, planned: PlannedPeerRecord) -> Result<(), Error>;

    /// Upsert the sighting, moving `last_advertised_at` only forward.
    async fn store_known_wire_hash(
        &self,
        kind: &str,
        content_hash: &str,
        advertised_by: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), Error>;

    /// In ONE transaction: the execution header (when not held) and every
    /// tombstone, the tombstoned attestations' wire-index entries and their
    /// detection projections.
    async fn store_purge_execution(
        &self,
        execution: &PurgeExecution,
        tombstones: &[PurgeTombstone],
    ) -> Result<PurgePutOutcome, Error>;
}

/// The door: every backend's `add_peer_record`.
pub(crate) async fn add_peer_record_planned<D: DirectoryStore>(
    dir: &D,
    key_id: &str,
    pubkey_ed25519_base64: &str,
    identity_type: &str,
    transport_identity: Option<String>,
) -> Result<(), Error> {
    for (name, value) in [
        ("key_id", key_id),
        ("pubkey_ed25519_base64", pubkey_ed25519_base64),
        ("identity_type", identity_type),
    ] {
        if value.is_empty() {
            return Err(Error::InvalidArgument(format!("{name} must be non-empty")));
        }
    }
    // v31.0.0 (CIRISPersist#656) — the fifth `federation_keys` admission
    // path writes a caller-supplied `identity_type`: the role gate runs
    // before any write.
    super::admission::check_peer_record_admission(dir, key_id, identity_type).await?;
    let now = Utc::now();
    let mut key = KeyRecord {
        key_id: key_id.to_owned(),
        pubkey_ed25519_base64: pubkey_ed25519_base64.to_owned(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: super::types::algorithm::HYBRID.to_owned(),
        identity_type: identity_type.to_owned(),
        identity_ref: key_id.to_owned(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({"peer_added_by_operator": true}),
        // 32 bytes of zeros: a placeholder digest, no signed envelope.
        original_content_hash: "00".repeat(32),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    key.persist_row_hash = super::types::compute_persist_row_hash(&key)?;
    let mut meta = PeerMetadataRow {
        key_id: key_id.to_owned(),
        alias: None,
        trust: super::TrustClass::Untrusted,
        notes: None,
        policy_blob: None,
        transport_identity,
        removed_at: None,
        inserted_at: now,
        updated_at: now,
        persist_row_hash: String::new(),
    };
    meta.persist_row_hash = super::types::compute_persist_row_hash(&meta)?;
    let original_content_hash = hex::decode(&key.original_content_hash)
        .map_err(|e| Error::InvalidArgument(format!("original_content_hash hex decode: {e}")))?;
    dir.store_planned_peer_record(PlannedPeerRecord {
        key,
        original_content_hash,
        meta,
    })
    .await
}

/// The held rows a peer add may not overwrite: a key held under another
/// pubkey, or a live metadata row with another transport.
fn refuse_held_peer_conflict(
    planned: &PlannedPeerRecord,
    held_pubkey: Option<&str>,
    held_meta: Option<&HeldPeerMeta>,
) -> Result<(), Error> {
    let key_id = &planned.key.key_id;
    if held_pubkey.is_some_and(|p| p != planned.key.pubkey_ed25519_base64) {
        return Err(Error::Conflict(format!(
            "key_id {key_id} already exists with different pubkey"
        )));
    }
    if held_meta
        .is_some_and(|m| !m.removed && m.transport_identity != planned.meta.transport_identity)
    {
        return Err(Error::Conflict(format!(
            "peer_metadata row for key_id {key_id} already exists with different \
             transport_identity"
        )));
    }
    Ok(())
}

/// **The peer add's held-row verdict**, asked by the executor inside its
/// transaction after the key insert: refused on a conflicting held row,
/// else what to do with the metadata row.
pub(crate) fn peer_record_held_verdict(
    planned: &PlannedPeerRecord,
    held_pubkey: Option<&str>,
    held_meta: Option<&HeldPeerMeta>,
) -> Result<PeerMetaWrite, Error> {
    refuse_held_peer_conflict(planned, held_pubkey, held_meta)?;
    Ok(match held_meta {
        None => PeerMetaWrite::Insert,
        Some(m) if m.removed => PeerMetaWrite::ReAdd,
        Some(_) => PeerMetaWrite::Keep,
    })
}

/// The door: every backend's `insert_known_wire_hash`.
pub(crate) async fn insert_known_wire_hash_planned<D: DirectoryStore>(
    dir: &D,
    kind: &str,
    content_hash: &str,
    advertised_by: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), Error> {
    super::wire_index::validate_content_hash("insert_known_wire_hash", content_hash)?;
    // v59.0.0 — a peer's advertisement of a framed key-plane hash is
    // refused: that carriage is retired.
    super::replication_policy::refuse_retired_framed(kind)?;
    dir.store_known_wire_hash(kind, content_hash, advertised_by, now)
        .await
}

/// The door: every backend's `purge_put_execution`. The set is checked
/// before anything is written.
pub(crate) async fn purge_put_execution_planned<D: DirectoryStore>(
    dir: &D,
    execution: &PurgeExecution,
    tombstones: &[PurgeTombstone],
) -> Result<PurgePutOutcome, Error> {
    super::steward_purge::check_purge_put_set(execution, tombstones)?;
    dir.store_purge_execution(execution, tombstones).await
}
