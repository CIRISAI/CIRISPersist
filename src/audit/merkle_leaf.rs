//! Merkle-tree leaf binding for cirislens audit entries (FSD §4.4).
//!
//! Per the every-append cadence, each `AuditEntry` becomes a leaf in
//! the tenant's `TransparencyLog<AuditLeaf>`. The leaf's canonical
//! bytes are the same canonical bytes the existing linear chain already
//! hashes for `entry_hash` — binding the Merkle leaf to the linear
//! chain entry by identity, not by a separate hash relationship.

#![allow(missing_docs)]

use ciris_verify_core::transparency::{TransparencyError, TransparencyLeaf};
use serde::{Deserialize, Serialize};

use super::types::AuditEntry;
use super::verify::canonical_bytes_for_entry;

/// A Merkle-tree leaf for one audit chain entry.
///
/// Holds the audit entry verbatim plus the `chain_event_id` —
/// the BIGINT primary key of the corresponding row in
/// `cirislens.audit_log` (the per-tenant monotonic sequence number
/// reused as the chain-event id, per FSD §4.4 +
/// V021__federation_trust_grants_and_merkle.sql). The
/// `chain_event_id` is **not** part of the Merkle leaf's
/// canonical-bytes hash — it's a side-channel projection field the
/// `TransparencyStore` impl needs to populate the
/// `merkle_leaves.chain_event_id` column (FK projection back to the
/// audit chain). Two semantically-identical AuditLeaves with
/// different `chain_event_id` values produce byte-equal
/// canonical_bytes (and therefore byte-equal leaf hashes); the audit
/// chain is the source of truth.
///
/// `canonical_bytes` returns the same canonical-byte representation
/// the linear chain hashes for `entry_hash` (with `entry_hash` and
/// `signature` zeroed to avoid self-referential cycles, per
/// `verify::compute_entry_hash`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLeaf {
    pub entry: AuditEntry,
    /// BIGINT PK of the matching `cirislens.audit_log` row. Captured
    /// at append time so `merkle_leaves.chain_event_id` projects back
    /// to the audit chain without an extra round-trip. Excluded from
    /// `canonical_bytes()` — the Merkle leaf hashes only the audit
    /// entry's canonical form so cross-substrate verifiers don't need
    /// the chain-event-id schema to recompute leaf hashes.
    pub chain_event_id: i64,
}

impl AuditLeaf {
    /// Construct a leaf with a `chain_event_id` of `0` (a sentinel
    /// only valid in test/scratch contexts where the audit-chain FK
    /// is irrelevant). Phase D ingest call sites use
    /// [`AuditLeaf::with_chain_event_id`] instead.
    pub fn new(entry: AuditEntry) -> Self {
        Self {
            entry,
            chain_event_id: 0,
        }
    }

    /// Construct a leaf bound to its audit-chain row. Phase D
    /// ingest-path constructor.
    pub fn with_chain_event_id(entry: AuditEntry, chain_event_id: i64) -> Self {
        Self {
            entry,
            chain_event_id,
        }
    }
}

impl TransparencyLeaf for AuditLeaf {
    fn canonical_bytes(&self) -> Result<Vec<u8>, TransparencyError> {
        // Use the same canonical-bytes computation the linear chain
        // already uses for entry_hash. Zero out entry_hash + signature
        // so the leaf-bytes are computable from the entry's identity
        // (not from its post-storage state).
        let mut for_canonical = self.entry.clone();
        for_canonical.entry_hash = Vec::new();
        for_canonical.signature = String::new();
        canonical_bytes_for_entry(&for_canonical)
            .map_err(|e| TransparencyError::Serialization(format!("audit canonical: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::GENESIS_PREV_HASH;
    use chrono::Utc;

    fn make_entry() -> AuditEntry {
        AuditEntry {
            entry_id: "test-entry-1".into(),
            sequence_number: 1,
            tenant_id: "test-tenant".into(),
            actor_id: "B64ACTOR".into(),
            action_type: "test_action".into(),
            subject_kind: "task".into(),
            subject_id: "task-1".into(),
            payload: serde_json::json!({"k": "v"}),
            prev_hash: GENESIS_PREV_HASH.to_vec(),
            entry_hash: vec![0; 32], // post-storage state
            recorded_at: Utc::now(),
            signature: "B64SIG".into(), // post-storage state
        }
    }

    #[test]
    fn leaf_canonical_bytes_deterministic() {
        let entry = make_entry();
        let leaf1 = AuditLeaf::new(entry.clone());
        let leaf2 = AuditLeaf::new(entry);
        assert_eq!(
            leaf1.canonical_bytes().unwrap(),
            leaf2.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn leaf_canonical_bytes_ignores_signature() {
        // Same entry with different signatures must yield identical
        // canonical bytes (signature is stripped from the canonical form).
        let mut a = make_entry();
        let mut b = a.clone();
        a.signature = "SIG_A".into();
        b.signature = "SIG_B".into();
        let leaf_a = AuditLeaf::new(a);
        let leaf_b = AuditLeaf::new(b);
        assert_eq!(
            leaf_a.canonical_bytes().unwrap(),
            leaf_b.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn leaf_canonical_bytes_ignores_entry_hash() {
        let mut a = make_entry();
        let mut b = a.clone();
        a.entry_hash = vec![0xAA; 32];
        b.entry_hash = vec![0xBB; 32];
        let leaf_a = AuditLeaf::new(a);
        let leaf_b = AuditLeaf::new(b);
        assert_eq!(
            leaf_a.canonical_bytes().unwrap(),
            leaf_b.canonical_bytes().unwrap()
        );
    }
}
