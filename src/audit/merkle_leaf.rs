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
/// Holds the audit entry verbatim; `canonical_bytes` returns the same
/// canonical-byte representation the linear chain hashes for
/// `entry_hash` (with `entry_hash` and `signature` zeroed to avoid
/// self-referential cycles, per `verify::compute_entry_hash`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLeaf {
    pub entry: AuditEntry,
}

impl AuditLeaf {
    pub fn new(entry: AuditEntry) -> Self {
        Self { entry }
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
