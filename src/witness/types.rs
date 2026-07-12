//! §19.1 WholenessWitness at-rest + build-input types
//! (CEG 1.0-RC11 §19; CIRISPersist#228 item 1 / #229 item 1).
//!
//! persist is the **store + the WW-2 leaf-walk owner**. The Merkle
//! construction, the PQC gate, and the equivocation classifier are
//! frozen in `ciris_verify_core::holonomic` (cross-impl-proven in
//! CIRISVerify v5.9.0) — persist CALLS them, never re-rolls them.
//!
//! What lives here:
//!   * [`WitnessLeaf`] — a candidate leaf for `build_local_witness`,
//!     carrying the tier / cohort_scope persist needs to apply the WW-2
//!     filter BEFORE the root is computed.
//!   * [`StoredWitness`] — one row of the `wholeness_witness_corpus`
//!     table (the verified witness's signed scalars + Merkle root + the
//!     bound-hybrid signature halves + claim_namespaces).
//!
//! § F-5 rule (verify at the gate, never trust an in-band flag): there
//! is NO `verified` field on [`StoredWitness`]. A verdict is recomputed
//! at the ingest gate ([`crate::witness::admit`]); a stored row is, by
//! construction, a row that already passed `verify_witness`.

use serde::{Deserialize, Serialize};

/// Witness schema version persist stores (`= 1`).
pub const WITNESS_VERSION_V1: u16 = 1;

/// Cap on the number of witnesses retained per peer in the corpus
/// (last-K, by `observed_at_unix_ms`). A bounded ring so a peer cannot
/// grow the corpus without limit; the comparison surface only needs the
/// recent set. K is a substrate const, NOT operator-tunable.
pub const WITNESS_CORPUS_K: usize = 8;

/// A candidate leaf for [`build_local_witness`](crate::witness::build_local_witness).
///
/// persist owns "gather all CEG envelopes a peer holds" → it MUST filter
/// out anonymous-tier rows AND `cohort_scope: self` rows BEFORE computing
/// the root (WW-2). A naive build that swept those into a signed
/// federating root would re-attribute deniable / self-private content to
/// a stable `peer_id`. The leaf carries exactly the two axes the filter
/// keys on plus the namespace it would contribute to and the raw bytes
/// that get hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessLeaf {
    /// The namespace this row would contribute to (e.g.
    /// `"scores:medical"`). A `self`/`anonymous` namespace is itself a
    /// WW-2 violation and is dropped.
    pub claim_namespace: String,
    /// The row's cohort scope (`"self" | "family" | "community" | ...`).
    /// `"self"` rows are deniable/self-private and MUST NOT enter the
    /// federating root (WW-2).
    pub cohort_scope: String,
    /// Whether the row is anonymous-tier. Anonymous rows MUST NOT enter
    /// the federating root (WW-2 / SR-2/3).
    pub anonymous_tier: bool,
    /// The raw leaf bytes hashed into the Merkle tree (the
    /// `holds_bytes:*` projection persist commits to). Opaque here.
    pub leaf_bytes: Vec<u8>,
}

impl WitnessLeaf {
    /// True iff this leaf is WW-2-eligible (NOT anonymous-tier, NOT
    /// `cohort_scope: self`, and its namespace does not itself name
    /// `self`/`anonymous`). Only eligible leaves enter the root.
    #[must_use]
    pub fn ww2_eligible(&self) -> bool {
        if self.anonymous_tier {
            return false;
        }
        let scope = self.cohort_scope.to_ascii_lowercase();
        if scope == "self" {
            return false;
        }
        let ns = self.claim_namespace.to_ascii_lowercase();
        !ns.contains("self") && !ns.contains("anonymous")
    }
}

/// A verified WholenessWitness as persisted to `wholeness_witness_corpus`.
///
/// Mirrors [`ciris_verify_core::holonomic::WholenessWitness`] (the signed
/// scalars + the Merkle root) plus the bound-hybrid signature halves and
/// the producer key ids persist needs to RE-verify on read / re-compare.
/// The Merkle root is stored as lowercase hex (64 chars).
///
/// No `verified` field (the §19.0 F-5 rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWitness {
    /// The witnessing peer's stable id.
    pub peer_id: String,
    /// Per-peer monotonic epoch (anti-rollback / eclipse guard, N4).
    pub epoch_id: u64,
    /// The namespaces this root covers. MUST NOT name anonymous/`self`
    /// (WW-2) — enforced at the gate by `verify_witness`.
    pub claim_namespaces: Vec<String>,
    /// The §19.1 Merkle root over the WW-2-filtered, lexicographically
    /// ordered leaves — lowercase hex (64 chars).
    pub merkle_root_hex: String,
    /// Number of Merkle leaves the root covers.
    pub leaf_count: u32,
    /// Producer observation time, unix-ms (the corpus sort/PK key).
    pub observed_at_unix_ms: u64,
    /// Witness schema version (`= 1`).
    pub witness_version: u16,
    /// Ed25519 signature over the §19.1 canonical preimage (base64).
    pub signature: String,
    /// ML-DSA-65 signature over `preimage ‖ ed25519_sig` (base64) —
    /// REQUIRED at the gate (§19.0 PQC-mandatory; no classical-only).
    pub signature_ml_dsa_65: String,
    /// The producer's ML-DSA-65 key id (provenance / re-verify lookup).
    pub pqc_key_id: String,
}

impl StoredWitness {
    /// Decode the stored hex root back to the 32-byte
    /// [`ciris_verify_core::holonomic::wholeness_witness::Hash`]. Errors
    /// if the column is not 64 hex chars (substrate corruption).
    pub fn merkle_root_bytes(&self) -> Result<[u8; 32], crate::witness::WitnessAdmitError> {
        decode_root_hex(&self.merkle_root_hex)
    }

    /// Reconstruct the verify-core [`WholenessWitness`](ciris_verify_core::holonomic::WholenessWitness)
    /// shape this row was admitted as — the comparison input.
    pub fn as_verify_witness(
        &self,
    ) -> Result<ciris_verify_core::holonomic::WholenessWitness, crate::witness::WitnessAdmitError>
    {
        Ok(ciris_verify_core::holonomic::WholenessWitness {
            peer_id: self.peer_id.clone(),
            epoch_id: self.epoch_id,
            claim_namespaces: self.claim_namespaces.clone(),
            merkle_root: self.merkle_root_bytes()?,
            leaf_count: self.leaf_count,
            observed_at_unix_ms: self.observed_at_unix_ms,
            witness_version: self.witness_version,
        })
    }
}

/// The PyO3 wire shape of a WholenessWitness (CIRISPersist#431 — the
/// CC 6.1.1 Engine projection). Mirrors the verify-core
/// [`WholenessWitness`](ciris_verify_core::holonomic::WholenessWitness)
/// scalars with the Merkle root carried as lowercase hex (the JSON-safe
/// form of the 32-byte `Hash`), plus the producer's ML-DSA-65 key id
/// (provenance — a [`StoredWitness`] column, not a signed scalar, so it
/// rides the wire object rather than the signature params).
///
/// No `verified` field (the §19.0 F-5 rule): a verdict is recomputed at
/// the ingest gate, never read from the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessWire {
    /// The witnessing peer's stable id.
    pub peer_id: String,
    /// Per-peer monotonic epoch (anti-rollback / eclipse guard, N4).
    pub epoch_id: u64,
    /// The namespaces this root covers. MUST NOT name anonymous/`self`
    /// (WW-2) — enforced at the gate by `verify_witness`.
    pub claim_namespaces: Vec<String>,
    /// The §19.1 Merkle root — lowercase hex (64 chars).
    pub merkle_root_hex: String,
    /// Number of Merkle leaves the root covers.
    pub leaf_count: u32,
    /// Producer observation time, unix-ms.
    pub observed_at_unix_ms: u64,
    /// Witness schema version. Defaults to V1 when omitted.
    #[serde(default = "default_witness_version")]
    pub witness_version: u16,
    /// The producer's ML-DSA-65 key id (provenance / re-verify lookup).
    /// Defaults empty when the caller has no keyring alias to record.
    #[serde(default)]
    pub pqc_key_id: String,
}

fn default_witness_version() -> u16 {
    WITNESS_VERSION_V1
}

impl WitnessWire {
    /// Decode the wire shape into the verify-core
    /// [`WholenessWitness`](ciris_verify_core::holonomic::WholenessWitness)
    /// the ingest gate verifies. Errors on a non-64-hex-char root.
    pub fn to_verify_witness(
        &self,
    ) -> Result<ciris_verify_core::holonomic::WholenessWitness, crate::witness::WitnessAdmitError>
    {
        Ok(ciris_verify_core::holonomic::WholenessWitness {
            peer_id: self.peer_id.clone(),
            epoch_id: self.epoch_id,
            claim_namespaces: self.claim_namespaces.clone(),
            merkle_root: decode_root_hex(&self.merkle_root_hex)?,
            leaf_count: self.leaf_count,
            observed_at_unix_ms: self.observed_at_unix_ms,
            witness_version: self.witness_version,
        })
    }
}

/// Lowercase-hex of a 32-byte Merkle root (the corpus column shape).
#[must_use]
pub fn encode_root_hex(root: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in root {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a 64-char lowercase-hex Merkle root.
pub fn decode_root_hex(hex: &str) -> Result<[u8; 32], crate::witness::WitnessAdmitError> {
    if hex.len() != 64 {
        return Err(crate::witness::WitnessAdmitError::MalformedRoot);
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or(crate::witness::WitnessAdmitError::MalformedRoot)?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or(crate::witness::WitnessAdmitError::MalformedRoot)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ww2_eligibility_drops_self_and_anonymous() {
        let ok = WitnessLeaf {
            claim_namespace: "scores:medical".into(),
            cohort_scope: "community".into(),
            anonymous_tier: false,
            leaf_bytes: b"x".to_vec(),
        };
        assert!(ok.ww2_eligible());

        let self_scope = WitnessLeaf {
            cohort_scope: "self".into(),
            ..ok.clone()
        };
        assert!(!self_scope.ww2_eligible(), "self scope dropped");

        let anon = WitnessLeaf {
            anonymous_tier: true,
            ..ok.clone()
        };
        assert!(!anon.ww2_eligible(), "anonymous-tier dropped");

        let self_ns = WitnessLeaf {
            claim_namespace: "cohort_scope:self:notes".into(),
            ..ok.clone()
        };
        assert!(!self_ns.ww2_eligible(), "self-named namespace dropped");
    }

    #[test]
    fn root_hex_round_trips() {
        let root = [0xABu8; 32];
        let hex = encode_root_hex(&root);
        assert_eq!(hex.len(), 64);
        assert_eq!(decode_root_hex(&hex).unwrap(), root);
        assert!(decode_root_hex("zz").is_err());
        assert!(decode_root_hex(&"x".repeat(64)).is_err());
    }
}
