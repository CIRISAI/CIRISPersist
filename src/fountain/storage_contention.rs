//! CC 6.1.5.2 §Q storage-contention — persist's Python-wheel surface over the
//! canonical verify-core shapes (CIRISPersist#356 / CIRISVerify#170).
//!
//! The signed shapes themselves live in
//! [`ciris_verify_core::holonomic::storage_contention`] (the canonical home for
//! every §19/§Q signed object). persist does NOT redefine the crypto — it wraps
//! it: serde **wire** structs that (de)serialize the JSON the PyO3 boundary
//! carries, plus `build` (sign a payload with the engine's local signer) and
//! `verify` (bound-hybrid verify at ingest) helpers. Same split as
//! [`crate::fountain::aggregation::AggregationMetaVerifyInputsV1`] wrapping the
//! verify-core `AggregationMetaV1`.
//!
//! These shapes are **verified-at-ingest, not stored** (CC 6.1.3 store-path):
//! there is no persist admit/put table for them — a consumer builds one to
//! advertise / verifies one it received. The pin-vs-revocation composition (the
//! §Q B6/N5 gate that couples a pinned budget with hard-delete eviction) is
//! tracked separately (CIRISPersist#356 follow-up) and does not gate this wheel
//! surface.

use serde::{Deserialize, Serialize};

use ciris_verify_core::holonomic::storage_contention::{
    verify_corpus_want_v1, verify_storage_budget_v1, CorpusWantV1, ScopeBudget, StorageBudgetV1,
    StorageContentionVerification,
};

/// Why a §Q wheel-surface call failed. `kind()` gives a stable telemetry token.
#[derive(Debug, thiserror::Error)]
pub enum StorageContentionError {
    /// The payload / wire JSON did not parse.
    #[error("storage-contention: malformed JSON ({0})")]
    MalformedJson(String),
    /// Structural validation failed (suppressed scope, reserve>budget, unsorted).
    #[error("storage-contention: structural validation failed ({0})")]
    Invalid(String),
    /// A base64 signature / pubkey field did not decode.
    #[error("storage-contention: malformed base64 ({0})")]
    MalformedBase64(&'static str),
    /// The bound-hybrid signature failed to verify (bad/absent classical or
    /// ML-DSA-65 half — PQC-mandatory).
    #[error("storage-contention: bound-hybrid signature did not verify (PQC-mandatory)")]
    SignatureFailed,
}

impl StorageContentionError {
    /// Stable string token for telemetry / structured logging.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::MalformedJson(_) => "storage_contention_malformed_json",
            Self::Invalid(_) => "storage_contention_invalid",
            Self::MalformedBase64(_) => "storage_contention_malformed_base64",
            Self::SignatureFailed => "storage_contention_signature_failed",
        }
    }
}

/// One `cohort_scope`'s allotment — wire mirror of verify-core [`ScopeBudget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeBudgetWire {
    /// The `cohort_scope` (`community` | `affiliations` | …; never self/family).
    pub cohort_scope: String,
    /// Total byte ceiling for this scope.
    pub budget_bytes: u64,
    /// Byte floor reserved for pinned corpus (MUST be ≤ `budget_bytes`).
    pub pin_reserve_bytes: u64,
}

/// The `StorageBudgetV1` payload (no signatures) — what a caller supplies to
/// [`build_storage_budget_v1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBudgetPayload {
    /// The owner node this budget binds.
    pub node_id: String,
    /// Epoch keying (CC 5.1).
    pub epoch_id: String,
    /// Monotonic revision (anti-rollback).
    pub revision: u64,
    /// Per-`cohort_scope` allotments (sorted + deduped by `cohort_scope`).
    pub scopes: Vec<ScopeBudgetWire>,
    /// Corpus `subject_kind`s the owner elects to pin (sorted + deduped).
    pub pinned_class: Vec<String>,
}

/// The signed `StorageBudgetV1` wire shape — payload + the bound-hybrid pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBudgetWire {
    /// The owner node this budget binds.
    pub node_id: String,
    /// Epoch keying (CC 5.1).
    pub epoch_id: String,
    /// Monotonic revision (anti-rollback).
    pub revision: u64,
    /// Per-`cohort_scope` allotments.
    pub scopes: Vec<ScopeBudgetWire>,
    /// Pinned `subject_kind`s.
    pub pinned_class: Vec<String>,
    /// Ed25519 signature over the CC 6.1.3 preimage, base64 standard.
    pub signature_ed25519_base64: String,
    /// ML-DSA-65 signature over `preimage ‖ ed25519_sig`, base64 standard.
    pub signature_ml_dsa_65_base64: String,
}

impl From<&ScopeBudgetWire> for ScopeBudget {
    fn from(s: &ScopeBudgetWire) -> Self {
        ScopeBudget {
            cohort_scope: s.cohort_scope.clone(),
            budget_bytes: s.budget_bytes,
            pin_reserve_bytes: s.pin_reserve_bytes,
        }
    }
}

impl StorageBudgetPayload {
    /// The verify-core payload (for preimage / validate).
    fn to_verify(&self) -> StorageBudgetV1 {
        StorageBudgetV1 {
            node_id: self.node_id.clone(),
            epoch_id: self.epoch_id.clone(),
            revision: self.revision,
            scopes: self.scopes.iter().map(ScopeBudget::from).collect(),
            pinned_class: self.pinned_class.clone(),
        }
    }
}

impl StorageBudgetWire {
    /// The verify-core payload (for preimage / verify).
    fn to_verify(&self) -> StorageBudgetV1 {
        StorageBudgetV1 {
            node_id: self.node_id.clone(),
            epoch_id: self.epoch_id.clone(),
            revision: self.revision,
            scopes: self.scopes.iter().map(ScopeBudget::from).collect(),
            pinned_class: self.pinned_class.clone(),
        }
    }

    /// `true` iff `self` supersedes `other` (same node, strictly-higher
    /// revision) — the §Q B3 anti-rollback rule.
    #[must_use]
    pub fn supersedes(&self, other: &StorageBudgetWire) -> bool {
        self.to_verify().supersedes(&other.to_verify())
    }
}

/// The `CorpusWantV1` payload (no signatures).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusWantPayload {
    /// The advertising peer.
    pub node_id: String,
    /// Epoch keying (CC 5.1).
    pub epoch_id: String,
    /// The scope this want draws budget from (never self/family).
    pub cohort_scope: String,
    /// Max single-object size this peer will accept.
    pub size_cap_bytes: u64,
    /// Advertised headroom in the scope.
    pub remaining_budget_bytes: u64,
    /// Content-addressed ids wanted (sorted + deduped).
    pub want: Vec<String>,
}

/// The signed `CorpusWantV1` wire shape — payload + the bound-hybrid pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusWantWire {
    /// The advertising peer.
    pub node_id: String,
    /// Epoch keying (CC 5.1).
    pub epoch_id: String,
    /// The scope this want draws budget from.
    pub cohort_scope: String,
    /// Max single-object size accepted.
    pub size_cap_bytes: u64,
    /// Advertised headroom.
    pub remaining_budget_bytes: u64,
    /// Content-addressed ids wanted (sorted + deduped).
    pub want: Vec<String>,
    /// Ed25519 signature over the CC 6.1.3 preimage, base64 standard.
    pub signature_ed25519_base64: String,
    /// ML-DSA-65 signature over `preimage ‖ ed25519_sig`, base64 standard.
    pub signature_ml_dsa_65_base64: String,
}

impl CorpusWantPayload {
    fn to_verify(&self) -> CorpusWantV1 {
        CorpusWantV1 {
            node_id: self.node_id.clone(),
            epoch_id: self.epoch_id.clone(),
            cohort_scope: self.cohort_scope.clone(),
            size_cap_bytes: self.size_cap_bytes,
            remaining_budget_bytes: self.remaining_budget_bytes,
            want: self.want.clone(),
        }
    }
}

impl CorpusWantWire {
    fn to_verify(&self) -> CorpusWantV1 {
        CorpusWantV1 {
            node_id: self.node_id.clone(),
            epoch_id: self.epoch_id.clone(),
            cohort_scope: self.cohort_scope.clone(),
            size_cap_bytes: self.size_cap_bytes,
            remaining_budget_bytes: self.remaining_budget_bytes,
            want: self.want.clone(),
        }
    }

    /// `true` iff a producer may push `content_id` of `object_bytes` against
    /// this want (B4 wanted-then-pulled: wanted AND within the size cap).
    #[must_use]
    pub fn admits(&self, content_id: &str, object_bytes: u64) -> bool {
        self.to_verify().admits(content_id, object_bytes)
    }
}

/// Parse + structurally-validate a `StorageBudgetPayload`, returning its CC
/// 6.1.3 signing preimage (the bytes the caller must bound-hybrid sign).
///
/// # Errors
/// [`StorageContentionError::MalformedJson`] / [`StorageContentionError::Invalid`].
pub fn storage_budget_preimage(payload_json: &str) -> Result<Vec<u8>, StorageContentionError> {
    let payload: StorageBudgetPayload = serde_json::from_str(payload_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    let v = payload.to_verify();
    v.validate()
        .map_err(|e| StorageContentionError::Invalid(e.to_string()))?;
    Ok(v.signing_preimage())
}

/// Parse + structurally-validate a `CorpusWantPayload`, returning its preimage.
///
/// # Errors
/// [`StorageContentionError::MalformedJson`] / [`StorageContentionError::Invalid`].
pub fn corpus_want_preimage(payload_json: &str) -> Result<Vec<u8>, StorageContentionError> {
    let payload: CorpusWantPayload = serde_json::from_str(payload_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    let v = payload.to_verify();
    v.validate()
        .map_err(|e| StorageContentionError::Invalid(e.to_string()))?;
    Ok(v.signing_preimage())
}

/// Assemble a signed [`StorageBudgetWire`] JSON from a payload + the two
/// base64-encoded signatures. Re-validates before assembling (never emit a
/// malformed shape).
///
/// # Errors
/// [`StorageContentionError`] on parse / validation failure.
pub fn assemble_storage_budget_wire(
    payload_json: &str,
    sig_ed25519_base64: String,
    sig_ml_dsa_65_base64: String,
) -> Result<String, StorageContentionError> {
    let payload: StorageBudgetPayload = serde_json::from_str(payload_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    payload
        .to_verify()
        .validate()
        .map_err(|e| StorageContentionError::Invalid(e.to_string()))?;
    let wire = StorageBudgetWire {
        node_id: payload.node_id,
        epoch_id: payload.epoch_id,
        revision: payload.revision,
        scopes: payload.scopes,
        pinned_class: payload.pinned_class,
        signature_ed25519_base64: sig_ed25519_base64,
        signature_ml_dsa_65_base64: sig_ml_dsa_65_base64,
    };
    serde_json::to_string(&wire).map_err(|e| StorageContentionError::MalformedJson(e.to_string()))
}

/// Assemble a signed [`CorpusWantWire`] JSON from a payload + base64 signatures.
///
/// # Errors
/// [`StorageContentionError`] on parse / validation failure.
pub fn assemble_corpus_want_wire(
    payload_json: &str,
    sig_ed25519_base64: String,
    sig_ml_dsa_65_base64: String,
) -> Result<String, StorageContentionError> {
    let payload: CorpusWantPayload = serde_json::from_str(payload_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    payload
        .to_verify()
        .validate()
        .map_err(|e| StorageContentionError::Invalid(e.to_string()))?;
    let wire = CorpusWantWire {
        node_id: payload.node_id,
        epoch_id: payload.epoch_id,
        cohort_scope: payload.cohort_scope,
        size_cap_bytes: payload.size_cap_bytes,
        remaining_budget_bytes: payload.remaining_budget_bytes,
        want: payload.want,
        signature_ed25519_base64: sig_ed25519_base64,
        signature_ml_dsa_65_base64: sig_ml_dsa_65_base64,
    };
    serde_json::to_string(&wire).map_err(|e| StorageContentionError::MalformedJson(e.to_string()))
}

/// Verify a signed [`StorageBudgetWire`] JSON at ingest (structure + PQC-mandatory
/// bound-hybrid signature) against the aggregator's raw pubkeys (base64).
///
/// # Errors
/// [`StorageContentionError`] on malformed input, structural invalidity, or a
/// failed signature.
pub fn verify_storage_budget_wire(
    wire_json: &str,
    ed25519_pubkey_base64: &str,
    ml_dsa_65_pubkey_base64: &str,
) -> Result<(), StorageContentionError> {
    let wire: StorageBudgetWire = serde_json::from_str(wire_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    let (ed_pub, mldsa_pub) = decode_pubkeys(ed25519_pubkey_base64, ml_dsa_65_pubkey_base64)?;
    let (sig_ed, sig_mldsa) = decode_sigs(
        &wire.signature_ed25519_base64,
        &wire.signature_ml_dsa_65_base64,
    )?;
    match verify_storage_budget_v1(&wire.to_verify(), &sig_ed, &sig_mldsa, &ed_pub, &mldsa_pub) {
        StorageContentionVerification::HybridVerified => Ok(()),
        StorageContentionVerification::Invalid(e) => {
            Err(StorageContentionError::Invalid(e.to_string()))
        }
        StorageContentionVerification::SignatureFailed => {
            Err(StorageContentionError::SignatureFailed)
        }
    }
}

/// Verify a signed [`CorpusWantWire`] JSON at ingest.
///
/// # Errors
/// [`StorageContentionError`] on malformed input, structural invalidity, or a
/// failed signature.
pub fn verify_corpus_want_wire(
    wire_json: &str,
    ed25519_pubkey_base64: &str,
    ml_dsa_65_pubkey_base64: &str,
) -> Result<(), StorageContentionError> {
    let wire: CorpusWantWire = serde_json::from_str(wire_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    let (ed_pub, mldsa_pub) = decode_pubkeys(ed25519_pubkey_base64, ml_dsa_65_pubkey_base64)?;
    let (sig_ed, sig_mldsa) = decode_sigs(
        &wire.signature_ed25519_base64,
        &wire.signature_ml_dsa_65_base64,
    )?;
    match verify_corpus_want_v1(&wire.to_verify(), &sig_ed, &sig_mldsa, &ed_pub, &mldsa_pub) {
        StorageContentionVerification::HybridVerified => Ok(()),
        StorageContentionVerification::Invalid(e) => {
            Err(StorageContentionError::Invalid(e.to_string()))
        }
        StorageContentionVerification::SignatureFailed => {
            Err(StorageContentionError::SignatureFailed)
        }
    }
}

/// Anti-rollback check between two signed budget wires (JSON): does `candidate`
/// supersede `existing`?
///
/// # Errors
/// [`StorageContentionError::MalformedJson`] if either does not parse.
pub fn storage_budget_supersedes(
    candidate_json: &str,
    existing_json: &str,
) -> Result<bool, StorageContentionError> {
    let candidate: StorageBudgetWire = serde_json::from_str(candidate_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    let existing: StorageBudgetWire = serde_json::from_str(existing_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    Ok(candidate.supersedes(&existing))
}

/// B4 admission check: may a producer push `content_id` of `object_bytes`
/// against this signed want (JSON)?
///
/// # Errors
/// [`StorageContentionError::MalformedJson`] if the wire does not parse.
pub fn corpus_want_admits(
    wire_json: &str,
    content_id: &str,
    object_bytes: u64,
) -> Result<bool, StorageContentionError> {
    let wire: CorpusWantWire = serde_json::from_str(wire_json)
        .map_err(|e| StorageContentionError::MalformedJson(e.to_string()))?;
    Ok(wire.admits(content_id, object_bytes))
}

fn b64_decode(s: &str, what: &'static str) -> Result<Vec<u8>, StorageContentionError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    B64.decode(s)
        .map_err(|_| StorageContentionError::MalformedBase64(what))
}

fn decode_pubkeys(
    ed_b64: &str,
    mldsa_b64: &str,
) -> Result<(Vec<u8>, Vec<u8>), StorageContentionError> {
    Ok((
        b64_decode(ed_b64, "ed25519_pubkey")?,
        b64_decode(mldsa_b64, "ml_dsa_65_pubkey")?,
    ))
}

fn decode_sigs(
    ed_b64: &str,
    mldsa_b64: &str,
) -> Result<(Vec<u8>, Vec<u8>), StorageContentionError> {
    Ok((
        b64_decode(ed_b64, "sig_ed25519")?,
        b64_decode(mldsa_b64, "sig_ml_dsa_65")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    struct Id {
        ed: Ed25519Signer,
        pqc: MlDsa65Signer,
    }
    fn id() -> Id {
        Id {
            ed: Ed25519Signer::random().unwrap(),
            pqc: MlDsa65Signer::new().unwrap(),
        }
    }
    fn pubs(id: &Id) -> (String, String) {
        (
            B64.encode(id.ed.public_key().unwrap()),
            B64.encode(id.pqc.public_key().unwrap()),
        )
    }
    /// Mirror the engine's bound-hybrid sign over a preimage.
    fn sign(id: &Id, preimage: &[u8]) -> (String, String) {
        let ed_sig = id.ed.sign(preimage).unwrap();
        let mut bound = preimage.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = id.pqc.sign(&bound).unwrap();
        (B64.encode(&ed_sig), B64.encode(&pqc_sig))
    }

    const BUDGET_PAYLOAD: &str = r#"{"node_id":"n1","epoch_id":"e1","revision":3,
        "scopes":[{"cohort_scope":"affiliations","budget_bytes":1000,"pin_reserve_bytes":200},
                  {"cohort_scope":"community","budget_bytes":2000,"pin_reserve_bytes":0}],
        "pinned_class":["av_chunk","trace"]}"#;
    const WANT_PAYLOAD: &str = r#"{"node_id":"n1","epoch_id":"e1","cohort_scope":"community",
        "size_cap_bytes":4096,"remaining_budget_bytes":1800,"want":["cid-a","cid-b"]}"#;

    fn build_budget(id: &Id, payload: &str) -> String {
        let (ed, pqc) = sign(id, &storage_budget_preimage(payload).unwrap());
        assemble_storage_budget_wire(payload, ed, pqc).unwrap()
    }

    #[test]
    fn budget_build_verify_round_trip_and_tamper() {
        let id = id();
        let (ed_pub, pqc_pub) = pubs(&id);
        let wire = build_budget(&id, BUDGET_PAYLOAD);
        assert!(verify_storage_budget_wire(&wire, &ed_pub, &pqc_pub).is_ok());

        // Tamper the revision → preimage diverges → signature fails.
        let mut w: serde_json::Value = serde_json::from_str(&wire).unwrap();
        w["revision"] = serde_json::json!(99);
        assert!(matches!(
            verify_storage_budget_wire(&w.to_string(), &ed_pub, &pqc_pub),
            Err(StorageContentionError::SignatureFailed)
        ));
    }

    #[test]
    fn budget_pqc_mandatory() {
        let id = id();
        let (ed_pub, pqc_pub) = pubs(&id);
        let wire = build_budget(&id, BUDGET_PAYLOAD);
        let mut w: serde_json::Value = serde_json::from_str(&wire).unwrap();
        w["signature_ml_dsa_65_base64"] = serde_json::json!("");
        assert!(matches!(
            verify_storage_budget_wire(&w.to_string(), &ed_pub, &pqc_pub),
            Err(StorageContentionError::SignatureFailed)
        ));
    }

    #[test]
    fn budget_suppressed_scope_and_reserve_rejected_at_preimage() {
        let bad_scope = r#"{"node_id":"n1","epoch_id":"e1","revision":1,
            "scopes":[{"cohort_scope":"self","budget_bytes":1,"pin_reserve_bytes":0}],"pinned_class":[]}"#;
        assert!(matches!(
            storage_budget_preimage(bad_scope),
            Err(StorageContentionError::Invalid(_))
        ));
        let bad_reserve = r#"{"node_id":"n1","epoch_id":"e1","revision":1,
            "scopes":[{"cohort_scope":"community","budget_bytes":10,"pin_reserve_bytes":11}],"pinned_class":[]}"#;
        assert!(matches!(
            storage_budget_preimage(bad_reserve),
            Err(StorageContentionError::Invalid(_))
        ));
    }

    #[test]
    fn budget_anti_rollback_supersedes() {
        let id = id();
        let lo = build_budget(&id, BUDGET_PAYLOAD); // revision 3
        let mut p: serde_json::Value = serde_json::from_str(BUDGET_PAYLOAD).unwrap();
        p["revision"] = serde_json::json!(5);
        let hi = build_budget(&id, &p.to_string());
        assert!(storage_budget_supersedes(&hi, &lo).unwrap());
        assert!(!storage_budget_supersedes(&lo, &hi).unwrap());
    }

    #[test]
    fn want_build_verify_and_admits() {
        let id = id();
        let (ed_pub, pqc_pub) = pubs(&id);
        let (ed, pqc) = sign(&id, &corpus_want_preimage(WANT_PAYLOAD).unwrap());
        let wire = assemble_corpus_want_wire(WANT_PAYLOAD, ed, pqc).unwrap();
        assert!(verify_corpus_want_wire(&wire, &ed_pub, &pqc_pub).is_ok());
        assert!(corpus_want_admits(&wire, "cid-a", 4096).unwrap());
        assert!(!corpus_want_admits(&wire, "cid-a", 4097).unwrap()); // over cap
        assert!(!corpus_want_admits(&wire, "cid-z", 1).unwrap()); // not wanted
    }

    #[test]
    fn malformed_json_raises_not_false() {
        assert!(matches!(
            verify_storage_budget_wire("{not json", "", ""),
            Err(StorageContentionError::MalformedJson(_))
        ));
    }
}
