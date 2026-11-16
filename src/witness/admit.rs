//! Verify-before-persist gate for the WholenessWitness corpus
//! (CEG 1.0-RC11 §19.1 / N3 / RC8; CIRISPersist#228 item 1 / #229 item 1).
//!
//! The §19.0 store-path rule (RC8 / §10.1.5.1.1): a federation-tier
//! object is PQC-verified **at ingest and BEFORE persistence**.
//! Store-then-quarantine is non-conformant. A witness missing or with an
//! invalid ML-DSA-65 half is REJECTED at this gate — nothing is written
//! (verify-before-mutation, AV-9).
//!
//! persist calls [`ciris_verify_core::substrate::verify_witness`] (the
//! hybrid gate + the WW-2 namespace guard + the optional leaf/root
//! recompute). It does NOT re-roll the Merkle / preimage / signature
//! check.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_verify_core::substrate::{
    self, compute_merkle_root, verify_witness, HolonomicError, WholenessWitness,
};

use crate::verify::sig19::{Sig19, Sig19Error};

use super::types::{encode_root_hex, StoredWitness, WitnessLeaf, WITNESS_VERSION_V1};

/// Rejection reasons for `put_wholeness_witness`. Stable `kind()` tokens
/// for telemetry / PyO3 sanitization (THREAT_MODEL.md AV-15), mirroring
/// the #225 fountain hard-cut error shape.
#[derive(Debug, thiserror::Error)]
pub enum WitnessAdmitError {
    /// The witness carried no ML-DSA-65 half (classical-only) — the
    /// §19.0 PQC-mandatory hard cut. No `require_hybrid:false` posture.
    #[error("wholeness witness classical-only / ML-DSA-65 half missing (PQC-mandatory) — §19.0 hard cut")]
    HybridRequired,

    /// The bound-hybrid signature failed to verify (a half mismatched, a
    /// malformed key/sig, or a bad length).
    #[error("wholeness witness hybrid verify failed: {0}")]
    HybridVerify(String),

    /// The witness named an empty namespace set, or a `self`/`anonymous`
    /// namespace (WW-2). Re-attributing deniable/self-private content to
    /// a stable peer_id is refused at the gate.
    #[error("wholeness witness namespace invalid (empty or names self/anonymous) — WW-2")]
    NamespaceInvalid,

    /// The signed `merkle_root` did not match a recompute over the
    /// disclosed leaves (the signer signed a root inconsistent with what
    /// it disclosed).
    #[error("wholeness witness root mismatch (signed root != recompute over disclosed leaves)")]
    RootMismatch,

    /// A producer key (Ed25519 or ML-DSA-65) was missing or not valid
    /// base64.
    #[error("wholeness witness malformed producer key: {0}")]
    MalformedKey(String),

    /// A signature half was not valid base64.
    #[error("wholeness witness malformed signature: {0}")]
    MalformedSignature(String),

    /// `witness_version` was not the supported V1 value.
    #[error("unsupported wholeness witness_version {got} (this build supports {supported})")]
    UnsupportedVersion {
        /// The version the caller sent.
        got: u16,
        /// The version this build supports.
        supported: u16,
    },

    /// A stored Merkle root column was not 64 hex chars (substrate
    /// corruption surfaced on read/compare).
    #[error("wholeness witness malformed merkle_root (not 64 hex chars)")]
    MalformedRoot,
}

impl WitnessAdmitError {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::HybridRequired => "witness_admit_hybrid_required",
            Self::HybridVerify(_) => "witness_admit_hybrid_verify",
            Self::NamespaceInvalid => "witness_admit_namespace_invalid",
            Self::RootMismatch => "witness_admit_root_mismatch",
            Self::MalformedKey(_) => "witness_admit_malformed_key",
            Self::MalformedSignature(_) => "witness_admit_malformed_signature",
            Self::UnsupportedVersion { .. } => "witness_admit_unsupported_version",
            Self::MalformedRoot => "witness_admit_malformed_root",
        }
    }
}

/// Map a verify-core [`HolonomicError`] onto the persist gate's error
/// shape, preserving the §19.0 classical-only → `hybrid_required` class.
fn map_substrate_error(err: HolonomicError) -> WitnessAdmitError {
    match err {
        HolonomicError::SignatureInvalid => {
            WitnessAdmitError::HybridVerify("composite signature invalid".to_owned())
        }
        HolonomicError::MalformedKeyOrSignature => {
            WitnessAdmitError::HybridVerify("malformed key or signature".to_owned())
        }
        HolonomicError::Invariant {
            reason: "ww_namespace",
        } => WitnessAdmitError::NamespaceInvalid,
        HolonomicError::Invariant {
            reason: "ww_root_mismatch",
        } => WitnessAdmitError::RootMismatch,
        HolonomicError::Invariant { reason } => WitnessAdmitError::HybridVerify(reason.to_owned()),
        // v38.7.0 — `HolonomicError` is `#[non_exhaustive]`: an unseen
        // variant is the CONSERVATIVE refusal class, never admissible.
        other => WitnessAdmitError::HybridVerify(format!(
            "unmapped verify HolonomicError variant (refusing conservatively): {other:?}"
        )),
    }
}

/// v62.0.0 — the earlier form's (CC 8.11.12) refusals onto the gate's shape.
fn map_sig19_error(err: Sig19Error) -> WitnessAdmitError {
    match err {
        Sig19Error::HybridRequired => WitnessAdmitError::HybridRequired,
        Sig19Error::EarlierInvalid => {
            WitnessAdmitError::HybridVerify("earlier-form signature invalid".to_owned())
        }
        Sig19Error::Malformed(m) => WitnessAdmitError::MalformedSignature(m),
        other => WitnessAdmitError::HybridVerify(other.to_string()),
    }
}

/// The WW-2 namespace guard and the disclosed-leaf recompute, as Verify's
/// `verify_witness` runs them around its signature check: for the EARLIER
/// form, whose signature Verify 23.1.0 cannot check.
fn earlier_form_structure(
    witness: &WholenessWitness,
    disclosed_leaves: Option<&[Vec<u8>]>,
) -> Result<(), WitnessAdmitError> {
    const FORBIDDEN: [&str; 2] = ["self", "anonymous"];
    if witness.claim_namespaces.is_empty()
        || witness.claim_namespaces.iter().any(|ns| {
            let lower = ns.to_ascii_lowercase();
            FORBIDDEN.iter().any(|m| lower.contains(m))
        })
    {
        return Err(WitnessAdmitError::NamespaceInvalid);
    }
    if let Some(leaves) = disclosed_leaves {
        if compute_merkle_root(leaves).map_err(map_substrate_error)? != witness.merkle_root {
            return Err(WitnessAdmitError::RootMismatch);
        }
    }
    Ok(())
}

/// WW-2 leaf filter (persist's responsibility, §19.1). Drop anonymous-tier
/// and `cohort_scope: self` leaves (and any leaf whose namespace itself
/// names self/anonymous), returning the surviving raw leaf-bytes set the
/// Merkle root is computed over. NEVER sweeps deniable/self-private rows
/// into a federating root.
#[must_use]
pub fn filter_witness_leaves(leaves: &[WitnessLeaf]) -> Vec<Vec<u8>> {
    leaves
        .iter()
        .filter(|l| l.ww2_eligible())
        .map(|l| l.leaf_bytes.clone())
        .collect()
}

/// The sorted, deduped set of WW-2-eligible namespaces the survivors
/// contribute — what `claim_namespaces` MUST be set to (it then provably
/// excludes self/anonymous).
#[must_use]
pub fn surviving_namespaces(leaves: &[WitnessLeaf]) -> Vec<String> {
    let mut ns: Vec<String> = leaves
        .iter()
        .filter(|l| l.ww2_eligible())
        .map(|l| l.claim_namespace.clone())
        .collect();
    ns.sort_unstable();
    ns.dedup();
    ns
}

/// Build a local WholenessWitness over `leaves`, applying the WW-2 filter
/// BEFORE computing the root (§19.1). Returns the verify-core
/// [`WholenessWitness`] shape (root over the survivors, namespaces drawn
/// from the survivors) ready to sign with the bound-hybrid discipline.
///
/// This is persist's "gather all CEG envelopes a peer holds" surface: it
/// is the single place the self/anonymous suppression is applied, so a
/// caller cannot accidentally federate deniable content.
#[must_use]
pub fn build_local_witness(
    peer_id: &str,
    epoch_id: u64,
    observed_at_unix_ms: u64,
    leaves: &[WitnessLeaf],
) -> WholenessWitness {
    let filtered = filter_witness_leaves(leaves);
    // v62.0.0 — Verify 23 refuses a repeated leaf (CC 6.1.1); the WW-2
    // survivors are deduplicated first (a set, CC 2.6.1.2), so a producer
    // never signs over a list Verify would refuse.
    let mut filtered = filtered;
    filtered.sort_unstable();
    filtered.dedup();
    let merkle_root = compute_merkle_root(&filtered).expect("deduplicated leaves have a root");
    let claim_namespaces = surviving_namespaces(leaves);
    WholenessWitness {
        peer_id: peer_id.to_owned(),
        epoch_id,
        claim_namespaces,
        merkle_root,
        leaf_count: filtered.len() as u32,
        observed_at_unix_ms,
        witness_version: WITNESS_VERSION_V1,
    }
}

/// Run the §19.1 verify-before-persist gate for a candidate witness, and
/// on `Ok` return the [`StoredWitness`] the backend may insert.
///
/// `signature` is the producer's signature in either FORM (v62.0.0): the
/// CC 2.6.1.7 composite, verified by Verify's `verify_witness` under the
/// composite key of the pinned pair; or the earlier bound-hybrid pair (CC
/// 8.11.12), verified here under the same WW-2 namespace guard and leaf
/// recompute. An earlier form with no ML-DSA-65 half, or a missing ML-DSA-65
/// pubkey, is the §19.0 hard cut ([`WitnessAdmitError::HybridRequired`]),
/// deterministic, before any signature math.
///
/// `disclosed_leaves`, when `Some`, are re-hashed and the resulting root
/// must equal the witness's `merkle_root`.
///
/// On `Err` NOTHING is written (verify-before-mutation, AV-9).
pub fn admit_witness(
    witness: &WholenessWitness,
    signature: &Sig19,
    pqc_key_id: &str,
    ed25519_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    disclosed_leaves: Option<&[Vec<u8>]>,
) -> Result<StoredWitness, WitnessAdmitError> {
    // (0) Version gate — this build only knows V1.
    if witness.witness_version != WITNESS_VERSION_V1 {
        return Err(WitnessAdmitError::UnsupportedVersion {
            got: witness.witness_version,
            supported: WITNESS_VERSION_V1,
        });
    }

    // (1) §19.0 PQC-mandatory hard cut, before any key or signature math.
    if let Sig19::Earlier { mldsa65, .. } = signature {
        if mldsa65.as_deref().is_none_or(<[u8]>::is_empty) {
            return Err(WitnessAdmitError::HybridRequired);
        }
    }
    let pqc_pubkey_b64 = match ml_dsa_65_pubkey_b64 {
        Some(s) if !s.is_empty() => s,
        _ => return Err(WitnessAdmitError::HybridRequired),
    };
    let ed_pubkey = BASE64
        .decode(ed25519_pubkey_b64)
        .map_err(|e| WitnessAdmitError::MalformedKey(format!("ed25519 pubkey: {e}")))?;
    let pqc_pubkey = BASE64
        .decode(pqc_pubkey_b64)
        .map_err(|e| WitnessAdmitError::MalformedKey(format!("ml_dsa_65 pubkey: {e}")))?;

    // (2) The §19.1 gate, by form.
    let preimage = witness.canonical_preimage();
    match signature {
        Sig19::Composite(sig) => verify_witness(
            witness,
            &preimage,
            sig,
            &crate::verify::sig19::composite_pubkey(&ed_pubkey, &pqc_pubkey),
            disclosed_leaves,
        )
        .map_err(map_substrate_error)?,
        Sig19::Earlier { .. } => {
            earlier_form_structure(witness, None)?;
            crate::verify::sig19::verify_sig19(&preimage, signature, &ed_pubkey, &pqc_pubkey)
                .map_err(map_sig19_error)?;
            earlier_form_structure(witness, disclosed_leaves)?;
        }
    }
    let (sig_stored, pqc_sig_stored) = match signature {
        Sig19::Composite(sig) => (BASE64.encode(sig), String::new()),
        Sig19::Earlier { ed25519, mldsa65 } => (
            BASE64.encode(ed25519),
            mldsa65
                .as_deref()
                .map(|m| BASE64.encode(m))
                .unwrap_or_default(),
        ),
    };

    // Admitted. Build the corpus row (no in-band `verified` flag, F-5).
    Ok(StoredWitness {
        peer_id: witness.peer_id.clone(),
        epoch_id: witness.epoch_id,
        claim_namespaces: witness.claim_namespaces.clone(),
        merkle_root_hex: encode_root_hex(&witness.merkle_root),
        leaf_count: witness.leaf_count,
        observed_at_unix_ms: witness.observed_at_unix_ms,
        witness_version: witness.witness_version,
        signature: sig_stored,
        signature_ml_dsa_65: pqc_sig_stored,
        pqc_key_id: pqc_key_id.to_owned(),
    })
}

/// v62.0.0 — sign a witness with the node's signer, in the form its ceremony
/// state writes (CC D4: earlier before the edition-2 ceremony row, composite
/// after), over the §19.1 canonical preimage [`admit_witness`] checks.
///
/// # Errors
/// The signer's error.
pub async fn sign_wholeness_witness(
    signer: &crate::signing::LocalSigner,
    witness: &WholenessWitness,
    ceremony: crate::federation::sth_form::CeremonyState,
) -> Result<Sig19, crate::signing::LocalSignerError> {
    crate::verify::sig19::sign_sig19(signer, &witness.canonical_preimage(), ceremony).await
}

/// Re-export so callers do not have to reach into verify-core for the
/// bound-hybrid signer helper shape.
pub use substrate::Preimage as WitnessPreimageBuilder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_local_witness_filters_self_and_anonymous() {
        let leaves = vec![
            WitnessLeaf {
                claim_namespace: "scores:medical".into(),
                cohort_scope: "community".into(),
                anonymous_tier: false,
                leaf_bytes: b"keep-1".to_vec(),
            },
            WitnessLeaf {
                claim_namespace: "notes:private".into(),
                cohort_scope: "self".into(),
                anonymous_tier: false,
                leaf_bytes: b"drop-self".to_vec(),
            },
            WitnessLeaf {
                claim_namespace: "blob:anon".into(),
                cohort_scope: "community".into(),
                anonymous_tier: true,
                leaf_bytes: b"drop-anon".to_vec(),
            },
            WitnessLeaf {
                claim_namespace: "scores:safety".into(),
                cohort_scope: "family".into(),
                anonymous_tier: false,
                leaf_bytes: b"keep-2".to_vec(),
            },
        ];
        let w = build_local_witness("peer-a", 3, 1000, &leaves);
        // Only the two eligible leaves entered the root.
        assert_eq!(w.leaf_count, 2);
        // Namespaces exclude self/anonymous.
        assert_eq!(w.claim_namespaces, vec!["scores:medical", "scores:safety"]);
        // The root equals a recompute over exactly the survivors.
        let expected = compute_merkle_root(&[b"keep-1".to_vec(), b"keep-2".to_vec()]).unwrap();
        assert_eq!(w.merkle_root, expected);
    }

    #[test]
    fn classical_only_is_hard_cut_rejected() {
        let w = build_local_witness(
            "p",
            1,
            1,
            &[WitnessLeaf {
                claim_namespace: "scores:medical".into(),
                cohort_scope: "community".into(),
                anonymous_tier: false,
                leaf_bytes: b"x".to_vec(),
            }],
        );
        // Empty PQC sig → hard cut, no signature math.
        let sig = Sig19::earlier_b64("AA==", Some("")).unwrap();
        let err = admit_witness(&w, &sig, "k", "AA==", Some("AA=="), None).unwrap_err();
        assert_eq!(err.kind(), "witness_admit_hybrid_required");
        // Absent PQC pubkey → hard cut.
        let sig = Sig19::earlier_b64("AA==", Some("AA==")).unwrap();
        let err = admit_witness(&w, &sig, "k", "AA==", None, None).unwrap_err();
        assert_eq!(err.kind(), "witness_admit_hybrid_required");
    }
}
