//! Admission validation for `put_fountain_content` (CIRISPersist#227).
//!
//! Verify-BEFORE-mutation (AV-9): every check here runs and must pass
//! before any backend insert. The order mirrors the trace-tier #225 hard
//! cut:
//!
//! 1. Manifest hybrid signature (`verify_hybrid`, [`HybridPolicy::Strict`])
//!    over the LOCKED canonical bytes — classical-only (missing
//!    ML-DSA-65) → REJECT, same shape as the trace path's
//!    `HybridRequired`.
//! 2. Structural invariants: `symbol_hashes.len() == n_source + k_repair`,
//!    `manifest_version == 1`, provided symbol_ids in range + no dups.
//! 3. Each provided symbol's SHA-256 == `symbol_hashes[symbol_id]`. Any
//!    mismatch → reject the WHOLE admission (a Tier-3 partial that isn't
//!    manifest-checked is unauthenticated bytes).
//!
//! Pure / backend-agnostic so all three backends share one gate.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::verify::canonical::Canonicalizer;
use crate::verify::{verify_hybrid, HybridPolicy};

use super::types::{FountainManifestV1, FountainSymbolV1, MANIFEST_VERSION_V1};

/// Rejection reasons for `put_fountain_content`. Stable `kind()` tokens
/// for telemetry / PyO3 sanitization (THREAT_MODEL.md AV-15), mirroring
/// the trace-tier error tokens.
#[derive(Debug, thiserror::Error)]
pub enum FountainAdmitError {
    /// The manifest carried no (or an empty) ML-DSA-65 signature, OR the
    /// hybrid verify rejected the hybrid-pending row under Strict — the
    /// #225 hard cut. No classical-only fountain manifests.
    #[error("fountain manifest classical-only / hybrid-pending rejected (Strict) — #225 hard cut")]
    HybridRequired,

    /// The manifest hybrid signature failed to verify (a half mismatched,
    /// a malformed PQC field, a bad length, etc.). Carries the verify
    /// error's stable token.
    #[error("fountain manifest hybrid verify failed: {0}")]
    HybridVerify(String),

    /// Canonicalizing the manifest's signed value failed.
    #[error("fountain manifest canonicalization failed: {0}")]
    Canonicalization(String),

    /// `manifest_version` was not the supported V1 value.
    #[error("unsupported fountain manifest_version {got} (this build supports {supported})")]
    UnsupportedManifestVersion {
        /// The version the caller sent.
        got: u16,
        /// The version this build supports.
        supported: u16,
    },

    /// `symbol_hashes.len() != n_source + k_repair`.
    #[error("symbol_hashes len {got} != n_source + k_repair ({expected})")]
    SymbolHashesLenMismatch {
        /// `symbol_hashes.len()`.
        got: usize,
        /// `n_source + k_repair`.
        expected: u64,
    },

    /// A provided symbol's `symbol_id` was `>= n_source + k_repair`.
    #[error("symbol_id {symbol_id} out of range (total {total})")]
    SymbolIdOutOfRange {
        /// The offending symbol_id.
        symbol_id: u32,
        /// `n_source + k_repair`.
        total: u64,
    },

    /// Two provided symbols shared a `symbol_id`.
    #[error("duplicate symbol_id {symbol_id} in the provided set")]
    DuplicateSymbolId {
        /// The duplicated symbol_id.
        symbol_id: u32,
    },

    /// A symbol's `content_id` didn't match the manifest's `content_id`.
    #[error("symbol content_id {symbol:?} != manifest content_id {manifest:?}")]
    SymbolContentIdMismatch {
        /// The symbol's content_id.
        symbol: String,
        /// The manifest's content_id.
        manifest: String,
    },

    /// A provided symbol's SHA-256 didn't match the signed
    /// `symbol_hashes[symbol_id]` (AV-9: verify-before-mutation).
    #[error("symbol {symbol_id} sha256 {got} != signed hash {expected}")]
    SymbolHashMismatch {
        /// The offending symbol_id.
        symbol_id: u32,
        /// SHA-256 (hex) persist computed over the provided bytes.
        got: String,
        /// The signed hash the manifest asserts.
        expected: String,
    },
}

impl FountainAdmitError {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::HybridRequired => "fountain_admit_hybrid_required",
            Self::HybridVerify(_) => "fountain_admit_hybrid_verify",
            Self::Canonicalization(_) => "fountain_admit_canonicalization",
            Self::UnsupportedManifestVersion { .. } => "fountain_admit_unsupported_version",
            Self::SymbolHashesLenMismatch { .. } => "fountain_admit_symbol_hashes_len",
            Self::SymbolIdOutOfRange { .. } => "fountain_admit_symbol_id_range",
            Self::DuplicateSymbolId { .. } => "fountain_admit_duplicate_symbol_id",
            Self::SymbolContentIdMismatch { .. } => "fountain_admit_symbol_content_id",
            Self::SymbolHashMismatch { .. } => "fountain_admit_symbol_hash",
        }
    }
}

/// Lowercase-hex SHA-256 of `bytes` — the on-the-wire `symbol_hashes`
/// shape (so producer + persist agree byte-for-byte).
pub fn symbol_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Run the full admission gate. On `Ok(())` every check passed and the
/// caller may insert. On `Err`, NOTHING must be written.
///
/// `ed25519_pubkey_b64` is the producer's Ed25519 verifying key (b64).
/// The producer's ML-DSA-65 pubkey rides the manifest envelope and the
/// caller resolves it; per the locked contract the manifest itself
/// carries `signature_ml_dsa_65` + `pqc_key_id` but NOT the PQC pubkey
/// as a top-level field — so the caller passes it in (typically read off
/// `manifest.envelope`, mirroring the trace path where the producer PQC
/// pubkey rides the trace envelope). Pass `ml_dsa_65_pubkey_b64 = None`
/// to force the hard-cut rejection deterministically.
pub fn check_admission<C>(
    manifest: &FountainManifestV1,
    symbols: &[FountainSymbolV1],
    canonicalizer: &C,
    ed25519_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
) -> Result<(), FountainAdmitError>
where
    C: Canonicalizer + ?Sized,
{
    // (0) Version gate — this build only knows V1.
    if manifest.manifest_version != MANIFEST_VERSION_V1 {
        return Err(FountainAdmitError::UnsupportedManifestVersion {
            got: manifest.manifest_version,
            supported: MANIFEST_VERSION_V1,
        });
    }

    // (1) Hybrid signature over the LOCKED canonical bytes. The #225 hard
    //     cut: a manifest carrying no ML-DSA-65 SIGNATURE is classical-only
    //     ⇒ REJECTED outright (`HybridRequired`), BEFORE any pubkey
    //     pairing. The PQC pubkey on the envelope is irrelevant to that
    //     determination — the load-bearing condition is the presence of
    //     the PQC signature half (mirrors the trace-tier gate, where
    //     `signature_ml_dsa_65 == None` is the rejection trigger). This
    //     also avoids `verify_hybrid`'s both-or-neither `PqcFieldsMustBeBoth`
    //     when a producer ships a PQC pubkey but no PQC sig.
    if manifest.signature_ml_dsa_65.is_empty() {
        return Err(FountainAdmitError::HybridRequired);
    }
    let canonical = manifest
        .canonical_bytes(canonicalizer)
        .map_err(|e| FountainAdmitError::Canonicalization(format!("{e}")))?;
    match verify_hybrid(
        &canonical,
        &manifest.signature,
        Some(manifest.signature_ml_dsa_65.as_str()),
        ed25519_pubkey_b64,
        ml_dsa_65_pubkey_b64,
        HybridPolicy::Strict,
        None,
    ) {
        Ok(_outcome) => {}
        Err(crate::verify::HybridVerifyError::HybridPendingRejected) => {
            return Err(FountainAdmitError::HybridRequired);
        }
        Err(e) => {
            return Err(FountainAdmitError::HybridVerify(e.kind().to_owned()));
        }
    }

    // (2) Structural invariants.
    let total = manifest.total_symbols();
    if manifest.symbol_hashes.len() as u64 != total {
        return Err(FountainAdmitError::SymbolHashesLenMismatch {
            got: manifest.symbol_hashes.len(),
            expected: total,
        });
    }

    let mut seen: HashSet<u32> = HashSet::with_capacity(symbols.len());
    for sym in symbols {
        if sym.content_id != manifest.content_id {
            return Err(FountainAdmitError::SymbolContentIdMismatch {
                symbol: sym.content_id.clone(),
                manifest: manifest.content_id.clone(),
            });
        }
        if u64::from(sym.symbol_id) >= total {
            return Err(FountainAdmitError::SymbolIdOutOfRange {
                symbol_id: sym.symbol_id,
                total,
            });
        }
        if !seen.insert(sym.symbol_id) {
            return Err(FountainAdmitError::DuplicateSymbolId {
                symbol_id: sym.symbol_id,
            });
        }

        // (3) Per-symbol hash auth: SHA-256 over the provided bytes MUST
        //     equal the signed symbol_hashes[symbol_id]. Mismatch → whole
        //     admission rejected (AV-9). The index is in-range by the
        //     check above and symbol_hashes.len() == total.
        let expected = &manifest.symbol_hashes[sym.symbol_id as usize];
        let got = symbol_sha256_hex(&sym.symbol_bytes);
        if &got != expected {
            return Err(FountainAdmitError::SymbolHashMismatch {
                symbol_id: sym.symbol_id,
                got,
                expected: expected.clone(),
            });
        }
    }

    Ok(())
}

/// Run [`check_admission`] resolving the producer pubkeys off the
/// manifest envelope by convention: `envelope.pubkey_ed25519` (REQUIRED,
/// string) + `envelope.pubkey_ml_dsa_65` (the PQC half; absent ⇒ the
/// hard-cut [`FountainAdmitError::HybridRequired`] rejection). Both
/// pubkeys are bound into the hybrid verify — a forged pubkey fails the
/// signature, so asserting them on the envelope cannot grant trust by
/// itself (same argument the V083 trace migration makes for the PQC
/// pubkey riding the trace envelope).
///
/// The single entry point the three backends call so the gate is
/// byte-identical across PG / SQLite / memory.
pub fn check_admission_via_envelope<C>(
    manifest: &FountainManifestV1,
    symbols: &[FountainSymbolV1],
    canonicalizer: &C,
) -> Result<(), FountainAdmitError>
where
    C: Canonicalizer + ?Sized,
{
    let ed_pubkey = manifest
        .envelope
        .get("pubkey_ed25519")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FountainAdmitError::HybridVerify("manifest envelope missing pubkey_ed25519".to_owned())
        })?;
    let pqc_pubkey = manifest
        .envelope
        .get("pubkey_ml_dsa_65")
        .and_then(|v| v.as_str());
    check_admission(manifest, symbols, canonicalizer, ed_pubkey, pqc_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_lowercase_64() {
        let h = symbol_sha256_hex(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(h.len(), 64);
    }
}
