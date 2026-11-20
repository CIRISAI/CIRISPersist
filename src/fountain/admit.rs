//! Admission validation for `put_fountain_content` (CIRISPersist#227).
//!
//! **v62.0.0 (F0-cp6d; CC's answer) — fountain coding is NODE-LOCAL.** The
//! fountain was cut from the Constitution (rc10, the residue gone at rc17):
//! `FountainManifestV1` is not a CC object, and CC 6.1.3's list is closed. In
//! v62 a blob crosses nodes only by descriptor (`{digest, size}`) plus the
//! composite holding claim. So this door admits only THIS node's own
//! fountain coding of its own blobs (`pqc_key_id` = this node's identity),
//! unpinned (CC 1.13.4: no other node verifies it); a manifest produced by
//! another node is refused by name ([`FOUNTAIN_MANIFEST_NOT_CC_OBJECT`]).
//!
//! Verify-BEFORE-mutation (AV-9): every check here runs and must pass
//! before any backend insert:
//!
//! 1. the producer is this node ([`require_node_local_producer`]);
//! 2. structural invariants: `manifest_version == 1`,
//!    `symbol_hashes.len() == n_source + k_repair`, provided symbol_ids in
//!    range + no dups;
//! 3. each provided symbol's SHA-256 == `symbol_hashes[symbol_id]`. Any
//!    mismatch → reject the WHOLE admission.
//!
//! Pure / backend-agnostic so every backend shares one gate.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::types::{FountainManifestV1, FountainSymbolV1, MANIFEST_VERSION_V1};

/// Rejection reasons for `put_fountain_content`. Stable `kind()` tokens
/// for telemetry / PyO3 sanitization (THREAT_MODEL.md AV-15), mirroring
/// the trace-tier error tokens.
#[derive(Debug, thiserror::Error)]
pub enum FountainAdmitError {
    /// v62.0.0 (F0-cp6d) — the manifest was produced by another node (its
    /// `pqc_key_id` is not this node's identity), or this node has no
    /// identity to compare: fountain coding is node-local, and a fountain
    /// manifest is not a CC object. Refused by name, nothing written.
    #[error("fountain_manifest_not_cc_object: {0}")]
    NotCcObject(String),

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
            Self::NotCcObject(_) => FOUNTAIN_MANIFEST_NOT_CC_OBJECT,
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

/// The stable token of a refused peer manifest (a core-list spelling).
pub const FOUNTAIN_MANIFEST_NOT_CC_OBJECT: &str = "fountain_manifest_not_cc_object";

/// **The node-local rule.** `manifest` is admissible only as THIS node's own
/// fountain coding: its `pqc_key_id` (the producer) is `node_identity`, this
/// node's identity (`FederationDirectory::node_key_id`). A manifest produced
/// by another node, or one offered to a node with no identity, is refused
/// [`FOUNTAIN_MANIFEST_NOT_CC_OBJECT`]: no other node's fountain coding
/// crosses into this one (CC: a blob crosses by descriptor plus the composite
/// holding claim).
///
/// # Errors
/// [`FountainAdmitError::NotCcObject`].
pub fn require_node_local_producer(
    manifest: &FountainManifestV1,
    node_identity: Option<&str>,
) -> Result<(), FountainAdmitError> {
    match node_identity {
        Some(me) if manifest.pqc_key_id.trim() == me => Ok(()),
        Some(me) => Err(FountainAdmitError::NotCcObject(format!(
            "manifest {} was produced by {:?}, not this node ({me}): fountain coding is \
             node-local in v62 (not a CC object); a blob crosses nodes by descriptor and \
             the composite holding claim",
            manifest.content_id, manifest.pqc_key_id
        ))),
        None => Err(FountainAdmitError::NotCcObject(format!(
            "manifest {}: this node has no identity (node_key_id unset), so no manifest \
             can be its own",
            manifest.content_id
        ))),
    }
}

/// Run the full admission gate. On `Ok(())` every check passed and the
/// caller may insert. On `Err`, NOTHING must be written. Unpinned (CC
/// 1.13.4): the manifest's signature fields are this node's own bookkeeping
/// and are not verified.
///
/// # Errors
/// [`FountainAdmitError`].
pub fn check_admission(
    manifest: &FountainManifestV1,
    symbols: &[FountainSymbolV1],
    node_identity: Option<&str>,
) -> Result<(), FountainAdmitError> {
    require_node_local_producer(manifest, node_identity)?;
    if manifest.manifest_version != MANIFEST_VERSION_V1 {
        return Err(FountainAdmitError::UnsupportedManifestVersion {
            got: manifest.manifest_version,
            supported: MANIFEST_VERSION_V1,
        });
    }
    check_structure(manifest, symbols)
}

/// Steps (2)–(3) of the admission: the structural invariants and the
/// per-symbol SHA-256 auth against the signed `symbol_hashes`.
fn check_structure(
    manifest: &FountainManifestV1,
    symbols: &[FountainSymbolV1],
) -> Result<(), FountainAdmitError> {
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
