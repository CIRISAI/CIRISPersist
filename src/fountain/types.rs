//! `FountainContentV1` — the LOCKED wire/at-rest types (CIRISPersist#227).
//!
//! RATIFIED + LOCKED on CIRISPersist#227 / CIRISEdge#133. **Codec-free**:
//! no raptorq/rav1e/dav1d/opus types cross this boundary. persist is
//! store-and-evict-ONLY; the symbol bytes are opaque, and reconstruction
//! lives in the edge/consumer codec.
//!
//! Versioning rule: `V1` is frozen the moment persist ships its V084
//! migration (shipped migrations are immutable). Additive changes →
//! `FountainManifestV2` + a new migration; persist keeps the
//! `manifest_version` column and supports both. NEVER mutate V1.

use serde::{Deserialize, Serialize};

use crate::verify::canonical::Canonicalizer;
use crate::verify::Error as CanonError;

/// `manifest_version` value for the V1 contract.
pub const MANIFEST_VERSION_V1: u16 = 1;

/// Always-retained, NEVER-evicted signed header. One per
/// `(content_id, corpus_kind)`.
///
/// The producer HYBRID signature (`signature` + `signature_ml_dsa_65`)
/// binds the manifest + every symbol hash + the envelope as one unit,
/// over the canonical bytes from [`FountainManifestV1::canonical_value`]
/// (and [`canonical_bytes`](FountainManifestV1::canonical_bytes)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FountainManifestV1 {
    /// Stable id within the corpus (trace_id, blob hash, av-chunk id).
    pub content_id: String,
    /// `"trace" | "blob" | "av_chunk" | "attestation_evidence" | ...`.
    pub corpus_kind: String,
    /// `= 1` for the V1 contract.
    pub manifest_version: u16,
    /// `>= n_source` DISTINCT symbols present ⇒ lossless reconstruct.
    pub n_source: u32,
    /// Repair (FEC) symbols.
    pub k_repair: u32,
    /// Bytes/symbol (uniform; last source symbol padded).
    pub symbol_size: u32,
    /// Exact pre-pad byte length (the ratification add). The last source
    /// symbol is zero-padded to `symbol_size`; this lets the decoder
    /// strip the pad without a magic sentinel.
    pub original_content_length: u64,
    /// Producer's BLINKING_DOT floor; below this ⇒ `EnvelopeOnly`.
    pub min_viable_symbols: u32,
    /// Ordered SHA-256 (hex) of every symbol; index == symbol_id,
    /// `len == n_source + k_repair`. Lets ANY surviving subset (incl. a
    /// partial) be authenticated against the signed envelope.
    pub symbol_hashes: Vec<String>,
    /// The corpus's own small signed header, opaque to the store. For
    /// `"trace"` this IS the #225 hybrid-signed trace envelope.
    pub envelope: serde_json::Value,
    /// Producer Ed25519 signature (base64, classical half).
    pub signature: String,
    /// Producer ML-DSA-65 signature (base64) — REQUIRED (#225 hard cut;
    /// no classical-only).
    pub signature_ml_dsa_65: String,
    /// Producer's ML-DSA-65 key identifier (provenance).
    pub pqc_key_id: String,
}

impl FountainManifestV1 {
    /// The canonical JSON value the producer HYBRID signature covers, in
    /// the LOCKED field order: `(content_id, corpus_kind,
    /// manifest_version, n_source, k_repair, symbol_size,
    /// original_content_length, min_viable_symbols, symbol_hashes,
    /// envelope)`. The signature fields + `pqc_key_id` are NOT part of
    /// the signed bytes (a signature can't cover itself).
    ///
    /// We canonicalize over a `serde_json::Value` (not typed Rust) for
    /// the same reason the trace path does — canonicalization is over
    /// the bytes, and the [`Canonicalizer`] is the single byte-exact
    /// rule both persist and the producer agree on.
    pub fn canonical_value(&self) -> serde_json::Value {
        serde_json::json!({
            "content_id": self.content_id,
            "corpus_kind": self.corpus_kind,
            "manifest_version": self.manifest_version,
            "n_source": self.n_source,
            "k_repair": self.k_repair,
            "symbol_size": self.symbol_size,
            "original_content_length": self.original_content_length,
            "min_viable_symbols": self.min_viable_symbols,
            "symbol_hashes": self.symbol_hashes,
            "envelope": self.envelope,
        })
    }

    /// Canonical signing bytes — [`canonical_value`](Self::canonical_value)
    /// run through `canonicalizer`. The admit gate signs/verifies over
    /// exactly these bytes via [`crate::verify::verify_hybrid`].
    pub fn canonical_bytes<C>(&self, canonicalizer: &C) -> Result<Vec<u8>, CanonError>
    where
        C: Canonicalizer + ?Sized,
    {
        canonicalizer.canonicalize_value(&self.canonical_value())
    }

    /// Total symbol count the manifest declares: `n_source + k_repair`.
    /// Equals the required `symbol_hashes.len()`.
    pub fn total_symbols(&self) -> u64 {
        u64::from(self.n_source) + u64::from(self.k_repair)
    }
}

/// One fountain symbol. Evictable. `(content_id, symbol_id)` is the PK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FountainSymbolV1 {
    /// The manifest this symbol belongs to.
    pub content_id: String,
    /// `0..n_source` = source, `n_source..(n_source+k_repair)` = repair.
    pub symbol_id: u32,
    /// THE eviction key. Lower = keep longest. The producer folds BOTH
    /// (SVC `ChunkLayer.quality`, source-vs-repair position) into this
    /// one u8; persist evicts highest-priority-value first. One ORDER BY.
    pub retention_priority: u8,
    /// Opaque to persist; the codec/consumer reconstructs.
    pub symbol_bytes: Vec<u8>,
}

/// Typed degraded read — never silently-degraded bytes (substrate
/// honesty). persist reports symbol availability vs the manifest
/// thresholds; it does NOT claim a reconstruction probability (the
/// consumer's codec maps `present/n_source` → probability via the
/// RaptorQ overhead profile).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FountainContent {
    /// `present >= n_source` — lossless reconstruct (± FEC headroom).
    Full {
        /// The always-retained signed manifest.
        manifest: FountainManifestV1,
        /// All present symbols (each SHA-256-re-verified against the
        /// signed `symbol_hashes`).
        symbols: Vec<FountainSymbolV1>,
    },
    /// `min_viable_symbols <= present < n_source` — partial (the
    /// consumer's codec maps to a reconstruction probability).
    Partial {
        /// The always-retained signed manifest.
        manifest: FountainManifestV1,
        /// The surviving symbols (each SHA-256-re-verified).
        symbols: Vec<FountainSymbolV1>,
        /// How many symbols survived.
        present: u32,
    },
    /// `present < min_viable_symbols` (incl. 0) — "existed w/ signature
    /// X, content unavailable". The manifest always stays.
    EnvelopeOnly {
        /// The always-retained signed manifest.
        manifest: FountainManifestV1,
    },
}

impl FountainContent {
    /// Borrow the always-retained manifest, whatever the degradation
    /// state.
    pub fn manifest(&self) -> &FountainManifestV1 {
        match self {
            FountainContent::Full { manifest, .. }
            | FountainContent::Partial { manifest, .. }
            | FountainContent::EnvelopeOnly { manifest } => manifest,
        }
    }

    /// Count of symbols actually present in this read.
    pub fn present(&self) -> u32 {
        match self {
            FountainContent::Full { symbols, .. } => symbols.len() as u32,
            FountainContent::Partial { present, .. } => *present,
            FountainContent::EnvelopeOnly { .. } => 0,
        }
    }

    /// Classify a `present` symbol count against a manifest's thresholds.
    /// The single source of truth for the Full / Partial / EnvelopeOnly
    /// boundary — used by the read path and unit-tested directly.
    ///
    /// - `present >= n_source` ⇒ `Full`
    /// - `min_viable <= present < n_source` ⇒ `Partial`
    /// - `present < min_viable` (incl. 0) ⇒ `EnvelopeOnly`
    pub fn classify(present: u32, n_source: u32, min_viable: u32) -> FountainReadClass {
        if present >= n_source {
            FountainReadClass::Full
        } else if present >= min_viable {
            FountainReadClass::Partial
        } else {
            FountainReadClass::EnvelopeOnly
        }
    }
}

/// The degradation class a `present` count maps to — the discriminant
/// without the payload, so it's cheap to unit-test the boundary logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FountainReadClass {
    /// `present >= n_source`.
    Full,
    /// `min_viable <= present < n_source`.
    Partial,
    /// `present < min_viable`.
    EnvelopeOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_boundaries() {
        // n_source = 10, min_viable = 3.
        assert_eq!(
            FountainContent::classify(10, 10, 3),
            FountainReadClass::Full
        );
        assert_eq!(
            FountainContent::classify(11, 10, 3),
            FountainReadClass::Full
        );
        assert_eq!(
            FountainContent::classify(9, 10, 3),
            FountainReadClass::Partial
        );
        assert_eq!(
            FountainContent::classify(3, 10, 3),
            FountainReadClass::Partial
        );
        assert_eq!(
            FountainContent::classify(2, 10, 3),
            FountainReadClass::EnvelopeOnly
        );
        assert_eq!(
            FountainContent::classify(0, 10, 3),
            FountainReadClass::EnvelopeOnly
        );
    }

    #[test]
    fn canonical_value_excludes_signatures() {
        let m = FountainManifestV1 {
            content_id: "c1".into(),
            corpus_kind: "trace".into(),
            manifest_version: MANIFEST_VERSION_V1,
            n_source: 4,
            k_repair: 2,
            symbol_size: 8,
            original_content_length: 30,
            min_viable_symbols: 1,
            symbol_hashes: vec!["a".into(), "b".into()],
            envelope: serde_json::json!({"x": 1}),
            signature: "SIG".into(),
            signature_ml_dsa_65: "PQC".into(),
            pqc_key_id: "k".into(),
        };
        let v = m.canonical_value();
        let obj = v.as_object().unwrap();
        // Signed bytes cover the 10 locked fields, NOT the signature
        // fields or pqc_key_id.
        assert!(obj.contains_key("symbol_hashes"));
        assert!(obj.contains_key("original_content_length"));
        assert!(!obj.contains_key("signature"));
        assert!(!obj.contains_key("signature_ml_dsa_65"));
        assert!(!obj.contains_key("pqc_key_id"));
        assert_eq!(m.total_symbols(), 6);
    }
}

/// #227 — publisher-facing metadata for one HELD fountain-coded content item.
///
/// What a publisher gets from
/// [`list_held_fountain_content`](crate::store::Backend::list_held_fountain_content):
/// the manifest essentials + the **current degradation state**
/// (`held_symbols` vs `min_viable_symbols` ⇒ `recoverable`), so a publisher can
/// watch their content fade (#227 "fades but can't be falsified") without
/// fetching any symbol bytes. No symbol payload is returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FountainHeldMeta {
    /// The content's id (`content_manifest.content_id`).
    pub content_id: String,
    /// The corpus kind (`content_manifest.corpus_kind`).
    pub corpus_kind: String,
    /// The publisher's PQC key_id — the manifest signer
    /// (`content_manifest.pqc_key_id`); the filter key.
    pub pqc_key_id: String,
    /// Decoded length of the original content.
    pub original_content_length: u64,
    /// Source-symbol count `n`.
    pub n_source: u32,
    /// Repair-symbol count `k`.
    pub k_repair: u32,
    /// Minimum symbols needed to reconstruct (`min_viable_symbols`).
    pub min_viable_symbols: u32,
    /// Per-symbol size (bytes).
    pub symbol_size: u32,
    /// Symbols CURRENTLY retained for this content (post-eviction /
    /// degradation) — `COUNT(content_symbols)`.
    pub held_symbols: u32,
    /// `held_symbols >= min_viable_symbols` — is the content still decodable
    /// from what persist currently holds?
    pub recoverable: bool,
    /// Admission timestamp (ISO-8601 UTC, as stored in `admitted_at`).
    pub admitted_at: String,
}
