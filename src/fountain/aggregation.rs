//! §19.7 inter-object aggregation — the **forever-memory** storage half
//! (CEG 1.0-RC12 §19.7 / CIRISPersist#230, v8.3.0).
//!
//! §19.7 reframes retirement as ONE pressure-driven monotonic fidelity
//! descent toward a **noise floor** (the individual-recoverability
//! boundary). Two mechanical degradation operators ride that one axis:
//!
//!   * **Operator 1 — intra-object fade** (already shipped, v8.0–8.2):
//!     drop symbols by `retention_priority` down to a per-tier keep-count
//!     ([`super::eviction::FountainTier`]); the manifest survives.
//!   * **Operator 2 — inter-object aggregation** (THIS cut, the substantive
//!     §19.7 addition): N source items → 1 composite (codec-side tile /
//!     downsample / statistical composite), recursed into a **mipmap
//!     pyramid** → **O(log T)** forever-memory. Each source's contribution
//!     sits BELOW the noise floor (individually unrecoverable), but the
//!     collective **blur** (the composite) persists forever — **descent
//!     never terminates at zero**.
//!
//! # persist is codec-free; this is the OPAQUE-bytes firewall
//! The N→1 resampling compute is codec-side (edge — CIRISEdge#133/#134);
//! persist stores + orchestrates. The composite **is** a
//! [`super::types::FountainManifestV1`] (the edge fountain-encodes it like
//! any content, with `corpus_kind = "aggregate:<source_corpus_kind>"`), so
//! it rides the EXISTING #225 hybrid-manifest admit gate
//! ([`super::admit::check_admission_via_envelope`]) unchanged.
//!
//! **The §19.7 aggregation WIRE SHAPE is NOT yet frozen** (ratification is
//! in parallel: CIRISRegistry §19.7 absorption extending #85, CIRISVerify
//! §19.7 verifiers ~v5.10.0, an edge ratification issue). So persist
//! stores the aggregation wire payload as **OPAQUE bytes**
//! ([`AggregationMetaV1::aggregation_meta`]) plus only the few navigation
//! scalars persist itself needs (level / fan-in / source corpus /
//! commitment). persist NEVER parses `aggregation_meta`. This keeps the
//! immutable V086 migration robust to whatever the §19.7 contract
//! finalizes — the wire-churn firewall.
//!
//! # Freeze-gated follow-ons (NOT in this cut — see CHANGELOG / #230)
//!   * Field-level / byte-exact verification of `aggregation_meta` and the
//!     `member_commitment` Merkle root — lands with the §19.7 verifiers
//!     (CIRISVerify v5.10.0). persist STORES the commitment + opaque meta;
//!     it does NOT verify them here.
//!   * Mapping persist's tiers + hard_delete onto a verify-exposed
//!     `EjectionVerdict` — v5.9.0 exposes only `RetentionDecision`. Until
//!     verify exposes it, persist uses its OWN internal [`EjectionVerdict`]
//!     framing (below).

use serde::{Deserialize, Serialize};

/// `corpus_kind` prefix for an aggregate composite: a composite folding
/// `"trace"` sources has `corpus_kind = "aggregate:trace"`.
pub const AGGREGATE_CORPUS_PREFIX: &str = "aggregate:";

/// Compose the composite's `corpus_kind` from the folded sources'
/// `source_corpus_kind` (`"trace"` → `"aggregate:trace"`). Recursion
/// nests (`"aggregate:trace"` → `"aggregate:aggregate:trace"`).
pub fn aggregate_corpus_kind(source_corpus_kind: &str) -> String {
    format!("{AGGREGATE_CORPUS_PREFIX}{source_corpus_kind}")
}

/// The §19.7 aggregation provenance persist records for a composite — the
/// few navigation scalars persist needs PLUS the opaque wire payload.
///
/// One record per composite (keyed by the composite's
/// [`aggregate_content_id`](Self::aggregate_content_id) =
/// `FountainManifestV1::content_id`). persist STORES `member_commitment`
/// and `aggregation_meta`; it does NOT verify them this cut (§19.7-freeze-
/// gated — see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationMetaV1 {
    /// The composite's `FountainContentV1` content_id (PK; one aggregation
    /// record per composite). The composite's `corpus_kind` is
    /// `"aggregate:<source_corpus_kind>"`.
    pub aggregate_content_id: String,
    /// What was folded: `"trace" | "blob" | "av_chunk" | "aggregate:..."`
    /// (for recursion).
    pub source_corpus_kind: String,
    /// Pyramid level: `0` = individual; level `L` folds `N` level-`(L-1)`
    /// items.
    pub aggregation_level: u64,
    /// `N` — the N→1 fan-in ratio at this fold.
    pub fan_in: u64,
    /// Merkle root (hex) over the folded source content_ids — proves
    /// membership WITHOUT storing N ids and WITHOUT making any source
    /// individually recoverable. persist STORES it; it does NOT verify it
    /// this cut (§19.7-freeze-gated, CIRISVerify v5.10.0).
    pub member_commitment: String,
    /// **OPAQUE** §19.7 aggregation wire payload. persist NEVER parses
    /// this — it is stored byte-for-byte (BYTEA on PG / BLOB on SQLite).
    /// This is the wire-churn firewall: whatever the §19.7 contract
    /// finalizes lives here without a migration change.
    #[serde(with = "crate::fountain::aggregation::meta_bytes_b64")]
    pub aggregation_meta: Vec<u8>,
}

/// The stored aggregation record (read shape) — [`AggregationMetaV1`] plus
/// persist's `aggregated_at_unix_ms` stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationRecordV1 {
    /// See [`AggregationMetaV1::aggregate_content_id`].
    pub aggregate_content_id: String,
    /// See [`AggregationMetaV1::source_corpus_kind`].
    pub source_corpus_kind: String,
    /// See [`AggregationMetaV1::aggregation_level`].
    pub aggregation_level: u64,
    /// See [`AggregationMetaV1::fan_in`].
    pub fan_in: u64,
    /// See [`AggregationMetaV1::member_commitment`].
    pub member_commitment: String,
    /// See [`AggregationMetaV1::aggregation_meta`] — opaque bytes.
    #[serde(with = "crate::fountain::aggregation::meta_bytes_b64")]
    pub aggregation_meta: Vec<u8>,
    /// When persist recorded the fold (epoch ms).
    pub aggregated_at_unix_ms: i64,
}

/// base64 (de)serialization for the opaque `aggregation_meta` over the
/// JSON-over-FFI boundary. The bytes stay opaque — base64 is only the
/// JSON-safe transport encoding (raw bytes can be non-UTF-8).
pub(crate) mod meta_bytes_b64 {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b64 = String::deserialize(d)?;
        BASE64
            .decode(b64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// §19.7 noise-floor framing (persist-INTERNAL until CIRISVerify exposes
/// its own `EjectionVerdict`; v5.9.0 exposes only `RetentionDecision`).
///
/// §19.7 unifies persist's discrete eviction tiers + hard_delete as STOPS
/// on the ONE pressure-driven descent axis toward the noise floor (the
/// individual-recoverability boundary). This enum names the verdict shape
/// §19.3/§19.7 describe so persist's descent orchestration can speak it
/// internally; when verify exposes the canonical type, persist maps onto
/// it (the residual tracked in #230). It does NOT depend on a verify
/// `EjectionVerdict` — there is none in v5.9.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EjectionVerdict {
    /// Above the floor / no pressure — retain at the current fidelity.
    Keep,
    /// A downward step on the descent axis — degrade to a tighter tier
    /// (operator-1 intra-object fade) via
    /// [`super::eviction::FountainTier`].
    EjectToTier(super::eviction::FountainTier),
    /// Forced below the floor — drop every still-recoverable symbol
    /// (`evict_fountain_content_hard_delete`). The manifest survives as
    /// `EnvelopeOnly` provenance; the collective gist (any composite this
    /// source folded into) is untouched — descent never terminates at zero.
    EjectHardDelete,
}

impl EjectionVerdict {
    /// Stable string-token (telemetry / logs).
    pub fn label(&self) -> &'static str {
        match self {
            EjectionVerdict::Keep => "keep",
            EjectionVerdict::EjectToTier(_) => "eject_to_tier",
            EjectionVerdict::EjectHardDelete => "eject_hard_delete",
        }
    }

    /// Map a descent target onto the verdict. The §19.7 descent
    /// orchestration uses this to pick the operator for one downward step:
    /// `None` ⇒ forced below the floor (`EjectHardDelete`); `Some(tier)` ⇒
    /// step to that tier (`EjectToTier`); `Full` is the no-pressure
    /// `Keep`-equivalent (full fidelity retained, nothing dropped).
    pub fn for_target_tier(tier: Option<super::eviction::FountainTier>) -> EjectionVerdict {
        match tier {
            None => EjectionVerdict::EjectHardDelete,
            Some(super::eviction::FountainTier::Full) => EjectionVerdict::Keep,
            Some(t) => EjectionVerdict::EjectToTier(t),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_corpus_kind_prefixes_and_nests() {
        assert_eq!(aggregate_corpus_kind("trace"), "aggregate:trace");
        assert_eq!(
            aggregate_corpus_kind("aggregate:trace"),
            "aggregate:aggregate:trace"
        );
    }

    #[test]
    fn opaque_meta_roundtrips_non_utf8_via_b64() {
        // Arbitrary non-JSON / non-UTF-8 bytes — persist never parses it.
        let raw = vec![0x00u8, 0xFF, 0x01, 0xFE, 0x80, 0x7F];
        let m = AggregationMetaV1 {
            aggregate_content_id: "agg-1".into(),
            source_corpus_kind: "trace".into(),
            aggregation_level: 1,
            fan_in: 3,
            member_commitment: "deadbeef".into(),
            aggregation_meta: raw.clone(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: AggregationMetaV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(back.aggregation_meta, raw, "opaque bytes round-trip exact");
        assert_eq!(back, m);
    }

    #[test]
    fn ejection_verdict_target_mapping() {
        use super::super::eviction::FountainTier;
        assert_eq!(
            EjectionVerdict::for_target_tier(None),
            EjectionVerdict::EjectHardDelete
        );
        assert_eq!(
            EjectionVerdict::for_target_tier(Some(FountainTier::Full)),
            EjectionVerdict::Keep
        );
        assert_eq!(
            EjectionVerdict::for_target_tier(Some(FountainTier::T3)),
            EjectionVerdict::EjectToTier(FountainTier::T3)
        );
        assert_eq!(
            EjectionVerdict::EjectHardDelete.label(),
            "eject_hard_delete"
        );
    }
}
