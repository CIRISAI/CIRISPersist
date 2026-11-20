//! Federation-internal pipeline wire types (v0.7.5, CIRISPersist#33).
//!
//! Per FSD/POST_INGEST_FILTER_PIPELINE.md §4.3: the wire shape
//! between edge and persist. `BatchEnvelope` continues to flow
//! agent → edge unchanged; between edge and persist, a federation-
//! internal extension envelope wraps the (now scrubbed) BatchEnvelope
//! plus a typed sidecar carrying the pipeline outputs.
//!
//! # Embedded mode (FSD §4.4)
//!
//! For sovereign-mode + agent-embedded deployments without a
//! standalone edge, the `PipelineEnvelope` is constructed in-process
//! and never serialized to the wire. `edge_signature` is replaced
//! by `Engine`'s own signing identity (a self-signed sidecar marker
//! — recorded for audit but trivially verifiable). All other
//! invariants still apply.
//!
//! # Scope per release
//!
//! - **v0.7.5** (this module): wire-type shapes + serde round-trip.
//!   Persist can deserialize / construct a `PipelineEnvelope`; the
//!   HTTP ingest route (`POST /api/v1/pipeline/ingest`) and the
//!   verify-and-store path (`Engine::receive_pipeline_envelope`)
//!   land in subsequent releases tracked in CIRISPersist#33.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg(feature = "classify")]
use crate::pipeline::classify::ContentClassMatch;
#[cfg(feature = "extract")]
use crate::pipeline::extract::Features;
use crate::schema::BatchEnvelope;
#[cfg(feature = "secrets")]
use crate::secrets::types::EncryptedSecretRecord;

/// v62.0.0 (JSON-cut slice F, F0-cp5) — the edge's signature block on the
/// pipeline wire: ONE composite (ML-DSA-65-Ed25519) signature, base64
/// (standard). RULINGS: composite signatures only; the earlier
/// `{ed25519, ml_dsa_65}` pair is refused by name at the route
/// (`verify_component_signature`). Defined locally to keep the pipeline
/// track decoupled from the federation-consensus track.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeSignatureBlock {
    /// Base64 (standard) composite signature over the canonical bytes.
    pub composite: String,
    /// Caller-asserted wall-clock at signing time.
    pub signed_at: DateTime<Utc>,
}

/// Wire envelope from edge to persist. Contains the (scrubbed) agent
/// [`BatchEnvelope`] plus the typed sidecar produced by the pipeline.
/// Edge-signed; persist verifies before storing.
///
/// FSD §4.3 invariants enforced on `receive_pipeline_envelope()`:
///
/// 1. `pipeline_schema_version` is a known version (`"1.0"`).
/// 2. `edge_signature` (one composite) verifies via
///    `verify_composite_via_directory` under `edge_key_id`'s live
///    edition-2 key.
/// 3. The inner agent `BatchEnvelope` signature ALSO verifies
///    (defense-in-depth — edge could be compromised; the agent's
///    signature is the ground truth for content authenticity).
/// 4. `pii_scrubbed` MUST be `true` if
///    `pipeline_metadata.stages_executed` contains `"scrub"`.
/// 5. `sidecar.classifications.len()` MUST equal the inner envelope's
///    component count.
/// 6. Each `EncryptedSecretRecord.secret_uuid` MUST appear at least
///    once in the scrubbed envelope as `{SECRET:uuid:description}`.
/// 7. `pipeline_metadata.fields_modified` is non-decreasing across
///    replays of the same envelope (replay safety).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineEnvelope {
    /// Federation-internal schema version. Bumped when the sidecar
    /// shape changes. Persist rejects unknown versions on the ingest
    /// route. Current value: `"1.0"`.
    pub pipeline_schema_version: String,

    /// The agent's BatchEnvelope, post-scrub. Original agent signature
    /// (Ed25519 + ML-DSA-65) is preserved on the inner envelope.
    pub envelope: BatchEnvelope,

    /// Typed pipeline outputs.
    pub sidecar: PipelineSidecar,

    /// Edge's composite signature over canonical(envelope || sidecar).
    /// Persist verifies via `verify_composite_via_directory`.
    pub edge_signature: CompositeSignatureBlock,

    /// v62.0.0 (F0-cp5) — the edge's edition-2 identity-ref
    /// (`urn:ietf:params:oauth:ckt:sha-256:…`); its live `key:record` is
    /// read from the directory. A label is refused (`verify_not_identity_ref`).
    pub edge_key_id: String,
}

impl PipelineEnvelope {
    /// Current pipeline wire-schema version. Bumped when
    /// [`PipelineSidecar`] or [`PipelineMetadata`] shapes change in
    /// non-additive ways.
    pub const SCHEMA_VERSION_V1: &'static str = "1.0";
}

/// Typed pipeline outputs sidecar. One per [`PipelineEnvelope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSidecar {
    /// Per-component classifications. Outer vec is in
    /// `BatchEnvelope.events[*].components[*]` order across all
    /// events; inner vec is per-span-match within that component.
    /// Empty if the `classify` stage didn't run.
    #[cfg(feature = "classify")]
    pub classifications: Vec<Vec<ContentClassMatch>>,

    /// Typed features. `None` if the `extract` stage didn't run
    /// (e.g. edge built without the `extract` feature).
    #[cfg(feature = "extract")]
    pub features: Option<Features>,

    /// Encrypted secret records produced by the `encrypt_and_store`
    /// stage. Edge writes these to persist via the secrets API as
    /// a transactional batch alongside the trace. Each row's
    /// `secret_uuid` MUST appear in the scrubbed envelope as
    /// `{SECRET:uuid:description}` (FSD §4.3 invariant 6).
    #[cfg(feature = "secrets")]
    pub encrypted_secrets: Vec<EncryptedSecretRecord>,

    /// Pipeline metadata for observability + invariant enforcement.
    pub pipeline_metadata: PipelineMetadata,
}

/// Pipeline observability + invariant-enforcement metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineMetadata {
    /// Stages that ran in canonical order. Allowed values:
    /// `"classify"`, `"scrub"`, `"encrypt_and_store"`, `"extract"`.
    /// FSD §4.3 invariant 4: if `"scrub"` appears here,
    /// `pii_scrubbed` MUST be true.
    pub stages_executed: Vec<String>,

    /// Total fields modified (sum across components). FSD §4.3
    /// invariant 7: non-decreasing across replays.
    pub fields_modified: usize,

    /// Whether scrub mutated at least one component's payload.
    pub pii_scrubbed: bool,

    /// Number of secrets encrypted by the `encrypt_and_store` stage.
    /// MUST equal `sidecar.encrypted_secrets.len()`.
    pub secrets_encrypted: usize,

    /// Wall-clock pipeline latency (milliseconds, edge-measured).
    pub pipeline_duration_ms: u32,

    /// Edge build identifier — binary version, host, etc. Used by
    /// forensic analysts to correlate a specific edge build with a
    /// specific PipelineEnvelope when investigating drift.
    pub edge_build_id: String,
}

impl PipelineMetadata {
    /// Construct an empty metadata block — caller fills in the
    /// fields as each stage runs.
    pub fn new(edge_build_id: impl Into<String>) -> Self {
        Self {
            stages_executed: Vec::new(),
            fields_modified: 0,
            pii_scrubbed: false,
            secrets_encrypted: 0,
            pipeline_duration_ms: 0,
            edge_build_id: edge_build_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_constant_locked() {
        assert_eq!(PipelineEnvelope::SCHEMA_VERSION_V1, "1.0");
    }

    #[test]
    fn metadata_new_is_zeroed() {
        let m = PipelineMetadata::new("edge-test-build");
        assert!(m.stages_executed.is_empty());
        assert_eq!(m.fields_modified, 0);
        assert!(!m.pii_scrubbed);
        assert_eq!(m.secrets_encrypted, 0);
        assert_eq!(m.pipeline_duration_ms, 0);
        assert_eq!(m.edge_build_id, "edge-test-build");
    }

    #[test]
    fn composite_signature_block_serde_round_trip() {
        let sig = CompositeSignatureBlock {
            composite: "AAAA".to_string(),
            signed_at: chrono::Utc::now(),
        };
        let s = serde_json::to_string(&sig).unwrap();
        let back: CompositeSignatureBlock = serde_json::from_str(&s).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn metadata_serde_round_trip() {
        let m = PipelineMetadata {
            stages_executed: vec!["scrub".into(), "extract".into()],
            fields_modified: 3,
            pii_scrubbed: true,
            secrets_encrypted: 0,
            pipeline_duration_ms: 12,
            edge_build_id: "edge-v0.1.0-abcdef".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: PipelineMetadata = serde_json::from_str(&s).unwrap();
        assert_eq!(m.stages_executed, back.stages_executed);
        assert_eq!(m.fields_modified, back.fields_modified);
        assert_eq!(m.pii_scrubbed, back.pii_scrubbed);
    }
}
