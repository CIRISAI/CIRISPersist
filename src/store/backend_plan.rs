//! v61 (CIRISPersist#934, S4a) — **the `Backend` trait's gated doors,
//! decided once**: the two trace erasures and the two fountain writes.
//!
//! `delete_traces_for_agent` and `delete_traces_for_agent_id_hash` were
//! written twice each, in `store/{sqlite,postgres}.rs`: the same attester
//! gate, the same pre-v57 detection rehome, the same `plan_store_erasure`
//! read before the transaction, and the same "announce only when something
//! moved" rule. `put_fountain_content` and `put_aggregated_tier` were the
//! same admission gate (and, for the tier, its second gate) in front of one
//! manifest-and-symbols insert written four times. Each door is now one
//! function here; a backend implements [`BackendStore`]: ONE erasure
//! transaction and ONE content transaction, scoped by what the plan hands
//! them. It decides nothing.
//!
//! # Which instant each plan reads
//!
//! An erasure's one clock read (`received_at`) is the rehome stamp, the
//! erasure plan's instant, the tombstone and the audit row's instant. A
//! fountain write stamps `admitted_at` with its one clock read on sqlite
//! (postgres keeps the column's database default).

use chrono::{DateTime, Utc};

use super::types::{DeleteSummary, ErasureSummary};
use super::Error;
use crate::federation::attestation_admit::{self, AttestationStore, HardCaseAttester};
use crate::federation::hard_case::{self, HardCaseEvent, TraceErasureCounts};
use crate::federation::subject_erasure::{self, ErasurePlan};
use crate::fountain::{AggregationMetaV1, FountainManifestV1, FountainSymbolV1};

/// Which erasure the door asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TraceErasureScope {
    /// `delete_traces_for_agent`: the traces one signing key signed (the
    /// per-key DSAR), and with `include_federation_key` that key's
    /// `federation_keys` row and the attestation and revocation rows naming
    /// it.
    OneKey {
        /// The signing key.
        signature_key_id: String,
        /// Whether the key's own federation rows go too.
        include_federation_key: bool,
    },
    /// `delete_traces_for_agent_id_hash`: every trace of the agent (Art. 17),
    /// and its thought signatures once no remaining event cites them.
    Full,
}

/// An erasure the plan admitted: who attests its audit row, and which
/// row-backed detections it erases (or refuses) under which `withdraws`.
#[derive(Debug, Clone)]
pub(crate) struct PlannedTraceErasure {
    /// The agent whose traces go.
    pub(crate) agent_id_hash: String,
    /// What goes.
    pub(crate) scope: TraceErasureScope,
    /// The node key the audit row is attested under.
    pub(crate) attester: HardCaseAttester,
    /// The row-backed detections reached, read before the transaction.
    pub(crate) plan: ErasurePlan,
    /// The door's one clock read.
    pub(crate) received_at: DateTime<Utc>,
}

/// What an erasure transaction removed, as counted inside it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ErasedTraces {
    /// `trace_events` rows deleted.
    pub(crate) trace_events: u64,
    /// `trace_llm_calls` rows deleted.
    pub(crate) trace_llm_calls: u64,
    /// Pre-v57 silo detections tombstoned in place.
    pub(crate) legacy_tombstoned: u64,
    /// Row-backed detections hard-deleted under their `withdraws`.
    pub(crate) detection_rows_erased: u64,
    /// `federation_keys` rows deleted (one-key scope only).
    pub(crate) federation_keys: u64,
    /// `federation_attestations` rows deleted (one-key scope only).
    pub(crate) federation_attestations: u64,
    /// `federation_revocations` rows deleted (one-key scope only).
    pub(crate) federation_revocations: u64,
}

impl PlannedTraceErasure {
    /// The signing key the scope pins, if any.
    #[must_use]
    pub(crate) fn signature_key_id(&self) -> Option<&str> {
        match &self.scope {
            TraceErasureScope::OneKey {
                signature_key_id, ..
            } => Some(signature_key_id),
            TraceErasureScope::Full => None,
        }
    }

    /// Whether the scope takes the key's federation rows too.
    #[must_use]
    pub(crate) fn includes_federation_key(&self) -> bool {
        matches!(
            self.scope,
            TraceErasureScope::OneKey {
                include_federation_key: true,
                ..
            }
        )
    }

    /// v38.0.0 (#721) / v58.0.0 (#1094 item 2, CC 4.5.3) — **the audit row,
    /// announced inside the transaction**: the subject-free
    /// `hard_case:trace_erasure` event for what moved, or `None` when nothing
    /// did (an idempotent re-run stays a clean no-op). The executor writes it
    /// with the erased citations before it commits.
    #[must_use]
    pub(crate) fn audit_event(&self, erased: &ErasedTraces) -> Option<HardCaseEvent> {
        let counts = TraceErasureCounts {
            op: match self.scope {
                TraceErasureScope::OneKey { .. } => hard_case::trace_erasure_op::ONE_KEY,
                TraceErasureScope::Full => hard_case::trace_erasure_op::FULL,
            },
            trace_events: erased.trace_events,
            trace_llm_calls: erased.trace_llm_calls,
            detection_events_tombstoned: erased.legacy_tombstoned + erased.detection_rows_erased,
            detection_rows_erased: erased.detection_rows_erased,
            detection_rows_refused: self.plan.refused.len() as u64,
            federation_keys: erased.federation_keys,
            federation_attestations: erased.federation_attestations,
            federation_revocations: erased.federation_revocations,
        };
        let moved = counts.trace_events > 0
            || counts.trace_llm_calls > 0
            || counts.detection_events_tombstoned > 0
            || counts.federation_keys > 0
            || counts.federation_attestations > 0
            || counts.federation_revocations > 0;
        moved.then(|| hard_case::trace_erasure_event(&counts, self.received_at))
    }
}

/// A fountain write the plan admitted, its integer columns checked into the
/// stored widths.
#[derive(Debug, Clone)]
pub(crate) struct PlannedFountainContent<'a> {
    /// The admitted manifest.
    pub(crate) manifest: &'a FountainManifestV1,
    /// Its symbols.
    pub(crate) symbols: &'a [FountainSymbolV1],
    /// `symbol_hashes`, a JSON array of strings.
    pub(crate) symbol_hashes: serde_json::Value,
    /// `original_content_length`, as stored.
    pub(crate) original_content_length: i64,
    /// The door's receipt instant.
    pub(crate) admitted_at: DateTime<Utc>,
    /// The aggregation provenance row, for an aggregated tier.
    pub(crate) aggregation: Option<PlannedAggregation<'a>>,
}

/// The `content_aggregation` row of an aggregated tier.
#[derive(Debug, Clone)]
pub(crate) struct PlannedAggregation<'a> {
    /// The verified aggregation metadata (its `aggregation_meta` stored
    /// opaque).
    pub(crate) agg: &'a AggregationMetaV1,
    /// `aggregation_level`, as stored.
    pub(crate) aggregation_level: i64,
    /// `fan_in`, as stored.
    pub(crate) fan_in: i64,
    /// The caller's aggregation instant.
    pub(crate) aggregated_at_unix_ms: i64,
}

/// The `Backend` doors' executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait BackendStore: AttestationStore {
    /// In ONE transaction: collect the scope's traces, tombstone their
    /// pre-v57 detections, store the plan's new `withdraws` and erase its
    /// cited rows, delete the LLM calls and the trace events (the scope's
    /// federation rows, or the orphaned thought signatures), then write
    /// [`PlannedTraceErasure::audit_event`] when it is `Some`, and commit.
    async fn store_planned_trace_erasure(
        &self,
        planned: &PlannedTraceErasure,
    ) -> Result<ErasedTraces, Error>;

    /// In ONE transaction: insert the manifest (idempotent on
    /// `(content_id, corpus_kind)`), upsert its symbols, and insert the
    /// aggregation row when there is one (idempotent on its id).
    async fn store_planned_fountain_content(
        &self,
        planned: PlannedFountainContent<'_>,
    ) -> Result<(), Error>;
}

/// The plan both erasure doors share: the attester gate (a node that cannot
/// attest its audit row erases nothing, CIRISPersist#988), the pre-v57
/// detection rehome (so a reached detection is erased the row way), and the
/// row-backed detections the erasure reaches (#1094 item 2).
async fn plan_trace_erasure<D: BackendStore>(
    dir: &D,
    agent_id_hash: &str,
    scope: TraceErasureScope,
    received_at: DateTime<Utc>,
) -> Result<PlannedTraceErasure, Error> {
    let attester = attestation_admit::hard_case_attester(dir)
        .await
        .map_err(Error::from_hard_case_attester)?;
    dir.rehome_legacy_detection_events(received_at)
        .await
        .map_err(|e| Error::Backend(format!("rehome before erasure: {e}")))?;
    let key = match &scope {
        TraceErasureScope::OneKey {
            signature_key_id, ..
        } => Some(signature_key_id.as_str()),
        TraceErasureScope::Full => None,
    };
    let plan = subject_erasure::plan_store_erasure(dir, agent_id_hash, key, received_at)
        .await
        .map_err(|e| Error::Backend(format!("erasure plan: {e}")))?;
    Ok(PlannedTraceErasure {
        agent_id_hash: agent_id_hash.to_owned(),
        scope,
        attester,
        plan,
        received_at,
    })
}

/// The door: every backend's `delete_traces_for_agent`.
pub(crate) async fn delete_traces_for_agent_planned<D: BackendStore>(
    dir: &D,
    agent_id_hash: &str,
    signature_key_id: &str,
    include_federation_key: bool,
) -> Result<DeleteSummary, Error> {
    let scope = TraceErasureScope::OneKey {
        signature_key_id: signature_key_id.to_owned(),
        include_federation_key,
    };
    let planned = plan_trace_erasure(dir, agent_id_hash, scope, Utc::now()).await?;
    let erased = dir.store_planned_trace_erasure(&planned).await?;
    Ok(DeleteSummary {
        trace_events_deleted: erased.trace_events,
        trace_llm_calls_deleted: erased.trace_llm_calls,
        federation_keys_deleted: erased.federation_keys,
        federation_attestations_deleted: erased.federation_attestations,
        federation_revocations_deleted: erased.federation_revocations,
        detection_rows_refused: planned.plan.refused,
        deleted_at: Utc::now(),
    })
}

/// The door: every backend's `delete_traces_for_agent_id_hash`.
pub(crate) async fn delete_traces_for_agent_id_hash_planned<D: BackendStore>(
    dir: &D,
    agent_id_hash: &str,
) -> Result<ErasureSummary, Error> {
    let erased_at = Utc::now();
    let planned =
        plan_trace_erasure(dir, agent_id_hash, TraceErasureScope::Full, erased_at).await?;
    let erased = dir.store_planned_trace_erasure(&planned).await?;
    Ok(ErasureSummary {
        trace_events: erased.trace_events,
        trace_llm_calls: erased.trace_llm_calls,
        detection_events_tombstoned: erased.legacy_tombstoned + erased.detection_rows_erased,
        detection_rows_refused: planned.plan.refused,
        erased_at,
    })
}

/// The manifest's columns as stored: the admission gate (AV-9,
/// verify-before-mutation) has run.
fn plan_fountain_content<'a>(
    manifest: &'a FountainManifestV1,
    symbols: &'a [FountainSymbolV1],
    aggregation: Option<PlannedAggregation<'a>>,
) -> Result<PlannedFountainContent<'a>, Error> {
    let original_content_length = i64::try_from(manifest.original_content_length)
        .map_err(|_| Error::Backend("original_content_length exceeds i64".into()))?;
    Ok(PlannedFountainContent {
        manifest,
        symbols,
        symbol_hashes: serde_json::Value::Array(
            manifest
                .symbol_hashes
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
        original_content_length,
        admitted_at: Utc::now(),
        aggregation,
    })
}

/// The door: every backend's `put_fountain_content`. The full admission
/// gate runs first; on any failure nothing is written.
pub(crate) async fn put_fountain_content_planned<D: BackendStore>(
    dir: &D,
    manifest: &FountainManifestV1,
    symbols: &[FountainSymbolV1],
) -> Result<(), Error> {
    crate::fountain::check_admission_via_envelope(
        manifest,
        symbols,
        &crate::verify::PythonJsonDumpsCanonicalizer,
    )?;
    let planned = plan_fountain_content(manifest, symbols, None)?;
    dir.store_planned_fountain_content(planned).await
}

/// The door: every backend's `put_aggregated_tier`. BOTH gates run before
/// any write: (i) the composite through the #225 fountain admission
/// (classical-only refused), (ii) the §19.7.1 PQC-mandatory aggregation
/// signature over the composite envelope. The stored `aggregation_meta`
/// stays opaque.
pub(crate) async fn put_aggregated_tier_planned<D: BackendStore>(
    dir: &D,
    manifest: &FountainManifestV1,
    symbols: &[FountainSymbolV1],
    agg: &AggregationMetaV1,
    aggregated_at_unix_ms: i64,
) -> Result<(), Error> {
    crate::fountain::check_admission_via_envelope(
        manifest,
        symbols,
        &crate::verify::PythonJsonDumpsCanonicalizer,
    )?;
    agg.verify_for_admission(manifest)?;
    let aggregation = PlannedAggregation {
        agg,
        aggregation_level: i64::try_from(agg.aggregation_level)
            .map_err(|_| Error::Backend("aggregation_level exceeds i64".into()))?,
        fan_in: i64::try_from(agg.fan_in)
            .map_err(|_| Error::Backend("fan_in exceeds i64".into()))?,
        aggregated_at_unix_ms,
    };
    let planned = plan_fountain_content(manifest, symbols, Some(aggregation))?;
    dir.store_planned_fountain_content(planned).await
}
