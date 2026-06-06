//! Section H — Privacy / scrub observability primitive.
//!
//! Moved from `src/read/scrub.rs` in v4.0 (FSD §3.3).
//!
//! Drives privacy dashboards. Two of the four fields require the
//! post-ingest classification pipeline (CIRISPersist#19 / v0.6.0)
//! before they have data to populate; the v0.5.5 shape is committed
//! now (single round trip), but `fields_scrubbed_total` returns 0 and
//! `by_entity_type` is empty until v0.6.0 lands the per-entity
//! taxonomy classifier.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ceg::types::TimeWindow;
use crate::schema::TraceLevel;

/// Scrub-stats aggregate for a window. Counts are distinct-trace
/// (not events) so the rollup matches the §G corpus_shape axis.
///
/// Empty windows return all zeros / empty maps (NULL-safe via SQL
/// COALESCE).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScrubAggregate {
    /// The window the rollup covers.
    pub window: TimeWindow,

    /// Distinct-trace count where `pii_scrubbed = true`.
    pub envelopes_scrubbed: i64,

    /// Total fields the scrubber redacted across all envelopes.
    ///
    /// **v0.5.5 limitation:** persist's V001-V006 schema doesn't carry
    /// a per-envelope "fields scrubbed" counter — the scrubber runs
    /// pre-persist and only the boolean `pii_scrubbed` flag survives
    /// to storage. The post-ingest classification pipeline
    /// (CIRISPersist#19 / v0.6.0) will introduce a `classification`
    /// JSONB column carrying per-entity-type counts; once that lands,
    /// this field starts reporting real values.
    /// Until then v0.5.5 returns `0` so consumers can detect the
    /// pipeline-pending state and gate their UI accordingly.
    pub fields_scrubbed_total: i64,

    /// Per-entity-type counts (PERSON / ORG / EMAIL / PHONE / ...).
    ///
    /// **v0.5.5 limitation:** same gating as `fields_scrubbed_total`.
    /// Returns an empty map until v0.6.0's classification pipeline
    /// populates the per-entity taxonomy at write time.
    pub by_entity_type: HashMap<String, i64>,

    /// Distinct-trace count by [`TraceLevel`] (Generic / Detailed /
    /// FullTraces) WHERE `pii_scrubbed = true`. Always populated;
    /// not gated on v0.6.0.
    pub by_trace_level: HashMap<TraceLevel, i64>,
}
