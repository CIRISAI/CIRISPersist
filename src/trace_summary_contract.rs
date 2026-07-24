//! v19.2.0 (CIRISPersist#494) — the trace-summary **extraction-path
//! contract**, single-sourced.
//!
//! `list_trace_summaries` builds the capacity scorer's feature matrix by
//! extracting flat JSON paths from `trace_events.payload`. Those paths are
//! a CONTRACT WITH THE EMITTER (CIRISAgent seals the payload) — and until
//! this cut they were hand-mirrored in three independent places (the
//! sqlite `json_extract` SELECT, the postgres `->>` SELECT, and the
//! agent's emitter test), exact-string matched with no cross-assertion. A
//! mismatch failed *silently*: NULL column → empty feature matrix → the
//! scorer emits nothing (`envelopes_sent=0`, no error) — exactly how the
//! trace plane sat dark (CIRISServer#315 field RCA).
//!
//! This module is the ONE source:
//! - [`TRACE_SUMMARY_EXTRACTION`] — the manifest of
//!   `(event_type, flat_path, alias, agg, min_tier)` tuples;
//! - both backends DERIVE their SELECT payload sections from it
//!   ([`sqlite_payload_select_fragment`] / [`postgres_payload_select_fragment`])
//!   — the dialect differs (CASE WHEN vs FILTER, MIN/MAX-over-0/1 vs
//!   BOOL_AND/OR, dynamic typing vs `::casts`), the CONTRACT cannot;
//! - [`extraction_manifest_json`] + [`TRACE_SUMMARY_EXTRACTION_SHA256`]
//!   expose it, mirroring `WIRE_VOCABULARY_HASH`: CIRISServer serves the
//!   hash on `/v1/health` next to `wire_vocabulary_sha256`, and the
//!   agent's emitter contract test asserts against it — a change on
//!   EITHER side fails loudly on BOTH.
//!
//! Same fix as the other closures of this class this cycle: identity
//! (one derivation), vocabulary (shared consts, CIRISVerify#217 /
//! v19.1.1's differential guard), roles surface (#486). Shared source
//! doesn't drift; hand-mirrored contracts do.

/// How a field folds across the rows of a trace group. Dialect rendering
/// differs per backend; the SEMANTIC (which fold) is part of the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Agg {
    /// Numeric mean (pg `AVG((…)::float8)`, sqlite `AVG(json_extract)`).
    AvgF64,
    /// Max of a text field (pg `MAX(->>')`, sqlite `MAX(json_extract)`).
    MaxText,
    /// Max of an integer field.
    MaxInt,
    /// Conjunction over a JSON boolean (pg `BOOL_AND(::bool)`; sqlite has
    /// no BOOL_AND — `MIN` over the 0/1 `json_extract` yields).
    BoolAnd,
    /// Disjunction over a JSON boolean (pg `BOOL_OR`; sqlite `MAX`).
    BoolOr,
}

/// One extraction-contract row: the emitter promises `flat_path` inside
/// the payload of `event_type` events at `min_tier` and above; persist
/// projects it as `alias` with the `agg` fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ExtractionField {
    /// The `trace_events.event_type` gate.
    pub event_type: &'static str,
    /// The FLAT payload key (the #315 fix: flat aliases, never nested).
    pub flat_path: &'static str,
    /// The projected column alias (what `TraceSummary` reads by name).
    pub alias: &'static str,
    /// The fold semantic.
    pub agg: Agg,
    /// Which projection consumes this field: `summary` (the
    /// `TRACE_SUMMARY_SELECT` feature matrix) or `task_page` (the
    /// task-list page's `initial_observation`).
    pub surface: &'static str,
    /// The minimum trace tier the emitter produces this field at
    /// (`generic` | `detailed` | `full_traces`). Extraction at a lower
    /// tier is a WRONG-TIER READ (the #494 ask-2 class) — the derivation
    /// gates non-`generic` fields on tier so the projection cannot ask
    /// for what the emitter never sent.
    pub min_tier: &'static str,
}

/// The manifest — THE contract. Order is part of the hashed canonical
/// form; append new fields at the end.
pub const TRACE_SUMMARY_EXTRACTION: &[ExtractionField] = &[
    ExtractionField {
        event_type: "THOUGHT_START",
        flat_path: "thought_type",
        alias: "thought_type",
        agg: Agg::MaxText,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "THOUGHT_START",
        flat_path: "thought_depth",
        alias: "thought_depth",
        agg: Agg::MaxInt,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "DMA_RESULTS",
        flat_path: "csdma_plausibility_score",
        alias: "csdma_plausibility_score",
        agg: Agg::AvgF64,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "DMA_RESULTS",
        flat_path: "dsdma_domain_alignment",
        alias: "dsdma_domain_alignment",
        agg: Agg::AvgF64,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "DMA_RESULTS",
        flat_path: "dsdma_domain",
        alias: "dsdma_domain",
        agg: Agg::MaxText,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "IDMA_RESULT",
        flat_path: "idma_k_eff",
        alias: "idma_k_eff",
        agg: Agg::AvgF64,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "IDMA_RESULT",
        flat_path: "idma_correlation_risk",
        alias: "idma_correlation_risk",
        agg: Agg::AvgF64,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "IDMA_RESULT",
        flat_path: "idma_fragility_flag",
        alias: "idma_fragility_flag",
        agg: Agg::BoolOr,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "IDMA_RESULT",
        flat_path: "idma_phase",
        alias: "idma_phase",
        agg: Agg::MaxText,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "CONSCIENCE_RESULT",
        flat_path: "conscience_passed",
        alias: "conscience_passed",
        agg: Agg::BoolAnd,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "CONSCIENCE_RESULT",
        flat_path: "action_was_overridden",
        alias: "action_was_overridden",
        agg: Agg::BoolOr,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "CONSCIENCE_RESULT",
        flat_path: "entropy_passed",
        alias: "entropy_passed",
        agg: Agg::BoolAnd,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "CONSCIENCE_RESULT",
        flat_path: "coherence_passed",
        alias: "coherence_passed",
        agg: Agg::BoolAnd,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "CONSCIENCE_RESULT",
        flat_path: "optimization_veto_passed",
        alias: "optimization_veto_passed",
        agg: Agg::BoolAnd,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "CONSCIENCE_RESULT",
        flat_path: "epistemic_humility_passed",
        alias: "epistemic_humility_passed",
        agg: Agg::BoolAnd,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "ACTION_RESULT",
        flat_path: "action_executed",
        alias: "selected_action",
        agg: Agg::MaxText,
        surface: "summary",
        min_tier: "generic",
    },
    ExtractionField {
        event_type: "ACTION_RESULT",
        flat_path: "success",
        alias: "action_success",
        agg: Agg::BoolAnd,
        surface: "summary",
        min_tier: "generic",
    },
    // #494 ask 2 — task_description is FREE REASONING TEXT: `detailed`-tier
    // by the TraceLevel model ("Detailed = Generic + reasoning text
    // fields"). Previously extracted with NO tier gate — a wrong-tier read
    // the emitter never populates at generic (permanently-NULL column).
    // Consumed by the TASK-PAGE query (alias `initial_observation`), not
    // the summary SELECT — carried here so the tier is single-sourced.
    ExtractionField {
        event_type: "THOUGHT_START",
        flat_path: "task_description",
        alias: "initial_observation",
        agg: Agg::MaxText,
        surface: "task_page",
        min_tier: "detailed",
    },
];

/// The `summary`-surface fields (the feature-matrix contract).
pub fn summary_fields() -> Vec<ExtractionField> {
    TRACE_SUMMARY_EXTRACTION
        .iter()
        .copied()
        .filter(|f| f.surface == "summary")
        .collect()
}

/// The `task_page`-surface fields.
pub fn task_page_fields() -> Vec<ExtractionField> {
    TRACE_SUMMARY_EXTRACTION
        .iter()
        .copied()
        .filter(|f| f.surface == "task_page")
        .collect()
}

/// The tier-gate SQL predicate for a field, or empty for `generic`
/// (every row qualifies). `detailed` admits `detailed` + `full_traces`.
fn tier_gate(min_tier: &str) -> &'static str {
    match min_tier {
        "generic" => "",
        "detailed" => " AND trace_level IN ('detailed', 'full_traces')",
        _ => " AND trace_level = 'full_traces'",
    }
}

/// Derive the SQLite payload-extraction SELECT fragment (comma-joined,
/// no trailing comma). SQLite dialect: `CASE WHEN` gates, `json_extract`,
/// booleans as the 0/1 integers `json_extract` yields (`BoolAnd`→`MIN`,
/// `BoolOr`→`MAX`), dynamic typing (no casts).
pub fn sqlite_payload_select_fragment(fields: &[ExtractionField]) -> String {
    fields
        .iter()
        .map(|f| {
            let outer = match f.agg {
                Agg::AvgF64 => "AVG",
                Agg::MaxText | Agg::MaxInt | Agg::BoolOr => "MAX",
                Agg::BoolAnd => "MIN",
            };
            format!(
                "{outer}(CASE WHEN event_type = '{et}'{gate} \
                 THEN json_extract(payload, '$.{path}') END) AS {alias}",
                et = f.event_type,
                gate = tier_gate(f.min_tier),
                path = f.flat_path,
                alias = f.alias,
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Derive the Postgres payload-extraction SELECT fragment. Postgres
/// dialect: `FILTER (WHERE …)` gates, `payload->>`, real `BOOL_AND`/
/// `BOOL_OR` with `::bool`, `::float8`/`::int` casts.
pub fn postgres_payload_select_fragment(fields: &[ExtractionField]) -> String {
    fields
        .iter()
        .map(|f| {
            let expr = match f.agg {
                Agg::AvgF64 => format!("AVG((payload->>'{}')::float8)", f.flat_path),
                Agg::MaxText => format!("MAX(payload->>'{}')", f.flat_path),
                Agg::MaxInt => format!("MAX((payload->>'{}')::int)", f.flat_path),
                Agg::BoolAnd => format!("BOOL_AND((payload->>'{}')::bool)", f.flat_path),
                Agg::BoolOr => format!("BOOL_OR((payload->>'{}')::bool)", f.flat_path),
            };
            format!(
                "{expr} FILTER (WHERE event_type = '{et}'{gate}) AS {alias}",
                et = f.event_type,
                gate = tier_gate(f.min_tier),
                alias = f.alias,
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The canonical manifest as JSON — the hashed representation and the
/// public API shape (served by CIRISServer beside `wire_vocabulary_sha256`;
/// asserted by the agent's emitter contract test).
pub fn extraction_manifest_json() -> serde_json::Value {
    serde_json::json!({
        "contract": "trace_summary_extraction",
        "version": 1,
        "fields": TRACE_SUMMARY_EXTRACTION,
    })
}

/// sha256 (lowercase hex) over the JCS canonical bytes of
/// [`extraction_manifest_json`] — computed, and pinned by
/// [`TRACE_SUMMARY_EXTRACTION_SHA256`] with a gating witness. A contract
/// change without a deliberate pin update fails persist CI; a pin update
/// is visible to every consumer asserting the hash.
pub fn extraction_manifest_sha256() -> String {
    use sha2::Digest as _;
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&extraction_manifest_json())
        .expect("extraction manifest canonicalizes");
    hex::encode(sha2::Sha256::digest(&canonical))
}

/// The PINNED contract hash. Consumers (CIRISServer `/v1/health`, the
/// CIRISAgent emitter test) assert against this value; the
/// `extraction_manifest_hash_is_pinned` witness asserts
/// `computed == pinned`, so drift anywhere is a LOUD failure on both
/// sides of the wire.
pub const TRACE_SUMMARY_EXTRACTION_SHA256: &str =
    "f4dfea6e8e8e3f11d2abd22cb4dd5adbe15cf662246b7f90fbcfd0bb9cf5b76d";

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin gate: the manifest's computed hash equals the pinned const.
    /// Changing the contract without deliberately re-pinning fails HERE.
    #[test]
    fn extraction_manifest_hash_is_pinned() {
        assert_eq!(
            extraction_manifest_sha256(),
            TRACE_SUMMARY_EXTRACTION_SHA256,
            "trace-summary extraction contract changed: re-pin \
             TRACE_SUMMARY_EXTRACTION_SHA256 deliberately (and notify the \
             CIRISServer /v1/health + CIRISAgent emitter-test consumers)"
        );
    }

    /// Aliases are unique (SELECT would silently shadow otherwise).
    #[test]
    fn aliases_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for f in TRACE_SUMMARY_EXTRACTION {
            assert!(seen.insert(f.alias), "duplicate alias {}", f.alias);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// v20.0.0 (#495, wall 1) — the TYPED per-event payload structs. The serde
// field names ARE the flat extraction paths; the
// `payload_structs_bind_extraction_manifest` witness asserts every
// manifest `flat_path` is a serde field of its event's struct — so a
// payload-field rename on either side fails the build's tests instead of
// silently NULLing a projection column. The emitter (CIRISAgent, Python)
// binds via TRACE_SUMMARY_EXTRACTION_SHA256; Rust producers/readers bind
// via these structs.
// ─────────────────────────────────────────────────────────────────────

/// `THOUGHT_START` payload — the summary + task-page fields.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct ThoughtStartPayload {
    /// Thought taxonomy token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thought_type: Option<String>,
    /// Recursion depth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thought_depth: Option<i64>,
    /// `detailed`-tier reasoning text (the task page's
    /// `initial_observation`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_description: Option<String>,
    /// Everything else the emitter ships, preserved.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// `DMA_RESULTS` payload.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct DmaResultsPayload {
    /// CSDMA plausibility (FLAT — the #315 fix; never nested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csdma_plausibility_score: Option<f64>,
    /// DSDMA domain alignment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsdma_domain_alignment: Option<f64>,
    /// DSDMA domain token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsdma_domain: Option<String>,
    /// Preserved extras.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// `IDMA_RESULT` payload.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct IdmaResultPayload {
    /// Effective k (FLAT alias).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idma_k_eff: Option<f64>,
    /// Correlation risk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idma_correlation_risk: Option<f64>,
    /// Fragility flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idma_fragility_flag: Option<bool>,
    /// Phase token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idma_phase: Option<String>,
    /// Preserved extras.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// `CONSCIENCE_RESULT` payload.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct ConscienceResultPayload {
    /// Overall verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conscience_passed: Option<bool>,
    /// Override marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_was_overridden: Option<bool>,
    /// Entropy gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_passed: Option<bool>,
    /// Coherence gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coherence_passed: Option<bool>,
    /// Optimization-veto gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimization_veto_passed: Option<bool>,
    /// Epistemic-humility gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epistemic_humility_passed: Option<bool>,
    /// Preserved extras.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// `ACTION_RESULT` payload.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct ActionResultPayload {
    /// The executed action token (projects as `selected_action`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_executed: Option<String>,
    /// Success marker (projects as `action_success`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    /// Preserved extras.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod payload_struct_tests {
    use super::*;

    fn serde_keys<T: serde::Serialize>(v: &T) -> Vec<String> {
        match serde_json::to_value(v).unwrap() {
            serde_json::Value::Object(m) => m.keys().cloned().collect(),
            other => panic!("payload struct must serialize to an object, got {other:?}"),
        }
    }

    /// THE wall-1 binding witness: every manifest `flat_path` is a serde
    /// field of its event's typed struct. A rename on either side (struct
    /// field OR manifest row) fails HERE — the class that sat the trace
    /// plane dark can no longer ship.
    #[test]
    fn payload_structs_bind_extraction_manifest() {
        fn full<T: Default + serde::Serialize>(fill: impl FnOnce(&mut T)) -> Vec<String> {
            let mut v = T::default();
            fill(&mut v);
            serde_keys(&v)
        }
        let by_event: std::collections::HashMap<&str, Vec<String>> = [
            (
                "THOUGHT_START",
                full::<ThoughtStartPayload>(|p| {
                    p.thought_type = Some("t".into());
                    p.thought_depth = Some(0);
                    p.task_description = Some("d".into());
                }),
            ),
            (
                "DMA_RESULTS",
                full::<DmaResultsPayload>(|p| {
                    p.csdma_plausibility_score = Some(0.5);
                    p.dsdma_domain_alignment = Some(0.5);
                    p.dsdma_domain = Some("d".into());
                }),
            ),
            (
                "IDMA_RESULT",
                full::<IdmaResultPayload>(|p| {
                    p.idma_k_eff = Some(1.0);
                    p.idma_correlation_risk = Some(0.1);
                    p.idma_fragility_flag = Some(false);
                    p.idma_phase = Some("p".into());
                }),
            ),
            (
                "CONSCIENCE_RESULT",
                full::<ConscienceResultPayload>(|p| {
                    p.conscience_passed = Some(true);
                    p.action_was_overridden = Some(false);
                    p.entropy_passed = Some(true);
                    p.coherence_passed = Some(true);
                    p.optimization_veto_passed = Some(true);
                    p.epistemic_humility_passed = Some(true);
                }),
            ),
            (
                "ACTION_RESULT",
                full::<ActionResultPayload>(|p| {
                    p.action_executed = Some("SPEAK".into());
                    p.success = Some(true);
                }),
            ),
        ]
        .into_iter()
        .collect();

        for f in TRACE_SUMMARY_EXTRACTION {
            let keys = by_event.get(f.event_type).unwrap_or_else(|| {
                panic!("manifest event_type {} has no typed struct", f.event_type)
            });
            assert!(
                keys.iter().any(|k| k == f.flat_path),
                "manifest path {}::{} is not a serde field of its typed payload struct",
                f.event_type,
                f.flat_path
            );
        }
    }

    /// M2 — every manifest event_type is a real `ReasoningEventType` wire
    /// token (the UPPERCASE stored-column form), single-sourcing the gate
    /// strings against the enum.
    #[test]
    fn manifest_event_types_are_reasoning_event_tokens() {
        use crate::schema::ReasoningEventType as E;
        let tokens: Vec<&str> = [
            E::ThoughtStart,
            E::SnapshotAndContext,
            E::DmaResults,
            E::IdmaResult,
            E::AspdmaResult,
            E::ConscienceResult,
            E::ActionResult,
        ]
        .iter()
        .map(|e| e.as_str())
        .collect();
        for f in TRACE_SUMMARY_EXTRACTION {
            assert!(
                tokens.contains(&f.event_type),
                "manifest event_type {} is not a ReasoningEventType token",
                f.event_type
            );
        }
    }
}
