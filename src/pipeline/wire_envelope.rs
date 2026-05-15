//! v1.1.0 (CIRISPersist#33): the `WireEnvelope` substrate trait + the
//! [`BatchEnvelope`] impl.
//!
//! `WireEnvelope` is the substrate-level abstraction that lets the
//! transit-touch pipeline stages (`ClassifyStage`, `ScrubStage`,
//! `EncryptAndStoreStage`) run over either:
//!
//! - a [`BatchEnvelope`] (one body per agent trace component — the
//!   ingest path), OR
//! - an [`InlineTextEnvelope`] (one body total — the SPEAK response /
//!   LLM-prompt / WBD / DSAR outbound paths per CIRISAgent#756 and
//!   the v1.1.0 FSD extension).
//!
//! [`ExtractStage`](super::ExtractStage) stays `Stage<BatchEnvelope>`-
//! specific because the `Features` projection is structurally trace-
//! coupled (per FSD §5.1 — features are walked off a `CompleteTrace`
//! tree, not a flat string).
//!
//! # Iterator signature deviation from the design analysis
//!
//! The v1.1.0 design analysis posted on CIRISPersist#33 specified
//! `text_bodies(&self) -> Box<dyn Iterator<Item = (MatchAddress,
//! &str)> + '_>`. Returning `&str` would force the envelope to hold
//! pre-serialized component payloads as a sidecar field (the
//! per-component JSON only exists ephemerally) — adding mutable
//! caching state to a `&self` method, or bloating the envelope's wire
//! shape with a transient cache. We instead yield owned `String`:
//!
//! ```ignore
//! fn text_bodies(&self) -> Box<dyn Iterator<Item = (MatchAddress, String)> + '_>;
//! ```
//!
//! Trade-off: one extra allocation per body per pipeline run (cheap;
//! the alternative ScrubStage path already round-trips through
//! `serde_json::Value`). Upside: the trait is honest about what it
//! returns and stages don't need to thread lifetimes through borrow
//! chains. Documented here because the design-analysis spec used
//! `&str`.

use serde::{Deserialize, Serialize};

/// Where a content-class match was located. Replaces v1.0.x's
/// `component_index: usize` + `json_path: Option<String>` field pair
/// on [`crate::pipeline::classify::ContentClassMatch`] so the
/// [`Pipeline`](super::Pipeline) can be generic over
/// [`crate::schema::BatchEnvelope`] (multi-component) AND
/// [`InlineTextEnvelope`](super::InlineTextEnvelope) (single-body
/// SPEAK / LLM-prompt / WBD / DSAR flows).
///
/// # Wire format
///
/// Adjacently-tagged JSON, snake_case `kind` discriminant. Empty
/// `json_path` is omitted on the wire (`skip_serializing_if`).
///
/// ```json
/// { "kind": "batch_component", "index": 0 }
/// { "kind": "batch_component", "index": 2, "json_path": "$.task_description" }
/// { "kind": "inline_text" }
/// { "kind": "inline_text", "json_path": "$.response_text" }
/// ```
///
/// # v1.1.0 (CIRISPersist#33) migration note
///
/// Per the v1.0.0 CHANGELOG, the classify matcher catalog was stubbed
/// — `ClassifyStage` populated empty per-component classification
/// vecs, so production `cirislens.trace_events.classifications` JSONB
/// blobs are empty or absent. The pre-v1.1.0 shape carried
/// `component_index: usize` + `json_path: Option<String>` flat fields
/// on `ContentClassMatch`; v1.1.0 collapses them into this single
/// `address` field. No on-wire-data migration is needed because no
/// real matches were ever serialized.
///
/// # Module location
///
/// Defined here (not in `classify/mod.rs` as in the original v1.1.0
/// design analysis) so the [`WireEnvelope`] trait — which is always-
/// compiled — can reference it without requiring the `classify`
/// feature. `classify::MatchAddress` re-exports this type for
/// import-path compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MatchAddress {
    /// Match inside a [`crate::schema::BatchEnvelope`] component.
    /// `index` is the 0-based component position (in event-order
    /// across `events[*].components[*]`); `json_path` (when Some)
    /// refines to a subfield of the component payload.
    BatchComponent {
        /// 0-based component index, in event-order across the batch.
        index: usize,
        /// Optional JSON-pointer-like path to the matched field within
        /// the component payload. `None` for whole-component matches.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_path: Option<String>,
    },
    /// Match in an [`InlineTextEnvelope`](super::InlineTextEnvelope)
    /// (SPEAK response, LLM prompt, WBD body, DSAR text).
    /// `json_path` (when Some) refines to a subfield of a structured
    /// text wrapper; typically `None` for plain text.
    InlineText {
        /// Optional JSON-pointer-like path to the matched field within
        /// a structured text wrapper. `None` for plain inline text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_path: Option<String>,
    },
}

/// v1.1.0 (CIRISPersist#33): substrate trait abstracting "an envelope
/// the pipeline operates on".
///
/// [`crate::schema::BatchEnvelope`] impls it (one body per component);
/// [`InlineTextEnvelope`] impls it for SPEAK / LLM-prompt / WBD /
/// DSAR flows (single body).
///
/// # Invariants
///
/// - [`Self::text_bodies`] yields exactly [`Self::body_count`] items
///   (in deterministic order).
/// - [`Self::mutate_body`] called with an [`MatchAddress`] yielded by
///   `text_bodies` MUST locate the same body and apply `mutator`
///   in place. An address that doesn't correspond to a body in this
///   envelope (e.g. an `InlineText` address on a `BatchEnvelope`, or
///   an out-of-range `BatchComponent.index`) is a silent no-op — the
///   pipeline orchestrator surfaces a typed error elsewhere if a
///   stage produces a mismatched address.
pub trait WireEnvelope: Send {
    /// Canonical bytes used for signature verification by upstream
    /// stages or downstream consumers. Implementation-defined per
    /// envelope type.
    ///
    /// For [`BatchEnvelope`] this is the
    /// [`canonicalize_envelope_for_signing`](crate::verify::canonicalize_envelope_for_signing)
    /// output; for [`InlineTextEnvelope`] this is a caller-supplied
    /// seed (typically empty for ephemeral inline use).
    fn canonical_bytes(&self) -> Vec<u8>;

    /// Iterate addressable text bodies.
    ///
    /// - For [`BatchEnvelope`]: yields `(BatchComponent { index,
    ///   json_path: None }, body)` per component (in event-order
    ///   across `events[*].components[*]`).
    /// - For [`InlineTextEnvelope`]: yields a single
    ///   `(InlineText { json_path: None }, body)`.
    ///
    /// See the module doc for the owned-`String` vs `&str` rationale.
    fn text_bodies(&self) -> Box<dyn Iterator<Item = (MatchAddress, String)> + '_>;

    /// Mutate a text body at the given address. Used by
    /// [`ScrubStage`](super::ScrubStage) to redact and by
    /// [`EncryptAndStoreStage`](super::EncryptAndStoreStage) to swap
    /// cleartext for `{SECRET:uuid:description}` placeholders.
    ///
    /// `mutator` receives the body as an owned `String` and may
    /// mutate it in place. Implementations write the post-mutation
    /// value back into the envelope.
    fn mutate_body(&mut self, addr: &MatchAddress, mutator: &mut dyn FnMut(&mut String));

    /// Number of bodies. Used for invariant checks — e.g. FSD §4.3
    /// invariant 5: `classifications.len()` must equal `body_count()`.
    fn body_count(&self) -> usize;

    /// Trace-level / scrub-tier hint passed to scrub-stage walkers.
    ///
    /// - [`BatchEnvelope`](crate::schema::BatchEnvelope) returns its
    ///   own [`crate::schema::TraceLevel`] (Generic / Detailed /
    ///   FullTraces).
    /// - [`InlineTextEnvelope`](super::InlineTextEnvelope) returns
    ///   [`crate::schema::TraceLevel::Detailed`] — inline text is
    ///   always regex-scrubbed; NER batching doesn't apply to a
    ///   single short body.
    ///
    /// Default impl returns `Detailed`; types with their own level
    /// (BatchEnvelope) override it. This is a v1.1.0 (CIRISPersist#33)
    /// extension to the substrate trait — required so ScrubStage can
    /// run generically over `E: WireEnvelope` without downcasting.
    fn scrub_level(&self) -> crate::schema::TraceLevel {
        crate::schema::TraceLevel::Detailed
    }
}

// ─── BatchEnvelope: WireEnvelope ───────────────────────────────────

impl WireEnvelope for crate::schema::BatchEnvelope {
    fn canonical_bytes(&self) -> Vec<u8> {
        // BatchEnvelope's canonical-bytes path goes through the
        // verify-layer canonicalizer (strips `signature` / `signature_pqc`
        // before hashing). On serialize failure (extremely unlikely —
        // BatchEnvelope is a typed struct that round-trips through
        // serde by construction) we surface an empty vec; the caller
        // is treating this as advisory (the trait surface doesn't
        // return Result).
        match serde_json::to_value(self) {
            Ok(v) => crate::verify::canonicalize_envelope_for_signing(&v).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    fn text_bodies(&self) -> Box<dyn Iterator<Item = (MatchAddress, String)> + '_> {
        // Flatten across events[*].components[*] in declaration order.
        // The body is the JSON-serialized component `data` Map — this
        // is the unit downstream stages scrub / classify over.
        let bodies: Vec<(MatchAddress, String)> = self
            .events
            .iter()
            .flat_map(|event| {
                let crate::schema::BatchEvent::CompleteTrace { trace, .. } = event;
                trace.components.iter()
            })
            .enumerate()
            .map(|(idx, c)| {
                let body = serde_json::to_string(&c.data).unwrap_or_default();
                (
                    MatchAddress::BatchComponent {
                        index: idx,
                        json_path: None,
                    },
                    body,
                )
            })
            .collect();
        Box::new(bodies.into_iter())
    }

    fn mutate_body(&mut self, addr: &MatchAddress, mutator: &mut dyn FnMut(&mut String)) {
        let MatchAddress::BatchComponent { index, .. } = addr else {
            // Address-kind mismatch (InlineText address on a Batch
            // envelope) → no-op. The trait contract calls this a
            // silent no-op; pipeline orchestrator surfaces typed
            // errors elsewhere if needed.
            return;
        };
        let mut cur = 0usize;
        for event in self.events.iter_mut() {
            let crate::schema::BatchEvent::CompleteTrace { trace, .. } = event;
            for component in trace.components.iter_mut() {
                if cur == *index {
                    let mut body = match serde_json::to_string(&component.data) {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    mutator(&mut body);
                    // Round-trip back through serde — body must be a
                    // valid JSON Object for the typed `Map`. If the
                    // mutator produced a non-Object, the deserialize
                    // fails and we leave the original in place.
                    if let Ok(parsed) =
                        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body)
                    {
                        component.data = parsed;
                    }
                    return;
                }
                cur += 1;
            }
        }
    }

    fn body_count(&self) -> usize {
        self.events
            .iter()
            .map(|event| {
                let crate::schema::BatchEvent::CompleteTrace { trace, .. } = event;
                trace.components.len()
            })
            .sum()
    }

    fn scrub_level(&self) -> crate::schema::TraceLevel {
        self.trace_level
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        BatchEnvelope, BatchEvent, CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion,
        TraceComponent, TraceLevel,
    };

    fn fixture(component_descs: Vec<&str>) -> BatchEnvelope {
        let components: Vec<TraceComponent> = component_descs
            .into_iter()
            .map(|desc| {
                let mut data = serde_json::Map::new();
                data.insert(
                    "task_description".to_string(),
                    serde_json::Value::String(desc.to_string()),
                );
                TraceComponent {
                    component_type: ComponentType::Conscience,
                    event_type: ReasoningEventType::ThoughtStart,
                    timestamp: "2026-04-30T00:16:00Z".parse().unwrap(),
                    data,
                    agent_id_hash: None,
                }
            })
            .collect();
        let trace = CompleteTrace {
            trace_id: "trace-test".into(),
            thought_id: "th_test".into(),
            task_id: Some("task_test".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12Z".parse().unwrap(),
            trace_level: TraceLevel::Detailed,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components,
            deployment_profile: None,
            signature: "AAAA".into(),
            signature_key_id: "ciris-agent-key:dead".into(),
        };
        BatchEnvelope {
            events: vec![BatchEvent::CompleteTrace {
                trace,
                trace_level: TraceLevel::Detailed,
            }],
            batch_timestamp: chrono::Utc::now(),
            consent_timestamp: chrono::Utc::now(),
            trace_level: TraceLevel::Detailed,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            correlation_metadata: None,
        }
    }

    #[test]
    fn batch_envelope_body_count_matches_components() {
        let env = fixture(vec!["a", "b", "c"]);
        assert_eq!(env.body_count(), 3);
    }

    #[test]
    fn batch_envelope_text_bodies_yields_each_component() {
        let env = fixture(vec!["hello", "world"]);
        let bodies: Vec<_> = env.text_bodies().collect();
        assert_eq!(bodies.len(), 2);
        match &bodies[0].0 {
            MatchAddress::BatchComponent { index, json_path } => {
                assert_eq!(*index, 0);
                assert!(json_path.is_none());
            }
            other => panic!("expected BatchComponent, got {other:?}"),
        }
        assert!(bodies[0].1.contains("hello"));
        match &bodies[1].0 {
            MatchAddress::BatchComponent { index, .. } => assert_eq!(*index, 1),
            other => panic!("expected BatchComponent, got {other:?}"),
        }
        assert!(bodies[1].1.contains("world"));
    }

    #[test]
    fn batch_envelope_mutate_body_updates_target_component() {
        let mut env = fixture(vec!["alpha", "beta"]);
        env.mutate_body(
            &MatchAddress::BatchComponent {
                index: 1,
                json_path: None,
            },
            &mut |body: &mut String| {
                *body = r#"{"task_description":"REPLACED"}"#.to_string();
            },
        );
        let BatchEvent::CompleteTrace { trace, .. } = &env.events[0];
        assert_eq!(
            trace.components[0].data["task_description"]
                .as_str()
                .unwrap(),
            "alpha"
        );
        assert_eq!(
            trace.components[1].data["task_description"]
                .as_str()
                .unwrap(),
            "REPLACED"
        );
    }

    #[test]
    fn batch_envelope_mutate_body_ignores_inline_text_address() {
        let mut env = fixture(vec!["alpha"]);
        env.mutate_body(
            &MatchAddress::InlineText { json_path: None },
            &mut |body: &mut String| {
                *body = "PWNED".to_string();
            },
        );
        // No change — InlineText address on a BatchEnvelope is a no-op.
        let BatchEvent::CompleteTrace { trace, .. } = &env.events[0];
        assert_eq!(
            trace.components[0].data["task_description"]
                .as_str()
                .unwrap(),
            "alpha"
        );
    }

    #[test]
    fn batch_envelope_mutate_body_out_of_range_is_noop() {
        let mut env = fixture(vec!["only"]);
        env.mutate_body(
            &MatchAddress::BatchComponent {
                index: 7,
                json_path: None,
            },
            &mut |body: &mut String| {
                *body = "WROTE".into();
            },
        );
        let BatchEvent::CompleteTrace { trace, .. } = &env.events[0];
        assert_eq!(
            trace.components[0].data["task_description"]
                .as_str()
                .unwrap(),
            "only"
        );
    }
}
