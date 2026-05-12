//! Authoritative `SCRUB_FIELDS` catalog (v0.6.0+, CIRISPersist#19).
//!
//! Lifted verbatim from CIRISLens `cirislens-core/src/scrubber/fields.rs`
//! (sole behavioral change: `lazy_static` → `std::sync::OnceLock`,
//! same lookup semantics + same O(1) cost amortized over first call).
//!
//! Updates require a code change — intentional, since `SCRUB_FIELDS`
//! is part of the security boundary. Adding a field here means the
//! walker (`super::walker`) recurses into matching JSON object keys
//! and runs NER + regex against their string values.

use std::collections::HashSet;
use std::sync::OnceLock;

static SCRUB_FIELDS_CELL: OnceLock<HashSet<&'static str>> = OnceLock::new();

/// The canonical set of payload field names that contain agent-text
/// content. The walker (`super::walker::walk`) only descends into
/// JSON objects when a key matches; non-matched fields are
/// pass-through (no text-bearing content).
pub fn scrub_fields() -> &'static HashSet<&'static str> {
    SCRUB_FIELDS_CELL.get_or_init(|| {
        let mut s = HashSet::new();

        // THOUGHT_START
        s.insert("task_description");
        s.insert("initial_context");
        s.insert("thought_content");

        // SNAPSHOT_AND_CONTEXT
        s.insert("system_snapshot");
        s.insert("gathered_context");
        s.insert("relevant_memories");
        s.insert("conversation_history");
        s.insert("current_thought_summary");

        // DMA_RESULTS
        s.insert("reasoning");
        s.insert("prompt_used");
        s.insert("combined_analysis");
        s.insert("flags");
        s.insert("alignment_check");
        s.insert("conflicts");
        s.insert("stakeholders");

        // ASPDMA_RESULT
        s.insert("action_rationale");
        s.insert("reasoning_summary");
        s.insert("action_parameters");
        s.insert("aspdma_prompt");
        s.insert("questions");
        s.insert("completion_reason");

        // CONSCIENCE_RESULT
        s.insert("conscience_override_reason");
        s.insert("epistemic_data");
        s.insert("updated_status_content");
        s.insert("entropy_reason");
        s.insert("coherence_reason");
        s.insert("optimization_veto_justification");
        s.insert("epistemic_humility_justification");
        s.insert("epistemic_humility_uncertainties");

        // ACTION_RESULT
        s.insert("execution_error");

        // IDMA_RESULT
        s.insert("intervention_recommendation");
        s.insert("next_best_recovery_step");
        s.insert("correlation_factors");
        s.insert("top_correlation_factors");
        s.insert("common_cause_flags");
        s.insert("sources_identified");
        s.insert("source_ids");
        s.insert("source_clusters");
        s.insert("source_types");
        s.insert("source_type_counts");
        s.insert("pairwise_correlation_summary");
        s.insert("reasoning_state");

        s
    })
}

/// Back-compat alias for the cirislens-core public name. Returns the
/// same `&'static HashSet` as [`scrub_fields()`].
#[allow(non_snake_case)]
pub fn SCRUB_FIELDS() -> &'static HashSet<&'static str> {
    scrub_fields()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_fields_present() {
        let s = scrub_fields();
        assert!(s.contains("task_description"));
        assert!(s.contains("flags"));
        assert!(s.contains("source_ids"));
        assert!(s.contains("thought_content"));
    }

    #[test]
    fn random_field_absent() {
        let s = scrub_fields();
        assert!(!s.contains("random_field_name"));
        assert!(!s.contains("agent_name"));
    }

    #[test]
    fn field_count_sanity() {
        // Ballpark: ~40 fields. If this drops massively, we lost coverage.
        // If it explodes, we may be over-scrubbing.
        let n = scrub_fields().len();
        assert!(n >= 35, "SCRUB_FIELDS shrunk to {n} — coverage regression?");
        assert!(n <= 60, "SCRUB_FIELDS grew to {n} — review for over-scope?");
    }
}
