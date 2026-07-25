//! v21.2.0 (CIRISPersist#509 FLOOR) — the seed of the closed consent
//! grammar.
//!
//! Contextual-integrity (Nissenbaum) frames a consented information flow
//! as five parameters: sender, subject, recipient, information-type, and
//! transmission-principle. Persist's existing wire vocabulary already
//! maps onto four of them:
//!
//! - **sender** → `attesting_key_id` (who authored the grant)
//! - **subject** → `subject_key_ids` (whose flow the grant concerns — for
//!   a `consent:replication:v1` grant, the peer(s) it extends
//!   replication trust to)
//! - **recipient** → `cohort_scope` (how far the granted content may
//!   travel: `self` / `family` / `community` / … / `federation`)
//! - **information-type** → `dimension`, narrowed by
//!   [`grant_attestation_prefixes`] / [`covers`] to the namespace-prefix
//!   set a grant actually authorizes
//!
//! The fifth — **transmission-principle** — is the `consent:*` dimension
//! family itself (the norm under which the flow is authorized).
//!
//! This module implements ONLY the one instance persist currently acts
//! on: [`GRANT_DIMENSION`]'s `payload.attestation_prefixes`, read by
//! [`crate::Engine::promote_consented_backlog`]. The full closed grammar
//! — a `CONSENT_GRAMMAR_HASH`-pinned enumeration of every legal (sender,
//! subject, recipient, information-type, transmission-principle) tuple —
//! is the tracked follow-up; this seed deliberately does not pre-build
//! that generality.

use super::consent_peer_set;

/// The consent-replication grant dimension (`"consent:replication:v1"`).
/// Single-sourced from [`consent_peer_set::DIMENSION`] — persist has
/// exactly one wire constant for this dimension string; this alias
/// exists so callers reasoning about the consent GRAMMAR (this module)
/// don't have to reach into the E7 PROJECTION module for it.
pub const GRANT_DIMENSION: &str = consent_peer_set::DIMENSION;

/// Read `envelope["payload"]["attestation_prefixes"]` as the JCS-sorted
/// array of namespace-prefix strings a `consent:replication:v1` grant
/// authorizes for promotion (e.g. `["trace:"]`). A trailing colon is
/// significant — `covers` matches by plain `str::starts_with`, so
/// `"trace"` (no colon) would ALSO match `"trace_summary:v1"`, which
/// `"trace:"` correctly excludes.
///
/// FAIL-CLOSED by construction — every malformed shape resolves to "this
/// grant covers nothing", never "this grant covers everything":
///
/// - `payload` absent/non-object, or `attestation_prefixes`
///   absent/non-array → empty vec.
/// - A non-string array entry is SKIPPED (not a hard error — the array
///   may carry future non-string metadata this reader doesn't
///   understand; skipping one malformed entry is safer than discarding
///   the whole grant).
/// - An EMPTY-STRING prefix is SKIPPED. `"".starts_with("")` is `true`
///   for every dimension — an empty prefix would silently grant
///   promotion of EVERYTHING this node ever local-mints. Never admit an
///   accidental total grant.
pub fn grant_attestation_prefixes(envelope: &serde_json::Value) -> Vec<String> {
    envelope
        .get("payload")
        .and_then(|p| p.get("attestation_prefixes"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// True iff any of `prefixes` is a `str::starts_with` prefix of
/// `dimension` — i.e. the grant covers `dimension`.
#[must_use]
pub fn covers(prefixes: &[String], dimension: &str) -> bool {
    prefixes.iter().any(|p| dimension.starts_with(p.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_dimension_is_the_consent_peer_set_dimension() {
        assert_eq!(GRANT_DIMENSION, consent_peer_set::DIMENSION);
    }

    #[test]
    fn happy_path_extracts_prefixes() {
        let envelope = serde_json::json!({
            "dimension": GRANT_DIMENSION,
            "payload": {
                "grants": "replication",
                "attestation_prefixes": ["trace:", "capacity:sustained_coherence:v1"],
            },
        });
        assert_eq!(
            grant_attestation_prefixes(&envelope),
            vec![
                "trace:".to_string(),
                "capacity:sustained_coherence:v1".to_string()
            ]
        );
    }

    #[test]
    fn missing_payload_yields_empty() {
        let envelope = serde_json::json!({"dimension": GRANT_DIMENSION});
        assert!(grant_attestation_prefixes(&envelope).is_empty());
    }

    #[test]
    fn non_array_attestation_prefixes_yields_empty() {
        let envelope = serde_json::json!({"payload": {"attestation_prefixes": "trace:"}});
        assert!(grant_attestation_prefixes(&envelope).is_empty());

        let envelope_missing_payload_object = serde_json::json!({"payload": "not-an-object"});
        assert!(grant_attestation_prefixes(&envelope_missing_payload_object).is_empty());
    }

    #[test]
    fn non_string_entries_are_skipped_not_fatal() {
        let envelope = serde_json::json!({
            "payload": {"attestation_prefixes": ["trace:", 42, null, {"x": 1}, "capacity:"]},
        });
        assert_eq!(
            grant_attestation_prefixes(&envelope),
            vec!["trace:".to_string(), "capacity:".to_string()]
        );
    }

    #[test]
    fn empty_string_prefix_is_skipped_never_a_total_grant() {
        let envelope = serde_json::json!({
            "payload": {"attestation_prefixes": ["", "trace:"]},
        });
        assert_eq!(
            grant_attestation_prefixes(&envelope),
            vec!["trace:".to_string()]
        );

        // An all-empty-string array covers nothing (fail-closed), not
        // everything.
        let all_empty = serde_json::json!({"payload": {"attestation_prefixes": [""]}});
        let prefixes = grant_attestation_prefixes(&all_empty);
        assert!(prefixes.is_empty());
        assert!(!covers(&prefixes, "trace:complete:v1"));
    }

    #[test]
    fn covers_matches_prefix_not_arbitrary_substring() {
        let prefixes = vec!["trace:".to_string()];
        assert!(covers(&prefixes, "trace:complete:v1"));
        assert!(!covers(&prefixes, "capacity:sustained_coherence:v1"));
        // Trailing colon is significant: "trace" (no colon) is NOT one of
        // our prefixes, so a same-named-but-different dimension family
        // must not match.
        assert!(!covers(&prefixes, "trace_summary:v1"));
    }
}
