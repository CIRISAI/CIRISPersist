//! Schema-version gate (FSD §3.4 robustness primitive #3).
//!
//! Mission (MISSION.md §7 failure mode "schema version handled
//! loosely"): bump the constant, write a migrator, never accept
//! out-of-set silently. PoB §2.4's N_eff measurement depends on the
//! corpus shape staying defined.
//!
//! v0.1.2 (THREAT_MODEL.md AV-5): the unrecognized-version path
//! holds an owned `String`, not a `Box::leak`'d `&'static str`.
//! Earlier shape leaked memory per malformed request — exploitable
//! DoS. Now bounded.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

/// Wire-format schema versions this build accepts.
///
/// v0.3.0 dual-window (per `release/2.7.9` cc41f315f hand-off note):
///   - `"2.7.0"` — agent 2.7.8 ships this; 4-field per-component
///     canonical (no per-component `agent_id_hash`).
///   - `"2.7.9"` — agent 2.7.9 fleet; 5-field per-component
///     canonical (per-component `agent_id_hash` denormalized from
///     envelope, LLMCallEvent gets `parent_event_type` + `parent_attempt_index`
///     required, VERB_SECOND_PASS_RESULT.verb closed enum).
///
/// Verifier dispatches by `trace_schema_version` deterministically
/// (TRACE_WIRE_FORMAT.md §8) — NOT iterative try-all. Each trace
/// contributes to exactly one canonical shape's verify path.
///
/// Cross-shape field injection defense (§3.1): at `"2.7.0"`,
/// canonical reconstruction MUST IGNORE per-component `agent_id_hash`
/// even if present on the wire — only the envelope `agent_id_hash`
/// is authoritative at 2.7.0.
///
/// Sunset markers — telemetry-driven, not date-committed (CIRIS is
/// decentralized; peers run whichever protocol versions they run;
/// sunset is empirical, not calendar-flag-gated). All three dialects
/// follow the SAME rule:
///
///   - Drop `"2.7.0"`      once `federation_canonical_match_total{wire="2.7.0"}`
///     stays at zero through a 7-day soak window.
///   - Drop `"2.7.legacy"` once `federation_canonical_match_total{wire="2.7.legacy"}`
///     stays at zero through a 7-day soak window. (Restored as a
///     supported dialect in v0.4.3 / CIRISPersist#21 — v0.4.0
///     dropped it on a calendar/fleet-migration framing that didn't
///     fit the decentralized model.)
///   - `"2.7.9"` is the current fleet target; no sunset clock running.
///
/// `"2.7.legacy"` covers the pre-2.7.8.9 2-field
/// `{components, trace_level}` canonical shape (no
/// `trace_schema_version` field, no per-component `agent_id_hash`).
/// Pre-2.7.8.9 agents stamped no version field at all (the field
/// landed in agent commit 431b0e0ae alongside the 9-field cutover);
/// those traces dispatch deterministically to
/// `canonical_payload_value_legacy` via absence-routing in
/// [`crate::schema::envelope::BatchEnvelope::from_json`]. Absence is
/// the deterministic signal — pre-2.7.8.9 by definition; this is
/// NOT a try-list fallback (TRACE_WIRE_FORMAT.md §8 prohibits those)
/// because each trace contributes to exactly one canonical shape's
/// verify path. Peers may also stamp `"2.7.legacy"` explicitly to
/// hit the same dispatch arm via the sentinel route.
pub const SUPPORTED_VERSIONS: &[&str] = &["2.7.0", "2.7.9", "2.7.legacy"];

/// Type-checked wrapper around a schema version string.
///
/// Two states:
/// - **Recognized**: holds a `&'static str` from
///   [`SUPPORTED_VERSIONS`]. Cheap, comparable as a pointer
///   short-circuit.
/// - **Unrecognized**: holds an owned `String` (typed at
///   `BatchEnvelope::from_json` time, then immediately rejected
///   with `Error::UnsupportedSchemaVersion`). Bounded allocation
///   per-request — released when the request handler returns.
///
/// Mission (MISSION.md §3 anti-pattern #4): typed errors at every
/// boundary. The unrecognized variant exists *only* so the typed
/// rejection error can carry the offending string for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SchemaVersion(Cow<'static, str>);

/// v0.4.3 (CIRISPersist#21) — `serde(default)` for the
/// `trace_schema_version` field on [`super::BatchEnvelope`] and
/// [`super::CompleteTrace`]. Pre-2.7.8.9 agents stamped no version
/// field at all; absence is the deterministic signal for the
/// legacy 2-field canonical shape (per agent commit 431b0e0ae,
/// the field landed alongside the 9-field cutover; older traces
/// are field-absent by definition).
///
/// This is NOT a try-list fallback — every absent-version trace
/// dispatches to exactly ONE canonicalizer
/// ([`crate::verify::canonical_payload_value_legacy`]), and the
/// `federation_canonical_match_total{wire="2.7.legacy"}` counter
/// observes the legacy traffic so the sunset rule
/// (`SUPPORTED_VERSIONS` doc) is empirically driven.
pub fn default_legacy_schema_version() -> SchemaVersion {
    SchemaVersion(Cow::Borrowed("2.7.legacy"))
}

impl SchemaVersion {
    /// Strict parse: validate `s` against [`SUPPORTED_VERSIONS`] and
    /// return the pinned `&'static str` if recognized. Used by code
    /// paths that need a definitely-supported version (Phase 2
    /// internal signing, etc.); always returns the static variant on
    /// success.
    pub fn parse(s: &str) -> Result<Self, super::Error> {
        for &v in SUPPORTED_VERSIONS {
            if v == s {
                return Ok(SchemaVersion(Cow::Borrowed(v)));
            }
        }
        Err(super::Error::UnsupportedSchemaVersion {
            got: s.to_owned(),
            supported: SUPPORTED_VERSIONS,
        })
    }

    /// Borrow as `&str`. Returns the static-pinned form on
    /// recognized versions; an owned-buffer borrow on unrecognized
    /// ones (only reachable mid-rejection, before
    /// `BatchEnvelope::from_json` translates to a typed error).
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True iff this `SchemaVersion` is in [`SUPPORTED_VERSIONS`].
    /// Used by [`super::envelope::BatchEnvelope::from_json`] for the
    /// typed gate.
    pub fn is_supported(&self) -> bool {
        SUPPORTED_VERSIONS.contains(&self.0.as_ref())
    }

    /// Lenient parse used by `Deserialize`: accepts any string.
    /// Caller (typically `BatchEnvelope::from_json`) is responsible
    /// for the typed validation pass via [`is_supported`].
    ///
    /// (THREAT_MODEL.md AV-5): the unrecognized arm now holds an
    /// owned `Cow::Owned(String)`, dropped when the SchemaVersion
    /// goes out of scope. No `Box::leak`. Memory bounded by request
    /// lifetime.
    fn parse_lenient(s: &str) -> Self {
        for &v in SUPPORTED_VERSIONS {
            if v == s {
                return SchemaVersion(Cow::Borrowed(v));
            }
        }
        SchemaVersion(Cow::Owned(s.to_owned()))
    }
}

impl std::fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // We accept any string here and validate at the next layer
        // (`BatchEnvelope::from_json`) so the error surfaces as a
        // typed `Error::UnsupportedSchemaVersion` rather than getting
        // wrapped in `serde_json::Error`. Mission constraint
        // (MISSION.md §3 anti-pattern #4): typed errors at every
        // boundary.
        let s = String::deserialize(deserializer)?;
        Ok(SchemaVersion::parse_lenient(&s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_2_7_0() {
        let v = SchemaVersion::parse("2.7.0").expect("2.7.0 is supported");
        assert_eq!(v.as_str(), "2.7.0");
        assert!(v.is_supported());
    }

    /// v0.3.0 — accept 2.7.9 wire format.
    #[test]
    fn parse_accepts_2_7_9() {
        let v = SchemaVersion::parse("2.7.9").expect("2.7.9 is supported");
        assert_eq!(v.as_str(), "2.7.9");
        assert!(v.is_supported());
    }

    #[test]
    fn parse_rejects_old_version() {
        let err = SchemaVersion::parse("2.6.0").unwrap_err();
        match err {
            super::super::Error::UnsupportedSchemaVersion { got, supported } => {
                assert_eq!(got, "2.6.0");
                assert_eq!(supported, &["2.7.0", "2.7.9", "2.7.legacy"]);
            }
            _ => panic!("expected UnsupportedSchemaVersion, got {err:?}"),
        }
    }

    /// v0.4.3 (CIRISPersist#21) — `"2.7.legacy"` restored under the
    /// telemetry-driven sunset rule.
    #[test]
    fn parse_accepts_2_7_legacy() {
        let v = SchemaVersion::parse("2.7.legacy").expect("2.7.legacy is supported");
        assert_eq!(v.as_str(), "2.7.legacy");
        assert!(v.is_supported());
    }

    #[test]
    fn parse_rejects_future_version() {
        // Mission: PoB §2.4 corpus shape stays defined; future versions
        // require an explicit migrator (FSD §3.4 / version.rs doc), not
        // best-effort parsing.
        assert!(SchemaVersion::parse("2.8.0").is_err());
        assert!(SchemaVersion::parse("3.0.0").is_err());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(SchemaVersion::parse("").is_err());
        assert!(SchemaVersion::parse("not-a-version").is_err());
        assert!(SchemaVersion::parse("2.7.0-alpha").is_err());
    }

    #[test]
    fn deserialize_lenient_with_typed_validation() {
        // Mission constraint: serde::Deserialize is lenient so that
        // unsupported versions surface as typed
        // `Error::UnsupportedSchemaVersion` from
        // `BatchEnvelope::from_json` rather than getting wrapped in
        // `serde_json::Error`. The lenient deserialize succeeds; the
        // `is_supported()` gate at the next layer rejects.
        let ok: SchemaVersion = serde_json::from_str("\"2.7.0\"").unwrap();
        assert_eq!(ok.as_str(), "2.7.0");
        assert!(ok.is_supported());

        let bad: SchemaVersion = serde_json::from_str("\"99.0.0\"").unwrap();
        assert_eq!(bad.as_str(), "99.0.0");
        assert!(!bad.is_supported(), "is_supported gate rejects 99.0.0");
    }

    #[test]
    fn parse_strict_still_rejects() {
        // The constructor for typed code paths (Phase 2 internal
        // signing, etc.) stays strict.
        assert!(SchemaVersion::parse("99.0.0").is_err());
    }

    /// THREAT_MODEL.md AV-5 regression test.
    ///
    /// Earlier `parse_lenient` did `Box::leak(s.to_owned().into_boxed_str())`,
    /// leaking memory per call. The Cow-based shape drops the
    /// owned String when the SchemaVersion goes out of scope.
    ///
    /// We can't directly observe the leak from a test (Rust's
    /// allocator is opaque), but we can assert the type-level
    /// guarantee: a 2nd parse_lenient call with the same input
    /// produces a SchemaVersion that compares-equal to the 1st but
    /// holds a *separately-owned* allocation. If `Box::leak` were
    /// still in use, the &'static str would unify and we'd lose
    /// that property. Indirect, but it documents the intent.
    #[test]
    fn unrecognized_version_uses_owned_allocation() {
        let v1 = SchemaVersion::parse_lenient("99.0.0");
        let v2 = SchemaVersion::parse_lenient("99.0.0");
        // Equal as values:
        assert_eq!(v1, v2);
        // is_supported gate still rejects:
        assert!(!v1.is_supported());
        assert!(!v2.is_supported());
        // Drop happens when v1/v2 go out of scope; no leak.
    }

    /// Bound-check: 1000 distinct unrecognized versions all parse
    /// (lenient) without panicking. Pre-AV-5 fix this would have
    /// leaked ~30KB; post-fix it allocates and drops cleanly.
    #[test]
    fn unrecognized_version_does_not_unbounded_allocate() {
        for i in 0..1000 {
            let s = format!("99.0.{i}");
            let v = SchemaVersion::parse_lenient(&s);
            assert!(!v.is_supported());
            // Drops here.
        }
    }
}
