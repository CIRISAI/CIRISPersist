//! v20.0.0 (CIRISPersist#495, wall 2) — the TYPED attestation-envelope
//! core: the universal envelope keys as a struct whose serde field names
//! ARE the projection paths.
//!
//! Before this cut the envelope was an opaque `serde_json::Value` on both
//! sides of every boundary: the server hand-built keys with `json!{}`,
//! persist hand-read them with `json_extract('$.x')` / `->>'x'`, and
//! nothing bound writer to reader — a rename of
//! `references_attestation_id` would have made the withdraws/supersedes
//! `NOT EXISTS` check never match, silently leaving **a withdrawn
//! attestation active**. Now:
//!
//! - [`EnvelopeCore`] carries the universal keys TYPED; dimension-specific
//!   payload rides `#[serde(flatten)] extra` — openness is preserved
//!   (covered by the vocabulary hash), the universal keys are not.
//! - [`paths`] is the ONE set of key constants; every SQL projection
//!   interpolates them, every Rust accessor reads through them, and the
//!   `envelope_core_paths_bind_serde_names` witness asserts each constant
//!   round-trips through serde — so a struct-field rename that isn't
//!   mirrored in the constant (or vice versa) fails the build's tests.
//! - The emit/local INPUT types now carry `EnvelopeCore` (the v20 flip):
//!   producers CONSTRUCT envelopes, they do not spell keys. Stored rows
//!   keep `serde_json::Value` — storage is byte-faithful; signatures ride
//!   JCS (order-independent), so the typed re-serialization is invisible
//!   to every verifier.

use serde::{Deserialize, Serialize};

/// The ONE set of universal envelope key constants. SQL interpolates
/// these; accessors read through them; the witness binds them to
/// [`EnvelopeCore`]'s serde names.
pub mod paths {
    /// The CEG Information-Type parameter (see the trace:* validator).
    pub const DIMENSION: &str = "dimension";
    /// The composer target: which attestation a `withdraws` / `supersedes`
    /// / `recants` / `delegates_to` row references.
    pub const REFERENCES_ATTESTATION_ID: &str = "references_attestation_id";
    /// Delegation scope: bare string OR array of tokens (both wire shapes
    /// are established — see `trust_root::scope_contains`).
    pub const SCOPE: &str = "scope";
    /// Charter pre-rotation commitment (v19.0.0 #488, the KERI lesson).
    pub const PRE_ROTATION_COMMITMENT: &str = "pre_rotation_commitment";
    /// Charter recovery: the predecessor root being rotated.
    pub const RECOVERS: &str = "recovers";
    /// Charter recovery: the pre-committed successor key set.
    pub const SUCCESSOR_KEYS: &str = "successor_keys";
    /// Withdraws composer: the producer's stated reason.
    pub const WITHDRAWAL_REASON: &str = "withdrawal_reason";
    /// v21.9.0 (CIRISPersist#519 item 2 field-hoist) — the CI
    /// recipient-RECEIVE axis: how a consented payload is delivered
    /// (edge-owned processor `reachability.rs`; persist types it). Hoisted
    /// from `extra` to a typed `EnvelopeCore` field, byte-invariant.
    pub const DELIVERY_MODE: &str = "delivery_mode";
    /// v21.9.0 (CIRISPersist#519 item 2 field-hoist) — the CI
    /// temporal-lifecycle erasure window: the deadline by which a
    /// consented payload must be deleted (persist-owned lifecycle
    /// processor — the breach signal). Hoisted from `extra`, byte-invariant.
    pub const DELETION_WINDOW: &str = "deletion_window";
}

/// A delegation `scope` in either established wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeSet {
    /// The bare-string form (`"scope": "consent_revocation"`).
    One(String),
    /// The token-set form (`"scope": ["infra:serve", …]`).
    Many(Vec<String>),
}

impl ScopeSet {
    /// Does the set contain `token` (exact match, either shape)?
    #[must_use]
    pub fn contains(&self, token: &str) -> bool {
        match self {
            ScopeSet::One(s) => s == token,
            ScopeSet::Many(v) => v.iter().any(|s| s == token),
        }
    }
}

/// v20.0.0 (#495) — the typed universal envelope. Every field is optional
/// (envelopes carry the keys their kind needs); everything else rides
/// `extra` untouched, byte-order-free (signatures are over JCS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EnvelopeCore {
    /// [`paths::DIMENSION`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimension: Option<String>,
    /// [`paths::REFERENCES_ATTESTATION_ID`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references_attestation_id: Option<String>,
    /// [`paths::SCOPE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
    /// [`paths::PRE_ROTATION_COMMITMENT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_rotation_commitment: Option<String>,
    /// [`paths::RECOVERS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovers: Option<String>,
    /// [`paths::SUCCESSOR_KEYS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_keys: Option<Vec<String>>,
    /// [`paths::WITHDRAWAL_REASON`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal_reason: Option<String>,
    /// [`paths::DELIVERY_MODE`] — v21.9.0 (#519 field-hoist). Typed here
    /// (was untyped `extra`); the PROCESSOR is edge's
    /// (`reachability.rs#ReachabilityTracker`). Byte-invariant: `None` ⇒ no
    /// key, `Some` ⇒ same `delivery_mode` key/value ⇒ identical JCS bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_mode: Option<String>,
    /// [`paths::DELETION_WINDOW`] — v21.9.0 (#519 field-hoist). Typed here
    /// (was untyped `extra`) with a persist-owned lifecycle processor (the
    /// breach signal — see [`super::deletion_window`]). Byte-invariant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_window: Option<String>,
    /// Every dimension-specific key, untyped and preserved. Covered by
    /// the envelope vocabulary hash, not by the compiler.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl EnvelopeCore {
    /// Parse from a JSON value. Refuses non-objects (an envelope is
    /// always an object); every unknown key lands in `extra` losslessly.
    pub fn from_value(v: serde_json::Value) -> Result<Self, super::Error> {
        if !v.is_object() {
            return Err(super::Error::InvalidArgument(
                "attestation envelope must be a JSON object".into(),
            ));
        }
        serde_json::from_value(v)
            .map_err(|e| super::Error::InvalidArgument(format!("envelope parse: {e}")))
    }

    /// Serialize to the storage/wire `Value` (the stored row keeps
    /// `Value`; signatures ride JCS so field order is immaterial).
    #[must_use]
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("EnvelopeCore serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE binding witness: every [`paths`] constant round-trips through
    /// [`EnvelopeCore`]'s serde — a struct-field rename not mirrored in
    /// the constant (or vice versa) fails HERE, at build-test time, not
    /// as a silent NULL in a projection.
    #[test]
    fn envelope_core_paths_bind_serde_names() {
        let core = EnvelopeCore {
            dimension: Some("d:v1".into()),
            references_attestation_id: Some("ref-1".into()),
            scope: Some(ScopeSet::Many(vec!["infra:serve".into()])),
            pre_rotation_commitment: Some("ab".repeat(32)),
            recovers: Some("old-root".into()),
            successor_keys: Some(vec!["k1".into()]),
            withdrawal_reason: Some("test".into()),
            delivery_mode: Some("mandatory".into()),
            deletion_window: Some("2027-01-01T00:00:00Z".into()),
            extra: serde_json::Map::new(),
        };
        let v = core.to_value();
        for (path, expect_present) in [
            (paths::DIMENSION, true),
            (paths::REFERENCES_ATTESTATION_ID, true),
            (paths::SCOPE, true),
            (paths::PRE_ROTATION_COMMITMENT, true),
            (paths::RECOVERS, true),
            (paths::SUCCESSOR_KEYS, true),
            (paths::WITHDRAWAL_REASON, true),
            (paths::DELIVERY_MODE, true),
            (paths::DELETION_WINDOW, true),
        ] {
            assert_eq!(
                v.get(path).is_some(),
                expect_present,
                "paths::{path} does not bind an EnvelopeCore serde field"
            );
        }
        // Round-trip losslessness incl. extras.
        let mut with_extra = core.clone();
        with_extra
            .extra
            .insert("score".into(), serde_json::json!(0.9));
        let rt = EnvelopeCore::from_value(with_extra.to_value()).unwrap();
        assert_eq!(rt, with_extra, "lossless round-trip incl. extras");
    }

    /// v21.9.0 (CIRISPersist#519 field-hoist) — THE byte-invariance witness:
    /// hoisting `delivery_mode` / `deletion_window` from untyped `extra` to
    /// typed fields must NOT change the canonical bytes, so a signature
    /// computed before the hoist still verifies after. A raw JSON envelope
    /// carrying these keys must canonicalize IDENTICALLY to the same envelope
    /// round-tripped through the (now-typed) `EnvelopeCore` — proving the two
    /// fields land under the same wire keys with the same values. If serde
    /// renamed them, or the flatten interaction reordered/renamed anything,
    /// this fails.
    #[test]
    fn hoisted_fields_are_canonicalization_byte_invariant() {
        use crate::verify::canonical::ceg_produce_canonicalize;
        // A raw envelope as a producer would emit it (keys in extra, pre-hoist
        // shape) — including an unrelated payload key to exercise flatten.
        let raw = serde_json::json!({
            "dimension": "trace:complete:v1",
            "delivery_mode": "mandatory",
            "deletion_window": "2027-01-01T00:00:00Z",
            "trace_id": "t-1",
            "score": 0.9,
        });
        let via_typed = EnvelopeCore::from_value(raw.clone()).unwrap().to_value();
        // The typed fields captured the two keys (not left in extra)...
        let parsed = EnvelopeCore::from_value(raw.clone()).unwrap();
        assert_eq!(parsed.delivery_mode.as_deref(), Some("mandatory"));
        assert_eq!(
            parsed.deletion_window.as_deref(),
            Some("2027-01-01T00:00:00Z")
        );
        assert!(!parsed.extra.contains_key("delivery_mode"));
        assert!(!parsed.extra.contains_key("deletion_window"));
        // ...and the canonical bytes are byte-identical raw vs round-tripped.
        assert_eq!(
            ceg_produce_canonicalize(&raw).unwrap(),
            ceg_produce_canonicalize(&via_typed).unwrap(),
            "the field-hoist changed the canonical bytes — existing signatures would break"
        );
    }

    /// Both established scope wire shapes parse and match.
    #[test]
    fn scope_set_both_wire_shapes() {
        let one: EnvelopeCore =
            serde_json::from_value(serde_json::json!({"scope": "manifest:foo"})).unwrap();
        assert!(one.scope.unwrap().contains("manifest:foo"));
        let many: EnvelopeCore =
            serde_json::from_value(serde_json::json!({"scope": ["a", "b"]})).unwrap();
        assert!(many.scope.as_ref().unwrap().contains("b"));
        assert!(!many.scope.unwrap().contains("c"));
    }
}

/// v20.0.0 (#495) — the envelope-vocabulary manifest: the universal path
/// constants + the consent-state dimension prefixes, as one canonical
/// JSON document. Mirrors `WIRE_VOCABULARY_HASH` / the trace-summary
/// contract: CIRISServer serves the hash on `/v1/health`, consumers
/// assert it, and a vocabulary change on either side fails loudly on
/// both.
pub fn envelope_vocabulary_json() -> serde_json::Value {
    use crate::federation::consent::consent_dimension as cd;
    serde_json::json!({
        "contract": "attestation_envelope_vocabulary",
        "version": 1,
        "universal_paths": [
            paths::DIMENSION,
            paths::REFERENCES_ATTESTATION_ID,
            paths::SCOPE,
            paths::PRE_ROTATION_COMMITMENT,
            paths::RECOVERS,
            paths::SUCCESSOR_KEYS,
            paths::WITHDRAWAL_REASON,
        ],
        "consent_dimension_prefixes": [
            cd::STATE_GRANTED_PREFIX,
            cd::STATE_REVOKED_PREFIX,
            cd::STATE_EXPIRED_PREFIX,
        ],
    })
}

/// sha256 (lowercase hex) over JCS of [`envelope_vocabulary_json`].
pub fn envelope_vocabulary_sha256() -> String {
    use sha2::Digest as _;
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope_vocabulary_json())
        .expect("envelope vocabulary canonicalizes");
    hex::encode(sha2::Sha256::digest(&canonical))
}

/// The PINNED envelope-vocabulary hash (see
/// `envelope_vocabulary_hash_is_pinned` — computed == pinned is a gating
/// witness; changing the vocabulary without a deliberate re-pin fails CI).
pub const ENVELOPE_VOCABULARY_SHA256: &str =
    "f1a0bc77d24915fc1e099c4715621c936ca4fb38678b71268b88a9d614c04929";

#[cfg(test)]
mod vocab_tests {
    use super::*;

    /// The pin gate (the loud-drift discipline, third instance).
    #[test]
    fn envelope_vocabulary_hash_is_pinned() {
        assert_eq!(
            envelope_vocabulary_sha256(),
            ENVELOPE_VOCABULARY_SHA256,
            "envelope vocabulary changed: re-pin ENVELOPE_VOCABULARY_SHA256 \
             deliberately (and notify /v1/health + consumer-test holders)"
        );
    }
}
