//! Ed25519 signature verification over canonical bytes.
//!
//! # Mission alignment (MISSION.md §2 — `verify/`)
//!
//! Verify-before-persist (FSD §3.3 step 2). The agent's signature is
//! the cryptographic floor of the corpus PoB §2.4 measures; storing
//! unverified bytes corrupts the federation primitive at its base.
//!
//! Constraint: `verify_strict` semantics. Reject weak keys, malleable
//! signatures, schema-version mismatch, audit-anchor inconsistency.
//! Every rejection emits a typed error variant (MISSION.md §3
//! anti-pattern #4); never silently coerce.
//!
//! Source-of-truth: TRACE_WIRE_FORMAT.md §8 (canonical payload
//! construction); FSD §3.3 step 2 (verify-before-persist contract).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};

use super::canonical::Canonicalizer;
use super::Error;
use crate::schema::CompleteTrace;

/// Public-key directory abstraction.
///
/// Phase 1: backed by `accord_public_keys` table. Phase 2+: same trait,
/// possibly fronted by an in-memory cache fed by Reticulum announces.
///
/// Mission (MISSION.md §3 anti-pattern #3): no bypass branches; admin
/// keys, agent keys, and federation peer keys all verify by the same
/// path. The directory is the single source-of-public-keys-truth.
pub trait PublicKeyDirectory {
    /// Look up a verifying key by its `signature_key_id`.
    ///
    /// `Ok(None)` is "we have no record of this key" — caller MUST
    /// reject the trace (the corpus only counts verified evidence).
    /// `Err` is an internal lookup failure (DB down, etc.) — also a
    /// rejection but for a different operational reason.
    fn lookup(
        &self,
        key_id: &str,
    ) -> Result<Option<VerifyingKey>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Build the canonical payload that the agent signed
/// (TRACE_WIRE_FORMAT.md §8).
///
/// Mission: the field set, ordering convention, and `_strip_empty`
/// semantics here are byte-load-bearing. The canonical_value
/// function below MUST match the agent's
/// `accord_metrics/services.py:_compute_canonical_payload` shape
/// (referenced in TRACE_WIRE_FORMAT.md §8).
///
/// We construct the payload as a `serde_json::Value` and let the
/// `Canonicalizer` produce the actual bytes — the canonicalizer is
/// pluggable (Python-compat or JCS), the field set is fixed.
pub fn canonical_payload_value(trace: &CompleteTrace) -> serde_json::Value {
    // Per §8, the canonical fields are:
    //   trace_id, thought_id, task_id, agent_id_hash, started_at,
    //   completed_at, trace_level, trace_schema_version, components.
    //
    // Each component contributes:
    //   component_type, data (post-_strip_empty), event_type, timestamp.
    //
    // The agent stripped empties before signing; what arrives over
    // the wire IS post-strip. The component `data` field on
    // TraceComponent is already in that shape.
    let components: Vec<serde_json::Value> = trace
        .components
        .iter()
        .map(|c| {
            serde_json::json!({
                "component_type": c.component_type,
                "data": serde_json::Value::Object(c.data.clone()),
                "event_type": c.event_type,
                "timestamp": format_iso8601(&c.timestamp),
            })
        })
        .collect();

    let mut payload = serde_json::Map::new();
    payload.insert(
        "trace_id".into(),
        serde_json::Value::String(trace.trace_id.clone()),
    );
    payload.insert(
        "thought_id".into(),
        serde_json::Value::String(trace.thought_id.clone()),
    );
    // task_id may be null per the wire-format spec.
    payload.insert(
        "task_id".into(),
        match &trace.task_id {
            Some(t) => serde_json::Value::String(t.clone()),
            None => serde_json::Value::Null,
        },
    );
    payload.insert(
        "agent_id_hash".into(),
        serde_json::Value::String(trace.agent_id_hash.clone()),
    );
    payload.insert(
        "started_at".into(),
        serde_json::Value::String(format_iso8601(&trace.started_at)),
    );
    payload.insert(
        "completed_at".into(),
        serde_json::Value::String(format_iso8601(&trace.completed_at)),
    );
    payload.insert(
        "trace_level".into(),
        serde_json::to_value(trace.trace_level).expect("TraceLevel serializes"),
    );
    payload.insert(
        "trace_schema_version".into(),
        serde_json::Value::String(trace.trace_schema_version.as_str().to_owned()),
    );
    payload.insert("components".into(), serde_json::Value::Array(components));

    serde_json::Value::Object(payload)
}

/// Format a `DateTime<Utc>` as Python `datetime.isoformat()` produces:
/// `"2026-04-30T00:15:53.123456+00:00"` — microsecond precision,
/// `+00:00` suffix (not `Z`).
///
/// Mission category §4 "Canonicalization parity": Python and chrono
/// disagree on the timestamp formatter by default; chrono prefers
/// trailing `Z` and may emit different fractional-second precision.
/// This function pins the format to what the agent's signer
/// produced.
///
/// **Caveat:** for verify against agent-produced canonical bytes, we
/// should round-trip the original timestamp string from the wire if
/// possible (preserves byte-exact). When that's not available (Phase
/// 2 internal-signing path), this format function is the canonical
/// shape.
fn format_iso8601(t: &chrono::DateTime<chrono::Utc>) -> String {
    // Python's datetime.isoformat() emits microsecond precision:
    //   "%Y-%m-%dT%H:%M:%S.%6f%:z"
    // chrono format: %.6f gives microseconds, %:z gives "+HH:MM".
    t.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string()
}

/// Verify a `CompleteTrace`'s signature against the canonical bytes
/// the canonicalizer produces.
///
/// This is the verify-before-persist gate (FSD §3.3 step 2). On
/// `Ok(())` the caller may persist; on `Err(_)` the caller MUST
/// reject and emit a structured 422 to the agent.
pub fn verify_trace<C, K>(
    trace: &CompleteTrace,
    canonicalizer: &C,
    keys: &K,
) -> Result<(), Error>
where
    C: Canonicalizer + ?Sized,
    K: PublicKeyDirectory + ?Sized,
{
    // 1. Decode signature bytes from base64.
    let sig_bytes = BASE64
        .decode(&trace.signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(Error::InvalidSignature(format!(
            "expected {SIGNATURE_LENGTH}-byte signature, got {}",
            sig_bytes.len()
        )));
    }
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .expect("length-checked above"),
    );

    // 2. Look up the verifying key for the claimed signature_key_id.
    let key = keys
        .lookup(&trace.signature_key_id)
        .map_err(|e| Error::InvalidSignature(format!("key lookup failed: {e}")))?
        .ok_or_else(|| Error::UnknownKey(trace.signature_key_id.clone()))?;

    // 3. Build the canonical payload value, then canonicalize bytes.
    let payload = canonical_payload_value(trace);
    let bytes = canonicalizer.canonicalize_value(&payload)?;

    // 4. Strict verify — rejects weak keys, malleable signatures,
    // small-order points. (MISSION.md §2 — verify_strict semantics.)
    key.verify_strict(&bytes, &sig)
        .map_err(|_| Error::SignatureMismatch)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::canonical::PythonJsonDumpsCanonicalizer;
    use super::*;
    use crate::schema::SchemaVersion;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap;

    /// In-memory PublicKeyDirectory for tests.
    struct MemKeys {
        keys: HashMap<String, VerifyingKey>,
    }
    impl PublicKeyDirectory for MemKeys {
        fn lookup(
            &self,
            key_id: &str,
        ) -> Result<Option<VerifyingKey>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.keys.get(key_id).copied())
        }
    }

    fn fixed_signing_key() -> SigningKey {
        // Deterministic test keypair — never used outside tests.
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn make_trace(signing_key: &SigningKey, key_id: &str) -> CompleteTrace {
        let trace_unsigned = CompleteTrace {
            trace_id: "trace-x-1".into(),
            thought_id: "th-1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![],
            signature: String::new(),
            signature_key_id: key_id.to_owned(),
        };
        // Sign the canonical bytes of the unsigned trace.
        let payload = canonical_payload_value(&trace_unsigned);
        let bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let sig = signing_key.sign(&bytes);
        CompleteTrace {
            signature: BASE64.encode(sig.to_bytes()),
            ..trace_unsigned
        }
    }

    /// Mission category §4 "Verify rejection": a known-good trace
    /// produced by our own signer round-trips through verify.
    #[test]
    fn round_trip_signed_trace_verifies() {
        let sk = fixed_signing_key();
        let key_id = "test-key:42";
        let trace = make_trace(&sk, key_id);

        let mut keys = MemKeys {
            keys: HashMap::new(),
        };
        keys.keys.insert(key_id.to_owned(), sk.verifying_key());

        verify_trace(&trace, &PythonJsonDumpsCanonicalizer, &keys)
            .expect("known-good trace must verify");
    }

    /// Mission category §4 "Verify rejection": tampered bytes →
    /// signature mismatch → typed error.
    #[test]
    fn mutated_trace_rejected() {
        let sk = fixed_signing_key();
        let key_id = "test-key:42";
        let mut trace = make_trace(&sk, key_id);
        // Mutate any signed field; signature must no longer verify.
        trace.thought_id = "th-tampered".into();

        let mut keys = MemKeys {
            keys: HashMap::new(),
        };
        keys.keys.insert(key_id.to_owned(), sk.verifying_key());

        let err = verify_trace(&trace, &PythonJsonDumpsCanonicalizer, &keys)
            .expect_err("tampered trace must be rejected");
        assert!(matches!(err, Error::SignatureMismatch), "got {err:?}");
    }

    /// Unknown key id → typed `UnknownKey` error (not silent skip).
    #[test]
    fn unknown_key_id_rejected() {
        let sk = fixed_signing_key();
        let key_id = "test-key:42";
        let trace = make_trace(&sk, key_id);
        // Empty directory.
        let keys = MemKeys {
            keys: HashMap::new(),
        };
        let err = verify_trace(&trace, &PythonJsonDumpsCanonicalizer, &keys).unwrap_err();
        assert!(matches!(err, Error::UnknownKey(_)));
    }

    /// Bad-base64 signature → typed `InvalidSignature` error.
    #[test]
    fn malformed_signature_rejected() {
        let sk = fixed_signing_key();
        let key_id = "test-key:42";
        let mut trace = make_trace(&sk, key_id);
        trace.signature = "not!base64!".into();

        let mut keys = MemKeys {
            keys: HashMap::new(),
        };
        keys.keys.insert(key_id.to_owned(), sk.verifying_key());

        let err = verify_trace(&trace, &PythonJsonDumpsCanonicalizer, &keys).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature(_)));
    }

    /// Wrong-length signature → typed `InvalidSignature` error.
    /// (Mission MDD anti-pattern #4: typed error, not panic.)
    #[test]
    fn wrong_length_signature_rejected() {
        let sk = fixed_signing_key();
        let key_id = "test-key:42";
        let mut trace = make_trace(&sk, key_id);
        // Valid base64 but wrong byte length.
        trace.signature = BASE64.encode(b"too short");

        let mut keys = MemKeys {
            keys: HashMap::new(),
        };
        keys.keys.insert(key_id.to_owned(), sk.verifying_key());

        let err = verify_trace(&trace, &PythonJsonDumpsCanonicalizer, &keys).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature(_)));
    }

    /// Wrong key in the directory → signature mismatch.
    #[test]
    fn wrong_key_rejected() {
        let sk_real = fixed_signing_key();
        let sk_other = SigningKey::from_bytes(&[0x99; 32]);
        let key_id = "test-key:42";
        let trace = make_trace(&sk_real, key_id);

        // Directory advertises a different key for the same key_id —
        // mission (MISSION.md §3 anti-pattern #3): no bypass; the
        // directory's claim must match the actual signer's key.
        let mut keys = MemKeys {
            keys: HashMap::new(),
        };
        keys.keys.insert(key_id.to_owned(), sk_other.verifying_key());

        let err = verify_trace(&trace, &PythonJsonDumpsCanonicalizer, &keys).unwrap_err();
        assert!(matches!(err, Error::SignatureMismatch));
    }
}
