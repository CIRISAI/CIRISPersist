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

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
// BASE64 is the alias used by the *signing* (test-only) path
// below — emits standard base64. Verify must accept both
// alphabets; see `decode_signature` for the production decoder.
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;

/// Decode a base64 signature string accepting both standard
/// (`+`, `/`, `=`) and URL-safe (`-`, `_`, optional `=`) alphabets.
///
/// THREAT_MODEL.md AV-4 (production-bug shape): the agent emits
/// signatures via Python's `base64.urlsafe_b64encode` (URL-safe
/// alphabet, no padding) per its wire-format §8 path. Persist's
/// pre-v0.1.15 decoder used `STANDARD` only, which rejected `-` /
/// `_` characters and produced wrong-length bytes — every
/// production batch failed `verify_invalid_signature` regardless
/// of canonicalization, payload, or trace level.
///
/// The fix is alphabet-agnostic decode: try standard first
/// (cheap, matches lots of code), fall back through URL-safe
/// variants. Same defensive shape `accord_api.py:1903` uses on
/// the Python side. No signer-side coordination needed; the agent
/// can flip alphabets without persist breaking.
fn decode_signature(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
}
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
///
/// **THREAT_MODEL.md AV-4 (closed v0.1.8)**: timestamps come from
/// [`crate::schema::WireDateTime::wire`], not from re-formatting a
/// `DateTime<Utc>`. The agent emitted Python `isoformat()` bytes
/// over the wire; we preserve those bytes verbatim into the
/// canonical input. Pre-v0.1.8 a `format_iso8601` helper
/// re-formatted via chrono's `%.6f%:z`, which always emitted six
/// digits of microseconds — diverging from Python's "drop
/// microseconds when zero" rule and breaking signature verify on
/// every batch with a `.000000`-shaped agent timestamp.
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
                "timestamp": c.timestamp.wire(),
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
        serde_json::Value::String(trace.started_at.wire().to_owned()),
    );
    payload.insert(
        "completed_at".into(),
        serde_json::Value::String(trace.completed_at.wire().to_owned()),
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

/// Build the **legacy 2-field** canonical payload — what the
/// agent fleet actually signs today.
///
/// CIRISPersist#5: agent's `Ed25519TraceSigner.sign_trace` (in
/// `CIRIS_Adapter/ciris_adapters/ciris_accord_metrics/services.py`)
/// signs:
///
/// ```python
/// components_data = [strip_empty(c.model_dump()) for c in trace.components]
/// signed_payload = {"components": components_data, "trace_level": trace_level}
/// message = json.dumps(signed_payload, sort_keys=True, separators=(",", ":"))
/// ```
///
/// Two fields total — `components` (post-`strip_empty`) and
/// `trace_level`. Matches `CIRISLens/api/accord_api.py::verify_trace_signature`.
///
/// `TRACE_WIRE_FORMAT.md` §8 names a 9-field shape as the spec
/// target ([`canonical_payload_value`] above), but the agent fleet
/// is shipping 2-field today and will for some time. v0.1.16
/// closes AV-4 (canonical-shape drift) by accepting both: try
/// 9-field first, fall back to 2-field.
///
/// The agent's wire data is already post-`strip_empty`, but
/// persist's deserialization re-introduces empties — `Option`s
/// without `skip_serializing_if` round-trip as `null`, empty
/// `Vec`s round-trip as `[]`, etc. So persist must re-apply the
/// strip before canonicalizing the legacy form.
pub(crate) fn canonical_payload_value_legacy(trace: &CompleteTrace) -> serde_json::Value {
    let components: Vec<serde_json::Value> = trace
        .components
        .iter()
        .map(|c| {
            let mut v = serde_json::to_value(c).expect("TraceComponent serializes");
            strip_empty(&mut v);
            v
        })
        .collect();

    let mut payload = serde_json::Map::new();
    payload.insert("components".into(), serde_json::Value::Array(components));
    payload.insert(
        "trace_level".into(),
        serde_json::to_value(trace.trace_level).expect("TraceLevel serializes"),
    );
    serde_json::Value::Object(payload)
}

/// Recursively drop `null`, `""`, `[]`, `{}` from a JSON value,
/// in place. Matches the agent's Python `strip_empty` recursion
/// (`CIRISAgent/ciris_adapters/ciris_accord_metrics/services.py`).
///
/// Used by [`canonical_payload_value_legacy`] to reconstruct the
/// agent's pre-signature-bytes shape from persist's deserialized
/// trace. Without this, `Option`-typed fields round-trip as
/// `null`, breaking byte-equality with the agent's signed input.
fn strip_empty(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            // Recurse first; keys with empty children are then
            // dropped by `retain`.
            for (_, child) in map.iter_mut() {
                strip_empty(child);
            }
            map.retain(|_, child| !is_empty(child));
        }
        serde_json::Value::Array(arr) => {
            for child in arr.iter_mut() {
                strip_empty(child);
            }
            arr.retain(|child| !is_empty(child));
        }
        _ => {} // primitives: nothing to recurse into
    }
}

fn is_empty(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => true,
        serde_json::Value::String(s) => s.is_empty(),
        serde_json::Value::Array(a) => a.is_empty(),
        serde_json::Value::Object(m) => m.is_empty(),
        // Numbers and booleans are never "empty" — `false` and
        // `0` are valid signed values.
        _ => false,
    }
}

/// v0.1.18 — produce the canonical-bytes diagnostic for the
/// `SignatureMismatch` breadcrumb (CIRISPersist#6 follow-up).
/// Returns `(nine_field_sha256_hex, two_field_sha256_hex,
/// nine_field_bytes, two_field_bytes)` so the caller can both log
/// hashes and (optionally) base64-expose the full bytes for an
/// out-of-band diff against the reference Python
/// `json.dumps(canonical, sort_keys=True, separators=(",",":"))`.
///
/// Re-canonicalizes both shapes; cheap (microseconds). Only called
/// on the `SignatureMismatch` slow path. The Sha256 + hex_encode
/// are constant-time wrt the input data; logged sha256s leak no
/// signature material.
pub(crate) fn canonical_payload_sha256s<C>(
    trace: &CompleteTrace,
    canonicalizer: &C,
) -> Result<CanonicalDiagnostic, super::Error>
where
    C: super::canonical::Canonicalizer + ?Sized,
{
    use sha2::{Digest, Sha256};
    let nine_field = canonical_payload_value(trace);
    let nine_bytes = canonicalizer.canonicalize_value(&nine_field)?;
    let two_field = canonical_payload_value_legacy(trace);
    let two_bytes = canonicalizer.canonicalize_value(&two_field)?;
    Ok(CanonicalDiagnostic {
        nine_field_sha256: hex::encode(Sha256::digest(&nine_bytes)),
        two_field_sha256: hex::encode(Sha256::digest(&two_bytes)),
        nine_field_bytes: nine_bytes,
        two_field_bytes: two_bytes,
    })
}

/// Diagnostic carrier for v0.1.18 breadcrumbs +
/// `Engine.debug_canonicalize`. See [`canonical_payload_sha256s`].
pub(crate) struct CanonicalDiagnostic {
    /// Hex sha256 of the spec 9-field canonical form.
    pub(crate) nine_field_sha256: String,
    /// Hex sha256 of the legacy 2-field canonical form.
    pub(crate) two_field_sha256: String,
    /// Raw 9-field canonical bytes (for `Engine.debug_canonicalize`
    /// to base64-expose). Not logged.
    pub(crate) nine_field_bytes: Vec<u8>,
    /// Raw 2-field canonical bytes (for `Engine.debug_canonicalize`
    /// to base64-expose). Not logged.
    pub(crate) two_field_bytes: Vec<u8>,
}

/// Verify a `CompleteTrace`'s signature against the canonical bytes
/// the canonicalizer produces, using a pre-fetched verifying key.
///
/// This is the verify-before-persist gate (FSD §3.3 step 2). On
/// `Ok(())` the caller may persist; on `Err(_)` the caller MUST
/// reject and emit a structured 422 to the agent.
///
/// The key lookup is the caller's responsibility (typically via
/// [`Backend::lookup_public_key`](crate::store::Backend::lookup_public_key))
/// — keeping verify itself synchronous avoids the async-inside-sync
/// awkwardness that PublicKeyDirectory.lookup() invited.
pub fn verify_trace<C>(
    trace: &CompleteTrace,
    canonicalizer: &C,
    key: &VerifyingKey,
) -> Result<(), Error>
where
    C: Canonicalizer + ?Sized,
{
    // 1. Decode signature bytes from base64. Agent emits URL-safe
    // (Python `base64.urlsafe_b64encode`); admin tooling and tests
    // sometimes emit standard. `decode_signature` tries both.
    let sig_bytes =
        decode_signature(&trace.signature).map_err(|e| Error::InvalidSignature(e.to_string()))?;
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

    // 2. Try the spec-target 9-field canonical first
    // (TRACE_WIRE_FORMAT.md §8). This is the eventual shape; agent
    // fleets that have migrated sign over this directly.
    let nine_field = canonical_payload_value(trace);
    let nine_bytes = canonicalizer.canonicalize_value(&nine_field)?;
    if key.verify_strict(&nine_bytes, &sig).is_ok() {
        return Ok(());
    }

    // 3. Fallback: legacy 2-field canonical
    // ({components, trace_level}, post-strip_empty). CIRISPersist#5:
    // the agent fleet today signs this shape per
    // `Ed25519TraceSigner.sign_trace` and `CIRISLens/api/accord_api.py
    // ::verify_trace_signature`. Same defensive shape v0.1.15 used
    // for the base64 alphabet fallback. Migration to 9-field is
    // tracked agent-side; persist accepts both through the window.
    let two_field = canonical_payload_value_legacy(trace);
    let two_bytes = canonicalizer.canonicalize_value(&two_field)?;
    if key.verify_strict(&two_bytes, &sig).is_ok() {
        return Ok(());
    }

    // 4. Both shapes failed. Strict verify rejected; typed error.
    // The signature shape was valid (length + base64 decode both
    // succeeded) so this is content mismatch, not malformation.
    Err(Error::SignatureMismatch)
}

/// Convenience wrapper: verify with a [`PublicKeyDirectory`] in front
/// (looks up the key by id, then defers to [`verify_trace`]). Useful
/// for the standalone-verifier test path; production ingest looks up
/// the key from the Backend asynchronously and calls [`verify_trace`]
/// directly.
pub fn verify_trace_via_directory<C, K>(
    trace: &CompleteTrace,
    canonicalizer: &C,
    keys: &K,
) -> Result<(), Error>
where
    C: Canonicalizer + ?Sized,
    K: PublicKeyDirectory + ?Sized,
{
    let key = keys
        .lookup(&trace.signature_key_id)
        .map_err(|e| Error::InvalidSignature(format!("key lookup failed: {e}")))?
        .ok_or_else(|| Error::UnknownKey(trace.signature_key_id.clone()))?;
    verify_trace(trace, canonicalizer, &key)
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

        verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys)
            .expect("known-good trace must verify");
    }

    /// THREAT_MODEL.md AV-4 (production-bug shape, v0.1.15):
    /// agent's signatures are URL-safe-no-pad base64 per wire-
    /// format §8 (Python `base64.urlsafe_b64encode`). Persist's
    /// pre-v0.1.15 STANDARD decoder rejected `-` / `_` chars; every
    /// production batch failed `verify_invalid_signature`.
    /// `decode_signature` accepts all four base64 variants.
    #[test]
    fn decode_signature_accepts_all_alphabets() {
        // Same 64-byte payload, encoded four ways:
        let sig_bytes = vec![0xAB; 64];
        let std_pad = STANDARD.encode(&sig_bytes);
        let url_pad = URL_SAFE.encode(&sig_bytes);
        let url_no_pad = URL_SAFE_NO_PAD.encode(&sig_bytes);
        // Standard-no-pad: STANDARD without trailing `=`.
        let std_no_pad = std_pad.trim_end_matches('=').to_owned();

        for (label, encoded) in [
            ("STANDARD with padding", &std_pad),
            ("STANDARD no padding", &std_no_pad),
            ("URL_SAFE with padding", &url_pad),
            ("URL_SAFE no padding", &url_no_pad),
        ] {
            let decoded =
                decode_signature(encoded).unwrap_or_else(|e| panic!("{label}: decode failed: {e}"));
            assert_eq!(
                decoded, sig_bytes,
                "{label}: decoded bytes must match original"
            );
        }
    }

    /// End-to-end: trace signed with URL-safe-no-pad (the agent's
    /// production form) verifies cleanly. Pre-v0.1.15 this rejected.
    #[test]
    fn url_safe_signed_trace_verifies() {
        let sk = fixed_signing_key();
        let key_id = "test-key:42";
        // Build the trace exactly like make_trace, but encode the
        // signature with URL_SAFE_NO_PAD instead of STANDARD —
        // matching what the production agent emits.
        let trace_unsigned = CompleteTrace {
            trace_id: "trace-urlsafe-1".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456+00:00".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012+00:00".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![],
            signature: String::new(),
            signature_key_id: key_id.to_owned(),
        };
        let payload = canonical_payload_value(&trace_unsigned);
        let bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let sig = sk.sign(&bytes);
        let trace = CompleteTrace {
            // The production-bug shape: URL-safe-no-pad, no `=` padding.
            signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            ..trace_unsigned
        };

        let mut keys = MemKeys {
            keys: HashMap::new(),
        };
        keys.keys.insert(key_id.to_owned(), sk.verifying_key());

        verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys)
            .expect("URL-safe-no-pad signature MUST verify post-v0.1.15");
    }

    /// CIRISPersist#5 (v0.1.16): trace signed with the **legacy
    /// 2-field canonical** ({components, trace_level}, post-strip)
    /// verifies via persist's try-both fallback. This is the form
    /// the agent fleet actually ships today; pre-v0.1.16 every
    /// real production batch rejected with `verify_signature_mismatch`.
    #[test]
    fn legacy_two_field_signed_trace_verifies() {
        let sk = fixed_signing_key();
        let key_id = "test-key:42";
        let mut data = serde_json::Map::new();
        data.insert("attempt_index".into(), serde_json::json!(0));
        data.insert("seq".into(), serde_json::json!(1));
        let trace_unsigned = CompleteTrace {
            trace_id: "trace-legacy-1".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456+00:00".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012+00:00".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![crate::schema::TraceComponent {
                component_type: crate::schema::ComponentType::Conscience,
                event_type: crate::schema::ReasoningEventType::ConscienceResult,
                timestamp: "2026-04-30T00:15:53.123456+00:00".parse().unwrap(),
                data,
            }],
            signature: String::new(),
            signature_key_id: key_id.to_owned(),
        };

        // Sign the LEGACY 2-field form (what the agent actually does):
        let legacy_payload = canonical_payload_value_legacy(&trace_unsigned);
        let bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&legacy_payload)
            .unwrap();
        let sig = sk.sign(&bytes);
        let trace = CompleteTrace {
            signature: BASE64.encode(sig.to_bytes()),
            ..trace_unsigned
        };

        let mut keys = MemKeys {
            keys: HashMap::new(),
        };
        keys.keys.insert(key_id.to_owned(), sk.verifying_key());

        // Persist's verify tries 9-field first (will fail —
        // signature is over 2-field), then falls back to 2-field
        // and succeeds.
        verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys)
            .expect("legacy 2-field signed trace MUST verify via fallback (CIRISPersist#5)");
    }

    /// CIRISPersist#5: a trace tampered after legacy-form signing
    /// must STILL reject (try-both fallback doesn't widen the
    /// security surface — both shapes have to fail before we
    /// surface SignatureMismatch).
    #[test]
    fn legacy_two_field_tampered_rejected() {
        let sk = fixed_signing_key();
        let key_id = "test-key:42";
        let trace_unsigned = CompleteTrace {
            trace_id: "trace-legacy-tamp".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456+00:00".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012+00:00".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![],
            signature: String::new(),
            signature_key_id: key_id.to_owned(),
        };

        // Sign legacy form, then mutate trace_level (which IS in
        // both canonical forms). Both 9-field AND 2-field verify
        // must fail.
        let legacy_payload = canonical_payload_value_legacy(&trace_unsigned);
        let bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&legacy_payload)
            .unwrap();
        let sig = sk.sign(&bytes);
        let mut trace = CompleteTrace {
            signature: BASE64.encode(sig.to_bytes()),
            ..trace_unsigned
        };
        trace.trace_level = crate::schema::TraceLevel::FullTraces;

        let mut keys = MemKeys {
            keys: HashMap::new(),
        };
        keys.keys.insert(key_id.to_owned(), sk.verifying_key());

        let err = verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys)
            .expect_err("tampered trace must reject even with try-both fallback");
        assert!(matches!(err, Error::SignatureMismatch));
    }

    /// CIRISPersist#5: `strip_empty` recursion matches the agent's
    /// Python implementation — drops `null`, `""`, `[]`, `{}` at
    /// every nesting level, retains numbers and booleans (false /
    /// 0 are valid signed values).
    #[test]
    fn strip_empty_drops_empties_recursively() {
        let mut v = serde_json::json!({
            "keep_int": 0,
            "keep_bool_false": false,
            "drop_null": null,
            "drop_empty_string": "",
            "drop_empty_array": [],
            "drop_empty_object": {},
            "keep_string": "x",
            "keep_array": [1, 2],
            "nested": {
                "drop_inner_null": null,
                "keep_inner": "y",
                "drop_after_recurse_then_emptied": {
                    "drop": null,
                    "drop2": ""
                }
            },
            "array_with_empties": [1, "", null, {}, "ok"]
        });
        strip_empty(&mut v);

        // Non-recursive expected after retain:
        let want = serde_json::json!({
            "keep_int": 0,
            "keep_bool_false": false,
            "keep_string": "x",
            "keep_array": [1, 2],
            "nested": {
                "keep_inner": "y",
                // drop_after_recurse_then_emptied becomes {} after
                // recursion clears its contents, then the outer
                // retain drops it
            },
            "array_with_empties": [1, "ok"]
        });
        assert_eq!(v, want);
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

        let err = verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys)
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
        let err =
            verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys).unwrap_err();
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

        let err =
            verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys).unwrap_err();
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

        let err =
            verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys).unwrap_err();
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
        keys.keys
            .insert(key_id.to_owned(), sk_other.verifying_key());

        let err =
            verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &keys).unwrap_err();
        assert!(matches!(err, Error::SignatureMismatch));
    }
}
