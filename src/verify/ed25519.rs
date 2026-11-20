//! Trace canonical bytes (v62.0.0, F0-cp6e: the classical Ed25519 trace
//! verifier this module was named for is deleted; see the note below the
//! module docs).
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

// v62.0.0 (F0-cp6e) — the classical Ed25519 trace verifier
// (`verify_trace`, `verify_trace_via_directory`, `PublicKeyDirectory`, the
// alphabet-agnostic `decode_signature`) is DELETED: a trace is verified as its
// edition-2 `trace:complete:v1` statement through the door. What remains here
// builds the canonical bytes the diagnostics and the trace blob read.
// BASE64 is the alias the test-only signing path below uses.
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(test)]
use base64::Engine as _;

use super::canonical::Canonicalizer;
use super::Error;
use crate::schema::CompleteTrace;

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
    // Per §8 at `trace_schema_version "2.7.0"`, the canonical fields are:
    //   trace_id, thought_id, task_id, agent_id_hash, started_at,
    //   completed_at, trace_level, trace_schema_version, components.
    //
    // Each component contributes 4 fields:
    //   component_type, data (post-_strip_empty), event_type, timestamp.
    //
    // **Cross-shape field injection defense (§3.1)**: at `"2.7.0"`,
    // canonical reconstruction MUST IGNORE per-component
    // `agent_id_hash` even if present on the wire — only the envelope
    // `agent_id_hash` is authoritative at 2.7.0. The TraceComponent's
    // `agent_id_hash` field stays `None` here regardless of whether
    // the wire bytes carried it; that's a feature, not a bug.
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

/// v0.3.0 — Build the canonical payload for `trace_schema_version "2.7.9"`.
///
/// Per TRACE_WIRE_FORMAT.md §3.1 + §4 + §8 at cc41f315f
/// (release/2.7.9 HEAD): same 9-field envelope as
/// [`canonical_payload_value`], but each component contributes 5
/// fields instead of 4 — `agent_id_hash` is denormalized from the
/// envelope onto every TraceComponent. Agents emit them locked-equal
/// at build time; persistence MAY reject mismatches but the
/// canonical reconstruction here trusts the wire value.
///
/// Component shape (alphabetical, matches Python `json.dumps(...,
/// sort_keys=True)`):
/// ```text
///   agent_id_hash, component_type, data, event_type, timestamp
/// ```
///
/// **Required at 2.7.9 — no transition.** A 2.7.9 trace whose
/// component is missing `agent_id_hash` is malformed; canonical
/// reconstruction here would substitute the envelope value, but the
/// agent's wire bytes wouldn't have had a substitution, so the
/// signature mismatches and verify fails. That's the right outcome:
/// 2.7.9 spec is "MUST emit per-component", verify enforces.
pub fn canonical_payload_value_v279(trace: &CompleteTrace) -> serde_json::Value {
    let components: Vec<serde_json::Value> = trace
        .components
        .iter()
        .map(|c| {
            // Use the per-component agent_id_hash if present (the
            // 2.7.9 wire shape); fall back to envelope value if the
            // wire was malformed (component sans agent_id_hash). The
            // fallback path produces a trace that can never verify
            // because the agent's signed bytes had a real per-component
            // value or would be rejected agent-side. Belt-and-braces
            // shape: doesn't crash on malformed input, fails verify
            // honestly.
            let aih = c
                .agent_id_hash
                .as_deref()
                .unwrap_or(trace.agent_id_hash.as_str());
            serde_json::json!({
                "agent_id_hash": aih,
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

    // v0.3.4 (CIRISPersist#13) — deployment_profile is the 10th key
    // in the 2.7.9 outer canonical, between `completed_at` and
    // `started_at` alphabetically (c < d < s). Required-on-wire at
    // 2.7.9 per FSD §3.2 + §8; the validate pass in
    // `BatchEnvelope::from_json` rejects 2.7.9 traces missing the
    // block. Expanded here only when present so verify-test fixtures
    // synthesizing a 2.7.9 trace without the block see the 9-key
    // shape and verify-fail honestly, rather than panic.
    if let Some(profile) = trace.deployment_profile.as_ref() {
        payload.insert(
            "deployment_profile".into(),
            serde_json::to_value(profile).expect("DeploymentProfile serializes"),
        );
    }

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
    // v54.1.0 (Codex round 2 on PR #1057) — the primary shape IS the
    // verifier's preimage: the same builder `verify_trace` and
    // `verify_trace_hybrid` sign-check against ([`canonical_bytes_for_trace`],
    // dispatched by the signed `trace_schema_version`, with the signed
    // `run_kind` joined). Before, it rebuilt the 2.7.0 shape WITHOUT
    // `run_kind`, so for a trace carrying one the breadcrumb named bytes no
    // verifier ever checked. A version no arm dispatches falls back to the
    // 2.7.0 shape (the diagnostic must not fail where the verifier refused).
    let nine_bytes = match canonical_bytes_for_trace(trace, canonicalizer) {
        Ok(bytes) => bytes,
        Err(super::Error::UnsupportedSchemaVersion(_)) => {
            let mut nine_field = canonical_payload_value(trace);
            with_signed_run_kind(&mut nine_field, trace);
            canonicalizer.canonicalize_value(&nine_field)?
        }
        Err(e) => return Err(e),
    };
    let mut two_field = canonical_payload_value_legacy(trace);
    with_signed_run_kind(&mut two_field, trace);
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
    /// Hex sha256 of the verifier's preimage ([`canonical_bytes_for_trace`]:
    /// the spec canonical form at the trace's signed schema version, signed
    /// `run_kind` included). The `9field` name is the v0.1.18 wire key.
    pub(crate) nine_field_sha256: String,
    /// Hex sha256 of the legacy 2-field canonical form. Read only by the
    /// PyO3 `debug_canonicalize` breadcrumb (v62 BF13: allowed dead without it).
    #[cfg_attr(not(feature = "_pyffi"), allow(dead_code))]
    pub(crate) two_field_sha256: String,
    /// Raw 9-field canonical bytes (for `Engine.debug_canonicalize`
    /// to base64-expose). Not logged.
    pub(crate) nine_field_bytes: Vec<u8>,
    /// Raw 2-field canonical bytes (for `Engine.debug_canonicalize`
    /// to base64-expose). Not logged.
    pub(crate) two_field_bytes: Vec<u8>,
}

/// v7.2.0 (CIRISPersist#225) — reconstruct the canonical bytes the
/// producer signed for `trace`, dispatching by the trace's SIGNED
/// `trace_schema_version` (the same deterministic, self-authenticating
/// dispatch `verify_trace` (deleted v62.0.0) uses). Shared by the Ed25519-only path and
/// the hybrid path so BOTH halves of a hybrid signature are checked
/// against byte-identical canonical input.
///
/// `trace_schema_version` is part of the signed canonical bytes, so the
/// dispatch key is attacker-uncontrollable: a forged version that flips
/// the canonical shape changes the bytes → signature mismatch, never a
/// check bypass (#176 / #174 §6).
pub fn canonical_bytes_for_trace<C>(
    trace: &CompleteTrace,
    canonicalizer: &C,
) -> Result<Vec<u8>, Error>
where
    C: Canonicalizer + ?Sized,
{
    let wire = trace.trace_schema_version.as_str();
    let mut canonical = match wire {
        "2.7.0" => canonical_payload_value(trace),
        "2.7.9" => canonical_payload_value_v279(trace),
        "3.0.0" | "3.1.0" | "3.1.1" => canonical_payload_value_v279(trace),
        "2.7.legacy" => canonical_payload_value_legacy(trace),
        other => return Err(Error::UnsupportedSchemaVersion(other.to_owned())),
    };
    with_signed_run_kind(&mut canonical, trace);
    canonicalizer.canonicalize_value(&canonical)
}

/// v54.1.0 (CC 3.1.5, CIRISConstitution#166 at rc8@8c8f536) — `run_kind`
/// is a SIGNED envelope member: when the trace carries it, it joins the
/// canonical payload as a top-level `"run_kind"` key (sorted with its
/// siblings by the canonicalizer), at every schema version. A trace without
/// it reconstructs exactly the bytes it did before, so no signature over a
/// pre-#1249 trace changes; a trace WITH it verifies only if the producer
/// signed it, so it cannot be added, dropped or edited after signing.
///
/// v56.0.0 (CIRISPersist#1089) — this lifts the TOP-LEVEL member only, and
/// must. A `trace_format` v2.8.0 trace signs `run_kind` inside
/// `deployment_profile`, which enters the canonical bytes as the typed
/// profile serializes (`DeploymentProfile::run_kind` /
/// `trace_format_version`); lifting it here as well would add a key the
/// producer never signed. Run-kind GATES read both places through
/// [`CompleteTrace::signed_run_kind`].
fn with_signed_run_kind(canonical: &mut serde_json::Value, trace: &CompleteTrace) {
    if let (Some(kind), Some(obj)) = (&trace.run_kind, canonical.as_object_mut()) {
        obj.insert(
            "run_kind".to_owned(),
            serde_json::Value::String(kind.clone()),
        );
    }
}

/// v4.6 (CIRISPersist#171 / #176 / CEG §0.9) — map a trace's **signed**
/// `trace_schema_version` to its canonicalization version (the #176
/// signed-epoch version gate). The JCS flip is a **major-version** era
/// boundary: `1.x`/`2.x` are Python-compat (pre-cut); **`3.x`+ is JCS**
/// (the agent's 2.9.6 / 3.0 flip). Robust to point-version bumps within
/// an era — no per-point-version enumeration.
///
/// `trace_schema_version` is part of the signed canonical bytes, so this
/// is attacker-uncontrollable (signed-bytes-bound, #176 / #174 §6): a
/// forged version that flips the canonicalizer changes the canonical →
/// signature mismatch → rejection, never a check bypass.
///
/// **Live as of v4.15.0 (#871):** `"3.0.0"` is in `SUPPORTED_VERSIONS`
/// with a `verify_trace` (deleted v62.0.0) dispatch arm (reusing the 2.7.9 field layout —
/// the agent's 2.9.6 cutover kept the layout, changed only the
/// canonicalizer). A `3.0.0` trace now routes here to `V2Jcs` and verifies
/// under RFC 8785; `2.7.x` traces stay `V1Python` so pre-cut rows keep
/// verifying under the legacy canonicalizer (bounded by trace retention).
pub fn canon_version_for_trace_schema(wire: &str) -> crate::verify::canonical::CanonVersion {
    use crate::verify::canonical::CanonVersion;
    if let Some((major, _)) = wire.split_once('.') {
        if let Ok(m) = major.parse::<u32>() {
            if m >= 3 {
                return CanonVersion::V2Jcs;
            }
        }
    }
    CanonVersion::V1Python
}

#[cfg(test)]
mod tests {
    use super::super::canonical::PythonJsonDumpsCanonicalizer;
    use super::*;
    use crate::schema::SchemaVersion;
    use ed25519_dalek::{Signer, SigningKey};

    /// v4.6 (#176) — the signed-epoch gate: 1.x/2.x → Python-compat,
    /// 3.x+ → JCS (the agent's 2.9.6 flip era), robust to point bumps;
    /// unparseable/major-less → Python (safe default).
    #[test]
    fn canon_version_gate_by_major() {
        use crate::verify::canonical::CanonVersion::{V1Python, V2Jcs};
        for (wire, want) in [
            ("2.7.0", V1Python),
            ("2.7.9", V1Python),
            ("2.7.legacy", V1Python),
            ("1.0.0", V1Python),
            ("3.0.0", V2Jcs),
            ("3.1.0", V2Jcs),
            ("3.1.1", V2Jcs),
            ("3.5.2", V2Jcs),
            ("10.0.0", V2Jcs),
            ("garbage", V1Python),
            ("", V1Python),
        ] {
            assert_eq!(canon_version_for_trace_schema(wire), want, "schema {wire}");
        }
    }

    /// **I699** (Codex round 2 on PR #1057) — the `SignatureMismatch`
    /// breadcrumb and `debug_canonicalize` hash the VERIFIER's preimage: for a
    /// trace carrying the signed `run_kind`, at each dispatched version, the
    /// diagnostic's primary hash is SHA-256 of [`canonical_bytes_for_trace`],
    /// and the legacy shape carries `run_kind` too.
    #[test]
    fn i699_the_diagnostic_hashes_the_verifiers_preimage() {
        use sha2::{Digest, Sha256};
        let sk = fixed_signing_key();
        for wire in ["2.7.0", "2.7.9", "3.0.0", "3.1.0", "3.1.1", "2.7.legacy"] {
            let mut trace = make_trace(&sk, "agent-i699");
            trace.trace_schema_version = SchemaVersion::parse(wire).unwrap();
            trace.run_kind = Some("production".into());
            let preimage =
                canonical_bytes_for_trace(&trace, &PythonJsonDumpsCanonicalizer).unwrap();
            let diag = canonical_payload_sha256s(&trace, &PythonJsonDumpsCanonicalizer).unwrap();
            assert_eq!(
                diag.nine_field_sha256,
                hex::encode(Sha256::digest(&preimage)),
                "I699 {wire}: the diagnostic names the bytes the verifier checks"
            );
            assert_eq!(diag.nine_field_bytes, preimage, "I699 {wire}");
            let legacy: serde_json::Value = serde_json::from_slice(&diag.two_field_bytes).unwrap();
            assert_eq!(
                legacy["run_kind"], "production",
                "I699 {wire}: the legacy shape carries the signed run_kind"
            );
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
            deployment_profile: None,
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: key_id.to_owned(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
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

    /// v0.3.0 — Cross-shape field injection defense (§3.1):
    /// at trace_schema_version "2.7.0", canonical reconstruction
    /// MUST IGNORE per-component agent_id_hash even if present on
    /// the wire. An attacker stuffing per-component agent_id_hash
    /// into a 2.7.0 trace cannot influence the canonical bytes.
    #[test]
    fn v270_ignores_per_component_agent_id_hash_injection() {
        // Build the same trace twice: once with per-component
        // agent_id_hash = None, once with Some(...). At "2.7.0",
        // the canonical bytes MUST be identical (the per-component
        // agent_id_hash is stripped at canonicalization).
        fn build(per_comp_aih: Option<String>) -> CompleteTrace {
            let mut data = serde_json::Map::new();
            data.insert("attempt_index".into(), serde_json::json!(0));
            CompleteTrace {
                trace_id: "trace-270-injection".into(),
                thought_id: "th-1".into(),
                task_id: None,
                agent_id_hash: "envelope_hash".into(),
                started_at: "2026-04-30T00:00:00+00:00".parse().unwrap(),
                completed_at: "2026-04-30T00:01:00+00:00".parse().unwrap(),
                trace_level: crate::schema::TraceLevel::Generic,
                trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
                components: vec![crate::schema::TraceComponent {
                    component_type: crate::schema::ComponentType::Conscience,
                    event_type: crate::schema::ReasoningEventType::ConscienceResult,
                    timestamp: "2026-04-30T00:00:00+00:00".parse().unwrap(),
                    data,
                    agent_id_hash: per_comp_aih,
                }],
                deployment_profile: None,
                cohort_scope: "federation".into(),
                cohort_target_id: None,
                signature: String::new(),
                signature_key_id: "k".into(),
                signature_ml_dsa_65: None,
                pubkey_ml_dsa_65: None,
                pqc_key_id: None,
                run_kind: None,
            }
        }
        let no_inject = build(None);
        let with_inject = build(Some("attacker_smuggled_hash".into()));

        let no_bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&canonical_payload_value(&no_inject))
            .unwrap();
        let with_bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&canonical_payload_value(&with_inject))
            .unwrap();
        assert_eq!(
            no_bytes, with_bytes,
            "2.7.0 canonical MUST ignore per-component agent_id_hash injection"
        );
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

    /// v0.3.4 (CIRISPersist#13) — At 2.7.9, `deployment_profile` is
    /// the 10th key of the outer canonical, sorted alphabetically
    /// between `completed_at` and `started_at` (c < d < s). A trace
    /// with the block produces canonical bytes that include the 6
    /// fields. The Python json.dumps(sort_keys=True, separators=...)
    /// shape produces specific known bytes — we assert byte-exact
    /// against the expected substring.
    #[test]
    fn v279_canonical_includes_deployment_profile() {
        use crate::schema::{
            ComponentType, DeploymentProfile, ReasoningEventType, SchemaVersion, TraceLevel,
        };
        let mut data = serde_json::Map::new();
        data.insert("attempt_index".into(), serde_json::json!(0));
        let trace = CompleteTrace {
            trace_id: "trace-279-dp".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "abcd".into(),
            started_at: "2026-04-30T00:00:00+00:00".parse().unwrap(),
            completed_at: "2026-04-30T00:01:00+00:00".parse().unwrap(),
            trace_level: TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.9").unwrap(),
            components: vec![crate::schema::TraceComponent {
                component_type: ComponentType::Conscience,
                event_type: ReasoningEventType::ConscienceResult,
                timestamp: "2026-04-30T00:00:30+00:00".parse().unwrap(),
                data,
                agent_id_hash: Some("abcd".into()),
            }],
            deployment_profile: Some(DeploymentProfile {
                agent_role: "ally".into(),
                agent_template: "ally-v3-default".into(),
                deployment_domain: "general".into(),
                deployment_type: "production".into(),
                deployment_region: None,
                deployment_trust_mode: "federated_peer".into(),
                run_kind: None,
                trace_format_version: None,
                calibration_version: None,
                pipeline_metadata: None,
            }),
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: "k".into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
        };
        let payload = canonical_payload_value_v279(&trace);
        let bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // sort_keys=True ordering: agent_id_hash, completed_at,
        // components, deployment_profile, started_at, task_id,
        // thought_id, trace_id, trace_level, trace_schema_version.
        // (`completed_at` < `components` because 'l' < 'o' at the 5th
        // char; `components` < `deployment_profile` because 'c' < 'd';
        // `deployment_profile` < `started_at` because 'd' < 's'.)
        // Field order inside the block is sort_keys=True too.
        assert!(
            s.contains(
                r#""deployment_profile":{"agent_role":"ally","agent_template":"ally-v3-default","deployment_domain":"general","deployment_region":null,"deployment_trust_mode":"federated_peer","deployment_type":"production"},"started_at""#
            ),
            "canonical bytes don't carry deployment_profile in expected sorted position; got:\n{s}"
        );
        // 10-key outer canonical (was 9 pre-v0.3.4).
        assert!(s.contains(r#""started_at":"2026-04-30T00:00:00+00:00""#));
    }

    /// v0.3.4 (CIRISPersist#13) — Cross-shape rule: at 2.7.0, a
    /// deployment_profile field in the wire JSON does NOT enter
    /// canonical bytes. Two traces — one without the block, one with
    /// — produce byte-identical 2.7.0 canonical bytes. Mirrors the
    /// existing per-component agent_id_hash injection test.
    #[test]
    fn v270_ignores_deployment_profile_injection() {
        use crate::schema::{
            ComponentType, DeploymentProfile, ReasoningEventType, SchemaVersion, TraceLevel,
        };
        fn build(profile: Option<DeploymentProfile>) -> CompleteTrace {
            let mut data = serde_json::Map::new();
            data.insert("attempt_index".into(), serde_json::json!(0));
            CompleteTrace {
                trace_id: "trace-270-dp-injection".into(),
                thought_id: "th-1".into(),
                task_id: None,
                agent_id_hash: "envelope".into(),
                started_at: "2026-04-30T00:00:00+00:00".parse().unwrap(),
                completed_at: "2026-04-30T00:01:00+00:00".parse().unwrap(),
                trace_level: TraceLevel::Generic,
                trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
                components: vec![crate::schema::TraceComponent {
                    component_type: ComponentType::Conscience,
                    event_type: ReasoningEventType::ConscienceResult,
                    timestamp: "2026-04-30T00:00:30+00:00".parse().unwrap(),
                    data,
                    agent_id_hash: None,
                }],
                deployment_profile: profile,
                cohort_scope: "federation".into(),
                cohort_target_id: None,
                signature: String::new(),
                signature_key_id: "k".into(),
                signature_ml_dsa_65: None,
                pubkey_ml_dsa_65: None,
                pqc_key_id: None,
                run_kind: None,
            }
        }
        let no_profile = build(None);
        let with_profile = build(Some(DeploymentProfile {
            agent_role: "smuggled".into(),
            agent_template: "smuggled".into(),
            deployment_domain: "smuggled".into(),
            deployment_type: "smuggled".into(),
            deployment_region: Some("attacker".into()),
            deployment_trust_mode: "smuggled".into(),
            run_kind: None,
            trace_format_version: None,
            calibration_version: None,
            pipeline_metadata: None,
        }));
        let bytes_a = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&canonical_payload_value(&no_profile))
            .unwrap();
        let bytes_b = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&canonical_payload_value(&with_profile))
            .unwrap();
        assert_eq!(
            bytes_a, bytes_b,
            "2.7.0 canonical MUST NOT include deployment_profile, even when wire injects it"
        );
    }
}
