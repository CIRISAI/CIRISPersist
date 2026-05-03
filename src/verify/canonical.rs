//! Canonical-bytes serialization for signed payloads.
//!
//! # Mission alignment (MISSION.md §2 — `verify/`)
//!
//! Signature verification is the cryptographic floor of the Coherent
//! Intersection Hypothesis (Accord Book IX Ch. 3-4). For every
//! signature the agent shipped to verify on the lens, the lens must
//! reproduce the *exact bytes* the agent signed. **Byte-exact** —
//! one differing escape, one mis-sorted key, one whitespace
//! difference and the signature fails, the trace gets rejected, the
//! corpus PoB §2.4 measures shrinks.
//!
//! # The Python-compat problem
//!
//! TRACE_WIRE_FORMAT.md §8 specifies the canonical bytes as
//!
//! ```python
//! json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
//! ```
//!
//! That **is not RFC 8785 JCS.** Three divergences (FSD/CRATE_RECOMMENDATIONS
//! §5.1):
//!
//! 1. Python's `json.dumps` defaults to `ensure_ascii=True` —
//!    non-ASCII characters become `\uXXXX` escapes; non-BMP code
//!    points become UTF-16 surrogate pairs `\uXXXX\uYYYY`.
//! 2. Python `sort_keys` orders keys by Python str ordering (Unicode
//!    codepoint, UTF-32 semantics for keys above U+FFFF).
//! 3. Python's `float.__repr__` (CPython's `Py_dg_dtoa`) picks
//!    different shortest-round-trip strings than Rust's `ryu` for
//!    ambiguous doubles. Concretely: ryu emits
//!    `0.003199200000000001` while Python emits
//!    `0.0031992000000000006` for the same f64. Both round-trip;
//!    different bytes.
//!
//! For ASCII-only ASCII-formatted-floats payloads the impls match;
//! for non-ASCII or float-divergent payloads they diverge. Until/
//! unless the agent flips to JCS, the lens must produce
//! Python-compatible bytes.
//!
//! ## Float divergence: preservation, not reproduction (v0.1.20)
//!
//! v0.1.19 tried to reproduce Python's float repr via lexical-core's
//! PYTHON_LITERAL format with threshold tuning. It didn't work:
//! lexical-core (like ryu) implements the same shortest-round-trip
//! tie-break choice as ryu, which differs from CPython's
//! `Py_dg_dtoa`. The original token is **not recoverable** from a
//! Rust f64 — `0.003199200000000001` and `0.0031992000000000006`
//! parse to the same double, and no formatter can know which one
//! the agent originally wrote.
//!
//! v0.1.20 fixes this at the source: serde_json's
//! `arbitrary_precision` feature stores `Number` as the original
//! parsed string, NOT as `f64`/`i64`/`u64`. Re-emission is then
//! byte-equal to the parsed input. The agent emitted Python's
//! `repr` form; we preserve it; verify succeeds.
//!
//! Mission constraint: pluggable behind a trait. The Phase 1 impl is
//! [`PythonJsonDumpsCanonicalizer`]; an [`Rfc8785Canonicalizer`] is
//! provided for the future-flip path (and as the dev-dep parity
//! reference; see CRATE_RECOMMENDATIONS §6 — `serde_json_canonicalizer`
//! is dev-deps only).

use super::Error;

/// Pluggable canonicalization. Phase 1 ships a Python-compat impl;
/// Phase 2 may add a JCS impl when/if the agent flips to RFC 8785.
pub trait Canonicalizer: Send + Sync {
    /// Serialize a `serde_json::Value` to the canonical byte sequence
    /// this canonicalizer represents.
    ///
    /// We canonicalize on JSON values rather than typed Rust values
    /// because canonicalization is *over the bytes*, not over Rust
    /// types. Round-tripping through `serde_json::Value` preserves
    /// the on-the-wire shape (in particular: timestamps as the
    /// strings the agent shipped, not chrono's preferred output).
    fn canonicalize_value(&self, v: &serde_json::Value) -> Result<Vec<u8>, Error>;
}

/// Phase 1 canonicalizer — byte-exact match with the agent's
/// `json.dumps(canonical, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)` output.
///
/// `ensure_ascii=True` is Python's default; the agent code in
/// `accord_metrics/services.py:208-368` does not pass
/// `ensure_ascii=False`, so the wire is ASCII-only.
pub struct PythonJsonDumpsCanonicalizer;

impl Canonicalizer for PythonJsonDumpsCanonicalizer {
    fn canonicalize_value(&self, v: &serde_json::Value) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(256);
        write_value(&mut buf, v);
        Ok(buf)
    }
}

/// RFC 8785 (JSON Canonicalization Scheme) canonicalizer. Reserved
/// for the future-flip path. Phase 1 keeps this around so the parity
/// test (MISSION.md §4) can assert the two impls *disagree* on
/// non-ASCII — which is exactly the gotcha CRATE_RECOMMENDATIONS
/// §5.1 names. Implementation delegates to a dev-only crate; this
/// impl is only available under `cfg(test)` so production builds
/// don't pull in the dev-dep.
#[cfg(test)]
pub struct Rfc8785Canonicalizer;

#[cfg(test)]
impl Canonicalizer for Rfc8785Canonicalizer {
    fn canonicalize_value(&self, v: &serde_json::Value) -> Result<Vec<u8>, Error> {
        // serde_json_canonicalizer 0.3 exposes `to_string` returning a
        // String of canonical JSON.
        serde_json_canonicalizer::to_string(v)
            .map(|s| s.into_bytes())
            .map_err(|e| Error::Canonicalization(e.to_string()))
    }
}

// ─── Python-compat writer ──────────────────────────────────────────

fn write_value(buf: &mut Vec<u8>, v: &serde_json::Value) {
    match v {
        serde_json::Value::Null => buf.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => buf.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => buf.extend_from_slice(b"false"),
        serde_json::Value::Number(n) => write_number(buf, n),
        serde_json::Value::String(s) => write_string(buf, s),
        serde_json::Value::Array(items) => {
            buf.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_value(buf, item);
            }
            buf.push(b']');
        }
        serde_json::Value::Object(map) => {
            // Python sort_keys=True: Python orders dict keys by str
            // comparison (codepoint order). For BMP-only keys this
            // matches lexicographic byte order of the UTF-8 form;
            // for keys with non-BMP characters Python's order is
            // UTF-32 (codepoint), which equals UTF-8 byte order
            // since UTF-8 is a codepoint-preserving encoding when
            // compared as byte sequences. Conclusion: sorting by the
            // raw UTF-8 string bytes IS Python's sort_keys order.
            //
            // (Note: this differs from RFC 8785, which uses UTF-16
            // code unit order — the divergence point above U+FFFF.
            // We are intentionally Python-compat here, not JCS.)
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            buf.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_string(buf, k);
                buf.push(b':');
                write_value(buf, map.get(*k).expect("key from map"));
            }
            buf.push(b'}');
        }
    }
}

fn write_number(buf: &mut Vec<u8>, n: &serde_json::Number) {
    // CIRISPersist#7 (closed v0.1.20): with the `arbitrary_precision`
    // feature on serde_json, `Number` is internally a `String` —
    // the original parsed token from the wire. `Number`'s `Display`
    // impl emits that string verbatim. So:
    //
    //   - Numbers parsed from agent wire bytes → emitted byte-equal
    //     to what the agent signed (closes the YO-rejected drift on
    //     `0.0031992000000000006` etc.).
    //   - Numbers constructed from Rust integers via `json!(42)` →
    //     emitted as `"42"` (Rust's `i64::to_string`, matches
    //     Python's `json.dumps(42)`).
    //   - Numbers constructed from Rust f64 via `json!(3.14)` →
    //     emitted via Rust's std f64 Display, which empirically
    //     agrees with Python's `repr(f)` on shortest-round-trip
    //     digits for production-range doubles (and ALL the values
    //     in v0.1.19's test fixture). Threshold/format details
    //     (`1e-05` vs `0.00001`, `1e-06` vs `1e-6`) can differ for
    //     constructed-from-Rust floats; for the verify path that
    //     does NOT matter because we never construct from Rust
    //     f64 — we always parse from agent wire bytes and preserve
    //     the original tokens.
    use std::io::Write;
    let _ = write!(buf, "{n}");
}

/// v0.4.1 (CIRISEdge ask) — Strip signature components from an
/// envelope and canonicalize. Returns the bytes the sender signed
/// — what the verifier needs to reproduce.
///
/// Rule: top-level `signature` and `signature_pqc` fields removed
/// before applying [`PythonJsonDumpsCanonicalizer`]. Same shape as
/// [`crate::federation::types::compute_persist_row_hash`]'s
/// `persist_row_hash` strip — a row's signed canonical bytes never
/// include the signature itself (else the hash would depend on
/// itself).
///
/// Used by:
/// - Edge's verify pipeline (strip-then-canonicalize-then-verify)
/// - Persist's PyO3 `Engine.canonicalize_envelope_for_signing`
///   wrapper (calls this directly)
/// - Federation peers verifying inbound envelopes from gossip /
///   direct send
///
/// **One implementation of the strip rule**: edge no longer
/// re-implements which fields to strip; persist owns the rule.
/// This closes the AV-5-class drift surface (canonicalization
/// mismatch between sender and verifier).
pub fn canonicalize_envelope_for_signing(
    envelope: &serde_json::Value,
) -> Result<Vec<u8>, super::Error> {
    let mut value = envelope.clone();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature");
        obj.remove("signature_pqc");
    }
    PythonJsonDumpsCanonicalizer
        .canonicalize_value(&value)
        .map_err(|e| super::Error::Canonicalization(format!("{e}")))
}

/// v0.4.1 (CIRISEdge ask) — SHA-256 of a body's verbatim wire
/// bytes. Used by:
/// - `body_sha256_prefix` forensic join key in persist's tables
/// - `in_reply_to` content-derived ACK matching
///   ([`crate::outbound::OutboundQueue::match_ack_to_outbound`])
/// - Edge's `body_sha256` field on `EdgeEnvelope`
///
/// Takes `&serde_json::value::RawValue` — the verbatim bytes the
/// caller received, not a re-serialized `Value`. Hashing
/// re-serialized bytes would re-canonicalize and lose the wire-
/// format identity.
///
/// Returns the raw 32-byte digest; callers hex-encode or
/// base64-encode as their downstream format requires.
pub fn body_sha256(body: &serde_json::value::RawValue) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(body.get().as_bytes());
    hasher.finalize().into()
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    // Python's json string encoding (ensure_ascii=True, default
    // separators):
    //   ascii printable except `"` and `\`  → verbatim
    //   `"`                                   → `\"`
    //   `\`                                   → `\\`
    //   `\b \f \n \r \t`                      → escaped forms
    //   other control chars (0x00-0x1F)       → `\u00XX`
    //   non-ASCII code points (>= 0x80)       → `\uXXXX` (BMP)
    //                                           or surrogate pair
    //                                           (non-BMP)
    //
    // Python does NOT escape `/`. We follow that.
    buf.push(b'"');
    for c in s.chars() {
        match c {
            '"' => buf.extend_from_slice(b"\\\""),
            '\\' => buf.extend_from_slice(b"\\\\"),
            '\u{08}' => buf.extend_from_slice(b"\\b"),
            '\u{0C}' => buf.extend_from_slice(b"\\f"),
            '\n' => buf.extend_from_slice(b"\\n"),
            '\r' => buf.extend_from_slice(b"\\r"),
            '\t' => buf.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                use std::io::Write;
                let _ = write!(buf, "\\u{:04x}", c as u32);
            }
            c if (c as u32) < 0x7F => {
                // ASCII printable.
                buf.push(c as u8);
            }
            c if (c as u32) <= 0xFFFF => {
                // BMP, but ensure_ascii — escape.
                use std::io::Write;
                let _ = write!(buf, "\\u{:04x}", c as u32);
            }
            c => {
                // Non-BMP: encode as UTF-16 surrogate pair, escaped.
                let cp = c as u32 - 0x10000;
                let hi = 0xD800 + (cp >> 10);
                let lo = 0xDC00 + (cp & 0x3FF);
                use std::io::Write;
                let _ = write!(buf, "\\u{hi:04x}\\u{lo:04x}");
            }
        }
    }
    buf.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pyc(v: serde_json::Value) -> String {
        let bytes = PythonJsonDumpsCanonicalizer.canonicalize_value(&v).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn jcs(v: serde_json::Value) -> String {
        let bytes = Rfc8785Canonicalizer.canonicalize_value(&v).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    // Mission category §4 "Canonicalization parity" — every expected
    // string here is the literal byte sequence
    // `python3 -c "import json; print(json.dumps(<value>,
    // sort_keys=True, separators=(',', ':')))"` produced when this
    // file was authored. Drift here silently breaks signature
    // verification across the corpus.

    #[test]
    fn empty_container_shapes() {
        assert_eq!(pyc(json!({})), "{}");
        assert_eq!(pyc(json!([])), "[]");
        assert_eq!(pyc(json!("")), "\"\"");
    }

    #[test]
    fn primitive_round_trips() {
        assert_eq!(pyc(json!(null)), "null");
        assert_eq!(pyc(json!(true)), "true");
        assert_eq!(pyc(json!(false)), "false");
        assert_eq!(pyc(json!(42)), "42");
        assert_eq!(pyc(json!(-7)), "-7");
        assert_eq!(pyc(json!("hello")), "\"hello\"");
    }

    #[test]
    fn no_whitespace_in_separators() {
        assert_eq!(pyc(json!({"a":1,"b":2})), "{\"a\":1,\"b\":2}");
        assert_eq!(pyc(json!([1, 2, 3])), "[1,2,3]");
    }

    #[test]
    fn keys_sorted_lexicographically() {
        let v = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(pyc(v), "{\"a\":2,\"m\":3,\"z\":1}");
    }

    #[test]
    fn ascii_string_named_escapes() {
        assert_eq!(pyc(json!("a\"b")), "\"a\\\"b\"");
        assert_eq!(pyc(json!("a\\b")), "\"a\\\\b\"");
        assert_eq!(pyc(json!("a\nb")), "\"a\\nb\"");
        assert_eq!(pyc(json!("a\rb")), "\"a\\rb\"");
        assert_eq!(pyc(json!("a\tb")), "\"a\\tb\"");
        // 0x08 → \b, 0x0c → \f
        assert_eq!(pyc(json!("\x08")), "\"\\b\"");
        assert_eq!(pyc(json!("\x0c")), "\"\\f\"");
    }

    #[test]
    fn ascii_other_control_chars_become_unicode_escape() {
        // Non-named control chars → \u00XX (lower-case hex per
        // Python's json default).
        assert_eq!(pyc(json!("\x01")), "\"\\u0001\"");
        assert_eq!(pyc(json!("\x1f")), "\"\\u001f\"");
        assert_eq!(pyc(json!("\x7f")), "\"\\u007f\"");
    }

    #[test]
    fn forward_slash_not_escaped() {
        // Python json does NOT escape `/` by default.
        assert_eq!(pyc(json!("a/b")), "\"a/b\"");
    }

    /// The byte-exact gotcha (CRATE_RECOMMENDATIONS §5.1). Non-ASCII
    /// characters become `\uXXXX` escapes; BMP chars one escape,
    /// non-BMP a UTF-16 surrogate pair. *This is where JCS diverges.*
    #[test]
    fn non_ascii_bmp_becomes_unicode_escape() {
        // U+00E9 (é) → é
        assert_eq!(pyc(json!("h\u{00e9}llo")), "\"h\\u00e9llo\"");
        // U+4E2D (中) → 中
        assert_eq!(pyc(json!("\u{4e2d}")), "\"\\u4e2d\"");
    }

    #[test]
    fn non_bmp_emits_surrogate_pair() {
        // U+1F389 🎉 → 🎉
        assert_eq!(pyc(json!("\u{1f389}")), "\"\\ud83c\\udf89\"");
    }

    #[test]
    fn nested_structure() {
        let v = json!({"outer": {"inner": [1, 2, 3]}});
        assert_eq!(pyc(v), "{\"outer\":{\"inner\":[1,2,3]}}");
    }

    /// Mission category §4: byte-exact recorded fixture for a minimal
    /// CompleteTrace mock. Updates require an explicit canonicalizer
    /// change PR.
    #[test]
    fn complete_trace_fixture() {
        let v = json!({
            "trace_id": "trace-x-1",
            "thought_id": "th-1",
            "task_id": "task-1",
            "agent_id_hash": "deadbeef",
            "started_at": "2026-04-30T00:15:53.123456+00:00",
            "completed_at": "2026-04-30T00:16:12.789012+00:00",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
            "components": [
                {
                    "component_type": "observation",
                    "data": {"attempt_index": 0},
                    "event_type": "THOUGHT_START",
                    "timestamp": "2026-04-30T00:15:53.123Z"
                }
            ]
        });
        let got = pyc(v);
        let expected = "{\"agent_id_hash\":\"deadbeef\",\"completed_at\":\"2026-04-30T00:16:12.789012+00:00\",\"components\":[{\"component_type\":\"observation\",\"data\":{\"attempt_index\":0},\"event_type\":\"THOUGHT_START\",\"timestamp\":\"2026-04-30T00:15:53.123Z\"}],\"started_at\":\"2026-04-30T00:15:53.123456+00:00\",\"task_id\":\"task-1\",\"thought_id\":\"th-1\",\"trace_id\":\"trace-x-1\",\"trace_level\":\"generic\",\"trace_schema_version\":\"2.7.0\"}";
        assert_eq!(got, expected);
    }

    /// Parity: ASCII-only payloads agree across Python-compat and JCS.
    #[test]
    fn ascii_only_python_matches_jcs() {
        let ascii_only = json!({"k": "hello", "n": 42, "list": [1, 2, 3]});
        assert_eq!(pyc(ascii_only.clone()), jcs(ascii_only));
    }

    /// Parity: non-ASCII payloads disagree — that's the documented
    /// gotcha (CRATE_RECOMMENDATIONS §5.1).
    #[test]
    fn non_ascii_python_diverges_from_jcs() {
        let v = json!({"k": "h\u{00e9}llo"});
        let py = pyc(v.clone());
        let j = jcs(v);
        assert_ne!(py, j, "non-ASCII MUST diverge — that's the gotcha");
        // Python form has the escape literal; JCS has UTF-8 bytes.
        assert!(py.contains("\\u00e9"), "python emits backslash-u-escape");
        assert!(j.contains("\u{00e9}"), "jcs emits raw UTF-8");
    }

    #[test]
    fn key_sort_uses_codepoint_byte_order() {
        // Codepoint order: "a" (0x61) < "z" (0x7a) < "é" (0x00E9).
        // UTF-8 byte order matches because UTF-8 preserves codepoint
        // ordering. After ensure_ascii, the key prints as é.
        let v = json!({"\u{00e9}": 1, "a": 2, "z": 3});
        assert_eq!(pyc(v), "{\"a\":2,\"z\":3,\"\\u00e9\":1}");
    }

    /// CIRISPersist#7 (closed v0.1.20) — wire-token preservation.
    ///
    /// The v0.1.19 approach (reproduce Python's float repr from f64
    /// via lexical-core) was fundamentally wrong: by the time we
    /// have an f64, the original token is gone —
    /// `0.003199200000000001` and `0.0031992000000000006` parse to
    /// the same double, and no formatter can recover which one was
    /// on the wire.
    ///
    /// v0.1.20: serde_json's `arbitrary_precision` feature stores
    /// `Number` as the parsed string. We never re-format —
    /// re-emission is byte-equal to the parse input.
    ///
    /// These tests use `from_str` to construct the input (mimicking
    /// the production wire-bytes path) and assert that
    /// canonicalization preserves the original tokens through a
    /// parse → walk → emit cycle.
    #[test]
    fn wire_floats_preserved_through_canonicalization() {
        // The bridge's captured YO-rejected values. Pre-v0.1.20
        // these came out via ryu (or lexical-core in v0.1.19) as
        // a different shortest-round-trip string. v0.1.20 preserves.
        let body = r#"{"cost_usd":0.0031992000000000006,"duration_ms":1433.2029819488525,"prompt_tokens":1234,"score":0.85}"#;
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(pyc(v), body);
    }

    /// Wire-token preservation for Python's various float shapes:
    /// scientific notation thresholds (`1e-05` vs `0.0001`),
    /// exponent padding (`1e-06`), positive-exponent sign (`1e+16`),
    /// and decimal range boundaries. These are exactly the format
    /// details v0.1.19's lexical-core threshold tune could *not*
    /// match across all cases. v0.1.20 sidesteps the entire
    /// reproduction problem by preserving.
    #[test]
    fn wire_python_format_variants_preserved() {
        let cases: &[&str] = &[
            r#"{"x":0.0001}"#,
            r#"{"x":1e-05}"#,
            r#"{"x":1e-06}"#,
            r#"{"x":1.5e-06}"#,
            r#"{"x":1e+16}"#,
            r#"{"x":1e+17}"#,
            r#"{"x":1e+100}"#,
            r#"{"x":1e-100}"#,
            r#"{"x":1.7976931348623157e+308}"#,
            r#"{"x":2.2250738585072014e-308}"#,
            r#"{"x":1000000000000000.0}"#,
            r#"{"x":0.30000000000000004}"#,
            r#"{"x":0.3333333333333333}"#,
            r#"{"x":-0.0}"#,
        ];
        for body in cases {
            let v: serde_json::Value = serde_json::from_str(body).unwrap();
            let got = pyc(v);
            assert_eq!(&got, body, "input={body} got={got}");
        }
    }

    /// Integer fast-path: `serde_json::Number` carrying an integer
    /// from a wire token round-trips as bare digits. Python:
    /// `json.dumps(42)` → `"42"`, NOT `"42.0"`.
    #[test]
    fn integers_render_bare_no_decimal_point() {
        // From json!() macro: Rust integer Display agrees with
        // Python.
        assert_eq!(pyc(json!(42)), "42");
        assert_eq!(pyc(json!(0)), "0");
        assert_eq!(pyc(json!(-1)), "-1");
        assert_eq!(pyc(json!(i64::MAX)), "9223372036854775807");
        assert_eq!(pyc(json!(u64::MAX)), "18446744073709551615");
        // From wire bytes: token preserved.
        let v: serde_json::Value =
            serde_json::from_str(r#"{"a":-1,"b":0,"c":42,"d":9223372036854775807}"#).unwrap();
        assert_eq!(pyc(v), r#"{"a":-1,"b":0,"c":42,"d":9223372036854775807}"#);
    }

    /// End-to-end shape: agent's wire body for an LLM-call
    /// component. Parsed → canonicalized → byte-equal to the wire
    /// input (with sort_keys re-ordering — keys arrive sorted in
    /// this case so output equals input).
    #[test]
    fn llm_call_data_blob_wire_preserved() {
        let body = r#"{"cost_usd":0.0031992000000000006,"duration_ms":1433.2029819488525,"prompt_tokens":1234,"score":0.85}"#;
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(pyc(v), body);
    }

    /// sort_keys is still applied — token preservation does NOT
    /// imply byte-for-byte input passthrough. The agent emits with
    /// `sort_keys=True`, so the wire is already sorted; we re-sort
    /// defensively (and so test bodies that arrive unsorted come
    /// out sorted on the canonical side).
    #[test]
    fn wire_preservation_with_key_resorting() {
        let unsorted = r#"{"z":0.0031992000000000006,"a":1e-05,"m":42}"#;
        let sorted_expected = r#"{"a":1e-05,"m":42,"z":0.0031992000000000006}"#;
        let v: serde_json::Value = serde_json::from_str(unsorted).unwrap();
        assert_eq!(pyc(v), sorted_expected);
    }

    /// v0.4.1 (CIRISEdge ask) — `canonicalize_envelope_for_signing`
    /// strips top-level `signature` and `signature_pqc` fields then
    /// applies PythonJsonDumpsCanonicalizer. Two envelopes (one
    /// without signature fields, one with) produce byte-identical
    /// canonical bytes — the strip rule + canonicalizer is the
    /// invertible-by-the-verifier shape.
    #[test]
    fn canonicalize_envelope_for_signing_strips_signature_fields() {
        let unsigned = serde_json::json!({
            "agent_role": "ally",
            "deployment_domain": "general",
            "trace_id": "abc",
        });
        let signed = serde_json::json!({
            "agent_role": "ally",
            "deployment_domain": "general",
            "trace_id": "abc",
            "signature": "0x1234567890abcdef",
            "signature_pqc": "0xfedcba0987654321",
        });
        let bytes_unsigned = canonicalize_envelope_for_signing(&unsigned).unwrap();
        let bytes_signed = canonicalize_envelope_for_signing(&signed).unwrap();
        assert_eq!(
            bytes_unsigned, bytes_signed,
            "strip rule must produce byte-identical canonical bytes"
        );
        // And the result is the standard sorted Python json.dumps shape.
        let expected = r#"{"agent_role":"ally","deployment_domain":"general","trace_id":"abc"}"#;
        assert_eq!(bytes_unsigned, expected.as_bytes());
    }

    /// v0.4.1 (CIRISEdge ask) — `body_sha256` returns SHA-256 of the
    /// raw bytes. Used as the `in_reply_to` content-derived ACK
    /// matching key + the `body_sha256_prefix` forensic join key.
    #[test]
    fn body_sha256_matches_sha256_of_input() {
        let body_str = r#"{"trace_id":"abc","action":"speak"}"#;
        let body: Box<serde_json::value::RawValue> =
            serde_json::value::RawValue::from_string(body_str.to_owned()).unwrap();
        let digest = body_sha256(&body);
        // Compare against direct sha256 of the verbatim bytes.
        use sha2::{Digest, Sha256};
        let expected: [u8; 32] = Sha256::digest(body_str.as_bytes()).into();
        assert_eq!(digest, expected);
    }
}
