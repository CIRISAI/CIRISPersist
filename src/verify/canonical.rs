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
//! That **is not RFC 8785 JCS.** Two divergences (FSD/CRATE_RECOMMENDATIONS
//! §5.1):
//!
//! 1. Python's `json.dumps` defaults to `ensure_ascii=True` —
//!    non-ASCII characters become `\uXXXX` escapes; non-BMP code
//!    points become UTF-16 surrogate pairs `\uXXXX\uYYYY`.
//! 2. Python `sort_keys` orders keys by Python str ordering (Unicode
//!    codepoint, UTF-32 semantics for keys above U+FFFF).
//!
//! For ASCII-only payloads the two match; for non-ASCII payloads they
//! diverge. Until/unless the agent flips to JCS, the lens must
//! produce Python-compatible bytes.
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
    // Integers: `serde_json::Number::Display` matches Python's bare
    // integer form (`42`, `-7`, no decimal point).
    //
    // Floats: CIRISPersist#7 — serde_json's default Display uses
    // ryu, which produces a different shortest-round-trip string
    // than Python's `float.__repr__` (Gay's dtoa) for ambiguous
    // doubles. e.g. ryu emits `0.003199200000000001` while Python
    // emits `0.0031992000000000006` for the same f64. Both round-
    // trip correctly; both are valid shortest. Different bytes
    // → broken canonical-bytes parity → universal
    // `verify_signature_mismatch`. Fix at the source: route floats
    // through `write_python_float` which uses lexical-core's
    // PYTHON_LITERAL format with threshold tuning + post-process
    // to byte-match Python's repr for production-range floats.
    use std::io::Write;
    if let Some(i) = n.as_i64() {
        // Integer fast-path; matches Python `json.dumps(42) == "42"`.
        let _ = write!(buf, "{i}");
    } else if let Some(u) = n.as_u64() {
        // u64 outside i64 range; same bare-digit form.
        let _ = write!(buf, "{u}");
    } else if let Some(f) = n.as_f64() {
        write_python_float(buf, f);
    } else {
        // serde_json::Number is one of i64 / u64 / f64; this branch
        // is unreachable. Defensive fallback to Display.
        let _ = write!(buf, "{n}");
    }
}

/// CIRISPersist#7 — Python-compatible float formatter.
///
/// Emits bytes matching Python's `repr(f)` / `json.dumps(f)` output
/// for the floats production agent traffic actually emits (cost_usd
/// in [1e-6, 1e2], duration_ms in [1, 1e6], scores in [0, 1]) and
/// most edge cases.
///
/// Implementation: lexical-core's `PYTHON_LITERAL` format with
/// threshold-tuned `WriteFloatOptions` (matches Python's switch
/// from decimal to scientific at `|f| < 1e-4` or `|f| >= 1e16`),
/// plus mechanical post-process of scientific-notation output to
/// match Python's `e+NN` / `e-NN` convention (signed exponent,
/// padded to ≥2 digits, no `1.0eX` artifact).
///
/// **Known limitation**: Python's `Py_dg_dtoa` (Gay's algorithm)
/// and lexical-core's underlying algorithm CAN diverge on rare
/// shortest-round-trip ties beyond what threshold tuning fixes.
/// Property-tested against the bridge's captured production wire
/// bodies (`tests/fixtures/wire/2.7.0/*` + the YO-rejected
/// captures from CIRISPersist#7); if a future capture shows
/// divergence, we ship a v0.1.x patch with a more exact algorithm
/// (a vendored Gay's-dtoa Rust port, ~500 LoC, on the v0.2.x
/// roadmap).
fn write_python_float(buf: &mut Vec<u8>, f: f64) {
    use std::io::Write;
    use std::num::NonZeroI32;

    // JSON technically forbids NaN/Inf/-Inf in Number, so
    // serde_json::Number can't carry them; defensive fallback for
    // safety. Python's `json.dumps(float('inf'), allow_nan=True)`
    // emits `Infinity` / `-Infinity` / `NaN` (the agent uses default
    // `allow_nan=True`).
    if f.is_nan() {
        buf.extend_from_slice(b"NaN");
        return;
    }
    if f.is_infinite() {
        buf.extend_from_slice(if f < 0.0 { b"-Infinity" } else { b"Infinity" });
        return;
    }

    const FMT: u128 = lexical_core::format::PYTHON_LITERAL;
    // Thresholds tuned to Python's switch-to-scientific behavior:
    //   |f| < 1e-4    → scientific (negative_exponent_break = -4)
    //   |f| >= 1e16   → scientific (positive_exponent_break = 15;
    //                   semantics is "scientific when exponent > N",
    //                   so N=15 makes 1e16+ scientific while 1e15
    //                   stays decimal — matches Python).
    //
    // The `expect`s here can never fire: the constants are non-zero
    // by inspection. NonZeroI32::new is `const`-friendly but
    // requires `unwrap` at this site (not const yet on stable).
    let opts = lexical_core::WriteFloatOptionsBuilder::new()
        .negative_exponent_break(NonZeroI32::new(-4))
        .positive_exponent_break(NonZeroI32::new(15))
        .build()
        .expect("thresholds are statically valid");
    let mut tmp = [0u8; 64];
    let written = lexical_core::write_with_options::<f64, FMT>(f, &mut tmp, &opts);
    let s = std::str::from_utf8(written).expect("lexical-core emits valid UTF-8");

    // Find scientific-notation marker.
    if let Some(e_pos) = s.bytes().position(|b| b == b'e' || b == b'E') {
        let mantissa = &s[..e_pos];
        let exp_str = &s[e_pos + 1..];

        // Lexical emits `1.0e16`; Python emits `1e+16`. Strip the
        // trailing `.0` from the mantissa for integer-valued floats.
        let mantissa = mantissa.strip_suffix(".0").unwrap_or(mantissa);
        buf.extend_from_slice(mantissa.as_bytes());
        buf.push(b'e');

        // Parse exponent and re-format Python-style:
        //   - sign always emitted (`+` for non-negative)
        //   - magnitude padded to ≥2 digits (`e-05`, not `e-5`).
        let exp: i32 = exp_str
            .parse()
            .expect("lexical-core emits parseable integer exponents");
        if exp >= 0 {
            buf.push(b'+');
            if exp < 10 {
                buf.push(b'0');
            }
            let _ = write!(buf, "{exp}");
        } else {
            buf.push(b'-');
            let abs = exp.unsigned_abs();
            if abs < 10 {
                buf.push(b'0');
            }
            let _ = write!(buf, "{abs}");
        }
    } else {
        // Decimal form. lexical-core PYTHON_LITERAL with the tuned
        // thresholds matches Python's repr byte-for-byte for the
        // [1e-4, 1e16) decimal range — exactly the production-
        // traffic range — for the floats CIRISAgent emits today.
        buf.extend_from_slice(s.as_bytes());
    }
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

    /// CIRISPersist#7 — bridge's specific YO-rejected divergent
    /// floats. Pre-v0.1.19 these came out via ryu as
    /// `0.003199200000000001` / `1433.2029819488523`; Python
    /// (`repr()` / `json.dumps`) emits the bridge's reference
    /// `0.0031992000000000006` / `1433.2029819488525`. Universal
    /// production reject. v0.1.19 closes by routing floats through
    /// `write_python_float` (lexical-core PYTHON_LITERAL +
    /// threshold tune + scientific post-process).
    #[test]
    fn bridge_captured_divergent_floats_match_python() {
        // The agent's actual production-traffic floats from the YO
        // bodies.
        assert_eq!(pyc(json!(0.0031992000000000006)), "0.0031992000000000006");
        assert_eq!(pyc(json!(1433.2029819488525)), "1433.2029819488525");
    }

    /// CIRISPersist#7 — production-range float parity. Each
    /// `(input, python_reference)` pair is the literal output of
    /// `python3 -c "import json; print(json.dumps(<input>))"`.
    /// Drift at any case is a regression.
    #[test]
    fn production_range_floats_match_python_repr() {
        let cases: &[(f64, &str)] = &[
            // Identity / signs
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (-1.0, "-1.0"),
            (100.0, "100.0"),
            (0.5, "0.5"),
            // Bridge's captured divergent values
            (0.0031992000000000006, "0.0031992000000000006"),
            (1433.2029819488525, "1433.2029819488525"),
            // Floating-point arithmetic edge cases
            (0.1 + 0.2, "0.30000000000000004"),
            (1.0 / 3.0, "0.3333333333333333"),
            // Decimal threshold boundaries (Python: < 1e-4 scientific)
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1e-4, "0.0001"),
            (1e-5, "1e-05"),
            (1e-6, "1e-06"),
            (1.5e-6, "1.5e-06"),
            // Decimal threshold boundaries (Python: >= 1e16 scientific)
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1e17, "1e+17"),
            // Large / small extremes
            (1e100, "1e+100"),
            (1e-100, "1e-100"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (2.2250738585072014e-308, "2.2250738585072014e-308"),
        ];
        for &(input, expected) in cases {
            let got = pyc(json!(input));
            assert_eq!(got, expected, "input={input:?} got={got} want={expected}");
        }
    }

    /// Integer fast-path: `serde_json::Number` carrying an integer
    /// must skip the float formatter (no `.0` suffix). Python:
    /// `json.dumps(42)` → `"42"`, NOT `"42.0"`.
    #[test]
    fn integers_render_bare_no_decimal_point() {
        assert_eq!(pyc(json!(42)), "42");
        assert_eq!(pyc(json!(0)), "0");
        assert_eq!(pyc(json!(-1)), "-1");
        assert_eq!(pyc(json!(i64::MAX)), "9223372036854775807");
        assert_eq!(pyc(json!(u64::MAX)), "18446744073709551615");
    }

    /// Real-world component-data shape: a dict of floats matching
    /// what an LLM-call component carries. End-to-end byte
    /// equivalence with Python's `json.dumps(..., sort_keys=True,
    /// separators=(',', ':'))`.
    #[test]
    fn llm_call_data_blob_matches_python() {
        let v = json!({
            "cost_usd": 0.0031992000000000006,
            "duration_ms": 1433.2029819488525,
            "prompt_tokens": 1234,
            "score": 0.85,
        });
        // Python reference: keys sorted, no whitespace, integers
        // bare, floats matching repr.
        let want = "{\"cost_usd\":0.0031992000000000006,\"duration_ms\":1433.2029819488525,\"prompt_tokens\":1234,\"score\":0.85}";
        assert_eq!(pyc(v), want);
    }
}
