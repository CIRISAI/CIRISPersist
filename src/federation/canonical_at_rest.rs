//! v31.0.0 (CIRISPersist#647) — **store the canonical envelope, not the
//! producer's bytes.**
//!
//! # The property this module exists to hold
//!
//! Every signature and every `original_content_hash` in the fabric is taken
//! over `ceg_produce_canonicalize(envelope)` — the JCS (RFC 8785) bytes. The
//! producer's *original* byte sequence therefore verifies nothing. Storing it
//! anyway costs bytes on every row forever, keeps the substrate sensitive to
//! producer serialization quirks (#645's whole class), and — the decisive one
//! — makes the artifact **un-verifiable by hand**: an operator holding the
//! stored column cannot `sha256sum` it and compare against
//! `original_content_hash` without first obtaining and running a JCS
//! implementation.
//!
//! With canonical bytes at rest, that operator check is exact:
//!
//! ```text
//! $ sha256sum <(psql -At -c "select attestation_envelope from federation_attestations where attestation_id = '…'")
//! ```
//!
//! equals the row's `original_content_hash`. That equality is asserted as a
//! test on all three backends (`envelope_bytes::test_support`).
//!
//! # Why this is signature-transparent
//!
//! Canonicalization is **idempotent**:
//!
//! ```text
//! canonicalize(parse(canonicalize(v))) == canonicalize(v)
//! ```
//!
//! so replacing an envelope with its canonical form does **not** move the
//! canonical bytes, does not move `SHA-256(canonical)`, and does not
//! invalidate a signature taken over them. Every gate downstream of
//! [`canonicalize_in_place`] — the `original_content_hash` cross-check, the
//! hybrid verify, `compute_persist_row_hash` — sees byte-identical input to
//! what it would have seen without it.
//!
//! That property is not assumed here. It is **proven** by
//! [`tests::canonicalization_is_idempotent_over_arbitrary_values`] and its
//! siblings, which run the round-trip over property-generated `Value`s,
//! property-generated number *tokens* (the `arbitrary_precision` danger
//! zone), and property-generated JSON *text*. The mutant guard
//! [`tests::the_idempotence_harness_has_teeth`] proves the harness can
//! actually fail.
//!
//! # What canonicalization is NOT: lossless
//!
//! JCS §3.2.2.3 serializes numbers through the ECMAScript
//! `Number::toString` algorithm — i.e. through an IEEE-754 double. Measured:
//!
//! | producer token | canonical form |
//! |---|---|
//! | `1E+2` | `100` |
//! | `1.5e-3` | `0.0015` |
//! | `1.000` | `1` |
//! | `9007199254740993` | `9007199254740992` |
//! | `12345678901234567890123` | `1.2345678901234568e+22` |
//! | `1e-400` | `0` |
//! | `1e400` | **rejected** (non-finite) |
//!
//! This is *lossy but idempotent*, and it is not a new loss: the hash and the
//! signature already went through it, so the precision was never covered by
//! any signature. What changes is that the un-covered precision is no longer
//! *retained* — an envelope carrying an integer beyond 2^53 stores the
//! double-rounded value. Producers needing exact wide integers must ship them
//! as strings, which is already true of anything they wanted a signature to
//! cover.
//!
//! `1e400` and friends are a hard **refusal** here, not a silent rounding —
//! and they were already refused, because `check_envelope_size_admission`
//! canonicalizes and every signature check canonicalizes. This module does
//! not narrow the admitted set on that axis.
//!
//! # The storage-stability guard
//!
//! Storing "the canonical form" as a `serde_json::Value` is only useful if
//! *re-serializing that Value* reproduces the canonical bytes — because the
//! backends bind envelope columns with `serde_json::to_string(&value)`. Those
//! two writers agree on everything except one axis: `serde_json::Map` orders
//! keys by UTF-8 byte order, JCS orders them by **UTF-16 code unit** order.
//! They differ only when one object holds both a supplementary-plane key
//! (U+10000+) and a key in U+E000..=U+FFFF — e.g. `{"\u{FFFF}":1,"😀":2}`.
//!
//! [`canonicalize_in_place`] therefore *checks* the round-trip and REFUSES an
//! envelope whose canonical form would not survive `serde_json`'s writer.
//! That refusal is the price of making hand-verifiability an invariant rather
//! than a usually-true property, and it costs nothing real: federation
//! envelope member names are ASCII identifiers.
//!
//! # Canon versioning — what canonical-at-rest pins
//!
//! [`ceg_produce_canonicalize`](crate::verify::canonical::ceg_produce_canonicalize)
//! is **versioned** ([`CanonVersion`](crate::verify::canonical::CanonVersion),
//! selected by
//! [`produce_canon_version`](crate::verify::canonical::produce_canon_version),
//! `V2Jcs` since v4.15.0). Storing canonical bytes therefore pins a row to
//! the canon version that admitted it: a future `V3` would leave existing
//! rows canonical-under-V2 and non-canonical-under-V3, exactly as a producer
//! byte-sequence is non-canonical today.
//!
//! This is **not** a new exposure. The row's *signature* was already pinned
//! to its canon version — that is what `canonicalizer_for` reads a per-row
//! signed epoch to resolve. Canonical-at-rest adds no new version coupling;
//! it makes the existing coupling visible in the stored bytes. A future canon
//! bump faces the same re-publish migration as v31, and it faces it whether
//! or not this change lands.
//!
//! The stored bytes deliberately do **not** carry a canon-version tag
//! alongside them. The version is already recoverable from the row (the
//! signed epoch the verify side reads), and a second, unsigned copy of it in
//! the payload would be a forgeable discriminator — the exact downgrade
//! surface `canonicalizer_for`'s doc comment warns about.

use crate::federation::Error;

/// The canonical at-rest bytes of an envelope: `ceg_produce_canonicalize`,
/// with the produce-side canon version gate applied.
///
/// This is the byte sequence `original_content_hash` digests and the byte
/// sequence a signature covers — and, after [`canonicalize_in_place`], the
/// byte sequence stored in the column.
///
/// # Errors
///
/// [`Error::InvalidArgument`] if the value cannot be canonicalized — in
/// practice a non-finite number (`1e400`), which JSON cannot represent under
/// the ECMAScript number algorithm JCS mandates.
pub fn canonical_bytes(envelope: &serde_json::Value) -> Result<Vec<u8>, Error> {
    crate::verify::canonical::ceg_produce_canonicalize(envelope)
        .map_err(|e| Error::InvalidArgument(format!("envelope canonicalize: {e}")))
}

/// Replace `envelope` with its canonical at-rest form, in place.
///
/// After this returns `Ok(())`, `serde_json::to_vec(envelope)` is
/// byte-identical to [`canonical_bytes`]`(envelope)` — so every backend's
/// existing `serde_json::to_string(&…envelope)` bind site writes the
/// canonical bytes without changing a line of it, and the stored column
/// `sha256sum`s to `original_content_hash`.
///
/// Idempotent: calling it on an already-canonical envelope is a no-op on the
/// bytes (proven in this module's property tests), so it is safe at every
/// chokepoint and safe to call twice.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] if the envelope cannot be canonicalized
///   (non-finite number).
/// - [`Error::InvalidArgument`] if the canonical form would not survive
///   `serde_json`'s writer — the UTF-16-vs-UTF-8 key-order divergence
///   described in the module docs. Refused rather than stored, because a
///   row that silently failed the round-trip would break exactly the
///   hand-verifiability this module exists to provide.
pub fn canonicalize_in_place(envelope: &mut serde_json::Value) -> Result<(), Error> {
    let bytes = canonical_bytes(envelope)?;
    let canonical: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        Error::InvalidArgument(format!(
            "canonical envelope bytes did not re-parse: {e} — this is a canonicalizer defect, \
             not a caller error"
        ))
    })?;
    let restored = serde_json::to_vec(&canonical).map_err(|e| {
        Error::InvalidArgument(format!("canonical envelope did not re-serialize: {e}"))
    })?;
    if restored != bytes {
        return Err(Error::InvalidArgument(format!(
            "envelope is not storage-stable under canonicalization: the JCS form and \
             serde_json's writer disagree, so the stored column would not sha256sum to \
             original_content_hash. This is the UTF-16-vs-UTF-8 object-key order axis \
             (an object holding both a supplementary-plane key and a U+E000..U+FFFF key); \
             rename the members to ASCII.\n  jcs:       {}\n  serde_json: {}",
            String::from_utf8_lossy(&bytes),
            String::from_utf8_lossy(&restored),
        )));
    }
    *envelope = canonical;
    Ok(())
}

/// Assert that `envelope` is already in canonical at-rest form — the
/// invariant [`canonicalize_in_place`] establishes.
///
/// Read-side / audit predicate: a row that fails this was written by
/// something that bypassed the ingest chokepoints.
///
/// # Errors
///
/// [`Error::InvalidArgument`] naming both byte sequences if the envelope's
/// `serde_json` serialization is not its canonical form.
pub fn check_canonical_at_rest(envelope: &serde_json::Value) -> Result<(), Error> {
    let bytes = canonical_bytes(envelope)?;
    let stored = serde_json::to_vec(envelope)
        .map_err(|e| Error::InvalidArgument(format!("envelope did not serialize: {e}")))?;
    if stored != bytes {
        return Err(Error::InvalidArgument(format!(
            "envelope is not canonical at rest — sha256sum of the stored column will NOT \
             equal original_content_hash.\n  stored:    {}\n  canonical: {}",
            String::from_utf8_lossy(&stored),
            String::from_utf8_lossy(&bytes),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    /// `canonicalize(parse(canonicalize(v))) == canonicalize(v)`.
    ///
    /// The single property the whole of #647 rests on. Returns the canonical
    /// bytes so callers can assert further things about them.
    fn assert_idempotent(v: &Value) -> Option<Vec<u8>> {
        // A value that cannot be canonicalized (non-finite number) is
        // REFUSED at ingest — it is not a counterexample, it is a rejection.
        let first = canonical_bytes(v).ok()?;
        let text = std::str::from_utf8(&first).expect("canonical output is UTF-8");
        let reparsed: Value = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("canonical bytes must re-parse: {e}\nbytes = {text}"));
        let second = canonical_bytes(&reparsed).unwrap_or_else(|e| {
            panic!("canonical bytes must re-canonicalize: {e}\nbytes = {text}")
        });
        assert_eq!(
            first,
            second,
            "CANONICALIZATION IS NOT IDEMPOTENT — canonical-at-rest (#647) is unsafe.\n  \
             first : {text}\n  second: {}",
            String::from_utf8_lossy(&second)
        );
        Some(first)
    }

    /// Arbitrary JSON *number tokens*. `serde_json` is built here with
    /// `arbitrary_precision`, so a parsed `Number` carries the producer's
    /// token verbatim — which is precisely why #645 was a live defect and
    /// precisely where a non-idempotent canonicalization would hide.
    fn number_token() -> impl Strategy<Value = String> {
        (
            prop::bool::ANY,
            "[0-9]{1,40}",
            prop::option::of("[0-9]{1,40}"),
            prop::option::of((prop::bool::ANY, prop::bool::ANY, "[0-9]{1,3}")),
        )
            .prop_map(|(neg, int, frac, exp)| {
                let mut s = String::new();
                if neg {
                    s.push('-');
                }
                // JSON forbids leading zeros on a multi-digit integer part.
                let int = int.trim_start_matches('0');
                s.push_str(if int.is_empty() { "0" } else { int });
                if let Some(f) = frac {
                    s.push('.');
                    s.push_str(&f);
                }
                if let Some((upper, negative, digits)) = exp {
                    s.push(if upper { 'E' } else { 'e' });
                    s.push(if negative { '-' } else { '+' });
                    s.push_str(&digits);
                }
                s
            })
    }

    fn arb_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            prop::bool::ANY.prop_map(Value::Bool),
            any::<i64>().prop_map(|i| Value::Number(i.into())),
            any::<u64>().prop_map(|i| Value::Number(i.into())),
            any::<f64>().prop_filter_map("finite", |f| serde_json::Number::from_f64(f)
                .map(Value::Number)),
            // Parsed from a token, NOT built through a Rust literal — the
            // whole point is to carry a producer token into the Value.
            number_token().prop_map(|t| serde_json::from_str::<Value>(&t).unwrap_or(Value::Null)),
            ".{0,24}".prop_map(Value::String),
            prop::string::string_regex("[\\PC\\p{Cc}]{0,12}")
                .expect("literal regex")
                .prop_map(Value::String),
        ];
        leaf.prop_recursive(5, 64, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::hash_map(".{0,10}", inner, 0..6)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// PHASE 1 of #647: the load-bearing property, over arbitrary values.
        #[test]
        fn canonicalization_is_idempotent_over_arbitrary_values(v in arb_value()) {
            assert_idempotent(&v);
        }

        /// The `arbitrary_precision` danger zone, hit directly.
        #[test]
        fn canonicalization_is_idempotent_over_number_tokens(t in number_token()) {
            let v: Value = serde_json::from_str(&t).expect("the generator emits legal JSON");
            assert_idempotent(&v);
        }

        /// The real ingest shape: arbitrary *bytes* that happen to parse.
        #[test]
        fn canonicalization_is_idempotent_over_arbitrary_text(s in ".{0,60}") {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                assert_idempotent(&v);
            }
        }

        /// The at-rest invariant survives the same generator: whatever
        /// `canonicalize_in_place` accepts, `check_canonical_at_rest` then
        /// passes, and the stored bytes hash to the canonical digest.
        #[test]
        fn canonicalize_in_place_establishes_the_at_rest_invariant(v in arb_value()) {
            let mut e = v.clone();
            if canonicalize_in_place(&mut e).is_ok() {
                check_canonical_at_rest(&e).expect("in_place establishes the invariant");
                // Idempotent as a whole operation, not just on the bytes.
                let once = serde_json::to_vec(&e).expect("serializes");
                canonicalize_in_place(&mut e).expect("second pass is a no-op");
                prop_assert_eq!(once, serde_json::to_vec(&e).expect("serializes"));
            }
        }
    }

    /// "A check that cannot fail is a report." A deliberately
    /// non-idempotent canonicalizer must make the harness above red — if it
    /// does not, the green above proves nothing.
    #[test]
    fn the_idempotence_harness_has_teeth() {
        use proptest::strategy::ValueTree as _;
        use proptest::test_runner::TestRunner;

        // Escapes backslashes on every pass without ever unescaping: a
        // realistic escaping bug, and non-idempotent by construction.
        fn bad_canon(v: &Value) -> Option<Vec<u8>> {
            let s = String::from_utf8(canonical_bytes(v).ok()?).expect("UTF-8");
            Some(s.replace('\\', "\\\\").into_bytes())
        }
        fn bad_is_idempotent(v: &Value) -> bool {
            let Some(first) = bad_canon(v) else {
                return true; // refused, not a counterexample
            };
            let Ok(text) = std::str::from_utf8(&first) else {
                return true;
            };
            let Ok(reparsed) = serde_json::from_str::<Value>(text) else {
                return true;
            };
            bad_canon(&reparsed).is_some_and(|second| first == second)
        }

        // The hand-picked witness the mutant must fail on.
        assert!(
            !bad_is_idempotent(&serde_json::json!(["\u{0}"])),
            "the mutant canonicalizer is idempotent — the harness would not \
             have caught a real non-idempotence"
        );

        // And the generator reaches it on its own, so the property tests
        // above are not merely running on trivial inputs.
        let mut runner = TestRunner::deterministic();
        let strategy = arb_value();
        let mut caught = 0_u32;
        let (mut non_ascii, mut nested, mut escaped) = (0_u32, 0_u32, 0_u32);
        for _ in 0..5_000 {
            let v = strategy
                .new_tree(&mut runner)
                .expect("generator produces a tree")
                .current();
            let text = v.to_string();
            if text.bytes().any(|b| b >= 0x80) {
                non_ascii += 1;
            }
            if text.matches('[').count() + text.matches('{').count() >= 3 {
                nested += 1;
            }
            if text.contains('\\') {
                escaped += 1;
            }
            if !bad_is_idempotent(&v) {
                caught += 1;
            }
        }
        assert!(
            caught > 0,
            "the generator never produced a value the mutant fails on"
        );
        assert!(non_ascii > 20, "the generator never produced non-ASCII");
        assert!(nested > 20, "the generator never produced nesting");
        assert!(escaped > 20, "the generator never produced string escapes");
    }

    /// The hand-picked table. The property tests are where the unexpected
    /// counterexample would be found; this is where a human looks to see
    /// what the canonical form of a known-awkward token actually IS.
    ///
    /// Every expectation is the MEASURED output, recorded so a canonicalizer
    /// or backend swap that moves it is a red rather than a silent wire-shape
    /// change.
    #[test]
    fn hand_picked_number_tokens_canonicalize_as_measured() {
        let cases: &[(&str, &str)] = &[
            ("1e+2", "100"),
            ("1.5e-3", "0.0015"),
            ("1E5", "100000"),
            ("1.0", "1"),
            ("1.000", "1"),
            ("-0", "0"),
            ("-0.0", "0"),
            ("0.1", "0.1"),
            ("1e21", "1e+21"),
            ("1e20", "100000000000000000000"),
            ("5e-324", "5e-324"),
            // Beyond f64's exact-integer range: JCS rounds through a double.
            ("9007199254740991", "9007199254740991"),
            ("9007199254740993", "9007199254740992"),
            ("18446744073709551615", "18446744073709552000"),
            ("12345678901234567890", "12345678901234567000"),
            ("123456789012345678901234567890", "1.2345678901234568e+29"),
            // A very long decimal expansion collapses to the shortest
            // round-tripping form of the double it names.
            ("0.1000000000000000000000000000001", "0.1"),
            ("0.0031992000000000006", "0.0031992000000000006"),
            // Underflow is a silent zero; overflow is a hard refusal (below).
            ("1e-400", "0"),
        ];
        for (token, expected) in cases {
            let v: Value = serde_json::from_str(token).expect("legal JSON number");
            let bytes =
                assert_idempotent(&v).unwrap_or_else(|| panic!("{token} should canonicalize"));
            assert_eq!(
                std::str::from_utf8(&bytes).expect("UTF-8"),
                *expected,
                "canonical form of {token} moved"
            );
        }
    }

    /// Overflow to a non-finite double is REFUSED, not silently rounded —
    /// and it was already refused before #647, by every gate that
    /// canonicalizes (`check_envelope_size_admission`, the hybrid verify).
    #[test]
    fn non_finite_numbers_are_refused_not_rounded() {
        for token in ["1e400", "-1e400", "1e309", "1.7976931348623159e308"] {
            let v: Value = serde_json::from_str(token).expect("legal JSON number");
            assert!(
                canonical_bytes(&v).is_err(),
                "{token} canonicalized instead of being refused"
            );
            let mut e = serde_json::json!({ "n": v });
            assert!(
                canonicalize_in_place(&mut e).is_err(),
                "{token} nested in an object canonicalized instead of being refused"
            );
        }
    }

    /// Strings: escapes, non-ASCII, and the lone-surrogate case (which the
    /// parser refuses outright, so it can never reach storage).
    #[test]
    fn string_shapes_are_idempotent() {
        for text in [
            r#""café""#,
            r#""😀""#,
            r#""a\/b""#,
            r#""\b\f\n\r\t""#,
            // Control characters MUST arrive escaped; the parser refuses
            // them raw (asserted below).
            "\"\\u0000\\u001f\"",
            // The same character escaped and raw must land on identical bytes.
            r#""é""#,
            "\"\\u00e9\"",
            // U+2028 LINE SEPARATOR and U+FEFF BOM: legal in a JSON string,
            // emitted RAW by JCS (RFC 8785 §3.2.2.2).
            "\"\\u2028\\ufeff\"",
        ] {
            let v: Value = serde_json::from_str(text).expect("legal JSON string");
            assert_idempotent(&v).expect("strings always canonicalize");
        }
        // Lone surrogates are not admissible JSON for serde_json, so no
        // envelope can carry one into the canonicalizer.
        assert!(serde_json::from_str::<Value>(r#""\ud800""#).is_err());
        assert!(serde_json::from_str::<Value>(r#""\udfff\ud800""#).is_err());
        // Raw control characters are likewise refused by the parser, so the
        // escaped forms above are the only way one reaches the canonicalizer.
        assert!(serde_json::from_str::<Value>("\"\u{1}\"").is_err());
    }

    /// Deep nesting: the parser's recursion limit caps depth before the
    /// canonicalizer sees it, so the recursive writer cannot be driven past
    /// it from the wire.
    #[test]
    fn deep_nesting_is_capped_by_the_parser_then_idempotent() {
        let deep = format!("{}1{}", "[".repeat(127), "]".repeat(127));
        let v: Value = serde_json::from_str(&deep).expect("127 deep parses");
        assert_idempotent(&v).expect("deep values canonicalize");
        let too_deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        assert!(
            serde_json::from_str::<Value>(&too_deep).is_err(),
            "the parser's recursion limit is what bounds canonicalizer depth"
        );
    }

    /// **Hand-verifiability**, at the unit level: the bytes
    /// `canonicalize_in_place` leaves behind are what a backend's
    /// `serde_json::to_string(&envelope)` bind site writes, and their SHA-256
    /// is the `original_content_hash` a producer signed.
    ///
    /// The end-to-end version of this — through the real put/read path, with
    /// the real column — is in `envelope_bytes::test_support`, on all three
    /// backends.
    #[test]
    fn stored_bytes_sha256_to_the_original_content_hash() {
        use sha2::{Digest as _, Sha256};

        // A producer's bytes: pretty-printed, unsorted keys, exponent tokens.
        let submitted = "{\n  \"zz\": \"last\",\n  \"exp\": 1E+2,\n  \"neg\": 1.5e-3,\n  \
                         \"aa\": \"first\",\n  \"uni\": \"A\\u00e9\"\n}";
        let mut envelope: Value = serde_json::from_str(submitted).expect("legal JSON");

        // What the producer signed / hashed, computed BEFORE canonicalizing.
        let original_content_hash = hex::encode(Sha256::digest(
            canonical_bytes(&envelope).expect("canonicalizes"),
        ));

        canonicalize_in_place(&mut envelope).expect("canonicalize at rest");

        // The bytes a backend writes into the TEXT column.
        let stored = serde_json::to_string(&envelope).expect("serializes");
        assert_eq!(
            stored, r#"{"aa":"first","exp":100,"neg":0.0015,"uni":"Aé","zz":"last"}"#,
            "the stored column is not the canonical form"
        );

        // The operator's check, verbatim: sha256sum the column.
        assert_eq!(
            hex::encode(Sha256::digest(stored.as_bytes())),
            original_content_hash,
            "sha256sum of the stored column does not equal original_content_hash — \
             the artifact is not decipherable by hand at rest"
        );
        check_canonical_at_rest(&envelope).expect("the invariant holds");
    }

    /// The storage-stability refusal: an object whose JCS key order differs
    /// from `serde_json`'s writer order cannot be stored, because the column
    /// would not sha256sum to the canonical digest.
    ///
    /// This is the one shape #647 narrows. It is asserted rather than
    /// documented so that a future `preserve_order` / key-order change turns
    /// it green-by-accident visibly.
    #[test]
    fn storage_unstable_key_order_is_refused() {
        // U+FFFF sorts BEFORE U+1F600 in UTF-8 byte order (EF BF BF < F0 …)
        // and AFTER it in UTF-16 code-unit order (D83D … < FFFF).
        let mut e: Value =
            serde_json::from_str("{\"\u{FFFF}\":1,\"\u{1F600}\":2}").expect("legal JSON");
        let jcs = String::from_utf8(canonical_bytes(&e).expect("canonicalizes")).expect("UTF-8");
        let serde = serde_json::to_string(&e).expect("serializes");
        assert_ne!(
            jcs, serde,
            "the two writers agreed — the refusal below is now unreachable and \
             `canonicalize_in_place`'s guard should be revisited"
        );
        let err = canonicalize_in_place(&mut e).expect_err("must refuse");
        assert!(
            format!("{err}").contains("storage-stable"),
            "wrong refusal: {err}"
        );
    }

    /// [`check_canonical_at_rest`] must REFUSE a non-canonical envelope, not
    /// merely accept a canonical one.
    ///
    /// Added because a mutation run caught this: replacing the whole function
    /// body with `Ok(())` survived every other test in the file. A predicate
    /// that only ever gets shown passing inputs is a report, not a check — so
    /// it is shown a failing one here, on each axis it is supposed to see.
    #[test]
    fn check_canonical_at_rest_refuses_non_canonical_envelopes() {
        // Number token the producer wrote but JCS does not: `1E+2` -> `100`.
        let producer: Value = serde_json::from_str(r#"{"exp":1E+2}"#).expect("legal JSON");
        let err =
            check_canonical_at_rest(&producer).expect_err("a producer token is not canonical");
        assert!(
            format!("{err}").contains("not canonical at rest"),
            "wrong refusal: {err}"
        );
        // Trailing zeros: `1.000` -> `1`.
        let trailing: Value = serde_json::from_str(r#"{"one":1.000}"#).expect("legal JSON");
        check_canonical_at_rest(&trailing).expect_err("trailing zeros are not canonical");
        // Precision beyond f64: the wide integer is rewritten.
        let wide: Value =
            serde_json::from_str(r#"{"big":12345678901234567890123}"#).expect("legal JSON");
        check_canonical_at_rest(&wide).expect_err("a wide integer is not canonical");
        // Non-canonicalizable at all.
        let overflow: Value = serde_json::from_str(r#"{"n":1e400}"#).expect("legal JSON");
        check_canonical_at_rest(&overflow).expect_err("a non-finite number cannot be canonical");
        // …and the canonical forms of all of the above DO pass, so the
        // refusals above are about canonicality and not about the shapes.
        for src in [
            r#"{"exp":1E+2}"#,
            r#"{"one":1.000}"#,
            r#"{"big":12345678901234567890123}"#,
        ] {
            let mut v: Value = serde_json::from_str(src).expect("legal JSON");
            canonicalize_in_place(&mut v).expect("canonicalizes");
            check_canonical_at_rest(&v).expect("the canonical form passes");
        }
    }

    /// The ASCII-keyed envelopes the fabric actually carries are unaffected
    /// by the guard above.
    #[test]
    fn ordinary_envelopes_are_storage_stable() {
        let mut e = serde_json::json!({
            "dimension": "trust:peer:v1",
            "subject_key_ids": ["k-1", "k-2"],
            "score": 0.95,
            "nested": { "b": 1, "a": [true, false, null] },
            "unicode": "Ωé😀",
        });
        canonicalize_in_place(&mut e).expect("ordinary envelopes are storage-stable");
        check_canonical_at_rest(&e).expect("invariant");
    }
}
