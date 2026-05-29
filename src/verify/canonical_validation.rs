//! v3.5.0 (CIRISPersist#126) — CEG §0.5 / §0.6 / §0.7 canonicalization
//! rejection rules.
//!
//! # Background
//!
//! CIRISConformance verifies the CEG-0.1 canonicalization discipline,
//! which is normative for both **CCP** (producers emit canonical) and
//! **CCC** (consumers MUST reject non-canonical forms when verifying a
//! signature). Three normative rejections:
//!
//! - **§0.5 datetime**: timestamp fields MUST be
//!   `YYYY-MM-DDTHH:MM:SS.sssZ` — literal uppercase `Z` (not `+00:00`,
//!   not lowercase `z`), exactly 3 fractional digits.
//! - **§0.6 hex**: all hex-typed fields (signatures, hashes) MUST be
//!   lowercase, unpadded, byte-length-exact.
//! - **§0.7 future timestamp**: `signed_at` more than 5 minutes in the
//!   future → reject as malformed.
//!
//! # Where this lives
//!
//! Before v3.5.0 the lower-level [`canonicalize_value`](super::canonical::Canonicalizer::canonicalize_value)
//! path performed sorted-key JCS-style serialization but did NOT
//! enforce the rejection rules. `verify_hybrid` took raw
//! `canonical_bytes` and never parsed the timestamp/hex either. Net:
//! there was no surface at which §0.5/§0.6/§0.7 was enforced or
//! observable.
//!
//! This module adds **opt-in** validation. The recommended integration
//! is via [`validate_envelope_canonical_form`] — a free function that
//! walks the envelope JSON applying field-name-based rules. Callers
//! that need strict validation invoke it explicitly. Existing callers
//! are unaffected (the lower-level `canonicalize_value` does NOT
//! invoke validation; see the module-level decision note below).
//!
//! # Why opt-in instead of in-canonicalize
//!
//! The brief explicitly weighs the two integration points:
//!
//! 1. Wire validation into `canonicalize_envelope` — every
//!    canonicalize call rejects bad input. Strict, but might break
//!    existing callers that pass non-validating envelopes for
//!    non-signing purposes (e.g., audit-side inspection paths,
//!    test fixtures that intentionally exercise edge cases).
//! 2. Expose as a standalone `validate_envelope_canonical_form` —
//!    caller opts in. Additive, won't break anything, conformance +
//!    future strict paths can opt in.
//!
//! v3.5.0 ships option 2 — same reasoning as the brief recommends:
//! lower risk for the minor cut, no existing-caller breakage, and the
//! rejection surface is observable from the conformance harness via
//! the [`CanonicalizationError::kind`] vocabulary. A future major may
//! flip the lower-level canonicalize-path to call validation
//! transparently once the consumer audit is complete.

use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};

/// v3.5.0 (CIRISPersist#126) — typed errors from CEG §0.5/§0.6/§0.7
/// validation. Each variant carries the offending value + a
/// human-readable reason for telemetry / logs; the
/// [`kind()`](CanonicalizationError::kind) tokens are the stable
/// closed-set vocabulary the CIRISConformance harness asserts against
/// (mirrors the `CEG-0.1` `kind` strings in the spec).
#[derive(Debug, Clone, thiserror::Error)]
pub enum CanonicalizationError {
    /// CEG §0.5: timestamp field is not `YYYY-MM-DDTHH:MM:SS.sssZ`.
    /// The value either has an explicit offset (`+00:00`), uses
    /// lowercase `z`, has the wrong number of fractional digits
    /// (not exactly 3), or fails RFC3339 parsing.
    #[error("CEG §0.5 invalid datetime: {value:?} — {reason}")]
    InvalidDatetime {
        /// The offending datetime string (truncated to 128 chars in
        /// log output to avoid log-flood on enormous garbage inputs).
        value: String,
        /// Human-readable reason — what specifically is wrong.
        reason: String,
    },

    /// CEG §0.6: hex field has uppercase digits or wrong byte length.
    #[error("CEG §0.6 invalid hex: {value:?} — {reason}")]
    InvalidHex {
        /// The offending hex string (truncated to 128 chars in log
        /// output).
        value: String,
        /// Human-readable reason.
        reason: String,
    },

    /// CEG §0.7: `signed_at` is more than 5 minutes in the future.
    #[error("CEG §0.7 signed_at in future: {signed_at:?} ({skew_secs}s ahead of now)")]
    SignedAtInFuture {
        /// The offending `signed_at` value.
        signed_at: String,
        /// How many seconds ahead of `now` the timestamp is.
        skew_secs: i64,
    },
}

impl CanonicalizationError {
    /// Stable string-token for telemetry / structured logging.
    /// THREAT_MODEL.md AV-15 closed-set vocabulary; the
    /// CIRISConformance harness asserts these exact tokens to verify
    /// the §0.5/§0.6/§0.7 rejection surface is observable.
    pub fn kind(&self) -> &'static str {
        match self {
            CanonicalizationError::InvalidDatetime { .. } => "canonicalization_timestamp",
            CanonicalizationError::InvalidHex { .. } => "canonicalization_hex",
            CanonicalizationError::SignedAtInFuture { .. } => "signed_at_in_future",
        }
    }
}

/// v3.5.0 (CIRISPersist#126) — CEG §0.7 clock-skew tolerance. A
/// `signed_at` that is more than this far in the future is rejected
/// as malformed.
///
/// The 5-minute window matches CEG §0.7 verbatim. Persist exposes the
/// constant so deployments doing their own validation use the same
/// tolerance as the canonical implementation.
pub const MAX_SIGNED_AT_FUTURE_SKEW: Duration = Duration::minutes(5);

/// v3.5.0 (CIRISPersist#126) — CEG §0.5 datetime validation.
///
/// Accepts iff the value matches `YYYY-MM-DDTHH:MM:SS.sssZ`:
///
/// - Calendar shape `YYYY-MM-DDTHH:MM:SS` (RFC3339 prefix).
/// - **Exactly 3 fractional digits** after `.` — `.sss`.
/// - Trailing literal uppercase `Z` — NOT `+00:00`, NOT lowercase `z`.
/// - Total length 24 characters.
///
/// # Rejection examples
///
/// - `2026-05-29T12:34:56.789+00:00` → `+00:00` offset (CEG §0.5
///   explicit: "MUST be literal `Z`").
/// - `2026-05-29T12:34:56.789z` → lowercase `z`.
/// - `2026-05-29T12:34:56.7Z` → 1 fractional digit.
/// - `2026-05-29T12:34:56.7890Z` → 4 fractional digits.
/// - `2026-05-29T12:34:56Z` → 0 fractional digits.
pub fn validate_canonical_datetime(s: &str) -> Result<(), CanonicalizationError> {
    // Fast-path: total length must be exactly 24 for `YYYY-MM-DDTHH:MM:SS.sssZ`.
    if s.len() != 24 {
        return Err(CanonicalizationError::InvalidDatetime {
            value: truncate_for_log(s),
            reason: format!(
                "length {} != 24 (expected YYYY-MM-DDTHH:MM:SS.sssZ)",
                s.len()
            ),
        });
    }
    // Trailing char must be uppercase `Z`.
    let bytes = s.as_bytes();
    if bytes[23] != b'Z' {
        return Err(CanonicalizationError::InvalidDatetime {
            value: truncate_for_log(s),
            reason: "trailing character is not literal uppercase 'Z' \
                     (CEG §0.5 forbids '+00:00' and 'z')"
                .to_owned(),
        });
    }
    // Fractional separator must be at byte 19; bytes 20..23 must be 3 ASCII digits.
    if bytes[19] != b'.' {
        return Err(CanonicalizationError::InvalidDatetime {
            value: truncate_for_log(s),
            reason: "expected '.' at position 19 (3 fractional digits required)".to_owned(),
        });
    }
    for (i, b) in bytes[20..23].iter().enumerate() {
        if !b.is_ascii_digit() {
            return Err(CanonicalizationError::InvalidDatetime {
                value: truncate_for_log(s),
                reason: format!("non-digit at fractional position {}", 20 + i),
            });
        }
    }
    // RFC3339 parse for the calendar shape — catches invalid months/days
    // (`2026-13-01`, `2026-02-30`, etc.). chrono accepts both `Z` and
    // `+00:00`, so the explicit byte check above is the
    // §0.5-specific guard; this is the structural fallback.
    if DateTime::<Utc>::from_str(s).is_err() {
        return Err(CanonicalizationError::InvalidDatetime {
            value: truncate_for_log(s),
            reason: "RFC3339 parse failed (invalid calendar values?)".to_owned(),
        });
    }
    Ok(())
}

/// v3.5.0 (CIRISPersist#126) — CEG §0.6 hex validation.
///
/// Accepts iff the value is **lowercase hex** (`0-9a-f` only) AND, if
/// `expected_byte_len` is supplied, the byte-decoded length matches.
///
/// # Rejection examples
///
/// - `"DEADBEEF"` → uppercase digits (`A-F`).
/// - `"deadbe"` when `expected_byte_len = Some(32)` → 3 bytes != 32.
/// - `"deadbef"` → odd-length hex (not a valid byte sequence).
///
/// # Why `expected_byte_len: Option<usize>`
///
/// Some callers know the exact length to enforce (Ed25519 signature
/// = 64 bytes; SHA-256 = 32 bytes); some only need the lowercase
/// invariant. `None` skips the length check.
pub fn validate_canonical_hex(
    s: &str,
    expected_byte_len: Option<usize>,
) -> Result<(), CanonicalizationError> {
    // Lowercase + valid-hex digits.
    for (i, b) in s.bytes().enumerate() {
        let is_lower_hex = b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        if !is_lower_hex {
            // Specifically call out uppercase as the §0.6 violation —
            // it's the most common one. Non-hex characters get a
            // generic rejection.
            let reason = if (b'A'..=b'F').contains(&b) {
                format!(
                    "uppercase digit {:?} at position {} (CEG §0.6: hex MUST be lowercase)",
                    b as char, i
                )
            } else {
                format!("non-hex character {:?} at position {}", b as char, i)
            };
            return Err(CanonicalizationError::InvalidHex {
                value: truncate_for_log(s),
                reason,
            });
        }
    }
    // Odd-length hex is structurally invalid (no whole-byte decoding).
    if s.len() % 2 != 0 {
        return Err(CanonicalizationError::InvalidHex {
            value: truncate_for_log(s),
            reason: format!("odd hex length {} (not a whole-byte sequence)", s.len()),
        });
    }
    if let Some(expected) = expected_byte_len {
        let actual_bytes = s.len() / 2;
        if actual_bytes != expected {
            return Err(CanonicalizationError::InvalidHex {
                value: truncate_for_log(s),
                reason: format!(
                    "decoded length {} bytes != expected {} bytes",
                    actual_bytes, expected
                ),
            });
        }
    }
    Ok(())
}

/// v3.5.0 (CIRISPersist#126) — CEG §0.7 future-skew validation.
///
/// Rejects iff `signed_at > now + max_skew`. The CEG-spec
/// max_skew is [`MAX_SIGNED_AT_FUTURE_SKEW`] = 5 minutes; the arg is
/// exposed for deterministic tests + sovereign tolerance overrides.
///
/// `signed_at` is parsed as RFC3339; a parse failure surfaces as
/// [`CanonicalizationError::InvalidDatetime`] (the same kind §0.5
/// uses — a malformed datetime IS a §0.5 violation, regardless of
/// the §0.7 skew check).
pub fn validate_signed_at_not_future(
    signed_at: &str,
    now: DateTime<Utc>,
    max_skew: Duration,
) -> Result<(), CanonicalizationError> {
    let ts = DateTime::<Utc>::from_str(signed_at).map_err(|e| {
        CanonicalizationError::InvalidDatetime {
            value: truncate_for_log(signed_at),
            reason: format!("RFC3339 parse failed: {e}"),
        }
    })?;
    let skew = ts - now;
    if skew > max_skew {
        return Err(CanonicalizationError::SignedAtInFuture {
            signed_at: truncate_for_log(signed_at),
            skew_secs: skew.num_seconds(),
        });
    }
    Ok(())
}

/// v3.5.0 (CIRISPersist#126) — opt-in walk-and-validate the canonical
/// form of an envelope JSON.
///
/// **This is the recommended integration point** (per the
/// CIRISPersist#126 brief's wiring decision):
///
/// - `canonicalize_value` continues to do byte-exact serialization
///   only — existing callers unaffected.
/// - Callers that need CEG §0.5/§0.6/§0.7 enforcement invoke
///   `validate_envelope_canonical_form(&envelope, now)` BEFORE
///   feeding the canonical bytes to a signer / verifier.
/// - The CIRISConformance harness invokes this directly to verify the
///   rejection surface is observable.
///
/// # Field-name → rule mapping
///
/// | Field-name pattern | Rule applied |
/// |---|---|
/// | `signed_at` | §0.5 datetime AND §0.7 future-skew (`max_skew = 5min`) |
/// | `asserted_at`, `scrub_timestamp`, `*_at` (any suffix `_at`) | §0.5 datetime |
/// | `*_hex` (any field name ending in `_hex`) | §0.6 hex (no length check — varies by field) |
/// | `*signature*` (field name CONTAINS `signature`) | §0.6 hex when shape looks like hex; skipped otherwise (signatures may be base64) |
/// | `*hash*` (field name CONTAINS `hash`) | §0.6 hex |
///
/// The walk is recursive — nested objects + array elements are
/// inspected by their key names too. A single bad field anywhere in
/// the envelope rejects the whole walk.
///
/// **Signature-field nuance**: persist's federation rows store
/// signatures as base64 (`scrub_signature_classical`,
/// `scrub_signature_pqc`). Those fields do NOT match the §0.6 hex
/// rule because the value won't be a hex shape; the walk skips
/// fields whose VALUE shape isn't hex-like (i.e., contains `=`, `/`,
/// `+`, or characters outside `[0-9a-fA-F]`). Pure-hex signature
/// fields like CIRISLens' `digest_hex` get the §0.6 rule applied.
pub fn validate_envelope_canonical_form(
    envelope: &serde_json::Value,
    now: DateTime<Utc>,
) -> Result<(), CanonicalizationError> {
    walk(envelope, now)
}

fn walk(v: &serde_json::Value, now: DateTime<Utc>) -> Result<(), CanonicalizationError> {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                check_field(k, child, now)?;
                walk(child, now)?;
            }
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                walk(child, now)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_field(
    key: &str,
    value: &serde_json::Value,
    now: DateTime<Utc>,
) -> Result<(), CanonicalizationError> {
    let Some(s) = value.as_str() else {
        return Ok(());
    };

    // §0.5 + §0.7: signed_at gets BOTH checks. We apply §0.5 first
    // (structural) — §0.7 only meaningful on a parseable timestamp.
    if key == "signed_at" {
        validate_canonical_datetime(s)?;
        validate_signed_at_not_future(s, now, MAX_SIGNED_AT_FUTURE_SKEW)?;
        return Ok(());
    }

    // §0.5: any other timestamp-shaped field. Pattern: exact names
    // (`asserted_at`, `scrub_timestamp`) OR suffix `_at`.
    if key == "asserted_at"
        || key == "scrub_timestamp"
        || key == "valid_from"
        || key == "valid_to"
        || key == "effective_at"
        || key == "revoked_at"
        || key.ends_with("_at")
    {
        validate_canonical_datetime(s)?;
        return Ok(());
    }

    // §0.6: hex-typed fields. `_hex` suffix is the canonical marker;
    // we also check name contains `hash` or `signature`.
    if key.ends_with("_hex") {
        validate_canonical_hex(s, None)?;
        return Ok(());
    }

    if key.contains("hash") {
        // hash fields are always hex.
        validate_canonical_hex(s, None)?;
        return Ok(());
    }

    if key.contains("signature") {
        // Signature fields MAY be base64 (persist's scrub-signature
        // shape) or hex (CIRISLens' digest-style shape). Only apply
        // the §0.6 hex rule when the value LOOKS hex-shaped — see the
        // method's "Signature-field nuance" doc-comment.
        if looks_like_hex(s) {
            validate_canonical_hex(s, None)?;
        }
        return Ok(());
    }

    Ok(())
}

/// Heuristic: does the value's character set look like a hex string?
///
/// Returns `true` iff every char is in `[0-9a-fA-F]`. We deliberately
/// allow uppercase here so that an uppercase hex shape gets pushed
/// into the §0.6 rule (which then rejects the uppercase). The
/// opposite case — a base64 signature with `=` / `/` / `+` — falls
/// through and bypasses §0.6.
fn looks_like_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b))
}

fn truncate_for_log(s: &str) -> String {
    const MAX: usize = 128;
    if s.len() <= MAX {
        s.to_owned()
    } else {
        let cut = s.char_indices().nth(MAX).map(|(i, _)| i).unwrap_or(MAX);
        format!("{}…", &s[..cut])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── §0.5 datetime ────────────────────────────────────────────────

    #[test]
    fn validate_canonical_datetime_accepts_correct_form() {
        validate_canonical_datetime("2026-05-29T12:34:56.789Z").expect("CEG §0.5 canonical");
    }

    #[test]
    fn validate_canonical_datetime_rejects_offset() {
        let err = validate_canonical_datetime("2026-05-29T12:34:56.789+00:00").unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
        assert!(matches!(err, CanonicalizationError::InvalidDatetime { .. }));
    }

    #[test]
    fn validate_canonical_datetime_rejects_lowercase_z() {
        let err = validate_canonical_datetime("2026-05-29T12:34:56.789z").unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
        assert!(matches!(err, CanonicalizationError::InvalidDatetime { .. }));
    }

    #[test]
    fn validate_canonical_datetime_rejects_wrong_fractional_precision() {
        // 6 digits — rejected.
        let err = validate_canonical_datetime("2026-05-29T12:34:56.789012Z").unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
        // 0 digits (no `.sss`) — rejected.
        let err = validate_canonical_datetime("2026-05-29T12:34:56Z").unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
        // 1 digit — rejected.
        let err = validate_canonical_datetime("2026-05-29T12:34:56.7Z").unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
        // 4 digits — rejected.
        let err = validate_canonical_datetime("2026-05-29T12:34:56.7890Z").unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
    }

    #[test]
    fn validate_canonical_datetime_rejects_invalid_calendar() {
        // Structurally shaped but month 13 doesn't exist.
        let err = validate_canonical_datetime("2026-13-01T12:34:56.789Z").unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
    }

    // ── §0.6 hex ─────────────────────────────────────────────────────

    #[test]
    fn validate_canonical_hex_accepts_lowercase() {
        validate_canonical_hex("deadbeef", None).expect("lowercase OK");
        validate_canonical_hex("0123456789abcdef", None).expect("lowercase OK");
    }

    #[test]
    fn validate_canonical_hex_rejects_uppercase() {
        let err = validate_canonical_hex("DEADBEEF", None).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_hex");
        assert!(matches!(err, CanonicalizationError::InvalidHex { .. }));
        // Mixed case should also reject.
        let err = validate_canonical_hex("dEadbeef", None).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_hex");
    }

    #[test]
    fn validate_canonical_hex_rejects_wrong_byte_length() {
        // 3 bytes when caller expected 32.
        let err = validate_canonical_hex("deadbe", Some(32)).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_hex");
        assert!(matches!(err, CanonicalizationError::InvalidHex { .. }));
        // Exactly 32 bytes (64 chars) passes the same check.
        validate_canonical_hex(&"ab".repeat(32), Some(32)).expect("32 bytes OK");
    }

    #[test]
    fn validate_canonical_hex_rejects_non_hex_characters() {
        let err = validate_canonical_hex("dead/beef", None).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_hex");
    }

    #[test]
    fn validate_canonical_hex_rejects_odd_length() {
        let err = validate_canonical_hex("deadbef", None).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_hex");
    }

    // ── §0.7 future-skew ─────────────────────────────────────────────

    #[test]
    fn validate_signed_at_accepts_4min_future() {
        let now = chrono::Utc::now();
        let future = now + chrono::Duration::minutes(4);
        let s = future.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        validate_signed_at_not_future(&s, now, MAX_SIGNED_AT_FUTURE_SKEW).expect("4min OK");
    }

    #[test]
    fn validate_signed_at_rejects_6min_future() {
        let now = chrono::Utc::now();
        let future = now + chrono::Duration::minutes(6);
        let s = future.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let err = validate_signed_at_not_future(&s, now, MAX_SIGNED_AT_FUTURE_SKEW).unwrap_err();
        assert_eq!(err.kind(), "signed_at_in_future");
        assert!(matches!(
            err,
            CanonicalizationError::SignedAtInFuture { .. }
        ));
    }

    #[test]
    fn validate_signed_at_accepts_past() {
        let now = chrono::Utc::now();
        let past = now - chrono::Duration::hours(1);
        let s = past.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        validate_signed_at_not_future(&s, now, MAX_SIGNED_AT_FUTURE_SKEW).expect("past OK");
    }

    // ── envelope walk ────────────────────────────────────────────────

    #[test]
    fn validate_envelope_canonical_form_accepts_clean_envelope() {
        let now = chrono::Utc::now();
        let signed_at = (now - chrono::Duration::minutes(1))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let env = serde_json::json!({
            "signed_at": signed_at,
            "asserted_at": "2026-05-29T12:34:56.000Z",
            "scrub_timestamp": "2026-05-29T12:34:56.000Z",
            "original_content_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "kind": "holds_bytes",
        });
        validate_envelope_canonical_form(&env, now).expect("clean envelope");
    }

    #[test]
    fn validate_envelope_canonical_form_rejects_offset_signed_at() {
        let env = serde_json::json!({
            "signed_at": "2026-05-29T12:34:56.789+00:00",
        });
        let err = validate_envelope_canonical_form(&env, chrono::Utc::now()).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
    }

    #[test]
    fn validate_envelope_canonical_form_rejects_uppercase_hash() {
        let env = serde_json::json!({
            "original_content_hash":
                "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        });
        let err = validate_envelope_canonical_form(&env, chrono::Utc::now()).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_hex");
    }

    #[test]
    fn validate_envelope_canonical_form_walks_nested_fields() {
        // A multi-field envelope with one bad datetime DEEP inside a
        // nested object — the walk must find it and surface the
        // exact kind token.
        let env = serde_json::json!({
            "kind": "holds_bytes",
            "metadata": {
                "nested": {
                    "asserted_at": "2026-05-29T12:34:56.789+00:00",
                },
            },
        });
        let err = validate_envelope_canonical_form(&env, chrono::Utc::now()).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
    }

    #[test]
    fn validate_envelope_canonical_form_walks_array_elements() {
        // Array elements get the same walk.
        let env = serde_json::json!({
            "kind": "holds_bytes",
            "entries": [
                {"asserted_at": "2026-05-29T12:34:56.000Z"},
                {"asserted_at": "2026-05-29T12:34:56.789+00:00"},
            ],
        });
        let err = validate_envelope_canonical_form(&env, chrono::Utc::now()).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_timestamp");
    }

    #[test]
    fn validate_envelope_canonical_form_rejects_future_signed_at() {
        let now = chrono::Utc::now();
        let future = now + chrono::Duration::minutes(6);
        let s = future.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let env = serde_json::json!({ "signed_at": s });
        let err = validate_envelope_canonical_form(&env, now).unwrap_err();
        assert_eq!(err.kind(), "signed_at_in_future");
    }

    #[test]
    fn validate_envelope_canonical_form_skips_base64_signature() {
        // Persist's scrub-signature fields are base64. The walk must
        // NOT apply §0.6 hex to them.
        let env = serde_json::json!({
            "scrub_signature_classical":
                "abcdef0123456789ABCDEF/+=abcdef0123456789ABCDEF/+=abcdef==",
        });
        validate_envelope_canonical_form(&env, chrono::Utc::now())
            .expect("base64 signature must pass — not a §0.6 hex shape");
    }

    #[test]
    fn validate_envelope_canonical_form_applies_hex_to_signature_when_shape_matches() {
        // When the signature field's value IS hex-shaped, §0.6 applies.
        let env = serde_json::json!({
            "scrub_signature_classical":
                "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        });
        let err = validate_envelope_canonical_form(&env, chrono::Utc::now()).unwrap_err();
        assert_eq!(err.kind(), "canonicalization_hex");
    }

    // Stable-kind discipline check: every variant has a distinct token.
    #[test]
    fn canonicalization_error_kind_tokens_are_distinct() {
        use std::collections::HashSet;
        let variants = [
            CanonicalizationError::InvalidDatetime {
                value: String::new(),
                reason: String::new(),
            },
            CanonicalizationError::InvalidHex {
                value: String::new(),
                reason: String::new(),
            },
            CanonicalizationError::SignedAtInFuture {
                signed_at: String::new(),
                skew_secs: 0,
            },
        ];
        let kinds: HashSet<_> = variants.iter().map(|e| e.kind()).collect();
        assert_eq!(kinds.len(), variants.len());
    }
}
