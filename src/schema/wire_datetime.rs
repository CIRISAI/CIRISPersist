//! Wire-format ISO-8601 timestamp that preserves the on-the-wire
//! byte representation.
//!
//! # Mission alignment (MISSION.md §2 — `verify/`, MISSION.md §4
//! "Canonicalization parity")
//!
//! THREAT_MODEL.md AV-4: the agent emits timestamps via Python
//! `datetime.isoformat()`, which has subtleties chrono's
//! `DateTime::format` doesn't reproduce byte-exact:
//!
//! - microseconds are emitted **only when non-zero** (Python
//!   `2026-04-30T00:15:53+00:00`; chrono `%.6f` always emits
//!   `.000000`)
//! - timezone is `+00:00` for UTC datetimes (Python isoformat
//!   default), not `Z`
//! - sub-microsecond precision is omitted entirely
//!
//! These timestamps appear in the canonical-bytes input the agent
//! signs over (TRACE_WIRE_FORMAT.md §8). Any divergence in
//! reproduction breaks signature verification — and breaks it
//! deterministically: every batch from a Python agent containing
//! a zero-microsecond timestamp would fail `verify_invalid_signature`
//! against persist v0.1.x ≤ 0.1.7.
//!
//! v0.1.8 closes AV-4 by storing the wire bytes verbatim alongside
//! the parsed `DateTime<Utc>`. Serialization emits the raw bytes
//! (so re-serialization is byte-equal); typed accessors return the
//! parsed value (so the rest of persist sees the same types it did
//! before).
//!
//! ## Why a wrapper, not parallel fields
//!
//! Two parallel fields (`started_at: DateTime<Utc>` +
//! `started_at_raw: String`) would couple the trace struct's API to
//! the persistence concern. The wrapper hides the duality behind
//! `wire()` / `parsed()` — call sites using `parsed()` are typed
//! exactly as they were before; only the canonicalization path
//! cares about `wire()`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

/// An ISO-8601 timestamp preserved byte-exactly from its
/// on-the-wire form.
///
/// Equality is on the wire bytes: two `WireDateTime`s with
/// different wire bytes that parse to the same instant ARE
/// different — signature verification cares about the bytes,
/// not the calendar value.
#[derive(Debug, Clone)]
pub struct WireDateTime {
    raw: String,
    parsed: DateTime<Utc>,
}

impl WireDateTime {
    /// The wire bytes — what canonicalization MUST use.
    pub fn wire(&self) -> &str {
        &self.raw
    }

    /// The parsed UTC instant — what application code uses for
    /// time arithmetic, ordering, persistence column writes, etc.
    pub fn parsed(&self) -> DateTime<Utc> {
        self.parsed
    }

    /// Construct from a wire string. Returns `Err` if the string
    /// isn't a parseable RFC 3339 timestamp.
    ///
    /// Used by deserialization and by tests / benches that build
    /// traces in code (instead of via the wire format).
    pub fn from_wire(s: impl Into<String>) -> Result<Self, chrono::ParseError> {
        let raw = s.into();
        let parsed = parse_rfc3339(&raw)?;
        Ok(Self { raw, parsed })
    }
}

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc))
}

impl FromStr for WireDateTime {
    type Err = chrono::ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_wire(s.to_owned())
    }
}

impl PartialEq for WireDateTime {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for WireDateTime {}

impl Serialize for WireDateTime {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for WireDateTime {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let parsed = parse_rfc3339(&raw).map_err(serde::de::Error::custom)?;
        Ok(Self { raw, parsed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact preservation: deserialize → serialize → equal.
    /// This is the property AV-4 closure depends on.
    #[test]
    fn round_trip_preserves_wire_bytes() {
        let cases = [
            // Python isoformat with microseconds + +00:00 form
            "\"2026-04-30T00:15:53.123456+00:00\"",
            // Python isoformat with zero microseconds (microseconds
            // dropped entirely — the production-bug case)
            "\"2026-04-30T00:15:53+00:00\"",
            // Z-suffix form
            "\"2026-04-30T00:15:53.123456Z\"",
            // Sub-second omitted, Z form
            "\"2026-04-30T00:15:53Z\"",
            // Millisecond precision (3 digits)
            "\"2026-04-30T00:15:53.123+00:00\"",
            // Non-UTC offset (theoretical; the agent emits UTC)
            "\"2026-04-30T00:15:53.123456+02:00\"",
        ];
        for input in cases {
            let dt: WireDateTime = serde_json::from_str(input).expect("parse");
            let out = serde_json::to_string(&dt).expect("serialize");
            assert_eq!(out, input, "byte-exact round-trip for {input}");
        }
    }

    /// `wire()` returns the original string verbatim — what
    /// canonicalization uses.
    #[test]
    fn wire_returns_original() {
        let s = "2026-04-30T00:15:53.000000+00:00";
        let dt = WireDateTime::from_wire(s).unwrap();
        assert_eq!(dt.wire(), s);
    }

    /// `parsed()` returns a sensible chrono DateTime.
    #[test]
    fn parsed_returns_utc_datetime() {
        let dt = WireDateTime::from_wire("2026-04-30T00:15:53.123456+00:00").unwrap();
        let p = dt.parsed();
        // 2026-04-30T00:15:53+00:00 → epoch seconds via direct compute
        // (doesn't depend on remembering the exact integer).
        let expected: chrono::DateTime<chrono::Utc> =
            "2026-04-30T00:15:53.123456+00:00".parse().unwrap();
        assert_eq!(p, expected);
    }

    /// Equality is byte-equality, not instant-equality.
    /// 2026-04-30T00:15:53Z and 2026-04-30T00:15:53+00:00 are the
    /// same instant but different wire bytes — they must compare
    /// unequal because canonicalization treats them differently.
    #[test]
    fn equality_is_wire_byte_equality_not_instant_equality() {
        let z = WireDateTime::from_wire("2026-04-30T00:15:53Z").unwrap();
        let plus = WireDateTime::from_wire("2026-04-30T00:15:53+00:00").unwrap();
        assert_eq!(z.parsed(), plus.parsed(), "same instant");
        assert_ne!(z, plus, "different wire bytes — must be unequal");
    }

    /// Bad timestamps reject typed.
    ///
    /// Note: RFC 3339 §5.6 explicitly allows space as a date/time
    /// separator, and chrono's `parse_from_rfc3339` accepts it.
    /// We don't reject space-separator inputs — if the agent ever
    /// emits one (current code uses default `T`), wire-byte
    /// preservation still works.
    #[test]
    fn invalid_format_rejects() {
        assert!(WireDateTime::from_wire("not a timestamp").is_err());
        assert!(WireDateTime::from_wire("").is_err());
        // Missing timezone is invalid RFC 3339.
        assert!(WireDateTime::from_wire("2026-04-30T00:15:53").is_err());
        // Day-out-of-range is invalid.
        assert!(WireDateTime::from_wire("2026-13-99T00:15:53Z").is_err());
    }
}
