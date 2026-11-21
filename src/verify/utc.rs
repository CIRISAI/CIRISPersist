//! v62.0.0 (PIN-fix2) — **the one boundary between persist's instants and
//! CIRISVerify's.**
//!
//! CIRISVerify 23.4.1 removed chrono from its tree: every instant in its API
//! that was a `chrono::DateTime<Utc>` is a
//! [`ciris_verify_core::utc::UtcDateTime`] (POSIX seconds plus nanoseconds,
//! chrono's range and ordering, no clock). Persist still keeps chrono
//! internally in v62.0 (its own chrono removal is a separate, paused slice),
//! so an instant that crosses into Verify or comes back out goes through
//! [`to_verify`] / [`from_verify`] and nowhere else.
//!
//! Both are lossless: seconds and the sub-second nanoseconds are carried as
//! they are. The two ranges are the same (years −262143 to 262142) and both
//! constructors refuse the same inputs (`from_timestamp` is `None` out of
//! range, or for nanoseconds of a second that is not a leap second), so
//! neither direction fails for an instant the other side holds. If one ever
//! does, the conversion answers [`InstantOutOfRange`] by name: it never
//! substitutes the epoch or a clamp.
//!
//! Where it is used (PIN-fix2.md lists every site): the signed tree head's
//! `timestamp` (`SignedTreeHead::signing_bytes` and the head's field), at
//! the audit log's and the stream log's producers, the stores that write
//! and read a head, and their witnesses. The signing bytes are seconds then
//! nanoseconds on both sides, so a head signed before the pin verifies after
//! it.

use chrono::{DateTime, Utc};
use ciris_verify_core::utc::UtcDateTime;

/// An instant one side holds and the other cannot represent: the POSIX
/// seconds and the sub-second nanoseconds that were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstantOutOfRange {
    /// POSIX seconds.
    pub secs: i64,
    /// Nanoseconds within the second.
    pub nanos: u32,
}

/// The token an out-of-range instant is refused under.
pub const INSTANT_OUT_OF_RANGE: &str = "instant_out_of_range";

impl std::fmt::Display for InstantOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{INSTANT_OUT_OF_RANGE}: {} s + {} ns is not a representable UTC instant",
            self.secs, self.nanos
        )
    }
}

impl std::error::Error for InstantOutOfRange {}

/// A persist instant as Verify's, losslessly.
///
/// # Errors
/// [`InstantOutOfRange`] when Verify's `UtcDateTime::from_timestamp` refuses
/// the seconds and nanoseconds (it does not for any instant chrono holds).
pub fn to_verify(t: DateTime<Utc>) -> Result<UtcDateTime, InstantOutOfRange> {
    let (secs, nanos) = (t.timestamp(), t.timestamp_subsec_nanos());
    UtcDateTime::from_timestamp(secs, nanos).ok_or(InstantOutOfRange { secs, nanos })
}

/// A Verify instant as persist's, losslessly.
///
/// # Errors
/// [`InstantOutOfRange`] when chrono's `DateTime::from_timestamp` refuses the
/// seconds and nanoseconds (it does not for any instant Verify holds).
pub fn from_verify(t: UtcDateTime) -> Result<DateTime<Utc>, InstantOutOfRange> {
    let (secs, nanos) = (t.timestamp(), t.timestamp_subsec_nanos());
    DateTime::<Utc>::from_timestamp(secs, nanos).ok_or(InstantOutOfRange { secs, nanos })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **I2432** — the boundary is lossless and the signing bytes do not
    /// move: an instant with nanoseconds round-trips both ways, the signed
    /// tree head's bytes over the converted instant are seconds then
    /// nanoseconds (as they were over chrono's), the serde text is chrono's,
    /// and the extremes of the shared range convert.
    #[test]
    fn i2432_the_verify_instant_boundary_is_lossless() {
        let t = DateTime::<Utc>::from_timestamp(1_700_000_000, 12_345).unwrap();
        let v = to_verify(t).unwrap();
        assert_eq!(v.timestamp(), 1_700_000_000);
        assert_eq!(v.timestamp_subsec_nanos(), 12_345);
        assert_eq!(from_verify(v).unwrap(), t);
        // The serde text is chrono's, byte for byte.
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            serde_json::to_string(&t).unwrap()
        );
        // The STH signing bytes: secs LE then nanos LE, the layout persist's
        // stored heads were signed over.
        let b =
            ciris_verify_core::transparency::SignedTreeHead::signing_bytes("l", 7, &[9u8; 32], v);
        let mut want = vec![1, 0, 0, 0, b'l'];
        want.extend_from_slice(&7u64.to_le_bytes());
        want.extend_from_slice(&[9u8; 32]);
        want.extend_from_slice(&t.timestamp().to_le_bytes());
        want.extend_from_slice(&t.timestamp_subsec_nanos().to_le_bytes());
        assert_eq!(b, want);
        // The shared extremes.
        for e in [DateTime::<Utc>::MIN_UTC, DateTime::<Utc>::MAX_UTC] {
            assert_eq!(from_verify(to_verify(e).unwrap()).unwrap(), e);
        }
        assert_eq!(
            from_verify(UtcDateTime::MAX).unwrap(),
            DateTime::<Utc>::MAX_UTC
        );
        assert_eq!(
            from_verify(UtcDateTime::MIN).unwrap(),
            DateTime::<Utc>::MIN_UTC
        );
    }
}
