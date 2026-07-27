//! v21.9.0 (CIRISPersist#519 item 2 / c1) — the **`deletion_window` lifecycle
//! processor**: the persist-owned breach signal.
//!
//! `deletion_window` is a signed temporal UPPER bound — the deadline by which a
//! consented payload must be deleted (GDPR/erasure). v21.9.0 hoisted it from
//! untyped `extra` to a typed [`super::envelope::EnvelopeCore`] field; this
//! module is the processor that graduates it out of the manifest's `UNASSIGNED`
//! row (a typed field with no processor is the carried-but-unprocessed
//! half-measure #519 exists to kill).
//!
//! **The breach is an absence-of-update judgment.** A `deletion_window` passing
//! is only meaningful against the question "was the row deleted in time?" — the
//! breach is: the window has passed AND the row is still present (no proof of
//! deletion). This module is the pure, total classifier of that judgment
//! ([`deletion_window_status`]); a periodic operator sweep feeds it each row +
//! whether that row was deleted, and emits/records a breach for the
//! `BreachedNotDeleted` verdicts. Keeping the judgment pure (no DB read) is
//! deliberate — the enforcement LOOP is a consumer concern, but the JUDGMENT
//! (what counts as a breach) is persist's, single-sourced here.

use chrono::{DateTime, Utc};

/// The lifecycle verdict for a payload carrying (or not) a `deletion_window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionWindowStatus {
    /// No `deletion_window` on the envelope — the lifecycle rule does not apply.
    NoWindow,
    /// The window is malformed (present but not an RFC-3339 timestamp) — a
    /// producer defect; treated as a breach-adjacent flag so it is not silently
    /// ignored (an unparseable erasure deadline enforces nothing).
    MalformedWindow,
    /// The window has not yet passed — nothing due.
    WithinWindow,
    /// The window passed and the row WAS deleted in time — compliant.
    DeletedInTime,
    /// The window passed and the row is STILL present — **the breach**: an
    /// erasure deadline elapsed without proof of deletion.
    BreachedNotDeleted,
}

/// Parse the typed `deletion_window` field (RFC-3339). `None` when absent;
/// `Err`-shaped callers use [`deletion_window_status`] instead of parsing raw.
pub fn parse_deletion_window(envelope: &serde_json::Value) -> Option<Result<DateTime<Utc>, ()>> {
    let raw = envelope
        .get(super::envelope::paths::DELETION_WINDOW)?
        .as_str()?;
    Some(
        raw.parse::<DateTime<Utc>>()
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| ()),
    )
}

/// The pure, total lifecycle judgment. `row_still_present` = whether the row
/// this envelope belongs to is still stored (`true`) or was deleted (`false`) —
/// the "proof of deletion" input the breach is defined against.
pub fn deletion_window_status(
    envelope: &serde_json::Value,
    row_still_present: bool,
    now: DateTime<Utc>,
) -> DeletionWindowStatus {
    match parse_deletion_window(envelope) {
        None => DeletionWindowStatus::NoWindow,
        Some(Err(())) => DeletionWindowStatus::MalformedWindow,
        Some(Ok(window)) => {
            if now <= window {
                DeletionWindowStatus::WithinWindow
            } else if row_still_present {
                DeletionWindowStatus::BreachedNotDeleted
            } else {
                DeletionWindowStatus::DeletedInTime
            }
        }
    }
}

/// True iff the payload is in breach of its erasure deadline (the window passed
/// with the row still present, or an unparseable window). The signal a sweep
/// emits on.
pub fn is_deletion_window_breached(
    envelope: &serde_json::Value,
    row_still_present: bool,
    now: DateTime<Utc>,
) -> bool {
    matches!(
        deletion_window_status(envelope, row_still_present, now),
        DeletionWindowStatus::BreachedNotDeleted | DeletionWindowStatus::MalformedWindow
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(window: Option<&str>) -> serde_json::Value {
        match window {
            Some(w) => serde_json::json!({ "dimension": "x:v1", "deletion_window": w }),
            None => serde_json::json!({ "dimension": "x:v1" }),
        }
    }
    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn no_window_is_noop() {
        assert_eq!(
            deletion_window_status(&env(None), true, t("2026-07-27T00:00:00Z")),
            DeletionWindowStatus::NoWindow
        );
    }

    #[test]
    fn within_window_is_not_breached() {
        let e = env(Some("2026-12-31T00:00:00Z"));
        assert_eq!(
            deletion_window_status(&e, true, t("2026-07-27T00:00:00Z")),
            DeletionWindowStatus::WithinWindow
        );
        assert!(!is_deletion_window_breached(
            &e,
            true,
            t("2026-07-27T00:00:00Z")
        ));
    }

    #[test]
    fn passed_and_still_present_is_the_breach() {
        let e = env(Some("2026-01-01T00:00:00Z"));
        assert_eq!(
            deletion_window_status(&e, true, t("2026-07-27T00:00:00Z")),
            DeletionWindowStatus::BreachedNotDeleted
        );
        assert!(is_deletion_window_breached(
            &e,
            true,
            t("2026-07-27T00:00:00Z")
        ));
    }

    #[test]
    fn passed_and_deleted_is_compliant() {
        let e = env(Some("2026-01-01T00:00:00Z"));
        assert_eq!(
            deletion_window_status(&e, false, t("2026-07-27T00:00:00Z")),
            DeletionWindowStatus::DeletedInTime
        );
        assert!(!is_deletion_window_breached(
            &e,
            false,
            t("2026-07-27T00:00:00Z")
        ));
    }

    #[test]
    fn malformed_window_is_flagged_not_ignored() {
        let e = env(Some("not-a-timestamp"));
        assert_eq!(
            deletion_window_status(&e, true, t("2026-07-27T00:00:00Z")),
            DeletionWindowStatus::MalformedWindow
        );
        assert!(is_deletion_window_breached(
            &e,
            true,
            t("2026-07-27T00:00:00Z")
        ));
    }
}
