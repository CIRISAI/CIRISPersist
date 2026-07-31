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
//! ([`deletion_window_status`]) AND — since v22.0.0 — the sweep that drives it
//! against stored rows ([`run_deletion_window_watch`]).
//!
//! # v22.0.0 (CIRISPersist#543 / ciris.ai/contextual-integrity) — the sweep
//!
//! v21.9.0 shipped the judgment with the loop deliberately left to consumers.
//! That posture was wrong. The published promise is:
//!
//! > Producers commit to deletion windows upon publishing. If subjects revoke
//! > and the window expires without deletion proof, **the network itself raises
//! > a breach signal.**
//!
//! "The network itself" is not the operator's cron script — persist IS the
//! network's storage half, and nothing anywhere called the classifier against
//! a stored row. A pure judgment nobody drives is exactly the
//! carried-but-unprocessed half-measure #519 exists to kill; keeping the
//! judgment pure is still right, but it now has an in-repo driver.
//!
//! **The sweep emits EVIDENCE, never a verdict.** [`super::types`] (see the
//! `slashing:*` note at `src/federation/types.rs:505`) is explicit that a
//! persist-side flag "can NEVER be sole evidence for `slashing:*`; the WA
//! quorum is" the authority. So the sweep records through the `hard_case:*`
//! observability surface ([`super::hard_case`], #146 — "emitted by persist when
//! it *observes*"), never a sanction. Persist observes and records; the WA
//! quorum turns evidence into sentences elsewhere.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::hard_case::HardCaseEvent;
use super::{Attestation, Error, FederationDirectory};

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

// ── v22.0.0 (CIRISPersist#543) — the sweep ────────────────────────────────

/// The `hard_case:{kind}` suffixes this processor emits.
///
/// Deliberately NOT `slashing:*`. `src/federation/types.rs:505` states the rule
/// plainly: a persist-side flag "can NEVER be sole evidence for `slashing:*`;
/// the WA quorum is" the authority. A breach signal is persist saying *what it
/// observed*, not persist passing sentence — so it rides the `hard_case:*`
/// observability surface (open suffix vocabulary, see [`super::hard_case::kind`]
/// for the other canonical suffixes), and a WA quorum composes the verdict.
pub mod kind {
    /// The window passed with the row still present and un-retracted: an
    /// erasure deadline elapsed without proof of deletion.
    /// ([`DeletionWindowStatus::BreachedNotDeleted`](super::DeletionWindowStatus::BreachedNotDeleted))
    pub const DELETION_WINDOW_BREACH: &str = "deletion_window_breach";
    /// The row carries a `deletion_window` that is not an RFC-3339 timestamp
    /// ([`DeletionWindowStatus::MalformedWindow`](super::DeletionWindowStatus::MalformedWindow)).
    /// A producer defect, emitted under its OWN suffix rather than folded into
    /// the breach: an unparseable deadline enforces nothing, so it must not be
    /// silently dropped, but it is not the same observation as a missed
    /// deadline and a consumer must be able to tell them apart.
    pub const DELETION_WINDOW_MALFORMED: &str = "deletion_window_malformed";
}

/// The PAGE SIZE one [`run_deletion_window_watch`] pass reads at a time from
/// [`FederationDirectory::list_attestations_since`].
///
/// Not a total: the sweep pages through the corpus (see [`MAX_SCAN_PAGES`]).
/// If it ever does stop early it says so —
/// [`DeletionWindowWatchReport::scan_truncated`] — rather than pretending it
/// saw everything (the same honesty as `scores::RESOLVE_CANDIDATE_CAP` /
/// `ComposedVerdict::candidates_truncated`). Silent truncation on a **breach**
/// sweep would be the worst kind of green.
pub const DELETION_WINDOW_SCAN_CAP: u32 = 10_000;

/// Outcome of one [`run_deletion_window_watch`] pass.
///
/// The counts are **conditions observed**, not rows written: emission is
/// idempotent on `event_id`, so a re-run over an unchanged corpus reports the
/// same `breaches` count while writing no duplicate rows (identical contract to
/// [`ConsentWatchReport::sla_breaches`](super::hard_case::ConsentWatchReport::sla_breaches)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionWindowWatchReport {
    /// Federation-tier rows examined this pass.
    pub rows_scanned: usize,
    /// Of those, rows carrying a `deletion_window` at all.
    pub windows_seen: usize,
    /// Windows that have not yet passed — nothing due.
    pub within_window: usize,
    /// Windows that passed with the row retracted by its producer — compliant.
    pub deleted_in_time: usize,
    /// **The breach**: window passed, row still present and un-retracted. One
    /// `hard_case:deletion_window_breach` per condition.
    pub breaches: usize,
    /// Rows whose `deletion_window` does not parse. One
    /// `hard_case:deletion_window_malformed` per condition.
    pub malformed: usize,
    /// The scan filled its page ([`DELETION_WINDOW_SCAN_CAP`]) — rows beyond it
    /// were NOT examined this pass.
    pub scan_truncated: bool,
}

/// Deterministic `event_id` for a [`kind::DELETION_WINDOW_BREACH`] emission —
/// the idempotency key.
///
/// Keyed on `(kind, breached row, deadline)` in the same
/// `{kind}:{target}:{instant}` shape as
/// [`super::hard_case::watch_event_id`]. The instant is the **deadline**, never
/// `now`: both components are immutable properties of the observed row, so
/// every tick of the watch derives the SAME id for one ongoing breach and the
/// idempotent insert collapses them. Keying on `now` would spam one duplicate
/// row per cron tick — a breach watcher that floods the evidence plane is
/// itself an integrity failure.
#[must_use]
pub fn breach_event_id(attestation_id: &str, deadline: DateTime<Utc>) -> String {
    format!(
        "{}:{attestation_id}:{}",
        kind::DELETION_WINDOW_BREACH,
        deadline.timestamp()
    )
}

/// Deterministic `event_id` for a [`kind::DELETION_WINDOW_MALFORMED`] emission.
/// No instant component: a malformed window has no deadline to key on, and the
/// condition is a static property of an immutable row, so `(kind, row)` is
/// already stable across every pass.
#[must_use]
pub fn malformed_event_id(attestation_id: &str) -> String {
    format!("{}:{attestation_id}", kind::DELETION_WINDOW_MALFORMED)
}

/// The breach observation [`run_deletion_window_watch`] records — built here,
/// in ONE place, so every backend and any future caller emits a byte-identical
/// event (the [`super::hard_case::membership_removed_event`] pattern).
///
/// `target_key_id` is the breached ROW (the field's contract is "the
/// Contribution / row the case is against"); `subject_key_id` is the producer
/// who committed the window and owes the erasure. Everything a consumer needs
/// is ALSO in `detail`, self-describing, so nobody has to know the column
/// convention to read the evidence.
#[must_use]
pub fn breach_event(
    row: &Attestation,
    deadline: DateTime<Utc>,
    now: DateTime<Utc>,
) -> HardCaseEvent {
    HardCaseEvent {
        event_id: breach_event_id(&row.attestation_id, deadline),
        kind: kind::DELETION_WINDOW_BREACH.to_string(),
        target_key_id: Some(row.attestation_id.clone()),
        subject_key_id: Some(row.attesting_key_id.clone()),
        detail: serde_json::json!({
            "attestation_id": row.attestation_id,
            "producer_key_id": row.attesting_key_id,
            "attested_key_id": row.attested_key_id,
            "dimension": super::admission::envelope_dimension(&row.attestation_envelope),
            "subject_key_ids": row.subject_key_ids,
            "published_at": row.asserted_at.to_rfc3339(),
            "deletion_window": deadline.to_rfc3339(),
            "observed_at": now.to_rfc3339(),
        }),
        emitted_at: now,
    }
}

/// The malformed-window observation. See [`kind::DELETION_WINDOW_MALFORMED`]
/// for why it is a separate suffix rather than a breach.
#[must_use]
pub fn malformed_event(row: &Attestation, now: DateTime<Utc>) -> HardCaseEvent {
    HardCaseEvent {
        event_id: malformed_event_id(&row.attestation_id),
        kind: kind::DELETION_WINDOW_MALFORMED.to_string(),
        target_key_id: Some(row.attestation_id.clone()),
        subject_key_id: Some(row.attesting_key_id.clone()),
        detail: serde_json::json!({
            "attestation_id": row.attestation_id,
            "producer_key_id": row.attesting_key_id,
            "dimension": super::admission::envelope_dimension(&row.attestation_envelope),
            "raw_deletion_window": row
                .attestation_envelope
                .get(super::envelope::paths::DELETION_WINDOW),
            "observed_at": now.to_rfc3339(),
        }),
        emitted_at: now,
    }
}

/// v22.0.0 (CIRISPersist#543 / ciris.ai/contextual-integrity) — **the breach
/// sweep**: drive the pure classifier against stored rows and record a
/// `hard_case:*` observation for every row in breach of its erasure deadline.
///
/// # What it scans
///
/// One page (up to [`DELETION_WINDOW_SCAN_CAP`]) of
/// [`FederationDirectory::list_attestations_since`] — i.e. **federation-tier
/// rows**, which is precisely the promise's subject: "producers commit to
/// deletion windows upon **publishing**". A local-tier row is
/// producer-only-authority and never reached the wire (the E5 invariant), so
/// there is no published commitment to breach.
///
/// # What counts as proof of deletion
///
/// A row is deleted when it is **absent** (hard-deleted rows simply do not come
/// back from the scan — nothing to judge) or **retracted by its own producer**:
/// a `withdraws` / `supersedes` / `recants` from the row's own
/// `attesting_key_id` naming it in `references_attestation_id`. The retraction
/// fold goes through [`super::precedence`] — the same CEG §6.1 grouping
/// `scores::compose_verdict` uses — rather than an ad-hoc "does a composer
/// exist" scan, so this judgment cannot drift away from the one the read path
/// applies.
///
/// **Same-attester is load-bearing, not incidental.** A *subject's* `withdraws`
/// (admission rule 2/3/4) is the revocation that STARTS the erasure clock — the
/// demand, not the proof. Counting it as deletion proof would make every
/// revocation instantly self-satisfying and the breach signal unreachable. Per
/// CEG §6.1 rule 4 the producer's chain is evaluated on its own, which is
/// exactly the right reading here: only the producer can prove the producer
/// deleted something.
///
/// # What it emits
///
/// [`kind::DELETION_WINDOW_BREACH`] / [`kind::DELETION_WINDOW_MALFORMED`]
/// `hard_case:*` rows through
/// [`FederationDirectory::record_hard_case`] — local-tier observability,
/// **never** `slashing:*` (see [`kind`]). Idempotent on a deterministic
/// `event_id` ([`breach_event_id`] / [`malformed_event_id`]), so a cron-driven
/// re-run of the same condition writes nothing new.
///
/// Backend-agnostic by construction: it composes trait methods over
/// `&dyn FederationDirectory`, so memory / sqlite / postgres get identical
/// behaviour with no per-backend code (and no store-file edit).
pub async fn run_deletion_window_watch(
    dir: &dyn FederationDirectory,
    now: DateTime<Utc>,
) -> Result<DeletionWindowWatchReport, Error> {
    use std::collections::{HashMap, HashSet};

    let mut report = DeletionWindowWatchReport::default();
    /// Per-producer retraction sets, resolved once. A producer with many
    /// windowed rows costs ONE `list_attestations_by`, not one per row.
    type RetractionCache = HashMap<String, HashSet<String>>;
    let mut retracted: RetractionCache = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cursor: Option<DateTime<Utc>> = None;
    let mut truncated = true;

    for _page in 0..MAX_SCAN_PAGES {
        let page = dir
            .list_attestations_since(cursor, DELETION_WINDOW_SCAN_CAP)
            .await?;
        let Some(last) = page.last() else {
            truncated = false;
            break;
        };
        let page_full = page.len() as u32 >= DELETION_WINDOW_SCAN_CAP;
        let last_visible = last.promoted_at.unwrap_or(last.asserted_at);

        for row in &page {
            // The overlap the cursor step-back below deliberately creates.
            if !seen.insert(row.attestation_id.clone()) {
                continue;
            }
            report.rows_scanned += 1;

            // `NoWindow` — the lifecycle rule does not apply. Checked with the
            // module's OWN parser (never a re-derived one) and BEFORE any
            // read, so a corpus of ordinary rows costs the sweep nothing.
            let Some(parsed) = parse_deletion_window(&row.attestation_envelope) else {
                continue;
            };
            report.windows_seen += 1;

            // Proof of deletion: the producer's own structural retraction.
            // Resolved per producer and cached for the pass.
            let producer = &row.attesting_key_id;
            if !retracted.contains_key(producer) {
                let ids = producer_retracted_ids(dir, producer).await?;
                retracted.insert(producer.clone(), ids);
            }
            let row_still_present = !retracted
                .get(producer)
                .is_some_and(|ids| ids.contains(&row.attestation_id));

            // THE judgment — the pure classifier, single-sourced. This sweep
            // decides nothing on its own; it only supplies the two inputs the
            // classifier is defined over and records what it answers.
            match deletion_window_status(&row.attestation_envelope, row_still_present, now) {
                // Unreachable (we parsed a window above), but this loop stays
                // total: a breach sweep must never panic on a surprising row.
                DeletionWindowStatus::NoWindow => {}
                DeletionWindowStatus::WithinWindow => report.within_window += 1,
                DeletionWindowStatus::DeletedInTime => report.deleted_in_time += 1,
                DeletionWindowStatus::MalformedWindow => {
                    dir.record_hard_case(malformed_event(row, now)).await?;
                    report.malformed += 1;
                }
                DeletionWindowStatus::BreachedNotDeleted => {
                    // `parsed` is `Ok` on this arm by construction; matched
                    // rather than unwrapped so the sweep stays panic-free.
                    if let Ok(deadline) = parsed {
                        dir.record_hard_case(breach_event(row, deadline, now))
                            .await?;
                        report.breaches += 1;
                    }
                }
            }
        }

        if !page_full {
            truncated = false;
            break;
        }
        // Step the cursor BACK one microsecond rather than to `last_visible`
        // exactly: the read filters `visibility > since`, so a page boundary
        // that lands inside a group of rows sharing one visibility instant
        // would silently drop the rest of that group — on a BREACH sweep, the
        // worst possible way to be green. The re-fetched overlap is free
        // because `seen` already dedups it.
        cursor = Some(last_visible - chrono::Duration::microseconds(1));
    }

    report.scan_truncated = truncated;
    Ok(report)
}

/// How many [`DELETION_WINDOW_SCAN_CAP`]-sized pages one pass will walk before
/// giving up and reporting [`DeletionWindowWatchReport::scan_truncated`].
///
/// The pass pages through the whole corpus rather than stopping at one page —
/// a breach is a property of OLD rows, so a watcher that only ever looked at
/// the newest 10 000 would miss precisely the rows it exists to find. The
/// guard exists so a pathological corpus (more rows sharing one visibility
/// instant than fit in a page) terminates instead of spinning.
pub const MAX_SCAN_PAGES: usize = 128;

/// The set of `producer`'s own attestation ids that `producer` has structurally
/// retracted — the sweep's proof-of-deletion oracle.
///
/// Folds through [`super::precedence`] (group by
/// `(attesting_key_id, references_attestation_id)`, take the CEG §6.1
/// precedence winner) rather than "does any composer exist", which is the SAME
/// fold `scores::compose_verdict` applies on the read path. Single-sourcing it
/// matters: if the composer set ever grows a member that does NOT retract, this
/// stays correct because the winner's TYPE is what is checked, not the mere
/// presence of a composer.
///
/// `list_attestations_by` already narrows to one attester, so grouping by the
/// referenced id alone IS the §6.1 per-attester grouping.
async fn producer_retracted_ids(
    dir: &dyn FederationDirectory,
    producer: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    use super::precedence;
    use std::collections::{HashMap, HashSet};

    let rows = dir.list_attestations_by(producer).await?;
    let mut groups: HashMap<&str, Vec<&Attestation>> = HashMap::new();
    for composer in &rows {
        if !precedence::is_structural_composer(&composer.attestation_type) {
            continue;
        }
        let Some(refs) =
            precedence::references_attestation_id_from_envelope(&composer.attestation_envelope)
        else {
            continue;
        };
        groups.entry(refs).or_default().push(composer);
    }
    let mut retracted = HashSet::new();
    for (refs, group) in groups {
        if precedence::precedence_winner(&group)
            .is_some_and(|w| precedence::is_structural_composer(&w.attestation_type))
        {
            retracted.insert(refs.to_owned());
        }
    }
    Ok(retracted)
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

    #[test]
    fn breach_event_id_is_keyed_on_the_deadline_not_the_tick() {
        let deadline = t("2026-02-01T00:00:00Z");
        let a = breach_event_id("row-1", deadline);
        // The SAME ongoing breach, observed on a later cron tick, derives the
        // same id — that is what makes the idempotent insert collapse it.
        assert_eq!(a, breach_event_id("row-1", deadline));
        // A different row, or a different committed deadline, is a different
        // observation.
        assert_ne!(a, breach_event_id("row-2", deadline));
        assert_ne!(a, breach_event_id("row-1", t("2026-03-01T00:00:00Z")));
        assert!(a.starts_with(kind::DELETION_WINDOW_BREACH));
        // Malformed rides its OWN suffix so a consumer can tell "missed the
        // deadline" from "never had a parseable one".
        assert!(malformed_event_id("row-1").starts_with(kind::DELETION_WINDOW_MALFORMED));
        assert_ne!(malformed_event_id("row-1"), a);
    }
}

/// **The `{backend}` breach witness** for the v22.0.0 sweep
/// (CIRISPersist#543 / ciris.ai/contextual-integrity).
///
/// The body is backend-agnostic (`&dyn FederationDirectory`) and every arm
/// drives the SAME body, because the class this repo keeps re-learning is
/// "memory tolerated what sqlite/postgres refuse" — a watch proven on one
/// backend is a watch proven on one backend.
#[cfg(test)]
pub(crate) mod watch_witness {
    use super::*;
    use crate::federation::hard_case::{HardCaseEvent, HardCaseFilter};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::SignedAttestation;
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    use crate::store::Backend as _;

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().expect("rfc3339 literal")
    }

    /// When the producer published. Fixed, not `now - k`: a clock-relative
    /// fixture rots on a date (the AV-77 expiry-horizon lesson).
    const PUBLISHED_AT: &str = "2026-01-01T00:00:00Z";
    /// A committed erasure deadline that has PASSED by [`SWEEP_AT`].
    const PAST_WINDOW: &str = "2026-02-01T00:00:00Z";
    /// A committed erasure deadline still in the future at [`SWEEP_AT`].
    const FUTURE_WINDOW: &str = "2099-01-01T00:00:00Z";
    /// When the retractions land — after publication, before the sweep.
    const RETRACTED_AT: &str = "2026-01-15T00:00:00Z";
    /// The instant the watch runs.
    const SWEEP_AT: &str = "2026-07-27T00:00:00Z";
    /// A much later tick of the same cron — the replay probe.
    const LATER_SWEEP_AT: &str = "2026-09-01T00:00:00Z";

    /// A deterministic, per-run attestation id. A UUIDv5 because postgres
    /// types the column as `uuid`; per-`tag` because the postgres arm runs
    /// against a SHARED database.
    fn row_id(tag: &str, label: &str) -> String {
        uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_OID,
            format!("ciris-persist/deletion_window/{tag}/{label}").as_bytes(),
        )
        .to_string()
    }

    fn producer_key(tag: &str) -> String {
        format!("dw-producer-{tag}")
    }
    fn subject_key(tag: &str) -> String {
        format!("dw-subject-{tag}")
    }

    /// A published (federation-tier) row, optionally committing a
    /// `deletion_window`. Signed LAST, over the final envelope, so the
    /// mandatory federation-tier ingest gate admits it.
    fn published(tag: &str, label: &str, window: Option<&str>) -> Attestation {
        let mut envelope = serde_json::json!({
            "dimension": "identity_binding:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        if let Some(w) = window {
            envelope.as_object_mut().expect("object").insert(
                super::super::envelope::paths::DELETION_WINDOW.into(),
                w.into(),
            );
        }
        row(
            tag,
            label,
            &producer_key(tag),
            attestation_type::SCORES,
            envelope,
            t(PUBLISHED_AT),
        )
    }

    /// A `withdraws` from `issuer` naming `target_id` — the structural
    /// retraction the sweep reads as (or, from a subject, does NOT read as)
    /// proof of deletion.
    fn withdraws(tag: &str, label: &str, issuer: &str, target_id: &str) -> Attestation {
        let envelope = serde_json::json!({
            "dimension": "identity_binding:v1",
            "score": 1.0,
            "confidence": 0.9,
            "references_attestation_id": target_id,
        });
        row(
            tag,
            label,
            issuer,
            attestation_type::WITHDRAWS,
            envelope,
            t(RETRACTED_AT),
        )
    }

    fn row(
        tag: &str,
        label: &str,
        attesting: &str,
        att_type: &str,
        envelope: serde_json::Value,
        at: DateTime<Utc>,
    ) -> Attestation {
        let (hash, classical, pqc) = ts::sign_envelope(attesting, &envelope);
        Attestation {
            attestation_id: row_id(tag, label),
            attesting_key_id: attesting.to_owned(),
            attested_key_id: subject_key(tag),
            attestation_type: att_type.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: attesting.to_owned(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject_key(tag)],
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    async fn publish(dir: &dyn FederationDirectory, row: Attestation) {
        let id = row.attestation_id.clone();
        dir.put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("put_attestation {id}: {e}"));
    }

    async fn breach_events(dir: &dyn FederationDirectory, kind: &str) -> Vec<HardCaseEvent> {
        dir.list_hard_case_events(HardCaseFilter {
            kind: Some(kind.to_owned()),
            since: None,
        })
        .await
        .expect("list_hard_case_events")
    }

    /// Events of `kind` naming one of THIS run's rows. The postgres arm shares
    /// a database with every other test, so a global count proves nothing;
    /// tag-scoping is what makes the assertion honest there.
    async fn mine(dir: &dyn FederationDirectory, kind: &str, tag: &str) -> Vec<HardCaseEvent> {
        let ids: Vec<String> = ["breached", "future", "deleted", "plain", "malformed"]
            .iter()
            .map(|l| row_id(tag, l))
            .collect();
        breach_events(dir, kind)
            .await
            .into_iter()
            .filter(|e| {
                e.target_key_id
                    .as_deref()
                    .is_some_and(|t| ids.iter().any(|i| i == t))
            })
            .collect()
    }

    /// **THE WITNESS.** Five published rows, two retractions, one sweep.
    ///
    /// `fresh` = this backend's database is this test's alone (memory /
    /// sqlite), so the report's absolute counts can be pinned; postgres shares
    /// a database and only the tag-scoped facts are its to assert.
    async fn exercise(dir: &dyn FederationDirectory, tag: &str, fresh: bool) {
        ts::register_hybrid_key(dir, &producer_key(tag)).await;
        ts::register_hybrid_key(dir, &subject_key(tag)).await;

        // The breach: published with a deletion window, the SUBJECT revoked,
        // the window passed, and the producer never deleted.
        publish(dir, published(tag, "breached", Some(PAST_WINDOW))).await;
        // Negative 1 — the window has not passed yet.
        publish(dir, published(tag, "future", Some(FUTURE_WINDOW))).await;
        // Negative 2 — window passed, but the PRODUCER retracted the row.
        publish(dir, published(tag, "deleted", Some(PAST_WINDOW))).await;
        // Negative 3 — no commitment at all; the lifecycle rule does not apply.
        publish(dir, published(tag, "plain", None)).await;
        // A producer defect: a deadline that enforces nothing.
        publish(dir, published(tag, "malformed", Some("whenever"))).await;

        // The subject's revocation is the DEMAND, not the proof — it must NOT
        // clear the breach (admission rule 2: subject named in subject_key_ids).
        publish(
            dir,
            withdraws(
                tag,
                "w-subject",
                &subject_key(tag),
                &row_id(tag, "breached"),
            ),
        )
        .await;
        // The producer's own retraction IS the proof (admission rule 1).
        publish(
            dir,
            withdraws(
                tag,
                "w-producer",
                &producer_key(tag),
                &row_id(tag, "deleted"),
            ),
        )
        .await;

        let now = t(SWEEP_AT);
        let report = run_deletion_window_watch(dir, now)
            .await
            .expect("watch runs");

        let breaches = mine(dir, kind::DELETION_WINDOW_BREACH, tag).await;
        assert_eq!(
            breaches.len(),
            1,
            "the network itself must raise ONE breach signal for the undeleted \
             row; got {breaches:#?} (report: {report:?})"
        );
        let ev = &breaches[0];
        assert_eq!(
            ev.target_key_id.as_deref(),
            Some(row_id(tag, "breached").as_str())
        );
        assert_eq!(
            ev.subject_key_id.as_deref(),
            Some(producer_key(tag).as_str()),
            "the breaching producer is named"
        );
        assert_eq!(ev.detail["deletion_window"], t(PAST_WINDOW).to_rfc3339());
        assert_eq!(ev.detail["producer_key_id"], producer_key(tag));
        assert_eq!(ev.detail["attestation_id"], row_id(tag, "breached"));
        assert_eq!(ev.detail["observed_at"], now.to_rfc3339());
        assert_eq!(ev.emitted_at, now);

        // The malformed window is flagged, under its own suffix.
        let malformed = mine(dir, kind::DELETION_WINDOW_MALFORMED, tag).await;
        assert_eq!(
            malformed.len(),
            1,
            "an unparseable erasure deadline is not silently ignored"
        );
        assert_eq!(
            malformed[0].target_key_id.as_deref(),
            Some(row_id(tag, "malformed").as_str())
        );

        // The negatives: no signal for a live window, a deleted row, or a row
        // that never committed one.
        for label in ["future", "deleted", "plain"] {
            let id = row_id(tag, label);
            assert!(
                !breaches
                    .iter()
                    .any(|e| e.target_key_id.as_deref() == Some(id.as_str())),
                "{label}: no breach signal is owed"
            );
            assert!(
                !malformed
                    .iter()
                    .any(|e| e.target_key_id.as_deref() == Some(id.as_str())),
                "{label}: no malformed signal is owed"
            );
        }

        if fresh {
            assert_eq!(
                report,
                DeletionWindowWatchReport {
                    rows_scanned: 7,
                    windows_seen: 4,
                    within_window: 1,
                    deleted_in_time: 1,
                    breaches: 1,
                    malformed: 1,
                    scan_truncated: false,
                },
                "the pass reports exactly what it saw"
            );
        } else {
            assert!(report.breaches >= 1 && report.malformed >= 1);
        }

        // ── replay idempotence ──
        // Same tick, then a MUCH later tick: one ongoing breach is one row of
        // evidence, not one per cron tick. `emitted_at` must stay the FIRST
        // observation — when the network raised the signal.
        let again = run_deletion_window_watch(dir, now).await.expect("replay");
        assert_eq!(again, report, "a replay re-detects, it does not re-write");
        let later = run_deletion_window_watch(dir, t(LATER_SWEEP_AT))
            .await
            .expect("later tick");
        assert_eq!(later.breaches, report.breaches);
        let after = mine(dir, kind::DELETION_WINDOW_BREACH, tag).await;
        assert_eq!(after.len(), 1, "no duplicate evidence after three passes");
        assert_eq!(
            after[0].emitted_at, now,
            "the recorded instant is when the breach was FIRST observed"
        );
    }

    /// Seed ONE undeleted, past-window row and return `(its id, the instant to
    /// sweep at)`. Shared with the Engine-handle test in `engine.rs` so the
    /// host-reachability witness drives the same fixture this module proves,
    /// rather than a lookalike that could drift from it.
    ///
    /// Gated on the feature of its ONE caller: an `Engine` exists only on a
    /// backend build, and a memory-only build would see this as dead code
    /// (`-D warnings` — the build CI also runs).
    #[cfg(feature = "sqlite")]
    pub(crate) async fn seed_one_breach(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) -> (String, DateTime<Utc>) {
        ts::register_hybrid_key(dir, &producer_key(tag)).await;
        ts::register_hybrid_key(dir, &subject_key(tag)).await;
        publish(dir, published(tag, "breached", Some(PAST_WINDOW))).await;
        (row_id(tag, "breached"), t(SWEEP_AT))
    }

    #[tokio::test]
    async fn deletion_window_breach_witness_memory() {
        let dir = crate::store::MemoryBackend::new();
        exercise(&dir, "mem", true).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn deletion_window_breach_witness_sqlite() {
        let dir = crate::store::SqliteBackend::open_in_memory().await.unwrap();
        dir.run_migrations().await.unwrap();
        exercise(&dir, "sq", true).await;
    }

    /// Skips cleanly when `CIRIS_PERSIST_TEST_PG_URL` is unset — the same gate
    /// every other pg test in the tree uses.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn deletion_window_breach_witness_postgres() {
        let Some(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let dir = crate::store::PostgresBackend::connect(&dsn)
            .await
            .expect("connect postgres");
        dir.run_migrations().await.expect("migrations");
        // A per-process tag: the database is shared and long-lived.
        let tag = format!("pg{:x}", std::process::id());
        exercise(&dir, &tag, false).await;
    }
}
