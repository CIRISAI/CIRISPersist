//! v62.0.0 (SL-fix1; CC 3.4.7, CC 4.5.5; CIRISConstitution divergences
//! C447 / C458) — **a `slashing:{outcome}` verdict counts only from a holder
//! of the `slash` duty in its community, at its own signed instant.** sqlite
//! and postgres, through the statement door, in both arrival orders.
//!
//! CC 3.4.7: *"`slashing:{outcome}`, `quarantine:{state}` | the holder of the
//! slashing duty | `slash` | the community's authority set |
//! `federation_delegated_scope_unauthorized`"*, and *"A row in it counts only
//! when its signer holds that duty at the row's signed instant."* Before
//! v62.0.0 the duty gate (`admission::check_delegated_duty_scores_admission`)
//! had no `slashing:` arm and any registered key's verdict landed.
//!
//! The verdicts carry the producer's shape (`cirisnode::rows::plan_slashing_row`):
//! a federation-scope `scores` row naming the accused as `attested_key_id` and
//! subject, the moderation event it adjudicates by `references_attestation_id`,
//! and the event's `community_id`.
//!
//! - **I4120** — the room's founder (a holder of every duty in its room) signs:
//!   the verdict lands.
//! - **I4121** — a registered plain member signs: HELD (`Pending`, GC1
//!   `delegated_scope_unauthorized`), no typed row.
//! - **I4122** — row first, seat second: a member's held verdict re-folds and
//!   lands when the founder's `delegates_to(slash)` onto it lands afterwards,
//!   dated so the seat covers the verdict's instant.
//! - **I4123** — row first, seat second, the seat dated AFTER the verdict's
//!   instant: the verdict stays held, with the same reason.
//! - **I4124** — seat first: a deputy on a live slash-scoped chain
//!   (founder → d1 with `sub_delegation` → d2) signs: the verdict lands.
//! - **I4125** — a holder of ANOTHER duty (`moderate` only) signs: held.
//!
//! Every seat edge NAMES the room (`community_id`): since CW-fix1 a room's
//! duty walk follows only edges naming that room (an unscoped duty edge
//! confers no room duty), so I4122–I4125's seats are room appointments.
//! - **I4126** — a verdict naming no `community_id` is refused
//!   `slashing_community_required` and nothing is kept: it never falls through
//!   to the accord resolver (the quarantine arm's alone) or to "any registered
//!   key".

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::{
        DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_SLASH, SLASHING_COMMUNITY_REQUIRED,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::voices::carried_row_id;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, Attestation};
    use crate::federation::FederationDirectory;
    use chrono::{DateTime, Duration, Utc};

    /// A federation-scope `scores` row by `by` under `dimension`, attested to
    /// and naming as subject `accused`, at `at`, carrying `members`: an
    /// edition-2 row (its id the row id the statement names).
    fn scores(
        by: &str,
        accused: &str,
        dimension: &str,
        score: f64,
        mut members: serde_json::Value,
        at: DateTime<Utc>,
    ) -> Attestation {
        members["dimension"] = serde_json::json!(dimension);
        members["score"] = serde_json::json!(score);
        members["confidence"] = serde_json::json!(1.0);
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, accused, &members);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::FEDERATION.into();
        r.subject_key_ids = vec![accused.to_owned()];
        r.asserted_at = at;
        e2::row_of(&r, by)
    }

    /// `granter`'s `delegates_to(granter → grantee)` bearing `scope` (and
    /// `sub_delegation` when `sub`), NAMING `room`, asserted at `at` with a
    /// test term from it, landed with the grantee's voice (a seat is two
    /// consents).
    async fn seat(
        d: &dyn FederationDirectory,
        room: &str,
        granter: &str,
        grantee: &str,
        scope: &[&str],
        sub: bool,
        at: DateTime<Utc>,
    ) {
        // v62.0.0 (CW-fix1, SL-fix4) — a duty edge confers in a room only
        // when it NAMES the room (`community_id`): an unscoped edge confers
        // no room duty (CW-fix1's ruling, the cross-room leak closed).
        let mut envelope = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "scope": scope,
            "community_id": room,
        });
        if sub {
            envelope["sub_delegation"] = serde_json::json!(true);
        }
        crate::federation::admission::with_test_term(&mut envelope, at);
        let mut row = ts::bare_attestation("", granter, grantee, &envelope);
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        row.asserted_at = at;
        ts::seal_row_in_place(granter, &mut row);
        let (out, _unvoiced) = e2::land_delegation(d, &row)
            .await
            .unwrap_or_else(|e| panic!("the {scope:?} seat {granter} → {grantee}: {e}"));
        assert!(
            !matches!(out, StatementOutcome::Pending { .. }),
            "the {scope:?} seat {granter} → {grantee} lands with its voices: {out:?}"
        );
    }

    async fn landed(d: &dyn FederationDirectory, row: &Attestation) -> bool {
        let rid = carried_row_id(row).expect("an edition-2 row");
        d.get_attestation(&rid.hex()).await.unwrap().is_some()
    }

    /// `row` is held by the duty gate: no typed row, and the fold names the
    /// GC1 reason.
    async fn held_unseated(d: &dyn FederationDirectory, row: &Attestation, what: &str) {
        let rid = carried_row_id(row).expect("an edition-2 row");
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_none(),
            "{what}: no typed row"
        );
        let why = fold::why_held(d, &rid)
            .await
            .expect("read the hold")
            .unwrap_or_else(|| panic!("{what}: held"));
        assert_eq!(
            why.reason,
            fold::reason::gc1::DELEGATED_SCOPE_UNAUTHORIZED,
            "{what}: {why:?}"
        );
    }

    pub(crate) async fn i4120_slashing_needs_the_slash_duty(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::room_roster_authority_invariants::bodies::make_group;
        let tag = format!("i4120-{s}");
        let (room, keys) = make_group(
            d,
            &tag,
            crate::federation::types::consensus_protocol::MAJORITY,
            &["f", "accused", "plain", "early", "late", "d1", "d2", "modr"],
            1,
            None,
            None,
        )
        .await;
        let (founder, accused, plain, early, late, d1, d2, modr) = (
            &keys[0], &keys[1], &keys[2], &keys[3], &keys[4], &keys[5], &keys[6], &keys[7],
        );
        let now = Utc::now();
        let hours = Duration::hours;

        // The moderation event the verdicts adjudicate, filed by the founder.
        let event = scores(
            founder,
            accused,
            "moderation:rogue_vote:v1",
            -1.0,
            serde_json::json!({ "community_id": room, "payload": {} }),
            now - hours(8),
        );
        let out = e2::put_signed(d, &event)
            .await
            .expect("I4120: the founder's moderation event");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I4120: the moderation event lands: {out:?}"
        );
        let verdict = |by: &str, at: DateTime<Utc>| {
            scores(
                by,
                accused,
                "slashing:proven_rogue:v1",
                1.0,
                serde_json::json!({
                    "community_id": room,
                    "references_attestation_id": event.attestation_id,
                    "payload": {},
                }),
                at,
            )
        };
        let put = |row: Attestation| async move {
            e2::put_signed(d, &row)
                .await
                .unwrap_or_else(|e| panic!("a verdict is kept or lands, never refused: {e}"))
        };

        // ── I4120: the founder holds `slash` in its room.
        let by_founder = verdict(founder, now - hours(7));
        let out = put(by_founder.clone()).await;
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I4120: the founder's verdict lands: {out:?}"
        );
        assert!(landed(d, &by_founder).await, "I4120: a typed row");

        // ── I4121: a registered plain member holds no duty.
        let by_plain = verdict(plain, now - hours(7));
        let out = put(by_plain.clone()).await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4121: a plain member's verdict is held: {out:?}"
        );
        held_unseated(d, &by_plain, "I4121").await;

        // ── I4122: row first; the seat lands after it, dated to cover it.
        let by_early = verdict(early, now - hours(3));
        let out = put(by_early.clone()).await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4122: held before the seat: {out:?}"
        );
        held_unseated(d, &by_early, "I4122 (before the seat)").await;
        seat(
            d,
            &room,
            founder,
            early,
            &[DELEGATION_SCOPE_SLASH],
            false,
            now - hours(4),
        )
        .await;
        assert!(
            landed(d, &by_early).await,
            "I4122: the seat covering the verdict's instant re-folds it, and it lands"
        );

        // ── I4123: row first; the seat lands after it, dated AFTER it.
        let by_late = verdict(late, now - hours(3));
        let out = put(by_late.clone()).await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4123: held before the seat: {out:?}"
        );
        seat(
            d,
            &room,
            founder,
            late,
            &[DELEGATION_SCOPE_SLASH],
            false,
            now - hours(2),
        )
        .await;
        held_unseated(
            d,
            &by_late,
            "I4123: a seat that begins after the verdict's instant does not cover it",
        )
        .await;

        // ── I4124: seat first; a deputy on a live slash-scoped chain.
        seat(
            d,
            &room,
            founder,
            d1,
            &[DELEGATION_SCOPE_SLASH],
            true,
            now - hours(4),
        )
        .await;
        seat(
            d,
            &room,
            d1,
            d2,
            &[DELEGATION_SCOPE_SLASH],
            false,
            now - hours(4),
        )
        .await;
        let by_deputy = verdict(d2, now - hours(1));
        let out = put(by_deputy.clone()).await;
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I4124: the deputy's verdict lands: {out:?}"
        );
        assert!(landed(d, &by_deputy).await, "I4124: a typed row");

        // ── I4125: a holder of another duty (`moderate` only).
        seat(
            d,
            &room,
            founder,
            modr,
            &[DELEGATION_SCOPE_MODERATE],
            false,
            now - hours(4),
        )
        .await;
        let by_moderator = verdict(modr, now - hours(1));
        let out = put(by_moderator.clone()).await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4125: a moderate-only holder's verdict is held: {out:?}"
        );
        held_unseated(d, &by_moderator, "I4125").await;

        // ── I4126: a verdict in no community's name, by the founder.
        let nameless = scores(
            founder,
            accused,
            "slashing:proven_rogue:v1",
            1.0,
            serde_json::json!({
                "references_attestation_id": event.attestation_id,
                "payload": {},
            }),
            now - hours(1),
        );
        let e = e2::put_signed(d, &nameless)
            .await
            .expect_err("I4126: a verdict naming no community is refused");
        assert!(
            e.to_string().contains(SLASHING_COMMUNITY_REQUIRED),
            "I4126: refused by name: {e}"
        );
        let rid = carried_row_id(&nameless).expect("an edition-2 row");
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_none(),
            "I4126: no typed row"
        );
        assert!(
            fold::why_held(d, &rid).await.unwrap().is_none(),
            "I4126: refused, not held"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4120_slashing_needs_the_slash_duty_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4120_slashing_needs_the_slash_duty(
            &b,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4120_slashing_needs_the_slash_duty_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4120_slashing_needs_the_slash_duty(
            &b,
            &suffix(),
        ))
        .await;
        eprintln!("i4120 postgres: RAN");
    }
}
