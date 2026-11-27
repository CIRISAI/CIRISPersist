//! v62.0.0 (SL-fix2; CC 4.4.3.12, CC 3.4.7) — **in an affiliation with ONE
//! deciding seat, a `slash` act counts only countersigned by a key outside
//! that seat**, for both `slash` families (`quarantine:{state}`,
//! `slashing:{outcome}`). sqlite and postgres, through the statement door, in
//! both arrival orders.
//!
//! CC 4.4.3.12: *"Where the body has one deciding seat, an act against a
//! member (`membership:removal`, quarantine, slash, a takedown of the member's
//! content) counts as a decision only when countersigned by a key outside the
//! deciding seat."* CC's family cell makes such a row COUNTED
//! (`group=affiliations & seats=one => counted ; authored`): it carries no
//! author, and each signer is one voice over it. The countersign is
//! `affiliation_config::check_one_voice_countersign`, the door
//! `membership:removal` already asks (I1513); the deciding seats are
//! `affiliation_config::deciding_seats` (the active founders, or the members
//! where none is named), which the door's authorship context now counts too.
//!
//! The room: a sole practitioner's affiliation `solo` (one founder `f`, a
//! designated official `official`, members `m` and `n`).
//!
//! - **I4130** — slashing, the seat first: `f`'s voice alone is kept
//!   `Pending` (held `count_short`, no typed row); the official's voice lands
//!   it.
//! - **I4131** — slashing, the countersign first: the official's voice alone
//!   is held (`delegated_scope_unauthorized`: it holds no `slash`); `f`'s
//!   voice lands it.
//! - **I4132** — quarantine, the seat first: as I4130.
//! - **I4133** — quarantine, the countersign first: as I4131.
//! - **I4134** — a member who is not a designated official is not "outside
//!   the seat" for the floor: `f` + `n` stays held.
//! - **I4135** — never a plain community, never two seats: in an affiliation
//!   of two founders (`pair`), `f`'s authored verdict lands alone.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::affiliation_floor_invariants::bodies::{affiliation, seat};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::names::RowId;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_room_with_blob, id_of, reg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, Attestation};
    use crate::federation::FederationDirectory;
    use chrono::{DateTime, Duration, Utc};

    /// A federation-scope `scores` row by `by` about `subject` carrying
    /// `envelope`, at `at`, with `subject_key_ids`: the earlier-form shape the
    /// codec signs.
    fn base(
        by: &str,
        subject: &str,
        envelope: &serde_json::Value,
        subjects: Vec<String>,
        at: DateTime<Utc>,
    ) -> Attestation {
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, subject, envelope);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = cohort_scope::FEDERATION.into();
        r.subject_key_ids = subjects;
        r.asserted_at = at;
        r
    }

    /// The producer's verdict shape (`cirisnode::rows::plan_slashing_row`):
    /// attested to and naming the accused, in `room`.
    fn verdict(by: &str, accused: &str, room: &str, at: DateTime<Utc>) -> Attestation {
        let env = serde_json::json!({
            "dimension": "slashing:proven_rogue:v1",
            "score": 1.0,
            "confidence": 1.0,
            "community_id": room,
            "payload": {},
        });
        base(by, accused, &env, vec![accused.to_owned()], at)
    }

    /// A `quarantine:withheld:v1` marker against `subject` in `room`.
    fn marker(by: &str, subject: &str, room: &str, at: DateTime<Utc>) -> Attestation {
        let env = crate::federation::quarantine::withhold_envelope(
            subject,
            room,
            &format!("sl2-deleg-{}", uuid::Uuid::new_v4().simple()),
            "spam",
        );
        base(by, subject, &env, Vec::new(), at)
    }

    /// The counted statement of `row` signed by `seed`, and the further
    /// voice of `other` over the same payload.
    fn voices(row: &Attestation, seed: &str, other: &str) -> (Vec<u8>, Vec<u8>, RowId) {
        let st = e2::counted_statement_of(row, seed);
        let voice = e2::voice_of(&st, other);
        let rid = RowId::of_statement(&st).expect("a row statement");
        (st, voice, rid)
    }

    async fn put(d: &dyn FederationDirectory, st: &[u8], what: &str) -> StatementOutcome {
        e2::put_statement(d, st)
            .await
            .unwrap_or_else(|e| panic!("{what}: a voice is kept or lands, never refused: {e}"))
    }

    async fn held_with(d: &dyn FederationDirectory, rid: &RowId, reason: &str, what: &str) {
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_none(),
            "{what}: no typed row"
        );
        let why = fold::why_held(d, rid)
            .await
            .expect("read the hold")
            .unwrap_or_else(|| panic!("{what}: held"));
        assert_eq!(why.reason, reason, "{what}: {why:?}");
    }

    async fn lands(d: &dyn FederationDirectory, out: StatementOutcome, rid: &RowId, what: &str) {
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{what}: lands: {out:?}"
        );
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_some(),
            "{what}: a typed row"
        );
    }

    /// One family, both orders: `make(by, at)` builds the act.
    async fn both_orders(
        d: &dyn FederationDirectory,
        make: &dyn Fn(&str, DateTime<Utc>) -> Attestation,
        f: &str,
        official: &str,
        at: DateTime<Utc>,
        seat_first: &str,
        countersign_first: &str,
    ) {
        // The seat first.
        let (st, voice, rid) = voices(&make(f, at), f, official);
        let out = put(d, &st, seat_first).await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "{seat_first}: the one seat alone is kept short: {out:?}"
        );
        held_with(d, &rid, fold::reason::COUNT_SHORT, seat_first).await;
        let out = put(d, &voice, seat_first).await;
        lands(d, out, &rid, seat_first).await;

        // The countersign first.
        let (st, voice, rid) = voices(&make(f, at + Duration::minutes(1)), f, official);
        let out = put(d, &voice, countersign_first).await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "{countersign_first}: the official's voice alone is held: {out:?}"
        );
        held_with(
            d,
            &rid,
            fold::reason::gc1::DELEGATED_SCOPE_UNAUTHORIZED,
            countersign_first,
        )
        .await;
        let out = put(d, &st, countersign_first).await;
        lands(d, out, &rid, countersign_first).await;
    }

    pub(crate) async fn i4130_one_seat_slash_acts_need_a_countersign(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i4130-{n}-{s}");
        let (f, g, official, m, n, solo, pair) = (
            k("f"),
            k("g"),
            k("official"),
            k("m"),
            k("n"),
            k("solo"),
            k("pair"),
        );
        reg(d, &[&f, &g, &official, &m, &n, &solo, &pair]).await;
        let (f, g, official, m, n, solo, pair) = (
            id_of(&f),
            id_of(&g),
            id_of(&official),
            id_of(&m),
            id_of(&n),
            id_of(&solo),
            id_of(&pair),
        );
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let solo = found_room_with_blob(
            d,
            &solo,
            "founder_only",
            &[&f],
            &[],
            Some(affiliation(Some(&official))),
        )
        .await
        .expect("I4130: a sole practitioner's affiliation");
        let at = Utc::now() - Duration::hours(2);
        seat(d, &solo, &f, &m, at).await;
        seat(d, &solo, &f, &n, at + Duration::minutes(1)).await;
        let acts = at + Duration::minutes(10);

        // ── I4130 / I4131: slashing.
        let slashing = |by: &str, t: DateTime<Utc>| verdict(by, &m, &solo, t);
        both_orders(d, &slashing, &f, &official, acts, "I4130", "I4131").await;

        // ── I4132 / I4133: quarantine.
        let quarantine = |by: &str, t: DateTime<Utc>| marker(by, &m, &solo, t);
        both_orders(
            d,
            &quarantine,
            &f,
            &official,
            acts + Duration::minutes(5),
            "I4132",
            "I4133",
        )
        .await;

        // ── I4134: a plain member is not outside the seat for the floor.
        let (st, by_member, rid) = voices(&slashing(&f, acts + Duration::minutes(20)), &f, &n);
        put(d, &st, "I4134").await;
        let out = put(d, &by_member, "I4134").await;
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I4134: the seat and a non-official member stay short: {out:?}"
        );
        held_with(d, &rid, fold::reason::COUNT_SHORT, "I4134").await;

        // ── I4135: two deciding seats decide under their own protocol.
        found_room_with_blob(
            d,
            &pair,
            "founder_only",
            &[&f, &g],
            &[],
            Some(affiliation(None)),
        )
        .await
        .expect("I4135: a two-seat affiliation");
        let alone = e2::row_of(&verdict(&f, &m, &pair, acts), &f);
        let out = e2::put_signed(d, &alone)
            .await
            .expect("I4135: a two-seat affiliation's verdict");
        let rid = crate::federation::edition2::voices::carried_row_id(&alone).expect("a row");
        lands(d, out, &rid, "I4135: one founder of two acts alone").await;
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4130_one_seat_slash_acts_need_a_countersign_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4130_one_seat_slash_acts_need_a_countersign(
            &b,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4130_one_seat_slash_acts_need_a_countersign_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4130_one_seat_slash_acts_need_a_countersign(
            &b,
            &suffix(),
        ))
        .await;
        eprintln!("i4130 postgres: RAN");
    }
}
