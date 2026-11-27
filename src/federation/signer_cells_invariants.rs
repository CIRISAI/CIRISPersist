//! v62.0.0 (FS-sig-a; CIRISConstitution v1.0-rc22-pre3 `family_model.json`
//! signer cells, where the text's rule and persist's code differed) — **four
//! signer cells, each through the statement door, sqlite and postgres.**
//!
//! - **I5704** — `attestation:self_verify` (CC 3.1.2.1, "the running node
//!   about itself"): a key's row about itself lands; a row about another key
//!   is REFUSED `self_signed_family_names_another_party` and nothing is kept.
//! - **I5705** — `hardware_custody:{platform}` (CC 3.4.5, "a statement about
//!   the emitter itself"): the same two legs.
//! - **I5706** — `age_self_declared:band:*` (CC 3.4.11, "admitted only where
//!   the signer acts for the subject"): the subject's own row lands; its
//!   device's row about it lands (an admitted occurrence of the subject);
//!   the person's row about its device and a stranger's row about the person
//!   are HELD `signer_not_acting_for`, no typed row.
//! - **I5707** — `watchlist:{id}` (CC 3.1.9.4, "a `moderate`- or
//!   `takedown`-scope holder enables a watchlist `{id}` for a group they
//!   moderate"): the founder's row lands; a plain member's is HELD
//!   `delegated_scope_unauthorized`; a `takedown`-only deputy's lands; a
//!   `review`-only deputy's is held; a row naming no group is held.
//!
//! None of the four reads a trust root or an owner binding: a rootless or an
//! unowned node decides them the same (the self cells read the row and the
//! occurrence fold; the watchlist reads the group's own authority set).

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::{
        DELEGATION_SCOPE_REVIEW, DELEGATION_SCOPE_TAKEDOWN,
        SELF_SIGNED_FAMILY_NAMES_ANOTHER_PARTY_REASON,
    };
    use crate::federation::edition2::fixture_occurrence::{put_bind, BindOptions};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::voices::carried_row_id;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type as it;
    use crate::federation::types::{attestation_type, cohort_scope, device_class, Attestation};
    use crate::federation::FederationDirectory;
    use chrono::{DateTime, Duration, Utc};

    /// A `scores` row by the key of seed `by` about `about` under
    /// `dimension`, placed at `scope`, carrying `members`: an edition-2 row.
    fn scores(
        by: &str,
        about: &str,
        dimension: &str,
        scope: &str,
        mut members: serde_json::Value,
        at: DateTime<Utc>,
    ) -> Attestation {
        members["dimension"] = serde_json::json!(dimension);
        members["score"] = serde_json::json!(1.0);
        members["confidence"] = serde_json::json!(1.0);
        let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, about, &members);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = scope.into();
        r.asserted_at = at;
        e2::row_of(&r, by)
    }

    async fn landed(d: &dyn FederationDirectory, row: &Attestation) -> bool {
        let rid = carried_row_id(row).expect("an edition-2 row");
        d.get_attestation(&rid.hex()).await.unwrap().is_some()
    }

    /// `row` lands through the statement door.
    async fn lands(d: &dyn FederationDirectory, row: &Attestation, what: &str) {
        let out = e2::put_signed(d, row)
            .await
            .unwrap_or_else(|e| panic!("{what}: lands, not refused: {e}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "{what}: lands: {out:?}"
        );
        assert!(landed(d, row).await, "{what}: a typed row");
    }

    /// `row` is HELD under `reason`: kept, no typed row.
    async fn held(d: &dyn FederationDirectory, row: &Attestation, reason: &str, what: &str) {
        e2::put_signed(d, row)
            .await
            .unwrap_or_else(|e| panic!("{what}: held, not refused: {e}"));
        let rid = carried_row_id(row).expect("an edition-2 row");
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_none(),
            "{what}: no typed row"
        );
        let why = fold::why_held(d, &rid)
            .await
            .expect("read the hold")
            .unwrap_or_else(|| panic!("{what}: held"));
        assert_eq!(why.reason, reason, "{what}: {why:?}");
    }

    /// `row` is REFUSED naming `needle`: no typed row and no hold.
    async fn refused(d: &dyn FederationDirectory, row: &Attestation, needle: &str, what: &str) {
        let e = e2::put_signed(d, row)
            .await
            .expect_err(&format!("{what}: refused"));
        assert!(
            e.to_string().contains(needle),
            "{what}: refused by name: {e}"
        );
        let rid = carried_row_id(row).expect("an edition-2 row");
        assert!(
            d.get_attestation(&rid.hex()).await.unwrap().is_none(),
            "{what}: no typed row"
        );
        assert!(
            fold::why_held(d, &rid).await.unwrap().is_none(),
            "{what}: refused, not held"
        );
    }

    /// The two legs of a `self` cell over `dimension`.
    async fn self_cell(d: &dyn FederationDirectory, tag: &str, dimension: &str, what: &str) {
        let node = format!("{what}-node-{tag}");
        let other = format!("{what}-other-{tag}");
        e2::put_key(d, &node, &[it::AGENT]).await;
        e2::put_key(d, &other, &[it::AGENT]).await;
        let now = Utc::now();
        let own = scores(
            &node,
            &node,
            dimension,
            cohort_scope::SELF,
            serde_json::json!({}),
            now - Duration::minutes(2),
        );
        lands(d, &own, &format!("{what}: a key's row about itself")).await;
        let about_other = scores(
            &node,
            &other,
            dimension,
            cohort_scope::SELF,
            serde_json::json!({}),
            now - Duration::minutes(1),
        );
        refused(
            d,
            &about_other,
            SELF_SIGNED_FAMILY_NAMES_ANOTHER_PARTY_REASON,
            &format!("{what}: a key's row about another key"),
        )
        .await;
    }

    pub(crate) async fn i5704_self_verify_is_about_its_signer(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        self_cell(d, s, "attestation:self_verify", "I5704").await;
    }

    pub(crate) async fn i5705_hardware_custody_is_about_its_signer(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        self_cell(d, s, "hardware_custody:tpm_discrete:v1", "I5705").await;
    }

    /// An age row (the self rung, `token`) by `by` about `about`, sealed.
    fn age_row(by: &str, about: &str, token: &str, at: DateTime<Utc>) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut a = ts::bare_attestation(&id, by, about, &serde_json::json!({ "id": id }));
        a.attestation_type = token.to_owned();
        a.asserted_at = at;
        a.scrub_timestamp = at;
        ts::seal_row_in_place(by, &mut a);
        a
    }

    pub(crate) async fn i5706_age_self_declared_is_by_the_subject_or_its_occurrence(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let person = format!("i5706-person-{s}");
        let device = format!("i5706-device-{s}");
        let stranger = format!("i5706-stranger-{s}");
        for k in [&person, &device, &stranger] {
            ts::register_identity_key(d, k, it::USER).await;
        }
        put_bind(
            d,
            &person,
            &person,
            &device,
            device_class::LAPTOP,
            &BindOptions::default(),
        )
        .await
        .expect("I5706: the person binds its device");
        assert_eq!(
            d.active_identity_for_occurrence(&e2::kid_or_keep(&device))
                .await
                .expect("the device resolves"),
            e2::kid_or_keep(&person),
            "I5706 premise: the device is an occurrence of the person"
        );
        let now = Utc::now();
        let token = "age_self_declared:band:adult:v1";
        let own = age_row(&person, &person, token, now - Duration::minutes(4));
        lands(d, &own, "I5706: the subject's own declaration").await;
        let by_device = age_row(&device, &person, token, now - Duration::minutes(3));
        lands(d, &by_device, "I5706: its device declares for its person").await;
        held(
            d,
            &age_row(&person, &device, token, now - Duration::minutes(2)),
            fold::reason::SIGNER_NOT_ACTING_FOR,
            "I5706: a person does not declare for its device",
        )
        .await;
        held(
            d,
            &age_row(&stranger, &person, token, now - Duration::minutes(1)),
            fold::reason::SIGNER_NOT_ACTING_FOR,
            "I5706: a stranger does not declare for the person",
        )
        .await;
    }

    /// `granter`'s `delegates_to(granter → grantee)` bearing `scope`, naming
    /// `room`, asserted at `at`, landed with the grantee's voice.
    async fn seat(
        d: &dyn FederationDirectory,
        room: &str,
        granter: &str,
        grantee: &str,
        scope: &[&str],
        at: DateTime<Utc>,
    ) {
        let mut envelope = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "scope": scope,
            "community_id": room,
        });
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

    pub(crate) async fn i5707_watchlist_needs_moderate_or_takedown(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::room_roster_authority_invariants::bodies::make_group;
        let tag = format!("i5707-{s}");
        let (room, keys) = make_group(
            d,
            &tag,
            crate::federation::types::consensus_protocol::MAJORITY,
            &["f", "plain", "tk", "rv"],
            1,
            None,
            None,
        )
        .await;
        let (founder, plain, tk, rv) = (&keys[0], &keys[1], &keys[2], &keys[3]);
        let now = Utc::now();
        let hours = Duration::hours;
        let dimension = format!("watchlist:i5707_{s}:v1");
        let config = |by: &str, group: Option<&str>, at: DateTime<Utc>| {
            let members = match group {
                Some(g) => serde_json::json!({ "community_id": g }),
                None => serde_json::json!({}),
            };
            scores(by, by, &dimension, cohort_scope::FEDERATION, members, at)
        };
        let unseated = fold::reason::gc1::DELEGATED_SCOPE_UNAUTHORIZED;

        lands(
            d,
            &config(founder, Some(&room), now - hours(6)),
            "I5707: the founder (every duty in its room)",
        )
        .await;
        held(
            d,
            &config(plain, Some(&room), now - hours(5)),
            unseated,
            "I5707: a plain member holds neither duty",
        )
        .await;
        seat(
            d,
            &room,
            founder,
            tk,
            &[DELEGATION_SCOPE_TAKEDOWN],
            now - hours(9),
        )
        .await;
        lands(
            d,
            &config(tk, Some(&room), now - hours(4)),
            "I5707: a takedown-only deputy",
        )
        .await;
        seat(
            d,
            &room,
            founder,
            rv,
            &[DELEGATION_SCOPE_REVIEW],
            now - hours(9),
        )
        .await;
        held(
            d,
            &config(rv, Some(&room), now - hours(3)),
            unseated,
            "I5707: a review-only deputy",
        )
        .await;
        held(
            d,
            &config(founder, None, now - hours(2)),
            unseated,
            "I5707: a watchlist naming no group (never global)",
        )
        .await;
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! on_every_backend {
        ($name:ident) => {
            mod $name {
                #[cfg(feature = "sqlite")]
                #[tokio::test]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    Box::pin(super::super::bodies::$name(&b, &super::suffix())).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    Box::pin(super::super::bodies::$name(&b, &super::suffix())).await;
                    eprintln!("{} postgres: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i5704_self_verify_is_about_its_signer);
    on_every_backend!(i5705_hardware_custody_is_about_its_signer);
    on_every_backend!(i5706_age_self_declared_is_by_the_subject_or_its_occurrence);
    on_every_backend!(i5707_watchlist_needs_moderate_or_takedown);
}
