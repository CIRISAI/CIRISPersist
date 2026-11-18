//! v60.0.0 (CIRISPersist#934 step 4, CIRISPersist#1105) — **I1192–I1201:
//! the consent doors, the consent reads and the sweeps decide in ONE
//! function each, and every backend executes that function's verdict.**
//!
//! Each backend body runs on memory, sqlite and postgres (the room leg on
//! sqlite and postgres: memory has no blob plane), so a mutation of a shared
//! plan or selection is red on every backend, and a mutation of one
//! backend's executor is red on that backend.
//!
//! - **I1192 (the consent-role door)** — a recognized token is stored and
//!   read back; the `'unregistered'` default is the wire `None`; an
//!   unrecognized token is `InvalidArgument` and the held role does not
//!   move; a key with no row is `InvalidArgument` naming the missing row.
//! - **I1193 (the trust-grant door)** — a granter-signed grant lands with
//!   `trusted_at` the door's own clock; a grant whose signature does not
//!   verify is refused before its shape is read; self-trust, a `Registry`
//!   grant without domains, a `Direct` grant with domains are
//!   `InvalidArgument`; a grant for a key never put is refused naming the
//!   missing row; the held row does not move on any refusal.
//! - **I1194 (the consent-peer and live-grant folds)** — the peers of a node
//!   are sorted and deduplicated whatever order the projection holds them
//!   in; `(author, peer)` pairs for a machine likewise; the live grants come
//!   newest first, ties by id descending, for both keys of the read.
//! - **I1195 (the consent-revocation fold)** — a `consent:state:revoked`
//!   stance is a revocation and a producer's own `withdraws` (rule 1) is
//!   not; newest first; `since` bounds the scan.
//! - **I1196** — retired in v62 with the PQC cold path (a composite is atomic).
//! - **I1197 (the reaper's selection)** — the never-offered types are never
//!   offered; ids come oldest expiry first, ties by id; walking the pages by
//!   OFFSET yields every row exactly once; an empty page reads nothing.
//! - **I1198 (the known-hash eviction)** — only entries not advertised since
//!   the cutoff go; the report counts them, the remainder, and the overage
//!   over the bound (reported, never evicted).
//! - **I1199 (the room leg's selection, unit + sqlite / postgres)** — the
//!   predicate's every clause, and the executor that runs it in one
//!   transaction: chunks of a terminated room epoch at or below the bound go
//!   and the epoch is stamped; an open epoch, one above the bound, a
//!   self-scope epoch and an already-evicted one are kept.
//! - **I1200 (the observation prune plan, unit)** — an empty batch plans
//!   nothing; `transport_destinations` carries its keep predicate on both
//!   dialects and postgres re-checks the age in the outer DELETE.
//! - v62.0.0 (JSON cut, E7): I1193 (the signed JSON trust-grant door; a
//!   trust grant is a `delegates_to` row, RULINGS) and I1201 (the earlier key
//!   plane's `key:record:v1` attestation rows; an edition-2 key lives in
//!   `ceg_statements`) are deleted.
//! - **I1201 (the #1105 family-scoped holdings read)** — the page for a
//!   key-plane family is exactly the `Attestation` hashes whose rows are
//!   that family's `scores` rows, in hash order; paging on the hash
//!   reconstructs it; a non-key-plane dimension is refused, never answered
//!   empty.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::consent_sweep_principals_invariants::bodies::{
        grant, put, row, withdraws,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{consent_role, identity_type::NODE};
    use crate::federation::{Attestation, Error, FederationDirectory};

    /// v62.0.0 (JSON cut, E7) — a dimension Verify's family matcher
    /// registers (the fixtures' `x:v1` is not; an edition-2 row of it is
    /// refused at the door).
    const DIMENSION: &str = "evidence:safety_battery:capture:a:b:v1";

    /// `owner` binds `node`: the owner's row, then the node's own statement
    /// over it (RULINGS C557).
    async fn bind_owner(d: &dyn FederationDirectory, owner: &str, node: &str) {
        // The builder dates its binding 2026-05-01; the node's voice is a
        // node-key row, which must be now-relative (CC 2.4.1.1): re-date and
        // re-seal the binding before the voice is taken.
        let mut ob = ts::owner_binding_attestation("", &e2::seed_of(owner), &e2::seed_of(node));
        let at = crate::federation::admission::truncate_to_substrate_resolution(
            Utc::now() - Duration::days(1),
        );
        ob.asserted_at = at;
        ob.scrub_timestamp = at;
        ob.attestation_envelope[crate::federation::envelope::paths::ASSERTED_AT] =
            serde_json::Value::String(crate::federation::admission::render_signed_instant(at));
        ts::reseal(&mut ob);
        put(d, ob.clone()).await;
        let voice = e2::voice_of(
            &e2::carried_statement(&ob).expect("the binding carries its statement"),
            node,
        );
        e2::put_statement(d, &voice)
            .await
            .expect("the node's voice on its owner binding");
    }
    use chrono::{DateTime, Duration, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        "2026-09-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap() + Duration::seconds(secs)
    }

    fn invalid(r: Result<(), Error>, what: &str) -> String {
        match r {
            Err(Error::InvalidArgument(m)) => m,
            other => panic!("{what}: expected InvalidArgument, got {other:?}"),
        }
    }

    /// I1192 — the consent-role door.
    pub(crate) async fn i1192_consent_role(d: &dyn FederationDirectory, s: &str) {
        let k = e2::put_key(d, &format!("i1192-k-{s}"), &[NODE]).await;
        let role = consent_role::PARTNERED;
        d.set_consent_role(&k, Some(role))
            .await
            .expect("I1192: a recognized role");
        let read = d.lookup_public_key(&k).await.unwrap().unwrap().consent_role;
        assert_eq!(
            read.as_deref(),
            Some(role),
            "I1192: the role is stored and read back"
        );

        let m = invalid(
            d.set_consent_role(&k, Some("i1192-not-a-role")).await,
            "I1192: an unrecognized token",
        );
        assert!(
            m.contains("not a recognized"),
            "I1192: the token gate's wording: {m}"
        );
        let read = d.lookup_public_key(&k).await.unwrap().unwrap().consent_role;
        assert_eq!(
            read.as_deref(),
            Some(role),
            "I1192: a refused token moves nothing"
        );

        d.set_consent_role(&k, Some(consent_role::UNREGISTERED))
            .await
            .expect("I1192: the stored default is admissible");
        let read = d.lookup_public_key(&k).await.unwrap().unwrap().consent_role;
        assert_eq!(read, None, "I1192: 'unregistered' is the wire None");

        d.set_consent_role(&k, Some(role)).await.unwrap();
        d.set_consent_role(&k, None)
            .await
            .expect("I1192: revoke to the default");
        assert_eq!(
            d.lookup_public_key(&k).await.unwrap().unwrap().consent_role,
            None,
            "I1192: None revokes"
        );

        let m = invalid(
            d.set_consent_role(&format!("i1192-absent-{s}"), Some(role))
                .await,
            "I1192: a key with no row",
        );
        assert!(
            m.contains("no federation_keys row"),
            "I1192: names the missing row: {m}"
        );
    }

    fn grant_at(
        id: &str,
        author: &str,
        peer: &str,
        for_key: Option<&str>,
        t: DateTime<Utc>,
    ) -> Attestation {
        // E0.api v1.4 — the earlier-form helpers behind `grant` / `row` seed
        // from the name, never from an identity-ref: pass the seed.
        let author = e2::seed_of(author);
        let author = author.as_str();
        let g = grant(id, author, peer, for_key, &["trace:"]);
        let mut r = row(
            id,
            author,
            author,
            g.attestation_envelope,
            g.subject_key_ids,
            t,
        );
        r.asserted_at = t;
        ts::reseal(&mut r);
        r
    }

    fn ids(rows: Vec<Attestation>) -> Vec<String> {
        rows.into_iter().map(|a| a.attestation_id).collect()
    }

    /// I1194 — the consent-peer and live-grant folds.
    pub(crate) async fn i1194_consent_folds(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::types::identity_type::USER;
        // v62.0.0 (JSON cut, E7) — edition-2 keys (ids are identity-refs) and
        // edition-2 rows (ids are node-computed): every expected order is
        // computed from the held ids, never assumed from the names.
        let alice = e2::put_key(d, &format!("i1194-alice-{s}"), &[USER]).await;
        let mallory = e2::put_key(d, &format!("i1194-mallory-{s}"), &[USER]).await;
        let node = e2::put_key(d, &format!("i1194-node-{s}"), &[NODE]).await;
        let p1 = e2::put_key(d, &format!("i1194-p1-{s}"), &[NODE]).await;
        let p2 = e2::put_key(d, &format!("i1194-p2-{s}"), &[NODE]).await;
        bind_owner(d, &alice, &node).await;
        // `p1` is granted twice by alice (a self grant and one for the node:
        // two projection rows), so the peer read must dedup; `ga` and `gb`
        // share their instant, so the id decides.
        let mut minted = Vec::new();
        for (label, peer, for_key, t) in [
            ("i1194-g0", &p2, None, at(10)),
            ("i1194-ga", &p1, None, at(20)),
            ("i1194-gb", &p1, Some(node.as_str()), at(20)),
        ] {
            let g = grant_at(label, &alice, peer, for_key, t);
            minted.push(g.attestation_id.clone());
            put(d, g).await;
        }
        let (g_old, g_tie_a, g_tie_b) = (minted[0].clone(), minted[1].clone(), minted[2].clone());
        let mut peers = vec![p1.clone(), p2.clone()];
        peers.sort();
        assert_eq!(
            d.list_consent_peers(&alice).await.unwrap(),
            peers,
            "I1194: peers sorted, the twice-granted peer once"
        );
        let mut ties = vec![g_tie_a.clone(), g_tie_b.clone()];
        ties.sort();
        ties.reverse();
        let mut newest_first = ties;
        newest_first.push(g_old.clone());
        assert_eq!(
            ids(d.list_live_consent_grants_by(&alice).await.unwrap()),
            newest_first,
            "I1194: newest first, ties by id descending"
        );

        let f_old = grant_at("i1194-f0", &alice, &p2, Some(&node), at(30));
        let m_new = grant_at("i1194-m1", &mallory, &p1, Some(&node), at(40));
        let (f_old_id, m_new_id) = (f_old.attestation_id.clone(), m_new.attestation_id.clone());
        put(d, f_old).await;
        put(d, m_new).await;
        let mut pairs = vec![
            (alice.clone(), p1.clone()),
            (alice.clone(), p2.clone()),
            (mallory.clone(), p1.clone()),
        ];
        pairs.sort();
        assert_eq!(
            d.list_consent_peers_for(&node).await.unwrap(),
            pairs,
            "I1194: (author, peer) pairs sorted"
        );
        assert_eq!(
            ids(d.list_live_consent_grants_for(&node).await.unwrap()),
            vec![m_new_id.clone(), f_old_id.clone(), g_tie_b.clone()],
            "I1194: the machine's live grants newest first"
        );
        // A withdrawn grant leaves both reads.
        put(d, withdraws("", &e2::seed_of(&mallory), &m_new_id)).await;
        assert_eq!(
            ids(d.list_live_consent_grants_for(&node).await.unwrap()),
            vec![f_old_id.clone(), g_tie_b.clone()]
        );
        let mut alice_pairs = vec![(alice.clone(), p1.clone()), (alice.clone(), p2.clone())];
        alice_pairs.sort();
        assert_eq!(d.list_consent_peers_for(&node).await.unwrap(), alice_pairs);
    }

    /// I1195 — the consent-revocation fold.
    pub(crate) async fn i1195_consent_revocations(d: &dyn FederationDirectory, s: &str) {
        // v62.0.0 (JSON cut, E7) — edition-2 keys; the signed rows' ids are
        // node-computed, so "mine" is the set of ids this body minted, not a
        // suffix of the run tag.
        let subject = e2::put_key(d, &format!("i1195-subject-{s}"), &[NODE]).await;
        let target = e2::put_key(d, &format!("i1195-target-{s}"), &[NODE]).await;
        // A second subject: the local upsert keeps one stance per signer
        // and dimension.
        let subject2 = e2::put_key(d, &format!("i1195-subject2-{s}"), &[NODE]).await;
        let now = Utc::now();
        // v62.0.0 (E0.api v1.8) — each subject-side revocation is an edition-2
        // `consent:state:revoked:v1` row at tier local, signed by the
        // subject's composite and stored through the statement entry. Its id is
        // node-computed: read it off the row.
        let mut revoked = Vec::new();
        for (label, who, t) in [
            ("i1195-r0", &subject, now - Duration::minutes(10)),
            ("i1195-r1", &subject2, now - Duration::minutes(5)),
        ] {
            let r = e2::transit_revocation_row(
                label,
                who,
                &target,
                vec![who.clone()],
                crate::federation::types::cohort_scope::SELF,
                t,
                serde_json::json!({ "id": format!("{label}-{s}") }),
            );
            e2::put_signed(d, &r)
                .await
                .expect("I1195: a subject-side revocation transits");
            revoked.push(r.attestation_id.clone());
        }
        let (r_old, r_new) = (revoked[0].clone(), revoked[1].clone());
        // A producer's own `withdraws` (rule 1) is not a consent event.
        let own = row(
            "",
            &e2::seed_of(&subject),
            &subject,
            serde_json::json!({"dimension": DIMENSION, "label": "own"}),
            vec![subject.clone()],
            now,
        );
        let own_id = own.attestation_id.clone();
        put(d, own).await;
        let w = withdraws("", &e2::seed_of(&subject), &own_id);
        let w_id = w.attestation_id.clone();
        put(d, w).await;
        // A SUBJECT's `withdraws` of a row naming it (rule 2) is one.
        let about = row(
            "",
            &e2::seed_of(&target),
            &target,
            serde_json::json!({"dimension": DIMENSION, "label": "about"}),
            vec![target.clone(), subject.clone()],
            now,
        );
        let about_id = about.attestation_id.clone();
        put(d, about).await;
        let w2 = withdraws("", &e2::seed_of(&subject), &about_id);
        let w2_id = w2.attestation_id.clone();
        put(d, w2).await;
        assert_eq!(
            d.get_attestation(&w2_id)
                .await
                .unwrap()
                .unwrap()
                .withdraws_admission_rule,
            Some(2),
            "I1195: the fixture is a rule-2 withdraws"
        );
        let minted = [
            r_old.clone(),
            r_new.clone(),
            own_id.clone(),
            w_id.clone(),
            about_id.clone(),
            w2_id.clone(),
        ];
        let mine = |rows: Vec<Attestation>| -> Vec<String> {
            rows.into_iter()
                .filter(|a| minted.contains(&a.attestation_id))
                .map(|a| a.attestation_id)
                .collect()
        };
        let all = d.list_consent_revocations(None).await.unwrap();
        assert!(
            all.iter()
                .all(crate::federation::consent_admit::is_subject_side_revocation),
            "I1195: every row returned is a subject-side revocation"
        );
        let got = mine(all);
        assert!(
            !got.contains(&w_id),
            "I1195: a rule-1 withdraws is not a consent revocation"
        );
        assert_eq!(
            got,
            vec![w2_id.clone(), r_new.clone(), r_old.clone()],
            "I1195: the subject's withdraws and both stances, newest first"
        );
        assert_eq!(
            mine(
                d.list_consent_revocations(Some(now - Duration::minutes(7)))
                    .await
                    .unwrap()
            ),
            vec![w2_id.clone(), r_new.clone()],
            "I1195: since bounds the scan"
        );
    }

    /// I1197 — the reaper's selection.
    pub(crate) async fn i1197_expired(d: &dyn FederationDirectory, s: &str) {
        let k = e2::put_key(d, &format!("i1197-k-{s}"), &[NODE]).await;
        let now = Utc::now();
        let mk = |label: &str, exp: DateTime<Utc>| {
            let mut r = row(
                "",
                &e2::seed_of(&k),
                &k,
                serde_json::json!({"dimension": DIMENSION, "label": label}),
                vec![k.clone()],
                now,
            );
            r.expires_at =
                Some(crate::federation::admission::truncate_to_substrate_resolution(exp));
            ts::reseal(&mut r);
            r
        };
        let (early_row, tie_1, tie_2) = (
            mk("early", now + Duration::days(1)),
            mk("tie-1", now + Duration::days(2)),
            mk("tie-2", now + Duration::days(2)),
        );
        let early = early_row.attestation_id.clone();
        // v62.0.0 (JSON cut, E7) — ties are by id, and the ids are computed:
        // the expected order is the two ids sorted.
        let mut ties = [tie_1.attestation_id.clone(), tie_2.attestation_id.clone()];
        ties.sort();
        for r in [early_row, tie_1, tie_2] {
            put(d, r).await;
        }
        let mut w = withdraws("", &e2::seed_of(&k), &early);
        w.expires_at = Some(
            crate::federation::admission::truncate_to_substrate_resolution(now + Duration::days(1)),
        );
        ts::reseal(&mut w);
        let w_id = w.attestation_id.clone();
        put(d, w).await;
        let minted = [early.clone(), ties[0].clone(), ties[1].clone()];

        // Expiry is strict: a row expiring AT the judged instant has not
        // expired yet.
        let at_e =
            crate::federation::admission::truncate_to_substrate_resolution(now + Duration::days(1));
        assert!(
            !d.list_expired_attestation_ids(at_e, 10_000, 0)
                .await
                .unwrap()
                .contains(&early),
            "I1197: expires_at == now is not expired"
        );
        assert!(
            d.list_expired_attestation_ids(at_e + Duration::milliseconds(1), 10_000, 0)
                .await
                .unwrap()
                .contains(&early),
            "I1197: a millisecond later it is"
        );
        let judged = now + Duration::days(3);
        let full = d
            .list_expired_attestation_ids(judged, 10_000, 0)
            .await
            .unwrap();
        assert!(!full.contains(&w_id), "I1197: a withdraws is never offered");
        let mine: Vec<&String> = full.iter().filter(|x| minted.contains(x)).collect();
        assert_eq!(
            mine,
            vec![&early, &ties[0], &ties[1]],
            "I1197: expiry order, ties by id"
        );
        let mut walked = Vec::new();
        for off in 0..full.len() {
            walked.extend(
                d.list_expired_attestation_ids(judged, 1, off)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            walked, full,
            "I1197: OFFSET pages are the order, each row once"
        );
        assert!(d
            .list_expired_attestation_ids(judged, 0, 0)
            .await
            .unwrap()
            .is_empty());
        assert!(
            !d.list_expired_attestation_ids(now, 10_000, 0)
                .await
                .unwrap()
                .iter()
                .any(|x| minted.contains(x)),
            "I1197: nothing of mine has expired yet"
        );
    }

    /// I1198 — the known-hash eviction.
    pub(crate) async fn i1198_known_hashes(d: &dyn FederationDirectory) {
        let t0 = Utc::now() - Duration::hours(3);
        let hashes: Vec<String> = (0..4)
            .map(|i| format!("{:064x}", 0x1198_0000u64 + i))
            .collect();
        for (i, h) in hashes.iter().enumerate() {
            d.insert_known_wire_hash("Attestation", h, None, t0 + Duration::hours(i as i64 / 2))
                .await
                .unwrap();
        }
        let r = d
            .evict_known_wire_hashes(t0 + Duration::minutes(30), 1)
            .await
            .unwrap();
        assert_eq!(
            (r.evicted, r.remaining, r.over_bound_by),
            (2, 2, 1),
            "I1198: {r:?}"
        );
        let r = d
            .evict_known_wire_hashes(t0 + Duration::minutes(30), 5)
            .await
            .unwrap();
        assert_eq!(
            (r.evicted, r.remaining, r.over_bound_by),
            (0, 2, 0),
            "I1198: {r:?}"
        );
    }
}

#[cfg(test)]
mod units {
    use crate::federation::sweep_plan::{RoomChunkEviction, RoomEpochRow};

    fn epoch(
        scope: &str,
        room: Option<i64>,
        terminated: bool,
        evicted: bool,
        held: bool,
    ) -> RoomEpochRow {
        RoomEpochRow {
            stream_id: "s".into(),
            epoch: 0,
            cohort_scope: scope.into(),
            room_epoch: room,
            terminated,
            evicted,
            manifest_held: held,
        }
    }

    /// I1199 (unit) — the room leg's predicate, clause by clause.
    #[test]
    fn i1199_room_selection_predicate() {
        let e = RoomChunkEviction {
            community_key_id: "c".into(),
            minter_key_id: "m".into(),
            max_room_epoch: 5,
            now: chrono::Utc::now(),
        };
        assert!(
            e.selects(&epoch("community", Some(5), true, false, false)),
            "at the bound"
        );
        assert!(e.selects(&epoch("affiliations", Some(0), true, false, false)));
        assert!(
            !e.selects(&epoch("community", Some(6), true, false, false)),
            "above the bound"
        );
        assert!(
            !e.selects(&epoch("self", Some(1), true, false, false)),
            "not a room scope"
        );
        assert!(!e.selects(&epoch("family", Some(1), true, false, false)));
        assert!(
            !e.selects(&epoch("community", None, true, false, false)),
            "not a room stream"
        );
        assert!(
            !e.selects(&epoch("community", Some(-1), true, false, false)),
            "a negative epoch"
        );
        assert!(
            !e.selects(&epoch("community", Some(1), false, false, false)),
            "open"
        );
        assert!(
            !e.selects(&epoch("community", Some(1), true, true, false)),
            "already evicted"
        );
        assert!(
            !e.selects(&epoch("community", Some(1), true, false, true)),
            "manifest held"
        );
    }

    /// I1200 (unit) — the observation prune plan.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn i1200_observation_prune_plan() {
        use crate::federation::attestation_query::Dialect;
        use crate::retention::{plan_observation_prune, ObservationTable};
        let t = chrono::Utc::now();
        assert!(
            plan_observation_prune(ObservationTable::AnnouncedPeers, t, 0)
                .unwrap()
                .is_none()
        );
        let p = plan_observation_prune(ObservationTable::TransportDestinations, t, 7)
            .unwrap()
            .unwrap();
        assert_eq!(p.limit, 7);
        let keep = ObservationTable::TransportDestinations
            .keep_predicate()
            .unwrap();
        let lite = p.render(Dialect::Sqlite);
        assert!(
            lite.contains(keep) && lite.contains("transport_destinations"),
            "{lite}"
        );
        let pg = p.render(Dialect::Postgres);
        assert_eq!(
            pg.matches(keep).count(),
            2,
            "postgres re-checks the keep predicate: {pg}"
        );
        assert_eq!(
            pg.matches("last_seen_at < $1").count(),
            2,
            "and the age: {pg}"
        );
        let peers = plan_observation_prune(ObservationTable::AnnouncedPeers, t, 1)
            .unwrap()
            .unwrap()
            .render(Dialect::Sqlite);
        assert!(!peers.contains("signature IS NULL"), "{peers}");
        assert!(ObservationTable::AnnouncedPeers.keep_predicate().is_none());
    }

    /// I1197 (unit) — the selection's bounds plan nothing for an
    /// empty or unreachable page.
    #[test]
    fn i1197_selection_bounds() {
        use crate::federation::sweep_plan::plan_expired;
        let now = chrono::Utc::now();
        assert!(plan_expired(now, 0, 0).is_none());
        assert!(plan_expired(now, 1, usize::MAX).is_none());
        let sel = plan_expired(now, 2, 1).unwrap();
        assert_eq!((sel.limit, sel.offset), (2, 1));
    }
}

/// I1200 (postgres) — the observation prunes' executor runs the plan's
/// statement: bounded, oldest first, sparing assertions, signed routes and
/// tombstones. (The sqlite twin is #767 / #776 in `retention`.)
#[cfg(all(test, feature = "postgres"))]
mod prune_postgres {
    use crate::store::Backend as _;

    #[tokio::test(flavor = "multi_thread")]
    async fn i1200_observation_prunes_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let day = |d: u32| -> chrono::DateTime<chrono::Utc> {
            format!("2026-01-{d:02}T00:00:00Z").parse().unwrap()
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        // `transport_destinations.occurrence_key_id` references a held key.
        // v62.0.0 (JSON cut, E7) — an edition-2 key; its id is the
        // identity-ref `e2::put_key` returns.
        let mut occ = std::collections::BTreeMap::new();
        for k in ["assert", "seen", "signed"] {
            let id = crate::federation::edition2::fixture_switch::put_key(
                &b,
                &format!("i1200-{k}-{run}"),
                &[crate::federation::types::identity_type::NODE],
            )
            .await;
            occ.insert(k, id);
        }
        {
            let c = b.checkout().await.unwrap();
            for i in 0..4u32 {
                c.execute(
                    "INSERT INTO cirislens.announced_peers \
                     (key_id, pubkey_ed25519_base64, first_seen_at, last_seen_at) \
                     VALUES ($1, 'cHVia2V5', $2, $2)",
                    &[&format!("i1200-peer-{i}-{run}"), &day(i + 1)],
                )
                .await
                .unwrap();
            }
            for (k, seen, sig) in [
                ("assert", None, None),
                ("seen", Some(day(1)), None),
                ("signed", Some(day(1)), Some("c2ln")),
            ] {
                c.execute(
                    "INSERT INTO cirislens.transport_destinations \
                     (occurrence_key_id, transport_kind, destination, asserted_at, last_seen_at, \
                      admitted_at, signature) \
                     VALUES ($1, 'reticulum', $1, $2, $3, $2, $4)",
                    &[&occ[k], &day(1), &seen, &sig],
                )
                .await
                .unwrap();
            }
        }
        use crate::retention::postgres as rp;
        let cutoff = day(3) + chrono::Duration::hours(12);
        assert_eq!(
            rp::prune_announced_peers_not_seen_since_pg(&b, cutoff, 0)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            rp::prune_announced_peers_not_seen_since_pg(&b, cutoff, 1)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            rp::prune_announced_peers_not_seen_since_pg(&b, cutoff, 10)
                .await
                .unwrap(),
            2
        );
        let c = b.checkout().await.unwrap();
        let left: Vec<String> = c
            .query(
                "SELECT key_id FROM cirislens.announced_peers WHERE key_id LIKE 'i1200-%' ORDER BY 1",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(
            left,
            vec![format!("i1200-peer-3-{run}")],
            "I1200: oldest first, bounded"
        );
        assert_eq!(
            rp::prune_transport_destinations_not_seen_since_pg(&b, cutoff, 100)
                .await
                .unwrap(),
            1,
            "I1200: only the unsigned observation"
        );
        let mine: Vec<&String> = occ.values().collect();
        let left: Vec<String> = c
            .query(
                "SELECT occurrence_key_id FROM cirislens.transport_destinations ORDER BY 1",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| r.get::<_, String>(0))
            .filter(|k| mine.contains(&k))
            .collect();
        let mut want = vec![occ["assert"].clone(), occ["signed"].clone()];
        want.sort();
        assert_eq!(left, want);
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies as b;
                use crate::federation::FederationDirectory;
                #[tokio::test(flavor = "multi_thread")]
                async fn i1192_consent_role() {
                    let Some(d) = $fresh.await else { return };
                    b::i1192_consent_role(&d as &dyn FederationDirectory, &super::suffix()).await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i1194_consent_folds() {
                    let Some(d) = $fresh.await else { return };
                    b::i1194_consent_folds(&d as &dyn FederationDirectory, &super::suffix()).await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i1195_consent_revocations() {
                    let Some(d) = $fresh.await else { return };
                    b::i1195_consent_revocations(&d as &dyn FederationDirectory, &super::suffix())
                        .await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i1197_expired() {
                    let Some(d) = $fresh.await else { return };
                    b::i1197_expired(&d as &dyn FederationDirectory, &super::suffix()).await
                }
                #[tokio::test(flavor = "multi_thread")]
                async fn i1198_known_hashes() {
                    let Some(d) = $fresh.await else { return };
                    b::i1198_known_hashes(&d as &dyn FederationDirectory).await
                }
            }
        };
    }

    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
