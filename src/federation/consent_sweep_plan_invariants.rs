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
//! - **I1196 (the PQC sweep's selection)** — a zero or negative page reads
//!   nothing on every backend (sqlite read EVERY row for `-1`, postgres
//!   refused it); pages come oldest first, ties by id, cut at the limit.
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
//! - **I1201 (the #1105 family-scoped holdings read)** — the page for a
//!   key-plane family is exactly the `Attestation` hashes whose rows are
//!   that family's `scores` rows, in hash order; paging on the hash
//!   reconstructs it; a non-key-plane dimension is refused, never answered
//!   empty.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::consent_sweep_principals_invariants::bodies::{
        grant, put, row, withdraws,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{consent_role, identity_type::NODE};
    use crate::federation::{
        Attestation, Error, FederationDirectory, TrustGrant, TrustRelationship, TrustType,
    };
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
        let k = format!("i1192-k-{s}");
        ts::register_identity_key(d, &k, NODE).await;
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

    fn trust(
        key: &str,
        by: &str,
        rel: TrustRelationship,
        domains: Option<Vec<String>>,
    ) -> TrustGrant {
        TrustGrant {
            key: key.to_owned(),
            trust_type: TrustType::Partnered,
            trust_relationship: rel,
            trust_domains: domains,
            trusted_by: by.to_owned(),
            expires_at: None,
        }
    }

    /// I1193 — the trust-grant door.
    pub(crate) async fn i1193_grant_trust(d: &dyn FederationDirectory, s: &str) {
        let steward = format!("i1193-steward-{s}");
        let k = format!("i1193-k-{s}");
        ts::register_hybrid_key(d, &steward).await;
        ts::register_hybrid_key(d, &k).await;

        let before = Utc::now();
        d.grant_trust(ts::signed_trust_grant(trust(
            &k,
            &steward,
            TrustRelationship::Direct,
            None,
        )))
        .await
        .expect("I1193: a granter-signed grant lands");
        let after = Utc::now();
        let held = d
            .lookup_trust(&k)
            .await
            .unwrap()
            .expect("I1193: the trust row");
        assert_eq!(held.trusted_by, steward);
        assert_eq!(held.trust_relationship, TrustRelationship::Direct);
        // Postgres keeps microseconds, sqlite the RFC 3339 text: compare
        // at the coarser of the two.
        let ms = |t: DateTime<Utc>| t.timestamp_millis();
        assert!(
            ms(held.trusted_at) >= ms(before) - 1 && ms(held.trusted_at) <= ms(after) + 1,
            "I1193: trusted_at is the door's clock: {} not in [{before}, {after}]",
            held.trusted_at
        );

        // The authority gate runs before the shape: a grant whose signature
        // does not cover it is refused even though its shape is valid.
        let mut forged =
            ts::signed_trust_grant(trust(&k, &steward, TrustRelationship::Direct, None));
        forged.grant.trust_type = TrustType::Temporary;
        assert!(
            d.grant_trust(forged).await.is_err(),
            "I1193: an unverified grant is refused"
        );

        for (bad, why) in [
            (trust(&k, &k, TrustRelationship::Direct, None), "self-trust"),
            (
                trust(&k, &steward, TrustRelationship::Registry, None),
                "registry without domains",
            ),
            (
                trust(&k, &steward, TrustRelationship::Registry, Some(Vec::new())),
                "registry with an empty domain list",
            ),
            (
                trust(
                    &k,
                    &steward,
                    TrustRelationship::Direct,
                    Some(vec!["d".into()]),
                ),
                "direct with domains",
            ),
        ] {
            invalid(d.grant_trust(ts::signed_trust_grant(bad)).await, why);
        }
        let still = d.lookup_trust(&k).await.unwrap().unwrap();
        assert_eq!(
            still.trust_type,
            TrustType::Partnered,
            "I1193: no refusal moved the row"
        );
        assert_eq!(still.trusted_by, steward);

        let ghost = format!("i1193-ghost-{s}");
        let m = invalid(
            d.grant_trust(ts::signed_trust_grant(trust(
                &ghost,
                &steward,
                TrustRelationship::Direct,
                None,
            )))
            .await,
            "I1193: a key never put",
        );
        assert!(
            m.contains("does not exist"),
            "I1193: names the missing row: {m}"
        );
    }

    fn grant_at(
        id: &str,
        author: &str,
        peer: &str,
        for_key: Option<&str>,
        t: DateTime<Utc>,
    ) -> Attestation {
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
        let alice = format!("i1194-alice-{s}");
        let mallory = format!("i1194-mallory-{s}");
        let node = format!("i1194-node-{s}");
        let (p1, p2) = (format!("i1194-p1-{s}"), format!("i1194-p2-{s}"));
        ts::register_identity_key(d, &alice, USER).await;
        ts::register_identity_key(d, &mallory, USER).await;
        for k in [&node, &p1, &p2] {
            ts::register_identity_key(d, k, NODE).await;
        }
        put(
            d,
            ts::owner_binding_attestation(&format!("i1194-ob-{s}"), &alice, &node),
        )
        .await;
        // Inserted oldest first and the higher peer first, so the
        // projection's own order is neither the fold's sort nor its
        // newest-first order. `p1` is granted twice by alice (a self grant
        // and one for the node: two projection rows), so the peer read must
        // dedup; `ga` and `gb` share their instant, so the id decides.
        let g_old = format!("i1194-g0-{s}");
        let (g_tie_a, g_tie_b) = (format!("i1194-ga-{s}"), format!("i1194-gb-{s}"));
        put(d, grant_at(&g_old, &alice, &p2, None, at(10))).await;
        put(d, grant_at(&g_tie_a, &alice, &p1, None, at(20))).await;
        put(d, grant_at(&g_tie_b, &alice, &p1, Some(&node), at(20))).await;
        assert_eq!(
            d.list_consent_peers(&alice).await.unwrap(),
            vec![p1.clone(), p2.clone()],
            "I1194: peers sorted, the twice-granted peer once"
        );
        assert_eq!(
            ids(d.list_live_consent_grants_by(&alice).await.unwrap()),
            vec![g_tie_b.clone(), g_tie_a.clone(), g_old.clone()],
            "I1194: newest first, ties by id descending"
        );

        let f_old = format!("i1194-f0-{s}");
        let m_new = format!("i1194-m1-{s}");
        put(d, grant_at(&f_old, &alice, &p2, Some(&node), at(30))).await;
        put(d, grant_at(&m_new, &mallory, &p1, Some(&node), at(40))).await;
        assert_eq!(
            d.list_consent_peers_for(&node).await.unwrap(),
            vec![
                (alice.clone(), p1.clone()),
                (alice.clone(), p2.clone()),
                (mallory.clone(), p1.clone()),
            ],
            "I1194: (author, peer) pairs sorted"
        );
        assert_eq!(
            ids(d.list_live_consent_grants_for(&node).await.unwrap()),
            vec![m_new.clone(), f_old.clone(), g_tie_b.clone()],
            "I1194: the machine's live grants newest first"
        );
        // A withdrawn grant leaves both reads.
        put(d, withdraws(&format!("i1194-w-{s}"), &mallory, &m_new)).await;
        assert_eq!(
            ids(d.list_live_consent_grants_for(&node).await.unwrap()),
            vec![f_old.clone(), g_tie_b.clone()]
        );
        assert_eq!(
            d.list_consent_peers_for(&node).await.unwrap(),
            vec![(alice.clone(), p1.clone()), (alice.clone(), p2.clone())]
        );
    }

    /// I1195 — the consent-revocation fold.
    pub(crate) async fn i1195_consent_revocations(d: &dyn FederationDirectory, s: &str) {
        let subject = format!("i1195-subject-{s}");
        let target = format!("i1195-target-{s}");
        ts::register_identity_key(d, &subject, NODE).await;
        ts::register_identity_key(d, &target, NODE).await;
        // A second subject: the local upsert keeps one stance per signer
        // and dimension.
        let subject2 = format!("i1195-subject2-{s}");
        ts::register_identity_key(d, &subject2, NODE).await;
        let now = Utc::now();
        let (r_old, r_new) = (format!("i1195-r0-{s}"), format!("i1195-r1-{s}"));
        for (id, who, t) in [
            (&r_old, &subject, now - Duration::minutes(10)),
            (&r_new, &subject2, now - Duration::minutes(5)),
        ] {
            d.attestation_upsert_local(ts::bound_transit_revocation_input(
                id,
                who,
                &target,
                vec![who.clone()],
                crate::federation::types::cohort_scope::SELF,
                t,
                serde_json::json!({ "id": id }),
            ))
            .await
            .expect("I1195: a subject-side revocation transits");
        }
        // A producer's own `withdraws` (rule 1) is not a consent event.
        let own = format!("i1195-own-{s}");
        put(
            d,
            row(
                &own,
                &subject,
                &subject,
                serde_json::json!({"dimension": "x:v1"}),
                vec![subject.clone()],
                now,
            ),
        )
        .await;
        let w = format!("i1195-w-{s}");
        put(d, withdraws(&w, &subject, &own)).await;
        let mine = |rows: Vec<Attestation>| -> Vec<String> {
            rows.into_iter()
                .filter(|a| a.attestation_id.ends_with(s))
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
            !got.contains(&w),
            "I1195: a rule-1 withdraws is not a consent revocation"
        );
        assert_eq!(
            got,
            vec![r_new.clone(), r_old.clone()],
            "I1195: newest first"
        );
        assert_eq!(
            mine(
                d.list_consent_revocations(Some(now - Duration::minutes(7)))
                    .await
                    .unwrap()
            ),
            vec![r_new.clone()],
            "I1195: since bounds the scan"
        );
    }

    /// I1196 — the PQC sweep's selection.
    pub(crate) async fn i1196_hybrid_pending(d: &dyn FederationDirectory, s: &str) {
        let (a, b) = (format!("i1196-a-{s}"), format!("i1196-b-{s}"));
        // Inserted b first; both carry the fixture's one `valid_from`, so the
        // id decides their order.
        for k in [&b, &a] {
            let (rec, _, _) =
                crate::federation::admission::pqc_attach_test_support::hybrid_pending_self_scrubbed(
                    k,
                    crate::federation::types::identity_type::PRIMITIVE,
                );
            d.put_public_key(crate::federation::SignedKeyRecord { record: rec })
                .await
                .expect("I1196: a hybrid-pending key");
        }
        for limit in [0, -1, i64::MIN] {
            assert!(
                d.list_hybrid_pending_keys(limit).await.unwrap().is_empty(),
                "I1196: a page of {limit} reads nothing"
            );
            assert!(d
                .list_hybrid_pending_attestations(limit)
                .await
                .unwrap()
                .is_empty());
        }
        let full: Vec<String> = d
            .list_hybrid_pending_keys(10_000)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        let pa = full
            .iter()
            .position(|x| *x == a)
            .expect("I1196: a is pending");
        let pb = full
            .iter()
            .position(|x| *x == b)
            .expect("I1196: b is pending");
        assert_eq!(pb, pa + 1, "I1196: ties on valid_from by id: {full:?}");
        let cut: Vec<String> = d
            .list_hybrid_pending_keys(i64::try_from(pa + 1).unwrap())
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            cut,
            full[..=pa].to_vec(),
            "I1196: the page is the order's prefix"
        );
    }

    /// I1197 — the reaper's selection.
    pub(crate) async fn i1197_expired(d: &dyn FederationDirectory, s: &str) {
        let k = format!("i1197-k-{s}");
        ts::register_identity_key(d, &k, NODE).await;
        let now = Utc::now();
        let mk = |id: &str, exp: DateTime<Utc>| {
            let mut r = row(
                id,
                &k,
                &k,
                serde_json::json!({"dimension": "x:v1"}),
                vec![k.clone()],
                now,
            );
            r.expires_at =
                Some(crate::federation::admission::truncate_to_substrate_resolution(exp));
            ts::reseal(&mut r);
            r
        };
        let early = format!("i1197-0-{s}");
        let (tie_b, tie_a) = (format!("i1197-b-{s}"), format!("i1197-a-{s}"));
        put(d, mk(&early, now + Duration::days(1))).await;
        put(d, mk(&tie_b, now + Duration::days(2))).await;
        put(d, mk(&tie_a, now + Duration::days(2))).await;
        let mut w = withdraws(&format!("i1197-w-{s}"), &k, &early);
        w.expires_at = Some(
            crate::federation::admission::truncate_to_substrate_resolution(now + Duration::days(1)),
        );
        ts::reseal(&mut w);
        let w_id = w.attestation_id.clone();
        put(d, w).await;

        let judged = now + Duration::days(3);
        let full = d
            .list_expired_attestation_ids(judged, 10_000, 0)
            .await
            .unwrap();
        assert!(!full.contains(&w_id), "I1197: a withdraws is never offered");
        let mine: Vec<&String> = full.iter().filter(|x| x.ends_with(s)).collect();
        assert_eq!(
            mine,
            vec![&early, &tie_a, &tie_b],
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
                .any(|x| x.ends_with(s)),
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

    /// I1201 — the #1105 family-scoped holdings read.
    pub(crate) async fn i1201_key_plane_holdings(d: &dyn FederationDirectory, s: &str) {
        for i in 0..3 {
            ts::register_identity_key(d, &format!("i1201-k{i}-{s}"), NODE).await;
        }
        let k = format!("i1201-k0-{s}");
        put(
            d,
            row(
                &format!("i1201-x-{s}"),
                &k,
                &k,
                serde_json::json!({"dimension": "x:v1"}),
                vec![k.clone()],
                Utc::now(),
            ),
        )
        .await;
        let all = d
            .list_wire_hashes_since("Attestation", None, u32::MAX)
            .await
            .unwrap();
        let mut by_family: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
        for h in &all {
            let bytes = d
                .lookup_signed_record_by_content_hash("Attestation", h)
                .await
                .unwrap()
                .expect("an advertised hash resolves");
            let a: Attestation = serde_json::from_slice(&bytes).unwrap();
            if a.attestation_type != crate::federation::types::attestation_type::SCORES {
                continue;
            }
            let dim = crate::federation::admission::envelope_dimension(&a.attestation_envelope);
            if let Some(f) = crate::federation::key_plane::HOLDINGS_FAMILIES
                .into_iter()
                .find(|f| Some(*f) == dim)
            {
                by_family.entry(f).or_default().push(h.clone());
            }
        }
        assert!(
            by_family.get("key:record:v1").is_some_and(|v| v.len() >= 3),
            "I1201: the fixture holds key-record rows: {by_family:?}"
        );
        for family in crate::federation::key_plane::HOLDINGS_FAMILIES {
            let mut want = by_family.remove(family).unwrap_or_default();
            want.sort();
            let got = d
                .list_key_plane_wire_hashes_since(family, None, u32::MAX)
                .await
                .unwrap();
            assert_eq!(
                got, want,
                "I1201: {family} is exactly its rows' hashes, hash order"
            );
            let mut paged = Vec::new();
            let mut after: Option<String> = None;
            loop {
                let page = d
                    .list_key_plane_wire_hashes_since(family, after.as_deref(), 1)
                    .await
                    .unwrap();
                let Some(last) = page.last().cloned() else {
                    break;
                };
                assert_eq!(page.len(), 1, "I1201: the limit holds");
                paged.extend(page);
                after = Some(last);
            }
            assert_eq!(
                paged, want,
                "I1201: paging on the hash reconstructs {family}"
            );
        }
        for bad in ["consent:replication:v1", "trace:demo:v1", ""] {
            match d.list_key_plane_wire_hashes_since(bad, None, 10).await {
                Err(Error::InvalidArgument(m)) => {
                    assert!(m.contains("not a key-plane family"), "I1201: {m}")
                }
                other => panic!("I1201: '{bad}' must be refused, got {other:?}"),
            }
        }
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

    /// I1196 / I1197 (unit) — the selections' bounds plan nothing for an
    /// empty or unreachable page, and the memory cut is the SQL order.
    #[test]
    fn i1196_i1197_selection_bounds() {
        use crate::federation::sweep_plan::{plan_expired, plan_hybrid_pending, HybridPlane};
        assert!(plan_hybrid_pending(HybridPlane::Keys, 0).is_none());
        assert!(plan_hybrid_pending(HybridPlane::Keys, -5).is_none());
        assert_eq!(
            plan_hybrid_pending(HybridPlane::Attestations, 3)
                .unwrap()
                .limit,
            3
        );
        let now = chrono::Utc::now();
        assert!(plan_expired(now, 0, 0).is_none());
        assert!(plan_expired(now, 1, usize::MAX).is_none());
        let sel = plan_expired(now, 2, 1).unwrap();
        assert_eq!((sel.limit, sel.offset), (2, 1));
        let past = now - chrono::Duration::seconds(1);
        let rows = vec![
            ("c".into(), "scores".into(), Some(past)),
            ("b".into(), "scores".into(), Some(past)),
            ("a".into(), "scores".into(), Some(past)),
            ("w".into(), "withdraws".into(), Some(past)),
            ("n".into(), "scores".into(), Some(now)),
            ("z".into(), "scores".into(), None),
        ];
        assert_eq!(sel.cut(rows), vec!["b".to_owned(), "c".to_owned()]);
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
        for k in ["assert", "seen", "signed"] {
            crate::federation::tier_ingest::test_support::register_identity_key(
                &b,
                &format!("i1200-{k}-{run}"),
                crate::federation::types::identity_type::NODE,
            )
            .await;
        }
        {
            let c = b.pool().get().await.unwrap();
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
                    &[&format!("i1200-{k}-{run}"), &day(1), &seen, &sig],
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
        let c = b.pool().get().await.unwrap();
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
        let left: Vec<String> = c
            .query(
                "SELECT occurrence_key_id FROM cirislens.transport_destinations \
                 WHERE occurrence_key_id LIKE 'i1200-%' ORDER BY 1",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(
            left,
            vec![format!("i1200-assert-{run}"), format!("i1200-signed-{run}")]
        );
    }
}

#[cfg(test)]
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
                async fn i1193_grant_trust() {
                    let Some(d) = $fresh.await else { return };
                    b::i1193_grant_trust(&d as &dyn FederationDirectory, &super::suffix()).await
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
                async fn i1196_hybrid_pending() {
                    let Some(d) = $fresh.await else { return };
                    b::i1196_hybrid_pending(&d as &dyn FederationDirectory, &super::suffix()).await
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
                #[tokio::test(flavor = "multi_thread")]
                async fn i1201_key_plane_holdings() {
                    let Some(d) = $fresh.await else { return };
                    b::i1201_key_plane_holdings(&d as &dyn FederationDirectory, &super::suffix())
                        .await
                }
            }
        };
    }

    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

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
