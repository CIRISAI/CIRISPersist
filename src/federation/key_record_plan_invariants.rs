//! v60.0.0 (CIRISPersist#934 step 3; CC 3.1.3, CC 3.4.7.1–3) — **I1183–I1190:
//! the key-record write doors decide in ONE plan
//! (`key_plane::plan_key_record_write`), and every backend stores exactly the
//! plan's verdict through its one executor
//! (`KeyPlaneStore::store_planned_key_record`).**
//!
//! Each body runs on memory, sqlite and postgres, so a mutation of the
//! shared plan is red on every backend, and a mutation of one backend's
//! executor is red on that backend.
//!
//! - **I1183 (the insert door)** — a fresh record lands with its
//!   `key:record:v1` row and a self-consistent `persist_row_hash`; an
//!   identical re-offer settles (same row); a differing one is `Conflict` and
//!   the held record does not move; a non-hybrid algorithm, a non-hex content
//!   hash and an unknown `consent_role` are refused and nothing is stored;
//!   the stored-form `'unregistered'` is the wire `None` (the hash is over
//!   what the read surface returns); CC 3.4.7.3 Clause A refuses a fused
//!   `node` key at a local mint.
//! - **I1184 (the genesis seed)** — a baked record lands with its row and its
//!   whole scrub set (`additional_scrubs`); a second seed of the same
//!   `key_id` keeps the held record; a non-hybrid or fused record is refused.
//! - **I1185 (the scrub upgrade)** — a self-signed row is re-rooted to the
//!   anchor-scrubbed record (its row follows, `consent_role` is kept); the
//!   same record again is `AlreadyAdopted`; a differing anchored record, a
//!   self-signed incoming record, a pubkey change, an absent row, a fused
//!   record and a `node` move are each refused, and the held record does not
//!   move.
//! - **I1186 (the replicated apply)** — a first sight is `Inserted`, a
//!   re-offer `Unchanged`, an anchored record over a self-signed row
//!   `Upgraded` (memory included, v60), and a fused `node` key minted
//!   elsewhere is admitted (Clause A gates minting only).
//! - **I1187 (the executor's atomic re-assertion)** — a plan made against a
//!   row that changed before the write stores nothing and is refused with
//!   the plan's wording, for every write shape: the upgrade's self-signed
//!   guard, the supersede's anchored-version guard, the re-anchor's pubkey
//!   guard, the replace's hash guard (and no history row), the hybrid
//!   completion's not-yet-complete guard, the scrub rehydrate's empty-set
//!   guard; an insert over a differing held row is `Conflict`, over an
//!   identical one, or with `OnHeld::Keep`, it stands.
//! - **I1189 (the re-anchor's own refusals)** — over the real v2 ceremony
//!   (holders seeded, the pre-ceremony anchor held, the artifact baked and
//!   the canonical re-anchored), the door refuses, directly, the same record
//!   again (`valid_from` not newer: rollback) and a record the bundle does
//!   not carry; the held record does not move. The bake door pre-checks the
//!   rollback, so only a direct call reaches the plan's own copy. RED on
//!   postgres before v60.0.0: the nanosecond bundle instant against the
//!   microsecond held one read as newer, and the same record re-anchored.
//! - **I1190 (the canonical supersede's own decisions)** — over an anchored
//!   incumbent (the #656 fixture): a byte-identical re-offer settles before
//!   any verify (`Unchanged`); a successor whose ML-DSA key alone differs is
//!   the pubkey-change refusal; a successor the supersede policy refuses
//!   (not canonical-scoped, its signed `valid_from` older) is `Conflict`
//!   naming the policy; nothing moves.
//! - **I1188 (the row step, unit)** — `key_record_row_step` keeps a row the
//!   pointer already names, replaces any other, and drops the rows of an
//!   unverifiable or absent record; `PlannedKeyRecord::raced` /
//!   `insert_held` word every lost race the way the three backends did.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::key_plane::{
        self, KeyPlaneStore, KeyRecordWrite, KeyRecordWritten, OnHeld, PlannedKeyRecord,
        RewriteGuard,
    };
    use crate::federation::key_plane_invariants::bodies::{key_row, pop_record};
    use crate::federation::register::test_support::authority_signed_record;
    use crate::federation::register::AdoptScrubOutcome;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        compute_persist_row_hash, identity_type, KeyRecord, KeyReplacementKind, ScrubSig,
    };
    use crate::federation::{Error, FederationDirectory, SignedKeyRecord};

    fn signed(record: KeyRecord) -> SignedKeyRecord {
        SignedKeyRecord { record }
    }

    async fn held(d: &dyn FederationDirectory, key_id: &str) -> KeyRecord {
        d.lookup_public_key(key_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{key_id} is held"))
    }

    async fn absent(d: &dyn FederationDirectory, key_id: &str) -> bool {
        d.lookup_public_key(key_id).await.unwrap().is_none()
    }

    /// `key_id` scrubbed by `signer`, over `key_id`'s own pubkeys.
    fn anchored(key_id: &str, identity: &str, signer: &str) -> KeyRecord {
        let (ed, mldsa) = ts::hybrid_pubkeys(key_id);
        authority_signed_record(key_id, identity, &ed, mldsa.as_deref(), signer)
    }

    /// `key_id`'s own record with `identity`.
    fn own(key_id: &str, identity: &str) -> KeyRecord {
        anchored(key_id, identity, key_id)
    }

    /// The stored record's hash is a function of the record as stored.
    fn self_consistent(r: &KeyRecord) -> bool {
        compute_persist_row_hash(r).is_ok_and(|h| h == r.persist_row_hash)
    }

    /// I1183 — the insert door.
    pub(crate) async fn i1183_put<B: KeyPlaneStore>(b: &B, tag: &str) {
        let d = b.as_dyn_directory();
        let k = format!("i1183-k-{tag}");
        let rec = pop_record(&k);
        b.put_public_key(signed(rec.clone()))
            .await
            .expect("I1183: a fresh record is admitted");
        let stored = held(d, &k).await;
        assert!(
            self_consistent(&stored),
            "I1183: the stored hash is the stored record's"
        );
        let row = key_row(d, &k).await.expect("I1183: the record is a row");
        b.put_public_key(signed(rec.clone()))
            .await
            .expect("I1183: an identical re-offer settles");
        assert_eq!(
            key_row(d, &k).await.map(|r| r.attestation_id),
            Some(row.attestation_id.clone()),
            "I1183: a settled re-offer keeps the row"
        );
        let mut other = rec.clone();
        other.identity_ref = format!("elsewhere-{tag}");
        match b.put_public_key(signed(other)).await {
            Err(Error::Conflict(m)) => assert!(m.contains("different content"), "I1183: {m}"),
            o => panic!("I1183: a differing re-offer is Conflict, got {o:?}"),
        }
        assert_eq!(
            held(d, &k).await.persist_row_hash,
            stored.persist_row_hash,
            "I1183: the held record does not move"
        );
        // The shape refusals, each before anything is stored.
        type Shape = (&'static str, fn(&mut KeyRecord));
        let shapes: [Shape; 3] = [
            ("alg", |r| r.algorithm = "ed25519".to_owned()),
            ("hex", |r| r.original_content_hash = "not-hex".to_owned()),
            ("role", |r| r.consent_role = Some("overlord".to_owned())),
        ];
        for (what, shape) in shapes {
            let k2 = format!("i1183-{what}-{tag}");
            let mut r = pop_record(&k2);
            shape(&mut r);
            match b.put_public_key(signed(r)).await {
                Err(Error::InvalidArgument(_)) => {}
                o => panic!("I1183 {what}: refused InvalidArgument, got {o:?}"),
            }
            assert!(absent(d, &k2).await, "I1183 {what}: nothing stored");
        }
        // The stored-form `'unregistered'` is the wire `None`.
        let k3 = format!("i1183-unreg-{tag}");
        let mut r = pop_record(&k3);
        r.consent_role = Some("unregistered".to_owned());
        b.put_public_key(signed(r.clone()))
            .await
            .expect("I1183: 'unregistered' is admissible");
        let s3 = held(d, &k3).await;
        assert_eq!(s3.consent_role, None, "I1183: read back as None");
        assert!(
            self_consistent(&s3),
            "I1183: the hash is over the wire None, not the stored token"
        );
        b.put_public_key(signed(r))
            .await
            .expect("I1183: the same offer again settles (its hash is the stored one)");
        // The record's capability roles are stored as offered.
        let k5 = format!("i1183-roles-{tag}");
        let mut r = pop_record(&k5);
        r.capability_roles = vec!["substrate_persist".to_owned()];
        b.put_public_key(signed(r))
            .await
            .expect("I1183: a role-bearing record");
        assert_eq!(
            held(d, &k5).await.capability_roles,
            vec!["substrate_persist".to_owned()],
            "I1183: the roles are stored"
        );
        // CC 3.4.7.3 Clause A at a local mint.
        let k4 = format!("i1183-fused-{tag}");
        match b.put_public_key(signed(own(&k4, "node,user"))).await {
            Err(Error::NodeIdentityNotExclusive { .. }) => {}
            o => panic!("I1183: a fused local mint is refused, got {o:?}"),
        }
        assert!(absent(d, &k4).await, "I1183: the fused key is not stored");
    }

    /// I1184 — the genesis seed.
    pub(crate) async fn i1184_seed<B: KeyPlaneStore>(b: &B, tag: &str) {
        let d = b.as_dyn_directory();
        let k = format!("i1184-k-{tag}");
        let mut rec = pop_record(&k);
        let extra = ScrubSig {
            scrub_key_id: format!("i1184-cosigner-{tag}"),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            cosigned_at: None,
        };
        rec.additional_scrubs = vec![extra];
        key_plane::seed_genesis_accord_holders_planned(b, &[signed(rec.clone())])
            .await
            .expect("I1184: a baked record seeds");
        let stored = held(d, &k).await;
        assert_eq!(
            stored.additional_scrubs.len(),
            1,
            "I1184: the seed stores the whole scrub set"
        );
        assert!(
            self_consistent(&stored),
            "I1184: the seeded hash is the record's"
        );
        assert!(key_row(d, &k).await.is_some(), "I1184: and its row");
        let mut other = rec.clone();
        other.identity_ref = format!("reseeded-{tag}");
        key_plane::seed_genesis_accord_holders_planned(b, &[signed(other)])
            .await
            .expect("I1184: a second seed of a held key is not an error");
        assert_eq!(
            held(d, &k).await.persist_row_hash,
            stored.persist_row_hash,
            "I1184: the held record is kept"
        );
        let k2 = format!("i1184-alg-{tag}");
        let mut r = pop_record(&k2);
        r.algorithm = "ed25519".to_owned();
        assert!(matches!(
            key_plane::seed_genesis_accord_holders_planned(b, &[signed(r)]).await,
            Err(Error::InvalidArgument(_))
        ));
        assert!(
            absent(d, &k2).await,
            "I1184: a non-hybrid seed stores nothing"
        );
        let k3 = format!("i1184-fused-{tag}");
        assert!(matches!(
            key_plane::seed_genesis_accord_holders_planned(b, &[signed(own(&k3, "node,user"))])
                .await,
            Err(Error::NodeIdentityNotExclusive { .. })
        ));
        assert!(absent(d, &k3).await, "I1184: a fused seed stores nothing");
    }

    /// I1185 — the scrub upgrade.
    pub(crate) async fn i1185_scrub_upgrade<B: KeyPlaneStore>(b: &B, tag: &str) {
        let d = b.as_dyn_directory();
        let k = format!("i1185-k-{tag}");
        let s = format!("i1185-s-{tag}");
        let s2 = format!("i1185-t-{tag}");
        for key in [&k, &s, &s2] {
            b.put_public_key(signed(pop_record(key))).await.unwrap();
        }
        b.set_consent_role(&k, Some("peer")).await.unwrap();
        let before = held(d, &k).await;
        // Refusals first, each leaving the self-signed row where it was.
        let refusals: Vec<(&str, KeyRecord)> = vec![
            ("self-signed incoming", own(&k, identity_type::USER)),
            ("fused", anchored(&k, "node,user", &s)),
            ("node move", anchored(&k, identity_type::NODE, &s)),
            ("non-hybrid", {
                let mut r = anchored(&k, identity_type::USER, &s);
                r.algorithm = "ed25519".to_owned();
                r
            }),
            ("pubkey change", {
                let (ed, mldsa) = ts::hybrid_pubkeys(&s2);
                authority_signed_record(&k, identity_type::USER, &ed, mldsa.as_deref(), &s)
            }),
        ];
        for (what, r) in refusals {
            match b.adopt_scrub_upgrade(signed(r)).await {
                Err(
                    Error::InvalidArgument(_)
                    | Error::Conflict(_)
                    | Error::NodeIdentityNotExclusive { .. }
                    | Error::NodeIdentityImmutable { .. },
                ) => {}
                o => panic!("I1185 {what}: refused, got {o:?}"),
            }
            assert_eq!(
                held(d, &k).await.persist_row_hash,
                before.persist_row_hash,
                "I1185 {what}: the held record does not move"
            );
        }
        assert!(matches!(
            b.adopt_scrub_upgrade(signed(anchored(
                &format!("i1185-none-{tag}"),
                identity_type::USER,
                &s
            )))
            .await,
            Err(Error::InvalidArgument(_))
        ));
        let up = anchored(&k, identity_type::USER, &s);
        assert_eq!(
            b.adopt_scrub_upgrade(signed(up.clone())).await.unwrap(),
            AdoptScrubOutcome::Upgraded,
            "I1185: the self-signed row is re-rooted"
        );
        let after = held(d, &k).await;
        assert_eq!(after.scrub_key_id, s, "I1185: the anchor's scrub is stored");
        assert_eq!(
            after.consent_role.as_deref(),
            Some("peer"),
            "I1185: the local consent role is not rewritten"
        );
        let row = key_row(d, &k).await.expect("I1185: the row follows");
        assert_eq!(row.scrub_key_id, s, "I1185: the row is the anchored claim");
        assert_eq!(
            b.adopt_scrub_upgrade(signed(up)).await.unwrap(),
            AdoptScrubOutcome::AlreadyAdopted,
            "I1185: the same record again settles"
        );
        match b
            .adopt_scrub_upgrade(signed(anchored(&k, identity_type::USER, &s2)))
            .await
        {
            Err(Error::Conflict(m)) => assert!(m.contains("already anchored"), "I1185: {m}"),
            o => panic!("I1185: a second anchor is refused, got {o:?}"),
        }
        assert_eq!(
            held(d, &k).await.scrub_key_id,
            s,
            "I1185: still the first anchor"
        );
    }

    /// I1186 — the replicated apply.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub(crate) async fn i1186_replicated_apply<B: KeyPlaneStore>(b: &B, tag: &str) {
        use crate::federation::register::ReplicatedKeyOutcome as O;
        let d = b.as_dyn_directory();
        let k = format!("i1186-k-{tag}");
        let s = format!("i1186-s-{tag}");
        assert_eq!(
            b.apply_replicated_key_record(signed(pop_record(&s)))
                .await
                .unwrap(),
            O::Inserted,
            "I1186: a first sight inserts"
        );
        assert!(key_row(d, &s).await.is_some(), "I1186: with its row");
        assert_eq!(
            b.apply_replicated_key_record(signed(pop_record(&s)))
                .await
                .unwrap(),
            O::Unchanged,
            "I1186: a re-offer is unchanged"
        );
        // The upgrade arm: a self-signed node row, its single owner bound
        // (the #371 `owner_of` gate), then the anchor's record of it.
        let owner = format!("i1186-o-{tag}");
        ts::register_identity_key(d, &owner, identity_type::USER).await;
        let boot = ts::replicated_key_record(&k, identity_type::NODE, &k, &k, "v1");
        assert_eq!(
            b.apply_replicated_key_record(signed(boot)).await.unwrap(),
            O::Inserted
        );
        d.put_attestation(crate::federation::SignedAttestation {
            attestation: ts::owner_binding_attestation(
                &uuid::Uuid::new_v4().to_string(),
                &owner,
                &k,
            ),
        })
        .await
        .expect("I1186: the owner binding");
        let up = ts::replicated_key_record(&k, identity_type::NODE, &s, &s, "v1");
        assert_eq!(
            b.apply_replicated_key_record(signed(up.clone()))
                .await
                .unwrap(),
            O::Upgraded,
            "I1186: an anchored record over a self-signed row upgrades it"
        );
        assert_eq!(held(d, &k).await.scrub_key_id, s);
        assert_eq!(
            key_row(d, &k).await.map(|r| r.scrub_key_id),
            Some(s.clone()),
            "I1186: the row follows the upgrade"
        );
        assert_eq!(
            b.apply_replicated_key_record(signed(up)).await.unwrap(),
            O::Unchanged,
            "I1186: the upgraded record again is unchanged"
        );
        let f = format!("i1186-fused-{tag}");
        assert_eq!(
            b.apply_replicated_key_record(signed(own(&f, "node,user")))
                .await
                .unwrap(),
            O::Inserted,
            "I1186: a fused key minted elsewhere is admitted as data"
        );
    }

    /// I1189 — the re-anchor's own refusals.
    pub(crate) async fn i1189_reanchor_refusals<B: KeyPlaneStore>(b: &B) {
        use crate::federation::genesis::{self, bundle};
        let d = b.as_dyn_directory();
        key_plane::seed_genesis_accord_holders_planned(
            b,
            &genesis::effective_accord_holder_records(),
        )
        .await
        .expect("I1189: the holder roster seeds");
        let prior: Vec<SignedKeyRecord> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/canonical_seed_pre_ceremony.json"
        )))
        .expect("pre-ceremony seed fixture parses");
        for rec in prior {
            b.put_public_key(rec)
                .await
                .expect("I1189: the prior anchor");
        }
        genesis::seed_accord_family(b)
            .await
            .expect("I1189: the constitutional family");
        let artifact = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/genesis_v2.json"
        ));
        let report = bundle::bake_assembled_genesis(d, artifact)
            .await
            .expect("I1189: the real ceremony bakes");
        assert!(
            report
                .serve_nodes
                .iter()
                .all(|(_, o)| *o == bundle::BakeItemOutcome::ReAnchored),
            "I1189 precondition: the canonical is re-anchored: {:?}",
            report.serve_nodes
        );
        let parsed = bundle::parse_genesis_bundle(artifact).unwrap();
        let sn = parsed.serve_nodes[0].clone();
        let anchored = held(d, &sn.record.key_id).await;
        assert_eq!(
            anchored.registration_envelope, sn.record.registration_envelope,
            "I1189: the bake re-anchored the bundle's record"
        );
        assert_eq!(
            key_row(d, &sn.record.key_id).await.map(|r| r.scrub_key_id),
            Some(sn.record.scrub_key_id.clone()),
            "I1189: and its row follows"
        );
        match b.adopt_genesis_reanchor(sn.clone(), &parsed).await {
            Err(Error::GenesisBundleInvalid { detail }) if detail.contains("rollback refused") => {}
            o => panic!("I1189: the same record again is a rollback, got {o:?}"),
        }
        let mut uncarried = sn.clone();
        uncarried.record.registration_envelope["i1189"] = serde_json::json!("not in the bundle");
        match b.adopt_genesis_reanchor(uncarried, &parsed).await {
            Err(Error::GenesisBundleInvalid { detail }) if detail.contains("not carried") => {}
            o => panic!("I1189: a record the bundle does not carry is refused, got {o:?}"),
        }
        assert_eq!(
            held(d, &sn.record.key_id).await,
            anchored,
            "I1189: the anchored record does not move"
        );
    }

    /// I1190 — the canonical supersede's own decisions.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub(crate) async fn i1190_supersede<B: KeyPlaneStore>(b: &B, tag: &str) {
        use crate::federation::register::ReplicatedKeyOutcome as O;
        let d = b.as_dyn_directory();
        let (laundering, _clean) =
            crate::federation::admission::ungated_doors_test_support::seed_canonical_supersede_fixture(
                d, tag,
            )
            .await;
        let incumbent = held(d, &laundering.key_id).await;
        assert_eq!(
            key_plane::supersede_canonical_planned(b, signed(incumbent.clone()))
                .await
                .unwrap(),
            O::Unchanged,
            "I1190: a byte-identical re-offer settles before any verify"
        );
        let mut mldsa_only = incumbent.clone();
        mldsa_only.pubkey_ml_dsa_65_base64 = ts::hybrid_pubkeys(&format!("i1190-other-{tag}")).1;
        mldsa_only.registration_envelope["valid_from"] = "2026-07-01T00:00:00Z".into();
        match key_plane::supersede_canonical_planned(b, signed(mldsa_only)).await {
            Err(Error::Conflict(m)) => assert!(m.contains("pubkey change refused"), "I1190: {m}"),
            o => panic!("I1190: an ML-DSA key change alone is a pubkey change, got {o:?}"),
        }
        let mut older = incumbent.clone();
        older.registration_envelope["valid_from"] = "2025-01-01T00:00:00Z".into();
        match key_plane::supersede_canonical_planned(b, signed(older)).await {
            Err(Error::Conflict(m)) => {
                assert!(m.contains("supersede policy refused"), "I1190: {m}")
            }
            o => panic!("I1190: a successor the policy refuses is Conflict, got {o:?}"),
        }
        assert_eq!(
            held(d, &incumbent.key_id).await,
            incumbent,
            "I1190: the incumbent does not move"
        );
    }

    /// The executor run directly with a plan the held row no longer
    /// matches: nothing moves, and the refusal is the plan's wording.
    async fn stale<B: KeyPlaneStore>(
        b: &B,
        what: &str,
        planned: PlannedKeyRecord,
        expect: fn(&Error) -> bool,
    ) {
        let d = b.as_dyn_directory();
        let key_id = planned.key_id().to_owned();
        let before = d.lookup_public_key(&key_id).await.unwrap();
        let history = d.list_key_registration_history(&key_id).await.ok();
        match b.store_planned_key_record(planned).await {
            Err(e) if expect(&e) => {}
            o => panic!("I1187 {what}: refused as the plan words it, got {o:?}"),
        }
        assert_eq!(
            d.lookup_public_key(&key_id).await.unwrap(),
            before,
            "I1187 {what}: the held record does not move"
        );
        assert_eq!(
            d.list_key_registration_history(&key_id).await.ok(),
            history,
            "I1187 {what}: no history row"
        );
    }

    /// I1187 — the executor's atomic re-assertion, every write shape.
    pub(crate) async fn i1187_executor_guards<B: KeyPlaneStore>(b: &B, tag: &str) {
        let d = b.as_dyn_directory();
        let k = format!("i1187-k-{tag}");
        let s = format!("i1187-s-{tag}");
        let x = format!("i1187-x-{tag}");
        for key in [&k, &s] {
            b.put_public_key(signed(pop_record(key))).await.unwrap();
        }
        let selfsigned = held(d, &k).await;
        let mut up = anchored(&k, identity_type::USER, &s);
        up.persist_row_hash = compute_persist_row_hash(&up).unwrap();
        // The supersede's guard on a self-signed row, and on a stale version.
        let conflict = |e: &Error| matches!(e, Error::Conflict(m) if m.contains("concurrently"));
        stale(
            b,
            "anchored guard on a self-signed row",
            PlannedKeyRecord::Rewrite {
                record: up.clone(),
                guard: RewriteGuard::Anchored {
                    prior_hash: selfsigned.persist_row_hash.clone(),
                },
            },
            conflict,
        )
        .await;
        // The re-anchor's pubkey guard.
        let mut moved = up.clone();
        moved.pubkey_ed25519_base64 = held(d, &s).await.pubkey_ed25519_base64;
        stale(
            b,
            "re-anchor over another pubkey",
            PlannedKeyRecord::Rewrite {
                record: moved,
                guard: RewriteGuard::SamePubkey,
            },
            |e| matches!(e, Error::Backend(m) if m.contains("expected 1 row")),
        )
        .await;
        // The replace's hash guard.
        stale(
            b,
            "replace against a stale hash",
            PlannedKeyRecord::Replace {
                record: up.clone(),
                existing_hash: "0".repeat(64),
                kind: KeyReplacementKind::InvalidReplaced,
            },
            conflict,
        )
        .await;
        // The scrub rehydrate's hash guard.
        stale(
            b,
            "rehydrate against another hash",
            PlannedKeyRecord::RehydrateScrubs { record: up.clone() },
            conflict,
        )
        .await;
        // The upgrade lands under its own guard, then a second upgrade
        // plan (made while the row was self-signed) finds it anchored.
        b.store_planned_key_record(PlannedKeyRecord::Rewrite {
            record: up.clone(),
            guard: RewriteGuard::SelfSigned,
        })
        .await
        .expect("I1187: the upgrade's own guard holds on a self-signed row");
        let anchored_now = held(d, &k).await;
        assert_eq!(anchored_now.scrub_key_id, s);
        stale(
            b,
            "self-signed guard on an anchored row",
            PlannedKeyRecord::Rewrite {
                record: up.clone(),
                guard: RewriteGuard::SelfSigned,
            },
            conflict,
        )
        .await;
        // The supersede's guard on an anchored row: a stale version is
        // refused, the version the plan saw lands.
        let mut successor = anchored(&k, identity_type::USER, &s);
        successor.identity_ref = format!("successor-{tag}");
        successor.persist_row_hash = compute_persist_row_hash(&successor).unwrap();
        stale(
            b,
            "anchored guard on a stale version",
            PlannedKeyRecord::Rewrite {
                record: successor.clone(),
                guard: RewriteGuard::Anchored {
                    prior_hash: "0".repeat(64),
                },
            },
            conflict,
        )
        .await;
        b.store_planned_key_record(PlannedKeyRecord::Rewrite {
            record: successor.clone(),
            guard: RewriteGuard::Anchored {
                prior_hash: anchored_now.persist_row_hash.clone(),
            },
        })
        .await
        .expect("I1187: the anchored guard holds on the version the plan saw");
        assert_eq!(
            held(d, &k).await.identity_ref,
            successor.identity_ref,
            "I1187: the successor is stored"
        );
        let anchored_now = held(d, &k).await;
        // A rebind requires a self-signed row even at the right hash.
        stale(
            b,
            "rebind of an anchored row",
            PlannedKeyRecord::Replace {
                record: up.clone(),
                existing_hash: anchored_now.persist_row_hash.clone(),
                kind: KeyReplacementKind::Rebind,
            },
            conflict,
        )
        .await;
        // The hybrid completion's guard: the row is already complete.
        stale(
            b,
            "complete a completed row",
            PlannedKeyRecord::CompletePqc {
                key_id: k.clone(),
                pubkey_ml_dsa_65_base64: "AAAA".to_owned(),
                scrub_signature_pqc: "AAAA".to_owned(),
                completed_at: chrono::Utc::now(),
                persist_row_hash: "0".repeat(64),
            },
            conflict,
        )
        .await;
        // An insert over a differing held row is Conflict; over the same
        // record, or with Keep, it stands.
        let mut differing = pop_record(&s);
        differing.identity_ref = format!("other-{tag}");
        differing.persist_row_hash = compute_persist_row_hash(&differing).unwrap();
        stale(
            b,
            "insert over a differing held row",
            PlannedKeyRecord::Insert {
                record: differing.clone(),
                on_held: OnHeld::Conflict,
            },
            |e| matches!(e, Error::Conflict(m) if m.contains("different content")),
        )
        .await;
        let s_held = held(d, &s).await;
        b.store_planned_key_record(PlannedKeyRecord::Insert {
            record: differing,
            on_held: OnHeld::Keep,
        })
        .await
        .expect("I1187: Keep stands over a held row");
        b.store_planned_key_record(PlannedKeyRecord::Insert {
            record: s_held.clone(),
            on_held: OnHeld::Conflict,
        })
        .await
        .expect("I1187: an identical held row stands");
        assert_eq!(held(d, &s).await, s_held, "I1187: and nothing moved");
        // The scrub rehydrate lands on a stranded row (the hash binds the
        // whole scrub set, the column is empty) and only there.
        let r = format!("i1187-r-{tag}");
        let mut full = pop_record(&r);
        full.additional_scrubs = vec![ScrubSig {
            scrub_key_id: format!("i1187-cosigner-{tag}"),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            cosigned_at: None,
        }];
        full.persist_row_hash = compute_persist_row_hash(&full).unwrap();
        let mut stranded = full.clone();
        stranded.additional_scrubs.clear();
        b.store_planned_key_record(PlannedKeyRecord::Insert {
            record: stranded,
            on_held: OnHeld::Conflict,
        })
        .await
        .unwrap();
        b.store_planned_key_record(PlannedKeyRecord::RehydrateScrubs {
            record: full.clone(),
        })
        .await
        .expect("I1187: the stranded row is rehydrated");
        assert_eq!(
            held(d, &r).await.additional_scrubs,
            full.additional_scrubs,
            "I1187: the scrub set is back"
        );
        stale(
            b,
            "rehydrate a row that carries its scrubs",
            PlannedKeyRecord::RehydrateScrubs { record: full },
            conflict,
        )
        .await;
        // A fresh insert lands, admitted, with its row.
        let mut fresh = pop_record(&x);
        fresh.persist_row_hash = compute_persist_row_hash(&fresh).unwrap();
        b.store_planned_key_record(PlannedKeyRecord::Insert {
            record: fresh,
            on_held: OnHeld::Conflict,
        })
        .await
        .unwrap();
        assert!(
            key_row(d, &x).await.is_some(),
            "I1187: a fresh insert has its row"
        );
    }

    /// The plan settles a byte-identical re-offer without a write, on every
    /// door that can: the door reports `Settled`.
    pub(crate) async fn i1187_settled<B: KeyPlaneStore>(b: &B, tag: &str) {
        let k = format!("i1187-settle-{tag}");
        b.put_public_key(signed(pop_record(&k))).await.unwrap();
        assert_eq!(
            key_plane::key_record_write_planned(
                b,
                KeyRecordWrite::Put {
                    record: pop_record(&k),
                    door: crate::federation::register::KeyDoor::LocalMint,
                },
            )
            .await
            .unwrap(),
            KeyRecordWritten::Settled
        );
    }
}

#[cfg(test)]
mod unit {
    use crate::federation::key_plane::{
        key_record_row_step, KeyRecordRowStep, OnHeld, PlannedKeyRecord, RewriteGuard,
    };
    use crate::federation::key_plane_invariants::bodies::pop_record;
    use crate::federation::types::{compute_persist_row_hash, KeyRecord, KeyReplacementKind};
    use crate::federation::Error;

    fn hashed(key_id: &str) -> KeyRecord {
        let mut r = pop_record(key_id);
        r.persist_row_hash = compute_persist_row_hash(&r).unwrap();
        r
    }

    /// I1188 — the row step.
    #[test]
    fn i1188_the_row_step() {
        let r = hashed("i1188-row-step-key-aaaaaaaaaaaaaaaa");
        let KeyRecordRowStep::Replace(Some(row)) = key_record_row_step(Some(&r), None, &None)
        else {
            panic!("I1188: a record that proves possession plans its row");
        };
        assert_eq!(
            key_record_row_step(Some(&r), Some(&row.attestation_id), &None),
            KeyRecordRowStep::Keep,
            "I1188: the pointer already names it"
        );
        assert_eq!(
            key_record_row_step(Some(&r), Some("another-row"), &None),
            KeyRecordRowStep::Replace(Some(row)),
            "I1188: any other row is replaced"
        );
        assert_eq!(
            key_record_row_step(None, Some("a-gone-key's-row"), &None),
            KeyRecordRowStep::Replace(None),
            "I1188: a gone key's rows leave"
        );
        let mut forged = r.clone();
        forged.scrub_key_id = "i1188-unheld-signer-bbbbbbbbbbbbbbbb".to_owned();
        assert_eq!(
            key_record_row_step(Some(&forged), Some("its-old-row"), &None),
            KeyRecordRowStep::Replace(None),
            "I1188: an unverifiable record is held without a row"
        );
    }

    /// I1188 — every lost race in the plan's one wording.
    #[test]
    fn i1188_the_race_wording() {
        let r = hashed("i1188-race-wording-key-cccccccccccc");
        let rewrite = |guard| PlannedKeyRecord::Rewrite {
            record: r.clone(),
            guard,
        };
        let conflict = |p: &PlannedKeyRecord, needle: &str| match p.raced(0) {
            Some(Error::Conflict(m)) => {
                assert!(m.contains(needle) && m.contains(&r.key_id), "I1188: {m}")
            }
            o => panic!("I1188: {needle}: Conflict, got {o:?}"),
        };
        let shapes = [
            (rewrite(RewriteGuard::SelfSigned), "adopt_scrub_upgrade"),
            (
                rewrite(RewriteGuard::Anchored {
                    prior_hash: "h".to_owned(),
                }),
                "supersede_canonical_record",
            ),
            (
                PlannedKeyRecord::Replace {
                    record: r.clone(),
                    existing_hash: "h".to_owned(),
                    kind: KeyReplacementKind::Rebind,
                },
                "rebind key registration",
            ),
            (
                PlannedKeyRecord::CompletePqc {
                    key_id: r.key_id.clone(),
                    pubkey_ml_dsa_65_base64: String::new(),
                    scrub_signature_pqc: String::new(),
                    completed_at: chrono::Utc::now(),
                    persist_row_hash: String::new(),
                },
                "concurrently completed",
            ),
            (
                PlannedKeyRecord::RehydrateScrubs { record: r.clone() },
                "rehydrate_dropped_key_scrubs",
            ),
        ];
        for (p, needle) in &shapes {
            conflict(p, needle);
            assert!(p.raced(1).is_none(), "I1188: {needle}: one row landed");
            assert!(p.raced(2).is_none(), "I1188: {needle}: rows landed");
        }
        let reanchor = rewrite(RewriteGuard::SamePubkey);
        assert!(
            reanchor.raced(1).is_none(),
            "I1188: the re-anchor wrote one row"
        );
        for n in [0, 2] {
            match reanchor.raced(n) {
                Some(Error::Backend(m)) => {
                    assert!(m.contains(&format!("got {n}")), "I1188: {m}")
                }
                o => panic!("I1188: re-anchor {n} rows: Backend, got {o:?}"),
            }
        }
        let insert = |on_held| PlannedKeyRecord::Insert {
            record: r.clone(),
            on_held,
        };
        assert!(insert(OnHeld::Conflict).raced(0).is_none());
        assert!(insert(OnHeld::Conflict).insert_held(None).is_ok());
        assert!(insert(OnHeld::Conflict)
            .insert_held(Some(&r.persist_row_hash))
            .is_ok());
        assert!(matches!(
            insert(OnHeld::Conflict).insert_held(Some("other")),
            Err(Error::Conflict(m)) if m.contains("different content")
        ));
        assert!(insert(OnHeld::Keep).insert_held(Some("other")).is_ok());
        for p in shapes.iter().map(|(p, _)| p) {
            assert!(p.insert_held(Some("other")).is_ok(), "I1188: not an insert");
        }
    }
}

#[cfg(test)]
mod backends {
    use super::bodies;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::store::Backend as _;

    fn tag(n: &str) -> String {
        format!("{n}-{}", uuid::Uuid::new_v4().simple())
    }

    // ── memory ─────────────────────────────────────────────────────────
    #[tokio::test(flavor = "multi_thread")]
    async fn i1183_put_memory() {
        bodies::i1183_put(&crate::store::memory::MemoryBackend::new(), &tag("m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1184_seed_memory() {
        bodies::i1184_seed(&crate::store::memory::MemoryBackend::new(), &tag("m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1185_scrub_upgrade_memory() {
        bodies::i1185_scrub_upgrade(&crate::store::memory::MemoryBackend::new(), &tag("m")).await;
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1186_replicated_apply_memory() {
        bodies::i1186_replicated_apply(&crate::store::memory::MemoryBackend::new(), &tag("m"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1187_executor_guards_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        bodies::i1187_executor_guards(&b, &tag("m")).await;
        bodies::i1187_settled(&b, &tag("m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i1189_reanchor_refusals_memory() {
        bodies::i1189_reanchor_refusals(&crate::store::memory::MemoryBackend::new()).await;
    }

    // ── sqlite ─────────────────────────────────────────────────────────
    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1183_put_sqlite() {
        bodies::i1183_put(&sqlite().await, &tag("s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1184_seed_sqlite() {
        bodies::i1184_seed(&sqlite().await, &tag("s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1185_scrub_upgrade_sqlite() {
        bodies::i1185_scrub_upgrade(&sqlite().await, &tag("s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1186_replicated_apply_sqlite() {
        bodies::i1186_replicated_apply(&sqlite().await, &tag("s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1187_executor_guards_sqlite() {
        let b = sqlite().await;
        bodies::i1187_executor_guards(&b, &tag("s")).await;
        bodies::i1187_settled(&b, &tag("s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1189_reanchor_refusals_sqlite() {
        bodies::i1189_reanchor_refusals(&sqlite().await).await;
    }

    // ── postgres ───────────────────────────────────────────────────────
    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("key_record_plan postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return None;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1183_put_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1183_put(&b, &tag("p")).await;
        eprintln!("i1183_put_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1184_seed_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1184_seed(&b, &tag("p")).await;
        eprintln!("i1184_seed_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1185_scrub_upgrade_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1185_scrub_upgrade(&b, &tag("p")).await;
        eprintln!("i1185_scrub_upgrade_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1186_replicated_apply_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1186_replicated_apply(&b, &tag("p")).await;
        eprintln!("i1186_replicated_apply_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1187_executor_guards_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1187_executor_guards(&b, &tag("p")).await;
        bodies::i1187_settled(&b, &tag("p")).await;
        eprintln!("i1187_executor_guards_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1189_reanchor_refusals_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1189_reanchor_refusals(&b).await;
        eprintln!("i1189_reanchor_refusals_postgres: RAN");
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1190_supersede_memory() {
        bodies::i1190_supersede(&crate::store::memory::MemoryBackend::new(), &tag("m")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1190_supersede_sqlite() {
        bodies::i1190_supersede(&sqlite().await, &tag("s")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1190_supersede_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i1190_supersede(&b, &tag("p")).await;
        eprintln!("i1190_supersede_postgres: RAN");
    }
}
