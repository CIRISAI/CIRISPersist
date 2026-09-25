//! v49.0.0 (CIRISPersist#910; `FSD/ROOM_ROSTER_AUTHORITY.md` §10) — **a
//! family's roster converges both ways, and a family change is judged by the
//! family's own protocol.**
//!
//! I177 — a family widening converges across two directories through the
//! signed since-read (B applies A's rows; B's fold = A's; B's record is the
//! original), and a removed family member is re-added and active again, then
//! removed again (#910.1). I179 — family standing is the family's protocol
//! (I171's arms on the family plane), and `verify_membership_quorum`'s prior
//! roster is the fold, not the raw record (#910.2).

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::cohort::Cohort;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        consensus_protocol, identity_type, Family, FamilyMember, FamilyMembershipRevocation,
        FamilyMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    fn widening(
        fam: &str,
        member: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
        role: Option<&str>,
    ) -> FamilyMembershipWidening {
        FamilyMembershipWidening {
            family_key_id: fam.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: effective_at,
            effective_at,
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        }
    }

    fn revocation(
        fam: &str,
        member: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
    ) -> FamilyMembershipRevocation {
        FamilyMembershipRevocation {
            family_key_id: fam.to_owned(),
            removed_identity_key_id: member.to_owned(),
            removed_at: effective_at,
            effective_at,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        }
    }

    async fn user(d: &dyn FederationDirectory, k: &str) {
        ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
    }

    /// The signed record of a family of `keys`, the first `founders` of them
    /// tagged `founder`, under `protocol`, signed by the first member. The
    /// family id is no key (the doctrine: a family is keyless).
    fn family_record(
        fam: &str,
        keys: &[String],
        founders: usize,
        protocol: &str,
    ) -> crate::federation::SignedFamily {
        ts::sign_family(
            &keys[0],
            Family {
                family_key_id: fam.to_owned(),
                family_name: "household".into(),
                members: keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| FamilyMember {
                        key_id: k.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: (i < founders).then(|| "founder".to_owned()),
                    })
                    .collect(),
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: protocol.to_owned(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        )
    }

    /// A family `{tag}-{fam_name}` of `names` (registered user keys
    /// `{name}-{tag}` — the distinguishing part LEADS: the test signer seeds
    /// from a key id's first 32 bytes, and a uuid tag in front would give
    /// every member one keypair) on `d`. Returns the family id and the member
    /// key ids.
    async fn make_family(
        d: &dyn FederationDirectory,
        tag: &str,
        fam_name: &str,
        protocol: &str,
        names: &[&str],
        founders: usize,
    ) -> (String, Vec<String>) {
        let fam = format!("{tag}-{fam_name}");
        let keys: Vec<String> = names.iter().map(|n| format!("{n}-{tag}")).collect();
        for k in &keys {
            user(d, k).await;
        }
        d.put_family(family_record(&fam, &keys, founders, protocol))
            .await
            .unwrap_or_else(|e| panic!("{tag}: family {fam}: {e}"));
        (fam, keys)
    }

    /// A widening signed by `signers[0]` and co-signed by the rest.
    async fn widen_by(
        d: &dyn FederationDirectory,
        signers: &[&str],
        w: FamilyMembershipWidening,
    ) -> Result<(), Error> {
        let mut s = ts::sign_family_membership_widening(signers[0], w);
        for c in &signers[1..] {
            ts::cosign_family_membership_widening(&mut s, c);
        }
        d.put_family_membership_widening(s).await
    }

    /// A revocation signed by `signers[0]` and co-signed by the rest.
    async fn revoke_by(
        d: &dyn FederationDirectory,
        signers: &[&str],
        r: FamilyMembershipRevocation,
    ) -> Result<(), Error> {
        let mut s = ts::sign_family_membership_revocation(signers[0], r);
        for c in &signers[1..] {
            ts::cosign_family_membership_revocation(&mut s, c);
        }
        d.put_family_membership_revocation(s).await
    }

    async fn active(d: &dyn FederationDirectory, fam: &str) -> Vec<String> {
        let mut v: Vec<String> = d
            .active_family_members(fam)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        v.sort();
        v
    }

    async fn record_hash(d: &dyn FederationDirectory, fam: &str) -> String {
        d.lookup_family(fam)
            .await
            .unwrap()
            .expect("family")
            .persist_row_hash
    }

    fn rule_of(e: &Error) -> &'static str {
        match e {
            Error::RosterAuthorityUnauthorized { rule, .. } => rule,
            other => panic!("expected RosterAuthorityUnauthorized, got {other}"),
        }
    }

    /// Is `member` admitted to `fam` by every family admission reader?
    async fn admitted(d: &dyn FederationDirectory, member: &str, fam: &str) -> bool {
        let adm =
            crate::scope::admission::build_caller_admission_from_directory(d, &member.to_owned())
                .await
                .unwrap();
        let by_admission = adm.family_key_ids.contains(fam);
        let by_active = d
            .list_families_for_member_active(member)
            .await
            .unwrap()
            .iter()
            .any(|f| f.family_key_id == fam);
        let by_ids = d
            .active_family_key_ids_for(member)
            .await
            .unwrap()
            .iter()
            .any(|f| f == fam);
        let by_groups = d
            .groups_of(Cohort::Family, member)
            .await
            .unwrap()
            .iter()
            .any(|g| g.group_key_id == fam);
        assert!(
            by_admission == by_active && by_active == by_ids && by_ids == by_groups,
            "every family admission reader must agree for {member} in {fam}: \
             admission={by_admission} active={by_active} ids={by_ids} groups={by_groups}"
        );
        by_admission
    }

    /// Apply every row A serves on the family planes to B, through the signed
    /// since-reads and the replicated doors — widenings first, then
    /// revocations, the order a replicator that pages planes one by one uses.
    async fn replicate_family_planes(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        fam: &str,
    ) {
        for w in a
            .list_signed_family_membership_widenings_since(None, u32::MAX)
            .await
            .unwrap()
        {
            if w.widening.family_membership_widening.family_key_id == fam {
                b.put_family_membership_widening(w.widening)
                    .await
                    .unwrap_or_else(|e| panic!("B must admit A's served widening: {e}"));
            }
        }
        for r in a
            .list_signed_family_membership_revocations_since(None, u32::MAX)
            .await
            .unwrap()
        {
            if r.revocation.family_membership_revocation.family_key_id == fam {
                b.put_family_membership_revocation(r.revocation)
                    .await
                    .unwrap_or_else(|e| panic!("B must admit A's served revocation: {e}"));
            }
        }
    }

    /// **I177 — a family widening converges, and a removed member comes back.**
    pub async fn i177_a_family_widening_converges(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let names = ["alice", "bob", "carol"];
        let keys: Vec<String> = names.iter().map(|n| format!("{n}-{tag}")).collect();
        let (alice, bob, carol) = (&keys[0], &keys[1], &keys[2]);
        for d in [a, b] {
            for k in &keys {
                user(d, k).await;
            }
        }
        let fam = format!("{tag}-fam");
        // The founding record names alice (founder) and bob; carol is not on
        // it. Both nodes hold the same signed record (replicated).
        let record = family_record(&fam, &keys[..2], 1, consensus_protocol::FOUNDER_ONLY);
        for d in [a, b] {
            d.put_family(record.clone())
                .await
                .unwrap_or_else(|e| panic!("{tag}: family: {e}"));
        }
        let original_hash = record_hash(a, &fam).await;
        assert_eq!(
            record_hash(b, &fam).await,
            original_hash,
            "{tag}: one record"
        );
        assert!(
            !admitted(a, carol, &fam).await,
            "{tag} I177 control: before the widening carol is not admitted"
        );

        // (1) alice widens carol through the LOCAL door onto the plane.
        let t1 = at("2026-02-01T00:00:00Z");
        let carol_row = FamilyMember {
            key_id: carol.clone(),
            joined_at: t1,
            role: None,
        };
        let spec = ts::family_widening_admit_spec(alice, &fam, &carol_row);
        assert!(
            a.add_family_member(&fam, carol_row.clone(), &spec)
                .await
                .unwrap_or_else(|e| panic!("{tag} I177: the founder widens carol: {e}")),
            "{tag} I177: a genuine add"
        );
        assert!(
            !a.add_family_member(&fam, carol_row, &spec).await.unwrap(),
            "{tag} I177: the same row again is the idempotent no-op"
        );
        assert_eq!(
            record_hash(a, &fam).await,
            original_hash,
            "{tag} I177: the family record is never rewritten to grow"
        );
        assert_eq!(active(a, &fam).await, {
            let mut v = vec![alice.clone(), bob.clone(), carol.clone()];
            v.sort();
            v
        });
        assert!(
            admitted(a, carol, &fam).await,
            "{tag} I177: carol is in on A"
        );

        // (2) B applies A's served rows: admitted, and the folds agree.
        replicate_family_planes(a, b, &fam).await;
        assert_eq!(
            active(b, &fam).await,
            active(a, &fam).await,
            "{tag} I177: B's fold is A's"
        );
        assert_eq!(
            record_hash(b, &fam).await,
            original_hash,
            "{tag} I177: B's record is unchanged (no fork, no rewrite)"
        );
        assert!(
            admitted(b, carol, &fam).await,
            "{tag} I177: carol is in on B"
        );

        // (3) #910.1 — removed, re-added, removed again: every event is its
        // own row, and the fold follows the history on both nodes.
        let (t2, t3, t4) = (
            at("2026-03-01T00:00:00Z"),
            at("2026-04-01T00:00:00Z"),
            at("2026-05-01T00:00:00Z"),
        );
        revoke_by(a, &[alice], revocation(&fam, carol, t2))
            .await
            .unwrap_or_else(|e| panic!("{tag} I177: the founder removes carol: {e}"));
        assert!(!admitted(a, carol, &fam).await, "{tag} I177: removed");
        widen_by(a, &[alice], widening(&fam, carol, t3, None))
            .await
            .unwrap_or_else(|e| panic!("{tag} I177: a removed member can be re-added: {e}"));
        assert!(
            admitted(a, carol, &fam).await,
            "{tag} I177 (#910.1): the re-added member is active again"
        );
        revoke_by(a, &[alice], revocation(&fam, carol, t4))
            .await
            .unwrap_or_else(|e| panic!("{tag} I177: a re-added member can be removed again: {e}"));
        assert!(!admitted(a, carol, &fam).await, "{tag} I177: removed again");
        assert_eq!(
            a.list_family_membership_revocations_for(&fam)
                .await
                .unwrap()
                .iter()
                .filter(|r| &r.removed_identity_key_id == carol)
                .count(),
            2,
            "{tag} I177 (#910.1): two removals of one member are two rows"
        );
        // The exact retry of a stored removal is still the #861 no-op.
        revoke_by(a, &[alice], revocation(&fam, carol, t4))
            .await
            .unwrap_or_else(|e| panic!("{tag} I177: the #861 retry is Ok: {e}"));
        assert_eq!(
            a.list_family_membership_revocations_for(&fam)
                .await
                .unwrap()
                .len(),
            2,
            "{tag} I177: the exact retry stored nothing"
        );

        // …and B converges on the whole history, at every instant.
        replicate_family_planes(a, b, &fam).await;
        for (when, carol_in) in [
            (at("2026-02-15T00:00:00Z"), true),
            (at("2026-03-15T00:00:00Z"), false),
            (at("2026-04-15T00:00:00Z"), true),
            (at("2026-05-15T00:00:00Z"), false),
        ] {
            for (node, d) in [("A", a), ("B", b)] {
                let f = d.lookup_family(&fam).await.unwrap().expect("family");
                let roster = crate::federation::authorized_family_roster_at(d, &f, when)
                    .await
                    .unwrap();
                assert_eq!(
                    roster.iter().any(|m| &m.key_id == carol),
                    carol_in,
                    "{tag} I177: on {node} at {when} carol is {}",
                    if carol_in { "in" } else { "out" }
                );
            }
        }
        assert_eq!(
            record_hash(b, &fam).await,
            original_hash,
            "{tag} I177: still one record"
        );
    }

    /// **I179 — family standing is the family's protocol.**
    pub async fn i179_family_standing_is_the_protocol(d: &dyn FederationDirectory, tag: &str) {
        let now_ish = at("2026-02-01T00:00:00Z");

        // founder_only: a plain member is refused; the founder is admitted.
        let (fo, k) = make_family(
            d,
            tag,
            "fo",
            consensus_protocol::FOUNDER_ONLY,
            &["fo-alice", "fo-bob"],
            1,
        )
        .await;
        let newbie = format!("newbie-{tag}");
        let stranger = format!("stranger-{tag}");
        for x in [&newbie, &stranger] {
            user(d, x).await;
        }
        let e = widen_by(d, &[&k[1]], widening(&fo, &newbie, now_ish, None))
            .await
            .expect_err("founder_only: a plain member cannot widen");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            "{tag} I179"
        );
        assert!(
            !active(d, &fo).await.contains(&newbie),
            "{tag} I179: a refused widening stores no row"
        );
        // A stranger's valid signature: the retryable not-established rule.
        let e = widen_by(d, &[&stranger], widening(&fo, &newbie, now_ish, None))
            .await
            .expect_err("a stranger cannot widen");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED,
            "{tag} I179: a signer with no event in the family is not-established"
        );
        widen_by(d, &[&k[0]], widening(&fo, &newbie, now_ish, None))
            .await
            .unwrap_or_else(|e| panic!("{tag} I179: the founder widens: {e}"));
        assert!(active(d, &fo).await.contains(&newbie), "{tag} I179");
        // The last founder may not leave a family that keeps members.
        let e = revoke_by(
            d,
            &[&k[0]],
            revocation(&fo, &k[0], at("2026-02-02T00:00:00Z")),
        )
        .await
        .expect_err("the last founder may not leave");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_LAST_FOUNDER,
            "{tag} I179"
        );
        // #910.4 — a role change rides the plane: the same member with a
        // different role is a new widening, judged by the protocol; the same
        // role again is the no-op. Promoted, bob is a founder, so alice is no
        // longer the last one and may leave.
        let promote = FamilyMember {
            key_id: k[1].clone(),
            joined_at: at("2026-02-03T00:00:00Z"),
            role: Some("founder".to_owned()),
        };
        let spec = ts::family_widening_admit_spec(&k[0], &fo, &promote);
        assert!(
            d.add_family_member(&fo, promote.clone(), &spec)
                .await
                .unwrap_or_else(|e| panic!("{tag} I179: the founder promotes bob: {e}")),
            "{tag} I179 (#910.4): a role change is a genuine change"
        );
        let again = FamilyMember {
            joined_at: at("2026-02-04T00:00:00Z"),
            ..promote
        };
        let spec = ts::family_widening_admit_spec(&k[0], &fo, &again);
        assert!(
            !d.add_family_member(&fo, again, &spec).await.unwrap(),
            "{tag} I179 (#910.4): the same role again is the no-op"
        );
        assert_eq!(
            d.lookup_family(&fo).await.unwrap().unwrap().members.len(),
            2,
            "{tag} I179: a role change never rewrites the record"
        );
        revoke_by(
            d,
            &[&k[0]],
            revocation(&fo, &k[0], at("2026-02-05T00:00:00Z")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I179: with bob a founder, alice may leave: {e}"));
        assert!(!active(d, &fo).await.contains(&k[0]), "{tag} I179");
        // A stranger cannot remove a member either.
        let e = revoke_by(
            d,
            &[&stranger],
            revocation(&fo, &k[1], at("2026-02-02T00:00:00Z")),
        )
        .await
        .expect_err("a stranger cannot remove");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED,
            "{tag} I179"
        );
        assert!(
            active(d, &fo).await.contains(&k[1]),
            "{tag} I179: a refused revocation stores no row"
        );

        // majority of three: one signature refused, two (a co-signature)
        // admitted; a member leaving needs no one.
        let (mj, m) = make_family(
            d,
            tag,
            "mj",
            consensus_protocol::MAJORITY,
            &["mj-a", "mj-b", "mj-c"],
            0,
        )
        .await;
        let e = widen_by(d, &[&m[0]], widening(&mj, &newbie, now_ish, None))
            .await
            .expect_err("majority: one of three is not a majority");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            "{tag} I179"
        );
        widen_by(d, &[&m[0], &m[1]], widening(&mj, &newbie, now_ish, None))
            .await
            .unwrap_or_else(|e| panic!("{tag} I179: two of three is a majority: {e}"));
        assert!(active(d, &mj).await.contains(&newbie), "{tag} I179");
        revoke_by(
            d,
            &[&m[2]],
            revocation(&mj, &m[2], at("2026-02-02T00:00:00Z")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I179: a member leaves on their own signature: {e}"));
        assert!(
            !active(d, &mj).await.contains(&m[2]),
            "{tag} I179: the member who left is gone"
        );

        // unanimous: all but one refused, all admitted.
        let (un, u) = make_family(
            d,
            tag,
            "un",
            consensus_protocol::UNANIMOUS,
            &["un-a", "un-b", "un-c"],
            0,
        )
        .await;
        let e = widen_by(d, &[&u[0], &u[1]], widening(&un, &newbie, now_ish, None))
            .await
            .expect_err("unanimous: all but one is not unanimous");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            "{tag} I179"
        );
        widen_by(
            d,
            &[&u[0], &u[1], &u[2]],
            widening(&un, &newbie, now_ish, None),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I179: every member signed: {e}"));
        assert!(active(d, &un).await.contains(&newbie), "{tag} I179");

        // The local door carries co-signatures too (AdmitSpec.cosignatures).
        let (lm, l) = make_family(
            d,
            tag,
            "lm",
            consensus_protocol::MAJORITY,
            &["lm-a", "lm-b", "lm-c"],
            0,
        )
        .await;
        let row = FamilyMember {
            key_id: newbie.clone(),
            joined_at: now_ish,
            role: None,
        };
        let alone = ts::family_widening_admit_spec(&l[0], &lm, &row);
        let e = d
            .add_family_member(&lm, row.clone(), &alone)
            .await
            .expect_err("add_family_member is judged by the protocol");
        assert_eq!(
            rule_of(&e),
            crate::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            "{tag} I179"
        );
        let quorum = ts::family_widening_admit_spec_by_consensus(d, &lm, &row).await;
        assert_eq!(quorum.cosignatures.len(), 1, "{tag}: two of three sign");
        assert!(d.add_family_member(&lm, row, &quorum).await.unwrap());
        assert!(active(d, &lm).await.contains(&newbie), "{tag} I179");

        // #910.2 — verify_membership_quorum's prior roster is the FOLD. q3 is
        // removed by a revocation row alone (q3 leaves); the record still
        // names three members.
        let (qf, q) = make_family(
            d,
            tag,
            "qf",
            consensus_protocol::MAJORITY,
            &["q1", "q2", "q3"],
            0,
        )
        .await;
        revoke_by(
            d,
            &[&q[2]],
            revocation(&qf, &q[2], at("2026-02-02T00:00:00Z")),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I179: q3 leaves: {e}"));
        assert_eq!(
            d.lookup_family(&qf).await.unwrap().unwrap().members.len(),
            3,
            "{tag} I179: the record is untouched"
        );
        let change = d
            .build_membership_change_envelope(
                Cohort::Family,
                &qf,
                &[q[0].clone(), q[1].clone(), newbie.clone()],
                false,
                Some(consensus_protocol::MAJORITY),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I179: build change: {e}"));
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        // Under the raw record q1 + q3 would be two of three — a majority. q3
        // is off the fold, so their signature counts for nothing: one of two.
        let e = d
            .verify_membership_quorum(
                Cohort::Family,
                &qf,
                &change,
                &[
                    ts::threshold_sign(&q[0], &bytes),
                    ts::threshold_sign(&q[2], &bytes),
                ],
            )
            .await
            .expect_err("a removed member no longer counts toward the quorum");
        assert!(
            e.to_string().contains("not authorized"),
            "{tag} I179 (#910.2): refused by the protocol over the fold: {e}"
        );
        d.verify_membership_quorum(
            Cohort::Family,
            &qf,
            &change,
            &[
                ts::threshold_sign(&q[0], &bytes),
                ts::threshold_sign(&q[1], &bytes),
            ],
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I179: two of the fold's two admit: {e}"));
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i177() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i177_a_family_widening_converges(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &format!("i177-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i179() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i179_family_standing_is_the_protocol(
                        &d as &dyn FederationDirectory,
                        &format!("i179-{}", super::suffix()),
                    )
                    .await
                }
            }
        };
    }

    dyn_runners!(memory_dyn, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite_dyn, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres_dyn, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
