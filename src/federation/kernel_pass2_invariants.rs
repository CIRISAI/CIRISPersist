//! v62.0.0 (kernel pass 2, K1) — **I2811–I2816: forks held as tips, the
//! answer's read set, and a key's end through the kernel.** The backend
//! bodies run on sqlite and on postgres.
//!
//! - **I2811** (CC 2.7.8, "Two versions of one head wait as tips") — a
//!   version of a held family that names another version than the head (a
//!   sibling of the head) is held as a tip, not refused: the supersede is
//!   `Ok` at the head's version, the head does not move, the tip is listed
//!   once however often it is offered, and it is in no version history.
//! - **I2812** (CC 2.7.8, a row waiting for the head it names) — a version
//!   offered before its predecessor is held as a tip; once the predecessor
//!   is the head, the same version offered again extends it and leaves the
//!   tips.
//! - **I2813** (pure) — the held-head verdict, by truth table: a successor
//!   extends; a sibling, a second founding version and a version naming an
//!   unheld one are tips; a proof naming the version's own prior rides with
//!   it; a proof naming another prior than the version's is refused (the
//!   stale proof when the version names the head,
//!   `supersede_proof_contradicts_prev_head` when it names another); an
//!   unheld group is refused.
//! - **I2810** (pure, in `kernel::head`) — the head answer carries its read
//!   set; **I2814–I2816** (pure, in `kernel::key_end`) — a key's end.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::cohort::Cohort;
    use crate::federation::operational::test_support as ops;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type;
    use crate::federation::FederationDirectory;

    /// A family of three holders under `quorum:2/3`, at version 1.
    async fn family_v1(
        d: &dyn FederationDirectory,
        tag: &str,
        s: &str,
    ) -> (String, Vec<String>, crate::federation::types::Family) {
        let holders: Vec<String> = (0..3).map(|i| format!("{tag}-h{i}-{s}")).collect();
        for h in &holders {
            ops::register_typed_key(d, h, identity_type::NODE)
                .await
                .expect("register");
        }
        let fam = format!("{tag}-fam-{s}");
        ops::seed_test_family(d, &fam, &holders, "quorum:2/3")
            .await
            .expect("v1");
        let v1 = d.lookup_family(&fam).await.unwrap().expect("held");
        (fam, holders, v1)
    }

    /// `base` renamed `name`, naming `prev`, its hash cleared for the door.
    fn version_of(
        base: &crate::federation::types::Family,
        prev: &str,
        name: &str,
    ) -> crate::federation::types::Family {
        let mut v = base.clone();
        v.prev_head_digest = prev.to_owned();
        v.family_name = name.to_owned();
        v.persist_row_hash = String::new();
        v
    }

    fn hash_of(f: &crate::federation::types::Family) -> String {
        crate::federation::types::compute_persist_row_hash(f).expect("hash")
    }

    /// **I2811** — see the module doc.
    pub(crate) async fn i2811_a_fork_is_held_as_a_tip_and_the_head_stays(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (fam, holders, v1) = family_v1(d, "i2811", s).await;
        let v2 = version_of(&v1, &v1.persist_row_hash, "v2");
        assert_eq!(
            d.supersede_family(ts::sign_family(&holders[0], v2), None)
                .await
                .expect("I2811: v2 names the held head"),
            2
        );
        let head = d.lookup_family(&fam).await.unwrap().expect("held");
        let v3 = version_of(&v1, &v1.persist_row_hash, "v3");
        for round in 0..2 {
            let v = d
                .supersede_family(ts::sign_family(&holders[0], v3.clone()), None)
                .await
                .unwrap_or_else(|e| panic!("I2811 ({round}): the sibling is held: {e}"));
            assert_eq!(v, 2, "I2811 ({round}): the head's version, unchanged");
        }
        assert_eq!(
            d.lookup_family(&fam).await.unwrap().expect("held"),
            head,
            "I2811: the head did not move"
        );
        let tips = d
            .list_group_tips(Cohort::Family, &fam)
            .await
            .expect("I2811: list_group_tips");
        assert_eq!(
            tips.len(),
            1,
            "I2811: one tip, however often offered: {tips:?}"
        );
        assert_eq!(tips[0].cohort, "family", "I2811");
        assert_eq!(tips[0].group_key_id, fam, "I2811");
        assert_eq!(
            tips[0].persist_row_hash,
            hash_of(&v3),
            "I2811: the tip is v3"
        );
        assert_eq!(
            tips[0].prev_head_digest, v1.persist_row_hash,
            "I2811: it names v1, the head's predecessor"
        );
        assert_eq!(
            tips[0]
                .snapshot
                .get("family")
                .and_then(|f| f.get("family_name"))
                .and_then(|n| n.as_str()),
            Some("v3"),
            "I2811: the signed wrapper is held as offered"
        );
        let history = d.list_group_versions(Cohort::Family, &fam).await.unwrap();
        assert_eq!(
            history.iter().map(|v| v.version).collect::<Vec<_>>(),
            vec![1, 2],
            "I2811: a tip is no version of the history"
        );
        assert!(
            d.list_group_tips(Cohort::Family, "i2811-no-such-group")
                .await
                .expect("I2811: an unknown group")
                .is_empty(),
            "I2811: an unknown group holds no tip"
        );
        assert!(
            matches!(
                d.list_group_tips(Cohort::SelfId, &fam).await,
                Err(crate::federation::Error::InvalidArgument(_))
            ),
            "I2811: the `self` cohort is not versioned"
        );
    }

    /// **I2812** — see the module doc.
    pub(crate) async fn i2812_a_version_held_before_its_predecessor_extends_when_reoffered(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (fam, holders, v1) = family_v1(d, "i2812", s).await;
        let v2 = version_of(&v1, &v1.persist_row_hash, "v2");
        let v3 = version_of(&v1, &hash_of(&v2), "v3");
        // v3 arrives first: it names a version this node does not hold
        assert_eq!(
            d.supersede_family(ts::sign_family(&holders[0], v3.clone()), None)
                .await
                .expect("I2812: v3 is held, waiting for v2"),
            1,
            "I2812: the head is still v1"
        );
        let tips = d.list_group_tips(Cohort::Family, &fam).await.unwrap();
        assert_eq!(tips.len(), 1, "I2812: {tips:?}");
        assert_eq!(tips[0].prev_head_digest, hash_of(&v2), "I2812");
        // v2 arrives and extends v1
        assert_eq!(
            d.supersede_family(ts::sign_family(&holders[0], v2), None)
                .await
                .expect("I2812: v2 extends v1"),
            2
        );
        // v3 offered again extends v2 and leaves the tips
        assert_eq!(
            d.supersede_family(ts::sign_family(&holders[0], v3.clone()), None)
                .await
                .expect("I2812: v3 extends v2"),
            3
        );
        let head = d.lookup_family(&fam).await.unwrap().expect("held");
        assert_eq!(head.persist_row_hash, hash_of(&v3), "I2812: v3 is the head");
        assert!(
            d.list_group_tips(Cohort::Family, &fam)
                .await
                .unwrap()
                .is_empty(),
            "I2812: the head is no tip"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod pure {
    use crate::federation::group_supersede_admit::{
        held_head_verdict, HeadVerdict, PlannedHead, PlannedSupersede,
    };
    use crate::federation::types::consensus_protocol as cp;
    use crate::federation::types::{Family, GroupSupersedeProof, SignedFamily};

    fn proof(prior: &str) -> GroupSupersedeProof {
        GroupSupersedeProof {
            prior_persist_row_hash: prior.to_owned(),
            change_envelope: serde_json::json!({}),
            quorum_signatures: Vec::new(),
        }
    }

    fn family(prev: &str, proof: Option<GroupSupersedeProof>) -> PlannedSupersede {
        PlannedSupersede {
            cohort_str: "family",
            head: PlannedHead::Family(SignedFamily {
                family: Family {
                    prev_head_digest: prev.to_owned(),
                    charter_digest: String::new(),
                    family_key_id: "i2813-family".to_owned(),
                    family_name: "I2813".into(),
                    members: Vec::new(),
                    founded_at: "2026-01-01T00:00:00Z".parse().expect("instant"),
                    consensus_protocol: cp::MAJORITY.to_owned(),
                    consensus_protocol_entrenched: false,
                    dissolved_at: None,
                    persist_row_hash: String::new(),
                },
                authority_key_id: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                supersede_proof: proof,
                cosignatures: Vec::new(),
            }),
            authorization: None,
        }
    }

    fn conflict(r: Result<HeadVerdict, crate::federation::Error>, token: &str) -> bool {
        matches!(r, Err(crate::federation::Error::Conflict(m)) if m.contains(token))
    }

    /// **I2813** — see the module doc.
    #[test]
    fn i2813_the_held_head_verdict_by_truth_table() {
        const HELD: &str = "i2813-held";
        const OTHER: &str = "i2813-other";
        const THIRD: &str = "i2813-third";
        let v = |prev: &str, p: Option<&str>| {
            held_head_verdict(&family(prev, p.map(proof)), Some(HELD))
        };
        assert_eq!(
            v(HELD, None).unwrap(),
            HeadVerdict::Extends,
            "I2813: a successor"
        );
        assert_eq!(v(HELD, Some(HELD)).unwrap(), HeadVerdict::Extends, "I2813");
        assert_eq!(
            v(OTHER, None).unwrap(),
            HeadVerdict::Tip,
            "I2813: a sibling"
        );
        assert_eq!(
            v("", None).unwrap(),
            HeadVerdict::Tip,
            "I2813: a second founding"
        );
        assert_eq!(
            v(OTHER, Some(OTHER)).unwrap(),
            HeadVerdict::Tip,
            "I2813: a proof naming the version's own prior rides with it"
        );
        assert!(
            conflict(v(HELD, Some(OTHER)), "stale supersede_proof"),
            "I2813: the version names the head, its proof another"
        );
        assert!(
            conflict(
                v(OTHER, Some(THIRD)),
                "supersede_proof_contradicts_prev_head"
            ),
            "I2813: a proof naming a third prior contradicts its version"
        );
        // v62.0.0 (CC 2.7) — nothing held yet is the wait, not a refusal.
        assert!(
            matches!(
                held_head_verdict(&family(HELD, None), None),
                Err(ref e @ crate::federation::Error::LinkNotHeld { .. }) if e.is_wait()
            ),
            "I2813: an unheld group has nothing to supersede yet: a wait"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn tag(b: &str) -> String {
        format!("{b}{}", uuid::Uuid::new_v4().simple())
    }

    macro_rules! on_sqlite_and_postgres {
        ($name:ident, $body:path) => {
            mod $name {
                use super::tag;

                #[cfg(feature = "sqlite")]
                #[tokio::test]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    Box::pin($body(&b, &tag("s"))).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!(
                            "{} postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED",
                            stringify!($name)
                        );
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    Box::pin($body(&b, &tag("p"))).await;
                    eprintln!("{} postgres: RAN", stringify!($name));
                }
            }
        };
    }

    on_sqlite_and_postgres!(
        i2811,
        crate::federation::kernel_pass2_invariants::bodies::i2811_a_fork_is_held_as_a_tip_and_the_head_stays
    );
    on_sqlite_and_postgres!(
        i2812,
        crate::federation::kernel_pass2_invariants::bodies::i2812_a_version_held_before_its_predecessor_extends_when_reoffered
    );
}
