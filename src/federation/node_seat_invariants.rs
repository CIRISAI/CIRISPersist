//! CIRISPersist#972 (CC 3.1.3.2, "a node gives no acceptance") — **I335–I339:
//! a node is seated in an `infrastructure` community by the founders' quorum
//! and the accord's scrub on its own key record; nobody else is.**
//! Memory, sqlite, postgres.

pub(crate) mod bodies {
    use crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID as CANON;
    use crate::federation::canonical_community_invariants::bodies::{
        canonical_row, put_conferred, signed, stand_up, widening_by, FOUNDERS, SERVE_NODE,
    };
    use crate::federation::membership_acceptance::{
        RULE_ACCEPTANCE_UNRESOLVED, RULE_FOUNDING_MEMBER_UNSIGNED,
    };
    use crate::federation::membership_acceptance_invariants::bodies as m;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type;
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    /// A node whose key record the accord co-scrubbed, and one it did not.
    const BLESSED: &str = "bn1-blessed-node";
    const PLAIN: &str = "pn2-plain-node";
    const HUMAN: &str = "hx3-conferred-human";

    /// v61 (CIRISPersist#1101, CC 5.4.6) — the node's owner announces:
    /// a live owner binding at `cohort_scope: federation`. Returns the
    /// binding's id.
    pub(crate) async fn announce(d: &dyn FederationDirectory, node: &str) -> String {
        let owner = format!("own-{node}");
        m::reg(d, &[&owner]).await;
        let id = uuid::Uuid::new_v4().to_string();
        d.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(&id, &owner, node),
        })
        .await
        .expect("the owner announces the node");
        id
    }

    async fn seated(d: &dyn FederationDirectory, group: &str, key: &str) -> bool {
        d.active_community_members(group)
            .await
            .unwrap()
            .iter()
            .any(|x| x.key_id == key)
    }

    /// The canonical birth row with `node` as its one `member`, signed by the
    /// accord quorum and the founders — and NOT by the node.
    fn birth_listing(node: &str) -> crate::federation::SignedCommunity {
        let mut row = canonical_row(&FOUNDERS);
        for mem in &mut row.members {
            if mem.key_id == SERVE_NODE {
                mem.key_id = node.to_owned();
            }
        }
        let mut s = signed(row, &["A1", "B1"]);
        s.cosignatures.retain(|c| c.authority_key_id != node);
        s
    }

    /// **I335 — the founding record seats an accord-scrubbed node that never
    /// signed it.**
    pub async fn i335_founding_seats_a_blessed_node(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, BLESSED, identity_type::NODE).await;
        d.put_community(birth_listing(BLESSED))
            .await
            .expect("I335: the founders' signatures seat the node; it never signs");
        assert!(seated(d, CANON, BLESSED).await, "I335: the node is seated");
    }

    /// **I336 — a widening seats such a node on the founders' quorum, with no
    /// acceptance row; without the quorum it is the roster rule that refuses.**
    pub async fn i336_widening_seats_a_blessed_node(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        put_conferred(d, &holders, BLESSED, identity_type::NODE).await;
        announce(d, BLESSED).await;
        let e = d
            .put_community_membership_widening(widening_by(&[FOUNDERS[0]], BLESSED, Some("member")))
            .await
            .expect_err("I336: one founder of three is not the quorum");
        assert!(
            !matches!(e, Error::MembershipAcceptanceRefused { .. }),
            "I336: the roster-authority rule refuses, not the acceptance gate: {e}"
        );
        assert!(!seated(d, CANON, BLESSED).await);
        d.put_community_membership_widening(widening_by(
            &[FOUNDERS[0], FOUNDERS[1]],
            BLESSED,
            Some("member"),
        ))
        .await
        .expect("I336: the founders' quorum seats the node, no acceptance");
        assert!(seated(d, CANON, BLESSED).await, "I336: seated");
    }

    /// **I337 — a node whose key record lacks the accord's scrub is not
    /// exempt, at the widening or at the founding.**
    pub async fn i337_an_unblessed_node_is_refused(d: &dyn FederationDirectory) {
        stand_up(d).await;
        ts::register_hybrid_key_as(d, PLAIN, PLAIN, identity_type::NODE).await;
        let e = d
            .put_community(birth_listing(PLAIN))
            .await
            .expect_err("I337: an unblessed node listed and unsigned at the founding");
        assert_eq!(m::rule_of(&e), RULE_FOUNDING_MEMBER_UNSIGNED, "I337: {e}");
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let e = d
            .put_community_membership_widening(widening_by(
                &[FOUNDERS[0], FOUNDERS[1]],
                PLAIN,
                Some("member"),
            ))
            .await
            .expect_err("I337: an unblessed node on the plane");
        assert_eq!(m::rule_of(&e), RULE_ACCEPTANCE_UNRESOLVED, "I337: {e}");
        assert!(!seated(d, CANON, PLAIN).await);
    }

    /// **I338 — a PERSON in the same community still needs their acceptance,
    /// accord-scrubbed record or not.**
    pub async fn i338_a_human_member_still_accepts(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        put_conferred(d, &holders, HUMAN, identity_type::USER).await;
        let e = d
            .put_community_membership_widening(widening_by(
                &[FOUNDERS[0], FOUNDERS[1]],
                HUMAN,
                Some("member"),
            ))
            .await
            .expect_err("I338: a person joins only by their own acceptance");
        assert_eq!(m::rule_of(&e), RULE_ACCEPTANCE_UNRESOLVED, "I338: {e}");
        assert!(!seated(d, CANON, HUMAN).await);
    }

    /// **I1101 — a serve seat needs an announced owner (CC 5.4.6,
    /// `CLM-serve-seat-announced`).** An accord-scrubbed node whose owner
    /// binding is `self`-scope only is refused `serve_seat_owner_unannounced`
    /// at the widening and is not seated (a founding record seats its node
    /// as before: a genesis bundle carries no owner binding); the owner
    /// announcing later satisfies the predicate and the re-offered widening
    /// seats it; withdrawing the announcement un-satisfies the predicate.
    pub async fn i1101_a_serve_seat_needs_an_announced_owner(d: &dyn FederationDirectory) {
        use crate::federation::admission::{
            serve_seat_owner_announced, SERVE_SEAT_OWNER_UNANNOUNCED,
        };
        use crate::federation::membership_acceptance::is_retryable_rule;
        let holders = stand_up(d).await;
        put_conferred(d, &holders, BLESSED, identity_type::NODE).await;
        // The owner's binding at `self` only: the node is owned, not announced.
        let owner = format!("own-{BLESSED}");
        m::reg(d, &[&owner]).await;
        let mut private =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &owner, BLESSED);
        private.cohort_scope = crate::federation::types::cohort_scope::SELF.to_owned();
        ts::reseal(&mut private);
        d.put_attestation(SignedAttestation {
            attestation: private,
        })
        .await
        .expect("I1101: the owner binds the node at self");
        assert!(!serve_seat_owner_announced(d, BLESSED).await.unwrap());
        assert!(is_retryable_rule(SERVE_SEAT_OWNER_UNANNOUNCED));
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let widening = || widening_by(&[FOUNDERS[0], FOUNDERS[1]], BLESSED, Some("member"));
        let e = d
            .put_community_membership_widening(widening())
            .await
            .expect_err("I1101: an unannounced node is not seated by a widening");
        assert_eq!(m::rule_of(&e), SERVE_SEAT_OWNER_UNANNOUNCED, "I1101: {e}");
        assert!(!seated(d, CANON, BLESSED).await);

        // The owner announces later: live, not instant-bound.
        let announced = announce(d, BLESSED).await;
        assert!(serve_seat_owner_announced(d, BLESSED).await.unwrap());
        d.put_community_membership_widening(widening())
            .await
            .expect("I1101: the announced node is seated");
        assert!(seated(d, CANON, BLESSED).await);

        // Withdrawing the announcement un-satisfies the predicate.
        let binding = d.get_attestation(&announced).await.unwrap().unwrap();
        let mut w = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &binding.attesting_key_id,
            BLESSED,
            &serde_json::json!({
                "dimension": crate::federation::types::owner_binding::DIMENSION,
                "references_attestation_id": announced,
                "withdrawal_reason": "the owner withdraws the announcement",
            }),
        );
        w.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.to_owned();
        let w = ts::seal_row(&binding.attesting_key_id, w);
        d.put_attestation(SignedAttestation { attestation: w })
            .await
            .expect("I1101: the owner withdraws the announcement");
        assert!(
            !serve_seat_owner_announced(d, BLESSED).await.unwrap(),
            "I1101: a withdrawn announcement does not satisfy the predicate"
        );
    }

    /// **I339 — the exemption is the infrastructure community's only: the same
    /// accord-scrubbed node is refused in an ordinary community and a family.**
    pub async fn i339_a_node_elsewhere_is_refused(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, BLESSED, identity_type::NODE).await;
        let s = m::suffix();
        let (cid, fid, founder, owner) = (
            format!("i339-c-{s}"),
            format!("i339-f-{s}"),
            format!("i339-u-{s}"),
            format!("i339-o-{s}"),
        );
        m::reg(d, &[&cid, &fid, &founder, &owner]).await;
        // The node is CLAIMED, by someone who is not a signer here: the
        // ordinary community's "no unstewarded node" rule passes, the owner's
        // signature is not on the record, and the consent gate is reached.
        d.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(&format!("i339-bind-{s}"), &owner, BLESSED),
        })
        .await
        .expect("I339: the owner claims the node");
        let now = chrono::Utc::now();
        let e = m::found_community(
            d,
            &format!("i339-x-{s}"),
            "quorum:1/1",
            &[&founder],
            &[BLESSED],
        )
        .await
        .expect_err("I339: an unsigned node at an ordinary community's founding");
        assert_eq!(m::rule_of(&e), RULE_FOUNDING_MEMBER_UNSIGNED, "I339: {e}");
        m::found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .unwrap();
        let e = m::widen_community(d, &cid, &[&founder], BLESSED, None, now)
            .await
            .expect_err("I339: a node in an ordinary community");
        assert_eq!(m::rule_of(&e), RULE_ACCEPTANCE_UNRESOLVED, "I339: {e}");
        m::found_family(d, &fid, "founder_only", &[&founder], &[])
            .await
            .unwrap();
        m::widen_family(d, &fid, &founder, BLESSED, None, now)
            .await
            .expect_err("I339: a node in a family");
        assert!(
            !d.active_family_members(&fid)
                .await
                .unwrap()
                .iter()
                .any(|x| x.key_id == BLESSED),
            "I339: not seated in the family"
        );
        assert!(
            !seated(d, &cid, BLESSED).await,
            "I339: not seated in the community"
        );
        // A FAMILY that shares the infrastructure community's id is still a
        // family: the exemption is read for the community plane only.
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        m::found_family(d, CANON, "founder_only", &[&founder], &[])
            .await
            .expect("I339: a family under the same id");
        m::widen_family(d, CANON, &founder, BLESSED, None, chrono::Utc::now())
            .await
            .expect_err("I339: a node in a family named like the infrastructure community");
        assert!(
            !d.active_family_members(CANON)
                .await
                .unwrap()
                .iter()
                .any(|x| x.key_id == BLESSED),
            "I339: not seated in that family"
        );
    }
}

mod run {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i335() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i335_founding_seats_a_blessed_node(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i336() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i336_widening_seats_a_blessed_node(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i337() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i337_an_unblessed_node_is_refused(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i338() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i338_a_human_member_still_accepts(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i1101() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i1101_a_serve_seat_needs_an_announced_owner(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i339() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i339_a_node_elsewhere_is_refused(&d as &dyn FederationDirectory).await
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
