//! v62.0.0 (KR-fix10; CC 3.1.3.2 "A node gives no acceptance", CC 3.3.6 "An
//! agent key never signs as its owner") — **I4280–I4284: a node is its
//! owner's writer, never its consent or its standing.**
//!
//! The owner binding gives a node the right to WRITE for its owner
//! (`admission::writer_principal`) and nothing else. Every consent and
//! standing comparison reads `admission::consenting_person`: a person's own
//! key or one of the person's devices is the person; an agent is itself; a
//! node is nobody.
//!
//! - **I4280** an owned node cannot accept its owner's invitation (refused
//!   by name, `node_gives_no_consent`; the room does not grow); the person's
//!   second device can.
//! - **I4281** an agent accepts for itself under its own key; its owner's
//!   signature is not the agent's acceptance.
//! - **I4282** an owned node cannot retract its owner's proposal; the
//!   proposer's second device can.
//! - **I4283** an owned node cannot state a standing proposal as the founder
//!   whose machine it is; the founder's second device can.
//! - **I4284** the founding rule (`check_founding_signers`, called directly):
//!   a node's signature founds for nobody but itself.
//!
//! sqlite and postgres; every row through the statement door (`put_e2`),
//! except I4284 (the gate function).

pub(crate) mod bodies {
    use crate::federation::admission::NODE_GIVES_NO_CONSENT;
    use crate::federation::edition2::fixture_occurrence::{put_bind, BindOptions};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::membership_acceptance::{
        check_founding_signers, RULE_ACCEPTANCE_MISMATCH, RULE_PROPOSAL_EXPIRED,
    };
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_public_room, id_of, proposal, put_e2, reg, reply, rule_of,
        widen_community,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::COMMUNITY;
    use crate::federation::types::consensus_protocol::OPEN_SELF_ADMIT;
    use crate::federation::types::{attestation_type, device_class};
    use crate::federation::{Attestation, FederationDirectory};
    use chrono::{Duration, Utc};

    /// A `node` key `seed`, owned by the person `owner_seed` (the counted
    /// owner binding, the node's voice included). Its key id.
    async fn owned_node(d: &dyn FederationDirectory, owner_seed: &str, seed: &str) -> String {
        let node = e2::put_key(d, seed, &["node"]).await;
        crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
            d, owner_seed, seed,
        )
        .await;
        assert_eq!(
            crate::federation::admission::owner_of(d, &node)
                .await
                .expect("owner_of")
                .as_deref(),
            Some(id_of(owner_seed).as_str()),
            "premise: {seed} is {owner_seed}'s node"
        );
        node
    }

    /// A second device of the person `person_seed`: a `user` key bound as an
    /// occurrence of the person (the device's own voice, then the person's).
    async fn second_device(d: &dyn FederationDirectory, person_seed: &str, seed: &str) -> String {
        reg(d, &[seed]).await;
        put_bind(
            d,
            person_seed,
            person_seed,
            seed,
            device_class::LAPTOP,
            &BindOptions::default(),
        )
        .await
        .expect("the person binds its second device");
        let device = id_of(seed);
        assert_eq!(
            d.active_identity_for_occurrence(&device)
                .await
                .expect("the device resolves"),
            id_of(person_seed),
            "premise: {seed} is a device of {person_seed}"
        );
        device
    }

    fn names_the_refusal(e: &crate::federation::Error) -> bool {
        e.to_string().contains(NODE_GIVES_NO_CONSENT)
    }

    /// `signer`'s `withdraws` of the row `target`.
    fn withdrawal(signer: &str, target: &Attestation) -> Attestation {
        let mut w = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            signer,
            signer,
            &serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "references_attestation_id": e2::rid(target),
                "withdrawal_reason": "rescinded",
            }),
        );
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.weight = None;
        ts::seal_row_in_place(signer, &mut w);
        w
    }

    /// **I4280.**
    pub async fn i4280_a_node_cannot_accept_for_its_owner(d: &dyn FederationDirectory, s: &str) {
        let (cid, founder, k) = (
            format!("i4280-c-{s}"),
            format!("i4280-f-{s}"),
            format!("i4280-k-{s}"),
        );
        reg(d, &[&cid, &founder, &k]).await;
        let node = owned_node(d, &k, &format!("i4280-n-{s}")).await;
        let device = second_device(d, &k, &format!("i4280-d-{s}")).await;
        let (cid, founder, k) = (id_of(&cid), id_of(&founder), id_of(&k));
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .expect("I4280: the founder founds the room");
        let now = Utc::now();
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &k,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &p).await.expect("I4280: the invitation");

        // K's NODE signs the acceptance: refused by name, and the room does
        // not grow.
        let e = put_e2(d, &reply(&node, &k, &p, true, now))
            .await
            .expect_err("I4280: a node's signature is not its owner's acceptance");
        assert!(names_the_refusal(&e), "I4280: refused by name: {e}");
        widen_community(d, &cid, &[&founder], &k, None, now)
            .await
            .expect_err("I4280: no growth on a node-signed acceptance");

        // K's second DEVICE signs it: K's own consent.
        put_e2(d, &reply(&device, &k, &p, true, now))
            .await
            .expect("I4280: the person's second device accepts for the person");
        widen_community(d, &cid, &[&founder], &k, None, now)
            .await
            .expect("I4280: the room grows on the person's own acceptance");
    }

    /// **I4281.**
    pub async fn i4281_an_agent_accepts_for_itself(d: &dyn FederationDirectory, s: &str) {
        let (cid, founder, owner) = (
            format!("i4281-c-{s}"),
            format!("i4281-f-{s}"),
            format!("i4281-o-{s}"),
        );
        reg(d, &[&cid, &founder, &owner]).await;
        let agent_seed = format!("i4281-a-{s}");
        let agent = e2::put_key(d, &agent_seed, &["agent"]).await;
        e2::put_agent_owner_binding(
            d,
            &owner,
            &agent_seed,
            e2::ms(Utc::now() - Duration::minutes(5)),
        )
        .await;
        let (cid, founder, owner) = (id_of(&cid), id_of(&founder), id_of(&owner));
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .expect("I4281: the founder founds the room");
        let now = Utc::now();
        let p = proposal(
            &founder,
            COMMUNITY,
            &cid,
            &agent,
            None,
            now,
            Some(Duration::days(7)),
        );
        put_e2(d, &p)
            .await
            .expect("I4281: the invitation to the agent");
        // The OWNER signs for the agent: not the agent's acceptance.
        let e = put_e2(d, &reply(&owner, &agent, &p, true, now))
            .await
            .expect_err("I4281: an owner does not accept for its agent here");
        assert_eq!(rule_of(&e), RULE_ACCEPTANCE_MISMATCH, "I4281: {e}");
        // The agent signs for itself, under its own key.
        put_e2(d, &reply(&agent, &agent, &p, true, now))
            .await
            .expect("I4281: an agent accepts for itself");
    }

    /// **I4282.**
    pub async fn i4282_a_node_cannot_retract_its_owners_proposal(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (cid, founder, m1, m2) = (
            format!("i4282-c-{s}"),
            format!("i4282-f-{s}"),
            format!("i4282-m1-{s}"),
            format!("i4282-m2-{s}"),
        );
        reg(d, &[&cid, &founder, &m1, &m2]).await;
        let node = owned_node(d, &founder, &format!("i4282-n-{s}")).await;
        let device = second_device(d, &founder, &format!("i4282-d-{s}")).await;
        let (cid, founder, m1, m2) = (id_of(&cid), id_of(&founder), id_of(&m1), id_of(&m2));
        found_community(d, &cid, "quorum:1/1", &[&founder], &[])
            .await
            .expect("I4282: the founder founds the room");
        let now = Utc::now();
        let invite = |k: &str| {
            proposal(
                &founder,
                COMMUNITY,
                &cid,
                k,
                None,
                now,
                Some(Duration::days(7)),
            )
        };
        // The founder's NODE "withdraws" the founder's proposal to M1: kept
        // or refused, it retracts nothing, and M1 still joins.
        let p1 = invite(&m1);
        put_e2(d, &p1).await.expect("I4282: the invitation to M1");
        put_e2(d, &reply(&m1, &m1, &p1, true, now))
            .await
            .expect("I4282: M1 accepts");
        let _ = put_e2(d, &withdrawal(&node, &p1)).await;
        widen_community(d, &cid, &[&founder], &m1, None, now)
            .await
            .expect("I4282: a node's withdrawal does not retract its owner's proposal");

        // The founder's second DEVICE withdraws the proposal to M2: retracted.
        let p2 = invite(&m2);
        put_e2(d, &p2).await.expect("I4282: the invitation to M2");
        put_e2(d, &reply(&m2, &m2, &p2, true, now))
            .await
            .expect("I4282: M2 accepts");
        put_e2(d, &withdrawal(&device, &p2))
            .await
            .expect("I4282: the proposer's second device withdraws the proposal");
        let e = widen_community(d, &cid, &[&founder], &m2, None, now)
            .await
            .expect_err("I4282: a proposal its proposer's device withdrew");
        assert_eq!(rule_of(&e), RULE_PROPOSAL_EXPIRED, "I4282: {e}");
    }

    /// **I4283.**
    pub async fn i4283_a_node_cannot_propose_as_the_founder(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::open_admission_invariants::bodies::standing;
        use crate::federation::public_room::live_standing_proposal;
        let (cid, founder) = (format!("i4283-c-{s}"), format!("i4283-f-{s}"));
        reg(d, &[&cid, &founder]).await;
        let node = owned_node(d, &founder, &format!("i4283-n-{s}")).await;
        let device = second_device(d, &founder, &format!("i4283-d-{s}")).await;
        let (cid, founder) = (id_of(&cid), id_of(&founder));
        found_public_room(d, &cid, OPEN_SELF_ADMIT, &[&founder], &[])
            .await
            .expect("I4283: the founder founds the public room");
        let at = Utc::now() - Duration::hours(1);
        // The founder's NODE states the standing proposal: it does not stand.
        let _ = put_e2(d, &standing(&node, &cid, at)).await;
        assert!(
            live_standing_proposal(d, &cid)
                .await
                .expect("I4283: reads")
                .is_none(),
            "I4283: a founder's node holds no founder standing: no standing proposal is live"
        );
        // The founder's second DEVICE states it: the founder's own act.
        let p = standing(&device, &cid, at + Duration::seconds(1));
        put_e2(d, &p)
            .await
            .expect("I4283: the founder's second device states the standing proposal");
        assert_eq!(
            live_standing_proposal(d, &cid)
                .await
                .expect("I4283: reads")
                .map(|r| r.attestation_id),
            Some(p.attestation_id.clone()),
            "I4283: the founder's own standing proposal is live"
        );
    }

    /// **I4284.**
    pub async fn i4284_a_node_founds_for_nobody_but_itself(d: &dyn FederationDirectory, s: &str) {
        let (group, k) = (format!("i4284-g-{s}"), format!("i4284-k-{s}"));
        reg(d, &[&group, &k]).await;
        let node = owned_node(d, &k, &format!("i4284-n-{s}")).await;
        let device = second_device(d, &k, &format!("i4284-d-{s}")).await;
        let (group, k) = (id_of(&group), id_of(&k));
        // K is listed; K's NODE signed: K did not sign.
        check_founding_signers(d, &group, &[&k], &[&node])
            .await
            .expect_err("I4284: a node's signature is not its owner's founding voice");
        // K's second device signed: K signed.
        check_founding_signers(d, &group, &[&k], &[&device])
            .await
            .expect("I4284: the person's device signs the founding for the person");
        // K's own key.
        check_founding_signers(d, &group, &[&k], &[&k])
            .await
            .expect("I4284: the person's own key");
        // A listed NODE that signed for itself.
        check_founding_signers(d, &group, &[&node], &[&node])
            .await
            .expect("I4284: a node listed in its own right signs for itself");
    }
}

#[cfg(test)]
mod run {
    use super::bodies;
    use crate::federation::membership_acceptance_invariants::bodies::suffix;

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::{bodies, suffix};
                #[tokio::test]
                async fn i4280() {
                    let Some(b) = $fresh.await else { return };
                    Box::pin(bodies::i4280_a_node_cannot_accept_for_its_owner(
                        &b,
                        &suffix(),
                    ))
                    .await
                }
                #[tokio::test]
                async fn i4281() {
                    let Some(b) = $fresh.await else { return };
                    Box::pin(bodies::i4281_an_agent_accepts_for_itself(&b, &suffix())).await
                }
                #[tokio::test]
                async fn i4282() {
                    let Some(b) = $fresh.await else { return };
                    Box::pin(bodies::i4282_a_node_cannot_retract_its_owners_proposal(
                        &b,
                        &suffix(),
                    ))
                    .await
                }
                #[tokio::test]
                async fn i4283() {
                    let Some(b) = $fresh.await else { return };
                    Box::pin(bodies::i4283_a_node_cannot_propose_as_the_founder(
                        &b,
                        &suffix(),
                    ))
                    .await
                }
                #[tokio::test]
                async fn i4284() {
                    let Some(b) = $fresh.await else { return };
                    Box::pin(bodies::i4284_a_node_founds_for_nobody_but_itself(
                        &b,
                        &suffix(),
                    ))
                    .await
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
