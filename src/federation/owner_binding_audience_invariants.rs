//! v61 S2 (CIRISPersist#1140; CC rc14 3.2, 2.4.1.2) — **I1511: the
//! owner-binding audience.** sqlite and postgres.
//!
//! An owner-binding is written at `self`. When an unannounced node joins a
//! group, the owner re-signs the binding at that group's scope as a SECOND
//! owner-signed row alongside the `self` one (never a `supersedes`), so the
//! group's members can see who owns the node. Every one of the scopes is an
//! admissible audience (a substrate refuses none), and `owner_of` folds every
//! live binding.
//!
//! - the group-scope re-sign is admitted: AV-84's `attested_party` arm reads
//!   the row type and never applies to a `delegates_to`, whose attested key
//!   is the delegate by definition, and a NODE's binding naming a group is an
//!   audience, not an organisation on the bond (#1062's gate is for an
//!   `agent` key held on an organisation's behalf);
//! - both rows stay live and `owner_of` names the one owner;
//! - the group-scope row is not delivered to a non-member's node (it rides
//!   the room's content audience);
//! - a family-scope and a federation-scope re-sign are admitted as well;
//! - a binding naming the room from a NON-targeted placement (federation) is
//!   an organisation's bond, not an audience: #1062's gate refuses it
//!   (`owner_binding_affiliation_refused`; the room is no affiliation);
//! - a second, different owner's binding of the node is still refused (the
//!   single-owner gate), and a `delegates_to` at community scope that names
//!   a foreign subject is still refused by `named_subject`.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_family, reg,
    };
    use crate::federation::replication_audience::may_receive;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_tier, cohort_scope, identity_type};
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};

    fn binding_at(
        owner: &str,
        node: &str,
        scope: &str,
        target: Option<(&str, &str)>,
    ) -> Attestation {
        let mut b = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), owner, node);
        b.cohort_scope = scope.to_owned();
        if scope == cohort_scope::SELF {
            b.tier = attestation_tier::LOCAL.to_owned();
        }
        if let Some((member, id)) = target {
            b.attestation_envelope[member] = serde_json::json!(id);
        }
        b.asserted_at = chrono::Utc::now() - chrono::Duration::minutes(5);
        b.scrub_timestamp = b.asserted_at;
        ts::seal_row_in_place(owner, &mut b);
        b
    }

    async fn put(d: &dyn FederationDirectory, r: &Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation {
            attestation: r.clone(),
        })
        .await
        .map(|_| ())
    }

    /// **I1511** — the binding at the group's scope.
    pub(crate) async fn i1511_the_owner_re_signs_the_binding_at_the_group(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let k = |n: &str| format!("i1511-{n}-{s}");
        let (owner, node, peer, other, room, fam) = (
            k("owner"),
            k("node"),
            k("peer"),
            k("other"),
            k("room"),
            k("fam"),
        );
        for u in [&owner, &peer, &other] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        ts::register_hybrid_key_as(d, &node, &node, identity_type::NODE).await;
        reg(d, &[&room, &fam]).await;
        found_community(d, &room, "quorum:1/1", &[&owner, &peer], &[])
            .await
            .unwrap();
        found_family(d, &fam, "founder_only", &[&owner], &[])
            .await
            .unwrap();
        // Written at self.
        let at_self = binding_at(&owner, &node, cohort_scope::SELF, None);
        put(d, &at_self).await.expect("I1511: the self binding");
        // Re-signed at the room's scope: a second row, alongside.
        let at_room = binding_at(
            &owner,
            &node,
            cohort_scope::COMMUNITY,
            Some(("community_key_id", &room)),
        );
        put(d, &at_room)
            .await
            .expect("I1511: the owner re-signs the binding at the room's scope");
        for r in [&at_self, &at_room] {
            assert!(
                d.get_attestation(&r.attestation_id)
                    .await
                    .unwrap()
                    .is_some(),
                "I1511: both bindings stand"
            );
        }
        assert_eq!(
            crate::federation::admission::owner_of(d, &node)
                .await
                .unwrap(),
            Some(owner.clone()),
            "I1511: owner_of folds every live binding to the one owner"
        );
        // The group-scope row rides the room's content audience: its members'
        // claimed nodes (CC 6.1.5.3; the delivery rule I390–I399 witness),
        // never a non-member's node.
        let outsider_node = k("outsider-node");
        ts::register_hybrid_key_as(d, &outsider_node, &outsider_node, identity_type::NODE).await;
        put(
            d,
            &binding_at(&other, &outsider_node, cohort_scope::SELF, None),
        )
        .await
        .expect("I1511: a non-member owns its node");
        assert!(
            !may_receive(d, &outsider_node, &at_room)
                .await
                .unwrap()
                .allowed(),
            "I1511: a non-member's node does not receive the room-scope binding"
        );
        // A family and federation are admissible audiences too.
        put(
            d,
            &binding_at(
                &owner,
                &node,
                cohort_scope::FAMILY,
                Some(("family_key_id", &fam)),
            ),
        )
        .await
        .expect("I1511: the family scope");
        put(
            d,
            &binding_at(&owner, &node, cohort_scope::FEDERATION, None),
        )
        .await
        .expect("I1511: announcing at federation");
        assert_eq!(
            crate::federation::admission::owner_of(d, &node)
                .await
                .unwrap(),
            Some(owner.clone()),
            "I1511: still one owner"
        );
        // v61 S2 — the audience reading is the TARGETED placement's alone. A
        // binding that names the room from a non-targeted placement
        // (federation) is an organisation's bond, judged by #1062's gate. The
        // room is no affiliation and the bond carries one signature, so it is
        // refused by that gate's name, and no affiliation is read off it.
        let bonded = k("bond-node");
        ts::register_hybrid_key_as(d, &bonded, &bonded, identity_type::NODE).await;
        let bond = binding_at(
            &owner,
            &bonded,
            cohort_scope::FEDERATION,
            Some(("community_key_id", &room)),
        );
        match put(d, &bond).await {
            Err(Error::InvalidArgument(m)) => assert!(
                m.starts_with(crate::federation::admission::OWNER_BINDING_AFFILIATION_REFUSED),
                "I1511: a non-group placement naming a group is an organisation's bond: {m}"
            ),
            other => panic!("I1511: the bond at federation must meet #1062's gate: {other:?}"),
        }
        assert!(
            d.get_attestation(&bond.attestation_id)
                .await
                .unwrap()
                .is_none(),
            "I1511: the refused bond stores nothing"
        );
        // A different owner is still refused, whatever the scope.
        let rival = binding_at(
            &peer,
            &node,
            cohort_scope::COMMUNITY,
            Some(("community_key_id", &room)),
        );
        put(d, &rival).await.expect_err("I1511: a second owner");
        // v61 S2 (#1161) — a delegates_to naming a subject outside the room's
        // audience is refused on the audience rule.
        let mut named = binding_at(
            &owner,
            &node,
            cohort_scope::COMMUNITY,
            Some(("community_key_id", &room)),
        );
        named.subject_key_ids = vec![other.clone()];
        ts::seal_row_in_place(&owner, &mut named);
        let e = put(d, &named).await.expect_err("I1511: a foreign subject");
        assert!(
            matches!(
                e,
                Error::CohortStandingRefused {
                    reason:
                        crate::federation::admission::CohortStandingRefusal::SubjectOutsideAudience,
                    ..
                }
            ),
            "I1511: subject_outside_audience refuses: {e:?}"
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
    async fn i1511_the_owner_re_signs_the_binding_at_the_group_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i1511_the_owner_re_signs_the_binding_at_the_group(&b, &suffix()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1511_the_owner_re_signs_the_binding_at_the_group_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::bodies::i1511_the_owner_re_signs_the_binding_at_the_group(&b, &suffix()).await;
    }
}
