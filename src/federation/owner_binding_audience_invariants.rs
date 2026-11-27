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
//! - v62.0.0 (BIND-1; CC rc22 rule `owner-binding`) — the organisation on
//!   the bond is the one `on_behalf_of` names, never a placement: a binding
//!   on behalf of the room (no affiliation) is HELD
//!   `owner_binding_not_an_affiliation` and stores nothing (the earlier leg,
//!   "a non-targeted placement naming the room is a bond", witnessed the
//!   retired reading and is deleted);
//! - a second, different owner's binding of the node is held (v62.0.0,
//!   I2844: the single-owner gate is deleted; two counted owners read as
//!   unowned), and a `delegates_to` at community scope that names a foreign
//!   subject is still refused by `named_subject`.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::membership_acceptance_invariants::bodies::{
        found_community, found_family, reg,
    };
    use crate::federation::replication_audience::may_receive;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_tier, cohort_scope, identity_type};
    use crate::federation::{Attestation, Error, FederationDirectory};

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

    /// v62.0.0 (JSON cut, flip wave 2, E5) — the sealed row's edition-2
    /// statement through the one entry (every attestation gate runs).
    async fn put(d: &dyn FederationDirectory, r: &Attestation) -> Result<(), Error> {
        e2::put_signed(d, r).await.map(|_| ())
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
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let room = found_community(d, &room, "quorum:1/1", &[&owner, &peer], &[])
            .await
            .unwrap();
        // LEAD-gid2 — the room's DERIVED id (the founding helper returns it).
        let fam = found_family(d, &fam, "founder_only", &[&owner], &[])
            .await
            .unwrap();
        // v62.0.0 (flip wave 2, E5) — every key and group is named by its
        // identity-ref from here on (the rosters entered as edition-2 voices).
        let (owner, node, peer, other, room, fam) = (
            e2::kid(&owner),
            e2::kid(&node),
            e2::kid(&peer),
            e2::kid(&other),
            e2::kid(&room),
            e2::kid(&fam),
        );
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
                d.get_attestation(&e2::rid(r)).await.unwrap().is_some(),
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
        let outsider_node = e2::kid(&outsider_node);
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
        // v62.0.0 (BIND-1; CC rc22 rule `owner-binding`) — the earlier leg
        // here ("a binding naming the room from a non-targeted placement is
        // an organisation's bond, refused by #1062's gate") witnessed the
        // retired reading of a placement as accountability, and is deleted.
        // The organisation is the one `on_behalf_of` names: on behalf of a
        // room that is no affiliation, the binding is HELD
        // `owner_binding_not_an_affiliation`, stores nothing, and names no
        // affiliation on the bond.
        let bonded = k("bond-node");
        ts::register_hybrid_key_as(d, &bonded, &bonded, identity_type::NODE).await;
        let bonded = e2::kid(&bonded);
        let bond = binding_at(
            &owner,
            &bonded,
            cohort_scope::SELF,
            Some((crate::federation::admission::ON_BEHALF_OF_FIELD, &room)),
        );
        let _ = e2::land_owner_binding(d, &bond, &e2::seed_of(&bonded)).await;
        let bond_id = crate::federation::edition2::names::RowId::of_statement(
            &e2::carried_statement(&bond).expect("I1511: the bond's statement"),
        )
        .expect("I1511: a row id");
        let v = crate::federation::edition2::verdict::row_state(d, &bond_id)
            .await
            .unwrap();
        assert_eq!(
            v.held().map(|h| h.reason.as_str()),
            Some(crate::federation::edition2::fold::reason::gc1::OWNER_BINDING_NOT_AN_AFFILIATION),
            "I1511: both voices in, on behalf of a room that is no affiliation: held: {v:?}"
        );
        assert!(
            d.get_attestation(&e2::rid(&bond)).await.unwrap().is_none(),
            "I1511: a binding on behalf of a room that is no affiliation stores nothing"
        );
        assert_eq!(
            crate::federation::admission::affiliation_of_binding(d, &bonded)
                .await
                .unwrap(),
            None,
            "I1511: and names no affiliation on the bond"
        );
        // v62.0.0 (kernel pass 2, I2844; KERNEL_SEAMS B1 / C557) — a different
        // owner is no longer refused at any scope: the binding is held, and
        // cosigned by the node (the fixture sealer's co-scrub) the seat counts
        // two owners and reads the node as unowned, fail-closed.
        let rival = binding_at(
            &peer,
            &node,
            cohort_scope::COMMUNITY,
            Some(("community_key_id", &room)),
        );
        put(d, &rival)
            .await
            .expect("I2844: a second owner's binding is held, not refused");
        assert!(
            matches!(
                crate::federation::admission::owner_of(d, &node).await,
                Err(Error::AmbiguousNodeOwner { .. })
            ),
            "I2844: two counted owners read as unowned"
        );
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
