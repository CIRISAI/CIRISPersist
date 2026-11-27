//! v61 S2 (CIRISPersist#1140; CC rc14 3.2, 2.4.1.2) — **I1511: the
//! owner-binding audience.** sqlite and postgres. v62.0.0 (WD-fix14) —
//! **I4417**: a machine occurrence follows its owner's bindings (CC 5.4.6),
//! at the serve rule (`edition2::serve::servable_to`). WD-fix14.rev2 —
//! **I4418**: a PERSON's occurrence is held where one of the person's nodes
//! is placed, two nodes through the serve feed: absent at the seal before,
//! granted after.
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

    /// **I4417** (WD-fix14; CC 5.4.6 "An occurrence follows its bindings") —
    /// a MACHINE occurrence (a key bound under a node identity) is served
    /// only to the audiences its identity's owner bindings are placed at:
    /// - bound at `self` only (unannounced): no third party is served it, a
    ///   room member's node included, nor an anonymous read;
    /// - re-signed at room R: R's member's node is served it; a non-member's
    ///   node and an anonymous read are not;
    /// - announced at `federation`: then an anonymous read is served it;
    /// - throughout, the NODE's own self pair is public (unchanged, the
    ///   bootstrap kind it was).
    pub(crate) async fn i4417_a_machine_occurrence_follows_its_bindings(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::edition2::fixture_occurrence::put_occurrence_signed;
        use crate::federation::edition2::serve::servable_to;
        use crate::federation::types::{device_class, IdentityOccurrence};
        let k = |n: &str| format!("i4417-{n}-{s}");
        let (owner, peer, outsider, room) = (k("owner"), k("peer"), k("outsider"), k("room"));
        let (node, svc, peer_node, outsider_node) =
            (k("node"), k("svc"), k("peernode"), k("outnode"));
        for u in [&owner, &peer, &outsider] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        for n in [&node, &peer_node, &outsider_node] {
            ts::register_hybrid_key_as(d, n, n, identity_type::NODE).await;
        }
        ts::register_hybrid_key_as(d, &svc, &svc, identity_type::PRIMITIVE).await;
        reg(d, &[&room]).await;
        let room = found_community(d, &room, "quorum:1/1", &[&owner, &peer], &[])
            .await
            .unwrap();
        let (owner, peer, outsider, node, svc, peer_node, outsider_node, room) = (
            e2::kid(&owner),
            e2::kid(&peer),
            e2::kid(&outsider),
            e2::kid(&node),
            e2::kid(&svc),
            e2::kid(&peer_node),
            e2::kid(&outsider_node),
            e2::kid(&room),
        );
        // Each person owns its node, at `self`.
        for (o, n) in [
            (&owner, &node),
            (&peer, &peer_node),
            (&outsider, &outsider_node),
        ] {
            put(d, &binding_at(o, n, cohort_scope::SELF, None))
                .await
                .expect("I4417: a self owner binding");
        }
        // The node's own self pair, and a service key bound under the node.
        let occ = |identity: &str, occurrence: &str, class: &str| IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        };
        put_occurrence_signed(d, occ(&node, &node, device_class::SERVER))
            .await
            .expect("I4417: the node's self pair");
        put_occurrence_signed(d, occ(&node, &svc, device_class::SERVICE))
            .await
            .expect("I4417: the service key's bind under the node");
        let statements =
            crate::federation::key_grant_invariants::two_node::bind_statements_for(d, &node).await;
        let of = |key: &str| -> Vec<Vec<u8>> {
            statements
                .iter()
                .filter(|st| {
                    crate::federation::edition2::liveness::statement_parts(st)
                        .and_then(|(_, p)| {
                            p.get_text("occurrence_key_id")
                                .and_then(ciris_verify_core::cde::Value::as_text)
                                .map(|o| o == key)
                        })
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        };
        let (self_pair, bound) = (of(&node), of(&svc));
        assert!(
            !self_pair.is_empty() && !bound.is_empty(),
            "I4417 premise: both binds are held and listed"
        );
        let served = |st: Vec<Vec<u8>>, who: Option<String>| async move {
            let mut all = true;
            for v in &st {
                all &= servable_to(d, v, who.as_deref())
                    .await
                    .expect("I4417: the serve rule reads");
            }
            all
        };
        // Unannounced: the self pair is public; the service bind reaches
        // nobody else.
        assert!(
            served(self_pair.clone(), None).await,
            "I4417: the node's self pair is public"
        );
        for who in [None, Some(peer_node.clone()), Some(outsider_node.clone())] {
            assert!(
                !served(bound.clone(), who.clone()).await,
                "I4417: bound at self only, it is served to no third party ({who:?})"
            );
        }
        // Re-signed at the room: its member's node, not a non-member's.
        put(
            d,
            &binding_at(
                &owner,
                &node,
                cohort_scope::COMMUNITY,
                Some(("community_key_id", &room)),
            ),
        )
        .await
        .expect("I4417: the binding at the room");
        assert!(
            served(bound.clone(), Some(peer_node.clone())).await,
            "I4417: a member of the room the binding is placed at is served it"
        );
        assert!(
            !served(bound.clone(), Some(outsider_node.clone())).await,
            "I4417: a non-member is not"
        );
        assert!(
            !served(bound.clone(), None).await,
            "I4417: nor an anonymous read"
        );
        // Announced at federation: public.
        put(
            d,
            &binding_at(&owner, &node, cohort_scope::FEDERATION, None),
        )
        .await
        .expect("I4417: announcing at federation");
        assert!(
            served(bound.clone(), None).await,
            "I4417: announced, an anonymous read is served it"
        );
        assert!(
            served(self_pair, None).await,
            "I4417: the self pair stays public"
        );
    }

    /// **I4418** (WD-fix14.rev2; CC 5.4.6 as Constitution ruled 11-23, the
    /// PERSON's case) — two nodes: P's (A) and co-member Q's (B), both in
    /// room R. P owns node NP by a binding placed at `self` only, and has a
    /// keyed personal device DP.
    /// - B pulls A's serve feed: DP's occurrence is NOT among it (P placed
    ///   nothing at R; a seat places nothing), so B holds no occurrence of P,
    ///   and B's seal at R reports P `absent` (not refused: Q seals);
    /// - P re-signs NP's binding at R: B pulls again and now holds DP's
    ///   occurrence under P (every occurrence of P is held wherever one of
    ///   P's nodes is placed), and B's next seal grants P.
    pub(crate) async fn i4418_a_person_is_held_where_a_node_is_placed<B>(a: &B, b: &B, s: &str)
    where
        B: crate::federation::BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
        use crate::federation::edition2::fixture_occurrence::put_occurrence_signed;
        use crate::federation::key_grant_invariants::two_node::{
            node_as, seed_community_everywhere,
        };
        use crate::federation::types::{device_class, IdentityOccurrence};
        let k = |n: &str| format!("i4418-{n}-{s}");
        let pnode = node_as(a, &k("pnode"), identity_type::NODE).await;
        let qnode = node_as(b, &k("qnode"), identity_type::NODE).await;
        let (p, q) = (e2::kid(&k("pers")), e2::kid(&k("qmem")));
        let comm = e2::kid(&k("comm"));
        seed_community_everywhere(&[&pnode, &qnode], &comm, &[(&p, None), (&q, Some(&qnode))])
            .await;
        let room = e2::room_id(&comm);
        // On A: P's device DP (keyed), and P's node bound at `self` only.
        ts::register_hybrid_key_as(a, &k("pdev"), &k("pdev"), identity_type::USER).await;
        let dp = e2::kid(&k("pdev"));
        put_occurrence_signed(
            a,
            IdentityOccurrence {
                identity_key_id: p.clone(),
                occurrence_key_id: dp.clone(),
                device_class: device_class::PHONE.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(pnode.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            },
        )
        .await
        .expect("I4418: P's device binds on A");
        put(a, &binding_at(&p, &pnode.key, cohort_scope::SELF, None))
            .await
            .expect("I4418: P owns its node at self");
        async fn held<D: FederationDirectory + ?Sized>(d: &D, p: &str, dp: &str) -> bool {
            d.list_identity_occurrences_for(p)
                .await
                .unwrap()
                .iter()
                .any(|o| o.occurrence_key_id == dp)
        }
        // B pulls: no placement at R, nothing of P's is held there.
        crate::federation::key_grant_invariants::two_node::deliver_served(a, b, &qnode.key).await;
        assert!(
            !held(b, &p, &dp).await,
            "I4418: with no placement at R, B holds no occurrence of P"
        );
        let first = encrypt_and_cascade_community(b, &room, b"before", None, Some(&qnode.key))
            .await
            .unwrap_or_else(|e| panic!("I4418: Q seals (P absent is no refusal): {e}"));
        assert!(
            first.roster.absent.contains(&p),
            "I4418: P is reported absent at the seal: {:?}",
            first.roster
        );
        // P places its node's binding at R.
        put(
            a,
            &binding_at(
                &p,
                &pnode.key,
                cohort_scope::COMMUNITY,
                Some(("community_key_id", &room)),
            ),
        )
        .await
        .expect("I4418: P re-signs its node's binding at R");
        crate::federation::key_grant_invariants::two_node::deliver_served(a, b, &qnode.key).await;
        assert!(
            held(b, &p, &dp).await,
            "I4418: placed at R, P's device occurrence is held by R's co-member"
        );
        let second = encrypt_and_cascade_community(b, &room, b"after", None, Some(&qnode.key))
            .await
            .unwrap_or_else(|e| panic!("I4418: Q seals again: {e}"));
        assert!(
            second.roster.granted.iter().any(|g| g.member_key_id == p)
                && !second.roster.absent.contains(&p),
            "I4418: the next seal grants P: {:?}",
            second.roster
        );
    }

    /// **I4421** (WD-fix16 part 3; CC 5.4.6, WD-fix14's AGENT arm) — an
    /// AGENT's occurrence follows the placements of its owner's binding of
    /// the agent (BIND-2's `put_agent_owner_binding_placed`):
    /// - bound at `self` only: the agent's occurrence is served to no third
    ///   party (a room member's node, an outsider's node, an anonymous read);
    /// - the owner re-signs the agent's binding at room R: R's member's node
    ///   is served it; an outsider's node and an anonymous read are not.
    pub(crate) async fn i4421_an_agent_occurrence_follows_its_binding(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::edition2::fixture_occurrence::{
            put_agent_owner_binding_placed, put_occurrence_signed,
        };
        use crate::federation::edition2::serve::servable_to;
        use crate::federation::types::{device_class, IdentityOccurrence};
        let k = |n: &str| format!("i4421-{n}-{s}");
        let (owner, peer, outsider, room) = (k("owner"), k("peer"), k("outsider"), k("room"));
        let (peer_node, outsider_node, agent_seed, agent_dev) =
            (k("peernode"), k("outnode"), k("agent"), k("agentkey"));
        for u in [&owner, &peer, &outsider] {
            ts::register_hybrid_key_as(d, u, u, identity_type::USER).await;
        }
        for n in [&peer_node, &outsider_node] {
            ts::register_hybrid_key_as(d, n, n, identity_type::NODE).await;
        }
        let agent = e2::put_key(d, &agent_seed, &[identity_type::AGENT]).await;
        let agent_key = e2::put_key(d, &agent_dev, &[identity_type::AGENT]).await;
        reg(d, &[&room]).await;
        let room = found_community(d, &room, "quorum:1/1", &[&owner, &peer], &[])
            .await
            .unwrap();
        let room = e2::kid(&room);
        let (peer, outsider, peer_node, outsider_node) = (
            e2::kid(&peer),
            e2::kid(&outsider),
            e2::kid(&peer_node),
            e2::kid(&outsider_node),
        );
        for (o, n) in [(&peer, &peer_node), (&outsider, &outsider_node)] {
            put(d, &binding_at(o, n, cohort_scope::SELF, None))
                .await
                .expect("I4421: a person owns its node at self");
        }
        let at = |back_min: i64| {
            u64::try_from(
                (chrono::Utc::now() - chrono::Duration::minutes(back_min)).timestamp_millis(),
            )
            .expect("after 1970")
        };
        // The owner binds the agent at self only, then the agent's occurrence.
        let _ =
            put_agent_owner_binding_placed(d, &owner, &agent_seed, at(5), cohort_scope::SELF, None)
                .await;
        put_occurrence_signed(
            d,
            IdentityOccurrence {
                identity_key_id: agent.clone(),
                occurrence_key_id: agent_key.clone(),
                device_class: device_class::AGENT.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: None,
                transport_binding: None,
                persist_row_hash: String::new(),
            },
        )
        .await
        .expect("I4421: the agent's occurrence, owner-authored");
        let statements: Vec<Vec<u8>> =
            crate::federation::key_grant_invariants::two_node::bind_statements_for(d, &agent).await;
        assert!(
            !statements.is_empty(),
            "I4421 premise: the agent's occurrence is held and listed"
        );
        let served = |who: Option<String>| {
            let statements = statements.clone();
            async move {
                let mut all = true;
                for v in &statements {
                    all &= servable_to(d, v, who.as_deref())
                        .await
                        .expect("I4421: the serve rule reads");
                }
                all
            }
        };
        for who in [None, Some(peer_node.clone()), Some(outsider_node.clone())] {
            assert!(
                !served(who.clone()).await,
                "I4421: bound at self only, the agent's occurrence reaches no third party ({who:?})"
            );
        }
        // The owner re-signs the agent's binding at R.
        let _ = put_agent_owner_binding_placed(
            d,
            &owner,
            &agent_seed,
            at(4),
            cohort_scope::COMMUNITY,
            Some(&room),
        )
        .await;
        assert!(
            served(Some(peer_node.clone())).await,
            "I4421: placed at R, R's member's node is served the agent's occurrence"
        );
        assert!(
            !served(Some(outsider_node.clone())).await,
            "I4421: a non-member's node is not"
        );
        assert!(!served(None).await, "I4421: nor an anonymous read");
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

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4417_a_machine_occurrence_follows_its_bindings_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4417_a_machine_occurrence_follows_its_bindings(&b, &suffix()))
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4417_a_machine_occurrence_follows_its_bindings_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4417_a_machine_occurrence_follows_its_bindings(&b, &suffix()))
            .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4418_a_person_is_held_where_a_node_is_placed_sqlite() {
        use crate::store::Backend as _;
        let open = || async {
            let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            b
        };
        let (a, b) = (open().await, open().await);
        Box::pin(super::bodies::i4418_a_person_is_held_where_a_node_is_placed(&a, &b, &suffix()))
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4418_a_person_is_held_where_a_node_is_placed_postgres() {
        use crate::store::Backend as _;
        let (Some(da), Some(db)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn())
        else {
            return;
        };
        let a = crate::store::postgres::PostgresBackend::connect(&da)
            .await
            .unwrap();
        let b = crate::store::postgres::PostgresBackend::connect(&db)
            .await
            .unwrap();
        a.run_migrations().await.unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4418_a_person_is_held_where_a_node_is_placed(&a, &b, &suffix()))
            .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i4421_an_agent_occurrence_follows_its_binding_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4421_an_agent_occurrence_follows_its_binding(&b, &suffix())).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i4421_an_agent_occurrence_follows_its_binding_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(super::bodies::i4421_an_agent_occurrence_follows_its_binding(&b, &suffix())).await;
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
