//! CIRISPersist#873 — witnesses for `FSD/OCCURRENCE_PRINCIPAL.md` §4
//! (I121–I125): an occurrence resolves to its ACTIVE non-singleton binding,
//! deterministically, on every backend; the hold-side audience question
//! unions every principal; a revoked anchor returns the device to itself.
//! One body per invariant, generic over the directory, run by memory,
//! sqlite and postgres.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{
        cohort_scope, device_class, Community, CommunityMember, IdentityOccurrence,
        IdentityOccurrenceRevocation,
    };
    use crate::federation::{
        would_hold, BlobError, BlobProvenance, DiskPressureSnapshot, FederationDirectory,
        HoldContext,
    };

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().unwrap()
    }

    /// One `federation_identity_occurrences` row: `identity` speaks through
    /// `occurrence`, asserted at `when`. The boot singleton is
    /// `bind(d, node, node, ..)` with the `agent` class; the login anchor is
    /// `bind(d, human, node, ..)` with the `server` class — the two rows every
    /// claimed node carries (#873).
    async fn bind(d: &dyn FederationDirectory, identity: &str, occurrence: &str, when: &str) {
        let class = if identity == occurrence {
            device_class::AGENT
        } else {
            device_class::SERVER
        };
        d.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            asserted_at: at(when),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("bind {identity} through {occurrence}: {e}"));
    }

    async fn revoke(d: &dyn FederationDirectory, identity: &str, occurrence: &str, when: &str) {
        d.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            revoked_at: at(when),
            effective_at: at(when),
            reason: None,
            witness_set: vec![identity.to_owned()],
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("revoke {identity} through {occurrence}: {e}"));
    }

    /// A community founded by `founder` with `members` on its roster.
    async fn room(d: &dyn FederationDirectory, comm: &str, members: &[&str]) {
        ts::register_identity_key(d, comm, USER).await;
        d.put_community(ts::sign_community(
            comm,
            Community {
                community_key_id: comm.to_owned(),
                community_name: "Room".into(),
                members: members
                    .iter()
                    .map(|m| CommunityMember {
                        key_id: (*m).to_owned(),
                        joined_at: at("2026-06-01T00:00:00Z"),
                        role: None,
                    })
                    .collect(),
                founded_at: at("2026-06-01T00:00:00Z"),
                consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                    .to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("room {comm}: {e}"));
    }

    /// `would_hold` on `node` for community content of `comm` authored by a
    /// stranger — the #873 shape, exactly.
    async fn holds(
        d: &dyn FederationDirectory,
        node: &str,
        comm: &str,
        author: &str,
    ) -> Result<(), BlobError> {
        let ctx = HoldContext {
            pressure: DiskPressureSnapshot::normal(),
            is_local_or_family: |k: &str| k == node,
            our_key_id: node,
        };
        would_hold(
            d,
            &ctx,
            &BlobProvenance {
                author_key_id: author.to_owned(),
                cohort_scope: cohort_scope::COMMUNITY.to_owned(),
                community_key_id: Some(comm.to_owned()),
                epoch: Some(0),
                tier: cohort_scope::CryptoTier::CommunityDek,
                minter_key_id: None,
            },
        )
        .await
    }

    /// **I121 — both rows present, singleton first: the principal is the
    /// owner; the ordered lookup returns the anchor; insertion order does
    /// not change the answer.**
    pub async fn i121_the_principal_is_the_owner(d: &dyn FederationDirectory, s: &str) {
        let (node, owner) = (format!("i121-node-{s}"), format!("i121-owner-{s}"));
        ts::register_identity_key(d, &node, NODE).await;
        ts::register_identity_key(d, &owner, USER).await;
        bind(d, &node, &node, "2026-06-01T00:00:00Z").await; // boot
        bind(d, &owner, &node, "2026-06-02T00:00:00Z").await; // claim
        assert_eq!(
            d.active_identity_for_occurrence(&node).await.unwrap(),
            owner,
            "I121: the node resolves to its owner, not to itself"
        );
        assert_eq!(
            d.active_identities_for_occurrence(&node).await.unwrap(),
            vec![owner.clone()],
            "I121: the plural lists the one principal"
        );
        let looked = d
            .lookup_identity_for_occurrence(&node)
            .await
            .unwrap()
            .expect("bound");
        assert_eq!(
            looked.identity_key_id, owner,
            "I121: the ordered lookup returns the anchor, not the singleton"
        );
        // The other insertion order: the same answers.
        let (node2, owner2) = (format!("i121-node2-{s}"), format!("i121-owner2-{s}"));
        ts::register_identity_key(d, &node2, NODE).await;
        ts::register_identity_key(d, &owner2, USER).await;
        bind(d, &owner2, &node2, "2026-06-02T00:00:00Z").await;
        bind(d, &node2, &node2, "2026-06-03T00:00:00Z").await; // singleton asserted LATER
        assert_eq!(
            d.active_identity_for_occurrence(&node2).await.unwrap(),
            owner2,
            "I121: a later-asserted singleton does not outrank the anchor"
        );
        assert_eq!(
            d.lookup_identity_for_occurrence(&node2)
                .await
                .unwrap()
                .unwrap()
                .identity_key_id,
            owner2
        );
        // An unbound key is its own principal; a singleton-only key too.
        let lone = format!("i121-lone-{s}");
        ts::register_identity_key(d, &lone, NODE).await;
        assert_eq!(d.active_identity_for_occurrence(&lone).await.unwrap(), lone);
        assert!(d
            .active_identities_for_occurrence(&lone)
            .await
            .unwrap()
            .is_empty());
        bind(d, &lone, &lone, "2026-06-01T00:00:00Z").await;
        assert_eq!(d.active_identity_for_occurrence(&lone).await.unwrap(), lone);
        assert!(d
            .active_identities_for_occurrence(&lone)
            .await
            .unwrap()
            .is_empty());
    }

    /// **I122 — `would_hold` admits community content of a room the owner
    /// is a member of, for a node carrying both rows.**
    /// **I141 — the read-side `self` gate admits the caller's self-collective
    /// (v46.3.1, CIRISPersist#888 / CIRISServer#624).** A claimed node's own
    /// `self` rows about itself (`config:*`) are readable by the node, by its
    /// owner, by the owner's other device and by the owner's other node; a
    /// stranger node reads none. Rust twin on every backend; the SQL twin
    /// through `ReadEngine::list_attestations` on sqlite / postgres.
    pub async fn i141_a_claimed_node_reads_its_own_self_rows<B>(d: &B, s: &str)
    where
        B: FederationDirectory + crate::ceg::ReadEngine,
    {
        use crate::scope::{caller_scope_from_directory, CallerScope};
        let (node, owner, device, node_c, stranger, other) = (
            format!("i141-node-{s}"),
            format!("i141-owner-{s}"),
            format!("i141-device-{s}"),
            format!("i141-node-c-{s}"),
            format!("i141-stranger-{s}"),
            format!("i141-other-{s}"),
        );
        for (k, t) in [
            (&node, NODE),
            (&node_c, NODE),
            (&stranger, NODE),
            (&owner, USER),
            (&device, USER),
            (&other, USER),
        ] {
            ts::register_identity_key(d, k, t).await;
        }
        // The node's own self rows, written UNCLAIMED (singleton): the CC 3.4.5
        // self-or-owner stamping — attester == attested == node, target = node.
        let dims = [
            "config:net.bootstrap_peers:v1",
            "config:net.announce_ownership:v1",
        ];
        for (i, dim) in dims.iter().enumerate() {
            let mut row = ts::bare_attestation(
                &format!("i141-row-{i}-{s}"),
                &node,
                &node,
                &serde_json::json!({"cohort_scope": "self", "dimension": dim}),
            );
            row.attestation_type = "scores".into();
            row.cohort_scope = crate::federation::types::cohort_scope::SELF.into();
            row.subject_key_ids = vec![node.clone()];
            ts::seal_row_in_place(&node, &mut row);
            d.put_attestation(crate::federation::SignedAttestation { attestation: row })
                .await
                .unwrap_or_else(|e| panic!("I141: the node writes its own self row: {e}"));
        }
        let reads = |caller: &str| {
            let caller = caller.to_owned();
            let node = node.clone();
            async move {
                let scope = caller_scope_from_directory(d, &caller).await.unwrap();
                let rust_twin = scope.admits(
                    crate::federation::types::cohort_scope::SELF,
                    &node,
                    Some("config:net.bootstrap_peers:v1"),
                );
                // The SQL twin, where there is SQL: the memory backend has no
                // CEG read substrate, so its leg measures the Rust twin only.
                let rows = match crate::ceg::ReadEngine::list_attestations(
                    d,
                    crate::ceg::AttestationFilter {
                        attesting_key_id: Some(node.clone()),
                        dimension_prefixes: vec!["config:".into()],
                        ..Default::default()
                    },
                    None,
                    10,
                    scope,
                )
                .await
                {
                    Ok(page) => Some(page.items.len()),
                    Err(crate::ceg::Error::Backend(m))
                        if m.contains("no relational read substrate") =>
                    {
                        None
                    }
                    Err(e) => panic!("I141: list_attestations: {e}"),
                };
                (rust_twin, rows)
            }
        };
        let expect = |got: (bool, Option<usize>), admitted: bool, rows: usize, why: &str| {
            assert_eq!(got.0, admitted, "{why} (Rust twin)");
            if let Some(n) = got.1 {
                assert_eq!(n, rows, "{why} (SQL twin)");
            }
        };
        expect(
            reads(&node).await,
            true,
            2,
            "I141: unclaimed, the node reads its own rows",
        );
        // THE CLAIM: owner binding + occurrence binding. Resolution now answers the owner.
        bind(d, &owner, &node, "2026-06-02T00:00:00Z").await;
        ts::put_owner_binding(d, &owner, &node).await;
        assert_eq!(
            d.active_identity_for_occurrence(&node).await.unwrap(),
            owner,
            "I141: the claimed node resolves to its owner (#873)"
        );
        expect(
            reads(&node).await,
            true,
            2,
            "I141: CLAIMED, the node still reads its own self rows (#888)",
        );
        expect(
            reads(&owner).await,
            true,
            2,
            "I141: the owner reads the node's self rows",
        );
        // The owner's other device (an occurrence) and other node (owned, never bound).
        bind(d, &owner, &device, "2026-06-03T00:00:00Z").await;
        ts::put_owner_binding(d, &owner, &node_c).await;
        expect(
            reads(&device).await,
            true,
            2,
            "I141: the owner's other device reads them (CC 5.2)",
        );
        expect(
            reads(&node_c).await,
            true,
            2,
            "I141: the owner's other node reads them (owned, not occurrence-bound)",
        );
        // The other direction — the bound node READS what the collective's
        // other members WRITE about themselves. The device is an occurrence
        // that owns no node (the occurrence union is the only path to it);
        // node C is an owned node bound as no occurrence (`nodes_owned_by`
        // is the only path to it). One self row each, under `profile:`.
        for (i, writer) in [&device, &node_c].iter().enumerate() {
            let mut row = ts::bare_attestation(
                &format!("i141-peer-row-{i}-{s}"),
                writer,
                writer,
                &serde_json::json!({"cohort_scope": "self", "dimension": format!("profile:display_name:v{i}")}),
            );
            row.attestation_type = "scores".into();
            row.cohort_scope = crate::federation::types::cohort_scope::SELF.into();
            row.subject_key_ids = vec![(*writer).clone()];
            ts::seal_row_in_place(writer, &mut row);
            d.put_attestation(crate::federation::SignedAttestation { attestation: row })
                .await
                .unwrap_or_else(|e| {
                    panic!("I141: a collective member writes its own self row: {e}")
                });
        }
        let reads_dim = |caller: &str, writer: &str, prefix: &str, dimension: &str| {
            let (caller, writer, prefix, dimension) = (
                caller.to_owned(),
                writer.to_owned(),
                prefix.to_owned(),
                dimension.to_owned(),
            );
            async move {
                let scope = caller_scope_from_directory(d, &caller).await.unwrap();
                let rust_twin = scope.admits(
                    crate::federation::types::cohort_scope::SELF,
                    &writer,
                    Some(&dimension),
                );
                let rows = match crate::ceg::ReadEngine::list_attestations(
                    d,
                    crate::ceg::AttestationFilter {
                        attesting_key_id: Some(writer.clone()),
                        dimension_prefixes: vec![prefix.clone()],
                        ..Default::default()
                    },
                    None,
                    10,
                    scope,
                )
                .await
                {
                    Ok(page) => Some(page.items.len()),
                    Err(crate::ceg::Error::Backend(m))
                        if m.contains("no relational read substrate") =>
                    {
                        None
                    }
                    Err(e) => panic!("I141: list_attestations: {e}"),
                };
                (rust_twin, rows)
            }
        };
        let reads_of = |caller: &str, writer: &str| {
            reads_dim(caller, writer, "profile:", "profile:display_name:v1")
        };
        expect(
            reads_of(&node, &device).await,
            true,
            1,
            "I141: the node reads its owner's DEVICE's self row (occurrence union)",
        );
        expect(
            reads_of(&node, &node_c).await,
            true,
            1,
            "I141: the node reads its owner's OTHER NODE's self row (nodes_owned_by)",
        );
        // A stranger node under another human reads none — the fix widened
        // `self` to the collective, not to the world.
        bind(d, &other, &stranger, "2026-06-03T00:00:00Z").await;
        ts::put_owner_binding(d, &other, &stranger).await;
        expect(
            reads(&stranger).await,
            false,
            0,
            "I141: a stranger node reads none",
        );
        expect(
            reads_of(&stranger, &device).await,
            false,
            0,
            "I141: nor the device's",
        );
        expect(
            reads_of(&stranger, &node_c).await,
            false,
            0,
            "I141: nor node C's",
        );
        // Review (PR #889, round three): a LOCAL-tier row is producer-only
        // authority (V4.4 §3) — visible to the producing occurrence alone,
        // whatever the collective. The node writes one through the local door.
        d.attestation_upsert_local(crate::federation::types::LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: node.clone(),
            attested_key_id: None,
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: Some(1.0),
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({"id": format!("i141-local-{s}"), "dimension": "identity_binding:v1", "score": 1.0, "confidence": 0.9}),
            )
            .unwrap(),
            subject_key_ids: vec![],
            cohort_scope: crate::federation::types::cohort_scope::SELF.to_string(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        })
        .await
        .unwrap_or_else(|e| panic!("I141: the node writes a local-tier row: {e}"));
        let reads_local = |caller: &str| {
            let (caller, node) = (caller.to_owned(), node.clone());
            async move {
                let scope = caller_scope_from_directory(d, &caller).await.unwrap();
                let rust_twin = scope
                    .admits_local_tier(crate::federation::types::attestation_tier::LOCAL, &node);
                let rows = match crate::ceg::ReadEngine::list_attestations(
                    d,
                    crate::ceg::AttestationFilter {
                        attesting_key_id: Some(node.clone()),
                        dimension_prefixes: vec!["identity_binding".into()],
                        tier: Some(crate::ceg::list::federation::Tier::Local),
                        ..Default::default()
                    },
                    None,
                    10,
                    scope,
                )
                .await
                {
                    Ok(page) => Some(page.items.len()),
                    Err(crate::ceg::Error::Backend(m))
                        if m.contains("no relational read substrate") =>
                    {
                        None
                    }
                    Err(e) => panic!("I141: list_attestations: {e}"),
                };
                (rust_twin, rows)
            }
        };
        expect(
            reads_local(&node).await,
            true,
            1,
            "I141: the producing occurrence reads its own local-tier row",
        );
        expect(
            reads_local(&device).await,
            false,
            0,
            "I141: the owner's device does NOT read the node's local-tier row",
        );
        expect(
            reads_local(&owner).await,
            false,
            0,
            "I141: nor the owner's key",
        );
        expect(
            reads_local(&node_c).await,
            false,
            0,
            "I141: nor the owner's other node",
        );
        // Review (PR #889, P1): a SENSITIVE config leaf (CC 3.4.5.1,
        // `CONFIG_SENSITIVE_LEAVES`) is node-local by the write floor; the
        // collective widening must not carry it to the owner's other keys on
        // a shared node. Node-only: the caller IS the target.
        let mut row = ts::bare_attestation(
            &format!("i141-sensitive-{s}"),
            &node,
            &node,
            &serde_json::json!({"cohort_scope": "self", "dimension": "config:admission:v1"}),
        );
        row.attestation_type = "scores".into();
        row.cohort_scope = crate::federation::types::cohort_scope::SELF.into();
        row.subject_key_ids = vec![node.clone()];
        ts::seal_row_in_place(&node, &mut row);
        d.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("I141: the node writes its sensitive leaf at self: {e}"));
        expect(
            reads_dim(&node, &node, "config:admission", "config:admission:v1").await,
            true,
            1,
            "I141: the node reads its own sensitive leaf",
        );
        expect(
            reads_dim(&device, &node, "config:admission", "config:admission:v1").await,
            false,
            0,
            "I141: the owner's device does NOT read the node's sensitive leaf",
        );
        expect(
            reads_dim(&owner, &node, "config:admission", "config:admission:v1").await,
            false,
            0,
            "I141: nor does the owner's own key",
        );
        expect(
            reads_dim(&node_c, &node, "config:admission", "config:admission:v1").await,
            false,
            0,
            "I141: nor the owner's other node",
        );
        // Review (PR #889, P1): a REVOKED occurrence with a live owner binding
        // is the lost device. It reads its own rows and nothing of the
        // collective's; `speaks_for` says the same (one fold).
        assert!(
            crate::federation::self_collective::speaks_for(d, &node, &owner)
                .await
                .unwrap(),
            "I141: before revocation the node speaks for its owner"
        );
        revoke(d, &owner, &node, "2026-06-04T00:00:00Z").await;
        assert!(
            !crate::federation::self_collective::speaks_for(d, &node, &owner)
                .await
                .unwrap(),
            "I141: a revoked occurrence no longer speaks for its owner, owner binding or not"
        );
        expect(
            reads(&node).await,
            true,
            3,
            "I141: revoked, the node still reads its OWN rows — all three config rows, its sensitive leaf included",
        );
        expect(
            reads_of(&node, &device).await,
            false,
            0,
            "I141: revoked, the node no longer reads the device's row",
        );
        expect(
            reads_of(&node, &node_c).await,
            false,
            0,
            "I141: revoked, the node no longer reads the other node's row",
        );
        expect(
            reads(&device).await,
            true,
            2,
            "I141: the owner's device still reads the (owned) node's rows — the two plain ones, never the sensitive leaf",
        );
        let _ = CallerScope::Unauthenticated;
    }

    pub async fn i122_the_node_is_party_through_its_owner(d: &dyn FederationDirectory, s: &str) {
        let (node, owner, other, comm) = (
            format!("i122-node-{s}"),
            format!("i122-owner-{s}"),
            format!("i122-other-{s}"),
            format!("i122-room-{s}"),
        );
        for (k, t) in [(&node, NODE), (&owner, USER), (&other, USER)] {
            ts::register_identity_key(d, k, t).await;
        }
        bind(d, &node, &node, "2026-06-01T00:00:00Z").await;
        bind(d, &owner, &node, "2026-06-02T00:00:00Z").await;
        room(d, &comm, &[&owner, &other]).await;
        let memberships = crate::federation::replication::hold::audience_memberships(d, &node)
            .await
            .unwrap();
        assert!(
            memberships.contains(&comm),
            "I122: the node's audience is its owner's rooms: {memberships:?}"
        );
        holds(d, &node, &comm, &other)
            .await
            .expect("I122: party to a room the owner founded — the #873 refusal is gone");
        // The node's OWN roster membership is still its own: a room that
        // lists the node itself (an infrastructure co-op) is in its audience
        // with no principal involved.
        let own_room = format!("i122-own-{s}");
        room(d, &own_room, &[&node, &other]).await;
        let memberships = crate::federation::replication::hold::audience_memberships(d, &node)
            .await
            .unwrap();
        assert!(
            memberships.contains(&own_room),
            "I122: the node's own memberships are not lost to the principal walk: {memberships:?}"
        );
        holds(d, &node, &own_room, &other)
            .await
            .expect("I122: party in its own right");
        // A room the owner is NOT in stays refused: the fix widened nothing.
        let stranger_room = format!("i122-elsewhere-{s}");
        room(d, &stranger_room, &[&other]).await;
        let err = holds(d, &node, &stranger_room, &other)
            .await
            .expect_err("I122: not party to a room the owner is not in");
        assert!(matches!(err, BlobError::NotPartyTo { .. }), "I122: {err}");
    }

    /// **I123 — a revoked anchor returns the device to itself: the resolver
    /// answers the node, the owner's room leaves its audience, `would_hold`
    /// refuses `NotPartyTo` again.**
    pub async fn i123_a_revoked_anchor_is_the_singleton_again(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (node, owner, other, comm) = (
            format!("i123-node-{s}"),
            format!("i123-owner-{s}"),
            format!("i123-other-{s}"),
            format!("i123-room-{s}"),
        );
        for (k, t) in [(&node, NODE), (&owner, USER), (&other, USER)] {
            ts::register_identity_key(d, k, t).await;
        }
        bind(d, &node, &node, "2026-06-01T00:00:00Z").await;
        bind(d, &owner, &node, "2026-06-02T00:00:00Z").await;
        room(d, &comm, &[&owner, &other]).await;
        holds(d, &node, &comm, &other)
            .await
            .expect("I123: party while the anchor is live");
        revoke(d, &owner, &node, "2026-06-03T00:00:00Z").await;
        assert_eq!(
            d.active_identity_for_occurrence(&node).await.unwrap(),
            node,
            "I123: a revoked anchor is not a principal"
        );
        assert!(d
            .active_identities_for_occurrence(&node)
            .await
            .unwrap()
            .is_empty());
        let memberships = crate::federation::replication::hold::audience_memberships(d, &node)
            .await
            .unwrap();
        assert!(!memberships.contains(&comm), "I123: {memberships:?}");
        let err = holds(d, &node, &comm, &other)
            .await
            .expect_err("I123: the device speaks for itself again");
        assert!(matches!(err, BlobError::NotPartyTo { .. }), "I123: {err}");
    }

    /// **I124 — two live anchors: the plural lists both, newest first; the
    /// single resolver answers the newest; the audience is both humans'
    /// rooms.**
    pub async fn i124_a_shared_device_is_party_to_both(d: &dyn FederationDirectory, s: &str) {
        let (node, first, second, other) = (
            format!("i124-node-{s}"),
            format!("i124-a-{s}"),
            format!("i124-b-{s}"),
            format!("i124-other-{s}"),
        );
        for (k, t) in [
            (&node, NODE),
            (&first, USER),
            (&second, USER),
            (&other, USER),
        ] {
            ts::register_identity_key(d, k, t).await;
        }
        bind(d, &node, &node, "2026-06-01T00:00:00Z").await;
        bind(d, &first, &node, "2026-06-02T00:00:00Z").await;
        bind(d, &second, &node, "2026-06-03T00:00:00Z").await; // logged in later
        assert_eq!(
            d.active_identities_for_occurrence(&node).await.unwrap(),
            vec![second.clone(), first.clone()],
            "I124: every principal, newest binding first"
        );
        assert_eq!(
            d.active_identity_for_occurrence(&node).await.unwrap(),
            second,
            "I124: the single-valued answer is the newest binding (FSD §2)"
        );
        let (room_a, room_b) = (format!("i124-room-a-{s}"), format!("i124-room-b-{s}"));
        room(d, &room_a, &[&first, &other]).await;
        room(d, &room_b, &[&second, &other]).await;
        let memberships = crate::federation::replication::hold::audience_memberships(d, &node)
            .await
            .unwrap();
        assert!(
            memberships.contains(&room_a) && memberships.contains(&room_b),
            "I124: party to both humans' rooms: {memberships:?}"
        );
        holds(d, &node, &room_a, &other)
            .await
            .expect("I124: room of the older binding");
        holds(d, &node, &room_b, &other)
            .await
            .expect("I124: room of the newer binding");
    }

    /// **I125 — from disk: no `LIMIT 1` without an order at this site; the
    /// audience walk asks the plural.**
    #[test]
    fn i125_no_unordered_limit_one() {
        for (name, text) in [
            ("sqlite.rs", include_str!("../store/sqlite.rs")),
            ("postgres.rs", include_str!("../store/postgres.rs")),
        ] {
            let body = text
                .split("async fn lookup_identity_for_occurrence(")
                .nth(1)
                .unwrap_or_else(|| panic!("I125: {name} has lookup_identity_for_occurrence"));
            let body = &body[..body.find("\n    }\n").expect("end")];
            assert!(
                body.contains("ORDER BY"),
                "I125: {name} lookup_identity_for_occurrence orders its LIMIT 1"
            );
            let order = &body[body.find("ORDER BY").unwrap()..];
            assert!(
                order.contains("asserted_at DESC"),
                "I125: {name} orders newest binding first"
            );
        }
        let hold = include_str!("replication/hold.rs");
        let body = hold
            .split("pub async fn audience_memberships<")
            .nth(1)
            .expect("I125: audience_memberships");
        let body = &body[..body.find("\n}\n").expect("end")];
        assert!(
            body.contains("active_identities_for_occurrence("),
            "I125: the audience walk unions every principal"
        );
        assert!(
            !body.contains("active_identity_for_occurrence("),
            "I125: and no longer asks the single-valued resolver"
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
                use super::super::bodies;
                #[tokio::test]
                async fn i121() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i121_the_principal_is_the_owner(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i122() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i122_the_node_is_party_through_its_owner(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i123() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i123_a_revoked_anchor_is_the_singleton_again(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i124() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i124_a_shared_device_is_party_to_both(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i141() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i141_a_claimed_node_reads_its_own_self_rows(&b, &super::suffix()).await
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
