//! CIRISPersist#884 — witnesses for `FSD/SELF_COLLECTIVE_TRANSFER.md` §5
//! (I137–I140): self/family bytes are DELIVERED, not discovered. The send set
//! includes the self-collective without a consent row; the retroactive
//! re-grant reaches a device admitted after the write; the puller asks the
//! MINTER, never `list_holders`.
//!
//! v62.0.0 (the JSON cut): keys are live by their edition-2 `key:record`
//! (`edition2::fixture_switch::put_key`) and named by `kid(label)`; an owner
//! binding is the owner's row plus the node's voice. I137's family leg is its
//! own test, through the edition-2 group door (wave T1). I138/I139's node
//! set-up rides other slices' two-node fixtures
//! (`key_grant_invariants::two_node`, `epoch_minter_invariants`) and the
//! Engine's own key: since cut B (4deb020f) an engine's key is its
//! composite's identity-ref (`local_derived_key_id`), so they run on
//! edition 2: the owner by kid, owner bindings voiced by the engine's alias.

#![cfg(any(feature = "sqlite", feature = "postgres"))]

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::key_grant_invariants::two_node::{introduce_as, Node};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{self, CryptoTier};
    use crate::federation::types::identity_type::USER;
    use crate::federation::{
        AdoptDisposition, BlobBody, BlobProvenance, BlobStorage, EncryptionPubkeys,
        FederationDirectory, IdentityOccurrence,
    };
    use crate::Engine;
    use std::sync::Arc;

    pub(crate) type Pick<B> = fn(&Engine) -> Arc<B>;

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().unwrap()
    }

    /// Bind `occurrence` as an active occurrence of `identity` on `d`, with
    /// `kem` as its content-KEM keys. v62.0.0 (P1-fix4; CC rc21 3.3.6): a
    /// person's `occurrence` is a PERSON's key (a phone); a node key binds
    /// only its own identity (`bind(d, node, node, kem)`, its
    /// self-occurrence), and belongs to a person by its owner binding
    /// ([`own`], `key_grant_invariants::two_node::place_device`).
    pub(crate) async fn bind(
        d: &dyn FederationDirectory,
        identity: &str,
        occurrence: &str,
        kem: Option<EncryptionPubkeys>,
    ) {
        d.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            // v53.0.0 (#963, CC 3.3.7) — the owner's PERSONAL device: a
            // server-class occurrence receives none of its owner's `self`
            // content by default, and these witnesses are about the
            // self-collective reaching the owner's own devices.
            device_class: crate::federation::types::device_class::LAPTOP.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: kem,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("bind {identity} through {occurrence}: {e}"));
    }

    /// A key named as the store holds it: its kid under edition 2, the label
    /// in a test held under the earlier form.
    fn sid(x: &str) -> String {
        if e2::emit_edition2() {
            e2::kid_or_keep(x)
        } else {
            x.to_owned()
        }
    }

    /// `owner` (a seed) owns `node` (a seed): the owner binding row, then the
    /// node's voice over it.
    pub(crate) async fn own(d: &dyn FederationDirectory, owner: &str, node: &str) {
        own_seeded(d, owner, node, node).await;
    }

    /// `owner` (a seed) owns the key `node` (a kid or a seed), whose voice
    /// is signed by `node_seed` (an engine's alias: its composite is
    /// `signing_key(alias)`, its id `kid(alias)`).
    pub(crate) async fn own_seeded(
        d: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        node_seed: &str,
    ) {
        let row = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), owner, node);
        // v62.0.0 (E2-fix3; K2.api) — the owner's statement, then the bound
        // node's voice, through K2's shared helper (no hand-rolled voice).
        e2::land_owner_binding(d, &row, node_seed)
            .await
            .unwrap_or_else(|e| panic!("{owner} owns {node}: {e}"));
    }

    /// **I137 — the send set includes the self-collective, without a
    /// consent row; and only where the plane is `SelfOwn`.**
    pub(crate) async fn i137_the_send_set_is_the_self_collective(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner_s, node_a_s, node_b_s, peer_s) = (
            format!("i137-owner-{s}"),
            format!("i137-node-a-{s}"),
            format!("i137-node-b-{s}"),
            format!("i137-peer-{s}"),
        );
        for k in [&owner_s, &peer_s] {
            let _ = e2::put_key(d, k, &[USER]).await;
        }
        for k in [&node_a_s, &node_b_s] {
            let _ = e2::put_key(d, k, &[crate::federation::types::identity_type::NODE]).await;
        }
        let (owner, node_a, node_b) = (e2::kid(&owner_s), e2::kid(&node_a_s), e2::kid(&node_b_s));
        // v62.0.0 (P1-fix4; CC rc21 3.3.6) — a node key is never an
        // occurrence of a person: the node is the owner's by its OWNER
        // binding, and states its own class (a personal device) and KEM on
        // its own SELF-occurrence (`replication_audience::owned_device`).
        bind(d, &node_a, &node_a, None).await;
        bind(d, &node_b, &node_b, None).await;
        // The nodes are OWNED (a live delegates_to owner binding — every node
        // has exactly one human owner); the phone is an occurrence only: a
        // KEM target, not a replication endpoint (edge §6.1).
        own(d, &owner_s, &node_a_s).await;
        own(d, &owner_s, &node_b_s).await;
        let phone_s = format!("i137-phone-{s}");
        let _ = e2::put_key(d, &phone_s, &[USER]).await;
        let phone = e2::kid(&phone_s);
        bind(d, &owner, &phone, None).await;
        // v53.0.0 (#963, CC 3.3.7) — a node the owner OWNS but never bound as
        // an occurrence is not one of the owner's devices: it receives none of
        // the owner's self content (it still SENDS — its principal is its
        // owner by `owner_of`). Before v53 ownership alone was the endpoint
        // fact (#884).
        let node_c_s = format!("i137-node-c-{s}");
        let _ = e2::put_key(
            d,
            &node_c_s,
            &[crate::federation::types::identity_type::NODE],
        )
        .await;
        own(d, &owner_s, &node_c_s).await;
        let node_c = e2::kid(&node_c_s);
        let consent = crate::federation::consent_by_humans::consent_peers_by_principals(d, &node_a)
            .await
            .unwrap();
        assert!(
            !consent.contains(&node_b),
            "I137: there is NO consent row between an owner's own nodes (CC 3.2)"
        );
        let self_set =
            crate::federation::self_collective::send_set_for(d, &node_a, cohort_scope::SELF)
                .await
                .unwrap();
        assert!(
            self_set.contains(&node_b),
            "I137: the owner's other NODE is in the self send set: {self_set:?}"
        );
        assert!(
            !self_set.contains(&node_a),
            "I137: a node does not send to itself"
        );
        assert!(
            !self_set.contains(&phone),
            "I137: an occurrence that owns no node is not an endpoint: {self_set:?}"
        );
        assert!(
            !self_set.contains(&node_c),
            "I137: an owned node with no occurrence is not the owner's device (CC 3.3.7): {self_set:?}"
        );
        let c_set =
            crate::federation::self_collective::send_set_for(d, &node_c, cohort_scope::SELF)
                .await
                .unwrap();
        assert!(
            c_set.contains(&node_b) && c_set.contains(&node_a),
            "I137: an owned node that is no KEM occurrence SENDS to its owner's other nodes (principal by owner_of): {c_set:?}"
        );
        assert!(
            !self_set.contains(&owner),
            "I137: the human's key is not an endpoint: {self_set:?}"
        );
        for c in &consent {
            assert!(
                self_set.contains(c),
                "I137: the consent peers are still in it"
            );
        }
        let community_set =
            crate::federation::self_collective::send_set_for(d, &node_a, cohort_scope::COMMUNITY)
                .await
                .unwrap();
        assert_eq!(
            community_set, consent,
            "I137: a community plane's set is the consent set, unchanged"
        );
    }

    /// **I137 (family leg)** — a family member's device is in the FAMILY send
    /// set and not in the SELF set. v62.0.0: split out of
    /// [`i137_the_send_set_is_the_self_collective`] and run HELD under the
    /// earlier form: the family record rides the typed family plane, which
    /// has no edition-2 projection yet. Every fixture here follows the switch
    /// (`register_identity_key`, `put_owner_binding`, `sign_family`).
    pub(crate) async fn i137_the_family_set_reaches_a_family_members_device(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (owner, node_a, node_b) = (
            format!("i137f-owner-{s}"),
            format!("i137f-node-a-{s}"),
            format!("i137f-node-b-{s}"),
        );
        let (member, member_node, fam) = (
            format!("i137f-member-{s}"),
            format!("i137f-member-node-{s}"),
            format!("i137f-fam-{s}"),
        );
        for k in [&owner, &member, &fam] {
            ts::register_identity_key(d, k, USER).await;
        }
        for k in [&node_a, &node_b, &member_node] {
            ts::register_identity_key(d, k, crate::federation::types::identity_type::NODE).await;
        }
        // v62.0.0 (P1-fix4; CC rc21 3.3.6) — a node key is never an
        // occurrence of a person: the node is the owner's by its OWNER
        // binding, and states its own class (a personal device) and KEM on
        // its own SELF-occurrence (`replication_audience::owned_device`).
        bind(d, &sid(&node_a), &sid(&node_a), None).await;
        bind(d, &sid(&node_b), &sid(&node_b), None).await;
        bind(d, &sid(&member_node), &sid(&member_node), None).await;
        for (o, n) in [
            (&owner, &node_a),
            (&owner, &node_b),
            (&member, &member_node),
        ] {
            // Under edition 2 the binding carries the node's voice (`own`).
            if e2::emit_edition2() {
                own(d, o, n).await;
            } else {
                ts::put_owner_binding(d, o, n).await;
            }
        }
        let signed = ts::sign_family(
            &fam,
            crate::federation::Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.clone(),
                family_name: "Fam".into(),
                members: vec![
                    crate::federation::FamilyMember {
                        key_id: owner.clone(),
                        joined_at: at("2026-06-01T00:00:00Z"),
                        role: None,
                    },
                    crate::federation::FamilyMember {
                        key_id: member.clone(),
                        joined_at: at("2026-06-01T00:00:00Z"),
                        role: None,
                    },
                ],
                founded_at: at("2026-06-01T00:00:00Z"),
                consensus_protocol: "unanimous".into(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        // v62.0.0 (wave T1): the family lands through the edition-2 group
        // door as its founders' voices; held, through the typed door.
        if e2::emit_edition2() {
            let voices =
                e2::family_voices_naming_held(d, &signed, e2::ms(chrono::Utc::now())).await;
            e2::put_voices(d, &voices).await.unwrap();
        } else {
            d.put_family(signed).await.unwrap();
        }
        let family_set = crate::federation::self_collective::send_set_for(
            d,
            &sid(&node_a),
            cohort_scope::FAMILY,
        )
        .await
        .unwrap();
        assert!(
            family_set.contains(&sid(&member_node)),
            "I137: a family member's device is in the family set: {family_set:?}"
        );
        assert!(
            family_set.contains(&sid(&node_b)),
            "I137: and so is the owner's other device"
        );
        let self_set =
            crate::federation::self_collective::send_set_for(d, &sid(&node_a), cohort_scope::SELF)
                .await
                .unwrap();
        assert!(
            !self_set.contains(&sid(&member_node)),
            "I137: a family member's device is NOT in the self set"
        );
    }

    /// **I139 — `minter_of_blob`: the community binding's minter, and the
    /// content set's attester for self; `None` for an unknown sha.**
    pub(crate) async fn i139_minter_of_blob<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = crate::federation::epoch_minter_invariants::bodies::ladder(dsn_a, dsn_b, run, pick)
            .await;
        let r = l
            .engine_a
            .put_blob_scoped(
                cohort_scope::COMMUNITY,
                Some(&l.comm),
                b"community minter",
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            l.ba.minter_of_blob(&r.at_rest_sha256)
                .await
                .unwrap()
                .as_deref(),
            Some(l.node_a.as_str()),
            "I139: a community blob's minter is the epoch binding's"
        );
        let unknown = [7u8; 32];
        assert_eq!(
            l.ba.minter_of_blob(&unknown).await.unwrap(),
            None,
            "I139: unknown sha → None"
        );
        // self: seal on A, carry the content set to B, ask B.
        // A PERSON authors the self write; the node that seals it is the
        // person's occurrence. The minter is the NODE — never the author.
        let owner = format!("i139-owner-{run}");
        ts::register_hybrid_key_as(l.ba.as_ref(), &owner, &owner, USER).await;
        ts::register_hybrid_key_as(l.bb.as_ref(), &owner, &owner, USER).await;
        // v62.0.0 (cut B): the owner is live as its kid; reads and the self
        // write name it so.
        let owner = e2::kid(&owner);
        let kem_a = {
            let id = l.ba.load_or_init_content_kem_identity().await.unwrap();
            EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            }
        };
        bind(l.ba.as_ref(), &owner, &l.node_a, Some(kem_a.clone())).await;
        // B is the owner's occurrence too, known to A before the seal: a row
        // is addressed to one occurrence, so A's row to B is what crosses
        // (v55.0.0, #989).
        let kem_b = {
            let id = l.bb.load_or_init_content_kem_identity().await.unwrap();
            EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            }
        };
        bind(l.ba.as_ref(), &owner, &l.node_b, Some(kem_b.clone())).await;
        let rs = l
            .engine_a
            .put_blob_scoped(cohort_scope::SELF, Some(&owner), b"self minter", None, None)
            .await
            .unwrap();
        assert_eq!(rs.tier, CryptoTier::InvisibleEncrypted);
        assert_eq!(
            l.ba.minter_of_blob(&rs.at_rest_sha256)
                .await
                .unwrap()
                .as_deref(),
            Some(l.node_a.as_str()),
            "I139: the self blob's minter is the sealing NODE, not the author"
        );
        assert_ne!(
            owner, l.node_a,
            "I139: the fixture's point — author ≠ sealer"
        );
        // The content set is emitted by the door or drained by the host's
        // emission sweep — the same sweep edge runs; either way it is a row.
        l.engine_a.emit_pending_key_grants().await.unwrap();
        // v55.0.0 (#989) — the content rows A's plane delivers to B.
        let sets = crate::federation::key_grant_invariants::two_node::key_grant_rows_for(
            l.ba.as_ref(),
            &l.node_a,
            &l.node_b,
        )
        .await
        .into_iter()
        .filter(|a| {
            a.attestation
                .attestation_envelope
                .get("at_rest_sha256")
                .and_then(|v| v.as_str())
                == Some(hex::encode(rs.at_rest_sha256).as_str())
        })
        .collect::<Vec<_>>();
        assert!(
            !sets.is_empty(),
            "I139: the self write emitted a content row for B"
        );
        // B knows A is the owner's occurrence (the binding's own plane), so
        // A speaks for the owner on B as on A.
        bind(l.bb.as_ref(), &owner, &l.node_a, Some(kem_a)).await;
        bind(l.bb.as_ref(), &owner, &l.node_b, Some(kem_b)).await;
        for a in &sets {
            l.engine_b
                .apply_replicated_key_grant(a.clone())
                .await
                .unwrap_or_else(|e| panic!("I139: B admits A's content row: {e:?}"));
        }
        // The peer ADOPTS the bytes with the row's author — the PERSON — so
        // its provenance names the author and the set names the sealer; the
        // read must answer the sealer. (B is the owner's occurrence too.)
        let Some(BlobBody::Inline(bytes)) = l.ba.get_blob(&rs.at_rest_sha256).await.unwrap() else {
            panic!("inline")
        };
        l.engine_b
            .adopt_sealed_blob(
                &bytes,
                BlobProvenance {
                    author_key_id: owner.clone(),
                    cohort_scope: cohort_scope::SELF.to_owned(),
                    community_key_id: None,
                    epoch: None,
                    tier: CryptoTier::InvisibleEncrypted,
                    minter_key_id: Some(l.node_a.clone()),
                },
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("I139: the peer adopts the person-authored self bytes");
        let on_b = l.bb.minter_of_blob(&rs.at_rest_sha256).await.unwrap();
        assert_eq!(
            on_b.as_deref(),
            Some(l.node_a.as_str()),
            "I139: on the peer, a self blob's minter is the content set's attester, not the row's author"
        );
        assert_ne!(on_b.as_deref(), Some(owner.as_str()));
    }

    /// **I138 — a device admitted after the write opens the write.** Seal a
    /// self blob on A while A is the only occurrence; then B becomes an
    /// occurrence of A's owner; the retroactive re-key on A emits the content
    /// set naming B; carried to B, the bytes adopted `LocalOnly`, B opens.
    pub(crate) async fn i138_a_device_admitted_after_the_write_opens_it<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (alias_a, alias_b) = (format!("sc-a-{run}"), format!("sc-b-{run}"));
        let engine_a = Engine::with_signer_pre_genesis(ts::local_signer(&alias_a), dsn_a)
            .await
            .unwrap();
        let engine_b = Engine::with_signer_pre_genesis(ts::local_signer(&alias_b), dsn_b)
            .await
            .unwrap();
        // The engines are NODES (a user target would make the owner binding
        // below a custody claim, refused for an age-unverified user).
        for (e, _alias) in [(&engine_a, &alias_a), (&engine_b, &alias_b)] {
            e.register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                None,
                None,
            )
            .await
            .unwrap();
        }
        let (sa, sb) = (pick(&engine_a), pick(&engine_b));
        let kem =
            |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            };
        let a = Node {
            backend: sa.as_ref(),
            signer: ts::local_signer(&alias_a),
            key: engine_a.local_derived_key_id().await.unwrap(),
            kem: kem(sa.load_or_init_content_kem_identity().await.unwrap()),
        };
        let b = Node {
            backend: sb.as_ref(),
            signer: ts::local_signer(&alias_b),
            key: engine_b.local_derived_key_id().await.unwrap(),
            kem: kem(sb.load_or_init_content_kem_identity().await.unwrap()),
        };
        introduce_as(
            &[&a, &b],
            &[&alias_a, &alias_b],
            crate::federation::types::identity_type::NODE,
        )
        .await;
        // The owner, with A as the only occurrence, on both nodes.
        // v62.0.0 (cut B): the owner is live as its kid (`owner`), signed by
        // its seed (`owner_s`); a node's key is its engine's identity-ref
        // (`local_derived_key_id`), voiced by its alias.
        let owner_s = format!("sc-owner-{run}");
        let owner = e2::kid(&owner_s);
        for n in [&a, &b] {
            ts::register_hybrid_key_as(n.backend, &owner_s, &owner_s, USER).await;
            // v62.0.0 (P1-fix4; CC rc21 3.3.6): A's own self-occurrence
            // (its class and KEM), and the owner's binding of A.
            bind(n.backend, &a.key, &a.key, Some(a.kem.clone())).await;
            own_seeded(n.backend, &owner_s, &a.key, &alias_a).await;
        }
        let r = engine_a
            .put_blob_scoped(
                cohort_scope::SELF,
                Some(&owner),
                b"before the second device existed",
                None,
                None,
            )
            .await
            .expect("A seals a self blob");
        let sha = r.at_rest_sha256;
        // Now B becomes an occurrence of the owner (on both nodes), AFTER the write.
        for n in [&a, &b] {
            bind(n.backend, &b.key, &b.key, Some(b.kem.clone())).await;
            own_seeded(n.backend, &owner_s, &b.key, &alias_b).await;
        }
        assert!(
            crate::federation::self_collective::send_set_for(
                sa.as_ref(),
                &a.key,
                cohort_scope::SELF
            )
            .await
            .unwrap()
            .contains(&b.key),
            "I138: B is in A's self send set with no grant (R2)"
        );
        let rk = engine_a
            .rekey_self_occurrence_add(&owner, std::slice::from_ref(&b.key))
            .await
            .expect("I138: the retroactive re-key runs on A");
        assert!(
            rk.granted.iter().any(|(r, n)| r == &b.key && *n >= 1),
            "I138: a wrap for B was granted: {rk:?}"
        );
        // The sets A emitted travel to B (the R2 send set now names B).
        engine_a.emit_pending_key_grants().await.unwrap();
        // v55.0.0 (#989) — the content rows A's plane delivers to B.
        let sets = crate::federation::key_grant_invariants::two_node::key_grant_rows_for(
            sa.as_ref(),
            &a.key,
            &b.key,
        )
        .await;
        assert!(
            !sets.is_empty(),
            "I138: A emitted at least one content row for B (the re-key)"
        );
        // The rows arrive BEFORE the bytes (the ordinary case: B was offline
        // at write time): admitted, pending, nothing projected (I65). They are
        // signed by the NODE A, not the owner who authored the row — §4.1 is
        // what lets the adopt below project them.
        for s in &sets {
            let adm = engine_b
                .apply_replicated_key_grant(s.clone())
                .await
                .expect("I138: a node-signed content row is admitted");
            assert!(
                adm.pending && !adm.projected,
                "I138: pending until the bytes name the author: {adm:?}"
            );
        }
        // The bytes: B asks the MINTER (A), which holds them by construction.
        assert_eq!(
            sb.minter_of_blob(&sha).await.unwrap().as_deref(),
            Some(a.key.as_str()),
            "I138/R4"
        );
        let Some(BlobBody::Inline(bytes)) = sa.get_blob(&sha).await.unwrap() else {
            panic!("inline")
        };
        engine_b
            .adopt_sealed_blob(
                &bytes,
                BlobProvenance {
                    author_key_id: owner.clone(),
                    cohort_scope: cohort_scope::SELF.to_owned(),
                    community_key_id: None,
                    epoch: None,
                    tier: CryptoTier::InvisibleEncrypted,
                    minter_key_id: Some(a.key.clone()),
                },
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("I138: B adopts its owner's bytes LocalOnly (self arm: principal equality)");
        assert_eq!(
            engine_b
                .read_blob_as(&sha, &b.key, None)
                .await
                .expect("I138: B OPENS what A wrote before B existed"),
            b"before the second device existed"
        );
        // §4.1's other edge: a row for the same blob signed by a key that
        // shares NO principal with the author — a stranger who somehow knows
        // the DEK — is refused by name once the bytes name the author.
        let stranger_alias = format!("sc-stranger-{run}");
        let stranger = ts::local_signer(&stranger_alias);
        ts::register_hybrid_key_as(
            sb.as_ref(),
            &stranger.derived_key_id(),
            &stranger_alias,
            USER,
        )
        .await;
        let forged = crate::federation::key_grant::KeyGrantRow {
            axis: crate::federation::key_grant::KeyGrantAxis::Content {
                at_rest_sha256: hex::encode(sha),
                cohort_scope: cohort_scope::SELF.into(),
                owner_key_id: owner.clone(),
            },
            wrap: crate::federation::GrantWrap {
                recipient_key_id: b.key.clone(),
                wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
                wrapped_dek: "{}".into(),
            },
        };
        let signed = crate::federation::key_grant_invariants::two_node::sign_row_unstored(
            &stranger, &forged,
        )
        .await;
        let err = engine_b
            .apply_replicated_key_grant(signed)
            .await
            .expect_err("I138: a stranger's content row is refused once the bytes name the author");
        assert!(
            matches!(&err, crate::federation::Error::KeyGrantRefused { reason, .. }
                if *reason == crate::federation::key_grant::KeyGrantRefusalReason::SignerNotAuthor.as_str()),
            "I138: refused BY NAME, not by a neighbouring gate: {err}"
        );
    }

    /// **I140 — from disk: the three doors reach Python, and no claim was added.**
    #[test]
    fn i140_the_doors_reach_python_and_no_claim_was_added() {
        const PY: &str = include_str!("../ffi/pyo3.rs");
        for door in [
            "fn send_set_for_json(",
            "fn minter_of_blob_json(",
            "fn rekey_self_occurrence_add_json(",
            "fn rekey_family_member_add_json(",
        ] {
            assert!(PY.contains(door), "I140: {door} is on the PyO3 surface");
        }
        const TYPES: &str = include_str!("types.rs");
        assert!(
            TYPES.contains("matches!(s, SELF | FAMILY)"),
            "I140: is_structurally_invisible still says self | family — their claims stay in the cohort (CC 5.2)"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! dir_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i137() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i137_the_send_set_is_the_self_collective(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i137_family() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i137_the_family_set_reaches_a_family_members_device(
                        &b,
                        &super::suffix(),
                    )
                    .await
                }
            }
        };
    }
    macro_rules! engine_runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i138() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i138_a_device_admitted_after_the_write_opens_it(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i139() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i139_minter_of_blob(&a, &b, &super::suffix(), $pick).await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    dir_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    dir_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "sqlite")]
    engine_runners!(
        sqlite_engine,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
            as bodies::Pick<crate::store::sqlite::SqliteBackend>
    );
    #[cfg(feature = "postgres")]
    engine_runners!(
        postgres_engine,
        (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as bodies::Pick<crate::store::postgres::PostgresBackend>
    );
}
