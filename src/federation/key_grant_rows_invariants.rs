//! v55.0.0 (CIRISPersist#989, CC 3.3.2 rc7, CIRISConstitution#143) — I740–I749,
//! **the key-grant SET retired: one `scores` row per recipient.**
//!
//! - **I740** / **I741** (pure, `key_grant::tests`) — the row round-trips
//!   through its envelope on every axis; every departure from the shape is
//!   `malformed`, a retired set type `set_retired`.
//! - **I742** (memory, sqlite, postgres) — the admission rule at the attestation
//!   plane's own door: a SET row is refused (a retired carrier); a `key_grant:`
//!   dimension on a composer is `malformed`; a non-minter's epoch row is
//!   `signer_not_minter`; the minter's row to a member's occurrence admits and
//!   its row to a stranger is `recipient_not_in_audience`; a `withdraws` and a
//!   `recants` naming the admitted row are refused. Nothing refused is stored.
//! - **I743** (sqlite, postgres) — delivery through the planes: the sealer's
//!   serve gate hands each member node exactly its own row and a non-member
//!   node none; each row crosses through the generic
//!   `apply_replicated_attestation` (and `put_attestation_synced`), which
//!   projects the wrap; the held SET is not served.
//! - **I744** (sqlite, postgres) — re-emission is idempotent: a second
//!   emission of the same axis emits nothing, and a wrap whose recipient has
//!   left the audience is withheld.
//! - **I745** (sqlite, postgres) — THE UPGRADED NODE. A node holding v54 state
//!   (wraps in its grant tables, the axis marked emitted, its own legacy SET
//!   row) takes V192 and boots on the new code: the boot sweep re-emits each
//!   wrap as a per-recipient row, a recipient removed since is not re-wrapped,
//!   the legacy set is not served, the peer admits its row through the
//!   generic door and opens the blob, a set re-offered is refused, and a
//!   second boot emits nothing.

#![cfg(test)]

/// I746 (sqlite; v60 #1002 moved it off the retired memory backend) — a held retired carrier (a v54 SET row, planted below the
/// door) is never served by the since-read, under `Report`; a row planted
/// the same way of a registered type is (the control).
#[cfg(feature = "sqlite")]
mod sqlite_serve {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::FederationDirectory;

    #[tokio::test]
    async fn i746_never_serves_a_held_retired_carrier() {
        let m = crate::store::test_backend::test_backend();
        let control = ts::owner_binding_attestation("i746-control", "i746-owner", "i746-node");
        let mut set = ts::owner_binding_attestation("i746-set", "i746-owner", "i746-node");
        set.attestation_type = crate::federation::key_grant::KEY_GRANT_EPOCH_DIMENSION.into();
        m.plant_attestation_below_the_door(control);
        m.plant_attestation_below_the_door(set);
        let served: Vec<String> = m
            .list_attestations_since(None, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.attestation.attestation_id)
            .collect();
        assert!(
            served.iter().any(|id| id == "i746-control"),
            "I746 control: {served:?}"
        );
        assert!(
            !served.iter().any(|id| id == "i746-set"),
            "I746: {served:?}"
        );
    }
}

/// I742 — the admission rule, at the attestation plane's door, on any
/// directory (no blob plane needed). It signs through the two-node harness,
/// which is backend-gated.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) mod directory {
    use crate::federation::key_grant::{KeyGrantAxis, KeyGrantRefusalReason, KeyGrantRow};
    use crate::federation::key_grant_invariants::two_node::sign_row_unstored;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::{Error, FederationDirectory, GrantWrap, SignedAttestation};

    fn wrap(r: &str) -> GrantWrap {
        GrantWrap {
            recipient_key_id: r.to_owned(),
            wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
            wrapped_dek: "{}".into(),
        }
    }

    fn reason(e: &Error) -> &'static str {
        match e {
            Error::KeyGrantRefused { reason, .. } => reason,
            other => panic!("expected a typed KeyGrantRefused, got {other:?}"),
        }
    }

    async fn occurrence<D: FederationDirectory + ?Sized>(d: &D, identity: &str, occ: &str) {
        d.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occ.to_owned(),
            device_class: crate::federation::types::device_class::LAPTOP.into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now() - chrono::Duration::seconds(5),
            valid_until: None,
            encryption_pubkeys: Some({
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                let (_, x_pub, _, ml_pub) =
                    crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
                crate::federation::EncryptionPubkeys {
                    x25519_base64: B64.encode(x_pub),
                    ml_kem_768_base64: B64.encode(&ml_pub),
                }
            }),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("occurrence {occ} of {identity}: {e}"));
    }

    /// **I742** — see the module doc.
    pub(crate) async fn i742_the_row_rule_at_the_plane_door<D>(d: &D, s: &str)
    where
        D: FederationDirectory + Sync + 'static,
    {
        let comm = format!("i742-comm-{s}");
        let (alice, bob) = (format!("i742-alice-{s}"), format!("i742-bob-{s}"));
        let minter = ts::local_signer(&format!("i742-minter-{s}"));
        let mallory = ts::local_signer(&format!("i742-mallory-{s}"));
        let (m_key, mal_key) = (minter.derived_key_id(), mallory.derived_key_id());
        let bob_dev = format!("i742-bobdev-{s}");
        // A key that is no member's occurrence.
        let x_key = format!("i742-stranger-{s}");
        for (k, alias) in [
            (&m_key, format!("i742-minter-{s}")),
            (&mal_key, format!("i742-mallory-{s}")),
        ] {
            ts::register_hybrid_key_as(d, k, &alias, USER).await;
        }
        for k in [&comm, &alice, &bob, &bob_dev, &x_key] {
            ts::register_hybrid_key_as(d, k, k, USER).await;
        }
        occurrence(d, &alice, &m_key).await;
        occurrence(d, &bob, &bob_dev).await;
        // Mallory is a member's device (bob's), so the write-scope gate admits
        // her and the key-grant rule is what refuses: she is not the minter.
        occurrence(d, &bob, &mal_key).await;
        d.put_community(ts::sign_community(
            &comm,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: comm.clone(),
                community_name: "I742 Co-op".into(),
                members: [&alice, &bob]
                    .into_iter()
                    .map(|k| crate::federation::types::CommunityMember {
                        key_id: k.clone(),
                        joined_at: chrono::Utc::now() - chrono::Duration::seconds(60),
                        role: None,
                    })
                    .collect(),
                founded_at: chrono::Utc::now() - chrono::Duration::seconds(60),
                consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                    .to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("I742 seed community: {e}"));
        let row_to = |recipient: &str| KeyGrantRow {
            axis: KeyGrantAxis::Epoch {
                community_key_id: comm.clone(),
                minter_key_id: m_key.clone(),
                epoch: 0,
            },
            wrap: wrap(recipient),
        };
        let put = |a: crate::federation::Attestation| async move {
            let id = a.attestation_id.clone();
            let r = d
                .put_attestation(SignedAttestation { attestation: a })
                .await
                .map(|_| ());
            (id, r)
        };

        // A row signed under another attestation_type (a forger's shapes),
        // with a valid signature, so the door's own rules are what answer.
        // The mint refuses a retired carrier, so this skips the mint's slot.
        let signed_as = |t: &'static str| {
            let row = row_to(&bob_dev);
            let (minter, bob_dev) = (minter.clone(), bob_dev.clone());
            async move {
                let mut input = row.emit_input().unwrap();
                input.attestation_type = t.to_owned();
                input.attested_key_id = Some(bob_dev);
                let key = minter.derived_key_id();
                let canonical = crate::federation::attestation_emit::stamp_and_canonicalize(
                    &mut input,
                    &key,
                    chrono::Utc::now(),
                )
                .unwrap();
                let sig = minter.sign_hybrid(&canonical).await.unwrap();
                crate::federation::attestation_emit::assemble_for_door_witness(
                    key, &canonical, sig, input,
                )
                .unwrap()
                .0
            }
        };

        // (1) A SET row — the retired rc6 carrier — is refused.
        let (id, r) =
            put(signed_as(crate::federation::key_grant::KEY_GRANT_EPOCH_DIMENSION).await).await;
        // The plane door's row-type gate: a retired carrier (CC 2.4 rc7).
        let e = r.expect_err("I742 (1)");
        assert!(
            matches!(&e, Error::AttestationTypeUnregistered { .. }),
            "I742 (1): {e:?}"
        );
        assert!(d.get_attestation(&id).await.unwrap().is_none(), "I742 (1)");

        // (2) A `key_grant:` dimension on a composer is no key-grant row.
        // At the door the targeted-cohort gate may answer first (a composer
        // naming bob at community scope); the key-grant rule itself, asked
        // directly, names it malformed.
        let composer = signed_as(crate::federation::types::attestation_type::DELEGATES_TO).await;
        assert_eq!(
            reason(
                &crate::federation::key_grant::check_key_grant_row_admission(
                    d as &dyn FederationDirectory,
                    &composer
                )
                .await
                .expect_err("I742 (2) the rule")
            ),
            "malformed"
        );
        let (id, r) = put(composer).await;
        let e = r.expect_err("I742 (2)");
        assert!(
            matches!(&e, Error::CohortStandingRefused { .. })
                || matches!(
                    &e,
                    Error::KeyGrantRefused {
                        reason: "malformed",
                        ..
                    }
                ),
            "I742 (2): {e:?}"
        );
        assert!(d.get_attestation(&id).await.unwrap().is_none(), "I742 (2)");

        // (3) Mallory signs the minter's counter.
        let (id, r) = put(sign_row_unstored(&mallory, &row_to(&bob_dev))
            .await
            .attestation)
        .await;
        let refused = reason(&r.expect_err("I742 (3)"));
        assert_eq!(refused, "signer_not_minter");
        // v60.1.0 (CIRISPersist#1064) — the token the door raised classifies
        // through persist's own predicate: a sealer refusal is terminal.
        assert_eq!(
            KeyGrantRefusalReason::from_token(refused).map(KeyGrantRefusalReason::is_retryable),
            Some(false),
            "I742 (3) / #1064: signer_not_minter is terminal"
        );
        assert!(d.get_attestation(&id).await.unwrap().is_none(), "I742 (3)");

        // (4) The minter to a key that is no member's occurrence.
        let (id, r) = put(sign_row_unstored(&minter, &row_to(&x_key))
            .await
            .attestation)
        .await;
        let refused = reason(&r.expect_err("I742 (4)"));
        assert_eq!(refused, "recipient_not_in_audience");
        // v60.1.0 (CIRISPersist#1064) — an ordering gap: the recipient's
        // occurrence may land later, so the same row is re-offered.
        assert_eq!(
            KeyGrantRefusalReason::from_token(refused).map(KeyGrantRefusalReason::is_retryable),
            Some(true),
            "I742 (4) / #1064: recipient_not_in_audience is retryable"
        );
        assert!(d.get_attestation(&id).await.unwrap().is_none(), "I742 (4)");

        // (5) The minter to bob's device: admitted.
        let (row_id, r) = put(sign_row_unstored(&minter, &row_to(&bob_dev))
            .await
            .attestation)
        .await;
        r.unwrap_or_else(|e| panic!("I742 (5) the minter's row to a member's device: {e}"));
        assert!(d.get_attestation(&row_id).await.unwrap().is_some());

        // (6) Never withdrawn: a `withdraws` (any signer) and the sealer's own
        // `recants` naming the row are refused.
        for (kind, ty) in [
            (
                "withdraws",
                crate::federation::types::attestation_type::WITHDRAWS,
            ),
            (
                "recants",
                crate::federation::types::attestation_type::RECANTS,
            ),
        ] {
            let cid = format!("i742-{kind}-{s}");
            let mut c = ts::bare_attestation(
                &cid,
                &m_key,
                &m_key,
                &serde_json::json!({
                    "id": cid,
                    "kind": kind,
                    "references_attestation_id": row_id,
                }),
            );
            c.attestation_type = ty.to_owned();
            let c = ts::seal_row(&m_key, c);
            let e =
                crate::federation::admission::check_withdraws_admission(d.as_dyn_directory(), &c)
                    .await
                    .expect_err("I742 (6) a composer naming a key-grant row is refused");
            assert!(
                e.to_string().contains("cannot be retroactively"),
                "I742 (6) {kind}: {e}"
            );
        }
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                fn suffix() -> String {
                    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
                }
                #[tokio::test]
                async fn i742() {
                    let Some(b) = $fresh.await else { return };
                    super::i742_the_row_rule_at_the_plane_door(&b, &suffix()).await
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

/// I743–I745 — two nodes, over a blob-capable backend.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) mod two_nodes {
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::key_grant::{
        emit_epoch_key_grant_with_local_signer, is_key_grant_row, KeyGrantAxis, KeyGrantRow,
        KEY_GRANT_EPOCH_DIMENSION,
    };
    use crate::federation::key_grant_invariants::two_node::{
        carry_bytes, seed_community_everywhere, Node,
    };
    use crate::federation::replication_audience::may_receive;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
    use crate::federation::types::identity_type::USER;
    use crate::federation::{BlobStorage, FederationDirectory, SignedAttestation};

    /// The key-grant rows `n` signed on `(comm, minter, epoch)`.
    pub(crate) async fn rows_signed<B: FederationDirectory + Sync + ?Sized>(
        n: &B,
        signer: &str,
        comm: &str,
        epoch: u64,
    ) -> Vec<(crate::federation::Attestation, KeyGrantRow)> {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        n.all_attestations_by(signer)
            .await
            .unwrap()
            .into_iter()
            .filter(is_key_grant_row)
            .filter_map(|a| KeyGrantRow::from_attestation(&a).ok().map(|r| (a, r)))
            .filter(|(_, r)| {
                matches!(&r.axis, KeyGrantAxis::Epoch { community_key_id, epoch: e, .. }
                    if community_key_id == comm && *e == epoch)
            })
            .collect()
    }

    /// **I743** — see the module doc. `c` is a third member; `out` a node of
    /// nobody's.
    pub(crate) async fn i743_delivery_through_the_planes<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        c: &Node<'_, B>,
        out: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let (alice, bob, carol) = (
            format!("{tag}-alice-{run}"),
            format!("{tag}-bob-{run}"),
            format!("{tag}-carol-{run}"),
        );
        seed_community_everywhere(
            &[a, b, c],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&carol, Some(c))],
        )
        .await;
        let sealed =
            encrypt_and_cascade_community(a.backend, &comm, b"three ways", None, Some(&a.key))
                .await
                .unwrap_or_else(|e| panic!("{tag} I743: A seals: {e}"));
        let emitted = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("A holds wraps");
        assert_eq!(
            emitted.attestation_ids.len(),
            3,
            "{tag} I743: one row per recipient (A, B, C): {emitted:?}"
        );
        // The serve gate on A: each node gets its own row and only that.
        let served: Vec<_> = a
            .backend
            .list_attestations_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.attestation)
            .filter(|r| emitted.attestation_ids.contains(&r.attestation_id))
            .collect();
        assert_eq!(served.len(), 3, "{tag} I743: every row is on the cursor");
        for (node, label) in [(b, "B"), (c, "C"), (out, "outsider")] {
            let mut mine = Vec::new();
            for r in &served {
                if may_receive(a.backend, &node.key, r)
                    .await
                    .unwrap()
                    .allowed()
                {
                    mine.push(r.clone());
                }
            }
            if label == "outsider" {
                assert!(mine.is_empty(), "{tag} I743: a non-member node gets no row");
                continue;
            }
            assert_eq!(
                mine.len(),
                1,
                "{tag} I743: {label} gets exactly its own row"
            );
            assert_eq!(mine[0].attested_key_id, node.key, "{tag} I743: {label}");
            // Through the generic door (B), and the attributed sync door (C).
            let row = mine.remove(0);
            if label == "B" {
                node.backend
                    .apply_replicated_attestation(SignedAttestation { attestation: row })
                    .await
                    .unwrap_or_else(|e| panic!("{tag} I743: B admits its row: {e}"));
            } else {
                node.backend
                    .put_attestation_synced(SignedAttestation { attestation: row }, &a.key)
                    .await
                    .unwrap_or_else(|e| panic!("{tag} I743: C admits its row over sync: {e}"));
            }
            assert!(
                node.backend
                    .community_dek_has_member_grant(&comm, &a.key, 0, &node.key)
                    .await
                    .unwrap(),
                "{tag} I743: the typed door projected {label}'s wrap"
            );
            // …and only its own.
            let other = if label == "B" { &c.key } else { &b.key };
            assert!(
                !node
                    .backend
                    .community_dek_has_member_grant(&comm, &a.key, 0, other)
                    .await
                    .unwrap(),
                "{tag} I743: {label} holds no other recipient's wrap"
            );
        }
        // B opens the bytes with the key that crossed.
        carry_bytes(
            a,
            b,
            &sealed.at_rest_sha256,
            COMMUNITY,
            &comm,
            Some(0),
            CryptoTier::CommunityDek,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer(
                b.backend,
                &sealed.at_rest_sha256,
                &b.key,
                None,
            )
            .await
            .unwrap(),
            b"three ways"
        );
    }

    /// **I744** — see the module doc.
    pub(crate) async fn i744_reemission_is_idempotent_and_rechecks<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let (alice, bob, xavier) = (
            format!("{tag}-alice-{run}"),
            format!("{tag}-bob-{run}"),
            format!("{tag}-xavier-{run}"),
        );
        seed_community_everywhere(
            &[a, b],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&xavier, None)],
        )
        .await;
        let x_occ = format!("{tag}-x-occ-{run}");
        ts::register_hybrid_key_as(a.backend, &x_occ, &x_occ, USER).await;
        crate::federation::at_rest_cascade::blob_invariants::join_as_occurrence(
            a.backend, &xavier, &x_occ,
        )
        .await;
        let sealed = encrypt_and_cascade_community(a.backend, &comm, b"once", None, Some(&a.key))
            .await
            .unwrap();
        assert!(sealed.granted.contains(&x_occ), "{tag} I744: X wrapped");
        // X leaves BEFORE the first emission: the wrap stays local, no row.
        let rev = ts::sign_community_membership_revocation(
            &xavier,
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: comm.clone(),
                removed_identity_key_id: xavier.clone(),
                removed_at: chrono::Utc::now(),
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        a.backend
            .put_community_membership_revocation(rev)
            .await
            .unwrap();
        let first = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("wraps");
        assert_eq!(first.attestation_ids.len(), 2, "{tag} I744: {first:?}");
        assert_eq!(first.withheld, vec![x_occ.clone()], "{tag} I744: {first:?}");
        assert!(
            rows_signed(a.backend, &a.key, &comm, 0)
                .await
                .iter()
                .all(|(_, r)| r.recipient() != x_occ),
            "{tag} I744: no row to the removed member (CC 4.4.3.2.2)"
        );
        // The second emission of the same axis emits nothing new.
        let second = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("wraps");
        assert!(second.attestation_ids.is_empty(), "{tag} I744: {second:?}");
        assert_eq!(second.already_emitted.len(), 2, "{tag} I744: {second:?}");
        assert_eq!(
            rows_signed(a.backend, &a.key, &comm, 0).await.len(),
            2,
            "{tag} I744: still one row per admitted recipient"
        );
        let _ = b;
    }

    /// Replay V192's bytes over `backend` — the upgrade step, as the migration
    /// runner runs it on a node that took v54's migrations.
    pub(crate) type ReplayV192<B> =
        fn(&B) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

    /// Write a held legacy SET row below the doors (the v54 node stored it
    /// through the door that admitted sets then).
    pub(crate) type SeedHeldRow<B> =
        fn(
            &B,
            crate::federation::Attestation,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;

    /// **I745** — see the module doc. `boot` constructs an Engine over the
    /// node's database (the boot sweep runs inside it).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn i745_the_upgraded_node<B, F, Fut>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        boot: F,
        replay_v192: ReplayV192<B>,
        seed_held: SeedHeldRow<B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = crate::Engine>,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let (alice, bob, xavier) = (
            format!("{tag}-alice-{run}"),
            format!("{tag}-bob-{run}"),
            format!("{tag}-xavier-{run}"),
        );
        seed_community_everywhere(
            &[a, b],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&xavier, None)],
        )
        .await;
        let x_occ = format!("{tag}-x-occ-{run}");
        ts::register_hybrid_key_as(a.backend, &x_occ, &x_occ, USER).await;
        crate::federation::at_rest_cascade::blob_invariants::join_as_occurrence(
            a.backend, &xavier, &x_occ,
        )
        .await;
        // ── v54 state ─────────────────────────────────────────────────
        // The cascade wrote the wraps (A, B, X) to the grant tables...
        let sealed =
            encrypt_and_cascade_community(a.backend, &comm, b"legacy minutes", None, Some(&a.key))
                .await
                .unwrap();
        assert!(sealed.granted.contains(&x_occ) && sealed.granted.contains(&b.key));
        // ...the v54 emitter carried them as ONE set row, signed by A...
        let set = crate::federation::key_grant::build_epoch_set(a.backend, &comm, &a.key, 0)
            .await
            .unwrap()
            .expect("A holds wraps");
        let legacy = {
            let env = serde_json::json!({
                "kind": "key_grant",
                "axis": "epoch",
                "community_key_id": comm,
                "minter_key_id": a.key,
                "epoch": 0,
                "wraps": set.wraps.iter().map(|w| serde_json::json!({
                    "recipient_occurrence_key_id": w.recipient_key_id,
                    "wrap_algorithm": w.wrap_algorithm,
                    "wrapped_dek": w.wrapped_dek,
                })).collect::<Vec<_>>(),
            });
            let mut input = crate::federation::EmitAttestationInput::with_envelope(
                KEY_GRANT_EPOCH_DIMENSION,
                crate::federation::envelope::EnvelopeCore::from_value(env).unwrap(),
                COMMUNITY,
            );
            let canonical = crate::federation::attestation_emit::stamp_and_canonicalize(
                &mut input,
                &a.key,
                chrono::Utc::now(),
            )
            .unwrap();
            let sig = a.signer.sign_hybrid(&canonical).await.unwrap();
            // A v54 node minted it; v55's mint refuses the retired carrier.
            crate::federation::attestation_emit::assemble_for_door_witness(
                a.key.clone(),
                &canonical,
                sig,
                input,
            )
            .unwrap()
            .0
        };
        let legacy_id = legacy.attestation_id.clone();
        seed_held(a.backend, legacy.clone()).await;
        // ...and marked the axis emitted.
        let wm = a
            .backend
            .community_dek_key_grant_watermark(&comm, &a.key, 0)
            .await
            .unwrap()
            .expect("a grant exists");
        a.backend
            .community_dek_mark_key_grant_emitted(&comm, &a.key, 0, wm)
            .await
            .unwrap();
        assert!(
            !a.backend
                .community_dek_key_grant_dirty(&comm, &a.key, 0)
                .await
                .unwrap(),
            "{tag} I745 precondition: the v54 node holds the axis clean"
        );
        // X left while the node ran v54.
        let rev = ts::sign_community_membership_revocation(
            &xavier,
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: comm.clone(),
                removed_identity_key_id: xavier.clone(),
                removed_at: chrono::Utc::now(),
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        a.backend
            .put_community_membership_revocation(rev)
            .await
            .unwrap();
        assert!(rows_signed(a.backend, &a.key, &comm, 0).await.is_empty());

        // ── the upgrade: V192, then the boot ──────────────────────────
        replay_v192(a.backend).await;
        assert!(
            a.backend
                .community_dek_key_grant_dirty(&comm, &a.key, 0)
                .await
                .unwrap(),
            "{tag} I745: V192 marks the axis dirty"
        );
        let engine = boot().await;
        let rows = rows_signed(a.backend, &a.key, &comm, 0).await;
        let mut recipients: Vec<String> =
            rows.iter().map(|(_, r)| r.recipient().to_owned()).collect();
        recipients.sort();
        let mut want = vec![a.key.clone(), b.key.clone()];
        want.sort();
        assert_eq!(
            recipients, want,
            "{tag} I745: the boot re-emitted one row per recipient still in the audience; the \
             removed member is not re-wrapped"
        );
        assert!(
            !a.backend
                .community_dek_key_grant_dirty(&comm, &a.key, 0)
                .await
                .unwrap(),
            "{tag} I745: and the axis is clean again"
        );
        // The legacy set is held, not served (either serve read).
        assert!(a
            .backend
            .get_attestation(&legacy_id)
            .await
            .unwrap()
            .is_some());
        let served = a
            .backend
            .list_attestations_since(None, 10_000)
            .await
            .unwrap();
        assert!(
            served
                .iter()
                .all(|s| s.attestation.attestation_id != legacy_id),
            "{tag} I745: the legacy set is not on the cursor"
        );
        // The peer: the set is refused, the row admitted through the generic
        // door, the bytes open.
        // The plane door: a retired carrier, refused by the row-type gate.
        let e = b
            .backend
            .apply_replicated_attestation(SignedAttestation {
                attestation: legacy.clone(),
            })
            .await
            .expect_err("a set is refused");
        assert!(
            matches!(
                &e,
                crate::federation::Error::AttestationTypeUnregistered { .. }
            ),
            "{tag} I745 (plane door): {e:?}"
        );
        // The key-grant door: `set_retired`, in its own token.
        let e = crate::federation::key_grant::admit_replicated_key_grant(
            b.backend,
            crate::federation::key_grant::SignedKeyGrantRow {
                attestation: legacy,
            },
        )
        .await
        .expect_err("a set is refused at the key-grant door");
        assert!(
            matches!(&e, crate::federation::Error::KeyGrantRefused { reason, .. }
                if *reason == "set_retired"),
            "{tag} I745 (key-grant door): {e:?}"
        );
        let to_b = rows
            .iter()
            .find(|(_, r)| r.recipient() == b.key)
            .map(|(a, _)| a.clone())
            .unwrap();
        assert!(may_receive(a.backend, &b.key, &to_b)
            .await
            .unwrap()
            .allowed());
        // B already HOLDS the row, unprojected (stored below the door, as a
        // put interrupted before its projection would leave it): the
        // re-offer is `Unchanged` and still projects the wrap.
        seed_held(b.backend, to_b.clone()).await;
        let outcome = b
            .backend
            .apply_replicated_attestation(SignedAttestation { attestation: to_b })
            .await
            .unwrap_or_else(|e| panic!("{tag} I745: B admits its re-emitted row: {e}"));
        assert!(
            matches!(
                outcome,
                crate::federation::attestation_apply::ReplicatedAttestationOutcome::Unchanged
            ),
            "{tag} I745: {outcome:?}"
        );
        carry_bytes(
            a,
            b,
            &sealed.at_rest_sha256,
            COMMUNITY,
            &comm,
            Some(0),
            CryptoTier::CommunityDek,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer(
                b.backend,
                &sealed.at_rest_sha256,
                &b.key,
                None,
            )
            .await
            .unwrap(),
            b"legacy minutes"
        );
        // A second boot, and V192 replayed again: nothing new.
        drop(engine);
        replay_v192(a.backend).await;
        let _again = boot().await;
        assert_eq!(
            rows_signed(a.backend, &a.key, &comm, 0).await.len(),
            2,
            "{tag} I745: the re-emit is idempotent"
        );
    }

    #[cfg(feature = "sqlite")]
    mod sqlite {
        use super::*;
        use crate::federation::key_grant_invariants::two_node::{introduce, node, node_as};
        use crate::store::sqlite::SqliteBackend;
        use crate::store::Backend as _;

        async fn fresh() -> SqliteBackend {
            let b = SqliteBackend::open_in_memory().await.unwrap();
            b.run_migrations().await.unwrap();
            b
        }

        #[tokio::test]
        async fn i743_sqlite() {
            let (ba, bb, bc, bo) = (fresh().await, fresh().await, fresh().await, fresh().await);
            let a = node(&ba, "i743-a").await;
            let b = node(&bb, "i743-b").await;
            let c = node(&bc, "i743-c").await;
            let o = node_as(&bo, "i743-o", crate::federation::types::identity_type::NODE).await;
            introduce(&[&a, &b, &c, &o], &["i743-a", "i743-b", "i743-c", "i743-o"]).await;
            i743_delivery_through_the_planes(&a, &b, &c, &o, "sqlite").await;
        }

        #[tokio::test]
        async fn i744_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i744-a").await;
            let b = node(&bb, "i744-b").await;
            introduce(&[&a, &b], &["i744-a", "i744-b"]).await;
            i744_reemission_is_idempotent_and_rechecks(&a, &b, "sqlite").await;
        }

        fn replay(
            b: &SqliteBackend,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                let conn = b.conn_handle();
                let conn = conn.lock();
                conn.execute_batch(include_str!(
                    "../../migrations/sqlite/lens/V192__key_grant_rows_reemit.sql"
                ))
                .expect("V192 replays");
            })
        }

        fn seed(
            b: &SqliteBackend,
            row: crate::federation::Attestation,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                let conn = b.conn_handle();
                let conn = conn.lock();
                conn.execute(
                    "INSERT INTO federation_attestations (\
                        attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                        weight, asserted_at, expires_at, attestation_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, tier, \
                        cohort_scope, admitted_at\
                     ) VALUES (?1, ?2, ?2, ?3, NULL, ?4, NULL, ?5, x'00', ?6, ?7, ?2, ?4, NULL, \
                        ?8, 'federation', 'community', ?4)",
                    rusqlite::params![
                        row.attestation_id,
                        row.attesting_key_id,
                        row.attestation_type,
                        row.asserted_at.to_rfc3339(),
                        row.attestation_envelope.to_string(),
                        row.scrub_signature_classical,
                        row.scrub_signature_pqc,
                        row.persist_row_hash,
                    ],
                )
                .expect("the v54 node held its set");
            })
        }

        #[tokio::test]
        async fn i745_the_upgraded_node_sqlite() {
            use crate::federation::tier_ingest::test_support as ts;
            let dir = tempfile::tempdir().unwrap();
            let dsn = format!("sqlite:///{}", dir.path().join("a.db").display());
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias_a = format!("i745-a-{run}");
            // The node's first life: its own Engine, its own file.
            let engine = crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias_a), &dsn)
                .await
                .unwrap();
            engine
                .register_self_federation_key(
                    crate::federation::types::identity_type::USER,
                    &alias_a,
                    None,
                    serde_json::json!({}),
                    vec![],
                )
                .await
                .unwrap();
            let sa = engine.sqlite_backend().unwrap().clone();
            let kem = sa.load_or_init_content_kem_identity().await.unwrap();
            let a = Node {
                backend: sa.as_ref(),
                signer: ts::local_signer(&alias_a),
                key: engine.local_derived_key_id().await.unwrap(),
                kem: crate::federation::EncryptionPubkeys {
                    x25519_base64: kem.x25519_pubkey_b64,
                    ml_kem_768_base64: kem.ml_kem_768_pubkey_b64,
                },
            };
            let bb = fresh().await;
            let b = node(&bb, "i745-b").await;
            introduce(&[&a, &b], &[alias_a.as_str(), "i745-b"]).await;
            let boot_dsn = dsn.clone();
            let boot_alias = alias_a.clone();
            i745_the_upgraded_node(
                &a,
                &b,
                || {
                    let (d, al) = (boot_dsn.clone(), boot_alias.clone());
                    async move {
                        crate::Engine::with_signer_pre_genesis(ts::local_signer(&al), &d)
                            .await
                            .expect("the upgraded node boots")
                    }
                },
                replay,
                seed,
                "sqlite",
            )
            .await;
            drop(engine);
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres {
        use super::*;
        use crate::federation::key_grant_invariants::two_node::{introduce, node, node_as};
        use crate::store::postgres::PostgresBackend;
        use crate::store::Backend as _;

        async fn fresh() -> Option<PostgresBackend> {
            let dsn = crate::test_pg::empty_dsn()?;
            let b = PostgresBackend::connect(&dsn).await.unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        }

        #[tokio::test]
        async fn i743_postgres() {
            let (Some(ba), Some(bb), Some(bc), Some(bo)) =
                (fresh().await, fresh().await, fresh().await, fresh().await)
            else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i743-a").await;
            let b = node(&bb, "i743-b").await;
            let c = node(&bc, "i743-c").await;
            let o = node_as(&bo, "i743-o", crate::federation::types::identity_type::NODE).await;
            introduce(&[&a, &b, &c, &o], &["i743-a", "i743-b", "i743-c", "i743-o"]).await;
            i743_delivery_through_the_planes(&a, &b, &c, &o, "postgres").await;
        }

        #[tokio::test]
        async fn i744_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i744-a").await;
            let b = node(&bb, "i744-b").await;
            introduce(&[&a, &b], &["i744-a", "i744-b"]).await;
            i744_reemission_is_idempotent_and_rechecks(&a, &b, "postgres").await;
        }

        fn replay(
            b: &PostgresBackend,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                b.get_client()
                    .await
                    .unwrap()
                    .batch_execute(include_str!(
                        "../../migrations/postgres/lens/V192__key_grant_rows_reemit.sql"
                    ))
                    .await
                    .expect("V192 replays");
            })
        }

        fn seed(
            b: &PostgresBackend,
            row: crate::federation::Attestation,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                let client = b.get_client().await.unwrap();
                let hash = hex::decode(&row.original_content_hash).unwrap_or_default();
                let envelope = row.attestation_envelope.to_string();
                client
                    .execute(
                        "INSERT INTO cirislens.federation_attestations (\
                            attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                            asserted_at, attestation_envelope, original_content_hash, \
                            scrub_signature_classical, scrub_signature_pqc, scrub_key_id, \
                            scrub_timestamp, persist_row_hash, tier, cohort_scope, admitted_at\
                         ) VALUES ($1, $2, $2, $3, $4, $5, $6, $7, $8, $2, $4, $9, 'federation', \
                            'community', $4)",
                        &[
                            &row.attestation_id,
                            &row.attesting_key_id,
                            &row.attestation_type,
                            &row.asserted_at,
                            &envelope,
                            &hash,
                            &row.scrub_signature_classical,
                            &row.scrub_signature_pqc,
                            &row.persist_row_hash,
                        ],
                    )
                    .await
                    .expect("the v54 node held its set");
            })
        }

        #[tokio::test]
        async fn i745_the_upgraded_node_postgres() {
            use crate::federation::tier_ingest::test_support as ts;
            let Some(dsn) = crate::test_pg::empty_dsn() else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias_a = format!("i745-a-{run}");
            let engine = crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias_a), &dsn)
                .await
                .unwrap();
            engine
                .register_self_federation_key(
                    crate::federation::types::identity_type::USER,
                    &alias_a,
                    None,
                    serde_json::json!({}),
                    vec![],
                )
                .await
                .unwrap();
            let pa = engine.postgres_backend().unwrap().clone();
            let kem = pa.load_or_init_content_kem_identity().await.unwrap();
            let a = Node {
                backend: pa.as_ref(),
                signer: ts::local_signer(&alias_a),
                key: engine.local_derived_key_id().await.unwrap(),
                kem: crate::federation::EncryptionPubkeys {
                    x25519_base64: kem.x25519_pubkey_b64,
                    ml_kem_768_base64: kem.ml_kem_768_pubkey_b64,
                },
            };
            let Some(bb) = fresh().await else { return };
            let b = node(&bb, "i745-b").await;
            introduce(&[&a, &b], &[alias_a.as_str(), "i745-b"]).await;
            let boot_dsn = dsn.clone();
            let boot_alias = alias_a.clone();
            i745_the_upgraded_node(
                &a,
                &b,
                || {
                    let (d, al) = (boot_dsn.clone(), boot_alias.clone());
                    async move {
                        crate::Engine::with_signer_pre_genesis(ts::local_signer(&al), &d)
                            .await
                            .expect("the upgraded node boots")
                    }
                },
                replay,
                seed,
                "postgres",
            )
            .await;
            drop(engine);
        }
    }
}
