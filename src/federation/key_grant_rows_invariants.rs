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

// v62.0.0 (JSON cut, E7) — I746 (a held retired v54 SET carrier planted
// below the door is never served) is deleted: nothing carries into an
// edition-2 store (the earlier store is deleted at upgrade), so no node holds
// a retired carrier to serve.

/// I742 — the admission rule, at the attestation plane's door, on any
/// directory (no blob plane needed). It signs through the two-node harness,
/// which is backend-gated.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) mod directory {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::key_grant::{KeyGrantAxis, KeyGrantRefusalReason, KeyGrantRow};
    use crate::federation::key_grant_invariants::two_node::sign_row_unstored;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::{Error, FederationDirectory, GrantWrap};

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
        d.test_seam_put_identity_occurrence(crate::federation::types::IdentityOccurrence {
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
        // v62.0.0 (JSON cut, E7) — edition-2 keys (ids are identity-refs), the
        // room as its `group:roster` voices (T1 §3), occurrences and wraps keyed
        // by identity-refs, and rows through the one entry (`e2::put_signed`).
        let (minter_alias, mallory_alias) =
            (format!("i742-minter-{s}"), format!("i742-mallory-{s}"));
        let minter = ts::local_signer(&minter_alias);
        let mallory = ts::local_signer(&mallory_alias);
        let m_key = e2::put_key(d, &minter_alias, &[USER]).await;
        e2::put_key(d, &mallory_alias, &[USER]).await;
        let mal_key = e2::kid(&mallory_alias);
        let (comm_s, alice_s, bob_s) = (
            format!("i742-comm-{s}"),
            format!("i742-alice-{s}"),
            format!("i742-bob-{s}"),
        );
        let comm = e2::put_key(d, &comm_s, &[USER]).await;
        let alice = e2::put_key(d, &alice_s, &[USER]).await;
        let bob = e2::put_key(d, &bob_s, &[USER]).await;
        let bob_dev = e2::put_key(d, &format!("i742-bobdev-{s}"), &[USER]).await;
        // A key that is no member's occurrence.
        let x_key = e2::put_key(d, &format!("i742-stranger-{s}"), &[USER]).await;
        occurrence(d, &alice, &m_key).await;
        occurrence(d, &bob, &bob_dev).await;
        // Mallory is a member's device (bob's), so the write-scope gate admits
        // her and the key-grant rule is what refuses: she is not the minter.
        occurrence(d, &bob, &mal_key).await;
        let signed = ts::sign_community(
            &comm_s,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: comm_s.clone(),
                community_name: "I742 Co-op".into(),
                members: [&alice_s, &bob_s]
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
        );
        let at_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).expect("after 1970");
        e2::put_voices(d, &e2::community_voices(&signed, 1, None, at_ms))
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
            let r = e2::put_signed(d, &a).await.map(|_| ());
            (id, r)
        };

        // v62.0.0 (JSON cut, E7) — legs (1) (a retired SET carrier: a row
        // whose TYPE is the key-grant dimension) and (2) (a `key_grant:`
        // dimension on a `delegates_to` composer, through the earlier emit
        // path) are deleted: an edition-2 row type is one of five and its
        // family is the header's, so neither shape can be minted.

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

        // (6) Never withdrawn: a `withdraws` and the sealer's own `recants`
        // naming the row are refused (the composer carries the row's family).
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
            let mut c = ts::bare_attestation(
                "",
                &m_key,
                &m_key,
                &serde_json::json!({
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
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::key_grant::{
        emit_epoch_key_grant_with_local_signer, is_key_grant_row, KeyGrantAxis, KeyGrantRow,
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
        let comm_s = format!("{tag}-comm-{run}");
        let (alice, bob, carol) = (
            format!("{tag}-alice-{run}"),
            format!("{tag}-bob-{run}"),
            format!("{tag}-carol-{run}"),
        );
        // v62.0.0 (JSON cut, E7) — E6's flipped `seed_community_everywhere`
        // takes SEEDS and lands the room as its roster voices; the room is
        // read back as its identity-ref.
        seed_community_everywhere(
            &[a, b, c],
            &comm_s,
            &[(&alice, Some(a)), (&bob, Some(b)), (&carol, Some(c))],
        )
        .await;
        let comm = e2::kid(&comm_s);
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
                // v62.0.0 (JSON cut, E7) — the generic door for a row carrying
                // its statement is the one entry.
                e2::put_signed(node.backend, &row)
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
        let comm_s = format!("{tag}-comm-{run}");
        let (alice, bob, xavier) = (
            format!("{tag}-alice-{run}"),
            format!("{tag}-bob-{run}"),
            format!("{tag}-xavier-{run}"),
        );
        seed_community_everywhere(
            &[a, b],
            &comm_s,
            &[(&alice, Some(a)), (&bob, Some(b)), (&xavier, None)],
        )
        .await;
        // v62.0.0 (JSON cut, E7) — identity-refs throughout (E6's helpers).
        let comm = e2::kid(&comm_s);
        let x_occ = e2::put_key(a.backend, &format!("{tag}-x-occ-{run}"), &[USER]).await;
        crate::federation::at_rest_cascade::blob_invariants::join_as_occurrence(
            a.backend,
            &e2::kid(&xavier),
            &x_occ,
        )
        .await;
        let sealed = encrypt_and_cascade_community(a.backend, &comm, b"once", None, Some(&a.key))
            .await
            .unwrap();
        assert!(sealed.granted.contains(&x_occ), "{tag} I744: X wrapped");
        // X leaves BEFORE the first emission: the wrap stays local, no row.
        // v62.0.0 (lead ruling) — the leave is a `membership:removal`
        // statement naming the held roster head (T1 §3), X's own voice.
        let rev = ts::sign_community_membership_revocation(
            &xavier,
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: comm_s.clone(),
                removed_identity_key_id: xavier.clone(),
                removed_at: chrono::Utc::now(),
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
                leaf: crate::federation::types::RevocationLeaf::Resignation,
            },
        );
        let head = e2::held_head(a.backend, &comm).await.map(|(h, _)| h);
        e2::put_voices(
            a.backend,
            &e2::community_revocation_voices(&rev, head.as_ref()),
        )
        .await
        .expect("I744: X leaves");
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

    #[cfg(feature = "sqlite")]
    mod sqlite {
        use super::*;
        use crate::federation::key_grant_invariants::two_node::{introduce_as, node_owned_as};
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
            let a =
                node_owned_as(&ba, "i743-a", crate::federation::types::identity_type::NODE).await;
            let b =
                node_owned_as(&bb, "i743-b", crate::federation::types::identity_type::NODE).await;
            let c =
                node_owned_as(&bc, "i743-c", crate::federation::types::identity_type::NODE).await;
            let o =
                node_owned_as(&bo, "i743-o", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b, &c, &o],
                &["i743-a", "i743-b", "i743-c", "i743-o"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            i743_delivery_through_the_planes(&a, &b, &c, &o, "sqlite").await;
        }

        #[tokio::test]
        async fn i744_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a =
                node_owned_as(&ba, "i744-a", crate::federation::types::identity_type::NODE).await;
            let b =
                node_owned_as(&bb, "i744-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i744-a", "i744-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            i744_reemission_is_idempotent_and_rechecks(&a, &b, "sqlite").await;
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres {
        use super::*;
        use crate::federation::key_grant_invariants::two_node::{introduce_as, node_owned_as};
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
            let a =
                node_owned_as(&ba, "i743-a", crate::federation::types::identity_type::NODE).await;
            let b =
                node_owned_as(&bb, "i743-b", crate::federation::types::identity_type::NODE).await;
            let c =
                node_owned_as(&bc, "i743-c", crate::federation::types::identity_type::NODE).await;
            let o =
                node_owned_as(&bo, "i743-o", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b, &c, &o],
                &["i743-a", "i743-b", "i743-c", "i743-o"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            i743_delivery_through_the_planes(&a, &b, &c, &o, "postgres").await;
        }

        #[tokio::test]
        async fn i744_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a =
                node_owned_as(&ba, "i744-a", crate::federation::types::identity_type::NODE).await;
            let b =
                node_owned_as(&bb, "i744-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i744-a", "i744-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            i744_reemission_is_idempotent_and_rechecks(&a, &b, "postgres").await;
        }
    }
}
