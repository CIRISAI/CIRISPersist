//! v50.0.0 (CIRISPersist#916; `FSD/SECOND_DEVICE.md` §3) — **a member's new
//! device receives exactly what the member holds.**
//!
//! I188 — `rekey_community_member_device_add` re-wraps every retained
//! `(community, minter, epoch)` DEK the member already holds a grant on to the
//! new occurrence's content-KEM keys; idempotently; with no epoch bump; only
//! for a device the member's owner-binding names, only while the member is
//! ACTIVE; a keyless device is refused and recorded; an epoch whose DEK this
//! node does not retain is REPORTED, never skipped in silence.
//!
//! Runs on sqlite and postgres. The memory backend has no community DEK plane
//! (it implements no `BlobStorage`), so it has no runner here.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::at_rest_cascade::orchestrate::{
        rekey_community_member_device_add, DeviceRekeyResult, EpochMissReason,
    };
    use crate::federation::at_rest_cascade::{unwrap_dek_v2_json, DEK_LEN};
    use crate::federation::community_dek::orchestrate::ensure_epoch_dek;
    use crate::federation::identity_aggregate::{mint_content_kem_keypair, ContentKemPrivate};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{
        consensus_protocol, device_class, Community, CommunityMember,
        CommunityMembershipRevocation, IdentityOccurrence,
    };
    use crate::federation::{
        hard_case, BlobStorage, EncryptionPubkeys, Error, FederationDirectory, SignedAttestation,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::future::Future;
    use std::pin::Pin;

    /// The per-backend hook arm (g) needs: DELETE the `(community, minter,
    /// epoch)` self-retention row, leaving the member grants — the state of
    /// an epoch this node holds only a wrap for.
    pub(crate) type DropDekRow<'a> =
        &'a (dyn Fn(String, String, u64) -> Pin<Box<dyn Future<Output = ()> + Send>> + Sync);

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// A fresh content-KEM keypair: the public halves for the occurrence row,
    /// the private halves kept so the witness can OPEN what was granted.
    fn kem() -> (EncryptionPubkeys, ContentKemPrivate) {
        let (x_priv, x_pub, ml_priv, ml_pub) = mint_content_kem_keypair().expect("mint kem");
        (
            EncryptionPubkeys {
                x25519_base64: B64.encode(x_pub),
                ml_kem_768_base64: B64.encode(&ml_pub),
            },
            ContentKemPrivate {
                x25519_priv: x_priv,
                ml_kem_768_priv: ml_priv,
                ml_kem_768_pub: ml_pub,
            },
        )
    }

    /// `identity` speaks through `occurrence`, carrying `keys`.
    async fn occur<B>(b: &B, identity: &str, occurrence: &str, keys: Option<EncryptionPubkeys>)
    where
        B: FederationDirectory + Sync,
    {
        b.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            device_class: device_class::SERVER.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: keys,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("occurrence {identity} -> {occurrence}: {e}"));
    }

    /// A device the way CIRISServer claims one: a NODE key, its owner's live
    /// owner-binding `delegates_to(owner → node)` through the real door, and
    /// the login anchor `(owner, node)` carrying the node's content-KEM keys.
    /// `owner = None` is an unbound device (its singleton row only).
    async fn device<B>(
        b: &B,
        node: &str,
        owner: Option<&str>,
        keys: Option<EncryptionPubkeys>,
        tag: &str,
    ) where
        B: FederationDirectory + Sync,
    {
        ts::register_identity_key(b, node, NODE).await;
        match owner {
            Some(owner) => {
                b.put_attestation(SignedAttestation {
                    attestation: ts::owner_binding_attestation(
                        &format!("bind-{node}-{tag}"),
                        owner,
                        node,
                    ),
                })
                .await
                .unwrap_or_else(|e| panic!("owner-binding {owner} -> {node}: {e}"));
                assert_eq!(
                    crate::federation::admission::owner_of(b, node)
                        .await
                        .unwrap()
                        .as_deref(),
                    Some(owner),
                    "precondition: {node} is bound to {owner}"
                );
                occur(b, owner, node, keys).await;
            }
            None => occur(b, node, node, keys).await,
        }
    }

    fn rule_of(e: &Error) -> &'static str {
        match e {
            Error::DeviceRekeyRefused { rule, .. } => rule,
            other => panic!("expected DeviceRekeyRefused, got {other}"),
        }
    }

    async fn grants_on<B: BlobStorage + Sync>(
        b: &B,
        comm: &str,
        epochs: &[(String, u64)],
        occ: &str,
    ) -> usize {
        let mut n = 0;
        for (m, e) in epochs {
            if b.community_dek_has_member_grant(comm, m, *e, occ)
                .await
                .unwrap()
            {
                n += 1;
            }
        }
        n
    }

    async fn open<B: BlobStorage + Sync>(
        b: &B,
        comm: &str,
        (m, e): &(String, u64),
        occ: &str,
        private: &ContentKemPrivate,
    ) -> [u8; DEK_LEN] {
        let (_alg, wrap) = b
            .community_dek_member_grant_wrap(comm, m, *e, occ)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{occ} holds no wrap on ({m}, {e})"));
        unwrap_dek_v2_json(private, &wrap)
            .unwrap_or_else(|err| panic!("{occ}'s wrap on ({m}, {e}) does not open: {err}"))
    }

    fn sorted(mut v: Vec<(String, u64)>) -> Vec<(String, u64)> {
        v.sort();
        v
    }

    /// **I188** — the whole invariant, arm by arm, on one fixture.
    pub(crate) async fn i188_the_device_gets_what_the_member_holds<B>(
        b: &B,
        tag: &str,
        drop_dek_row: DropDekRow<'_>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        // Ids lead with their distinguishing token: a test signer seeds from
        // the first 32 bytes of the key id.
        let comm = format!("room-{tag}");
        let alice = format!("alice-{tag}");
        let bob = format!("bob-{tag}");
        let carol = format!("carol-{tag}");
        let alice_1 = format!("a1-{tag}");
        let bob_1 = format!("b1-{tag}");

        for k in [&comm, &alice, &bob, &carol, &alice_1, &bob_1] {
            ts::register_hybrid_key_as(b, k, k, USER).await;
        }
        b.put_community(ts::sign_community(
            &comm,
            Community {
                community_key_id: comm.clone(),
                community_name: "second device".into(),
                members: vec![
                    CommunityMember {
                        key_id: alice.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: Some("founder".into()),
                    },
                    CommunityMember {
                        key_id: bob.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: None,
                    },
                ],
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: consensus_protocol::MAJORITY.to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("room: {e}"));

        let (alice_1_keys, _alice_1_priv) = kem();
        let (bob_1_keys, bob_1_priv) = kem();
        occur(b, &alice, &alice_1, Some(alice_1_keys)).await;
        occur(b, &bob, &bob_1, Some(bob_1_keys)).await;

        // Three epochs, two minters: alice-1 mints E1 and (after its own
        // rotation) E2; bob-1 mints E3. Every one fans out to bob-1.
        let e1 = (
            alice_1.clone(),
            ensure_epoch_dek(b, &comm, &alice_1, 0).await.unwrap().epoch,
        );
        b.community_dek_bump_epoch(&comm, &alice_1).await.unwrap();
        let e2 = (
            alice_1.clone(),
            ensure_epoch_dek(b, &comm, &alice_1, 1).await.unwrap().epoch,
        );
        let e3 = (
            bob_1.clone(),
            ensure_epoch_dek(b, &comm, &bob_1, 0).await.unwrap().epoch,
        );
        let epochs = vec![e1.clone(), e2.clone(), e3.clone()];
        assert_eq!(
            (e1.1, e2.1, e3.1),
            (0, 1, 0),
            "precondition: E1..E3 as minted"
        );
        assert_eq!(
            grants_on(b, &comm, &epochs, &bob_1).await,
            3,
            "precondition: bob-1 holds a grant on E1..E3"
        );
        let pointers = (
            b.community_dek_current_epoch(&comm, &alice_1)
                .await
                .unwrap(),
            b.community_dek_current_epoch(&comm, &bob_1).await.unwrap(),
        );
        let states = (
            b.community_dek_epochs(&comm, &alice_1).await.unwrap(),
            b.community_dek_epochs(&comm, &bob_1).await.unwrap(),
        );

        // The devices, added AFTER the epochs were minted (the second-device
        // moment): bob-2 bound to bob; carol's device; an unbound one; a bob
        // device with no content-KEM keys; bob-4 for the unretained arm.
        let bob_2 = format!("b2-{tag}");
        let carol_dev = format!("c1-{tag}");
        let loose = format!("u1-{tag}");
        let bob_3 = format!("b3-{tag}");
        let bob_4 = format!("b4-{tag}");
        let bob_5 = format!("b5-{tag}");
        let (bob_2_keys, bob_2_priv) = kem();
        device(b, &bob_2, Some(&bob), Some(bob_2_keys), tag).await;
        device(b, &carol_dev, Some(&carol), Some(kem().0), tag).await;
        device(b, &loose, None, Some(kem().0), tag).await;
        device(b, &bob_3, Some(&bob), None, tag).await;
        device(b, &bob_4, Some(&bob), Some(kem().0), tag).await;
        device(b, &bob_5, Some(&bob), Some(kem().0), tag).await;
        assert_eq!(
            grants_on(b, &comm, &epochs, &bob_2).await,
            0,
            "precondition: the new device holds nothing yet"
        );

        let door = |occ: String, authority: String| {
            let (comm, bob) = (comm.clone(), bob.clone());
            async move {
                rekey_community_member_device_add(
                    b,
                    &comm,
                    &bob,
                    &occ,
                    &authority,
                    chrono::Utc::now(),
                )
                .await
            }
        };

        // (a) — the device holds a grant on E1, E2, E3, each opening to the
        // SAME DEK bob-1's wrap opens to.
        let r: DeviceRekeyResult = door(bob_2.clone(), bob.clone())
            .await
            .unwrap_or_else(|e| panic!("(a) the door refused bob's own device: {e}"));
        assert_eq!(
            sorted(r.granted.clone()),
            sorted(epochs.clone()),
            "(a) every epoch bob holds is granted"
        );
        assert_eq!(r.epochs_scanned, 3, "(a) {r:?}");
        assert!(r.content_miss.is_empty(), "(a) {r:?}");
        for ep in &epochs {
            assert_eq!(
                open(b, &comm, ep, &bob_2, &bob_2_priv).await,
                open(b, &comm, ep, &bob_1, &bob_1_priv).await,
                "(a) bob-2's wrap on {ep:?} opens to bob-1's DEK"
            );
        }

        // (b) — idempotent: nothing new, and the grant rows did not grow.
        let mut counts = Vec::new();
        for (m, e) in &epochs {
            counts.push(
                b.community_dek_member_grant_recipients(&comm, m, *e)
                    .await
                    .unwrap()
                    .len(),
            );
        }
        let again = door(bob_2.clone(), bob.clone()).await.unwrap();
        assert!(
            again.granted.is_empty(),
            "(b) a re-run grants nothing: {again:?}"
        );
        assert_eq!(
            sorted(again.already_held.clone()),
            sorted(epochs.clone()),
            "(b)"
        );
        for ((m, e), n) in epochs.iter().zip(&counts) {
            assert_eq!(
                b.community_dek_member_grant_recipients(&comm, m, *e)
                    .await
                    .unwrap()
                    .len(),
                *n,
                "(b) the grant count on ({m}, {e}) is unchanged"
            );
        }

        // (c) — a device bound to ANOTHER owner is refused by name, and
        // receives nothing — whoever claims the authority.
        for authority in [&bob, &carol] {
            let e = door(carol_dev.clone(), authority.clone())
                .await
                .unwrap_err();
            assert_eq!(
                rule_of(&e),
                crate::federation::DEVICE_REKEY_RULE_OWNER_MISMATCH,
                "(c) {e}"
            );
        }
        assert_eq!(grants_on(b, &comm, &epochs, &carol_dev).await, 0, "(c)");

        // (c') — bob's device, but an authority that is not its owner.
        let e = door(bob_4.clone(), alice.clone()).await.unwrap_err();
        assert_eq!(
            rule_of(&e),
            crate::federation::DEVICE_REKEY_RULE_AUTHORITY_NOT_OWNER,
            "(c') {e}"
        );
        assert_eq!(grants_on(b, &comm, &epochs, &bob_4).await, 0, "(c')");

        // (d) — an unbound occurrence is refused.
        let e = door(loose.clone(), bob.clone()).await.unwrap_err();
        assert_eq!(
            rule_of(&e),
            crate::federation::DEVICE_REKEY_RULE_UNBOUND,
            "(d) {e}"
        );
        assert_eq!(grants_on(b, &comm, &epochs, &loose).await, 0, "(d)");

        // (f) — a device with no content-KEM keys is refused, recorded as
        // `recipient_excluded`, and granted nothing (no plaintext fallback).
        let e = door(bob_3.clone(), bob.clone()).await.unwrap_err();
        assert_eq!(
            rule_of(&e),
            crate::federation::DEVICE_REKEY_RULE_NO_ENCRYPTION_PUBKEYS,
            "(f) {e}"
        );
        assert_eq!(grants_on(b, &comm, &epochs, &bob_3).await, 0, "(f)");
        let recorded = b
            .list_hard_case_events(hard_case::HardCaseFilter {
                kind: Some(hard_case::kind::RECIPIENT_EXCLUDED.to_owned()),
                since: None,
            })
            .await
            .unwrap();
        assert!(
            recorded
                .iter()
                .any(|ev| ev.subject_key_id.as_deref() == Some(bob_3.as_str())
                    && ev.target_key_id.as_deref() == Some(comm.as_str())),
            "(f) the exclusion is recorded: {recorded:?}"
        );

        // (g) — E2's DEK row is gone from this node: E2 is REPORTED, E1 and
        // E3 are still granted.
        drop_dek_row(comm.clone(), e2.0.clone(), e2.1).await;
        let r = door(bob_4.clone(), bob.clone()).await.unwrap();
        assert_eq!(
            sorted(r.granted.clone()),
            sorted(vec![e1.clone(), e3.clone()]),
            "(g) the retained epochs are granted: {r:?}"
        );
        assert_eq!(r.content_miss.len(), 1, "(g) {r:?}");
        assert_eq!(
            (
                r.content_miss[0].minter_key_id.clone(),
                r.content_miss[0].epoch
            ),
            e2.clone(),
            "(g) the unretained epoch is named"
        );
        assert_eq!(
            r.content_miss[0].reason,
            EpochMissReason::NotRetainedHere,
            "(g)"
        );
        assert!(
            !b.community_dek_has_member_grant(&comm, &e2.0, e2.1, &bob_4)
                .await
                .unwrap(),
            "(g) nothing was granted on the unretained epoch"
        );

        // (h) — no epoch bump: every minter's pointer and epoch list is as
        // it was before any door ran (less the row arm (g) itself deleted).
        assert_eq!(
            (
                b.community_dek_current_epoch(&comm, &alice_1)
                    .await
                    .unwrap(),
                b.community_dek_current_epoch(&comm, &bob_1).await.unwrap(),
            ),
            pointers,
            "(h) the epoch counters are unchanged"
        );
        assert_eq!(
            (
                b.community_dek_epochs(&comm, &alice_1).await.unwrap(),
                b.community_dek_epochs(&comm, &bob_1).await.unwrap(),
            ),
            (
                states
                    .0
                    .iter()
                    .filter(|(e, _)| *e != e2.1)
                    .cloned()
                    .collect::<Vec<_>>(),
                states.1.clone(),
            ),
            "(h) no epoch was minted, disabled or destroyed"
        );

        // (e) — bob leaves the room (his own signature: self-leave); his next
        // device is refused and receives nothing.
        let now = chrono::Utc::now();
        b.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &bob,
            CommunityMembershipRevocation {
                community_key_id: comm.clone(),
                removed_identity_key_id: bob.clone(),
                removed_at: now,
                effective_at: now,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("(e) bob's self-leave: {e}"));
        let e = door(bob_5.clone(), bob.clone()).await.unwrap_err();
        assert_eq!(
            rule_of(&e),
            crate::federation::DEVICE_REKEY_RULE_MEMBER_NOT_ACTIVE,
            "(e) {e}"
        );
        assert_eq!(grants_on(b, &comm, &epochs, &bob_5).await, 0, "(e)");
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i188_sqlite() {
        use crate::store::sqlite::SqliteBackend;
        use crate::store::Backend as _;
        let b = std::sync::Arc::new(SqliteBackend::open_in_memory().await.unwrap());
        b.run_migrations().await.unwrap();
        let hook = b.clone();
        let drop = move |comm: String, minter: String, epoch: u64| {
            let b = hook.clone();
            Box::pin(async move {
                b.write(move |c| {
                    c.execute(
                        "DELETE FROM federation_community_dek \
                          WHERE community_key_id = ?1 AND minter_key_id = ?2 AND epoch = ?3",
                        rusqlite::params![comm, minter, epoch as i64],
                    )
                })
                .await
                .unwrap();
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        };
        super::bodies::i188_the_device_gets_what_the_member_holds(
            b.as_ref(),
            &format!("i188-{}", suffix()),
            &drop,
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i188_postgres() {
        use crate::store::postgres::PostgresBackend;
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = std::sync::Arc::new(PostgresBackend::connect(&dsn).await.unwrap());
        b.run_migrations().await.unwrap();
        let hook = b.clone();
        let drop = move |comm: String, minter: String, epoch: u64| {
            let b = hook.clone();
            Box::pin(async move {
                b.get_client()
                    .await
                    .unwrap()
                    .execute(
                        "DELETE FROM cirislens.federation_community_dek \
                          WHERE community_key_id = $1 AND minter_key_id = $2 AND epoch = $3",
                        &[&comm, &minter, &(epoch as i64)],
                    )
                    .await
                    .unwrap();
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        };
        super::bodies::i188_the_device_gets_what_the_member_holds(
            b.as_ref(),
            &format!("i188-{}", suffix()),
            &drop,
        )
        .await;
    }
}
