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
        rekey_community_member_device_add, rewrap_own_epochs_to_member_devices, DeviceRekeyResult,
        EpochMissReason,
    };
    use crate::federation::at_rest_cascade::{unwrap_dek_v2_json, DEK_LEN};
    use crate::federation::community_dek::orchestrate::{ensure_epoch_dek, set_key_state};
    use crate::federation::identity_aggregate::{mint_content_kem_keypair, ContentKemPrivate};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{
        consensus_protocol, device_class, Community, CommunityMember,
        CommunityMembershipRevocation, CommunityMembershipWidening, IdentityOccurrence,
        IdentityOccurrenceRevocation,
    };
    use crate::federation::{
        hard_case, BlobStorage, DekKeyState, EncryptionPubkeys, Error, FederationDirectory,
        GrantWrap, SignedAttestation,
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

    /// **I188** — the whole invariant, arm by arm, on one fixture. The
    /// backend's own node key is `a1-{tag}` (the runner sets it), so an epoch
    /// minted by `a1` is "ours" and every other minter is a peer.
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
        // A bob device that later passes to carol (arm (i)).
        let passed = format!("n1-{tag}");

        for k in [&comm, &alice, &bob, &carol, &alice_1, &bob_1] {
            ts::register_hybrid_key_as(b, k, k, USER).await;
        }
        ts::register_identity_key(b, &passed, NODE).await;
        b.put_community(ts::sign_community(
            &comm,
            Community {
                community_key_id: comm.clone(),
                community_name: "second device".into(),
                members: [(&alice, true), (&bob, false), (&carol, false)]
                    .into_iter()
                    .map(|(k, founder)| CommunityMember {
                        key_id: k.clone(),
                        joined_at: at("2026-01-01T00:00:00Z"),
                        role: founder.then(|| "founder".to_owned()),
                    })
                    .collect(),
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
        occur(b, &bob, &passed, Some(kem().0)).await;

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

        // (b') — the insert decides: a grant written by someone else between
        // the pre-check and the put is `already_held`, not `granted`. The
        // floor reports it (a second put of the same row inserts nothing).
        assert!(
            !b.community_dek_put_member_grant(
                &comm,
                &e1.0,
                e1.1,
                &bob_2,
                crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2,
                "b3RoZXI",
            )
            .await
            .unwrap(),
            "(b') a put over an existing grant reports no insert"
        );

        // (b'') — two concurrent calls for one device: between them every
        // epoch is `granted` exactly once and `already_held` the other time,
        // whichever pre-check ran first. Always true of a correct door; a door
        // that reports its intent rather than its insert double-counts
        // whenever the two pre-checks interleave.
        for n in 0..3 {
            let racer = format!("r{n}-{tag}");
            device(b, &racer, Some(&bob), Some(kem().0), tag).await;
            let (x, y) = tokio::join!(
                door(racer.clone(), bob.clone()),
                door(racer.clone(), bob.clone())
            );
            let (x, y) = (x.unwrap(), y.unwrap());
            let mut granted = x.granted.clone();
            granted.extend(y.granted.clone());
            assert_eq!(
                sorted(granted),
                sorted(epochs.clone()),
                "(b'') each epoch granted exactly once across two racing calls: {x:?} / {y:?}"
            );
            let mut held = x.already_held.clone();
            held.extend(y.already_held.clone());
            assert_eq!(
                sorted(held),
                sorted(epochs.clone()),
                "(b'') and already-held exactly once: {x:?} / {y:?}"
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

        // (g) — three epochs bob holds that this node cannot re-wrap, each
        // reported with its own reason; E1 and E3 are still granted.
        //   LostLocally — OUR epoch E2 (minter a1 = this node) lost its row.
        drop_dek_row(comm.clone(), e2.0.clone(), e2.1).await;
        //   MintedElsewhere — a peer's epoch, known here only by bob-1's wrap.
        let peer = (format!("pm-{tag}"), 0u64);
        let bob_1_wrap = |w: String| GrantWrap {
            recipient_key_id: bob_1.clone(),
            wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.to_owned(),
            wrapped_dek: w,
        };
        b.community_dek_put_member_grants(&comm, &peer.0, peer.1, &[bob_1_wrap("cGVlcg".into())])
            .await
            .unwrap();
        //   Destroyed — an epoch of ours destroyed by policy, whose grant to
        //   bob-1 came back through the KeyGrant union (an echo of our own set).
        let gone = (format!("d1-{tag}"), 0u64);
        ensure_epoch_dek(b, &comm, &gone.0, 0).await.unwrap();
        let (_, saved) = b
            .community_dek_member_grant_wrap(&comm, &gone.0, 0, &bob_1)
            .await
            .unwrap()
            .expect("bob-1 is wrapped at mint");
        b.community_dek_bump_epoch(&comm, &gone.0).await.unwrap();
        set_key_state(b, &comm, &gone.0, 0, DekKeyState::Destroyed)
            .await
            .unwrap_or_else(|e| panic!("(g) destroy: {e}"));
        b.community_dek_put_member_grants(&comm, &gone.0, 0, &[bob_1_wrap(saved)])
            .await
            .unwrap();

        let r = door(bob_4.clone(), bob.clone()).await.unwrap();
        assert_eq!(
            sorted(r.granted.clone()),
            sorted(vec![e1.clone(), e3.clone()]),
            "(g) the retained epochs are granted: {r:?}"
        );
        let mut misses: Vec<(String, u64, EpochMissReason)> = r
            .content_miss
            .iter()
            .map(|m| (m.minter_key_id.clone(), m.epoch, m.reason))
            .collect();
        misses.sort_by(|x, y| (&x.0, x.1).cmp(&(&y.0, y.1)));
        let mut want = vec![
            (e2.0.clone(), e2.1, EpochMissReason::LostLocally),
            (peer.0.clone(), peer.1, EpochMissReason::MintedElsewhere),
            (gone.0.clone(), gone.1, EpochMissReason::Destroyed),
        ];
        want.sort_by(|x, y| (&x.0, x.1).cmp(&(&y.0, y.1)));
        assert_eq!(
            misses, want,
            "(g) every unretained epoch is named, by reason"
        );
        for (m, e, _) in &want {
            assert!(
                !b.community_dek_has_member_grant(&comm, m, *e, &bob_4)
                    .await
                    .unwrap(),
                "(g) nothing was granted on ({m}, {e})"
            );
        }

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
        let left = chrono::Utc::now();
        b.put_community_membership_revocation(ts::sign_community_membership_revocation(
            &bob,
            CommunityMembershipRevocation {
                community_key_id: comm.clone(),
                removed_identity_key_id: bob.clone(),
                removed_at: left,
                effective_at: left,
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

        // (i) — THE ABSENCE SPAN. While bob is out, E4 and E5 are minted
        // (minter a2), and two keys that bob's history names come to hold
        // them under someone else:
        //   `passed` — bob's own device (a stale `(bob, n1)` row, holding
        //   E1..E3 from bob's time) that passes to carol by an owner-binding
        //   and is re-wrapped E4, E5 by the minter as carol's device;
        //   `lent` — carol's occurrence while bob is out (E4, E5 by the fan-out),
        //   then revoked and bound to bob.
        let lent = format!("n2-{tag}");
        ts::register_identity_key(b, &lent, NODE).await;
        occur(b, &carol, &lent, Some(kem().0)).await;
        b.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(
                &format!("bind-carol-{passed}"),
                &carol,
                &passed,
            ),
        })
        .await
        .unwrap_or_else(|e| panic!("(i) carol binds the passed device: {e}"));
        let a2 = format!("a2-{tag}");
        let e4 = (
            a2.clone(),
            ensure_epoch_dek(b, &comm, &a2, 0).await.unwrap().epoch,
        );
        b.community_dek_bump_epoch(&comm, &a2).await.unwrap();
        let e5 = (
            a2.clone(),
            ensure_epoch_dek(b, &comm, &a2, 1).await.unwrap().epoch,
        );
        let absence = vec![e4.clone(), e5.clone()];
        let swept = rewrap_own_epochs_to_member_devices(b, &a2, None, chrono::Utc::now())
            .await
            .unwrap_or_else(|e| panic!("(i) the minter's sweep: {e}"));
        assert_eq!(
            grants_on(b, &comm, &absence, &passed).await,
            2,
            "(i) precondition: the passed device holds E4, E5 as carol's ({swept:?})"
        );
        assert_eq!(
            grants_on(b, &comm, &absence, &lent).await,
            2,
            "(i) precondition: carol's occurrence holds E4, E5"
        );
        assert_eq!(
            grants_on(b, &comm, &absence, &bob_1).await,
            0,
            "(i) precondition: bob held nothing minted while he was out"
        );
        b.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: carol.clone(),
            occurrence_key_id: lent.clone(),
            revoked_at: chrono::Utc::now(),
            effective_at: chrono::Utc::now(),
            reason: None,
            witness_set: vec![carol.clone()],
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("(i) carol revokes the lent occurrence: {e}"));
        b.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(&format!("bind-bob-{lent}"), &bob, &lent),
        })
        .await
        .unwrap_or_else(|e| panic!("(i) bob binds the lent device: {e}"));

        // bob is re-added (alice and carol: the room's majority).
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let back = chrono::Utc::now();
        let mut w = ts::sign_community_membership_widening(
            &alice,
            CommunityMembershipWidening {
                community_key_id: comm.clone(),
                member_key_id: bob.clone(),
                joined_at: back,
                effective_at: back,
                role: None,
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_community_membership_widening(&mut w, &carol);
        b.put_community_membership_widening(w)
            .await
            .unwrap_or_else(|e| panic!("(i) bob re-added: {e}"));

        // bob's new device: what bob's devices held before he left (Option
        // A), reported misses as before — and NOTHING from the absence span.
        let bob_6 = format!("b6-{tag}");
        device(b, &bob_6, Some(&bob), Some(kem().0), tag).await;
        let r = door(bob_6.clone(), bob.clone())
            .await
            .unwrap_or_else(|e| panic!("(i) the re-added member's device: {e}"));
        assert_eq!(
            sorted(r.granted.clone()),
            sorted(vec![e1.clone(), e3.clone()]),
            "(i) the re-added member's device gets what bob held: {r:?}"
        );
        assert_eq!(
            grants_on(b, &comm, &absence, &bob_6).await,
            0,
            "(i) nothing from the absence span reaches bob's device: {r:?}"
        );
        assert!(
            r.content_miss
                .iter()
                .all(|m| !absence.contains(&(m.minter_key_id.clone(), m.epoch))),
            "(i) the absence span is not even 'held': {r:?}"
        );
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
        let tag = format!("i188-{}", suffix());
        // The node's own key: epochs minted by `a1-{tag}` are this node's.
        b.set_node_key_id(format!("a1-{tag}"));
        super::bodies::i188_the_device_gets_what_the_member_holds(b.as_ref(), &tag, &drop).await;
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
        let tag = format!("i188-{}", suffix());
        // The node's own key: epochs minted by `a1-{tag}` are this node's.
        b.set_node_key_id(format!("a1-{tag}"));
        super::bodies::i188_the_device_gets_what_the_member_holds(b.as_ref(), &tag, &drop).await;
    }
}

/// v50.0.0 (CIRISPersist#916 review) — **the minter side, across two nodes,
/// delivered through the planes.** Node A (alice's) minted the room's
/// history; bob's node B is where bob adds a device. The device's owner-binding
/// and occurrence travel B → A on the signed since-reads; A re-wraps its own
/// epochs and emits the sets; B admits them and the device's wraps open.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod two_node {
    use crate::federation::at_rest_cascade::orchestrate::EpochMissReason;
    use crate::federation::at_rest_cascade::unwrap_dek_v2_json;
    use crate::federation::community_dek::orchestrate::ensure_epoch_dek;
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::key_grant::{
        publish_signed_content_only_occurrence, KeyGrantAxis, KeyGrantSet, SignedKeyGrantSet,
        KEY_GRANT_EPOCH_ATTESTATION_TYPE,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::COMMUNITY;
    use crate::federation::types::identity_type::NODE;
    use crate::federation::types::{device_class, IdentityOccurrence};
    use crate::federation::{
        attestation_apply::ReplicatedAttestationOutcome, Attestation, BlobStorage,
        FederationDirectory, SignedAttestation,
    };

    /// Every epoch-axis set on `backend` for `(comm, minter, epoch)`.
    async fn sets_on<B: FederationDirectory + Sync>(
        backend: &B,
        comm: &str,
        minter: &str,
        epoch: u64,
    ) -> Vec<(Attestation, KeyGrantSet)> {
        backend
            .list_attestations_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.attestation)
            .filter(|a| a.attestation_type == KEY_GRANT_EPOCH_ATTESTATION_TYPE)
            .filter_map(|a| KeyGrantSet::from_attestation(&a).ok().map(|s| (a, s)))
            .filter(|(_, s)| {
                matches!(&s.axis, KeyGrantAxis::Epoch { community_key_id, minter_key_id, epoch: e }
                    if community_key_id == comm && minter_key_id == minter && *e == epoch)
            })
            .collect()
    }

    /// A set on `backend` for `(comm, minter, epoch)` that carries a wrap to
    /// `device`, if any.
    async fn set_carrying<B: FederationDirectory + Sync>(
        backend: &B,
        comm: &str,
        minter: &str,
        epoch: u64,
        device: &str,
    ) -> Option<Attestation> {
        sets_on(backend, comm, minter, epoch)
            .await
            .into_iter()
            .find(|(_, s)| s.wraps.iter().any(|w| w.recipient_key_id == device))
            .map(|(a, _)| a)
    }

    /// A device node: its derived key registered as a NODE on both sides, its
    /// singleton occurrence signed by itself on B (boot precedes claim), its
    /// private KEM halves kept by the witness.
    async fn device_on_b<B>(
        a: &B,
        b: &B,
        alias: &str,
    ) -> (
        String,
        crate::federation::identity_aggregate::ContentKemPrivate,
    )
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let signer = ts::local_signer(alias);
        let key = signer.derived_key_id();
        for n in [a, b] {
            ts::register_hybrid_key_as(n, &key, alias, NODE).await;
        }
        let (x_priv, x_pub, ml_priv, ml_pub) =
            crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        publish_signed_content_only_occurrence(
            b,
            &signer,
            &key,
            &key,
            device_class::SERVER,
            None,
            crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x_pub),
                ml_kem_768_base64: B64.encode(&ml_pub),
            },
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{alias}: publish the singleton on B: {e}"));
        (
            key,
            crate::federation::identity_aggregate::ContentKemPrivate {
                x25519_priv: x_priv,
                ml_kem_768_priv: ml_priv,
                ml_kem_768_pub: ml_pub,
            },
        )
    }

    /// B's signed occurrence for `device`, carried to A (the since-read).
    async fn carry_occurrence<B: FederationDirectory + Sync>(a: &B, b: &B, device: &str) {
        let served = b
            .list_signed_identity_occurrences_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.occurrence.identity_occurrence.occurrence_key_id == device)
            .unwrap_or_else(|| panic!("{device}'s occurrence is on B's since-read"));
        a.put_identity_occurrence(served.occurrence)
            .await
            .unwrap_or_else(|e| panic!("A admits {device}'s occurrence: {e}"));
    }

    /// bob's owner-binding for `device`, admitted on B, then read off B's
    /// since-read — the row A's replication bridge would receive.
    async fn bind_on_b<B: FederationDirectory + Sync>(
        b: &B,
        bob: &str,
        device: &str,
        run: &str,
    ) -> Attestation {
        let id = format!("bind-{device}-{run}");
        b.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(&id, bob, device),
        })
        .await
        .unwrap_or_else(|e| panic!("B admits bob's binding for {device}: {e}"));
        b.list_attestations_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.attestation)
            .find(|a| a.attestation_id == id)
            .expect("the binding is on B's since-read")
    }

    /// **I188 (two nodes)** — the minter re-wraps its own history to the
    /// member's new device on the binding's arrival (trigger), or in its
    /// pending sweep when the device's keys arrive after the binding; the
    /// host's door on the minter emits only what the minter minted.
    pub(crate) async fn i188_the_minter_rewraps_its_own_history<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let bob = format!("em-bob-{run}");
        let (a, b) = (l.ba.as_ref(), l.bb.as_ref());

        // A mints E1..E3 through the production door (each seal emits its set).
        for (i, body) in [&b"one"[..], &b"two"[..], &b"three"[..]]
            .into_iter()
            .enumerate()
        {
            if i > 0 {
                a.community_dek_bump_epoch(&l.comm, &l.node_a)
                    .await
                    .unwrap();
            }
            l.engine_a
                .put_blob_scoped(COMMUNITY, Some(&l.comm), body, None, None)
                .await
                .unwrap_or_else(|e| panic!("A seals #{i}: {e}"));
        }
        let own: Vec<u64> = vec![0, 1, 2];
        for e in &own {
            assert!(
                a.community_dek_has_member_grant(&l.comm, &l.node_a, *e, &l.node_b)
                    .await
                    .unwrap(),
                "precondition: bob's node holds A's epoch {e} on A"
            );
        }
        // B mints its own epoch; A admits B's set — a PEER's epoch on A.
        l.engine_b
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"b's", None, None)
            .await
            .unwrap_or_else(|e| panic!("B seals: {e}"));
        let (b_set, _) = sets_on(b, &l.comm, &l.node_b, 0)
            .await
            .into_iter()
            .next()
            .expect("B emitted its set");
        l.engine_a
            .apply_replicated_key_grant(SignedKeyGrantSet { attestation: b_set })
            .await
            .unwrap_or_else(|e| panic!("A admits B's set: {e}"));
        // And an epoch A holds a self-retention for under a FOREIGN minter's
        // name: the door may re-wrap it locally, never sign a set for it.
        let foreign = format!("fm-{run}");
        ensure_epoch_dek(a, &l.comm, &foreign, 0).await.unwrap();

        // (T) THE TRIGGER — bob's device d2 on B: its singleton, then bob's
        // binding; both carried to A over the since-reads.
        let (d2, d2_priv) = device_on_b(a, b, &format!("d2-{run}")).await;
        let binding = bind_on_b(b, &bob, &d2, run).await;
        carry_occurrence(a, b, &d2).await;
        let outcome = l
            .engine_a
            .apply_replicated_attestation(SignedAttestation {
                attestation: binding,
            })
            .await
            .unwrap_or_else(|e| panic!("(T) A admits bob's binding for d2: {e}"));
        assert_eq!(outcome, ReplicatedAttestationOutcome::Inserted, "(T)");
        for e in &own {
            assert!(
                a.community_dek_has_member_grant(&l.comm, &l.node_a, *e, &d2)
                    .await
                    .unwrap(),
                "(T) A re-wrapped its epoch {e} to d2 on the binding's arrival"
            );
        }
        assert!(
            !a.community_dek_has_member_grant(&l.comm, &l.node_b, 0, &d2)
                .await
                .unwrap(),
            "(T) A never wraps B's epoch: only B can sign that set"
        );
        // A's sets carry d2 → B admits them → d2's wraps on B open to the DEK
        // bob's node already holds.
        let b_priv = b.load_content_kem_private_halves().await.unwrap();
        for e in &own {
            let set = set_carrying(a, &l.comm, &l.node_a, *e, &d2)
                .await
                .unwrap_or_else(|| panic!("(T) A emitted a set for epoch {e} carrying d2"));
            l.engine_b
                .apply_replicated_key_grant(SignedKeyGrantSet { attestation: set })
                .await
                .unwrap_or_else(|err| panic!("(T) B admits A's set for epoch {e}: {err}"));
            let (_, d2_wrap) = b
                .community_dek_member_grant_wrap(&l.comm, &l.node_a, *e, &d2)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("(T) d2's wrap on A's epoch {e} reached B"));
            let (_, bob_wrap) = b
                .community_dek_member_grant_wrap(&l.comm, &l.node_a, *e, &l.node_b)
                .await
                .unwrap()
                .expect("bob's node's own wrap on B");
            assert_eq!(
                unwrap_dek_v2_json(&d2_priv, &d2_wrap).unwrap(),
                unwrap_dek_v2_json(&b_priv, &bob_wrap).unwrap(),
                "(T) on B, d2 opens A's epoch {e} to the DEK bob's node holds"
            );
        }

        // (S) THE SWEEP — d3's binding reaches A BEFORE its keys: nothing can
        // be wrapped yet; the keys arrive; the pending sweep re-wraps and
        // emits.
        let (d3, _d3_priv) = device_on_b(a, b, &format!("d3-{run}")).await;
        let binding = bind_on_b(b, &bob, &d3, run).await;
        l.engine_a
            .apply_replicated_attestation(SignedAttestation {
                attestation: binding,
            })
            .await
            .unwrap_or_else(|e| panic!("(S) A admits bob's binding for d3: {e}"));
        assert!(
            !a.community_dek_has_member_grant(&l.comm, &l.node_a, 0, &d3)
                .await
                .unwrap(),
            "(S) precondition: no keys on A yet, nothing wrapped"
        );
        carry_occurrence(a, b, &d3).await;
        l.engine_a
            .emit_pending_key_grants()
            .await
            .unwrap_or_else(|e| panic!("(S) A's pending sweep: {e}"));
        for e in &own {
            assert!(
                a.community_dek_has_member_grant(&l.comm, &l.node_a, *e, &d3)
                    .await
                    .unwrap(),
                "(S) the sweep re-wrapped A's epoch {e} to d3"
            );
            assert!(
                set_carrying(a, &l.comm, &l.node_a, *e, &d3).await.is_some(),
                "(S) and emitted epoch {e}'s set carrying d3"
            );
        }

        // (D) THE HOST'S DOOR on the minter — d4 bound and keyed on A directly
        // (no trigger): the door grants A's epochs, the foreign-named one
        // locally, reports B's as minted elsewhere, and emits sets for A's
        // own epochs only.
        let d4_alias = format!("d4-{run}");
        let d4 = ts::local_signer(&d4_alias).derived_key_id();
        ts::register_hybrid_key_as(a, &d4, &d4_alias, NODE).await;
        a.put_attestation(SignedAttestation {
            attestation: ts::owner_binding_attestation(&format!("bind-{d4}-{run}"), &bob, &d4),
        })
        .await
        .unwrap_or_else(|e| panic!("(D) bind d4 on A: {e}"));
        let (d4_keys, _) = {
            let (x_priv, x_pub, ml_priv, ml_pub) =
                crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            (
                crate::federation::EncryptionPubkeys {
                    x25519_base64: B64.encode(x_pub),
                    ml_kem_768_base64: B64.encode(&ml_pub),
                },
                (x_priv, ml_priv),
            )
        };
        a.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: d4.clone(),
            occurrence_key_id: d4.clone(),
            device_class: device_class::SERVER.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: Some(d4_keys),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap();
        let r = l
            .engine_a
            .rekey_community_member_device_add(&l.comm, &bob, &d4, &bob)
            .await
            .unwrap_or_else(|e| panic!("(D) the door on A: {e}"));
        let mut granted = r.granted.clone();
        granted.sort();
        let mut want: Vec<(String, u64)> = own.iter().map(|e| (l.node_a.clone(), *e)).collect();
        want.push((foreign.clone(), 0));
        want.sort();
        assert_eq!(granted, want, "(D) {r:?}");
        assert_eq!(
            r.content_miss
                .iter()
                .map(|m| (m.minter_key_id.clone(), m.epoch, m.reason))
                .collect::<Vec<_>>(),
            vec![(l.node_b.clone(), 0, EpochMissReason::MintedElsewhere)],
            "(D) B's epoch is B's to re-wrap: {r:?}"
        );
        for e in &own {
            assert!(
                set_carrying(a, &l.comm, &l.node_a, *e, &d4).await.is_some(),
                "(D) the door emitted A's epoch {e} set carrying d4"
            );
        }
        assert!(
            sets_on(a, &l.comm, &foreign, 0).await.is_empty(),
            "(D) no set is ever signed for an epoch this node did not mint"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run_two_node {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i188_two_node_sqlite() {
        super::two_node::i188_the_minter_rewraps_its_own_history(
            "sqlite::memory:",
            "sqlite::memory:",
            &suffix(),
            (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::sqlite::SqliteBackend,
                >,
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i188_two_node_postgres() {
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        super::two_node::i188_the_minter_rewraps_its_own_history(
            &a,
            &b,
            &suffix(),
            (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::postgres::PostgresBackend,
                >,
        )
        .await;
    }
}
