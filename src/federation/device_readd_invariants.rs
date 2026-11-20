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
//!
//! v62.0.0 (JSON cut, E13) — **edition 2.** Every key is an E0 identity-ref
//! (`e2::put_key`); the room, its members, occurrences and DEK minters are
//! named by identity-refs (the node's own key included). The room is founded
//! by alice's `group:roster` voice alone; bob and carol are widened in
//! (proposal, acceptance, `membership:widening` voices: T1.api §3); bob's
//! self-leave is his `membership:removal` voice and his re-add a fresh
//! proposal, acceptance and widening voiced by alice and carol. Owner
//! bindings are edition-2 rows dated now-relative, each with the bound
//! node's own voice (CC 3.2: the node is a second signer of its binding).

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::at_rest_cascade::orchestrate::{
        rekey_community_member_device_add, rewrap_own_epochs_to_member_devices, DeviceRekeyResult,
        EpochMissReason,
    };
    use crate::federation::at_rest_cascade::{unwrap_dek_v2_json, DEK_LEN};
    use crate::federation::community_dek::orchestrate::{ensure_epoch_dek, set_key_state};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::{GroupRecord, MembershipRecord};
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::identity_aggregate::{mint_content_kem_keypair, ContentKemPrivate};
    use crate::federation::membership_acceptance::test_support::{acceptance_row, proposal_row};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::COMMUNITY;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{
        consensus_protocol, device_class, Community, CommunityMember,
        CommunityMembershipRevocation, CommunityMembershipWidening, IdentityOccurrence,
    };
    use crate::federation::{
        hard_case, BlobStorage, DekKeyState, EncryptionPubkeys, Error, FederationDirectory,
        GrantWrap,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use ciris_crypto::composite::CompositeSigningKey;
    use std::future::Future;
    use std::pin::Pin;

    /// The per-backend hook arm (g) needs: DELETE the `(community, minter,
    /// epoch)` self-retention row, leaving the member grants — the state of
    /// an epoch this node holds only a wrap for.
    pub(crate) type DropDekRow<'a> =
        &'a (dyn Fn(String, String, u64) -> Pin<Box<dyn Future<Output = ()> + Send>> + Sync);

    /// `t` at the millisecond an edition-2 payload carries.
    fn at_ms(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(t.timestamp_millis())
            .expect("an instant")
    }

    /// The voices, asserting the typed row landed.
    async fn landed<B>(b: &B, voices: &[Vec<u8>], what: &str)
    where
        B: FederationDirectory + Sync,
    {
        match e2::put_voices(b, voices).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{what}: expected the row to land, got {other:?}"),
        }
    }

    fn keys_of(signers: &[&str]) -> Vec<CompositeSigningKey> {
        signers.iter().map(|s| e2::signing_key(s)).collect()
    }

    /// v62.0.0 (E13) — **`member` widened into `comm`** at `at`: the
    /// proposal (by `signers[0]`) and the member's own acceptance as
    /// edition-2 rows, then the `membership:widening` voices of `signers`
    /// counted over the room's held roster head (T1.api §3).
    async fn widen<B>(
        b: &B,
        comm: &str,
        member: &str,
        signers: &[&str],
        at: chrono::DateTime<chrono::Utc>,
    ) where
        B: FederationDirectory + Sync,
    {
        let at = at_ms(at);
        let p = proposal_row(signers[0], COMMUNITY, comm, member, None, at);
        e2::put_signed(b, &p)
            .await
            .unwrap_or_else(|e| panic!("the proposal of {member}: {e}"));
        e2::put_signed(b, &acceptance_row(member, &p, at))
            .await
            .unwrap_or_else(|e| panic!("{member}'s acceptance: {e}"));
        let (head, _) = e2::held_head(b, comm)
            .await
            .unwrap_or_else(|| panic!("{comm}: a held roster head"));
        let w = MembershipRecord::CommunityWidening(CommunityMembershipWidening {
            community_key_id: comm.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: at,
            effective_at: at,
            role: None,
            persist_row_hash: String::new(),
        });
        let k = keys_of(signers);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        landed(
            b,
            &e2::membership_voices(&w, Some(&head), &refs),
            &format!("{member} widened into {comm}"),
        )
        .await;
    }

    /// v62.0.0 (E13) — **`owner` binds `node`**: the owner-binding row
    /// `delegates_to(owner → node)` dated now-relative (a node key's rows
    /// lapse with its record), then the bound node's own voice over it.
    async fn bind<B>(b: &B, owner: &str, node: &str) -> crate::federation::Attestation
    where
        B: FederationDirectory + Sync,
    {
        let mut row = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), owner, node);
        row.asserted_at = at_ms(chrono::Utc::now() - chrono::Duration::minutes(5));
        row.scrub_timestamp = row.asserted_at;
        ts::seal_row_in_place(owner, &mut row);
        e2::put_signed(b, &row)
            .await
            .unwrap_or_else(|e| panic!("owner-binding {owner} -> {node}: {e}"));
        let st = e2::carried_statement(&row).expect("the binding carries its statement");
        e2::put_statement(b, &e2::voice_of(&st, node))
            .await
            .unwrap_or_else(|e| panic!("{node}'s voice on its binding by {owner}: {e}"));
        row
    }

    /// v62.0.0 (E13) — `owner` withdraws its binding `row` (a `withdraws`
    /// composer naming it): the node is no longer the owner's device.
    async fn unbind<B>(b: &B, owner: &str, row: &crate::federation::Attestation)
    where
        B: FederationDirectory + Sync,
    {
        e2::put_signed(b, &e2::composer_of("withdraws", row, owner))
            .await
            .unwrap_or_else(|e| panic!("{owner} withdraws its binding {}: {e}", e2::rid(row)));
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
    /// v62.0.0 (E13): `node` and `owner` are identity-refs E0 minted. P5c
    /// (lead's ruling): a node is never an occurrence of a person
    /// (`occurrence_binds_machine_to_person`); WHO it belongs to is the owner
    /// binding, WHAT KIND it is its own self-occurrence `(node, node)`.
    async fn device<B>(
        b: &B,
        node: &str,
        owner: Option<&str>,
        keys: Option<EncryptionPubkeys>,
        tag: &str,
    ) where
        B: FederationDirectory + Sync,
    {
        let _ = tag;
        e2::put_key(b, node, &[NODE]).await;
        match owner {
            Some(owner) => {
                let _ = bind(b, owner, node).await;
                assert_eq!(
                    crate::federation::admission::owner_of(b, node)
                        .await
                        .unwrap()
                        .as_deref(),
                    Some(owner),
                    "precondition: {node} is bound to {owner}"
                );
                occur(b, node, node, keys).await;
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
    /// backend's own node key is `kid("a1-{tag}")` (the runner sets it), so an
    /// epoch minted by `a1` is "ours" and every other minter is a peer.
    pub(crate) async fn i188_the_device_gets_what_the_member_holds<B>(
        b: &B,
        tag: &str,
        drop_dek_row: DropDekRow<'_>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        // v62.0.0 (E13) — every id is the identity-ref of its seed (`kid`):
        // the seeds lead with their distinguishing token.
        let k = |n: &str| e2::kid(&format!("{n}-{tag}"));
        let comm = k("room");
        let alice = k("alice");
        let bob = k("bob");
        let carol = k("carol");
        let alice_1 = k("a1");
        let bob_1 = k("b1");
        // A bob device that later passes to carol (arm (i)).
        let passed = k("n1");

        for key in [&comm, &alice, &bob, &carol, &alice_1, &bob_1] {
            e2::put_key(b, key, &[USER]).await;
        }
        e2::put_key(b, &passed, &[NODE]).await;
        // The room, founded by alice's voice alone (a founding roster admits
        // only the members who voice it); bob and carol are widened in, each
        // with their own acceptance, by the room's majority at that moment.
        let founded = at_ms(chrono::Utc::now() - chrono::Duration::days(1));
        let room = Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: comm.clone(),
            community_name: "second device".into(),
            members: vec![CommunityMember {
                key_id: alice.clone(),
                joined_at: founded,
                role: Some("founder".to_owned()),
            }],
            founded_at: founded,
            consensus_protocol: consensus_protocol::MAJORITY.to_owned(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        let ka = keys_of(&[alice.as_str()]);
        let ra: Vec<&CompositeSigningKey> = ka.iter().collect();
        landed(
            b,
            &e2::roster_voices(&GroupRecord::Community(room), 1, None, e2::ms(founded), &ra),
            "room",
        )
        .await;
        let joined = chrono::Utc::now() - chrono::Duration::minutes(2);
        widen(b, &comm, &bob, &[&alice], joined).await;
        widen(b, &comm, &carol, &[&alice, &bob], joined).await;

        let (alice_1_keys, _alice_1_priv) = kem();
        let (bob_1_keys, bob_1_priv) = kem();
        occur(b, &alice, &alice_1, Some(alice_1_keys)).await;
        occur(b, &bob, &bob_1, Some(bob_1_keys)).await;
        // `passed`: bob's node device (bob's binding, its own occurrence).
        let passed_bound = bind(b, &bob, &passed).await;
        occur(b, &passed, &passed, Some(kem().0)).await;

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
        let bob_2 = k("b2");
        let carol_dev = k("c1");
        let loose = k("u1");
        let bob_3 = k("b3");
        let bob_4 = k("b4");
        let bob_5 = k("b5");
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
        // E1 and E2 are this node's own (minter a1 = the node key): granted,
        // their sets emitted. E3 was minted under b1 — re-wrapped here, but
        // no set can carry it from this node: `local_only`, not `granted`.
        assert_eq!(
            sorted(r.granted.clone()),
            sorted(vec![e1.clone(), e2.clone()]),
            "(a) every epoch of this node's own that bob holds is granted"
        );
        assert_eq!(
            r.local_only,
            vec![e3.clone()],
            "(a) a grant under another minter is reported local-only: {r:?}"
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
        crate::federation::at_rest_cascade::orchestrate::REWRAPS_COMPUTED.with(|c| c.set(0));
        let again = door(bob_2.clone(), bob.clone()).await.unwrap();
        assert_eq!(
            crate::federation::at_rest_cascade::orchestrate::REWRAPS_COMPUTED.with(|c| c.get()),
            0,
            "(b) a re-run computes no wrap for an epoch the device already holds"
        );
        assert!(
            again.granted.is_empty() && again.local_only.is_empty(),
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
            let racer = e2::kid(&format!("r{n}-{tag}"));
            device(b, &racer, Some(&bob), Some(kem().0), tag).await;
            let (x, y) = tokio::join!(
                door(racer.clone(), bob.clone()),
                door(racer.clone(), bob.clone())
            );
            let (x, y) = (x.unwrap(), y.unwrap());
            let mut granted = x.granted.clone();
            granted.extend(y.granted.clone());
            granted.extend(x.local_only.clone());
            granted.extend(y.local_only.clone());
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
                emitter_key_id: None,
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
        let peer = (k("pm"), 0u64);
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
        let gone = (k("d1"), 0u64);
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
            (r.granted.clone(), r.local_only.clone()),
            (vec![e1.clone()], vec![e3.clone()]),
            "(g) the retained epochs are granted (E3 locally): {r:?}"
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
        let left = at_ms(chrono::Utc::now());
        let (head, _) = e2::held_head(b, &comm)
            .await
            .expect("(e) the room's held roster head");
        let leave = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
            community_key_id: comm.clone(),
            removed_identity_key_id: bob.clone(),
            removed_at: left,
            effective_at: left,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        });
        let kb = keys_of(&[bob.as_str()]);
        let rb: Vec<&CompositeSigningKey> = kb.iter().collect();
        landed(
            b,
            &e2::membership_voices(&leave, Some(&head), &rb),
            "(e) bob's self-leave",
        )
        .await;
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
        //   `passed` — bob's own node device (from bob's time) that passes to
        //   carol: bob withdraws his binding, carol binds it, and the minter
        //   re-wraps E4, E5 to it as carol's device;
        //   `lent` — carol's node device while bob is out (E4, E5), then
        //   carol withdraws her binding and bob binds it.
        // v62.0.0 (E13): ownership moves by bindings (P5c); no node is ever a
        // person's occurrence row.
        let lent = k("n2");
        e2::put_key(b, &lent, &[NODE]).await;
        let lent_bound = bind(b, &carol, &lent).await;
        occur(b, &lent, &lent, Some(kem().0)).await;
        // (i) the passed device passes from bob to carol.
        unbind(b, &bob, &passed_bound).await;
        let _ = bind(b, &carol, &passed).await;
        let a2 = k("a2");
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
        // The passed device holds E4, E5 as carol's: wraps a set carried to
        // this node (the KeyGrant union) — carol's minter wrapped it there.
        for (m, e) in &absence {
            b.community_dek_put_member_grants(
                &comm,
                m,
                *e,
                &[GrantWrap {
                    recipient_key_id: passed.clone(),
                    wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2
                        .to_owned(),
                    wrapped_dek: "cGFzc2Vk".into(),
                }],
            )
            .await
            .unwrap();
        }
        assert_eq!(
            grants_on(b, &comm, &absence, &passed).await,
            2,
            "(i) precondition: the passed device holds E4, E5 as carol's"
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
        // (i) carol lets the lent device go; bob binds it.
        unbind(b, &carol, &lent_bound).await;
        let _ = bind(b, &bob, &lent).await;

        // bob is re-added (alice and carol: the room's majority).
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let back = chrono::Utc::now();
        widen(b, &comm, &bob, &[&alice, &carol], back).await;

        // bob's new device: what bob's devices held before he left (Option
        // A), reported misses as before — and NOTHING from the absence span.
        let bob_6 = k("b6");
        device(b, &bob_6, Some(&bob), Some(kem().0), tag).await;
        let r = door(bob_6.clone(), bob.clone())
            .await
            .unwrap_or_else(|e| panic!("(i) the re-added member's device: {e}"));
        assert_eq!(
            (r.granted.clone(), r.local_only.clone()),
            (vec![e1.clone()], vec![e3.clone()]),
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

        // (j) — v62.0.0 (E13; lead's ruling, P5c): a node bob OWNS (his owner
        // binding) with its own self-occurrence IS bob's device: the `(bob,
        // node)` occurrence row the earlier arm required can never exist (a
        // machine under a person is refused). The door grants it what bob
        // holds, and the minter's sweep reaches it as it reaches bob_7. A node
        // with NO owner binding is not bob's device: refused, and the sweep
        // never targets it.
        let infra = k("x1");
        e2::put_key(b, &infra, &[NODE]).await;
        let _ = bind(b, &bob, &infra).await;
        occur(b, &infra, &infra, Some(kem().0)).await;
        // Shut switch only (guarded at the top): with the doors open the
        // earlier rule refuses it `device_rekey_not_an_occurrence`.
        let r = door(infra.clone(), bob.clone())
            .await
            .unwrap_or_else(|e| panic!("(j) bob's owner-bound node is his device: {e}"));
        assert_eq!(
            (r.granted.clone(), r.local_only.clone()),
            (vec![e1.clone()], vec![e3.clone()]),
            "(j) the owner-bound node gets what bob holds: {r:?}"
        );
        let stray = k("x2");
        e2::put_key(b, &stray, &[NODE]).await;
        occur(b, &stray, &stray, Some(kem().0)).await;
        let e = door(stray.clone(), bob.clone()).await.unwrap_err();
        assert!(
            [
                crate::federation::DEVICE_REKEY_RULE_UNBOUND,
                crate::federation::DEVICE_REKEY_RULE_NOT_AN_OCCURRENCE,
            ]
            .contains(&rule_of(&e)),
            "(j) a node with no owner binding is not bob's device: {e}"
        );
        let bob_7 = k("b7");
        device(b, &bob_7, Some(&bob), Some(kem().0), tag).await;
        let swept = rewrap_own_epochs_to_member_devices(b, &alice_1, None, chrono::Utc::now())
            .await
            .unwrap_or_else(|e| panic!("(j) the minter's sweep: {e}"));
        assert_eq!(
            grants_on(b, &comm, &epochs, &stray).await,
            0,
            "(j) the unowned node receives nothing: {swept:?}"
        );
        for dev in [&infra, &bob_7] {
            assert!(
                b.community_dek_has_member_grant(&comm, &e1.0, e1.1, dev)
                    .await
                    .unwrap(),
                "(j) the sweep reaches bob's device {dev}: {swept:?}"
            );
        }
    }
}

/// v50.0.0 (#916 review, N1) — a backend nobody told its node key (a host
/// that never set it) cannot tell its own epochs from a peer's: the door
/// refuses by name rather than misclassify, and the receive-door hook
/// re-wraps nothing (logged).
#[cfg(test)]
pub(crate) async fn i188_no_node_key<B>(b: &B, tag: &str)
where
    B: crate::federation::BlobStorage + crate::federation::FederationDirectory + Sync,
{
    assert!(b.node_key_id().is_none(), "precondition: no node key");
    let e = crate::federation::at_rest_cascade::orchestrate::rekey_community_member_device_add(
        b,
        &format!("room-{tag}"),
        &format!("bob-{tag}"),
        &format!("b2-{tag}"),
        &format!("bob-{tag}"),
        chrono::Utc::now(),
    )
    .await
    .expect_err("a backend with no node key must refuse");
    match e {
        crate::federation::Error::DeviceRekeyRefused { rule, .. } => assert_eq!(
            rule,
            crate::federation::DEVICE_REKEY_RULE_NODE_KEY_UNKNOWN,
            "the refusal names the missing key"
        ),
        other => panic!("expected DeviceRekeyRefused, got {other}"),
    }
    b.rewrap_own_epochs_for_device(&format!("bob-{tag}"), &format!("b2-{tag}"))
        .await
        .expect("the hook skips (logged), it does not fail the admitted row");
}

#[cfg(test)]
mod run {
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i188_no_node_key_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::i188_no_node_key(&b, &format!("nk-{}", suffix())).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i188_no_node_key_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::i188_no_node_key(&b, &format!("nk-{}", suffix())).await;
    }

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
        // The node's own key: epochs minted by `kid("a1-{tag}")` are this
        // node's (v62.0.0, E13: an identity-ref).
        b.set_node_key_id(crate::federation::edition2::fixture_switch::kid(&format!(
            "a1-{tag}"
        )));
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
        // The node's own key: epochs minted by `kid("a1-{tag}")` are this
        // node's (v62.0.0, E13: an identity-ref).
        b.set_node_key_id(crate::federation::edition2::fixture_switch::kid(&format!(
            "a1-{tag}"
        )));
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
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::{
        apply_replicated_statement, ReplicatedStatementOutcome, StatementOutcome,
    };
    use crate::federation::edition2::names::RowId;
    use crate::federation::epoch_minter_invariants::bodies::{ladder, Pick};
    use crate::federation::key_grant::{
        is_key_grant_row, KeyGrantAxis, KeyGrantRow, SignedKeyGrantRow,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::COMMUNITY;
    use crate::federation::types::identity_type::NODE;
    use crate::federation::types::{device_class, IdentityOccurrence};
    use crate::federation::{Attestation, BlobStorage, FederationDirectory};

    /// Every epoch-axis key-grant ROW on `backend` for `(comm, minter,
    /// epoch)` (v55.0.0, #989: one per recipient).
    async fn sets_on<B: FederationDirectory + Sync>(
        backend: &B,
        comm: &str,
        minter: &str,
        epoch: u64,
    ) -> Vec<(Attestation, KeyGrantRow)> {
        backend
            .list_attestations_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.attestation)
            .filter(is_key_grant_row)
            .filter_map(|a| KeyGrantRow::from_attestation(&a).ok().map(|r| (a, r)))
            .filter(|(_, r)| {
                matches!(&r.axis, KeyGrantAxis::Epoch { community_key_id, minter_key_id, epoch: e }
                    if community_key_id == comm && minter_key_id == minter && *e == epoch)
            })
            .collect()
    }

    /// The row on `backend` for `(comm, minter, epoch)` whose recipient is
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
            .find(|(_, r)| r.recipient() == device)
            .map(|(a, _)| a)
    }

    /// A device: its key (`e2::put_key` of `alias`, `node`) live on both
    /// nodes, a fresh content-KEM keypair whose private halves the witness
    /// keeps, and the device's own signer. v62.0.0 (E13): the device's id is
    /// its identity-ref, which is the signer's `federation_id` (cut B).
    struct Device {
        key: String,
        keys: crate::federation::EncryptionPubkeys,
        /// The raw public halves `(x25519, ml_kem_768)`, for an edition-2 bind.
        raw: (Vec<u8>, Vec<u8>),
        private: crate::federation::identity_aggregate::ContentKemPrivate,
    }

    async fn device<B>(a: &B, b: &B, alias: &str) -> Device
    where
        B: FederationDirectory + Sync,
    {
        let mut key = String::new();
        for n in [a, b] {
            key = e2::put_key(n, alias, &[NODE]).await;
        }
        assert_eq!(
            ts::local_signer(alias).federation_id().await,
            key,
            "fixture: the device's signer states its rows under its identity-ref"
        );
        let (x_priv, x_pub, ml_priv, ml_pub) =
            crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        Device {
            key,
            keys: crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x_pub),
                ml_kem_768_base64: B64.encode(&ml_pub),
            },
            raw: (x_pub.to_vec(), ml_pub.clone()),
            private: crate::federation::identity_aggregate::ContentKemPrivate {
                x25519_priv: x_priv,
                ml_kem_768_priv: ml_priv,
                ml_kem_768_pub: ml_pub,
            },
        }
    }

    /// The device's own occurrence `(device, device)` written by `backend`'s
    /// own host through the trusted-local door (what PyEngine's
    /// `put_identity_occurrence_json` writes) — no receive-door hook. v62.0.0
    /// (E13; P5c): a node is never a person's occurrence; bob's claim on it
    /// is his owner binding. `_bob` is kept for the call sites' reading.
    async fn anchor_local<B: FederationDirectory + Sync + ?Sized>(
        backend: &B,
        _bob: &str,
        d: &Device,
    ) {
        backend
            .put_identity_occurrence_local(IdentityOccurrence {
                identity_key_id: d.key.clone(),
                occurrence_key_id: d.key.clone(),
                device_class: device_class::SERVER.to_owned(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(d.keys.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap_or_else(|e| panic!("anchor {} locally: {e}", d.key));
    }

    /// v62.0.0 (E13) — the device's own signed self-occurrence on `n`: O1's
    /// `identity:occurrence` bind of the self pair (author = identity =
    /// occurrence = the node key; one statement), carrying the device's
    /// class and content-KEM keys. A node key is never bound under a person
    /// (`occurrence_binds_machine_to_person`): bob's claim on it is the owner
    /// binding. Returns its row id.
    async fn anchor_self_on<B: FederationDirectory + Sync>(n: &B, d: &Device) -> RowId {
        use ciris_verify_core::cde::Value;
        let enc = Value::Map(vec![
            (Value::Text("x25519".into()), Value::Bytes(d.raw.0.clone())),
            (
                Value::Text("ml_kem_768".into()),
                Value::Bytes(d.raw.1.clone()),
            ),
        ]);
        let opts = e2::BindOptions {
            extra: vec![("encryption_pubkeys", enc)],
            ..e2::BindOptions::default()
        };
        match e2::put_bind(n, &d.key, &d.key, &d.key, device_class::SERVER, &opts).await {
            Ok(StatementOutcome::Row { row_id, .. }) => row_id,
            other => panic!("publish {}'s anchor: {other:?}", d.key),
        }
    }

    /// v62.0.0 (E13) — **bob's owner-binding for `device` on node `n`**: the
    /// binding row (now-relative) and the device's own voice over it (CC 3.2:
    /// the bound node co-signs; `owner_of` requires it). Returns its row id.
    async fn bind_on<B: FederationDirectory + Sync>(n: &B, bob: &str, device: &str) -> RowId {
        let mut row = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), bob, device);
        row.asserted_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            (chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp_millis(),
        )
        .expect("an instant");
        row.scrub_timestamp = row.asserted_at;
        ts::seal_row_in_place(bob, &mut row);
        e2::put_signed(n, &row)
            .await
            .unwrap_or_else(|e| panic!("bob's binding for {device}: {e}"));
        let st = e2::carried_statement(&row).expect("the binding carries its statement");
        e2::put_statement(n, &e2::voice_of(&st, device))
            .await
            .unwrap_or_else(|e| panic!("{device}'s voice on bob's binding: {e}"));
        e2::row_id_of(&st)
    }

    /// v62.0.0 (E13) — **what `from` serves `requester`** of the rows `rows`:
    /// every statement (each voice) of those rows on cut B's FILTERED serve
    /// path (`statements_served_to`), in `from`'s admission order.
    async fn served<B: FederationDirectory + Sync + ?Sized>(
        from: &B,
        requester: &str,
        rows: &[RowId],
    ) -> Vec<(Vec<u8>, RowId)> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                from,
                cursor.as_ref(),
                1000,
                Some(requester),
            )
            .await
            .expect("serve statements");
            for st in page.statements {
                if let Some(id) = RowId::of_statement(&st.bytes) {
                    if rows.contains(&id) {
                        out.push((st.bytes, id));
                    }
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert!(
            !out.is_empty(),
            "{requester} is served the rows it asked for"
        );
        out
    }

    /// Each served statement through `to`'s replicated statement door
    /// (`apply_replicated_statement`), under the id it names.
    async fn deliver(
        to: &dyn FederationDirectory,
        statements: &[(Vec<u8>, RowId)],
    ) -> Vec<ReplicatedStatementOutcome> {
        let mut out = Vec::new();
        for (bytes, id) in statements {
            out.push(
                apply_replicated_statement(to, bytes, &id.0)
                    .await
                    .unwrap_or_else(|e| panic!("a replicated statement: {e}")),
            );
        }
        out
    }

    /// The pending-set loop every host runs — PyEngine's `emit_pending_key_grants`
    /// and init sweep, spelled as they spell it: `dirty_axes` for this node's
    /// key, each emitted by the node's LocalSigner.
    async fn dirty_emit<B>(a: &B, signer: &crate::signing::LocalSigner, me: &str) -> usize
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let mut n = 0;
        for axis in crate::federation::key_grant::dirty_axes(a, me)
            .await
            .unwrap()
        {
            if let Some(e) = crate::federation::key_grant::emit_key_grant_axis_with_local_signer(
                a, signer, &axis,
            )
            .await
            .unwrap()
            {
                n += e.attestation_ids.len();
            }
        }
        n
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
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        // v62.0.0 (E13) — `ladder` names bob by his identity-ref.
        let bob = e2::kid(&format!("em-bob-{run}"));
        let (a, b) = (l.ba.as_ref(), l.bb.as_ref());
        let a_dyn: &dyn FederationDirectory = a;

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
        let b_set = set_carrying(b, &l.comm, &l.node_b, 0, &l.node_a)
            .await
            .expect("B emitted its row to A");
        l.engine_a
            .apply_replicated_key_grant(SignedKeyGrantRow { attestation: b_set })
            .await
            .unwrap_or_else(|e| panic!("A admits B's row: {e}"));
        // And an epoch A holds a self-retention for under a FOREIGN minter's
        // name: the door may re-wrap it locally, never sign a set for it.
        let foreign = format!("fm-{run}");
        ensure_epoch_dek(a, &l.comm, &foreign, 0).await.unwrap();

        let (comm_r, node_a_r, node_b_r, foreign_r) = (&l.comm, &l.node_a, &l.node_b, &foreign);
        let grants_of = move |device: String| async move {
            let mut n = 0;
            for e in [0u64, 1, 2] {
                if a.community_dek_has_member_grant(comm_r, node_a_r, e, &device)
                    .await
                    .unwrap()
                {
                    n += 1;
                }
            }
            n
        };
        let peer_grant = move |device: String| async move {
            a.community_dek_has_member_grant(comm_r, node_b_r, 0, &device)
                .await
                .unwrap()
                || a.community_dek_has_member_grant(comm_r, foreign_r, 0, &device)
                    .await
                    .unwrap()
        };

        // v62.0.0 (E13) — every arm below delivers B's statements to A the
        // way edition 2 replicates: B serves them on cut B's FILTERED path
        // (`statements_served_to`, A's node the requester) and A puts each
        // through a replicated statement door. Each arm keeps what A ends up
        // holding. DEPENDS ON T1.serve.patch (the serve filter's arms).

        // (T0) THE ENGINE — the binding through A's backend door, then A's
        // Engine emits the dirtied sets (an Engine has no statement door of
        // its own; its pending loop is the one every host runs).
        let d0 = device(a, b, &format!("d0-{run}")).await;
        anchor_local(a, &bob, &d0).await;
        let binding = bind_on(b, &bob, &d0.key).await;
        deliver(a_dyn, &served(b, &l.node_a, &[binding]).await).await;
        assert_eq!(grants_of(d0.key.clone()).await, 3, "(T0) re-wrapped");
        l.engine_a
            .emit_pending_key_grants()
            .await
            .unwrap_or_else(|e| panic!("(T0) A's engine emits: {e}"));
        for e in &own {
            assert!(
                set_carrying(a, &l.comm, &l.node_a, *e, &d0.key)
                    .await
                    .is_some(),
                "(T0) the engine emitted epoch {e}'s set carrying d0"
            );
        }

        // (T1) THE TRAIT DOOR — `edition2::ingest::apply_replicated_statement`
        // over A's backend, the call PyEngine and CIRISEdge's bridge make.
        // d1's anchor is already on A (A's host wrote it).
        let d1 = device(a, b, &format!("d1-{run}")).await;
        anchor_local(a, &bob, &d1).await;
        let binding = bind_on(b, &bob, &d1.key).await;
        let outcomes = deliver(a_dyn, &served(b, &l.node_a, &[binding]).await).await;
        assert!(
            outcomes
                .iter()
                .all(|o| matches!(o, ReplicatedStatementOutcome::Admitted(_))),
            "(T1) every statement of the binding is new on A: {outcomes:?}"
        );
        assert_eq!(
            grants_of(d1.key.clone()).await,
            3,
            "(T1) the replicated door re-wrapped A's epochs to d1"
        );
        assert!(
            !peer_grant(d1.key.clone()).await,
            "(T1) never B's epoch, never a foreign-named one"
        );

        // (T2) THE SYNC PATH — CIRISEdge's attributed sync now carries
        // statements: the same door, the sender attributed by the serve
        // requester.
        let d2 = device(a, b, &format!("d2-{run}")).await;
        anchor_local(a, &bob, &d2).await;
        let binding = bind_on(b, &bob, &d2.key).await;
        deliver(a_dyn, &served(b, &l.node_a, &[binding]).await).await;
        assert_eq!(
            grants_of(d2.key.clone()).await,
            3,
            "(T2) the sync path re-wrapped A's epochs to d2"
        );

        // (T3) THE OCCURRENCE DOOR — the other wire order: d3's own signed
        // self-occurrence first (its class and content-KEM keys; no owner yet,
        // so d3 is no device of bob's on A: nothing), then bob's binding,
        // owner's statement plus d3's voice. The grants appear once the
        // binding lands.
        let d3 = device(a, b, &format!("d3-{run}")).await;
        let anchor = anchor_self_on(b, &d3).await;
        deliver(a_dyn, &served(b, &l.node_a, &[anchor]).await).await;
        assert_eq!(
            grants_of(d3.key.clone()).await,
            0,
            "(T3) precondition: d3 has no owner on A yet, so it is no device of bob's"
        );
        let binding = bind_on(b, &bob, &d3.key).await;
        deliver(a_dyn, &served(b, &l.node_a, &[binding]).await).await;
        assert_eq!(
            grants_of(d3.key.clone()).await,
            3,
            "(T3) once the binding lands, A's epochs are re-wrapped to d3"
        );

        // (T4)/(T5) THE CAPSULE — CIRISEdge's shape: an `OpsDirectory` over
        // A's backend. d6 through the capsule's `ApplyReplicatedStatement` op
        // body (`dispatch_directory_op`, what runs inside persist's `.so`), d7
        // through the replicated door composed over the proxy itself. Either
        // way the one hook re-wraps on A's backend.
        let rt = std::sync::Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("capsule runtime"),
        );
        // Never dropped: a runtime may not be dropped inside this async test.
        std::mem::forget(rt.clone());
        let proxy = crate::ffi::directory_capsule::build_ops_directory(
            crate::ffi::directory_capsule::build_persist_directory(
                l.ba.clone() as std::sync::Arc<dyn FederationDirectory>
            ),
            std::sync::Arc::new(crate::ffi::executor_capsule::build_persist_executor(rt)),
        )
        .expect("abi ok");
        let d6 = device(a, b, &format!("d6-{run}")).await;
        anchor_local(a, &bob, &d6).await;
        let binding = bind_on(b, &bob, &d6.key).await;
        for (bytes, id) in served(b, &l.node_a, &[binding]).await {
            let out = crate::ffi::directory_capsule::dispatch_directory_op(
                a_dyn,
                crate::ffi::directory_capsule::DirectoryOp::ApplyReplicatedStatement {
                    statement: bytes,
                    offered_row_id: id.0,
                },
            )
            .await;
            assert!(
                matches!(
                    out,
                    crate::ffi::directory_capsule::DirectoryOpResult::ReplicatedStatementOutcome(_)
                ),
                "(T4) the capsule's op admits bob's binding for d6: {out:?}"
            );
        }
        assert_eq!(
            grants_of(d6.key.clone()).await,
            3,
            "(T4) the capsule's op re-wrapped A's epochs to d6 on A's backend"
        );
        let d7 = device(a, b, &format!("d7-{run}")).await;
        anchor_local(a, &bob, &d7).await;
        let binding = bind_on(b, &bob, &d7.key).await;
        deliver(&*proxy, &served(b, &l.node_a, &[binding]).await).await;
        assert_eq!(
            grants_of(d7.key.clone()).await,
            3,
            "(T5) the door over the proxy re-wrapped A's epochs to d7 on A's backend"
        );

        // The rows: A's pending loop (the one PyEngine runs) signs and emits
        // one row per wrap the doors wrote; each device's row, read off A's
        // `list_attestations_since`, opens to the DEK bob's node already
        // holds on B (v55.0.0, #989: a row to a device crosses to that
        // device's node, never to bob's).
        let signer_a = ts::local_signer(&format!("em-a-{run}"));
        assert_eq!(signer_a.derived_key_id(), l.node_a, "fixture: A's signer");
        assert!(
            dirty_emit(a, &signer_a, &l.node_a).await >= 3,
            "(T) the doors left A's three epochs dirty"
        );
        let b_priv = b.load_content_kem_private_halves().await.unwrap();
        // B holds A's epochs through A's rows to bob's node, delivered.
        for e in &own {
            let row = set_carrying(a, &l.comm, &l.node_a, *e, &l.node_b)
                .await
                .unwrap_or_else(|| panic!("(T) A's row for epoch {e} to bob's node"));
            l.engine_b
                .apply_replicated_key_grant(SignedKeyGrantRow { attestation: row })
                .await
                .unwrap_or_else(|e| panic!("(T) B admits A's row: {e:?}"));
        }
        for e in &own {
            for d in [&d1, &d2, &d3, &d6, &d7] {
                let set = set_carrying(a, &l.comm, &l.node_a, *e, &d.key)
                    .await
                    .unwrap_or_else(|| panic!("(T) A's loop emitted epoch {e}'s row to {}", d.key));
                let wrap = KeyGrantRow::from_attestation(&set)
                    .unwrap()
                    .wrap
                    .wrapped_dek;
                let (_, bob_wrap) = b
                    .community_dek_member_grant_wrap(&l.comm, &l.node_a, *e, &l.node_b)
                    .await
                    .unwrap()
                    .expect("bob's node's own wrap on B");
                assert_eq!(
                    unwrap_dek_v2_json(&d.private, &wrap).unwrap(),
                    unwrap_dek_v2_json(&b_priv, &bob_wrap).unwrap(),
                    "(T) on B, {} opens A's epoch {e} to the DEK bob's node holds",
                    d.key
                );
            }
        }

        // (S) THE SWEEP — d4's binding reaches A through the trait door before
        // its anchor (nothing); the anchor lands through a door with no hook;
        // the pending sweep re-wraps and emits.
        let d4 = device(a, b, &format!("d4-{run}")).await;
        let binding = bind_on(b, &bob, &d4.key).await;
        let statements = served(b, &l.node_a, &[binding]).await;
        deliver(a_dyn, &statements).await;
        anchor_local(a, &bob, &d4).await;
        // (U) A settled statement never re-wraps (#917 phase 2): the same
        // binding re-delivered is `Unchanged`, and the hook, which fires on
        // the store's insert only, does not run — so d4, now anchored, still
        // holds nothing until the sweep.
        let again = deliver(a_dyn, &statements).await;
        assert!(
            again
                .iter()
                .all(|o| matches!(o, ReplicatedStatementOutcome::Unchanged(_))),
            "(U) re-delivery is Unchanged: {again:?}"
        );
        assert_eq!(
            grants_of(d4.key.clone()).await,
            0,
            "(S) precondition: no door re-wrapped d4 yet"
        );
        l.engine_a
            .emit_pending_key_grants()
            .await
            .unwrap_or_else(|e| panic!("(S) A's pending sweep: {e}"));
        assert_eq!(
            grants_of(d4.key.clone()).await,
            3,
            "(S) the sweep re-wrapped A's epochs to d4"
        );
        for e in &own {
            assert!(
                set_carrying(a, &l.comm, &l.node_a, *e, &d4.key)
                    .await
                    .is_some(),
                "(S) and emitted epoch {e}'s set carrying d4"
            );
        }

        // (D) THE HOST'S DOOR on the minter — d5 bound and anchored on A
        // through doors with no hook: the door grants A's epochs, the
        // foreign-named one LOCALLY ONLY, reports B's as minted elsewhere, and
        // emits sets for A's own epochs only.
        let d5 = device(a, b, &format!("d5-{run}")).await;
        // (D) bob binds d5 on A (A's host's own door).
        bind_on(a, &bob, &d5.key).await;
        anchor_local(a, &bob, &d5).await;
        let r = l
            .engine_a
            .rekey_community_member_device_add(&l.comm, &bob, &d5.key, &bob)
            .await
            .unwrap_or_else(|e| panic!("(D) the door on A: {e}"));
        let mut granted = r.granted.clone();
        granted.sort();
        let want: Vec<(String, u64)> = own.iter().map(|e| (l.node_a.clone(), *e)).collect();
        assert_eq!(granted, want, "(D) {r:?}");
        assert_eq!(
            r.local_only,
            vec![(foreign.clone(), 0)],
            "(D) the foreign-named epoch is granted here and reported local-only: {r:?}"
        );
        // v55.0.0 (#989): B's rows to bob's holders cross to THEIR nodes, never
        // to A (CC 6.1.5.3 refers-to), so A holds no B epoch for bob and has
        // none to report; B re-wraps its own on the binding's arrival. The
        // single-node `MintedElsewhere` witness (a peer epoch known here by a
        // holder's wrap) is unchanged above.
        assert_eq!(
            r.content_miss
                .iter()
                .map(|m| (m.minter_key_id.clone(), m.epoch, m.reason))
                .collect::<Vec<_>>(),
            Vec::<(String, u64, EpochMissReason)>::new(),
            "(D) B's epoch never reached A for bob's holders: {r:?}"
        );
        for e in &own {
            assert!(
                set_carrying(a, &l.comm, &l.node_a, *e, &d5.key)
                    .await
                    .is_some(),
                "(D) the door emitted A's epoch {e} set carrying d5"
            );
        }
        assert!(
            sets_on(a, &l.comm, &foreign, 0).await.is_empty(),
            "(D) no set is ever signed for an epoch this node did not mint"
        );

        // (D') THE POSITIVE OUTCOME (v55.0.0, #989, CC 6.1.5.3): B's epoch is
        // B's to re-wrap. d5's binding and anchor reach B; B's own door
        // re-wraps B's epoch 0 to d5 and emits B's row to d5, and d5 opens it
        // to the DEK B sealed under, so the re-added device reads B's content.
        anchor_local(b, &bob, &d5).await;
        let _ = bind_on(b, &bob, &d5.key).await;
        let rb = l
            .engine_b
            .rekey_community_member_device_add(&l.comm, &bob, &d5.key, &bob)
            .await
            .unwrap_or_else(|e| panic!("(D') the door on B: {e}"));
        assert!(
            rb.granted.contains(&(l.node_b.clone(), 0)),
            "(D') B re-wraps its own epoch 0 to d5: {rb:?}"
        );
        let row = set_carrying(b, &l.comm, &l.node_b, 0, &d5.key)
            .await
            .expect("(D') B emitted its epoch 0 row to d5");
        let d5_wrap = KeyGrantRow::from_attestation(&row).unwrap().wrap;
        assert_eq!(d5_wrap.recipient_key_id, d5.key, "(D') the row's recipient");
        // B's serve gate hands the row to d5's node (refers-to), and to A —
        // which hosts none of bob's holders — not at all.
        assert!(
            crate::federation::replication_audience::may_receive(b, &d5.key, &row)
                .await
                .unwrap()
                .allowed(),
            "(D') B's row crosses to d5"
        );
        assert!(
            !crate::federation::replication_audience::may_receive(b, &l.node_a, &row)
                .await
                .unwrap()
                .allowed(),
            "(D') B's row to d5 never crosses to A"
        );
        let (_, b_own) = b
            .community_dek_member_grant_wrap(&l.comm, &l.node_b, 0, &l.node_b)
            .await
            .unwrap()
            .expect("(D') B's own wrap of its epoch 0");
        let b_priv = b.load_content_kem_private_halves().await.unwrap();
        assert_eq!(
            unwrap_dek_v2_json(&d5.private, &d5_wrap.wrapped_dek)
                .unwrap_or_else(|e| panic!("(D') d5 opens B's row: {e}")),
            unwrap_dek_v2_json(&b_priv, &b_own).unwrap(),
            "(D') d5 holds the DEK B's content is sealed under"
        );
    }

    /// **I188(k) — CIRISPersist#967: a room that NEVER rotated is re-wrapped
    /// too.** Its only epoch is 0: no bump, no retain policy, so the minter's
    /// pointer table holds no row for it. The enumeration the #916 walk uses
    /// must still name it, and a member device arriving after epoch 0 was
    /// minted must be granted epoch 0 — the pair-room case (CIRISEdge#768).
    pub(crate) async fn i188k_a_never_rotated_room_rewraps<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let bob = e2::kid(&format!("em-bob-{run}"));
        let (a, b) = (l.ba.as_ref(), l.bb.as_ref());
        l.engine_a
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"epoch zero only", None, None)
            .await
            .unwrap_or_else(|e| panic!("(k) A seals at epoch 0: {e}"));
        assert_eq!(
            a.community_dek_retain_past_epochs(&l.comm, &l.node_a)
                .await
                .unwrap(),
            None,
            "(k) precondition: no retain policy"
        );
        assert!(
            a.community_dek_communities()
                .await
                .unwrap()
                .contains(&l.comm),
            "(k) a room with key state at epoch 0 is enumerated (#967)"
        );
        let d = device(a, b, &format!("dk-{run}")).await;
        anchor_local(a, &bob, &d).await;
        // v62.0.0 (E13) — bob's binding delivered as statements (filtered
        // serve, A's replicated statement door). DEPENDS ON T1.serve.patch.
        let binding = bind_on(b, &bob, &d.key).await;
        deliver(a, &served(b, &l.node_a, &[binding]).await).await;
        assert!(
            a.community_dek_has_member_grant(&l.comm, &l.node_a, 0, &d.key)
                .await
                .unwrap(),
            "(k) the late device holds epoch 0 of a never-rotated room (#967)"
        );
        let set = set_carrying(a, &l.comm, &l.node_a, 0, &d.key)
            .await
            .expect("(k) epoch 0's set carries the late device");
        let wrap = KeyGrantRow::from_attestation(&set).unwrap().wrap;
        assert_eq!(wrap.recipient_key_id, d.key, "(k) the wrap");
        let dek = unwrap_dek_v2_json(&d.private, &wrap.wrapped_dek)
            .unwrap_or_else(|e| panic!("(k) the device opens its wrap: {e}"));
        assert_eq!(dek.len(), 32, "(k) a 32-byte DEK");
    }

    /// Re-open `dsn` as a FRESH backend handle — one no `Engine` has ever told
    /// its node key; the shape a host hands `Engine::from_shared*`.
    pub(crate) type Reopen = fn(
        String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::engine::BackendDispatch> + Send>,
    >;

    /// **I380 (CIRISPersist#966)** — an `Engine` over a SHARED backend tells
    /// that backend its node key at construction, so the backend's own
    /// receive door (the one every host's sync reaches, no signer in hand)
    /// re-wraps the node's epochs to a member's late device. Before the fix
    /// the shared backend's node key was `None` and the door re-wrapped
    /// nothing: "none set: nothing is theirs to re-wrap".
    pub(crate) async fn i380_a_shared_engine_rewraps_for_a_late_device<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
        reopen: Reopen,
    ) where
        B: BlobStorage + FederationDirectory + Sync + 'static,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let bob = e2::kid(&format!("em-bob-{run}"));
        l.engine_a
            .put_blob_scoped(COMMUNITY, Some(&l.comm), b"before the device", None, None)
            .await
            .unwrap_or_else(|e| panic!("I380 A seals at epoch 0: {e}"));

        // Both shared constructors, each over its own fresh handle.
        let plain =
            crate::Engine::from_shared(reopen(dsn_a.to_owned()).await, l.engine_a.signer().clone());
        let with_local = crate::Engine::from_shared_with_local(
            reopen(dsn_a.to_owned()).await,
            l.engine_a.signer().clone(),
            None,
        );
        for (name, e) in [
            ("from_shared", &plain),
            ("from_shared_with_local", &with_local),
        ] {
            assert_eq!(
                pick(e).node_key_id().as_deref(),
                Some(l.node_a.as_str()),
                "I380 {name} tells the shared backend its node key — the same id \
                 `register_self_federation_key` uses"
            );
        }

        let shared = pick(&plain);
        let b = l.bb.as_ref();
        let d = device(shared.as_ref(), b, &format!("d380-{run}")).await;
        anchor_local(shared.as_ref(), &bob, &d).await;
        let binding = bind_on(b, &bob, &d.key).await;
        // The backend's own receive door — not the Engine's, which tells the
        // backend its key on the way in (#916 N1) and so hides the gap.
        // v62.0.0 (E13): the replicated statement door over the shared
        // backend. DEPENDS ON T1.serve.patch.
        deliver(
            &*plain.federation_directory(),
            &served(b, &l.node_a, &[binding]).await,
        )
        .await;
        assert!(
            shared
                .community_dek_has_member_grant(&l.comm, &l.node_a, 0, &d.key)
                .await
                .unwrap(),
            "I380 the shared backend re-wrapped its own epoch to the late device"
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
        // v62.0.0 (E13) — edition 2; DEPENDS ON T1.serve.patch.
        Box::pin(super::two_node::i188_the_minter_rewraps_its_own_history(
            "sqlite::memory:",
            "sqlite::memory:",
            &suffix(),
            (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::sqlite::SqliteBackend,
                >,
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i188_two_node_postgres() {
        // v62.0.0 (E13) — edition 2; DEPENDS ON T1.serve.patch.
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        Box::pin(super::two_node::i188_the_minter_rewraps_its_own_history(
            &a,
            &b,
            &suffix(),
            (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::postgres::PostgresBackend,
                >,
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i380_shared_engine_sqlite() {
        // v62.0.0 (E13) — edition 2; DEPENDS ON T1.serve.patch.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        Box::pin(
            super::two_node::i380_a_shared_engine_rewraps_for_a_late_device(
                &format!("sqlite:///{}", path.display()),
                "sqlite::memory:",
                &suffix(),
                (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                    as crate::federation::epoch_minter_invariants::bodies::Pick<
                        crate::store::sqlite::SqliteBackend,
                    >,
                |dsn| {
                    Box::pin(async move {
                        let path = dsn.strip_prefix("sqlite:///").unwrap().to_owned();
                        crate::engine::BackendDispatch::Sqlite(std::sync::Arc::new(
                            crate::store::sqlite::SqliteBackend::open(path)
                                .await
                                .unwrap(),
                        ))
                    })
                },
            ),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i380_shared_engine_postgres() {
        // v62.0.0 (E13) — edition 2; DEPENDS ON T1.serve.patch.
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        Box::pin(
            super::two_node::i380_a_shared_engine_rewraps_for_a_late_device(
                &a,
                &b,
                &suffix(),
                (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                    as crate::federation::epoch_minter_invariants::bodies::Pick<
                        crate::store::postgres::PostgresBackend,
                    >,
                |dsn| {
                    Box::pin(async move {
                        crate::engine::BackendDispatch::Postgres(std::sync::Arc::new(
                            crate::store::postgres::PostgresBackend::connect(&dsn)
                                .await
                                .unwrap(),
                        ))
                    })
                },
            ),
        )
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i188k_never_rotated_sqlite() {
        // v62.0.0 (E13) — edition 2; DEPENDS ON T1.serve.patch.
        Box::pin(super::two_node::i188k_a_never_rotated_room_rewraps(
            "sqlite::memory:",
            "sqlite::memory:",
            &suffix(),
            (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::sqlite::SqliteBackend,
                >,
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i188k_never_rotated_postgres() {
        // v62.0.0 (E13) — edition 2; DEPENDS ON T1.serve.patch.
        let (Some(a), Some(b)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
            return;
        };
        Box::pin(super::two_node::i188k_a_never_rotated_room_rewraps(
            &a,
            &b,
            &suffix(),
            (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::postgres::PostgresBackend,
                >,
        ))
        .await;
    }
}
