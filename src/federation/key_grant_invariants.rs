//! CIRISPersist#848 (`FSD/BLOB_REPLICATION.md` §18) — **the
//! two-node witnesses, I59–I67.**
//!
//! "Two nodes" is two backends, each with its own signer and its own
//! content-KEM keyring, connected only by taking an envelope from one and
//! handing it to the other's apply door. No shared directory: every node
//! resolves every signer from its OWN `federation_keys`, exactly as a peer
//! would (CEG §0).
//!
//! Generic over the backend so the same drive runs on sqlite and postgres —
//! the `#[cfg(test)]` wrappers at the bottom instantiate two (or three)
//! in-memory sqlite backends, and two (or three) `test_pg::empty_dsn()`
//! databases when the postgres feature and a test cluster are present.

/// The fixture and the exercises: [`Node`], the crossings
/// ([`carry_key_grant`](two_node::carry_key_grant),
/// [`carry_bytes`](two_node::carry_bytes)), and one `exercise_*` per
/// behavioural invariant.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod two_node {
    use crate::federation::adopt_cascade::{adopt_sealed_blob, AdoptDisposition};
    use crate::federation::at_rest_cascade::blob_invariants::{hold_ctx, node_signer};
    use crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer;
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::key_grant::{
        admit_replicated_key_grant, emit_content_key_grant_with_local_signer,
        emit_epoch_key_grant_with_local_signer, KeyGrantAxis, KeyGrantSet, SignedKeyGrantSet,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY, SELF};
    use crate::federation::types::identity_type::USER;
    use crate::federation::{
        BlobBody, BlobError, BlobProvenance, BlobStorage, EncryptionPubkeys, Error,
        FederationDirectory, GrantWrap,
    };
    use std::sync::Arc;

    /// One node: a backend, its signer, its derived federation key, and the
    /// content-KEM pubkeys its own keyring holds the private halves for.
    pub struct Node<'a, B> {
        /// The node's substrate.
        pub backend: &'a B,
        /// The node's hybrid signer (the minter / author on this node).
        pub signer: Arc<crate::signing::LocalSigner>,
        /// `signer.derived_key_id()` — the node's occurrence key everywhere.
        pub key: String,
        /// This node's content-KEM identity: what a peer wraps to when it
        /// wraps to this node's occurrence, and what only this node can open.
        pub kem: EncryptionPubkeys,
    }

    /// Bring up a node on `backend`: register the alias and its derived key
    /// in the node's own directory, mint its content-KEM identity.
    pub async fn node<'a, B>(backend: &'a B, alias: &str) -> Node<'a, B>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let signer = node_signer(backend, alias).await;
        let key = signer.derived_key_id();
        let id = backend
            .load_or_init_content_kem_identity()
            .await
            .expect("content-KEM identity");
        Node {
            backend,
            signer,
            key,
            kem: EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            },
        }
    }

    /// Every node learns every other node's derived key — the ONE piece of
    /// shared knowledge two real nodes have after a key-record exchange. The
    /// pubkeys are the alias's deterministic pair (`ts::hybrid_pubkeys`), so
    /// a signature made on one node verifies on the other against a row the
    /// other node registered itself.
    pub async fn introduce<B>(nodes: &[&Node<'_, B>], aliases: &[&str])
    where
        B: FederationDirectory + Sync,
    {
        for (i, n) in nodes.iter().enumerate() {
            for (j, other) in nodes.iter().enumerate() {
                if i != j {
                    ts::register_hybrid_key_as(n.backend, &other.key, aliases[j], USER).await;
                }
            }
        }
    }

    /// Seed the same community on every node: the community key, each
    /// member identity, and each member's occurrence = the member's NODE
    /// (its derived key, with the node's content-KEM pubkeys). A member
    /// with `None` node is on the roster with no occurrence anywhere.
    pub async fn seed_community_everywhere<B>(
        nodes: &[&Node<'_, B>],
        comm: &str,
        members: &[(&str, Option<&Node<'_, B>>)],
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        for n in nodes {
            ts::register_hybrid_key_as(n.backend, comm, comm, USER).await;
            for (ident, occ) in members {
                ts::register_hybrid_key_as(n.backend, ident, ident, USER).await;
                if let Some(o) = occ {
                    n.backend
                        .put_identity_occurrence_local(
                            crate::federation::types::IdentityOccurrence {
                                identity_key_id: (*ident).to_owned(),
                                occurrence_key_id: o.key.clone(),
                                device_class: crate::federation::types::device_class::SERVER.into(),
                                hardware_attestation: None,
                                asserted_at: chrono::Utc::now(),
                                valid_until: None,
                                encryption_pubkeys: Some(o.kem.clone()),
                                transport_binding: None,
                                persist_row_hash: String::new(),
                            },
                        )
                        .await
                        .unwrap_or_else(|e| panic!("occurrence {} of {ident}: {e}", o.key));
                }
            }
            let roster = members
                .iter()
                .map(|(ident, _)| crate::federation::types::CommunityMember {
                    key_id: (*ident).to_owned(),
                    joined_at: chrono::Utc::now(),
                    role: None,
                })
                .collect();
            n.backend
                .put_community(ts::sign_community(
                    comm,
                    crate::federation::types::Community {
                        community_key_id: comm.to_owned(),
                        community_name: "Two-node Co-op".into(),
                        members: roster,
                        founded_at: chrono::Utc::now(),
                        consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                            .to_owned(),
                        policy_blob: None,
                        persist_row_hash: String::new(),
                    },
                ))
                .await
                .unwrap_or_else(|e| panic!("seed community {comm}: {e}"));
        }
    }

    /// The wire crossing: take the row `emitted` on `from` and hand it to
    /// `to`'s apply door. Nothing else moves.
    pub async fn carry_key_grant<B>(
        from: &Node<'_, B>,
        to: &Node<'_, B>,
        attestation_id: &str,
    ) -> Result<crate::federation::key_grant::KeyGrantAdmission, Error>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let row = from
            .backend
            .get_attestation(attestation_id)
            .await
            .expect("read the emitted row")
            .expect("the emitted row exists on the emitter");
        admit_replicated_key_grant(to.backend, SignedKeyGrantSet { attestation: row }).await
    }

    /// The bytes crossing: `to` adopts the sealed bytes `from` holds, with
    /// the provenance the referencing attestation would declare. `family`
    /// is `to`'s operator predicate (#846 §4): for `self` / `family`
    /// content the holder is party to it exactly when the author is
    /// local-or-family — the owner's other device names the first one.
    #[allow(clippy::too_many_arguments)]
    pub async fn carry_bytes<B>(
        from: &Node<'_, B>,
        to: &Node<'_, B>,
        sha: &[u8; 32],
        cohort_scope: &str,
        community_or_owner: &str,
        epoch: Option<u64>,
        tier: CryptoTier,
        family: &[String],
    ) -> Result<[u8; 32], BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let Some(BlobBody::Inline(bytes)) = from.backend.get_blob(sha).await? else {
            panic!("the sealed blob is inline on the author");
        };
        let ctx = hold_ctx(false, &to.key, family);
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(to.signer.clone());
        let out = adopt_sealed_blob(
            to.backend,
            &adapter,
            &ctx,
            &bytes,
            &BlobProvenance {
                author_key_id: from.key.clone(),
                cohort_scope: cohort_scope.to_owned(),
                community_key_id: Some(community_or_owner.to_owned()),
                epoch,
                tier,
            },
            None,
            AdoptDisposition::LocalOnly,
        )
        .await?;
        Ok(out.sha256)
    }

    /// Sign a set with `signer` WITHOUT storing it anywhere — a forger's
    /// row, or a row built off-node.
    pub async fn sign_set_unstored(
        signer: &crate::signing::LocalSigner,
        set: &KeyGrantSet,
    ) -> SignedKeyGrantSet {
        let key = signer.derived_key_id();
        let mut input = set.emit_input();
        let canonical = crate::federation::attestation_emit::stamp_and_canonicalize(
            &mut input,
            &key,
            chrono::Utc::now(),
        )
        .expect("canonicalize");
        let sig = signer.sign_hybrid(&canonical).await.expect("hybrid sign");
        let (row, _) = crate::federation::attestation_emit::assemble(key, &canonical, sig, input)
            .expect("assemble");
        SignedKeyGrantSet { attestation: row }
    }

    fn refusal_reason(e: &Error) -> &'static str {
        match e {
            Error::KeyGrantRefused { reason, .. } => reason,
            other => panic!("expected a typed KeyGrantRefused, got {other:?}"),
        }
    }

    // ── I60 ──────────────────────────────────────────────────────────────
    /// **A `KeyGrant` whose signer is not the set's minter, or not an active
    /// member of the community at `asserted_at`, is refused at admission;
    /// the signer is resolved from the admitting node's directory.**
    pub async fn exercise_i60_forged_set_refused<B>(a: &Node<'_, B>, b: &Node<'_, B>, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let bob = format!("{tag}-bob-{run}");
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;

        // Mallory: a registered key on BOTH nodes, a member of nothing.
        let mallory_alias = format!("{tag}-mallory-{run}");
        let mallory = node_signer(a.backend, &mallory_alias).await;
        let mallory_key = mallory.derived_key_id();
        ts::register_hybrid_key_as(b.backend, &mallory_key, &mallory_alias, USER).await;

        // A mints (C, A, 0) and wraps to both nodes' occurrences.
        let sealed =
            encrypt_and_cascade_community(a.backend, &comm, b"minutes", None, Some(&a.key))
                .await
                .unwrap_or_else(|e| panic!("{tag} I60: A seals: {e}"));
        let honest = crate::federation::key_grant::build_epoch_set(a.backend, &comm, &a.key, 0)
            .await
            .unwrap()
            .expect("A holds wraps for (C, A, 0)");
        assert_eq!(sealed.epoch, 0);

        // (1) Mallory signs A's set, claiming A's counter.
        let forged = sign_set_unstored(&mallory, &honest).await;
        let err = admit_replicated_key_grant(b.backend, forged)
            .await
            .expect_err("a set signed by someone other than its minter must be refused");
        assert_eq!(
            refusal_reason(&err),
            "signer_not_minter",
            "{tag} I60: mallory signing A's counter must be refused as not-the-minter, got {err}"
        );

        // (2) Mallory signs a set for Mallory's own counter — but Mallory is
        //     no member of C at asserted_at per B's roster fold.
        let own = KeyGrantSet {
            axis: KeyGrantAxis::Epoch {
                community_key_id: comm.clone(),
                minter_key_id: mallory_key.clone(),
                epoch: 0,
            },
            wraps: honest.wraps.clone(),
        };
        let err = admit_replicated_key_grant(b.backend, sign_set_unstored(&mallory, &own).await)
            .await
            .expect_err("a non-member's set must be refused");
        assert_eq!(
            refusal_reason(&err),
            "signer_not_active_member",
            "{tag} I60: {err}"
        );

        // (3) A wrap that is not v2, signed by the honest minter.
        let mut v1 = honest.clone();
        v1.wraps[0].wrap_algorithm = "v1".into();
        let err = admit_replicated_key_grant(b.backend, sign_set_unstored(&a.signer, &v1).await)
            .await
            .expect_err("a non-v2 wrap must be refused");
        assert_eq!(
            refusal_reason(&err),
            "wrap_algorithm_not_v2",
            "{tag} I60: {err}"
        );

        // (4) A community B has never heard of: the signer cannot be an
        //     active member of a roster B does not hold.
        let ghost = KeyGrantSet {
            axis: KeyGrantAxis::Epoch {
                community_key_id: format!("{tag}-ghost-{run}"),
                minter_key_id: a.key.clone(),
                epoch: 0,
            },
            wraps: honest.wraps.clone(),
        };
        let err = admit_replicated_key_grant(b.backend, sign_set_unstored(&a.signer, &ghost).await)
            .await
            .expect_err("a set for an unknown community must be refused");
        assert_eq!(
            refusal_reason(&err),
            "signer_not_active_member",
            "{tag} I60: {err}"
        );

        // Nothing was projected by any refusal.
        assert!(
            !b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I60: a refused set must project NOTHING"
        );
        assert!(
            !b.backend
                .community_dek_has_member_grant(&comm, &mallory_key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I60: a refused set must project NOTHING (mallory's counter)"
        );
    }

    // ── I61 ──────────────────────────────────────────────────────────────
    /// **THE END TO END.** A seals a community blob under (C, A, E) and
    /// emits its set; B admits the set and adopts the bytes; B's member
    /// occurrence opens the blob; a non-member on B is `NotGranted`.
    pub async fn exercise_i61_end_to_end<B>(a: &Node<'_, B>, b: &Node<'_, B>, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let bob = format!("{tag}-bob-{run}");
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;

        // A seals under (C, A, 0) — the fan-out wraps to B's occurrence
        // with B's OWN content-KEM pubkeys, which only B can open.
        let sealed =
            encrypt_and_cascade_community(a.backend, &comm, b"the minutes", None, Some(&a.key))
                .await
                .unwrap_or_else(|e| panic!("{tag} I61: A seals: {e}"));
        assert_eq!(sealed.minter_key_id, a.key, "{tag} I61: A is the minter");
        assert!(
            sealed.granted.contains(&b.key),
            "{tag} I61: precondition — A wrapped to B's occurrence; granted={:?}",
            sealed.granted
        );
        let sha = sealed.at_rest_sha256;

        // Before anything crosses: B holds the bytes? No. The key? No.
        let err = read_any_for_viewer(b.backend, &sha, &b.key, None)
            .await
            .expect_err("{tag} I61: nothing has crossed yet");
        assert!(
            matches!(err, BlobError::NotHeld { .. }),
            "{tag} I61: got {err:?}"
        );

        // A emits the FULL set for (C, A, 0) through its attestation store.
        let emitted = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap_or_else(|e| panic!("{tag} I61: A emits: {e}"))
            .expect("A holds wraps to emit");

        // The set is what a PEER pulls: it rides the federation-tier
        // attestation cursor (§14 — "listable by the replication reader"),
        // under the epoch-axis row type, signed by the minter.
        let served = a
            .backend
            .list_attestations_since(None, 1_000)
            .await
            .expect("the attestation cursor");
        let row = served
            .iter()
            .find(|x| x.attestation.attestation_id == emitted.attestation_id)
            .unwrap_or_else(|| {
                panic!("{tag} I61: the emitted set is not on A's replication cursor")
            });
        assert_eq!(
            row.attestation.attestation_type,
            crate::federation::key_grant::KEY_GRANT_EPOCH_ATTESTATION_TYPE
        );
        assert_eq!(
            row.attestation.attesting_key_id, a.key,
            "{tag} I61: signed by the minter"
        );

        // The wire: the set, then the bytes.
        let admission = carry_key_grant(a, b, &emitted.attestation_id)
            .await
            .unwrap_or_else(|e| panic!("{tag} I61: B admits A's set: {e}"));
        assert!(
            admission.wraps_written >= 1,
            "{tag} I61: B projected A's wraps: {admission:?}"
        );
        assert!(
            b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I61: B's occurrence holds a grant on (C, A, 0) after admission"
        );
        let adopted = carry_bytes(
            a,
            b,
            &sha,
            COMMUNITY,
            &comm,
            Some(0),
            CryptoTier::CommunityDek,
            &[],
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I61: B adopts the bytes: {e}"));
        assert_eq!(adopted, sha);
        assert_eq!(
            b.backend.community_dek_blob_epoch(&sha).await.unwrap(),
            Some((comm.clone(), a.key.clone(), 0)),
            "{tag} I61: the binding on B names (C, A, 0) — the author is the minter"
        );

        // B's member occurrence OPENS it — with a DEK B recovered from the
        // wrap addressed to it, since B never minted (C, A, 0).
        assert!(
            b.backend
                .community_dek_get_self_retention(&comm, &a.key, 0)
                .await
                .unwrap()
                .is_none(),
            "{tag} I61: B holds no self-retention for A's epoch — the open must come from B's grant"
        );
        let got = read_any_for_viewer(b.backend, &sha, &b.key, None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I61: B's member opens A's blob on B: {e}"));
        assert_eq!(
            got, b"the minutes",
            "{tag} I61: the plaintext, on the other node"
        );

        // A non-member on B is NotGranted, naming nothing.
        let stranger = format!("{tag}-stranger-{run}");
        let err = read_any_for_viewer(b.backend, &sha, &stranger, None)
            .await
            .expect_err("{tag} I61: a stranger must be refused");
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I61: expected NotGranted, got {err:?}"
        );
        // And A's own occurrence, asked on B, is granted there too (the set
        // carried every wrap) — but its private half lives on A, so B cannot
        // open for it. The refusal names that, not `NotGranted`.
        assert!(
            b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &a.key)
                .await
                .unwrap(),
            "{tag} I61: the set carried A's own wrap too (§13: every recipient)"
        );
        let err = read_any_for_viewer(b.backend, &sha, &a.key, None)
            .await
            .expect_err("{tag} I61: A's private half is not on B");
        assert!(
            !matches!(err, BlobError::NotGranted { .. }),
            "{tag} I61: A IS granted; B just cannot open for A — got {err:?}"
        );
    }

    // ── I62 ──────────────────────────────────────────────────────────────
    /// **The projection is a union and order-independent**: re-applying a
    /// set, applying a superset, and applying the set before the bytes
    /// arrive all leave every prior grant in place and add the new ones.
    pub async fn exercise_i62_union_order_independent<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let bob = format!("{tag}-bob-{run}");
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;
        let sealed = encrypt_and_cascade_community(a.backend, &comm, b"v1", None, Some(&a.key))
            .await
            .unwrap();
        let sha = sealed.at_rest_sha256;
        let emitted = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("wraps");

        // (1) The set BEFORE the bytes: stored, nothing lost.
        let first = carry_key_grant(a, b, &emitted.attestation_id)
            .await
            .unwrap();
        assert!(
            first.wraps_written >= 2,
            "{tag} I62: first admit writes: {first:?}"
        );
        let before: Vec<String> = b
            .backend
            .community_dek_member_grant_recipients(&comm, &a.key, 0)
            .await
            .unwrap();
        assert!(
            before.contains(&b.key) && before.contains(&a.key),
            "{tag} I62: {before:?}"
        );

        // (2) Re-apply the SAME set: idempotent, nothing removed.
        let again = carry_key_grant(a, b, &emitted.attestation_id)
            .await
            .unwrap();
        assert_eq!(
            again.wraps_written, 0,
            "{tag} I62: a re-applied set writes nothing new"
        );
        assert_eq!(
            b.backend
                .community_dek_member_grant_recipients(&comm, &a.key, 0)
                .await
                .unwrap(),
            before,
            "{tag} I62: re-emission un-granted somebody"
        );

        // (3) A SUPERSET (a late recipient) adds and keeps.
        let mut superset =
            crate::federation::key_grant::build_epoch_set(a.backend, &comm, &a.key, 0)
                .await
                .unwrap()
                .unwrap();
        let late = format!("{tag}-late-occ-{run}");
        superset.wraps.push(GrantWrap {
            recipient_key_id: late.clone(),
            wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
            wrapped_dek: "{\"algorithm\":\"x25519_mlkem768_aes256_gcm_hkdf_sha256\"}".into(),
        });
        let sup =
            admit_replicated_key_grant(b.backend, sign_set_unstored(&a.signer, &superset).await)
                .await
                .unwrap_or_else(|e| panic!("{tag} I62: superset: {e}"));
        assert_eq!(
            sup.wraps_written, 1,
            "{tag} I62: exactly the late wrap is new"
        );
        let after: Vec<String> = b
            .backend
            .community_dek_member_grant_recipients(&comm, &a.key, 0)
            .await
            .unwrap();
        for prior in &before {
            assert!(
                after.contains(prior),
                "{tag} I62: {prior} was dropped by a superset"
            );
        }
        assert!(
            after.contains(&late),
            "{tag} I62: the late recipient was added"
        );

        // (4) A SUBSET later (a partial re-emission) removes nothing.
        let subset = KeyGrantSet {
            axis: superset.axis.clone(),
            wraps: vec![superset.wraps[0].clone()],
        };
        admit_replicated_key_grant(b.backend, sign_set_unstored(&a.signer, &subset).await)
            .await
            .unwrap();
        assert_eq!(
            b.backend
                .community_dek_member_grant_recipients(&comm, &a.key, 0)
                .await
                .unwrap(),
            after,
            "{tag} I62: a subset re-emission must remove NOTHING (CC 3: cannot un-share)"
        );

        // (5) Now the bytes arrive — and open.
        carry_bytes(
            a,
            b,
            &sha,
            COMMUNITY,
            &comm,
            Some(0),
            CryptoTier::CommunityDek,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            read_any_for_viewer(b.backend, &sha, &b.key, None)
                .await
                .unwrap(),
            b"v1",
            "{tag} I62: a set admitted before its bytes is read when they arrive"
        );
    }

    // ── I63 ──────────────────────────────────────────────────────────────
    /// **B admits A's revocation of X; B's next seal is under a new B-epoch;
    /// the old B-epoch is `disabled`; X is absent from B's new set.**
    pub async fn exercise_i63_rotation_on_admitted_removal<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let bob = format!("{tag}-bob-{run}");
        let xavier = format!("{tag}-xavier-{run}");
        // X has an occurrence on A's node (it is A's device that X uses);
        // what matters is X is on the roster and gets wrapped to.
        seed_community_everywhere(
            &[a, b],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&xavier, None)],
        )
        .await;
        // Give X an occurrence with keys on both nodes so B wraps to it.
        let x_occ = format!("{tag}-x-occ-{run}");
        for n in [a, b] {
            ts::register_hybrid_key_as(n.backend, &x_occ, &x_occ, USER).await;
            crate::federation::at_rest_cascade::blob_invariants::join_as_occurrence(
                n.backend, &xavier, &x_occ,
            )
            .await;
        }

        // B seals under (C, B, 0): X is granted.
        let first = encrypt_and_cascade_community(b.backend, &comm, b"before", None, Some(&b.key))
            .await
            .unwrap();
        assert_eq!(first.epoch, 0);
        assert!(
            first.granted.contains(&x_occ),
            "{tag} I63: X granted at B's e0"
        );
        let e0_minted = b
            .backend
            .community_dek_minted_at(&comm, &b.key, 0)
            .await
            .unwrap()
            .expect("minted_at recorded");

        // A revokes X (signed by the community key A holds); B ADMITS the
        // replicated revocation through its directory door — the only way a
        // removal reaches a non-revoker.
        let removed_at = chrono::Utc::now();
        assert!(
            removed_at >= e0_minted,
            "{tag} I63: the removal is newer than the mint"
        );
        let rev = ts::sign_community_membership_revocation(
            &comm,
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: comm.clone(),
                removed_identity_key_id: xavier.clone(),
                removed_at,
                effective_at: removed_at,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        a.backend
            .put_community_membership_revocation(rev.clone())
            .await
            .unwrap();
        b.backend
            .put_community_membership_revocation(rev)
            .await
            .unwrap_or_else(|e| panic!("{tag} I63: B admits A's revocation: {e}"));

        // B's next seal: a NEW B-epoch, the old one disabled, X absent.
        let second = encrypt_and_cascade_community(b.backend, &comm, b"after", None, Some(&b.key))
            .await
            .unwrap();
        assert!(
            second.epoch > first.epoch,
            "{tag} I63: B's next seal must be under a new B-epoch ({} -> {})",
            first.epoch,
            second.epoch
        );
        assert_eq!(
            b.backend
                .community_dek_key_state(&comm, &b.key, first.epoch)
                .await
                .unwrap(),
            Some(crate::federation::DekKeyState::Disabled),
            "{tag} I63: the old B-epoch is disabled"
        );
        assert!(
            !second.granted.contains(&x_occ),
            "{tag} I63: X is absent from B's new set: {:?}",
            second.granted
        );
        let new_set =
            crate::federation::key_grant::build_epoch_set(b.backend, &comm, &b.key, second.epoch)
                .await
                .unwrap()
                .expect("B holds wraps at the new epoch");
        assert!(
            new_set.wraps.iter().all(|w| w.recipient_key_id != x_occ),
            "{tag} I63: the new KeyGrant set carries no wrap for X"
        );
        // X keeps e0 (AV-70): forward-only.
        assert!(
            b.backend
                .community_dek_has_member_grant(&comm, &b.key, first.epoch, &x_occ)
                .await
                .unwrap(),
            "{tag} I63: X keeps its pre-rotation grant (AV-70)"
        );
    }

    // ── I64 ──────────────────────────────────────────────────────────────
    /// **Two minters at the same epoch number coexist**: B's viewer opens A's
    /// content at (C, A, 3) and C's content at (C, C, 3).
    pub async fn exercise_i64_two_minters_same_epoch<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        c: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let bob = format!("{tag}-bob-{run}");
        let carol = format!("{tag}-carol-{run}");
        seed_community_everywhere(
            &[a, b, c],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&carol, Some(c))],
        )
        .await;
        // Both A and C advance their OWN counters to 3.
        for n in [a, c] {
            for _ in 0..3 {
                n.backend
                    .community_dek_bump_epoch(&comm, &n.key)
                    .await
                    .unwrap();
            }
        }
        let from_a = encrypt_and_cascade_community(a.backend, &comm, b"from A", None, Some(&a.key))
            .await
            .unwrap();
        let from_c = encrypt_and_cascade_community(c.backend, &comm, b"from C", None, Some(&c.key))
            .await
            .unwrap();
        assert_eq!(
            (from_a.epoch, from_c.epoch),
            (3, 3),
            "{tag} I64: both at epoch 3"
        );
        assert_ne!(from_a.at_rest_sha256, from_c.at_rest_sha256);

        for (n, epoch_holder) in [(a, &from_a), (c, &from_c)] {
            let emitted = emit_epoch_key_grant_with_local_signer(n.backend, &n.signer, &comm, 3)
                .await
                .unwrap()
                .expect("wraps");
            carry_key_grant(n, b, &emitted.attestation_id)
                .await
                .unwrap_or_else(|e| panic!("{tag} I64: B admits {}'s set: {e}", n.key));
            carry_bytes(
                n,
                b,
                &epoch_holder.at_rest_sha256,
                COMMUNITY,
                &comm,
                Some(3),
                CryptoTier::CommunityDek,
                &[],
            )
            .await
            .unwrap();
        }
        // Two grants, two DEKs, one epoch number — both open on B.
        assert!(b
            .backend
            .community_dek_has_member_grant(&comm, &a.key, 3, &b.key)
            .await
            .unwrap());
        assert!(b
            .backend
            .community_dek_has_member_grant(&comm, &c.key, 3, &b.key)
            .await
            .unwrap());
        assert_eq!(
            read_any_for_viewer(b.backend, &from_a.at_rest_sha256, &b.key, None)
                .await
                .unwrap(),
            b"from A",
            "{tag} I64: A's content at (C, A, 3)"
        );
        assert_eq!(
            read_any_for_viewer(b.backend, &from_c.at_rest_sha256, &b.key, None)
                .await
                .unwrap(),
            b"from C",
            "{tag} I64: C's content at (C, C, 3)"
        );
        assert_eq!(
            b.backend
                .community_dek_blob_epoch(&from_a.at_rest_sha256)
                .await
                .unwrap(),
            Some((comm.clone(), a.key.clone(), 3))
        );
        assert_eq!(
            b.backend
                .community_dek_blob_epoch(&from_c.at_rest_sha256)
                .await
                .unwrap(),
            Some((comm.clone(), c.key.clone(), 3))
        );
    }

    // ── I65 ──────────────────────────────────────────────────────────────
    /// **Content axis**: the owner's second occurrence on B opens a self blob
    /// sealed on A once A's set is admitted on B.
    pub async fn exercise_i65_content_axis_second_device<B>(
        a: &Node<'_, B>,
        a2: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let owner = format!("{tag}-owner-{run}");
        // The owner's identity, with BOTH devices as active occurrences, on
        // both nodes' directories.
        for n in [a, a2] {
            ts::register_hybrid_key_as(n.backend, &owner, &owner, USER).await;
            for dev in [a, a2] {
                n.backend
                    .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                        identity_key_id: owner.clone(),
                        occurrence_key_id: dev.key.clone(),
                        device_class: crate::federation::types::device_class::SERVER.into(),
                        hardware_attestation: None,
                        asserted_at: chrono::Utc::now(),
                        valid_until: None,
                        encryption_pubkeys: Some(dev.kem.clone()),
                        transport_binding: None,
                        persist_row_hash: String::new(),
                    })
                    .await
                    .unwrap();
            }
        }
        // A seals a self blob: fresh DEK, wrapped to both devices.
        let sealed = encrypt_and_cascade(
            a.backend,
            SELF,
            &owner,
            b"my photo",
            None,
            None,
            Some(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I65: A seals self: {e}"));
        assert!(
            sealed.granted.contains(&a2.key),
            "{tag} I65: the second device is granted"
        );
        let sha = sealed.at_rest_sha256;
        // (1) A FORGED content set from the second device — a recipient who
        // knows the DEK — naming an outsider, delivered BEFORE the bytes.
        // The author is not yet known here, so the signer cannot be checked
        // against it: the carrier is stored, NOTHING is projected (§13,
        // PR #850 review) — and nothing ever will be, see (3).
        let outsider = format!("{tag}-outsider-{run}");
        let forged = KeyGrantSet {
            axis: KeyGrantAxis::Content {
                at_rest_sha256: hex::encode(sha),
                cohort_scope: SELF.into(),
                owner_key_id: owner.clone(),
            },
            wraps: vec![crate::federation::GrantWrap {
                recipient_key_id: outsider.clone(),
                wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
                wrapped_dek: "{}".into(),
            }],
        };
        let forged_admission =
            admit_replicated_key_grant(a2.backend, sign_set_unstored(&a2.signer, &forged).await)
                .await
                .unwrap_or_else(|e| panic!("{tag} I65: a set before its bytes is stored: {e}"));
        assert!(
            forged_admission.pending && forged_admission.wraps_written == 0,
            "{tag} I65: before the bytes, a content set projects NOTHING: {forged_admission:?}"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &outsider)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: the outsider has no grant row"
        );
        // (2) The AUTHOR's set, also before the bytes: pending, nothing yet.
        let emitted =
            emit_content_key_grant_with_local_signer(a.backend, &a.signer, &sha, SELF, &owner)
                .await
                .unwrap()
                .expect("wraps");
        let admission = carry_key_grant(a, a2, &emitted.attestation_id)
            .await
            .unwrap_or_else(|e| panic!("{tag} I65: the second device admits the set: {e}"));
        assert_eq!(
            match &admission.axis {
                KeyGrantAxis::Content { at_rest_sha256, .. } => at_rest_sha256.clone(),
                other => panic!("{other:?}"),
            },
            hex::encode(sha)
        );
        assert!(
            admission.pending && admission.wraps_written == 0,
            "{tag} I65: the author's set is pending until the bytes name the author: {admission:?}"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &a2.key)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: nothing projects before the author is known"
        );
        // The second device's operator names the first as family (#846 §4):
        // that is what makes it party to the owner's own content.
        carry_bytes(
            a,
            a2,
            &sha,
            SELF,
            &owner,
            None,
            CryptoTier::InvisibleEncrypted,
            std::slice::from_ref(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I65: the second device adopts: {e}"));
        // (3) The adopt named the author: the author's set projected, the
        // forged one did not and never will (order independence, kept).
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &a2.key)
                .await
                .unwrap()
                .is_some(),
            "{tag} I65: the second device's grant row landed with the bytes"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &outsider)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: a set the author did not sign never projects"
        );
        // (4) A re-delivered author set after the bytes projects directly —
        // the row is present, the author is checked, every wrap already held.
        let again = carry_key_grant(a, a2, &emitted.attestation_id)
            .await
            .unwrap_or_else(|e| panic!("{tag} I65: re-delivery: {e}"));
        assert!(
            !again.pending && again.wraps_written == 0,
            "{tag} I65: {again:?}"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, crate::federation::at_rest_cascade::PERSIST_SELF_RECIPIENT)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: no persist self-retention on the second device — the open comes from its grant"
        );
        assert_eq!(
            read_any_for_viewer(a2.backend, &sha, &a2.key, None)
                .await
                .unwrap_or_else(|e| panic!("{tag} I65: the second device opens: {e}")),
            b"my photo"
        );
        // Order independence on the content axis: a stranger stays refused.
        let err = read_any_for_viewer(a2.backend, &sha, &format!("{tag}-stranger-{run}"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I65: {err:?}"
        );
        let err = read_any_for_viewer(a2.backend, &sha, &outsider, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I65: the outsider the forged set named stays refused: {err:?}"
        );
    }

    /// **I60b — a set from a minter occurrence that is no longer active is
    /// refused, even one asserted before the revocation — and by the RIGHT
    /// gate.** The KeyGrant check folds membership at the row's
    /// `asserted_at` (consistent with the community-removal fold, §13): a set
    /// asserted while the occurrence was active passes it. The attestation
    /// plane's cohort gate then asks about the signer NOW and refuses — and
    /// that gate must stay at now: `asserted_at` is signer-chosen, so a
    /// revoked occurrence must never regain admission by back-dating. The
    /// two legs give different typed reasons, which is what makes the fold
    /// observable: early → the plane's own refusal (the fold passed); late →
    /// `signer_not_active_member` (the fold refused first).
    /// Ruled on PR #850's review.
    pub async fn exercise_i60b_delayed_set_survives_a_later_occurrence_revocation<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let bob = format!("{tag}-bob-{run}");
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;
        encrypt_and_cascade_community(a.backend, &comm, b"while active", None, Some(&a.key))
            .await
            .unwrap_or_else(|e| panic!("{tag} I60b: A seals: {e}"));
        let early = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("A holds wraps");
        let early_row = a
            .backend
            .get_attestation(&early.attestation_id)
            .await
            .unwrap()
            .expect("the early row");
        // B learns that A's occurrence was revoked AFTER the early set was
        // asserted (and before now).
        b.backend
            .put_identity_occurrence_revocation_local(
                crate::federation::types::IdentityOccurrenceRevocation {
                    identity_key_id: alice.clone(),
                    occurrence_key_id: a.key.clone(),
                    revoked_at: chrono::Utc::now(),
                    effective_at: early_row.asserted_at + chrono::Duration::milliseconds(1),
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I60b: B records the revocation: {e}"));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let err = carry_key_grant(a, b, &early.attestation_id)
            .await
            .expect_err("{tag} I60b: the plane's cohort gate refuses a revoked occurrence");
        // The plane's write-path gate propagates as its own error, not as a
        // typed KeyGrant refusal: the fold at `asserted_at` PASSED, and the
        // refusal names the plane's membership gate.
        assert!(
            !matches!(err, Error::KeyGrantRefused { .. }),
            "{tag} I60b: the fold at asserted_at must pass a set asserted while active: {err}"
        );
        assert!(
            err.to_string().contains("not a member"),
            "{tag} I60b: the plane's cohort gate (at now) is what refuses: {err}"
        );
        assert!(
            !b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I60b: nothing projected"
        );
        // The same minter, speaking AFTER the revocation: the fold itself
        // refuses, before the plane is asked.
        let late = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("A still holds wraps");
        assert_ne!(late.attestation_id, early.attestation_id);
        let err = carry_key_grant(a, b, &late.attestation_id)
            .await
            .expect_err("{tag} I60b: a set asserted after the revocation is refused");
        assert_eq!(
            refusal_reason(&err),
            "signer_not_active_member",
            "{tag} I60b: {err}"
        );
    }
}

#[cfg(test)]
mod tests {
    // ── I59 ──────────────────────────────────────────────────────────────
    /// `KeyGrant` is the sixteenth kind with a policy row exactly as §12
    /// states; the manifest witness holds (`replication_policy_hash_is_pinned`
    /// beside it); the wire table documents it.
    #[test]
    fn i59_key_grant_is_the_sixteenth_kind_with_the_stated_policy_row() {
        use crate::federation::replication_policy::*;
        assert_eq!(EnvelopeKind::ALL.len(), 16);
        assert_eq!(
            EnvelopeKind::ALL[15],
            EnvelopeKind::KeyGrant,
            "appended, never inserted"
        );
        assert_eq!(EnvelopeKind::KeyGrant.as_str(), "KeyGrant");
        let p = policy_for(EnvelopeKind::KeyGrant);
        assert_eq!(p.signer, SignerSource::RegisteredSigner);
        assert_eq!(p.binding, SignerBinding::SelfOwn);
        assert_eq!(p.pop_on_insert, PopOnInsert::NotApplicable);
        assert_eq!(p.tier, WireTier::FederationOnly);
        assert_eq!(p.projections, &[Projection::KeyGrants]);
        assert_eq!(
            replication_policy_sha256(),
            REPLICATION_POLICY_HASH,
            "the re-pin must be deliberate and recorded"
        );
        assert_eq!(
            REPLICATION_POLICY_HASH,
            "c1082c12db13b6d0f2240b910da2c0008a85b363df4f9b9b73a013ab28cb389d"
        );
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("WIRE_VOCABULARY_KINDS.md"),
        )
        .expect("WIRE_VOCABULARY_KINDS.md");
        assert!(
            doc.contains("KeyGrant") && doc.contains("key_grant:epoch:v1"),
            "I59: the wire table must document the sixteenth kind and its row types"
        );
    }

    // ── I67 ──────────────────────────────────────────────────────────────
    /// No production path removes a grant within an epoch: the only `DELETE`
    /// on the member-grant table is the epoch destroy, and the only deletes
    /// on the at-rest grant table ride blob deletion (the row goes with the
    /// blob it grants).
    #[test]
    fn i67_no_production_delete_on_the_grant_tables_outside_destroy() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for (file, table) in [
            (
                "src/store/sqlite.rs",
                "federation_community_dek_member_grants",
            ),
            (
                "src/store/postgres.rs",
                "cirislens.federation_community_dek_member_grants",
            ),
        ] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            let prod = production_only(&text);
            let needle = format!("DELETE FROM {table}");
            let sites: Vec<usize> = prod.match_indices(&needle).map(|(i, _)| i).collect();
            assert_eq!(
                sites.len(),
                1,
                "I67: {file} must delete member grants in exactly ONE place (destroy), found {}",
                sites.len()
            );
            let fn_name = enclosing_fn(&prod, sites[0]);
            assert_eq!(
                fn_name, "community_dek_set_key_state",
                "I67: {file}: the one member-grant DELETE must be the destroy path"
            );
        }
        for (file, table) in [
            ("src/store/sqlite.rs", "federation_blob_key_grants"),
            (
                "src/store/postgres.rs",
                "cirislens.federation_blob_key_grants",
            ),
        ] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            let prod = production_only(&text);
            let needle = format!("DELETE FROM {table}");
            let fns: std::collections::BTreeSet<String> = prod
                .match_indices(&needle)
                .map(|(i, _)| enclosing_fn(&prod, i))
                .collect();
            let allowed: std::collections::BTreeSet<String> =
                ["delete_blob", "community_dek_evict_epoch_objects"]
                    .into_iter()
                    .map(String::from)
                    .collect();
            assert!(
                fns.is_subset(&allowed),
                "I67: {file}: at-rest grant deletes may ride only blob deletion, found in {fns:?}"
            );
        }
        // And no cascade / door module un-grants through a floor: there is
        // no such floor.
        let blobs = std::fs::read_to_string(root.join("src/federation/blobs.rs")).unwrap();
        assert!(
            !blobs.contains("fn community_dek_remove_member_grant")
                && !blobs.contains("fn remove_at_rest_grant")
                && !blobs.contains("fn community_dek_delete_member_grant"),
            "I67: the trait must offer no un-grant floor"
        );
    }

    /// Strip `#[cfg(test)] mod` regions from a source file.
    /// The body of `fn NAME(` in `text`, up to the next method at the same
    /// indentation (its doc comment included, which is harmless).
    fn method_body<'t>(text: &'t str, name: &str) -> &'t str {
        let start = text
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("{name} is defined"));
        let rest = &text[start + 1..];
        let end = [
            "\n    pub async fn ",
            "\n    pub fn ",
            "\n    async fn ",
            "\n    fn ",
            "\n}\n",
        ]
        .iter()
        .filter_map(|m| rest.find(m))
        .min()
        .map(|i| start + 1 + i)
        .unwrap_or(text.len());
        &text[start..end]
    }

    /// **I69 (from disk) — every Python write door emits** (PR #850
    /// review: the two specialized doors did not). Each `#[pymethods]` door
    /// calls the one emission helper.
    #[test]
    fn i69_every_python_write_door_emits_the_key_grant_set() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(root.join("src/ffi/pyo3.rs")).unwrap();
        let prod = production_only(&text);
        for door in [
            "put_blob_scoped",
            "put_blob_encrypted_community",
            "put_blob_encrypted_self_family",
            "put_blob_chunk_scoped",
            "seal_stream_scoped",
        ] {
            assert!(
                method_body(&prod, door).contains("emit_key_grant_axis_async"),
                "I69: PyEngine::{door} must emit the KeyGrant set after its cascade (§14)"
            );
        }
    }

    /// **I66e (from disk) — every DEK-plane door of the Engine resolves the
    /// sentinel first**, so an `Engine` built by `from_shared*` (which cannot
    /// repair synchronously) is repaired at its first such door. And **I68's
    /// carrier**: both retroactive-ADD doors consume `changed_blobs`.
    #[test]
    fn i66e_every_dek_plane_door_resolves_the_sentinel_first() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(root.join("src/engine.rs")).unwrap();
        let prod = production_only(&text);
        for door in [
            "put_blob_scoped",
            "put_blob_encrypted_community",
            "put_blob_encrypted_self_family",
            "put_blob_chunk_scoped",
            "seal_stream_scoped",
            "read_blob_as",
            "read_blob_range_as",
            "read_stream_chunk_as",
            "read_blob_for_community_viewer",
            "adopt_sealed_blob",
            "adopt_sealed_chunk",
            "apply_replicated_key_grant",
            "emit_key_grant",
            "community_dek_set_key_state",
            "community_dek_set_retain_past_epochs",
            "rekey_community_member_revoke",
        ] {
            assert!(
                method_body(&prod, door).contains("ensure_minter_sentinels_resolved()"),
                "I66e: Engine::{door} must resolve V145's sentinel before touching the DEK plane"
            );
        }
        for door in ["rekey_family_member_add", "rekey_self_occurrence_add"] {
            let body = method_body(&prod, door);
            assert!(
                body.contains("changed_blobs") && body.contains("emit_key_grant("),
                "I68: Engine::{door} must emit each changed blob's content set (§14)"
            );
        }
    }

    fn production_only(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut depth = 0i32;
        let mut in_tests = false;
        for line in text.lines() {
            if !in_tests && line.trim_start().starts_with("#[cfg(test)]") {
                in_tests = true;
                depth = 0;
                continue;
            }
            if in_tests {
                depth += line.matches('{').count() as i32;
                depth -= line.matches('}').count() as i32;
                if depth <= 0 && line.contains('}') {
                    in_tests = false;
                }
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// The name of the `fn` whose body contains byte offset `at`.
    fn enclosing_fn(text: &str, at: usize) -> String {
        let head = &text[..at];
        let idx = head.rfind("fn ").expect("a fn precedes the site");
        let rest = &head[idx + 3..];
        rest.split(|c: char| c == '(' || c == '<' || c.is_whitespace())
            .next()
            .unwrap_or("")
            .to_owned()
    }

    // ── I66 ──────────────────────────────────────────────────────────────
    /// A pre-V145 database resolves every `__this_node__` sentinel to the
    /// node's own key at boot, its existing content still opens, and a
    /// sentinel that survives aborts the boot.
    #[cfg(feature = "sqlite")]
    mod i66_sqlite {
        use crate::federation::at_rest_cascade::{
            fresh_dek, seal, wrap_dek_for_persist, WRAP_ALGORITHM_V2,
        };
        use crate::federation::community_dek::orchestrate::read_for_community_viewer;
        use crate::federation::BlobStorage;
        use crate::store::sqlite::SqliteBackend;
        use crate::store::Backend as _;
        use sha2::Digest as _;

        /// Seed the V144 shape: a sealed community blob, its epoch pointer,
        /// self-retention, one member grant, and its binding — exactly the
        /// rows a v44.2.x node holds. Returns the sha and the plaintext.
        async fn seed_pre_v145(backend: &SqliteBackend) -> [u8; 32] {
            let master = backend.load_or_init_content_master().await.unwrap();
            let dek = fresh_dek().unwrap();
            let wrapped = wrap_dek_for_persist(&master, &dek).unwrap();
            let envelope = seal(&dek, b"pre-V145 minutes", None).unwrap().to_bytes();
            let sha: [u8; 32] = sha2::Sha256::digest(&envelope).into();
            let conn = backend.conn_handle();
            let conn = conn.lock();
            conn.execute(
                "INSERT INTO federation_blobs (sha256, storage_kind, bytes_inline, size_bytes, \
                    cohort_scope, crypto_tier, author_key_id) \
                 VALUES (?1, 'inline', ?2, ?3, 'community', 'community_dek', NULL)",
                rusqlite::params![sha.to_vec(), envelope, envelope.len() as i64],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO federation_community_dek_epoch (community_key_id, epoch) VALUES ('legacy-comm', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO federation_community_dek (community_key_id, epoch, wrap_algorithm, wrapped_dek) \
                 VALUES ('legacy-comm', 1, 'aes256_gcm_content_master', ?1)",
                rusqlite::params![wrapped],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO federation_community_dek_member_grants \
                    (community_key_id, epoch, member_key_id, wrap_algorithm, wrapped_dek) \
                 VALUES ('legacy-comm', 1, 'viewer-occ', ?1, '{}')",
                rusqlite::params![WRAP_ALGORITHM_V2],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO federation_community_blob_epoch (at_rest_sha256, community_key_id, epoch) \
                 VALUES (?1, 'legacy-comm', 1)",
                rusqlite::params![sha.to_vec()],
            )
            .unwrap();
            sha
        }

        fn sentinel_rows(backend: &SqliteBackend) -> i64 {
            let conn = backend.conn_handle();
            let conn = conn.lock();
            conn.query_row(
                "SELECT (SELECT COUNT(*) FROM federation_community_dek_epoch WHERE minter_key_id = '__this_node__') \
                      + (SELECT COUNT(*) FROM federation_community_dek WHERE minter_key_id = '__this_node__') \
                      + (SELECT COUNT(*) FROM federation_community_dek_member_grants WHERE minter_key_id = '__this_node__') \
                      + (SELECT COUNT(*) FROM federation_community_blob_epoch WHERE minter_key_id = '__this_node__')",
                [],
                |r| r.get(0),
            )
            .unwrap()
        }

        #[tokio::test]
        async fn i66_pre_v145_rows_resolve_to_the_node_and_still_open_sqlite() {
            let backend = SqliteBackend::open_in_memory().await.unwrap();
            backend.run_migrations_through(144).await.unwrap();
            let sha = seed_pre_v145(&backend).await;
            backend.run_migrations().await.unwrap();
            assert_eq!(
                sentinel_rows(&backend),
                4,
                "I66: V145 wrote the sentinel on every re-keyed row (SQL cannot know the node)"
            );
            let n = backend
                .repair_minter_sentinel(Some("node-x"))
                .await
                .unwrap();
            assert_eq!(n, 4, "I66: every sentinel resolved");
            assert_eq!(sentinel_rows(&backend), 0);
            assert_eq!(
                backend
                    .community_dek_current_epoch("legacy-comm", "node-x")
                    .await
                    .unwrap(),
                1,
                "I66: the pointer is this node's"
            );
            assert!(backend
                .community_dek_get_self_retention("legacy-comm", "node-x", 1)
                .await
                .unwrap()
                .is_some());
            assert!(backend
                .community_dek_has_member_grant("legacy-comm", "node-x", 1, "viewer-occ")
                .await
                .unwrap());
            assert_eq!(
                backend.community_dek_blob_epoch(&sha).await.unwrap(),
                Some(("legacy-comm".into(), "node-x".into(), 1)),
                "I66: the binding's minter is this node (the row had no author)"
            );
            assert_eq!(
                read_for_community_viewer(&backend, &sha, "viewer-occ")
                    .await
                    .expect("I66: existing content still opens"),
                b"pre-V145 minutes"
            );
            // Idempotent.
            assert_eq!(
                backend
                    .repair_minter_sentinel(Some("node-x"))
                    .await
                    .unwrap(),
                0
            );
            // A sentinel that cannot resolve — the resolved row already
            // exists — aborts, and the sentinel is not silently left behind.
            {
                let conn = backend.conn_handle();
                let conn = conn.lock();
                conn.execute(
                    "INSERT INTO federation_community_dek \
                        (community_key_id, minter_key_id, epoch, wrap_algorithm, wrapped_dek) \
                     VALUES ('legacy-comm', '__this_node__', 1, 'aes256_gcm_content_master', 'x')",
                    [],
                )
                .unwrap();
            }
            let err = backend
                .repair_minter_sentinel(Some("node-x"))
                .await
                .expect_err("I66: a sentinel that survives must abort the boot");
            assert!(
                err.to_string().contains("minter-sentinel"),
                "I66: the abort names the sentinel resolution: {err}"
            );
            // And a node that cannot name itself resolves nothing but still
            // refuses to boot over a sentinel — never fail-open.
            let err = backend
                .repair_minter_sentinel(None)
                .await
                .expect_err("I66: no key to resolve to must not mean the sentinel is ignored");
            assert!(
                err.to_string().contains("None = no Ed25519 identity"),
                "{err}"
            );
        }

        /// The boot path itself: `Engine::with_signer` on a pre-V145 file
        /// runs V145 and resolves the sentinel to the engine's derived key
        /// before it returns.
        #[tokio::test]
        async fn i66_engine_boot_resolves_the_sentinel_sqlite() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pre-v145.db");
            {
                let backend = SqliteBackend::open(path.to_string_lossy().to_string())
                    .await
                    .unwrap();
                backend.run_migrations_through(144).await.unwrap();
                seed_pre_v145(&backend).await;
            }
            let signer = crate::federation::tier_ingest::test_support::local_signer("i66-node");
            let key = signer.derived_key_id();
            let engine = crate::Engine::with_signer_pre_genesis(
                signer,
                &format!("sqlite:///{}", path.display()),
            )
            .await
            .expect("I66: the boot resolves the sentinel and succeeds");
            let sq = engine.sqlite_backend().unwrap();
            assert_eq!(sentinel_rows(sq), 0, "I66: no sentinel survives the boot");
            assert_eq!(
                sq.community_dek_current_epoch("legacy-comm", &key)
                    .await
                    .unwrap(),
                1,
                "I66: the pointer belongs to the engine's own derived key"
            );
            assert!(sq
                .community_dek_get_self_retention("legacy-comm", &key, 1)
                .await
                .unwrap()
                .is_some());
        }
        /// **I66d — an `Engine` over a SHARED backend resolves the sentinel
        /// at its first DEK-plane door** (PR #850 review). `from_shared*` are
        /// synchronous and cannot repair; the first door does, and a
        /// survivor fails THAT door rather than leaving bindings unreadable.
        #[tokio::test]
        async fn i66_from_shared_resolves_the_sentinel_at_the_first_door_sqlite() {
            use std::sync::Arc;
            let dir = tempfile::tempdir().unwrap();
            for survivor in [false, true] {
                let path = dir.path().join(format!("shared-{survivor}.db"));
                let sha = {
                    let backend = SqliteBackend::open(path.to_string_lossy().to_string())
                        .await
                        .unwrap();
                    backend.run_migrations_through(144).await.unwrap();
                    seed_pre_v145(&backend).await
                };
                let backend = SqliteBackend::open(path.to_string_lossy().to_string())
                    .await
                    .unwrap();
                backend.run_migrations().await.unwrap();
                assert_eq!(sentinel_rows(&backend), 4, "I66d: V145 wrote the sentinel");
                let local = crate::federation::tier_ingest::test_support::local_signer(&format!(
                    "i66d-{survivor}"
                ));
                let key = local.derived_key_id();
                if survivor {
                    // The resolved row already exists: the sentinel cannot
                    // resolve onto it.
                    let conn = backend.conn_handle();
                    let conn = conn.lock();
                    conn.execute(
                        "INSERT INTO federation_community_dek \
                            (community_key_id, minter_key_id, epoch, wrap_algorithm, wrapped_dek) \
                         VALUES ('legacy-comm', ?1, 1, 'aes256_gcm_content_master', 'x')",
                        rusqlite::params![key],
                    )
                    .unwrap();
                }
                let backend = Arc::new(backend);
                let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
                    crate::signing::LocalSignerHardwareAdapter::new(local.clone()),
                );
                let engine = crate::Engine::from_shared_with_local(
                    crate::engine::BackendDispatch::Sqlite(backend.clone()),
                    signer,
                    Some(local),
                );
                assert_eq!(
                    sentinel_rows(&backend),
                    4,
                    "I66d: a synchronous constructor resolves nothing"
                );
                let read = engine
                    .read_blob_for_community_viewer(&sha, "viewer-occ")
                    .await;
                if survivor {
                    let err = read.expect_err("I66d: a survivor fails the first door");
                    assert!(
                        err.to_string().contains("minter-sentinel"),
                        "I66d: the failure names the sentinel resolution: {err}"
                    );
                } else {
                    assert_eq!(
                        read.expect("I66d: the first door resolved and read"),
                        b"pre-V145 minutes"
                    );
                    assert_eq!(
                        sentinel_rows(&backend),
                        0,
                        "I66d: resolved at the first door"
                    );
                    assert_eq!(
                        backend.community_dek_blob_epoch(&sha).await.unwrap(),
                        Some(("legacy-comm".into(), key.clone(), 1)),
                        "I66d: the binding's minter is the shared engine's own key"
                    );
                }
            }
        }
    }

    #[cfg(feature = "postgres")]
    mod i66_postgres {
        use crate::federation::at_rest_cascade::{
            fresh_dek, seal, wrap_dek_for_persist, WRAP_ALGORITHM_V2,
        };
        use crate::federation::community_dek::orchestrate::read_for_community_viewer;
        use crate::federation::BlobStorage;
        use crate::store::postgres::PostgresBackend;
        use crate::store::Backend as _;
        use sha2::Digest as _;

        async fn count(b: &PostgresBackend) -> i64 {
            let client = b.get_client().await.unwrap();
            let row = client
                .query_one(
                    "SELECT ((SELECT COUNT(*) FROM cirislens.federation_community_dek_epoch WHERE minter_key_id = '__this_node__') \
                           + (SELECT COUNT(*) FROM cirislens.federation_community_dek WHERE minter_key_id = '__this_node__') \
                           + (SELECT COUNT(*) FROM cirislens.federation_community_dek_member_grants WHERE minter_key_id = '__this_node__') \
                           + (SELECT COUNT(*) FROM cirislens.federation_community_blob_epoch WHERE minter_key_id = '__this_node__'))::bigint AS n",
                    &[],
                )
                .await
                .unwrap();
            row.get::<_, i64>("n")
        }

        #[tokio::test]
        async fn i66_pre_v145_rows_resolve_to_the_node_and_still_open_postgres() {
            let Some(dsn) = crate::test_pg::empty_dsn() else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let backend = PostgresBackend::connect(&dsn).await.unwrap();
            backend.run_migrations_through(144).await.unwrap();
            let master = backend.load_or_init_content_master().await.unwrap();
            let dek = fresh_dek().unwrap();
            let wrapped = wrap_dek_for_persist(&master, &dek).unwrap();
            let envelope = seal(&dek, b"pre-V145 minutes (pg)", None)
                .unwrap()
                .to_bytes();
            let sha: [u8; 32] = sha2::Sha256::digest(&envelope).into();
            {
                let client = backend.get_client().await.unwrap();
                client
                    .execute(
                        "INSERT INTO cirislens.federation_blobs (sha256, storage_kind, bytes_inline, \
                            size_bytes, cohort_scope, crypto_tier) \
                         VALUES ($1, 'inline', $2, $3, 'community', 'community_dek')",
                        &[
                            &sha.to_vec() as &(dyn tokio_postgres::types::ToSql + Sync),
                            &envelope,
                            &(envelope.len() as i64),
                        ],
                    )
                    .await
                    .unwrap();
                client
                    .execute(
                        "INSERT INTO cirislens.federation_community_dek_epoch (community_key_id, epoch) \
                         VALUES ('legacy-comm', 1)",
                        &[],
                    )
                    .await
                    .unwrap();
                client
                    .execute(
                        "INSERT INTO cirislens.federation_community_dek \
                            (community_key_id, epoch, wrap_algorithm, wrapped_dek) \
                         VALUES ('legacy-comm', 1, 'aes256_gcm_content_master', $1)",
                        &[&wrapped],
                    )
                    .await
                    .unwrap();
                client
                    .execute(
                        "INSERT INTO cirislens.federation_community_dek_member_grants \
                            (community_key_id, epoch, member_key_id, wrap_algorithm, wrapped_dek) \
                         VALUES ('legacy-comm', 1, 'viewer-occ', $1, '{}')",
                        &[&WRAP_ALGORITHM_V2],
                    )
                    .await
                    .unwrap();
                client
                    .execute(
                        "INSERT INTO cirislens.federation_community_blob_epoch \
                            (at_rest_sha256, community_key_id, epoch) VALUES ($1, 'legacy-comm', 1)",
                        &[&sha.to_vec()],
                    )
                    .await
                    .unwrap();
            }
            backend.run_migrations().await.unwrap();
            assert_eq!(
                count(&backend).await,
                4,
                "I66 (pg): the sentinel on every re-keyed row"
            );
            let n = backend
                .repair_minter_sentinel(Some("node-x"))
                .await
                .unwrap();
            assert_eq!(n, 4);
            assert_eq!(count(&backend).await, 0);
            assert_eq!(
                backend
                    .community_dek_current_epoch("legacy-comm", "node-x")
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                backend.community_dek_blob_epoch(&sha).await.unwrap(),
                Some(("legacy-comm".into(), "node-x".into(), 1))
            );
            assert_eq!(
                read_for_community_viewer(&backend, &sha, "viewer-occ")
                    .await
                    .expect("I66 (pg): existing content still opens"),
                b"pre-V145 minutes (pg)"
            );
            assert_eq!(
                backend
                    .repair_minter_sentinel(Some("node-x"))
                    .await
                    .unwrap(),
                0
            );
            {
                let client = backend.get_client().await.unwrap();
                client
                    .execute(
                        "INSERT INTO cirislens.federation_community_dek \
                            (community_key_id, minter_key_id, epoch, wrap_algorithm, wrapped_dek) \
                         VALUES ('legacy-comm', '__this_node__', 1, 'aes256_gcm_content_master', 'x')",
                        &[],
                    )
                    .await
                    .unwrap();
            }
            let err = backend
                .repair_minter_sentinel(Some("node-x"))
                .await
                .expect_err("I66 (pg): a sentinel that survives must abort the boot");
            assert!(err.to_string().contains("minter-sentinel"), "{err}");
        }
    }

    #[cfg(feature = "sqlite")]
    mod sqlite {
        use super::super::two_node::*;
        use crate::store::sqlite::SqliteBackend;
        use crate::store::Backend as _;

        async fn fresh() -> SqliteBackend {
            let b = SqliteBackend::open_in_memory().await.unwrap();
            b.run_migrations().await.unwrap();
            b
        }

        #[tokio::test]
        async fn i60_forged_set_refused_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i60-a").await;
            let b = node(&bb, "i60-b").await;
            introduce(&[&a, &b], &["i60-a", "i60-b"]).await;
            exercise_i60_forged_set_refused(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i60b_delayed_set_survives_a_later_occurrence_revocation_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i60b-a").await;
            let b = node(&bb, "i60b-b").await;
            introduce(&[&a, &b], &["i60b-a", "i60b-b"]).await;
            exercise_i60b_delayed_set_survives_a_later_occurrence_revocation(&a, &b, "sqlite")
                .await;
        }

        #[tokio::test]
        async fn i61_end_to_end_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i61-a").await;
            let b = node(&bb, "i61-b").await;
            introduce(&[&a, &b], &["i61-a", "i61-b"]).await;
            exercise_i61_end_to_end(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i62_union_order_independent_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i62-a").await;
            let b = node(&bb, "i62-b").await;
            introduce(&[&a, &b], &["i62-a", "i62-b"]).await;
            exercise_i62_union_order_independent(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i63_rotation_on_admitted_removal_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i63-a").await;
            let b = node(&bb, "i63-b").await;
            introduce(&[&a, &b], &["i63-a", "i63-b"]).await;
            exercise_i63_rotation_on_admitted_removal(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i64_two_minters_same_epoch_sqlite() {
            let (ba, bb, bc) = (fresh().await, fresh().await, fresh().await);
            let a = node(&ba, "i64-a").await;
            let b = node(&bb, "i64-b").await;
            let c = node(&bc, "i64-c").await;
            introduce(&[&a, &b, &c], &["i64-a", "i64-b", "i64-c"]).await;
            exercise_i64_two_minters_same_epoch(&a, &b, &c, "sqlite").await;
        }

        #[tokio::test]
        async fn i65_content_axis_second_device_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i65-a").await;
            let a2 = node(&bb, "i65-a2").await;
            introduce(&[&a, &a2], &["i65-a", "i65-a2"]).await;
            exercise_i65_content_axis_second_device(&a, &a2, "sqlite").await;
        }

        /// **I68 — a retroactive ADD emits each changed blob's content set**
        /// (PR #850 review). `rekey_self_occurrence_add` writes new per-blob
        /// wraps for a newcomer device; the Engine door emits the FULL
        /// content-axis set for every blob it changed, so the newcomer's
        /// remote node receives the key for historical bytes through the
        /// same path a fresh write uses. Idempotent: a second walk changes
        /// nothing and emits nothing.
        #[tokio::test]
        async fn i68_rekey_for_a_newcomer_emits_each_changed_blobs_content_set_sqlite() {
            use crate::federation::key_grant::{
                KeyGrantAxis, KeyGrantSet, KEY_GRANT_CONTENT_ATTESTATION_TYPE,
            };
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::cohort_scope::SELF;
            use crate::federation::types::identity_type::USER;
            use crate::federation::{BlobStorage, EncryptionPubkeys, FederationDirectory};
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i68-node-{run}");
            let engine =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            engine
                .register_self_federation_key(USER, &alias, None, serde_json::json!({}), vec![])
                .await
                .unwrap();
            let sq = engine.sqlite_backend().unwrap().clone();
            let me = engine.local_derived_key_id().await.unwrap();
            let kem =
                |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
                    x25519_base64: id.x25519_pubkey_b64,
                    ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
                };
            let owner = format!("i68-owner-{run}");
            ts::register_hybrid_key_as(sq.as_ref(), &owner, &owner, USER).await;
            let occurrence =
                |occ: &str, pk: EncryptionPubkeys| crate::federation::types::IdentityOccurrence {
                    identity_key_id: owner.clone(),
                    occurrence_key_id: occ.to_owned(),
                    device_class: crate::federation::types::device_class::SERVER.into(),
                    hardware_attestation: None,
                    asserted_at: chrono::Utc::now(),
                    valid_until: None,
                    encryption_pubkeys: Some(pk),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                };
            sq.put_identity_occurrence_local(occurrence(
                &me,
                kem(sq.load_or_init_content_kem_identity().await.unwrap()),
            ))
            .await
            .unwrap();
            let r = engine
                .put_blob_encrypted_self_family(SELF, &owner, b"photo", None)
                .await
                .expect("I68: the owner's first device seals");
            let sha = r.at_rest_sha256;
            let sets_for = |sq: std::sync::Arc<SqliteBackend>, me: String| async move {
                let mut out: Vec<KeyGrantSet> = Vec::new();
                for row in sq.list_attestations_by(&me).await.unwrap() {
                    if row.attestation_type != KEY_GRANT_CONTENT_ATTESTATION_TYPE {
                        continue;
                    }
                    let set = KeyGrantSet::from_attestation(&row).unwrap();
                    if matches!(&set.axis, KeyGrantAxis::Content { at_rest_sha256, .. } if *at_rest_sha256 == hex::encode(sha))
                    {
                        out.push(set);
                    }
                }
                out
            };
            let before = sets_for(sq.clone(), me.clone()).await;
            assert_eq!(before.len(), 1, "I68: the write emitted one content set");
            // A NEW device of the owner, with its own content-KEM identity.
            let other = fresh().await;
            let dev2 = format!("i68-dev2-{run}");
            ts::register_hybrid_key_as(sq.as_ref(), &dev2, &dev2, USER).await;
            sq.put_identity_occurrence_local(occurrence(
                &dev2,
                kem(other.load_or_init_content_kem_identity().await.unwrap()),
            ))
            .await
            .unwrap();
            let rk = engine
                .rekey_self_occurrence_add(&owner, std::slice::from_ref(&dev2))
                .await
                .expect("I68: the retroactive add");
            assert_eq!(
                rk.changed_blobs,
                vec![sha],
                "I68: the walk names the blob it changed"
            );
            assert!(sq.get_at_rest_grant(&sha, &dev2).await.unwrap().is_some());
            let after = sets_for(sq.clone(), me.clone()).await;
            assert_eq!(
                after.len(),
                2,
                "I68: the rekey emitted the blob's content set"
            );
            assert!(
                after
                    .iter()
                    .any(|s| s.wraps.iter().any(|w| w.recipient_key_id == dev2)
                        && s.wraps.iter().any(|w| w.recipient_key_id == me)),
                "I68: the emitted set is the FULL set — the new device AND the first"
            );
            // Idempotent: nothing changed, nothing emitted.
            let rk2 = engine
                .rekey_self_occurrence_add(&owner, std::slice::from_ref(&dev2))
                .await
                .unwrap();
            assert!(rk2.changed_blobs.is_empty(), "I68: {rk2:?}");
            assert_eq!(sets_for(sq.clone(), me.clone()).await.len(), 2);
        }

        /// I61 through the CONSUMER-HELD doors: two `Engine`s, each its own
        /// in-memory sqlite. `put_blob_scoped` on A emits the set through
        /// `emit_attestation_self`; B admits it through
        /// `Engine::apply_replicated_key_grant`, adopts the bytes through
        /// `Engine::adopt_sealed_blob`, and opens them through
        /// `Engine::read_blob_as`. `Engine::emit_key_grant` re-emits on demand.
        #[tokio::test]
        async fn i61_end_to_end_through_the_engine_doors_sqlite() {
            use crate::federation::key_grant::{KeyGrantAxis, SignedKeyGrantSet};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
            use crate::federation::types::identity_type::USER;
            use crate::federation::{
                AdoptDisposition, BlobBody, BlobProvenance, BlobStorage, EncryptionPubkeys,
                FederationDirectory,
            };
            let run = uuid::Uuid::new_v4().simple().to_string();
            let (alias_a, alias_b) = (format!("eng-a-{run}"), format!("eng-b-{run}"));
            let engine_a = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&alias_a),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            let engine_b = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&alias_b),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            for (e, alias) in [(&engine_a, &alias_a), (&engine_b, &alias_b)] {
                e.register_self_federation_key(USER, alias, None, serde_json::json!({}), vec![])
                    .await
                    .expect("register the engine's own key");
            }
            let (sa, sb) = (
                engine_a.sqlite_backend().unwrap().clone(),
                engine_b.sqlite_backend().unwrap().clone(),
            );
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
            introduce(&[&a, &b], &[&alias_a, &alias_b]).await;
            let comm = format!("eng-comm-{run}");
            let (alice, bob) = (format!("eng-alice-{run}"), format!("eng-bob-{run}"));
            seed_community_everywhere(&[&a, &b], &comm, &[(&alice, Some(&a)), (&bob, Some(&b))])
                .await;

            // A writes through THE door; the set is emitted by the door.
            let r = engine_a
                .put_blob_scoped(COMMUNITY, Some(&comm), b"engine minutes", None, None)
                .await
                .expect("A's scoped put");
            assert_eq!(r.tier, CryptoTier::CommunityDek);
            assert!(
                r.key_grant_emission.is_some(),
                "the first seal minted: a set was reported"
            );
            let sha = r.at_rest_sha256;
            let emitted: Vec<_> = sa
                .list_attestations_by(&a.key)
                .await
                .unwrap()
                .into_iter()
                .filter(|x| {
                    x.attestation_type
                        == crate::federation::key_grant::KEY_GRANT_EPOCH_ATTESTATION_TYPE
                })
                .collect();
            assert_eq!(
                emitted.len(),
                1,
                "exactly one epoch-axis set emitted by the door"
            );

            // B admits through the Engine door, adopts through the Engine door.
            let admission = engine_b
                .apply_replicated_key_grant(SignedKeyGrantSet {
                    attestation: emitted[0].clone(),
                })
                .await
                .expect("B admits A's set through the Engine door");
            assert!(admission.wraps_written >= 1);
            let Some(BlobBody::Inline(bytes)) = sa.get_blob(&sha).await.unwrap() else {
                panic!("inline")
            };
            engine_b
                .adopt_sealed_blob(
                    &bytes,
                    BlobProvenance {
                        author_key_id: a.key.clone(),
                        cohort_scope: COMMUNITY.into(),
                        community_key_id: Some(comm.clone()),
                        epoch: Some(0),
                        tier: CryptoTier::CommunityDek,
                    },
                    None,
                    AdoptDisposition::LocalOnly,
                )
                .await
                .expect("B adopts through the Engine door");
            assert_eq!(
                engine_b
                    .read_blob_as(&sha, &b.key, None)
                    .await
                    .expect("B reads through the Engine door"),
                b"engine minutes"
            );
            // Re-emission on demand carries the full set again (idempotent).
            let again = engine_a
                .emit_key_grant(&KeyGrantAxis::Epoch {
                    community_key_id: comm.clone(),
                    minter_key_id: a.key.clone(),
                    epoch: 0,
                })
                .await
                .expect("re-emit");
            assert!(
                again.is_some(),
                "A holds wraps, so a re-emission carries them"
            );
            // A second seal in the same epoch changes no grant: no new set.
            let r2 = engine_a
                .put_blob_scoped(COMMUNITY, Some(&comm), b"more minutes", None, None)
                .await
                .unwrap();
            assert!(
                r2.key_grant_emission.is_none(),
                "an unchanged fan-out emits nothing (§14)"
            );
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres {
        use super::super::two_node::*;
        use crate::store::postgres::PostgresBackend;
        use crate::store::Backend as _;

        async fn fresh() -> Option<PostgresBackend> {
            let dsn = crate::test_pg::empty_dsn()?;
            let b = PostgresBackend::connect(&dsn).await.unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        }

        #[tokio::test]
        async fn i61_end_to_end_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i61-a").await;
            let b = node(&bb, "i61-b").await;
            introduce(&[&a, &b], &["i61-a", "i61-b"]).await;
            exercise_i61_end_to_end(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i60_forged_set_refused_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i60-a").await;
            let b = node(&bb, "i60-b").await;
            introduce(&[&a, &b], &["i60-a", "i60-b"]).await;
            exercise_i60_forged_set_refused(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i60b_delayed_set_survives_a_later_occurrence_revocation_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i60b-a").await;
            let b = node(&bb, "i60b-b").await;
            introduce(&[&a, &b], &["i60b-a", "i60b-b"]).await;
            exercise_i60b_delayed_set_survives_a_later_occurrence_revocation(&a, &b, "postgres")
                .await;
        }

        #[tokio::test]
        async fn i62_union_order_independent_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i62-a").await;
            let b = node(&bb, "i62-b").await;
            introduce(&[&a, &b], &["i62-a", "i62-b"]).await;
            exercise_i62_union_order_independent(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i63_rotation_on_admitted_removal_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i63-a").await;
            let b = node(&bb, "i63-b").await;
            introduce(&[&a, &b], &["i63-a", "i63-b"]).await;
            exercise_i63_rotation_on_admitted_removal(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i64_two_minters_same_epoch_postgres() {
            let (Some(ba), Some(bb), Some(bc)) = (fresh().await, fresh().await, fresh().await)
            else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i64-a").await;
            let b = node(&bb, "i64-b").await;
            let c = node(&bc, "i64-c").await;
            introduce(&[&a, &b, &c], &["i64-a", "i64-b", "i64-c"]).await;
            exercise_i64_two_minters_same_epoch(&a, &b, &c, "postgres").await;
        }

        #[tokio::test]
        async fn i65_content_axis_second_device_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i65-a").await;
            let a2 = node(&bb, "i65-a2").await;
            introduce(&[&a, &a2], &["i65-a", "i65-a2"]).await;
            exercise_i65_content_axis_second_device(&a, &a2, "postgres").await;
        }
    }
}
