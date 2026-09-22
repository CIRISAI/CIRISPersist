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
    /// A [`Node`] whose own key is registered on its backend under `role`
    /// (`identity_type::NODE` when an owner binding must target it — #851).
    /// The same construction as [`node`] (via `node_signer`), role aside.
    pub async fn node_as<'a, B>(backend: &'a B, alias: &str, role: &str) -> Node<'a, B>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        ts::register_hybrid_key_as(backend, alias, alias, role).await;
        let signer = ts::local_signer(alias);
        let key = signer.derived_key_id();
        ts::register_hybrid_key_as(backend, &key, alias, role).await;
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

    /// Register every node's key on every node as a USER (the historical
    /// fixture role). Use [`introduce_as`] with `identity_type::NODE` when an
    /// owner binding must target the key (#851).
    pub async fn introduce<B>(nodes: &[&Node<'_, B>], aliases: &[&str])
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        introduce_as(nodes, aliases, USER).await;
    }

    /// Register every node's key on every node under `role`.
    pub async fn introduce_as<B>(nodes: &[&Node<'_, B>], aliases: &[&str], role: &str)
    where
        B: FederationDirectory + Sync,
    {
        for (i, n) in nodes.iter().enumerate() {
            for (j, other) in nodes.iter().enumerate() {
                if i != j {
                    ts::register_hybrid_key_as(n.backend, &other.key, aliases[j], role).await;
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
        let out = adopt_sealed_blob(
            to.backend,
            Some(&*to.signer),
            &ctx,
            &bytes,
            &BlobProvenance {
                author_key_id: from.key.clone(),
                cohort_scope: cohort_scope.to_owned(),
                community_key_id: Some(community_or_owner.to_owned()),
                epoch,
                tier,
                // #876 — this two-node fixture seals with the node's own
                // key, so author == minter here; the author != sealer
                // ladder lives in `epoch_minter_invariants`.
                minter_key_id: None,
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
        // v46.3.0 (#884, §4.1): an ACTIVE occurrence of the owner speaks
        // with the owner's voice on the key plane (the sealing node is one),
        // so the forger here is the owner's LOST device — its occurrence
        // revoked, no owner binding — which still knows the DEK. The author
        // is not yet known here, so the signer cannot be checked against it:
        // the carrier is stored, NOTHING is projected (§13, PR #850 review)
        // — and nothing ever will be, see (3).
        // Revoked NOW: `IdentityOccurrenceRevocation::revokes` treats an
        // occurrence asserted after its revocation as re-established.
        let revoked_at = chrono::Utc::now();
        a2.backend
            .put_identity_occurrence_revocation_local(
                crate::federation::types::IdentityOccurrenceRevocation {
                    identity_key_id: owner.clone(),
                    occurrence_key_id: a2.key.clone(),
                    revoked_at,
                    effective_at: revoked_at,
                    reason: Some("lost device (I65)".into()),
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            )
            .await
            .unwrap_or_else(|e| {
                panic!("{tag} I65: the second device's occurrence is revoked: {e}")
            });
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
        // The pending index (V146) was TAKEN by the adopt: nothing left.
        assert!(
            a2.backend
                .key_grant_pending_list(&sha, SELF)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I65: the adopt retired every pending row for the blob"
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
        // (5) A retroactive ADD on the ADOPTING node (PR #850, round three):
        // the owner admits a third device on a2. The peer-authored blob is
        // not this node's to re-wrap (no self-retention here) — the walk
        // skips it rather than aborting, and grants it nothing.
        let dev3 = format!("{tag}-dev3-{run}");
        ts::register_hybrid_key_as(a2.backend, &dev3, &dev3, USER).await;
        a2.backend
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: owner.clone(),
                occurrence_key_id: dev3.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(a.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
        let rk = crate::federation::at_rest_cascade::orchestrate::rekey_self_occurrence_add(
            a2.backend,
            &owner,
            std::slice::from_ref(&dev3),
            chrono::Utc::now(),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I65: a rekey on the adopting node must not abort: {e}"));
        assert!(
            !rk.changed_blobs.contains(&sha),
            "{tag} I65: the peer-authored blob is not re-wrapped here"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &dev3)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: only the author's node can grant the third device"
        );
    }

    /// **I71 — rotation is keyed on the removal's EFFECTIVE instant** (PR
    /// #850 review). A removal admitted with a future `effective_at` (inside
    /// the skew window) and a bump-and-seal in between mint an epoch NEWER
    /// than `removed_at` that still grants the member. Once the removal takes
    /// effect, the next seal must rotate that epoch too: compared against
    /// `removed_at` it never would.
    pub async fn exercise_i71_rotation_keys_on_effective_at<B>(
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
        seed_community_everywhere(
            &[a, b],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&xavier, None)],
        )
        .await;
        let x_occ = format!("{tag}-x-occ-{run}");
        for n in [a, b] {
            ts::register_hybrid_key_as(n.backend, &x_occ, &x_occ, USER).await;
            crate::federation::at_rest_cascade::blob_invariants::join_as_occurrence(
                n.backend, &xavier, &x_occ,
            )
            .await;
        }
        let first = encrypt_and_cascade_community(a.backend, &comm, b"e0", None, Some(&a.key))
            .await
            .unwrap();
        assert!(first.granted.contains(&x_occ), "{tag} I71: X granted at e0");
        // The removal is RECORDED now and takes EFFECT shortly (skew window).
        let removed_at = chrono::Utc::now();
        let effective_at = removed_at + chrono::Duration::milliseconds(400);
        let rev = ts::sign_community_membership_revocation(
            &comm,
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: comm.clone(),
                removed_identity_key_id: xavier.clone(),
                removed_at,
                effective_at,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        a.backend
            .put_community_membership_revocation(rev)
            .await
            .unwrap_or_else(|e| panic!("{tag} I71: a future-effective removal is admitted: {e}"));
        // Between admission and effect: the revoker's bump, then a seal —
        // an epoch minted AFTER `removed_at` that still grants X.
        a.backend
            .community_dek_bump_epoch(&comm, &a.key)
            .await
            .unwrap();
        let between =
            encrypt_and_cascade_community(a.backend, &comm, b"between", None, Some(&a.key))
                .await
                .unwrap();
        assert!(
            between.epoch > first.epoch,
            "{tag} I71: the bump minted a new epoch"
        );
        assert!(
            between.granted.contains(&x_occ),
            "{tag} I71: before the removal takes effect X is still granted (by design)"
        );
        let between_minted = a
            .backend
            .community_dek_minted_at(&comm, &a.key, between.epoch)
            .await
            .unwrap()
            .expect("minted_at");
        assert!(between_minted > removed_at && between_minted < effective_at);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        // The removal is in effect: the next seal must rotate the in-between
        // epoch (its mint predates `effective_at`), disable it, and exclude X.
        let after = encrypt_and_cascade_community(a.backend, &comm, b"after", None, Some(&a.key))
            .await
            .unwrap();
        assert!(
            after.epoch > between.epoch,
            "{tag} I71: the epoch minted before the removal took EFFECT rotates ({} -> {})",
            between.epoch,
            after.epoch
        );
        assert_eq!(
            a.backend
                .community_dek_key_state(&comm, &a.key, between.epoch)
                .await
                .unwrap(),
            Some(crate::federation::DekKeyState::Disabled),
            "{tag} I71: the in-between epoch is disabled"
        );
        assert!(
            !after.granted.contains(&x_occ),
            "{tag} I71: X is absent after the removal takes effect: {:?}",
            after.granted
        );
    }

    /// **I77 (#851 §20.1) — admission asks about the PRINCIPAL.** The
    /// minter is an owned node with NO occurrence row on the admitting node:
    /// refused while no live owner binding lifts it; admitted once the
    /// owner's binding (a replicated attestation) is on B and the owner is an
    /// active member; refused again once the owner is removed at
    /// `asserted_at`.
    pub async fn exercise_i77_owned_node_minter_admitted_by_principal<B>(
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
        // alice is a deterministic-keyed USER on both nodes (the owner-binding
        // helper signs as her); bob likewise; the community on both.
        for n in [a, b] {
            ts::register_identity_key(n.backend, &alice, USER).await;
            ts::register_identity_key(n.backend, &bob, USER).await;
            ts::register_hybrid_key_as(n.backend, &comm, &comm, USER).await;
            n.backend
                .put_community(ts::sign_community(
                    &comm,
                    crate::federation::types::Community {
                        community_key_id: comm.clone(),
                        community_name: "Principal Co-op".into(),
                        members: [&alice, &bob]
                            .into_iter()
                            .map(|k| crate::federation::types::CommunityMember {
                                key_id: k.clone(),
                                joined_at: chrono::Utc::now(),
                                role: None,
                            })
                            .collect(),
                        founded_at: chrono::Utc::now(),
                        consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                            .to_owned(),
                        policy_blob: None,
                        persist_row_hash: String::new(),
                    },
                ))
                .await
                .unwrap_or_else(|e| panic!("{tag} I77: seed community: {e}"));
        }
        // On A only: A's own occurrence under alice (the local decrypt target,
        // trusted-local — exactly what does NOT replicate) and B's occurrence
        // under bob, so A's fan-out has a far recipient.
        for (ident, o) in [(&alice, a), (&bob, b)] {
            a.backend
                .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                    identity_key_id: ident.clone(),
                    occurrence_key_id: o.key.clone(),
                    device_class: crate::federation::types::device_class::SERVER.into(),
                    hardware_attestation: None,
                    asserted_at: chrono::Utc::now(),
                    valid_until: None,
                    encryption_pubkeys: Some(o.kem.clone()),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                })
                .await
                .unwrap();
        }
        // On B: bob's own occurrence (B's decrypt target), NOTHING for A.
        b.backend
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: bob.clone(),
                occurrence_key_id: b.key.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(b.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
        let sealed =
            encrypt_and_cascade_community(a.backend, &comm, b"principal", None, Some(&a.key))
                .await
                .unwrap_or_else(|e| panic!("{tag} I77: A seals: {e}"));
        assert!(
            sealed.granted.contains(&b.key),
            "{tag} I77: A wrapped to B's occurrence"
        );
        let emitted = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("A holds wraps");
        // (1) No occurrence for A on B, no binding: refused — as today.
        let err = carry_key_grant(a, b, &emitted.attestation_id)
            .await
            .expect_err("{tag} I77: an unbound node is nobody's instrument");
        assert_eq!(
            refusal_reason(&err),
            "signer_not_active_member",
            "{tag} I77: {err}"
        );
        // (2) alice's owner binding for A lands on B (a replicated
        // attestation — what the mesh already carries): admitted.
        let binding = ts::owner_binding_attestation(&format!("ob-{run}"), &alice, &a.key);
        b.backend
            .apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: binding,
            })
            .await
            .unwrap_or_else(|e| panic!("{tag} I77: B admits alice's owner binding for A: {e}"));
        let admission = carry_key_grant(a, b, &emitted.attestation_id)
            .await
            .unwrap_or_else(|e| panic!("{tag} I77: an owned node lifts to its owner: {e}"));
        assert!(admission.wraps_written >= 1, "{tag} I77: {admission:?}");
        assert!(
            b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I77: B's own wrap projected"
        );
        // (3) alice removed, effective before a later set's asserted_at: the
        // principal is no longer a member — refused.
        let rev = ts::sign_community_membership_revocation(
            &comm,
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: comm.clone(),
                removed_identity_key_id: alice.clone(),
                removed_at: chrono::Utc::now(),
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        b.backend
            .put_community_membership_revocation(rev)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let late = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("A still holds wraps");
        let err = carry_key_grant(a, b, &late.attestation_id)
            .await
            .expect_err("{tag} I77: the removed owner's instrument is refused");
        assert_eq!(
            refusal_reason(&err),
            "signer_not_active_member",
            "{tag} I77: {err}"
        );
        // (4) PR #852 round two — the peer holds the node's occurrence row
        // (under alice) but NO owner binding: a NODE minter lifts only
        // through the live binding, never through the row. A fresh
        // backend, seeded like B was but with A's occurrence and without
        // alice's binding or removal.
        #[cfg(feature = "sqlite")]
        {
            let c = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            crate::store::Backend::run_migrations(&c).await.unwrap();
            ts::register_hybrid_key_as(
                &c,
                &a.key,
                "i77-a",
                crate::federation::types::identity_type::NODE,
            )
            .await;
            ts::register_identity_key(&c, &alice, USER).await;
            ts::register_identity_key(&c, &bob, USER).await;
            ts::register_hybrid_key_as(&c, &comm, &comm, USER).await;
            c.put_community(ts::sign_community(
                &comm,
                crate::federation::types::Community {
                    community_key_id: comm.clone(),
                    community_name: "Principal Co-op".into(),
                    members: [&alice, &bob]
                        .into_iter()
                        .map(|k| crate::federation::types::CommunityMember {
                            key_id: k.clone(),
                            joined_at: chrono::Utc::now(),
                            role: None,
                        })
                        .collect(),
                    founded_at: chrono::Utc::now(),
                    consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                        .to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap();
            c.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: alice.clone(),
                occurrence_key_id: a.key.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(a.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
            let row = a
                .backend
                .get_attestation(&emitted.attestation_id)
                .await
                .unwrap()
                .unwrap();
            let err = admit_replicated_key_grant(
                &c,
                SignedKeyGrantSet {
                    attestation: row.clone(),
                },
            )
            .await
            .expect_err("{tag} I77: the occurrence row alone never lifts a NODE minter");
            assert_eq!(
                refusal_reason(&err),
                "signer_not_active_member",
                "{tag} I77 (4): {err}"
            );
            // …and with the binding it is admitted; then (5) the occurrence
            // REVOKED (effective before the set's asserted_at) with the
            // binding still live: refused — the revocation gate wins.
            c.apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: ts::owner_binding_attestation(&format!("ob-c-{run}"), &alice, &a.key),
            })
            .await
            .unwrap();
            admit_replicated_key_grant(
                &c,
                SignedKeyGrantSet {
                    attestation: row.clone(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I77 (4): with the live binding: {e}"));
            c.put_identity_occurrence_revocation_local(
                crate::federation::types::IdentityOccurrenceRevocation {
                    identity_key_id: alice.clone(),
                    occurrence_key_id: a.key.clone(),
                    revoked_at: chrono::Utc::now(),
                    effective_at: chrono::Utc::now(),
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            )
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let fresh = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
                .await
                .unwrap()
                .expect("A still holds wraps");
            let row2 = a
                .backend
                .get_attestation(&fresh.attestation_id)
                .await
                .unwrap()
                .unwrap();
            let err = admit_replicated_key_grant(&c, SignedKeyGrantSet { attestation: row2 })
                .await
                .expect_err("{tag} I77 (5): a revoked occurrence is not lifted by a live binding");
            assert_eq!(
                refusal_reason(&err),
                "signer_not_active_member",
                "{tag} I77 (5): {err}"
            );
        }
        // (6) PR #852 round three — one occurrence key under TWO identities
        // (ownership moved alice → bob; alice's row left, inserted FIRST so a
        // LIMIT-1 lookup would return it): bob's row revoked, bob's binding
        // live and alice's absent. The revocation on ANY row is final.
        #[cfg(feature = "sqlite")]
        {
            let d = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            crate::store::Backend::run_migrations(&d).await.unwrap();
            ts::register_hybrid_key_as(
                &d,
                &a.key,
                "i77-a",
                crate::federation::types::identity_type::NODE,
            )
            .await;
            ts::register_identity_key(&d, &alice, USER).await;
            ts::register_identity_key(&d, &bob, USER).await;
            ts::register_hybrid_key_as(&d, &comm, &comm, USER).await;
            d.put_community(ts::sign_community(
                &comm,
                crate::federation::types::Community {
                    community_key_id: comm.clone(),
                    community_name: "Principal Co-op".into(),
                    members: [&alice, &bob]
                        .into_iter()
                        .map(|k| crate::federation::types::CommunityMember {
                            key_id: k.clone(),
                            joined_at: chrono::Utc::now(),
                            role: None,
                        })
                        .collect(),
                    founded_at: chrono::Utc::now(),
                    consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                        .to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap();
            let long_ago = chrono::Utc::now() - chrono::Duration::seconds(30);
            for ident in [&alice, &bob] {
                d.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                    identity_key_id: ident.clone(),
                    occurrence_key_id: a.key.clone(),
                    device_class: crate::federation::types::device_class::SERVER.into(),
                    hardware_attestation: None,
                    asserted_at: long_ago,
                    valid_until: None,
                    encryption_pubkeys: Some(a.kem.clone()),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                })
                .await
                .unwrap();
            }
            d.apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: ts::owner_binding_attestation(&format!("ob-d-{run}"), &bob, &a.key),
            })
            .await
            .unwrap();
            d.put_identity_occurrence_revocation_local(
                crate::federation::types::IdentityOccurrenceRevocation {
                    identity_key_id: bob.clone(),
                    occurrence_key_id: a.key.clone(),
                    revoked_at: chrono::Utc::now(),
                    effective_at: chrono::Utc::now(),
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            )
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let newest = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
                .await
                .unwrap()
                .expect("A still holds wraps");
            let row3 = a
                .backend
                .get_attestation(&newest.attestation_id)
                .await
                .unwrap()
                .unwrap();
            let err = admit_replicated_key_grant(&d, SignedKeyGrantSet { attestation: row3 })
                .await
                .expect_err("{tag} I77 (6): a revocation on ANY row for the key is final");
            assert_eq!(
                refusal_reason(&err),
                "signer_not_active_member",
                "{tag} I77 (6): {err}"
            );
        }
        // (7) PR #852 round four — a revocation counts only on the row of
        // the identity the lift resolves to. carol (a member, the attacker)
        // binds A's key under HERSELF (an identity may attest any key as its
        // occurrence) and revokes that row; alice's binding is live and
        // alice's row unrevoked: A's set is still admitted.
        #[cfg(feature = "sqlite")]
        {
            let e = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            crate::store::Backend::run_migrations(&e).await.unwrap();
            let carol = format!("{tag}-carol-{run}");
            ts::register_hybrid_key_as(
                &e,
                &a.key,
                "i77-a",
                crate::federation::types::identity_type::NODE,
            )
            .await;
            for ident in [&alice, &bob, &carol] {
                ts::register_identity_key(&e, ident, USER).await;
            }
            ts::register_hybrid_key_as(&e, &comm, &comm, USER).await;
            e.put_community(ts::sign_community(
                &comm,
                crate::federation::types::Community {
                    community_key_id: comm.clone(),
                    community_name: "Principal Co-op".into(),
                    members: [&alice, &bob, &carol]
                        .into_iter()
                        .map(|k| crate::federation::types::CommunityMember {
                            key_id: k.clone(),
                            joined_at: chrono::Utc::now(),
                            role: None,
                        })
                        .collect(),
                    founded_at: chrono::Utc::now(),
                    consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                        .to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap();
            e.apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: ts::owner_binding_attestation(&format!("ob-e-{run}"), &alice, &a.key),
            })
            .await
            .unwrap();
            // carol's identity-signed content-only occurrence binding A's key.
            let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                chrono::Utc::now().timestamp_millis() - 30_000,
            )
            .unwrap();
            let env = serde_json::json!({
                "attesting_key_id": carol,
                "identity_key_id": carol,
                "occurrence_key_id": a.key,
                "device_class": crate::federation::types::device_class::SERVER,
                "encryption_pubkeys": {
                    "x25519_base64": a.kem.x25519_base64,
                    "ml_kem_768_base64": a.kem.ml_kem_768_base64,
                },
                "asserted_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "valid_until": serde_json::Value::Null,
                "hardware_attestation": serde_json::Value::Null,
            });
            let carol_signer = ts::local_signer(&carol);
            let (signed_envelope, signature) =
                ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
                    &crate::signing::LocalSelfSigner::new(carol_signer.as_ref()),
                    env,
                )
                .await
                .unwrap();
            e.put_identity_occurrence(crate::federation::SignedIdentityOccurrence {
                identity_occurrence: crate::federation::types::IdentityOccurrence {
                    identity_key_id: carol.clone(),
                    occurrence_key_id: a.key.clone(),
                    device_class: crate::federation::types::device_class::SERVER.into(),
                    hardware_attestation: None,
                    asserted_at: at,
                    valid_until: None,
                    encryption_pubkeys: Some(a.kem.clone()),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                },
                attesting_key_id: carol.clone(),
                signed_envelope,
                signature,
            })
            .await
            .unwrap_or_else(|err| {
                panic!("{tag} I77 (7): an identity may bind a key as its occurrence: {err}")
            });
            e.put_identity_occurrence_revocation_local(
                crate::federation::types::IdentityOccurrenceRevocation {
                    identity_key_id: carol.clone(),
                    occurrence_key_id: a.key.clone(),
                    revoked_at: chrono::Utc::now(),
                    effective_at: chrono::Utc::now(),
                    reason: None,
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
            )
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let latest = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
                .await
                .unwrap()
                .expect("A still holds wraps");
            let row4 = a
                .backend
                .get_attestation(&latest.attestation_id)
                .await
                .unwrap()
                .unwrap();
            admit_replicated_key_grant(&e, SignedKeyGrantSet { attestation: row4 })
                .await
                .unwrap_or_else(|err| {
                    panic!("{tag} I77 (7): carol's revocation of HER row must not disable A: {err}")
                });
        }
        // (8) PR #852 round five — ownership moved alice → dave: A keeps an
        // unrevoked occurrence row under alice (the member); the live binding
        // is dave's, who is NOT on the roster. A NODE minter has exactly one
        // principal — its live owner — so the set is refused; the stale row
        // and the member-occurrence walk are not fallbacks.
        #[cfg(feature = "sqlite")]
        {
            let f = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            crate::store::Backend::run_migrations(&f).await.unwrap();
            let dave = format!("{tag}-dave-{run}");
            ts::register_hybrid_key_as(
                &f,
                &a.key,
                "i77-a",
                crate::federation::types::identity_type::NODE,
            )
            .await;
            for ident in [&alice, &bob, &dave] {
                ts::register_identity_key(&f, ident, USER).await;
            }
            ts::register_hybrid_key_as(&f, &comm, &comm, USER).await;
            f.put_community(ts::sign_community(
                &comm,
                crate::federation::types::Community {
                    community_key_id: comm.clone(),
                    community_name: "Principal Co-op".into(),
                    members: [&alice, &bob]
                        .into_iter()
                        .map(|k| crate::federation::types::CommunityMember {
                            key_id: k.clone(),
                            joined_at: chrono::Utc::now(),
                            role: None,
                        })
                        .collect(),
                    founded_at: chrono::Utc::now(),
                    consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                        .to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap();
            f.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: alice.clone(),
                occurrence_key_id: a.key.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now() - chrono::Duration::seconds(30),
                valid_until: None,
                encryption_pubkeys: Some(a.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
            f.apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: ts::owner_binding_attestation(&format!("ob-f-{run}"), &dave, &a.key),
            })
            .await
            .unwrap();
            let row5 = a
                .backend
                .get_attestation(&emitted.attestation_id)
                .await
                .unwrap()
                .unwrap();
            let err = admit_replicated_key_grant(&f, SignedKeyGrantSet { attestation: row5 })
                .await
                .expect_err("{tag} I77 (8): a stale row under a former owner is not a principal");
            assert_eq!(
                refusal_reason(&err),
                "signer_not_active_member",
                "{tag} I77 (8): {err}"
            );
        }
    }

    /// **I76 (#851 §20.2) — the content-only signed occurrence.** A node
    /// signs its own occurrence (no transport destination, KEM pubkeys
    /// present): refused while nothing lifts the node to the identity;
    /// admitted once a live owner binding does; a second row claiming
    /// ANOTHER identity is refused. The admitted row is advertised by the
    /// plane's since-read; a trusted-local row is not (I78).
    pub async fn exercise_i76_content_only_occurrence<B>(n: &Node<'_, B>, alias: &str, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        // `alias` names the node's twin in leg (5), a sqlite-only leg.
        let _ = alias;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let alice = format!("{tag}-alice-{run}");
        let carol = format!("{tag}-carol-{run}");
        ts::register_identity_key(n.backend, &alice, USER).await;
        ts::register_identity_key(n.backend, &carol, USER).await;
        let content_only = |identity: &str| {
            let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                chrono::Utc::now().timestamp_millis(),
            )
            .unwrap();
            let env = serde_json::json!({
                "attesting_key_id": n.key,
                "identity_key_id": identity,
                "occurrence_key_id": n.key,
                "device_class": crate::federation::types::device_class::SERVER,
                "encryption_pubkeys": {
                    "x25519_base64": n.kem.x25519_base64,
                    "ml_kem_768_base64": n.kem.ml_kem_768_base64,
                },
                "asserted_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "valid_until": serde_json::Value::Null,
                "hardware_attestation": serde_json::Value::Null,
            });
            (identity.to_owned(), env, at)
        };
        let sign = |identity: String, env: serde_json::Value, at: chrono::DateTime<chrono::Utc>| async move {
            let (signed_envelope, signature) =
                ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
                    &crate::signing::LocalSelfSigner::new(n.signer.as_ref()),
                    env,
                )
                .await
                .unwrap();
            crate::federation::SignedIdentityOccurrence {
                identity_occurrence: crate::federation::types::IdentityOccurrence {
                    identity_key_id: identity,
                    occurrence_key_id: n.key.clone(),
                    device_class: crate::federation::types::device_class::SERVER.into(),
                    hardware_attestation: None,
                    asserted_at: at,
                    valid_until: None,
                    encryption_pubkeys: Some(n.kem.clone()),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                },
                attesting_key_id: n.key.clone(),
                signed_envelope,
                signature,
            }
        };
        // (1) Unbound: refused.
        let (i, e, at) = content_only(&alice);
        let err = n
            .backend
            .put_identity_occurrence(sign(i, e, at).await)
            .await
            .expect_err("{tag} I76: an unbound node cannot vouch for itself");
        assert!(
            err.to_string().contains("neither identity")
                || err.to_string().contains("acts for")
                || err.to_string().contains("nor a node it owns"),
            "{tag} I76: the refusal is signer_acts_for: {err}"
        );
        // (2) alice's live owner binding lifts the node: admitted, advertised.
        n.backend
            .apply_replicated_attestation(crate::federation::SignedAttestation {
                attestation: ts::owner_binding_attestation(&format!("ob-{run}"), &alice, &n.key),
            })
            .await
            .unwrap();
        let (i, e, at) = content_only(&alice);
        let admitted = sign(i, e, at).await;
        n.backend
            .put_identity_occurrence(admitted.clone())
            .await
            .unwrap_or_else(|e| panic!("{tag} I76: the owner binding lifts the node: {e}"));
        let row = n
            .backend
            .lookup_identity_for_occurrence(&n.key)
            .await
            .unwrap()
            .expect("the occurrence exists");
        assert_eq!(row.identity_key_id, alice);
        assert!(row.encryption_pubkeys.is_some() && row.transport_binding.is_none());
        let served = n
            .backend
            .list_signed_identity_occurrences_since(None, 1_000)
            .await
            .unwrap();
        assert!(
            served
                .iter()
                .any(|s| s.occurrence.identity_occurrence.occurrence_key_id == n.key),
            "{tag} I78: the published occurrence is advertised by the plane"
        );
        // I78: a trusted-local row is never advertised.
        let local_occ = format!("{tag}-local-{run}");
        ts::register_hybrid_key_as(n.backend, &local_occ, &local_occ, USER).await;
        n.backend
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: alice.clone(),
                occurrence_key_id: local_occ.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(n.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
        let served = n
            .backend
            .list_signed_identity_occurrences_since(None, 1_000)
            .await
            .unwrap();
        assert!(
            !served
                .iter()
                .any(|s| s.occurrence.identity_occurrence.occurrence_key_id == local_occ),
            "{tag} I78: a trusted-local row is not on the plane"
        );
        // (3) The same node claiming ANOTHER identity: refused.
        let (i, e, at) = content_only(&carol);
        let err = n
            .backend
            .put_identity_occurrence(sign(i, e, at).await)
            .await
            .expect_err("{tag} I76: a node bound to alice cannot claim carol");
        assert!(
            err.to_string().contains("neither identity")
                || err.to_string().contains("acts for")
                || err.to_string().contains("nor a node it owns"),
            "{tag} I76: {err}"
        );
        // (10) Hybrid-only (operator directive) — a content-only occurrence
        // whose signature carries no ML-DSA-65 half is refused before any
        // verification, however valid the Ed25519 half.
        {
            let mut classical_only = admitted.clone();
            classical_only.signature.mldsa65_signature_base64 = None;
            let err = n
                .backend
                .put_identity_occurrence(classical_only)
                .await
                .expect_err("{tag} I76 (10): a classical-only occurrence signature is refused");
            assert!(
                err.to_string().contains("ML-DSA-65") && err.to_string().contains("hybrid-only"),
                "{tag} I76 (10): the refusal names the missing half: {err}"
            );
        }
        // (8) PR #852 round five — a future-dated content-only occurrence is
        // refused by the write-gate skew bound, however consistent envelope
        // and row are: a compromised node with a live binding must not
        // out-rank authentic replacements or escape a later revocation.
        {
            let future = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp_millis(),
            )
            .unwrap();
            let env = serde_json::json!({
                "attesting_key_id": n.key,
                "identity_key_id": alice,
                "occurrence_key_id": n.key,
                "device_class": crate::federation::types::device_class::SERVER,
                "encryption_pubkeys": {
                    "x25519_base64": n.kem.x25519_base64,
                    "ml_kem_768_base64": n.kem.ml_kem_768_base64,
                },
                "asserted_at": future.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "valid_until": serde_json::Value::Null,
                "hardware_attestation": serde_json::Value::Null,
            });
            let err = n
                .backend
                .put_identity_occurrence(sign(alice.clone(), env, future).await)
                .await
                .expect_err("{tag} I76 (8): a future-dated occurrence is refused");
            assert!(
                err.to_string().to_lowercase().contains("skew")
                    || err.to_string().to_lowercase().contains("future"),
                "{tag} I76 (8): the refusal is the skew bound: {err}"
            );
        }
        // (9) PR #852 round five — a NODE vouching for a SIBLING key under its
        // owner: admitted where its owner binding is live; refused on a
        // backend that holds only its occurrence row (no binding) — the raw
        // row never vouches, for the node's own key or any other.
        {
            let sibling = format!("{tag}-sibling-{run}");
            ts::register_hybrid_key_as(n.backend, &sibling, &sibling, USER).await;
            let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                chrono::Utc::now().timestamp_millis(),
            )
            .unwrap();
            let env = serde_json::json!({
                "attesting_key_id": n.key,
                "identity_key_id": alice,
                "occurrence_key_id": sibling,
                "device_class": crate::federation::types::device_class::AGENT,
                "encryption_pubkeys": {
                    "x25519_base64": n.kem.x25519_base64,
                    "ml_kem_768_base64": n.kem.ml_kem_768_base64,
                },
                "asserted_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "valid_until": serde_json::Value::Null,
                "hardware_attestation": serde_json::Value::Null,
            });
            let (signed_envelope, signature) =
                ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
                    &crate::signing::LocalSelfSigner::new(n.signer.as_ref()),
                    env,
                )
                .await
                .unwrap();
            let sibling_row = crate::federation::SignedIdentityOccurrence {
                identity_occurrence: crate::federation::types::IdentityOccurrence {
                    identity_key_id: alice.clone(),
                    occurrence_key_id: sibling.clone(),
                    device_class: crate::federation::types::device_class::AGENT.into(),
                    hardware_attestation: None,
                    asserted_at: at,
                    valid_until: None,
                    encryption_pubkeys: Some(n.kem.clone()),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                },
                attesting_key_id: n.key.clone(),
                signed_envelope,
                signature,
            };
            n.backend
                .put_identity_occurrence(sibling_row.clone())
                .await
                .unwrap_or_else(|e| {
                    panic!("{tag} I76 (9): a bound node vouches for a sibling: {e}")
                });
            #[cfg(feature = "sqlite")]
            {
                let o2 = crate::store::sqlite::SqliteBackend::open_in_memory()
                    .await
                    .unwrap();
                crate::store::Backend::run_migrations(&o2).await.unwrap();
                let _twin =
                    node_as(&o2, alias, crate::federation::types::identity_type::NODE).await;
                ts::register_identity_key(&o2, &alice, USER).await;
                ts::register_hybrid_key_as(&o2, &sibling, &sibling, USER).await;
                o2.put_identity_occurrence_local(admitted.identity_occurrence.clone())
                    .await
                    .unwrap();
                let err = o2
                    .put_identity_occurrence(sibling_row)
                    .await
                    .expect_err("{tag} I76 (9): the node's raw row never vouches for a sibling");
                assert!(
                    err.to_string().contains("nor a node it owns")
                        || err.to_string().contains("acts for"),
                    "{tag} I76 (9): {err}"
                );
            }
        }
        // (7) PR #852 round four — the typed instant must be millisecond-exact:
        // a relay that keeps the signed millisecond but adds an unsigned
        // sub-millisecond part (enough to hop a same-millisecond revocation)
        // is refused.
        {
            let mut sub_ms = admitted.clone();
            sub_ms.identity_occurrence.asserted_at =
                admitted.identity_occurrence.asserted_at + chrono::Duration::microseconds(500);
            let err = n
                .backend
                .put_identity_occurrence(sub_ms)
                .await
                .expect_err("{tag} I76 (7): a sub-millisecond typed instant is refused");
            assert!(
                err.to_string().contains("asserted_at"),
                "{tag} I76 (7): {err}"
            );
        }
        // (6) PR #852 round two — the envelope's attester must be the
        // wrapper's signer: a valid signature under an envelope that names
        // ANOTHER key as attester is refused.
        {
            let (i, mut e, at) = content_only(&alice);
            e["attesting_key_id"] = serde_json::Value::String(carol.clone());
            let err = n
                .backend
                .put_identity_occurrence(sign(i, e, at).await)
                .await
                .expect_err(
                    "{tag} I76 (6): envelope attester diverging from the wrapper is refused",
                );
            assert!(
                err.to_string().contains("attesting_key_id"),
                "{tag} I76 (6): the refusal names the field: {err}"
            );
        }
        // (4) PR #852 review — a RELAY forwards the admitted row with the
        // typed `asserted_at` pushed into the future under the valid
        // signature: every persisted field is bound to the envelope.
        let mut forward_dated = admitted.clone();
        forward_dated.identity_occurrence.asserted_at =
            admitted.identity_occurrence.asserted_at + chrono::Duration::days(365);
        let err = n
            .backend
            .put_identity_occurrence(forward_dated)
            .await
            .expect_err("{tag} I76: a typed asserted_at diverging from the envelope is refused");
        assert!(
            err.to_string().contains("asserted_at"),
            "{tag} I76: the refusal names the diverging field: {err}"
        );
        // (5) PR #852 review — the occurrence row alone never vouches: on a
        // backend that holds the admitted row but NO owner binding, the same
        // node's self-signed re-submission is refused. (An in-memory sqlite
        // twin, so this leg runs under the sqlite feature only.)
        #[cfg(feature = "sqlite")]
        {
            let other = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            crate::store::Backend::run_migrations(&other).await.unwrap();
            // The same node (same alias ⇒ same deterministic signer and key),
            // registered on the fresh backend with its REAL pubkeys.
            let twin = node_as(&other, alias, crate::federation::types::identity_type::NODE).await;
            assert_eq!(twin.key, n.key);
            ts::register_identity_key(&other, &alice, USER).await;
            other
                .put_identity_occurrence_local(admitted.identity_occurrence.clone())
                .await
                .unwrap();
            let (i, e, at) = content_only(&alice);
            let err = other
                .put_identity_occurrence(sign(i, e, at).await)
                .await
                .expect_err(
                "{tag} I76: the row a prior admission left never vouches without the live binding",
            );
            assert!(
                err.to_string().contains("neither identity")
                    || err.to_string().contains("acts for"),
                "{tag} I76: {err}"
            );
        }
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

    /// **I72 (from disk) — both adopt doors reconcile pending content sets**
    /// (PR #850, round three): a self/family chunk has its own DEK and its
    /// own set, so `adopt_sealed_chunk` projects exactly as `adopt_sealed_blob`.
    #[test]
    fn i72_both_adopt_doors_project_pending_content_grants() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(root.join("src/federation/adopt_cascade.rs")).unwrap();
        let prod = production_only(&text);
        for door in ["adopt_sealed_blob", "adopt_sealed_chunk"] {
            let start = prod.find(&format!("pub async fn {door}<")).unwrap();
            let end = prod[start + 1..]
                .find("\npub async fn ")
                .map(|i| start + 1 + i)
                .unwrap_or(prod.len());
            assert!(
                prod[start..end].contains("project_pending_content_grants("),
                "I72: {door} must project the pending content sets once the row names its author"
            );
        }
    }

    /// **I78 (from disk, #851) — the occurrence plane advertises signed-put
    /// rows only**: both dialects' `list_signed_identity_occurrences_since`
    /// keep the `attesting_key_id IS NOT NULL` filter, so a trusted-local
    /// row can never be listed (the behavioural half is in I76).
    #[test]
    fn i78_occurrence_plane_lists_signed_put_rows_only() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for file in ["src/store/sqlite.rs", "src/store/postgres.rs"] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            let prod = production_only(&text);
            let body = method_body(&prod, "list_signed_identity_occurrences_since");
            assert!(
                body.contains("federation_identity_occurrences")
                    && body.contains("attesting_key_id IS NOT NULL"),
                "I78: {file}: list_signed_identity_occurrences_since must list signed-put rows only"
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
            // PR #850 round three — a second blob under the SAME local epoch
            // whose row names an OLD signer as author (the node's signer
            // rotated after the write), and an ADOPTED blob (#846) under an
            // epoch this node holds no DEK for.
            let old_signer_blob = seal(&dek, b"written under the old signer", None)
                .unwrap()
                .to_bytes();
            let old_sha: [u8; 32] = sha2::Sha256::digest(&old_signer_blob).into();
            conn.execute(
                "INSERT INTO federation_blobs (sha256, storage_kind, bytes_inline, size_bytes, \
                    cohort_scope, crypto_tier, author_key_id) \
                 VALUES (?1, 'inline', ?2, ?3, 'community', 'community_dek', 'old-signer-A')",
                rusqlite::params![
                    old_sha.to_vec(),
                    old_signer_blob,
                    old_signer_blob.len() as i64
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO federation_community_blob_epoch (at_rest_sha256, community_key_id, epoch) \
                 VALUES (?1, 'legacy-comm', 1)",
                rusqlite::params![old_sha.to_vec()],
            )
            .unwrap();
            let adopted = seal(&fresh_dek().unwrap(), b"adopted from a peer", None)
                .unwrap()
                .to_bytes();
            let adopted_sha: [u8; 32] = sha2::Sha256::digest(&adopted).into();
            conn.execute(
                "INSERT INTO federation_blobs (sha256, storage_kind, bytes_inline, size_bytes, \
                    cohort_scope, crypto_tier, author_key_id) \
                 VALUES (?1, 'inline', ?2, ?3, 'community', 'community_dek', 'peer-P')",
                rusqlite::params![adopted_sha.to_vec(), adopted, adopted.len() as i64],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO federation_community_blob_epoch (at_rest_sha256, community_key_id, epoch) \
                 VALUES (?1, 'legacy-comm', 7)",
                rusqlite::params![adopted_sha.to_vec()],
            )
            .unwrap();
            sha
        }

        /// The sha of the seeded row authored by `old-signer-A`.
        fn old_signer_sha(backend: &SqliteBackend) -> [u8; 32] {
            let conn = backend.conn_handle();
            let conn = conn.lock();
            let v: Vec<u8> = conn
                .query_row(
                    "SELECT sha256 FROM federation_blobs WHERE author_key_id = 'old-signer-A'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            v.try_into().unwrap()
        }

        /// The minter V145 + the boot gave each pre-V145 binding under
        /// `legacy-comm` at `epoch`, keyed by the row's author.
        fn binding_minters(backend: &SqliteBackend, epoch: i64) -> Vec<(String, String)> {
            let conn = backend.conn_handle();
            let conn = conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT COALESCE(b.author_key_id, ''), e.minter_key_id \
                       FROM federation_community_blob_epoch e \
                       JOIN federation_blobs b ON b.sha256 = e.at_rest_sha256 \
                      WHERE e.community_key_id = 'legacy-comm' AND e.epoch = ?1 \
                      ORDER BY 1",
                )
                .unwrap();
            stmt.query_map([epoch], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
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
            // PR #850 rounds three/four — the binding is the AUTHOR's, and the
            // author is the minter: a NULL-author row (pre-V144) resolves to
            // this node; a row an OLD signer authored stays the old
            // occurrence's — a rotated signer is a new occurrence, and a new
            // occurrence does not open an old one's epoch without a grant
            // (fail-secure, never silent: the read refuses); an adopted row
            // keeps its peer author.
            assert_eq!(
                binding_minters(sq, 1),
                vec![
                    (String::new(), key.clone()),
                    ("old-signer-A".to_owned(), "old-signer-A".to_owned())
                ],
                "I66: pre-V145 bindings: NULL author → the node; an old signer's row stays its own"
            );
            assert_eq!(
                binding_minters(sq, 7),
                vec![("peer-P".to_owned(), "peer-P".to_owned())],
                "I66: an adopted binding keeps its author as minter"
            );
            let old_sha = old_signer_sha(sq);
            assert!(
                sq.community_dek_blob_epoch(&old_sha).await.unwrap().is_some()
                    && read_for_community_viewer(sq.as_ref(), &old_sha, "viewer-occ")
                        .await
                        .is_err(),
                "I66: the old occurrence's content refuses under the new key — not silently stranded, refused"
            );
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
        async fn i76_content_only_occurrence_sqlite() {
            let bn = fresh().await;
            let n = node_as(&bn, "i76-n", crate::federation::types::identity_type::NODE).await;
            exercise_i76_content_only_occurrence(&n, "i76-n", "sqlite").await;
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
        async fn i77_owned_node_minter_admitted_by_principal_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i77-a").await;
            let b = node(&bb, "i77-b").await;
            introduce_as(
                &[&a, &b],
                &["i77-a", "i77-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i77_owned_node_minter_admitted_by_principal(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i71_rotation_keys_on_effective_at_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i71-a").await;
            let b = node(&bb, "i71-b").await;
            introduce(&[&a, &b], &["i71-a", "i71-b"]).await;
            exercise_i71_rotation_keys_on_effective_at(&a, &b, "sqlite").await;
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

        /// **I75 (#851 §20.4) — THE END TO END, DELIVERED.** Two Engines. Every
        /// row crosses only through a since-read and the gated door on the
        /// other side: keys through the Key plane, owner bindings through the
        /// attestation cursor, occurrences through
        /// `list_signed_identity_occurrences_since` → `put_identity_occurrence`,
        /// the set through the cursor → `apply_replicated_key_grant`. Nothing
        /// is copied by hand — the plane I61 could not run.
        #[tokio::test]
        async fn i75_end_to_end_delivered_by_the_planes_sqlite() {
            use crate::federation::key_grant::SignedKeyGrantSet;
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
            use crate::federation::types::identity_type::USER;
            use crate::federation::{
                AdoptDisposition, BlobBody, BlobProvenance, BlobStorage, FederationDirectory,
                SignedAttestation, SignedKeyRecord,
            };
            let run = uuid::Uuid::new_v4().simple().to_string();
            let (alias_a, alias_b) = (format!("i75-a-{run}"), format!("i75-b-{run}"));
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
                e.register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    alias,
                    None,
                    serde_json::json!({}),
                    vec![],
                )
                .await
                .unwrap();
            }
            let (sa, sb) = (
                engine_a.sqlite_backend().unwrap().clone(),
                engine_b.sqlite_backend().unwrap().clone(),
            );
            let (a_key, b_key) = (
                engine_a.local_derived_key_id().await.unwrap(),
                engine_b.local_derived_key_id().await.unwrap(),
            );
            // ── the planes ────────────────────────────────────────────
            async fn deliver_keys(from: &SqliteBackend, to: &SqliteBackend) -> usize {
                let mut n = 0;
                for served in from
                    .list_signed_key_records_since(None, 1_000)
                    .await
                    .unwrap()
                {
                    if FederationDirectory::lookup_public_key(to, &served.record.key_id)
                        .await
                        .unwrap()
                        .is_none()
                    {
                        to.put_public_key(SignedKeyRecord {
                            record: served.record,
                        })
                        .await
                        .unwrap();
                        n += 1;
                    }
                }
                n
            }
            async fn deliver_attestations(
                from: &SqliteBackend,
                to: &crate::Engine,
                to_backend: &SqliteBackend,
            ) -> usize {
                let mut n = 0;
                for served in from.list_attestations_since(None, 1_000).await.unwrap() {
                    let row = served.attestation;
                    if to_backend
                        .get_attestation(&row.attestation_id)
                        .await
                        .unwrap()
                        .is_some()
                    {
                        continue;
                    }
                    let kind = format!(
                        "{} (tier={}, pqc_sig={})",
                        row.attestation_type,
                        row.tier,
                        row.scrub_signature_pqc.is_some()
                    );
                    let signer = row.attesting_key_id.clone();
                    if row.attestation_type.starts_with("key_grant:") {
                        to.apply_replicated_key_grant(SignedKeyGrantSet { attestation: row })
                            .await
                            .unwrap_or_else(|e| panic!("I75: the far node admits the set: {e}"));
                    } else {
                        to_backend
                            .apply_replicated_attestation(SignedAttestation { attestation: row })
                            .await
                            .unwrap_or_else(|e| {
                                panic!("I75: the far node admits the row {kind} by {signer}: {e}")
                            });
                    }
                    n += 1;
                }
                n
            }
            async fn deliver_occurrences(from: &SqliteBackend, to: &SqliteBackend) -> usize {
                let mut n = 0;
                for served in from
                    .list_signed_identity_occurrences_since(None, 1_000)
                    .await
                    .unwrap()
                {
                    let occ = served.occurrence;
                    if to
                        .lookup_identity_for_occurrence(&occ.identity_occurrence.occurrence_key_id)
                        .await
                        .unwrap()
                        .is_some()
                    {
                        continue;
                    }
                    to.put_identity_occurrence(occ)
                        .await
                        .unwrap_or_else(|e| panic!("I75: the far node admits the occurrence: {e}"));
                    n += 1;
                }
                n
            }
            // ── identities and the community, each born on ONE node ───
            let (alice, bob, comm) = (
                format!("i75-alice-{run}"),
                format!("i75-bob-{run}"),
                format!("i75-comm-{run}"),
            );
            ts::register_identity_key(sa.as_ref(), &alice, USER).await;
            ts::register_identity_key(sb.as_ref(), &bob, USER).await;
            ts::register_hybrid_key_as(sa.as_ref(), &comm, &comm, USER).await;
            // alice owns A (born on A); bob owns B (born on B) — attestations.
            sa.apply_replicated_attestation(SignedAttestation {
                attestation: ts::owner_binding_attestation(&format!("ob-a-{run}"), &alice, &a_key),
            })
            .await
            .unwrap();
            sb.apply_replicated_attestation(SignedAttestation {
                attestation: ts::owner_binding_attestation(&format!("ob-b-{run}"), &bob, &b_key),
            })
            .await
            .unwrap();
            // Keys cross (both ways) so each side can verify the other's rows.
            assert!(deliver_keys(&sa, &sb).await >= 3, "I75: A's keys reach B");
            assert!(deliver_keys(&sb, &sa).await >= 2, "I75: B's keys reach A");
            let a_on_b = FederationDirectory::lookup_public_key(sb.as_ref(), &a_key)
                .await
                .unwrap()
                .expect("A's key on B");
            assert!(
                a_on_b.pubkey_ml_dsa_65_base64.is_some(),
                "I75: A's key record on B carries the ML-DSA-65 pubkey (hybrid rows verify)"
            );
            // The community row (roster plane: the signed row, both sides).
            let community = ts::sign_community(
                &comm,
                crate::federation::types::Community {
                    community_key_id: comm.clone(),
                    community_name: "Delivered Co-op".into(),
                    members: [&alice, &bob]
                        .into_iter()
                        .map(|k| crate::federation::types::CommunityMember {
                            key_id: k.clone(),
                            joined_at: chrono::Utc::now(),
                            role: None,
                        })
                        .collect(),
                    founded_at: chrono::Utc::now(),
                    consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                        .to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            );
            sa.put_community(community.clone()).await.unwrap();
            sb.put_community(community).await.unwrap();
            // Bindings cross.
            deliver_attestations(&sa, &engine_b, &sb).await;
            deliver_attestations(&sb, &engine_a, &sa).await;
            // ── each node publishes its OWN occurrence (§20.3) ────────
            engine_a
                .publish_self_occurrence(
                    &alice,
                    crate::federation::types::device_class::SERVER,
                    None,
                )
                .await
                .expect("I75: A publishes its occurrence under alice");
            engine_b
                .publish_self_occurrence(&bob, crate::federation::types::device_class::SERVER, None)
                .await
                .expect("I75: B publishes its occurrence under bob");
            // Occurrences cross through the plane and the gated door.
            assert_eq!(
                deliver_occurrences(&sa, &sb).await,
                1,
                "I75: A's occurrence reaches B"
            );
            assert_eq!(
                deliver_occurrences(&sb, &sa).await,
                1,
                "I75: B's occurrence reaches A"
            );
            // ── A seals; B's node is IN the set ───────────────────────
            let r = engine_a
                .put_blob_scoped(COMMUNITY, Some(&comm), b"delivered minutes", None, None)
                .await
                .expect("A seals through the door");
            assert!(
                r.granted.contains(&b_key),
                "I75: the far member's node is in A's fan-out: {:?}",
                r.granted
            );
            assert!(r.key_grant_emission.is_some());
            let sha = r.at_rest_sha256;
            // The set crosses through the cursor to the Engine door.
            assert!(
                deliver_attestations(&sa, &engine_b, &sb).await >= 1,
                "I75: the set reaches B"
            );
            assert!(
                sb.community_dek_has_member_grant(&comm, &a_key, r.epoch.unwrap_or(0), &b_key)
                    .await
                    .unwrap(),
                "I75: B's own wrap is projected on B"
            );
            // The bytes cross (CIRISEdge#601's hook is the fetch; here the adopt).
            let Some(BlobBody::Inline(bytes)) = sa.get_blob(&sha).await.unwrap() else {
                panic!("inline")
            };
            engine_b
                .adopt_sealed_blob(
                    &bytes,
                    BlobProvenance {
                        author_key_id: a_key.clone(),
                        cohort_scope: COMMUNITY.into(),
                        community_key_id: Some(comm.clone()),
                        epoch: r.epoch,
                        tier: CryptoTier::CommunityDek,
                        minter_key_id: None,
                    },
                    None,
                    AdoptDisposition::LocalOnly,
                )
                .await
                .expect("B adopts");
            assert_eq!(
                engine_b
                    .read_blob_as(&sha, &b_key, None)
                    .await
                    .expect("I75: B's member opens — the mesh's red leg"),
                b"delivered minutes"
            );
        }

        /// **I82 (PR #852 round five) — `publish_self_occurrence` publishes
        /// only THIS node's key.** An Engine over a shared backend whose
        /// composed signer is one identity and whose LocalSigner is another
        /// (`from_shared_with_local`) is refused: the occurrence would name a
        /// key that is not the node.
        #[tokio::test]
        async fn i82_publish_self_occurrence_refuses_a_foreign_local_signer_sqlite() {
            use crate::federation::tier_ingest::test_support as ts;
            use std::sync::Arc;
            let backend = Arc::new(fresh().await);
            let node_local = ts::local_signer("i82-node");
            let foreign_local = ts::local_signer("i82-foreign");
            let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
                crate::signing::LocalSignerHardwareAdapter::new(node_local.clone()),
            );
            let engine = crate::Engine::from_shared_with_local(
                crate::engine::BackendDispatch::Sqlite(backend.clone()),
                signer,
                Some(foreign_local),
            );
            let err = engine
                .publish_self_occurrence(
                    "i82-owner",
                    crate::federation::types::device_class::SERVER,
                    None,
                )
                .await
                .expect_err("I82: a LocalSigner that is not the node's identity is refused");
            assert!(
                err.to_string().contains("not this node's identity"),
                "I82: the refusal names the mismatch: {err}"
            );
        }

        /// **I91 (§21.2, #855) — `valid_until` is one more bound member.**
        /// Stored at millisecond precision, carried in the envelope, admitted
        /// by the gate; `None` stores NULL; and a republish carrying the expiry
        /// KEEPS it — the republish that dropped an operator's expiry is the
        /// defect.
        #[tokio::test]
        async fn i91_publish_self_occurrence_carries_valid_until_sqlite() {
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::identity_type::USER;
            use crate::federation::{FederationDirectory, SignedAttestation};
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i91-node-{run}");
            let engine =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            engine
                .register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    &alias,
                    None,
                    serde_json::json!({}),
                    vec![],
                )
                .await
                .unwrap();
            let s = engine.sqlite_backend().unwrap().clone();
            let me = engine.local_derived_key_id().await.unwrap();
            let alice = format!("i91-alice-{run}");
            ts::register_identity_key(s.as_ref(), &alice, USER).await;
            // alice owns this node — the binding the lift resolves through.
            s.apply_replicated_attestation(SignedAttestation {
                attestation: ts::owner_binding_attestation(&format!("ob-{run}"), &alice, &me),
            })
            .await
            .unwrap();

            // A sub-millisecond instant: the door must truncate BEFORE signing,
            // or it signs one rendering and stores another.
            let until = chrono::DateTime::parse_from_rfc3339("2031-06-01T12:00:00.123456Z")
                .unwrap()
                .with_timezone(&chrono::Utc);
            let until_ms =
                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(until.timestamp_millis())
                    .unwrap();
            let server = crate::federation::types::device_class::SERVER;

            let signed = engine
                .publish_self_occurrence(&alice, server, Some(until))
                .await
                .expect("I91: publish with an expiry");
            assert_eq!(
                signed.identity_occurrence.valid_until,
                Some(until_ms),
                "I91: the typed row carries the expiry at ms precision"
            );
            assert_eq!(
                signed
                    .signed_envelope
                    .get("valid_until")
                    .and_then(|v| v.as_str()),
                Some(
                    until_ms
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                        .as_str()
                ),
                "I91: the envelope carries the SAME instant"
            );
            let stored = |s: &std::sync::Arc<SqliteBackend>| {
                let s = s.clone();
                let alice = alice.clone();
                let me = me.clone();
                async move {
                    FederationDirectory::list_identity_occurrences_for(s.as_ref(), &alice)
                        .await
                        .unwrap()
                        .into_iter()
                        .find(|o| o.occurrence_key_id == me)
                        .expect("I91: the node's occurrence is stored")
                        .valid_until
                }
            };
            assert_eq!(
                stored(&s).await,
                Some(until_ms),
                "I91: stored, not just returned"
            );
            // It is on the plane — the gate admitted the bound member.
            assert!(
                s.list_signed_identity_occurrences_since(None, 1_000)
                    .await
                    .unwrap()
                    .iter()
                    .any(|x| x.occurrence.identity_occurrence.valid_until == Some(until_ms)),
                "I91: the plane serves the row with its expiry"
            );

            // Republish WITH the expiry: it stays. This is the heal Edge needs.
            engine
                .publish_self_occurrence(&alice, server, Some(until_ms))
                .await
                .expect("I91: republish with the same expiry");
            assert_eq!(
                stored(&s).await,
                Some(until_ms),
                "I91: a republish keeps the expiry"
            );

            // And `None` stores NULL — the door does not invent an expiry.
            engine
                .publish_self_occurrence(&alice, server, None)
                .await
                .expect("I91: publish without an expiry");
            assert_eq!(stored(&s).await, None, "I91: None stores NULL");
        }

        /// **I92 (§21.3, #856) — the device occurrence's producer is
        /// `self_at_login`, and what it produces crosses the plane.** With
        /// the identity's signer, each pubkey-bearing occurrence is admitted
        /// through the GATED door: the stored row is signed-put, the plane
        /// advertises it, and a second node admits it through the same gate.
        /// Without the signer the rows are trusted-local and the plane does
        /// not list them — today's behaviour, unchanged.
        #[tokio::test]
        async fn i92_self_at_login_publishes_device_occurrences_through_the_gated_door_sqlite() {
            use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::identity_type::{AGENT, USER};
            use crate::federation::FederationDirectory;
            let run = uuid::Uuid::new_v4().simple().to_string();
            let (alias_a, alias_b) = (format!("i92-a-{run}"), format!("i92-b-{run}"));
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
                e.register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    alias,
                    None,
                    serde_json::json!({}),
                    vec![],
                )
                .await
                .unwrap();
            }
            let (sa, sb) = (
                engine_a.sqlite_backend().unwrap().clone(),
                engine_b.sqlite_backend().unwrap().clone(),
            );
            // The identity: registered on BOTH nodes under its DERIVED id with
            // the label's real pubkeys, because the far node verifies the
            // identity's signature over the occurrence.
            let identity_label = format!("i92-alice-{run}");
            let identity_signer = ts::local_signer(&identity_label);
            let identity = identity_signer.derived_key_id();
            for s in [&sa, &sb] {
                ts::register_hybrid_key_as(s.as_ref(), &identity, &identity_label, USER).await;
            }
            // The device keys, on both nodes (the occurrence names them).
            let (app_key, agent_key) = (format!("i92-app-{run}"), format!("i92-agent-{run}"));
            for s in [&sa, &sb] {
                ts::register_hybrid_key_as(s.as_ref(), &app_key, &app_key, USER).await;
                ts::register_hybrid_key_as(s.as_ref(), &agent_key, &agent_key, AGENT).await;
            }
            let mk_keys = || {
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                let (_xp, x_pub, _mp, ml_pub) =
                    crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
                crate::federation::EncryptionPubkeys {
                    x25519_base64: B64.encode(x_pub),
                    ml_kem_768_base64: B64.encode(ml_pub),
                }
            };
            let input =
                |signer: Option<std::sync::Arc<crate::signing::LocalSigner>>| SelfAtLoginInput {
                    identity_key_id: identity.clone(),
                    identity_signer: signer,
                    app: SelfAtLoginOccurrence {
                        occurrence_key_id: app_key.clone(),
                        device_class: crate::federation::types::device_class::PHONE.to_owned(),
                        // The producer's Some(..) path: a bound member the
                        // node's own occurrence never exercises.
                        hardware_attestation: Some("hw-attest-i92".to_owned()),
                        encryption_pubkeys: Some(mk_keys()),
                        transport_destinations: vec![],
                    },
                    agent: SelfAtLoginOccurrence {
                        occurrence_key_id: agent_key.clone(),
                        device_class: crate::federation::types::device_class::AGENT.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: Some(mk_keys()),
                        transport_destinations: vec![],
                    },
                    bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                    delegation_scope: None,
                };

            // ── leg 1: with the signer, the rows are ON THE PLANE ─────────
            let outcome = engine_a
                .self_at_login(input(Some(identity_signer.clone())))
                .await
                .expect("I92: self_at_login with the identity's signer");
            assert_eq!(
                outcome.occurrences_published.len(),
                2,
                "I92: both pubkey-bearing occurrences were published: {outcome:?}"
            );
            assert!(outcome.occurrences_local_only.is_empty(), "{outcome:?}");
            let on_plane: Vec<String> = sa
                .list_signed_identity_occurrences_since(None, 1_000)
                .await
                .unwrap()
                .into_iter()
                .map(|s| s.occurrence.identity_occurrence.occurrence_key_id)
                .collect();
            assert!(
                on_plane.contains(&app_key) && on_plane.contains(&agent_key),
                "I92: the plane advertises BOTH device occurrences: {on_plane:?}"
            );
            // The far node admits them through the SAME gate — the identity's
            // signature verifies against the identity's key, no lift needed.
            let mut delivered = 0;
            for served in sa
                .list_signed_identity_occurrences_since(None, 1_000)
                .await
                .unwrap()
            {
                let occ = served.occurrence;
                let k = occ.identity_occurrence.occurrence_key_id.clone();
                if k != app_key && k != agent_key {
                    continue;
                }
                sb.put_identity_occurrence(occ)
                    .await
                    .unwrap_or_else(|e| panic!("I92: B admits {k} through the gated door: {e}"));
                delivered += 1;
            }
            assert_eq!(delivered, 2, "I92: both crossed");
            let far: Vec<String> =
                FederationDirectory::list_identity_occurrences_for(sb.as_ref(), &identity)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|o| o.occurrence_key_id)
                    .collect();
            assert!(
                far.contains(&app_key) && far.contains(&agent_key),
                "I92: on B: {far:?}"
            );
            // The hardware attestation crossed as a BOUND member: the far row
            // carries the string the producer rendered into the envelope.
            let far_app =
                FederationDirectory::list_identity_occurrences_for(sb.as_ref(), &identity)
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|o| o.occurrence_key_id == app_key)
                    .expect("I92: the app row on B");
            assert_eq!(
                far_app.hardware_attestation.as_deref(),
                Some("hw-attest-i92"),
                "I92: hardware_attestation is bound into the envelope and crosses intact"
            );

            // ── leg 2: WITHOUT the signer, trusted-local, not on the plane ──
            let engine_c = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&format!("i92-c-{run}")),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            engine_c
                .register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    &format!("i92-c-{run}"),
                    None,
                    serde_json::json!({}),
                    vec![],
                )
                .await
                .unwrap();
            let sc = engine_c.sqlite_backend().unwrap().clone();
            ts::register_hybrid_key_as(sc.as_ref(), &identity, &identity_label, USER).await;
            ts::register_hybrid_key_as(sc.as_ref(), &app_key, &app_key, USER).await;
            ts::register_hybrid_key_as(sc.as_ref(), &agent_key, &agent_key, AGENT).await;
            let outcome_c = engine_c
                .self_at_login(input(None))
                .await
                .expect("I92: self_at_login without a signer still lands (local)");
            assert!(outcome_c.occurrences_published.is_empty(), "{outcome_c:?}");
            assert_eq!(outcome_c.occurrences_local_only.len(), 2, "{outcome_c:?}");
            let plane_c: Vec<String> = sc
                .list_signed_identity_occurrences_since(None, 1_000)
                .await
                .unwrap()
                .into_iter()
                .map(|s| s.occurrence.identity_occurrence.occurrence_key_id)
                .collect();
            assert!(
                !plane_c.contains(&app_key) && !plane_c.contains(&agent_key),
                "I92: a trusted-local row is never on the plane: {plane_c:?}"
            );
            // But they ARE stored locally, so the node's own cascade sees them.
            let local_c =
                FederationDirectory::list_identity_occurrences_for(sc.as_ref(), &identity)
                    .await
                    .unwrap();
            assert_eq!(local_c.len(), 2, "I92: stored locally");
        }

        /// **I92 (b) — an occurrence with no `encryption_pubkeys` has no
        /// replicable form.** It is written trusted-local even when the signer
        /// is present, login does NOT fail for it, and the outcome names it.
        #[tokio::test]
        async fn i92b_a_pubkey_less_occurrence_stays_local_and_is_named_sqlite() {
            use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::identity_type::{AGENT, USER};
            use crate::federation::FederationDirectory;
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i92b-{run}");
            let engine =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            engine
                .register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    &alias,
                    None,
                    serde_json::json!({}),
                    vec![],
                )
                .await
                .unwrap();
            let s = engine.sqlite_backend().unwrap().clone();
            let identity_label = format!("i92b-alice-{run}");
            let identity_signer = ts::local_signer(&identity_label);
            let identity = identity_signer.derived_key_id();
            ts::register_hybrid_key_as(s.as_ref(), &identity, &identity_label, USER).await;
            let (app_key, agent_key) = (format!("i92b-app-{run}"), format!("i92b-agent-{run}"));
            ts::register_hybrid_key_as(s.as_ref(), &app_key, &app_key, USER).await;
            ts::register_hybrid_key_as(s.as_ref(), &agent_key, &agent_key, AGENT).await;
            let keys = {
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                let (_xp, x_pub, _mp, ml_pub) =
                    crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
                crate::federation::EncryptionPubkeys {
                    x25519_base64: B64.encode(x_pub),
                    ml_kem_768_base64: B64.encode(ml_pub),
                }
            };
            let outcome = engine
                .self_at_login(SelfAtLoginInput {
                    identity_key_id: identity.clone(),
                    identity_signer: Some(identity_signer),
                    app: SelfAtLoginOccurrence {
                        occurrence_key_id: app_key.clone(),
                        device_class: crate::federation::types::device_class::PHONE.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: Some(keys),
                        transport_destinations: vec![],
                    },
                    agent: SelfAtLoginOccurrence {
                        occurrence_key_id: agent_key.clone(),
                        device_class: crate::federation::types::device_class::AGENT.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: None, // ← no replicable form
                        transport_destinations: vec![],
                    },
                    bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                    delegation_scope: None,
                })
                .await
                .expect("I92 (b): login does not fail for a row that cannot replicate");
            assert_eq!(
                outcome.occurrences_published,
                vec![app_key.clone()],
                "{outcome:?}"
            );
            assert_eq!(
                outcome.occurrences_local_only,
                vec![agent_key.clone()],
                "{outcome:?}"
            );
            let plane: Vec<String> = s
                .list_signed_identity_occurrences_since(None, 1_000)
                .await
                .unwrap()
                .into_iter()
                .map(|x| x.occurrence.identity_occurrence.occurrence_key_id)
                .collect();
            assert!(plane.contains(&app_key), "I92 (b): the app is on the plane");
            assert!(
                !plane.contains(&agent_key),
                "I92 (b): the pubkey-less agent is NOT"
            );
        }

        /// **I93 — a signer that is not the identity refuses BEFORE any
        /// occurrence is written.** The check existed (step 5); step 1 now
        /// signs with the signer, so the check moves ahead of it.
        #[tokio::test]
        async fn i93_a_foreign_identity_signer_refuses_before_any_occurrence_is_written_sqlite() {
            use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::identity_type::{AGENT, USER};
            use crate::federation::FederationDirectory;
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i93-{run}");
            let engine =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            engine
                .register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    &alias,
                    None,
                    serde_json::json!({}),
                    vec![],
                )
                .await
                .unwrap();
            let s = engine.sqlite_backend().unwrap().clone();
            let identity_label = format!("i93-alice-{run}");
            let identity = ts::local_signer(&identity_label).derived_key_id();
            ts::register_hybrid_key_as(s.as_ref(), &identity, &identity_label, USER).await;
            let (app_key, agent_key) = (format!("i93-app-{run}"), format!("i93-agent-{run}"));
            ts::register_hybrid_key_as(s.as_ref(), &app_key, &app_key, USER).await;
            ts::register_hybrid_key_as(s.as_ref(), &agent_key, &agent_key, AGENT).await;
            let foreign = ts::local_signer(&format!("i93-mallory-{run}"));
            let err = engine
                .self_at_login(SelfAtLoginInput {
                    identity_key_id: identity.clone(),
                    identity_signer: Some(foreign),
                    app: SelfAtLoginOccurrence {
                        occurrence_key_id: app_key.clone(),
                        device_class: crate::federation::types::device_class::PHONE.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: None,
                        transport_destinations: vec![],
                    },
                    agent: SelfAtLoginOccurrence {
                        occurrence_key_id: agent_key.clone(),
                        device_class: crate::federation::types::device_class::AGENT.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: None,
                        transport_destinations: vec![],
                    },
                    bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                    delegation_scope: None,
                })
                .await
                .expect_err("I93: a foreign signer is refused");
            assert!(
                matches!(err, crate::federation::Error::CustodyIsNotTheActor { .. }),
                "I93: the existing refusal, now first: {err:?}"
            );
            // NOTHING was written — the refusal precedes step 1.
            let rows = FederationDirectory::list_identity_occurrences_for(s.as_ref(), &identity)
                .await
                .unwrap();
            assert!(
                rows.is_empty(),
                "I93: no occurrence written before the refusal: {rows:?}"
            );
        }

        /// **I74 — the ledger stamps the WATERMARK, never the clock** (PR
        /// #850, round three). A grant that lands after the emitted set was
        /// built is newer than the mark and keeps the axis dirty; a mark at
        /// the newest grant cleans it; the mark never moves backwards.
        #[tokio::test]
        async fn i74_ledger_mark_is_the_snapshot_watermark_sqlite() {
            use crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2;
            use crate::federation::{BlobStorage, GrantWrap};
            let sq = fresh().await;
            let (comm, me) = ("i74-comm", "i74-me");
            sq.community_dek_put_self_retention(comm, me, 0, "{}")
                .await
                .unwrap();
            let wrap = |r: &str| GrantWrap {
                recipient_key_id: r.into(),
                wrap_algorithm: WRAP_ALGORITHM_V2.into(),
                wrapped_dek: "{}".into(),
            };
            sq.community_dek_put_member_grants(comm, me, 0, &[wrap("r1")])
                .await
                .unwrap();
            let w1 = sq
                .community_dek_key_grant_watermark(comm, me, 0)
                .await
                .unwrap()
                .expect("a grant exists");
            assert!(sq.community_dek_key_grant_dirty(comm, me, 0).await.unwrap());
            // The concurrent grant: lands AFTER the snapshot's watermark.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            sq.community_dek_put_member_grants(comm, me, 0, &[wrap("r2")])
                .await
                .unwrap();
            // Mark at the SNAPSHOT's watermark (what the emitter read): still
            // dirty — r2 was not in the emitted set.
            sq.community_dek_mark_key_grant_emitted(comm, me, 0, w1)
                .await
                .unwrap();
            assert!(
                sq.community_dek_key_grant_dirty(comm, me, 0).await.unwrap(),
                "I74: a grant newer than the emitted snapshot keeps the axis dirty"
            );
            // Mark at the NEW watermark (a later emission that carried r2): clean.
            let w2 = sq
                .community_dek_key_grant_watermark(comm, me, 0)
                .await
                .unwrap()
                .unwrap();
            assert!(w2 > w1);
            sq.community_dek_mark_key_grant_emitted(comm, me, 0, w2)
                .await
                .unwrap();
            assert!(!sq.community_dek_key_grant_dirty(comm, me, 0).await.unwrap());
            // Never backwards: an older mark does not re-dirty.
            sq.community_dek_mark_key_grant_emitted(comm, me, 0, w1)
                .await
                .unwrap();
            assert!(!sq.community_dek_key_grant_dirty(comm, me, 0).await.unwrap());
        }

        /// **I70 — the emission ledger (V146): a door that died between its
        /// cascade and its emission is repaired by the next door, and by the
        /// boot sweep** (PR #850 review). The cascade is driven directly on the
        /// engine's backend — the exact state a crash leaves: DEK and wraps
        /// durable, no set on the cursor.
        #[tokio::test]
        async fn i70_emission_ledger_repairs_a_missed_emission_sqlite() {
            use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
            use crate::federation::key_grant::KEY_GRANT_EPOCH_ATTESTATION_TYPE;
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::cohort_scope::COMMUNITY;
            use crate::federation::types::identity_type::USER;
            use crate::federation::{BlobStorage, EncryptionPubkeys, FederationDirectory};
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i70-node-{run}");
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
            // A community of me (occurrence: this node) and a member whose
            // occurrence lives elsewhere (a second in-memory identity).
            let other = fresh().await;
            let member_occ = format!("i70-member-occ-{run}");
            ts::register_hybrid_key_as(sq.as_ref(), &member_occ, &member_occ, USER).await;
            let node = Node {
                backend: sq.as_ref(),
                signer: ts::local_signer(&alias),
                key: me.clone(),
                kem: kem(sq.load_or_init_content_kem_identity().await.unwrap()),
            };
            let comm = format!("i70-comm-{run}");
            let (alice, bob) = (format!("i70-alice-{run}"), format!("i70-bob-{run}"));
            seed_community_everywhere(&[&node], &comm, &[(&alice, Some(&node)), (&bob, None)])
                .await;
            sq.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: bob.clone(),
                occurrence_key_id: member_occ.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(kem(other
                    .load_or_init_content_kem_identity()
                    .await
                    .unwrap())),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
            let epoch_sets = |sq: std::sync::Arc<SqliteBackend>, me: String| async move {
                sq.list_attestations_by(&me)
                    .await
                    .unwrap()
                    .into_iter()
                    .filter(|r| r.attestation_type == KEY_GRANT_EPOCH_ATTESTATION_TYPE)
                    .count()
            };
            // (1) The crash shape: the cascade ran, no door emitted.
            let sealed =
                encrypt_and_cascade_community(sq.as_ref(), &comm, b"minutes", None, Some(&me))
                    .await
                    .unwrap();
            assert!(sealed.granted.contains(&member_occ));
            assert_eq!(
                epoch_sets(sq.clone(), me.clone()).await,
                0,
                "I70: nothing carried"
            );
            assert!(
                sq.community_dek_key_grant_dirty(&comm, &me, sealed.epoch)
                    .await
                    .unwrap(),
                "I70: the epoch's set is DIRTY"
            );
            // (2) The next door — fan-out unchanged — emits anyway.
            let r = engine
                .put_blob_scoped(COMMUNITY, Some(&comm), b"next", None, None)
                .await
                .unwrap();
            assert!(
                r.key_grant_emission.is_some(),
                "I70: the dirty epoch reports an emission"
            );
            assert_eq!(
                epoch_sets(sq.clone(), me.clone()).await,
                1,
                "I70: the set is on the cursor"
            );
            assert!(!sq
                .community_dek_key_grant_dirty(&comm, &me, sealed.epoch)
                .await
                .unwrap());
            // (3) Clean: a further unchanged write emits nothing more.
            let r2 = engine
                .put_blob_scoped(COMMUNITY, Some(&comm), b"again", None, None)
                .await
                .unwrap();
            assert!(
                r2.key_grant_emission.is_none(),
                "I70: clean epoch, no emission"
            );
            assert_eq!(epoch_sets(sq.clone(), me.clone()).await, 1);
            // (4) The boot sweep on a fresh community left dirty by a "crash".
            let comm2 = format!("i70-comm2-{run}");
            // Seeded by hand: alice (this node's identity) is already
            // registered — one occurrence, one identity — and joins a second
            // community with bob2.
            let bob2 = format!("i70-bob2-{run}");
            let member_occ2 = format!("i70-member-occ2-{run}");
            for k in [&comm2, &bob2, &member_occ2] {
                ts::register_hybrid_key_as(sq.as_ref(), k, k, USER).await;
            }
            sq.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: bob2.clone(),
                occurrence_key_id: member_occ2.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(kem(other
                    .load_or_init_content_kem_identity()
                    .await
                    .unwrap())),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
            let roster = [&alice, &bob2]
                .into_iter()
                .map(|k| crate::federation::types::CommunityMember {
                    key_id: k.clone(),
                    joined_at: chrono::Utc::now(),
                    role: None,
                })
                .collect();
            sq.put_community(ts::sign_community(
                &comm2,
                crate::federation::types::Community {
                    community_key_id: comm2.clone(),
                    community_name: "Second Co-op".into(),
                    members: roster,
                    founded_at: chrono::Utc::now(),
                    consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                        .to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap();
            encrypt_and_cascade_community(sq.as_ref(), &comm2, b"crashed", None, Some(&me))
                .await
                .unwrap();
            assert_eq!(
                engine.emit_pending_key_grants().await.unwrap(),
                1,
                "I70: the sweep emits the dirty epoch"
            );
            assert_eq!(epoch_sets(sq.clone(), me.clone()).await, 2);
            assert_eq!(
                engine.emit_pending_key_grants().await.unwrap(),
                0,
                "I70: nothing left to emit"
            );
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
                        minter_key_id: None,
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
        async fn i76_content_only_occurrence_postgres() {
            let Some(bn) = fresh().await else {
                eprintln!("no postgres — skipped");
                return;
            };
            let n = node_as(&bn, "i76-n", crate::federation::types::identity_type::NODE).await;
            exercise_i76_content_only_occurrence(&n, "i76-n", "postgres").await;
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
        async fn i77_owned_node_minter_admitted_by_principal_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i77-a").await;
            let b = node(&bb, "i77-b").await;
            introduce_as(
                &[&a, &b],
                &["i77-a", "i77-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i77_owned_node_minter_admitted_by_principal(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i71_rotation_keys_on_effective_at_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i71-a").await;
            let b = node(&bb, "i71-b").await;
            introduce(&[&a, &b], &["i71-a", "i71-b"]).await;
            exercise_i71_rotation_keys_on_effective_at(&a, &b, "postgres").await;
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
