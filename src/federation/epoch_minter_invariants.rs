//! CIRISPersist#876 — witnesses for `FSD/EPOCH_MINTER.md` §5 (I126–I130):
//! the minter of `(community, epoch)` is NAMED or DERIVED, never inferred
//! from the row's author.
//!
//! **The fixture is the point.** Every pre-v46 witness on this plane has
//! `author == sealer` — a node authoring its own content — which is exactly
//! why the bug shipped. The ladder here is the product shape: a row
//! attested by A's OWNER (a person), sealed by A's NODE, carried to B.

#![cfg(any(feature = "sqlite", feature = "postgres"))]

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::key_grant::SignedKeyGrantSet;
    use crate::federation::key_grant_invariants::two_node::{
        introduce, seed_community_everywhere, Node,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
    use crate::federation::types::identity_type::USER;
    use crate::federation::{
        AdoptDisposition, BlobBody, BlobError, BlobProvenance, BlobStorage, EncryptionPubkeys,
        FederationDirectory,
    };
    use crate::Engine;
    use std::sync::Arc;

    /// How a body reaches the typed backend under an `Engine` — the one
    /// difference between the sqlite and postgres runs.
    pub(crate) type Pick<B> = fn(&Engine) -> Arc<B>;

    /// The two engines, introduced, with a community whose members are two
    /// PERSONS — `alice` occurring through node A, `bob` through node B.
    /// Returns `(engine_a, engine_b, node_a_key, node_b_key, alice, comm)`.
    pub(crate) struct Ladder<B> {
        pub engine_a: Engine,
        pub engine_b: Engine,
        /// A's backend, and B's — typed, so one body runs on both stores.
        pub ba: Arc<B>,
        pub bb: Arc<B>,
        pub node_a: String,
        pub node_b: String,
        /// A's OWNER: the person who attests A's rows. NOT the sealer.
        pub alice: String,
        pub comm: String,
    }

    pub(crate) async fn ladder<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>) -> Ladder<B>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (alias_a, alias_b) = (format!("em-a-{run}"), format!("em-b-{run}"));
        let engine_a = Engine::with_signer_pre_genesis(ts::local_signer(&alias_a), dsn_a)
            .await
            .unwrap();
        let engine_b = Engine::with_signer_pre_genesis(ts::local_signer(&alias_b), dsn_b)
            .await
            .unwrap();
        for (e, alias) in [(&engine_a, &alias_a), (&engine_b, &alias_b)] {
            e.register_self_federation_key(USER, alias, None, serde_json::json!({}), vec![])
                .await
                .expect("register the engine's own key");
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
        introduce(&[&a, &b], &[&alias_a, &alias_b]).await;
        let comm = format!("em-comm-{run}");
        let (alice, bob) = (format!("em-alice-{run}"), format!("em-bob-{run}"));
        seed_community_everywhere(&[&a, &b], &comm, &[(&alice, Some(&a)), (&bob, Some(&b))]).await;
        let (node_a, node_b) = (a.key.clone(), b.key.clone());
        Ladder {
            engine_a,
            engine_b,
            ba: sa,
            bb: sb,
            node_a,
            node_b,
            alice,
            comm,
        }
    }

    /// A's seal through the production door, and the epoch set it emitted.
    async fn seal_and_set<B>(
        l: &Ladder<B>,
        plaintext: &[u8],
    ) -> ([u8; 32], Vec<u8>, SignedKeyGrantSet)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let r = l
            .engine_a
            .put_blob_scoped(COMMUNITY, Some(&l.comm), plaintext, None, None)
            .await
            .expect("A's scoped put");
        assert_eq!(r.tier, CryptoTier::CommunityDek);
        let sha = r.at_rest_sha256;
        let sa = l.ba.clone();
        let emitted: Vec<_> = sa
            .list_attestations_by(&l.node_a)
            .await
            .unwrap()
            .into_iter()
            .filter(|x| {
                x.attestation_type == crate::federation::key_grant::KEY_GRANT_EPOCH_ATTESTATION_TYPE
            })
            .collect();
        assert_eq!(emitted.len(), 1, "one epoch-axis set, signed by the NODE");
        let Some(BlobBody::Inline(bytes)) = sa.get_blob(&sha).await.unwrap() else {
            panic!("inline")
        };
        (
            sha,
            bytes,
            SignedKeyGrantSet {
                attestation: emitted[0].clone(),
            },
        )
    }

    /// The provenance a chat row produces: authored by the PERSON.
    fn person_authored<B>(l: &Ladder<B>, minter: Option<&str>) -> BlobProvenance {
        BlobProvenance {
            author_key_id: l.alice.clone(),
            cohort_scope: COMMUNITY.into(),
            community_key_id: Some(l.comm.clone()),
            epoch: Some(0),
            tier: CryptoTier::CommunityDek,
            minter_key_id: minter.map(str::to_owned),
        }
    }

    /// **I126 — the ladder, author ≠ sealer.** A row attested by A's OWNER
    /// and sealed by A's NODE opens on B; the recorded binding names the
    /// NODE. Without the set carried, it still refuses.
    pub(crate) async fn i126_author_is_not_the_sealer<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, bytes, set) = seal_and_set(&l, b"chat body").await;
        assert_ne!(l.alice, l.node_a, "I126: the fixture's whole point");

        // (a) bytes with no key set: still NotGranted — the fix admits nothing.
        let l2 = ladder(dsn_a, dsn_b, &format!("{run}x"), pick).await;
        let (sha2, bytes2, _) = seal_and_set(&l2, b"unkeyed").await;
        l2.engine_b
            .adopt_sealed_blob(
                &bytes2,
                person_authored(&l2, None),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("I126: the adopt itself succeeds");
        let err = l2
            .engine_b
            .read_blob_as(&sha2, &l2.node_b, None)
            .await
            .expect_err("I126: no key set carried, no read");
        assert!(matches!(err, BlobError::NotGranted { .. }), "I126: {err}");

        // (b) the product path: set carried, then the bytes.
        let admission = l
            .engine_b
            .apply_replicated_key_grant(set)
            .await
            .expect("B admits A's set");
        assert!(admission.wraps_written >= 1);
        l.engine_b
            .adopt_sealed_blob(
                &bytes,
                person_authored(&l, None),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("B adopts");
        assert_eq!(
            l.engine_b
                .read_blob_as(&sha, &l.node_b, None)
                .await
                .expect("I126: the body OPENS for B's node key"),
            b"chat body"
        );
        let (_c, minter, _e) =
            l.bb.community_dek_blob_epoch(&sha)
                .await
                .unwrap()
                .expect("I126: the binding exists");
        assert_eq!(
            minter, l.node_a,
            "I126: the binding names the SEALER, not the author"
        );
    }

    /// **I127 — explicit wins, and an empty one is refused by member.**
    pub(crate) async fn i127_explicit_minter_wins<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, bytes, set) = seal_and_set(&l, b"explicit").await;
        l.engine_b.apply_replicated_key_grant(set).await.unwrap();
        let err = l
            .engine_b
            .adopt_sealed_blob(
                &bytes,
                person_authored(&l, Some("")),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect_err("I127: an empty minter is not a minter");
        assert!(
            err.to_string().contains("minter_key_id"),
            "I127: refused by member: {err}"
        );
        l.engine_b
            .adopt_sealed_blob(
                &bytes,
                person_authored(&l, Some(&l.node_a)),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("I127: the named minter is admitted");
        let (_c, minter, _e) = l.bb.community_dek_blob_epoch(&sha).await.unwrap().unwrap();
        assert_eq!(minter, l.node_a, "I127: the NAMED minter is recorded");
        assert_eq!(
            l.engine_b
                .read_blob_as(&sha, &l.node_b, None)
                .await
                .unwrap(),
            b"explicit"
        );
    }

    /// **I128 — derivation answers from ONE admitted set, and declines to
    /// guess between two.**
    pub(crate) async fn i128_derivation_and_its_limit<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (_sha, _bytes, set) = seal_and_set(&l, b"derived").await;
        l.engine_b.apply_replicated_key_grant(set).await.unwrap();
        let b = l.bb.clone();
        assert_eq!(
            b.community_dek_minters_granting(&l.comm, 0, &l.node_b)
                .await
                .unwrap(),
            vec![l.node_a.clone()],
            "I128: exactly one admitted set names the minter"
        );
        assert_eq!(
            crate::federation::epoch_minter::resolve(
                b.as_ref(),
                None,
                &l.comm,
                0,
                &l.node_b,
                &l.alice,
            )
            .await
            .unwrap(),
            l.node_a,
            "I128: an unnamed provenance derives the sealer"
        );
        // A set that granted only a THIRD PARTY is not a minter THIS node can
        // derive from: the derivation asks "who granted ME a wrap", and a
        // wrap addressed to someone else proves nothing about our own.
        let elsewhere = format!("em-elsewhere-{run}");
        let third = format!("em-third-{run}");
        for k in [&elsewhere, &third] {
            ts::register_identity_key(b.as_ref(), k, USER).await;
        }
        b.as_ref()
            .community_dek_put_member_grant(
                &l.comm,
                &elsewhere,
                0,
                &third,
                crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2,
                "dGhpcmQ",
            )
            .await
            .unwrap();
        assert_eq!(
            b.community_dek_minters_granting(&l.comm, 0, &l.node_b)
                .await
                .unwrap(),
            vec![l.node_a.clone()],
            "I128: a set that granted only a third party is not ours to derive from"
        );
        assert_eq!(
            crate::federation::epoch_minter::resolve(
                b.as_ref(),
                None,
                &l.comm,
                0,
                &l.node_b,
                &l.alice,
            )
            .await
            .unwrap(),
            l.node_a,
            "I128: and the derivation still answers the one that granted US"
        );

        // A second minter at the same (community, epoch): no guess.
        let other = format!("em-other-{run}");
        ts::register_identity_key(b.as_ref(), &other, USER).await;
        b.as_ref()
            .community_dek_put_member_grant(
                &l.comm,
                &other,
                0,
                &l.node_b,
                crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2,
                "d3JhcA",
            )
            .await
            .unwrap();
        let mut minters = b
            .community_dek_minters_granting(&l.comm, 0, &l.node_b)
            .await
            .unwrap();
        minters.sort();
        assert_eq!(minters.len(), 2, "I128: two minters now grant this node");
        assert_eq!(
            crate::federation::epoch_minter::resolve(
                b.as_ref(),
                None,
                &l.comm,
                0,
                &l.node_b,
                &l.alice,
            )
            .await
            .unwrap(),
            l.alice,
            "I128: ambiguous derivation falls back to the author, never guesses"
        );
        assert_eq!(
            crate::federation::epoch_minter::resolve(
                b.as_ref(),
                Some(&l.node_a),
                &l.comm,
                0,
                &l.node_b,
                &l.alice,
            )
            .await
            .unwrap(),
            l.node_a,
            "I128: naming it is the way through the ambiguity"
        );
    }

    /// **I129 — repair: bytes before the key set rebind when it lands; a
    /// binding whose minter holds state is never touched.**
    pub(crate) async fn i129_a_stranded_binding_rebinds<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, bytes, set) = seal_and_set(&l, b"out of order").await;
        // The bytes arrive FIRST: nothing to derive from, so the author is
        // recorded — the pre-v46 answer, and stranded.
        l.engine_b
            .adopt_sealed_blob(
                &bytes,
                person_authored(&l, None),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("B adopts before the set");
        let b = l.bb.clone();
        let (_c, minter, _e) = b.community_dek_blob_epoch(&sha).await.unwrap().unwrap();
        assert_eq!(minter, l.alice, "I129: stranded on the author, as expected");
        assert!(l
            .engine_b
            .read_blob_as(&sha, &l.node_b, None)
            .await
            .is_err());
        // The set lands: the stranded binding rebinds and the body opens.
        l.engine_b.apply_replicated_key_grant(set).await.unwrap();
        let (_c, minter, _e) = b.community_dek_blob_epoch(&sha).await.unwrap().unwrap();
        assert_eq!(minter, l.node_a, "I129: rebound to the set's minter");
        assert_eq!(
            l.engine_b
                .read_blob_as(&sha, &l.node_b, None)
                .await
                .unwrap(),
            b"out of order"
        );
        // The OTHER half of "stranded", on its own: DEK STATE with NO member
        // grant. Reachable in production when a community's other members
        // hold no encryption pubkeys — the cascade mints, self-retains and
        // wraps to nobody (#843's fail-secure exclusion) — and the binding
        // is then protected by the DEK check ALONE. Built with the doors
        // that write exactly that state, and probed toward an INTERLOPER so
        // the guard is what has to hold (rebinding toward the row's own
        // minter is excluded by `minter <> new` and witnesses nothing).
        let ba = l.ba.clone();
        let keyless = format!("em-keyless-{run}");
        ts::register_identity_key(ba.as_ref(), &keyless, USER).await;
        assert!(
            ba.community_dek_minters_granting(&l.comm, 0, &keyless)
                .await
                .unwrap()
                .is_empty(),
            "I129: this minter wrapped to nobody — no grant row exists"
        );
        let (sha_k, bytes_k, _set_k) = seal_and_set(&l, b"keyless-minter").await;
        let bb = l.bb.clone();
        bb.community_dek_put_self_retention(&l.comm, &keyless, 0, "c2VsZg")
            .await
            .expect("the minter self-retains its DEK");
        l.engine_b
            .adopt_sealed_blob(
                &bytes_k,
                person_authored(&l, Some(&keyless)),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("B adopts naming the keyless minter");
        let interloper = format!("em-interloper-{run}");
        let stolen = bb
            .rebind_stranded_blob_epochs(&l.comm, &interloper, 0)
            .await
            .unwrap();
        assert_eq!(
            stolen, 0,
            "I129: DEK state with no grants is BOUND — the repair must not steal it"
        );
        assert_eq!(
            bb.community_dek_blob_epoch(&sha_k)
                .await
                .unwrap()
                .unwrap()
                .1,
            keyless,
            "I129: and that binding is untouched"
        );

        // A correct binding is NOT rebound by a later set from elsewhere.
        let l2 = ladder(dsn_a, dsn_b, &format!("{run}y"), pick).await;
        let (sha2, bytes2, set2) = seal_and_set(&l2, b"already right").await;
        l2.engine_b.apply_replicated_key_grant(set2).await.unwrap();
        l2.engine_b
            .adopt_sealed_blob(
                &bytes2,
                person_authored(&l2, Some(&l2.node_a)),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .unwrap();
        let before = l2
            .bb
            .community_dek_blob_epoch(&sha2)
            .await
            .unwrap()
            .unwrap();
        // Toward an INTERLOPER: the row names node_a, which holds a GRANT
        // here (B admitted A's set) but no DEK state, so the grants guard is
        // the only thing between this binding and the interloper.
        let interloper2 = format!("em-interloper2-{run}");
        let count = l2
            .bb
            .rebind_stranded_blob_epochs(&l2.comm, &interloper2, 0)
            .await
            .unwrap();
        assert_eq!(
            count, 0,
            "I129: a minter that HOLDS A GRANT is bound — an interloper does not take it"
        );
        assert_eq!(
            l2.bb
                .community_dek_blob_epoch(&sha2)
                .await
                .unwrap()
                .unwrap(),
            before,
            "I129: and it is left exactly as it was"
        );
    }

    /// The source lines that are not comments, `//` tails removed. A
    /// commented-out call is not a call, and a comment QUOTING the old
    /// spelling is not the old spelling — #871's M27 taught this grep the
    /// hard way.
    fn live_lines(text: &str) -> impl Iterator<Item = &str> {
        text.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .filter(|l| !l.trim().is_empty())
    }

    /// **I131 — the row IS the provenance.** `BLOB_REPLICATION.md` §5 puts
    /// provenance on the referencing attestation;
    /// [`BlobProvenance::from_attestation`] is that sentence as code. The
    /// product shape: a row attested by the PERSON, naming its community in
    /// the signed envelope, citing the sealed bytes in `evidence_refs`. The
    /// adopt takes the provenance READ OFF that row — no member is
    /// transcribed by hand, which is how #876 was written in the first
    /// place — and the body opens.
    pub(crate) async fn i131_the_row_is_the_provenance<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::media_source_invariants::bodies::row as fixture_row;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, bytes, set) = seal_and_set(&l, b"row-derived").await;
        let sha_hex = hex::encode(sha);
        // The referencing row: ATTESTED BY THE PERSON, naming the community,
        // citing the bytes.
        let referencing = fixture_row(
            &format!("em-row-{run}"),
            &l.alice,
            &l.alice,
            serde_json::json!({
                "dimension": "external_content:image:v1",
                "evidence_refs": [sha_hex],
                "community_key_id": l.comm,
            }),
            COMMUNITY,
        );
        let p = BlobProvenance::from_attestation(&referencing, &sha, Some(0), None)
            .expect("I131: the row answers every member persist can know");
        assert_eq!(p.author_key_id, l.alice, "I131: the author is the attester");
        assert_eq!(p.community_key_id.as_deref(), Some(l.comm.as_str()));
        assert_eq!(
            p.tier,
            CryptoTier::CommunityDek,
            "I131: the tier is resolved, not declared"
        );
        assert!(
            p.minter_key_id.is_none(),
            "I131: the minter is a key-plane fact, not a row one"
        );
        // A row that does not cite these bytes is not the row they flowed from.
        let other = fixture_row(
            &format!("em-row-other-{run}"),
            &l.alice,
            &l.alice,
            serde_json::json!({
                "dimension": "external_content:image:v1",
                "evidence_refs": ["ab".repeat(32)],
                "community_key_id": l.comm,
            }),
            COMMUNITY,
        );
        let err = BlobProvenance::from_attestation(&other, &sha, Some(0), None)
            .expect_err("I131: a row that cites other bytes is refused");
        assert!(
            err.to_string().contains("evidence_refs"),
            "I131: by member: {err}"
        );
        // And the derived provenance carries the adopt end to end.
        l.engine_b.apply_replicated_key_grant(set).await.unwrap();
        l.engine_b
            .adopt_sealed_blob(&bytes, p, None, AdoptDisposition::LocalOnly)
            .await
            .expect("I131: B adopts on the row's own provenance");
        assert_eq!(
            l.engine_b
                .read_blob_as(&sha, &l.node_b, None)
                .await
                .unwrap(),
            b"row-derived"
        );
    }

    /// The chat shape (CIRISEdge#646 / #878): a row placed at `self`,
    /// authored by the PERSON, whose body is sealed under the ROOM's DEK and
    /// referenced by a typed `BlobPointer` under a named member — plus the
    /// blob-native citation edge now writes beside it.
    fn chat_row(
        id: &str,
        author: &str,
        comm: &str,
        sha_hex: &str,
        tier: &str,
        epoch: Option<u64>,
        cite: bool,
    ) -> crate::federation::Attestation {
        use crate::federation::media_source_invariants::bodies::row as fixture_row;
        let mut pointer = serde_json::json!({
            "community_key_id": comm,
            "tier": tier,
            "content_sha256": sha_hex,
            "content_field": "body",
        });
        if let Some(e) = epoch {
            pointer["epoch"] = serde_json::json!(e);
        }
        let mut env = serde_json::json!({
            "dimension": "chat:message:v1",
            "content": pointer,
        });
        if cite {
            env["evidence_refs"] = serde_json::json!([sha_hex]);
        }
        fixture_row(
            id,
            author,
            author,
            env,
            crate::federation::types::cohort_scope::SELF,
        )
    }

    /// **I132 — the chat shape, end to end.** A `self`-scoped row authored by
    /// a person, its body under the room's DEK, referenced by a pointer: the
    /// provenance read off it names the ROOM and the room's tier (not `self`
    /// / `InvisibleEncrypted`), and the peer OPENS the body with it. This is
    /// the shape v46.0.0's constructor answered wrongly.
    pub(crate) async fn i132_the_chat_shape_opens<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, bytes, set) = seal_and_set(&l, b"chat body under the room dek").await;
        let sha_hex = hex::encode(sha);
        let row = chat_row(
            &format!("i132-{run}"),
            &l.alice,
            &l.comm,
            &sha_hex,
            "community_dek",
            Some(0),
            true,
        );
        assert_eq!(
            row.cohort_scope,
            crate::federation::types::cohort_scope::SELF,
            "I132: the row sits at self"
        );
        let p = BlobProvenance::from_attestation(&row, &sha, None, None)
            .expect("I132: the pointer is a reference");
        assert_eq!(p.author_key_id, l.alice, "I132: authorship is the row's");
        assert_eq!(
            p.tier,
            CryptoTier::CommunityDek,
            "I132: the tier is the POINTER's"
        );
        assert_eq!(
            p.community_key_id.as_deref(),
            Some(l.comm.as_str()),
            "I132: the key plane is the POINTER's"
        );
        assert_eq!(p.epoch, Some(0), "I132: the epoch rides the pointer");
        assert_eq!(
            p.cohort_scope,
            crate::federation::types::cohort_scope::COMMUNITY,
            "I132: community-DEK bytes are placed in the community whose DEK sealed them"
        );
        assert!(
            p.minter_key_id.is_none(),
            "I132: the minter is still derived"
        );
        l.engine_b.apply_replicated_key_grant(set).await.unwrap();
        l.engine_b
            .adopt_sealed_blob(&bytes, p, None, AdoptDisposition::LocalOnly)
            .await
            .expect("I132: B adopts on the row's own provenance");
        assert_eq!(
            l.engine_b
                .read_blob_as(&sha, &l.node_b, None)
                .await
                .unwrap(),
            b"chat body under the room dek"
        );
    }

    /// **I133 — a pointer is a reference on its own, and the pointer wins.**
    /// A row that carries no `evidence_refs` at all still resolves through
    /// its pointer; a row carrying BOTH takes the key plane from the
    /// pointer, never from its own scope.
    pub(crate) async fn i133_the_pointer_is_a_reference<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, _bytes, _set) = seal_and_set(&l, b"pointer only").await;
        let sha_hex = hex::encode(sha);
        let uncited = chat_row(
            &format!("i133-uncited-{run}"),
            &l.alice,
            &l.comm,
            &sha_hex,
            "community_dek",
            Some(0),
            false,
        );
        let p = BlobProvenance::from_attestation(&uncited, &sha, None, None)
            .expect("I133: a typed pointer IS the reference (BLOB_REPLICATION §5)");
        assert_eq!(p.tier, CryptoTier::CommunityDek);
        assert_eq!(p.community_key_id.as_deref(), Some(l.comm.as_str()));
        // A pointer for OTHER bytes is not a reference to these.
        let elsewhere = chat_row(
            &format!("i133-elsewhere-{run}"),
            &l.alice,
            &l.comm,
            &"ab".repeat(32),
            "community_dek",
            Some(0),
            false,
        );
        let err = BlobProvenance::from_attestation(&elsewhere, &sha, None, None)
            .expect_err("I133: a pointer at other bytes does not reference these");
        assert!(
            err.to_string().contains("evidence_refs") || err.to_string().contains("content_sha256"),
            "I133: refused by member: {err}"
        );
        // An explicit epoch still wins over the pointer's.
        let p = BlobProvenance::from_attestation(&uncited, &sha, Some(7), None).unwrap();
        assert_eq!(p.epoch, Some(7), "I133: the caller's epoch wins");
    }

    /// **I134 — the pointer's refusals, by member.** A community-DEK pointer
    /// naming no community, and a pointer whose tier contradicts the
    /// placement it implies, are refused; an `evidence_refs`-only row still
    /// resolves exactly as v46.0.0 resolved it.
    pub(crate) async fn i134_pointer_refusals<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, _bytes, _set) = seal_and_set(&l, b"refusals").await;
        let sha_hex = hex::encode(sha);
        let no_community = chat_row(
            &format!("i134-nocomm-{run}"),
            &l.alice,
            "",
            &sha_hex,
            "community_dek",
            Some(0),
            true,
        );
        let err = BlobProvenance::from_attestation(&no_community, &sha, None, None)
            .expect_err("I134: community-DEK names its community");
        assert!(err.to_string().contains("community_key_id"), "I134: {err}");
        // A `self` row whose pointer claims plaintext: the floor's own rule
        // (a self/family row is never plaintext) refuses it, one spelling.
        let plaintext_self = chat_row(
            &format!("i134-plain-{run}"),
            &l.alice,
            &l.comm,
            &sha_hex,
            "plaintext",
            None,
            true,
        );
        let err = BlobProvenance::from_attestation(&plaintext_self, &sha, None, None)
            .expect_err("I134: a self row is never plaintext");
        assert!(
            err.to_string().contains("tier") || err.to_string().contains("storage floor"),
            "I134: {err}"
        );
        // And the v46.0.0 shape is untouched: evidence_refs only, community row.
        use crate::federation::media_source_invariants::bodies::row as fixture_row;
        let cited_only = fixture_row(
            &format!("i134-cited-{run}"),
            &l.alice,
            &l.alice,
            serde_json::json!({
                "dimension": "external_content:image:v1",
                "evidence_refs": [sha_hex],
                "community_key_id": l.comm,
            }),
            COMMUNITY,
        );
        let p = BlobProvenance::from_attestation(&cited_only, &sha, Some(0), None)
            .expect("I134: the v46.0.0 path is unchanged");
        assert_eq!(p.tier, CryptoTier::CommunityDek);
        assert_eq!(p.cohort_scope, COMMUNITY);
    }

    /// **I130 — from disk: one derivation, and the old spelling is gone.**
    #[test]
    fn i130_one_derivation_for_every_minter_writer() {
        const ADOPT: &str = include_str!("adopt_cascade.rs");
        assert!(
            !live_lines(ADOPT).any(|l| l.contains("minter_key_id: provenance.author_key_id")),
            "I130: the adopt no longer infers the minter from the author"
        );
        assert!(
            live_lines(ADOPT).any(|l| l.contains("epoch_minter::resolve(")),
            "I130: it resolves through the one function"
        );
        for (name, text) in [
            ("sqlite.rs", include_str!("../store/sqlite.rs")),
            ("postgres.rs", include_str!("../store/postgres.rs")),
        ] {
            assert!(
                live_lines(text).any(|l| l.contains("rebind_stranded_blob_epochs")),
                "I130: {name} implements the repair"
            );
        }
        const GRANT: &str = include_str!("key_grant.rs");
        assert!(
            live_lines(GRANT).any(|l| l.contains("rebind_stranded_blob_epochs(")),
            "I130: admitting a key_grant set runs the repair"
        );
        const SELF_SRC: &str = include_str!("epoch_minter_invariants.rs");
        assert!(
            live_lines(SELF_SRC).any(|l| l.contains("BlobProvenance::from_attestation(")),
            "I130: the DX path (provenance READ off the row) is the tested path"
        );
        // #878 — the constructor must read the key plane from the pointer,
        // not from the row's scope. A grep, so a future edit that "simplifies"
        // it back to `crypto_tier(&row.cohort_scope)` has to argue with this.
        const HOLD: &str = include_str!("replication/hold.rs");
        let ctor = HOLD
            .split("pub fn from_attestation(")
            .nth(1)
            .expect("I130: from_attestation exists");
        let ctor = &ctor[..ctor.find("\n    }\n").expect("end")];
        assert!(
            live_lines(ctor).any(|l| l.contains("blob_pointer::pointer_for(")),
            "I130: the constructor consults the typed pointer (#878)"
        );
        assert!(
            live_lines(ctor).any(|l| l.contains("check_scope(")),
            "I130: and the pointer's tier is checked against the placement it implies"
        );
        const CASCADE: &str = include_str!("community_dek.rs");
        assert!(
            live_lines(CASCADE).any(|l| l.contains("epoch_minter::")),
            "I130: the seal path names the minter through the same function"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i126() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i126_author_is_not_the_sealer(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i127() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i127_explicit_minter_wins(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i128() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i128_derivation_and_its_limit(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i132() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i132_the_chat_shape_opens(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i133() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i133_the_pointer_is_a_reference(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i134() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i134_pointer_refusals(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i131() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i131_the_row_is_the_provenance(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i129() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i129_a_stranded_binding_rebinds(&a, &b, &super::suffix(), $pick).await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners!(
        sqlite,
        Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
            as bodies::Pick<crate::store::sqlite::SqliteBackend>
    );
    #[cfg(feature = "postgres")]
    runners!(
        postgres,
        (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as bodies::Pick<crate::store::postgres::PostgresBackend>
    );
}
