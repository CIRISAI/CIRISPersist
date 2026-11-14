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
    use crate::federation::key_grant::SignedKeyGrantRow;
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

    /// A's seal through the production door, and the epoch-axis row it
    /// emitted to B's node (v55.0.0, #989: one row per recipient).
    async fn seal_and_set<B>(
        l: &Ladder<B>,
        plaintext: &[u8],
    ) -> ([u8; 32], Vec<u8>, SignedKeyGrantRow)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let r = l
            .engine_a
            .put_blob_scoped(COMMUNITY, Some(&l.comm), plaintext, None, None)
            .await
            .expect("A's scoped put");
        assert_eq!(r.tier, CryptoTier::CommunityDek);
        let sha = r.at_rest_sha256;
        let sa = l.ba.clone();
        let emitted: Vec<_> = sa
            .all_attestations_by(&l.node_a)
            .await
            .unwrap()
            .into_iter()
            .filter(|x| {
                crate::federation::admission::envelope_dimension(&x.attestation_envelope)
                    == Some(crate::federation::key_grant::KEY_GRANT_EPOCH_DIMENSION)
                    && x.attested_key_id == l.node_b
            })
            .collect();
        let to_b = emitted
            .iter()
            .max_by_key(|x| x.asserted_at)
            .expect("an epoch-axis row to B, signed by the NODE");
        let Some(BlobBody::Inline(bytes)) = sa.get_blob(&sha).await.unwrap() else {
            panic!("inline")
        };
        (
            sha,
            bytes,
            SignedKeyGrantRow {
                attestation: to_b.clone(),
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
            .expect("B admits A's row");
        assert!(admission.projected, "{admission:?}");
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
        // v59.1.1 — of two minters, the one that acts for the author is the
        // sealer: `other` is nobody's occurrence, node A is alice's.
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
            "I128: of two minters, the one that acts for the author is derived"
        );
        // I1475 — the pair-room shape: the VIEWER's own node minted the same
        // epoch and wrapped it to itself. It acts for bob, not for alice, so
        // a row alice authored still derives node A.
        b.as_ref()
            .community_dek_put_member_grant(
                &l.comm,
                &l.node_b,
                0,
                &l.node_b,
                crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2,
                "b3du",
            )
            .await
            .unwrap();
        assert_eq!(
            b.community_dek_minters_granting(&l.comm, 0, &l.node_b)
                .await
                .unwrap()
                .len(),
            3,
            "I1475: the viewer's own node is a third minter granting it"
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
            "I1475: the viewer's own epoch is not the author's sealer"
        );
        // No candidate acts for the author: falls back, never guesses.
        assert_eq!(
            crate::federation::epoch_minter::resolve(
                b.as_ref(),
                None,
                &l.comm,
                0,
                &l.node_b,
                &third,
            )
            .await
            .unwrap(),
            third,
            "I128: no minter acts for the author, so it falls back to the author"
        );
        // Two candidates act for the author: still no guess.
        b.as_ref()
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: l.alice.clone(),
                occurrence_key_id: other.clone(),
                device_class: crate::federation::types::device_class::LAPTOP.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: None,
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
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
            "I128: two minters act for the author, so it falls back to the author"
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
    pub(crate) fn chat_row(
        id: &str,
        author: &str,
        comm: &str,
        sha_hex: &str,
        tier: &str,
        epoch: Option<u64>,
        cite: bool,
    ) -> crate::federation::Attestation {
        chat_row_at(
            id,
            author,
            comm,
            sha_hex,
            tier,
            epoch,
            cite,
            crate::federation::types::cohort_scope::COMMUNITY,
        )
    }

    /// The same row at an explicit placement — `self` is the owner's
    /// fan-out to their own node; `community` is what a room member's node
    /// receives (crossed or born there).
    #[allow(clippy::too_many_arguments)]
    fn chat_row_at(
        id: &str,
        author: &str,
        comm: &str,
        sha_hex: &str,
        tier: &str,
        epoch: Option<u64>,
        cite: bool,
        scope: &str,
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
        // A community row NAMES its cohort at top level — the write gate
        // admits and routes on that member; the pointer's community is the
        // key plane, not the audience (review P1). A self row carries none.
        if scope == crate::federation::types::cohort_scope::COMMUNITY {
            env["community_key_id"] = serde_json::json!(comm);
        }
        if cite {
            env["evidence_refs"] = serde_json::json!([sha_hex]);
        }
        fixture_row(id, author, author, env, scope)
    }

    /// **I132 — the chat shape, end to end.** A room message as a member's
    /// node receives it: a `community` row authored by a person, its body
    /// under the room's DEK, referenced by a typed pointer. The provenance
    /// read off it takes the TIER from the pointer (v46.0.0 answered
    /// `InvisibleEncrypted` here) and the PLACEMENT from the row, and the
    /// peer OPENS the body with it.
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
            crate::federation::types::cohort_scope::COMMUNITY,
            "I132: a room message reaches a member's node as a community row"
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
            "I132: the placement is the ROW's — the attestation is the grant"
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

    /// **I135 — the attestation is the grant.** A `self` row pointing at
    /// community-DEK bytes is the owner's fan-out to their own node: the
    /// provenance keeps `self` (the pointer's community does NOT widen it),
    /// the tier still comes from the pointer, and a node that is not the
    /// owner's is refused `NotPartyTo` at `would_hold` — a room message
    /// that never widened to the room is not the room's to hold.
    pub(crate) async fn i135_the_attestation_is_the_grant<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::{would_hold, DiskPressureSnapshot, HoldContext};
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, _bytes, _set) = seal_and_set(&l, b"owner fan-out").await;
        let sha_hex = hex::encode(sha);
        let row = chat_row_at(
            &format!("i135-{run}"),
            &l.alice,
            &l.comm,
            &sha_hex,
            "community_dek",
            Some(0),
            true,
            crate::federation::types::cohort_scope::SELF,
        );
        let p = BlobProvenance::from_attestation(&row, &sha, None, None)
            .expect("I135: a self row with a community-DEK pointer is a legitimate shape");
        assert_eq!(
            p.cohort_scope,
            crate::federation::types::cohort_scope::SELF,
            "I135: the row's placement stands; the pointer does not widen it"
        );
        assert_eq!(
            p.tier,
            CryptoTier::CommunityDek,
            "I135: the tier is still the pointer's"
        );
        assert_eq!(p.community_key_id.as_deref(), Some(l.comm.as_str()));
        // B is a room member's node, not alice's: the self arm refuses it.
        let bb = l.bb.clone();
        let ctx = HoldContext {
            pressure: DiskPressureSnapshot::normal(),
            is_local_or_family: |k: &str| k == l.node_b,
            our_key_id: &l.node_b,
        };
        let err = would_hold(bb.as_ref(), &ctx, &p)
            .await
            .expect_err("I135: a self row is the owner's; a member's node is not party to it");
        assert!(matches!(err, BlobError::NotPartyTo { .. }), "I135: {err}");
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
        let plaintext_self = chat_row_at(
            &format!("i134-plain-{run}"),
            &l.alice,
            &l.comm,
            &sha_hex,
            "plaintext",
            None,
            true,
            crate::federation::types::cohort_scope::SELF,
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

    /// **I136 — the pointer does not choose the audience, and a malformed
    /// pointer never falls back to the citation.** (Review of PR #883.)
    /// A `community` row signed for room C1 whose pointer names C2 is
    /// refused by member — `would_hold` takes the audience from
    /// `community_key_id`, and C2's members are not party to C1's content.
    /// A row citing the bytes in `evidence_refs` AND carrying a pointer with
    /// a tier persist cannot read is refused, not resolved through the
    /// citation with a tier derived from the row's scope.
    pub(crate) async fn i136_the_pointer_does_not_choose_the_audience<B>(
        dsn_a: &str,
        dsn_b: &str,
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::media_source_invariants::bodies::row as fixture_row;
        let l = ladder(dsn_a, dsn_b, run, pick).await;
        let (sha, _bytes, _set) = seal_and_set(&l, b"audience").await;
        let sha_hex = hex::encode(sha);
        let other_room = format!("em-other-room-{run}");
        // Signed for l.comm at top level; the pointer names another room.
        let mismatched = fixture_row(
            &format!("i136-mismatch-{run}"),
            &l.alice,
            &l.alice,
            serde_json::json!({
                "dimension": "chat:message:v1",
                "community_key_id": l.comm,
                "evidence_refs": [sha_hex],
                "content": {"community_key_id": other_room, "tier": "community_dek",
                             "content_sha256": sha_hex, "content_field": "body", "epoch": 0},
            }),
            crate::federation::types::cohort_scope::COMMUNITY,
        );
        let err = BlobProvenance::from_attestation(&mismatched, &sha, None, None)
            .expect_err("I136: a pointer naming another room does not widen the audience");
        assert!(
            err.to_string().contains("community_key_id") && err.to_string().contains(&other_room),
            "I136: by member, naming both: {err}"
        );
        // The same row with the pointer agreeing is admitted.
        let agreeing = chat_row(
            &format!("i136-agree-{run}"),
            &l.alice,
            &l.comm,
            &sha_hex,
            "community_dek",
            Some(0),
            true,
        );
        // chat_row puts community_key_id inside the pointer only; sign the
        // top-level target too, as the write gate requires of a community row.
        let mut agreeing = agreeing;
        agreeing.attestation_envelope["community_key_id"] = serde_json::json!(l.comm);
        let p = BlobProvenance::from_attestation(&agreeing, &sha, None, None)
            .expect("I136: pointer and signed cohort agree");
        assert_eq!(p.community_key_id.as_deref(), Some(l.comm.as_str()));
        // A citation plus an unreadable pointer: refused, never the citation path.
        let bad_tier = fixture_row(
            &format!("i136-badtier-{run}"),
            &l.alice,
            &l.alice,
            serde_json::json!({
                "dimension": "chat:message:v1",
                "community_key_id": l.comm,
                "evidence_refs": [sha_hex],
                "content": {"community_key_id": l.comm, "tier": "quantum",
                             "content_sha256": sha_hex, "content_field": "body"},
            }),
            crate::federation::types::cohort_scope::COMMUNITY,
        );
        let err = BlobProvenance::from_attestation(&bad_tier, &sha, None, None)
            .expect_err("I136: an unreadable pointer at these bytes is a refusal, not a fallback");
        assert!(err.to_string().contains("tier"), "I136: by member: {err}");
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
                async fn i136() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i136_the_pointer_does_not_choose_the_audience(
                        &a,
                        &b,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i135() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i135_the_attestation_is_the_grant(&a, &b, &super::suffix(), $pick).await
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

/// CIRISPersist#1271 — **the late-seated member, I1776–I1780.**
///
/// A three-person room, one node per person, each node its OWN backend. On
/// Carol's node the first epoch-0 grant to land is BOB's; Alice's bytes are
/// adopted with no named minter; Alice's epoch-0 grant lands after. v61.4.0
/// bound Alice's bytes to Bob's node — "the only minter granting me" — and
/// the read was a permanent `SealDidNotOpen` (Edge `seal_mismatch`): Bob
/// holds state, so the stranded repair never looked at the row again.
///
/// The fixture is the ORDER, not a count: every body below lands the
/// crossings on Carol's node in the sequence the harness logged.
#[cfg(test)]
pub(crate) mod room_1271 {
    use super::bodies::Pick;
    use crate::federation::key_grant::SignedKeyGrantRow;
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

    /// Three engines, introduced; a room of three PERSONS, each occurring
    /// through their own node.
    pub(crate) struct Room<B> {
        pub alice_engine: Engine,
        pub bob_engine: Engine,
        pub carol_engine: Engine,
        pub ba: Arc<B>,
        pub bb: Arc<B>,
        pub bc: Arc<B>,
        pub node_a: String,
        pub node_b: String,
        pub node_c: String,
        pub alice: String,
        pub comm: String,
    }

    pub(crate) async fn room<B>(dsns: &[String; 3], run: &str, pick: Pick<B>) -> Room<B>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        room_with(dsns, run, pick, true).await
    }

    /// [`room`], with `alice_occurs_on_carol = false` leaving Carol's node
    /// WITHOUT the record that Alice occurs through node A: Alice is on
    /// Carol's roster but node A resolves to no human there.
    pub(crate) async fn room_with<B>(
        dsns: &[String; 3],
        run: &str,
        pick: Pick<B>,
        alice_occurs_on_carol: bool,
    ) -> Room<B>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let aliases = [
            format!("r1271-a-{run}"),
            format!("r1271-b-{run}"),
            format!("r1271-c-{run}"),
        ];
        let mut engines = Vec::new();
        for (dsn, alias) in dsns.iter().zip(aliases.iter()) {
            let e = Engine::with_signer_pre_genesis(ts::local_signer(alias), dsn)
                .await
                .unwrap();
            e.register_self_federation_key(USER, alias, None, serde_json::json!({}), vec![])
                .await
                .expect("register the engine's own key");
            engines.push(e);
        }
        let carol_engine = engines.pop().unwrap();
        let bob_engine = engines.pop().unwrap();
        let alice_engine = engines.pop().unwrap();
        let (sa, sb, sc) = (pick(&alice_engine), pick(&bob_engine), pick(&carol_engine));
        let kem =
            |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            };
        let mut nodes = Vec::new();
        for ((engine, backend), alias) in [
            (&alice_engine, &sa),
            (&bob_engine, &sb),
            (&carol_engine, &sc),
        ]
        .into_iter()
        .zip(aliases.iter())
        {
            nodes.push(Node {
                backend: backend.as_ref(),
                signer: ts::local_signer(alias),
                key: engine.local_derived_key_id().await.unwrap(),
                kem: kem(backend.load_or_init_content_kem_identity().await.unwrap()),
            });
        }
        let refs: Vec<&Node<'_, B>> = nodes.iter().collect();
        let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();
        introduce(&refs, &alias_refs).await;
        let comm = format!("r1271-comm-{run}");
        let (alice, bob, carol) = (
            format!("r1271-alice-{run}"),
            format!("r1271-bob-{run}"),
            format!("r1271-carol-{run}"),
        );
        let seats_alice = if alice_occurs_on_carol {
            &refs[..]
        } else {
            &refs[..2]
        };
        seed_community_everywhere(
            seats_alice,
            &comm,
            &[
                (&alice, Some(refs[0])),
                (&bob, Some(refs[1])),
                (&carol, Some(refs[2])),
            ],
        )
        .await;
        if !alice_occurs_on_carol {
            seed_community_everywhere(
                &refs[2..],
                &comm,
                &[
                    (&alice, None),
                    (&bob, Some(refs[1])),
                    (&carol, Some(refs[2])),
                ],
            )
            .await;
        }
        let (node_a, node_b, node_c) = (
            nodes[0].key.clone(),
            nodes[1].key.clone(),
            nodes[2].key.clone(),
        );
        drop(nodes);
        Room {
            alice_engine,
            bob_engine,
            carol_engine,
            ba: sa,
            bb: sb,
            bc: sc,
            node_a,
            node_b,
            node_c,
            alice,
            comm,
        }
    }

    /// `engine` (node `minter`) seals `plaintext` into the room through the
    /// production door; returns the sha, the sealed bytes, and the epoch-axis
    /// row it emitted to `recipient`.
    async fn seal<B>(
        engine: &Engine,
        backend: &Arc<B>,
        minter: &str,
        comm: &str,
        plaintext: &[u8],
        recipient: &str,
    ) -> ([u8; 32], Vec<u8>, SignedKeyGrantRow)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let r = engine
            .put_blob_scoped(COMMUNITY, Some(comm), plaintext, None, None)
            .await
            .expect("scoped put");
        assert_eq!(r.tier, CryptoTier::CommunityDek);
        let to = backend
            .all_attestations_by(minter)
            .await
            .unwrap()
            .into_iter()
            .filter(|x| {
                crate::federation::admission::envelope_dimension(&x.attestation_envelope)
                    == Some(crate::federation::key_grant::KEY_GRANT_EPOCH_DIMENSION)
                    && x.attested_key_id == recipient
            })
            .max_by_key(|x| x.asserted_at)
            .expect("an epoch-axis row to the recipient, signed by the minting NODE");
        let Some(BlobBody::Inline(bytes)) = backend.get_blob(&r.at_rest_sha256).await.unwrap()
        else {
            panic!("inline")
        };
        (
            r.at_rest_sha256,
            bytes,
            SignedKeyGrantRow { attestation: to },
        )
    }

    fn provenance(author: &str, comm: &str, minter: Option<&str>) -> BlobProvenance {
        BlobProvenance {
            author_key_id: author.to_owned(),
            cohort_scope: COMMUNITY.into(),
            community_key_id: Some(comm.to_owned()),
            epoch: Some(0),
            tier: CryptoTier::CommunityDek,
            minter_key_id: minter.map(str::to_owned),
        }
    }

    async fn bound<B: BlobStorage + Sync>(b: &Arc<B>, sha: &[u8; 32]) -> String {
        b.community_dek_blob_epoch(sha)
            .await
            .unwrap()
            .expect("the binding exists")
            .1
    }

    /// The harness ordering on Carol's node, up to (not including) Alice's
    /// grant: Bob's epoch-0 grant admitted, Alice's bytes adopted unnamed.
    /// Returns Alice's sha, her bytes, and her not-yet-carried row to Carol.
    async fn bob_first<B>(r: &Room<B>) -> ([u8; 32], Vec<u8>, SignedKeyGrantRow)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (sha_a, bytes_a, a_to_c) = seal(
            &r.alice_engine,
            &r.ba,
            &r.node_a,
            &r.comm,
            b"alice, before carol",
            &r.node_c,
        )
        .await;
        let (_sha_b, _bytes_b, b_to_c) = seal(
            &r.bob_engine,
            &r.bb,
            &r.node_b,
            &r.comm,
            b"bob's epoch",
            &r.node_c,
        )
        .await;
        r.carol_engine
            .apply_replicated_key_grant(b_to_c)
            .await
            .expect("Carol admits Bob's epoch-0 row");
        assert_eq!(
            r.bc.community_dek_minters_granting(&r.comm, 0, &r.node_c)
                .await
                .unwrap(),
            vec![r.node_b.clone()],
            "#1271: Bob is the ONLY minter granting Carol when Alice's bytes land"
        );
        r.carol_engine
            .adopt_sealed_blob(
                &bytes_a,
                provenance(&r.alice, &r.comm, None),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("Carol adopts Alice's bytes");
        (sha_a, bytes_a, a_to_c)
    }

    /// **I1776 — the harness ordering, end to end.** Bob's grant, Alice's
    /// bytes unnamed, Alice's grant: the binding names ALICE'S node before
    /// anything reads it (the derivation and the repair, no heal), and the
    /// read opens.
    pub(crate) async fn i1776_the_late_seat_ordering_opens<B>(
        dsns: &[String; 3],
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let r = room(dsns, run, pick).await;
        let (sha_a, _bytes, a_to_c) = bob_first(&r).await;
        r.carol_engine
            .apply_replicated_key_grant(a_to_c)
            .await
            .expect("Carol admits Alice's epoch-0 row");
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.node_a,
            "I1776: the binding names the node that SEALED the bytes before any read"
        );
        assert_eq!(
            r.carol_engine
                .read_blob_as(&sha_a, &r.node_c, None)
                .await
                .expect("I1776: Carol's read OPENS"),
            b"alice, before carol"
        );
    }

    /// **I1777 — (a) one candidate is filtered too.** With Bob the only
    /// minter granting Carol, an unnamed adopt of Alice's bytes does NOT
    /// derive Bob: it falls back to the author (stranded, repairable).
    pub(crate) async fn i1777_one_candidate_is_filtered<B>(
        dsns: &[String; 3],
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let r = room(dsns, run, pick).await;
        let (sha_a, _bytes, _a_to_c) = bob_first(&r).await;
        assert_eq!(
            crate::federation::epoch_minter::resolve(
                r.bc.as_ref(),
                None,
                &r.comm,
                0,
                &r.node_c,
                &r.alice,
            )
            .await
            .unwrap(),
            r.alice,
            "I1777: Bob's node does not act for Alice — the lone candidate is not derived"
        );
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.alice,
            "I1777: the adopt recorded the STRANDED author fallback, not Bob's node"
        );
        // And the lone candidate that DOES act for the author is still derived.
        let bob_person =
            r.bc.active_identities_for_occurrence(&r.node_b)
                .await
                .unwrap();
        assert_eq!(bob_person.len(), 1, "fixture: node B occurs for one person");
        assert_eq!(
            crate::federation::epoch_minter::resolve(
                r.bc.as_ref(),
                None,
                &r.comm,
                0,
                &r.node_c,
                &bob_person[0],
            )
            .await
            .unwrap(),
            r.node_b,
            "I1777: a lone candidate that acts for the author is derived"
        );
    }

    /// **I1778 — (b) the repair asks whose row it is.** Alice's bytes are
    /// stranded on her author key (no grant at all when they land). Bob's
    /// epoch-0 set is admitted next: it must NOT claim Alice's row. Alice's
    /// set then rebinds it, and it opens.
    pub(crate) async fn i1778_the_repair_checks_the_author<B>(
        dsns: &[String; 3],
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let r = room(dsns, run, pick).await;
        let (sha_a, bytes_a, a_to_c) = seal(
            &r.alice_engine,
            &r.ba,
            &r.node_a,
            &r.comm,
            b"bytes before any key",
            &r.node_c,
        )
        .await;
        let (_sha_b, _bytes_b, b_to_c) = seal(
            &r.bob_engine,
            &r.bb,
            &r.node_b,
            &r.comm,
            b"bob's epoch",
            &r.node_c,
        )
        .await;
        r.carol_engine
            .adopt_sealed_blob(
                &bytes_a,
                provenance(&r.alice, &r.comm, None),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("Carol adopts with no grant held");
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.alice,
            "I1778: stranded on the author"
        );
        assert_eq!(
            r.bc.list_stranded_blob_epochs(&r.comm, 0).await.unwrap(),
            vec![(sha_a, r.alice.clone(), Some(r.alice.clone()))],
            "I1778: the stranded row is listed with its author"
        );
        r.carol_engine
            .apply_replicated_key_grant(b_to_c)
            .await
            .expect("Carol admits Bob's epoch-0 row");
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.alice,
            "I1778: Bob's set does not claim a row Alice authored"
        );
        r.carol_engine
            .apply_replicated_key_grant(a_to_c)
            .await
            .expect("Carol admits Alice's epoch-0 row");
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.node_a,
            "I1778: Alice's set rebinds her stranded row"
        );
        assert!(
            r.bc.list_stranded_blob_epochs(&r.comm, 0)
                .await
                .unwrap()
                .is_empty(),
            "I1778: nothing stranded remains"
        );
        assert_eq!(
            r.carol_engine
                .read_blob_as(&sha_a, &r.node_c, None)
                .await
                .expect("I1778: opens"),
            b"bytes before any key"
        );
    }

    /// **I1779 — (c) a row ALREADY wrong heals on read.** Alice's bytes
    /// bound to Bob's node (named, as the pre-#1271 derivation wrote it), Bob
    /// holding state, Alice's grant admitted after: the repair does not
    /// touch it, and the read opens it under Alice's DEK, re-pointing the
    /// binding. The negative: bytes that open under no granted minter still
    /// refuse, and nothing is rebound.
    pub(crate) async fn i1779_a_wrong_binding_heals_on_read<B>(
        dsns: &[String; 3],
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let r = room(dsns, run, pick).await;
        let (sha_a, bytes_a, a_to_c) = seal(
            &r.alice_engine,
            &r.ba,
            &r.node_a,
            &r.comm,
            b"bound wrong",
            &r.node_c,
        )
        .await;
        let (_sha_b, _bytes_b, b_to_c) = seal(
            &r.bob_engine,
            &r.bb,
            &r.node_b,
            &r.comm,
            b"bob's epoch",
            &r.node_c,
        )
        .await;
        r.carol_engine
            .apply_replicated_key_grant(b_to_c)
            .await
            .unwrap();
        r.carol_engine
            .adopt_sealed_blob(
                &bytes_a,
                provenance(&r.alice, &r.comm, Some(&r.node_b)),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("the pre-#1271 state: bound to Bob's node");
        assert_eq!(bound(&r.bc, &sha_a).await, r.node_b);
        // A second Alice row in the same state, healed through the OTHER
        // production read door (`read_blob_for_community_viewer`).
        let (sha_a2, bytes_a2, _) = seal(
            &r.alice_engine,
            &r.ba,
            &r.node_a,
            &r.comm,
            b"bound wrong, community door",
            &r.node_c,
        )
        .await;
        r.carol_engine
            .adopt_sealed_blob(
                &bytes_a2,
                provenance(&r.alice, &r.comm, Some(&r.node_b)),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .unwrap();

        // NEGATIVE first: Carol holds only Bob's grant. Nothing opens these
        // bytes, so the refusal stands and the row is untouched.
        let err = r
            .carol_engine
            .read_blob_as(&sha_a, &r.node_c, None)
            .await
            .expect_err("I1779: no granted minter opens these bytes");
        assert!(
            matches!(err, BlobError::SealDidNotOpen { .. }),
            "I1779: the refusal is the seal mismatch, unchanged: {err}"
        );
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.node_b,
            "I1779: a failed heal rebinds nothing"
        );

        r.carol_engine
            .apply_replicated_key_grant(a_to_c)
            .await
            .unwrap();
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.node_b,
            "I1779: Bob holds state, so the stranded repair leaves the row WRONG"
        );
        assert_eq!(
            r.carol_engine
                .read_blob_as(&sha_a, &r.node_c, None)
                .await
                .expect("I1779: the read HEALS and opens"),
            b"bound wrong"
        );
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.node_a,
            "I1779: the binding is re-pointed to the minter AEAD proved"
        );
        let healed = r
            .carol_engine
            .read_blob_for_community_viewer(&sha_a2, &r.node_c)
            .await;
        assert_eq!(
            healed.expect("I1779: the community door heals too"),
            b"bound wrong, community door"
        );
        assert_eq!(bound(&r.bc, &sha_a2).await, r.node_a, "I1779: re-pointed");
        // The compare-and-set refuses a stale expectation: the row names
        // Alice's node now, so "if it still names Bob's" changes nothing.
        assert!(
            !r.bc
                .rebind_blob_epoch_minter_cas(&sha_a, &r.node_b, "r1271-nobody")
                .await
                .unwrap(),
            "I1779: a CAS on a stale minter is refused"
        );
        assert_eq!(bound(&r.bc, &sha_a).await, r.node_a);
        // Healed for good: the next read takes the ordinary path.
        assert_eq!(
            r.carol_engine
                .read_blob_as(&sha_a, &r.node_c, None)
                .await
                .unwrap(),
            b"bound wrong"
        );
        // A second NEGATIVE, after the heal: the wrong AAD opens under no
        // minter at all — refused, and the (now correct) row is untouched.
        let err = r
            .carol_engine
            .read_blob_as(&sha_a, &r.node_c, Some(b"not the row's aad"))
            .await
            .expect_err("I1779: wrong associated data opens nothing");
        assert!(matches!(err, BlobError::SealDidNotOpen { .. }), "{err}");
        assert_eq!(bound(&r.bc, &sha_a).await, r.node_a);
    }

    /// **I1780 — (c)'s boundary: an UNGRANTED binding is not healed.** A
    /// row whose binding names a minter that never granted the viewer —
    /// here a stranded key no repair can claim (its author is nobody the
    /// room's nodes act for) — refuses `NotGranted` at authorization, before
    /// any body, on both read doors, and stays bound as it was: even once a
    /// minter that DID grant the viewer holds the DEK that would open it. The
    /// heal is the AEAD arm only, for a viewer the bound minter already
    /// authorized; reaching past `NotGranted` would re-point a rotated
    /// signer's rows onto the node's key, which PR #850 ruled must refuse
    /// (I66).
    pub(crate) async fn i1780_an_ungranted_binding_is_not_healed<B>(
        dsns: &[String; 3],
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let r = room(dsns, run, pick).await;
        let (sha_a, bytes_a, a_to_c) = seal(
            &r.alice_engine,
            &r.ba,
            &r.node_a,
            &r.comm,
            b"ghost bound",
            &r.node_c,
        )
        .await;
        let (_sha_b, _bytes_b, b_to_c) = seal(
            &r.bob_engine,
            &r.bb,
            &r.node_b,
            &r.comm,
            b"bob's epoch",
            &r.node_c,
        )
        .await;
        // The row names `ghost` — a key holding no DEK and no grant — and
        // its recorded author is a key no node in the room acts for, so no
        // admitted set can prove a claim to it and the repair leaves it.
        let ghost = format!("r1271-ghost-{run}");
        let ghost_author = format!("r1271-ghost-author-{run}");
        for k in [&ghost, &ghost_author] {
            ts::register_identity_key(r.bc.as_ref(), k, USER).await;
        }
        r.carol_engine
            .adopt_sealed_blob(
                &bytes_a,
                provenance(&ghost_author, &r.comm, Some(&ghost)),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("bound to a minter that holds nothing");
        let (sha_a2, bytes_a2, _) = seal(
            &r.alice_engine,
            &r.ba,
            &r.node_a,
            &r.comm,
            b"ghost bound, community door",
            &r.node_c,
        )
        .await;
        r.carol_engine
            .adopt_sealed_blob(
                &bytes_a2,
                provenance(&ghost_author, &r.comm, Some(&ghost)),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .unwrap();
        r.carol_engine
            .apply_replicated_key_grant(b_to_c)
            .await
            .unwrap();
        // NEGATIVE: only Bob grants Carol; his DEK does not open Alice's
        // bytes. NotGranted, as before, and the row is untouched.
        let err = r
            .carol_engine
            .read_blob_as(&sha_a, &r.node_c, None)
            .await
            .expect_err("I1780: nothing that granted Carol opens these bytes");
        assert!(matches!(err, BlobError::NotGranted { .. }), "I1780: {err}");
        assert_eq!(bound(&r.bc, &sha_a).await, ghost, "I1780: nothing rebound");
        // A stranger with no grant at all is refused the same way.
        let err = r
            .carol_engine
            .read_blob_as(&sha_a, "r1271-stranger", None)
            .await
            .expect_err("a stranger");
        assert!(matches!(err, BlobError::NotGranted { .. }), "{err}");

        r.carol_engine
            .apply_replicated_key_grant(a_to_c)
            .await
            .unwrap();
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            ghost,
            "I1780: the repair cannot prove Alice's node acts for this row's author"
        );
        // Alice's node now grants Carol, and its DEK would open both rows.
        // Neither door reaches past NotGranted, and nothing is re-pointed.
        let err = r
            .carol_engine
            .read_blob_as(&sha_a, &r.node_c, None)
            .await
            .expect_err("I1780: an ungranted binding still refuses");
        assert!(matches!(err, BlobError::NotGranted { .. }), "I1780: {err}");
        let err = r
            .carol_engine
            .read_blob_for_community_viewer(&sha_a2, &r.node_c)
            .await
            .expect_err("I1780: and on the community door");
        assert!(matches!(err, BlobError::NotGranted { .. }), "I1780: {err}");
        assert_eq!(bound(&r.bc, &sha_a).await, ghost, "I1780: nothing rebound");
        assert_eq!(bound(&r.bc, &sha_a2).await, ghost, "I1780: nothing rebound");
        // The bytes ARE Alice's epoch: re-pointed by an authority that can
        // (here the CAS by hand), they open — so the refusal
        // above is the boundary, not a broken fixture.
        assert!(r
            .bc
            .rebind_blob_epoch_minter_cas(&sha_a, &ghost, &r.node_a)
            .await
            .unwrap());
        assert_eq!(
            r.carol_engine
                .read_blob_as(&sha_a, &r.node_c, None)
                .await
                .expect("fixture: Alice's DEK opens the row"),
            b"ghost bound"
        );
    }

    /// **I1781 — (c) tries only the author's minters.** Bytes SEALED under
    /// Bob's DEK but attributed to Alice, bound to Alice's node. Carol holds
    /// both grants, so Bob's DEK WOULD open them — but Bob's node does not act
    /// for Alice, so it is never tried: the refusal is unchanged and nothing
    /// is rebound. AEAD proves which key sealed the bytes, not whose bytes
    /// they are.
    pub(crate) async fn i1781_a_non_author_minter_is_not_tried<B>(
        dsns: &[String; 3],
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let r = room(dsns, run, pick).await;
        let (_sha_a, _bytes_a, a_to_c) = seal(
            &r.alice_engine,
            &r.ba,
            &r.node_a,
            &r.comm,
            b"alice's epoch",
            &r.node_c,
        )
        .await;
        let (sha_b, bytes_b, b_to_c) = seal(
            &r.bob_engine,
            &r.bb,
            &r.node_b,
            &r.comm,
            b"sealed by bob, claimed for alice",
            &r.node_c,
        )
        .await;
        for row in [a_to_c, b_to_c] {
            r.carol_engine
                .apply_replicated_key_grant(row)
                .await
                .unwrap();
        }
        r.carol_engine
            .adopt_sealed_blob(
                &bytes_b,
                provenance(&r.alice, &r.comm, Some(&r.node_a)),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("bound to Alice's node, attributed to Alice");
        // Fixture check: Bob's DEK, recovered for Carol, DOES open the bytes.
        let dek = crate::federation::community_dek::orchestrate::recover_epoch_dek_for_viewer(
            r.bc.as_ref(),
            &r.comm,
            &r.node_b,
            0,
            &r.node_c,
        )
        .await
        .expect("Carol holds Bob's wrap");
        let envelope =
            crate::federation::at_rest_cascade::AtRestEnvelope::from_bytes(&bytes_b).unwrap();
        assert_eq!(
            crate::federation::at_rest_cascade::open(&dek, &envelope, None).unwrap(),
            b"sealed by bob, claimed for alice",
            "fixture: a non-author minter's DEK would open these bytes"
        );
        for _ in 0..2 {
            let err = r
                .carol_engine
                .read_blob_as(&sha_b, &r.node_c, None)
                .await
                .expect_err("I1781: a non-author minter's DEK is not tried");
            assert!(
                matches!(err, BlobError::SealDidNotOpen { .. }),
                "I1781: the refusal is unchanged: {err}"
            );
        }
        let err = r
            .carol_engine
            .read_blob_for_community_viewer(&sha_b, &r.node_c)
            .await
            .expect_err("I1781: nor through the community door");
        assert!(matches!(err, BlobError::SealDidNotOpen { .. }), "{err}");
        assert_eq!(
            bound(&r.bc, &sha_b).await,
            r.node_a,
            "I1781: nothing rebound onto a minter that does not act for the author"
        );
    }

    /// **I1782 — an unresolved lone candidate is unreachable.** (a) falls
    /// back to the author for a lone candidate that does not act for the
    /// author. The v61.4.0 answer would differ only for a candidate this node
    /// resolves to NO human — and no such candidate can exist: a peer's
    /// epoch row is admitted only if its signer is an active member
    /// occurrence of the room (`key_grant::is_active_member_at`, read through
    /// the same occurrence / owner records `principals_of` folds).
    ///
    /// Carol's node holds Alice on the roster but not the record that Alice
    /// occurs through node A. Node A's grant is REFUSED, retryably, so it is
    /// no candidate; the unnamed adopt strands on the author. When the
    /// occurrence lands and the row is re-offered, it is admitted, the
    /// strict repair rebinds the row (node A now acts for Alice), and the
    /// read opens — nothing was lost by not guessing.
    pub(crate) async fn i1782_an_unresolved_lone_candidate_is_unreachable<B>(
        dsns: &[String; 3],
        run: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let r = room_with(dsns, run, pick, false).await;
        assert_eq!(
            crate::federation::self_collective::principals_of(r.bc.as_ref(), &r.node_a)
                .await
                .unwrap()
                .into_iter()
                .filter(|p| *p != r.node_a)
                .count(),
            0,
            "fixture: node A resolves to no human on Carol's node"
        );
        let (sha_a, bytes_a, a_to_c) = seal(
            &r.alice_engine,
            &r.ba,
            &r.node_a,
            &r.comm,
            b"alice, node unresolved on carol",
            &r.node_c,
        )
        .await;
        let err = r
            .carol_engine
            .apply_replicated_key_grant(a_to_c.clone())
            .await
            .expect_err("I1782: an unresolved node's epoch row is not admitted");
        assert!(
            matches!(
                &err,
                crate::federation::Error::KeyGrantRefused { reason, .. }
                    if *reason == "signer_not_active_member"
            ),
            "I1782: refused as signer_not_active_member: {err}"
        );
        assert!(
            r.bc.community_dek_minters_granting(&r.comm, 0, &r.node_c)
                .await
                .unwrap()
                .is_empty(),
            "I1782: so it is no candidate"
        );
        r.carol_engine
            .adopt_sealed_blob(
                &bytes_a,
                provenance(&r.alice, &r.comm, None),
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("Carol adopts Alice's bytes");
        assert_eq!(bound(&r.bc, &sha_a).await, r.alice, "I1782: stranded");
        // The occurrence lands (the same record the other nodes hold).
        let kem_a = r.ba.load_or_init_content_kem_identity().await.unwrap();
        r.bc.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
            identity_key_id: r.alice.clone(),
            occurrence_key_id: r.node_a.clone(),
            device_class: crate::federation::types::device_class::LAPTOP.into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now() - chrono::Duration::minutes(5),
            valid_until: None,
            encryption_pubkeys: Some(EncryptionPubkeys {
                x25519_base64: kem_a.x25519_pubkey_b64,
                ml_kem_768_base64: kem_a.ml_kem_768_pubkey_b64,
            }),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap();
        r.carol_engine
            .apply_replicated_key_grant(a_to_c)
            .await
            .expect("I1782: re-offered after the occurrence, admitted");
        assert_eq!(
            bound(&r.bc, &sha_a).await,
            r.node_a,
            "I1782: the strict repair rebinds it"
        );
        assert_eq!(
            r.carol_engine
                .read_blob_as(&sha_a, &r.node_c, None)
                .await
                .expect("I1782: the read opens"),
            b"alice, node unresolved on carol"
        );
    }
}

#[cfg(test)]
mod run_1271 {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners_1271 {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::super::room_1271 as bodies;
                #[tokio::test]
                async fn i1776() {
                    let Some(d) = $dsns else { return };
                    bodies::i1776_the_late_seat_ordering_opens(&d, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i1777() {
                    let Some(d) = $dsns else { return };
                    bodies::i1777_one_candidate_is_filtered(&d, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i1778() {
                    let Some(d) = $dsns else { return };
                    bodies::i1778_the_repair_checks_the_author(&d, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i1779() {
                    let Some(d) = $dsns else { return };
                    bodies::i1779_a_wrong_binding_heals_on_read(&d, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i1782() {
                    let Some(d) = $dsns else { return };
                    bodies::i1782_an_unresolved_lone_candidate_is_unreachable(
                        &d,
                        &super::suffix(),
                        $pick,
                    )
                    .await
                }
                #[tokio::test]
                async fn i1781() {
                    let Some(d) = $dsns else { return };
                    bodies::i1781_a_non_author_minter_is_not_tried(&d, &super::suffix(), $pick)
                        .await
                }
                #[tokio::test]
                async fn i1780() {
                    let Some(d) = $dsns else { return };
                    bodies::i1780_an_ungranted_binding_is_not_healed(&d, &super::suffix(), $pick)
                        .await
                }
            }
        };
    }
    #[cfg(feature = "sqlite")]
    runners_1271!(
        sqlite,
        Some([
            "sqlite::memory:".to_owned(),
            "sqlite::memory:".to_owned(),
            "sqlite::memory:".to_owned(),
        ]),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
            as crate::federation::epoch_minter_invariants::bodies::Pick<
                crate::store::sqlite::SqliteBackend,
            >
    );
    #[cfg(feature = "postgres")]
    runners_1271!(
        postgres,
        (|| Some([
            crate::test_pg::empty_dsn()?,
            crate::test_pg::empty_dsn()?,
            crate::test_pg::empty_dsn()?,
        ]))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
            as crate::federation::epoch_minter_invariants::bodies::Pick<
                crate::store::postgres::PostgresBackend,
            >
    );
}
