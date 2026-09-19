//! CIRISPersist#870 — **a holder claim's `signed_wire_index` entry moves with
//! the row.** Witnesses I113 (the put door), I113b (the adopt door) and I114
//! (from disk: every attestation INSERT site outside `put_attestation` runs
//! the index hook).
//!
//! The defect, measured on a three-node chat ladder: `put_blob_with_scope` and
//! `adopt_sealed_blob_at` INSERT the `holds_bytes` claim inside their own
//! transaction and never ran the post-write `index_stored_record("Attestation",
//! …)` that `put_attestation` runs. The claim was *advertised* (the summary
//! reads `list_attestations_since`, a federation-tier row qualifies) and
//! *unfetchable* (the packer resolves a want through `signed_wire_index`), so
//! no peer ever learned a holder and every blob-backed body read `not_fetched`
//! until the holder's next restart rebuilt the index. #610's rule — the index
//! moves WITH the row — held at every door but the two that write a claim.
//!
//! The memory backend implements no `BlobStorage`, so I113/I113b run on
//! sqlite and postgres; I114 reads both backend files.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::adopt_cascade::{adopt_sealed_blob, AdoptDisposition};
    use crate::federation::at_rest_cascade::blob_invariants::hold_ctx;
    use crate::federation::key_grant_invariants::two_node::node_as;
    use crate::federation::replication::hold::BlobProvenance;
    use crate::federation::types::cohort_scope::{CryptoTier, FEDERATION};
    use crate::federation::types::identity_type::NODE;
    use crate::federation::{wire_index, Attestation, BlobBody, BlobStorage, FederationDirectory};

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).into()
    }

    /// The `holds_bytes` row `holder` wrote for `sha`, from the directory.
    async fn holder_claim<B: FederationDirectory + Sync>(
        d: &B,
        holder: &str,
        sha: &[u8; 32],
    ) -> Attestation {
        let want = crate::federation::holds_bytes_attestation_type(sha);
        d.list_attestations_by(holder)
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.attestation_type == want)
            .expect("the holder claim is a stored row")
    }

    /// The property both doors must satisfy: the claim's index entry exists
    /// NOW — advertised on the wire-hash plane and resolvable by the point
    /// read the packer uses — with no rebuild in between.
    async fn assert_claim_is_fetchable<B: FederationDirectory + Sync>(
        d: &B,
        claim: &Attestation,
        tag: &str,
    ) {
        let key = wire_index::record_key(&[("attestation_id", &claim.attestation_id)]);
        let hash = wire_index::entry_as_stored(d, "Attestation", &key)
            .await
            .unwrap()
            .expect("the stored row hashes");
        let advertised = d
            .list_wire_hashes_since("Attestation", None, 100_000)
            .await
            .unwrap();
        assert!(
            advertised.iter().any(|h| *h == hash),
            "{tag}: the claim's hash is on the wire-hash plane the moment it is written (#870): \
             {hash} not among {} advertised",
            advertised.len()
        );
        let bytes = d
            .lookup_signed_record_by_content_hash("Attestation", &hash)
            .await
            .unwrap();
        assert!(
            bytes.is_some(),
            "{tag}: the packer's point read resolves the claim through signed_wire_index — \
             advertised AND fetchable, without a rebuild"
        );
    }

    /// **I113 — `put_blob_with_scope` (behind `put_blob_signing_scoped` /
    /// `Engine::put_blob_scoped`) indexes the holder claim it writes.**
    pub async fn i113_the_put_door_indexes_its_holder_claim<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let n = node_as(b, &format!("i113-holder-{s}"), NODE).await;
        let bytes = format!("i113 public bytes {s}").into_bytes();
        let sha = sha256_of(&bytes);
        b.put_blob_signing_scoped(
            FEDERATION,
            None,
            &sha,
            BlobBody::Inline(bytes),
            None,
            &n.key,
            &n.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .expect("I113: the announcing put succeeds");
        assert_eq!(b.list_holders(&sha).await.unwrap(), vec![n.key.clone()]);
        let claim = holder_claim(b, &n.key, &sha).await;
        assert_claim_is_fetchable(b, &claim, "I113 put").await;
    }

    /// **I113b — `adopt_sealed_blob_at` with `Announce` indexes the holder
    /// claim it writes (the puller's re-announcement, at the chat's
    /// CommunityDek shape).**
    pub async fn i113b_the_adopt_door_indexes_its_holder_claim<B>(b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::{fresh_dek, seal};
        use crate::federation::key_grant_invariants::two_node::seed_community_everywhere;
        use crate::federation::types::cohort_scope::COMMUNITY;
        let author = node_as(b, &format!("i113b-author-{s}"), NODE).await;
        let adopter = node_as(b, &format!("i113b-adopter-{s}"), NODE).await;
        let comm = format!("i113b-comm-{s}");
        let member = format!("i113b-member-{s}");
        seed_community_everywhere(&[&adopter], &comm, &[(&member, Some(&adopter))]).await;
        let envelope = seal(
            &fresh_dek().unwrap(),
            format!("i113b sealed bytes {s}").as_bytes(),
            None,
        )
        .unwrap()
        .to_bytes();
        let sha = sha256_of(&envelope);
        let ctx = hold_ctx(false, &adopter.key, &[]);
        let out = adopt_sealed_blob(
            b,
            Some(&*adopter.signer),
            &ctx,
            &envelope,
            &BlobProvenance {
                author_key_id: author.key.clone(),
                cohort_scope: COMMUNITY.to_owned(),
                community_key_id: Some(comm.clone()),
                epoch: Some(0),
                tier: CryptoTier::CommunityDek,
            },
            None,
            AdoptDisposition::Announce,
        )
        .await
        .expect("I113b: the announcing adopt succeeds");
        assert_eq!(out.sha256, sha);
        assert!(out.announced);
        assert_eq!(
            b.list_holders(&sha).await.unwrap(),
            vec![adopter.key.clone()]
        );
        let claim = holder_claim(b, &adopter.key, &sha).await;
        assert_claim_is_fetchable(b, &claim, "I113b adopt").await;
    }

    /// Deliver A's whole Attestation plane to B the way edge does: the
    /// advertised wire hashes, one point read per hash, one
    /// `apply_replicated_attestation` per row. Returns how many rows B
    /// admitted. Nothing is hand-copied — a row A holds but does not index
    /// never arrives, which is the defect's exact shape.
    async fn deliver_attestation_plane<B>(a: &B, b: &B) -> usize
    where
        B: FederationDirectory + Sync,
    {
        use crate::federation::attestation_apply::ReplicatedAttestationOutcome as O;
        let mut delivered = 0usize;
        let mut cursor: Option<String> = None;
        loop {
            let page = a
                .list_wire_hashes_since("Attestation", cursor.as_deref(), 256)
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            cursor = page.last().cloned();
            for hash in &page {
                let Some(bytes) = a
                    .lookup_signed_record_by_content_hash("Attestation", hash)
                    .await
                    .unwrap()
                else {
                    panic!("advertised-then-unfetchable on A itself: {hash} (#429)");
                };
                let row: Attestation = serde_json::from_slice(&bytes).unwrap();
                match b
                    .apply_replicated_attestation(crate::federation::SignedAttestation {
                        attestation: row,
                    })
                    .await
                {
                    Ok(O::Inserted) => delivered += 1,
                    Ok(_) => {}
                    Err(e) => panic!("B refused a row A advertised: {e}"),
                }
            }
        }
        delivered
    }

    /// **I113c — the production path, two nodes: A writes a community blob
    /// exactly as `Engine::put_blob_scoped` does (the chat body's shape);
    /// B learns the holder ONLY through A's advertised hashes and point
    /// reads. Before #870 the claim was advertised on the row plane and
    /// absent from the index, so B's `list_holders` stayed empty and every
    /// body read `not_fetched`.**
    pub async fn i113c_a_peer_learns_the_holder_through_the_planes<B>(a: &B, b: &B, s: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
        use crate::federation::key_grant_invariants::two_node::{
            introduce_as, seed_community_everywhere,
        };
        use crate::federation::types::cohort_scope::COMMUNITY;
        let na = node_as(a, &format!("i113c-a-{s}"), NODE).await;
        let nb = node_as(b, &format!("i113c-b-{s}"), NODE).await;
        introduce_as(
            &[&na, &nb],
            &[&format!("i113c-a-{s}"), &format!("i113c-b-{s}")],
            NODE,
        )
        .await;
        let comm = format!("i113c-comm-{s}");
        let (alice, bob) = (format!("i113c-alice-{s}"), format!("i113c-bob-{s}"));
        seed_community_everywhere(
            &[&na, &nb],
            &comm,
            &[(&alice, Some(&na)), (&bob, Some(&nb))],
        )
        .await;

        // A writes the chat body: sealed under the community DEK, announced.
        let put = put_blob_scoped(
            a,
            &na.signer,
            COMMUNITY,
            Some(&comm),
            format!("hamburger {s}").as_bytes(),
            None,
            None,
        )
        .await
        .expect("I113c: A's scoped put succeeds");
        let sha = put.at_rest_sha256;
        assert_eq!(
            a.list_holders(&sha).await.unwrap(),
            vec![na.key.clone()],
            "I113c: A holds"
        );
        assert!(
            b.list_holders(&sha).await.unwrap().is_empty(),
            "I113c: B knows no holder yet"
        );

        // B pulls A's Attestation plane the way edge does.
        let delivered = deliver_attestation_plane(a, b).await;
        assert!(
            delivered >= 1,
            "I113c: at least the holder claim crossed ({delivered})"
        );
        assert_eq!(
            b.list_holders(&sha).await.unwrap(),
            vec![na.key.clone()],
            "I113c: B learned the holder through the planes — the pull can now find the bytes"
        );
        // And B's own claim, once it adopts and re-announces, is fetchable by A.
        let claim = holder_claim(b, &na.key, &sha).await;
        assert_claim_is_fetchable(b, &claim, "I113c on B").await;
    }
}

#[cfg(test)]
mod run {
    /// **I114 — from disk: every `INSERT INTO federation_attestations` outside
    /// `put_attestation` is followed, in its own function, by the index hook
    /// — or is a named local-tier writer, whose rows never enter the wire
    /// index until they cross (`enter_mesh` indexes them then).**
    ///
    /// The class this pins: "a second write door for the same table without
    /// the first door's post-write". It recurred at two doors before anyone
    /// measured it; the next door that grows an INSERT reds here.
    #[test]
    fn i114_every_attestation_insert_site_runs_the_index_hook() {
        const LOCAL_TIER_WRITERS: &[&str] = &[
            // Local-tier rows are not on the wire until they cross; the crossing
            // (`enter_mesh`) indexes them. Named, with the reason, on purpose.
            "sqlite_write_local_attestation",
            "pg_write_local_attestation",
        ];
        let mut sites_seen = 0usize;
        let mut offenders: Vec<String> = Vec::new();
        for (rel, text, needle) in [
            (
                "src/store/sqlite.rs",
                include_str!("../store/sqlite.rs"),
                "INSERT INTO federation_attestations",
            ),
            (
                "src/store/sqlite.rs",
                include_str!("../store/sqlite.rs"),
                "INSERT OR IGNORE INTO federation_attestations",
            ),
            (
                "src/store/postgres.rs",
                include_str!("../store/postgres.rs"),
                "INSERT INTO cirislens.federation_attestations",
            ),
        ] {
            // Production text only: everything before the file's trailing test
            // modules. Both backends open them with a top-level `#[cfg(test)]`
            // in the second half of the file (postgres.rs also carries a small
            // `#[cfg(test)] mod attestation_id_is_text_622` near the top, which
            // holds no INSERT and is not the boundary).
            let prod_end = text
                .match_indices("\n#[cfg(test)]\nmod ")
                .map(|(i, _)| i)
                .find(|&i| i > text.len() / 2)
                .expect("the backend file has a trailing test module");
            let prod = &text[..prod_end];
            for (site, _) in prod.match_indices(needle) {
                // The INSERT OR IGNORE of put_attestation is the reference door.
                let head = &prod[..site];
                let fn_start = [
                    "\n    async fn ",
                    "\n    pub async fn ",
                    "\n    pub(crate) async fn ",
                    "\n    fn ",
                ]
                .iter()
                .filter_map(|p| head.rfind(p).map(|i| (i, p.len())))
                .max_by_key(|(i, _)| *i)
                .expect("an INSERT site sits inside a method");
                let name_start = fn_start.0 + fn_start.1;
                let name_end = prod[name_start..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .map(|k| name_start + k)
                    .unwrap();
                let name = &prod[name_start..name_end];
                let body_end = prod[site..]
                    .find("\n    }\n")
                    .map(|k| site + k)
                    .unwrap_or(prod.len());
                let body = &prod[fn_start.0..body_end];
                sites_seen += 1;
                let indexed = body.contains("index_stored_record(\"Attestation\"")
                    || body.contains("index_stored_record(\n") && body.contains("\"Attestation\",");
                if !indexed && !LOCAL_TIER_WRITERS.contains(&name) {
                    offenders.push(format!("{rel}: `{name}` inserts a federation_attestations row and never indexes it"));
                }
            }
        }
        assert!(
            sites_seen >= 8,
            "I114: expected at least 8 production INSERT sites across both backends (put door, \
             two blob doors, local writer, each), saw {sites_seen} — a gate that finds nothing \
             holds nothing"
        );
        assert!(
            offenders.is_empty(),
            "I114 (#870): a write door for federation_attestations without put_attestation's \
             post-write index hook — advertised but unfetchable:\n{}",
            offenders.join("\n")
        );
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i113() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i113_the_put_door_indexes_its_holder_claim(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i113b() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i113b_the_adopt_door_indexes_its_holder_claim(&b, &super::suffix())
                        .await
                }
                #[tokio::test]
                async fn i113c() {
                    let Some(a) = $fresh.await else { return };
                    let Some(b) = $fresh.await else { return };
                    bodies::i113c_a_peer_learns_the_holder_through_the_planes(
                        &a,
                        &b,
                        &super::suffix(),
                    )
                    .await
                }
            }
        };
    }
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
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
