//! CIRISPersist#973 — **I345–I349: the community boot leg and the re-bake
//! path.** Memory, sqlite, postgres.
//!
//! The "new bundle" here is minted by SOFTWARE holders: the bare-backend
//! roster (`A1`/`B1`/`C1` under deterministic test keys), so a row can be
//! re-signed. The real baked files are never touched.

pub(crate) mod bodies {
    use crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID as CANON;
    use crate::federation::canonical_community_invariants::bodies::{
        canonical_row, put_conferred, signed, stand_up_holders, SERVE_NODE,
    };
    use crate::federation::genesis::{
        canonical_genesis_bundle, install_or_supersede_delegation_row,
        seed_canonical_community_from, verify_canonical_community_seeded_for, CommunityLegOutcome,
        DelegationRowOutcome, GenesisFault, GenesisLeg,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{identity_type, ScrubSig};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// The ceremony's shape (#973): the three seated accord holders found the
    /// community and all three sign once; the one node it lists is seated by
    /// their signatures and its accord-scrubbed key record, and never signs.
    const HOLDERS: [&str; 3] = ["A1", "B1", "C1"];
    const NODE: &str = "rn1-remint-node";

    fn birth_row() -> crate::federation::types::Community {
        let mut row = canonical_row(&HOLDERS);
        for mem in &mut row.members {
            if mem.key_id == SERVE_NODE {
                mem.key_id = NODE.to_owned();
            }
        }
        row
    }

    fn sign_birth(
        row: crate::federation::types::Community,
        signers: &[&str],
    ) -> crate::federation::SignedCommunity {
        let mut s = signed(row, signers);
        s.cosignatures
            .retain(|c| signers.contains(&c.authority_key_id.as_str()));
        s
    }

    fn birth() -> crate::federation::SignedCommunity {
        sign_birth(birth_row(), &HOLDERS)
    }

    /// Holders typed as the baked records are, the accord family, and the
    /// node's accord-scrubbed key record.
    async fn stand_up(
        d: &dyn FederationDirectory,
    ) -> Vec<crate::federation::accord_test_support::Identity> {
        let holders = stand_up_holders(d).await;
        put_conferred(d, &holders, NODE, identity_type::NODE).await;
        holders
    }

    /// A baked delegation row re-minted by software holders: the same id and
    /// statement, `asserted_at` moved to `at`, signed by `signers[0]` and
    /// co-scrubbed by the rest. `scope_extra` changes the signed content.
    fn remint(
        baked: &Attestation,
        at: chrono::DateTime<chrono::Utc>,
        signers: &[&str],
        scope_extra: Option<&str>,
    ) -> SignedAttestation {
        let mut a = baked.clone();
        a.asserted_at = at;
        a.scrub_timestamp = at;
        a.pqc_completed_at = Some(at);
        a.attesting_key_id = signers[0].to_owned();
        a.scrub_key_id = signers[0].to_owned();
        a.attestation_envelope["asserted_at"] =
            serde_json::json!(crate::federation::admission::render_signed_instant(at));
        a.attestation_envelope["row"]["attesting_key_id"] = serde_json::json!(signers[0]);
        if let Some(extra) = scope_extra {
            a.attestation_envelope["note"] = serde_json::json!(extra);
        }
        crate::federation::canonical_at_rest::canonicalize_in_place(&mut a.attestation_envelope)
            .expect("canonicalize");
        let (och, sc, sp) = ts::sign_envelope(signers[0], &a.attestation_envelope);
        a.original_content_hash = och;
        a.scrub_signature_classical = sc;
        a.scrub_signature_pqc = sp;
        a.additional_scrubs = signers[1..]
            .iter()
            .map(|s| {
                let (_, c, p) = ts::sign_envelope(s, &a.attestation_envelope);
                ScrubSig {
                    scrub_key_id: (*s).to_owned(),
                    scrub_signature_classical: c,
                    scrub_signature_pqc: p,
                    cosigned_at: None,
                }
            })
            .collect();
        a.persist_row_hash = String::new();
        SignedAttestation { attestation: a }
    }

    async fn stored(d: &dyn FederationDirectory, id: &str) -> Attestation {
        d.get_attestation(id)
            .await
            .expect("read")
            .unwrap_or_else(|| panic!("{id} must be stored"))
    }

    /// The software world the delegation rows live in: holders, family,
    /// founders, and the key the grant row names.
    async fn world(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        for sa in &canonical_genesis_bundle().attestations {
            let k = &sa.attestation.attested_key_id;
            if d.lookup_public_key(k).await.unwrap().is_none()
                && k != crate::federation::canonical_community::accord_family_key_id()
            {
                put_conferred(d, &holders, k, identity_type::NODE).await;
            }
        }
    }

    fn t(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// **I345 — the leg is inert without an asset, and seeds through the
    /// signed door with one.**
    pub async fn i345_inert_then_seeds(d: &dyn FederationDirectory) {
        stand_up(d).await;
        assert_eq!(
            seed_canonical_community_from(d, None, crate::federation::genesis::RosterSource::Bake)
                .await
                .unwrap(),
            CommunityLegOutcome::NotBaked,
            "I345: no asset, nothing done"
        );
        assert!(d.lookup_community(CANON).await.unwrap().is_none());
        verify_canonical_community_seeded_for(d, None)
            .await
            .expect("I345: no asset, nothing to verify");
        assert_eq!(
            crate::federation::genesis::canonical_community_asset()
                .map(|b| b.community.community_key_id.as_str()),
            Some(CANON),
            "I345: the final genesis bakes the ciris-canonical birth (v53.1.1)"
        );
        let asset = birth();
        let fault = verify_canonical_community_seeded_for(d, Some(&asset))
            .await
            .expect_err("I345: baked and not yet held");
        assert!(
            matches!(
                fault,
                GenesisFault::Absent {
                    leg: GenesisLeg::Community,
                    ..
                }
            ),
            "I345: {fault:?}"
        );
        assert_eq!(
            seed_canonical_community_from(
                d,
                Some(&asset),
                crate::federation::genesis::RosterSource::Bake
            )
            .await
            .unwrap(),
            CommunityLegOutcome::Installed
        );
        let held = d.lookup_community(CANON).await.unwrap().expect("seeded");
        assert_eq!(held.members.len(), asset.community.members.len());
        verify_canonical_community_seeded_for(d, Some(&asset))
            .await
            .expect("I345: seeded");
        assert_eq!(
            seed_canonical_community_from(
                d,
                Some(&asset),
                crate::federation::genesis::RosterSource::Bake
            )
            .await
            .unwrap(),
            CommunityLegOutcome::AlreadyHeld,
            "I345: a second boot is a no-op"
        );
    }

    /// **I346 — a birth the door refuses is `Absent`, never `Divergent`, and
    /// nothing is stored.** The signed door is what refuses.
    pub async fn i346_refusal_is_absent(d: &dyn FederationDirectory) {
        stand_up(d).await;
        // one accord signer: below the quorum
        let weak = sign_birth(birth_row(), &["A1"]);
        // a tampered record under intact signatures
        let mut forged = birth();
        forged.community.community_name = "Someone Else's Root".to_owned();
        // a birth on a node with no roster at all is covered by the fresh
        // backend below; here both refusals come from the signed door
        for (what, asset) in [("under-quorum", weak), ("tampered", forged)] {
            let fault = seed_canonical_community_from(
                d,
                Some(&asset),
                crate::federation::genesis::RosterSource::Bake,
            )
            .await
            .expect_err(what);
            assert!(
                matches!(
                    fault,
                    GenesisFault::Absent {
                        leg: GenesisLeg::Community,
                        ..
                    }
                ),
                "I346 {what}: {fault:?}"
            );
            assert!(!fault.refuses_boot(), "I346 {what}: must boot");
            assert!(
                d.lookup_community(CANON).await.unwrap().is_none(),
                "I346 {what}: a refused birth writes nothing"
            );
        }
    }

    /// **I346b — on a node with no accord roster (pre-genesis), the leg is
    /// `Absent` and the node boots.**
    pub async fn i346b_pre_genesis_is_absent(d: &dyn FederationDirectory) {
        let fault = seed_canonical_community_from(
            d,
            Some(&birth()),
            crate::federation::genesis::RosterSource::Bake,
        )
        .await
        .expect_err("I346b: no roster to verify against");
        assert!(
            matches!(
                fault,
                GenesisFault::Absent {
                    leg: GenesisLeg::Community,
                    ..
                }
            ),
            "I346b: {fault:?}"
        );
        assert!(!fault.refuses_boot());
    }

    /// **I347 — a node that holds a different record under the id keeps it.**
    pub async fn i347_held_record_is_left(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let mut other = birth_row();
        other.community_name = "CIRIS Canonical Services (ahead)".to_owned();
        d.put_community(sign_birth(other.clone(), &HOLDERS))
            .await
            .expect("the held record admits");
        assert_eq!(
            seed_canonical_community_from(
                d,
                Some(&birth()),
                crate::federation::genesis::RosterSource::Bake
            )
            .await
            .unwrap(),
            CommunityLegOutcome::HeldDiffers
        );
        assert_eq!(
            d.lookup_community(CANON)
                .await
                .unwrap()
                .unwrap()
                .community_name,
            other.community_name,
            "I347: the held record is untouched"
        );
        verify_canonical_community_seeded_for(d, Some(&birth()))
            .await
            .expect("I347: held is seeded");
    }

    /// **I348 — the re-bake: same ids, strictly newer instants supersede;
    /// equal instants do not; an identical row is current.**
    pub async fn i348_rebake_supersedes_by_instant(d: &dyn FederationDirectory) {
        world(d).await;
        let today = t("2026-08-14T14:48:29.049Z");
        let later = t("2026-08-20T10:00:00.000Z");
        for baked in &canonical_genesis_bundle().attestations {
            let id = baked.attestation.attestation_id.clone();
            // "today's" row, as a software ceremony would have minted it
            let old = remint(&baked.attestation, today, &["A1", "B1"], None);
            assert_eq!(
                install_or_supersede_delegation_row(d, &old, None)
                    .await
                    .unwrap_or_else(|e| panic!("I348 {id}: today's row installs: {e}")),
                DelegationRowOutcome::Installed
            );
            let before = stored(d, &id).await;
            // identical ⇒ current
            assert_eq!(
                install_or_supersede_delegation_row(d, &old, Some(before.clone()))
                    .await
                    .unwrap(),
                DelegationRowOutcome::AlreadyCurrent,
                "I348 {id}"
            );
            // EQUAL instant, different content ⇒ never replaces, never faults
            let tie = remint(&baked.attestation, today, &["A1", "B1"], Some("tie"));
            assert_eq!(
                install_or_supersede_delegation_row(d, &tie, Some(before.clone()))
                    .await
                    .unwrap_or_else(|e| panic!("I348 {id}: a tie must not fault the boot: {e}")),
                DelegationRowOutcome::LeftAsNewerCeremony,
                "I348 {id}: equal vintage is not a successor"
            );
            assert_eq!(
                stored(d, &id).await.original_content_hash,
                before.original_content_hash
            );
            // STRICTLY newer ⇒ supersedes, id kept
            let new = remint(&baked.attestation, later, &["A1", "B1"], Some("re-mint"));
            assert_eq!(
                install_or_supersede_delegation_row(d, &new, Some(before.clone()))
                    .await
                    .unwrap_or_else(|e| panic!("I348 {id}: the re-mint supersedes: {e}")),
                DelegationRowOutcome::Superseded,
                "I348 {id}"
            );
            let after = stored(d, &id).await;
            assert_eq!(after.attestation_id, id, "I348: the id is kept");
            assert_eq!(after.asserted_at, later);
            assert_ne!(after.original_content_hash, before.original_content_hash);
            // and the OLD row offered again is a rollback, refused
            assert_eq!(
                install_or_supersede_delegation_row(d, &old, Some(after.clone()))
                    .await
                    .unwrap(),
                DelegationRowOutcome::LeftAsNewerCeremony,
                "I348 {id}: no rollback"
            );
        }
        // the canonical server record, byte-identical, is Unchanged
        let grant = &canonical_genesis_bundle().attestations[1].attestation;
        let node = d
            .lookup_public_key(&grant.attested_key_id)
            .await
            .unwrap()
            .expect("the serve node record");
        let outcome = d
            .apply_replicated_key_record(crate::federation::SignedKeyRecord { record: node })
            .await
            .expect("re-offer");
        assert_eq!(
            outcome,
            crate::federation::register::ReplicatedKeyOutcome::Unchanged,
            "I348: a byte-identical canonical record is Unchanged"
        );
    }

    /// **I349 — a re-minted row carrying a THIRD co-scrub (C1) verifies and
    /// stores, fresh and as a successor.**
    pub async fn i349_third_coscrub_stores(d: &dyn FederationDirectory) {
        world(d).await;
        let today = t("2026-08-14T14:48:29.049Z");
        let later = t("2026-08-20T10:00:00.000Z");
        for baked in &canonical_genesis_bundle().attestations {
            let id = baked.attestation.attestation_id.clone();
            let old = remint(&baked.attestation, today, &["A1", "B1"], None);
            install_or_supersede_delegation_row(d, &old, None)
                .await
                .unwrap();
            let before = stored(d, &id).await;
            let three = remint(
                &baked.attestation,
                later,
                &["A1", "B1", "C1"],
                Some("three"),
            );
            assert_eq!(
                install_or_supersede_delegation_row(d, &three, Some(before))
                    .await
                    .unwrap_or_else(|e| panic!("I349 {id}: three scrubs supersede: {e}")),
                DelegationRowOutcome::Superseded
            );
            let after = stored(d, &id).await;
            let scrubbers: Vec<&str> = after
                .additional_scrubs
                .iter()
                .map(|s| s.scrub_key_id.as_str())
                .collect();
            assert_eq!(scrubbers, ["B1", "C1"], "I349 {id}: both co-scrubs stored");
            assert_eq!(after.scrub_key_id, "A1");
            // settled: the same three-scrub row is current on the next boot
            assert_eq!(
                install_or_supersede_delegation_row(d, &three, Some(after))
                    .await
                    .unwrap(),
                DelegationRowOutcome::AlreadyCurrent,
                "I349 {id}"
            );
        }
    }
}

mod run {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i345() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i345_inert_then_seeds(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i346() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i346_refusal_is_absent(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i346b() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i346b_pre_genesis_is_absent(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i347() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i347_held_record_is_left(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i348() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i348_rebake_supersedes_by_instant(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i349() {
                    let Some(d) = $fresh.await else { return };
                    bodies::i349_third_coscrub_stores(&d as &dyn FederationDirectory).await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
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
