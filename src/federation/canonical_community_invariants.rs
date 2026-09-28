//! v50.0.0 (CIRISPersist#926, ruling (b); FSD `SECOND_DEVICE.md` §9) — **I190:
//! the `ciris-canonical` community row is admitted under the accord's quorum
//! and served beside the bundle.**
//!
//! (a) the fixture row, co-scrubbed 2-of-3 by the accord holders, admits and
//! resolves to a non-empty founder set, `infrastructure`, entrenched — and its
//! co-signatures are served back; (b) 1-of-3 is refused, and a founder's
//! signature does not count toward the ACCORD's quorum; (c) a `node`-bearing
//! founder is refused (#925's rule), so is a founder the accord did not confer,
//! so is each CC 3.2 shape clause; (d) `trust:accepts:v1` on `ciris-canonical`
//! is the one-row un-trust (CC 3.2 T3) and leaves the row standing; (e) the
//! CC 5.3.4 response carries the row beside the bundle and a fresh consumer
//! pins from that one response; (f) #809 — a bundle whose holder quorum is
//! short is REFUSED, not reported; (g) a supersede cannot lift the
//! entrenchment, drop the constraint, or change without the founders' quorum.
//!
//! The fixture is a BARE directory standing up the genesis accord roster under
//! test-held keys ([`register_genesis_accord_roster`]) — nobody holds the #268
//! ceremony's private halves, so the real row's signing is outside persist.
//!
//! [`register_genesis_accord_roster`]: crate::federation::accord_test_support::register_genesis_accord_roster

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::accord_test_support as ops;
    use crate::federation::canonical_community::{
        self as cc, CIRIS_CANONICAL_COMMUNITY_KEY_ID as CANON,
    };
    use crate::federation::genesis::bundle::{
        authorization_digest, GenesisAuthorization, GenesisBundle,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        identity_type, Community, CommunityMember, KeyRecord, RosterCosignature, SignedCommunity,
        SignedKeyRecord,
    };
    use crate::federation::{Error, FederationDirectory};

    /// The three founders (human steward keys) and the one serve node. Short,
    /// distinct-first-byte ids: the test signer seeds from the first 32 bytes.
    pub(crate) const FOUNDERS: [&str; 3] = ["us-steward", "eu-steward", "ap-steward"];
    pub(crate) const SERVE_NODE: &str = "cc1-serve-node";

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    /// A key record for `key_id` with its deterministic test pubkeys.
    fn key_record(key_id: &str, identity: &str) -> KeyRecord {
        let (ed, mldsa) = ts::hybrid_pubkeys(key_id);
        let now = at("2026-01-01T00:00:00Z");
        KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed,
            pubkey_ml_dsa_65_base64: mldsa,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// `key_id` as an accord-CONFERRED record: its registration co-scrubbed
    /// 2-of-3 by the genesis holders (the ceremony plane, CC 3.2 T2).
    pub(crate) async fn put_conferred(
        d: &dyn FederationDirectory,
        holders: &[ops::Identity],
        key_id: &str,
        identity: &str,
    ) {
        let record =
            ops::accord_conferred(key_record(key_id, identity), &[&holders[0], &holders[1]]);
        d.put_public_key(SignedKeyRecord { record })
            .await
            .unwrap_or_else(|e| panic!("conferred {key_id} admits: {e}"));
    }

    /// The trust root stood up on a bare directory: the genesis holders under
    /// test keys, the entrenched accord family, three human stewards the
    /// accord conferred, and one serve node. Returns the holders.
    pub(crate) async fn stand_up(d: &dyn FederationDirectory) -> Vec<ops::Identity> {
        let holders = ops::register_genesis_accord_roster(d)
            .await
            .expect("genesis accord roster");
        crate::federation::genesis::seed_accord_family(d)
            .await
            .expect("accord family");
        for f in FOUNDERS {
            put_conferred(d, &holders, f, "user,steward").await;
        }
        ts::register_hybrid_key_as(d, SERVE_NODE, SERVE_NODE, identity_type::NODE).await;
        holders
    }

    /// The CC 3.2 worked example as a record.
    pub(crate) fn canonical_row(founders: &[&str]) -> Community {
        let joined = at("2026-09-20T00:00:00Z");
        let mut members: Vec<CommunityMember> = founders
            .iter()
            .map(|k| CommunityMember {
                key_id: (*k).to_owned(),
                joined_at: joined,
                role: Some("founder".to_owned()),
            })
            .collect();
        members.push(CommunityMember {
            key_id: SERVE_NODE.to_owned(),
            joined_at: joined,
            role: Some("member".to_owned()),
        });
        Community {
            community_key_id: CANON.to_owned(),
            community_name: "CIRIS Canonical Services".to_owned(),
            members,
            founded_at: joined,
            consensus_protocol: "quorum:2/3".to_owned(),
            policy_blob: Some(serde_json::json!({
                "cohort_subkind": "infrastructure",
                "cohort_subkind_payload": {
                    "infrastructure_constraint": {
                        "service_class": "canonical",
                        "admission_quorum_basis": "founders",
                    }
                },
                "consensus_protocol_entrenched": true,
            })),
            persist_row_hash: String::new(),
        }
    }

    /// Sign `row` by `signers[0]` and co-sign by the rest.
    pub(crate) fn signed(row: Community, signers: &[&str]) -> SignedCommunity {
        let mut s = ts::sign_community(signers[0], row);
        for c in &signers[1..] {
            let (_h, classical, pqc) = ts::sign_envelope(c, &s.community.signing_envelope());
            s.cosignatures.push(RosterCosignature {
                authority_key_id: (*c).to_owned(),
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
            });
        }
        s
    }

    fn assert_violation(e: &Error, needle: &str) {
        let msg = e.to_string();
        assert!(
            matches!(e, Error::CommunityConsensusProtocolViolation { .. })
                && msg.contains("hard_case:community_consensus_protocol_violation")
                && msg.contains(needle),
            "expected a typed community_consensus_protocol_violation naming {needle:?}, got: {e:?}"
        );
    }

    async fn assert_not_stored(d: &dyn FederationDirectory) {
        assert!(
            d.lookup_community(CANON).await.unwrap().is_none(),
            "a refused row writes nothing"
        );
    }

    /// (a) — admitted under a 2-of-3 accord co-scrub; resolves.
    pub async fn a_admitted_under_the_accord_quorum(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let row = signed(canonical_row(&FOUNDERS), &["A1", "B1"]);
        d.put_community(row.clone())
            .await
            .expect("2-of-3 accord co-scrub admits the ciris-canonical row");
        let r = cc::resolve_community(d, CANON)
            .await
            .unwrap()
            .expect("a fresh install resolves ciris-canonical");
        assert_eq!(r.founders, FOUNDERS.to_vec(), "{r:?}");
        assert_eq!(r.members, vec![SERVE_NODE.to_owned()], "{r:?}");
        assert_eq!(r.cohort_subkind.as_deref(), Some("infrastructure"));
        assert_eq!(r.consensus_protocol, "quorum:2/3");
        assert!(r.consensus_protocol_entrenched);
        // The co-signature is persisted and served: a peer re-derives the quorum.
        let served = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .expect("the signed row is served");
        assert_eq!(
            served.cosignatures, row.cosignatures,
            "co-signatures served byte-exact"
        );
        assert_eq!(served.authority_key_id, "A1");
        let q = cc::accord_quorum_over_community(d, &served).await.unwrap();
        assert!(q.met() && q.distinct_holders == 2, "{q:?}");
        // An identical re-put is the #758 no-op, never a second door.
        d.put_community(row)
            .await
            .expect("identical re-put is a no-op");
    }

    /// (b) — 1-of-3 refused; a founder's co-signature is not an accord vote.
    pub async fn b_one_of_three_is_refused(d: &dyn FederationDirectory) {
        stand_up(d).await;
        for signers in [
            &["A1"][..],
            &["A1", FOUNDERS[0]][..],
            &[FOUNDERS[0], FOUNDERS[1]][..],
        ] {
            let e = d
                .put_community(signed(canonical_row(&FOUNDERS), signers))
                .await
                .expect_err("short of the accord quorum");
            assert!(
                matches!(
                    &e,
                    Error::RosterAuthorityUnauthorized { rule, group_key_id, .. }
                        if *rule == crate::federation::ROSTER_CONSENSUS_INSUFFICIENT
                            && group_key_id == CANON
                ),
                "signers {signers:?}: the typed insufficient-quorum refusal, got {e:?}"
            );
        }
        // A co-signature that does not verify does not count.
        let mut forged = signed(canonical_row(&FOUNDERS), &["A1", "B1"]);
        forged.cosignatures[0].scrub_signature_classical = forged.scrub_signature_classical.clone();
        assert!(
            d.put_community(forged).await.is_err(),
            "a forged co-scrub counts for nothing"
        );
        // A quorate row carrying one bad co-scrub more is refused AT THE DOOR,
        // not admitted on the two that verify: evidence that does not verify
        // is never stored as decoration (the roster-row rule).
        let mut padded = signed(canonical_row(&FOUNDERS), &["A1", "B1", "C1"]);
        padded.cosignatures[1].scrub_signature_classical = padded.scrub_signature_classical.clone();
        let e = d
            .put_community(padded)
            .await
            .expect_err("an unverifiable co-signature is refused even beside a quorum");
        assert!(
            !matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "refused by the co-signature check, not the count: {e:?}"
        );
        let mut doubled = signed(canonical_row(&FOUNDERS), &["A1", "B1"]);
        doubled.cosignatures.push(doubled.cosignatures[0].clone());
        let e = d
            .put_community(doubled)
            .await
            .expect_err("a co-signer counted twice is refused");
        assert!(e.to_string().contains("counted once"), "{e:?}");
        assert_not_stored(d).await;
    }

    /// (c) — founder eligibility and the CC 3.2 shape.
    pub async fn c_founders_and_shape(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        // #925: a node-bearing key, even accord-conferred, cannot be a founder.
        put_conferred(d, &holders, "nd-founder", "node,steward").await;
        let e = d
            .put_community(signed(
                canonical_row(&[FOUNDERS[0], FOUNDERS[1], "nd-founder"]),
                &["A1", "B1"],
            ))
            .await
            .expect_err("a node-bearing founder is refused");
        assert_violation(&e, "#925");
        // A human steward the accord did not confer is not a founder.
        ts::register_hybrid_key_as(d, "sf-steward", "sf-steward", "user,steward").await;
        let e = d
            .put_community(signed(
                canonical_row(&[FOUNDERS[0], FOUNDERS[1], "sf-steward"]),
                &["A1", "B1"],
            ))
            .await
            .expect_err("a self-declared steward is not an accord-conferred founder");
        assert!(
            matches!(&e, Error::RoleNotAccordConferred { key_id, .. } if key_id == "sf-steward"),
            "{e:?}"
        );
        // The shape clauses, each alone.
        let mut not_entrenched = canonical_row(&FOUNDERS);
        not_entrenched.policy_blob.as_mut().unwrap()["consensus_protocol_entrenched"] =
            serde_json::json!(false);
        let mut majority = canonical_row(&FOUNDERS);
        majority.consensus_protocol = "majority".to_owned();
        let mut basis = canonical_row(&FOUNDERS);
        basis.policy_blob.as_mut().unwrap()["cohort_subkind_payload"]
            ["infrastructure_constraint"]["admission_quorum_basis"] = serde_json::json!("members");
        let mut geographic = canonical_row(&FOUNDERS);
        geographic.policy_blob.as_mut().unwrap()["cohort_subkind"] =
            serde_json::json!("geographic");
        let mut no_founder = canonical_row(&[]);
        no_founder.members[0].role = Some("member".to_owned());
        for (row, needle) in [
            (not_entrenched, "entrenched"),
            (majority, "quorum:M/N"),
            (basis, "admission_quorum_basis"),
            (geographic, "cohort_subkind"),
            (no_founder, "no founder"),
        ] {
            let e = d
                .put_community(signed(row, &["A1", "B1"]))
                .await
                .expect_err("non-conformant trust-root shape");
            assert_violation(&e, needle);
        }
        // The reserved id cannot be squatted by a plain self-signed row.
        ts::register_hybrid_key_as(d, "squatter", "squatter", identity_type::USER).await;
        let mut squat = canonical_row(&["squatter"]);
        squat.members.truncate(1);
        squat.policy_blob = None;
        squat.consensus_protocol = "founder_only".to_owned();
        let e = d
            .put_community(ts::sign_community("squatter", squat))
            .await
            .expect_err("ciris-canonical is reserved to the trust-root door");
        assert_violation(&e, "cohort_subkind");
        assert_not_stored(d).await;
    }

    /// The accord family chartered as a VALID root: `delegates_to(A1 →
    /// humanity-accord)` labelled `trust:charter:v1`, co-scrubbed by B1 and C1
    /// (the family's 2-of-3 and more), with a recovery pre-commitment.
    pub(crate) async fn charter_the_accord(d: &dyn FederationDirectory) {
        use crate::federation::trust_root::{
            pre_rotation_commitment, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE, TRUST_CHARTER_DIMENSION,
        };
        let family = cc::accord_family_key_id();
        let id = uuid::Uuid::new_v4().to_string();
        let commitment =
            pre_rotation_commitment(&["accord-succ-a".to_owned(), "accord-succ-b".to_owned()])
                .unwrap();
        let charter = ops::co_signed_trust_attestation(
            &id,
            "A1",
            family,
            crate::federation::types::attestation_type::DELEGATES_TO,
            serde_json::json!({
                "references_attestation_id": id,
                "dimension": TRUST_CHARTER_DIMENSION,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                "pre_rotation_commitment": commitment,
            }),
            &["B1", "C1"],
        );
        d.put_attestation(crate::federation::SignedAttestation {
            attestation: charter,
        })
        .await
        .expect("the accord charters itself 3-of-3");
    }

    /// (d) — CC 3.2 T3 and the community arm of `trust_root_valid`: a consumer
    /// whose one `trust:accepts:v1` row names `ciris-canonical` holds a VALID
    /// root (the accord family's legs, the community's edge); withdrawing that
    /// one row makes it not accepted; the community row is untouched by it
    /// (trust ≠ membership).
    pub async fn d_the_one_row_untrust(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::trust_root::{trust_root_valid, RootKind};
        stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let consumer = format!("{tag}-consumer");
        ts::register_hybrid_key_as(d, &consumer, &consumer, identity_type::USER).await;
        let before = trust_root_valid(d, &consumer, CANON).await.unwrap();
        assert!(
            !before.valid && !before.edge_exists,
            "no trust before the consumer's own edge: {before:?}"
        );
        let edge = ops::emit_trust_edge(d, &consumer, CANON, None)
            .await
            .expect("the consumer pins ciris-canonical");
        // The community is a roster rooted in its family, never a root of its
        // own: with the accord not yet chartered, the edge alone is not valid.
        let unchartered = trust_root_valid(d, &consumer, CANON).await.unwrap();
        assert!(
            unchartered.edge_exists
                && unchartered.root_kind == RootKind::Community
                && !unchartered.valid,
            "the community root is valid only through a valid family root: {unchartered:?}"
        );
        charter_the_accord(d).await;
        let pinned = trust_root_valid(d, &consumer, CANON).await.unwrap();
        assert!(
            pinned.valid && pinned.root_kind == RootKind::Community,
            "the trust:accepts:v1 edge to ciris-canonical is a VALID root through the \
             accord family: {pinned:?}"
        );
        assert!(
            pinned.charter_quorum.is_some_and(|q| q.met()),
            "the charter leg is the accord family's quorum: {pinned:?}"
        );
        ops::withdraw_attestation(d, &consumer, CANON, &edge)
            .await
            .expect("one withdraws row");
        let untrusted = trust_root_valid(d, &consumer, CANON).await.unwrap();
        assert!(
            !untrusted.valid,
            "one row un-trusts: the root is no longer accepted: {untrusted:?}"
        );
        let still = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert_eq!(
            still.founders.len(),
            3,
            "un-trust does not touch the community row"
        );
    }

    /// A GenesisBundle over the test holders, authorized by `signers`.
    pub(crate) async fn test_bundle(
        d: &dyn FederationDirectory,
        signers: &[&str],
    ) -> GenesisBundle {
        let mut holders = Vec::new();
        for h in ["A1", "B1", "C1"] {
            holders.push(SignedKeyRecord {
                record: d
                    .lookup_public_key(h)
                    .await
                    .unwrap()
                    .expect("holder seeded"),
            });
        }
        let mut bundle = GenesisBundle {
            version: 3,
            family_key_id: ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
                .to_owned(),
            holders,
            serve_nodes: Vec::new(),
            consensus_protocol: "quorum:2/3".to_owned(),
            attestations: Vec::new(),
            authorizations: Vec::new(),
            produced_at: "2026-09-27T00:00:00Z".to_owned(),
        };
        let digest = authorization_digest(&bundle).unwrap();
        for s in signers {
            let sig = ts::threshold_sign(s, &digest);
            bundle.authorizations.push(GenesisAuthorization {
                holder_key_id: (*s).to_owned(),
                signature_classical: sig.ed25519_signature_base64,
                signature_pqc: sig.mldsa65_signature_base64.unwrap(),
            });
        }
        bundle
    }

    /// (e) — the CC 5.3.4 response carries the row beside the bundle, and a
    /// fresh consumer pins from that one response.
    pub async fn e_served_beside_the_bundle(
        server: &dyn FederationDirectory,
        consumer: &dyn FederationDirectory,
        fresh: &dyn FederationDirectory,
    ) {
        stand_up(server).await;
        let bundle = test_bundle(server, &["A1", "B1"]).await;
        let empty = cc::trust_root_bundle_response(server, &bundle)
            .await
            .unwrap();
        assert!(
            empty.community.is_none(),
            "no row yet: served as absent, honestly"
        );
        server
            .put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let resp = cc::trust_root_bundle_response(server, &bundle)
            .await
            .unwrap();
        let wire = serde_json::to_string(&resp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert!(
            v["bundle"]["authorizations"].is_array(),
            "the bundle rides as carried"
        );
        assert!(
            v["bundle"].get("community").is_none(),
            "the row is BESIDE the bundle, never inside it"
        );
        assert_eq!(v["community"]["community"]["community_key_id"], CANON);
        assert_eq!(v["charter_root_key_id"], "humanity-accord");
        assert!(
            [
                "A1",
                "B1",
                FOUNDERS[0],
                FOUNDERS[1],
                FOUNDERS[2],
                SERVE_NODE
            ]
            .iter()
            .all(|k| resp
                .community_member_records
                .iter()
                .any(|r| r.record.key_id == *k))
                && resp.community_member_records.len() == 6,
            "the records of every key the chain names (founders, serve node, the birth's \
             authority) travel with the row"
        );
        // The consumer: a fresh install of the same accord (genesis holders +
        // family), nothing else.
        ops::register_genesis_accord_roster(consumer).await.unwrap();
        crate::federation::genesis::seed_accord_family(consumer)
            .await
            .unwrap();
        assert!(cc::resolve_community(consumer, CANON)
            .await
            .unwrap()
            .is_none());
        let from_wire: cc::TrustRootBundleResponse = serde_json::from_str(&wire).unwrap();
        let pinned = cc::pin_trust_from_bundle_response(consumer, &from_wire)
            .await
            .expect("one response pins ciris-canonical");
        assert_eq!(pinned.family, "humanity-accord");
        assert_eq!(pinned.bundle_holders_verified, 2);
        assert_eq!(pinned.community.founders, FOUNDERS.to_vec());
        // A response whose row lost a co-signature in transit pins nothing on a
        // GENUINELY fresh consumer: the door re-derives the accord quorum and
        // refuses by the typed insufficient-quorum refusal.
        ops::register_genesis_accord_roster(fresh).await.unwrap();
        crate::federation::genesis::seed_accord_family(fresh)
            .await
            .unwrap();
        let mut stripped = from_wire.clone();
        stripped.community.as_mut().unwrap().cosignatures.clear();
        let e = cc::pin_trust_from_bundle_response(fresh, &stripped)
            .await
            .expect_err("a row short of its co-signature pins nothing");
        assert!(
            matches!(
                &e,
                Error::RosterAuthorityUnauthorized { rule, .. }
                    if *rule == crate::federation::ROSTER_CONSENSUS_INSUFFICIENT
            ),
            "{e:?}"
        );
        assert!(cc::resolve_community(fresh, CANON).await.unwrap().is_none());
    }

    /// (f) — #809: a bundle whose holder quorum is short is REFUSED.
    pub async fn f_a_short_bundle_is_refused(
        server: &dyn FederationDirectory,
        consumer: &dyn FederationDirectory,
    ) {
        stand_up(server).await;
        server
            .put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        ops::register_genesis_accord_roster(consumer).await.unwrap();
        crate::federation::genesis::seed_accord_family(consumer)
            .await
            .unwrap();
        for signers in [&["A1"][..], &[][..]] {
            let short = test_bundle(server, signers).await;
            let resp = cc::trust_root_bundle_response(server, &short)
                .await
                .unwrap();
            let e = cc::pin_trust_from_bundle_response(consumer, &resp)
                .await
                .expect_err("a short bundle quorum is refused, not reported");
            assert!(
                matches!(&e, Error::GenesisBundleInvalid { detail } if detail.contains("quorum not met")),
                "{signers:?}: {e:?}"
            );
        }
        assert!(
            cc::resolve_community(consumer, CANON)
                .await
                .unwrap()
                .is_none(),
            "a refused bundle pins nothing"
        );
    }

    /// The change envelope `d` builds for `next`, bound to it
    /// ([`cc::bind_next_version`]) at `amended_at`, then `edit`ed.
    async fn bound_envelope(
        d: &dyn FederationDirectory,
        next: &Community,
        amended_at: chrono::DateTime<chrono::Utc>,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> serde_json::Value {
        let ids: Vec<String> = next.members.iter().map(|m| m.key_id.clone()).collect();
        let mut change = d
            .build_membership_change_envelope(
                crate::federation::cohort::Cohort::Community,
                CANON,
                &ids,
                false,
                Some(&next.consensus_protocol),
            )
            .await
            .unwrap();
        cc::bind_next_version(&mut change, next, amended_at).unwrap();
        edit(&mut change);
        change
    }

    /// A founders'-quorum supersede of the stored row to `next` on the LOCAL
    /// door: the envelope bound to `next`, signed by `founder_signers`, the new
    /// version signed by the first of them.
    pub(crate) async fn founders_supersede(
        d: &dyn FederationDirectory,
        next: Community,
        founder_signers: &[&str],
    ) -> Result<u32, Error> {
        let change = bound_envelope(d, &next, chrono::Utc::now(), |_| {}).await;
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        let sigs = founder_signers
            .iter()
            .map(|k| ts::threshold_sign(k, &bytes))
            .collect();
        d.supersede_community_with_quorum(
            ts::sign_community(founder_signers[0], next),
            change,
            sigs,
        )
        .await
    }

    fn with_member(mut row: Community, key_id: &str, role: &str) -> Community {
        row.members.push(CommunityMember {
            key_id: key_id.to_owned(),
            joined_at: at("2026-09-21T00:00:00Z"),
            role: Some(role.to_owned()),
        });
        row
    }

    /// `row` with `from` replaced by `to` (same role, same instant).
    fn swapped(mut row: Community, from: &str, to: &str) -> Community {
        for m in &mut row.members {
            if m.key_id == from {
                m.key_id = to.to_owned();
            }
        }
        row
    }

    /// A founders' proof over `next` built by hand against `d`'s held version,
    /// for the REPLICATED door: the bound envelope, then `edit`, signed by
    /// `signers`; the version signed by `authority` and carrying the held
    /// row's chain.
    async fn hand_proof(
        d: &dyn FederationDirectory,
        next: Community,
        signers: &[&str],
        authority: &str,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> SignedCommunity {
        let change = bound_envelope(d, &next, chrono::Utc::now(), edit).await;
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        let held = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        let mut offered = ts::sign_community(authority, next);
        offered.lineage = cc::chain_of(&held);
        offered.supersede_proof = Some(crate::federation::types::GroupSupersedeProof {
            prior_persist_row_hash: held.community.persist_row_hash.clone(),
            change_envelope: change,
            quorum_signatures: signers
                .iter()
                .map(|k| ts::threshold_sign(k, &bytes))
                .collect(),
        });
        offered
    }

    async fn fresh_consumer(d: &dyn FederationDirectory) {
        ops::register_genesis_accord_roster(d).await.unwrap();
        crate::federation::genesis::seed_accord_family(d)
            .await
            .unwrap();
    }

    /// (h) — after the accord's birth, the row amends by its FOUNDERS' quorum
    /// and travels as a CHAIN from that birth; founder seats move only through
    /// the record.
    ///
    /// Node `a` amends twice: v2 adds a serve node; v3 adds another AND swaps
    /// founder F2 for a newly conferred founder (h′). A FRESH consumer pins v3
    /// from `a`'s one response, walking from the birth; it refuses v3 without
    /// its chain and a chain that skips v2. Peer `b`, holding v1, never shown
    /// v2, walks to v3. Refused on the local door: a single founder, a protocol
    /// move, an unconferred added founder. Refused on peer `c`: a short proof,
    /// a protocol move under a genuine proof, a BODY VARIANT under a genuine
    /// proof (one proof, one body), a body keeping a founder the signed
    /// envelope demoted, a proof-less version, an authority that is not a
    /// counted founder, and (h″) a proof counting a founder whose conferral was
    /// withdrawn before the link.
    pub async fn h_amended_by_the_founders(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        c: &dyn FederationDirectory,
        fresh: &dyn FederationDirectory,
    ) {
        for dir in [a, b, c] {
            let holders = stand_up(dir).await;
            put_conferred(dir, &holders, "f3-steward", "user,steward").await;
            dir.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
                .await
                .unwrap();
            for n in ["cc2-serve-node", "cc3-serve-node"] {
                ts::register_hybrid_key_as(dir, n, n, identity_type::NODE).await;
            }
        }
        let v2_body = with_member(canonical_row(&FOUNDERS), "cc2-serve-node", "member");
        let v3_body = swapped(
            with_member(v2_body.clone(), "cc3-serve-node", "member"),
            FOUNDERS[2],
            "f3-steward",
        );
        // Local refusals.
        let e = founders_supersede(a, v2_body.clone(), &[FOUNDERS[0]])
            .await
            .expect_err("one founder is not the founders' quorum");
        assert!(
            matches!(
                &e,
                Error::RosterAuthorityUnauthorized { rule, .. }
                    if *rule == crate::federation::ROSTER_CONSENSUS_INSUFFICIENT
            ),
            "the founders' link judges the local door too: {e:?}"
        );
        let mut loosened = v2_body.clone();
        loosened.consensus_protocol = "quorum:3/3".to_owned();
        let e = founders_supersede(a, loosened, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect_err("an entrenched protocol does not move");
        assert_violation(&e, "entrenched");
        ts::register_hybrid_key_as(a, "uc-steward", "uc-steward", "user,steward").await;
        let e = founders_supersede(
            a,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "uc-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect_err("an added founder must be accord-conferred");
        assert!(
            matches!(&e, Error::RoleNotAccordConferred { key_id, .. } if key_id == "uc-steward"),
            "{e:?}"
        );
        // The founders' quorum amends: v2, then v3 (h′: a founder swapped).
        founders_supersede(a, v2_body.clone(), &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders' 2-of-3 amends the trust root (v2)");
        let v2 = cc::lookup_signed_community(a, CANON)
            .await
            .unwrap()
            .unwrap();
        founders_supersede(a, v3_body.clone(), &[FOUNDERS[1], FOUNDERS[2]])
            .await
            .expect("…and swaps a founder through the record (v3)");
        let v3 = cc::lookup_signed_community(a, CANON)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            v3.lineage.len(),
            2,
            "v3 carries its chain: the birth and v2"
        );
        assert!(matches!(
            cc::stored_standing(a, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        // A FRESH node: nothing without the chain, nothing through a skip.
        fresh_consumer(fresh).await;
        for k in [FOUNDERS[0], FOUNDERS[1], FOUNDERS[2], "f3-steward"] {
            let record = a.lookup_public_key(k).await.unwrap().unwrap();
            fresh
                .put_public_key(crate::federation::types::SignedKeyRecord { record })
                .await
                .unwrap();
        }
        let mut orphan = v3.clone();
        orphan.lineage.clear();
        let e = fresh
            .put_community(orphan)
            .await
            .expect_err("a fresh node admits no amended row without its chain from the birth");
        assert_violation(&e, "accord birth");
        // A lineage entry whose authority signature does not verify.
        let mut forged = v3.clone();
        forged.lineage[1].scrub_signature_classical =
            forged.lineage[0].scrub_signature_classical.clone();
        assert!(
            fresh.put_community(forged).await.is_err(),
            "every lineage entry's authority signature is verified"
        );
        let mut skipping = v3.clone();
        skipping.lineage.truncate(1);
        let e = fresh
            .put_community(skipping)
            .await
            .expect_err("a link whose proof names a version the chain skips");
        assert_violation(&e, "does not name the version it follows");
        assert!(fresh.lookup_community(CANON).await.unwrap().is_none());
        // …and pins v3 from a's one response.
        let bundle = test_bundle(a, &["A1", "B1"]).await;
        let resp = cc::trust_root_bundle_response(a, &bundle).await.unwrap();
        let wire = serde_json::to_string(&resp).unwrap();
        let pinned =
            cc::pin_trust_from_bundle_response(fresh, &serde_json::from_str(&wire).unwrap())
                .await
                .expect("a fresh consumer walks the chain and pins the amended row");
        assert_eq!(
            pinned.community.founders,
            vec![
                FOUNDERS[0].to_owned(),
                FOUNDERS[1].to_owned(),
                "f3-steward".to_owned()
            ]
        );
        assert_eq!(pinned.community.members.len(), 3);
        // Peer b holds v1 and never saw v2: it walks from v1 to v3.
        b.put_community(v3.clone())
            .await
            .expect("a peer that missed v2 walks the chain from what it holds");
        assert!(
            b.list_group_versions(crate::federation::cohort::Cohort::Community, CANON)
                .await
                .unwrap()
                .len()
                >= 3,
            "b applied v2 and v3 in order"
        );
        // Peer refusals, on c (holding v1).
        let mut short = v2.clone();
        short
            .supersede_proof
            .as_mut()
            .unwrap()
            .quorum_signatures
            .truncate(1);
        let e = c
            .put_community(short)
            .await
            .expect_err("a proof short of the founders' quorum");
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "{e:?}"
        );
        let mut loosened = v2_body.clone();
        loosened.consensus_protocol = "quorum:3/3".to_owned();
        let offered = hand_proof(
            c,
            loosened,
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
            |_| {},
        )
        .await;
        let e = c
            .put_community(offered)
            .await
            .expect_err("the entrenched protocol does not move on the replicated door");
        assert_violation(&e, "entrenched");
        // MEDIUM-B: one genuine proof admits exactly one body.
        let mut variant = v2.clone();
        variant.community.policy_blob.as_mut().unwrap()["cohort_subkind_payload"]
            ["infrastructure_constraint"]["service_class"] = serde_json::json!("registry");
        let variant = SignedCommunity {
            supersede_proof: v2.supersede_proof.clone(),
            lineage: v2.lineage.clone(),
            ..ts::sign_community(FOUNDERS[0], variant.community)
        };
        let e = c
            .put_community(variant)
            .await
            .expect_err("a body variant under a genuine proof");
        assert_violation(&e, "one proof, one body");
        let kept = hand_proof(
            c,
            v2_body.clone(),
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
            |env| {
                for m in env["members"].as_array_mut().unwrap() {
                    if m["key_id"] == FOUNDERS[2] {
                        m["role"] = serde_json::json!("member");
                    }
                }
            },
        )
        .await;
        let e = c
            .put_community(kept)
            .await
            .expect_err("the founders' envelope binds the founder roles");
        assert_violation(&e, "bind the founder roles");
        // A founder-set change whose envelope names the new founder as a
        // member: the roles bind even when the set moves.
        let promoted_body = swapped(v2_body.clone(), FOUNDERS[2], "f3-steward");
        let unbound = hand_proof(
            c,
            promoted_body,
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
            |env| {
                for m in env["members"].as_array_mut().unwrap() {
                    if m["key_id"] == "f3-steward" {
                        m["role"] = serde_json::json!("member");
                    }
                }
            },
        )
        .await;
        let e = c
            .put_community(unbound)
            .await
            .expect_err("a moved founder set must be bound by the envelope's roles");
        assert_violation(&e, "bind the founder roles");
        for (when, why) in [
            (
                "2000-01-01T00:00:00Z",
                "an amended_at before the version it follows",
            ),
            ("2099-01-01T00:00:00Z", "an amended_at in the future"),
        ] {
            let off = hand_proof(
                c,
                v2_body.clone(),
                &[FOUNDERS[0], FOUNDERS[1]],
                FOUNDERS[0],
                |env| env[cc::AMENDED_AT] = serde_json::json!(when),
            )
            .await;
            let e = c.put_community(off).await.expect_err(why);
            assert_violation(&e, "amended_at");
        }
        let bare = ts::sign_community(FOUNDERS[0], v2_body.clone());
        assert!(
            c.put_community(bare).await.is_err(),
            "a different version with no founders' proof is refused"
        );
        let stranger = hand_proof(
            c,
            v2_body.clone(),
            &[FOUNDERS[0], FOUNDERS[1]],
            "cc2-serve-node",
            |_| {},
        )
        .await;
        let e = c
            .put_community(stranger)
            .await
            .expect_err("the version's authority must be a counted founder");
        assert_violation(&e, "not one of the founders");
        // h″: F2's conferral is withdrawn; a proof counting F2 does not reach
        // the quorum (the body demotes F2, so every founder it names counts).
        withdraw_steward_by_accord(
            c,
            FOUNDERS[2],
            chrono::Utc::now() + chrono::Duration::seconds(1),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
        let demoted = swapped(v2_body.clone(), FOUNDERS[2], "f3-steward");
        let counted_withdrawn = hand_proof(
            c,
            demoted.clone(),
            &[FOUNDERS[0], FOUNDERS[2]],
            FOUNDERS[0],
            |_| {},
        )
        .await;
        let e = c
            .put_community(counted_withdrawn)
            .await
            .expect_err("a withdrawn founder's signature does not count");
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "{e:?}"
        );
        // The same demotion by two founders that count: the founders retire F2
        // through the record, and the row is rooted again.
        let retire = hand_proof(c, demoted, &[FOUNDERS[0], FOUNDERS[1]], FOUNDERS[0], |_| {}).await;
        c.put_community(retire)
            .await
            .expect("the founders retire a withdrawn founder through the record");
        assert_eq!(
            cc::resolve_community(c, CANON)
                .await
                .unwrap()
                .unwrap()
                .founders,
            vec![
                FOUNDERS[0].to_owned(),
                FOUNDERS[1].to_owned(),
                "f3-steward".to_owned()
            ]
        );
    }

    fn widening_row(
        member: &str,
        role: Option<&str>,
    ) -> crate::federation::types::CommunityMembershipWidening {
        // Now, not earlier: a moderator's standing is judged at the row's
        // instant, and the appointment was issued moments ago.
        let t = chrono::Utc::now();
        crate::federation::types::CommunityMembershipWidening {
            community_key_id: CANON.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: t,
            effective_at: t,
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        }
    }

    fn widening_by(
        signers: &[&str],
        member: &str,
        role: Option<&str>,
    ) -> crate::federation::SignedCommunityMembershipWidening {
        let mut w = ts::sign_community_membership_widening(signers[0], widening_row(member, role));
        for c in &signers[1..] {
            ts::cosign_community_membership_widening(&mut w, c);
        }
        w
    }

    fn founder_revocation(
        signers: &[&str],
        founder: &str,
    ) -> crate::federation::SignedCommunityMembershipRevocation {
        founder_revocation_at(signers, founder, chrono::Utc::now())
    }

    /// [`founder_revocation`] dated `t` (removed and effective).
    fn founder_revocation_at(
        signers: &[&str],
        founder: &str,
        t: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::SignedCommunityMembershipRevocation {
        let mut r = ts::sign_community_membership_revocation(
            signers[0],
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: CANON.to_owned(),
                removed_identity_key_id: founder.to_owned(),
                removed_at: t,
                effective_at: t,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        for c in &signers[1..] {
            ts::cosign_community_membership_revocation(&mut r, c);
        }
        r
    }

    /// (k) — rooted needs EVERY recorded founder to count now. A founder whose
    /// steward conferral is withdrawn STALLS the row (not resolved, not
    /// served, naming the founder); a founders' amendment retiring that seat
    /// through the record roots it again.
    pub async fn k_every_recorded_founder_counts(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, "kr-steward", "user,steward").await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_some());
        withdraw_steward_by_accord(d, FOUNDERS[2], chrono::Utc::now()).await;
        match cc::stored_standing(d, CANON).await.unwrap() {
            cc::StoredStanding::Stalled { reason, .. } => {
                assert!(reason.contains(FOUNDERS[2]), "{reason}")
            }
            other => panic!("a withdrawn founder stalls the row: {other:?}"),
        }
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_none());
        let retired = swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "kr-steward");
        founders_supersede(d, retired, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders retire the withdrawn founder through the record");
        let r = cc::resolve_community(d, CANON)
            .await
            .unwrap()
            .expect("rooted again once every recorded founder counts");
        assert_eq!(
            r.founders,
            vec![
                FOUNDERS[0].to_owned(),
                FOUNDERS[1].to_owned(),
                "kr-steward".to_owned()
            ]
        );
    }

    /// Withdraw `key`'s steward conferral THROUGH THE ACCORD: a stored
    /// proposal (window ending at `window_until`) with A1's and B1's signed YES,
    /// re-tallied by `withdraw_accord_role_over_roster`. The withdrawal's
    /// instant is then the proposal's signed `window_until` on every node.
    pub(crate) async fn withdraw_steward_by_accord(
        d: &dyn FederationDirectory,
        key: &str,
        window_until: chrono::DateTime<chrono::Utc>,
    ) {
        use crate::federation::accord_quorum::test_fixtures::signed_participation;
        use ciris_verify_core::accord_live_quorum::Vote;
        let proposal = withdrawal_proposal(key, window_until);
        store_proposal(d, &proposal).await;
        let roster: Vec<ciris_verify_core::threshold::ThresholdMember> = ["A1", "B1", "C1"]
            .iter()
            .map(|k| ops::Identity::new(k).member())
            .collect();
        for h in ["A1", "B1"] {
            d.put_accord_participation(
                signed_participation(&ops::Identity::new(h), &proposal, Vote::Yes),
                &roster,
            )
            .await
            .unwrap();
        }
        crate::federation::admission::withdraw_accord_role_over_roster(
            d,
            identity_type::STEWARD,
            key,
            &proposal.digest(),
            &crate::federation::admission::accord_holder_roster_key_ids(),
        )
        .await
        .expect("the accord withdraws the conferral");
    }

    /// An accord proposal to withdraw `key`'s steward conferral, its window
    /// ending at `window_until` (not stored).
    fn withdrawal_proposal(
        key: &str,
        window_until: chrono::DateTime<chrono::Utc>,
    ) -> ciris_verify_core::accord_live_quorum::AccordProposal {
        use ciris_verify_core::accord_live_quorum::{AccordAction, AccordProposal};
        let op = crate::federation::admission::op_withdraw_role(identity_type::STEWARD);
        AccordProposal {
            family_key_id: cc::accord_family_key_id().to_owned(),
            action: AccordAction::RosterChange,
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            window_until: crate::federation::admission::truncate_to_substrate_resolution(
                window_until,
            )
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            prior_family_digest: "prior-family-digest".to_owned(),
            payload_sha256: crate::federation::admission::canonical_withdrawal_payload_sha256(
                &op, key, None,
            )
            .unwrap(),
        }
    }

    /// Store `proposal` on `d` (its nonce issued first).
    async fn store_proposal(
        d: &dyn FederationDirectory,
        proposal: &ciris_verify_core::accord_live_quorum::AccordProposal,
    ) {
        d.issue_accord_nonce(cc::accord_family_key_id(), &proposal.nonce)
            .await
            .unwrap();
        d.put_accord_proposal(proposal.clone(), None).await.unwrap();
    }

    /// (k′) — the recovery ruling: two withdrawn conferrals stall the row and
    /// the lone founder cannot reach `quorum:2/3`; an accord RE-BIRTH (founded
    /// later) replaces the STALLED row and it is rooted again. A re-birth never
    /// replaces a ROOTED row.
    pub async fn k2_rebirth_over_a_stalled_row(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        for k in ["f4-steward", "f5-steward"] {
            put_conferred(d, &holders, k, "user,steward").await;
        }
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let mut rebirth = canonical_row(&[FOUNDERS[0], "f4-steward", "f5-steward"]);
        rebirth.founded_at = at("2026-09-25T00:00:00Z");
        let e = d
            .put_community(signed(rebirth.clone(), &["A1", "B1"]))
            .await
            .expect_err("a re-birth does not replace a ROOTED row");
        assert_violation(&e, "does not extend");
        for f in [FOUNDERS[1], FOUNDERS[2]] {
            withdraw_steward_by_accord(d, f, chrono::Utc::now()).await;
        }
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Stalled { .. }
        ));
        let mut lone = canonical_row(&FOUNDERS);
        lone.members[1].role = Some("member".to_owned());
        lone.members[2].role = Some("member".to_owned());
        assert!(
            founders_supersede(d, lone, &[FOUNDERS[0]]).await.is_err(),
            "the lone founder cannot reach the quorum"
        );
        let mut not_later = rebirth.clone();
        not_later.founded_at = at("2026-09-20T00:00:00Z");
        let e = d
            .put_community(signed(not_later, &["A1", "B1"]))
            .await
            .expect_err("a re-birth must be founded LATER than the held chain's birth");
        assert_violation(&e, "does not extend");
        d.put_community(signed(rebirth, &["A1", "B1"]))
            .await
            .expect("an accord re-birth replaces the stalled row");
        let r = cc::resolve_community(d, CANON)
            .await
            .unwrap()
            .expect("rooted again");
        assert_eq!(
            r.founders,
            vec![
                FOUNDERS[0].to_owned(),
                "f4-steward".to_owned(),
                "f5-steward".to_owned()
            ]
        );
        let versions = d
            .list_group_versions(crate::federation::cohort::Cohort::Community, CANON)
            .await
            .unwrap();
        assert!(
            versions.iter().any(|v| v
                .authorization
                .as_ref()
                .is_some_and(|a| a.get("accord_rebirth_replaces_stalled").is_some())),
            "the re-birth is recorded as such"
        );
    }

    /// (o) — the consent floor: a founder's OWN plane revocation is a
    /// RESIGNATION. It is admitted without moving the record, the row stalls,
    /// a later link counting the resigned founder falls short, and the other
    /// founders retire the seat through the record.
    pub async fn o_a_founder_resigns(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, "or-steward", "user,steward").await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        d.put_community_membership_revocation(founder_revocation(&[FOUNDERS[2]], FOUNDERS[2]))
            .await
            .expect("a founder resigns by their own signature");
        match cc::stored_standing(d, CANON).await.unwrap() {
            cc::StoredStanding::Stalled { reason, .. } => {
                assert!(reason.contains(FOUNDERS[2]), "{reason}")
            }
            other => panic!("a resignation stalls the row: {other:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let retired = swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "or-steward");
        let counting_resigned = hand_proof(
            d,
            retired.clone(),
            &[FOUNDERS[0], FOUNDERS[2]],
            FOUNDERS[0],
            |_| {},
        )
        .await;
        let e = d
            .put_community(counting_resigned)
            .await
            .expect_err("a resigned founder's signature does not count");
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "{e:?}"
        );
        founders_supersede(d, retired, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the remaining founders retire the seat through the record");
        assert_eq!(
            cc::resolve_community(d, CANON)
                .await
                .unwrap()
                .expect("rooted again")
                .founders,
            vec![
                FOUNDERS[0].to_owned(),
                FOUNDERS[1].to_owned(),
                "or-steward".to_owned()
            ]
        );
        // LOW-1: a resignation is older than the version that RE-SEATS the
        // key; the founders re-seat F2 through the record and the old
        // resignation no longer applies.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let reseat = canonical_row(&FOUNDERS);
        founders_supersede(d, reseat, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders re-seat the resigned key through the record");
        assert_eq!(
            cc::resolve_community(d, CANON)
                .await
                .unwrap()
                .expect("a re-seat clears the older resignation")
                .founders,
            FOUNDERS.to_vec()
        );
        // …and the re-seated founder's signature counts on a LATER link: the
        // old resignation is not later than that link's prior version
        // (MEDIUM-R (b)).
        ts::register_hybrid_key_as(d, "or-serve-node", "or-serve-node", identity_type::NODE).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            d,
            with_member(canonical_row(&FOUNDERS), "or-serve-node", "member"),
            &[FOUNDERS[2], FOUNDERS[0]],
        )
        .await
        .expect("a re-seated founder co-signs a later link");
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_some());
    }

    /// (o″) — the counting rule (round 9 ruling) and the lapse trace. F2
    /// resigns at t1, after the birth. The other founders' v6 that still
    /// RECORDS F2 is admitted on the replicated chain door: F2 counts as
    /// nothing, so the row reads Stalled, naming F2. v6 → v7: F2's resignation
    /// lies in (seated_since(F2) = the birth, t7], so F2 with F0 produces no v7
    /// on either door — the resignation did not lapse although v6's instant is
    /// after it. F0 + F1 amend F2 out (Rooted), then RE-SEAT F2, so
    /// seated_since(F2) = t8 > t1: F2 counts again and co-signs a later link.
    pub async fn o3_a_resignation_does_not_lapse(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, "rr-steward", "user,steward").await;
        for n in ["rr-serve-node", "rr2-serve-node", "rr3-serve-node"] {
            ts::register_hybrid_key_as(d, n, n, identity_type::NODE).await;
        }
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        d.put_community_membership_revocation(founder_revocation(&[FOUNDERS[2]], FOUNDERS[2]))
            .await
            .expect("F2 resigns");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let v6 = with_member(canonical_row(&FOUNDERS), "rr-serve-node", "member");
        let offered = hand_proof(
            d,
            v6.clone(),
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
            |_| {},
        )
        .await;
        d.put_community(offered)
            .await
            .expect("a later version MAY still record the resigned founder");
        match cc::stored_standing(d, CANON).await.unwrap() {
            cc::StoredStanding::Stalled { reason, .. } => {
                assert!(reason.contains(FOUNDERS[2]), "{reason}")
            }
            other => panic!("a version recording a resigned founder is Stalled: {other:?}"),
        }
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_none());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // The lapse: v6's instant is after F2's resignation, but F2 was seated
        // at the birth, so the resignation still un-counts F2 on v6 → v7.
        for v7 in [
            with_member(v6.clone(), "rr2-serve-node", "member"),
            swapped(v6.clone(), FOUNDERS[2], "rr-steward"),
        ] {
            assert!(
                founders_supersede(d, v7.clone(), &[FOUNDERS[2], FOUNDERS[0]])
                    .await
                    .is_err(),
                "local: F2 and F0 produce no v7"
            );
            let offered = hand_proof(d, v7, &[FOUNDERS[2], FOUNDERS[0]], FOUNDERS[0], |_| {}).await;
            assert!(
                d.put_community(offered).await.is_err(),
                "replicated: F2 and F0 produce no v7"
            );
        }
        founders_supersede(
            d,
            swapped(v6.clone(), FOUNDERS[2], "rr-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("the others amend the resigned seat out");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(d, v6.clone(), &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the others re-seat F2 through the record");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            d,
            with_member(v6, "rr3-serve-node", "member"),
            &[FOUNDERS[2], FOUNDERS[0]],
        )
        .await
        .expect("after the re-seat F2 counts again");
        assert_eq!(
            cc::resolve_community(d, CANON)
                .await
                .unwrap()
                .unwrap()
                .founders,
            FOUNDERS.to_vec()
        );
    }

    /// (o‴) — every resignation counts, not only the earliest: F2 resigns,
    /// the founders retire F2 and then RE-SEAT F2 through the record (the
    /// re-seat clears the first resignation), and F2 resigns AGAIN, dated after
    /// the re-seat head. The row stalls, naming F2.
    pub async fn o4_a_second_resignation_counts(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, "rs-steward", "user,steward").await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        d.put_community_membership_revocation(founder_revocation(&[FOUNDERS[2]], FOUNDERS[2]))
            .await
            .expect("F2 resigns");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            d,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "rs-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("the founders retire F2");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(d, canonical_row(&FOUNDERS), &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders re-seat F2");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        d.put_community_membership_revocation(founder_revocation(&[FOUNDERS[2]], FOUNDERS[2]))
            .await
            .expect("the re-seated F2 resigns again");
        match cc::stored_standing(d, CANON).await.unwrap() {
            cc::StoredStanding::Stalled { reason, .. } => {
                assert!(reason.contains(FOUNDERS[2]), "{reason}")
            }
            other => panic!("the second resignation stalls the row: {other:?}"),
        }
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_none());
    }

    /// F2 resigns, the others retire F2 and re-seat F2 through the record:
    /// a Rooted row whose folded roster already excludes F2 (the shape in
    /// which a new resignation moved nothing but its own instant).
    async fn resigned_retired_reseated(d: &dyn FederationDirectory, successor: &str) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, successor, "user,steward").await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        d.put_community_membership_revocation(founder_revocation(&[FOUNDERS[2]], FOUNDERS[2]))
            .await
            .expect("F2 resigns");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            d,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], successor),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("the founders retire F2");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(d, canonical_row(&FOUNDERS), &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders re-seat F2");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
    }

    /// (u) — round 9, 2a: a cached verdict holds only until the earliest
    /// time-dependent boundary after the instant it was judged at. F2 resigns,
    /// is retired and re-seated (Rooted), then signs a SECOND resignation
    /// dated r = now + 50 s, inside the plane's 60 s skew. Judged at r − 1 s:
    /// Rooted, and a second read there is a cache hit. Judged at r + 1 s:
    /// Stalled, naming F2 — no input changed, so only `valid_until` can make
    /// the cache miss.
    pub async fn u_a_future_resignation_bounds_the_cache(d: &dyn FederationDirectory) {
        resigned_retired_reseated(d, "us-steward").await;
        let r = chrono::Utc::now() + chrono::Duration::seconds(50);
        d.put_community_membership_revocation(founder_revocation_at(
            &[FOUNDERS[2]],
            FOUNDERS[2],
            r,
        ))
        .await
        .expect("a resignation dated inside the plane's future skew is admitted");
        let cache = d
            .trust_root_standing_cache()
            .expect("every real backend holds a standing cache");
        let before = r - chrono::Duration::seconds(1);
        assert!(matches!(
            cc::stored_standing_at(d, CANON, before).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        let n = cache.computations();
        assert!(matches!(
            cc::stored_standing_at(d, CANON, before).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        assert_eq!(
            cache.computations(),
            n,
            "before the resignation: a cache hit"
        );
        match cc::stored_standing_at(d, CANON, r + chrono::Duration::seconds(1))
            .await
            .unwrap()
        {
            cc::StoredStanding::Stalled { reason, .. } => {
                assert!(reason.contains(FOUNDERS[2]), "{reason}")
            }
            other => panic!("after the resignation's instant the row stalls: {other:?}"),
        }
        assert!(
            cache.computations() > n,
            "the resignation's instant passed: the cache must miss"
        );
    }

    /// (v) — round 9, 2b: F2 self-signs its agreement to be an occurrence of
    /// a `node` identity with a FUTURE `asserted_at` (inside the occurrence
    /// plane's 5-minute skew). Judged before it: Rooted, and cached. Judged
    /// after it: Stalled, naming F2 — the interval's start bounds the verdict.
    pub async fn v_a_future_occurrence_bounds_the_cache(d: &dyn FederationDirectory) {
        stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        ts::register_hybrid_key_as(d, "vn-node-id", "vn-node-id", identity_type::NODE).await;
        let t = chrono::Utc::now() + chrono::Duration::seconds(120);
        for (signer, when) in [
            ("vn-node-id", t),
            (FOUNDERS[2], t + chrono::Duration::seconds(1)),
        ] {
            d.put_identity_occurrence(
                ts::signed_content_only_occurrence(signer, "vn-node-id", FOUNDERS[2], when).await,
            )
            .await
            .unwrap_or_else(|e| panic!("future-dated occurrence row by {signer}: {e}"));
        }
        let cache = d
            .trust_root_standing_cache()
            .expect("every real backend holds a standing cache");
        let before = t - chrono::Duration::seconds(1);
        assert!(matches!(
            cc::stored_standing_at(d, CANON, before).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        let n = cache.computations();
        assert!(matches!(
            cc::stored_standing_at(d, CANON, before).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        assert_eq!(cache.computations(), n, "before the binding: a cache hit");
        match cc::stored_standing_at(d, CANON, t + chrono::Duration::seconds(3))
            .await
            .unwrap()
        {
            cc::StoredStanding::Stalled { reason, .. } => {
                assert!(reason.contains(FOUNDERS[2]), "{reason}")
            }
            other => panic!("after the binding's instant F2 is node-bearing: {other:?}"),
        }
        assert!(
            cache.computations() > n,
            "the binding's instant passed: the cache must miss"
        );
    }

    /// (w) — round 9, 2c: a withdrawal whose accord proposal this node does
    /// not hold is dated MIN (fail-secure), so F2's signature on v2 stops
    /// counting and the row is NotRooted. When the proposal lands, its signed
    /// `window_until` (after v2) is a changed input: the next read recomputes
    /// and the row is Rooted — F2 was already amended out at v3.
    pub async fn w_a_landed_proposal_is_a_changed_input(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, "ws-steward", "user,steward").await;
        ts::register_hybrid_key_as(d, "ws-serve-node", "ws-serve-node", identity_type::NODE).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let v2 = with_member(canonical_row(&FOUNDERS), "ws-serve-node", "member");
        founders_supersede(d, v2.clone(), &[FOUNDERS[0], FOUNDERS[2]])
            .await
            .expect("F0 and F2 co-sign v2");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            d,
            swapped(v2, FOUNDERS[2], "ws-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("the founders amend F2 out");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        let proposal =
            withdrawal_proposal(FOUNDERS[2], chrono::Utc::now() + chrono::Duration::hours(1));
        d.record_role_withdrawal(
            identity_type::STEWARD,
            FOUNDERS[2],
            None,
            &proposal.digest(),
        )
        .await
        .expect("a trusted-local withdrawal, its proposal not held");
        match cc::stored_standing(d, CANON).await.unwrap() {
            cc::StoredStanding::NotRooted { .. } => {}
            other => panic!("a withdrawal with no proposal dates MIN: {other:?}"),
        }
        let cache = d
            .trust_root_standing_cache()
            .expect("every real backend holds a standing cache");
        let n = cache.computations();
        store_proposal(d, &proposal).await;
        assert!(
            matches!(
                cc::stored_standing(d, CANON).await.unwrap(),
                cc::StoredStanding::Rooted(_)
            ),
            "the proposal landed: F2's signature on v2 precedes its window"
        );
        assert!(cache.computations() > n, "the landed proposal is a new key");
    }

    /// (x) — the reviewer's split (4a), converged by the counting rule,
    /// through the real doors on two nodes. Node `a` holds the birth H1 (t1).
    /// Node `b` holds H2 (t2), signed by F0 + F1 and still recording F2. F2
    /// resigns at t_r, t1 < t_r ≤ t2, having NOT signed H2: `a` admits the
    /// resignation (after its head) and `b` refuses it (`resignation_backdated`).
    /// `a` then ADMITS H2, F2 counting as nothing: `a` Stalled, `b` Rooted.
    /// H3 amends F2 out on `b`; `a` admits it; both read Rooted on H3. No
    /// re-birth.
    pub async fn x_a_resignation_split_converges(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        for d in [a, b] {
            let holders = stand_up(d).await;
            put_conferred(d, &holders, "xs-steward", "user,steward").await;
            ts::register_hybrid_key_as(d, "xs-serve-node", "xs-serve-node", identity_type::NODE)
                .await;
            d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
                .await
                .unwrap();
        }
        let t_r = chrono::Utc::now() - chrono::Duration::seconds(2);
        a.put_community_membership_revocation(founder_revocation_at(
            &[FOUNDERS[2]],
            FOUNDERS[2],
            t_r,
        ))
        .await
        .expect("a: the resignation is after a's head (the birth)");
        let h2_body = with_member(canonical_row(&FOUNDERS), "xs-serve-node", "member");
        founders_supersede(b, h2_body.clone(), &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("b: F0 and F1 sign H2, still recording F2");
        let e = b
            .put_community_membership_revocation(founder_revocation_at(
                &[FOUNDERS[2]],
                FOUNDERS[2],
                t_r,
            ))
            .await
            .expect_err("b: the resignation is not after b's head H2");
        assert_violation(
            &e,
            crate::federation::admission::TRUST_ROOT_RULE_RESIGNATION_BACKDATED,
        );
        let h2 = cc::lookup_signed_community(b, CANON)
            .await
            .unwrap()
            .unwrap();
        a.put_community(h2)
            .await
            .expect("a admits H2: F2 counts as nothing, F0 and F1 are the quorum");
        match cc::stored_standing(a, CANON).await.unwrap() {
            cc::StoredStanding::Stalled { reason, .. } => {
                assert!(reason.contains(FOUNDERS[2]), "{reason}")
            }
            other => panic!("a holds H2 with a resigned founder recorded: {other:?}"),
        }
        assert!(matches!(
            cc::stored_standing(b, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            b,
            swapped(h2_body, FOUNDERS[2], "xs-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("b: H3 amends F2 out");
        let h3 = cc::lookup_signed_community(b, CANON)
            .await
            .unwrap()
            .unwrap();
        a.put_community(h3.clone())
            .await
            .expect("a admits H3 from its stalled H2");
        for d in [a, b] {
            match cc::stored_standing(d, CANON).await.unwrap() {
                cc::StoredStanding::Rooted(held) => assert_eq!(
                    held.community.persist_row_hash, h3.community.persist_row_hash,
                    "both nodes hold H3"
                ),
                other => panic!("both nodes converge Rooted on H3: {other:?}"),
            }
        }
    }

    /// A founders' link `prior` → `next` built by hand: the envelope bound to
    /// `next` at `amended_at`, signed by `signers`, the version signed by
    /// `authority` and carrying `lineage`.
    async fn link_by_hand(
        d: &dyn FederationDirectory,
        prior: &SignedCommunity,
        lineage: Vec<SignedCommunity>,
        next: Community,
        signers: &[&str],
        authority: &str,
    ) -> SignedCommunity {
        let change = bound_envelope(d, &next, chrono::Utc::now(), |_| {}).await;
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        let mut offered = ts::sign_community(authority, next);
        offered.lineage = lineage;
        offered.supersede_proof = Some(crate::federation::types::GroupSupersedeProof {
            prior_persist_row_hash: crate::federation::types::compute_persist_row_hash(
                &prior.community,
            )
            .unwrap(),
            change_envelope: change,
            quorum_signatures: signers
                .iter()
                .map(|k| ts::threshold_sign(k, &bytes))
                .collect(),
        });
        offered
    }

    /// (y) — rounds 9 and 10: an offered lineage cannot re-date a founder's
    /// seat. `a` holds v1 → v3 (v3 still records F2, who resigned after v1:
    /// Stalled). The founders also signed another path to the SAME content:
    /// v1 → v2b (F2 out) → v3′ (F2 back, content equal to v3), which would
    /// date F2's seat after the resignation. A v4 over that path does not
    /// extend the version `a` holds (the held version is matched by position
    /// and proof, not by content), whoever signs it. Over the chain `a` holds,
    /// v4 by F2 and F0 falls short (F2 has been seated since the birth), and
    /// v4 by F0 and F1 is admitted and stored on that chain.
    pub async fn y_an_offered_prefix_cannot_reseat(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, "ys-steward", "user,steward").await;
        for n in ["ys-serve-node", "ys2-serve-node"] {
            ts::register_hybrid_key_as(d, n, n, identity_type::NODE).await;
        }
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let v1 = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        d.put_community_membership_revocation(founder_revocation(&[FOUNDERS[2]], FOUNDERS[2]))
            .await
            .expect("F2 resigns after the birth");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let v3_body = with_member(canonical_row(&FOUNDERS), "ys-serve-node", "member");
        founders_supersede(d, v3_body.clone(), &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("v3 still records F2");
        let held = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Stalled { .. }
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let v2b = link_by_hand(
            d,
            &v1,
            vec![],
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "ys-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let v3b = link_by_hand(
            d,
            &v2b,
            vec![],
            v3_body.clone(),
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
        )
        .await;
        assert_eq!(
            crate::federation::types::compute_persist_row_hash(&v3b.community).unwrap(),
            held.community.persist_row_hash,
            "the other path reaches the content this node holds"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let v4_body = with_member(v3_body, "ys2-serve-node", "member");
        let forged_prefix = vec![v1.clone(), v2b.clone(), v3b.clone()];
        for signers in [[FOUNDERS[2], FOUNDERS[0]], [FOUNDERS[0], FOUNDERS[1]]] {
            let over_forged = link_by_hand(
                d,
                &v3b,
                forged_prefix.clone(),
                v4_body.clone(),
                &signers,
                FOUNDERS[0],
            )
            .await;
            let e = d
                .put_community(over_forged)
                .await
                .expect_err("another path to the held content does not extend the held version");
            assert_violation(&e, "does not extend");
        }
        let by_f2 = link_by_hand(
            d,
            &held,
            cc::chain_of(&held),
            v4_body.clone(),
            &[FOUNDERS[2], FOUNDERS[0]],
            FOUNDERS[0],
        )
        .await;
        let e = d
            .put_community(by_f2)
            .await
            .expect_err("on the held chain F2 has been seated since the birth");
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "{e:?}"
        );
        let by_others = link_by_hand(
            d,
            &held,
            cc::chain_of(&held),
            v4_body,
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
        )
        .await;
        d.put_community(by_others)
            .await
            .expect("the others' v4 extends the held v3");
        let stored = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored
                .lineage
                .iter()
                .map(|v| v.community.persist_row_hash.clone())
                .collect::<Vec<_>>(),
            cc::chain_of(&held)
                .iter()
                .map(|v| v.community.persist_row_hash.clone())
                .collect::<Vec<_>>(),
            "v4 is stored on the chain this node holds"
        );
    }

    /// (z) — round 10: a re-seat back to the birth roster REPEATS content, so
    /// the held version is matched by its position and proof, never by
    /// content. On `b`: F2 resigns after the birth X; v2 retires F2 (Y); v3
    /// re-seats F2, content X again; v4 is signed by F2 and F0 (F2 counts:
    /// re-seated after the resignation). Every node holds F2's resignation.
    /// Arm 1: replica `c` receives v2, then v3 (the LAST occurrence of X),
    /// then v4, and MUST admit it (a first-occurrence match replayed v2 and v3
    /// after v3). Arm 2: `a` holds the birth (the FIRST occurrence of X), is
    /// never shown v2 or v3, and MUST admit v4 by walking every link (a
    /// last-occurrence match skipped the re-seat and read F2 as seated since
    /// the birth). All three end Rooted on v4.
    pub async fn z_repeated_content_is_matched_by_position(
        b: &dyn FederationDirectory,
        a: &dyn FederationDirectory,
        c: &dyn FederationDirectory,
    ) {
        for d in [b, a, c] {
            let holders = stand_up(d).await;
            put_conferred(d, &holders, "zs-steward", "user,steward").await;
            ts::register_hybrid_key_as(d, "zs-serve-node", "zs-serve-node", identity_type::NODE)
                .await;
            d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
                .await
                .unwrap();
        }
        let birth_hash = cc::lookup_signed_community(b, CANON)
            .await
            .unwrap()
            .unwrap()
            .community
            .persist_row_hash;
        let t_r = chrono::Utc::now();
        for d in [b, a, c] {
            d.put_community_membership_revocation(founder_revocation_at(
                &[FOUNDERS[2]],
                FOUNDERS[2],
                t_r,
            ))
            .await
            .expect("F2 resigns after the birth, on every node");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            b,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "zs-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("b: v2 retires F2");
        let v2 = cc::lookup_signed_community(b, CANON)
            .await
            .unwrap()
            .unwrap();
        c.put_community(v2).await.expect("c: v2");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(b, canonical_row(&FOUNDERS), &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("b: v3 re-seats F2");
        let v3 = cc::lookup_signed_community(b, CANON)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            v3.community.persist_row_hash, birth_hash,
            "the re-seat reproduces the birth's content"
        );
        c.put_community(v3).await.expect("c: v3");
        assert_eq!(
            cc::lookup_signed_community(c, CANON)
                .await
                .unwrap()
                .unwrap()
                .lineage
                .len(),
            2,
            "c holds the re-seated head, the last occurrence of the birth's content"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            b,
            with_member(canonical_row(&FOUNDERS), "zs-serve-node", "member"),
            &[FOUNDERS[2], FOUNDERS[0]],
        )
        .await
        .expect("b: v4 by F2 and F0, F2 re-seated after the resignation");
        let v4 = cc::lookup_signed_community(b, CANON)
            .await
            .unwrap()
            .unwrap();
        c.put_community(v4.clone())
            .await
            .expect("arm 1: a replica holding the re-seated head admits the next link");
        a.put_community(v4.clone())
            .await
            .expect("arm 2: a node holding the first occurrence walks every link");
        for d in [b, a, c] {
            match cc::stored_standing(d, CANON).await.unwrap() {
                cc::StoredStanding::Rooted(held) => {
                    assert_eq!(
                        held.community.persist_row_hash,
                        v4.community.persist_row_hash
                    );
                    assert_eq!(held.lineage.len(), 3, "the whole chain is stored");
                }
                other => panic!("every node converges Rooted on v4: {other:?}"),
            }
        }
    }

    /// (z′) — round 11: a CORRECT extension whose offered prefix carries
    /// corrupted signature bytes is admitted, and the node stores the chain it
    /// HOLDS, never the offered prefix. `same_version` compares content,
    /// authority and the founders' proof, not the authority or co-signature
    /// bytes, and the door walks only the links after the held version. So
    /// storing the offered prefix would keep bytes nobody verified, and the
    /// next re-judgement would recount them: the birth short of the accord
    /// quorum, or a link whose authority signature fails, reads NotRooted.
    /// (a) v3 offered over a prefix whose birth co-signature is corrupted;
    /// (b) v4 offered over a prefix whose v2 authority signature is corrupted.
    /// Each is admitted, the row stays Rooted, and the stored lineage is the
    /// held chain byte for byte.
    pub async fn z2_a_corrupted_prefix_is_never_stored(d: &dyn FederationDirectory) {
        stand_up(d).await;
        for n in ["zc-serve-node", "zc2-serve-node", "zc3-serve-node"] {
            ts::register_hybrid_key_as(d, n, n, identity_type::NODE).await;
        }
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let mut body = with_member(canonical_row(&FOUNDERS), "zc-serve-node", "member");
        founders_supersede(d, body.clone(), &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("v2");
        type Corrupt = fn(&mut Vec<SignedCommunity>);
        let corruptions: [(&str, Corrupt); 2] = [
            ("the birth's co-signature", |lineage| {
                lineage[0].cosignatures[0].scrub_signature_classical = "Y29ycnVwdA==".to_owned();
            }),
            ("v2's authority signature", |lineage| {
                lineage[1].scrub_signature_classical = "Y29ycnVwdA==".to_owned();
            }),
        ];
        for ((what, corrupt), serve) in corruptions
            .into_iter()
            .zip(["zc2-serve-node", "zc3-serve-node"])
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let held = cc::lookup_signed_community(d, CANON)
                .await
                .unwrap()
                .unwrap();
            body = with_member(body, serve, "member");
            let mut offered = hand_proof(
                d,
                body.clone(),
                &[FOUNDERS[0], FOUNDERS[1]],
                FOUNDERS[0],
                |_| {},
            )
            .await;
            corrupt(&mut offered.lineage);
            assert_ne!(
                serde_json::to_value(&offered.lineage).unwrap(),
                serde_json::to_value(cc::chain_of(&held)).unwrap(),
                "{what}: the offered prefix differs from the held chain in its bytes"
            );
            d.put_community(offered)
                .await
                .unwrap_or_else(|e| panic!("{what}: a correct extension is admitted: {e}"));
            assert!(
                matches!(
                    cc::stored_standing(d, CANON).await.unwrap(),
                    cc::StoredStanding::Rooted(_)
                ),
                "{what}: the row stays Rooted on its next re-judgement"
            );
            let stored = cc::lookup_signed_community(d, CANON)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::to_value(&stored.lineage).unwrap(),
                serde_json::to_value(cc::chain_of(&held)).unwrap(),
                "{what}: the stored lineage is the held chain, byte for byte"
            );
        }
    }

    /// Review TOCTOU: `supersede_community_with_quorum` skips the generic
    /// quorum when a trust root's chain holds, and `prepare_trust_root_supersede`
    /// re-reads the standing. If the chain stopped holding in between (here: a
    /// NotRooted constraint row kept as data), a flagged prepare refuses rather
    /// than passing a non-grade version through unquorate; unflagged, the
    /// generic quorum already ran and the version passes to the write.
    pub async fn t_a_skipped_quorum_is_never_written(d: &dyn FederationDirectory) {
        stand_up(d).await;
        const OTHER: &str = "infra-room-t";
        let mut other = canonical_row(&FOUNDERS);
        other.community_key_id = OTHER.to_owned();
        other.members.retain(|m| m.key_id != SERVE_NODE);
        d.apply_replicated_community(ts::sign_community(FOUNDERS[0], other.clone()))
            .await
            .unwrap();
        assert!(matches!(
            cc::stored_standing(d, OTHER).await.unwrap(),
            cc::StoredStanding::NotRooted { .. }
        ));
        let mut plain = other;
        plain.policy_blob = None;
        let e = cc::prepare_trust_root_supersede(
            d,
            ts::sign_community(FOUNDERS[0], plain.clone()),
            true,
        )
        .await
        .expect_err("the quorum was skipped and the chain no longer holds");
        assert_violation(&e, "stopped holding");
        cc::prepare_trust_root_supersede(d, ts::sign_community(FOUNDERS[0], plain), false)
            .await
            .expect("unflagged: the generic quorum already judged it");
    }

    /// (r) — #925's NODE-BEARING half, apart from the `user` half: a
    /// `user,steward` founder that becomes an agreed occurrence of a `node`
    /// identity (the identity claims it, the occurrence signs its own
    /// agreement) stops counting. A Rooted row, its standing already cached,
    /// reads Stalled naming that founder (the cache key carries the
    /// node-bearing inputs); and a birth naming such a founder is refused at
    /// the door.
    pub async fn r_a_founder_turned_node_bearing(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        put_conferred(d, &holders, "oc-steward", "user,steward").await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        ts::register_hybrid_key_as(d, "oc-node-id", "oc-node-id", identity_type::NODE).await;
        let t = chrono::Utc::now() - chrono::Duration::seconds(2);
        for (signer, occ, when) in [
            ("oc-node-id", FOUNDERS[2], t),
            (FOUNDERS[2], FOUNDERS[2], t + chrono::Duration::seconds(1)),
            ("oc-node-id", "oc-steward", t),
            ("oc-steward", "oc-steward", t + chrono::Duration::seconds(1)),
        ] {
            d.put_identity_occurrence(
                ts::signed_content_only_occurrence(signer, "oc-node-id", occ, when).await,
            )
            .await
            .unwrap_or_else(|e| panic!("occurrence row by {signer}: {e}"));
        }
        match cc::stored_standing(d, CANON).await.unwrap() {
            cc::StoredStanding::Stalled { reason, .. } => {
                assert!(reason.contains(FOUNDERS[2]), "{reason}")
            }
            other => panic!("a founder turned node-bearing stalls the row: {other:?}"),
        }
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_none());
        let mut rebirth = canonical_row(&[FOUNDERS[0], FOUNDERS[1], "oc-steward"]);
        rebirth.founded_at = at("2026-09-25T00:00:00Z");
        let e = d
            .put_community(signed(rebirth, &["A1", "B1"]))
            .await
            .expect_err("a founder that is an occurrence of a node is refused");
        assert_violation(
            &e,
            crate::federation::admission::INFRA_RULE_NODE_BEARING_FOUNDER,
        );
    }

    /// (o′) — MEDIUM-R: a founder cannot BACKDATE a resignation past a link
    /// they co-signed. F2 co-signs v2; a resignation dated between the birth
    /// and v2's `amended_at` is refused at the plane door with the typed
    /// `resignation_backdated` rule, nothing is stored, and the row stays
    /// Rooted. The same resignation dated now is admitted and stalls the row
    /// (the door refused the DATE, not the resignation).
    pub async fn o2_a_backdated_resignation_is_refused(d: &dyn FederationDirectory) {
        stand_up(d).await;
        ts::register_hybrid_key_as(d, "cc2-serve-node", "cc2-serve-node", identity_type::NODE)
            .await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        founders_supersede(
            d,
            with_member(canonical_row(&FOUNDERS), "cc2-serve-node", "member"),
            &[FOUNDERS[0], FOUNDERS[2]],
        )
        .await
        .expect("F0 and F2 co-sign v2");
        let backdated =
            founder_revocation_at(&[FOUNDERS[2]], FOUNDERS[2], at("2026-09-21T00:00:00Z"));
        let e = d
            .put_community_membership_revocation(backdated)
            .await
            .expect_err("a resignation dated before a link the founder co-signed");
        assert_violation(
            &e,
            crate::federation::admission::TRUST_ROOT_RULE_RESIGNATION_BACKDATED,
        );
        assert!(
            matches!(
                cc::stored_standing(d, CANON).await.unwrap(),
                cc::StoredStanding::Rooted(_)
            ),
            "a refused resignation leaves the row Rooted"
        );
        assert_eq!(
            cc::resolve_community(d, CANON)
                .await
                .unwrap()
                .unwrap()
                .founders,
            FOUNDERS.to_vec()
        );
        // Equality: dated EXACTLY at the link head's `amended_at` is refused
        // too — the head's own link judges resignations up to and including
        // its instant, so admitting it would un-root the chain.
        let head = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        let t2: chrono::DateTime<chrono::Utc> =
            head.supersede_proof.as_ref().unwrap().change_envelope[cc::AMENDED_AT]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
        let e = d
            .put_community_membership_revocation(founder_revocation_at(
                &[FOUNDERS[2]],
                FOUNDERS[2],
                t2,
            ))
            .await
            .expect_err("a resignation dated exactly at the head's instant");
        assert_violation(
            &e,
            crate::federation::admission::TRUST_ROOT_RULE_RESIGNATION_BACKDATED,
        );
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        d.put_community_membership_revocation(founder_revocation_at(
            &[FOUNDERS[2]],
            FOUNDERS[2],
            t2 + chrono::Duration::seconds(1),
        ))
        .await
        .expect("the same resignation one second after the head is admitted");
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Stalled { .. }
        ));
    }

    /// (q) — ONE predicate on BOTH community doors (#931 / #926 fold): the
    /// local `put_community` and the replicated `apply_replicated_community`.
    /// A reserved-id squat, a short birth, a body variant under a genuine
    /// proof and a role-binding replay are refused on each (the local door
    /// returns the typed refusal; the replicated entry maps a typed
    /// `community_consensus_protocol_violation` to
    /// `Refused { DegradesConformance }` and propagates an insufficient
    /// quorum), and nothing moves. The accord birth and a genuine founders'
    /// link are admitted through the replicated entry. A constraint row at
    /// ANOTHER id that does not verify is refused locally and kept as data on
    /// the replicated entry — NotRooted, never resolved.
    pub async fn q_both_doors_one_predicate(d: &dyn FederationDirectory) {
        use crate::federation::group_amendment::{
            ReplicatedCommunityOutcome as O, ReplicatedCommunityRefusal as R,
        };
        const DEGRADES: O = O::Refused {
            reason: R::DegradesConformance,
        };
        stand_up(d).await;
        ts::register_hybrid_key_as(d, "cc2-serve-node", "cc2-serve-node", identity_type::NODE)
            .await;
        ts::register_hybrid_key_as(d, "squatter", "squatter", identity_type::USER).await;
        let mut squat = canonical_row(&["squatter"]);
        squat.members.truncate(1);
        squat.policy_blob = None;
        squat.consensus_protocol = "founder_only".to_owned();
        let squat = ts::sign_community("squatter", squat);
        let e = d
            .put_community(squat.clone())
            .await
            .expect_err("local: the reserved id is refused");
        assert_violation(&e, "cohort_subkind");
        assert_eq!(
            d.apply_replicated_community(squat).await.unwrap(),
            DEGRADES,
            "replicated: the reserved id is refused"
        );
        assert_not_stored(d).await;
        let short = signed(canonical_row(&FOUNDERS), &["A1"]);
        for r in [
            d.put_community(short.clone()).await.map(|()| None),
            d.apply_replicated_community(short).await.map(Some),
        ] {
            assert!(
                matches!(
                    &r,
                    Err(Error::RosterAuthorityUnauthorized { rule, .. })
                        if *rule == crate::federation::ROSTER_CONSENSUS_INSUFFICIENT
                ),
                "a short birth is refused on both doors: {r:?}"
            );
        }
        assert_not_stored(d).await;
        // The accord birth through the replicated entry; an identical re-offer.
        let birth = signed(canonical_row(&FOUNDERS), &["A1", "B1"]);
        assert_eq!(
            d.apply_replicated_community(birth.clone()).await.unwrap(),
            O::Inserted
        );
        assert_eq!(
            d.apply_replicated_community(birth.clone()).await.unwrap(),
            O::Unchanged
        );
        let held = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        let v2_body = with_member(canonical_row(&FOUNDERS), "cc2-serve-node", "member");
        let genuine = hand_proof(
            d,
            v2_body.clone(),
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
            |_| {},
        )
        .await;
        let mut body = genuine.community.clone();
        body.policy_blob.as_mut().unwrap()["cohort_subkind_payload"]["infrastructure_constraint"]
            ["service_class"] = serde_json::json!("registry");
        let variant = SignedCommunity {
            supersede_proof: genuine.supersede_proof.clone(),
            lineage: genuine.lineage.clone(),
            ..ts::sign_community(FOUNDERS[0], body)
        };
        let replay = hand_proof(
            d,
            v2_body.clone(),
            &[FOUNDERS[0], FOUNDERS[1]],
            FOUNDERS[0],
            |env| {
                for m in env["members"].as_array_mut().unwrap() {
                    if m["key_id"] == FOUNDERS[2] {
                        m["role"] = serde_json::json!("member");
                    }
                }
            },
        )
        .await;
        for (offered, needle) in [
            (variant, "one proof, one body"),
            (replay, "bind the founder roles"),
        ] {
            let e = d
                .put_community(offered.clone())
                .await
                .expect_err("local door");
            assert_violation(&e, needle);
            assert_eq!(
                d.apply_replicated_community(offered).await.unwrap(),
                DEGRADES,
                "replicated door: {needle}"
            );
            assert_eq!(
                cc::lookup_signed_community(d, CANON)
                    .await
                    .unwrap()
                    .unwrap()
                    .community
                    .persist_row_hash,
                held.community.persist_row_hash,
                "a refused version moves nothing ({needle})"
            );
        }
        assert_eq!(
            d.apply_replicated_community(genuine).await.unwrap(),
            O::Superseded,
            "a genuine founders' link through the replicated entry"
        );
        let v2 = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v2.lineage.len(), 1, "v2 carries the birth");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        // Another id declaring the constraint, never accord-born.
        const OTHER: &str = "infra-room-q";
        let mut other = canonical_row(&FOUNDERS);
        other.community_key_id = OTHER.to_owned();
        // No serve node: a row the grade does not cover still carries the
        // ordinary steward binding for a `node` member.
        other.members.retain(|m| m.key_id != SERVE_NODE);
        let other = ts::sign_community(FOUNDERS[0], other);
        assert!(
            d.put_community(other.clone()).await.is_err(),
            "local: an unverifying constraint row is refused"
        );
        assert!(d.lookup_community(OTHER).await.unwrap().is_none());
        assert_eq!(
            d.apply_replicated_community(other).await.unwrap(),
            O::Inserted,
            "replicated: another id's legacy constraint row is kept as data"
        );
        assert!(matches!(
            cc::stored_standing(d, OTHER).await.unwrap(),
            cc::StoredStanding::NotRooted { .. }
        ));
        assert!(cc::resolve_community(d, OTHER).await.unwrap().is_none());
        // A row kept as data amends by the ordinary folded quorum: one founder
        // of its `quorum:2/3` cannot turn it into a plain room.
        let mut plain = d.lookup_community(OTHER).await.unwrap().unwrap();
        plain.policy_blob = None;
        let ids: Vec<String> = plain.members.iter().map(|m| m.key_id.clone()).collect();
        let change = d
            .build_membership_change_envelope(
                crate::federation::cohort::Cohort::Community,
                OTHER,
                &ids,
                false,
                Some(&plain.consensus_protocol),
            )
            .await
            .unwrap();
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        assert!(
            d.supersede_community_with_quorum(
                ts::sign_community(FOUNDERS[0], plain),
                change,
                vec![ts::threshold_sign(FOUNDERS[0], &bytes)],
            )
            .await
            .is_err(),
            "a NotRooted constraint row keeps the generic quorum on the local door"
        );
        assert!(d
            .lookup_community(OTHER)
            .await
            .unwrap()
            .unwrap()
            .policy_blob
            .is_some());
    }

    /// (p) — MEDIUM-W: a withdrawal's instant is the accord proposal's SIGNED
    /// window, the same on every node. `a` withdraws F2 through the accord and
    /// its founders retire F2; a FRESH consumer takes the withdrawal evidence
    /// from `a`'s response (re-tallied through the ordinary evidence door) and
    /// then refuses a retired-key fork — F0 and F2 signing a different v2 after
    /// the window — even though it recorded the withdrawal AFTER the fork was
    /// signed.
    pub async fn p_withdrawal_instant_is_node_independent(
        a: &dyn FederationDirectory,
        fresh: &dyn FederationDirectory,
        pinner: &dyn FederationDirectory,
        late: &dyn FederationDirectory,
    ) {
        let holders = stand_up(a).await;
        for k in ["pr-steward", "pf-steward"] {
            put_conferred(a, &holders, k, "user,steward").await;
        }
        ts::register_hybrid_key_as(a, "ck-serve-node", "ck-serve-node", identity_type::NODE).await;
        a.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let v1 = cc::lookup_signed_community(a, CANON)
            .await
            .unwrap()
            .unwrap();
        let window = chrono::Utc::now() + chrono::Duration::seconds(2);
        withdraw_steward_by_accord(a, FOUNDERS[2], window).await;
        let retired = swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "pr-steward");
        founders_supersede(a, retired, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders retire F2 through the record");
        let bundle = test_bundle(a, &["A1", "B1"]).await;
        let resp = cc::trust_root_bundle_response(a, &bundle).await.unwrap();
        assert!(
            !resp.steward_withdrawal_evidence.is_empty(),
            "the response carries F2's withdrawal evidence"
        );
        tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
        // The fork, signed AFTER the window by F0 and the retired F2.
        let fork_body = swapped(
            with_member(canonical_row(&FOUNDERS), "ck-serve-node", "member"),
            FOUNDERS[2],
            "pf-steward",
        );
        let change = bound_envelope(a, &fork_body, chrono::Utc::now(), |_| {}).await;
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        let mut fork = ts::sign_community(FOUNDERS[0], fork_body);
        fork.lineage = cc::chain_of(&v1);
        fork.supersede_proof = Some(crate::federation::types::GroupSupersedeProof {
            prior_persist_row_hash: v1.community.persist_row_hash.clone(),
            change_envelope: change,
            quorum_signatures: [FOUNDERS[0], FOUNDERS[2]]
                .iter()
                .map(|k| ts::threshold_sign(k, &bytes))
                .collect(),
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        fresh_consumer(fresh).await;
        for r in &resp.community_member_records {
            if fresh
                .lookup_public_key(&r.record.key_id)
                .await
                .unwrap()
                .is_none()
            {
                fresh.put_public_key(r.clone()).await.unwrap();
            }
        }
        // The fork's new founder is known on the consumer too (so only the
        // count decides).
        let pf = a.lookup_public_key("pf-steward").await.unwrap().unwrap();
        fresh
            .put_public_key(crate::federation::types::SignedKeyRecord { record: pf })
            .await
            .unwrap();
        cc::admit_response_withdrawals(fresh, &resp)
            .await
            .expect("the withdrawal evidence re-tallies on the consumer");
        assert!(fresh
            .lookup_role_withdrawal(identity_type::STEWARD, FOUNDERS[2])
            .await
            .unwrap()
            .is_some());
        let e = fresh
            .put_community(fork.clone())
            .await
            .expect_err("a retired-key fork signed after the withdrawal window");
        assert!(
            matches!(e, Error::RosterAuthorityUnauthorized { .. }),
            "{e:?}"
        );
        assert!(fresh.lookup_community(CANON).await.unwrap().is_none());
        // The pin admits the same evidence on its own.
        fresh_consumer(pinner).await;
        cc::pin_trust_from_bundle_response(pinner, &resp)
            .await
            .expect("a fresh consumer pins a's retired-and-amended row");
        assert!(
            pinner
                .lookup_role_withdrawal(identity_type::STEWARD, FOUNDERS[2])
                .await
                .unwrap()
                .is_some(),
            "the pin re-derived F2's withdrawal from the carried evidence"
        );
        // LOW-4, fork-then-evidence: a consumer that meets the fork BEFORE the
        // evidence admits it (its own state cannot tell); the evidence then
        // un-roots the fork's link, and a's legitimate chain replaces it
        // through the unrooted path.
        fresh_consumer(late).await;
        for r in &resp.community_member_records {
            if late
                .lookup_public_key(&r.record.key_id)
                .await
                .unwrap()
                .is_none()
            {
                late.put_public_key(r.clone()).await.unwrap();
            }
        }
        let pf = a.lookup_public_key("pf-steward").await.unwrap().unwrap();
        late.put_public_key(crate::federation::types::SignedKeyRecord { record: pf })
            .await
            .unwrap();
        late.put_community(fork.clone())
            .await
            .expect("without the evidence the fork verifies");
        assert!(matches!(
            cc::stored_standing(late, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        cc::admit_response_withdrawals(late, &resp).await.unwrap();
        match cc::stored_standing(late, CANON).await.unwrap() {
            cc::StoredStanding::NotRooted { .. } => {}
            other => panic!("the evidence un-roots the fork's link: {other:?}"),
        }
        let head = resp.community.clone().expect("a serves its head");
        late.put_community(head)
            .await
            .expect("the legitimate chain replaces the un-rooted fork");
        assert_eq!(
            cc::resolve_community(late, CANON)
                .await
                .unwrap()
                .expect("rooted on the legitimate chain")
                .founders,
            vec![
                FOUNDERS[0].to_owned(),
                FOUNDERS[1].to_owned(),
                "pr-steward".to_owned()
            ]
        );
    }

    /// (i) — HIGH-3 ruling: the roster planes admit and remove MEMBERS of a
    /// trust-root community only. A serve node joins by the founders' quorum
    /// with no steward; any founder-seat change on the plane — seating (even
    /// an eligible founder, even under the full founders' quorum), re-roling,
    /// revoking — is refused.
    pub async fn i_roster_planes_carry_the_founder_rules(d: &dyn FederationDirectory) {
        let holders = stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        ts::register_hybrid_key_as(d, "cc3-serve-node", "cc3-serve-node", identity_type::NODE)
            .await;
        d.put_community_membership_widening(widening_by(
            &[FOUNDERS[0], FOUNDERS[1]],
            "cc3-serve-node",
            Some("member"),
        ))
        .await
        .expect("a serve node joins the trust root through the plane, no steward needed");
        put_conferred(d, &holders, "x4-steward", "user,steward").await;
        let e = d
            .put_community_membership_widening(widening_by(
                &[FOUNDERS[0], FOUNDERS[1], FOUNDERS[2]],
                "x4-steward",
                Some("founder"),
            ))
            .await
            .expect_err("no founder is seated on the plane, even by every founder");
        assert_violation(&e, "only through the record");
        let e = d
            .put_community_membership_widening(widening_by(
                &[FOUNDERS[0], FOUNDERS[1]],
                FOUNDERS[2],
                Some("member"),
            ))
            .await
            .expect_err("no founder is re-roled on the plane");
        assert_violation(&e, "only through the record");
        let e = d
            .put_community_membership_revocation(founder_revocation(
                &[FOUNDERS[0], FOUNDERS[1]],
                FOUNDERS[2],
            ))
            .await
            .expect_err("no founder is revoked on the plane, even by the founders' quorum");
        assert_violation(&e, "only through the record");
        // Seats move through the record instead.
        ts::register_hybrid_key_as(d, "cc9-serve-node", "cc9-serve-node", identity_type::NODE)
            .await;
        founders_supersede(
            d,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "x4-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("a founder is seated through the record");
        let r = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert!(r.founders.contains(&"x4-steward".to_owned()), "{r:?}");
        assert!(r.members.contains(&"cc3-serve-node".to_owned()), "{r:?}");
    }

    /// (l) — a founder KEY ROTATION does not break the chain: F2 co-signs v2,
    /// then F2's conferral is withdrawn in favour of a successor, and v3 swaps
    /// F2 for it. Node `a` (which recorded the withdrawal AFTER v2) still reads
    /// its chain rooted — F2 counted at v2's instant — and a fresh node walks
    /// v1 → v3 from `a`'s one response, verifying F2's historical signature
    /// against F2's key record (never deleted, served beside the row).
    pub async fn l_a_founder_key_rotation(
        a: &dyn FederationDirectory,
        fresh: &dyn FederationDirectory,
    ) {
        let holders = stand_up(a).await;
        put_conferred(a, &holders, "f2r-steward", "user,steward").await;
        ts::register_hybrid_key_as(a, "cc2-serve-node", "cc2-serve-node", identity_type::NODE)
            .await;
        a.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let v2_body = with_member(canonical_row(&FOUNDERS), "cc2-serve-node", "member");
        founders_supersede(a, v2_body.clone(), &[FOUNDERS[0], FOUNDERS[2]])
            .await
            .expect("F2 co-signs v2");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        withdraw_steward_by_accord(
            a,
            FOUNDERS[2],
            chrono::Utc::now() + chrono::Duration::seconds(1),
        )
        .await;
        founders_supersede(
            a,
            swapped(v2_body, FOUNDERS[2], "f2r-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("the founders seat the successor through the record");
        assert!(
            matches!(
                cc::stored_standing(a, CANON).await.unwrap(),
                cc::StoredStanding::Rooted(_)
            ),
            "F2's signature on v2 still counts: it preceded the rotation"
        );
        fresh_consumer(fresh).await;
        let bundle = test_bundle(a, &["A1", "B1"]).await;
        let resp = cc::trust_root_bundle_response(a, &bundle).await.unwrap();
        assert!(
            resp.community_member_records
                .iter()
                .any(|r| r.record.key_id == FOUNDERS[2]),
            "the retired founder's key record travels with the chain"
        );
        let pinned = cc::pin_trust_from_bundle_response(fresh, &resp)
            .await
            .expect("a fresh node walks v1 → v3 across the rotation");
        assert!(pinned
            .community
            .founders
            .contains(&"f2r-steward".to_owned()));
    }

    /// (m) — MEDIUM-C: a second read with every input unchanged verifies no
    /// signature (the directory's standing cache serves it); a holder
    /// revocation in the accord family is a changed input, recomputes, and
    /// un-roots the accord-born row (CC T4: loud by design). Round 9: the
    /// revocation is dated 30 s ahead, so the row is still Rooted judged just
    /// before its instant, and the family fold's boundary makes the cache miss
    /// just after it.
    pub async fn m_standing_is_cached_per_directory(d: &dyn FederationDirectory) {
        stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        let cache = d
            .trust_root_standing_cache()
            .expect("every real backend holds a standing cache");
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_some());
        let after_first = cache.computations();
        assert!(after_first >= 1);
        for _ in 0..3 {
            assert!(cc::resolve_community(d, CANON).await.unwrap().is_some());
            let bundle_resp = cc::stored_standing(d, CANON).await.unwrap();
            assert!(matches!(bundle_resp, cc::StoredStanding::Rooted(_)));
        }
        assert_eq!(
            cache.computations(),
            after_first,
            "unchanged inputs: zero recomputations (zero signature verifications)"
        );
        // A holder revocation: B1 leaves the accord family (A1 + C1 sign),
        // effective 30 s from now.
        let t = chrono::Utc::now() + chrono::Duration::seconds(30);
        let mut rev = ts::sign_family_membership_revocation(
            "A1",
            crate::federation::types::FamilyMembershipRevocation {
                family_key_id: cc::accord_family_key_id().to_owned(),
                removed_identity_key_id: "B1".to_owned(),
                removed_at: t,
                effective_at: t,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        );
        ts::cosign_family_membership_revocation(&mut rev, "C1");
        d.put_family_membership_revocation(rev)
            .await
            .expect("the accord's 2-of-3 revokes a holder");
        assert!(
            matches!(
                cc::stored_standing_at(d, CANON, t - chrono::Duration::seconds(1))
                    .await
                    .unwrap(),
                cc::StoredStanding::Rooted(_)
            ),
            "before its instant the revocation does not fold B1 out"
        );
        let before = cache.computations();
        assert!(
            before > after_first,
            "a holder revocation is a changed input"
        );
        assert!(
            matches!(
                cc::stored_standing_at(d, CANON, t + chrono::Duration::seconds(1))
                    .await
                    .unwrap(),
                cc::StoredStanding::NotRooted { .. }
            ),
            "the birth no longer reaches the accord quorum: un-rooted until a re-birth"
        );
        assert!(
            cache.computations() > before,
            "the revocation's instant passed: the cache must miss"
        );
    }

    /// (n) — the chain caps: more than [`cc::MAX_LINEAGE_LEN`] versions, or a
    /// lineage over [`cc::MAX_LINEAGE_BYTES`], is refused at the door before
    /// any signature is checked.
    pub async fn n_lineage_is_capped(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let born = signed(canonical_row(&FOUNDERS), &["A1", "B1"]);
        let mut long = born.clone();
        long.lineage = vec![cc::chain_of(&born)[0].clone(); cc::MAX_LINEAGE_LEN];
        let e = d
            .put_community(long)
            .await
            .expect_err("a chain over the length cap");
        assert_violation(&e, "exceeds the cap");
        let mut heavy_entry = born.clone();
        heavy_entry.community.community_name = "x".repeat(cc::MAX_LINEAGE_BYTES + 1);
        let mut heavy = born.clone();
        heavy.lineage = vec![heavy_entry];
        let e = d
            .put_community(heavy)
            .await
            .expect_err("a chain over the byte cap");
        assert!(matches!(e, Error::EnvelopeTooLarge { .. }), "{e:?}");
        assert_not_stored(d).await;
    }

    /// (i), the moderator half: a moderator a founder appointed may seat a
    /// MEMBER, but a moderator's standing never seats a founder of a trust-root
    /// community.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i_a_moderator_never_seats_a_founder(d: &dyn FederationDirectory) {
        use crate::federation::admission::steward_liveness_test_support::{signed_row, store};
        use crate::federation::admission::DELEGATION_SCOPE_MODERATE;
        let holders = stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .unwrap();
        crate::federation::admission::steward_liveness_test_support::register(
            d,
            "mo-moderator",
            &[identity_type::PRIMITIVE],
        )
        .await;
        let id = uuid::Uuid::new_v4().to_string();
        let mut appointment = signed_row(
            FOUNDERS[0],
            "mo-moderator",
            crate::federation::types::attestation_type::DELEGATES_TO,
            serde_json::json!({
                "id": id,
                "scope": [DELEGATION_SCOPE_MODERATE],
                "sub_delegation": false,
                "community_id": CANON,
            }),
        );
        appointment.subject_key_ids = vec!["mo-moderator".to_owned()];
        ts::reseal(&mut appointment);
        store(d, &appointment)
            .await
            .expect("a founder appoints a moderator");
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        ts::register_hybrid_key_as(d, "mm-member", "mm-member", identity_type::USER).await;
        d.put_community_membership_widening(widening_by(&["mo-moderator"], "mm-member", None))
            .await
            .expect("the moderator's standing seats a member");
        put_conferred(d, &holders, "mf-steward", "user,steward").await;
        let e = d
            .put_community_membership_widening(widening_by(
                &["mo-moderator"],
                "mf-steward",
                Some("founder"),
            ))
            .await
            .expect_err("a moderator's standing never seats a founder of a trust root");
        assert_violation(&e, "only through the record");
    }

    /// The pre-v50 squat (review MEDIUM-4): a self-signed, non-conformant row
    /// at the reserved id, as it would have been stored before this door. The
    /// runner plants it below the door on each backend.
    pub(crate) async fn j_squat(d: &dyn FederationDirectory) -> SignedCommunity {
        stand_up(d).await;
        charter_the_accord(d).await;
        ts::register_hybrid_key_as(d, "squatter2", "squatter2", identity_type::USER).await;
        let mut squat = canonical_row(&["squatter2"]);
        squat.members.truncate(1);
        squat.policy_blob = None;
        squat.consensus_protocol = "founder_only".to_owned();
        ts::sign_community("squatter2", squat)
    }

    /// The other pre-v50 shape: a CONFORMANT row with eligible founders that
    /// one founder signed alone — never accord-born, carrying no founders'
    /// proof. Only the read side's accord re-check tells it from a birth row.
    pub(crate) async fn j_unborn(d: &dyn FederationDirectory) -> SignedCommunity {
        stand_up(d).await;
        charter_the_accord(d).await;
        ts::sign_community(FOUNDERS[0], canonical_row(&FOUNDERS))
    }

    /// The v49 squat the re-check named: a conformant row naming ONE real
    /// steward and two squatter founders, carrying a squatter-signed "proof".
    /// It must not read as rooted: there is no proof-only arm, and its chain
    /// does not start at an accord birth.
    pub(crate) async fn j_squatters_with_proof(d: &dyn FederationDirectory) -> SignedCommunity {
        stand_up(d).await;
        charter_the_accord(d).await;
        for k in ["sqa-steward", "sqb-steward"] {
            ts::register_hybrid_key_as(d, k, k, "user,steward").await;
        }
        let row = canonical_row(&[FOUNDERS[0], "sqa-steward", "sqb-steward"]);
        let change = serde_json::json!({
            "family_key_id": CANON,
            "members": row.members.iter().map(|m| serde_json::json!({
                "key_id": m.key_id, "role": m.role,
            })).collect::<Vec<_>>(),
            "consensus_protocol": row.consensus_protocol,
        });
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();
        let mut s = ts::sign_community("sqa-steward", row);
        s.supersede_proof = Some(crate::federation::types::GroupSupersedeProof {
            prior_persist_row_hash: "00".repeat(32),
            change_envelope: change,
            quorum_signatures: ["sqa-steward", "sqb-steward"]
                .iter()
                .map(|k| ts::threshold_sign(k, &bytes))
                .collect(),
        });
        s
    }

    /// (j) — a planted squat is never honoured, and the accord's birth row
    /// replaces it.
    pub async fn j_a_squat_is_never_honoured(d: &dyn FederationDirectory, tag: &str, reason: &str) {
        use crate::federation::trust_root::trust_root_valid;
        assert!(
            d.lookup_community(CANON).await.unwrap().is_some(),
            "fixture: planted"
        );
        assert!(
            cc::resolve_community(d, CANON).await.unwrap().is_none(),
            "a squat resolves to nothing"
        );
        let bundle = test_bundle(d, &["A1", "B1"]).await;
        let resp = cc::trust_root_bundle_response(d, &bundle).await.unwrap();
        assert!(resp.community.is_none(), "a squat is not served");
        assert!(
            resp.community_withheld
                .as_deref()
                .is_some_and(|r| r.contains(reason)),
            "…and the reason is named: {resp:?}"
        );
        let consumer = format!("{tag}-consumer");
        ts::register_hybrid_key_as(d, &consumer, &consumer, identity_type::USER).await;
        assert!(
            ops::emit_trust_edge(d, &consumer, CANON, None)
                .await
                .is_err(),
            "a squat is not a trust:accepts subject"
        );
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .expect("the accord's birth row replaces the squat");
        let r = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert_eq!(r.founders, FOUNDERS.to_vec());
        ops::emit_trust_edge(d, &consumer, CANON, None)
            .await
            .expect("now it is a subject");
        assert!(trust_root_valid(d, &consumer, CANON).await.unwrap().valid);
    }

    /// (g) — the CC 3.2 supersede rule.
    pub async fn g_supersede_stays_in_grade(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let row = signed(canonical_row(&FOUNDERS), &["A1", "B1"]);
        d.put_community(row.clone()).await.unwrap();
        // Without the founders' quorum (the plain local door), nothing changes.
        let mut renamed = row.community.clone();
        renamed.community_name = "renamed".to_owned();
        let e = d
            .supersede_community(ts::sign_community(FOUNDERS[0], renamed), None)
            .await
            .expect_err("a trust-root row changes only by its founders' quorum");
        assert_violation(&e, "founders' quorum");
        // Lifting entrenchment or dropping the constraint is refused before
        // any quorum is consulted.
        let mut lifted = row.community.clone();
        lifted.policy_blob.as_mut().unwrap()["consensus_protocol_entrenched"] =
            serde_json::json!(false);
        let e = d
            .supersede_community(ts::sign_community(FOUNDERS[0], lifted.clone()), None)
            .await
            .expect_err("no amendment without the founders' quorum");
        assert_violation(&e, "founders' quorum");
        let e = founders_supersede(d, lifted, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect_err("entrenchment cannot be lifted, even by the founders");
        assert_violation(&e, "entrenched");
        let mut weakened = row.community.clone();
        weakened.consensus_protocol = "quorum:3/3".to_owned();
        let e = founders_supersede(d, weakened, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect_err("an entrenched protocol does not move, even by the founders");
        assert_violation(&e, "entrenched");
        // A group cannot promote itself into the grade.
        ts::register_hybrid_key_as(d, "gp-owner", "gp-owner", identity_type::USER).await;
        let mut plain = canonical_row(&["gp-owner"]);
        plain.community_key_id = "gp-room".to_owned();
        plain.members.truncate(1);
        plain.policy_blob = None;
        plain.consensus_protocol = "founder_only".to_owned();
        d.put_community(ts::sign_community("gp-owner", plain.clone()))
            .await
            .expect("a plain room admits");
        let mut promoted = canonical_row(&FOUNDERS);
        promoted.community_key_id = "gp-room".to_owned();
        let e = d
            .supersede_community(ts::sign_community("gp-owner", promoted), None)
            .await
            .expect_err("no promotion into trust-root grade by supersede");
        assert_violation(&e, "promote");
        assert_eq!(
            d.lookup_community(CANON)
                .await
                .unwrap()
                .unwrap()
                .community_name,
            "CIRIS Canonical Services",
            "every refusal left the row as founded"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    /// (f), the CI half — #809 restored as a GATE in the release pre-flight.
    /// From disk: the workflow runs the extracted script, self-test first, on
    /// the live body; no step still says the quorum is "NOT asserted"; and the
    /// fixture #809 named (`authorizations: []` against `quorum:2/3`) exits 1
    /// when the script is actually run.
    #[test]
    fn i190_f_ci_preflight_gates_the_bundle_quorum() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
        let code: Vec<&str> = ci
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect();
        for needle in [
            "python3 scripts/preflight_trust_root.py --self-test",
            "python3 scripts/preflight_trust_root.py dist/steward-key.json",
        ] {
            assert!(
                code.iter().any(|l| l.contains(needle)),
                "the pre-flight step runs {needle:?}"
            );
        }
        assert!(
            !code.iter().any(|l| l.contains("quorum NOT asserted")),
            "no step reports the quorum instead of gating it (#809)"
        );
        let script = root.join("scripts/preflight_trust_root.py");
        let self_test = std::process::Command::new("python3")
            .arg(&script)
            .arg("--self-test")
            .output()
            .expect("python3 runs the pre-flight self-test");
        assert!(
            self_test.status.success(),
            "self-test: {}",
            String::from_utf8_lossy(&self_test.stderr)
        );
        let dir = tempfile::tempdir().unwrap();
        let body = dir.path().join("steward-key.json");
        std::fs::write(
            &body,
            serde_json::json!({
                "bundle": {
                    "holders": [{"record": {"key_id": "A1"}}, {"record": {"key_id": "B1"}},
                                {"record": {"key_id": "C1"}}],
                    "consensus_protocol": "quorum:2/3",
                    "authorizations": [],
                }
            })
            .to_string(),
        )
        .unwrap();
        let short = std::process::Command::new("python3")
            .arg(&script)
            .arg(&body)
            .output()
            .unwrap();
        assert_eq!(
            short.status.code(),
            Some(1),
            "a short bundle quorum reds the pre-flight: {}",
            String::from_utf8_lossy(&short.stderr)
        );
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i190_a() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::a_admitted_under_the_accord_quorum(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_b() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::b_one_of_three_is_refused(&d as &dyn FederationDirectory)
                        .await
                }
                #[tokio::test]
                async fn i190_c() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::c_founders_and_shape(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i190_d() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::d_the_one_row_untrust(
                        &d as &dyn FederationDirectory,
                        &format!("i190d{}", &super::suffix()[..8]),
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_e() {
                    let (Some(a), Some(b), Some(c)) = ($fresh.await, $fresh.await, $fresh.await)
                    else {
                        return;
                    };
                    super::super::bodies::e_served_beside_the_bundle(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &c as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_h() {
                    let (Some(a), Some(b), Some(c), Some(f)) =
                        ($fresh.await, $fresh.await, $fresh.await, $fresh.await)
                    else {
                        return;
                    };
                    super::super::bodies::h_amended_by_the_founders(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                        &c as &dyn FederationDirectory,
                        &f as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_k() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::k_every_recorded_founder_counts(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_l() {
                    let (Some(a), Some(f)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::l_a_founder_key_rotation(
                        &a as &dyn FederationDirectory,
                        &f as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_m() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::m_standing_is_cached_per_directory(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_k2() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::k2_rebirth_over_a_stalled_row(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_o() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::o_a_founder_resigns(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i190_o2() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::o2_a_backdated_resignation_is_refused(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_r() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::r_a_founder_turned_node_bearing(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_o3() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::o3_a_resignation_does_not_lapse(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_o4() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::o4_a_second_resignation_counts(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_u() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::u_a_future_resignation_bounds_the_cache(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_v() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::v_a_future_occurrence_bounds_the_cache(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_w() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::w_a_landed_proposal_is_a_changed_input(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_x() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::x_a_resignation_split_converges(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_y() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::y_an_offered_prefix_cannot_reseat(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_z() {
                    let (Some(b), Some(a), Some(c)) = ($fresh.await, $fresh.await, $fresh.await)
                    else {
                        return;
                    };
                    super::super::bodies::z_repeated_content_is_matched_by_position(
                        &b as &dyn FederationDirectory,
                        &a as &dyn FederationDirectory,
                        &c as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_z2() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::z2_a_corrupted_prefix_is_never_stored(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_t() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::t_a_skipped_quorum_is_never_written(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_q() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::q_both_doors_one_predicate(&d as &dyn FederationDirectory)
                        .await
                }
                #[tokio::test]
                async fn i190_p() {
                    let (Some(a), Some(f), Some(g), Some(l)) =
                        ($fresh.await, $fresh.await, $fresh.await, $fresh.await)
                    else {
                        return;
                    };
                    super::super::bodies::p_withdrawal_instant_is_node_independent(
                        &a as &dyn FederationDirectory,
                        &f as &dyn FederationDirectory,
                        &g as &dyn FederationDirectory,
                        &l as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_n() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::n_lineage_is_capped(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i190_i() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i_roster_planes_carry_the_founder_rules(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[cfg(any(feature = "sqlite", feature = "postgres"))]
                #[tokio::test]
                async fn i190_i_moderator() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i_a_moderator_never_seats_a_founder(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_f() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::f_a_short_bundle_is_refused(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i190_g() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::g_supersede_stays_in_grade(&d as &dyn FederationDirectory)
                        .await
                }
            }
        };
    }

    dyn_runners!(memory_dyn, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite_dyn, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres_dyn, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    /// The two planted shapes: a non-conformant squat, and a conformant row
    /// that was never accord-born. Each gets a fresh backend.
    type Setup = for<'a> fn(
        &'a dyn crate::federation::FederationDirectory,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::federation::SignedCommunity> + 'a>,
    >;
    fn variants() -> [(Setup, &'static str); 3] {
        [
            (|d| Box::pin(super::bodies::j_squat(d)), "non-conformant"),
            (|d| Box::pin(super::bodies::j_unborn(d)), "not accord-born"),
            (
                |d| Box::pin(super::bodies::j_squatters_with_proof(d)),
                "not accord-born",
            ),
        ]
    }

    #[tokio::test]
    async fn i190_j_memory() {
        for (setup, reason) in variants() {
            let d = crate::store::memory::MemoryBackend::new();
            let squat = setup(&d).await;
            d.plant_community_below_the_door(squat);
            super::bodies::j_a_squat_is_never_honoured(&d, &format!("j{}", &suffix()[..8]), reason)
                .await;
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i190_j_sqlite() {
        use crate::store::Backend as _;
        for (setup, reason) in variants() {
            let d = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            d.run_migrations().await.unwrap();
            let squat = setup(&d).await;
            let members = serde_json::to_string(&squat.community.members).unwrap();
            let policy = squat
                .community
                .policy_blob
                .as_ref()
                .map(|v| serde_json::to_string(v).unwrap());
            let hash =
                crate::federation::types::compute_persist_row_hash(&squat.community).unwrap();
            let proof = squat
                .supersede_proof
                .as_ref()
                .map(|p| serde_json::to_string(p).unwrap());
            d.write(move |c| {
                c.execute(
                    "INSERT INTO federation_communities (community_key_id, community_name, \
                     members, founded_at, consensus_protocol, policy_blob, persist_row_hash, \
                     authority_key_id, scrub_signature_classical, scrub_signature_pqc, \
                     admitted_at, supersede_proof) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?4, ?11)",
                    rusqlite::params![
                        squat.community.community_key_id,
                        squat.community.community_name,
                        members,
                        squat.community.founded_at.to_rfc3339(),
                        squat.community.consensus_protocol,
                        policy,
                        hash,
                        squat.authority_key_id,
                        squat.scrub_signature_classical,
                        squat.scrub_signature_pqc,
                        proof,
                    ],
                )
            })
            .await
            .unwrap();
            super::bodies::j_a_squat_is_never_honoured(&d, &format!("j{}", &suffix()[..8]), reason)
                .await;
        }
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i190_j_postgres() {
        use crate::store::Backend as _;
        for (setup, reason) in variants() {
            let Some(dsn) = crate::test_pg::empty_dsn() else {
                return;
            };
            let d = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            d.run_migrations().await.unwrap();
            let squat = setup(&d).await;
            let members = serde_json::to_value(&squat.community.members).unwrap();
            let hash =
                crate::federation::types::compute_persist_row_hash(&squat.community).unwrap();
            d.get_client()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO cirislens.federation_communities (community_key_id, \
                     community_name, members, founded_at, consensus_protocol, policy_blob, \
                     persist_row_hash, authority_key_id, scrub_signature_classical, \
                     scrub_signature_pqc, admitted_at, supersede_proof) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $4, $11)",
                    &[
                        &squat.community.community_key_id,
                        &squat.community.community_name,
                        &members,
                        &squat.community.founded_at,
                        &squat.community.consensus_protocol,
                        &squat.community.policy_blob,
                        &hash,
                        &squat.authority_key_id,
                        &squat.scrub_signature_classical,
                        &squat.scrub_signature_pqc,
                        &squat
                            .supersede_proof
                            .as_ref()
                            .map(|p| serde_json::to_value(p).unwrap()),
                    ],
                )
                .await
                .unwrap();
            super::bodies::j_a_squat_is_never_honoured(&d, &format!("j{}", &suffix()[..8]), reason)
                .await;
        }
    }
}
