//! v51.0.0 — the rc6 trust-root security set, witnessed on memory, sqlite and
//! postgres over the I190 fixture (`canonical_community_invariants`): FSD
//! `TRUST_ROOT_RC6.md` §5.
//!
//! - **I191** the cosign door: each refusal of §2.1, the identical re-put, a
//!   cosign for an unknown head held as evidence.
//! - **I192** the witnessed head: an unwitnessed extension is held (the
//!   standing is judged at the witnessed prefix, the tail reported); one
//!   independent cosign adopts it; a never-witnessed lineage is judged as
//!   before rc6.
//! - **I193** equivocation (two nodes + one witness): two founder-signed heads
//!   over one prefix, each witnessed — a node holding both cosigns freezes at
//!   the fork, serves the fork version, emits `lineage_equivocation` once.
//! - **I194** attach freshness: under a charter with a window, an acceptance
//!   edge naming no head, an unwitnessed head, or a head older than the window
//!   is `trust_root_head_stale`; a fresh witnessed head attaches; an attached
//!   node whose head goes stale stays Rooted; a pre-rc6 charter keeps the
//!   pre-rc6 edge shape.
//! - **I195** the liveness margin: a resignation stalls and DECLARES it
//!   (`community_liveness_stalled` once), the record's amendment restores it
//!   (`…_restored`), and a trust-root row founded at N = M is refused.
//! - **I196** restore discipline: a node behind the witness plane refuses its
//!   own supersede until it fetches the witnessed head.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::accord_test_support as ops;
    use crate::federation::canonical_community as cc;
    use crate::federation::canonical_community_invariants::bodies::{
        canonical_row, founder_revocation, founders_supersede, put_conferred, signed, stand_up,
        swapped, with_member, FOUNDERS,
    };
    use crate::federation::hard_case::{kind, HardCaseFilter};
    use crate::federation::lineage_witness::{
        LineageCosignOutcome as Out, LineageCosignRefusal as R, LineageHeadCosign,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type;
    use crate::federation::{Error, FederationDirectory};

    const CANON: &str = "ciris-canonical";

    /// A witness's cosign over the head this node holds for `lineage`, signed
    /// with the witness's deterministic hybrid test keys over the SAME bytes
    /// the door verifies (`ceg_produce_canonicalize(signing_envelope())`).
    pub(crate) async fn cosign_held_head(
        d: &dyn FederationDirectory,
        lineage: &str,
        witness: &str,
        prior: Option<&str>,
    ) -> LineageHeadCosign {
        let signed_row = cc::lookup_signed_community(d, lineage)
            .await
            .unwrap()
            .expect("a signed row is held");
        let held = d.lookup_community(lineage).await.unwrap().expect("held");
        let head_at = cc::head_instant(&signed_row);
        cosign_for(
            lineage,
            &held.persist_row_hash,
            head_at,
            witness,
            prior,
            chrono::Utc::now(),
        )
    }

    pub(crate) fn cosign_for(
        lineage: &str,
        head_digest: &str,
        head_at: chrono::DateTime<chrono::Utc>,
        witness: &str,
        prior: Option<&str>,
        signed_at: chrono::DateTime<chrono::Utc>,
    ) -> LineageHeadCosign {
        let mut c = LineageHeadCosign {
            lineage_key_id: lineage.to_owned(),
            head_digest_sha256_hex: head_digest.to_owned(),
            head_asserted_at: head_at.to_rfc3339(),
            prior_head_digest_sha256_hex: prior.map(str::to_owned),
            signed_at: signed_at.to_rfc3339(),
            witness_key_id: witness.to_owned(),
            signature_classical: String::new(),
            signature_pqc: None,
        };
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&c.signing_envelope())
            .expect("cosign envelope canonicalizes");
        let sig = ts::threshold_sign(witness, &bytes);
        c.signature_classical = sig.ed25519_signature_base64;
        c.signature_pqc = sig.mldsa65_signature_base64;
        c
    }

    async fn born(d: &dyn FederationDirectory) -> Vec<ops::Identity> {
        let holders = stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .expect("the accord births the row");
        ts::register_hybrid_key_as(d, "w1", "w1", identity_type::WITNESS).await;
        ts::register_hybrid_key_as(d, "w2", "w2", identity_type::WITNESS).await;
        ts::register_hybrid_key_as(d, "plain-user", "plain-user", identity_type::USER).await;
        holders
    }

    async fn count(d: &dyn FederationDirectory, kind: &str) -> usize {
        d.list_hard_case_events(HardCaseFilter {
            kind: Some(kind.to_owned()),
            since: None,
        })
        .await
        .unwrap()
        .len()
    }

    /// **I191** — the door.
    pub async fn i191_the_cosign_door(d: &dyn FederationDirectory) {
        let holders = born(d).await;
        let good = cosign_held_head(d, CANON, "w1", None).await;
        assert_eq!(
            d.put_lineage_head_cosign(good.clone()).await.unwrap(),
            Out::Inserted
        );
        assert_eq!(
            d.put_lineage_head_cosign(good.clone()).await.unwrap(),
            Out::Unchanged,
            "the identical cosign is held once"
        );
        let refused = |o: Out, r: R| assert_eq!(o, Out::Refused { reason: r });
        // unregistered witness
        let mut c = cosign_held_head(d, CANON, "w1", None).await;
        c.witness_key_id = "nobody".into();
        refused(
            d.put_lineage_head_cosign(c).await.unwrap(),
            R::WitnessNotRegistered,
        );
        // registered, not a witness
        let c = cosign_held_head(d, CANON, "plain-user", None).await;
        refused(
            d.put_lineage_head_cosign(c).await.unwrap(),
            R::WitnessNotWitnessType,
        );
        // a founder of the lineage, even with identity_type witness added
        let row = swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "founder-witness");
        // seat founder-witness through the record, then it may not witness
        put_conferred(d, &holders, "founder-witness", "user,steward,witness").await;
        founders_supersede(d, row, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("re-seat");
        let c = cosign_held_head(d, CANON, "founder-witness", None).await;
        refused(
            d.put_lineage_head_cosign(c).await.unwrap(),
            R::WitnessIsFounder,
        );
        // bad signature
        let mut c = cosign_held_head(d, CANON, "w2", None).await;
        c.signature_classical = c.signature_classical.chars().rev().collect();
        refused(
            d.put_lineage_head_cosign(c).await.unwrap(),
            R::SignatureInvalid,
        );
        // wrong head instant (re-signed, so the signature is valid)
        let held = d.lookup_community(CANON).await.unwrap().unwrap();
        let c = cosign_for(
            CANON,
            &held.persist_row_hash,
            chrono::Utc::now(),
            "w2",
            None,
            chrono::Utc::now(),
        );
        refused(
            d.put_lineage_head_cosign(c).await.unwrap(),
            R::HeadInstantMismatch,
        );
        // skew: signed far in the future
        let s = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        let c = cosign_for(
            CANON,
            &held.persist_row_hash,
            cc::head_instant(&s),
            "w2",
            None,
            chrono::Utc::now() + chrono::Duration::hours(2),
        );
        refused(d.put_lineage_head_cosign(c).await.unwrap(), R::Skew);
        // an unknown head is held as evidence
        let c = cosign_for(
            CANON,
            &"ab".repeat(32),
            chrono::Utc::now(),
            "w2",
            None,
            chrono::Utc::now(),
        );
        assert_eq!(
            d.put_lineage_head_cosign(c).await.unwrap(),
            Out::HeldForUnknownHead
        );
        // malformed digest
        let mut c = cosign_held_head(d, CANON, "w2", None).await;
        c.head_digest_sha256_hex = "not-hex".into();
        refused(d.put_lineage_head_cosign(c).await.unwrap(), R::Malformed);
        // a prior that is a LATER held version than the head is not an ancestor
        let head_v2 = d
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        let birth = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        let birth_digest = birth.lineage[0].community.persist_row_hash.clone();
        let birth_at = cc::head_instant(&birth.lineage[0]);
        let c = cosign_for(
            CANON,
            &birth_digest,
            birth_at,
            "w2",
            Some(&head_v2),
            chrono::Utc::now(),
        );
        refused(
            d.put_lineage_head_cosign(c).await.unwrap(),
            R::PriorNotAncestor,
        );
    }

    /// **I192** — the witnessed head.
    pub async fn i192_the_witnessed_head(d: &dyn FederationDirectory) {
        let holders = born(d).await;
        // never witnessed: judged as before rc6
        let v = d_view(d).await;
        assert_eq!(v.judged, None);
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_some());
        // witness the birth
        assert_eq!(
            d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w1", None).await)
                .await
                .unwrap(),
            Out::Inserted
        );
        assert_eq!(d_view(d).await.judged, Some(0));
        // an unwitnessed extension is HELD: the standing is judged at the birth
        put_conferred(d, &holders, "new-steward", "user,steward").await;
        let v2 = swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "new-steward");
        founders_supersede(d, v2, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders amend");
        let view = d_view(d).await;
        assert_eq!(view.judged, Some(0), "judged at the witnessed birth");
        assert_eq!(view.unwitnessed_tail, 1);
        let r = cc::resolve_community(d, CANON)
            .await
            .unwrap()
            .expect("rooted at the birth");
        assert_eq!(
            r.founders,
            FOUNDERS.to_vec(),
            "the served founders are the BIRTH's"
        );
        assert!(r.witnessed);
        assert_eq!(r.unwitnessed_tail, 1);
        // one independent cosign adopts v2
        let birth_digest = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap()
            .lineage[0]
            .community
            .persist_row_hash
            .clone();
        assert_eq!(
            d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w2", Some(&birth_digest)).await)
                .await
                .unwrap(),
            Out::Inserted
        );
        let view = d_view(d).await;
        assert_eq!(view.judged, Some(1));
        assert_eq!(view.unwitnessed_tail, 0);
        let r = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert!(r.founders.contains(&"new-steward".to_owned()), "{r:?}");
    }

    /// The accord's charter with rc6 members (mirrors
    /// `canonical_community_invariants::bodies::charter_the_accord`).
    async fn charter_the_accord_with(d: &dyn FederationDirectory, members: serde_json::Value) {
        use crate::federation::trust_root::{
            pre_rotation_commitment, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE, TRUST_CHARTER_DIMENSION,
        };
        let family = cc::accord_family_key_id();
        let id = uuid::Uuid::new_v4().to_string();
        let commitment =
            pre_rotation_commitment(&["accord-succ-a".to_owned(), "accord-succ-b".to_owned()])
                .unwrap();
        let mut env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": commitment,
        });
        if let (Some(e), Some(m)) = (env.as_object_mut(), members.as_object()) {
            for (k, v) in m {
                e.insert(k.clone(), v.clone());
            }
        }
        let charter = ops::co_signed_trust_attestation(
            &id,
            "A1",
            family,
            crate::federation::types::attestation_type::DELEGATES_TO,
            env,
            &["B1", "C1"],
        );
        d.put_attestation(crate::federation::SignedAttestation {
            attestation: charter,
        })
        .await
        .expect("the accord charters itself 3-of-3");
    }

    /// A consumer's `trust:accepts:v1` edge to the root, optionally naming the
    /// head it attaches under.
    async fn accept_edge(
        d: &dyn FederationDirectory,
        consumer: &str,
        head: Option<&str>,
    ) -> Result<String, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
            "scope": [crate::federation::trust_root::INFRA_SERVE_SCOPE],
        });
        if let Some(h) = head {
            env["attached_head_digest"] = serde_json::Value::String(h.to_owned());
        }
        let mut edge = crate::federation::operational::test_support::signed_trust_attestation(
            &id,
            consumer,
            CANON,
            crate::federation::types::attestation_type::DELEGATES_TO,
            env,
        );
        ts::reseal(&mut edge);
        d.put_attestation(crate::federation::SignedAttestation { attestation: edge })
            .await?;
        Ok(id)
    }

    fn assert_stale(r: Result<String, Error>, needle: &str) {
        match r {
            Err(Error::TrustRootHeadStale { detail, .. }) => {
                assert!(detail.contains(needle), "{detail}")
            }
            other => panic!("expected trust_root_head_stale ({needle}), got {other:?}"),
        }
    }

    /// **I194** — attach freshness.
    pub async fn i194_attach_freshness(d: &dyn FederationDirectory) {
        use crate::federation::trust_root::trust_root_valid;
        born(d).await;
        let consumer = "i194-consumer";
        ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        // pre-rc6 charter (no window): the old edge shape attaches
        let pre = "i194-pre";
        ts::register_hybrid_key_as(d, pre, pre, identity_type::USER).await;
        accept_edge(d, pre, None)
            .await
            .expect("a pre-rc6 charter keeps the pre-rc6 shape");
        // the accord re-scrubs its charter with a 30-day window
        charter_the_accord_with(
            d,
            serde_json::json!({ "attach_window_secs": 2_592_000, "witness_quorum": 1 }),
        )
        .await;
        let head = d
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        assert_stale(
            accept_edge(d, consumer, None).await,
            "requires the witnessed lineage head",
        );
        assert_stale(accept_edge(d, consumer, Some(&head)).await, "not witnessed");
        assert_stale(
            accept_edge(d, consumer, Some(&"ab".repeat(32))).await,
            "not the head this node holds",
        );
        d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w1", None).await)
            .await
            .unwrap();
        let edge = accept_edge(d, consumer, Some(&head))
            .await
            .expect("a fresh witnessed head attaches");
        assert!(
            trust_root_valid(d, consumer, CANON)
                .await
                .unwrap()
                .edge_exists
        );
        // the window shrinks to 1 s (the birth is days old): a NEW attach is stale …
        charter_the_accord_with(
            d,
            serde_json::json!({ "attach_window_secs": 1, "witness_quorum": 1 }),
        )
        .await;
        let late = "i194-late";
        ts::register_hybrid_key_as(d, late, late, identity_type::USER).await;
        assert_stale(
            accept_edge(d, late, Some(&head)).await,
            "older than the root's attach window",
        );
        // … but the ATTACHED consumer is untouched (T4: valid until revoked)
        let v = trust_root_valid(d, consumer, CANON).await.unwrap();
        assert!(v.edge_exists, "attached never detaches on a timer: {v:?}");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        let _ = edge;
    }

    async fn born_on(d: &dyn FederationDirectory) -> Vec<ops::Identity> {
        born(d).await
    }

    /// **I193** — equivocation, two nodes and one witness.
    pub async fn i193_equivocation_freezes_at_the_fork(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        let ha = born_on(a).await;
        let hb = born_on(b).await;
        for (d, h) in [(a, &ha), (b, &hb)] {
            put_conferred(d, h, "eq-steward", "user,steward").await;
            ts::register_hybrid_key_as(d, "eq-serve-node", "eq-serve-node", identity_type::NODE)
                .await;
        }
        let birth_digest = a
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        assert_eq!(
            birth_digest,
            b.lookup_community(CANON)
                .await
                .unwrap()
                .unwrap()
                .persist_row_hash
        );
        // both nodes witness the birth
        for d in [a, b] {
            d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w1", None).await)
                .await
                .unwrap();
        }
        // the founders sign two DIFFERENT heads over the birth, one per node
        founders_supersede(
            a,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "eq-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("a: H2a");
        founders_supersede(
            b,
            with_member(canonical_row(&FOUNDERS), "eq-serve-node", "member"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("b: H2b");
        let cos_a = cosign_held_head(a, CANON, "w1", Some(&birth_digest)).await;
        let cos_b = cosign_held_head(b, CANON, "w1", Some(&birth_digest)).await;
        assert_eq!(
            a.put_lineage_head_cosign(cos_a.clone()).await.unwrap(),
            Out::Inserted
        );
        assert_eq!(
            b.put_lineage_head_cosign(cos_b.clone()).await.unwrap(),
            Out::Inserted
        );
        assert_eq!(
            d_view(a).await.judged,
            Some(1),
            "a adopts its witnessed H2a"
        );
        // a receives the witness plane's cosign of b's head: evidence, frozen at the birth
        assert_eq!(
            a.put_lineage_head_cosign(cos_b).await.unwrap(),
            Out::HeldForUnknownHead
        );
        let view = d_view(a).await;
        assert_eq!(view.judged, Some(0), "frozen at the last common ancestor");
        let e = view.equivocation.expect("equivocation is reported");
        assert_eq!(e.fork_digest, birth_digest);
        assert_eq!(e.competing_witnesses, vec!["w1".to_owned()]);
        let r = cc::resolve_community(a, CANON)
            .await
            .unwrap()
            .expect("the fork version roots");
        assert_eq!(r.founders, FOUNDERS.to_vec(), "served at the birth");
        assert!(r.equivocation.is_some());
        let _ = d_view(a).await;
        assert_eq!(
            count(a, kind::LINEAGE_EQUIVOCATION).await,
            1,
            "emitted once"
        );
        // b, symmetrically
        assert_eq!(
            b.put_lineage_head_cosign(cos_a).await.unwrap(),
            Out::HeldForUnknownHead
        );
        assert_eq!(d_view(b).await.judged, Some(0));
    }

    /// **I196** — restore discipline.
    pub async fn i196_a_node_behind_the_witness_plane_fetches_first(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        let ha = born_on(a).await;
        let hb = born_on(b).await;
        for (d, h) in [(a, &ha), (b, &hb)] {
            put_conferred(d, h, "rs-steward", "user,steward").await;
            put_conferred(d, h, "rs-steward-2", "user,steward").await;
        }
        let birth_digest = a
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        // b advances to v2, witnessed
        founders_supersede(
            b,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "rs-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("b: v2");
        let cos = cosign_held_head(b, CANON, "w1", Some(&birth_digest)).await;
        b.put_lineage_head_cosign(cos.clone()).await.unwrap();
        // a (restored to the birth) learns of the witnessed head through the plane
        assert_eq!(
            a.put_lineage_head_cosign(cos).await.unwrap(),
            Out::HeldForUnknownHead
        );
        let e = founders_supersede(
            a,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "rs-steward-2"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect_err("a is behind the witness plane: fetch first");
        let msg = e.to_string();
        assert!(
            msg.contains(crate::federation::admission::TRUST_ROOT_RULE_BEHIND_WITNESS),
            "{e:?}"
        );
        // a fetches b's witnessed head, then extends
        let v2 = cc::lookup_signed_community(b, CANON)
            .await
            .unwrap()
            .unwrap();
        a.put_community(v2)
            .await
            .expect("a applies the witnessed head");
        assert_eq!(d_view(a).await.judged, Some(1));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            a,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "rs-steward-2"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("a extends from the witnessed head");
    }

    async fn d_view(d: &dyn FederationDirectory) -> cc::WitnessedHead {
        cc::lineage_witness_view(d, CANON, chrono::Utc::now())
            .await
            .unwrap()
            .expect("a signed row is held")
    }

    /// **I195** — the liveness margin.
    pub async fn i195_the_liveness_margin(d: &dyn FederationDirectory) {
        let holders = born(d).await;
        let r = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert!(r.live, "3 founders at quorum:2/3: live (M + 1)");
        assert_eq!(count(d, kind::COMMUNITY_LIVENESS_STALLED).await, 0);
        // a resignation: stalled, declared once
        d.put_community_membership_revocation(founder_revocation(&[FOUNDERS[2]], FOUNDERS[2]))
            .await
            .expect("a founder resigns");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Stalled { .. }
        ));
        assert!(
            cc::resolve_community(d, CANON).await.unwrap().is_none(),
            "non-admitting, not served"
        );
        let _ = cc::stored_standing(d, CANON).await.unwrap();
        assert_eq!(
            count(d, kind::COMMUNITY_LIVENESS_STALLED).await,
            1,
            "declared exactly once"
        );
        // the record restores it
        put_conferred(d, &holders, "repl-steward", "user,steward").await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            d,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "repl-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("the founders retire the seat");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
        let _ = cc::stored_standing(d, CANON).await.unwrap();
        assert_eq!(count(d, kind::COMMUNITY_LIVENESS_RESTORED).await, 1);
        assert_eq!(count(d, kind::COMMUNITY_LIVENESS_STALLED).await, 1);
    }

    /// **I195b** — founding at N = M is refused for a trust-root-grade row.
    pub async fn i195b_founding_needs_a_margin(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let mut row = canonical_row(&FOUNDERS[..2]);
        row.consensus_protocol = "quorum:2/2".into();
        let e = d
            .put_community(signed(row, &["A1", "B1"]))
            .await
            .expect_err("N = M is stalled from birth");
        assert!(
            matches!(&e, Error::CommunityConsensusProtocolViolation { rule, .. } if *rule == crate::federation::admission::INFRA_RULE_LIVENESS_MARGIN_AT_FOUNDING),
            "{e:?}"
        );
    }
}

#[cfg(test)]
mod runners {
    macro_rules! rc6_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i191() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i191_the_cosign_door(&d as &dyn FederationDirectory).await
                }
                #[tokio::test]
                async fn i192() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i192_the_witnessed_head(&d as &dyn FederationDirectory)
                        .await
                }
                #[tokio::test]
                async fn i195() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i195_the_liveness_margin(&d as &dyn FederationDirectory)
                        .await
                }
                #[tokio::test]
                async fn i194() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i194_attach_freshness(&d as &dyn FederationDirectory)
                        .await
                }
                #[tokio::test]
                async fn i193() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i193_equivocation_freezes_at_the_fork(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i196() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i196_a_node_behind_the_witness_plane_fetches_first(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i195b() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i195b_founding_needs_a_margin(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
            }
        };
    }
    rc6_runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
    #[cfg(feature = "sqlite")]
    rc6_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    rc6_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
