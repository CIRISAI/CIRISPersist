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
//! - **I192b / I193b / I197 / I198** (PR #943 review): witnessed mode engages
//!   at the quorum; a deep fork freezes at the common ancestor; a deferred
//!   cosign is re-checked against the head it names; the quorum counts
//!   persons, not keys.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::accord_test_support as ops;
    use crate::federation::canonical_community as cc;
    use crate::federation::canonical_community_invariants::bodies::{
        at, canonical_row, founder_revocation, founders_supersede, put_conferred, signed, stand_up,
        swapped, widening_by, with_member, FOUNDERS,
    };
    use crate::federation::hard_case::{kind, HardCaseFilter};
    use crate::federation::lineage_witness::{
        LineageCosignOutcome as Out, LineageCosignRefusal as R, LineageHeadCosign,
    };
    use crate::federation::membership_acceptance::test_support::ConsentedWidening as _;
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

    /// #973 — the pre-existing witnesses were written when a silent charter
    /// meant a quorum of ONE. Silence is now witnessed mode off and a quorum
    /// of one is not a valid charter value, so they run under an explicit
    /// quorum of 2 ([`born_witnessed`]) and every witness act is made by a
    /// witness AND its twin (`w1` + `w1t`): one act still crosses the quorum.
    async fn wit(d: &dyn FederationDirectory, c: LineageHeadCosign) -> Result<Out, Error> {
        let mut twin = c.clone();
        twin.witness_key_id = format!("{}t", c.witness_key_id);
        twin.signature_classical = String::new();
        twin.signature_pqc = None;
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&twin.signing_envelope())
            .expect("cosign envelope canonicalizes");
        let sig = ts::threshold_sign(&twin.witness_key_id, &bytes);
        twin.signature_classical = sig.ed25519_signature_base64;
        twin.signature_pqc = sig.mldsa65_signature_base64;
        let out = d.put_lineage_head_cosign(c).await;
        let _ = d.put_lineage_head_cosign(twin).await;
        out
    }

    /// [`born`] under a charter declaring `witness_quorum: 2`.
    async fn born_witnessed(d: &dyn FederationDirectory) -> Vec<ops::Identity> {
        let holders = born(d).await;
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 2 })).await;
        holders
    }

    async fn born(d: &dyn FederationDirectory) -> Vec<ops::Identity> {
        let holders = stand_up(d).await;
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .expect("the accord births the row");
        ts::register_hybrid_key_as(d, "w1", "w1", identity_type::WITNESS).await;
        ts::register_hybrid_key_as(d, "w2", "w2", identity_type::WITNESS).await;
        ts::register_hybrid_key_as(d, "w1t", "w1t", identity_type::WITNESS).await;
        ts::register_hybrid_key_as(d, "w2t", "w2t", identity_type::WITNESS).await;
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
        let holders = born_witnessed(d).await;
        let good = cosign_held_head(d, CANON, "w1", None).await;
        assert_eq!(wit(d, good.clone()).await.unwrap(), Out::Inserted);
        assert_eq!(
            wit(d, good.clone()).await.unwrap(),
            Out::Unchanged,
            "the identical cosign is held once"
        );
        // PR #943 review — a RENEWAL (the same witness re-cosigning the same
        // head at a later instant, the cadence) is a new row and advances the
        // liveness signal; it is not `Unchanged`.
        let before = cc::root_witness_view(d, CANON, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap()
            .latest_cosign_at
            .expect("the first cosign counts");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            wit(d, cosign_held_head(d, CANON, "w1", None).await)
                .await
                .unwrap(),
            Out::Inserted,
            "a renewal is stored"
        );
        let after = cc::root_witness_view(d, CANON, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap()
            .latest_cosign_at
            .unwrap();
        assert!(after > before, "the renewal advances latest_cosign_at");
        // PR #943 review — the stored cosign is the SIGNED one, byte for byte
        // (postgres kept the instants as TEXT: a TIMESTAMPTZ round trip
        // truncates nanoseconds and re-renders the offset, and the signature
        // over the listed row would no longer verify)
        let listed = d.list_lineage_head_cosigns_for(CANON).await.unwrap();
        assert!(listed.contains(&good), "listed as signed: {listed:?}");
        // PR #943 review — a FAMILY lineage has a witness view too
        let family = cc::accord_family_key_id();
        let fam = d.lookup_family(family).await.unwrap().expect("seeded");
        assert_eq!(
            wit(
                d,
                cosign_for(
                    family,
                    &fam.persist_row_hash,
                    fam.founded_at,
                    "w1",
                    None,
                    chrono::Utc::now(),
                )
            )
            .await
            .unwrap(),
            Out::Inserted
        );
        let fv = cc::root_witness_view(d, family, chrono::Utc::now())
            .await
            .unwrap()
            .expect("a family root has a witness view");
        assert!(fv.community.is_none());
        assert_eq!(
            fv.witnessed_head.map(|(h, _)| h),
            Some(fam.persist_row_hash.clone()),
            "the family's head is witnessed"
        );
        let refused = |o: Out, r: R| assert_eq!(o, Out::Refused { reason: r });
        // PR #943 review — a witness key not valid at the cosign's instant
        // (w2 registered NOW; the cosign is dated a day after the birth)
        let held_now = d.lookup_community(CANON).await.unwrap().unwrap();
        let signed_now = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap();
        let c = cosign_for(
            CANON,
            &held_now.persist_row_hash,
            cc::head_instant(&signed_now),
            "w2",
            None,
            at("2026-09-21T00:00:00Z"),
        );
        refused(wit(d, c).await.unwrap(), R::WitnessNotValidAt);
        // unregistered witness
        let mut c = cosign_held_head(d, CANON, "w1", None).await;
        c.witness_key_id = "nobody".into();
        refused(wit(d, c).await.unwrap(), R::WitnessNotRegistered);
        // registered, not a witness
        let c = cosign_held_head(d, CANON, "plain-user", None).await;
        refused(wit(d, c).await.unwrap(), R::WitnessNotWitnessType);
        // a founder of the lineage, even with identity_type witness added
        let row = swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "founder-witness");
        // seat founder-witness through the record, then it may not witness
        put_conferred(d, &holders, "founder-witness", "user,steward,witness").await;
        founders_supersede(d, row, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("re-seat");
        let c = cosign_held_head(d, CANON, "founder-witness", None).await;
        refused(wit(d, c).await.unwrap(), R::WitnessIsFounder);
        // bad signature
        let mut c = cosign_held_head(d, CANON, "w2", None).await;
        c.signature_classical = c.signature_classical.chars().rev().collect();
        refused(wit(d, c).await.unwrap(), R::SignatureInvalid);
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
        refused(wit(d, c).await.unwrap(), R::HeadInstantMismatch);
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
        refused(wit(d, c).await.unwrap(), R::Skew);
        // an unknown head is held as evidence
        let c = cosign_for(
            CANON,
            &"ab".repeat(32),
            chrono::Utc::now(),
            "w2",
            None,
            chrono::Utc::now(),
        );
        assert_eq!(wit(d, c).await.unwrap(), Out::HeldForUnknownHead);
        // malformed digest
        let mut c = cosign_held_head(d, CANON, "w2", None).await;
        c.head_digest_sha256_hex = "not-hex".into();
        refused(wit(d, c).await.unwrap(), R::Malformed);
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
        refused(wit(d, c).await.unwrap(), R::PriorNotAncestor);
    }

    /// **I192** — the witnessed head.
    pub async fn i192_the_witnessed_head(d: &dyn FederationDirectory) {
        let holders = born_witnessed(d).await;
        // never witnessed: judged as before rc6
        let v = d_view(d).await;
        assert_eq!(v.judged, None);
        assert!(cc::resolve_community(d, CANON).await.unwrap().is_some());
        // witness the birth
        assert_eq!(
            wit(d, cosign_held_head(d, CANON, "w1", None).await)
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
            wit(
                d,
                cosign_held_head(d, CANON, "w2", Some(&birth_digest)).await
            )
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
        try_charter_the_accord_with(d, members)
            .await
            .expect("the accord charters itself 3-of-3");
    }

    async fn try_charter_the_accord_with(
        d: &dyn FederationDirectory,
        members: serde_json::Value,
    ) -> Result<(), Error> {
        use crate::federation::trust_root::{
            test_pre_rotation_commitment, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
            TRUST_CHARTER_DIMENSION,
        };
        let family = cc::accord_family_key_id();
        let id = uuid::Uuid::new_v4().to_string();
        let commitment =
            test_pre_rotation_commitment(&["accord-succ-a".to_owned(), "accord-succ-b".to_owned()])
                .unwrap();
        let mut env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": commitment,
                "recovery_commitments":
                    crate::federation::trust_root::test_accord_recovery_commitments_held(d).await,
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
        .map(|_| ())
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
        // the consumer's OWN attach: the author's door (#973, I372–I375)
        d.put_attestation_authored(crate::federation::SignedAttestation { attestation: edge })
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
        let holders = born(d).await;
        let consumer = "i194-consumer";
        ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        // #973 (T4a) — a NEW edge names its head under any charter; the
        // pre-rc6 headless shape stays valid only for an edge already held
        // (I357).
        let pre = "i194-pre";
        ts::register_hybrid_key_as(d, pre, pre, identity_type::USER).await;
        assert_unnamed(accept_edge(d, pre, None).await, "I194 pre-rc6 charter");
        // the accord re-scrubs its charter with a window (ten years: the birth
        // is pinned to 2026-09-20, and a shorter window would decay the witness
        // on a calendar date)
        charter_the_accord_with(
            d,
            serde_json::json!({ "attach_window_secs": LONG_WINDOW, "witness_quorum": 2 }),
        )
        .await;
        let head = d
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        assert_unnamed(
            accept_edge(d, consumer, None).await,
            "I194 windowed charter",
        );
        assert_stale(accept_edge(d, consumer, Some(&head)).await, "not witnessed");
        wit(d, cosign_held_head(d, CANON, "w1", None).await)
            .await
            .unwrap();
        assert_stale(
            accept_edge(d, consumer, Some(&"ab".repeat(32))).await,
            "not the witnessed head this node serves",
        );
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
            serde_json::json!({ "attach_window_secs": 1, "witness_quorum": 2 }),
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
        // PR #943 review — a window beyond an instant's range is no bound,
        // never an overflow. The largest window an envelope can carry exactly
        // is 2^53 − 1 s (JCS numbers are IEEE doubles; a larger one never
        // reaches the arithmetic): ~285 million years, past chrono's range.
        charter_the_accord_with(
            d,
            serde_json::json!({ "attach_window_secs": 9_007_199_254_740_991_u64, "witness_quorum": 2 }),
        )
        .await;
        let huge = "i194-huge";
        ts::register_hybrid_key_as(d, huge, huge, identity_type::USER).await;
        accept_edge(d, huge, Some(&head))
            .await
            .expect("a window beyond an instant's range never makes a head stale");
        // PR #943 review — the attach anchor is the WITNESSED head, not the
        // stored one: after an unwitnessed amendment the birth (witnessed)
        // attaches and the held-but-unwitnessed v2 does not.
        charter_the_accord_with(
            d,
            serde_json::json!({ "attach_window_secs": LONG_WINDOW, "witness_quorum": 2 }),
        )
        .await;
        put_conferred(d, &holders, "fr-steward", "user,steward").await;
        founders_supersede(
            d,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "fr-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("an unwitnessed amendment");
        let v2 = d
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        assert_ne!(v2, head);
        let mid = "i194-mid";
        ts::register_hybrid_key_as(d, mid, mid, identity_type::USER).await;
        assert_stale(
            accept_edge(d, mid, Some(&v2)).await,
            "not the witnessed head this node serves",
        );
        accept_edge(d, mid, Some(&head))
            .await
            .expect("the witnessed birth attaches while v2 is unwitnessed");
    }

    /// Ten years, in seconds — an attach window no run of this suite outlives.
    const LONG_WINDOW: u64 = 315_360_000;

    async fn born_on(d: &dyn FederationDirectory) -> Vec<ops::Identity> {
        born(d).await
    }

    /// **I193** — equivocation, two nodes and one witness.
    pub async fn i193_equivocation_freezes_at_the_fork(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        let ha = born_witnessed(a).await;
        let hb = born_witnessed(b).await;
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
            wit(d, cosign_held_head(d, CANON, "w1", None).await)
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
        assert_eq!(wit(a, cos_a.clone()).await.unwrap(), Out::Inserted);
        assert_eq!(wit(b, cos_b.clone()).await.unwrap(), Out::Inserted);
        assert_eq!(
            d_view(a).await.judged,
            Some(1),
            "a adopts its witnessed H2a"
        );
        // a receives the witness plane's cosign of b's head: evidence, frozen at the birth
        assert_eq!(wit(a, cos_b).await.unwrap(), Out::HeldForUnknownHead);
        let view = d_view(a).await;
        assert_eq!(view.judged, Some(0), "frozen at the last common ancestor");
        let e = view.equivocation.expect("equivocation is reported");
        assert_eq!(e.fork_digest, birth_digest);
        assert_eq!(
            e.competing_witnesses,
            vec!["w1".to_owned(), "w1t".to_owned()],
            "the quorum of two that signed both heads"
        );
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
        assert_eq!(wit(b, cos_a).await.unwrap(), Out::HeldForUnknownHead);
        assert_eq!(d_view(b).await.judged, Some(0));
    }

    /// **I196** — restore discipline.
    pub async fn i196_a_node_behind_the_witness_plane_fetches_first(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        let ha = born_witnessed(a).await;
        let hb = born_witnessed(b).await;
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
        wit(b, cos.clone()).await.unwrap();
        // a (restored to the birth) learns of the witnessed head through the plane
        assert_eq!(wit(a, cos).await.unwrap(), Out::HeldForUnknownHead);
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

    /// The I340/I341 shape: with witnessed mode OFF, a cosign is stored as
    /// evidence and judges nothing — the founders' amendment is the current
    /// head, the lineage is live, and nothing is "held behind a witness".
    async fn off_mode_judges_on_the_founders(d: &dyn FederationDirectory, tag: &str) {
        let holders = born(d).await;
        if tag == "explicit-0" {
            charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 0 })).await;
        }
        assert_eq!(
            d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w1", None).await)
                .await
                .unwrap(),
            Out::Inserted,
            "({tag}) a cosign is still stored as evidence"
        );
        assert_eq!(
            d_view(d).await.judged,
            None,
            "({tag}) witnessed mode is off: one cosign engages nothing"
        );
        put_conferred(d, &holders, "new-steward", "user,steward").await;
        let v2 = swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "new-steward");
        founders_supersede(d, v2, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders amend");
        let view = d_view(d).await;
        assert_eq!(view.judged, None, "({tag}) still off after an amendment");
        assert_eq!(view.unwitnessed_tail, 0, "({tag}) nothing is held back");
        assert!(view.equivocation.is_none());
        let r = cc::resolve_community(d, CANON)
            .await
            .unwrap()
            .expect("rooted");
        assert!(
            r.founders.contains(&"new-steward".to_owned()),
            "({tag}) the founder-quorum head is current: {r:?}"
        );
        assert!(r.live, "({tag}) live on the founders' quorum");
        assert!(!r.witnessed, "({tag}) reported unwitnessed");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Rooted(_)
        ));
    }

    /// **I340** (#973; CC 3.2 T6) — a charter SILENT on `witness_quorum` is in
    /// witnessed mode off. No internal default is substituted.
    pub async fn i340_a_silent_charter_is_witnessed_mode_off(d: &dyn FederationDirectory) {
        off_mode_judges_on_the_founders(d, "silent").await;
    }

    /// **I341** — an explicit `witness_quorum: 0` is the same state as silence.
    pub async fn i341_an_explicit_zero_is_the_same_as_silence(d: &dyn FederationDirectory) {
        off_mode_judges_on_the_founders(d, "explicit-0").await;
    }

    /// **I342** — with witnessed mode off, attaching is by an out-of-band
    /// anchor only: an edge naming the head this node holds attaches (no
    /// cosign needed, the window does not apply); one naming another head, or
    /// none under a charter that declares a window, is refused.
    pub async fn i342_off_mode_attaches_by_anchor_only(d: &dyn FederationDirectory) {
        born(d).await;
        // a 1 s window over a birth pinned days ago: only the anchor can attach
        charter_the_accord_with(
            d,
            serde_json::json!({ "attach_window_secs": 1, "witness_quorum": 0 }),
        )
        .await;
        let head = d
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        for (i, name) in ["i342-a", "i342-b", "i342-c"].iter().enumerate() {
            ts::register_hybrid_key_as(d, name, name, identity_type::USER).await;
            let _ = i;
        }
        assert_unnamed(accept_edge(d, "i342-a", None).await, "I342 off mode");
        assert_stale(
            accept_edge(d, "i342-b", Some(&"ab".repeat(32))).await,
            "not the head this node holds",
        );
        accept_edge(d, "i342-c", Some(&head))
            .await
            .expect("I342: the anchor naming the held head attaches with no cosign");
        assert!(
            crate::federation::trust_root::trust_root_valid(d, "i342-c", CANON)
                .await
                .unwrap()
                .edge_exists
        );
    }

    /// A signed acceptance edge for `consumer` → the canonical root, unstored.
    fn accept_edge_row(
        id: &str,
        consumer: &str,
        head: Option<&str>,
        scope: &str,
    ) -> crate::federation::SignedAttestation {
        let mut env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
            "scope": [scope],
        });
        if let Some(h) = head {
            env["attached_head_digest"] = serde_json::Value::String(h.to_owned());
        }
        let mut edge = crate::federation::operational::test_support::signed_trust_attestation(
            id,
            consumer,
            CANON,
            crate::federation::types::attestation_type::DELEGATES_TO,
            env,
        );
        ts::reseal(&mut edge);
        crate::federation::SignedAttestation { attestation: edge }
    }

    fn assert_unnamed(r: Result<String, Error>, what: &str) {
        match r {
            Err(e) if e.kind() == "trust_root_head_unnamed" => {}
            other => panic!("{what}: expected trust_root_head_unnamed, got {other:?}"),
        }
    }

    /// **I356** (#973; CC 3.2 T4a rc6) — a NEW acceptance edge that names no
    /// head is refused by name in every mode: witnessed mode off (a silent
    /// charter with no window, the shape that used to admit) and witnessed
    /// mode on, with or without a window.
    pub async fn i356_a_new_headless_edge_is_refused_in_every_mode(d: &dyn FederationDirectory) {
        born(d).await;
        for name in ["i356-off", "i356-on", "i356-win"] {
            ts::register_hybrid_key_as(d, name, name, identity_type::USER).await;
        }
        assert_unnamed(
            accept_edge(d, "i356-off", None).await,
            "off, silent charter",
        );
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 2 })).await;
        assert_unnamed(
            accept_edge(d, "i356-on", None).await,
            "witnessed, no window",
        );
        charter_the_accord_with(
            d,
            serde_json::json!({ "attach_window_secs": LONG_WINDOW, "witness_quorum": 2 }),
        )
        .await;
        assert_unnamed(accept_edge(d, "i356-win", None).await, "witnessed, window");
        // #973 "bundle only" — a NEW row with NO job label is not an
        // acceptance edge at all (CC 3.2 T4a): outside the pinned bundle the
        // gate has nothing to judge, so the row is stored as a plain
        // delegation under a window and without one, and gives no acceptance.
        ts::register_hybrid_key_as(d, "i356-unl", "i356-unl", identity_type::USER).await;
        let unlabeled = |id: &str| {
            let mut edge = crate::federation::operational::test_support::signed_trust_attestation(
                id,
                "i356-unl",
                CANON,
                crate::federation::types::attestation_type::DELEGATES_TO,
                serde_json::json!({
                    "references_attestation_id": id,
                    "scope": [crate::federation::trust_root::INFRA_SERVE_SCOPE],
                }),
            );
            ts::reseal(&mut edge);
            crate::federation::SignedAttestation { attestation: edge }
        };
        let id = uuid::Uuid::new_v4().to_string();
        d.put_attestation(unlabeled(&id))
            .await
            .expect("I356: an unlabeled row is no acceptance edge; nothing to gate (window)");
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 2 })).await;
        let id = uuid::Uuid::new_v4().to_string();
        d.put_attestation(unlabeled(&id))
            .await
            .expect("I356: nor under a charter with no window");
        assert!(
            !crate::federation::trust_root::trust_root_valid(d, "i356-unl", CANON)
                .await
                .unwrap()
                .edge_exists,
            "I356: the stored unlabeled rows give no acceptance"
        );
        assert!(
            crate::federation::trust_root::trusted_roots_of(d, "i356-unl", chrono::Utc::now())
                .await
                .unwrap()
                .is_empty(),
            "I356: and name no subscribed root"
        );
        for name in ["i356-off", "i356-on", "i356-win"] {
            assert!(
                !crate::federation::trust_root::trust_root_valid(d, name, CANON)
                    .await
                    .unwrap()
                    .edge_exists,
                "I356: a refused edge is not stored ({name})"
            );
        }
    }

    /// **I357** — an edge this node ALREADY holds with no head (admitted
    /// before the node held the lineage: the pre-enforcement shape) stays
    /// valid, and re-putting the same edge re-runs nothing — in off mode and
    /// after the charter turns witnessing and a window on.
    /// **I371** (#973) — the envelope a host copies. `acceptance_edge_envelope`
    /// names the job and the head the attach gate asks for, so an edge built
    /// from it is admitted and gives acceptance; toward a key root (no lineage
    /// held) it names the job and no head.
    pub async fn i371_the_helper_builds_an_admitted_acceptance_edge(d: &dyn FederationDirectory) {
        use crate::federation::canonical_community::{acceptance_edge_envelope, attach_head_for};
        use crate::federation::trust_root::{INFRA_SERVE_SCOPE, TRUST_ACCEPTS_DIMENSION};
        born(d).await;
        let now = chrono::Utc::now();
        let env = acceptance_edge_envelope(d, CANON, &[INFRA_SERVE_SCOPE], now)
            .await
            .unwrap();
        let head = attach_head_for(d, CANON, now)
            .await
            .unwrap()
            .expect("I371: a held lineage has an attachable head");
        assert_eq!(
            env,
            serde_json::json!({
                "dimension": TRUST_ACCEPTS_DIMENSION,
                "scope": [INFRA_SERVE_SCOPE],
                "attached_head_digest": head,
            }),
            "I371: the whole shape"
        );
        ts::register_hybrid_key_as(d, "i371-node", "i371-node", identity_type::USER).await;
        let id = uuid::Uuid::new_v4().to_string();
        let mut edge = crate::federation::operational::test_support::signed_trust_attestation(
            &id,
            "i371-node",
            CANON,
            crate::federation::types::attestation_type::DELEGATES_TO,
            env,
        );
        ts::reseal(&mut edge);
        d.put_attestation(crate::federation::SignedAttestation { attestation: edge })
            .await
            .expect("I371: the helper's envelope passes the attach gate");
        assert!(
            crate::federation::trust_root::trust_root_valid(d, "i371-node", CANON)
                .await
                .unwrap()
                .edge_exists,
            "I371: and gives acceptance"
        );
        let key_root = acceptance_edge_envelope(d, "i371-some-key-root", &[INFRA_SERVE_SCOPE], now)
            .await
            .unwrap();
        assert_eq!(
            key_root,
            serde_json::json!({
                "dimension": TRUST_ACCEPTS_DIMENSION,
                "scope": [INFRA_SERVE_SCOPE],
            }),
            "I371: a key root has no head to name"
        );
    }

    pub async fn i357_a_held_headless_edge_stays_valid(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let consumer = "i357-consumer";
        ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        ts::register_hybrid_key_as(d, CANON, CANON, identity_type::USER).await;
        let id = uuid::Uuid::new_v4().to_string();
        let edge = accept_edge_row(
            &id,
            consumer,
            None,
            crate::federation::trust_root::INFRA_SERVE_SCOPE,
        );
        d.put_attestation(edge.clone())
            .await
            .expect("I357: admitted before this node held the lineage");
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .expect("the lineage arrives");
        d.put_attestation(edge.clone())
            .await
            .expect("I357: the same edge re-put in off mode is not re-judged");
        charter_the_accord_with(
            d,
            serde_json::json!({ "attach_window_secs": 1, "witness_quorum": 2 }),
        )
        .await;
        d.put_attestation(edge.clone())
            .await
            .expect("I357: nor under a witnessed charter with a lapsed window");
        d.apply_replicated_attestation(edge)
            .await
            .expect("I357: nor when it is replicated back");
        assert!(
            crate::federation::trust_root::trust_root_valid(d, consumer, CANON)
                .await
                .unwrap()
                .edge_exists,
            "I357: attached stays attached"
        );
    }

    /// **I358** — a held edge's id re-offered with DIFFERENT content and no
    /// head is a new edge: refused, and the held row is untouched.
    pub async fn i358_a_changed_edge_under_a_held_id_is_new(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let consumer = "i358-consumer";
        ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        ts::register_hybrid_key_as(d, CANON, CANON, identity_type::USER).await;
        let id = uuid::Uuid::new_v4().to_string();
        let held = accept_edge_row(
            &id,
            consumer,
            None,
            crate::federation::trust_root::INFRA_SERVE_SCOPE,
        );
        d.put_attestation(held.clone()).await.expect("held");
        d.put_community(signed(canonical_row(&FOUNDERS), &["A1", "B1"]))
            .await
            .expect("the lineage arrives");
        let changed = accept_edge_row(&id, consumer, None, "infra:attest");
        let e = d
            .put_attestation(changed)
            .await
            .expect_err("I358: a different edge under the held id");
        // The id-conflict door answers before the attach gate on every
        // backend; either refusal leaves the held edge as it was.
        assert!(
            matches!(e.kind(), "federation_conflict" | "trust_root_head_unnamed"),
            "I358: {e:?}"
        );
        // The gate itself judges it as new, whatever door order precedes it:
        // a held id with a different signed envelope is not "already admitted".
        let changed = accept_edge_row(&id, consumer, None, "infra:attest").attestation;
        let e = cc::check_attach_freshness(
            d,
            cc::AttachDoor::Author,
            Some(&id),
            &changed.attesting_key_id,
            &changed.attestation_type,
            &changed.attested_key_id,
            &changed.attestation_envelope,
            chrono::Utc::now(),
        )
        .await
        .expect_err("I358: the gate reads a changed envelope as a new edge");
        assert_eq!(e.kind(), "trust_root_head_unnamed", "I358: {e:?}");
        let same = held.attestation.clone();
        cc::check_attach_freshness(
            d,
            cc::AttachDoor::Author,
            Some(&id),
            &same.attesting_key_id,
            &same.attestation_type,
            &same.attested_key_id,
            &same.attestation_envelope,
            chrono::Utc::now(),
        )
        .await
        .expect("I358: the held edge itself is not re-judged");
        let after = d.get_attestation(&id).await.unwrap().expect("still held");
        assert_eq!(
            after.original_content_hash, held.attestation.original_content_hash,
            "I358: the held edge is untouched"
        );
    }

    /// **I359** — a new edge naming the head this node holds attaches in off
    /// mode under a silent charter with no window: the anchor is enough.
    pub async fn i359_a_new_edge_naming_the_held_head_attaches_off(d: &dyn FederationDirectory) {
        born(d).await;
        let consumer = "i359-consumer";
        ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        let head = d
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        assert_stale(
            accept_edge(d, consumer, Some(&"cd".repeat(32))).await,
            "not the head this node holds",
        );
        accept_edge(d, consumer, Some(&head))
            .await
            .expect("I359: the anchored head attaches");
        assert!(
            crate::federation::trust_root::trust_root_valid(d, consumer, CANON)
                .await
                .unwrap()
                .edge_exists
        );
    }

    /// Advance `d`'s canonical head by a founders' amendment; returns the new head.
    async fn advance_head(d: &dyn FederationDirectory, holders: &[ops::Identity]) -> String {
        put_conferred(d, holders, "new-steward", "user,steward").await;
        let v2 = swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "new-steward");
        founders_supersede(d, v2, &[FOUNDERS[0], FOUNDERS[1]])
            .await
            .expect("the founders amend");
        held_head(d).await
    }

    async fn held_head(d: &dyn FederationDirectory) -> String {
        d.lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash
    }

    /// The author's own write of its acceptance edge (the attaching node's door).
    async fn author_edge(
        d: &dyn FederationDirectory,
        consumer: &str,
        head: Option<&str>,
    ) -> Result<crate::federation::SignedAttestation, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let edge = accept_edge_row(
            &id,
            consumer,
            head,
            crate::federation::trust_root::INFRA_SERVE_SCOPE,
        );
        d.put_attestation_authored(edge.clone()).await?;
        Ok(edge)
    }

    async fn reads_as_attached(d: &dyn FederationDirectory, consumer: &str, what: &str) {
        assert!(
            crate::federation::trust_root::trust_root_valid(d, consumer, CANON)
                .await
                .unwrap()
                .edge_exists,
            "{what}: the receiver holds the sender's acceptance edge"
        );
        assert!(
            crate::federation::trust_root::trusted_roots_of(d, consumer, chrono::Utc::now())
                .await
                .unwrap()
                .contains(&CANON.to_owned()),
            "{what}: the receiver reads the sender as rooted (`trusted_roots_of`)"
        );
    }

    /// **I372** (#973; CC 3.2 T4a "a write-side gate … first admission only")
    /// — a peer does not re-judge another node's attach. The receiver's head
    /// has ADVANCED past the head the edge names: the replicated edge is
    /// admitted and the sender reads as rooted there.
    pub async fn i372_a_receiver_ahead_admits_the_replicated_edge(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        born(a).await;
        let holders_b = born(b).await;
        let consumer = "i372-consumer";
        for d in [a, b] {
            ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        }
        let h1 = held_head(a).await;
        let edge = author_edge(a, consumer, Some(&h1))
            .await
            .expect("I372: the author attaches on the head it holds");
        let h2 = advance_head(b, &holders_b).await;
        assert_ne!(h1, h2, "I372: the receiver's head moved");
        b.put_attestation(edge.clone())
            .await
            .expect("I372: a peer ahead of the edge's head admits it on replication");
        reads_as_attached(b, consumer, "I372").await;
        // and through the replication apply door, idempotently
        b.apply_replicated_attestation(edge)
            .await
            .expect("I372: the apply door");
    }

    /// **I373** — the receiver is BEHIND the head the edge names: admitted too.
    pub async fn i373_a_receiver_behind_admits_the_replicated_edge(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        let holders_a = born(a).await;
        born(b).await;
        let consumer = "i373-consumer";
        for d in [a, b] {
            ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        }
        let h2 = advance_head(a, &holders_a).await;
        assert_ne!(h2, held_head(b).await, "I373: the receiver is behind");
        let edge = author_edge(a, consumer, Some(&h2))
            .await
            .expect("I373: the author attaches on its newer head");
        b.apply_replicated_attestation(edge)
            .await
            .expect("I373: a peer behind the edge's head admits it on replication");
        reads_as_attached(b, consumer, "I373").await;
        // the authenticated-sync door is a replicated door too
        let second = "i373-second";
        for d in [a, b] {
            ts::register_hybrid_key_as(d, second, second, identity_type::USER).await;
        }
        let edge2 = author_edge(a, second, Some(&h2))
            .await
            .expect("I373: a second attach");
        b.put_attestation_synced(edge2, consumer)
            .await
            .expect("I373: the sync door admits it too");
        reads_as_attached(b, second, "I373 (sync)").await;
    }

    /// **I374** — the local gate is not weakened, and the shape rule holds on
    /// both doors: the author's own write naming a head it does not hold is
    /// refused; a labelled edge naming no head is refused on apply too.
    pub async fn i374_the_authors_gate_and_the_shape_rule_stand(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        born(a).await;
        born(b).await;
        let consumer = "i374-consumer";
        for d in [a, b] {
            ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        }
        match author_edge(a, consumer, Some(&"cd".repeat(32))).await {
            Err(Error::TrustRootHeadStale { detail, .. }) => {
                assert!(detail.contains("not the head this node holds"), "{detail}")
            }
            other => panic!("I374: the author's stale attach must refuse, got {other:?}"),
        }
        // the local-tier write is an author's door too
        let local = a
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: consumer.to_owned(),
                attested_key_id: Some(CANON.to_owned()),
                attestation_type: crate::federation::types::attestation_type::DELEGATES_TO
                    .to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({
                        "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
                        "scope": [crate::federation::trust_root::INFRA_SERVE_SCOPE],
                        "attached_head_digest": "cd".repeat(32),
                    }),
                )
                .unwrap(),
                subject_key_ids: vec![],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await;
        match local {
            Err(Error::TrustRootHeadStale { .. }) => {}
            other => panic!("I374 (local tier): a stale local attach must refuse, got {other:?}"),
        }
        let headless = accept_edge_row(
            &uuid::Uuid::new_v4().to_string(),
            consumer,
            None,
            crate::federation::trust_root::INFRA_SERVE_SCOPE,
        );
        let id = headless.attestation.attestation_id.clone();
        for (door, r) in [
            (
                "wire",
                b.put_attestation(headless.clone()).await.map(|_| ()),
            ),
            (
                "apply",
                b.apply_replicated_attestation(headless.clone())
                    .await
                    .map(|_| ()),
            ),
            (
                "authored",
                a.put_attestation_authored(headless.clone())
                    .await
                    .map(|_| ()),
            ),
        ] {
            match r {
                Err(e) if e.kind() == "trust_root_head_unnamed" => {}
                other => {
                    panic!("I374 ({door}): a headless labelled edge must refuse, got {other:?}")
                }
            }
        }
        assert!(b.get_attestation(&id).await.unwrap().is_none());
    }

    /// **I375** — witnessed mode ON at the receiver (explicit quorum 2), the
    /// receiver has NOT witnessed the head: the replicated edge is admitted
    /// (the witness quorum is the attaching node's question), while the
    /// receiver's own attach on that unwitnessed head is still refused.
    pub async fn i375_a_witnessed_receiver_admits_an_edge_it_did_not_witness(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        born_witnessed(a).await;
        born_witnessed(b).await;
        let (consumer, local) = ("i375-consumer", "i375-local");
        for d in [a, b] {
            for k in [consumer, local] {
                ts::register_hybrid_key_as(d, k, k, identity_type::USER).await;
            }
        }
        for w in ["w1", "w2"] {
            a.put_lineage_head_cosign(cosign_held_head(a, CANON, w, None).await)
                .await
                .unwrap();
        }
        let head = held_head(a).await;
        let edge = author_edge(a, consumer, Some(&head))
            .await
            .expect("I375: the author attaches on its witnessed head");
        assert_eq!(
            d_view(b).await.judged,
            None,
            "I375: b has witnessed nothing"
        );
        b.put_attestation(edge)
            .await
            .expect("I375: a replicated edge is not judged against the receiver's witness view");
        reads_as_attached(b, consumer, "I375").await;
        assert_stale(
            author_edge(b, local, Some(&head))
                .await
                .map(|e| e.attestation.attestation_id),
            "not witnessed",
        );
    }

    /// **I343** — an explicit, valid quorum keeps working as before: under
    /// `witness_quorum: 2` one cosign engages nothing and two witness the head.
    pub async fn i343_an_explicit_quorum_still_witnesses(d: &dyn FederationDirectory) {
        born(d).await;
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 2 })).await;
        d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w1", None).await)
            .await
            .unwrap();
        assert_eq!(d_view(d).await.judged, None, "one of two");
        d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w2", None).await)
            .await
            .unwrap();
        assert_eq!(d_view(d).await.judged, Some(0), "two of two: witnessed");
        assert!(
            cc::resolve_community(d, CANON)
                .await
                .unwrap()
                .unwrap()
                .witnessed
        );
    }

    /// **I344** — a charter declaring `witness_quorum: 1` is refused at
    /// admission by name (CC 3.2 T6: zero, or a strict majority of the
    /// directory and at least 2), and nothing is stored.
    pub async fn i344_a_quorum_of_one_is_refused_at_the_charter(d: &dyn FederationDirectory) {
        born(d).await;
        let e = try_charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 1 }))
            .await
            .expect_err("I344: a quorum of one is not a valid charter value");
        assert!(
            matches!(&e, Error::CharterInvalid { detail }
                if detail.contains(crate::federation::trust_root::CHARTER_RULE_WITNESS_QUORUM_BELOW_MAJORITY)),
            "{e:?}"
        );
        assert!(
            cc::charter_members_for(d, CANON).await.unwrap().is_none(),
            "I344: the refused charter is not stored"
        );
        // 0 and 2 are both admitted
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 0 })).await;
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 2 })).await; // the KEY-root charter door (a self-loop charter) applies the same rule
        let root = "i344-key-root";
        ts::register_hybrid_key_as(d, root, root, identity_type::USER).await;
        let key_charter = |quorum: u64| {
            let id = uuid::Uuid::new_v4().to_string();
            let commitment = crate::federation::trust_root::test_pre_rotation_commitment(&[
                "i344-succ-a".to_owned(),
                "i344-succ-b".to_owned(),
            ])
            .unwrap();
            let mut row = crate::federation::operational::test_support::signed_trust_attestation(
                &id,
                root,
                root,
                crate::federation::types::attestation_type::DELEGATES_TO,
                serde_json::json!({
                    "references_attestation_id": id,
                    "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
                    "scope": [crate::federation::trust_root::INFRA_SERVE_SCOPE],
                    "pre_rotation_commitment": commitment,
                    "witness_quorum": quorum,
                }),
            );
            ts::reseal(&mut row);
            crate::federation::SignedAttestation { attestation: row }
        };
        let token = crate::federation::trust_root::CHARTER_RULE_WITNESS_QUORUM_BELOW_MAJORITY;
        let e = d
            .put_attestation(key_charter(1))
            .await
            .expect_err("I344: a key root's charter with a quorum of one");
        assert!(
            matches!(&e, Error::CharterInvalid { detail } if detail.contains(token)),
            "{e:?}"
        );
        if let Err(e) = d.put_attestation(key_charter(2)).await {
            assert!(
                !e.to_string().contains(token),
                "I344: a quorum of two is never refused under this rule: {e:?}"
            );
        }
    }

    /// **I195** — the liveness margin.
    pub async fn i195_the_liveness_margin(d: &dyn FederationDirectory) {
        use crate::federation::trust_root::{trust_root_valid, RootKind};
        let holders = born(d).await;
        let r = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert!(r.live, "3 founders at quorum:2/3: live (M + 1)");
        // a consumer attached before the stall, naming the head it holds
        // (#973: a new edge names its head; witnessed mode is off here)
        let consumer = "i195-consumer";
        ts::register_hybrid_key_as(d, consumer, consumer, identity_type::USER).await;
        let head = d
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        accept_edge(d, consumer, Some(&head))
            .await
            .expect("attaches");
        ts::register_hybrid_key_as(d, "stall-node", "stall-node", identity_type::NODE).await;
        assert_eq!(count(d, kind::COMMUNITY_LIVENESS_STALLED).await, 0);
        // a resignation: stalled, declared once
        d.put_community_membership_revocation(founder_revocation(&[FOUNDERS[2]], FOUNDERS[2]))
            .await
            .expect("a founder resigns");
        assert!(matches!(
            cc::stored_standing(d, CANON).await.unwrap(),
            cc::StoredStanding::Stalled { .. }
        ));
        // PR #943 review (CC 3.2 T7) — a stalled root is VALID but
        // non-admitting: still served (live = false), still the community arm
        // of trust_root_valid, and a new member is refused.
        let r = cc::resolve_community(d, CANON)
            .await
            .unwrap()
            .expect("a stalled root is still served");
        assert!(!r.live, "stalled: not live");
        let v = trust_root_valid(d, consumer, CANON).await.unwrap();
        assert!(
            v.edge_exists && matches!(v.root_kind, RootKind::Community),
            "a stalled root stays the attached consumer's community root: {v:?}"
        );
        let e = d
            .put_community_membership_widening_consented(widening_by(
                &[FOUNDERS[0], FOUNDERS[1]],
                "stall-node",
                Some("member"),
            ))
            .await
            .expect_err("a stalled root admits no one");
        assert!(
            matches!(&e, Error::CommunityConsensusProtocolViolation { rule, .. }
                if *rule == crate::federation::admission::TRUST_ROOT_RULE_STALLED_NON_ADMITTING),
            "{e:?}"
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
        assert!(cc::resolve_community(d, CANON).await.unwrap().unwrap().live);
        d.put_community_membership_widening_consented(widening_by(
            &[FOUNDERS[0], FOUNDERS[1]],
            "stall-node",
            Some("member"),
        ))
        .await
        .expect("restored: admitting again");
    }

    /// **I192b** (PR #943 review) — witnessed mode engages at the QUORUM, not
    /// at the first cosign: under `witness_quorum: 2`, one cosign on the birth
    /// leaves a two-version lineage judged as before rc6 (served at its stored
    /// head, never rolled back to the birth); the second independent cosign
    /// engages it.
    pub async fn i192b_witnessed_mode_needs_the_quorum(d: &dyn FederationDirectory) {
        let holders = born(d).await;
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 2 })).await;
        put_conferred(d, &holders, "q2-steward", "user,steward").await;
        founders_supersede(
            d,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "q2-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("v2");
        let birth = cc::lookup_signed_community(d, CANON)
            .await
            .unwrap()
            .unwrap()
            .lineage[0]
            .clone();
        let birth_digest = birth.community.persist_row_hash.clone();
        let c = cosign_for(
            CANON,
            &birth_digest,
            cc::head_instant(&birth),
            "w1",
            None,
            chrono::Utc::now(),
        );
        assert_eq!(d.put_lineage_head_cosign(c).await.unwrap(), Out::Inserted);
        assert_eq!(d_view(d).await.judged, None, "1 of 2: not witnessed mode");
        let r = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert!(
            r.founders.contains(&"q2-steward".to_owned()),
            "served at the stored head: {r:?}"
        );
        let c = cosign_for(
            CANON,
            &birth_digest,
            cc::head_instant(&birth),
            "w2",
            None,
            chrono::Utc::now(),
        );
        assert_eq!(d.put_lineage_head_cosign(c).await.unwrap(), Out::Inserted);
        let v = d_view(d).await;
        assert_eq!(v.judged, Some(0), "2 of 2 on the birth: judged there");
        assert_eq!(v.unwitnessed_tail, 1);
        let r = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert_eq!(r.founders, FOUNDERS.to_vec(), "served at the birth");
        // a below-quorum cosign on this node's OWN stored tail: the node is not
        // behind the witness plane (the restore discipline reads the stored
        // chain); an amendment on the unwitnessed tail is refused because it
        // does not follow the witnessed head — named as that, not as a lag
        let v2_digest = d
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        assert_ne!(v2_digest, birth_digest);
        d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w1", Some(&birth_digest)).await)
            .await
            .unwrap();
        put_conferred(d, &holders, "q2-steward-b", "user,steward").await;
        let e = founders_supersede(
            d,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "q2-steward-b"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect_err("an unwitnessed tail is not extended");
        assert!(
            !e.to_string()
                .contains(crate::federation::admission::TRUST_ROOT_RULE_BEHIND_WITNESS),
            "a cosign on the node's own tail is not a lag: {e:?}"
        );
        // the charter raises the quorum to 3: no version reaches it, so the
        // lineage is judged as before rc6 again — the CACHED standing must not
        // survive a charter change (the charter members are in its key)
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 3 })).await;
        let r = cc::resolve_community(d, CANON).await.unwrap().unwrap();
        assert!(
            r.founders.contains(&"q2-steward".to_owned()),
            "a raised quorum re-judges, never a stale cache: {r:?}"
        );
    }

    /// **I193b** (PR #943 review) — a DEEP fork: `a` holds birth → H2a
    /// (witnessed 2-of-2); the witness plane saw birth → H2b → H3b, and `a`
    /// receives H3b's two cosigns and ONE of H2b's (below the quorum). H3b's
    /// immediate prior is unknown to `a`; walking the priors reaches the birth,
    /// so `a` freezes there.
    pub async fn i193b_a_deep_fork_freezes_at_the_common_ancestor(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        let ha = born_on(a).await;
        let hb = born_on(b).await;
        for (d, h) in [(a, &ha), (b, &hb)] {
            charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 2 })).await;
            put_conferred(d, h, "df-steward", "user,steward").await;
            ts::register_hybrid_key_as(d, "df-serve-node", "df-serve-node", identity_type::NODE)
                .await;
            for w in ["w1", "w2"] {
                d.put_lineage_head_cosign(cosign_held_head(d, CANON, w, None).await)
                    .await
                    .unwrap();
            }
            assert_eq!(d_view(d).await.judged, Some(0));
        }
        let birth_digest = a
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        founders_supersede(
            a,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "df-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("a: H2a");
        for w in ["w1", "w2"] {
            a.put_lineage_head_cosign(cosign_held_head(a, CANON, w, Some(&birth_digest)).await)
                .await
                .unwrap();
        }
        assert_eq!(d_view(a).await.judged, Some(1), "a adopts H2a");
        founders_supersede(
            b,
            with_member(canonical_row(&FOUNDERS), "df-serve-node", "member"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("b: H2b");
        let h2b = b
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        // b's H2b is witnessed 2-of-2 on b (a founders' amendment follows the
        // WITNESSED head), but only w1's cosign reaches a: on a, H2b is below
        // the quorum and only H3b is a witnessed competing head.
        let cos_h2b = cosign_held_head(b, CANON, "w1", Some(&birth_digest)).await;
        b.put_lineage_head_cosign(cos_h2b.clone()).await.unwrap();
        b.put_lineage_head_cosign(cosign_held_head(b, CANON, "w2", Some(&birth_digest)).await)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        founders_supersede(
            b,
            with_member(
                swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "df-steward"),
                "df-serve-node",
                "member",
            ),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("b: H3b");
        let h3b = b
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        let mut cos_h3b = Vec::new();
        for w in ["w1", "w2"] {
            let c = cosign_held_head(b, CANON, w, Some(&h2b)).await;
            b.put_lineage_head_cosign(c.clone()).await.unwrap();
            cos_h3b.push(c);
        }
        assert_eq!(d_view(b).await.judged, Some(2), "b: H3b witnessed");
        // the witness plane delivers b's cosigns to a
        for c in std::iter::once(cos_h2b).chain(cos_h3b) {
            assert_eq!(
                a.put_lineage_head_cosign(c).await.unwrap(),
                Out::HeldForUnknownHead
            );
        }
        let view = d_view(a).await;
        assert_eq!(view.judged, Some(0), "frozen at the common ancestor");
        let e = view.equivocation.expect("the deep fork is equivocation");
        assert_eq!(e.fork_digest, birth_digest);
        assert_eq!(e.competing_head_digest, h3b);
    }

    /// **I197** (PR #943 review) — a cosign stored before its head arrived is
    /// re-checked when the head does: one naming the WRONG instant for that
    /// head does not count; the correctly-instanted one does.
    pub async fn i197_a_deferred_cosign_is_rechecked_on_arrival(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
    ) {
        let ha = born_witnessed(a).await;
        let hb = born_witnessed(b).await;
        for (d, h) in [(a, &ha), (b, &hb)] {
            put_conferred(d, h, "dc-steward", "user,steward").await;
            wit(d, cosign_held_head(d, CANON, "w1", None).await)
                .await
                .unwrap();
        }
        let birth_digest = a
            .lookup_community(CANON)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        founders_supersede(
            b,
            swapped(canonical_row(&FOUNDERS), FOUNDERS[2], "dc-steward"),
            &[FOUNDERS[0], FOUNDERS[1]],
        )
        .await
        .expect("b: v2");
        let v2 = cc::lookup_signed_community(b, CANON)
            .await
            .unwrap()
            .unwrap();
        let v2_digest = v2.community.persist_row_hash.clone();
        let v2_at = cc::head_instant(&v2);
        // a lying cosign reaches a first: the right digest, a wrong instant
        let lie = cosign_for(
            CANON,
            &v2_digest,
            v2_at - chrono::Duration::hours(1),
            "w2",
            Some(&birth_digest),
            chrono::Utc::now(),
        );
        assert_eq!(wit(a, lie).await.unwrap(), Out::HeldForUnknownHead);
        a.put_community(v2.clone()).await.expect("a applies v2");
        let view = d_view(a).await;
        assert_eq!(
            view.judged,
            Some(0),
            "the deferred cosign names the wrong instant: it does not count"
        );
        assert_eq!(view.unwitnessed_tail, 1);
        let honest = cosign_for(
            CANON,
            &v2_digest,
            v2_at,
            "w2",
            Some(&birth_digest),
            chrono::Utc::now(),
        );
        assert_eq!(wit(a, honest).await.unwrap(), Out::Inserted);
        assert_eq!(d_view(a).await.judged, Some(1));
    }

    /// **I198** (PR #943 review) — the quorum counts PERSONS: two witness keys
    /// owned by one person are one witness.
    pub async fn i198_one_person_is_one_witness(d: &dyn FederationDirectory) {
        born(d).await;
        charter_the_accord_with(d, serde_json::json!({ "witness_quorum": 2 })).await;
        ts::register_hybrid_key_as(d, "wp-owner", "wp-owner", identity_type::USER).await;
        for k in ["wp-a", "wp-b"] {
            ts::register_hybrid_key_as(d, k, k, identity_type::WITNESS).await;
            d.put_attestation(crate::federation::SignedAttestation {
                attestation: ts::owner_binding_attestation(
                    &uuid::Uuid::new_v4().to_string(),
                    "wp-owner",
                    k,
                ),
            })
            .await
            .expect("one person owns both witness keys");
        }
        for k in ["wp-a", "wp-b"] {
            assert_eq!(
                d.put_lineage_head_cosign(cosign_held_head(d, CANON, k, None).await)
                    .await
                    .unwrap(),
                Out::Inserted
            );
        }
        assert_eq!(d_view(d).await.judged, None, "two keys, one person: 1 of 2");
        d.put_lineage_head_cosign(cosign_held_head(d, CANON, "w1", None).await)
            .await
            .unwrap();
        assert_eq!(d_view(d).await.judged, Some(0), "a second person: 2 of 2");
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
                async fn i372() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i372_a_receiver_ahead_admits_the_replicated_edge(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i373() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i373_a_receiver_behind_admits_the_replicated_edge(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i374() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i374_the_authors_gate_and_the_shape_rule_stand(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i375() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i375_a_witnessed_receiver_admits_an_edge_it_did_not_witness(
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
                async fn i192b() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i192b_witnessed_mode_needs_the_quorum(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i198() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i198_one_person_is_one_witness(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i193b() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i193b_a_deep_fork_freezes_at_the_common_ancestor(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i197() {
                    let (Some(a), Some(b)) = ($fresh.await, $fresh.await) else {
                        return;
                    };
                    super::super::bodies::i197_a_deferred_cosign_is_rechecked_on_arrival(
                        &a as &dyn FederationDirectory,
                        &b as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i356() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i356_a_new_headless_edge_is_refused_in_every_mode(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i371() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i371_the_helper_builds_an_admitted_acceptance_edge(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i357() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i357_a_held_headless_edge_stays_valid(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i358() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i358_a_changed_edge_under_a_held_id_is_new(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i359() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i359_a_new_edge_naming_the_held_head_attaches_off(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i340() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i340_a_silent_charter_is_witnessed_mode_off(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i341() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i341_an_explicit_zero_is_the_same_as_silence(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i342() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i342_off_mode_attaches_by_anchor_only(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i343() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i343_an_explicit_quorum_still_witnesses(
                        &d as &dyn FederationDirectory,
                    )
                    .await
                }
                #[tokio::test]
                async fn i344() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i344_a_quorum_of_one_is_refused_at_the_charter(
                        &d as &dyn FederationDirectory,
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
