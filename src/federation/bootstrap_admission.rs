//! v22.0.0 (CIRISPersist#543) — **the bootstrap/Sybil admission matrix**: the
//! cross-backend witnesses for every put-gate that stands between an admitted
//! mesh peer and this node's state.
//!
//! # Why this module exists
//!
//! Canonical servers exist to bootstrap new peers, so admission is deliberately
//! cheap: [`register_federation_key`](super::register) requires a **self-signed
//! hybrid proof-of-possession and nothing else**. That proves key *custody* —
//! not identity, and not authorization. Key material is free, so the threat
//! model must assume **unlimited admitted identities**.
//!
//! What makes that survivable is the layer below: an admitted peer can PUSH
//! rows, but every row must pass persist's put-gates. Edge's consent plane is
//! SEND-only (`apply_envelope_bytes` never receives the peer id — CIRISEdge#426),
//! and the server's owner-gated HTTP admission is bypassed entirely by the mesh
//! receive path. **So persist's put-gates are the entire defence.** A gate that
//! leaks is not defence-in-depth lost; it is the only depth.
//!
//! CIRISPersist#543 audited them and found three leaking. This module holds the
//! witnesses that keep them shut, as a `{gate} × {backend}` matrix — the same
//! shape as [`super::self_at_login::test_support::run_signed_transport_route_matrix`],
//! and for the same reason [`super::operational`]'s conferral fixtures learned
//! the hard way (CIRISPersist#518/#534/#536/#541): a gate proven on one backend
//! is a gate unproven, because the backends have repeatedly disagreed.
//!
//! # The invariants this matrix pins
//!
//! | # | Invariant | Threat it denies |
//! |---|---|---|
//! | B1 | A `capacity:*` claim is never self-attested, on EITHER wire shape (`attestation_type` OR `dimension`) | Sybil self-inflation of its own capacity score (AV-62) |
//! | B2 | Every authority-conferring `identity_type` / role is gated at registration, not self-assertable | A Sybil asserting `witness` / `substrate_persist` / … to gain authority over a third party |
//! | B3 | Third-party `scores` about a subject are bounded by the emitter's standing | ≥3 Sybils fabricating a verdict about an uninvolved subject |
//! | B4 | A row that will fail crypto verification is rejected before it can spend DB walks | Bootstrap amplification: cheap requests doing expensive work |
//! | B5 | A federation-tier `capacity:*` score about S from P needs a live `analyze` consent from S covering P | An admitted stranger publishing a reputation verdict about someone who never authorized it (CIRISConstitution#46) |
//! | B7 | B5's gate is `capacity:*` and NOTHING else: the verify-owned artifact-integrity and adversarial-detector families admit with the subject silent (CC 3.4.5) | An adversary opting out of `rollback_detected:*` by declining `analyze`, and integrity verification stopping at the forger's own consent (CIRISPersist#569, adjudicated) |
//! | B8 | A row does not escape a put-gate by entering at the local tier and being PROMOTED, and `capacity:*` never reaches the local tier on any door | Minting the `capacity:composite` CC 3.4.5 says MUST NOT be emitted — and, for every other family, laundering a row past AV-45/AV-77/moderation through the promote path (CIRISPersist#589 / AV-83) |
//! | B9 | A row reaches a TARGETED cohort plane (`family` / `community`) only when it names no party but its own producer | Publishing a stranger's row — or a verdict about a stranger — into a cohort plane, which is the placement AV-45 refuses at the put door and nothing checked at the promote door (CIRISPersist#592 / AV-84) |
//!
//! Each invariant is stated as ONE sentence on purpose. A gate whose property
//! cannot be stated in one sentence is a gate nobody can review.

/// Shared, backend-agnostic exercise bodies for the bootstrap-admission
/// matrix. Compiled under `test` and under the `test-anchor` feature so
/// downstream conformance runs can drive the same witnesses against their own
/// directory implementation (the CIRISConformance adoption path).
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod test_support {
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// Build a federation-tier `scores` row REALLY signed by `attester`'s
    /// deterministic hybrid key, carrying `dimension` in its envelope. This is
    /// the shape reputation actually travels in — `attestation_type = scores`
    /// with the family in `dimension` — which is precisely the shape the
    /// pre-#543 type-keyed capacity guard never saw.
    pub fn scores_row(id: &str, attester: &str, attested: &str, dimension: &str) -> Attestation {
        let envelope = serde_json::json!({
            "dimension": dimension,
            "score": 1.0,
            "confidence": 0.9,
        });
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(attester, &envelope);
        let now = chrono::Utc::now();
        let mut sealed_row_ = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
            weight: Some(1.0),
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::tier_ingest::test_support::seal_row_in_place(attester, &mut sealed_row_);
        crate::federation::tier_ingest::test_support::reseal(&mut sealed_row_);
        sealed_row_
    }

    /// **B1 — capacity self-attestation is refused on BOTH wire shapes.**
    ///
    /// CIRISPersist#543 finding 2: the CC 3.4.5 arm keys on the
    /// `attestation_type` namespace, but reputation rides
    /// `attestation_type = scores` + `dimension = capacity:*`. On that real
    /// shape the arm never fired, and the dimension-keyed guard written for it
    /// ([`crate::federation::admission::check_capacity_not_self_attested`],
    /// v4.4.0 / AV-62) had **zero callers** — so capacity self-inflation was
    /// open while the vendored manifest cited the guard as a live processor.
    ///
    /// Pins all three arms: the dimension shape is refused, the type shape is
    /// still refused (no regression), and a genuine THIRD-PARTY capacity score
    /// is still admitted (the gate denies self-emission, not the family).
    pub async fn exercise_capacity_self_emission_gate(dir: &dyn FederationDirectory, tag: &str) {
        let sybil = format!("{tag}-sybil");
        let scorer = format!("{tag}-scorer");
        for k in [&sybil, &scorer] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }

        // (a) THE HOLE: the real wire shape — scores + dimension=capacity:*,
        // attester == attested. Pre-#543 this was ADMITTED.
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: scores_row(
                    &uuid::Uuid::new_v4().to_string(),
                    &sybil,
                    &sybil,
                    "capacity:core_identity:v1",
                ),
            })
            .await
            .expect_err(
                "({tag}) B1: a self-attested capacity score on the REAL wire shape \
                 (scores + dimension=capacity:*) must be refused — this is the \
                 CIRISPersist#543 self-inflation hole",
            );
        assert!(
            format!("{err}").contains("capacity"),
            "({tag}) B1: refusal must name the capacity rule: {err}"
        );

        // (b) NO REGRESSION: a genuine third-party capacity score still admits.
        // The gate denies SELF-emission, not the family — an anti-Goodhart rule
        // that also blocked honest scoring would be a denial-of-service on the
        // reputation plane.
        //
        // v22.0.0 (CIRISConstitution#46) — this arm now needs the SUBJECT'S
        // CONSENT to be about self-emission at all. Consent-before-scoring
        // means an unconsented third-party score is refused by
        // [`crate::federation::admission::check_capacity_consent_admission`],
        // so without this grant the arm would pass for the wrong reason (a
        // green B1 that actually proves B5). The grant makes the ONE variable
        // under test attester-vs-attested, as it was.
        dir.put_attestation(SignedAttestation {
            attestation: consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &sybil,
                &scorer,
                &format!(
                    "{}:v1",
                    crate::federation::consent::consent_dimension::STATE_GRANTED_PREFIX
                ),
                &[crate::federation::admission::ANALYZE_CONSENT_SCOPE],
                chrono::Utc::now() - chrono::Duration::seconds(60),
            ),
        })
        .await
        .expect("({tag}) B1: the subject's analyze grant admits");

        dir.put_attestation(SignedAttestation {
            attestation: scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &scorer,
                &sybil,
                "capacity:core_identity:v1",
            ),
        })
        .await
        .expect("({tag}) B1: a THIRD-PARTY capacity score is still admitted");
    }

    /// Build a SUBJECT-authored `consent:state:{stance}` row naming `scopes`,
    /// pointed at `covers` — the reverse edge of a third-party claim.
    ///
    /// This is the consent representation the substrate ALREADY maintains (it
    /// is not a new shape invented for CC#46): `attesting_key_id` = the subject
    /// declaring the stance, `attested_key_id` = who/what the stance is about,
    /// envelope `dimension` = `consent:state:granted|revoked|expired:*`,
    /// envelope `scope` = the CC 3.3.1 grant kind(s). It is read back by
    /// [`crate::federation::FederationDirectory::resolve_scoped_consent`], the
    /// one canonical scoped fold (latest-wins by `asserted_at`, expiry-aware,
    /// grants must name their scope exactly, a scope-less non-grant is
    /// blanket).
    ///
    /// `asserted_at` is EXPLICIT because the fold is latest-wins on it, and it
    /// is stamped INTO the signed envelope as well as onto the row column —
    /// [`crate::federation::admission::check_instant_binding`]
    /// refuses the row if the two disagree (v31.0.0, CIRISPersist#598).
    /// Truncated to the substrate resolution so the fixture measures ordering
    /// rather than the precision difference between postgres `TIMESTAMPTZ` and
    /// `Utc::now()`.
    ///
    /// v31.0.0 — the note that used to live here ("a grant and a revoke
    /// minted at the same `Utc::now()` tie, and `max_by_key` on a tie is
    /// unspecified — the sequence must advance") DOCUMENTED the missing
    /// tie-break instead of fixing it. The fold now carries a deterministic
    /// restriction-wins tie-break ([`crate::federation::consent::fold_ordering_key`]),
    /// so a tie resolves to the restrictive stance on all three backends and
    /// the fixture no longer has to keep the sequence advancing to be
    /// meaningful.
    ///
    /// v36.0.0 (CIRISPersist#642) — delegates to
    /// [`consent_scope_row_superseding`] with no causal edge, which is the
    /// pre-#642 wire shape every existing caller means.
    pub fn consent_scope_row(
        id: &str,
        subject: &str,
        covers: &str,
        stance_dimension: &str,
        scopes: &[&str],
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        consent_scope_row_superseding(
            id,
            subject,
            covers,
            stance_dimension,
            scopes,
            asserted_at,
            None,
        )
    }

    /// v36.0.0 (CIRISPersist#642) — [`consent_scope_row`] plus **the causal
    /// edge**: `supersedes` names, through the consent plane's own
    /// [`consent_supersedes`](crate::federation::envelope::paths::CONSENT_SUPERSEDES)
    /// key, the prior consent statement this row supersedes. NOT the composer
    /// pointer — see that constant for why CC 4.5.1.1 made this a field split.
    ///
    /// `supersedes` takes any JSON value on purpose — the fail-closed arms of
    /// [`crate::federation::consent::causal_edge`] are about a pointer that is
    /// present and UNUSABLE (a number, `""`, a self-reference), and a fixture
    /// that can only express well-formed strings cannot drive them. `None`
    /// omits the member entirely.
    pub fn consent_scope_row_superseding(
        id: &str,
        subject: &str,
        covers: &str,
        stance_dimension: &str,
        scopes: &[&str],
        asserted_at: chrono::DateTime<chrono::Utc>,
        supersedes: Option<serde_json::Value>,
    ) -> Attestation {
        let asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(asserted_at);
        let mut envelope = serde_json::json!({
            "dimension": stance_dimension,
            "scope": scopes,
            crate::federation::envelope::paths::ASSERTED_AT: asserted_at.to_rfc3339(),
        });
        if let Some(target) = supersedes {
            envelope[crate::federation::envelope::paths::CONSENT_SUPERSEDES] = target;
        }
        let envelope = envelope;
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(subject, &envelope);
        let mut sealed_row_ = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: subject.to_owned(),
            attested_key_id: covers.to_owned(),
            attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: subject.to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject.to_owned()],
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::tier_ingest::test_support::seal_row_in_place(subject, &mut sealed_row_);
        crate::federation::tier_ingest::test_support::reseal(&mut sealed_row_);
        sealed_row_
    }

    /// v36.0.0 (CIRISPersist#642) — the subject's own `withdraws` against one
    /// of its consent statements, filed against the SAME target so it lands in
    /// the `list_attestations_for(covers)` slice the consent fold reads.
    ///
    /// Admitted under `withdraws` rule 1 (the target's own attester retracts
    /// it), which is what makes it reach
    /// [`crate::federation::precedence::retired_ids`] as an entitled
    /// retraction rather than being dropped by the #686 entitlement gate.
    pub fn consent_withdraws_row(
        id: &str,
        subject: &str,
        covers: &str,
        target_attestation_id: &str,
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(asserted_at);
        let envelope = serde_json::json!({
            crate::federation::envelope::paths::REFERENCES_ATTESTATION_ID: target_attestation_id,
            crate::federation::envelope::paths::WITHDRAWAL_REASON: "consent-plane retraction",
            crate::federation::envelope::paths::ASSERTED_AT: asserted_at.to_rfc3339(),
        });
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(subject, &envelope);
        let mut sealed_row_ = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: subject.to_owned(),
            attested_key_id: covers.to_owned(),
            attestation_type: crate::federation::types::attestation_type::WITHDRAWS.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: subject.to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject.to_owned()],
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::tier_ingest::test_support::seal_row_in_place(subject, &mut sealed_row_);
        crate::federation::tier_ingest::test_support::reseal(&mut sealed_row_);
        sealed_row_
    }

    /// **B5 (CIRISConstitution#46) — consent BEFORE scoring, for `capacity:*`.**
    ///
    /// > A party MUST NOT emit a `capacity:*` score about a subject unless a
    /// > live `consent:scope:analyze` from that subject covers the attester.
    ///
    /// RC2's status quo is the opposite: CC 3.4.5's *entire* emitter rule for
    /// `capacity:*` is `attesting_key_id != attested_key_id`, so any registered
    /// key may score any third party (CC 3.3.7 states the position outright —
    /// "admission is by key registration; consent is the governance record").
    /// CC#46 inverts that default for the open-sender families, which is the
    /// contextual-integrity question in its purest form: *were you permitted to
    /// compute and publish this about me?*
    ///
    /// Pins the four arms that make it a rule rather than a happy path:
    /// (a) no consent edge ⇒ REFUSED; (b) a live `analyze` grant from S
    /// covering P ⇒ admitted; (c) S revokes ⇒ refused again (consent is
    /// revocable — that is the page's whole point); (d) a NON-capacity
    /// `scores` row is untouched (the gate is one family, not a lockdown).
    pub async fn exercise_capacity_consent_gate(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::consent::consent_dimension;

        // Invocation-unique ids — see the B6 note: static ids are not
        // re-runnable against the shared postgres database.
        let run = uuid::Uuid::new_v4().simple().to_string();
        let attester = format!("{tag}-attester-{run}"); // P — the scorer
        let subject = format!("{tag}-subject-{run}"); // S — the scored
        for k in [&attester, &subject] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }
        const DIM: &str = "capacity:core_identity:v1";
        let capacity = || scores_row(&uuid::Uuid::new_v4().to_string(), &attester, &subject, DIM);
        let t0 = chrono::Utc::now() - chrono::Duration::seconds(120);

        // (a) NO CONSENT — P scores S with nothing from S authorizing it.
        // Under RC2 this is ADMITTED; under CC#46 it is the whole point.
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: capacity(),
            })
            .await
            .expect_err(
                "({tag}) B5/CC#46: a capacity:* score about S from P must be REFUSED with \
                 no live consent:scope:analyze from S covering P",
            );
        let msg = format!("{err}");
        assert!(
            msg.contains("consent") && msg.contains(DIM),
            "({tag}) B5: the refusal must name the consent rule AND the dimension: {msg}"
        );
        // The KIND is pinned here, in the SHARED body, not per-backend: it is
        // what `substrate_machine::assert_parity` hard-asserts across backends,
        // so a backend that refuses correctly but reports a different kind is
        // still a divergence — and it would surface as a differential failure
        // far from this gate. Asserting it once, in the body all three arms
        // drive, is the cheap place to catch it.
        //
        // v25.1.0 (CIRISPersist#569) — the kind CHANGED, deliberately: this
        // refusal was a bare `federation_invalid_argument`, indistinguishable
        // on the wire from every other argument complaint, so a consumer could
        // only recognize it by matching message text. It is now its own typed
        // refusal carrying WHICH rule fired and against WHICH dimension.
        assert_eq!(
            err.kind(),
            "federation_consent_gate_refused",
            "({tag}) B5: every backend refuses at the SAME error kind: {err:?}"
        );
        assert!(
            matches!(&err, crate::federation::Error::ConsentGateRefused(r)
                if r.family == crate::federation::ConsentGatedFamily::Capacity
                    && r.dimension == DIM),
            "({tag}) B5: and the refusal names the CAPACITY rule and its dimension: {err:?}"
        );

        // (b) THE GRANT — S authorizes P to analyze. `analyze` is CC 3.3.1's
        // canonical kind for "derive features / scores / classifications".
        dir.put_attestation(SignedAttestation {
            attestation: consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
                &[crate::federation::admission::ANALYZE_CONSENT_SCOPE],
                t0,
            ),
        })
        .await
        .expect("({tag}) B5: a subject's own analyze grant is admissible");

        dir.put_attestation(SignedAttestation {
            attestation: capacity(),
        })
        .await
        .expect("({tag}) B5: with a live analyze grant covering P, the score admits");

        // (c) THE REVOCATION — consent is revocable, and revoking it closes the
        // gate again. Strictly LATER than the grant: the fold is latest-wins on
        // `asserted_at`, so a tie would make this arm decide nothing.
        dir.put_attestation(SignedAttestation {
            attestation: consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &format!("{}:v1", consent_dimension::STATE_REVOKED_PREFIX),
                &[crate::federation::admission::ANALYZE_CONSENT_SCOPE],
                t0 + chrono::Duration::seconds(60),
            ),
        })
        .await
        .expect("({tag}) B5: a subject's own revocation is admissible");

        let err = dir
            .put_attestation(SignedAttestation {
                attestation: capacity(),
            })
            .await
            .expect_err("({tag}) B5: once S revokes, P's capacity scores are refused again");
        assert!(
            format!("{err}").contains("consent"),
            "({tag}) B5: the post-revocation refusal names the consent rule: {err}"
        );

        // (d) SCOPED TO ONE FAMILY — a non-capacity `scores` row about the same
        // subject, from the same attester, with consent now revoked, is
        // untouched. CC#46 is a rule about `capacity:*`, and a gate that took
        // the whole `scores` plane down with it would be an outage.
        dir.put_attestation(SignedAttestation {
            attestation: scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &attester,
                &subject,
                "trust:demo:v1",
            ),
        })
        .await
        .expect("({tag}) B5: a non-capacity scores row is not consent-gated");
    }

    /// Build a federation-tier row on the TYPE-keyed wire shape: the family
    /// travels in `attestation_type`, not in an envelope `dimension`.
    ///
    /// Both shapes exist on the wire and #543 finding 2 was exactly a gate
    /// that saw one of them, so a consent-gate witness that only drives
    /// `scores` + `dimension` would repeat the AV-74 mistake at a new address.
    pub fn typed_family_row(
        id: &str,
        attester: &str,
        attested: &str,
        attestation_type: &str,
    ) -> Attestation {
        let envelope = serde_json::json!({ "note": "type-keyed wire shape" });
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(attester, &envelope);
        let now = chrono::Utc::now();
        let mut sealed_row_ = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: attestation_type.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::tier_ingest::test_support::seal_row_in_place(attester, &mut sealed_row_);
        crate::federation::tier_ingest::test_support::reseal(&mut sealed_row_);
        sealed_row_
    }

    /// The families CC 3.4.5 dispositioned OUTSIDE the consent gate by name,
    /// as concrete admissible `scores` dimensions.
    ///
    /// Written out rather than filtered out of verify's registry **on
    /// purpose**, and it is the one place in this crate where that is the right
    /// call. These four are the adjudicated cases — a reader of this witness
    /// has to see which families the Constitution ruled on — and pinning them
    /// here keeps every classification-shaped read of
    /// `ciris_verify_core::federation_provenance::dim` inside the single
    /// adjudication test
    /// (`crate::federation::admission::tests::verify_dimension_registry_is_the_only_enumeration`),
    /// which is what a consumer of an upstream registry owes the person who
    /// has to re-pin it.
    ///
    /// The list cannot go stale silently in either direction: the adjudication
    /// test asserts persist gates NOTHING in `dim::ALL` (so a family this list
    /// omits is still covered), and [`exercise_verify_families_are_not_consent_gated`]
    /// re-resolves each name in verify's registry (so a rename lands as a red
    /// test here, not as a probe that quietly stopped probing).
    pub const CC_345_UNGATED_PROBES: &[&str] = &[
        // Adversarial detector, −1-only polarity — abuse-response side.
        "rollback_detected:agent_version:v1",
        // Artifact-integrity verification — a forger never consents.
        "attestation:license_validity",
        "attestation:registry_consensus",
        "cert_validity:probe:v1",
    ];

    /// **B7 (CIRISPersist#569, adjudicated by CC 3.4.5) — the verify-owned
    /// verification families are ADMITTED with NO consent from the subject.
    /// The consent gate is `capacity:*` and nothing else.**
    ///
    /// # The hundred minutes this witness records
    ///
    /// CIRISPersist#569 widened the CC#46 gate from `capacity:*` to every
    /// family CIRISVerify's registry then classified `ConsensualReputation`,
    /// which in practice gated four more families:
    /// `attestation:registry_consensus`, `attestation:license_validity`,
    /// `cert_validity:{authority}` and `rollback_detected:{revision_field}`.
    /// **CC 3.4.5 disposed of all four the other way** — ratified 100 minutes
    /// after that commit was authored, and disposing of each family
    /// individually rather than by category:
    ///
    /// > *Artifact-integrity verification … scores builds, manifests, licenses
    /// > and certificates — not a subject's conduct or capacity; integrity
    /// > checking is the trust precondition, and **a forger never consents to
    /// > verification**.*
    /// >
    /// > **`rollback_detected:{revision_field}`** *is an adversarial detector
    /// > (−1-only polarity), **on the abuse-response side of the line by
    /// > construction**.*
    /// >
    /// > *Consent-before-scoring binds the family that judges **agents** —
    /// > `capacity:*` — never the families that verify **artifacts**.*
    ///
    /// Arm (a) is why this is a witness and not a comment. Gating
    /// `rollback_detected:*` behind the subject's own `analyze` consent lets
    /// **an adversary opt out of rollback detection by declining to be
    /// analyzed** — the detector that fires when a party ships a *backwards*
    /// revision is exactly the signal that party wants suppressed. That
    /// contradicts #569's own stated principle, *never gate abuse-response*,
    /// which #569 applied correctly to `detection:*` / `moderation:*` /
    /// `slashing:*` and then missed on the one adversarial family living
    /// inside verify's namespace.
    ///
    /// # Why the narrowing is not a weakening
    ///
    /// CC 3.4.5's reciprocity clause: *"A subject that declines analysis
    /// cannot be scored; its `capacity:composite` is undefined and MUST NOT be
    /// emitted; and every gate that requires a capacity verdict therefore
    /// **fails closed** for that subject."* A declining subject is not scored
    /// **at all** — a stronger outcome than being scored without consent —
    /// while the artifact-integrity and abuse-response planes, which never
    /// judged that subject's conduct, keep working.
    ///
    /// # What it pins, on every backend
    ///
    /// (a) an unconsented `rollback_detected:*` claim ADMITS; (b) an
    /// unconsented `attestation:license_validity` claim ADMITS; (c) so does
    /// every other family in [`CC_345_UNGATED_PROBES`], each re-resolved in
    /// verify's registry so a rename cannot leave a probe silently probing
    /// nothing; (d) the TYPE-keyed wire shape is ungated too (a one-shape
    /// answer is the AV-74 mistake at a new address); (e) CONTRAST —
    /// `capacity:*` from the same P about the same S is still REFUSED, with
    /// the typed refusal naming the `Capacity` rule, so the gate NARROWED
    /// rather than evaporated; (f) and the subject's own `analyze` grant
    /// re-opens it.
    pub async fn exercise_verify_families_are_not_consent_gated(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::consent::consent_dimension;

        // Invocation-unique ids — the postgres arm shares a long-lived DB.
        let run = uuid::Uuid::new_v4().simple().to_string();
        let attester = format!("{tag}-vp-{run}"); // P — the verifier / detector
        let subject = format!("{tag}-vs-{run}"); // S — the party named
        for k in [&attester, &subject] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }
        let t0 = chrono::Utc::now() - chrono::Duration::seconds(120);

        let signal = |dimension: &str| {
            scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &attester,
                &subject,
                dimension,
            )
        };
        // No consent edge exists anywhere in this run until arm (f). Every put
        // below arm (e) therefore faces the gate with the subject silent.

        // (a) THE ADVERSARIAL DETECTOR — first, and by name, because it is the
        // sharpest case. `rollback_detected:*` is −1-only polarity: it never
        // praises, it only reports that a party shipped a revision that went
        // backwards. CC 3.4.5 puts it "on the abuse-response side of the line
        // by construction" — a gate here hands the adversary the off switch
        // for its own detector.
        //
        // (b) ARTIFACT-INTEGRITY VERIFICATION — `attestation:license_validity`
        // and its siblings score a LICENSE, a MANIFEST, a CERTIFICATE, not the
        // subject's conduct. "Integrity checking is the trust precondition,
        // and a forger never consents to verification."
        //
        // (c) the rest of the adjudicated set, same rule, same silence.
        for dimension in CC_345_UNGATED_PROBES {
            // Re-resolve in verify's registry FIRST: a probe naming a family
            // that no longer exists upstream would "pass" while testing
            // nothing.
            assert!(
                ciris_verify_core::federation_provenance::dim::lookup(dimension).is_some(),
                "({tag}) B7: {dimension} no longer resolves in verify's registry — this probe \
                 names a family that has moved, so it is testing nothing. Re-read CC 3.4.5's \
                 per-family disposition before re-pointing it."
            );
            dir.put_attestation(SignedAttestation {
                attestation: signal(dimension),
            })
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({tag}) B7/CC 3.4.5: an unconsented {dimension} claim about S must ADMIT — \
                     it verifies an artifact or reports abuse; it does not judge the subject. \
                     Gating the adversarial detector in particular would let an adversary opt \
                     out of its own rollback detection: {e:?}"
                )
            });
        }

        // (d) BOTH WIRE SHAPES. The same claim carried in `attestation_type`
        // instead of an envelope `dimension`. Stated precisely rather than as
        // "admits": other gates may legitimately refuse a type-keyed probe
        // (T3 version-pinning), and the claim under test is narrower — that
        // the CONSENT gate is not the thing refusing it.
        if let Err(e) = dir
            .put_attestation(SignedAttestation {
                attestation: typed_family_row(
                    &uuid::Uuid::new_v4().to_string(),
                    &attester,
                    &subject,
                    "cert_validity:probe",
                ),
            })
            .await
        {
            assert!(
                !matches!(e, crate::federation::Error::ConsentGateRefused(_)),
                "({tag}) B7: the TYPE-keyed wire shape must be ungated identically — a gate that \
                 sees one shape and not the other is the AV-74 mistake at a new address: {e:?}"
            );
        }

        // (e) THE CONTRAST — the gate narrowed, it did not evaporate. Same P,
        // same silent S, the family that judges the AGENT. CC 3.4.5:
        // "Consent-before-scoring binds the family that judges *agents* —
        // `capacity:*` — never the families that verify *artifacts*."
        const CAPACITY: &str = "capacity:core_identity:v1";
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: signal(CAPACITY),
            })
            .await
            .expect_err(
                "({tag}) B7: narrowing the gate must not open capacity:* — an unconsented \
                 capacity score is still refused",
            );
        assert!(
            matches!(&err, crate::federation::Error::ConsentGateRefused(r)
                if r.family == crate::federation::ConsentGatedFamily::Capacity
                    && r.dimension == CAPACITY),
            "({tag}) B7: and the refusal still names the CAPACITY rule and its dimension: {err:?}"
        );

        // (f) AND IT RE-OPENS. The subject grants `analyze`; the same capacity
        // claim admits. CC 3.4.5's reciprocity clause is a real choice in both
        // directions, so the gate must be a door and not a wall.
        dir.put_attestation(SignedAttestation {
            attestation: consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
                &[crate::federation::admission::ANALYZE_CONSENT_SCOPE],
                t0,
            ),
        })
        .await
        .expect("({tag}) B7: a subject's own analyze grant is admissible");

        dir.put_attestation(SignedAttestation {
            attestation: signal(CAPACITY),
        })
        .await
        .expect("({tag}) B7: with the subject's live analyze grant, the capacity score admits");
    }

    /// **B6 (CIRISEdge#428) — the `delivery_mode` vocabulary is CLOSED at the
    /// wire.** Edge's processor recognizes exactly `"mandatory"` and demotes
    /// every other value to may-drop BestEffort — so before this gate, a TYPO
    /// in `delivery_mode` was admitted faithfully and silently stopped meaning
    /// "must deliver". Pins: a typo is refused with the field and vocabulary
    /// named; the two legal states (absent, `"mandatory"`) still admit; a
    /// non-string junk shape is refused (edge's typed reader resolves it to
    /// `None` ⇒ the same silent demotion wearing a type error).
    pub async fn exercise_delivery_mode_vocabulary_gate(dir: &dyn FederationDirectory, tag: &str) {
        // Unique per INVOCATION, not per arm: the postgres arm runs against a
        // SHARED long-lived database, and `register_hybrid_key` stamps
        // `valid_from: Utc::now()` into hash-covered content — so a static id
        // re-registered by a later run (or by the pre-push hook's pg sweep
        // sharing the same DSN) is "same key, different content" and refuses.
        // Same doctrine as `substrate_machine::fresh_tag`.
        let writer = format!("{tag}-dmv-{}", uuid::Uuid::new_v4().simple());
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &writer).await;

        let with_mode = |mode: serde_json::Value| {
            let mut envelope = serde_json::json!({
                "dimension": "trust:demo:v1",
                "score": 1.0,
                "confidence": 0.9,
            });
            if !mode.is_null() {
                envelope["delivery_mode"] = mode;
            }
            let (och, sc, sp) =
                crate::federation::tier_ingest::test_support::sign_envelope(&writer, &envelope);
            let now = chrono::Utc::now();
            let mut sealed_row_ = Attestation {
                attestation_id: uuid::Uuid::new_v4().to_string(),
                attesting_key_id: writer.clone(),
                attested_key_id: writer.clone(),
                attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
                weight: Some(1.0),
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: sc,
                scrub_signature_pqc: sp,
                scrub_key_id: writer.clone(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            };
            crate::federation::tier_ingest::test_support::seal_row_in_place(
                &writer,
                &mut sealed_row_,
            );
            crate::federation::tier_ingest::test_support::reseal(&mut sealed_row_);
            sealed_row_
        };

        // (a) THE HAZARD: a typo'd mode must be refused, loudly, at the wire.
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: with_mode(serde_json::json!("manditory")),
            })
            .await
            .expect_err("({tag}) B6: a typo'd delivery_mode must be REFUSED, not silently demoted");
        let msg = format!("{err}");
        assert!(
            msg.contains("delivery_mode") && msg.contains("manditory"),
            "({tag}) B6: the refusal names the field and the offending value: {msg}"
        );
        assert_eq!(
            err.kind(),
            "federation_invalid_argument",
            "({tag}) B6: refusal kind is parity-asserted across backends"
        );

        // (b) junk shape (non-string) — same silent-demotion hazard, refused.
        dir.put_attestation(SignedAttestation {
            attestation: with_mode(serde_json::json!(7)),
        })
        .await
        .expect_err("({tag}) B6: a non-string delivery_mode is refused");

        // (c) the two LEGAL states still admit.
        dir.put_attestation(SignedAttestation {
            attestation: with_mode(serde_json::Value::Null), // absent
        })
        .await
        .expect("({tag}) B6: absent delivery_mode (BestEffort) admits");
        dir.put_attestation(SignedAttestation {
            attestation: with_mode(serde_json::json!("mandatory")),
        })
        .await
        .expect("({tag}) B6: delivery_mode=mandatory admits");
    }

    /// **AV-77 — de-admission actually stops an abuser, and is revocable.**
    ///
    /// CIRISPersist#543 finding 5: before v22.0.0 there was NO CEG-encoded way
    /// to stop a bootstrap abuser — "nothing between 'ignore it' and 'halt the
    /// node'." `moderation:*` records an event, not a sanction; `slashing:*`
    /// has a verdict shape with no emit and no act; `consent:*` withdrawal is
    /// SEND-side and cannot stop inbound injection.
    ///
    /// Pins the full lifecycle: an abuser's writes are admitted before, refused
    /// after the node de-admits it, and admitted AGAIN once the node withdraws
    /// its own de-admission — so the sanction is a first-class revocable act,
    /// not a one-way door. Also pins that de-admission is scoped: an innocent
    /// third party is unaffected.
    pub async fn exercise_peer_deadmission(
        dir: &dyn FederationDirectory,
        self_key_id: &str,
        tag: &str,
    ) {
        use crate::federation::admission::PEER_DEADMISSION_DIMENSION;

        let abuser = format!("{tag}-abuser");
        let innocent = format!("{tag}-innocent");
        for k in [self_key_id, &abuser, &innocent] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }
        let write =
            |who: &str| scores_row(&uuid::Uuid::new_v4().to_string(), who, who, "trust:demo:v1");

        // (a) BEFORE — the abuser's writes are admitted like anyone's.
        dir.put_attestation(SignedAttestation {
            attestation: write(&abuser),
        })
        .await
        .expect("({tag}) AV-77: pre-de-admission writes are admitted");

        // (b) THE ACT — this node de-admits the abuser from its OWN corpus.
        dir.put_attestation(SignedAttestation {
            attestation: scores_row(
                &uuid::Uuid::new_v4().to_string(),
                self_key_id,
                &abuser,
                PEER_DEADMISSION_DIMENSION,
            ),
        })
        .await
        .expect("({tag}) AV-77: a node may always author its own de-admission");

        // (c) AFTER — the abuser's writes are refused. THIS is the act that was
        // missing: an in-band, signed, replicable response that actually stops
        // injection.
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: write(&abuser),
            })
            .await
            .expect_err("({tag}) AV-77: a de-admitted peer's writes must be REFUSED");
        assert!(
            format!("{err}").contains("de-admitted"),
            "({tag}) AV-77: the refusal names the de-admission: {err}"
        );

        // (d) SCOPED — an innocent third party is untouched. De-admission is a
        // judgement about ONE peer, not a general lockdown.
        dir.put_attestation(SignedAttestation {
            attestation: write(&innocent),
        })
        .await
        .expect("({tag}) AV-77: de-admitting one peer must not affect another");

        // (e) v31.0.0 (CIRISPersist#608) — **THE SANCTION COVERS THE
        // SANCTIONING DIMENSION.**
        //
        // The gate used to exempt any row carrying `PEER_DEADMISSION_DIMENSION`
        // regardless of author, so the de-admitted abuser could keep writing
        // de-admission rows ABOUT THIRD PARTIES — the one dimension a sanctioned
        // peer most wants, since it is how this node decides who else to refuse.
        // Legs (a)-(d) all passed over that hole for eight majors: (c) refuses
        // the abuser on `trust:demo:v1`, and nothing asked what happened on the
        // sanction dimension itself.
        let smuggled = scores_row(
            &uuid::Uuid::new_v4().to_string(),
            &abuser,   // ATTESTER — already de-admitted at (b)
            &innocent, // about a THIRD PARTY, not itself
            PEER_DEADMISSION_DIMENSION,
        );
        let smuggled_id = smuggled.attestation_id.clone();
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: smuggled,
            })
            .await
            .expect_err(
                "({tag}) #608: a de-admitted peer must not author the de-admission dimension",
            );
        assert!(
            format!("{err}").contains("de-admitted"),
            "({tag}) #608: the refusal names the de-admission: {err}"
        );

        // REFUSED, not refused-after-storing. AV-9 wants the former, and the two
        // are indistinguishable from the error alone.
        let by_abuser = dir
            .list_attestations_by(&abuser)
            .await
            .expect("({tag}) #608: list_attestations_by");
        assert!(
            !by_abuser.iter().any(|a| a.attestation_id == smuggled_id),
            "({tag}) #608: the refused row was STORED anyway — refusal must leave no trace"
        );
    }

    /// **B8 — the promotion admission stack, at the crossing** (CIRISPersist#589
    /// / AV-83; re-cut in v39.0.0 over `enter_mesh`).
    ///
    /// (a) a `tier = local` `capacity:*` row is refused at `put_attestation`
    /// (the #589 open door) by the LOCAL-TIER rule, not by "no consent";
    /// (b) the TYPE-keyed capacity shape is refused too (AV-74 at a new
    /// address); (c) an ordinary local row admits and CROSSES — over the same
    /// bytes, at its own scope; (d) a de-admitted author's row is refused at
    /// the crossing (AV-77 reaching this door) and left BYTE-IDENTICAL (AV-9,
    /// the substrate state machine's I2a at unit scale); (e) `(federation,
    /// self)` is the crossing's OWN shape — it was #315's "dead plane" only
    /// while nothing consumed it, and a widening that is not strictly wider is
    /// refused at the widening door instead; (f) a pre-v26.0.0 local capacity
    /// row's crossing is refused by the CAPACITY consent rule (CC 3.4.5) and
    /// admitted once the subject's own `analyze` grant is live.
    pub async fn exercise_promotion_admission_gate(
        dir: &dyn FederationDirectory,
        self_key_id: &str,
        tag: &str,
    ) {
        use crate::federation::admission::PEER_DEADMISSION_DIMENSION;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_tier, cohort_scope};
        use crate::federation::{CrossingBasis, Error, MeshCrossingOutcome};

        let run = uuid::Uuid::new_v4().simple().to_string();
        let attester = format!("{tag}-p589-{run}"); // P — the scorer
        let subject = format!("{tag}-s589-{run}"); // S — the scored, and silent
        for k in [self_key_id, &attester, &subject] {
            ts::register_hybrid_key(dir, k).await;
        }
        const DIM: &str = "capacity:composite:v1";
        let local_row = |id: &str, dimension: &str, att_type: Option<&str>| {
            let mut row = scores_row(id, &attester, &subject, dimension);
            if let Some(t) = att_type {
                row.attestation_type = t.to_owned();
            }
            row.tier = attestation_tier::LOCAL.to_owned();
            row.cohort_scope = cohort_scope::SELF.to_owned();
            ts::reseal(&mut row);
            row
        };
        let cross = |id: String| async move {
            let row = dir.get_attestation(&id).await.expect("read").expect("row");
            let ci = ts::describe_own(&row, CrossingBasis::ProducerAuthority);
            dir.enter_mesh(&id, &ci, &ts::actor_reseal(&row)).await
        };

        // (a)
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: local_row(&uuid::Uuid::new_v4().to_string(), DIM, None),
            })
            .await
            .expect_err(
                "({tag}) B8: a tier='local' capacity:* row must be REFUSED by put_attestation \
                 — this is the #589 open door",
            );
        let msg = format!("{err}");
        assert!(
            msg.contains("local tier") && msg.contains(DIM),
            "({tag}) B8: the refusal must name the LOCAL-TIER rule and the dimension \
             (not 'no consent' — the row is inadmissible even WITH a grant): {msg}"
        );
        assert_eq!(
            err.kind(),
            "federation_invalid_argument",
            "({tag}) B8: every backend refuses at the SAME error kind: {err:?}"
        );
        // (b)
        dir.put_attestation(SignedAttestation {
            attestation: local_row(
                &uuid::Uuid::new_v4().to_string(),
                "trust:demo:v1",
                Some("capacity:composite"),
            ),
        })
        .await
        .expect_err(
            "({tag}) B8: the TYPE-keyed capacity shape is refused at the local tier too \
             — answering one shape is the AV-74 mistake at a new address",
        );
        // (c)
        let ok_id = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: local_row(&ok_id, "trust:demo:v1", None),
        })
        .await
        .expect("({tag}) B8: an ordinary local row still admits");
        let crossed = cross(ok_id.clone())
            .await
            .expect("({tag}) B8: an ordinary crossing still succeeds");
        assert!(
            matches!(crossed, MeshCrossingOutcome::Crossed(_)),
            "({tag}) B8: and it flips the tier: {crossed:?}"
        );
        let after = dir
            .get_attestation(&ok_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(after.tier, attestation_tier::FEDERATION);
        assert_eq!(
            after.cohort_scope,
            cohort_scope::SELF,
            "({tag}) B8 (c): the crossing never changes the scope — it is one of the bytes"
        );
        // (d)
        let doomed_id = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: local_row(&doomed_id, "trust:demo:v1", None),
        })
        .await
        .expect("({tag}) B8: the local write lands while the author is in good standing");
        let before = dir
            .get_attestation(&doomed_id)
            .await
            .expect("read")
            .expect("row");
        dir.put_attestation(SignedAttestation {
            attestation: scores_row(
                &uuid::Uuid::new_v4().to_string(),
                self_key_id,
                &attester,
                PEER_DEADMISSION_DIMENSION,
            ),
        })
        .await
        .expect("({tag}) B8: a node may always author its own de-admission");
        let err = cross(doomed_id.clone()).await.expect_err(
            "({tag}) B8: crossing a DE-ADMITTED author's row must be refused — AV-77 \
             reaching the crossing for the first time",
        );
        assert!(
            format!("{err}").contains("de-admitted"),
            "({tag}) B8: the refusal names the de-admission: {err}"
        );
        let after = dir
            .get_attestation(&doomed_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(
            after.tier,
            attestation_tier::LOCAL,
            "({tag}) B8: a refused crossing leaves the tier"
        );
        assert_eq!(after.cohort_scope, before.cohort_scope);
        assert_eq!(
            after.persist_row_hash, before.persist_row_hash,
            "({tag}) B8: byte-identical — the substrate state machine's I2a, at unit scale"
        );
        // (e)
        let bystander = format!("{tag}-b589-{run}");
        ts::register_hybrid_key(dir, &bystander).await;
        let self_id = uuid::Uuid::new_v4().to_string();
        let mut self_row = scores_row(&self_id, &bystander, &subject, "trust:demo:v1");
        self_row.tier = attestation_tier::LOCAL.to_owned();
        self_row.cohort_scope = cohort_scope::SELF.to_owned();
        ts::reseal(&mut self_row);
        dir.put_attestation(SignedAttestation {
            attestation: self_row,
        })
        .await
        .expect("({tag}) B8: arm (e)'s local row admits");
        let crossed = cross(self_id.clone()).await.expect(
            "({tag}) B8 (e): `(federation, self)` IS the crossing's shape (CC 5.2 / 5.3.2.4.2) — \
             it was refused as #315's dead plane only while nothing consumed it",
        );
        let MeshCrossingOutcome::Crossed(report) = crossed else {
            panic!("({tag}) B8 (e): expected Crossed, got {crossed:?}");
        };
        assert!(
            !report.replicates.discoverable,
            "({tag}) B8 (e): replicated by consent fan-out, never advertised"
        );
        let self_after = dir
            .get_attestation(&self_id)
            .await
            .expect("read")
            .expect("row");
        let err = ts::widen(dir, &self_after, crate::federation::Audience::SelfOnly, &[])
            .await
            .expect_err("({tag}) B8 (e): a widening that is not strictly wider is refused");
        assert!(
            matches!(err, Error::AudienceNotWider { .. }),
            "({tag}) B8 (e): the refusal is the WIDENING door's, by kind: {err}"
        );
        // (f)
        let mut legacy = scores_row(&uuid::Uuid::new_v4().to_string(), &bystander, &subject, DIM);
        legacy.tier = attestation_tier::FEDERATION.to_owned();
        legacy.cohort_scope = cohort_scope::FEDERATION.to_owned();
        ts::reseal(&mut legacy);
        let err = crate::federation::admission::check_promotion_admission(dir, &legacy, None)
            .await
            .expect_err(
                "({tag}) B8: crossing a pre-v26.0.0 local capacity row must be refused — \
                 CC 3.4.5: its capacity:composite MUST NOT be emitted",
            );
        assert!(
            matches!(&err, Error::ConsentGateRefused(r)
                if r.family == crate::federation::ConsentGatedFamily::Capacity
                    && r.dimension == DIM),
            "({tag}) B8: and the refusal names the CAPACITY consent rule: {err:?}"
        );
        dir.put_attestation(SignedAttestation {
            attestation: consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &bystander,
                &format!(
                    "{}:v1",
                    crate::federation::consent::consent_dimension::STATE_GRANTED_PREFIX
                ),
                &[crate::federation::admission::ANALYZE_CONSENT_SCOPE],
                chrono::Utc::now() - chrono::Duration::seconds(60),
            ),
        })
        .await
        .expect("({tag}) B8: the subject's own analyze grant admits");
        crate::federation::admission::check_promotion_admission(dir, &legacy, None)
            .await
            .expect("({tag}) B8: with a live analyze grant the same crossing is admitted");
    }

    /// **#649 / W6 — a crossed row is admissible at a PEER**, and so is its
    /// widening. This is the assertion whose absence hid #649: promotion
    /// returned `Ok` while every peer refused the result.
    ///
    /// (a) a locally-minted row already carries its signed mirror and instants
    /// (the put door is tier-blind); (a2)/(a3) `expires_at` is truncated to the
    /// signed resolution and a stale envelope expiry is cleared; (b) the
    /// crossing stores the bytes the actor signed — the mirror names the scope
    /// the row HAS; (c) the crossed row admits at a peer; (c2) so does the
    /// `supersedes` that widens it; (d) a row whose columns diverge from its
    /// signed mirror is refused by the peer, naming the column; (e) offering a
    /// RE-STAMPED envelope as the actor's custody is refused at the primitive
    /// as a moved preimage (W1 — the #649 class, by kind); (f) a refused
    /// crossing leaves the row byte-identical.
    pub async fn exercise_promoted_row_crosses_to_a_peer(
        origin: &dyn FederationDirectory,
        peer: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::render_signed_instant;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_tier, cohort_scope, LocalAttestationInput};
        use crate::federation::{CrossingBasis, Error, MeshCrossingOutcome, TierPromotionCustody};

        let run = uuid::Uuid::new_v4().simple().to_string();
        let producer = format!("{tag}-p649-{run}");
        ts::register_hybrid_key(origin, &producer).await;
        ts::register_hybrid_key(peer, &producer).await;

        let local_input = |dimension: &str| {
            let mut envelope = crate::federation::envelope::EnvelopeCore {
                dimension: Some(dimension.to_owned()),
                ..Default::default()
            };
            envelope
                .extra
                .insert("score".into(), serde_json::json!(1.0));
            envelope
                .extra
                .insert("confidence".into(), serde_json::json!(0.9));
            LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: producer.clone(),
                attested_key_id: None,
                attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
                weight: Some(1.0),
                expires_at: None,
                attestation_envelope: envelope,
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            }
        };

        // (a)
        let id = origin
            .attestation_insert_local(local_input("trust:demo:v1"))
            .await
            .expect("({tag}) #649: the local write admits");
        let local = origin
            .get_attestation(&id)
            .await
            .expect("read back")
            .expect("row");
        crate::federation::admission::check_row_column_binding(&local).unwrap_or_else(|e| {
            panic!(
                "({tag}) #649 (a): a locally-minted row must already carry its own signed \
                 typed-column mirror — `put_attestation`'s binding gate is TIER-BLIND: {e}"
            )
        });
        // (a2)
        let ns_expiry = crate::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now() + chrono::Duration::days(30),
        ) + chrono::Duration::nanoseconds(500);
        let expiring_id = {
            let mut input = local_input("trust:demo:v1");
            input.expires_at = Some(ns_expiry);
            origin
                .attestation_insert_local(input)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "({tag}) #598 (a2): a durable local write carrying a sub-resolution \
                     `expires_at` must be ADMITTED — the door TRUNCATES where it mints the \
                     signed twin: {e}"
                    )
                })
        };
        let expiring = origin
            .get_attestation(&expiring_id)
            .await
            .expect("read back")
            .expect("row");
        let want = crate::federation::admission::truncate_to_substrate_resolution(ns_expiry);
        assert_eq!(
            expiring.expires_at,
            Some(want),
            "({tag}) #598 (a2): the COLUMN is truncated"
        );
        assert_eq!(
            expiring
                .attestation_envelope
                .get(crate::federation::envelope::paths::EXPIRES_AT)
                .and_then(|v| v.as_str()),
            Some(render_signed_instant(want).as_str()),
            "({tag}) #598 (a2) / CC 2.6.2: the SIGNED envelope carries the same instant, \
             rendered `.sssZ`"
        );
        crate::federation::admission::check_instant_binding(
            &expiring,
            chrono::Utc::now(),
            crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
        )
        .unwrap_or_else(|e| panic!("({tag}) #598 (a2): the instant binding holds: {e}"));
        // (a3)
        let cleared_id =
            {
                let mut input = local_input("trust:demo:v1");
                input.attestation_envelope.expires_at =
                    Some("2031-01-01T00:00:00.000000+00:00".to_owned());
                input.expires_at = None;
                origin.attestation_insert_local(input).await.unwrap_or_else(|e| {
                panic!("({tag}) #598 (a3): a stale envelope expiry with a None column admits: {e}")
            })
            };
        let cleared = origin
            .get_attestation(&cleared_id)
            .await
            .expect("read back")
            .expect("row");
        assert_eq!(cleared.expires_at, None);
        assert!(
            cleared
                .attestation_envelope
                .get(crate::federation::envelope::paths::EXPIRES_AT)
                .is_none(),
            "({tag}) #598 (a3): the signed envelope must not keep an expiry the column does not have"
        );

        // (b)
        let ci = ts::describe_own(&local, CrossingBasis::ProducerAuthority);
        let crossed = origin
            .enter_mesh(&id, &ci, &ts::actor_reseal(&local))
            .await
            .expect("({tag}) #649: the crossing succeeds");
        assert!(
            matches!(crossed, MeshCrossingOutcome::Crossed(_)),
            "{crossed:?}"
        );
        let promoted = origin
            .get_attestation(&id)
            .await
            .expect("read back")
            .expect("row");
        assert_eq!(promoted.tier, attestation_tier::FEDERATION);
        assert_eq!(promoted.cohort_scope, cohort_scope::SELF);
        assert_eq!(
            promoted
                .attestation_envelope
                .get(crate::federation::envelope::paths::ROW)
                .and_then(|r| r.get(crate::federation::envelope::row_paths::COHORT_SCOPE))
                .and_then(|v| v.as_str()),
            Some(cohort_scope::SELF),
            "({tag}) #649 (b): the STORED signed envelope is the bytes the actor signed — the \
             mirror names the scope the row HAS"
        );
        // (c)
        peer.put_attestation(SignedAttestation {
            attestation: promoted.clone(),
        })
        .await
        .unwrap_or_else(|e| {
            panic!(
                "({tag}) #649 (c) / W6: a CROSSED row must be admissible at a PEER — a crossing \
                 every peer refuses is a crossing that did nothing. Refusal: {e}"
            )
        });
        let at_peer = peer
            .get_attestation(&id)
            .await
            .expect("read at peer")
            .expect("stored");
        assert_eq!(at_peer.tier, attestation_tier::FEDERATION);
        assert_eq!(at_peer.cohort_scope, cohort_scope::SELF);
        // (c2)
        let widened = ts::widen(
            origin,
            &promoted,
            crate::federation::Audience::Federation,
            &[],
        )
        .await
        .expect("({tag}) W6: the widening is written");
        let MeshCrossingOutcome::Crossed(report) = widened else {
            panic!("({tag}) W6: expected Crossed, got {widened:?}");
        };
        let sup = origin
            .get_attestation(&report.attestation_id)
            .await
            .expect("read back")
            .expect("the supersedes row");
        peer.put_attestation(SignedAttestation { attestation: sup })
            .await
            .unwrap_or_else(|e| panic!("({tag}) W6: the widening admits at the peer: {e}"));
        assert!(
            peer.get_attestation(&report.attestation_id)
                .await
                .expect("read at peer")
                .is_some(),
            "({tag}) W6: the peer stored the widening"
        );

        // (d)
        let stale_id = origin
            .attestation_insert_local(local_input("trust:demo:v1"))
            .await
            .expect("({tag}) #649: the second local write admits");
        let stale_local = origin
            .get_attestation(&stale_id)
            .await
            .expect("read back")
            .expect("row");
        let mut diverging = stale_local.clone();
        diverging.tier = attestation_tier::FEDERATION.to_owned();
        diverging.cohort_scope = cohort_scope::FEDERATION.to_owned(); // column says one thing…
        diverging.promoted_at = Some(chrono::Utc::now()); // …the signed mirror still says `self`
        let err = peer
            .put_attestation(SignedAttestation {
                attestation: diverging,
            })
            .await
            .expect_err("({tag}) #649 (d): a column diverging from its signed mirror is REFUSED");
        assert!(
            format!("{err}").contains(crate::federation::envelope::row_paths::COHORT_SCOPE),
            "({tag}) #649 (d): the refusal names the column that diverged: {err}"
        );
        // (e) — W1
        let before = origin
            .get_attestation(&stale_id)
            .await
            .expect("read back")
            .expect("row");
        let restamped = ts::reseal_for_scope(&producer, &stale_local, cohort_scope::FEDERATION);
        let ci = ts::describe_own(&stale_local, CrossingBasis::ProducerAuthority);
        let err = origin
            .enter_mesh(
                &stale_id,
                &ci,
                &TierPromotionCustody::ActorSigned(restamped),
            )
            .await
            .expect_err(
                "({tag}) W1: custody over RE-STAMPED bytes is refused at the primitive — a tier \
                 crossing is byte-identical (CC 5.3.2.4.2)",
            );
        assert!(
            matches!(err, Error::PromotionMovedThePreimage { .. }),
            "({tag}) W1: refused BY KIND, not by a neighbouring gate: {err}"
        );
        // (f)
        let after = origin
            .get_attestation(&stale_id)
            .await
            .expect("read back")
            .expect("row");
        assert_eq!(
            after.tier,
            attestation_tier::LOCAL,
            "({tag}) #649 (f): tier untouched"
        );
        assert_eq!(
            after.persist_row_hash, before.persist_row_hash,
            "({tag}) #649 (f): byte-identical"
        );
    }

    /// **B9 — cohort standing at the WIDENING door** (CIRISPersist#592 / AV-84;
    /// re-cut in v39.0.0). A crossing never places a row at `family` /
    /// `community` — the placement is the row's own — so the targeted-cohort
    /// self-declaration rule now bites where a row is WIDENED into a cohort
    /// plane: the `supersedes` goes through the put door, which asks it.
    ///
    /// A row naming a THIRD PARTY: crosses (self), is refused a widening into
    /// `community` / `family` (`federation_cohort_standing_refused`, naming the
    /// placement and the party), leaves the prior byte-identical, and still
    /// widens to a broad tier. A producer's OWN row widens to `community`. The
    /// same verdict at the same kind for a row born federation-tier.
    pub async fn exercise_promotion_cohort_standing_gate(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_tier, cohort_scope, identity_type};
        use crate::federation::{CrossingBasis, MeshCrossingOutcome};

        let run = uuid::Uuid::new_v4().simple().to_string();
        let producer = format!("{tag}-p592-{run}"); // P — the row's author
        let stranger = format!("{tag}-s592-{run}"); // S — the party P names
        let comm = format!("{tag}-c592-{run}"); // a community P belongs to
        let fam = format!("{tag}-f592-{run}"); // a family P belongs to
                                               // P is a human (USER): the community door binds agent/node members to a
                                               // steward and this fixture is about STANDING, not stewardship.
        ts::register_hybrid_key_as(dir, &producer, &producer, identity_type::USER).await;
        for k in [&stranger, &comm, &fam] {
            ts::register_hybrid_key(dir, k).await;
        }
        // P is a MEMBER of both cohorts: a cohort placement is a membership
        // claim the put door proves first (AV-45); with membership proven, what
        // is left to refuse is STANDING — the party the row names.
        let now = chrono::Utc::now();
        dir.put_community(ts::sign_community(
            &producer,
            crate::federation::types::Community {
                community_key_id: comm.clone(),
                community_name: format!("{tag}-community-{run}"),
                members: vec![crate::federation::types::CommunityMember {
                    key_id: producer.clone(),
                    joined_at: now,
                    role: Some("founder".to_owned()),
                }],
                founded_at: now,
                consensus_protocol: "founder_only".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("B9: the community admits");
        dir.put_family(ts::sign_family(
            &producer,
            crate::federation::types::Family {
                family_key_id: fam.clone(),
                family_name: format!("{tag}-family-{run}"),
                members: vec![crate::federation::types::FamilyMember {
                    key_id: producer.clone(),
                    joined_at: now,
                    role: Some("founder".to_owned()),
                }],
                founded_at: now,
                consensus_protocol: "founder_only".to_owned(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("B9: the family admits");
        let community = crate::federation::Audience::Community {
            community_key_id: comm.clone(),
        };
        let family = crate::federation::Audience::Family {
            family_key_id: fam.clone(),
        };
        let stage = |attested: String| {
            let producer = producer.clone();
            async move {
                let mut row = scores_row(
                    &uuid::Uuid::new_v4().to_string(),
                    &producer,
                    &attested,
                    "trust:demo:v1",
                );
                row.tier = attestation_tier::LOCAL.to_owned();
                row.cohort_scope = cohort_scope::SELF.to_owned();
                ts::reseal(&mut row);
                let id = row.attestation_id.clone();
                dir.put_attestation(SignedAttestation { attestation: row })
                    .await
                    .expect("B9: the local write itself is admissible");
                let local = dir.get_attestation(&id).await.expect("read").expect("row");
                let ci = ts::describe_own(&local, CrossingBasis::ProducerAuthority);
                dir.enter_mesh(&id, &ci, &ts::actor_reseal(&local))
                    .await
                    .expect("B9: the crossing is not where standing is asked");
                dir.get_attestation(&id).await.expect("read").expect("row")
            }
        };

        for audience in [community.clone(), family.clone()] {
            let scope = audience.cohort_scope();
            let prior = stage(stranger.clone()).await;
            let err = ts::widen(dir, &prior, audience.clone(), &[])
                .await
                .expect_err(
                    "({tag}) B9: widening a row that names a THIRD PARTY into a targeted cohort \
                 plane must be refused — this is the #592 open door",
                );
            assert_eq!(
                err.kind(),
                "federation_cohort_standing_refused",
                "({tag}) B9: every backend refuses at the SAME error kind: {err:?}"
            );
            let msg = format!("{err}");
            assert!(
                msg.contains(scope) && msg.contains(&stranger),
                "({tag}) B9: the refusal names the placement and the party: {msg}"
            );
            let after = dir
                .get_attestation(&prior.attestation_id)
                .await
                .expect("read")
                .expect("row");
            assert_eq!(
                after.cohort_scope, prior.cohort_scope,
                "({tag}) B9: the prior is not moved"
            );
            assert_eq!(
                after.persist_row_hash, prior.persist_row_hash,
                "({tag}) B9: byte-identical"
            );
        }
        {
            let prior = stage(stranger.clone()).await;
            let out = ts::widen(dir, &prior, crate::federation::Audience::Federation, &[])
                .await
                .expect("({tag}) B9: a broad-tier widening of the same row still succeeds");
            assert!(matches!(out, MeshCrossingOutcome::Crossed(_)), "{out:?}");
        }
        {
            let prior = stage(producer.clone()).await;
            let out = ts::widen(dir, &prior, community.clone(), &[])
                .await
                .expect("({tag}) B9: a producer's OWN row still reaches the community plane");
            let MeshCrossingOutcome::Crossed(report) = out else {
                panic!("({tag}) B9: expected Crossed, got {out:?}");
            };
            let sup = dir
                .get_attestation(&report.attestation_id)
                .await
                .expect("read")
                .expect("row");
            assert_eq!(sup.cohort_scope, cohort_scope::COMMUNITY);
        }
        {
            // Born federation-tier: the same verdict, the same kind.
            let third = scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &producer,
                &stranger,
                "trust:demo:v1",
            );
            let id = third.attestation_id.clone();
            dir.put_attestation(SignedAttestation { attestation: third })
                .await
                .expect("({tag}) B9: the federation-tier third-party row admits");
            let prior = dir.get_attestation(&id).await.expect("read").expect("row");
            // `federation` is the widest scope; widen from a narrower born row.
            let mut narrower = scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &producer,
                &stranger,
                "trust:demo:v1",
            );
            narrower.cohort_scope = cohort_scope::AFFILIATIONS.to_owned();
            ts::reseal(&mut narrower);
            let _ = prior;
            let nid = narrower.attestation_id.clone();
            dir.put_attestation(SignedAttestation {
                attestation: narrower,
            })
            .await
            .expect("({tag}) B9: an affiliations-tier third-party row admits");
            let prior = dir.get_attestation(&nid).await.expect("read").expect("row");
            let err = ts::widen(dir, &prior, crate::federation::Audience::Species, &[])
                .await
                .err();
            // species is a broad tier: no standing to have → admitted.
            assert!(
                err.is_none(),
                "({tag}) B9: a broad-tier widening admits: {err:?}"
            );
        }
    }

    /// **W1–W14 — the actor's signature survives the crossing**
    /// (`FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md` §6), at the directory
    /// primitive, on every backend. Each arm names the mutation that must fail
    /// it; a witness whose mutation survives is a claim about the witness.
    ///
    /// W12 (a transit revocation's caller signature survives) rides the same
    /// mechanism as W2 — the base scrub is never replaced by any custody — and
    /// is not fixtured separately here.
    pub async fn exercise_actor_signature_survives_the_crossing(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
        use crate::federation::{
            attestation_emit, crossing, envelope::paths, types::ScrubSig, CrossingBasis, Custody,
            Error, MeshCrossingOutcome, SignedAttestation, TierPromotionCustody,
        };

        let run = uuid::Uuid::new_v4().simple().to_string();
        let actor = format!("{tag}-actor-{run}");
        let node = format!("{tag}-node-{run}");
        let stranger = format!("{tag}-stranger-{run}");
        for k in [&actor, &node, &stranger] {
            ts::register_hybrid_key(dir, k).await;
        }
        // A local row the ACTOR signed at write (sealed as its attester).
        let signed_local = || {
            let mut row = scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &actor,
                &actor,
                "trust:demo:v1",
            );
            row.tier = attestation_tier::LOCAL.to_owned();
            row.cohort_scope = cohort_scope::SELF.to_owned();
            ts::reseal(&mut row);
            row
        };
        let put = |row: Attestation| async move {
            let id = row.attestation_id.clone();
            dir.put_attestation(SignedAttestation { attestation: row })
                .await
                .expect("the local write admits");
            dir.get_attestation(&id).await.expect("read").expect("row")
        };
        let ci_self = |row: &Attestation| ts::describe_own(row, CrossingBasis::ProducerAuthority);

        // W4 — an UNSIGNED local row cannot be entered by a node co-scrub.
        let unsigned_id = dir
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: actor.clone(),
                attested_key_id: None,
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: Some(1.0),
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({ "dimension": "trust:demo:v1", "score": 1.0, "confidence": 0.9 }),
                )
                .unwrap(),
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect("an unsigned durable local row admits (CC 5.3.2.2)");
        let unsigned = dir
            .get_attestation(&unsigned_id)
            .await
            .expect("read")
            .expect("row");
        // W10 — persist mints signed instants as `.sssZ` (CC 2.6.2).
        let minted = unsigned.attestation_envelope[paths::ASSERTED_AT]
            .as_str()
            .expect("asserted_at is signed");
        assert!(
            minted.len() == 24 && minted.ends_with('Z') && minted.as_bytes()[19] == b'.',
            "({tag}) W10: a minted instant renders as YYYY-MM-DDTHH:MM:SS.sssZ, got {minted}"
        );
        let err = dir
            .enter_mesh(
                &unsigned_id,
                &ci_self(&unsigned),
                &ts::node_coscrub(&node, &unsigned),
            )
            .await
            .expect_err("({tag}) W4: the fabric cannot be the only signer of an actor's claim");
        assert!(
            matches!(err, Error::NoActorSignature { .. }),
            "({tag}) W4 by kind: {err}"
        );
        let still = dir
            .get_attestation(&unsigned_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(still.tier, attestation_tier::LOCAL);
        assert_eq!(
            still.persist_row_hash, unsigned.persist_row_hash,
            "({tag}) W4: untouched"
        );

        // W5 — custody offered as the actor's but signed by somebody else.
        let r1 = put(signed_local()).await;
        let by_stranger = match ts::actor_reseal(&r1) {
            TierPromotionCustody::ActorSigned(mut reseal) => {
                let (och, sc, sp) = ts::sign_envelope(&stranger, &reseal.attestation_envelope);
                reseal.original_content_hash = och;
                reseal.scrub_signature_classical = sc;
                reseal.scrub_signature_pqc = sp;
                reseal.scrub_key_id = stranger.clone();
                TierPromotionCustody::ActorSigned(reseal)
            }
            other => other,
        };
        let err = dir
            .enter_mesh(&r1.attestation_id, &ci_self(&r1), &by_stranger)
            .await
            .expect_err("({tag}) W5: the fabric never replaces the actor's key");
        assert!(
            matches!(err, Error::CustodyIsNotTheActor { .. }),
            "({tag}) W5 by kind: {err}"
        );

        // W13 — the description must match the row, by axis.
        let mut lying = ci_self(&r1);
        lying.sender = stranger.clone();
        let err = dir
            .enter_mesh(&r1.attestation_id, &lying, &ts::node_coscrub(&node, &r1))
            .await
            .expect_err("({tag}) W13: a misdescribed row never crosses");
        assert!(
            matches!(
                err,
                Error::ContextualIntegrityMismatch { axis: "sender", .. }
            ),
            "({tag}) W13: refused by the NAME of the axis: {err}"
        );

        // W2 / W3 / W9 / W11 / W14 — the node co-scrubs; the actor survives.
        let bytes_before = crossing::canonical_bytes(&mut r1.attestation_envelope.clone())
            .unwrap()
            .0;
        let out = dir
            .enter_mesh(
                &r1.attestation_id,
                &ci_self(&r1),
                &ts::node_coscrub(&node, &r1),
            )
            .await
            .expect("({tag}) W2: a signed row crosses under node custody");
        let MeshCrossingOutcome::Crossed(report) = out else {
            panic!("({tag}) W2: expected Crossed, got {out:?}");
        };
        let Custody::ActorSignedNodeCoScrubbed { cosigned_at } = &report.custody else {
            panic!(
                "({tag}) W2: expected a node co-scrub, got {:?}",
                report.custody
            );
        };
        assert!(
            !report.replicates.discoverable,
            "({tag}) W14: self is replicated, not advertised"
        );
        assert!(
            report.age_at_crossing_ms >= 0 && report.age_at_crossing_ms < 60_000,
            "({tag}) W11: age is now − the SIGNED asserted_at (seconds old, not the fixture's \
             scrub_timestamp): {}",
            report.age_at_crossing_ms
        );
        let after = dir
            .get_attestation(&r1.attestation_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(after.tier, attestation_tier::FEDERATION);
        assert_eq!(
            after.scrub_key_id, actor,
            "({tag}) W2: the actor's base scrub survives"
        );
        assert_eq!(
            after.scrub_signature_classical, r1.scrub_signature_classical,
            "({tag}) W2"
        );
        assert_eq!(
            after.scrub_signature_pqc, r1.scrub_signature_pqc,
            "({tag}) W2"
        );
        assert_eq!(
            after.additional_scrubs.len(),
            1,
            "({tag}) W3: the co-scrub is appended"
        );
        assert_eq!(after.additional_scrubs[0].scrub_key_id, node);
        assert_eq!(
            after.additional_scrubs[0].cosigned_at.as_deref(),
            Some(cosigned_at.as_str()),
            "({tag}) `modified` rides the ScrubSig"
        );
        assert!(
            cosigned_at.len() == 24 && cosigned_at.ends_with('Z'),
            "({tag}) W10: {cosigned_at}"
        );
        let bytes_after = crossing::canonical_bytes(&mut after.attestation_envelope.clone())
            .unwrap()
            .0;
        assert_eq!(
            bytes_before, bytes_after,
            "({tag}) W1: JCS(envelope) is byte-identical"
        );
        crate::federation::verify_row_hybrid_signature(dir, &after)
            .await
            .expect("({tag}) W6/W9: actor signature AND co-scrub verify; cosigned_at is outside the preimage");

        // W3 (inherited) — a pre-existing co-scrub is preserved, and VERIFIED:
        // a corrupt one refuses the crossing rather than laundering into the mesh.
        let mut r2 = signed_local();
        let (_h, sc, sp) = ts::sign_envelope(&stranger, &r2.attestation_envelope);
        r2.additional_scrubs.push(ScrubSig {
            scrub_key_id: stranger.clone(),
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            cosigned_at: None,
        });
        let r2 = put(r2).await;
        let out = dir
            .enter_mesh(
                &r2.attestation_id,
                &ci_self(&r2),
                &ts::node_coscrub(&node, &r2),
            )
            .await
            .expect("({tag}) W3: a co-scrubbed local row crosses");
        assert!(matches!(out, MeshCrossingOutcome::Crossed(_)));
        let after2 = dir
            .get_attestation(&r2.attestation_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(
            after2
                .additional_scrubs
                .iter()
                .map(|s| s.scrub_key_id.as_str())
                .collect::<Vec<_>>(),
            vec![stranger.as_str(), node.as_str()],
            "({tag}) W3: inherited co-scrub kept, node's appended"
        );
        let mut r3 = signed_local();
        r3.additional_scrubs.push(ScrubSig {
            scrub_key_id: stranger.clone(),
            scrub_signature_classical: "AAAA".into(),
            scrub_signature_pqc: Some("AAAA".into()),
            cosigned_at: None,
        });
        let r3 = put(r3).await;
        let err = dir
            .enter_mesh(
                &r3.attestation_id,
                &ci_self(&r3),
                &ts::node_coscrub(&node, &r3),
            )
            .await
            .expect_err("({tag}) W3/#556: a corrupt inherited co-scrub refuses the crossing");
        assert!(
            format!("{err}").contains("additional_scrubs"),
            "({tag}) W3: the refusal names the co-scrub: {err}"
        );

        // W7 / W8 — widening is a supersedes by the actor; the prior is untouched.
        let out = ts::widen(dir, &after, crate::federation::Audience::Affiliations, &[])
            .await
            .expect("({tag}) W7: the actor widens");
        let MeshCrossingOutcome::Crossed(wreport) = out else {
            panic!("({tag}) W7: expected Crossed, got {out:?}");
        };
        assert!(
            wreport.replicates.discoverable,
            "({tag}) W14: community is advertised"
        );
        let prior_after = dir
            .get_attestation(&r1.attestation_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(
            prior_after.persist_row_hash, after.persist_row_hash,
            "({tag}) W7: byte-identical"
        );
        let sup = dir
            .get_attestation(&wreport.attestation_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(sup.attestation_type, attestation_type::SUPERSEDES);
        assert_eq!(
            sup.attesting_key_id, actor,
            "({tag}) W8: signed by the actor"
        );
        assert_eq!(
            sup.attestation_envelope[paths::DIFFERS_IN],
            serde_json::json!(["cohort_scope"])
        );
        // W8 negative — a widening signed by a NON-actor.
        let forged = {
            let mut input =
                crossing::build_widening(&sup, &crossing::Audience::Federation, &[]).unwrap();
            let canonical =
                attestation_emit::stamp_and_canonicalize(&mut input, &stranger, chrono::Utc::now())
                    .unwrap();
            let sig = ts::local_signer(&stranger)
                .sign_hybrid(&canonical)
                .await
                .unwrap();
            attestation_emit::assemble(stranger.clone(), &canonical, sig, input)
                .unwrap()
                .0
        };
        let ci = ts::describe_for(
            &sup,
            crate::federation::Audience::Federation,
            CrossingBasis::ProducerAuthority,
        );
        let err = dir
            .widen_audience(
                &sup.attestation_id,
                &ci,
                SignedAttestation {
                    attestation: forged,
                },
            )
            .await
            .expect_err("({tag}) W8: a supersedes by a non-actor is refused");
        assert!(
            matches!(err, Error::CustodyIsNotTheActor { .. }),
            "({tag}) W8 by kind: {err}"
        );
        // Re-authoring under the guise of widening.
        let reauthored = {
            let mut input =
                crossing::build_widening(&sup, &crossing::Audience::Federation, &[]).unwrap();
            input
                .attestation_envelope
                .extra
                .insert("score".into(), serde_json::json!(0.1));
            let canonical =
                attestation_emit::stamp_and_canonicalize(&mut input, &actor, chrono::Utc::now())
                    .unwrap();
            let sig = ts::local_signer(&actor)
                .sign_hybrid(&canonical)
                .await
                .unwrap();
            attestation_emit::assemble(actor.clone(), &canonical, sig, input)
                .unwrap()
                .0
        };
        let err = dir
            .widen_audience(
                &sup.attestation_id,
                &ci,
                SignedAttestation {
                    attestation: reauthored,
                },
            )
            .await
            .expect_err("({tag}) a widening that changes the body is a new claim");
        assert!(
            matches!(&err, Error::WideningReAuthors { member, .. } if member == "score"),
            "({tag}) refused naming the member: {err}"
        );
    }

    // ── B10 (CIRISPersist#598) — THE CONSENT INSTANT BINDING ─────────────
    //
    // | # | Invariant | Threat it denies |
    // |---|---|---|
    // | B10 | A `consent:state:*` row's `asserted_at` / `expires_at` COLUMNS
    //        equal the instants in its own SIGNED envelope, on the substrate's
    //        microsecond resolution and not in the future | Replaying a
    //        subject's still-valid grant with a bumped column to un-revoke
    //        their consent — no forgery, no broken signature |
    //
    // The pre-existing fold coverage was `sqlite.rs` only, single-writer, and
    // assigned `asserted_at` BY HAND — which is precisely the operation the
    // defect permits. Three legs, three backends, one body.

    /// The three consent instants a witness needs, all on the substrate
    /// resolution and all safely in the past: `t1` (grant), `t2` (revoke,
    /// later), `t3` (the replay's bumped column, later still).
    fn replay_instants() -> (
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    ) {
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        (
            now - chrono::Duration::seconds(300),
            now - chrono::Duration::seconds(120),
            now - chrono::Duration::seconds(10),
        )
    }

    /// A third-party `capacity:*` claim by `attester` about `subject` — the
    /// gate INSIDE persist that the replay re-opens
    /// ([`crate::federation::admission::check_capacity_consent_admission`]).
    fn capacity_claim(attester: &str, subject: &str) -> Attestation {
        scores_row(
            &uuid::Uuid::new_v4().to_string(),
            attester,
            subject,
            "capacity:core_identity:v1",
        )
    }

    /// **B10-a — THE REPLAY IS REFUSED.**
    ///
    /// The reported defect, end to end. `asserted_at` is a row column stored
    /// verbatim by every backend and covered by no signature, so an attacker
    /// needs no key material at all:
    ///
    /// 1. subject `S` grants `analyze` covering `P` at `t1`, then revokes at
    ///    `t2 > t1`. The fold reads `Revoked` and `P`'s `capacity:*` claim
    ///    about `S` is refused.
    /// 2. the replay resubmits `S`'s **byte-identical, still-validly-signed**
    ///    `t1` grant — same envelope, same `original_content_hash`, same
    ///    hybrid signature, same `attesting_key_id` — with a fresh
    ///    `attestation_id` and `asserted_at = t3 > t2`.
    ///
    /// Persist's ingest door carries **no caller identity**, which is why
    /// "a DIFFERENT key replays it" is indistinguishable at the door from `S`
    /// re-sending — and therefore why the defence has to be a property of the
    /// ROW rather than of the sender. The row is refused because its column
    /// diverges from its own signed envelope.
    ///
    /// Asserts the put is refused, the fold is STILL `Revoked`, and
    /// `check_capacity_consent_admission` still refuses the third-party
    /// `capacity:*` row — the last one because the fold and the gate are two
    /// surfaces and a witness on only the fold would not have caught #598
    /// biting inside persist.
    pub async fn exercise_consent_replay_refusal(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::consent::consent_dimension;
        use crate::federation::hard_case::ConsentState;

        let subject = format!("{tag}-598-subject");
        let attester = format!("{tag}-598-attester");
        for k in [&subject, &attester] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }
        let (t1, t2, t3) = replay_instants();
        let analyze = crate::federation::admission::ANALYZE_CONSENT_SCOPE;

        // (a) the grant at t1 — this row is the attacker's ammunition, so keep
        // it: the replay is this exact row with two fields changed.
        let grant = consent_scope_row(
            &uuid::Uuid::new_v4().to_string(),
            &subject,
            &attester,
            &format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
            &[analyze],
            t1,
        );
        dir.put_attestation(SignedAttestation {
            attestation: grant.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("({tag}) B10-a: the subject's own grant admits: {e}"));

        // (b) the revocation at t2 > t1 — the fold closes.
        dir.put_attestation(SignedAttestation {
            attestation: consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &format!("{}:v1", consent_dimension::STATE_REVOKED_PREFIX),
                &[analyze],
                t2,
            ),
        })
        .await
        .unwrap_or_else(|e| panic!("({tag}) B10-a: the subject's own revocation admits: {e}"));
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Revoked,
            "({tag}) B10-a: after the revoke the fold must read Revoked"
        );
        dir.put_attestation(SignedAttestation {
            attestation: capacity_claim(&attester, &subject),
        })
        .await
        .expect_err("({tag}) B10-a: with consent revoked, a capacity:* claim about S is refused");

        // (c) THE REPLAY. Byte-identical signed envelope (so the hybrid verify
        // still passes and `original_content_hash` still matches) and the
        // ordering key bumped past the revocation.
        //
        // v31.0.0 (CIRISPersist#643) — the `attestation_id` bump this arm used
        // to carry MOVED to (c2). #643 put the row id inside the signed mirror,
        // so a fresh-id replay is now refused by the ID binding BEFORE the
        // instant binding is reached — which would leave this arm passing for
        // the wrong rule, i.e. no longer a #598 witness at all. Same id here,
        // only the COLUMN bumped: that is the divergence #598 exists for.
        let mut replay = grant.clone();
        replay.asserted_at = t3;
        assert_eq!(
            replay.attestation_envelope, grant.attestation_envelope,
            "({tag}) B10-a: the replay must be BYTE-IDENTICAL in the signed half — a witness \
             that mutates the envelope is testing the signature, not the binding"
        );
        assert_eq!(
            replay.scrub_signature_classical, grant.scrub_signature_classical,
            "({tag}) B10-a: …and carries the subject's own still-valid signature"
        );
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: replay,
            })
            .await
            .expect_err(
                "({tag}) B10-a: a replayed grant whose asserted_at COLUMN diverges from its \
                 signed envelope must be REFUSED (CIRISPersist#598)",
            );
        let msg = format!("{err}");
        assert!(
            msg.contains("asserted_at") && msg.contains("598"),
            "({tag}) B10-a: the refusal must name the field and the rule: {msg}"
        );

        // (c2) v31.0.0 (CIRISPersist#643) — THE SAME REPLAY WEARING A FRESH
        // ID, which is how the attack was actually written before the row id
        // was signed: `attestation_id` is the only PK and the §6.1 dedup
        // returns `false` for a `scores` row, so a new id made the resubmission
        // a NEW row rather than an idempotent no-op. Now the id rides the
        // mirror, so the same signed bytes can only ever name one row — the
        // replay is refused on the ID, one gate earlier than #598, and this arm
        // pins WHICH rule caught it.
        // The instant COLUMN is left alone here so the #598 gate passes and the
        // ID binding is what refuses — one variable, one rule.
        let mut fresh_id = grant.clone();
        fresh_id.attestation_id = uuid::Uuid::new_v4().to_string();
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: fresh_id,
            })
            .await
            .expect_err(
                "({tag}) B10-a/#643: a replay under a FRESH attestation_id must be REFUSED — \
                 the row id is inside the signed mirror",
            );
        let msg = format!("{err}");
        assert!(
            msg.contains("attestation_id") && msg.contains("643"),
            "({tag}) B10-a/#643: the refusal must name the id binding: {msg}"
        );

        // (d) …and nothing moved: the fold is still closed and the gate INSIDE
        // persist still refuses.
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Revoked,
            "({tag}) B10-a: the replay must not flip the fold back to Granted"
        );
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: capacity_claim(&attester, &subject),
            })
            .await
            .expect_err(
                "({tag}) B10-a: check_capacity_consent_admission must STILL refuse a \
                 third-party capacity:* row about S",
            );
        assert_eq!(
            err.kind(),
            "federation_consent_gate_refused",
            "({tag}) B10-a: and it refuses at the consent gate, not incidentally: {err:?}"
        );
    }

    /// **B11 (CIRISPersist#643) — THE TYPED COLUMNS ARE SIGNED MATERIAL.**
    ///
    /// The signature covers `attestation_envelope` and nothing else, so before
    /// this every typed column was a field a relay could rewrite while keeping
    /// the producer's own signature valid. Two of them decide everything:
    ///
    /// - **the VERB.** `references_attestation_id` — the TARGET of a retraction
    ///   — was already inside the signed envelope; `attestation_type` — whether
    ///   this is a retraction at all — was not. Flip `withdraws` → `scores` and
    ///   the retraction becomes an ordinary claim while the thing it retracted
    ///   stays live.
    /// - **the AUTHORITY.** `resolve_withdraws_admission_rule` returns rule-2
    ///   standing when a canonical binding hash of the issuer appears in
    ///   `subject_key_ids`. APPENDING one in transit hands that key revocation
    ///   authority over the row.
    ///
    /// Every arm below MUTATES A COLUMN AND NOTHING ELSE on a row this
    /// directory has already accepted in its honest form, so the signature, the
    /// content hash and every other gate are held constant and the ONLY variable
    /// is the binding. The control arm (a) is what makes that claim checkable:
    /// without it, a refusal could be any of the twenty other gates.
    ///
    /// Absence is its own arm (h): the operator's standing decision on this
    /// break window is to refuse an unbound row outright — no grandfathering, no
    /// regime flag, nothing to find later.
    pub async fn exercise_row_column_binding(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::envelope::{paths, row_paths};

        // Invocation-unique: the postgres arm shares a long-lived database.
        let run = uuid::Uuid::new_v4().simple().to_string();
        let author = format!("{tag}-643a-{run}");
        let other = format!("{tag}-643b-{run}");
        for k in [&author, &other] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }

        // The honest row, sealed the way a producer must now seal one.
        let honest = |id: &str| {
            let mut row = scores_row(id, &author, &author, "trust:demo:v1");
            row.attestation_envelope
                .as_object_mut()
                .expect("envelope is an object")
                .insert("references_attestation_id".into(), "target-1".into());
            crate::federation::tier_ingest::test_support::reseal(&mut row);
            row
        };

        // ── (a) THE CONTROL. The honest row ADMITS. Without this arm every
        //    refusal below could be some other gate and the witness would be a
        //    check that cannot fail.
        dir.put_attestation(SignedAttestation {
            attestation: honest(&uuid::Uuid::new_v4().to_string()),
        })
        .await
        .unwrap_or_else(|e| panic!("({tag}) B11-a: a correctly sealed row must ADMIT: {e}"));

        // Mutate ONE column on a freshly sealed row and demand a refusal that
        // NAMES that column and the rule. `expect_err` alone would pass on an
        // unregistered key or a broken signature.
        async fn refuses(
            dir: &dyn FederationDirectory,
            tag: &str,
            arm: &str,
            member: &str,
            row: Attestation,
        ) {
            let id = row.attestation_id.clone();
            let Err(err) = dir
                .put_attestation(SignedAttestation { attestation: row })
                .await
            else {
                panic!("({tag}) B11-{arm}: a rewritten `{member}` must be REFUSED");
            };
            let msg = format!("{err}");
            assert!(
                msg.contains(member) && msg.contains("643"),
                "({tag}) B11-{arm}: the refusal must name `{member}` and the rule: {msg}"
            );
            assert_eq!(
                err.kind(),
                "federation_invalid_argument",
                "({tag}) B11-{arm}: refusal kind is parity-asserted across backends: {err:?}"
            );
            // REFUSED, not refused-after-storing (AV-9).
            assert!(
                dir.get_attestation(&id)
                    .await
                    .expect("get_attestation")
                    .is_none(),
                "({tag}) B11-{arm}: a refused row must leave no trace"
            );
        }

        // ── (b) VERB SUBSTITUTION — the headline. Sign a `withdraws`, ship a
        //    `scores`. The envelope still names the target it retracts.
        let mut verb = honest(&uuid::Uuid::new_v4().to_string());
        verb.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.to_owned();
        crate::federation::tier_ingest::test_support::reseal(&mut verb);
        assert_eq!(
            verb.attestation_envelope[paths::ROW][row_paths::ATTESTATION_TYPE],
            serde_json::json!(crate::federation::types::attestation_type::WITHDRAWS),
            "({tag}) B11-b: precondition — the signed mirror says `withdraws`"
        );
        verb.attestation_type = crate::federation::types::attestation_type::SCORES.to_owned();
        refuses(dir, tag, "b", row_paths::ATTESTATION_TYPE, verb).await;

        // ── (c) AUTHORITY INJECTION — append a canonical binding hash to
        //    `subject_key_ids`, which is what grants rule-2 revocation standing.
        let mut authority = honest(&uuid::Uuid::new_v4().to_string());
        authority
            .subject_key_ids
            .push(format!("sha256:{}", "0".repeat(64)));
        refuses(dir, tag, "c", row_paths::SUBJECT_KEY_IDS, authority).await;

        // ── (d) WHO THE CLAIM IS ABOUT.
        let mut about = honest(&uuid::Uuid::new_v4().to_string());
        about.attested_key_id = other.clone();
        refuses(dir, tag, "d", row_paths::ATTESTED_KEY_ID, about).await;

        // ── (e) WHO MAY SEE IT. Widening the audience of somebody else's row
        //    is the confused-deputy shape one plane over from #443's route
        //    hijack.
        let mut audience = honest(&uuid::Uuid::new_v4().to_string());
        audience.cohort_scope = crate::federation::types::cohort_scope::COMMUNITY.to_owned();
        refuses(dir, tag, "e", row_paths::COHORT_SCOPE, audience).await;

        // ── (f) HOW MUCH IT COUNTS. `trust_scoring` / `topology` fold
        //    `weight.unwrap_or(1.0)`, so an unsigned weight is an unsigned
        //    volume knob on a signed claim.
        let mut louder = honest(&uuid::Uuid::new_v4().to_string());
        louder.weight = Some(99.0);
        refuses(dir, tag, "f", row_paths::WEIGHT, louder).await;

        // ── (g) THE ROW'S IDENTITY. A fresh id on byte-identical signed
        //    content is the REPLAY shape (#598 B10-a): with the id bound, the
        //    same envelope can only ever name one row.
        let mut replay = honest(&uuid::Uuid::new_v4().to_string());
        replay.attestation_id = uuid::Uuid::new_v4().to_string();
        refuses(dir, tag, "g", row_paths::ATTESTATION_ID, replay).await;

        // ── (g2) WHO MADE THE CLAIM. Bound explicitly rather than left to the
        //    ingest verifier's implicit binding, so the property survives the
        //    local tier where signature verification is deferred.
        let mut author_swap = honest(&uuid::Uuid::new_v4().to_string());
        author_swap.attesting_key_id = other.clone();
        let id = author_swap.attestation_id.clone();
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: author_swap,
            })
            .await
            .expect_err("({tag}) B11-g2: a rewritten `attesting_key_id` must be REFUSED");
        assert!(
            format!("{err}").contains(row_paths::ATTESTING_KEY_ID)
                && format!("{err}").contains("643"),
            "({tag}) B11-g2: the refusal must name the authorship binding, not merely the \
             signature: {err}"
        );
        assert!(
            dir.get_attestation(&id).await.expect("get").is_none(),
            "({tag}) B11-g2: a refused row must leave no trace"
        );

        // ── (h) ABSENCE. No `row` object at all — the pre-#643 wire shape.
        //    REFUSED, not tolerated: there is no legacy regime.
        let mut unbound = honest(&uuid::Uuid::new_v4().to_string());
        unbound
            .attestation_envelope
            .as_object_mut()
            .expect("envelope is an object")
            .remove(paths::ROW);
        // Re-sign the STRIPPED envelope, so the row is internally consistent in
        // every way the OLD gates could see: valid hybrid signature, matching
        // `original_content_hash`. The only thing wrong with it is that nothing
        // binds its columns — which is exactly the pre-#643 status quo.
        let (och, sc, sp) = crate::federation::tier_ingest::test_support::sign_envelope(
            &author,
            &unbound.attestation_envelope,
        );
        unbound.original_content_hash = och;
        unbound.scrub_signature_classical = sc;
        unbound.scrub_signature_pqc = sp;
        let id = unbound.attestation_id.clone();
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: unbound,
            })
            .await
            .expect_err(
                "({tag}) B11-h: a row carrying no signed `row` object must be REFUSED — no \
                 grandfathering (CIRISPersist#643)",
            );
        let msg = format!("{err}");
        assert!(
            msg.contains(paths::ROW) && msg.contains("643"),
            "({tag}) B11-h: the refusal must name the missing mirror and the rule: {msg}"
        );
        // v31.0.0 (CIRISPersist#658) — the message is a SPECIFICATION, not
        // prose. This is the text an external producer builds its mirror from
        // during the v31.0.0 re-mint, `RowMirror` is `deny_unknown_fields`,
        // and only `subject_key_ids` / `weight` default — so a message that
        // omits a required member refuses the producer a second time, by the
        // very text that told it what to build. It named five while the gate
        // enforced seven. Asserted EXHAUSTIVELY off `row_paths::ALL`, so a
        // future eighth member cannot be added to the mirror and left out of
        // the message.
        for member in crate::federation::envelope::row_paths::ALL {
            assert!(
                msg.contains(member),
                "({tag}) B11-h: the refusal must name every member a producer has to stamp — \
                 `{member}` is missing from: {msg}"
            );
        }
        assert!(
            dir.get_attestation(&id).await.expect("get").is_none(),
            "({tag}) B11-h: a refused row must leave no trace"
        );

        // ── (i) MALFORMED. A mirror missing ONE member is not a partial
        //    binding, it is no binding — refused, and refused with the member
        //    set named so a producer can fix it.
        let mut partial = honest(&uuid::Uuid::new_v4().to_string());
        partial.attestation_envelope[paths::ROW]
            .as_object_mut()
            .expect("mirror is an object")
            .remove(row_paths::COHORT_SCOPE);
        let (och, sc, sp) = crate::federation::tier_ingest::test_support::sign_envelope(
            &author,
            &partial.attestation_envelope,
        );
        partial.original_content_hash = och;
        partial.scrub_signature_classical = sc;
        partial.scrub_signature_pqc = sp;
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: partial,
            })
            .await
            .expect_err("({tag}) B11-i: a mirror missing a member must be REFUSED");
        let msg = format!("{err}");
        assert!(
            msg.contains("643"),
            "({tag}) B11-i: the refusal must name the rule: {msg}"
        );
        // v31.0.0 (CIRISPersist#658) — same specification duty as (h): this is
        // the message the producer sees when its mirror is one member short,
        // so it must list the members in full.
        for member in crate::federation::envelope::row_paths::ALL {
            assert!(
                msg.contains(member),
                "({tag}) B11-i: the malformed-mirror refusal must name every member — \
                 `{member}` is missing from: {msg}"
            );
        }

        // ── (j) NON-VACUITY OF THE CONTROL, at the end. The gate is a rule and
        //    not a lockdown: after seven refusals a fresh honest row still
        //    admits, so nothing above wedged the directory into refusing
        //    everything (which would make every arm above pass for free).
        dir.put_attestation(SignedAttestation {
            attestation: honest(&uuid::Uuid::new_v4().to_string()),
        })
        .await
        .unwrap_or_else(|e| panic!("({tag}) B11-j: the gate is a door, not a wall: {e}"));
    }

    /// **B10-b — TWO DIRECTORIES FED THE SAME ENVELOPES CANNOT DISAGREE.**
    ///
    /// The divergent-order leg. Replica A is fed the two signed envelopes with
    /// their true instants. Replica B is fed **the same two signed envelopes**
    /// with the two `asserted_at` COLUMNS SWAPPED — a relaying node (or a
    /// skewed clock) reordering a subject's consent history without touching a
    /// signature. Before #598 that made the two replicas fold to opposite
    /// verdicts about the same signed facts, which is the property a mesh
    /// cannot have on the consent plane.
    ///
    /// Both replicas live in ONE directory under disjoint key pairs: the fold
    /// is keyed on `(target, subject)`, so two disjoint pairs are two
    /// independent replicas of the same history — and using one directory is
    /// what lets the same body run on all three backends.
    ///
    /// The property proved is that **the signed envelopes decide the verdict
    /// and the columns cannot change it**: replica B's swapped feed is
    /// REFUSED, B stays non-Granted while it holds only the swapped rows, and
    /// when B is fed the same envelopes with the instants those envelopes
    /// themselves state, it converges on A's verdict exactly. Ordering is no
    /// longer an input a relay gets to choose.
    pub async fn exercise_consent_divergent_order(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::consent::consent_dimension;
        use crate::federation::hard_case::ConsentState;

        let analyze = crate::federation::admission::ANALYZE_CONSENT_SCOPE;
        let (t1, t2, _t3) = replay_instants();
        let granted = format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX);
        let revoked = format!("{}:v1", consent_dimension::STATE_REVOKED_PREFIX);

        let mut verdicts = Vec::new();
        for (replica, swap) in [("a", false), ("b", true)] {
            let subject = format!("{tag}-598-div{replica}-subject");
            let attester = format!("{tag}-598-div{replica}-attester");
            for k in [&subject, &attester] {
                crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
            }
            // The SIGNED envelopes are identical on both replicas (same
            // stance, same scope, same signed instant). Only the row COLUMNS
            // differ — swapped on replica B.
            let grant = consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &granted,
                &[analyze],
                t1,
            );
            let revoke = consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &revoked,
                &[analyze],
                t2,
            );
            if swap {
                let mut swapped_grant = grant.clone();
                let mut swapped_revoke = revoke.clone();
                std::mem::swap(
                    &mut swapped_grant.asserted_at,
                    &mut swapped_revoke.asserted_at,
                );
                for (row, what) in [(swapped_grant, "grant"), (swapped_revoke, "revoke")] {
                    dir.put_attestation(SignedAttestation { attestation: row })
                        .await
                        .expect_err(&format!(
                            "({tag}) B10-b: replica b's {what} carries a column its own signed \
                             envelope does not agree with and must be REFUSED \
                             (CIRISPersist#598)"
                        ));
                }
                // While B holds ONLY the swapped feed it must not have been
                // talked into a grant. Pre-#598 this read Granted while A read
                // Revoked — the mesh split this leg exists to deny.
                assert_ne!(
                    dir.resolve_scoped_consent(
                        &attester,
                        &subject,
                        analyze,
                        None,
                        chrono::Utc::now()
                    )
                    .await
                    .expect("fold reads"),
                    ConsentState::Granted,
                    "({tag}) B10-b: a swapped ordering column must never buy a GRANT"
                );
            }
            // Both replicas are now fed the envelopes with the instants those
            // envelopes THEMSELVES state — for A that is the only feed it ever
            // saw; for B it is the honest relay of the same signed bytes.
            for (row, what) in [(grant, "grant"), (revoke, "revoke")] {
                dir.put_attestation(SignedAttestation { attestation: row })
                    .await
                    .unwrap_or_else(|e| {
                        panic!("({tag}) B10-b/{replica}: the bound {what} admits: {e}")
                    });
            }
            verdicts.push(
                dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                    .await
                    .expect("fold reads"),
            );
        }
        assert_eq!(
            verdicts[0], verdicts[1],
            "({tag}) B10-b: two directories fed the SAME signed envelopes must fold to the same \
             verdict — a swapped ordering column must not buy a different answer"
        );
        assert_eq!(
            verdicts[0],
            ConsentState::Revoked,
            "({tag}) B10-b: …and the verdict they converge on is the subject's actual latest \
             stance, not a shared blank"
        );
    }

    /// **B12 (CIRISPersist#642) — THE CLOCK SAYS GRANT, THE EDGE SAYS REVOKED,
    /// AND THE CLOCK-ORDERED FOLD LOSES.**
    ///
    /// #598 bound `asserted_at` to the signed envelope, so a peer can no longer
    /// FORGE the instant — but the producer still chooses it, and
    /// [`crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW`] (300s) is the
    /// width of the remaining race: a grant minted ahead out-sorts the
    /// revocation issued inside that window. This drives the fix through the
    /// REAL write path on every backend: a revocation that NAMES the grant it
    /// supersedes (the signed `consent_supersedes` key, read by
    /// [`crate::federation::consent::causal_edge`]) wins regardless of the
    /// clock.
    ///
    /// Six legs, each on its own `(subject, attester)` pair so the folds cannot
    /// contaminate each other:
    ///
    /// - **A — the witness**, plus the CONTROL that makes it mean something:
    ///   the identical pair of rows with the pointer REMOVED must read
    ///   `Granted`. Without the control a green A could just be a fold that
    ///   never saw the grant. Both entry points (`resolve_consent_state` and
    ///   `resolve_scoped_consent`) are pinned, and so is the gate downstream of
    ///   them — a verdict that does not reach `capacity:*` admission is a
    ///   verdict no consumer feels.
    /// - **B — fail-closed**: an edge naming a row this node cannot resolve
    ///   (absent, or junk) does not fall back to clock ordering in the
    ///   direction that favours the grant.
    /// - **C — the asymmetry**: the same pointer on a GRANT confers nothing.
    /// - **D — the ratchet**: a back-dated revocation naming the real
    ///   revocation must not hand the fold to the grant underneath it.
    /// - **E — the §6.1 retraction fold reaches the consent plane**: the
    ///   subject's own `withdraws` against its only grant leaves no live
    ///   statement (`Unspecified`, not `Granted`).
    /// - **F — a door, not a wall**: an affirmative later grant still re-opens.
    pub async fn exercise_consent_causal_supersedes(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::consent::consent_dimension;
        use crate::federation::hard_case::ConsentState;

        let analyze = crate::federation::admission::ANALYZE_CONSENT_SCOPE;
        let granted = format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX);
        let revoked = format!("{}:v1", consent_dimension::STATE_REVOKED_PREFIX);
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        // The forward mint: 120s ahead of the revocation and INSIDE the 300s
        // skew tolerance, so `check_instant_binding` admits it. This is the
        // race #642 is about — not a rejected row, an admitted one that wins.
        let ahead = now + chrono::Duration::seconds(120);
        let earlier = now - chrono::Duration::seconds(120);
        let earliest = now - chrono::Duration::seconds(240);

        // Per-leg key pair. Registering fresh keys per leg is what keeps the
        // folds independent (the fold is keyed on `(target, subject)`).
        async fn keys(dir: &dyn FederationDirectory, tag: &str, leg: &str) -> (String, String) {
            let subject = format!("{tag}-642{leg}-subject");
            let attester = format!("{tag}-642{leg}-attester");
            for k in [&subject, &attester] {
                crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
            }
            (subject, attester)
        }
        let put = |row: Attestation, what: &'static str| async move {
            dir.put_attestation(SignedAttestation { attestation: row })
                .await
                .unwrap_or_else(|e| panic!("B12: {what} must admit: {e}"));
        };

        // ── A — THE WITNESS ──────────────────────────────────────────────
        let (subject, attester) = keys(dir, tag, "a").await;
        let grant_id = uuid::Uuid::new_v4().to_string();
        put(
            consent_scope_row(&grant_id, &subject, &attester, &granted, &[analyze], ahead),
            "the forward-minted grant",
        )
        .await;
        put(
            consent_scope_row_superseding(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &revoked,
                &[analyze],
                now,
                Some(serde_json::Value::String(grant_id.clone())),
            ),
            "the revocation naming its grant",
        )
        .await;
        for (entry, got) in [
            (
                "resolve_scoped_consent",
                dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                    .await
                    .expect("scoped fold reads"),
            ),
            (
                "resolve_consent_state",
                dir.resolve_consent_state(&attester, &subject, chrono::Utc::now())
                    .await
                    .expect("unscoped fold reads"),
            ),
        ] {
            assert_eq!(
                got,
                ConsentState::Revoked,
                "({tag}) B12-A/{entry}: the revocation NAMES the grant it revokes, so causality \
                 decides — a grant minted 120s ahead is still the latest by `asserted_at` and \
                 must NOT win (CIRISPersist#642)"
            );
        }
        // …and the verdict reaches the gate a consumer actually feels.
        dir.put_attestation(SignedAttestation {
            attestation: capacity_claim(&attester, &subject),
        })
        .await
        .expect_err(&format!(
            "({tag}) B12-A: the causally-ordered revocation must CLOSE the capacity gate — a \
             fold the admission path does not inherit changes nothing"
        ));

        // ── A' — THE CONTROL. Same two rows, no pointer: the clock genuinely
        //    favours the grant, which is what makes A a measurement.
        let (subject, attester) = keys(dir, tag, "actl").await;
        put(
            consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &granted,
                &[analyze],
                ahead,
            ),
            "the control grant",
        )
        .await;
        put(
            consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &revoked,
                &[analyze],
                now,
            ),
            "the control revocation",
        )
        .await;
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Granted,
            "({tag}) B12-A': WITHOUT the edge this is the #642 defect itself — the forward-minted \
             grant out-sorts the revocation. If this leg reads Revoked the fixture is not \
             reproducing the race and leg A proves nothing about the edge"
        );

        // ── B — FAIL-CLOSED on an edge nobody can resolve ────────────────
        for (leg, pointer, what) in [
            (
                "b1",
                serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
                "a grant this node has never seen",
            ),
            ("b2", serde_json::json!(42), "a junk pointer"),
        ] {
            let (subject, attester) = keys(dir, tag, leg).await;
            put(
                consent_scope_row(
                    &uuid::Uuid::new_v4().to_string(),
                    &subject,
                    &attester,
                    &granted,
                    &[analyze],
                    ahead,
                ),
                "the forward-minted grant",
            )
            .await;
            put(
                consent_scope_row_superseding(
                    &uuid::Uuid::new_v4().to_string(),
                    &subject,
                    &attester,
                    &revoked,
                    &[analyze],
                    now,
                    Some(pointer),
                ),
                "the revocation with an unresolvable edge",
            )
            .await;
            assert_eq!(
                dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                    .await
                    .expect("fold reads"),
                ConsentState::Revoked,
                "({tag}) B12-B/{leg}: a revocation naming {what} means this node's view is \
                 INCOMPLETE. Degrading to the clock there hands the answer to the grant minted \
                 ahead — the defect reached through the fix (CIRISPersist#642)"
            );
        }

        // ── C — THE ASYMMETRY: a GRANT's pointer confers nothing ─────────
        //
        // Recorded honestly: this OUTCOME is defended TWICE — by `causal_edge`
        // refusing to read a grant's pointer at all, and independently by the
        // ratchet, which would discard the looser answer even if it did.
        // Removing either mechanism alone leaves this leg GREEN, so it is not a
        // witness for the asymmetry itself; that is pinned directly, on the
        // function's own contract, in
        // `consent::causal_fold_tests::causal_edge_is_asymmetric_and_never_degrades_silently`.
        // What this leg proves is the property a consumer depends on: the
        // outcome holds through the real write path on every backend.
        let (subject, attester) = keys(dir, tag, "c").await;
        let revoke_id = uuid::Uuid::new_v4().to_string();
        put(
            consent_scope_row(&revoke_id, &subject, &attester, &revoked, &[analyze], now),
            "the revocation",
        )
        .await;
        put(
            consent_scope_row_superseding(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &granted,
                &[analyze],
                earlier,
                Some(serde_json::Value::String(revoke_id)),
            ),
            "an earlier grant naming the revocation",
        )
        .await;
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Revoked,
            "({tag}) B12-C: `granted` is the sole fail-OPEN stance and carries no causal \
             authority here — an earlier grant naming the revocation must not delete it"
        );

        // ── D — THE RATCHET ──────────────────────────────────────────────
        let (subject, attester) = keys(dir, tag, "d").await;
        let real_revoke = uuid::Uuid::new_v4().to_string();
        put(
            consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &granted,
                &[analyze],
                earlier,
            ),
            "the grant underneath",
        )
        .await;
        put(
            consent_scope_row(&real_revoke, &subject, &attester, &revoked, &[analyze], now),
            "the real revocation",
        )
        .await;
        put(
            consent_scope_row_superseding(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &revoked,
                &[analyze],
                earliest,
                Some(serde_json::Value::String(real_revoke)),
            ),
            "a back-dated revocation naming the real one",
        )
        .await;
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Revoked,
            "({tag}) B12-D: eliminating the real revocation leaves {{grant, back-dated revoke}} \
             and the grant is the later of those. The causal plane may only TIGHTEN — consent is \
             re-opened by an affirmative later grant, never by deleting a refusal"
        );

        // ── E — THE §6.1 RETRACTION FOLD REACHES THIS PLANE ──────────────
        let (subject, attester) = keys(dir, tag, "e").await;
        let only_grant = uuid::Uuid::new_v4().to_string();
        put(
            consent_scope_row(
                &only_grant,
                &subject,
                &attester,
                &granted,
                &[analyze],
                earlier,
            ),
            "the subject's only grant",
        )
        .await;
        put(
            consent_withdraws_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &only_grant,
                now,
            ),
            "the subject's own withdraws (rule 1)",
        )
        .await;
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Unspecified,
            "({tag}) B12-E: the grant was retracted through the substrate's OWN retraction \
             primitive (`precedence::retired_ids`, entitlement-gated). Before #642 the consent \
             fold could not see `withdraws` at all and kept answering Granted"
        );

        // ── F — A DOOR, NOT A WALL ───────────────────────────────────────
        let (subject, attester) = keys(dir, tag, "f").await;
        let first_grant = uuid::Uuid::new_v4().to_string();
        put(
            consent_scope_row(
                &first_grant,
                &subject,
                &attester,
                &granted,
                &[analyze],
                earliest,
            ),
            "the first grant",
        )
        .await;
        put(
            consent_scope_row_superseding(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &revoked,
                &[analyze],
                earlier,
                Some(serde_json::Value::String(first_grant)),
            ),
            "the revocation naming it",
        )
        .await;
        put(
            consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &granted,
                &[analyze],
                now,
            ),
            "the affirmative re-grant",
        )
        .await;
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Granted,
            "({tag}) B12-F: a later grant re-opens consent exactly as it did before the causal \
             plane existed — the edge orders history, it does not freeze it"
        );
        dir.put_attestation(SignedAttestation {
            attestation: capacity_claim(&attester, &subject),
        })
        .await
        .unwrap_or_else(|e| panic!("({tag}) B12-F: …and the gate re-opens with it: {e}"));

        // ── G — THE RESOLUTION UNIVERSE IS THE SUBJECT'S WHOLE HISTORY ────
        //
        // A blanket revocation naming a grant that answers a DIFFERENT scope.
        // The named grant is filtered out of the scoped slice, so a fold that
        // resolved edges against the SLICE would call this an incomplete view
        // and freeze the subject out of a scope it never revoked. Resolving
        // against the subject's whole consent history for the target is what
        // keeps the later `view` grant winning on its own instant.
        let (subject, attester) = keys(dir, tag, "g").await;
        let export_grant = uuid::Uuid::new_v4().to_string();
        put(
            consent_scope_row(
                &export_grant,
                &subject,
                &attester,
                &granted,
                &["export"],
                earliest,
            ),
            "the export grant",
        )
        .await;
        put(
            consent_scope_row_superseding(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &revoked,
                &[],
                earlier,
                Some(serde_json::Value::String(export_grant)),
            ),
            "a BLANKET revocation naming the export grant",
        )
        .await;
        put(
            consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &granted,
                &[analyze],
                now,
            ),
            "a later analyze grant",
        )
        .await;
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Granted,
            "({tag}) B12-G: the blanket revocation's edge RESOLVES against the subject's own \
             history (the export grant is in it), so it carries no unresolved-view restriction \
             and the later grant wins on the clock as it always did"
        );
        assert_eq!(
            dir.resolve_scoped_consent(&attester, &subject, "export", None, chrono::Utc::now())
                .await
                .expect("fold reads"),
            ConsentState::Revoked,
            "({tag}) B12-G: …and on the scope it DID revoke, the blanket revocation still closes \
             the gate — resolving the edge widens nothing"
        );
    }

    /// **B10-c — SUB-MICROSECOND SPACING IS REFUSED, AND A TRUE TIE RESOLVES
    /// RESTRICTIVE.**
    ///
    /// Two properties the three backends previously disagreed about.
    ///
    /// **(1) resolution.** sqlite stores RFC-3339 TEXT and memory holds a
    /// `chrono` `DateTime` — both keep the full nanosecond — while postgres
    /// `TIMESTAMPTZ` truncates to microseconds. So a grant and a revoke 500ns
    /// apart were a strict order on two backends and a TIE on the third: the
    /// same op sequence, two verdicts, decided by which database you asked.
    /// The substrate now REFUSES a bound instant finer than a microsecond
    /// (see [`crate::federation::admission::CONSENT_INSTANT_RESOLUTION_NANOS`]
    /// for why refuse and not truncate), identically on all three.
    ///
    /// **(2) the tie.** With the sub-microsecond pair gone, a genuine tie is
    /// still reachable — two claims in the same microsecond — and the fold had
    /// **no tie-break at all**, so `max_by_key` returned whichever row the
    /// backend's iteration order presented last. It now resolves
    /// RESTRICTION-WINS, deterministically. Driven in BOTH insertion orders on
    /// purpose: a single order can pass by luck on the backend whose row order
    /// happens to favour the revoke, which is exactly how the gap survived.
    pub async fn exercise_consent_tie_restriction_wins(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::consent::consent_dimension;
        use crate::federation::hard_case::ConsentState;

        let analyze = crate::federation::admission::ANALYZE_CONSENT_SCOPE;
        let granted = format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX);
        let revoked = format!("{}:v1", consent_dimension::STATE_REVOKED_PREFIX);
        let base =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now())
                - chrono::Duration::seconds(60);

        // (1) 500ns apart — refused on EVERY backend, so no backend can be the
        // one that reads this pair as a strict order.
        {
            let subject = format!("{tag}-598-ns-subject");
            let attester = format!("{tag}-598-ns-attester");
            for k in [&subject, &attester] {
                crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
            }
            // `consent_scope_row` truncates, so build the sub-microsecond row
            // by hand: bump BOTH the column and the signed envelope so the
            // divergence arm cannot be what refuses it — this arm must fail on
            // RESOLUTION or it is testing the wrong rule.
            let mut row = consent_scope_row(
                &uuid::Uuid::new_v4().to_string(),
                &subject,
                &attester,
                &revoked,
                &[analyze],
                base,
            );
            let skewed = base + chrono::Duration::nanoseconds(500);
            row.asserted_at = skewed;
            let (och, sc, sp) = {
                let mut env = row.attestation_envelope.clone();
                env[crate::federation::envelope::paths::ASSERTED_AT] =
                    serde_json::Value::String(skewed.to_rfc3339());
                let signed =
                    crate::federation::tier_ingest::test_support::sign_envelope(&subject, &env);
                row.attestation_envelope = env;
                // Deliberately NOT `reseal`: the seal TRUNCATES to the
                // substrate resolution, which is the very skew this arm exists
                // to have refused. Re-sealing here truncated the 500ns away and
                // re-signed, and then the hand-computed signature below was
                // written back over the re-sealed envelope — so the row was
                // refused for a FAILED ED25519 VERIFY while the assertion
                // demanded the resolution rule. The comment above already
                // forbade this ("build the sub-microsecond row by hand"); the
                // call contradicted it.
                signed
            };
            row.original_content_hash = och;
            row.scrub_signature_classical = sc;
            row.scrub_signature_pqc = sp;
            let err = dir
                .put_attestation(SignedAttestation { attestation: row })
                .await
                .expect_err(
                    "({tag}) B10-c: a sub-microsecond consent instant must be REFUSED — \
                     postgres TIMESTAMPTZ cannot store it, so admitting it makes the fold's \
                     answer depend on the backend (CIRISPersist#598)",
                );
            let msg = format!("{err}");
            assert!(
                msg.contains("sub-microsecond"),
                "({tag}) B10-c: the refusal must name the RESOLUTION rule, not the binding: \
                 {msg}"
            );
        }

        // (2) a TRUE tie, fed in both orders. Restriction wins, both times,
        // on every backend.
        for (order, first_is_grant) in [("grant-first", true), ("revoke-first", false)] {
            let subject = format!("{tag}-598-tie-{order}-subject");
            let attester = format!("{tag}-598-tie-{order}-attester");
            for k in [&subject, &attester] {
                crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
            }
            // The ids are ADVERSARIAL, not incidental. `fold_ordering_key` is
            // `(asserted_at, restriction_rank, attestation_id)` resolved by
            // `max_by_key`, so at a true instant-tie the id is the THIRD
            // component — and with two random uuids it decides the winner
            // roughly half the time. This arm then passed or failed by luck:
            // deleting the restriction-rank tie-break entirely left it GREEN on
            // whichever backend drew the kinder uuid, which is how it was
            // caught (green on sqlite, red on memory, same binary).
            //
            // So: give the GRANT the lexically LARGER id. If the rank component
            // is ever removed or reordered, the grant wins on id and the
            // assertion below fails on every backend, deterministically. The
            // ids stay real uuids because `attestation_id` is a UUID column on
            // postgres — a symbolic id fails in the driver, before any fold.
            let (lo, hi) = {
                let (a, b) = (
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string(),
                );
                if a < b {
                    (a, b)
                } else {
                    (b, a)
                }
            };
            let mk = |id: &str, dimension: &str| {
                consent_scope_row(id, &subject, &attester, dimension, &[analyze], base)
            };
            let pair = if first_is_grant {
                [mk(&hi, &granted), mk(&lo, &revoked)]
            } else {
                [mk(&lo, &revoked), mk(&hi, &granted)]
            };
            for row in pair {
                dir.put_attestation(SignedAttestation { attestation: row })
                    .await
                    .unwrap_or_else(|e| {
                        panic!("({tag}) B10-c/{order}: both tied stances admit: {e}")
                    });
            }
            assert_eq!(
                dir.resolve_scoped_consent(&attester, &subject, analyze, None, chrono::Utc::now())
                    .await
                    .expect("fold reads"),
                ConsentState::Revoked,
                "({tag}) B10-c/{order}: a grant and a revoke at the SAME instant must resolve \
                 to the RESTRICTIVE stance, in either insertion order and on every backend \
                 (CIRISPersist#598)"
            );
            // The gate inside persist must agree with the fold — the tie-break
            // is only worth anything if it reaches the consumer.
            dir.put_attestation(SignedAttestation {
                attestation: capacity_claim(&attester, &subject),
            })
            .await
            .expect_err(&format!(
                "({tag}) B10-c/{order}: and the tied verdict CLOSES the capacity gate"
            ));
        }
    }
}
