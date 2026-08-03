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
        Attestation {
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
        }
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
    /// `asserted_at` is EXPLICIT because the fold is latest-wins on it: a
    /// grant and a revoke minted at the same `Utc::now()` tie, and
    /// `max_by_key` on a tie is unspecified — the sequence must advance.
    pub fn consent_scope_row(
        id: &str,
        subject: &str,
        covers: &str,
        stance_dimension: &str,
        scopes: &[&str],
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let envelope = serde_json::json!({
            "dimension": stance_dimension,
            "scope": scopes,
        });
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(subject, &envelope);
        Attestation {
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
        }
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
        Attestation {
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
        }
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
            Attestation {
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
            }
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
    }

    // ── CIRISPersist#589 — THE RED DEMO (temporary, pre-fix) ───────────
    /// TEMPORARY: assert the #589 exploit SUCCEEDS, so the premise is
    /// executed rather than read. Deleted / inverted by the fix.
    pub async fn exercise_589_red_demo(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::types::{attestation_tier, cohort_scope};

        let run = uuid::Uuid::new_v4().simple().to_string();
        let attester = format!("{tag}-p589-{run}"); // P — the scorer
        let subject = format!("{tag}-s589-{run}"); // S — the scored, silent
        for k in [&attester, &subject] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }
        const DIM: &str = "capacity:composite:v1";

        // Control: the DIRECT federation-tier write is refused (B5 holds).
        let direct = dir
            .put_attestation(SignedAttestation {
                attestation: scores_row(
                    &uuid::Uuid::new_v4().to_string(),
                    &attester,
                    &subject,
                    DIM,
                ),
            })
            .await;
        eprintln!("[589/{tag}] CONTROL direct federation-tier put: {direct:?}");
        assert!(direct.is_err(), "[589/{tag}] control: direct write refused");

        // (1) THE LOCAL DOOR — `put_attestation` at tier=local.
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = scores_row(&id, &attester, &subject, DIM);
        row.tier = attestation_tier::LOCAL.to_owned();
        row.cohort_scope = cohort_scope::FEDERATION.to_owned();
        let och = row.original_content_hash.clone();
        let sc = row.scrub_signature_classical.clone();
        let sp = row.scrub_signature_pqc.clone();
        let local_put = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await;
        eprintln!("[589/{tag}] BEFORE (1) put_attestation tier=local capacity: {local_put:?}");
        local_put.expect("[589] the local-tier capacity row is ADMITTED (the open door)");

        // (2) THE PROMOTE — no tier-4 gate re-runs.
        let promoted = dir
            .promote_attestation(&id, &sc, sp.as_deref(), &och, &attester, chrono::Utc::now())
            .await;
        eprintln!("[589/{tag}] BEFORE (2) promote_attestation: {promoted:?}");
        assert!(
            promoted.expect("[589] promote succeeds"),
            "[589] promote flipped the tier"
        );

        // (3) THE ARTIFACT — a federation-tier capacity:composite row about a
        // subject that granted nothing. CC 3.4.5: MUST NOT be emitted.
        let after = dir
            .get_attestation(&id)
            .await
            .expect("read back")
            .expect("row");
        eprintln!(
            "[589/{tag}] BEFORE (3) stored row: tier={} cohort_scope={} dimension={:?} \
             attester={} subject={} promoted_at={:?}",
            after.tier,
            after.cohort_scope,
            crate::federation::admission::envelope_dimension(&after.attestation_envelope),
            after.attesting_key_id,
            after.attested_key_id,
            after.promoted_at,
        );
        assert_eq!(
            after.tier,
            attestation_tier::FEDERATION,
            "[589] EXPLOIT CONFIRMED: a federation-tier capacity:composite row exists \
             for a subject with no analyze consent"
        );
    }
}
