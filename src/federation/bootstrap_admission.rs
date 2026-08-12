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
    pub fn consent_scope_row(
        id: &str,
        subject: &str,
        covers: &str,
        stance_dimension: &str,
        scopes: &[&str],
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let asserted_at =
            crate::federation::admission::truncate_to_substrate_resolution(asserted_at);
        let envelope = serde_json::json!({
            "dimension": stance_dimension,
            "scope": scopes,
            crate::federation::envelope::paths::ASSERTED_AT: asserted_at.to_rfc3339(),
        });
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

    /// **B8 (CIRISPersist#589 / AV-83) — a PROMOTION faces the tier-4 stack,
    /// and `capacity:*` never reaches the local tier at all.**
    ///
    /// # The hole this closes
    ///
    /// `Engine::attestation_promote` and the backends' `promote_attestation` /
    /// `promote_attestation_transformed` re-signed a row and flipped `tier`
    /// local→federation while running **no** put-gate whatsoever. Every gate
    /// that no-ops at the local tier had therefore never been asked about a
    /// promoted row, and promotion is the moment those rows become
    /// federation-tier.
    ///
    /// CC 3.4.5's reciprocity clause is what turned that from a gap into a
    /// **MUST** violation: a subject that declines analysis *"cannot be scored;
    /// its `capacity:composite` is undefined and MUST NOT be emitted"*. The
    /// two-step below minted exactly that row, and because `capacity:composite`
    /// is `min` over five factors, one leaked row certifies five.
    ///
    /// The sharp part, and the reason this is the SHIPPED-means-host-reachable
    /// class a third time (after AV-77 and #444's route table): the rule
    /// *"capacity is never local"* was already written, tested and shipped in
    /// [`crate::federation::admission::check_local_tier_eligibility`] — behind a
    /// door the attack does not use. `put_attestation` accepts `tier = "local"`
    /// on every backend and never called it.
    ///
    /// # What it pins, on every backend
    ///
    /// (a) the local-tier `capacity:*` write is REFUSED, and the refusal names
    /// the LOCAL-TIER rule rather than consent — the accurate rule, since the
    /// row would be inadmissible even with a live grant; (b) the TYPE-keyed
    /// wire shape is refused too (one-shape answers are the AV-74 mistake at a
    /// new address); (c) an ordinary local row still admits and still promotes,
    /// so the gate is a rule and not a lockdown; (d) THE CLASS, not the
    /// symptom: a row whose author this node de-admits AFTER the local write is
    /// refused at promotion — AV-77 reaching the promote door, which it never
    /// did before, and which no amount of capacity-specific fixing would have
    /// closed; (e) a REFUSED promotion leaves the row BYTE-IDENTICAL (AV-9),
    /// which is the property the old `set_attestation_cohort_scope`-then-promote
    /// two-step could not hold once promotion could refuse; and (f) the
    /// incoherent `(federation, self)` placement is refused by the PRIMITIVE,
    /// not merely by `Engine::attestation_promote`, so a caller that skips the
    /// Engine cannot mint the #315 dead-plane row.
    pub async fn exercise_promotion_admission_gate(
        dir: &dyn FederationDirectory,
        self_key_id: &str,
        tag: &str,
    ) {
        use crate::federation::admission::PEER_DEADMISSION_DIMENSION;
        use crate::federation::types::{attestation_tier, cohort_scope};

        // Invocation-unique — the postgres arm shares a long-lived database.
        let run = uuid::Uuid::new_v4().simple().to_string();
        let attester = format!("{tag}-p589-{run}"); // P — the scorer
        let subject = format!("{tag}-s589-{run}"); // S — the scored, and silent
        for k in [self_key_id, &attester, &subject] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }
        const DIM: &str = "capacity:composite:v1";

        // Build a LOCAL-tier row: the shape `put_attestation` used to admit.
        let local_row = |id: &str, dimension: &str, att_type: Option<&str>| {
            let mut row = scores_row(id, &attester, &subject, dimension);
            if let Some(t) = att_type {
                row.attestation_type = t.to_owned();
                crate::federation::tier_ingest::test_support::reseal(&mut row);
            }
            row.tier = attestation_tier::LOCAL.to_owned();
            row.cohort_scope = cohort_scope::SELF.to_owned();
            crate::federation::tier_ingest::test_support::reseal(&mut row);
            row
        };

        // ── (a) THE DOOR IS SHUT — capacity:* is never local. ──────────
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

        // ── (b) BOTH WIRE SHAPES — the type-keyed form too. ────────────
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

        // ── (c) NOT A LOCKDOWN — an ordinary local row admits AND promotes.
        let ok_id = uuid::Uuid::new_v4().to_string();
        let ok_row = local_row(&ok_id, "trust:demo:v1", None);
        let (ok_och, ok_sc, ok_sp) = (
            ok_row.original_content_hash.clone(),
            ok_row.scrub_signature_classical.clone(),
            ok_row.scrub_signature_pqc.clone(),
        );
        dir.put_attestation(SignedAttestation {
            attestation: ok_row,
        })
        .await
        .expect("({tag}) B8: an ordinary local row still admits");
        assert!(
            dir.promote_attestation(
                &ok_id,
                cohort_scope::FEDERATION,
                &ok_sc,
                ok_sp.as_deref(),
                &ok_och,
                &attester,
                chrono::Utc::now(),
            )
            .await
            .expect("({tag}) B8: an ordinary promotion still succeeds"),
            "({tag}) B8: and it flips the tier"
        );

        // Arm (f)'s row belongs to a SECOND author who is never de-admitted, so
        // that arm proves the placement rule and only the placement rule. Using
        // `attester` would make it refusable for two independent reasons at
        // once, and the assertion would then silently depend on which gate runs
        // first — a witness that passes for a reason it does not name.
        let bystander = format!("{tag}-b589-{run}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &bystander).await;
        let self_id = uuid::Uuid::new_v4().to_string();
        let mut self_row = scores_row(&self_id, &bystander, &subject, "trust:demo:v1");
        self_row.tier = attestation_tier::LOCAL.to_owned();
        self_row.cohort_scope = cohort_scope::SELF.to_owned();
        crate::federation::tier_ingest::test_support::reseal(&mut self_row);
        let (s_och, s_sc, s_sp) = (
            self_row.original_content_hash.clone(),
            self_row.scrub_signature_classical.clone(),
            self_row.scrub_signature_pqc.clone(),
        );
        dir.put_attestation(SignedAttestation {
            attestation: self_row,
        })
        .await
        .expect("({tag}) B8: arm (f)'s local row admits");

        // ── (d) THE CLASS, NOT THE SYMPTOM ────────────────────────────
        // A local row written while its author was in good standing, promoted
        // AFTER this node de-admits that author. Before AV-83 the promotion
        // sailed through: AV-77 lives in `put_attestation` and promote called
        // nothing. Nothing about `capacity:*` is involved — closing only the
        // capacity arm would have left this exactly as it was.
        let doomed_id = uuid::Uuid::new_v4().to_string();
        let doomed = local_row(&doomed_id, "trust:demo:v1", None);
        let (d_och, d_sc, d_sp) = (
            doomed.original_content_hash.clone(),
            doomed.scrub_signature_classical.clone(),
            doomed.scrub_signature_pqc.clone(),
        );
        dir.put_attestation(SignedAttestation {
            attestation: doomed,
        })
        .await
        .expect("({tag}) B8: the local write lands while the author is in good standing");
        let before = dir
            .get_attestation(&doomed_id)
            .await
            .expect("read back")
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

        let err = dir
            .promote_attestation(
                &doomed_id,
                cohort_scope::FEDERATION,
                &d_sc,
                d_sp.as_deref(),
                &d_och,
                &attester,
                chrono::Utc::now(),
            )
            .await
            .expect_err(
                "({tag}) B8: promoting a DE-ADMITTED author's row must be refused — AV-77 \
                 reaching the promote door for the first time",
            );
        assert!(
            format!("{err}").contains("de-admitted"),
            "({tag}) B8: the refusal names the de-admission: {err}"
        );

        // ── (e) A REFUSED PROMOTION MUTATES NOTHING (AV-9). ────────────
        // The property the old pre-stamp two-step could not hold: it rewrote
        // `cohort_scope` + `persist_row_hash` before promotion could refuse.
        let after = dir
            .get_attestation(&doomed_id)
            .await
            .expect("read back")
            .expect("row");
        assert_eq!(
            after.tier,
            attestation_tier::LOCAL,
            "({tag}) B8: a refused promotion leaves the row at its original tier"
        );
        assert_eq!(
            after.cohort_scope, before.cohort_scope,
            "({tag}) B8: and does NOT stamp the target placement"
        );
        assert_eq!(
            after.persist_row_hash, before.persist_row_hash,
            "({tag}) B8: byte-identical — the substrate state machine's I2a, at unit scale"
        );

        // ── (f) THE PRIMITIVE OWNS THE PLACEMENT RULE. ────────────────
        // `(federation, self)` is the #315 incoherent state. It was refused by
        // `Engine::attestation_promote` only, so any caller reaching the
        // directory directly could mint it. Authored by `bystander`, who is in
        // good standing, so the ONLY reason this promotion can be refused is
        // the placement itself.
        let err = dir
            .promote_attestation(
                &self_id,
                cohort_scope::SELF,
                &s_sc,
                s_sp.as_deref(),
                &s_och,
                &bystander,
                chrono::Utc::now(),
            )
            .await
            .expect_err("({tag}) B8: (federation, self) is refused by the primitive itself");
        assert!(
            format!("{err}").contains("self"),
            "({tag}) B8: the refusal names the placement: {err}"
        );

        // ── (g) THE LEGACY ROW — why the consent arm is not dead code. ──
        // Arm (a) means a `capacity:*` row can no longer ENTER the local tier,
        // so no sequence starting from an empty corpus can drive one into
        // `check_promotion_admission`'s consent arm. That is a fair question to
        // ask of any gate ("SHIPPED means host-reachable", read in reverse: an
        // arm nothing can reach is an arm nobody proves), and it has a concrete
        // answer rather than a defence-in-depth hand-wave.
        //
        // Every release up to and including v25.1.0 ADMITTED local-tier
        // `capacity:*` through `put_attestation`. Deployments therefore hold
        // exactly these rows already, and the upgrade does not delete them —
        // the local door closing does nothing about a row that is already
        // inside. The promotion gate is what stops those rows federating, and
        // it is the arm that enforces the CC 3.4.5 MUST directly.
        //
        // Driven against the gate itself: manufacturing the row through the
        // storage layer would need a different bypass on each backend, and what
        // needs proving is the VERDICT — which every backend answers through
        // this one shared predicate, so it is checked on all three here.
        let mut legacy = scores_row(&uuid::Uuid::new_v4().to_string(), &bystander, &subject, DIM);
        legacy.tier = attestation_tier::FEDERATION.to_owned();
        legacy.cohort_scope = cohort_scope::FEDERATION.to_owned();
        crate::federation::tier_ingest::test_support::reseal(&mut legacy);
        let err = crate::federation::admission::check_promotion_admission(dir, &legacy, None)
            .await
            .expect_err(
                "({tag}) B8: promoting a pre-v26.0.0 local capacity row must be refused — \
                 CC 3.4.5: its capacity:composite MUST NOT be emitted",
            );
        assert!(
            matches!(&err, crate::federation::Error::ConsentGateRefused(r)
                if r.family == crate::federation::ConsentGatedFamily::Capacity
                    && r.dimension == DIM),
            "({tag}) B8: and the refusal names the CAPACITY consent rule: {err:?}"
        );

        // The same row with the subject's live `analyze` grant admits — the
        // arm is the CONSENT rule, not a blanket ban on promoting capacity.
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
            .expect("({tag}) B8: with a live analyze grant the same promotion is admitted");
    }

    /// **B9 (CIRISPersist#592 / AV-84) — a TARGETED-COHORT placement is a
    /// producer self-declaration, or it is refused.**
    ///
    /// # The hole this closes
    ///
    /// AV-45 at `put_attestation` asks *"is the writer a member of the target
    /// cohort it names?"* On `federation_attestations` that question is
    /// **unaskable** — the row carries a `cohort_scope` and no
    /// `cohort_target_id` — so the put door answers it the only honest way it
    /// can: `family` / `community` are refused outright. That door is SHUT,
    /// not leaking.
    ///
    /// The promote door cannot copy that answer, because promotion is the only
    /// door those placements have ever had; copying it would delete the
    /// #519/#510 audience plane. CIRISPersist#589 wrote down why the asymmetry
    /// is defensible — a promotion *"re-publishes a row this node itself
    /// authored … a self-declaration about its own content's visibility, not a
    /// claim about someone else's cohort"* — and **nothing enforced that
    /// sentence.** `attestation_promote` is a raw primitive that will place ANY
    /// local row into the `community` plane, including one authored by, and
    /// about, a peer; and `promote_consented_backlog` pages
    /// `WHERE tier = 'local'` with no author predicate, so a peer's row is
    /// promoted under THIS node's grant and THIS node's fresh signature.
    ///
    /// So the excuse for AV-45's absence was itself unchecked. B9 makes it a
    /// gate: the one cohort placement the promote door CAN adjudicate without a
    /// target is the producer's own content, and it now has to actually be
    /// that.
    ///
    /// # What it pins, on every backend
    ///
    /// (a) a THIRD-PARTY row — a verdict by P about S — is refused at
    /// `community`, and the refusal names the standing rule rather than a
    /// membership the row could never have expressed; (b) the same at `family`;
    /// (c) **NOT A LOCKDOWN**: that identical row still promotes at
    /// `federation`, because a broad belonging-tier has no cohort to belong to
    /// and AV-45 itself admits any authenticated writer there; (d) **THE
    /// AUDIENCE PLANE SURVIVES** — a producer's own row promotes to `community`
    /// exactly as #510's `audience: community` grant needs it to; (e) the
    /// refused promotion leaves the row byte-identical (AV-9), the same
    /// property B8 pins for the gates it added; and (f) **THE SECOND DOOR** —
    /// the same verdict, the same error kind, at `set_attestation_cohort_scope`,
    /// which is how the #530 repair motion places a row and whose broaden-only
    /// guard lets `community` straight through. A gate on one door and a motion
    /// using the other is this repo's own recurring class.
    pub async fn exercise_promotion_cohort_standing_gate(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::types::{attestation_tier, cohort_scope};

        // Invocation-unique — the postgres arm shares a long-lived database.
        let run = uuid::Uuid::new_v4().simple().to_string();
        let producer = format!("{tag}-p592-{run}"); // P — the row's author
        let stranger = format!("{tag}-s592-{run}"); // S — the party P names
        for k in [&producer, &stranger] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }

        // A LOCAL-tier row by P ABOUT S. Nothing about it is malformed: P is
        // registered and in good standing, the dimension is ordinary, the
        // signature is real. The only thing wrong with promoting it into a
        // cohort plane is that it is not P's own content.
        let third_party = |id: &str| {
            let mut row = scores_row(id, &producer, &stranger, "trust:demo:v1");
            row.tier = attestation_tier::LOCAL.to_owned();
            row.cohort_scope = cohort_scope::SELF.to_owned();
            crate::federation::tier_ingest::test_support::reseal(&mut row);
            row
        };
        // …and P's OWN row: it names nobody but P.
        let own = |id: &str| {
            let mut row = scores_row(id, &producer, &producer, "trust:demo:v1");
            row.tier = attestation_tier::LOCAL.to_owned();
            row.cohort_scope = cohort_scope::SELF.to_owned();
            crate::federation::tier_ingest::test_support::reseal(&mut row);
            row
        };

        let store = |row: Attestation| async {
            let (id, och, sc, sp) = (
                row.attestation_id.clone(),
                row.original_content_hash.clone(),
                row.scrub_signature_classical.clone(),
                row.scrub_signature_pqc.clone(),
            );
            dir.put_attestation(SignedAttestation { attestation: row })
                .await
                .expect("B9: the local write itself is admissible");
            (id, och, sc, sp)
        };

        // ── (a) + (b) THE HOLE: a stranger's row into a cohort plane. ──
        for scope in [cohort_scope::COMMUNITY, cohort_scope::FAMILY] {
            let (id, och, sc, sp) = store(third_party(&uuid::Uuid::new_v4().to_string())).await;
            let before = dir
                .get_attestation(&id)
                .await
                .expect("read back")
                .expect("row");
            let err = dir
                .promote_attestation(
                    &id,
                    scope,
                    &sc,
                    sp.as_deref(),
                    &och,
                    &producer,
                    chrono::Utc::now(),
                )
                .await
                .expect_err(
                    "({tag}) B9: promoting a row that names a THIRD PARTY into a targeted \
                     cohort plane must be refused — this is the #592 open door",
                );
            assert_eq!(
                err.kind(),
                "federation_cohort_standing_refused",
                "({tag}) B9: every backend refuses at the SAME error kind: {err:?}"
            );
            let msg = format!("{err}");
            assert!(
                msg.contains(scope) && msg.contains(&stranger),
                "({tag}) B9: the refusal names the placement and the party the row is not \
                 entitled to publish about — not a membership the row could never express: {msg}"
            );

            // ── (e) AV-9 — a refused promotion mutates nothing. ────────
            let after = dir
                .get_attestation(&id)
                .await
                .expect("read back")
                .expect("row");
            assert_eq!(
                after.tier,
                attestation_tier::LOCAL,
                "({tag}) B9: a refused promotion leaves the row at its original tier"
            );
            assert_eq!(
                after.cohort_scope, before.cohort_scope,
                "({tag}) B9: and does NOT stamp the target placement"
            );
            assert_eq!(
                after.persist_row_hash, before.persist_row_hash,
                "({tag}) B9: byte-identical"
            );
        }

        // ── (c) NOT A LOCKDOWN — the SAME row promotes at a broad tier. ──
        // AV-45's own rule for `affiliations` / `species` / `biosphere` /
        // `federation` is "no per-row target; any authenticated writer may
        // emit". B9 is the targeted-cohort arm and must not become a general
        // ban on promoting third-party rows — that would be a different gate,
        // silently widened under this one's name.
        {
            let (id, och, sc, sp) = store(third_party(&uuid::Uuid::new_v4().to_string())).await;
            assert!(
                dir.promote_attestation(
                    &id,
                    cohort_scope::FEDERATION,
                    &sc,
                    sp.as_deref(),
                    &och,
                    &producer,
                    chrono::Utc::now(),
                )
                .await
                .expect("({tag}) B9: a broad-tier promotion of the same row still succeeds"),
                "({tag}) B9: and it flips the tier"
            );
        }

        // ── (d) THE AUDIENCE PLANE SURVIVES. ──────────────────────────
        // The #519/#510 motion this gate must not amputate: a producer's own
        // row, promoted to the audience its own signed grant named.
        {
            let (id, och, sc, sp) = store(own(&uuid::Uuid::new_v4().to_string())).await;
            assert!(
                dir.promote_attestation(
                    &id,
                    cohort_scope::COMMUNITY,
                    &sc,
                    sp.as_deref(),
                    &och,
                    &producer,
                    chrono::Utc::now(),
                )
                .await
                .expect(
                    "({tag}) B9: a producer's OWN row still reaches the community plane — \
                     the #510 audience plane is intact"
                ),
                "({tag}) B9: and it flips the tier"
            );
            let after = dir
                .get_attestation(&id)
                .await
                .expect("read back")
                .expect("row");
            assert_eq!(after.cohort_scope, cohort_scope::COMMUNITY);
        }

        // ── (f) THE SECOND DOOR. ──────────────────────────────────────
        // `promote_attestation` is not the only way a row acquires a
        // placement: `Engine::repair_stranded_scope_backlog` (CIRISPersist#530)
        // re-scopes an ALREADY-federation row to a covering grant's audience
        // via `set_attestation_cohort_scope`, and its broaden-only guard skips
        // only `self`/`family` — `community` goes straight through. A gate on
        // one door and a motion using the other is this repo's own recurring
        // defect; the standing rule therefore lives at BOTH placement doors,
        // and both leave a refused row byte-identical.
        {
            let stranded_id = uuid::Uuid::new_v4().to_string();
            dir.put_attestation(SignedAttestation {
                attestation: scores_row(&stranded_id, &producer, &stranger, "trust:demo:v1"),
            })
            .await
            .expect("({tag}) B9: the federation-tier third-party row admits");
            let before = dir
                .get_attestation(&stranded_id)
                .await
                .expect("read back")
                .expect("row");
            let err = dir
                .set_attestation_cohort_scope(&stranded_id, cohort_scope::COMMUNITY)
                .await
                .expect_err(
                    "({tag}) B9: re-scoping a third-party row into a cohort plane must be \
                     refused at the repair door too",
                );
            assert_eq!(
                err.kind(),
                "federation_cohort_standing_refused",
                "({tag}) B9: the same verdict, the same kind, at both doors: {err:?}"
            );
            let after = dir
                .get_attestation(&stranded_id)
                .await
                .expect("read back")
                .expect("row");
            assert_eq!(
                after.cohort_scope, before.cohort_scope,
                "({tag}) B9: a refused re-scope stamps nothing"
            );
            assert_eq!(
                after.persist_row_hash, before.persist_row_hash,
                "({tag}) B9: byte-identical — memory holds this as tightly as the SQL backends"
            );

            // And the producer's own row still re-scopes: the repair motion is
            // narrowed, not disabled.
            let own_id = uuid::Uuid::new_v4().to_string();
            dir.put_attestation(SignedAttestation {
                attestation: scores_row(&own_id, &producer, &producer, "trust:demo:v1"),
            })
            .await
            .expect("({tag}) B9: the federation-tier own row admits");
            dir.set_attestation_cohort_scope(&own_id, cohort_scope::COMMUNITY)
                .await
                .expect("({tag}) B9: the #530 repair motion still works on a producer's own row");
        }
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
        assert!(
            format!("{err}").contains("643"),
            "({tag}) B11-i: the refusal must name the rule: {err}"
        );

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
                crate::federation::tier_ingest::test_support::reseal(&mut row);
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
            let mk = |dimension: &str| {
                consent_scope_row(
                    &uuid::Uuid::new_v4().to_string(),
                    &subject,
                    &attester,
                    dimension,
                    &[analyze],
                    base,
                )
            };
            let pair = if first_is_grant {
                [mk(&granted), mk(&revoked)]
            } else {
                [mk(&revoked), mk(&granted)]
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
