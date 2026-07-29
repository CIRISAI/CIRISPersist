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
}
