//! CIRISPersist#1042 — witnesses for the typed, RETRYABLE ordering-gap refusal
//! (`Error::AttesterKeyUnknown`, kind `federation_attester_key_unknown`; on the
//! key plane `KeyRefusalReason::AttesterKeyUnknown`, token
//! `attester_key_unknown`), kept apart from the TERMINAL bad-signature verdict.
//! One body per plane over `&dyn FederationDirectory`, run by memory, sqlite
//! and postgres so the three cannot diverge.
//!
//! Each body is the same three steps the issue names: an unknown signer is
//! the ordering gap; a KNOWN signer with a signature over other bytes is the
//! terminal verdict; once the signer's Key row lands the SAME row admits.
//!
//! v54.1.0 (#1042 follow-ups, CIRISEdge#858): I630 — the signer-acts-for arm
//! is the retryable `federation_signer_not_acting_for` on all four doors that
//! ask it; I631 — a backend failure of the shared envelope verifier's attester
//! lookup propagates as itself, never as a verdict.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::register::{self, KeyRefusalReason, ReplicatedKeyOutcome};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{
        Attestation, Error, FederationDirectory, SignedAttestation, SignedKeyRecord,
    };

    /// The kind every plane's ordering gap reports.
    const GAP: &str = "federation_attester_key_unknown";

    /// **I613 — the key plane.** A record scrubbed by a key this node does not
    /// hold: the direct registration gate (`verify_key_registration`, the one
    /// `register_federation_key` runs) reports the gap, and the replicated
    /// Insert arm returns the typed `attester_key_unknown` refusal (before
    /// v54.1.0: a bare `Err`, CIRISEdge#858). A known scrubber whose signature
    /// covers other bytes is the terminal `unverifiable_signature`. After the
    /// scrubber's Key row lands, the same record is inserted.
    pub async fn i613_key_plane(d: &dyn FederationDirectory, s: &str) {
        let anchor = format!("i613-anchor-{s}");
        let k = format!("i613-k-{s}");
        let record = ts::replicated_key_record(&k, AGENT, &anchor, &anchor, "n1");

        let direct = register::verify_key_registration(d, &record)
            .await
            .expect_err("I613: an unknown scrubber cannot be verified");
        assert_eq!(direct.kind(), GAP, "I613: direct door: {direct}");
        assert!(
            matches!(&direct, Error::AttesterKeyUnknown { attesting_key_id, plane: "key_registration" } if *attesting_key_id == anchor),
            "I613: the gap names the scrubber: {direct:?}"
        );

        let out = d
            .apply_replicated_key_record(SignedKeyRecord {
                record: record.clone(),
            })
            .await
            .expect("I613: a refusal is an outcome, never a bare Err");
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::AttesterKeyUnknown
            },
            "I613: replicated Insert, unknown scrubber"
        );
        assert_eq!(
            KeyRefusalReason::AttesterKeyUnknown.as_str(),
            "attester_key_unknown"
        );
        assert!(
            d.lookup_public_key(&k).await.unwrap().is_none(),
            "I613: nothing stored on the refusal"
        );

        // The scrubber's Key row lands.
        ts::register_identity_key(d, &anchor, NODE).await;

        // A known scrubber, a signature over OTHER bytes: terminal.
        let other = ts::replicated_key_record(&k, AGENT, &anchor, &anchor, "n2");
        let mut forged = record.clone();
        forged.scrub_signature_classical = other.scrub_signature_classical;
        forged.scrub_signature_pqc = other.scrub_signature_pqc;
        let terminal = register::verify_key_registration(d, &forged)
            .await
            .expect_err("I613: a signature over other bytes does not verify");
        assert_eq!(
            terminal.kind(),
            "federation_signature_invalid",
            "I613: direct door, known scrubber: {terminal}"
        );
        let out = d
            .apply_replicated_key_record(SignedKeyRecord { record: forged })
            .await
            .expect("I613: a refusal is an outcome");
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::UnverifiableSignature
            },
            "I613: replicated Insert, known scrubber, bad signature"
        );
        assert!(d.lookup_public_key(&k).await.unwrap().is_none());

        // The SAME record, re-offered, now admits.
        let out = d
            .apply_replicated_key_record(SignedKeyRecord { record })
            .await
            .unwrap();
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Inserted,
            "I613: re-offered after the key plane"
        );
    }

    /// **I614 — the identity_occurrence plane** (the 2026-10-08 fresh-install
    /// defect). `put_identity_occurrence` is the one door for the wire and the
    /// HTTP route. A signer this node does not hold reports the gap; a known
    /// signer with a signature over another envelope is the terminal
    /// `federation_signature_invalid`; after the signer's Key row lands the
    /// same row admits.
    pub async fn i614_occurrence_plane(d: &dyn FederationDirectory, s: &str) {
        let identity = format!("i614-id-{s}");
        let occurrence = format!("i614-occ-{s}");
        let at = chrono::Utc::now();
        // The occurrence's own Key row is held; only the SIGNER's is missing.
        ts::register_identity_key(d, &occurrence, AGENT).await;
        let signed =
            ts::signed_content_only_occurrence(&identity, &identity, &occurrence, at).await;

        let gap = d
            .put_identity_occurrence(signed.clone())
            .await
            .expect_err("I614: an unknown signer cannot be verified");
        assert_eq!(gap.kind(), GAP, "I614: {gap}");
        assert!(
            matches!(&gap, Error::AttesterKeyUnknown { attesting_key_id, plane: "identity_occurrence" } if *attesting_key_id == identity),
            "I614: {gap:?}"
        );

        ts::register_identity_key(d, &identity, USER).await;

        let other_occ = format!("i614-other-{s}");
        ts::register_identity_key(d, &other_occ, AGENT).await;
        let other = ts::signed_content_only_occurrence(&identity, &identity, &other_occ, at).await;
        let mut forged = signed.clone();
        forged.signature = other.signature;
        let terminal = d
            .put_identity_occurrence(forged)
            .await
            .expect_err("I614: a signature over another envelope does not verify");
        assert_eq!(
            terminal.kind(),
            "federation_signature_invalid",
            "I614: {terminal}"
        );

        d.put_identity_occurrence(signed)
            .await
            .expect("I614: the same row admits after the key plane");
    }

    /// A self-scored federation-tier row by `attester`, sealed (the erasable
    /// witnesses' shape).
    fn scored_row(attester: &str, id: &str) -> Attestation {
        let envelope = serde_json::json!({
            "id": id,
            "dimension": "identity_binding:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        let now = chrono::Utc::now();
        let mut row = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attester.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: Some(1.0),
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: attestation_tier::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        ts::seal_row_in_place(attester, &mut row);
        row
    }

    /// **I615 — the attestation plane** (`put_attestation`, the door the
    /// replication apply and the direct route share). An attester this node
    /// does not hold reports the gap at the door's attester lookup (before
    /// v54.1.0: `federation_invalid_argument`; and where that lookup is
    /// passed, the shared envelope verifier — which also serves revocations
    /// and the group planes — reported the terminal
    /// `federation_federation_tier_unverified`); a known attester with a
    /// signature over other bytes keeps that terminal kind; after the
    /// attester's Key row lands the same row admits.
    pub async fn i615_signed_envelope_plane(d: &dyn FederationDirectory, s: &str) {
        let attester = format!("i615-att-{s}");
        let row = scored_row(&attester, &format!("i615-a-{s}"));

        let gap = d
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .expect_err("I615: an unknown attester cannot be verified");
        assert_eq!(gap.kind(), GAP, "I615: {gap}");
        assert!(
            matches!(&gap, Error::AttesterKeyUnknown { attesting_key_id, plane: "attestation" } if *attesting_key_id == attester),
            "I615: {gap:?}"
        );

        ts::register_hybrid_key(d, &attester).await;

        let other = scored_row(&attester, &format!("i615-b-{s}"));
        let mut forged = row.clone();
        forged.scrub_signature_classical = other.scrub_signature_classical;
        forged.scrub_signature_pqc = other.scrub_signature_pqc;
        let terminal = d
            .put_attestation(SignedAttestation {
                attestation: forged,
            })
            .await
            .expect_err("I615: a signature over other bytes does not verify");
        assert_eq!(
            terminal.kind(),
            "federation_federation_tier_unverified",
            "I615: {terminal}"
        );

        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("I615: the same row admits after the key plane");
    }

    /// The kind of the signer-acts-for ordering gap.
    const NOT_ACTING: &str = "federation_signer_not_acting_for";

    /// Assert `e` is the signer-acts-for gap naming `signer`, `identity` and
    /// `plane` exactly.
    fn expect_not_acting(e: &Error, signer: &str, identity: &str, plane: &str, what: &str) {
        assert_eq!(e.kind(), NOT_ACTING, "{what}: {e}");
        assert!(
            matches!(e, Error::SignerDoesNotActFor { attesting_key_id, identity_key_id, plane: p, .. }
                if attesting_key_id == signer && identity_key_id == identity && *p == plane),
            "{what}: {e:?}"
        );
    }

    /// Land `{identity → occurrence}` as an ACTIVE occurrence (the binding
    /// whose absence was the gap).
    async fn bind(d: &dyn FederationDirectory, identity: &str, occurrence: &str) {
        d.put_identity_occurrence_local(crate::federation::IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            device_class: crate::federation::types::device_class::AGENT.into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("the binding lands");
    }

    /// **I630 (#1042 follow-up, CIRISEdge#858) — the signer-acts-for arm is
    /// the retryable `federation_signer_not_acting_for`, on every door that
    /// asks it.** A REGISTERED signer whose signature verifies but who is not
    /// yet an active occurrence of the identity the row is about: on the
    /// `identity_occurrence`, `identity_occurrence_revocation`,
    /// `transport_destination` and `touch_claim` doors the refusal names the
    /// signer, the identity and the door (before: the terminal
    /// `federation_signature_invalid`). Once the binding lands, the SAME row
    /// admits.
    #[allow(clippy::too_many_lines)]
    pub async fn i630_signer_not_acting_for_is_retryable(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::freshness::test_support::signed_claim;
        use crate::federation::self_at_login::test_support::route;
        use crate::federation::types::{cohort_scope, SignerForm};
        let k = |n: &str| format!("i630{n}-{s}");
        let identity = k("id");
        ts::register_identity_key(d, &identity, USER).await;
        let at = chrono::Utc::now() - chrono::Duration::minutes(5);

        // identity_occurrence: `so` vouches for `o` before `so` is bound.
        let (so, o) = (k("so"), k("o"));
        ts::register_identity_key(d, &so, AGENT).await;
        ts::register_identity_key(d, &o, AGENT).await;
        let occ = ts::signed_content_only_occurrence(&so, &identity, &o, at).await;
        let e = d
            .put_identity_occurrence(occ.clone())
            .await
            .expect_err("I630: an unbound signer cannot vouch yet");
        expect_not_acting(&e, &so, &identity, "identity_occurrence", "I630 occurrence");
        bind(d, &identity, &so).await;
        d.put_identity_occurrence(occ)
            .await
            .expect("I630: the same occurrence admits once the signer is bound");

        // identity_occurrence_revocation: `sr` revokes `o` before `sr` is bound.
        let sr = k("sr");
        ts::register_identity_key(d, &sr, AGENT).await;
        // v58.0.0 (CIRISPersist#991, CC 3.3.6) — the revocation is a
        // `withdraws` on the occurrence's row; the same signer_acts_for rule.
        let rev = ts::occurrence_withdrawal(d, &sr, &identity, &o, chrono::Utc::now()).await;
        let e = d
            .put_attestation(rev.clone())
            .await
            .expect_err("I630: an unbound signer cannot revoke yet");
        expect_not_acting(
            &e,
            &sr,
            &identity,
            "identity_occurrence_withdraws",
            "I630 revocation",
        );
        bind(d, &identity, &sr).await;
        d.put_attestation(rev)
            .await
            .expect("I630: the same revocation admits once the signer is bound");

        // transport_destination: `st` asserts the identity's route.
        let st = k("st");
        ts::register_identity_key(d, &st, AGENT).await;
        let r = route(&identity, "reticulum", "d1", 0, "2026-06-10T00:00:00Z");
        let signer = ts::hybrid_identity(&st);
        let (env, sig) = ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
            signer.as_ref(),
            serde_json::to_value(&r).unwrap(),
        )
        .await
        .unwrap();
        let td = crate::federation::self_at_login::SignedTransportDestination {
            transport_destination: r,
            attesting_key_id: st.clone(),
            signed_envelope: env,
            signature: sig,
        };
        let e = d
            .put_signed_transport_destination(&td)
            .await
            .expect_err("I630: an unbound signer cannot assert the route yet");
        expect_not_acting(&e, &st, &identity, "transport_destination", "I630 route");
        bind(d, &identity, &st).await;
        d.put_signed_transport_destination(&td)
            .await
            .expect("I630: the same route admits once the signer is bound");

        // touch_claim (SelfTouch): `sc` touches the identity.
        let sc = k("sc");
        ts::register_identity_key(d, &sc, AGENT).await;
        let signer = ts::hybrid_identity(&sc);
        let claim = signed_claim(
            signer.as_ref(),
            &sc,
            &identity,
            "occurrence",
            chrono::Utc::now() - chrono::Duration::minutes(1),
            SignerForm::SelfTouch,
            cohort_scope::SELF,
        )
        .await;
        let e = d
            .put_touch_claim(&claim)
            .await
            .expect_err("I630: an unbound signer cannot touch yet");
        expect_not_acting(&e, &sc, &identity, "touch_claim", "I630 touch");
        bind(d, &identity, &sc).await;
        d.put_touch_claim(&claim)
            .await
            .expect("I630: the same touch admits once the signer is bound");
    }

    /// **I631 (#1042 follow-up, CIRISEdge#858) — a backend failure of the
    /// attester lookup is not a verdict.** `verify_envelope_hybrid_signature`
    /// (the shared envelope verifier) over a directory whose
    /// `lookup_public_key` FAILS returns that backend error, not the terminal
    /// `federation_federation_tier_unverified`; over the same directory
    /// without the fault, the attester's real row verifies.
    pub async fn i631_lookup_failure_is_not_a_verdict(
        d: std::sync::Arc<dyn FederationDirectory>,
        s: &str,
    ) {
        use crate::federation::directory_double::FaultInjectingDirectory;
        let attester = format!("i631-att-{s}");
        ts::register_hybrid_key(d.as_ref(), &attester).await;
        let row = scored_row(&attester, &format!("i631-a-{s}"));
        let verify = |dir: FaultInjectingDirectory| {
            let row = row.clone();
            let attester = attester.clone();
            async move {
                crate::federation::tier_ingest::verify_envelope_hybrid_signature(
                    &dir,
                    &attester,
                    &row.attestation_envelope,
                    &row.scrub_signature_classical,
                    row.scrub_signature_pqc.as_deref(),
                )
                .await
            }
        };
        let faulted = verify(FaultInjectingDirectory::new(d.clone()).erroring("lookup_public_key"))
            .await
            .expect_err("I631: the lookup failed");
        assert!(
            matches!(&faulted, Error::Backend(m) if m.contains("injected backend failure")),
            "I631: a backend failure propagates as itself, never a verdict: {} ({faulted:?})",
            faulted.kind()
        );
        verify(FaultInjectingDirectory::new(d))
            .await
            .expect("I631: without the fault the same row verifies");
    }

    /// `e` is the terminal `MalformedRow { reason: no_signer }` (v55.0.0,
    /// CIRISPersist#1055; before, an `InvalidArgument`), never the retryable
    /// gap.
    fn expect_malformed(e: &Error, what: &str) {
        // The key plane refuses an empty `scrub_key_id` before its lookup (its
        // own pre-existing guard); every other door reaches the lookup's.
        assert!(
            matches!(e, Error::MalformedRow { reason: "no_signer", message, .. }
                if message.contains("names no signer")
                    || message.contains("scrub_key_id must be non-empty")),
            "{what}: a row naming no signer is malformed (MalformedRow no_signer, from the \
             signer lookup's own guard), got {} ({e:?})",
            e.kind()
        );
        assert_eq!(e.kind(), "federation_malformed_row", "{what}");
    }

    /// `e` is the terminal `MalformedRow` on `plane` for `reason`.
    fn expect_malformed_as(e: &Error, plane: &str, reason: &str, what: &str) {
        assert!(
            matches!(e, Error::MalformedRow { plane: p, reason: r, .. } if *p == plane && *r == reason),
            "{what}: expected MalformedRow {{ {plane}, {reason} }}, got {} ({e:?})",
            e.kind()
        );
        assert_eq!(e.kind(), "federation_malformed_row", "{what}");
        assert!(
            crate::federation::malformed_row::ALL.contains(&reason),
            "{what}: {reason} is in the closed set"
        );
        assert!(
            !e.to_string().starts_with("invalid argument:"),
            "{what}: the Display does not read as an InvalidArgument: {e}"
        );
    }

    /// **I834 (v55.0.0, CIRISPersist#1055, CIRISEdge's adopt of v54.1) — a
    /// signed row whose typed columns diverge from its signed envelope is the
    /// TERMINAL `MalformedRow`, typed apart from a caller's argument error.**
    /// On the attestation door: a typed `asserted_at` and a typed mirror
    /// column (`attested_key_id`) moved off the envelope the signature
    /// covers. On the occurrence door: a typed `device_class` moved off the
    /// signed envelope (the exact case Edge reported). Each is refused with
    /// its plane and reason token, and the untouched row admits.
    pub async fn i834_typed_divergence_is_malformed_row(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::malformed_row as why;
        let attester = format!("i834-att-{s}");
        ts::register_hybrid_key(d, &attester).await;
        let row = scored_row(&attester, &format!("i834-a-{s}"));

        let mut moved = row.clone();
        moved.asserted_at += chrono::Duration::seconds(1);
        let e = d
            .put_attestation(SignedAttestation { attestation: moved })
            .await
            .expect_err("I834: a typed asserted_at off its envelope");
        expect_malformed_as(
            &e,
            "attestation",
            why::TYPED_DIVERGES_FROM_ENVELOPE,
            "I834 asserted_at",
        );

        let mut moved = row.clone();
        moved.attested_key_id = format!("i834-other-{s}");
        let e = d
            .put_attestation(SignedAttestation { attestation: moved })
            .await
            .expect_err("I834: a typed mirror column off its envelope");
        expect_malformed_as(
            &e,
            "attestation",
            why::TYPED_DIVERGES_FROM_ENVELOPE,
            "I834 mirror",
        );

        d.put_attestation(SignedAttestation { attestation: row })
            .await
            .expect("I834: the untouched row admits");

        let identity = format!("i834-id-{s}");
        let occ = format!("i834-occ-{s}");
        ts::register_identity_key(d, &identity, USER).await;
        ts::register_identity_key(d, &occ, AGENT).await;
        let signed =
            ts::signed_content_only_occurrence(&identity, &identity, &occ, chrono::Utc::now())
                .await;
        let mut moved = signed.clone();
        moved.identity_occurrence.device_class =
            if moved.identity_occurrence.device_class == "phone" {
                "laptop".to_owned()
            } else {
                "phone".to_owned()
            };
        let e = d
            .put_identity_occurrence(moved)
            .await
            .expect_err("I834: a typed device_class off its signed envelope");
        expect_malformed_as(
            &e,
            "identity_occurrence",
            why::TYPED_DIVERGES_FROM_ENVELOPE,
            "I834 device_class",
        );
        d.put_identity_occurrence(signed)
            .await
            .expect("I834: the untouched occurrence admits");
    }

    /// **I632 (#1042 follow-up B, CIRISEdge#858) — a row that names NO signer
    /// is malformed, never the retryable gap.** No Key row can ever land for
    /// `""`, so an empty signer id reaching a door's signer lookup is a
    /// terminal `InvalidArgument` (before: `AttesterKeyUnknown { "" }`). Run
    /// through the key plane (direct and replicated, where it is the terminal
    /// `unverifiable_signature` outcome), the attestation door, the signed
    /// occurrence door, and the shared envelope verifier.
    pub async fn i632_empty_signer_is_malformed(d: &dyn FederationDirectory, s: &str) {
        // Key plane: a record scrubbed by "".
        let k = format!("i632-k-{s}");
        let record = ts::replicated_key_record(&k, AGENT, "", "", "n1");
        let direct = register::verify_key_registration(d, &record)
            .await
            .expect_err("I632: a record scrubbed by nobody");
        expect_malformed(&direct, "I632 key plane (direct)");
        let out = d
            .apply_replicated_key_record(SignedKeyRecord { record })
            .await
            .expect("I632: a refusal is an outcome");
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::UnverifiableSignature
            },
            "I632 key plane (replicated): terminal, not attester_key_unknown"
        );

        // Attestation door: a row whose attesting_key_id is "".
        let row = scored_row("", &format!("i632-a-{s}"));
        let e = d
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .expect_err("I632: a row naming no attester");
        expect_malformed(&e, "I632 attestation door");

        // The shared envelope verifier, directly.
        let e = crate::federation::tier_ingest::verify_envelope_hybrid_signature(
            d,
            "",
            &row.attestation_envelope,
            &row.scrub_signature_classical,
            row.scrub_signature_pqc.as_deref(),
        )
        .await
        .expect_err("I632: the verifier with no signer");
        expect_malformed(&e, "I632 signed_envelope");

        // Signed occurrence door: signed by "".
        let identity = format!("i632-id-{s}");
        let occ = format!("i632-occ-{s}");
        ts::register_identity_key(d, &identity, USER).await;
        ts::register_identity_key(d, &occ, AGENT).await;
        let signed =
            ts::signed_content_only_occurrence("", &identity, &occ, chrono::Utc::now()).await;
        let e = d
            .put_identity_occurrence(signed)
            .await
            .expect_err("I632: an occurrence signed by nobody");
        expect_malformed(&e, "I632 identity_occurrence");
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i613_key_plane() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i613_key_plane(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i614_occurrence_plane() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i614_occurrence_plane(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i615_signed_envelope_plane() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i615_signed_envelope_plane(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i630_signer_not_acting_for_is_retryable() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i630_signer_not_acting_for_is_retryable(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i632_empty_signer_is_malformed() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i632_empty_signer_is_malformed(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i834_typed_divergence_is_malformed_row() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i834_typed_divergence_is_malformed_row(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i631_lookup_failure_is_not_a_verdict() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i631_lookup_failure_is_not_a_verdict(
                        std::sync::Arc::new(b),
                        &super::suffix(),
                    )
                    .await
                }
            }
        };
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
