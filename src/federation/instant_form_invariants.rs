//! v61 (CC 2.6.2; the steward's strict ruling) — witnesses for the
//! signed-instant form: the admission refusal and the open-time pass
//! ([`super::instant_form`]) on an upgraded v60-shaped node.
//!
//! v62.0.0 (VA-pair-signing): the v60-shaped seed (a stored row re-signed
//! with its author's separate Ed25519 + ML-DSA-65 pair) and I-IFP-10, the
//! Python open over it, are deleted: the v62 store is deleted at upgrade, so
//! no v60-shaped row exists to settle. I-IFP-8 counts the pass's dispositions
//! over a mock corpus.

// v62 BF13: the bodies' callers are `_pyffi`-gated; a non-pyffi lib-test
// build (the CI lib lane's `postgres,sqlite`) reads them as dead.
#[cfg_attr(not(feature = "_pyffi"), allow(dead_code, unused_imports))]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;

    /// I-IFP-2 — **the predicate, member by member.** Every CC 2.6.1.7
    /// `rfc3339-ms` member and `additional_scrubs[].cosigned_at` is held to
    /// `.sssZ`; `+00:00`, no fraction, six digits and a lowercase `z` are each
    /// refused, naming the member; a non-instant member shaped like one is not
    /// read.
    pub(crate) fn i_ifp_2_the_predicate_reads_every_typed_member() {
        use crate::federation::admission::{signed_instant_form_violation, SIGNED_INSTANT_MEMBERS};
        let base = || {
            let mut r = ts::bare_attestation("ifp2", "a", "a", &serde_json::json!({}));
            r.attestation_envelope = serde_json::json!({
                "dimension": "identity_binding:v1",
                "asserted_at": "2026-10-18T12:00:00.000Z",
                "note": "2026-10-18T12:00:00+00:00",
            });
            r
        };
        assert_eq!(signed_instant_form_violation(&base()), None);
        for member in SIGNED_INSTANT_MEMBERS {
            for bad in [
                "2026-10-18T12:00:00+00:00",
                "2026-10-18T12:00:00Z",
                "2026-10-18T12:00:00.000000Z",
                "2026-10-18T12:00:00.000z",
            ] {
                let mut r = base();
                r.attestation_envelope[*member] = serde_json::json!(bad);
                let v = signed_instant_form_violation(&r)
                    .unwrap_or_else(|| panic!("I-IFP-2: `{member}` = {bad:?} must be refused"));
                assert_eq!(v.member, *member);
                assert_eq!(v.value, bad);
            }
        }
        let mut r = base();
        r.additional_scrubs = vec![crate::federation::types::ScrubSig {
            scrub_key_id: "c".into(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            cosigned_at: Some("2026-10-18T12:00:00+00:00".into()),
        }];
        assert_eq!(
            signed_instant_form_violation(&r).map(|v| v.member),
            Some("additional_scrubs[0].cosigned_at".to_owned())
        );
    }

    /// I-IFP-3 — **who keeps force.** A peer's withdraws, delegation,
    /// revocation, removal and revoked consent stay in force when refused for
    /// form alone; a peer's ordinary claim is set aside; this node's own
    /// `scores` row is re-stated, and its own cosigned, local, expired or
    /// composer rows are left where they are.
    pub(crate) fn i_ifp_3_dispositions() {
        use crate::federation::instant_form::{disposition, Disposition};
        let now = chrono::Utc::now();
        let row = |attester: &str, ty: &str, dim: &str| {
            let mut r = ts::bare_attestation("ifp3", attester, attester, &serde_json::json!({}));
            r.attestation_type = ty.to_owned();
            r.attestation_envelope = serde_json::json!({ "dimension": dim });
            r
        };
        let s = attestation_type::SCORES;
        for (ty, dim) in [
            (attestation_type::WITHDRAWS, "identity_binding:v1"),
            (attestation_type::RECANTS, "identity_binding:v1"),
            (attestation_type::DELEGATES_TO, "self:delegates_to:v1"),
            (s, "revocation:peer_admission:v1"),
            (s, "key:revocation:v1"),
            (s, "membership:removal:v1"),
            (s, "membership:resignation:v1"),
            (s, "consent:state:revoked:v1"),
            (s, "hard_case:lineage_equivocation:v1"),
        ] {
            assert_eq!(
                disposition(&row("peer", ty, dim), "me", now),
                Disposition::KeepInForce,
                "I-IFP-3: {ty} {dim} keeps force"
            );
        }
        assert_eq!(
            disposition(&row("peer", s, "identity_binding:v1"), "me", now),
            Disposition::SetAside
        );
        assert_eq!(
            disposition(&row("me", s, "identity_binding:v1"), "me", now),
            Disposition::Heal
        );
        let mut cosigned = row("me", s, "identity_binding:v1");
        cosigned.additional_scrubs = vec![crate::federation::types::ScrubSig {
            scrub_key_id: "c".into(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            cosigned_at: None,
        }];
        let mut local = row("me", s, "identity_binding:v1");
        local.tier = crate::federation::types::attestation_tier::LOCAL.to_owned();
        let mut expired = row("me", s, "identity_binding:v1");
        expired.expires_at = Some(now - chrono::Duration::seconds(1));
        for r in [
            cosigned,
            local,
            expired,
            row("me", attestation_type::WITHDRAWS, "identity_binding:v1"),
        ] {
            assert_eq!(disposition(&r, "me", now), Disposition::OwnLeft);
        }
        // The expiry boundary: a row expiring at `now` is not live; one a
        // second later is.
        let mut at_now = row("me", s, "identity_binding:v1");
        at_now.expires_at = Some(now);
        assert_eq!(disposition(&at_now, "me", now), Disposition::OwnLeft);
        at_now.expires_at = Some(now + chrono::Duration::seconds(1));
        assert_eq!(disposition(&at_now, "me", now), Disposition::Heal);
    }
}

#[cfg(test)]
mod tests {
    use super::bodies;

    #[test]
    fn i_ifp_2_the_predicate_reads_every_typed_member() {
        bodies::i_ifp_2_the_predicate_reads_every_typed_member();
    }

    #[test]
    fn i_ifp_3_dispositions() {
        bodies::i_ifp_3_dispositions();
    }
}

/// v61 (CC 2.6.2) — the preimage and door witnesses the mutation scope
/// measures: the v2 domains' bytes, the two-domain trust verifier, the local
/// door's predicate and the key record's expiry binding.
#[cfg(test)]
mod preimages {
    use crate::federation::admission::{
        local_write_instant_form_violation, trust_grant_signing_bytes,
        trust_grant_signing_bytes_v1, trust_revocation_signing_bytes,
        trust_revocation_signing_bytes_v1, verify_envelope_binds_subject,
    };
    use chrono::{DateTime, Utc};

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn text(b: Vec<u8>) -> String {
        String::from_utf8(b).unwrap()
    }

    /// I-IFP-4 — **the v2 trust preimages**: the domain is named, the instant
    /// is `.sssZ`, v1 is a different byte string, and a sub-millisecond
    /// instant is refused rather than truncated into agreeing.
    #[test]
    fn i_ifp_4_the_v2_trust_preimages() {
        let grant = crate::federation::TrustGrant {
            key: "k".into(),
            trust_type: crate::federation::TrustType::Temporary,
            trust_relationship: crate::federation::TrustRelationship::Direct,
            trust_domains: None,
            trusted_by: "g".into(),
            expires_at: Some(t("2026-11-01T12:00:00.123Z")),
        };
        let v2 = text(trust_grant_signing_bytes(&grant).unwrap());
        assert_eq!(
            v2,
            r#"{"domain":"ciris.trust.grant.v2","grant":{"expires_at":"2026-11-01T12:00:00.123Z","key":"k","trust_relationship":"direct","trust_type":"temporary","trusted_by":"g"}}"#
        );
        let v1 = text(trust_grant_signing_bytes_v1(&grant).unwrap());
        assert!(v1.contains("ciris.trust.grant.v1") && v1 != v2);
        let mut fine = grant.clone();
        fine.expires_at = Some(t("2026-11-01T12:00:00.123456Z"));
        assert!(
            trust_grant_signing_bytes(&fine).is_err(),
            "sub-millisecond refused"
        );

        let at = t("2026-11-01T12:00:00.120Z");
        assert_eq!(
            text(trust_revocation_signing_bytes("k", "g", &at).unwrap()),
            r#"{"domain":"ciris.trust.revocation.v2","key":"k","revoked_at":"2026-11-01T12:00:00.120Z","revoked_by":"g"}"#
        );
        assert_eq!(
            text(trust_revocation_signing_bytes_v1("k", "g", &at).unwrap()),
            r#"{"domain":"ciris.trust.revocation.v1","key":"k","revoked_at":"2026-11-01T12:00:00.120000Z","revoked_by":"g"}"#
        );
        assert!(trust_revocation_signing_bytes("k", "g", &t("2026-11-01T12:00:00.1201Z")).is_err());
    }

    /// I-IFP-5 — **the trace scrub preimage**: v2 names its domain and writes
    /// `.sssZ`; v1 is the pre-v61 shape.
    #[test]
    fn i_ifp_5_the_v2_scrub_preimage() {
        let at = t("2026-11-01T12:00:00.123456Z");
        let v2 = text(crate::ingest::scrub_preimage(
            "p", "o", true, "generic", None, "s", at,
        ));
        assert_eq!(
            v2,
            r#"{"domain":"ciris.scrub_envelope.v2","ner_ran":true,"original_content_hash":"o","post_content_sha256":"p","scrub_key_id":"s","scrub_timestamp":"2026-11-01T12:00:00.123Z","scrubber_model_digest":null,"trace_level":"generic"}"#
        );
        let v1 = text(crate::ingest::scrub_preimage_v1(
            "p", "o", true, "generic", None, "s", at,
        ));
        assert!(!v1.contains("domain") && v1.contains("+00:00"), "{v1}");
    }

    /// I-IFP-6 — **the local door's predicate** reads the caller's instants
    /// and leaves `expires_at`, which the door stamps itself.
    #[test]
    fn i_ifp_6_the_local_door_predicate() {
        let offset = serde_json::json!({ "asserted_at": "2026-11-01T12:00:00+00:00" });
        assert_eq!(
            local_write_instant_form_violation(&offset).map(|v| v.member),
            Some("asserted_at".to_owned())
        );
        let stamped = serde_json::json!({
            "asserted_at": "2026-11-01T12:00:00.000Z",
            "expires_at": "2031-01-01T00:00:00.000000+00:00",
        });
        assert_eq!(local_write_instant_form_violation(&stamped), None);
    }

    /// I-IFP-7 — **the key record's expiry binds `.sssZ` as bytes**: the same
    /// instant spelled `+00:00` is refused naming the form, and a column finer
    /// than a millisecond is refused.
    #[test]
    fn i_ifp_7_the_key_record_expiry() {
        use crate::federation::operational::test_support::{signed_canonical_record, Identity};
        let until = t("2027-02-02T00:00:00.000Z");
        let mut rec = signed_canonical_record(
            "k1",
            "node",
            "ED",
            None,
            serde_json::json!({}),
            &[&Identity::new("s1")],
        );
        rec.valid_until = Some(until);
        rec.registration_envelope["valid_until"] = serde_json::json!("2027-02-02T00:00:00.000Z");
        verify_envelope_binds_subject(&rec).expect("the canonical expiry binds");
        rec.registration_envelope["valid_until"] = serde_json::json!("2027-02-02T00:00:00+00:00");
        let why = verify_envelope_binds_subject(&rec).unwrap_err();
        assert!(why.contains("CC 2.6.2"), "{why}");
        rec.registration_envelope["valid_until"] = serde_json::json!("2027-02-02T00:00:00.000Z");
        rec.valid_until = Some(until + chrono::Duration::microseconds(1));
        let why = verify_envelope_binds_subject(&rec).unwrap_err();
        assert!(why.contains("sub-millisecond"), "{why}");
    }
}

/// v61 — the pass's counters, over a store double: a row whose re-statement
/// the emit door refuses, a row with no instant to re-state, and own rows the
/// pass leaves where they are.
#[cfg(test)]
mod pass_counts {
    use crate::federation::admission::InstantFormViolation;
    use crate::federation::instant_form::{run_pass, InstantFormStore};
    use crate::federation::types::attestation_type;
    use crate::federation::{Attestation, EmitAttestationInput, Error};

    struct Double {
        rows: Vec<Attestation>,
    }

    impl InstantFormStore for Double {
        async fn corpus_page(
            &self,
            after: Option<&str>,
            _limit: u32,
        ) -> Result<Vec<Attestation>, Error> {
            Ok(if after.is_none() {
                self.rows.clone()
            } else {
                Vec::new()
            })
        }
        async fn own_composers_citing(
            &self,
            _ids: &[String],
            _me: &str,
        ) -> Result<Vec<Attestation>, Error> {
            Ok(Vec::new())
        }
        async fn emit_own(&self, _input: EmitAttestationInput) -> Result<String, Error> {
            Err(Error::InvalidArgument("the door refuses".into()))
        }
        async fn set_aside(
            &self,
            _row: &Attestation,
            _v: &InstantFormViolation,
        ) -> Result<bool, Error> {
            Ok(true)
        }
    }

    fn row(id: &str, ty: &str, valid_until: &str) -> Attestation {
        let mut r = crate::federation::tier_ingest::test_support::bare_attestation(
            id,
            "me",
            "me",
            &serde_json::json!({}),
        );
        r.attestation_type = ty.to_owned();
        r.attestation_envelope = serde_json::json!({
            "dimension": "identity_binding:v1",
            "valid_until": valid_until,
        });
        r
    }

    /// I-IFP-8 — **every counter counts.** Two re-statements the door
    /// refuses (one by the emit door, one with no instant to re-state), two
    /// own rows left (a composer and a local row), one canonical row.
    #[tokio::test]
    async fn i_ifp_8_the_pass_counts_every_disposition() {
        let mut local = row("r5", attestation_type::SCORES, "2030-01-01T00:00:00+00:00");
        local.tier = crate::federation::types::attestation_tier::LOCAL.to_owned();
        let store = Double {
            rows: vec![
                row("r1", attestation_type::SCORES, "2030-01-01T00:00:00+00:00"),
                row("r2", attestation_type::SCORES, "not an instant"),
                row(
                    "r3",
                    attestation_type::WITHDRAWS,
                    "2030-01-01T00:00:00+00:00",
                ),
                row("r4", attestation_type::SCORES, "2030-01-01T00:00:00.000Z"),
                local,
            ],
        };
        let pass = run_pass(&store, "me", chrono::Utc::now()).await.unwrap();
        assert_eq!(
            (
                pass.scanned,
                pass.violations,
                pass.heal_refused,
                pass.own_left,
                pass.healed,
                pass.set_aside
            ),
            (5, 4, 2, 2, 0, 0),
            "I-IFP-8: {pass:?}"
        );
    }
}
