//! v61 (CC 2.6.2; the steward's strict ruling) — witnesses for the
//! signed-instant form: the admission refusal and the open-time pass
//! ([`super::instant_form`]) on an upgraded v60-shaped node.
//!
//! The v60 shape is built the only way it can exist: a row is admitted in the
//! canonical form through the ordinary door, then its STORED envelope is
//! rewritten to spell one instant `+00:00` and re-signed over those bytes by
//! its own author, as a v60 producer did (no v61 door admits the form, so the
//! seam reaches the connection). The pass then runs at the next open, and the
//! result is counted from disk.

pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope, identity_type as it};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// A v60 producer's spelling of `t`: chrono's `to_rfc3339()`.
    fn offset_form(t: chrono::DateTime<chrono::Utc>) -> String {
        t.to_rfc3339()
    }

    /// The store seam: rewrite a stored row's envelope, content hash and both
    /// signature halves, as a v60 writer left them.
    #[allow(async_fn_in_trait)]
    pub(crate) trait V60Rewriter {
        async fn rewrite_signed(&self, row: &Attestation);
        async fn form_refused_count(&self) -> i64;
    }

    #[cfg(feature = "sqlite")]
    impl V60Rewriter for crate::store::sqlite::SqliteBackend {
        async fn rewrite_signed(&self, row: &Attestation) {
            let envelope = serde_json::to_string(&row.attestation_envelope).unwrap();
            let hash = hex::decode(&row.original_content_hash).unwrap();
            let conn = self.conn_handle();
            let guard = conn.lock();
            let n = guard
                .execute(
                    "UPDATE federation_attestations SET attestation_envelope = ?2, \
                     original_content_hash = ?3, scrub_signature_classical = ?4, \
                     scrub_signature_pqc = ?5 WHERE attestation_id = ?1",
                    rusqlite::params![
                        row.attestation_id,
                        envelope,
                        hash,
                        row.scrub_signature_classical,
                        row.scrub_signature_pqc
                    ],
                )
                .unwrap();
            assert_eq!(n, 1, "the seam rewrites exactly the row");
        }

        async fn form_refused_count(&self) -> i64 {
            let conn = self.conn_handle();
            let guard = conn.lock();
            guard
                .query_row(
                    "SELECT count(*) FROM federation_attestations_form_refused",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        }
    }

    #[cfg(feature = "postgres")]
    impl V60Rewriter for crate::store::postgres::PostgresBackend {
        async fn rewrite_signed(&self, row: &Attestation) {
            let envelope = serde_json::to_string(&row.attestation_envelope).unwrap();
            let hash = hex::decode(&row.original_content_hash).unwrap();
            let client = self.pool().get().await.unwrap();
            let n = client
                .execute(
                    "UPDATE cirislens.federation_attestations SET attestation_envelope = $2, \
                     original_content_hash = $3, scrub_signature_classical = $4, \
                     scrub_signature_pqc = $5 WHERE attestation_id = $1",
                    &[
                        &row.attestation_id,
                        &envelope,
                        &hash,
                        &row.scrub_signature_classical,
                        &row.scrub_signature_pqc,
                    ],
                )
                .await
                .unwrap();
            assert_eq!(n, 1, "the seam rewrites exactly the row");
        }

        async fn form_refused_count(&self) -> i64 {
            let client = self.pool().get().await.unwrap();
            client
                .query_one(
                    "SELECT count(*) FROM cirislens.federation_attestations_form_refused",
                    &[],
                )
                .await
                .unwrap()
                .get(0)
        }
    }

    /// Re-sign `row` over its (rewritten) envelope with `signer`'s
    /// deterministic fixture keys.
    fn resign_with_fixture(signer: &str, row: &mut Attestation) {
        let (och, sc, sp) = ts::sign_envelope(signer, &row.attestation_envelope);
        row.original_content_hash = och;
        row.scrub_signature_classical = sc;
        row.scrub_signature_pqc = sp;
    }

    /// Re-sign `row` over its (rewritten) envelope with the engine's own key.
    async fn resign_with_engine(engine: &crate::Engine, row: &mut Attestation) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use sha2::{Digest, Sha256};
        let canonical =
            crate::verify::canonical::ceg_produce_canonicalize(&row.attestation_envelope).unwrap();
        let sig = engine.sign_hybrid(&canonical).await.unwrap();
        row.original_content_hash = hex::encode(Sha256::digest(&canonical));
        row.scrub_signature_classical = B64.encode(&sig.classical.signature);
        row.scrub_signature_pqc = Some(B64.encode(&sig.pqc.signature));
    }

    fn scores_envelope(tag: &str, valid_until: Option<String>) -> serde_json::Value {
        let mut env = serde_json::json!({
            "id": format!("ifp-{tag}"),
            "dimension": "identity_binding:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        if let Some(vu) = valid_until {
            env["valid_until"] = serde_json::json!(vu);
        }
        env
    }

    /// The handles an open of the node returns.
    pub(crate) struct Opened<B> {
        pub(crate) engine: crate::Engine,
        pub(crate) backend: std::sync::Arc<B>,
    }

    /// I-IFP-1 — **the open-time pass on an upgraded v60-shaped node.**
    ///
    /// Four stored rows, each with one instant in the `+00:00` form and a
    /// signature over those bytes: this node's own `scores` row (re-stated as
    /// a canonical `supersedes`), a peer's `scores` row (set aside), a peer's
    /// `withdraws` (kept in force: a retraction never lapses for its form),
    /// and this node's own row it already re-stated (no second re-statement).
    /// Counted from disk after the open, and again after a second open, which
    /// does nothing.
    pub(crate) async fn i_ifp_1_open_settles_a_v60_node<B, F, Fut>(open: F, tag: &str)
    where
        B: V60Rewriter + FederationDirectory,
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Opened<B>>,
    {
        let peer = format!("ifp-peer-{tag}");
        let first = open().await;
        let me = first.engine.local_derived_key_id().await.unwrap();
        ts::register_hybrid_key_as(&*first.backend, &peer, &peer, it::NODE).await;
        let later = chrono::Utc::now() + chrono::Duration::days(30);

        // (1) Own row, canonical at the door, then rewritten to the v60 form.
        let own_id = first
            .engine
            .emit_attestation_self(crate::federation::EmitAttestationInput::with_envelope(
                attestation_type::SCORES,
                crate::federation::envelope::EnvelopeCore::from_value(scores_envelope(
                    &format!("own-{tag}"),
                    Some(crate::federation::admission::render_signed_instant(later)),
                ))
                .unwrap(),
                cohort_scope::FEDERATION,
            ))
            .await
            .expect("I-IFP-1: the own row is admitted in the canonical form");
        let mut own = first
            .backend
            .get_attestation(&own_id)
            .await
            .unwrap()
            .unwrap();
        own.attestation_envelope["valid_until"] = serde_json::json!(offset_form(later));
        resign_with_engine(&first.engine, &mut own).await;
        first.backend.rewrite_signed(&own).await;

        // (2) A peer's scores row, then rewritten to the v60 form.
        let mut foreign = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &peer,
            &peer,
            &scores_envelope(&format!("foreign-{tag}"), None),
        );
        foreign.attestation_type = attestation_type::SCORES.to_owned();
        let foreign = ts::seal_row(&peer, foreign);
        first
            .backend
            .put_attestation(SignedAttestation {
                attestation: foreign.clone(),
            })
            .await
            .expect("I-IFP-1: the peer row is admitted in the canonical form");
        let mut foreign_v60 = first
            .backend
            .get_attestation(&foreign.attestation_id)
            .await
            .unwrap()
            .unwrap();
        foreign_v60.attestation_envelope["valid_until"] = serde_json::json!(offset_form(later));
        resign_with_fixture(&peer, &mut foreign_v60);
        first.backend.rewrite_signed(&foreign_v60).await;

        // (3) A peer's withdraws of its own second row, rewritten to v60 form.
        let mut target = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &peer,
            &peer,
            &scores_envelope(&format!("target-{tag}"), None),
        );
        target.attestation_type = attestation_type::SCORES.to_owned();
        let target = ts::seal_row(&peer, target);
        first
            .backend
            .put_attestation(SignedAttestation {
                attestation: target.clone(),
            })
            .await
            .expect("I-IFP-1: the withdrawn row");
        let mut withdraws = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            &peer,
            &peer,
            &serde_json::json!({
                "dimension": "identity_binding:v1",
                "references_attestation_id": target.attestation_id,
                "withdrawal_reason": "superseded by events",
            }),
        );
        withdraws.attestation_type = attestation_type::WITHDRAWS.to_owned();
        let withdraws = ts::seal_row(&peer, withdraws);
        first
            .backend
            .put_attestation(SignedAttestation {
                attestation: withdraws.clone(),
            })
            .await
            .expect("I-IFP-1: the withdraws is admitted in the canonical form");
        let mut withdraws_v60 = first
            .backend
            .get_attestation(&withdraws.attestation_id)
            .await
            .unwrap()
            .unwrap();
        withdraws_v60.attestation_envelope["valid_until"] = serde_json::json!(offset_form(later));
        resign_with_fixture(&peer, &mut withdraws_v60);
        first.backend.rewrite_signed(&withdraws_v60).await;
        assert!(
            crate::federation::admission::signed_instant_form_violation(&withdraws_v60).is_some()
        );

        // The v60 node's rows are refused at every door now.
        let refused = first
            .backend
            .put_attestation(SignedAttestation {
                attestation: foreign_v60.clone(),
            })
            .await;
        assert!(
            matches!(
                &refused,
                Err(crate::federation::Error::MalformedRow { reason, .. })
                    if *reason == crate::federation::malformed_row::ENVELOPE_MEMBER_INVALID
            ),
            "I-IFP-1: a `+00:00` instant is refused envelope_member_invalid: {refused:?}"
        );
        // The pass, called directly once so its counts are read: the own row
        // re-stated, the peer row set aside, the withdraws kept in force.
        let pass = first.engine.settle_instant_forms().await.unwrap();
        assert_eq!(
            (
                pass.violations,
                pass.healed,
                pass.set_aside,
                pass.kept_in_force,
                pass.already_healed,
                pass.heal_refused,
                pass.own_left,
            ),
            (3, 1, 1, 1, 0, 0, 0),
            "I-IFP-1: the first pass: {pass:?}"
        );
        assert!(pass.scanned >= 5, "I-IFP-1: every row is read: {pass:?}");
        drop(first);

        // ── The next open runs the pass again, and finds it done. ─────────
        let second = open().await;
        assert!(
            second
                .backend
                .get_attestation(&foreign.attestation_id)
                .await
                .unwrap()
                .is_none(),
            "I-IFP-1: the peer's row is refused at read: absent from every read path"
        );
        assert_eq!(
            second.backend.form_refused_count().await,
            1,
            "I-IFP-1: from disk, exactly one row is set aside"
        );
        assert!(
            second
                .backend
                .get_attestation(&withdraws.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "I-IFP-1: the peer's withdraws stays in force"
        );
        assert!(
            second
                .backend
                .get_attestation(&own_id)
                .await
                .unwrap()
                .is_some(),
            "I-IFP-1: this node's original stays; its successor cites it"
        );
        let successors: Vec<Attestation> = second
            .backend
            .list_composers_referencing_any(std::slice::from_ref(&own_id), None, Some(&me))
            .await
            .unwrap()
            .into_iter()
            .filter(|c| c.attestation_type == attestation_type::SUPERSEDES)
            .collect();
        assert_eq!(successors.len(), 1, "I-IFP-1: one canonical re-statement");
        let s = &successors[0];
        assert_eq!(
            s.attestation_envelope["valid_until"],
            serde_json::json!(crate::federation::admission::render_signed_instant(later)),
            "I-IFP-1: the re-statement spells the same instant `.sssZ`"
        );
        assert_eq!(
            s.attestation_envelope["asserted_at"], own.attestation_envelope["asserted_at"],
            "I-IFP-1: the claim's own instant is kept"
        );
        assert!(crate::federation::admission::signed_instant_form_violation(s).is_none());

        // Idempotent: the pass again, then a third open.
        let again = second.engine.settle_instant_forms().await.unwrap();
        assert_eq!(
            (
                again.violations,
                again.healed,
                again.set_aside,
                again.already_healed,
                again.kept_in_force
            ),
            (2, 0, 0, 1, 1),
            "I-IFP-1: a second pass does nothing: {again:?}"
        );
        drop(second);
        let third = open().await;
        assert_eq!(third.backend.form_refused_count().await, 1);
        let successors = third
            .backend
            .list_composers_referencing_any(std::slice::from_ref(&own_id), None, Some(&me))
            .await
            .unwrap()
            .into_iter()
            .filter(|c| c.attestation_type == attestation_type::SUPERSEDES)
            .count();
        assert_eq!(
            successors, 1,
            "I-IFP-1: no second re-statement on a third open"
        );
    }

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
    use super::bodies::{self, Opened};

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[test]
    fn i_ifp_2_the_predicate_reads_every_typed_member() {
        bodies::i_ifp_2_the_predicate_reads_every_typed_member();
    }

    #[test]
    fn i_ifp_3_dispositions() {
        bodies::i_ifp_3_dispositions();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i_ifp_1_open_settles_a_v60_node_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let dsn = format!("sqlite:///{}", dir.path().join("node.db").display());
        let t = tag();
        let alias = format!("ifp-node-{t}");
        let open = || {
            let (dsn, alias) = (dsn.clone(), alias.clone());
            async move {
                let engine = crate::Engine::with_signer_pre_genesis(
                    crate::federation::tier_ingest::test_support::local_signer(&alias),
                    &dsn,
                )
                .await
                .unwrap();
                let _ = engine
                    .register_self_federation_key(
                        crate::federation::types::identity_type::NODE,
                        &alias,
                        None,
                        serde_json::json!({}),
                        vec![],
                    )
                    .await
                    .unwrap();
                let backend = engine.sqlite_backend().unwrap().clone();
                Opened { engine, backend }
            }
        };
        bodies::i_ifp_1_open_settles_a_v60_node(open, &t).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i_ifp_1_open_settles_a_v60_node_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let t = tag();
        let alias = format!("ifp-node-{t}");
        let open = || {
            let (dsn, alias) = (dsn.clone(), alias.clone());
            async move {
                let engine = crate::Engine::with_signer_pre_genesis(
                    crate::federation::tier_ingest::test_support::local_signer(&alias),
                    &dsn,
                )
                .await
                .unwrap();
                let _ = engine
                    .register_self_federation_key(
                        crate::federation::types::identity_type::NODE,
                        &alias,
                        None,
                        serde_json::json!({}),
                        vec![],
                    )
                    .await
                    .unwrap();
                let backend = engine.postgres_backend().unwrap().clone();
                Opened { engine, backend }
            }
        };
        bodies::i_ifp_1_open_settles_a_v60_node(open, &t).await;
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
