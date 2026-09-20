//! CIRISPersist#871 — witnesses for `FSD/MEDIA_SOURCE.md` §7 (I115–I120):
//! the media Source struct refused by name at every door, `size` required on
//! the holder claim, the rendition index, and the from-disk gates. One body
//! per invariant, generic over the directory, run by memory, sqlite and
//! postgres; the blob-door bodies run where a `BlobStorage` exists (sqlite,
//! postgres).

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
    use crate::federation::{admission, Attestation, FederationDirectory, SignedAttestation};

    pub(crate) fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        admission::truncate_to_substrate_resolution(s.parse().unwrap())
    }

    pub(crate) fn hex64(seed: &str) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(seed.as_bytes()))
    }

    /// A federation-tier `scores` row signed by `signer` over `envelope`.
    pub(crate) fn row(
        id: &str,
        signer: &str,
        target: &str,
        envelope: serde_json::Value,
        scope: &str,
    ) -> Attestation {
        let asserted = at("2026-05-01T00:00:00Z");
        let mut env = envelope;
        env["id"] = serde_json::Value::String(id.to_owned());
        env[crate::federation::envelope::paths::ASSERTED_AT] =
            serde_json::Value::String(asserted.to_rfc3339());
        let (och, ed_sig, pqc_sig) = ts::sign_envelope(signer, &env);
        let mut r = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: target.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: asserted,
            expires_at: None,
            attestation_envelope: env,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: asserted,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: scope.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        ts::seal_row_in_place(signer, &mut r);
        ts::reseal(&mut r);
        r
    }

    /// A well-formed struct over `digest`, cited by `evidence_refs`.
    pub(crate) fn media_row(
        id: &str,
        signer: &str,
        target: &str,
        digest: &str,
        media: serde_json::Value,
        scope: &str,
    ) -> Attestation {
        row(
            id,
            signer,
            target,
            serde_json::json!({
                "dimension": "external_content:image:v1",
                "score": 1.0,
                "evidence_refs": [digest],
                "media": media,
            }),
            scope,
        )
    }

    pub(crate) fn good_media(digest: &str) -> serde_json::Value {
        serde_json::json!({
            "digest": digest,
            "size": 4096,
            "format": "image/jpeg",
            "width": 64,
            "height": 48,
            "name": "cat.jpg",
        })
    }

    pub(crate) async fn put(
        d: &dyn FederationDirectory,
        a: Attestation,
    ) -> Result<(), crate::federation::Error> {
        d.put_attestation(SignedAttestation { attestation: a })
            .await
            .map(|_| ())
    }

    /// **I115 — a malformed struct is refused by name; a well-formed one is
    /// admitted.**
    pub async fn i115_the_struct_is_refused_by_name(d: &dyn FederationDirectory, s: &str) {
        let (signer, target) = (format!("i115-s-{s}"), format!("i115-t-{s}"));
        ts::register_identity_key(d, &signer, USER).await;
        ts::register_identity_key(d, &target, USER).await;
        let digest = hex64(&format!("i115-bytes-{s}"));
        let bad: &[(&str, serde_json::Value, &str)] = &[
            (
                "no-size",
                serde_json::json!({"digest": digest, "format": "image/jpeg"}),
                "size",
            ),
            (
                "zero-size",
                serde_json::json!({"digest": digest, "size": 0, "format": "image/jpeg"}),
                "size",
            ),
            (
                "string-size",
                serde_json::json!({"digest": digest, "size": "4096", "format": "image/jpeg"}),
                "size",
            ),
            (
                "no-format",
                serde_json::json!({"digest": digest, "size": 1}),
                "format",
            ),
            (
                "upper-format",
                serde_json::json!({"digest": digest, "size": 1, "format": "Image/JPEG"}),
                "format",
            ),
            (
                "param-format",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/jpeg; q=1"}),
                "format",
            ),
            (
                "mp4-no-codec",
                serde_json::json!({"digest": digest, "size": 1, "format": "video/mp4"}),
                "codec",
            ),
            (
                "bad-codec",
                serde_json::json!({"digest": digest, "size": 1, "format": "video/mp4", "codec": "avc1 baseline"}),
                "codec",
            ),
            (
                "slash-name",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "name": "../etc/passwd"}),
                "name",
            ),
            (
                "ctrl-name",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "name": "a\u{0007}b"}),
                "name",
            ),
            (
                "fat-placeholder",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "placeholder": "A".repeat(200)}),
                "placeholder",
            ),
            (
                "bad-digest",
                serde_json::json!({"digest": "abc", "size": 1, "format": "image/png"}),
                "digest",
            ),
            (
                "bad-dst",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "digital_source_type": "aiMadeIt"}),
                "digital_source_type",
            ),
            (
                "unknown-member",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "bitrate": 9}),
                "bitrate",
            ),
            (
                "safe",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "safe": true}),
                "safe",
            ),
            (
                "renderable",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "renderable": true}),
                "renderable",
            ),
            (
                "tier",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "tier": "A"}),
                "tier",
            ),
            (
                "crypto_tier",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "crypto_tier": "plaintext"}),
                "crypto_tier",
            ),
            (
                "render_tier",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "render_tier": "A"}),
                "render_tier",
            ),
            (
                "self-rendition",
                serde_json::json!({"digest": digest, "size": 1, "format": "image/png", "derived_from": digest}),
                "derived_from",
            ),
        ];
        for (n, media, member) in bad {
            let err = put(
                d,
                media_row(
                    &format!("i115-{n}-{s}"),
                    &signer,
                    &target,
                    &digest,
                    media.clone(),
                    cohort_scope::FEDERATION,
                ),
            )
            .await
            .expect_err(&format!("I115: `{n}` is refused"));
            assert_eq!(
                err.kind(),
                "federation_media_source_invalid",
                "I115 `{n}`: {err}"
            );
            assert!(
                err.to_string().contains(member),
                "I115 `{n}`: names `{member}`: {err}"
            );
        }
        for (n, member) in [
            ("safe", "safe"),
            ("renderable", "renderable"),
            ("tier", "tier"),
        ] {
            let mut m = good_media(&digest);
            m[member] = serde_json::Value::Bool(true);
            let err = put(
                d,
                media_row(
                    &format!("i115-cc-{n}-{s}"),
                    &signer,
                    &target,
                    &digest,
                    m,
                    cohort_scope::FEDERATION,
                ),
            )
            .await
            .unwrap_err();
            assert!(
                err.to_string().contains("5.3.2.6") || err.to_string().contains("receiver policy"),
                "I115 `{n}`: the MUST-NOT refusal names the rule, not 'unknown member': {err}"
            );
        }
        // Well-formed: admitted, and the struct survives the round trip.
        put(
            d,
            media_row(
                &format!("i115-ok-{s}"),
                &signer,
                &target,
                &digest,
                good_media(&digest),
                cohort_scope::FEDERATION,
            ),
        )
        .await
        .expect("I115: a well-formed struct is admitted");
        let stored = d
            .get_attestation(&format!("i115-ok-{s}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.attestation_envelope["media"]["size"], 4096);
        // mp4 with a codec; a video with captions cited.
        let vtt = hex64(&format!("i115-vtt-{s}"));
        let mut video = row(
            &format!("i115-video-{s}"),
            &signer,
            &target,
            serde_json::json!({
                "dimension": "external_content:video:v1", "score": 1.0,
                "evidence_refs": [digest, vtt],
                "media": {"digest": digest, "size": 10, "format": "video/mp4", "codec": "avc1.42E01E", "captions": vtt, "duration_ms": 1200},
            }),
            cohort_scope::FEDERATION,
        );
        video.attestation_id = format!("i115-video-{s}");
        put(d, video)
            .await
            .expect("I115: video/mp4 with a codec and cited captions is admitted");
        // The local door refuses the same way.
        let local = crate::federation::types::LocalAttestationInput {
            attestation_id: Some(format!("i115-local-{s}")),
            attesting_key_id: signer.clone(),
            attested_key_id: Some(target.clone()),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({
                    "dimension": "external_content:image:v1", "evidence_refs": [digest],
                    "media": {"digest": digest, "format": "image/png"},
                }),
            )
            .unwrap(),
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let err = d
            .attestation_upsert_local(local)
            .await
            .expect_err("I115: the local door refuses too");
        assert_eq!(err.kind(), "federation_media_source_invalid");
    }

    /// **I116 — the struct describes what the row cites; `evidence_refs`
    /// stays bare sha256.**
    pub async fn i116_the_struct_cites_what_the_row_cites(d: &dyn FederationDirectory, s: &str) {
        let (signer, target) = (format!("i116-s-{s}"), format!("i116-t-{s}"));
        ts::register_identity_key(d, &signer, USER).await;
        ts::register_identity_key(d, &target, USER).await;
        let (digest, other, vtt) = (
            hex64(&format!("i116-a-{s}")),
            hex64(&format!("i116-b-{s}")),
            hex64(&format!("i116-vtt-{s}")),
        );
        // digest not cited
        let err = put(d, row(&format!("i116-uncited-{s}"), &signer, &target,
            serde_json::json!({"dimension": "external_content:image:v1", "score": 1.0, "evidence_refs": [other], "media": good_media(&digest)}),
            cohort_scope::FEDERATION)).await.unwrap_err();
        assert_eq!(err.kind(), "federation_media_source_invalid");
        assert!(err.to_string().contains("evidence_refs"), "I116: {err}");
        // captions not cited
        let err = put(d, row(&format!("i116-uncited-vtt-{s}"), &signer, &target,
            serde_json::json!({"dimension": "external_content:video:v1", "score": 1.0, "evidence_refs": [digest],
                "media": {"digest": digest, "size": 10, "format": "video/mp4", "codec": "avc1.42E01E", "captions": vtt}}),
            cohort_scope::FEDERATION)).await.unwrap_err();
        assert!(err.to_string().contains("captions"), "I116: {err}");
        // evidence_refs stays strings: an object entry is not a citation (pinned).
        let env = serde_json::json!({"evidence_refs": [{"sha": digest, "size": 4096}]});
        assert!(
            !admission::envelope_binds_content(&env, &digest),
            "I116: an object entry does not cite (CC 3.3.13: evidence_refs stays bare sha256)"
        );
        assert!(admission::envelope_binds_content(
            &serde_json::json!({"evidence_refs": [digest]}),
            &digest
        ));
    }

    /// **I117 (directory half) — a `holds_bytes` claim without a size is
    /// refused at ingest.**
    pub async fn i117_a_claim_without_size_is_refused(d: &dyn FederationDirectory, s: &str) {
        let holder = format!("i117-h-{s}");
        ts::register_identity_key(d, &holder, USER).await;
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(format!("i117-bytes-{s}").as_bytes()).into()
        };
        let claim = |id: &str, size: serde_json::Value| {
            let mut env =
                serde_json::json!({"kind": "holds_bytes", "evidence_refs": [hex::encode(sha)]});
            if !size.is_null() {
                env["size"] = size;
            }
            let mut r = row(id, &holder, &holder, env, cohort_scope::FEDERATION);
            r.attestation_type = crate::federation::holds_bytes_attestation_type(&sha);
            ts::reseal(&mut r);
            r
        };
        for (n, size) in [
            ("absent", serde_json::Value::Null),
            ("zero", serde_json::json!(0)),
            ("string", serde_json::json!("12")),
            ("negative", serde_json::json!(-1)),
        ] {
            let err = put(d, claim(&format!("i117-{n}-{s}"), size))
                .await
                .expect_err(&format!("I117: `{n}` size is refused"));
            assert_eq!(
                err.kind(),
                "federation_media_source_invalid",
                "I117 `{n}`: {err}"
            );
            assert!(err.to_string().contains("size"), "I117 `{n}`: {err}");
        }
        put(d, claim(&format!("i117-ok-{s}"), serde_json::json!(12)))
            .await
            .expect("I117: a sized claim is admitted");
        let sized = d.list_holders_sized(&sha).await.unwrap();
        assert_eq!(sized.len(), 1);
        assert_eq!(
            (sized[0].key_id.as_str(), sized[0].size),
            (holder.as_str(), 12)
        );
    }

    /// **I118 — `derived_from` projects a rendition row in the same write;
    /// the index reads it; retraction removes it; placement is enforced
    /// where the original is held.**
    pub async fn i118_the_rendition_index(d: &dyn FederationDirectory, s: &str) {
        use crate::federation::renditions::Rendition;
        let (signer, target) = (format!("i118-s-{s}"), format!("i118-t-{s}"));
        ts::register_identity_key(d, &signer, USER).await;
        ts::register_identity_key(d, &target, USER).await;
        let original = hex64(&format!("i118-orig-{s}"));
        let thumb = hex64(&format!("i118-thumb-{s}"));
        assert!(d.list_derived_hex(&original).await.unwrap().is_empty());
        let rid = format!("i118-thumb-row-{s}");
        put(d, media_row(&rid, &signer, &target, &thumb,
            serde_json::json!({"digest": thumb, "size": 512, "format": "image/webp", "width": 32, "height": 24, "name": "thumbnail", "derived_from": original}),
            cohort_scope::FEDERATION)).await.expect("I118: a rendition row is admitted");
        let got = d.list_derived_hex(&original).await.unwrap();
        assert_eq!(
            got,
            vec![Rendition {
                rendition_sha256_hex: thumb.clone(),
                original_sha256_hex: original.clone(),
                format: "image/webp".into(),
                size: 512,
                width: Some(32),
                height: Some(24),
                role: "thumbnail".into(),
                source_attestation_id: rid.clone(),
                cohort_scope: cohort_scope::FEDERATION.into()
            }],
            "I118: one query answers 'the renditions of this digest'"
        );
        // Retracting the row removes the projection.
        let w = format!("i118-withdraw-{s}");
        let withdraw = {
            let mut r = row(
                &w,
                &signer,
                &target,
                serde_json::json!({"references_attestation_id": rid, "withdrawal_reason": "i118"}),
                cohort_scope::FEDERATION,
            );
            r.attestation_type = attestation_type::WITHDRAWS.to_owned();
            ts::reseal(&mut r);
            r
        };
        put(d, withdraw)
            .await
            .expect("I118: the producer withdraws its own row");
        assert!(
            d.list_derived_hex(&original).await.unwrap().is_empty(),
            "I118: a retired row's rendition is gone"
        );
    }

    /// **I118c — the local door projects too, and an upsert-replace retires
    /// the replaced row's rendition with it.** A `(local, self)` rendition
    /// row lands in the index on write; replacing it under the same
    /// `(attesting, dimension)` with a different rendition digest leaves ONE
    /// index row, the new one — the index is keyed by the rendition's digest
    /// and the row by its id, so without the cleanup the old row's projection
    /// would outlive the row.
    pub async fn i118c_the_local_door_projects_and_replace_retires(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::envelope::EnvelopeCore;
        use crate::federation::types::LocalAttestationInput;
        let signer = format!("i118c-s-{s}");
        ts::register_identity_key(d, &signer, USER).await;
        let original = hex64(&format!("i118c-orig-{s}"));
        let (thumb_a, thumb_b) = (
            hex64(&format!("i118c-a-{s}")),
            hex64(&format!("i118c-b-{s}")),
        );
        let local = |id: &str, thumb: &str| {
            LocalAttestationInput {
            attestation_id: Some(id.to_owned()),
            attesting_key_id: signer.clone(),
            attested_key_id: Some(signer.clone()),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: EnvelopeCore::from_value(serde_json::json!({
                "dimension": "external_content:image:v1", "evidence_refs": [thumb],
                "media": {"digest": thumb, "size": 96, "format": "image/webp", "name": "poster", "derived_from": original},
            }))
            .unwrap(),
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        }
        };
        let id_a = format!("i118c-a-row-{s}");
        d.attestation_upsert_local(local(&id_a, &thumb_a))
            .await
            .expect("I118c: a local rendition row is admitted");
        let got = d.list_derived_hex(&original).await.unwrap();
        assert_eq!(
            got.iter()
                .map(|r| (
                    r.rendition_sha256_hex.as_str(),
                    r.role.as_str(),
                    r.source_attestation_id.as_str(),
                    r.cohort_scope.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![(
                thumb_a.as_str(),
                "poster",
                id_a.as_str(),
                cohort_scope::SELF
            )],
            "I118c: the local door projects in the same write"
        );
        // Upsert-replace under the same (attesting, dimension): a NEW
        // rendition digest. The old projection must go with the old row.
        let id_b = format!("i118c-b-row-{s}");
        d.attestation_upsert_local(local(&id_b, &thumb_b))
            .await
            .expect("I118c: the replacing local row is admitted");
        assert!(
            d.get_attestation(&id_a).await.unwrap().is_none(),
            "I118c: the replaced row is gone"
        );
        let got = d.list_derived_hex(&original).await.unwrap();
        assert_eq!(
            got.iter()
                .map(|r| (
                    r.rendition_sha256_hex.as_str(),
                    r.source_attestation_id.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![(thumb_b.as_str(), id_b.as_str())],
            "I118c: exactly the replacing row's rendition remains"
        );
    }

    /// **I118b (blob half) — placement: a rendition at a different scope
    /// than a locally held original is refused.**
    // The blob-half bodies reach `key_grant_invariants::two_node`, which
    // exists only where a backend does (the #870 lesson: CI's
    // `--features server` job compiles tests with no backend and -D warnings).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i118b_placement_follows_the_original<B>(b: &B, s: &str)
    where
        B: crate::federation::BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::key_grant_invariants::two_node::node_as;
        use crate::federation::types::identity_type::NODE;
        use crate::federation::BlobBody;
        let n = node_as(b, &format!("i118b-n-{s}"), NODE).await;
        let bytes = format!("i118b original {s}").into_bytes();
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&bytes).into()
        };
        b.put_blob_signing_scoped(
            cohort_scope::FEDERATION,
            None,
            &sha,
            BlobBody::Inline(bytes),
            Some("image/png"),
            &n.key,
            &n.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
        let thumb = hex64(&format!("i118b-thumb-{s}"));
        let media = serde_json::json!({"digest": thumb, "size": 64, "format": "image/png", "name": "thumbnail", "derived_from": hex::encode(sha)});
        let err = put(
            b,
            media_row(
                &format!("i118b-wrong-{s}"),
                &n.key,
                &n.key,
                &thumb,
                media.clone(),
                cohort_scope::SPECIES,
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), "federation_media_source_invalid");
        assert!(
            err.to_string().contains("derived_from") && err.to_string().contains("cohort_scope"),
            "I118b: {err}"
        );
        put(
            b,
            media_row(
                &format!("i118b-right-{s}"),
                &n.key,
                &n.key,
                &thumb,
                media,
                cohort_scope::FEDERATION,
            ),
        )
        .await
        .expect("I118b: same scope as the original");
    }

    /// **I117d (blob half) — AV-89 at both doors: a claim whose `size` is
    /// not the byte length the door stores is refused before anything is
    /// written; the signer refuses a zero size outright; the same claim with
    /// the true length is admitted (the control).**
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i117d_a_claim_with_the_wrong_size_is_refused<B>(b: &B, s: &str)
    where
        B: crate::federation::BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::{fresh_dek, seal};
        use crate::federation::blobs::sign_holds_bytes_claim;
        use crate::federation::key_grant_invariants::two_node::{
            node_as, seed_community_everywhere,
        };
        use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
        use crate::federation::types::identity_type::NODE;
        use crate::federation::{BlobBody, BlobError, EpochBinding, StorageFloor};
        let n = node_as(b, &format!("i117d-n-{s}"), NODE).await;
        let now = chrono::Utc::now();
        // The put door.
        let bytes = format!("i117d public bytes {s}").into_bytes();
        let len = bytes.len() as u64;
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&bytes).into()
        };
        let zero = sign_holds_bytes_claim(&n.signer, &sha, &n.key, uuid::Uuid::new_v4(), now, 0)
            .await
            .expect_err("I117d: the signer refuses a zero size");
        assert!(
            matches!(zero, BlobError::InvalidArgument(_)),
            "I117d: {zero}"
        );
        let wrong =
            sign_holds_bytes_claim(&n.signer, &sha, &n.key, uuid::Uuid::new_v4(), now, len + 1)
                .await
                .unwrap();
        let err = b
            .put_blob_with_scope(
                None,
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                wrong,
                cohort_scope::FEDERATION,
                StorageFloor::resolved(CryptoTier::Plaintext),
            )
            .await
            .expect_err("I117d: the put door refuses a claim whose size is not the stored length");
        assert!(
            matches!(err, BlobError::InvalidArgument(_)) && err.to_string().contains("AV-89"),
            "I117d: {err}"
        );
        assert!(
            b.blob_cohort_scope(&sha).await.unwrap().is_none()
                && b.list_holders_sized(&sha).await.unwrap().is_empty(),
            "I117d: a refused put stores nothing and announces nothing"
        );
        let right = sign_holds_bytes_claim(&n.signer, &sha, &n.key, uuid::Uuid::new_v4(), now, len)
            .await
            .unwrap();
        b.put_blob_with_scope(
            None,
            &sha,
            BlobBody::Inline(bytes),
            None,
            right,
            cohort_scope::FEDERATION,
            StorageFloor::resolved(CryptoTier::Plaintext),
        )
        .await
        .expect("I117d: the true length is admitted");
        assert_eq!(b.list_holders_sized(&sha).await.unwrap()[0].size, len);
        // The adopt door, at the sealed community shape.
        let comm = format!("i117d-comm-{s}");
        seed_community_everywhere(&[&n], &comm, &[(&format!("i117d-m-{s}"), Some(&n))]).await;
        let envelope = seal(
            &fresh_dek().unwrap(),
            format!("i117d sealed {s}").as_bytes(),
            None,
        )
        .unwrap()
        .to_bytes();
        let elen = envelope.len() as u64;
        let esha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&envelope).into()
        };
        let binding = || {
            Some(EpochBinding {
                community_key_id: comm.clone(),
                minter_key_id: n.key.clone(),
                epoch: 0,
            })
        };
        let wrong = sign_holds_bytes_claim(
            &n.signer,
            &esha,
            &n.key,
            uuid::Uuid::new_v4(),
            now,
            elen + 1,
        )
        .await
        .unwrap();
        let err = b
            .adopt_sealed_blob_at(
                envelope.clone(),
                None,
                COMMUNITY,
                &n.key,
                StorageFloor::resolved(CryptoTier::CommunityDek),
                binding(),
                Some(wrong),
            )
            .await
            .expect_err(
                "I117d: the adopt door refuses an announce whose size is not the sealed length",
            );
        assert!(
            matches!(err, BlobError::InvalidArgument(_)) && err.to_string().contains("AV-89"),
            "I117d: {err}"
        );
        assert!(
            b.blob_cohort_scope(&esha).await.unwrap().is_none(),
            "I117d: a refused adopt stores nothing"
        );
        let right =
            sign_holds_bytes_claim(&n.signer, &esha, &n.key, uuid::Uuid::new_v4(), now, elen)
                .await
                .unwrap();
        let got = b
            .adopt_sealed_blob_at(
                envelope,
                None,
                COMMUNITY,
                &n.key,
                StorageFloor::resolved(CryptoTier::CommunityDek),
                binding(),
                Some(right),
            )
            .await
            .expect("I117d: the true sealed length is admitted");
        assert_eq!(got, esha);
        assert_eq!(b.list_holders_sized(&esha).await.unwrap()[0].size, elen);
    }

    /// **I119b — the promotion chokepoint refuses the struct, behaviourally.**
    /// A local row admitted before this cut carries no guarantee; the crossing
    /// asks the same gate (`check_promotion_admission`, the one function every
    /// promotion runs through `plan_enter_mesh`). Driven directly, as the
    /// bootstrap witnesses drive it: a malformed struct is refused by kind, a
    /// well-formed one is not refused by THIS kind.
    pub async fn i119b_the_promotion_chokepoint_refuses_the_struct(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        use crate::federation::admission::check_promotion_admission;
        let (signer, target) = (format!("i119b-s-{s}"), format!("i119b-t-{s}"));
        ts::register_identity_key(d, &signer, USER).await;
        ts::register_identity_key(d, &target, USER).await;
        let digest = hex64(&format!("i119b-{s}"));
        let bad = media_row(
            &format!("i119b-bad-{s}"),
            &signer,
            &target,
            &digest,
            serde_json::json!({"digest": digest, "format": "image/png", "safe": true}),
            cohort_scope::FEDERATION,
        );
        let err = check_promotion_admission(d, &bad, None)
            .await
            .expect_err("I119b: the chokepoint refuses a malformed struct");
        assert_eq!(
            err.kind(),
            "federation_media_source_invalid",
            "I119b: {err}"
        );
        let good = media_row(
            &format!("i119b-good-{s}"),
            &signer,
            &target,
            &digest,
            serde_json::json!({"digest": digest, "size": 7, "format": "image/png"}),
            cohort_scope::FEDERATION,
        );
        if let Err(err) = check_promotion_admission(d, &good, None).await {
            assert_ne!(
                err.kind(),
                "federation_media_source_invalid",
                "I119b: a well-formed struct is not what the chokepoint refuses: {err}"
            );
        }
        // The holder claim's size, carried to the same site: a `holds_bytes`
        // row without `size` does not cross either.
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(format!("i119b-bytes-{s}").as_bytes()).into()
        };
        let mut sizeless = row(
            &format!("i119b-sizeless-{s}"),
            &signer,
            &signer,
            serde_json::json!({"kind": "holds_bytes", "evidence_refs": [hex::encode(sha)]}),
            cohort_scope::FEDERATION,
        );
        sizeless.attestation_type = crate::federation::holds_bytes_attestation_type(&sha);
        ts::reseal(&mut sizeless);
        let err = check_promotion_admission(d, &sizeless, None)
            .await
            .expect_err("I119b: the chokepoint refuses a size-less holder claim");
        assert_eq!(
            err.kind(),
            "federation_media_source_invalid",
            "I119b: {err}"
        );
        assert!(err.to_string().contains("size"), "I119b: {err}");
    }

    /// **I117 (blob half) — the two doors' claims carry the stored length,
    /// and it crosses to a peer.**
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i117b_the_doors_carry_the_stored_length<B>(a: &B, b: &B, s: &str)
    where
        B: crate::federation::BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::adopt_cascade::{adopt_sealed_blob, AdoptDisposition};
        use crate::federation::at_rest_cascade::blob_invariants::hold_ctx;
        use crate::federation::at_rest_cascade::{fresh_dek, seal};
        use crate::federation::key_grant_invariants::two_node::{
            introduce_as, node_as, seed_community_everywhere,
        };
        use crate::federation::replication::hold::BlobProvenance;
        use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
        use crate::federation::types::identity_type::NODE;
        use crate::federation::BlobBody;
        let na = node_as(a, &format!("i117b-a-{s}"), NODE).await;
        let nb = node_as(b, &format!("i117b-b-{s}"), NODE).await;
        introduce_as(
            &[&na, &nb],
            &[&format!("i117b-a-{s}"), &format!("i117b-b-{s}")],
            NODE,
        )
        .await;
        // The put door.
        let bytes = format!("i117b public bytes {s}").into_bytes();
        let len = bytes.len() as u64;
        let sha: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(&bytes).into()
        };
        a.put_blob_signing_scoped(
            cohort_scope::FEDERATION,
            None,
            &sha,
            BlobBody::Inline(bytes),
            None,
            &na.key,
            &na.signer,
            chrono::Utc::now(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
        let sized = a.list_holders_sized(&sha).await.unwrap();
        assert_eq!(
            (sized[0].key_id.as_str(), sized[0].size),
            (na.key.as_str(), len),
            "I117b: the put door's claim carries the stored length"
        );
        // The claim crosses with its size (the #870 shape: hashes → point reads → apply).
        let mut cursor: Option<String> = None;
        loop {
            let page = a
                .list_wire_hashes_since("Attestation", cursor.as_deref(), 256)
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            cursor = page.last().cloned();
            for h in &page {
                let bytes = a
                    .lookup_signed_record_by_content_hash("Attestation", h)
                    .await
                    .unwrap()
                    .expect("advertised is fetchable (#870)");
                let r: Attestation = serde_json::from_slice(&bytes).unwrap();
                let _ = b
                    .apply_replicated_attestation(SignedAttestation { attestation: r })
                    .await
                    .unwrap();
            }
        }
        let on_b = b.list_holders_sized(&sha).await.unwrap();
        assert_eq!(
            (on_b[0].key_id.as_str(), on_b[0].size),
            (na.key.as_str(), len),
            "I117b: the peer learned the holder AND the size"
        );
        // The adopt door, at the sealed community shape.
        let comm = format!("i117b-comm-{s}");
        seed_community_everywhere(&[&nb], &comm, &[(&format!("i117b-m-{s}"), Some(&nb))]).await;
        let envelope = seal(
            &fresh_dek().unwrap(),
            format!("i117b sealed {s}").as_bytes(),
            None,
        )
        .unwrap()
        .to_bytes();
        let elen = envelope.len() as u64;
        let ctx = hold_ctx(false, &nb.key, &[]);
        let out = adopt_sealed_blob(
            b,
            Some(&*nb.signer),
            &ctx,
            &envelope,
            &BlobProvenance {
                author_key_id: na.key.clone(),
                cohort_scope: COMMUNITY.to_owned(),
                community_key_id: Some(comm),
                epoch: Some(0),
                tier: CryptoTier::CommunityDek,
            },
            None,
            AdoptDisposition::Announce,
        )
        .await
        .unwrap();
        let sized = b.list_holders_sized(&out.sha256).await.unwrap();
        assert_eq!(
            (sized[0].key_id.as_str(), sized[0].size),
            (nb.key.as_str(), elen),
            "I117b: the adopt door's claim carries the stored length"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    /// The source lines that are not comments, `//` tails removed.
    fn live_lines(text: &str) -> impl Iterator<Item = &str> {
        text.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .filter(|l| !l.trim().is_empty())
    }

    /// **I119 — from disk: the gate at every door, the vocabulary lists the
    /// member, and every blob write door stores size + validated format.**
    #[test]
    fn i119_every_door_and_the_vocabulary() {
        const SQLITE: &str = include_str!("../store/sqlite.rs");
        const PG: &str = include_str!("../store/postgres.rs");
        const MEM: &str = include_str!("../store/memory.rs");
        const ADMISSION: &str = include_str!("admission.rs");
        const ENVELOPE: &str = include_str!("envelope.rs");
        for (name, text, n) in [
            ("sqlite.rs", SQLITE, 2),
            ("postgres.rs", PG, 2),
            ("memory.rs", MEM, 2),
            ("admission.rs", ADMISSION, 1),
        ] {
            // Comment lines do not count: a commented-out call is not a door
            // (the `store::parity` discipline, applied to this grep).
            let calls = live_lines(text)
                .filter(|l| l.contains("check_media_source("))
                .count();
            assert!(
                calls >= n,
                "I119: {name} runs the media gate at its doors ({calls} < {n})"
            );
        }
        assert!(
            ENVELOPE.contains("paths::MEDIA,"),
            "I119: the vocabulary manifest lists the member (and re-pins)"
        );
        for (name, text) in [("sqlite.rs", SQLITE), ("postgres.rs", PG)] {
            for door in [
                "async fn put_blob_with_scope(",
                "async fn adopt_sealed_blob_at(",
            ] {
                let body = text
                    .split(door)
                    .nth(1)
                    .unwrap_or_else(|| panic!("I119: {name} has {door}"));
                let body = &body[..body.find("\n    }\n").expect("end")];
                assert!(
                    body.contains("size_bytes")
                        || body.contains("size_i64")
                        || body.contains("size,"),
                    "I119: {name} {door} stores the size"
                );
                assert!(
                    live_lines(body).any(|l| l.contains("index_holder_claim(")),
                    "I119: {name} {door} indexes the claim (#870)"
                );
            }
        }
        assert!(
            crate::federation::envelope::envelope_vocabulary_sha256()
                == crate::federation::envelope::ENVELOPE_VOCABULARY_SHA256,
            "I120: the vocabulary hash is re-pinned deliberately"
        );
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i115() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i115_the_struct_is_refused_by_name(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i116() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i116_the_struct_cites_what_the_row_cites(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i117() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i117_a_claim_without_size_is_refused(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i118() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i118_the_rendition_index(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i119b() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i119b_the_promotion_chokepoint_refuses_the_struct(&b, &super::suffix())
                        .await
                }
                #[tokio::test]
                async fn i118c() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i118c_the_local_door_projects_and_replace_retires(&b, &super::suffix())
                        .await
                }
            }
        };
    }
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    macro_rules! blob_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i117b() {
                    let Some(a) = $fresh.await else { return };
                    let Some(b) = $fresh.await else { return };
                    bodies::i117b_the_doors_carry_the_stored_length(&a, &b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i117d() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i117d_a_claim_with_the_wrong_size_is_refused(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i118b() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i118b_placement_follows_the_original(&b, &super::suffix()).await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "sqlite")]
    blob_runners!(sqlite_blob, async {
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
    #[cfg(feature = "postgres")]
    blob_runners!(postgres_blob, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
