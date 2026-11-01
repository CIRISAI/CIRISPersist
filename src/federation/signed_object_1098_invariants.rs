//! CIRISPersist#1098 (CC 2.6.1.1.1 and 2.6.1.7) — **I1478, I1479, I1493, I1494: the
//! signed-object cleanup**, and I1496 and I1498 from the CC re-vendors, on
//! every backend, through `put_attestation`.
//!
//! - **I1478 (F4, `envelope_member_null`)** — an optional envelope member
//!   written as an explicit JSON `null`, at the top level or inside the `row`
//!   mirror, is refused `federation_malformed_row` / `envelope_member_null`
//!   naming the member; the same row with the member absent admits.
//! - **I1479 (F5, `witnesses[]` is a set)** — a `witnesses` array sorted by
//!   each element's JCS string and carrying no repeat admits; an out-of-order
//!   pair and a repeat are refused `federation_set_semantics_unsorted`; a
//!   `witnesses` that is not an array is `envelope_member_invalid`.
//! - **I1493 (F2, a bare scope token)** — `"scope": "retain"` admits as the
//!   one-element set `["retain"]` denotes: every scope reader answers the same
//!   for both forms, and the stored envelope keeps the bare token (signed
//!   bytes are never normalised).
//! - **I1494 (the 13 vectors)** — CC's `signed_object_vectors.json` at the
//!   vendored tag, replayed: each admit vector's signed row (and each recipe's
//!   reconstructed one) admits with its published content hash, and each
//!   refuse vector is refused with the persist token its CC refusal names.
//!   The three vectors persist answers differently are recorded in
//!   `DIVERGENCES` with the ruling that keeps each, a latch both ways.
//! - **I1496 (rc12, `observation:access_assumption` at `+1.0` only)** — the
//!   leaf the rc12 registry adds admits a score of `1.0` and refuses any other
//!   with `score_outside_declared_polarity` (CC 3.1.9.4; its first-person rule
//!   is CIRISPersist#1115). Carried from the rc12 side branch, where it was
//!   I1482 (v59.1.2 shipped I1480–I1483).
//! - **I1498 (rc13, `listed` retired)** — CC removed `listed` from CC 2.1, the
//!   defaults table and the signed object, and persist no longer types it
//!   (#991). At admission it is an unknown envelope member like any other
//!   `signed:envelope-extra`: carried untyped, a value of any type admits (a
//!   non-boolean was ill-typed while it was a typed member), the stored bytes
//!   keep it as signed, and only the general rule refuses it, as
//!   `envelope_member_null` when written `null`.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::malformed_row;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, Attestation};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    fn ms_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("ms")
    }

    /// A self-report by `who` carrying `extra` members, sealed (mirror
    /// stamped, hybrid-signed).
    fn sealed_with(who: &str, extra: serde_json::Value) -> Attestation {
        let leaf = uuid::Uuid::new_v4().simple().to_string();
        let mut env = serde_json::json!({ "dimension": format!("config:act{}:v1", &leaf[..8]) });
        for (k, v) in extra.as_object().expect("extra is an object") {
            env[k] = v.clone();
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut r = ts::bare_attestation(&id, who, who, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = ms_now();
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(who, &mut r);
        r
    }

    /// Re-sign the envelope as it stands, without re-stamping the mirror.
    fn resign_only(who: &str, r: &mut Attestation) {
        let (och, sc, sp) = ts::sign_envelope(who, &r.attestation_envelope);
        r.original_content_hash = och;
        r.scrub_signature_classical = sc;
        r.scrub_signature_pqc = sp;
    }

    fn malformed_reason(e: Error, what: &str) -> &'static str {
        assert_eq!(e.kind(), "federation_malformed_row", "{what}: {e}");
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => panic!("{what}: expected a malformed row, got {other:?}"),
        }
    }

    async fn put(d: &dyn FederationDirectory, r: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .map(|_| ())
    }

    /// **I1478** — `envelope_member_null`.
    pub(crate) async fn i1478_envelope_member_null(d: &dyn FederationDirectory, tag: &str) {
        let a = format!("i1478-{tag}");
        ts::register_hybrid_key_as(d, &a, &a, it::USER).await;

        let top = sealed_with(&a, serde_json::json!({ "context": null }));
        let e = put(d, top)
            .await
            .expect_err("I1478: a top-level null member is refused");
        let message = e.to_string();
        assert_eq!(
            malformed_reason(e, "I1478 top"),
            malformed_row::ENVELOPE_MEMBER_NULL
        );
        assert!(
            message.contains("`context`"),
            "I1478 names the member: {message}"
        );

        let mut mirror = sealed_with(&a, serde_json::json!({}));
        mirror.attestation_envelope["row"]["weight"] = serde_json::Value::Null;
        resign_only(&a, &mut mirror);
        let e = put(d, mirror)
            .await
            .expect_err("I1478: a null mirror member is refused");
        let message = e.to_string();
        assert_eq!(
            malformed_reason(e, "I1478 mirror"),
            malformed_row::ENVELOPE_MEMBER_NULL
        );
        assert!(
            message.contains("`row.weight`"),
            "I1478 names the member: {message}"
        );

        // The #1151 carve-out is `role` on the two membership families only:
        // `role: null` on any other family is still refused.
        let e = put(d, sealed_with(&a, serde_json::json!({ "role": null })))
            .await
            .expect_err("I1478: role null outside membership rows is refused");
        assert_eq!(
            malformed_reason(e, "I1478 role"),
            malformed_row::ENVELOPE_MEMBER_NULL
        );

        put(d, sealed_with(&a, serde_json::json!({ "context": "x" })))
            .await
            .expect("I1478: the member carried as a value admits");
        put(d, sealed_with(&a, serde_json::json!({})))
            .await
            .expect("I1478: the member absent admits");
    }

    /// **I1479** — `witnesses[]` is a set.
    pub(crate) async fn i1479_witnesses_is_a_set(d: &dyn FederationDirectory, tag: &str) {
        let a = format!("i1479-{tag}");
        ts::register_hybrid_key_as(d, &a, &a, it::USER).await;
        let w = |k: &str| serde_json::json!({ "record": { "key_id": k } });
        // JCS strings: `{"record":{"key_id":"w-a"}}` < `…"w-b"…`.
        let sorted = serde_json::json!([w("w-a"), w("w-b")]);
        let unsorted = serde_json::json!([w("w-b"), w("w-a")]);
        let repeated = serde_json::json!([w("w-a"), w("w-a")]);

        for (what, witnesses) in [("unsorted", unsorted), ("repeated", repeated)] {
            let e = put(
                d,
                sealed_with(&a, serde_json::json!({ "witnesses": witnesses })),
            )
            .await
            .expect_err("I1479: an unsorted or repeated set is refused");
            assert_eq!(
                e.kind(),
                "federation_set_semantics_unsorted",
                "I1479 {what}: {e}"
            );
            assert!(
                e.to_string().contains("`witnesses`"),
                "I1479 {what} names the member"
            );
        }
        let e = put(
            d,
            sealed_with(&a, serde_json::json!({ "witnesses": "w-a" })),
        )
        .await
        .expect_err("I1479: a witnesses member that is not an array is refused");
        assert_eq!(
            malformed_reason(e, "I1479 not an array"),
            malformed_row::ENVELOPE_MEMBER_INVALID
        );
        put(
            d,
            sealed_with(&a, serde_json::json!({ "witnesses": sorted })),
        )
        .await
        .expect("I1479: a sorted, unique set admits");
    }

    /// **I1493** — a bare scope token admits as the one-element array it
    /// denotes, and the stored bytes keep the bare token.
    pub(crate) async fn i1493_a_bare_scope_token(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::admission::delegation_scope_set;
        use crate::federation::consent::named_scopes;
        let a = format!("i1493-{tag}");
        ts::register_hybrid_key_as(d, &a, &a, it::USER).await;
        let bare = sealed_with(&a, serde_json::json!({ "scope": "retain" }));
        let array = sealed_with(&a, serde_json::json!({ "scope": ["retain"] }));
        assert_eq!(
            named_scopes(&bare),
            named_scopes(&array),
            "I1493 consent reader"
        );
        assert_eq!(
            delegation_scope_set(&bare.attestation_envelope),
            delegation_scope_set(&array.attestation_envelope),
            "I1493 delegation reader"
        );
        assert!(
            crate::federation::trust_root::scope_contains(&bare.attestation_envelope, "retain")
                && crate::federation::trust_root::scope_contains(
                    &array.attestation_envelope,
                    "retain"
                ),
            "I1493 scope_contains"
        );
        let (bare_id, bare_hash) = (
            bare.attestation_id.clone(),
            bare.original_content_hash.clone(),
        );
        put(d, bare).await.expect("I1493: a bare token admits");
        put(d, array).await.expect("I1493: the array admits");
        let stored = d
            .get_attestation(&bare_id)
            .await
            .expect("read")
            .expect("I1493: the bare-token row is held");
        assert_eq!(
            stored.attestation_envelope["scope"],
            serde_json::json!("retain"),
            "I1493: the stored envelope keeps the bare token"
        );
        assert_eq!(
            stored.original_content_hash, bare_hash,
            "I1493: the signed bytes are the producer's"
        );
    }

    // ─── I1494 — CC's 13 signed-object vectors ─────────────────────────────

    const VECTORS: &str = include_str!("namespace/signed_object_vectors.json");

    struct VectorKey {
        key_id: String,
        ed: ciris_crypto::Ed25519Signer,
        mldsa: ciris_crypto::MlDsa65Signer,
        ed_pub_b64: String,
        mldsa_pub_b64: String,
    }

    fn seed(hexed: &serde_json::Value) -> [u8; 32] {
        hex::decode(hexed.as_str().expect("hex seed"))
            .expect("seed hex")
            .try_into()
            .expect("32-byte seed")
    }

    fn vector_key(k: &serde_json::Value) -> VectorKey {
        use base64::Engine as _;
        let b64 = |h: &serde_json::Value| {
            base64::engine::general_purpose::STANDARD
                .encode(hex::decode(h.as_str().expect("hex")).expect("hex"))
        };
        VectorKey {
            key_id: k["key_id"].as_str().expect("key_id").to_owned(),
            ed: ciris_crypto::Ed25519Signer::from_seed(&seed(&k["ed25519_seed_hex"]))
                .expect("ed seed"),
            mldsa: ciris_crypto::MlDsa65Signer::from_seed(&seed(&k["mldsa65_seed_hex"]))
                .expect("mldsa seed"),
            ed_pub_b64: b64(&k["ed25519_pub_hex"]),
            mldsa_pub_b64: b64(&k["mldsa65_pub_hex"]),
        }
    }

    /// Register a vector key with its published pubkeys, valid from before the
    /// vectors' instants (2026-10-18).
    async fn register_vector_key(d: &dyn FederationDirectory, k: &VectorKey) {
        let from = "2026-10-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("instant");
        let rec = crate::federation::KeyRecord {
            key_id: k.key_id.clone(),
            pubkey_ed25519_base64: k.ed_pub_b64.clone(),
            pubkey_ml_dsa_65_base64: Some(k.mldsa_pub_b64.clone()),
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: it::USER.to_owned(),
            identity_ref: k.key_id.clone(),
            valid_from: from,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": k.key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: k.key_id.clone(),
            scrub_timestamp: from,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: Some(
                crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(
                ),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        d.put_public_key(crate::federation::SignedKeyRecord { record: rec })
            .await
            .expect("register vector key");
    }

    /// The community a vector's row is scoped to, held here with `member`
    /// seated from before the vectors' instants, so the cohort-standing gate
    /// has a roster to read.
    async fn hold_community(
        d: &dyn FederationDirectory,
        community_key_id: &str,
        member: &VectorKey,
    ) {
        let from = "2026-10-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("instant");
        ts::register_hybrid_key_as(d, community_key_id, community_key_id, it::USER).await;
        let community = crate::federation::types::Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: community_key_id.to_owned(),
            community_name: "I1494 ward".into(),
            members: vec![crate::federation::types::CommunityMember {
                key_id: member.key_id.clone(),
                joined_at: from,
                role: None,
            }],
            founded_at: from,
            consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY.into(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        let mut signed = ts::sign_community(community_key_id, community);
        // The member's founding cosignature, by the vector key's own pen.
        let envelope = signed.community.signing_envelope();
        let (_, classical, pqc) = ts::sign_envelope_with(&member.ed, &member.mldsa, &envelope);
        signed.cosignatures = vec![crate::federation::types::RosterCosignature {
            authority_key_id: member.key_id.clone(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }];
        d.put_community(signed)
            .await
            .unwrap_or_else(|e| panic!("I1494: hold community {community_key_id}: {e}"));
    }

    fn instant(v: &serde_json::Value) -> chrono::DateTime<chrono::Utc> {
        v.as_str()
            .expect("instant string")
            .parse()
            .expect("RFC 3339 instant")
    }

    /// The row an envelope describes: its columns read from the signed `row`
    /// mirror where the envelope carries one, signed by `signer`.
    fn row_for(envelope: &serde_json::Value, signer: &VectorKey) -> Attestation {
        let mirror = envelope
            .get("row")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let s = |k: &str, default: &str| {
            mirror
                .get(k)
                .and_then(serde_json::Value::as_str)
                .unwrap_or(default)
                .to_owned()
        };
        let id = s("attestation_id", "00000000-0000-4000-8000-000000001481");
        let mut r = ts::bare_attestation(
            &id,
            &s("attesting_key_id", &signer.key_id),
            &s("attested_key_id", &signer.key_id),
            envelope,
        );
        r.attestation_type = s("attestation_type", attestation_type::SCORES);
        r.cohort_scope = s("cohort_scope", "federation");
        r.subject_key_ids = mirror
            .get("subject_key_ids")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        r.weight = mirror.get("weight").and_then(serde_json::Value::as_f64);
        r.asserted_at = envelope
            .get("asserted_at")
            .and_then(serde_json::Value::as_str)
            .and_then(|t| t.parse().ok())
            .unwrap_or_else(ms_now);
        r.scrub_timestamp = r.asserted_at;
        r.pqc_completed_at = Some(r.asserted_at);
        let (och, sc, sp) = ts::sign_envelope_with(&signer.ed, &signer.mldsa, envelope);
        r.original_content_hash = och;
        r.scrub_signature_classical = sc;
        r.scrub_signature_pqc = sp;
        r
    }

    /// An admit vector's published row, as persist's [`Attestation`].
    fn published_row(row: &serde_json::Value) -> Attestation {
        let s = |k: &str| {
            row[k]
                .as_str()
                .unwrap_or_else(|| panic!("row.{k}"))
                .to_owned()
        };
        let mut r = ts::bare_attestation(
            &s("attestation_id"),
            &s("attesting_key_id"),
            &s("attested_key_id"),
            &row["attestation_envelope"],
        );
        r.attestation_type = s("attestation_type");
        r.cohort_scope = s("cohort_scope");
        r.subject_key_ids = row
            .get("subject_key_ids")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        r.weight = row.get("weight").and_then(serde_json::Value::as_f64);
        r.asserted_at = instant(&row["asserted_at"]);
        r.expires_at = row.get("expires_at").map(instant);
        r.scrub_key_id = s("scrub_key_id");
        r.scrub_timestamp = instant(&row["scrub_timestamp"]);
        r.pqc_completed_at = Some(instant(&row["pqc_completed_at"]));
        r.original_content_hash = s("original_content_hash");
        r.scrub_signature_classical = s("scrub_signature_classical");
        r.scrub_signature_pqc = Some(s("scrub_signature_pqc"));
        if let Some(scrubs) = row.get("additional_scrubs") {
            r.additional_scrubs =
                serde_json::from_value(scrubs.clone()).expect("additional_scrubs");
        }
        r
    }

    /// Vectors persist answers differently from CC, each with the token persist
    /// emits and the ruling that keeps it. A latch both ways: a vector that
    /// starts agreeing, or a new disagreement, reds I1494.
    ///
    /// - `scores_subject_and_scope`: persist KEEPS refusing, now on the
    ///   `named_subject` arm (AV-84, CIRISPersist#592). CC re-minted the vector
    ///   on rc13 (`6054a03`): the producer is in `attested_key_id`, so the
    ///   `attested_party` arm no longer fires, but the third party stays in
    ///   `subject_key_ids`, and CC 2.1 (rc14) admits a targeted row naming
    ///   "the party it is about in `subject_key_ids`". Persist refuses any
    ///   foreign subject at a targeted scope (subject-naming is the
    ///   revocability-authority surface). Measured at the rc14 re-vendor. Ruled
    ///   for v61 S1: the arm stays (a security property); it is decided in S2
    ///   with the community-scope moderation carve-out on the same AV-84 doors
    ///   (CIRISPersist#1161).
    /// - `refuse_row_type`: the allowlist stays Report-only until the Enforce
    ///   flip's data preconditions are met (CIRISPersist#1150).
    /// - `refuse_timestamp_form`: CC 2.6.2 says a producer MUST write `Z` with
    ///   exactly three fractional digits. Admission keeps accepting other RFC
    ///   3339 forms until the steward rules on the upgrade path, because
    ///   refusing them would refuse replicated rows from every older peer.
    ///   Persist's own signed-instant emitters, as of this cut (the producer
    ///   fix is S3):
    ///   - CC's form (`render_signed_instant`, Millis + `Z`): the attestation
    ///     emit paths that stamp `asserted_at` / `expires_at`.
    ///   - `+00:00` (chrono's `to_rfc3339()`): `hard_case::membership_removed_event`
    ///     (`effective_at`), `mesh_config::mesh_config_envelope` (`valid_until`),
    ///     `ingest::scrub_preimage` (`scrub_timestamp`) and
    ///     `admission::revocation_binding` (the key plane's `scrub_timestamp`).
    ///   - `Z` with six digits: `admission::trust_revocation_signing_bytes`
    ///     (`revoked_at`); `Z` with none: `transform::round_timestamp`.
    const DIVERGENCES: &[(&str, &str, &str)] = &[
        (
            "scores_subject_and_scope",
            "federation_cohort_standing_refused",
            "persist refuses a targeted-cohort row whose subject_key_ids names a party other \
             than its producer (AV-84 named_subject, CIRISPersist#592); CC 2.1 at rc14 admits \
             it, and the rc13 re-mint (6054a03) moved only attested_key_id; decided in S2 with \
             CIRISPersist#1161",
        ),
        (
            "refuse_row_type",
            "admitted",
            "the row-type allowlist is Report-only until the Enforce flip's preconditions are \
             met (CIRISPersist#1150)",
        ),
        (
            "refuse_timestamp_form",
            "admitted",
            "admission accepts any RFC 3339 form until the steward's upgrade-path ruling; \
             persist's producers move to CC 2.6.2's form in S3",
        ),
    ];

    /// CC's refusal (a token or a description) → the token persist emits.
    fn persist_token_for(cc_refusal: &str) -> &'static str {
        match cc_refusal {
            "ENVELOPE_TOO_LARGE" => "federation_envelope_too_large",
            "envelope_member_missing" => malformed_row::ENVELOPE_MEMBER_MISSING,
            "envelope_member_invalid" => malformed_row::ENVELOPE_MEMBER_INVALID,
            "typed_diverges_from_envelope" => malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
            "attestation_type_unregistered" => "federation_attestation_type_unregistered",
            r if r.starts_with("cohort_scope not in the closed set") => {
                "federation_cohort_scope_rejected"
            }
            r if r.starts_with("subject_key_ids element malformed") => {
                malformed_row::SUBJECT_KEY_ID_MALFORMED
            }
            other => panic!("I1494: no persist token is mapped for CC refusal {other:?}"),
        }
    }

    /// The token a refusal carries: a malformed row's reason, else its kind.
    fn token_of(e: &Error) -> &'static str {
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => other.kind(),
        }
    }

    /// **I1496** — `observation:access_assumption:v1` is `+1.0` only.
    pub(crate) async fn i1496_access_assumption_is_plus_one_only(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let a = format!("i1496-{tag}");
        ts::register_hybrid_key_as(d, &a, &a, it::USER).await;
        let row = |score: f64| {
            let mut r = sealed_with(&a, serde_json::json!({ "score": score }));
            r.attestation_envelope["dimension"] =
                serde_json::json!("observation:access_assumption:v1");
            r.subject_key_ids = vec![a.clone()];
            ts::seal_row_in_place(&a, &mut r);
            r
        };
        for score in [0.5, -1.0, 0.0] {
            let e = put(d, row(score))
                .await
                .expect_err("I1496: a score other than +1.0 is refused");
            assert!(
                e.to_string().contains("score_outside_declared_polarity"),
                "I1496 score {score}: {e}"
            );
        }
        put(d, row(1.0))
            .await
            .expect("I1496: +1.0 admits on the vendored registry");
    }

    /// **I1498** — `listed` is an unknown envelope member at admission.
    pub(crate) async fn i1498_listed_is_an_unknown_member(d: &dyn FederationDirectory, tag: &str) {
        let a = format!("i1498-{tag}");
        ts::register_hybrid_key_as(d, &a, &a, it::USER).await;
        for value in [
            serde_json::json!(true),
            serde_json::json!("public"),
            serde_json::json!({ "members": [] }),
        ] {
            let r = sealed_with(&a, serde_json::json!({ "listed": value }));
            let (id, hash) = (r.attestation_id.clone(), r.original_content_hash.clone());
            put(d, r)
                .await
                .unwrap_or_else(|e| panic!("I1498: `listed: {value}` admits untyped: {e}"));
            let stored = d
                .get_attestation(&id)
                .await
                .expect("read")
                .expect("I1498: the row is held");
            assert_eq!(
                stored.attestation_envelope["listed"], value,
                "I1498: the stored envelope keeps `listed` as signed"
            );
            assert_eq!(
                stored.original_content_hash, hash,
                "I1498: the producer's bytes"
            );
        }
        let nulled = sealed_with(&a, serde_json::json!({ "listed": null }));
        let e = put(d, nulled)
            .await
            .expect_err("I1498: `listed: null` meets the general null rule");
        assert_eq!(
            malformed_reason(e, "I1498 null"),
            malformed_row::ENVELOPE_MEMBER_NULL
        );
    }

    /// **I1494** — the 13 vectors. Each runs on a fresh store from
    /// `fresh()`, because two vectors share an attestation id over different
    /// bytes.
    pub(crate) async fn i1494_the_signed_object_vectors<D, F, Fut>(fresh: F)
    where
        D: FederationDirectory,
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = D>,
    {
        let doc: serde_json::Value = serde_json::from_str(VECTORS).expect("vectors parse");
        let a = vector_key(&doc["keys"]["A"]);
        let b = vector_key(&doc["keys"]["B"]);
        let vectors = doc["vectors"].as_array().expect("vectors");
        assert_eq!(vectors.len(), 13, "CC publishes 13 signed-object vectors");
        let minimal = vectors
            .iter()
            .find(|v| v["name"] == "scores_minimal")
            .expect("scores_minimal");
        // (vector, what CC expects, what persist did) — `None` is "admitted".
        let mut outcomes: Vec<(String, Option<&'static str>, Option<String>)> = Vec::new();
        for v in vectors {
            let name = v["name"].as_str().expect("name");
            let d = fresh().await;
            register_vector_key(&d, &a).await;
            register_vector_key(&d, &b).await;
            let (expected, row) = match v["kind"].as_str().expect("kind") {
                "admit" => {
                    if name == "withdraws" {
                        put(&d, published_row(&minimal["row"]))
                            .await
                            .expect("I1494 withdraws: the row it withdraws is held");
                    }
                    let row = published_row(&v["row"]);
                    if let Some(c) = row.attestation_envelope["community_id"].as_str() {
                        hold_community(&d, c, &a).await;
                    }
                    let (_, sc, _) =
                        ts::sign_envelope_with(&a.ed, &a.mldsa, &row.attestation_envelope);
                    assert_eq!(
                        sc, row.scrub_signature_classical,
                        "I1494 {name}: persist's canonical bytes sign to the published Ed25519 \
                         signature"
                    );
                    (None, row)
                }
                "recipe" => {
                    let mut env = v["envelope_template"].clone();
                    let len = v["context_length"].as_u64().expect("context_length") as usize;
                    env["context"] = serde_json::json!("a".repeat(len));
                    let row = row_for(&env, &a);
                    assert_eq!(
                        row.original_content_hash,
                        v["original_content_hash"].as_str().expect("hash"),
                        "I1494 {name}: the reconstructed bytes are CC's"
                    );
                    let expected = v
                        .get("refusal")
                        .and_then(serde_json::Value::as_str)
                        .map(persist_token_for);
                    (expected, row)
                }
                "refuse" => {
                    let cc = v["refusal"].as_str().expect("refusal");
                    let row = match v.get("row") {
                        Some(published) => published_row(published),
                        None => row_for(&v["envelope"], &a),
                    };
                    (Some(persist_token_for(cc)), row)
                }
                other => panic!("I1494 {name}: unknown vector kind {other:?}"),
            };
            let actual = put(&d, row)
                .await
                .err()
                .map(|e| format!("{}: {e}", token_of(&e)));
            outcomes.push((name.to_owned(), expected, actual));
        }
        assert_eq!(outcomes.len(), 13, "I1494: every vector ran");
        let token = |actual: &Option<String>| {
            actual
                .as_deref()
                .map(|s| s.split(':').next().unwrap_or(s).to_owned())
        };
        let mut disagree = Vec::new();
        for (name, expected, actual) in &outcomes {
            let held = DIVERGENCES.iter().find(|(n, _, _)| n == name);
            let got = token(actual).or_else(|| Some("admitted".to_owned()));
            let expected_token = expected.unwrap_or("admitted");
            match held {
                None if got.as_deref() != Some(expected_token) => {
                    disagree.push(format!("{name}: CC {expected:?}, persist {actual:?}"));
                }
                Some((_, persist, _)) if got.as_deref() != Some(*persist) => {
                    disagree.push(format!(
                        "{name}: recorded divergence {persist:?} no longer holds; persist \
                         {actual:?} (CC {expected:?}) — move the line"
                    ));
                }
                _ => {}
            }
        }
        assert!(disagree.is_empty(), "I1494: {disagree:#?}");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!("1098 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i1478, bodies::i1478_envelope_member_null);
    on_every_backend!(i1479, bodies::i1479_witnesses_is_a_set);
    on_every_backend!(i1493, bodies::i1493_a_bare_scope_token);
    on_every_backend!(i1496, bodies::i1496_access_assumption_is_plus_one_only);
    on_every_backend!(i1498, bodies::i1498_listed_is_an_unknown_member);

    mod i1494 {
        use super::*;

        #[cfg(feature = "sqlite")]
        #[tokio::test(flavor = "multi_thread")]
        async fn sqlite() {
            bodies::i1494_the_signed_object_vectors(|| async {
                use crate::store::Backend as _;
                let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                    .await
                    .unwrap();
                b.run_migrations().await.unwrap();
                b
            })
            .await;
        }

        #[cfg(feature = "postgres")]
        #[tokio::test(flavor = "multi_thread")]
        async fn postgres() {
            if crate::test_pg::empty_dsn().is_none() {
                eprintln!("1098 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                return;
            }
            bodies::i1494_the_signed_object_vectors(|| async {
                use crate::store::Backend as _;
                let dsn = crate::test_pg::empty_dsn().expect("dsn");
                let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                    .await
                    .unwrap();
                b.run_migrations().await.unwrap();
                b
            })
            .await;
            eprintln!("i1494: RAN");
        }
    }
}
