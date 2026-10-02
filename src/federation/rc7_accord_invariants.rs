//! v53.0.0 — **the rc7 accord cut** (CIRISConstitution rc7 `fe459cf` /
//! `5e89627`, CIRISConstitution#139): commitments bind key material, the
//! accord's charter commits a recovery key per holder, and acceptance edges
//! rotate the way grants do.
//!
//! - **I430** — the commitment bytes are CC's spelling: JCS of
//!   `{key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64}` elements sorted
//!   by `key_id`, lowercase-hex SHA-256; one key twice, or an empty set, is
//!   refused; a record with no ML-DSA-65 key forms no element.
//! - **I431** — the T3 recovery door recomputes each successor's element from
//!   the key record this node stores: a record under a committed id with other
//!   keys does not satisfy the commitment (the squat).
//! - **I432** — the accord's charter must carry `recovery_commitments`, one per
//!   standing holder.
//! - **I433** — a commitment for a key that is not a standing holder is
//!   refused (stray).
//! - **I434** — a recovery key that is a holder's signing key, or one recovery
//!   key shared by two holders, is refused (not apart).
//! - **I435** — a non-accord family's charter carries no such requirement.
//! - **I436** — an accord decision carries no steward signatures, and stores
//!   and reads back on every backend without them.
//! - **I437** — `trust_root_valid`'s edge leg reads a superseded acceptance
//!   edge the way the capability walk reads a superseded grant: the successor
//!   is the live edge and the edge it replaced is not.
//! - **I438** — `trusted_roots_of` agrees with I437.
//! - **I439** — a keyless family confers only as it charters (CC 3.4.7): a
//!   grant one holder signs confers nothing as the family; the same grant
//!   scrubbed to the family's quorum does.

#[cfg(test)]
pub(crate) mod pure {
    use crate::federation::trust_root::{
        pre_rotation_commitment, recovery_commitment, CommittedKey,
    };

    fn key(id: &str, ed: &str, mldsa: &str) -> CommittedKey {
        CommittedKey {
            key_id: id.to_owned(),
            pubkey_ed25519_base64: ed.to_owned(),
            pubkey_ml_dsa_65_base64: mldsa.to_owned(),
        }
    }

    fn sha_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(bytes))
    }

    /// **I430** — the bytes, spelled by hand from CC rc7 `5e89627`.
    #[test]
    fn i430_the_commitment_bytes_are_ccs_spelling() {
        // Given out of order: the construction sorts by key_id.
        let keys = [key("b-key", "RUQy", "TUwy"), key("a-key", "RUQx", "TUwx")];
        let spelled = concat!(
            r#"[{"key_id":"a-key","pubkey_ed25519_base64":"RUQx","pubkey_ml_dsa_65_base64":"TUwx"},"#,
            r#"{"key_id":"b-key","pubkey_ed25519_base64":"RUQy","pubkey_ml_dsa_65_base64":"TUwy"}]"#
        );
        assert_eq!(
            pre_rotation_commitment(&keys).unwrap(),
            sha_hex(spelled.as_bytes()),
            "I430: JCS of the sorted elements, lowercase-hex sha256"
        );
        // The per-holder recovery commitment is the same over one element.
        let one = r#"[{"key_id":"a-key","pubkey_ed25519_base64":"RUQx","pubkey_ml_dsa_65_base64":"TUwx"}]"#;
        assert_eq!(
            recovery_commitment(&keys[1]).unwrap(),
            sha_hex(one.as_bytes()),
            "I430: a recovery commitment is the one-element array"
        );
        // The pre-v53 id-only digest is not what is committed any more.
        assert_ne!(
            pre_rotation_commitment(&keys).unwrap(),
            sha_hex(br#"["a-key","b-key"]"#),
            "I430: the ids alone are not the commitment"
        );
        // Same ids, other keys: another commitment.
        let other = [key("b-key", "RUQy", "TUwy"), key("a-key", "RUQz", "TUwx")];
        assert_ne!(
            pre_rotation_commitment(&keys).unwrap(),
            pre_rotation_commitment(&other).unwrap(),
            "I430: the commitment binds the key material, not only the ids"
        );
        assert!(
            pre_rotation_commitment(&[]).is_err(),
            "I430: an empty set commits to nothing"
        );
        assert!(
            pre_rotation_commitment(&[key("a-key", "RUQx", "TUwx"), key("a-key", "RUQy", "TUwy")])
                .is_err(),
            "I430: one key id twice is refused"
        );
        // A record without ML-DSA-65 forms no element (never a null member).
        let (ed, _) = crate::federation::tier_ingest::test_support::hybrid_pubkeys("i430");
        let mut rec = crate::federation::KeyRecord {
            key_id: "i430".to_owned(),
            pubkey_ed25519_base64: ed,
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: crate::federation::types::identity_type::NODE.to_owned(),
            identity_ref: "i430".to_owned(),
            valid_from: chrono::Utc::now(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": "i430" }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "i430".to_owned(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        assert!(
            CommittedKey::from_record(&rec).is_err(),
            "I430: no ML-DSA-65 key, no element"
        );
        rec.pubkey_ml_dsa_65_base64 = Some(String::new());
        assert!(
            CommittedKey::from_record(&rec).is_err(),
            "I430: an empty ML-DSA-65 key is no key"
        );
        rec.pubkey_ml_dsa_65_base64 = Some("TUwx".to_owned());
        assert_eq!(
            CommittedKey::from_record(&rec)
                .unwrap()
                .pubkey_ml_dsa_65_base64,
            "TUwx",
            "I430: the element carries the stored bytes as they are"
        );
    }
}

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::accord_test_support as ops;
    use crate::federation::canonical_community_invariants::bodies::stand_up;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{
        capability_roots_to_trusted_root, recovery_commitment, test_accord_recovery_commitments,
        test_committed_key, test_pre_rotation_commitment, trust_root_valid, trusted_roots_of,
        ConferralPlane, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE, TRUST_ACCEPTS_DIMENSION,
        TRUST_CHARTER_DIMENSION, TRUST_CONFERS_DIMENSION,
    };
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{Error, FederationDirectory, SignedAttestation};

    fn refused_with(r: Result<(), Error>, token: &str, what: &str) {
        match r {
            Err(Error::CharterInvalid { detail }) if detail.contains(token) => {}
            other => panic!("{what}: expected a charter refusal naming {token:?}, got {other:?}"),
        }
    }

    // ── I431 ────────────────────────────────────────────────────────────

    /// A self-charter for key root `root` committing to `successors`' test
    /// pairs, then a recovery charter by `attester` naming `successors`.
    async fn recovery_attempt(
        d: &dyn FederationDirectory,
        root: &str,
        attester: &str,
        successors: &[String],
    ) -> Result<(), Error> {
        let pred_id = format!("{root}-pred");
        let pred = ops::signed_trust_attestation(
            &pred_id,
            root,
            root,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "references_attestation_id": pred_id,
                "dimension": TRUST_CHARTER_DIMENSION,
                "scope": [INFRA_SERVE_SCOPE, INFRA_ATTEST_SCOPE],
                "pre_rotation_commitment": test_pre_rotation_commitment(successors).unwrap(),
            }),
        );
        d.put_attestation(SignedAttestation { attestation: pred })
            .await
            .expect("the predecessor charter admits");
        let succ_id = format!("{root}-succ");
        let succ = ops::signed_trust_attestation(
            &succ_id,
            attester,
            attester,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "references_attestation_id": succ_id,
                "dimension": TRUST_CHARTER_DIMENSION,
                "scope": [INFRA_SERVE_SCOPE, INFRA_ATTEST_SCOPE],
                "pre_rotation_commitment":
                    test_pre_rotation_commitment(&[format!("{root}-next")]).unwrap(),
                "recovers": root,
                "successor_keys": successors,
            }),
        );
        d.put_attestation(SignedAttestation { attestation: succ })
            .await
            .map(|_| ())
    }

    /// **I431** — the squat: an id the commitment names, registered with other
    /// keys, does not satisfy it.
    pub(crate) async fn i431_a_squatted_successor_does_not_bind(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // CONTROL — honest successors bind.
        let root = format!("i431-root-{tag}");
        let s1 = format!("i431-s1-{tag}");
        let s2 = format!("i431-s2-{tag}");
        for k in [&root, &s1, &s2] {
            ops::register_typed_key(d, k, identity_type::NODE)
                .await
                .unwrap();
        }
        recovery_attempt(d, &root, &s2, &[s1.clone(), s2.clone()])
            .await
            .expect("I431 CONTROL: the successors' stored keys reproduce the commitment");

        // The squat: s1's id is registered first, by someone holding other keys.
        let root = format!("i431-root-sq-{tag}");
        let s1 = format!("i431-s1-sq-{tag}");
        let s2 = format!("i431-s2-sq-{tag}");
        ops::register_typed_key(d, &root, identity_type::NODE)
            .await
            .unwrap();
        ops::register_typed_key(d, &s2, identity_type::NODE)
            .await
            .unwrap();
        ts::register_hybrid_key_as(d, &s1, &format!("squatter-{tag}"), identity_type::NODE).await;
        refused_with(
            recovery_attempt(d, &root, &s2, &[s1.clone(), s2.clone()]).await,
            "public keys these successor records carry",
            "I431: a record under a committed id with other keys",
        );

        // An unregistered successor cannot be checked against key material.
        let root = format!("i431-root-un-{tag}");
        let s2 = format!("i431-s2-un-{tag}");
        ops::register_typed_key(d, &root, identity_type::NODE)
            .await
            .unwrap();
        ops::register_typed_key(d, &s2, identity_type::NODE)
            .await
            .unwrap();
        refused_with(
            recovery_attempt(d, &root, &s2, &[format!("i431-ghost-{tag}"), s2.clone()]).await,
            "holds no key record",
            "I431: an unregistered successor",
        );
    }

    // ── I432–I435 ───────────────────────────────────────────────────────

    /// The accord's charter, 3-of-3, with `recovery` as its
    /// `recovery_commitments` member (`None` = absent).
    async fn charter_accord(
        d: &dyn FederationDirectory,
        recovery: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        let family = crate::federation::canonical_community::accord_family_key_id();
        let id = uuid::Uuid::new_v4().to_string();
        let mut env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": test_pre_rotation_commitment(&[
                "accord-succ-a".to_owned(),
                "accord-succ-b".to_owned(),
            ])
            .unwrap(),
        });
        if let Some(r) = recovery {
            env["recovery_commitments"] = r;
        }
        let charter = ops::co_signed_trust_attestation(
            &id,
            "A1",
            family,
            attestation_type::DELEGATES_TO,
            env,
            &["B1", "C1"],
        );
        d.put_attestation(SignedAttestation {
            attestation: charter,
        })
        .await
        .map(|_| ())
    }

    async fn roster(d: &dyn FederationDirectory) -> Vec<String> {
        let mut r: Vec<String> = d
            .active_family_members(crate::federation::canonical_community::accord_family_key_id())
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        r.sort();
        r
    }

    /// **I432** — the member is required, one entry per standing holder.
    pub(crate) async fn i432_the_accord_charter_commits_every_holder(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let holders = roster(d).await;
        assert!(
            holders.len() >= 3,
            "I432 fixture: the accord roster is seated"
        );
        refused_with(
            charter_accord(d, None).await,
            "accord_recovery_commitment_missing",
            "I432: no recovery_commitments at all",
        );
        refused_with(
            charter_accord(d, Some(test_accord_recovery_commitments(&holders[..2]))).await,
            "accord_recovery_commitment_missing",
            "I432: a standing holder without a recovery commitment",
        );
        let mut malformed = test_accord_recovery_commitments(&holders);
        malformed[holders[0].as_str()] = serde_json::json!("AB".repeat(32));
        refused_with(
            charter_accord(d, Some(malformed)).await,
            "accord_recovery_commitment_missing",
            "I432: a commitment that is not lowercase hex",
        );
        refused_with(
            charter_accord(d, Some(serde_json::json!(["not", "an", "object"]))).await,
            "accord_recovery_commitment_missing",
            "I432: a member that is not an object",
        );
        charter_accord(d, Some(test_accord_recovery_commitments(&holders)))
            .await
            .expect("I432: one recovery commitment per standing holder admits");
    }

    /// **I433** — a commitment for a non-holder is refused.
    pub(crate) async fn i433_a_stray_commitment_is_refused(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let mut holders = roster(d).await;
        holders.push("not-a-holder".to_owned());
        refused_with(
            charter_accord(d, Some(test_accord_recovery_commitments(&holders))).await,
            "accord_recovery_commitment_stray",
            "I433: a recovery commitment for a key that holds no seat",
        );
    }

    /// **I434** — a recovery key held with a signing key, or shared, is refused.
    pub(crate) async fn i434_a_recovery_key_is_held_apart(d: &dyn FederationDirectory) {
        stand_up(d).await;
        let holders = roster(d).await;
        // A commits to B's signing key, as B's record stores it.
        let b_record = d.lookup_public_key(&holders[1]).await.unwrap().unwrap();
        let b_signing = recovery_commitment(
            &crate::federation::trust_root::CommittedKey::from_record(&b_record).unwrap(),
        )
        .unwrap();
        let mut signing = test_accord_recovery_commitments(&holders);
        signing[holders[0].as_str()] = serde_json::json!(b_signing);
        refused_with(
            charter_accord(d, Some(signing)).await,
            "accord_recovery_key_not_apart",
            "I434: a recovery key that is a standing holder's signing key",
        );
        // Two holders commit to one recovery key.
        let mut shared = test_accord_recovery_commitments(&holders);
        let shared_key = recovery_commitment(&test_committed_key("i434-shared")).unwrap();
        shared[holders[0].as_str()] = serde_json::json!(shared_key);
        shared[holders[1].as_str()] = serde_json::json!(shared_key);
        refused_with(
            charter_accord(d, Some(shared)).await,
            "accord_recovery_key_not_apart",
            "I434: one recovery key for two holders",
        );
    }

    /// **I435** — the requirement is the accord's; another family charters
    /// without it.
    pub(crate) async fn i435_another_family_needs_no_recovery_member(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let user = format!("i435-user-{tag}");
        let fam = format!("i435-fam-{tag}");
        let holders: Vec<String> = (0..3).map(|i| format!("i435-h{i}-{tag}")).collect();
        for k in holders.iter().chain([&user]) {
            ops::register_typed_key(d, k, identity_type::NODE)
                .await
                .unwrap();
        }
        ops::seed_chartered_family_root(d, &fam, &holders, &user)
            .await
            .expect("I435: a non-accord family charters with no recovery_commitments");
    }

    // ── I436 ────────────────────────────────────────────────────────────

    /// **I436** — a decision with no steward signatures stores and reads back.
    pub(crate) async fn i436_a_decision_carries_no_steward_signatures(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use ciris_verify_core::accord_live_quorum::{AccordDecision, LiveQuorumTally};
        let family = format!("i436-fam-{tag}");
        let nonce = format!("i436-nonce-{tag}");
        let prop = crate::federation::accord_quorum::test_fixtures::proposal(&family, &nonce);
        d.issue_accord_nonce(&family, &nonce).await.unwrap();
        d.put_accord_proposal(prop.clone(), None)
            .await
            .expect("I436: the proposal admits");
        let tally = LiveQuorumTally {
            live_set: vec!["alice".to_owned()],
            yes: 1,
            no: 0,
            abstain: 0,
        };
        d.put_accord_decision(AccordDecision::new(prop.clone(), &tally, true))
            .await
            .expect("I436: the decision admits");
        let stored = d
            .get_accord_decision(&prop.digest())
            .await
            .unwrap()
            .expect("I436: the decision reads back");
        let json = serde_json::to_value(&stored).unwrap();
        assert!(
            json.get("steward_signatures").is_none(),
            "I436: a stored decision has no steward_signatures member: {json}"
        );
        assert!(stored.decision.authorized, "I436: the decision round-trips");
    }

    // ── I437 / I438 ─────────────────────────────────────────────────────

    struct Edges {
        user: String,
        r1: String,
        r2: String,
    }

    /// Two trusted key roots; the user's edge to `r1` is then superseded by the
    /// user's own successor naming `r2`.
    async fn rotate_the_edge(d: &dyn FederationDirectory, tag: &str) -> Edges {
        let user = format!("i437-user-{tag}");
        let r1 = format!("i437-r1-{tag}");
        let r2 = format!("i437-r2-{tag}");
        let s1 = format!("i437-s1-{tag}");
        let s2 = format!("i437-s2-{tag}");
        ops::register_typed_key(d, &user, identity_type::NODE)
            .await
            .unwrap();
        for s in [&s1, &s2] {
            ops::register_typed_key(d, s, identity_type::NODE)
                .await
                .unwrap();
        }
        ops::establish_trust_root_side(d, &r1, &s1, INFRA_SERVE_SCOPE)
            .await
            .unwrap();
        ops::establish_trust_root_side(d, &r2, &s2, INFRA_SERVE_SCOPE)
            .await
            .unwrap();
        let e1 = format!("i437-e1-{tag}");
        let edge = ops::signed_trust_attestation(
            &e1,
            &user,
            &r1,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "references_attestation_id": e1,
                "dimension": TRUST_ACCEPTS_DIMENSION,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            }),
        );
        d.put_attestation(SignedAttestation { attestation: edge })
            .await
            .expect("the user's edge to r1");
        assert!(
            trust_root_valid(d, &user, &r1).await.unwrap().edge_exists,
            "CONTROL: the edge to r1 stands before the rotation"
        );
        let e2 = format!("i437-e2-{tag}");
        let succ = ops::signed_trust_attestation(
            &e2,
            &user,
            &r2,
            attestation_type::SUPERSEDES,
            serde_json::json!({
                "references_attestation_id": e1,
                "dimension": TRUST_ACCEPTS_DIMENSION,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            }),
        );
        d.put_attestation(SignedAttestation { attestation: succ })
            .await
            .expect("the user's successor edge naming r2");
        Edges { user, r1, r2 }
    }

    /// **I437** — the edge leg reads the rotation.
    pub(crate) async fn i437_trust_root_valid_reads_a_superseded_edge(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let e = rotate_the_edge(d, tag).await;
        assert!(
            !trust_root_valid(d, &e.user, &e.r1)
                .await
                .unwrap()
                .edge_exists,
            "I437: the superseded edge to r1 is not live"
        );
        let v2 = trust_root_valid(d, &e.user, &e.r2).await.unwrap();
        assert!(
            v2.edge_exists && v2.valid,
            "I437: the successor edge to r2 is the live edge: {v2:?}"
        );
    }

    /// **I438** — the subscription read agrees.
    pub(crate) async fn i438_trusted_roots_of_reads_a_superseded_edge(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let e = rotate_the_edge(d, tag).await;
        let roots = trusted_roots_of(d, &e.user, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            roots,
            vec![e.r2.clone()],
            "I438: the subscription set is the successor's root, not the superseded edge's"
        );
    }

    // ── I439 ────────────────────────────────────────────────────────────

    /// **I439** — CC 3.4.7: a keyless family confers as it charters.
    pub(crate) async fn i439_a_keyless_family_confers_at_its_quorum(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let user = format!("i439-user-{tag}");
        let fam = format!("i439-fam-{tag}");
        let subject = format!("i439-subject-{tag}");
        let holders: Vec<String> = (0..3).map(|i| format!("i439-h{i}-{tag}")).collect();
        for k in holders.iter().chain([&user, &subject]) {
            ops::register_typed_key(d, k, identity_type::NODE)
                .await
                .unwrap();
        }
        ops::seed_chartered_family_root(d, &fam, &holders, &user)
            .await
            .unwrap();
        assert!(
            trust_root_valid(d, &user, &fam).await.unwrap().valid,
            "I439 CONTROL: the family is a valid root for the user"
        );
        let grant = |id: &str, cosigners: &[&str]| {
            ops::co_signed_trust_attestation(
                id,
                &holders[0],
                &subject,
                attestation_type::DELEGATES_TO,
                serde_json::json!({
                    "references_attestation_id": id,
                    "dimension": TRUST_CONFERS_DIMENSION,
                    "scope": [INFRA_SERVE_SCOPE],
                }),
                cosigners,
            )
        };
        let lone = format!("i439-lone-{tag}");
        let _ = d
            .put_attestation(SignedAttestation {
                attestation: grant(&lone, &[]),
            })
            .await;
        assert_eq!(
            capability_roots_to_trusted_root(d, &user, &subject, INFRA_SERVE_SCOPE)
                .await
                .unwrap()
                .map(|g| g.root_key_id),
            None,
            "I439: one holder's scrub is no grant by the family"
        );
        let quorate = format!("i439-quorate-{tag}");
        d.put_attestation(SignedAttestation {
            attestation: grant(&quorate, &[holders[1].as_str()]),
        })
        .await
        .expect("I439: the quorate grant admits");
        let g = capability_roots_to_trusted_root(d, &user, &subject, INFRA_SERVE_SCOPE)
            .await
            .unwrap()
            .expect("I439: the grant at the family's quorum confers");
        assert_eq!(g.root_key_id, fam, "I439: the family is the root");
        assert_eq!(g.grant_attestation_id, quorate, "I439: the quorate grant");
        assert_eq!(
            g.conferral_plane,
            ConferralPlane::FamilyQuorum,
            "I439: the plane"
        );
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! tagged {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(
                                &d as &dyn FederationDirectory,
                                &format!("{}-{}", stringify!($name), suffix()),
                            )
                            .await
                        }
                    };
                }
                macro_rules! plain {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(&d as &dyn FederationDirectory).await
                        }
                    };
                }
                tagged!(i431_a_squatted_successor_does_not_bind);
                plain!(i432_the_accord_charter_commits_every_holder);
                plain!(i433_a_stray_commitment_is_refused);
                plain!(i434_a_recovery_key_is_held_apart);
                tagged!(i435_another_family_needs_no_recovery_member);
                tagged!(i436_a_decision_carries_no_steward_signatures);
                tagged!(i437_trust_root_valid_reads_a_superseded_edge);
                tagged!(i438_trusted_roots_of_reads_a_superseded_edge);
                tagged!(i439_a_keyless_family_confers_at_its_quorum);
            }
        };
    }

    dyn_runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
