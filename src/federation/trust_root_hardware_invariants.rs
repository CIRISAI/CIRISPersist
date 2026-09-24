//! v47.3.0 (CIRISPersist#901, `FSD/TRUST_ROOT_HOLDER_HARDWARE.md` §4) — **a
//! root is as attested as its holders.** The ruling (CIRISEdge#659): a valid
//! root is defined by its holders' attested hardware property, evaluated
//! where the root is judged, from the records the judging node holds.
//!
//! Every body runs on memory, sqlite and postgres through the same `&dyn
//! FederationDirectory`; the runner is the only place a concrete backend is
//! named (the #534/#536 trap: a leg that is green on memory only is not green).
//!
//! A key record's evidence is IMMUTABLE for its key id — the doors admit,
//! upgrade scrubs, supersede a canonical or rebind, none rewrites evidence
//! (Registry-of-Record). So the witnesses vary the property across HOLDERS and
//! across the POLICY, never across versions of one record: every shape is a
//! fresh root with holders registered the way production registers them.

/// The backend-agnostic witness bodies (I154–I158), each over one
/// `&dyn FederationDirectory`; `run` below instantiates them per backend.
#[cfg(any(test, feature = "test-anchor"))]
pub mod bodies {
    use crate::federation::operational::test_support as ops;
    use crate::federation::trust_root::trust_root_valid;
    use crate::federation::types::identity_type;
    use crate::federation::{FederationDirectory, HardwareAttestationPolicy};
    use std::sync::Arc;

    /// The runner's handle on the concrete backend's policy slot
    /// (`set_hardware_attestation_policy` is not on the trait — the policy is
    /// the node's, never a caller's).
    pub type SetPolicy<'a> = &'a dyn Fn(Arc<HardwareAttestationPolicy>);

    fn strongbox_evidence_at(captured_at: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
        let mut v =
            crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence();
        v["nonce_captured_at"] = serde_json::json!(captured_at.to_rfc3339());
        v
    }

    /// A month-old nonce: Layer-A-valid, admission-stale. The property the
    /// whole leg turns on — validity must not re-check freshness.
    fn stale_strongbox() -> serde_json::Value {
        strongbox_evidence_at(chrono::Utc::now() - chrono::Duration::days(30))
    }

    /// A family root `{tag}-root` with three seated holders `{tag}-h{i}`,
    /// chartered `quorum:2/3`, and `{tag}-user`'s trust edge. A holder not yet
    /// registered is registered as `NODE` with the evidence given (`None` =
    /// software-class); a holder the caller registered beforehand keeps its
    /// record (evidence is immutable — there is no door to rewrite it).
    async fn family_root_with(
        d: &dyn FederationDirectory,
        tag: &str,
        evidence: [Option<serde_json::Value>; 3],
    ) -> (String, String, Vec<String>) {
        family_root_with_scrubs(d, tag, evidence, &[]).await
    }

    /// [`family_root_with`] where named seats scrub the charter with a chosen
    /// signer (see `ops::ScrubSigner`).
    async fn family_root_with_scrubs(
        d: &dyn FederationDirectory,
        tag: &str,
        evidence: [Option<serde_json::Value>; 3],
        scrubs: &[(&str, ops::ScrubSigner<'_>)],
    ) -> (String, String, Vec<String>) {
        let user = format!("{tag}-user");
        let holders: Vec<String> = (0..3).map(|i| format!("{tag}-h{i}")).collect();
        let root = format!("{tag}-root");
        // The user is NOT a holder: it attests the trust edge about the root
        // and carries no evidence. A leg that judged every attester about
        // the root (instead of the charter's verified scrubs) would refuse it.
        ops::register_typed_key_with_evidence(d, &user, identity_type::NODE, None)
            .await
            .unwrap();
        for (h, ev) in holders.iter().zip(evidence) {
            if d.lookup_public_key(h).await.unwrap().is_some() {
                continue;
            }
            ops::register_typed_key_with_evidence(d, h, identity_type::NODE, ev)
                .await
                .unwrap_or_else(|e| panic!("{tag}: register holder {h}: {e}"));
        }
        ops::seed_chartered_family_root_with_scrubs(d, &root, &holders, &user, scrubs)
            .await
            .unwrap_or_else(|e| panic!("{tag}: charter the family root: {e}"));
        (user, root, holders)
    }

    /// Three holders, all stale-nonce StrongBox: the control shape.
    async fn attested_family_root(
        d: &dyn FederationDirectory,
        tag: &str,
    ) -> (String, String, Vec<String>) {
        family_root_with(
            d,
            tag,
            [
                Some(stale_strongbox()),
                Some(stale_strongbox()),
                Some(stale_strongbox()),
            ],
        )
        .await
    }

    /// **I154 — a root is as attested as its holders.**
    pub async fn i154_a_root_is_as_attested_as_its_holders(
        d: &dyn FederationDirectory,
        set_policy: SetPolicy<'_>,
        tag: &str,
    ) {
        // Control: three attested holders, every nonce stale → valid.
        let (user, root, _holders) = attested_family_root(d, &format!("{tag}-a")).await;
        let v = trust_root_valid(d, &user, &root).await.unwrap();
        assert!(
            v.valid,
            "{tag} I154: control — three attested holders, stale nonces: {v:?}"
        );
        assert!(
            v.holders_hardware_attested,
            "{tag} I154: the leg holds: {v:?}"
        );
        assert_eq!(
            v.holders_hardware.len(),
            3,
            "{tag} I154: one entry per seated holder: {v:?}"
        );
        assert!(
            v.holders_hardware
                .iter()
                .all(|h| h.layer_a && h.layer_b.is_none() && h.refusal.is_none()),
            "{tag} I154: every holder Layer A, no pinned root for StrongBox: {v:?}"
        );
        let ids: Vec<&str> = v
            .holders_hardware
            .iter()
            .map(|h| h.key_id.as_str())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "{tag} I154: entries sorted by key id");

        // One holder registered with NO evidence: that holder fails Layer A,
        // the root is invalid, the other two and every other leg are unchanged.
        let (user_b, root_b, holders_b) = family_root_with(
            d,
            &format!("{tag}-b"),
            [Some(stale_strongbox()), None, Some(stale_strongbox())],
        )
        .await;
        let w = trust_root_valid(d, &user_b, &root_b).await.unwrap();
        assert!(
            !w.valid && !w.holders_hardware_attested,
            "{tag} I154: an unattested holder invalidates the root: {w:?}"
        );
        let bad = w
            .holders_hardware
            .iter()
            .find(|h| h.key_id == holders_b[1])
            .expect("named");
        assert!(
            !bad.layer_a && bad.class.is_none() && bad.layer_b.is_none(),
            "{tag} I154: the holder with no evidence: {bad:?}"
        );
        assert!(
            bad.refusal
                .as_deref()
                .is_some_and(|r| r.contains("missing")),
            "{tag} I154: the refusal says why: {bad:?}"
        );
        for ok in [&holders_b[0], &holders_b[2]] {
            assert!(
                w.holders_hardware
                    .iter()
                    .any(|h| &h.key_id == ok && h.layer_a),
                "{tag} I154: the attested holders are unchanged: {w:?}"
            );
        }
        assert_eq!(
            (
                w.edge_exists,
                w.root_self_declares,
                w.charter_has_recovery,
                w.halt_latched
            ),
            (
                v.edge_exists,
                v.root_self_declares,
                v.charter_has_recovery,
                v.halt_latched
            ),
            "{tag} I154: no other leg moved"
        );
        assert!(
            w.bounded_until.is_none(),
            "{tag} I154: a refusal carries no TTL: {w:?}"
        );

        // Root C: three seats, only h0 and h1 scrub the charter (quorum 2/3
        // met); h2 is seated, unattested, and did NOT sign. A seated holder
        // who did not sign is not a holder OF THIS CHARTER: valid, two
        // entries, h2 absent from the verdict.
        let tc = format!("{tag}-c");
        let h2c = format!("{tc}-h2");
        let (user_c, root_c, holders_c) = family_root_with_scrubs(
            d,
            &tc,
            [Some(stale_strongbox()), Some(stale_strongbox()), None],
            &[(&h2c, ops::ScrubSigner::Absent)],
        )
        .await;
        let c = trust_root_valid(d, &user_c, &root_c).await.unwrap();
        assert!(
            c.valid && c.holders_hardware_attested,
            "{tag} I154: a seated non-signer is not judged: {c:?}"
        );
        assert_eq!(
            c.holders_hardware
                .iter()
                .map(|h| h.key_id.as_str())
                .collect::<Vec<_>>(),
            vec![holders_c[0].as_str(), holders_c[1].as_str()],
            "{tag} I154: the verdict names the charter's verified scrubs and no one else"
        );
        assert_eq!(
            c.charter_quorum
                .map(|q| (q.distinct_holders, q.roster_size)),
            Some((2, 3)),
            "{tag} I154: the quorum accounting still sees the whole roster"
        );

        // The node's policy stops accepting the holders' class: the SAME
        // records, judged now, fail Layer A — validity is evaluated where the
        // root is judged, against the judging node's policy, not frozen at
        // admission. Restoring the policy restores the verdict.
        let mut narrow = HardwareAttestationPolicy::default();
        narrow
            .accepted_hardware_types
            .remove(&ciris_keyring::HardwareType::AndroidStrongbox);
        set_policy(Arc::new(narrow));
        let n = trust_root_valid(d, &user, &root).await.unwrap();
        assert!(
            !n.valid && !n.holders_hardware_attested,
            "{tag} I154: a class the policy no longer accepts fails Layer A: {n:?}"
        );
        assert!(
            n.holders_hardware.iter().all(|h| {
                !h.layer_a && h.refusal.as_deref().is_some_and(|r| r.contains("accepted"))
            }),
            "{tag} I154: every StrongBox holder refused by class: {n:?}"
        );
        set_policy(Arc::new(HardwareAttestationPolicy::default()));
        let back = trust_root_valid(d, &user, &root).await.unwrap();
        assert!(
            back.valid && back.holders_hardware == v.holders_hardware,
            "{tag} I154: the default policy restores the control verdict: {back:?}"
        );
    }

    /// **I155 — validity never re-checks freshness; admission always does.**
    /// The split is one function calling the other: `check` =
    /// `check_structure` + the freshness leg.
    pub async fn i155_validity_has_no_clock_admission_does(d: &dyn FederationDirectory, tag: &str) {
        let policy = HardwareAttestationPolicy::default();
        let now = chrono::Utc::now();
        let stale = stale_strongbox();
        let fresh = strongbox_evidence_at(now);
        assert!(
            policy
                .check(&format!("{tag}-k"), Some(&stale), now)
                .is_err(),
            "{tag} I155: ADMISSION refuses a stale nonce"
        );
        assert!(
            policy
                .check_structure(&format!("{tag}-k"), Some(&stale))
                .is_ok(),
            "{tag} I155: VALIDITY accepts it — structure, no clock"
        );
        assert!(
            policy.check(&format!("{tag}-k"), Some(&fresh), now).is_ok()
                && policy
                    .check_structure(&format!("{tag}-k"), Some(&fresh))
                    .is_ok(),
            "{tag} I155: a fresh nonce passes both"
        );
        // Through the door, on this backend: an accord_holder registering
        // locally with the stale nonce is refused (unchanged behaviour); the
        // same evidence on a NODE row is admitted (structure only).
        let err = ops::register_typed_key_with_evidence(
            d,
            &format!("{tag}-ah"),
            identity_type::ACCORD_HOLDER,
            Some(stale.clone()),
        )
        .await
        .expect_err("I155: the local accord_holder door keeps freshness");
        assert!(
            err.to_string().contains("stale") || err.kind().contains("stale"),
            "{tag} I155: refused for freshness: {err}"
        );
        ops::register_typed_key_with_evidence(
            d,
            &format!("{tag}-node"),
            identity_type::NODE,
            Some(stale),
        )
        .await
        .expect("I155: a NODE row with stale-but-well-formed evidence is admitted");
    }

    /// **I156 — Layer B binds the record's key** (YubiKey PIV, through
    /// `verify_member_fips_custody_against`, the walk persist already has).
    /// The runner installs a policy whose pinned root is `ca.root_der()` on
    /// the concrete backend before handing over `&dyn`. The YubiKey holder is
    /// seat 1 (a co-scrub), signing the charter AS the attested member so its
    /// scrub verifies against the pubkeys its chain names.
    #[cfg(test)] // the mock CA is verify-core test-only; a `test-anchor` build has no I156 body
    pub async fn i156_layer_b_binds_the_records_key(
        d: &dyn FederationDirectory,
        ca: &ciris_verify_core::accord_custody_attestation::test_support::MockYubicoCa,
        tag: &str,
    ) {
        // Root A: holder 1 is a YubiKey holder whose chain names ITS OWN key
        // (the record's pubkeys ARE the attested member's).
        let ta = format!("{tag}-a");
        let h1 = format!("{ta}-h1");
        let seed_a = [0x61u8; 32];
        let m = ca.attest_member(seed_a, &h1, "2026-07-26T00:00:00Z").await;
        ops::register_key_record_from_mock_member(d, &h1, &m, None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I156: register the YubiKey holder: {e}"));
        let (user, root, holders) = family_root_with_scrubs(
            d,
            &ta,
            [Some(stale_strongbox()), None, Some(stale_strongbox())],
            &[(&h1, ops::ScrubSigner::MockMember(seed_a))],
        )
        .await;
        let v = trust_root_valid(d, &user, &root).await.unwrap();
        assert_eq!(
            v.holders_hardware.len(),
            3,
            "{tag} I156: the YubiKey holder's scrub counted: {v:?}"
        );
        let y = v
            .holders_hardware
            .iter()
            .find(|h| h.key_id == holders[1])
            .expect("named");
        assert_eq!(
            (y.layer_a, y.layer_b),
            (true, Some(true)),
            "{tag} I156: the chain names the record's key: {y:?}"
        );
        assert_eq!(
            y.class,
            Some(ciris_keyring::HardwareType::ExternalSecureElement),
            "{tag} I156: a YubiKey PIV holder reports the external-SE class"
        );
        assert!(v.valid, "{tag} I156: valid: {v:?}");
        assert!(
            v.holders_hardware
                .iter()
                .filter(|h| h.key_id != holders[1])
                .all(|h| h.layer_a && h.layer_b.is_none()),
            "{tag} I156: the StrongBox holders are Layer-A-only: {v:?}"
        );

        // Root B: the same kind of chain on a record whose pubkeys are NOT
        // the attested key (the door does not walk the chain; the leg does).
        // The record's pubkeys are the deterministic pair for `other`, and
        // the holder scrubs the charter with THAT pair, so it IS a holder.
        let tb = format!("{tag}-b");
        let g1 = format!("{tb}-h1");
        let other = format!("{g1}-a-different-keypair-than-the-chain-names");
        let m2 = ca
            .attest_member([0x63u8; 32], &g1, "2026-07-26T00:00:00Z")
            .await;
        ops::register_key_record_from_mock_member(d, &g1, &m2, Some(&other))
            .await
            .unwrap_or_else(|e| panic!("{tag} I156: register the mismatched holder: {e}"));
        let (user_b, root_b, holders_b) = family_root_with_scrubs(
            d,
            &tb,
            [Some(stale_strongbox()), None, Some(stale_strongbox())],
            &[(&g1, ops::ScrubSigner::Deterministic(&other))],
        )
        .await;
        let w = trust_root_valid(d, &user_b, &root_b).await.unwrap();
        let bad = w
            .holders_hardware
            .iter()
            .find(|h| h.key_id == holders_b[1])
            .expect("named");
        assert_eq!(
            (bad.layer_a, bad.layer_b),
            (true, Some(false)),
            "{tag} I156: the attested key is not the record's: {bad:?}"
        );
        assert!(
            !w.valid && !w.holders_hardware_attested && bad.refusal.is_some(),
            "{tag} I156: Layer B false invalidates the root and names why: {w:?}"
        );
    }

    /// **I157 — replicated records are checked where they land.**
    pub async fn i157_replicated_records_are_checked_where_they_land(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let stale = stale_strongbox();
        let malformed =
            serde_json::json!({"platform_attestation": {"Android": {"strongbox_backed": "yes"}}});
        // Malformed evidence on a NON-accord_holder record, by replication:
        // refused, for the evidence (today: admitted unchecked).
        let r = ops::apply_replicated_typed_key_with_evidence(
            d,
            &format!("{tag}-bad"),
            identity_type::NODE,
            Some(malformed),
        )
        .await;
        match r {
            Err(e) => assert!(
                e.to_string().contains("malformed"),
                "{tag} I157: refused FOR THE EVIDENCE, not something else: {e}"
            ),
            Ok(o) => panic!(
                "{tag} I157: a replicated record with malformed evidence was admitted: {o:?}"
            ),
        }
        assert!(
            d.lookup_public_key(&format!("{tag}-bad"))
                .await
                .unwrap()
                .is_none(),
            "{tag} I157: a refused row leaves no trace"
        );
        // No evidence: admitted (software-class, never downgraded).
        ops::apply_replicated_typed_key_with_evidence(
            d,
            &format!("{tag}-none"),
            identity_type::NODE,
            None,
        )
        .await
        .expect("I157: a record with no evidence is admitted");
        // Stale-nonce VALID evidence by replication: admitted (structure only —
        // its nonce was fresh where it registered).
        ops::apply_replicated_typed_key_with_evidence(
            d,
            &format!("{tag}-stale"),
            identity_type::NODE,
            Some(stale.clone()),
        )
        .await
        .expect("I157: a replicated record's nonce was fresh where it registered");
        // A locally registering accord_holder with the same stale evidence:
        // still refused.
        ops::register_typed_key_with_evidence(
            d,
            &format!("{tag}-ah"),
            identity_type::ACCORD_HOLDER,
            Some(stale),
        )
        .await
        .expect_err("I157: local admission keeps the freshness leg");
    }

    /// **I158 — verdicts are memoised by their inputs.** Three holders,
    /// `trust_root_valid` twice → three evaluations, not six. The policy is an
    /// input: swapping it (even for one that judges identically) re-evaluates
    /// every holder once.
    pub async fn i158_verdicts_are_cached_per_record_version(
        d: &dyn FederationDirectory,
        set_policy: SetPolicy<'_>,
        tag: &str,
    ) {
        let (user, root, holders) = attested_family_root(d, tag).await;
        // Per holder key id: this witness's holders are unique to it, so a
        // parallel suite evaluating OTHER roots cannot move the count.
        let count = |hs: &[String]| -> u64 {
            hs.iter()
                .map(|h| crate::federation::trust_root::holder_hardware_verifications_for(h))
                .sum()
        };
        let before = count(&holders);
        let v1 = trust_root_valid(d, &user, &root).await.unwrap();
        let v2 = trust_root_valid(d, &user, &root).await.unwrap();
        assert!(
            v1.valid && v1 == v2,
            "{tag} I158: a memo hit is the same verdict"
        );
        assert_eq!(
            count(&holders) - before,
            3,
            "{tag} I158: three holders, evaluated once each across two calls"
        );
        // A different policy object that judges the same way: the inputs
        // changed, so every holder is evaluated again — and only once.
        let same_but_new = HardwareAttestationPolicy {
            max_nonce_age: std::time::Duration::from_secs(60),
            ..HardwareAttestationPolicy::default()
        };
        set_policy(Arc::new(same_but_new));
        let v3 = trust_root_valid(d, &user, &root).await.unwrap();
        trust_root_valid(d, &user, &root).await.unwrap();
        assert!(
            v3.valid && v3.holders_hardware == v1.holders_hardware,
            "{tag} I158: the freshness window is not a validity input: {v3:?}"
        );
        assert_eq!(
            count(&holders) - before,
            6,
            "{tag} I158: the policy is an input — three re-evaluations, then memo hits"
        );
        set_policy(Arc::new(HardwareAttestationPolicy::default()));
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
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i154() {
                    let Some(b) = $fresh.await else { return };
                    let set = |p| b.set_hardware_attestation_policy(p);
                    super::super::bodies::i154_a_root_is_as_attested_as_its_holders(
                        &b as &dyn FederationDirectory,
                        &set,
                        &format!("i154-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i155() {
                    let Some(b) = $fresh.await else { return };
                    super::super::bodies::i155_validity_has_no_clock_admission_does(
                        &b as &dyn FederationDirectory,
                        &format!("i155-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i156() {
                    let Some(b) = $fresh.await else { return };
                    let ca = ciris_verify_core::accord_custody_attestation::test_support::MockYubicoCa::new();
                    let mut policy = crate::federation::HardwareAttestationPolicy::default();
                    policy.yubico_root_der = std::borrow::Cow::Owned(ca.root_der().to_vec());
                    b.set_hardware_attestation_policy(std::sync::Arc::new(policy));
                    super::super::bodies::i156_layer_b_binds_the_records_key(
                        &b as &dyn FederationDirectory,
                        &ca,
                        &format!("i156-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i157() {
                    let Some(b) = $fresh.await else { return };
                    super::super::bodies::i157_replicated_records_are_checked_where_they_land(
                        &b as &dyn FederationDirectory,
                        &format!("i157-{}", super::suffix()),
                    )
                    .await
                }
                #[tokio::test]
                async fn i158() {
                    let Some(b) = $fresh.await else { return };
                    let set = |p| b.set_hardware_attestation_policy(p);
                    super::super::bodies::i158_verdicts_are_cached_per_record_version(
                        &b as &dyn FederationDirectory,
                        &set,
                        &format!("i158-{}", super::suffix()),
                    )
                    .await
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
