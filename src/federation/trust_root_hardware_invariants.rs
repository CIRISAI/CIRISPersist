//! v47.3.0 (CIRISPersist#901, `FSD/TRUST_ROOT_HOLDER_HARDWARE.md` §4) — **a
//! root is as attested as its holders.** The ruling (CIRISEdge#659): a valid
//! root is defined by its holders' attested hardware property, evaluated
//! where the root is judged, from the records the judging node holds.
//!
//! v62.0.0 (C4-fix4, CP2) — what remains is **I158** (the verdict memo),
//! restated on an edition-2 rooted root; the runner is the only place a
//! concrete backend is named, on sqlite and postgres.
//!
//! **I154, I155 and I156 are DELETED** (ruling 4: a test that asserts
//! earlier-form behaviour goes). Each stood its holders up through the
//! earlier-form `key_record` door, now shut (`earlier_form_object`), with
//! earlier-form evidence:
//!
//! - I154: JSON `StrongBox` bodies (a class, a nonce), a holder registered
//!   with no evidence, a seated non-signer of an earlier-form charter, and a
//!   policy that stops accepting `AndroidStrongbox`. In v62 a root's holders
//!   are holders of the genesis bundle in force, custody-gated at seating
//!   (CC 4.2.2.1), and their evidence is the edition-2 custody body
//!   (`YubiKey_5_FIPS`, `pq_custody`, a chain): no holder without evidence is
//!   seated, and the class is judged by the bundle reader's gate, not by the
//!   accepted-class list. The positive leg is W1's I3256
//!   (`v62_coverage_invariants`).
//! - I155: the accord-holder nonce-freshness leg at local registration. An
//!   edition-2 `key:record` carries no nonce; the custody path takes no
//!   challenge (C4-fix I2391). Its sibling I157 went at W1-fix5 for the same
//!   reason.
//! - I156: Layer B over an earlier-form mock-member record. Restated by W1's
//!   I3255 (a chain lifted from another key lands and is refused where custody
//!   is judged) and I3256 (a walked chain), and by C4-fix's I2390–I2393 on the
//!   real YubiKey chains.

/// The backend-agnostic witness body (I158), over one `&dyn
/// FederationDirectory`; `run` below instantiates it per backend.
#[cfg(any(test, feature = "test-anchor"))]
pub mod bodies {
    use crate::federation::edition2::fixture_genesis::{
        ceremony_v2, install_ceremony_v2, CeremonySpec,
    };
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    use crate::federation::trust_root::{holder_hardware_verifications_for, trust_root_valid};
    use crate::federation::{FederationDirectory, HardwareAttestationPolicy};
    use std::sync::Arc;

    /// The runner's handle on the concrete backend's policy slot
    /// (`set_hardware_attestation_policy` is not on the trait — the policy is
    /// the node's, never a caller's).
    pub type SetPolicy<'a> = &'a dyn Fn(Arc<HardwareAttestationPolicy>);

    /// This witness's holders: seeds no other rooted-root witness seats (the
    /// standard ceremony seats 1, 2, 3; v62_coverage's four-holder bundle
    /// 1..=4), so a parallel suite judging OTHER roots cannot move the
    /// per-key-id evaluation count.
    pub const I158_HOLDER_SEEDS: [u8; 3] = [5, 6, 7];

    /// A policy unique to this witness. The memo is keyed by the record AND
    /// the policy, so no other test's verdicts are memo hits here. Its
    /// freshness window is no input of an edition-2 holder's verdict (the
    /// custody body carries no nonce).
    fn policy(window_secs: u64) -> HardwareAttestationPolicy {
        HardwareAttestationPolicy {
            max_nonce_age: std::time::Duration::from_secs(window_secs),
            ..HardwareAttestationPolicy::default()
        }
    }

    /// **I158 — verdicts are memoised by their inputs.** A rooted edition-2
    /// root with three bundle-holder founders, `trust_root_valid` twice under
    /// one policy → three evaluations, not six. The policy is an input:
    /// swapping it (even for one that judges identically) re-evaluates every
    /// holder once, and the verdict is unchanged.
    pub async fn i158_verdicts_are_cached_per_record_version(
        d: &dyn FederationDirectory,
        set_policy: SetPolicy<'_>,
    ) {
        let spec = CeremonySpec {
            holders: I158_HOLDER_SEEDS.to_vec(),
            ..CeremonySpec::standard()
        };
        install_ceremony_v2(d, &ceremony_v2(&spec))
            .await
            .unwrap_or_else(|e| panic!("I158: install the bundle: {e:?}"));
        let r = rooted_trust_root(d, &I158_HOLDER_SEEDS, "quorum:2/3").await;
        let node = d.node_key_id().expect("I158: the runner set the node key");
        let count = |hs: &[String]| -> u64 {
            hs.iter()
                .map(|h| holder_hardware_verifications_for(h))
                .sum()
        };

        set_policy(Arc::new(policy(4_158)));
        let before = count(&r.founders);
        let v1 = trust_root_valid(d, &node, &r.root).await.unwrap();
        let v2 = trust_root_valid(d, &node, &r.root).await.unwrap();
        assert!(
            v1.valid && v1.holders_hardware_attested && v1 == v2,
            "I158: a memo hit is the same verdict: {v1:?}"
        );
        assert_eq!(
            v1.holders_hardware.len(),
            3,
            "I158: one entry per founder: {v1:?}"
        );
        assert_eq!(
            count(&r.founders) - before,
            3,
            "I158: three holders, evaluated once each across two calls"
        );

        // A different policy object that judges the same way: the inputs
        // changed, so every holder is evaluated again — and only once.
        set_policy(Arc::new(policy(4_159)));
        let v3 = trust_root_valid(d, &node, &r.root).await.unwrap();
        trust_root_valid(d, &node, &r.root).await.unwrap();
        assert!(
            v3.valid && v3.holders_hardware == v1.holders_hardware,
            "I158: the freshness window is not a validity input: {v3:?}"
        );
        assert_eq!(
            count(&r.founders) - before,
            6,
            "I158: the policy is an input — three re-evaluations, then memo hits"
        );
        set_policy(Arc::new(HardwareAttestationPolicy::default()));
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    use crate::federation::edition2::fixture_switch as e2;

    /// The node key's seed (distinct within its first 32 bytes from every
    /// other fixture seed).
    const NODE_SEED: &str = "c4f4-i158-trust-root-hw-node";

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i158_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let node = e2::put_key(&b, NODE_SEED, &["node"]).await;
        b.set_node_key_id(node);
        let set = |p| b.set_hardware_attestation_policy(p);
        Box::pin(super::bodies::i158_verdicts_are_cached_per_record_version(
            &b, &set,
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i158_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let node = e2::put_key(&b, NODE_SEED, &["node"]).await;
        b.set_node_key_id(node);
        let set = |p| b.set_hardware_attestation_policy(p);
        Box::pin(super::bodies::i158_verdicts_are_cached_per_record_version(
            &b, &set,
        ))
        .await;
    }
}
