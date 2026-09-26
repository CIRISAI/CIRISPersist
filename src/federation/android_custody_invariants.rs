//! v49.0.0 (CIRISPersist#915, CIRISServer#339) — **I185: Android custody
//! attested at key generation.**
//!
//! An [`AttestationEvidence::AndroidGenerationCustody`] chain is walked under
//! CIRISVerify's `GenerationOnly` policy against the record's OWN Ed25519 key.
//! The artifacts here chain to a MOCK Google CA (rcgen), so they are inert
//! against the baked Google anchors — the same posture as verify's mock
//! Yubico CA; the default-policy leg below is the proof.
//!
//! [`AttestationEvidence::AndroidGenerationCustody`]: super::hardware_attestation::AttestationEvidence::AndroidGenerationCustody

#![cfg(test)]

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, PublicKeyData, SignatureAlgorithm, PKCS_ED25519,
};

use super::hardware_attestation::HardwareAttestationPolicy;
use super::Error;
use ciris_keyring::HardwareType;

/// `KeyDescription` security levels, as the extension encodes them.
pub const SOFTWARE: u8 = 0;
/// Trusted execution environment.
pub const TEE: u8 = 1;
/// StrongBox.
pub const STRONGBOX: u8 = 2;

/// A bare Ed25519 public key — rcgen signs a leaf over a key whose private
/// half it never sees, which is exactly the record's situation.
struct RawEd25519(Vec<u8>);
impl PublicKeyData for RawEd25519 {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &SignatureAlgorithm {
        &PKCS_ED25519
    }
}

fn params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    p
}

/// DER `KeyDescription` (attestationVersion 4, both levels `km_level`, a
/// generation challenge the wire never carries).
fn key_description(km_level: u8) -> Vec<u8> {
    let challenge = b"set-at-generation";
    let mut inner = vec![
        0x02, 0x01, 0x04, 0x0a, 0x01, km_level, 0x02, 0x01, 0x01, 0x0a, 0x01, km_level, 0x04,
    ];
    inner.push(u8::try_from(challenge.len()).unwrap());
    inner.extend_from_slice(challenge);
    let mut der = vec![0x30, u8::try_from(inner.len()).unwrap()];
    der.extend_from_slice(&inner);
    der
}

/// A mock Google attestation CA: root → intermediate → leaf, the shape a
/// device returns.
pub struct MockGoogleCa {
    root: Certificate,
    intermediate: Certificate,
    intermediate_kp: KeyPair,
}

impl MockGoogleCa {
    pub fn new() -> Self {
        let root_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut rp = params("mock Google Hardware Attestation Root");
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = rp.self_signed(&root_kp).unwrap();
        let intermediate_kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut ip = params("mock Android attestation intermediate");
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate = ip.signed_by(&intermediate_kp, &root, &root_kp).unwrap();
        Self {
            root,
            intermediate,
            intermediate_kp,
        }
    }

    pub fn root_der(&self) -> Vec<u8> {
        self.root.der().to_vec()
    }

    /// A policy whose only Android anchor is this CA's root.
    pub fn policy(&self) -> HardwareAttestationPolicy {
        HardwareAttestationPolicy {
            android_root_ders: vec![std::borrow::Cow::Owned(self.root_der())],
            ..HardwareAttestationPolicy::default()
        }
    }

    /// Generation-custody evidence attesting `ed25519_raw` at `km_level`.
    pub fn evidence_for(&self, ed25519_raw: &[u8], km_level: u8) -> serde_json::Value {
        let mut lp = params("mock android key");
        lp.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description(km_level),
        )];
        let leaf = lp
            .signed_by(
                &RawEd25519(ed25519_raw.to_vec()),
                &self.intermediate,
                &self.intermediate_kp,
            )
            .unwrap();
        serde_json::json!({
            "android_key_attestation_leaf_hex": hex::encode(leaf.der()),
            "android_key_attestation_chain_hex": [hex::encode(self.intermediate.der())],
            "challenge_policy": "generation_only",
        })
    }
}

/// The raw Ed25519 key of the deterministic test record for `key_id`.
pub fn record_key(key_id: &str) -> Vec<u8> {
    use base64::Engine as _;
    let (ed, _) = super::tier_ingest::test_support::hybrid_pubkeys(key_id);
    base64::engine::general_purpose::STANDARD
        .decode(ed)
        .unwrap()
}

fn is_android_refusal(e: &Error, needle: &str) -> bool {
    matches!(e, Error::AccordHolderRequiresAttestationEvidence { detail, .. } if detail.contains(needle))
}

#[test]
fn i185_a_genuine_chain_admits_at_the_measured_class() {
    let ca = MockGoogleCa::new();
    let p = ca.policy();
    let k = record_key("i185-genuine");
    for (level, class) in [
        (TEE, HardwareType::AndroidKeystore),
        (STRONGBOX, HardwareType::AndroidStrongbox),
    ] {
        let ev = ca.evidence_for(&k, level);
        assert_eq!(
            p.check_structure("i185-genuine", Some(&k), Some(&ev))
                .unwrap(),
            Some(class),
            "a genuine chain for the record's key admits at the MEASURED class"
        );
    }
}

#[test]
fn i185_the_same_chain_for_another_key_is_refused_anti_lift() {
    let ca = MockGoogleCa::new();
    let p = ca.policy();
    let ev = ca.evidence_for(&record_key("i185-victim"), STRONGBOX);
    let err = p
        .check_structure("i185-lifter", Some(&record_key("i185-lifter")), Some(&ev))
        .unwrap_err();
    assert!(
        is_android_refusal(&err, "android key attestation refused"),
        "a chain attesting another key must be refused: {err}"
    );
}

#[test]
fn i185_a_chain_rooted_outside_the_anchors_is_refused() {
    // The DEFAULT policy: verify's baked Google anchors. A mock chain is
    // genuine to its own root and must be refused here.
    let ca = MockGoogleCa::new();
    let k = record_key("i185-foreign");
    let ev = ca.evidence_for(&k, STRONGBOX);
    let err = HardwareAttestationPolicy::default()
        .check_structure("i185-foreign", Some(&k), Some(&ev))
        .unwrap_err();
    assert!(
        is_android_refusal(&err, "android key attestation refused"),
        "{err}"
    );
    // And a DIFFERENT mock CA is foreign to this one.
    let err = MockGoogleCa::new()
        .policy()
        .check_structure("i185-foreign", Some(&k), Some(&ev))
        .unwrap_err();
    assert!(
        is_android_refusal(&err, "android key attestation refused"),
        "{err}"
    );
}

#[test]
fn i185_the_default_anchor_set_is_googles_two_roots() {
    // An empty default would refuse every Android chain and every witness
    // above would still pass against a mock-injected policy.
    assert_eq!(
        HardwareAttestationPolicy::default().android_root_ders.len(),
        2,
        "verify's baked Google Hardware Attestation Root and Key Attestation CA1"
    );
    let empty = HardwareAttestationPolicy {
        android_root_ders: Vec::new(),
        ..HardwareAttestationPolicy::default()
    };
    let ca = MockGoogleCa::new();
    let k = record_key("i185-empty");
    let err = empty
        .check_structure("i185-empty", Some(&k), Some(&ca.evidence_for(&k, TEE)))
        .unwrap_err();
    assert!(is_android_refusal(&err, "fail closed"), "{err}");
}

#[test]
fn i185_a_software_held_key_meets_the_software_floor() {
    let ca = MockGoogleCa::new();
    let k = record_key("i185-software");
    let err = ca
        .policy()
        .check_structure(
            "i185-software",
            Some(&k),
            Some(&ca.evidence_for(&k, SOFTWARE)),
        )
        .unwrap_err();
    assert!(
        matches!(&err, Error::HardwareTypeNotAccepted { got, .. } if got == "SoftwareOnly"),
        "the measured class is SoftwareOnly, which the default floor refuses: {err}"
    );
}

#[test]
fn i185_no_key_to_bind_refuses_rather_than_admitting_unwalked() {
    let ca = MockGoogleCa::new();
    let k = record_key("i185-nokey");
    let err = ca
        .policy()
        .check_structure("i185-nokey", None, Some(&ca.evidence_for(&k, TEE)))
        .unwrap_err();
    assert!(is_android_refusal(&err, "no key was supplied"), "{err}");
}

#[test]
fn i185_the_body_states_generation_only_and_nothing_else() {
    let ca = MockGoogleCa::new();
    let k = record_key("i185-shape");
    let p = ca.policy();
    for (field, value) in [
        ("challenge_policy", serde_json::json!("bound")),
        ("nonce", serde_json::json!("00")),
    ] {
        let mut ev = ca.evidence_for(&k, TEE);
        ev[field] = value;
        let err = p
            .check_structure("i185-shape", Some(&k), Some(&ev))
            .unwrap_err();
        assert!(is_android_refusal(&err, "malformed"), "{field}: {err}");
    }
}

/// The door legs: the walk is REACHED at registration and where a replicated
/// record lands, on every backend (a policy-level green proves enforcement,
/// not reachability).
pub mod bodies {
    use super::*;
    use crate::federation::operational::test_support as ops;
    use crate::federation::types::identity_type;
    use crate::federation::FederationDirectory;

    pub async fn i185_doors(d: &dyn FederationDirectory, ca: &MockGoogleCa, tag: &str) {
        // The PREFIX varies: test keys seed from the first 32 bytes of the id,
        // so `{tag}-good` and `{tag}-lifter` would be ONE key.
        let good = format!("good-{tag}");
        ops::register_typed_key_with_evidence(
            d,
            &good,
            identity_type::NODE,
            Some(ca.evidence_for(&record_key(&good), STRONGBOX)),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I185: a genuine chain registers: {e}"));
        let stored = d.lookup_public_key(&good).await.unwrap().expect("stored");
        assert_eq!(
            stored.attestation_evidence.as_ref().unwrap()["challenge_policy"],
            "generation_only",
            "{tag} I185: the stored record says no freshness was claimed"
        );

        let lifter = format!("lift-{tag}");
        let err = ops::register_typed_key_with_evidence(
            d,
            &lifter,
            identity_type::NODE,
            Some(ca.evidence_for(&record_key(&good), STRONGBOX)),
        )
        .await
        .expect_err("a lifted chain must be refused at registration");
        assert!(
            is_android_refusal(&err, "android key attestation refused"),
            "{tag} I185: {err}"
        );
        assert!(
            d.lookup_public_key(&lifter).await.unwrap().is_none(),
            "{tag} I185: nothing stored"
        );

        let replicated = format!("repl-{tag}");
        let err = ops::apply_replicated_typed_key_with_evidence(
            d,
            &replicated,
            identity_type::NODE,
            Some(ca.evidence_for(&record_key(&good), STRONGBOX)),
        )
        .await
        .expect_err("a lifted chain must be refused where a replicated record lands");
        assert!(
            is_android_refusal(&err, "android key attestation refused"),
            "{tag} I185: {err}"
        );

        // The trust-root holder-hardware leg: an Android holder's chain was
        // walked (against its record's key), so it reports the measured class
        // AND a passed walk — not Layer-A-only like a self-reported body.
        let user = format!("user-{tag}");
        let root = format!("root-{tag}");
        let holders: Vec<String> = (0..3).map(|i| format!("h{i}-{tag}")).collect();
        ops::register_typed_key_with_evidence(d, &user, identity_type::NODE, None)
            .await
            .unwrap();
        for h in &holders {
            ops::register_typed_key_with_evidence(
                d,
                h,
                identity_type::NODE,
                Some(ca.evidence_for(&record_key(h), TEE)),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I185: register holder {h}: {e}"));
        }
        ops::seed_chartered_family_root(d, &root, &holders, &user)
            .await
            .unwrap_or_else(|e| panic!("{tag} I185: charter: {e}"));
        let v = crate::federation::trust_root::trust_root_valid(d, &user, &root)
            .await
            .unwrap();
        assert!(v.valid && v.holders_hardware_attested, "{tag} I185: {v:?}");
        assert!(
            v.holders_hardware
                .iter()
                .all(|h| h.class == Some(HardwareType::AndroidKeystore)
                    && h.layer_a
                    && h.layer_b == Some(true)),
            "{tag} I185: every Android holder reports the measured class and a walked chain: {v:?}"
        );
    }
}

mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i185_doors() {
                    let Some(b) = $fresh.await else { return };
                    let ca = super::super::MockGoogleCa::new();
                    b.set_hardware_attestation_policy(std::sync::Arc::new(ca.policy()));
                    super::super::bodies::i185_doors(
                        &b as &dyn FederationDirectory,
                        &ca,
                        &format!("i185-{}", super::suffix()),
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
