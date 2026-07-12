//! v8.4.0 (CEG 1.0-RC14 §19.7 / CIRISPersist#230) — the §19.7 CONFORM step:
//! the **second-impl** reproduction of CIRISVerify's §19.7 conformance vectors.
//!
//! Per §19.7's conformance note, no reference implementation defined these
//! bytes, so the FIRST conformant implementation (CIRISVerify v5.10.0) emits
//! the canonical vectors and a SECOND reproduces them byte-for-byte. CIRISPersist
//! is that second impl: this test loads the vectors copied into persist's tree
//! (`tests/vectors/holonomic_v19_7/`) and asserts persist — THROUGH the
//! verify-core API exactly as persist integrates it (`signing_preimage`,
//! `member_commitment`, `descend_order`, `verify_aggregation_meta`) — reproduces
//! each one. Passing lifts §19.7 from RC-grade to 1.0.
//!
//! The vectors are byte-identical copies of
//! `ciris-verify-core/tests/vectors/holonomic_v19_7/` so persist's conformance
//! proof is self-contained (it does not reach into the verify-core checkout).

#![cfg(feature = "sqlite")]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner};
use ciris_verify_core::holonomic::aggregation::descend_order;
use ciris_verify_core::holonomic::{
    member_commitment, verify_aggregation_meta, AggregationMetaV1, AggregationMetaVerification,
};
use ed25519_dalek::{Signer as _, SigningKey};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/holonomic_v19_7");

fn load(rel: &str) -> serde_json::Value {
    let path = format!("{VECTORS}/{rel}");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read vector {path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse vector {path}: {e}"))
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte"))
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn str_list(v: &serde_json::Value, key: &str) -> Vec<String> {
    v[key]
        .as_array()
        .expect("array field")
        .iter()
        .map(|x| x.as_str().expect("string member").to_owned())
        .collect()
}

/// `domain_separators.json` — the §19.7.1 16-byte `AGG-META-v1` domain matches
/// (the constant persist's verifiers ride).
#[test]
fn domain_separator_matches_vector() {
    let v = load("domain_separators.json");
    let expected_hex = v["agg_meta_v1_hex"].as_str().unwrap();
    let expected_len = v["agg_meta_v1_len"].as_u64().unwrap() as usize;
    assert_eq!(
        ciris_verify_core::holonomic::DOMAIN_AGG_META.len(),
        expected_len
    );
    assert_eq!(
        hex_lower(ciris_verify_core::holonomic::DOMAIN_AGG_META),
        expected_hex,
        "AGG-META-v1 domain separator reproduces the vector byte-for-byte"
    );
}

/// `aggregation_meta/canonical_bytes.json` — build the verify-core
/// `AggregationMetaV1` from the vector inputs and assert `signing_preimage()`
/// equals the expected §19.7.1 canonical bytes byte-for-byte.
/// Covers BOTH the v1 golden AND the §19.7.1.2 v2 golden (CIRISVerify#167):
/// the v2 preimage appends a trailing big-endian `u32(n_eff)`, while the v1
/// preimage is byte-identical to the pre-#167 layout. Persist reproduces each
/// byte-for-byte — the cross-impl guarantee that a v2 aggregator's signature
/// verifies here.
#[test]
fn aggregation_meta_canonical_bytes_reproduced() {
    for rel in [
        "aggregation_meta/canonical_bytes.json",
        "aggregation_meta/canonical_bytes_v2.json",
    ] {
        let v = load(rel);

        // member_commitment is itself reproduced from the source ids (and equals
        // the vector's member_commitment_hex).
        let source_ids = str_list(&v, "source_member_ids");
        let mc = member_commitment(&source_ids);
        assert_eq!(
            hex_lower(&mc),
            v["member_commitment_hex"].as_str().unwrap(),
            "{rel}: member_commitment over source_member_ids reproduces the vector"
        );

        let meta = AggregationMetaV1 {
            version: v["version"].as_u64().unwrap() as u32,
            content_id: v["content_id"].as_str().unwrap().to_owned(),
            corpus_kind: v["corpus_kind"].as_str().unwrap().to_owned(),
            tier: v["tier"].as_u64().unwrap() as u32,
            aggregation_algorithm_id: v["aggregation_algorithm_id"].as_str().unwrap().to_owned(),
            source_count: v["source_count"].as_u64().unwrap() as u32,
            // §19.7.1.2 (#167): signed n_eff from the vector (version-2 golden)
            // or the v1 neutral placeholder (source_count) when absent.
            n_eff: v["n_eff"]
                .as_u64()
                .unwrap_or_else(|| v["source_count"].as_u64().unwrap()) as u32,
            // §19.7.1.3 (#191/#435): v3 surface from the vector when present;
            // zero-neutral for the byte-untouched v1/v2 goldens (append-only —
            // a pre-v3 preimage excludes both fields).
            max_source_multiplicity: v["max_source_multiplicity"].as_u64().unwrap_or(0) as u32,
            mass_commitment: v["mass_commitment_hex"]
                .as_str()
                .map(|h| hex_decode(h).try_into().expect("32-byte mass root"))
                .unwrap_or([0u8; 32]),
            member_commitment: mc,
            noise_floor_descriptor: v["noise_floor_descriptor"].as_str().unwrap().to_owned(),
        };

        let expected = hex_decode(v["expected_canonical_bytes_hex"].as_str().unwrap());
        assert_eq!(
            meta.signing_preimage(),
            expected,
            "{rel}: §19.7.1 canonical signing preimage reproduced byte-for-byte"
        );
        // The domain separator the preimage starts with also matches the vector.
        assert!(
            meta.signing_preimage()
                .starts_with(&hex_decode(v["domain_separator_hex"].as_str().unwrap())),
            "{rel}: preimage begins with the §19.7.1 domain separator"
        );
    }
}

/// `member_commitment/{single,three_unsorted,empty}.json` — each reproduces
/// the expected Merkle root. `three_unsorted` proves the canonical sort;
/// `empty` proves the `WW-v1-empty` sentinel.
#[test]
fn member_commitment_vectors_reproduced() {
    for rel in [
        "member_commitment/single.json",
        "member_commitment/three_unsorted.json",
        "member_commitment/empty.json",
    ] {
        let v = load(rel);
        let ids = str_list(&v, "source_member_ids");
        let got = member_commitment(&ids);
        assert_eq!(
            hex_lower(&got),
            v["expected_commitment_hex"].as_str().unwrap(),
            "{rel} reproduced byte-for-byte"
        );
    }

    // three_unsorted: the order-independence the canonical sort guarantees.
    let v = load("member_commitment/three_unsorted.json");
    let ids = str_list(&v, "source_member_ids");
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(
        member_commitment(&ids),
        member_commitment(&sorted),
        "member_commitment is order-independent (canonical lexicographic sort)"
    );
}

/// `descend/ordered_list.json` — `descend_order` returns the canonical
/// lexicographic order, and that order re-derives the committed root.
#[test]
fn descend_order_vector_reproduced() {
    let v = load("descend/ordered_list.json");
    let input = str_list(&v, "input_member_ids");
    let expected = str_list(&v, "expected_ordered_ids");
    assert_eq!(
        descend_order(&input),
        expected,
        "descend_order reproduces the canonical order vector"
    );
    // The descend-ordered list re-derives the committed root.
    assert_eq!(
        hex_lower(&member_commitment(&descend_order(&input))),
        v["expected_commitment_hex"].as_str().unwrap(),
        "descend order re-derives the committed member_commitment"
    );
}

/// A valid-vector `verify_aggregation_meta` round-trip ACCEPTS, and a
/// PQC-missing (classical-only) one is REJECTED — the store-path gate as
/// persist integrates it. Built from the canonical_bytes vector + a fresh
/// bound-hybrid signature over the reproduced §19.7.1 preimage.
#[tokio::test]
async fn verify_aggregation_meta_admit_and_reject() {
    let v = load("aggregation_meta/canonical_bytes.json");
    let source_ids = str_list(&v, "source_member_ids");
    let meta = AggregationMetaV1 {
        version: v["version"].as_u64().unwrap() as u32,
        content_id: v["content_id"].as_str().unwrap().to_owned(),
        corpus_kind: v["corpus_kind"].as_str().unwrap().to_owned(),
        tier: v["tier"].as_u64().unwrap() as u32,
        aggregation_algorithm_id: v["aggregation_algorithm_id"].as_str().unwrap().to_owned(),
        source_count: v["source_count"].as_u64().unwrap() as u32,
        // §19.7.1.2 (#167): read the signed n_eff when the vector carries it
        // (version-2 golden); default to source_count for a v1 vector (neutral
        // placeholder — a v1 preimage excludes n_eff).
        n_eff: v["n_eff"]
            .as_u64()
            .unwrap_or_else(|| v["source_count"].as_u64().unwrap()) as u32,
        // §19.7.1.3 (#191/#435): v3 surface from the vector when present;
        // zero-neutral for the byte-untouched v1/v2 goldens.
        max_source_multiplicity: v["max_source_multiplicity"].as_u64().unwrap_or(0) as u32,
        mass_commitment: v["mass_commitment_hex"]
            .as_str()
            .map(|h| hex_decode(h).try_into().expect("32-byte mass root"))
            .unwrap_or([0u8; 32]),
        member_commitment: member_commitment(&source_ids),
        noise_floor_descriptor: v["noise_floor_descriptor"].as_str().unwrap().to_owned(),
    };

    let ed_sk = SigningKey::from_bytes(&[0x33; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[0x44; 32], "conf-mldsa").unwrap();
    let ed_pub = ed_sk.verifying_key().to_bytes();
    let mldsa_pub = mldsa.public_key().await.unwrap();

    let preimage = meta.signing_preimage();
    let ed_sig = ed_sk.sign(&preimage).to_bytes();
    let mut bound = preimage.clone();
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = mldsa.sign(&bound).await.unwrap();

    // Valid bound-hybrid → admit accepts.
    assert_eq!(
        verify_aggregation_meta(&meta, &ed_sig, &pqc_sig, &ed_pub, &mldsa_pub),
        AggregationMetaVerification::HybridVerified,
        "valid bound-hybrid meta verifies"
    );

    // Classical-only / invalid PQC half → reject (store-path PQC-mandatory).
    let garbage_pqc = vec![0u8; pqc_sig.len()];
    assert_eq!(
        verify_aggregation_meta(&meta, &ed_sig, &garbage_pqc, &ed_pub, &mldsa_pub),
        AggregationMetaVerification::Failed,
        "an invalid ML-DSA-65 half is rejected (no classical-only acceptance)"
    );

    // Sanity: b64-encoding the sigs (persist's FFI transport) preserves them.
    assert_eq!(
        BASE64.decode(BASE64.encode(ed_sig)).unwrap(),
        ed_sig.to_vec()
    );
}
