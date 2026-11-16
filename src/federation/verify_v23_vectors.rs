//! v62.0.0 (slice D) — **CIRISVerify 23's independent vectors, pinned as
//! files.** I1850, I1851.
//!
//! Verify 23.0.0 published independent vectors that persist and CIRISKernel
//! pin. Persist keeps byte-identical copies of four, taken from the
//! `v23.0.0` tag, under `tests/vectors/verify_v23/`:
//!
//! | file | Verify path at v23.0.0 |
//! |---|---|
//! | `edition2/row_statements_v1.json` | `src/ciris-verify-core/tests/vectors/edition2/` |
//! | `composite/mldsa65_ed25519_draft_kats.json` | `src/ciris-crypto/tests/vectors/composite/` |
//! | `accord_lineage/accord_recovery_refusals_v1.json` | `src/ciris-verify-core/tests/vectors/accord_lineage/` |
//! | `substrate_composite/composite_signatures_v1.json` | `src/ciris-verify-core/tests/vectors/substrate_composite/` |
//!
//! - **I1850** each file's SHA-256 is the pinned one (a silent edit, or a
//!   re-copy from a later tag, is red), and each parses with the case counts
//!   it had at the tag. The edition-2 semantics these describe are a later
//!   slice's; this slice pins the bytes.
//! - **I1851** the substrate composite vector runs through persist's own
//!   forward §19 verifier ([`crate::verify::sig19::verify_sig19`], the
//!   composite arm): every case verifies under the vector's composite key, and
//!   every refusal is refused.
//!
//! To re-pin from a later tag: copy the file, update its digest here, and
//! say why in the CHANGELOG (`edition2/row_statements_v1.json` already
//! differs at Verify's 23.1.3 tag).

/// `(path under tests/vectors/verify_v23/, bytes, pinned SHA-256)`.
const PINNED: &[(&str, &[u8], &str)] = &[
    (
        "edition2/row_statements_v1.json",
        include_bytes!("../../tests/vectors/verify_v23/edition2/row_statements_v1.json"),
        "288addfa43969097d3f78d54385a82a09254271c51161ee67d0effab3abc2e52",
    ),
    (
        "composite/mldsa65_ed25519_draft_kats.json",
        include_bytes!("../../tests/vectors/verify_v23/composite/mldsa65_ed25519_draft_kats.json"),
        "7dc03ce5e7da7d54c2e1616593bce53ff4a09b0cb52b787a0a6061a22eb102f3",
    ),
    (
        "accord_lineage/accord_recovery_refusals_v1.json",
        include_bytes!(
            "../../tests/vectors/verify_v23/accord_lineage/accord_recovery_refusals_v1.json"
        ),
        "1c08942c4e6d4241d14f2eea3e4910f24c5f3497821191dd4d98bb144be12b92",
    ),
    (
        "substrate_composite/composite_signatures_v1.json",
        include_bytes!(
            "../../tests/vectors/verify_v23/substrate_composite/composite_signatures_v1.json"
        ),
        "ec6bf06e9b53c2f65d4a914912fe55eede95c0a283b7b7b7de457fb386b252e8",
    ),
];

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn vector(path: &str) -> serde_json::Value {
    let (_, bytes, _) = PINNED
        .iter()
        .find(|(p, _, _)| *p == path)
        .unwrap_or_else(|| panic!("{path} is not a pinned vector"));
    serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("{path} parses: {e}"))
}

/// The number of entries in the array at `key`.
fn len_of(v: &serde_json::Value, key: &str) -> usize {
    v[key].as_array().map_or(0, Vec::len)
}

/// I1850 — the four files are the bytes taken at Verify's v23.0.0 tag.
#[test]
fn i1850_verify_v23_vectors_are_pinned_by_sha256() {
    for (path, bytes, pinned) in PINNED {
        assert_eq!(
            sha256_hex(bytes),
            *pinned,
            "I1850: tests/vectors/verify_v23/{path} is not the pinned v23.0.0 copy"
        );
    }
    let rows = vector("edition2/row_statements_v1.json");
    for (key, n) in [
        ("valid", 5),
        ("refusals", 40),
        ("earlier_form", 5),
        ("family", 9),
        ("family_vendored", 8),
        ("key_directory", 5),
        ("key_records", 13),
        ("objects", 6),
        ("references", 11),
    ] {
        assert_eq!(len_of(&rows, key), n, "I1850: row_statements_v1 `{key}`");
    }
    let kats = vector("composite/mldsa65_ed25519_draft_kats.json");
    assert!(
        kats.get("jose_06").is_some() && kats.get("lamps_19").is_some(),
        "I1850: the composite KATs carry both profiles"
    );
    let recovery = vector("accord_lineage/accord_recovery_refusals_v1.json");
    assert_eq!(len_of(&recovery, "cases"), 5, "I1850: recovery refusals");
    let composite = vector("substrate_composite/composite_signatures_v1.json");
    assert_eq!(
        len_of(&composite, "cases"),
        12,
        "I1850: substrate composite"
    );
}

/// I1851 — persist's forward §19 verifier agrees with Verify's independent
/// composite vectors (generated with dilithium-py and pyca/cryptography, not
/// the Rust code).
#[test]
fn i1851_the_substrate_composite_vectors_verify_through_persists_sig19() {
    use crate::verify::sig19::{verify_sig19, Sig19};
    let v = vector("substrate_composite/composite_signatures_v1.json");
    let pk = hex::decode(v["composite_public_key_hex"].as_str().unwrap()).unwrap();
    assert_eq!(pk.len(), ciris_crypto::composite::PUBLIC_KEY_LEN);
    let (mldsa_pk, ed_pk) = pk.split_at(ciris_crypto::composite::MLDSA65_PK_LEN);
    let mut refusals = 0usize;
    for case in v["cases"].as_array().unwrap() {
        let id = case["vector_id"].as_str().unwrap();
        let preimage = hex::decode(case["preimage_hex"].as_str().unwrap()).unwrap();
        let sig = hex::decode(case["signature_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            verify_sig19(&preimage, &Sig19(sig), ed_pk, mldsa_pk),
            Ok(()),
            "I1851 {id}: the vector's composite verifies"
        );
        for (name, bad) in case["refusals"].as_object().unwrap() {
            let bad = hex::decode(bad.as_str().unwrap()).unwrap();
            assert!(
                verify_sig19(&preimage, &Sig19(bad), ed_pk, mldsa_pk).is_err(),
                "I1851 {id}/{name}: a refusal must not verify"
            );
            refusals += 1;
        }
    }
    assert!(refusals >= 12, "I1851: the refusals ran ({refusals})");
}
