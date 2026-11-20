//! v62.0.0 (slice D) — **CIRISVerify 23's independent vectors, pinned as
//! files.** I1850, I1851.
//!
//! Verify 23.0.0 published independent vectors that persist and CIRISKernel
//! pin. Persist keeps byte-identical copies, taken from the `v23.0.0` tag
//! (the edition-2 files at Verify `23.3.0`, slice C3), under
//! `tests/vectors/verify_v23/`:
//!
//! | file | Verify path at the tag |
//! |---|---|
//! | `edition2/row_statements_v4.json` (**Verify 23.3.2**, R1-v2332; v3 retired) | `src/ciris-verify-core/tests/vectors/edition2/` |
//! | `edition2/key_of_iss_v1.json` (**Verify 23.3.0**, 24 cases) | `src/ciris-verify-core/tests/vectors/edition2/` |
//! | `edition2/key_of_iss_v3.json` (**Verify 23.3.2**, 32 cases; R1-v2332; v2 retired) | `src/ciris-verify-core/tests/vectors/edition2/` |
//! | `accord_halt/accord_halt_v2.json` (**Verify 23.3.0**; v1 retired) | `src/ciris-verify-core/tests/vectors/accord_halt/` |
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
//! - **I2360** (slice C3) the three Verify 23.3.0 files carry the case
//!   counts they have at Verify tag 23.3.0 (ffd7af1).
//!
//! To re-pin from a later tag: copy the file, update its digest here, and
//! say why in the CHANGELOG. `edition2/row_statements_v4.json` and
//! `edition2/key_of_iss_v1.json` are the files persist's door replays
//! (`edition2::verify_vectors_replay`, I1901, I2365–I2367);
//! `accord_halt/accord_halt_v2.json` the halt door's
//! (`edition2::halt_invariants`, I2361–I2364).

/// `(path under tests/vectors/verify_v23/, bytes, pinned SHA-256)`.
const PINNED: &[(&str, &[u8], &str)] = &[
    (
        "edition2/row_statements_v4.json",
        include_bytes!("../../tests/vectors/verify_v23/edition2/row_statements_v4.json"),
        "ec83f2d8dc4080c62bc5482d7eaa99f778d374c8f126df884ee416cf67cb0b93",
    ),
    (
        "edition2/key_of_iss_v1.json",
        include_bytes!("../../tests/vectors/verify_v23/edition2/key_of_iss_v1.json"),
        "bd584d9b31b7271dc86c05a29eec75044b5fe74aae8dd586701a227f09001333",
    ),
    // v62.0.0 (R1-v2332) — CIRISVerify 23.3.2: the rc21 key check's known
    // answers (step 8's four ways, the strict end rule, location_proof
    // authored by its subject), the possession voice signed as the
    // occurrence key (CC rc21 90d537b). v2 (23.3.1) is retired.
    (
        "edition2/key_of_iss_v3.json",
        include_bytes!("../../tests/vectors/verify_v23/edition2/key_of_iss_v3.json"),
        "371eebcb647e802d522bf44fd979d7faa338d87c42a6af0377e5ab4aaab3a8f9",
    ),
    (
        "accord_halt/accord_halt_v2.json",
        include_bytes!("../../tests/vectors/verify_v23/accord_halt/accord_halt_v2.json"),
        "a70536271ee3d19af4390c4c603e17a4cba54fa18449d6296d3696f6756e9581",
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

/// I1850 — the files are the bytes taken at Verify's tags (v23.0.0; the
/// edition-2 and halt files Verify 23.3.0).
#[test]
fn i1850_verify_v23_vectors_are_pinned_by_sha256() {
    for (path, bytes, pinned) in PINNED {
        assert_eq!(
            sha256_hex(bytes),
            *pinned,
            "I1850: tests/vectors/verify_v23/{path} is not the pinned copy"
        );
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

/// I2360 — the Verify 23.3.0 files parse with the case counts they carry at
/// Verify tag 23.3.0 (a re-copy from another tag is red here as well as on its digest).
#[test]
fn i2360_verify_23_3_vectors_carry_their_case_counts() {
    let rows = vector("edition2/row_statements_v4.json");
    for (key, n) in [
        ("valid", 5),
        ("refusals", 50),
        ("family", 9),
        ("family_vendored", 33),
        ("family_vendored_groups", 4),
        ("key_directory", 6),
        ("key_records", 17),
        ("objects", 6),
        ("references", 11),
    ] {
        assert_eq!(len_of(&rows, key), n, "I2360: row_statements_v4 `{key}`");
    }
    let key_of = vector("edition2/key_of_iss_v1.json");
    assert_eq!(len_of(&key_of, "cases"), 24, "I2360: key_of_iss_v1");
    // v62.0.0 (R1-v2332) — Verify 23.3.2's v3 file (I4020 replays it).
    let key_of_v3 = vector("edition2/key_of_iss_v3.json");
    assert_eq!(len_of(&key_of_v3, "cases"), 32, "I2360: key_of_iss_v3");
    let halt = vector("accord_halt/accord_halt_v2.json");
    for (key, n) in [("invocations", 21), ("lifecycles", 22), ("latch", 13)] {
        assert_eq!(len_of(&halt, key), n, "I2360: accord_halt_v2 `{key}`");
    }
    assert_eq!(
        halt["rosters"].as_object().map_or(0, serde_json::Map::len),
        2,
        "I2360: accord_halt_v2 rosters"
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
