//! v62.0.0 (slice E2a, CIRISPersist#1274) — **the forward purge selection
//! digest** (CC 2.4.1.1, CC 3.3.2; the store's open encoding, CC 2.6.1.12).
//!
//! - **I1900** — `selection_digest` equals the known answers in
//!   `tests/vectors/purge_selection/selection_digest_v2.json`, produced by an
//!   independent stdlib-only encoder (`gen_selection_digest_v2.py`): the CDE
//!   preimage byte for byte, the digest, the 32-byte form. The set is ordered
//!   by each element's deterministic encoding (a shorter string first, so
//!   NOT UTF-8 order), duplicates drop, and input order never matters. The
//!   earlier JCS form never matches.

use super::steward_purge as sp;
use sha2::Digest as _;

const VECTOR: &str = include_str!("../../tests/vectors/purge_selection/selection_digest_v2.json");

#[test]
fn i1900_selection_digest_known_answers() {
    let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(v["vector"], "ciris.purge_selection_digest.v2");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7, "the pinned case count");
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let ids: Vec<String> = c["record_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            hex::encode(sp::selection_preimage(&ids)),
            c["preimage_hex"].as_str().unwrap(),
            "{id}: preimage"
        );
        assert_eq!(
            sp::selection_digest(&ids),
            c["digest_hex"].as_str().unwrap(),
            "{id}: digest"
        );
        assert_eq!(
            hex::encode(sp::selection_digest_bytes(&ids)),
            c["digest_hex"].as_str().unwrap(),
            "{id}: bytes"
        );
        // Input order never matters.
        let mut rev = ids.clone();
        rev.reverse();
        assert_eq!(
            sp::selection_digest(&rev),
            sp::selection_digest(&ids),
            "{id}: order"
        );
    }
}

#[test]
fn i1900_cde_order_is_length_first_not_utf8() {
    // UTF-8 order puts "attestation:zz" before "trace:t"; CDE puts the
    // shorter "trace:t" first.
    let p = sp::selection_preimage(&["attestation:zz", "trace:t"]);
    let first_len = (p[1] & 0x1f) as usize;
    assert_eq!(&p[2..2 + first_len], b"trace:t");
    // The earlier form (JCS, UTF-8 sorted) is a different digest.
    let jcs =
        ciris_verify_core::jcs::canonicalize(&serde_json::json!(["attestation:zz", "trace:t"]))
            .unwrap();
    assert_ne!(
        hex::encode(sha2::Sha256::digest(jcs)),
        sp::selection_digest(&["attestation:zz", "trace:t"])
    );
    // A repeated id is one member of the set.
    assert_eq!(
        sp::selection_digest(&["trace:t", "trace:t"]),
        sp::selection_digest(&["trace:t"])
    );
}
