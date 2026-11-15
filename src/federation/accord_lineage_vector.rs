//! **The accord lineage cross-implementation vector** (CIRISVerify parity).
//! I1783.
//!
//! Three versions of a SYNTHETIC accord family record, each admitted by
//! persist's real doors on a real backend:
//!
//! - **v1** a genesis head (no predecessor), installed through the trusted
//!   local door the genesis install uses (`put_family_local`);
//! - **v2** a roster change adding a holder, through the accord's one door
//!   ([`verify_accord_roster_change`](super::accord_roster::verify_accord_roster_change),
//!   reached by `supersede_family_signed`);
//! - **v3** a holder recovery on top of v2
//!   ([`recover_accord_holder`](super::accord_recovery::recover_accord_holder)).
//!
//! The generator ([`bodies::generate`]) records, per version, the stored serde
//! form, the exact `PythonJsonDumpsCanonicalizer` bytes `persist_row_hash`
//! hashes, the hash, the head link, and the envelope the holders sign with its
//! signing bytes; plus the canonicalizer's observed rules, each a probe input
//! and the bytes it produced. Every key is a deterministic test signer; every
//! instant is fixed. Nothing comes from the baked genesis.
//!
//! - **I1783** the checked-in vector
//!   (`tests/vectors/accord_lineage/accord_lineage_v1.json`) is persist's: every
//!   `persist_row_hash` recomputes from its stored record, every canonical byte
//!   string matches, every head link holds, every signing-bytes value is the
//!   encoder's, every signature verifies against the listed public keys, and
//!   every canonicalizer probe reproduces. The generator re-runs the doors and
//!   asserts it produces the checked-in vector byte for byte.
//!
//! Regenerate: `ACCORD_LINEAGE_VECTOR_OUT=<path> cargo nextest run --features
//! sqlite -E 'test(accord_lineage_vector)'`, then copy `<path>` over the
//! checked-in file.

/// The checked-in vector.
const VECTOR: &str = include_str!("../../tests/vectors/accord_lineage/accord_lineage_v1.json");

/// The bytes `compute_persist_row_hash` hashes for `row`: the serde value
/// without `persist_row_hash` / `consent_role`, every instant truncated to
/// microseconds, through `PythonJsonDumpsCanonicalizer`.
fn persist_row_hash_preimage<T: serde::Serialize>(row: &T) -> Vec<u8> {
    use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
    let mut value = serde_json::to_value(row).unwrap();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("persist_row_hash");
        obj.remove("consent_role");
    }
    crate::federation::types::truncate_instants_to_microseconds(&mut value);
    PythonJsonDumpsCanonicalizer
        .canonicalize_value(&value)
        .unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// `{utf8, hex}` of a byte string, so escaping is unambiguous.
fn bytes_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "utf8": String::from_utf8(bytes.to_vec()).expect("canonical bytes are UTF-8"),
        "hex": hex::encode(bytes),
    })
}

/// The canonicalizer probes: `(rule, input)`. The output is observed by
/// running `PythonJsonDumpsCanonicalizer` over `input`.
fn probes() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        (
            "key_order_and_separators",
            json!({"b": 1, "a": [1, 2], "A": {"z": null, "y": true}}),
        ),
        ("non_ascii_bmp_latin", json!("Hüterin")),
        ("non_ascii_bmp_cjk", json!("守护者")),
        ("non_bmp_emoji", json!("🦀")),
        ("non_bmp_emoji_with_variation_selector", json!("🛡️")),
        (
            "control_and_escapes",
            json!("tab\tnl\nquote\"bs\\slash/del\u{7f}nul\u{0}"),
        ),
        ("non_ascii_object_key", json!({"ü": 1, "u": 2, "z": 3})),
        // U+FB01 sorts BEFORE U+1F980 by code point, AFTER it by UTF-16 unit.
        ("non_bmp_object_key_order", json!({"\u{fb01}": 1, "🦀": 2})),
        ("float_one", json!(1.0)),
        ("float_small", json!(1e-7)),
        ("float_1e_minus_5", json!(1e-5)),
        ("float_0_0001", json!(0.0001)),
        ("float_1e15", json!(1e15)),
        ("float_1e16", json!(1e16)),
        ("float_fraction", json!(123_456.789)),
        ("float_tenth", json!(0.1)),
        ("float_large", json!(1e21)),
        ("float_huge", json!(1.5e300)),
        ("float_negative_zero", json!(-0.0)),
        ("int_2_pow_53_plus_1", json!(9_007_199_254_740_993_u64)),
        ("int_u64_max", json!(u64::MAX)),
        ("int_i64_min", json!(i64::MIN)),
        ("null_and_bools", json!([null, true, false])),
        ("empty_containers", json!({"o": {}, "a": []})),
    ]
}

/// Each probe's observed output.
fn probe_rows() -> Vec<serde_json::Value> {
    use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
    probes()
        .into_iter()
        .map(|(rule, input)| {
            let out = PythonJsonDumpsCanonicalizer
                .canonicalize_value(&input)
                .unwrap();
            serde_json::json!({ "rule": rule, "input": input, "output": bytes_json(&out) })
        })
        .collect()
}

/// The instant probes: `(raw RFC-3339, the serde rendering of the parsed
/// `DateTime<Utc>`, that rendering after truncation)`.
fn instant_rows() -> Vec<serde_json::Value> {
    [
        "2026-03-14T15:09:26.535897932Z",
        "2026-06-01T12:00:00.123000789Z",
        "2026-06-01T12:00:00.000000789Z",
        "2026-06-01T12:00:00.100000Z",
        "2026-06-01T12:00:00.5Z",
        "2026-06-01T12:00:00Z",
        "2026-06-01T14:00:00.123456789+02:00",
    ]
    .iter()
    .map(|raw| {
        let t: chrono::DateTime<chrono::Utc> = raw.parse().unwrap();
        let serde = serde_json::to_value(t).unwrap();
        let mut truncated = serde.clone();
        crate::federation::types::truncate_instants_to_microseconds(&mut truncated);
        serde_json::json!({ "raw": raw, "serde": serde, "truncated": truncated })
    })
    .collect()
}

#[cfg(test)]
pub(crate) mod bodies {
    use super::{bytes_json, instant_rows, persist_row_hash_preimage, probe_rows, sha256_hex};
    use crate::federation::accord_recovery::{
        draft_accord_recovery, recover_accord_holder, AccordRecoveryRequest,
    };
    use crate::federation::accord_roster::{SeatAdd, SeatChange};
    use crate::federation::accord_roster_invariants::bodies::{
        apply, decide, held, version_shaped,
    };
    use crate::federation::canonical_community::accord_family_key_id;
    use crate::federation::operational::test_support as ops;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{
        recovery_commitment, test_accord_recovery_commitments, test_committed_key,
        test_pre_rotation_commitment, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
        TRUST_CHARTER_DIMENSION,
    };
    use crate::federation::types::{attestation_type, identity_type, Family, FamilyMember};
    use crate::federation::FederationDirectory;
    use serde_json::json;

    /// The genesis holders.
    pub(crate) const HOLDERS: [&str; 3] = ["vec-holder-a", "vec-holder-b", "vec-holder-c"];
    /// The holder v2 seats.
    pub(crate) const ADDED: &str = "vec-holder-d";
    /// The key v3 seats in `vec-holder-a`'s place.
    pub(crate) const RECOVERED: &str = "vec-holder-a2";
    /// `vec-holder-a`'s committed recovery key.
    pub(crate) const RECOVERY_KEY: &str = "vec-holder-a-recovery";
    /// A non-ASCII family name with a non-BMP character.
    pub(crate) const FAMILY_NAME: &str = "Accord Lineage Vector — Hüterinnen 守护者 🛡️";
    /// The added seat's role: non-ASCII, with a non-BMP character.
    pub(crate) const ADDED_ROLE: &str = "Hüterin 🦀";
    const FOUNDED_AT: &str = "2026-01-01T00:00:00Z";
    /// v2's seat instant, carrying NANOSECONDS (truncates to `.535897`).
    pub(crate) const V2_JOINED_AT: &str = "2026-03-14T15:09:26.535897932Z";
    /// v3's seat instant, nanoseconds over whole milliseconds (truncates to `.123`).
    pub(crate) const V3_JOINED_AT: &str = "2026-06-01T12:00:00.123000789Z";
    const DECISION_CLOSES: &str = "2026-02-01T00:00:00Z";
    const CHARTER_V2_AT: &str = "2026-01-15T00:00:00Z";

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().unwrap()
    }

    /// A charter of the accord committing a test recovery key for each of
    /// `roster`, attested by `signers[0]` and co-scrubbed by the rest. A fixed
    /// id, so the digest is the same every run. Returns the digest.
    fn charter_row(
        roster: &[&str],
        signers: &[&str],
        id: &str,
        asserted_at: &str,
    ) -> crate::federation::Attestation {
        let env = json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": test_pre_rotation_commitment(&[
                "vec-successor-a".to_owned(),
                "vec-successor-b".to_owned(),
            ])
            .unwrap(),
            "recovery_commitments": test_accord_recovery_commitments(roster),
        });
        // `ops::co_signed_trust_attestation`, at a FIXED instant: the row's
        // instants are sealed into its envelope, so every scrub follows them.
        let mut row = ops::signed_trust_attestation(
            id,
            signers[0],
            accord_family_key_id(),
            attestation_type::DELEGATES_TO,
            env,
        );
        row.asserted_at = at(asserted_at);
        row.scrub_timestamp = at(asserted_at);
        ts::reseal(&mut row);
        let sealed = row.attestation_envelope.clone();
        row.additional_scrubs = signers[1..]
            .iter()
            .map(|k| {
                let (_, classical, pqc) = ts::sign_envelope(k, &sealed);
                crate::federation::types::ScrubSig {
                    cosigned_at: None,
                    scrub_key_id: (*k).to_owned(),
                    scrub_signature_classical: classical,
                    scrub_signature_pqc: pqc,
                }
            })
            .collect();
        row
    }

    /// Admit a charter row; returns its digest.
    async fn put_charter(d: &dyn FederationDirectory, c: crate::federation::Attestation) -> String {
        let digest = ops::charter_digest_of(&c);
        d.put_attestation(crate::federation::SignedAttestation { attestation: c })
            .await
            .expect("the charter is admitted");
        digest
    }

    /// [`charter_row`], admitted.
    async fn charter(
        d: &dyn FederationDirectory,
        roster: &[&str],
        signers: &[&str],
        id: &str,
        asserted_at: &str,
    ) -> String {
        put_charter(d, charter_row(roster, signers, id, asserted_at)).await
    }

    fn holder_keys(ids: &[&str]) -> serde_json::Value {
        ids.iter()
            .map(|k| {
                let (ed, mldsa) = ts::hybrid_pubkeys(k);
                json!({
                    "key_id": k,
                    "ed25519_public_key_base64": ed,
                    "ml_dsa_65_public_key_base64": mldsa,
                })
            })
            .collect()
    }

    /// The per-record block every version carries.
    fn record_block(offered: &Family, stored: &Family) -> serde_json::Value {
        let pre = persist_row_hash_preimage(offered);
        let hash = crate::federation::types::compute_persist_row_hash(offered).unwrap();
        assert_eq!(sha256_hex(&pre), hash, "the preimage is the hash's");
        assert_eq!(
            stored.persist_row_hash, hash,
            "the store's persist_row_hash is the offered record's"
        );
        assert_eq!(
            crate::federation::types::compute_persist_row_hash(stored).unwrap(),
            hash,
            "the stored record recomputes to its own hash"
        );
        assert_eq!(
            persist_row_hash_preimage(stored),
            pre,
            "the stored record's preimage is the offered one's"
        );
        json!({
            "offered_family": serde_json::to_value(offered).unwrap(),
            "stored_family": serde_json::to_value(stored).unwrap(),
            "canonical_bytes": bytes_json(&pre),
            "persist_row_hash": hash,
            "prev_head_digest": stored.prev_head_digest,
        })
    }

    /// **Build the vector**, admitting each version through persist's doors.
    pub(crate) async fn generate(d: &dyn FederationDirectory) -> serde_json::Value {
        let accord = accord_family_key_id();
        for h in HOLDERS.iter().chain([&ADDED, &RECOVERED]) {
            ops::register_accord_holder_as(d, &ops::Identity::new(h), identity_type::ACCORD_HOLDER)
                .await
                .expect("an accord_holder key");
        }
        ts::register_hybrid_key_as(d, RECOVERY_KEY, RECOVERY_KEY, identity_type::NODE).await;

        // v1 — the genesis head. The charter door judges a charter against
        // the held family, so the head is installed naming the charter's
        // digest first, then the charter row is admitted.
        let c1_row = charter_row(&HOLDERS, &HOLDERS, "vec-accord-charter-v1", FOUNDED_AT);
        let c1 = ops::charter_digest_of(&c1_row);
        let v1 = Family {
            family_key_id: accord.to_owned(),
            family_name: FAMILY_NAME.to_owned(),
            members: HOLDERS
                .iter()
                .map(|k| FamilyMember {
                    key_id: (*k).to_owned(),
                    joined_at: at(FOUNDED_AT),
                    role: Some("founder".to_owned()),
                })
                .collect(),
            founded_at: at(FOUNDED_AT),
            consensus_protocol: ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL
                .to_owned(),
            consensus_protocol_entrenched: true,
            dissolved_at: None,
            prev_head_digest: String::new(),
            charter_digest: c1.clone(),
            persist_row_hash: String::new(),
        };
        d.put_family_local(v1.clone())
            .await
            .expect("v1: the genesis head is installed");
        assert_eq!(
            put_charter(d, c1_row).await,
            c1,
            "v1: the charter it names is held"
        );
        let s1 = held(d).await;
        let mut r1 = record_block(&v1, &s1);
        assert_eq!(s1.prev_head_digest, "", "v1 is a genesis head");
        r1["kind"] = json!("genesis");
        r1["admitted_by"] =
            json!("FederationDirectory::put_family_local (the genesis install door)");
        r1["charter_digest"] = json!(c1);

        // v2 — a roster change seating ADDED.
        let change = SeatChange {
            remove: vec![],
            add: vec![SeatAdd {
                key_id: ADDED.to_owned(),
                role: Some(ADDED_ROLE.to_owned()),
            }],
        };
        let mut grown: Vec<&str> = HOLDERS.to_vec();
        grown.push(ADDED);
        let c2 = charter(d, &grown, &HOLDERS, "vec-accord-charter-v2", CHARTER_V2_AT).await;
        let decision = decide(
            d,
            &change,
            at(DECISION_CLOSES),
            true,
            "vec-accord-lineage-v2",
        )
        .await;
        let yes = [HOLDERS[0], HOLDERS[1]];
        let v2 = version_shaped(d, &change, &decision, &c2, &yes, ADDED, |f| {
            for m in &mut f.members {
                if m.key_id == ADDED {
                    m.joined_at = at(V2_JOINED_AT);
                }
            }
        })
        .await;
        let proof2 = v2.supersede_proof.clone().unwrap();
        let offered2 = v2.family.clone();
        apply(d, v2)
            .await
            .unwrap_or_else(|e| panic!("v2: the roster change is admitted: {e}"));
        let s2 = held(d).await;
        assert_eq!(s2.prev_head_digest, s1.persist_row_hash, "v2 links v1");
        let env2 = proof2.change_envelope.clone();
        let sb2 = ciris_verify_core::accord_genesis::accord_family_signing_bytes(&env2).unwrap();
        let mut r2 = record_block(&offered2, &s2);
        r2["kind"] = json!("roster_change");
        r2["admitted_by"] = json!(
            "accord_roster::verify_accord_roster_change via group_amendment::supersede_family_signed"
        );
        r2["charter_digest"] = json!(c2);
        r2["change_envelope"] = env2;
        r2["signing_bytes_fn"] =
            json!("ciris_verify_core::accord_genesis::accord_family_signing_bytes");
        r2["signing_bytes"] = bytes_json(&sb2);
        r2["quorum_signatures"] = serde_json::to_value(&proof2.quorum_signatures).unwrap();
        r2["decision"] = json!({
            "digest": decision,
            "window_until": at(DECISION_CLOSES).to_rfc3339(),
            "nonce": "vec-accord-lineage-v2",
            "seat_change_digest":
                crate::federation::accord_roster::seat_change_digest(accord, &change).unwrap(),
        });

        // v3 — vec-holder-a recovers onto RECOVERED.
        let draft = draft_accord_recovery(
            d,
            &AccordRecoveryRequest {
                family_key_id: accord.to_owned(),
                old_holder_key_id: HOLDERS[0].to_owned(),
                new_holder_key_id: RECOVERED.to_owned(),
                recovery_key_id: RECOVERY_KEY.to_owned(),
                next_recovery_commitment: recovery_commitment(&test_committed_key(&format!(
                    "{RECOVERED}-recovery"
                )))
                .unwrap(),
                joined_at: at(V3_JOINED_AT),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("v3: draft: {e}"));
        let offered3 = draft.next.clone();
        let env3 = draft.statement.clone();
        let stmt_bytes = draft.statement_bytes.clone();
        let rsig = ts::threshold_sign(RECOVERY_KEY, &stmt_bytes);
        let r = (
            rsig.ed25519_signature_base64.clone(),
            rsig.mldsa65_signature_base64.clone().unwrap(),
        );
        let n = ops::Identity::new(RECOVERED).sign_bytes(&draft.record_bytes);
        recover_accord_holder(d, draft, r, n)
            .await
            .unwrap_or_else(|e| panic!("v3: the recovery is admitted: {e}"));
        let s3 = held(d).await;
        assert_eq!(s3.prev_head_digest, s2.persist_row_hash, "v3 links v2");
        let sb3 = ciris_verify_core::accord_genesis::accord_family_signing_bytes(&env3).unwrap();
        let mut r3 = record_block(&offered3, &s3);
        r3["kind"] = json!("holder_recovery");
        r3["admitted_by"] = json!(
            "accord_recovery::recover_accord_holder (verify_accord_recovery, then \
             group_amendment::supersede_family_signed)"
        );
        r3["charter_digest"] = json!(s3.charter_digest);
        r3["change_envelope"] = env3;
        r3["signing_bytes_fn"] =
            json!("ciris_verify_core::accord_genesis::accord_family_signing_bytes");
        r3["signing_bytes"] = bytes_json(&sb3);
        r3["door_statement_bytes_fn"] = json!(
            "crate::verify::canonical::ceg_produce_canonicalize (what draft_accord_recovery \
             hands the recovery key to sign)"
        );
        r3["door_statement_bytes"] = bytes_json(&stmt_bytes);
        r3["quorum_signatures"] = json!([rsig]);

        json!({
            "vector": "ciris.accord_lineage.v1",
            "produced_by": "CIRISPersist (src/federation/accord_lineage_vector.rs, from v61.4.1)",
            "synthetic": "deterministic test signers (seed = the key id's bytes over a [0x11;32] overlay) and fixed instants; nothing from the baked genesis",
            "family_key_id": accord,
            "hash": "persist_row_hash = lowercase hex SHA-256 of canonical_bytes; canonical_bytes = PythonJsonDumpsCanonicalizer(serde value of the Family minus persist_row_hash and consent_role, every RFC-3339 instant with more than 6 fractional digits truncated to microseconds)",
            "keys": holder_keys(&[HOLDERS[0], HOLDERS[1], HOLDERS[2], ADDED, RECOVERED, RECOVERY_KEY]),
            "versions": [r1, r2, r3],
            "canonicalizer_rules": {
                "probes": probe_rows(),
                "instants": instant_rows(),
                "absent_option": {
                    "note": "FamilyMember.role None and Family.dissolved_at None are OMITTED (skip_serializing_if); prev_head_digest and charter_digest empty are OMITTED; a JSON null is written as null",
                    "member_role_none": serde_json::to_value(FamilyMember {
                        key_id: "k".to_owned(),
                        joined_at: at(FOUNDED_AT),
                        role: None,
                    }).unwrap(),
                },
            },
        })
    }

    /// The vector, pretty-printed, newline-terminated: the checked-in form.
    pub(crate) fn render(v: &serde_json::Value) -> String {
        let mut s = serde_json::to_string_pretty(v).unwrap();
        s.push('\n');
        s
    }
}

/// **I1783** — the checked-in vector is persist's own.
#[cfg(test)]
mod pin {
    use super::{instant_rows, persist_row_hash_preimage, probe_rows, sha256_hex, VECTOR};
    use crate::federation::types::{compute_persist_row_hash, Family};

    fn bytes_of(v: &serde_json::Value) -> Vec<u8> {
        let utf8 = v["utf8"].as_str().unwrap().as_bytes().to_vec();
        let hex = hex::decode(v["hex"].as_str().unwrap()).unwrap();
        assert_eq!(utf8, hex, "utf8 and hex name the same bytes");
        utf8
    }

    fn verify_sig(v: &serde_json::Value, sig: &serde_json::Value, bytes: &[u8]) {
        let id = sig["member_id"].as_str().unwrap();
        let key = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["key_id"] == id)
            .unwrap_or_else(|| panic!("I1783: {id} is listed"));
        crate::verify::hybrid::verify_hybrid(
            bytes,
            sig["ed25519_signature_base64"].as_str().unwrap(),
            sig["mldsa65_signature_base64"].as_str(),
            key["ed25519_public_key_base64"].as_str().unwrap(),
            key["ml_dsa_65_public_key_base64"].as_str(),
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        )
        .unwrap_or_else(|e| panic!("I1783: {id}'s signature verifies: {e}"));
    }

    #[test]
    fn i1783_the_accord_lineage_vector_is_persists() {
        let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
        let versions = v["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 3, "I1783: three versions");
        let mut prev = String::new();
        for (i, r) in versions.iter().enumerate() {
            let n = i + 1;
            let hash = r["persist_row_hash"].as_str().unwrap();
            let canonical = bytes_of(&r["canonical_bytes"]);
            assert_eq!(
                sha256_hex(&canonical),
                hash,
                "I1783 v{n}: hash of the bytes"
            );
            for form in ["offered_family", "stored_family"] {
                let f: Family = serde_json::from_value(r[form].clone()).unwrap();
                assert_eq!(
                    persist_row_hash_preimage(&f),
                    canonical,
                    "I1783 v{n}: {form}'s canonical bytes"
                );
                assert_eq!(
                    compute_persist_row_hash(&f).unwrap(),
                    hash,
                    "I1783 v{n}: {form} recomputes"
                );
                assert_eq!(
                    f.prev_head_digest, prev,
                    "I1783 v{n}: {form} links its predecessor"
                );
            }
            assert_eq!(
                r["prev_head_digest"],
                prev.as_str(),
                "I1783 v{n}: prev link"
            );
            if n > 1 {
                let env = &r["change_envelope"];
                assert_eq!(
                    env["prior_persist_row_hash"],
                    prev.as_str(),
                    "I1783 v{n}: prior"
                );
                assert_eq!(env["next_persist_row_hash"], hash, "I1783 v{n}: next");
                let sb = bytes_of(&r["signing_bytes"]);
                assert_eq!(
                    ciris_verify_core::accord_genesis::accord_family_signing_bytes(env).unwrap(),
                    sb,
                    "I1783 v{n}: signing bytes"
                );
                let signed = if n == 3 {
                    let door = bytes_of(&r["door_statement_bytes"]);
                    assert_eq!(
                        crate::verify::canonical::ceg_produce_canonicalize(env).unwrap(),
                        door,
                        "I1783 v3: the recovery door's statement bytes"
                    );
                    door
                } else {
                    sb
                };
                for sig in r["quorum_signatures"].as_array().unwrap() {
                    verify_sig(&v, sig, &signed);
                }
            }
            prev = hash.to_owned();
        }
        assert_eq!(
            v["canonicalizer_rules"]["probes"],
            serde_json::Value::Array(probe_rows()),
            "I1783: every canonicalizer probe reproduces"
        );
        assert_eq!(
            v["canonicalizer_rules"]["instants"],
            serde_json::Value::Array(instant_rows()),
            "I1783: every instant rendering reproduces"
        );
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod run_sqlite {
    /// I1783 (generator) — the doors still produce the checked-in vector.
    #[tokio::test]
    async fn i1783_the_doors_produce_the_vector() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let v = super::bodies::generate(&b).await;
        let rendered = super::bodies::render(&v);
        if let Ok(out) = std::env::var("ACCORD_LINEAGE_VECTOR_OUT") {
            std::fs::write(&out, &rendered).unwrap();
        }
        assert_eq!(
            rendered,
            super::VECTOR,
            "I1783: the doors produce the checked-in vector (regenerate: module doc)"
        );
    }
}

#[cfg(all(test, feature = "postgres"))]
mod run_postgres {
    /// I1783 (generator) on postgres — the same vector.
    #[tokio::test]
    async fn i1783_the_doors_produce_the_vector_pg() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let v = super::bodies::generate(&b).await;
        assert_eq!(
            super::bodies::render(&v),
            super::VECTOR,
            "I1783: postgres produces the checked-in vector"
        );
    }
}
