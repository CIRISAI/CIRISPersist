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
//!
//! **v2** (v62.0.0, CIRISPersist#1274; I1877): `accord_lineage_v2.json` extends
//! v1 with **v4**, a charter version whose charter re-lists the commitment
//! v3's recovery spent, plus the charter rows (as stored) and the commitments
//! in force at the head (CC rc20 4.2.6). v1 stays pinned. Regenerate with
//! `ACCORD_LINEAGE_VECTOR_V2_OUT=<path>`.

/// The checked-in vector.
const VECTOR: &str = include_str!("../../tests/vectors/accord_lineage/accord_lineage_v1.json");
/// v62.0.0 (CIRISPersist#1274) — the checked-in v2 vector: v1's versions plus
/// a charter version re-listing a spent commitment, the charter rows, and the
/// commitments in force. v1 stays pinned beside it.
const VECTOR_V2: &str = include_str!("../../tests/vectors/accord_lineage/accord_lineage_v2.json");

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
        charter_row_with(
            test_accord_recovery_commitments(roster),
            signers,
            id,
            asserted_at,
        )
    }

    /// [`charter_row`] with its `recovery_commitments` given (v2's v4 charter
    /// re-lists a spent commitment).
    fn charter_row_with(
        commitments: serde_json::Value,
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
            "recovery_commitments": commitments,
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

    /// v4's charter id and instant (v2 vector).
    const CHARTER_V4_ID: &str = "vec-accord-charter-v4";
    const CHARTER_V4_AT: &str = "2026-07-01T00:00:00Z";
    const DECISION4_CLOSES: &str = "2026-08-01T00:00:00Z";

    /// **Build the v2 vector** (CIRISPersist#1274, asked by CIRISVerify for
    /// `accord_live_quorum::recovery_commitment_in_force_with_charters`): the
    /// v1 vector's three versions, then **v4**, a charter version naming a new
    /// charter that RE-LISTS the commitment v3's recovery spent (as
    /// `vec-holder-a2`'s entry). Beside the versions it carries the charter
    /// rows the lineage adopts, as stored (each identified by its own
    /// `persist_row_hash`), and what persist reads from them: the commitment
    /// in force for every seat at the head and the spent commitments. CC rc20
    /// 4.2.6: "A spent commitment never returns: a row that names it again is
    /// read as naming none for that holder."
    pub(crate) async fn generate_v2(d: &dyn FederationDirectory) -> serde_json::Value {
        let mut v = generate(d).await;
        let accord = accord_family_key_id();
        let spent =
            recovery_commitment(&test_committed_key(&format!("{}-recovery", HOLDERS[0]))).unwrap();
        let a2_next =
            recovery_commitment(&test_committed_key(&format!("{RECOVERED}-recovery"))).unwrap();
        // v4 — a charter version: it names a new charter that RE-LISTS the
        // spent commitment as vec-holder-a2's entry. It also retires ADDED
        // through the accord's roster door (the accord's charter-adopting
        // version is a roster version; the charter commits the roster it
        // leaves: a2, b, c).
        let roster4 = [RECOVERED, HOLDERS[1], HOLDERS[2]];
        let mut entries = test_accord_recovery_commitments(&roster4[1..]);
        entries[RECOVERED] = json!(spent);
        let signers4 = [RECOVERED, HOLDERS[1], HOLDERS[2]];
        let c4 = put_charter(
            d,
            charter_row_with(entries, &signers4, CHARTER_V4_ID, CHARTER_V4_AT),
        )
        .await;
        let s3 = held(d).await;
        let change4 = SeatChange {
            remove: vec![ADDED.to_owned()],
            add: vec![],
        };
        let decision4 = decide(
            d,
            &change4,
            at(DECISION4_CLOSES),
            true,
            "vec-accord-lineage-v4",
        )
        .await;
        let v4 = version_shaped(d, &change4, &decision4, &c4, &signers4, RECOVERED, |_| {}).await;
        let proof4 = v4.supersede_proof.clone().unwrap();
        let offered4 = v4.family.clone();
        apply(d, v4)
            .await
            .unwrap_or_else(|e| panic!("v4: the charter version is admitted: {e}"));
        let s4 = held(d).await;
        assert_eq!(s4.prev_head_digest, s3.persist_row_hash, "v4 links v3");
        assert_eq!(s4.charter_digest, c4, "v4 names the new charter");
        let env4 = proof4.change_envelope.clone();
        let sb4 = ciris_verify_core::accord_genesis::accord_family_signing_bytes(&env4).unwrap();
        let mut r4 = record_block(&offered4, &s4);
        r4["kind"] = json!("charter_version");
        r4["admitted_by"] = json!(
            "accord_roster::verify_accord_roster_change via group_amendment::supersede_family_signed"
        );
        r4["charter_digest"] = json!(c4);
        r4["change_envelope"] = env4;
        r4["signing_bytes_fn"] =
            json!("ciris_verify_core::accord_genesis::accord_family_signing_bytes");
        r4["signing_bytes"] = bytes_json(&sb4);
        r4["quorum_signatures"] = serde_json::to_value(&proof4.quorum_signatures).unwrap();
        r4["decision"] = json!({
            "digest": decision4,
            "window_until": at(DECISION4_CLOSES).to_rfc3339(),
            "nonce": "vec-accord-lineage-v4",
            "seat_change_digest":
                crate::federation::accord_roster::seat_change_digest(accord, &change4).unwrap(),
        });
        // The charter rows, as stored.
        let mut charters = Vec::new();
        for id in [
            "vec-accord-charter-v1",
            "vec-accord-charter-v2",
            CHARTER_V4_ID,
        ] {
            let row = d
                .get_attestation(id)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{id} is held"));
            charters.push(serde_json::to_value(&row).unwrap());
        }
        // What persist reads at the head.
        let mut in_force = serde_json::Map::new();
        for m in &s4.members {
            let c = crate::federation::accord_recovery::recovery_commitment_in_force(
                d, accord, &m.key_id,
            )
            .await
            .unwrap();
            in_force.insert(m.key_id.clone(), json!(c));
        }
        assert_eq!(
            in_force[RECOVERED],
            json!(a2_next),
            "v2: the re-listed spent commitment names none; v3's next stands"
        );
        v["vector"] = json!("ciris.accord_lineage.v2");
        v["produced_by"] =
            json!("CIRISPersist (src/federation/accord_lineage_vector.rs, from v62.0.0)");
        v["versions"].as_array_mut().unwrap().push(r4);
        v["keys"] = holder_keys(&[
            HOLDERS[0],
            HOLDERS[1],
            HOLDERS[2],
            ADDED,
            RECOVERED,
            RECOVERY_KEY,
        ]);
        v["charters"] = json!(charters);
        v["charters_note"] = json!(
            "each charter row is the stored Attestation; it is named by its own persist_row_hash \
             (recompute it), which is the charter_digest a version adopts; recovery_commitments \
             is attestation_envelope.recovery_commitments"
        );
        v["expected"] = json!({
            "rule": "CC 4.2.6 (rc20): the commitment in force for a holder is the one named by the latest row of the lineage (by prev_head_digest links) that names one for that holder: a recovery version (next_recovery_commitment for new_holder_key_id) or a charter version (the genesis version, or one whose charter_digest differs from its predecessor's: every recovery_commitments entry); a recovery spends the commitment then in force for old_holder_key_id; a spent commitment named again names none",
            "in_force_at_head": in_force,
            "spent": [spent],
        });
        v
    }

    /// The statement + offered version + signed family a recovery of the
    /// head's seat `old` onto `new` would carry, built by hand so a refusal
    /// the drafter would catch earlier reaches the verifier.
    fn recovery_by_hand(
        held: &Family,
        old: &str,
        new: &str,
        recovery_key: &str,
        next_commitment: &str,
    ) -> crate::federation::types::SignedFamily {
        use crate::federation::accord_recovery::{
            recovery_version, AccordRecoveryDraft, RECOVERY_STATEMENT_KIND,
        };
        let mut next = held.clone();
        next.persist_row_hash = String::new();
        next.prev_head_digest = held.persist_row_hash.clone();
        for m in &mut next.members {
            if m.key_id == old {
                m.key_id = new.to_owned();
            }
        }
        let statement = json!({
            "kind": RECOVERY_STATEMENT_KIND,
            "family_key_id": held.family_key_id,
            "prior_persist_row_hash": held.persist_row_hash,
            "next_persist_row_hash": crate::federation::types::compute_persist_row_hash(&next).unwrap(),
            "old_holder_key_id": old,
            "new_holder_key_id": new,
            "recovery_key_id": recovery_key,
            "next_recovery_commitment": next_commitment,
        });
        let statement_bytes =
            crate::verify::canonical::ceg_produce_canonicalize(&statement).unwrap();
        let record_bytes =
            crate::verify::canonical::ceg_produce_canonicalize(&next.signing_envelope()).unwrap();
        let rsig = ts::threshold_sign(recovery_key, &statement_bytes);
        let draft = AccordRecoveryDraft {
            next,
            statement,
            statement_bytes,
            record_bytes,
        };
        recovery_version(
            &held.persist_row_hash,
            &draft,
            (
                rsig.ed25519_signature_base64.clone(),
                rsig.mldsa65_signature_base64.clone().unwrap(),
            ),
            ("c2ln".to_owned(), "c2ln".to_owned()),
        )
    }

    async fn refused_with(
        d: &dyn FederationDirectory,
        sf: &crate::federation::types::SignedFamily,
        token: &str,
        what: &str,
    ) {
        match crate::federation::accord_recovery::verify_accord_recovery(d, sf).await {
            Err(crate::federation::Error::CharterInvalid { detail })
                if detail.starts_with(token) => {}
            other => panic!("I1886 {what}: expected {token}, got {other:?}"),
        }
    }

    /// **I1886** (CC rc20 4.2.6) — the recovery sentences at the door, over
    /// the v2 vector's state (v4 head: a2, b, c; a2's commitment in force is
    /// the one v3 named, its key `vec-holder-a2-recovery`; v4's charter
    /// re-lists the commitment v3 spent).
    ///
    /// - "A recovery that names as the new signing key either the holder's
    ///   current signing key or the recovery key itself concludes nothing":
    ///   `accord_recovery_reuses_signing_key`, `accord_recovery_key_as_signing_key`;
    /// - "never becomes a seat's signing key, under any id; the test is the
    ///   public key material, not the id": a new key carrying the recovery
    ///   key's material under another id is `accord_recovery_key_as_signing_key`;
    /// - "A spent commitment never returns": a next commitment equal to a spent
    ///   one is `accord_recovery_next_commitment_not_fresh`; the spent
    ///   commitment v4 re-lists is not in force (a recovery under its key is
    ///   `accord_recovery_key_mismatch`);
    /// - the control: a well-formed recovery verifies.
    pub(crate) async fn i1886_recovery_refusals(d: &dyn FederationDirectory) -> Family {
        let accord = accord_family_key_id();
        let _ = generate_v2(d).await;
        let held = held(d).await;
        let rk = format!("{RECOVERED}-recovery");
        ts::register_hybrid_key_as(d, &rk, &rk, identity_type::NODE).await;
        let fresh_next =
            recovery_commitment(&test_committed_key("vec-holder-a3-recovery")).unwrap();
        let spent = recovery_commitment(&test_committed_key(RECOVERY_KEY)).unwrap();
        assert_eq!(
            crate::federation::accord_recovery::recovery_commitment_in_force(d, accord, RECOVERED)
                .await
                .unwrap(),
            Some(recovery_commitment(&test_committed_key(&rk)).unwrap()),
            "I1886: a2's commitment in force is v3's, not the spent one v4 re-lists"
        );
        // 2a — the holder's current key.
        refused_with(
            d,
            &recovery_by_hand(&held, RECOVERED, RECOVERED, &rk, &fresh_next),
            crate::federation::accord_recovery::ACCORD_RECOVERY_REUSES_SIGNING_KEY,
            "the current key",
        )
        .await;
        // 2b — the recovery key itself, by id.
        refused_with(
            d,
            &recovery_by_hand(&held, RECOVERED, &rk, &rk, &fresh_next),
            crate::federation::accord_recovery::ACCORD_RECOVERY_KEY_AS_SIGNING_KEY,
            "the recovery key by id",
        )
        .await;
        // A fresh holder key for the remaining legs.
        let fresh = "vec-holder-a3";
        ops::register_accord_holder_as(d, &ops::Identity::new(fresh), identity_type::ACCORD_HOLDER)
            .await
            .unwrap();
        // A spent commitment as the next one.
        refused_with(
            d,
            &recovery_by_hand(&held, RECOVERED, fresh, &rk, &spent),
            "accord_recovery_next_commitment_not_fresh",
            "a spent commitment as the next one",
        )
        .await;
        // The spent commitment v4 re-lists is not in force: its key does not
        // recover a2.
        refused_with(
            d,
            &recovery_by_hand(&held, RECOVERED, fresh, RECOVERY_KEY, &fresh_next),
            "accord_recovery_key_mismatch",
            "the re-listed spent commitment's key",
        )
        .await;
        // The control.
        assert_eq!(
            crate::federation::accord_recovery::verify_accord_recovery(
                d,
                &recovery_by_hand(&held, RECOVERED, fresh, &rk, &fresh_next),
            )
            .await
            .unwrap(),
            Some(fresh.to_owned()),
            "I1886: a well-formed recovery verifies"
        );
        held
    }

    /// I1886 (part 2) — after the runner seeded `twin`, an `accord_holder`
    /// record carrying the RECOVERY key's public key material under another
    /// id: refused by material.
    pub(crate) async fn i1886_by_material(d: &dyn FederationDirectory, held: &Family, twin: &str) {
        let rk = format!("{RECOVERED}-recovery");
        let fresh_next =
            recovery_commitment(&test_committed_key("vec-holder-a3-recovery")).unwrap();
        refused_with(
            d,
            &recovery_by_hand(held, RECOVERED, twin, &rk, &fresh_next),
            crate::federation::accord_recovery::ACCORD_RECOVERY_KEY_AS_SIGNING_KEY,
            "the recovery key's material under another id",
        )
        .await;
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

/// **I1877** — the checked-in v2 vector is persist's own, and its commitments
/// in force follow from its own rows by the CC 4.2.6 walk (re-derived here
/// from the vector alone, as CIRISVerify reads it).
#[cfg(test)]
mod pin_v2 {
    use super::VECTOR_V2;
    use crate::federation::types::{compute_persist_row_hash, Attestation, Family};

    #[test]
    fn i1877_the_v2_vector_walks_to_its_commitments() {
        let v: serde_json::Value = serde_json::from_str(VECTOR_V2).unwrap();
        let v1: serde_json::Value = serde_json::from_str(super::VECTOR).unwrap();
        let versions = v["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 4, "I1877: four versions");
        assert_eq!(
            &versions[..3],
            v1["versions"].as_array().unwrap().as_slice(),
            "I1877: v2 extends v1 (its three versions are v1's, byte for byte)"
        );
        // Charter rows by their own recomputed persist_row_hash.
        let mut charters = std::collections::BTreeMap::new();
        for c in v["charters"].as_array().unwrap() {
            let row: Attestation = serde_json::from_value(c.clone()).unwrap();
            let h = compute_persist_row_hash(&row).unwrap();
            assert_eq!(h, row.persist_row_hash, "I1877: a charter recomputes");
            charters.insert(h, row);
        }
        // The walk, from the vector alone.
        let mut named: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        let mut spent: std::collections::BTreeSet<String> = Default::default();
        let in_force = |named: &std::collections::BTreeMap<String, Vec<String>>,
                        spent: &std::collections::BTreeSet<String>,
                        k: &str| {
            named
                .get(k)
                .and_then(|cs| cs.iter().rev().find(|c| !spent.contains(*c)).cloned())
        };
        let mut prev_hash = String::new();
        let mut prev_charter = String::new();
        for (i, r) in versions.iter().enumerate() {
            let f: Family = serde_json::from_value(r["stored_family"].clone()).unwrap();
            assert_eq!(f.prev_head_digest, prev_hash, "I1877 v{}: the link", i + 1);
            if let Some(st) = r.get("change_envelope").filter(|e| {
                e["kind"] == crate::federation::accord_recovery::RECOVERY_STATEMENT_KIND
            }) {
                let old = st["old_holder_key_id"].as_str().unwrap();
                if let Some(c) = in_force(&named, &spent, old) {
                    spent.insert(c);
                }
                named
                    .entry(st["new_holder_key_id"].as_str().unwrap().to_owned())
                    .or_default()
                    .push(st["next_recovery_commitment"].as_str().unwrap().to_owned());
            }
            if (i == 0 || f.charter_digest != prev_charter) && !f.charter_digest.is_empty() {
                let row = charters
                    .get(&f.charter_digest)
                    .unwrap_or_else(|| panic!("I1877 v{}: the adopted charter is listed", i + 1));
                for (k, c) in row.attestation_envelope["recovery_commitments"]
                    .as_object()
                    .unwrap()
                {
                    named
                        .entry(k.clone())
                        .or_default()
                        .push(c.as_str().unwrap().to_owned());
                }
            }
            prev_hash = compute_persist_row_hash(&f).unwrap();
            prev_charter = f.charter_digest.clone();
        }
        let expected = v["expected"]["in_force_at_head"].as_object().unwrap();
        let head: Family = serde_json::from_value(versions[3]["stored_family"].clone()).unwrap();
        assert_eq!(expected.len(), head.members.len());
        for m in &head.members {
            assert_eq!(
                expected[&m.key_id],
                serde_json::json!(in_force(&named, &spent, &m.key_id)),
                "I1877: {}'s commitment in force",
                m.key_id
            );
        }
        let want_spent: Vec<String> = v["expected"]["spent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            spent.into_iter().collect::<Vec<_>>(),
            want_spent,
            "I1877: spent"
        );
        // The case the vector exists for: v4 re-lists the spent commitment as
        // vec-holder-a2's entry, and it names none.
        let relisted = charters[versions[3]["charter_digest"].as_str().unwrap()]
            .attestation_envelope["recovery_commitments"]["vec-holder-a2"]
            .clone();
        assert_eq!(relisted, v["expected"]["spent"][0], "I1877: v4 re-lists it");
        assert_ne!(
            expected["vec-holder-a2"], relisted,
            "I1877: and it names none"
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

    /// I1877 (generator) — the doors produce the checked-in v2 vector.
    #[tokio::test]
    async fn i1877_the_doors_produce_the_v2_vector() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let v = super::bodies::generate_v2(&b).await;
        let rendered = super::bodies::render(&v);
        if let Ok(out) = std::env::var("ACCORD_LINEAGE_VECTOR_V2_OUT") {
            std::fs::write(&out, &rendered).unwrap();
        }
        assert_eq!(
            rendered,
            super::VECTOR_V2,
            "I1877: the doors produce the checked-in v2 vector (regenerate: module doc)"
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

    /// I1877 (generator) on postgres — the same v2 vector.
    #[tokio::test]
    async fn i1877_the_doors_produce_the_v2_vector_pg() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let v = super::bodies::generate_v2(&b).await;
        assert_eq!(
            super::bodies::render(&v),
            super::VECTOR_V2,
            "I1877: postgres produces the checked-in v2 vector"
        );
    }
}

/// I1886 on both backends.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run_1886 {
    fn twin_record(twin: &str) -> crate::federation::SignedKeyRecord {
        use crate::federation::tier_ingest::test_support as ts;
        let rk = "vec-holder-a2-recovery";
        let mut r = ts::replicated_key_record(twin, "accord_holder", twin, twin, "n1");
        let (ed, mldsa) = ts::hybrid_pubkeys(rk);
        r.pubkey_ed25519_base64 = ed;
        r.pubkey_ml_dsa_65_base64 = mldsa;
        r.attestation_evidence = Some(
            crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(),
        );
        crate::federation::SignedKeyRecord { record: r }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1886_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let held = super::bodies::i1886_recovery_refusals(&b).await;
        let twin = "vec-twin-of-a2-recovery";
        b.seed_genesis_accord_holders(&[twin_record(twin)])
            .await
            .expect("seed the twin");
        super::bodies::i1886_by_material(&b, &held, twin).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1886_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let held = super::bodies::i1886_recovery_refusals(&b).await;
        let twin = "vec-twin-of-a2-recovery";
        b.seed_genesis_accord_holders(&[twin_record(twin)])
            .await
            .expect("seed the twin");
        super::bodies::i1886_by_material(&b, &held, twin).await;
    }
}
