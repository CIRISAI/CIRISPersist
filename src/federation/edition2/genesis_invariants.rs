//! **I2300–I2304**: the genesis bundle/2 reader in persist, pure (no store),
//! against CIRISVerify 23.3.1's own known answers (vendored at
//! `tests/vectors/verify_v23/genesis/`, SHA-256 pinned; v62.0.0 R1 moved
//! bundles v2 to v3 and reseat v1 to v2, CC v1.0-rc21-wire e6fd7c6; CE-fix3
//! moved bundles v3 to v4 and reseat v2 to v3, Verify 23.3.3 `dial_hints`).
//!
//! - I2300: the vendored files are Verify 23.3.1's, byte for byte.
//! - I2301: every case of `genesis_bundles_v5.json` read through
//!   [`read_lineage`] gives Verify's verdict for each offered object, with a
//!   case's predecessor chain HELD (each held first bundle rooted by its own
//!   object id, as the store re-reads it) and its anchor rooting only what
//!   it offers:
//!   - Valid: the placement (object id, version, prev, accord, counted,
//!     recovered, holders, seats, halt fuse);
//!   - Invalid: `genesis_bundle_malformed` with Verify's reason;
//!   - Waiting: the rows, prev and kids it waits on;
//!   - concludes nothing: Verify's token and detail.
//!
//!   The one case not replayed is `later_prev_not_valid`: its predecessor is
//!   given only as an object id that is not Valid, and persist holds no
//!   bundle by id alone (a held predecessor is re-read from its voices).
//! - I2302: on the fork cases, the genesis in force ([`GenesisInForce`])
//!   reports Verify's forks, head, and the tips' common holders and seats.
//! - I2303: persist's tokens are Verify's.
//! - I2304: `genesis_reseat_v4.json` read the same way: a seat re-seated at a
//!   new key keeps its identity-ref and canonical standing, at the new key and
//!   its X-Wing keys; a binding not signed by the key the bundle places for
//!   the seat is `genesis_bundle_row_invalid` (`row_signer`); a binding whose
//!   `identity_key_id` / `occurrence_key_id` name the new key, not the seat,
//!   is `genesis_bundle_row_invalid` (`row_invalid`).

use std::collections::BTreeMap;

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::genesis::{CommitmentFault, CustodyFault, Inconclusive, RowFault};
use ciris_verify_core::edition2::{sig_structure, Digest32};
use ciris_verify_core::trust_anchor_store::{environments, single, Purpose, TrustAnchorStore};
use serde_json::Value as J;

use super::door_invariants::fixture::*;
use super::genesis::{
    in_force_of, read_lineage, Fork, GenesisInForce, GenesisPlacement, GenesisVerdict,
    LineageInput, LineageReading, GENESIS_BUNDLE_TYP,
};
use crate::federation::malformed_row;

/// One holder's voice over a bundle payload `{version, asserted_at, refs?}`,
/// its `iat` derived from `asserted_at`.
pub(crate) fn bundle_voice(
    k: &CompositeSigningKey,
    version: u64,
    prev: Option<&Digest32>,
    asserted_at: u64,
) -> Vec<u8> {
    let mut m = vec![
        ("version", Value::Uint(version)),
        ("asserted_at", Value::Uint(asserted_at)),
    ];
    if let Some(p) = prev {
        m.push(("refs", map(vec![("prev", ref2(p))])));
    }
    voice_over(k, &map(m), Some(asserted_at / 1000))
}

/// One voice over any payload: a `ceg-object-statement` built by hand
/// (Verify publishes the reader, not an object producer).
pub(crate) fn voice_over(k: &CompositeSigningKey, payload: &Value, iat: Option<u64>) -> Vec<u8> {
    let mut claims = vec![(Value::int(1), Value::Text(iref(k)))];
    // CE-fix4 — `sub` (CWT 2) = the payload's `family_key_id`.
    if let Some(f) = payload.get_text("family_key_id").and_then(Value::as_text) {
        claims.push((Value::int(2), Value::Text(f.into())));
    }
    if let Some(i) = iat {
        claims.push((Value::int(6), Value::Uint(i)));
    }
    claims.push((Value::int(-70003), Value::Uint(2)));
    let protected = cde::encode(&Value::Map(vec![
        (Value::int(1), Value::int(-70100)),
        (Value::int(4), Value::Bytes(kid(k).to_vec())),
        (Value::int(15), Value::Map(claims)),
        (Value::int(16), Value::Text(GENESIS_BUNDLE_TYP.into())),
    ]));
    let payload_bytes = cde::encode(payload);
    let sig = k.sign(&sig_structure(&protected, &payload_bytes)).unwrap();
    cde::encode(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload_bytes),
            Value::Bytes(sig),
        ])),
    ))
}

/// CIRISVerify 23.3.1's genesis vectors, as vendored, and the readers of
/// their case lists (shared with the store witnesses, I2310–I2318).
pub(crate) mod vectors {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;

    use ciris_verify_core::edition2::Digest32;
    use serde_json::Value as J;

    use crate::federation::edition2::genesis::Anchor;

    macro_rules! vendored {
        ($f:literal) => {
            include_str!(concat!("../../../tests/vectors/verify_v23/genesis/", $f))
        };
    }

    /// `genesis_bundles_v5.json` (the case list; VB-vectors: v4 → v5, every
    /// bundle voice states CWT `sub`; CE-fix3: v3 → v4, every seat
    /// binding gains `dial_hints`, plus the 12 `binding_dial_hint*` cases).
    /// Before that, v62.0.0 (R1): Verify
    /// 23.3.1 replays v3 (CC v1.0-rc21-wire e6fd7c6: a seat's binding is the
    /// seat's own `identity:occurrence`); v2's valid bundles no longer verify,
    /// so v2 is no longer vendored. The const keeps its name (`V2`, the
    /// bundle/2 case list) for the store witnesses that read it.
    pub(crate) const V2: &str = vendored!("genesis_bundles_v5.json");
    /// The statements of `genesis_bundles_v5.json`, split as Verify splits them.
    pub(crate) const POOL: [&str; 8] = [
        vendored!("pool_v5_0.json"),
        vendored!("pool_v5_1.json"),
        vendored!("pool_v5_2.json"),
        vendored!("pool_v5_3.json"),
        vendored!("pool_v5_4.json"),
        vendored!("pool_v5_5.json"),
        vendored!("pool_v5_6.json"),
        vendored!("pool_v5_7.json"),
    ];
    /// `genesis_reseat_v4.json` (its own pool inside; VB-vectors: v3 → v4, the
    /// voices carry `sub`; CE-fix3: v2 → v3, the bindings carry `dial_hints`).
    pub(crate) const RESEAT: &str = vendored!("genesis_reseat_v4.json");

    /// Each vendored file and its SHA-256 at CIRISVerify 23.4.0 (VB-vectors:
    /// the v5 bundles and the v4 re-seat, every bundle voice carrying CWT
    /// `sub` = `family_key_id`; vendored byte for byte from `release/23.4.0`
    /// 7943a2af, `src/ciris-verify-core/tests/vectors/edition2/genesis/`).
    /// The hashes are set by the pass-4l regen from the vendored files' bytes.
    pub(crate) fn pinned() -> [(&'static str, &'static str, &'static str); 10] {
        [
            (
                "genesis_bundles_v5.json",
                V2,
                "2741477601eee9e1a698f68b0957012a301965c2d61cd3002a2a092535017f1b",
            ),
            (
                "genesis_reseat_v4.json",
                RESEAT,
                "8ba7aeb170da90572f1054b736b54c4a242521f96bef15042a53fb9213d2b505",
            ),
            (
                "pool_v5_0.json",
                POOL[0],
                "80dcc700c9e4f9f14fcc8ee06d2923d6035d200d946dfe587e5f93b4263aee3e",
            ),
            (
                "pool_v5_1.json",
                POOL[1],
                "669630e250b2a0c36ca35ac4a7f1cc324a766bfba59e3b1f5944c0e8cc6bf57b",
            ),
            (
                "pool_v5_2.json",
                POOL[2],
                "72d1856d04085e130bfdaab81f0eba7645fe8c5986139be5c44947c6a6182821",
            ),
            (
                "pool_v5_3.json",
                POOL[3],
                "64d221c2559e68da106f41ab2a13c971ce8367ff43a8b2828b77b30eb91714ae",
            ),
            (
                "pool_v5_4.json",
                POOL[4],
                "746eb80d06d2e4cff879ee07f8424ce5a00d559523fc29d016f6a2bd3956d320",
            ),
            (
                "pool_v5_5.json",
                POOL[5],
                "23ed4c148086a18ae1c760bda1c11202b8abbc4dd11ae8a4cbb30a7c1b139d3a",
            ),
            (
                "pool_v5_6.json",
                POOL[6],
                "7615043c7c61a8a79b390ba9c4bb30463a5c0567ef79ef84ddd25f7c08ef556b",
            ),
            (
                "pool_v5_7.json",
                POOL[7],
                "2bad347e1a4556633391b98d77f77fde714a07607897fc0c5a300fb86aff8ee6",
            ),
        ]
    }

    /// `genesis_bundles_v5.json` with its pool merged in under `pool`.
    pub(crate) fn v2() -> &'static J {
        static F: OnceLock<J> = OnceLock::new();
        F.get_or_init(|| {
            let mut f: J = serde_json::from_str(V2).unwrap();
            let mut pool = serde_json::Map::new();
            for part in POOL {
                let J::Object(m) = serde_json::from_str::<J>(part).unwrap() else {
                    panic!("a pool file is a map");
                };
                pool.extend(m);
            }
            f["pool"] = J::Object(pool);
            f
        })
    }

    /// `genesis_reseat_v4.json`.
    pub(crate) fn reseat() -> &'static J {
        static F: OnceLock<J> = OnceLock::new();
        F.get_or_init(|| serde_json::from_str(RESEAT).unwrap())
    }

    pub(crate) fn hex32(s: &str) -> Digest32 {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    pub(crate) fn case<'a>(f: &'a J, id: &str) -> &'a J {
        f["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no case {id}"))
    }

    fn pool(f: &J, k: &J) -> Vec<u8> {
        hex::decode(f["pool"][k.as_str().unwrap()].as_str().unwrap()).unwrap()
    }

    /// A case's bundle statements.
    pub(crate) fn statements(f: &J, c: &J) -> Vec<Vec<u8>> {
        c["statements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| pool(f, k))
            .collect()
    }

    /// A case's rows, by row id.
    pub(crate) fn rows(f: &J, c: &J) -> BTreeMap<Digest32, Vec<u8>> {
        c["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (hex32(r["id"].as_str().unwrap()), pool(f, &r["statement"])))
            .collect()
    }

    /// A case's statements and rows in one list, as the door takes them.
    pub(crate) fn offered(f: &J, c: &J) -> Vec<Vec<u8>> {
        let mut out = statements(f, c);
        out.extend(rows(f, c).into_values());
        out
    }

    /// A case's anchor.
    pub(crate) fn anchor(c: &J) -> Option<Anchor> {
        let a = &c["anchor"];
        if a.is_null() {
            return None;
        }
        if let Some(t) = a.get("thumbprints") {
            return Some(Anchor::Thumbprints(
                t.as_array()
                    .unwrap()
                    .iter()
                    .map(|x| hex32(x.as_str().unwrap()))
                    .collect(),
            ));
        }
        Some(Anchor::ObjectId(hex32(a["object_id"].as_str().unwrap())))
    }

    /// The cases a case's `predecessors` name, transitively, ancestors first.
    pub(crate) fn ancestors<'a>(f: &'a J, c: &J) -> Vec<&'a J> {
        let mut out = Vec::new();
        for p in c["predecessors"].as_array().unwrap() {
            if let Some(id) = p.get("case").and_then(J::as_str) {
                let a = case(f, id);
                for x in ancestors(f, a) {
                    if !out.iter().any(|y: &&J| std::ptr::eq(*y, x)) {
                        out.push(x);
                    }
                }
                if !out.iter().any(|y: &&J| std::ptr::eq(*y, a)) {
                    out.push(a);
                }
            }
        }
        out
    }

    /// The file's mock attestation root (DER).
    pub(crate) fn root_der(f: &J) -> Vec<u8> {
        hex::decode(f["attestation_root_der"].as_str().unwrap()).unwrap()
    }
}

use vectors::{ancestors, anchor, case, rows, statements};

fn h(d: &Digest32) -> String {
    hex::encode(d)
}

fn sha_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(b))
}

fn strs(v: &J) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect()
}

/// The mock root alone: the replay does not lean on the process-wide test
/// roots the store witnesses register.
fn mock_roots(f: &J) -> TrustAnchorStore {
    TrustAnchorStore::new().with_store(single(
        environments::YUBIKEY_PIV,
        Purpose::KeyAttestation,
        vec![vectors::root_der(f)],
    ))
}

/// A case read through persist's lineage reader: its ancestors' statements
/// held, its own offered under its anchor, every row given.
fn read_case(f: &J, c: &J, roots: &TrustAnchorStore) -> (LineageReading, GenesisInForce) {
    let chain = ancestors(f, c);
    let held: Vec<Vec<u8>> = chain.iter().flat_map(|a| statements(f, a)).collect();
    let mut all_rows: BTreeMap<Digest32, Vec<u8>> = BTreeMap::new();
    for a in &chain {
        all_rows.extend(rows(f, a));
    }
    all_rows.extend(rows(f, c));
    let offered = statements(f, c);
    let a = anchor(c);
    let reading = read_lineage(&LineageInput {
        held: &held,
        offered: &offered,
        rows: &all_rows,
        anchor: a.as_ref(),
        attestation_roots: roots,
    });
    let in_force = in_force_of(&reading, &all_rows);
    (reading, in_force)
}

fn check_placement(id: &str, p: &GenesisPlacement, e: &J) {
    assert_eq!(h(&p.object_id), e["object_id"].as_str().unwrap(), "{id}");
    assert_eq!(u64::from(p.version), e["version"].as_u64().unwrap(), "{id}");
    assert_eq!(p.asserted_at, e["asserted_at"].as_u64().unwrap(), "{id}");
    assert_eq!(
        p.family_key_id,
        e["family_key_id"].as_str().unwrap(),
        "{id}"
    );
    assert_eq!(
        p.prev.map(|d| h(&d)),
        e["prev"].as_str().map(str::to_owned),
        "{id}: prev"
    );
    assert_eq!(p.counted, strs(&e["counted"]), "{id}: counted");
    assert_eq!(p.recovered.as_deref(), e["recovered"].as_str(), "{id}");
    if let Some(fuse) = e.get("halt_fuse").and_then(J::as_u64) {
        assert_eq!(u64::from(p.charter.halt_fuse()), fuse, "{id}: fuse");
    }
    let eh = e["holders"].as_array().unwrap();
    assert_eq!(p.holders.len(), eh.len(), "{id}: holders");
    for (x, y) in p.holders.iter().zip(eh) {
        assert_eq!(x.identity_ref, y["identity_ref"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.kid), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.record), y["record"].as_str().unwrap(), "{id}");
        assert_eq!(
            h(&x.recovery_commitment),
            y["recovery_commitment"].as_str().unwrap(),
            "{id}"
        );
    }
    let es = e["seats"].as_array().unwrap();
    assert_eq!(p.seats.len(), es.len(), "{id}: seats");
    for (x, y) in p.seats.iter().zip(es) {
        assert_eq!(x.identity_ref, y["identity_ref"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.kid), y["kid"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.record), y["record"].as_str().unwrap(), "{id}");
        assert_eq!(h(&x.binding), y["binding"].as_str().unwrap(), "{id}");
        assert_eq!(x.valid_until, y["valid_until"].as_u64().unwrap(), "{id}");
        assert_eq!(
            sha_hex(&x.transit_xwing_pubkey),
            y["transit_xwing_pubkey_sha256"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            sha_hex(&x.onion_hop_xwing_pubkey),
            y["onion_hop_xwing_pubkey_sha256"].as_str().unwrap(),
            "{id}"
        );
    }
}

/// Each object the case offers gives the case's expected verdict.
fn check_case(f: &J, c: &J, roots: &TrustAnchorStore) -> GenesisInForce {
    let id = c["id"].as_str().unwrap();
    let (reading, in_force) = read_case(f, c, roots);
    let offered: BTreeMap<String, &GenesisVerdict> = reading
        .objects
        .iter()
        .filter(|o| o.offered)
        .map(|o| (h(&o.reading.object_id), &o.reading.verdict))
        .collect();
    let expect = c["expect"].as_array().unwrap();
    assert_eq!(offered.len(), expect.len(), "{id}: objects");
    for e in expect {
        let oid = e["object_id"].as_str().unwrap();
        let got = offered
            .get(oid)
            .unwrap_or_else(|| panic!("{id}: object {oid} not read"));
        match (e["verdict"].as_str().unwrap(), got) {
            ("valid", GenesisVerdict::Valid(p)) => check_placement(id, p, &e["placement"]),
            ("invalid", GenesisVerdict::Invalid(m)) => {
                assert_eq!(e["token"], malformed_row::GENESIS_BUNDLE_MALFORMED, "{id}");
                assert_eq!(m.reason(), e["detail"].as_str().unwrap(), "{id}");
            }
            ("waiting", GenesisVerdict::Waiting(w)) => {
                let ew = &e["waiting"];
                assert_eq!(
                    w.rows.iter().map(h).collect::<Vec<_>>(),
                    strs(&ew["rows"]),
                    "{id}"
                );
                assert_eq!(
                    w.kids.iter().map(h).collect::<Vec<_>>(),
                    strs(&ew["kids"]),
                    "{id}"
                );
                assert_eq!(
                    w.prev.map(|d| h(&d)),
                    ew["prev"].as_str().map(str::to_owned),
                    "{id}: prev"
                );
            }
            ("nothing", GenesisVerdict::Nothing(i)) => {
                assert_eq!(i.token(), e["token"].as_str().unwrap(), "{id}: {i:?}");
                assert_eq!(i.detail(), e["detail"].as_str(), "{id}: {i:?}");
            }
            (want, got) => panic!("{id}: want {want}, got {got:?}"),
        }
    }
    in_force
}

/// I2300: the vendored files are Verify 23.3.1's, byte for byte.
#[test]
fn i2300_the_genesis_vectors_are_verify_23_3_1s() {
    for (name, body, sha) in vectors::pinned() {
        assert_eq!(sha_hex(body.as_bytes()), sha, "I2300: {name}");
    }
    assert!(
        vectors::v2()["cases"].as_array().unwrap().len() >= 130,
        "I2300: the case list"
    );
}

/// I2301: every case through persist's lineage reader gives Verify's
/// verdict for each object it offers.
#[test]
fn i2301_every_v2_case_reads_through_persists_lineage() {
    let f = vectors::v2();
    let roots = mock_roots(f);
    let mut skipped = Vec::new();
    let mut replayed = 0usize;
    for c in f["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        if c["predecessors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p.get("not_valid").is_some())
        {
            skipped.push(id);
            continue;
        }
        check_case(f, c, &roots);
        replayed += 1;
    }
    assert_eq!(skipped, vec!["later_prev_not_valid"], "I2301: the one skip");
    assert!(replayed >= 115, "I2301: {replayed} cases");
}

/// I2302: on the fork cases, the genesis in force reports Verify's forks,
/// head, and the tips' common holders and seats.
#[test]
fn i2302_forks_are_held_as_tips_and_only_the_common_counts() {
    let f = vectors::v2();
    let roots = mock_roots(f);
    let mut seen = 0usize;
    for c in f["cases"].as_array().unwrap() {
        let Some(fx) = c.get("forks") else {
            continue;
        };
        let id = c["id"].as_str().unwrap();
        let in_force = check_case(f, c, &roots);
        let forks: Vec<(String, Option<String>, Vec<String>)> = in_force
            .forks
            .iter()
            .map(|fk| match fk {
                Fork::Genesis { bundles } => {
                    ("genesis".into(), None, bundles.iter().map(h).collect())
                }
                Fork::Successors { prev, bundles } => (
                    "successors".into(),
                    Some(h(prev)),
                    bundles.iter().map(h).collect(),
                ),
            })
            .collect();
        let want: Vec<(String, Option<String>, Vec<String>)> = fx["forks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                (
                    x["kind"].as_str().unwrap().into(),
                    x["prev"].as_str().map(str::to_owned),
                    strs(&x["bundles"]),
                )
            })
            .collect();
        assert_eq!(forks, want, "I2302 {id}: forks");
        assert_eq!(
            in_force.head.as_ref().map(|p| h(&p.object_id)),
            fx["head"].as_str().map(str::to_owned),
            "I2302 {id}: head"
        );
        match (&in_force.common, fx["common"].as_object()) {
            (None, None) => {
                assert!(in_force.holders().is_empty(), "I2302 {id}");
                assert!(in_force.seats().is_empty(), "I2302 {id}");
            }
            (Some(t), Some(w)) => {
                assert_eq!(
                    t.tips.iter().map(h).collect::<Vec<_>>(),
                    strs(&w["tips"]),
                    "{id}"
                );
                let holders: Vec<String> = in_force
                    .holders()
                    .iter()
                    .map(|x| x.identity_ref.clone())
                    .collect();
                assert_eq!(holders, strs(&w["holders"]), "I2302 {id}: holders");
                let seats: Vec<String> = in_force
                    .seats()
                    .iter()
                    .map(|x| x.identity_ref.clone())
                    .collect();
                assert_eq!(seats, strs(&w["seats"]), "I2302 {id}: seats");
                for s in &seats {
                    assert!(in_force.is_canonical(s), "I2302 {id}: common seat");
                }
            }
            (got, want) => panic!("I2302 {id}: common {got:?}, want {want:?}"),
        }
        seen += 1;
    }
    assert!(seen >= 5, "I2302: the fork cases");
}

/// I2303: persist's tokens are Verify's.
#[test]
fn i2303_persists_genesis_tokens_are_verifys() {
    use ciris_verify_core::edition2::genesis::GENESIS_BUNDLE_MALFORMED;
    assert_eq!(
        malformed_row::GENESIS_BUNDLE_MALFORMED,
        GENESIS_BUNDLE_MALFORMED
    );
    let pairs = [
        (
            Inconclusive::NotAnchored,
            malformed_row::GENESIS_BUNDLE_NOT_ANCHORED,
        ),
        (
            Inconclusive::PrevNotValid,
            malformed_row::GENESIS_BUNDLE_PREV_NOT_VALID,
        ),
        (
            Inconclusive::RowUnplaced {
                row: None,
                party: None,
            },
            malformed_row::GENESIS_BUNDLE_ROW_UNPLACED,
        ),
        (
            Inconclusive::RowInvalid {
                row: [0; 32],
                fault: RowFault::Signer,
            },
            malformed_row::GENESIS_BUNDLE_ROW_INVALID,
        ),
        (
            Inconclusive::HolderCustody {
                holder: String::new(),
                fault: CustodyFault::NoClass,
            },
            malformed_row::GENESIS_HOLDER_CUSTODY,
        ),
        (
            Inconclusive::CountUnmet,
            malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
        ),
        (
            Inconclusive::Commitment(CommitmentFault::Spent),
            malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
        ),
    ];
    for (i, t) in pairs {
        assert_eq!(i.token(), t, "I2303: {i:?}");
        assert!(malformed_row::ALL.contains(&t), "I2303: {t} is listed");
    }
}

/// I2304: a seat re-seated at a new key keeps its identity-ref and its
/// standing, at the new key; a binding the placed key did not sign is
/// `genesis_bundle_row_invalid` (`row_signer`); one naming the new key as its
/// identity is `row_invalid` (v3, `reseat_binding_names_new_key`).
#[test]
fn i2304_a_reseated_seat_keeps_its_identity_ref_at_the_new_key() {
    let f = vectors::reseat();
    let roots = mock_roots(f);
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5, "I2304: the case list");
    for c in cases {
        check_case(f, c, &roots);
    }
    let c = case(f, "reseat_seat_new_key");
    let (_, in_force) = read_case(f, c, &roots);
    let s1 = &f["parties"]["S1"];
    let s1n = &f["parties"]["S1N"];
    assert_ne!(s1["kid"], s1n["kid"], "I2304: a new key");
    let iss = s1["iss"].as_str().unwrap();
    assert!(in_force.is_canonical(iss), "I2304: still canonical");
    let seat = in_force.seat(iss).unwrap();
    assert_eq!(
        h(&seat.kid),
        s1n["kid"].as_str().unwrap(),
        "I2304: the new key"
    );
    let xw = &f["seat_xwing"]["S1N"];
    assert_eq!(
        hex::encode(seat.transit_xwing_pubkey),
        xw["transit_xwing_pubkey"].as_str().unwrap(),
        "I2304: the new key's transit X-Wing key"
    );
    assert_eq!(
        hex::encode(seat.onion_hop_xwing_pubkey),
        xw["onion_hop_xwing_pubkey"].as_str().unwrap(),
        "I2304"
    );
}
