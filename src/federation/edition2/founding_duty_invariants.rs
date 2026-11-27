//! v62.0.0 (SEAT-1; CC 4.5.4, pre4) — **the founding duty holders**: the
//! `duty_holders` member's codec and the founding cases' pure predicate.
//! Nothing here is a door's refusal: the text names no token for these
//! cases (P/SEAT-plan.md §1c).
//!
//! - **I7160** (pure) — the payload table's type: a well-formed
//!   `duty_holders` reads; an empty map, an empty key set, an unsorted or
//!   repeated set and a key that is no identity-ref are refused
//!   `edition2_payload_invalid` (the member's type, as for every member).
//! - **I7161** (pure) — the producer writes `duty_holders` as a TOP-LEVEL
//!   member of version 1 and of no other version, and never inside
//!   `policy`; with the member removed, a founding's bytes equal the bytes
//!   of the same founding stated without it, and a later version's bytes do
//!   not move at all (byte-identical when absent).
//! - **I7162** (pure) — a founding read back (`record_of_roster`) keeps the
//!   map in `policy_blob` as sets, and re-encodes to the same bytes.
//! - **I7163** (pure) — [`founding_duty_holders`]: the lone signer holds
//!   every declared duty; several persons naming none; a declared duty
//!   unheld; an undeclared duty; a holder not listed / not a signer / a node
//!   / an agent whose owner did not sign; the member on a later version or a
//!   family's record; a named map that stands.
//! - **I7164** (sqlite + pg) — a community founded through the door with
//!   `duty_holders` lands with the member at the top level of its first
//!   version (not inside `policy`), and the held record carries it in
//!   `policy_blob`. Red before SEAT-1: the member rode inside `policy`.

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::identity_ref;

use super::founding_duty::{
    declared_duties, duty_holders_of, duty_holders_of_blob, founding_duty_holders, DutyHolders,
    FoundingDutyFault as F, FoundingFacts, HolderKind, DUTY_HOLDERS,
};
use super::group::{founding_payload, record_of_roster, roster_payload, roster_view, GroupRecord};
use super::names::RowId;
use crate::federation::group_plane::GroupKind;
use crate::federation::types::{Community, CommunityMember};

fn key(n: u8) -> String {
    identity_ref(&[n; 32])
}

fn at(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).expect("an instant")
}

fn community(blob: Option<serde_json::Value>) -> GroupRecord {
    GroupRecord::Community(Community {
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        community_key_id: String::new(),
        community_name: "I7160 co-op".into(),
        members: [1u8, 2]
            .iter()
            .map(|n| CommunityMember {
                key_id: key(*n),
                joined_at: at(1_000),
                role: None,
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: "majority".into(),
        policy_blob: blob,
        persist_row_hash: String::new(),
    })
}

fn founding(blob: Option<serde_json::Value>) -> (String, Value) {
    let mut r = community(blob);
    founding_payload(&mut r, &[7; 32], 2_000).expect("I7160: the founding payload")
}

fn group_of(record: GroupRecord, id: &str) -> GroupRecord {
    let GroupRecord::Community(mut c) = record else {
        unreachable!()
    };
    c.community_key_id = id.to_owned();
    GroupRecord::Community(c)
}

/// The payload with `name` set to `v` (replacing it) or removed (`None`).
fn with_member(p: &Value, name: &str, v: Option<Value>) -> Value {
    let Value::Map(entries) = p else {
        unreachable!()
    };
    let mut m: Vec<(Value, Value)> = entries
        .iter()
        .filter(|(k, _)| k.as_text() != Some(name))
        .cloned()
        .collect();
    if let Some(v) = v {
        m.push((Value::Text(name.to_owned()), v));
    }
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

fn set(keys: &[u8]) -> Value {
    let mut a: Vec<Value> = keys.iter().map(|n| Value::Text(key(*n))).collect();
    a.sort_by_key(cde::encode);
    Value::Array(a)
}

fn holders_value(entries: Vec<(&str, Value)>) -> Value {
    let mut m: Vec<(Value, Value)> = entries
        .into_iter()
        .map(|(k, v)| (Value::Text(k.to_owned()), v))
        .collect();
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

fn reason(e: &crate::federation::Error) -> String {
    format!("{e:?}")
}

/// **I7160 — the member's type.**
#[test]
fn i7160_the_duty_holders_type() {
    let (_, p) = founding(None);
    let ok = |v: Value, what: &str| {
        let q = with_member(&p, DUTY_HOLDERS, Some(v));
        super::payloads::check("group:roster", &q)
            .unwrap_or_else(|e| panic!("I7160 {what}: {}", reason(&e)));
    };
    let bad = |v: Value, what: &str| {
        let q = with_member(&p, DUTY_HOLDERS, Some(v));
        let Err(e) = super::payloads::check("group:roster", &q) else {
            panic!("I7160 {what}: refused")
        };
        assert!(
            reason(&e).contains("duty_holders"),
            "I7160 {what}: the refusal names the member: {}",
            reason(&e)
        );
    };
    super::payloads::check("group:roster", &p).expect("I7160 premise: the founding reads");
    ok(
        holders_value(vec![("moderate", set(&[1]))]),
        "one duty, one key",
    );
    ok(
        holders_value(vec![("moderate", set(&[1, 2])), ("review", set(&[2]))]),
        "two duties",
    );
    bad(holders_value(vec![]), "an empty map");
    bad(
        holders_value(vec![("moderate", Value::Array(vec![]))]),
        "an empty key set",
    );
    let mut unsorted = match set(&[1, 2]) {
        Value::Array(a) => a,
        _ => unreachable!(),
    };
    unsorted.reverse();
    bad(
        holders_value(vec![("moderate", Value::Array(unsorted))]),
        "an unsorted set",
    );
    bad(
        holders_value(vec![(
            "moderate",
            Value::Array(vec![Value::Text(key(1)), Value::Text(key(1))]),
        )]),
        "a repeated key",
    );
    bad(
        holders_value(vec![(
            "moderate",
            Value::Array(vec![Value::Text("alice".into())]),
        )]),
        "a key that is no identity-ref",
    );
    bad(Value::Array(vec![]), "an array, not a map");
}

/// **I7161 — version 1 only, top level only; byte-identical when absent.**
#[test]
fn i7161_the_producer_writes_it_on_the_founding_alone() {
    let holders = serde_json::json!({ "moderate": [key(2), key(1)] });
    let other = serde_json::json!({ "duties": ["curate"] });
    let mut both = other.clone();
    both[DUTY_HOLDERS] = holders.clone();

    // Version 1, a blob of `duty_holders` alone: the top-level member, and
    // no `policy` at all.
    let (_, p1) = founding(Some(serde_json::json!({ DUTY_HOLDERS: holders.clone() })));
    assert_eq!(
        p1.get_text(DUTY_HOLDERS),
        Some(&holders_value(vec![("moderate", set(&[1, 2]))])),
        "I7161: the founding states the map at the top level, as sets"
    );
    assert!(
        p1.get_text("policy").is_none(),
        "I7161: a blob of duty_holders alone writes no policy"
    );
    let (_, p0) = founding(None);
    assert_eq!(
        cde::encode(&with_member(&p1, DUTY_HOLDERS, None)),
        cde::encode(&p0),
        "I7161: without the member, the founding's bytes are the bytes of the founding stated without it"
    );

    // Version 1 with another policy member: the policy is the rest.
    let (_, pb) = founding(Some(both.clone()));
    let (_, po) = founding(Some(other.clone()));
    assert!(pb.get_text(DUTY_HOLDERS).is_some(), "I7161: top level");
    assert_eq!(
        pb.get_text("policy"),
        po.get_text("policy"),
        "I7161: never inside policy"
    );
    assert_eq!(
        cde::encode(&with_member(&pb, DUTY_HOLDERS, None)),
        cde::encode(&po),
        "I7161: the rest of the founding is unchanged"
    );

    // A later version: never the member, and the bytes do not move.
    let (gid, _) = founding(Some(both.clone()));
    let head = RowId([9; 32]);
    let v2_with = roster_payload(
        &group_of(community(Some(both)), &gid),
        2,
        Some(&head),
        3_000,
    )
    .unwrap();
    let v2_without = roster_payload(
        &group_of(community(Some(other)), &gid),
        2,
        Some(&head),
        3_000,
    )
    .unwrap();
    assert!(
        v2_with.get_text(DUTY_HOLDERS).is_none(),
        "I7161: no version after the first carries it"
    );
    assert_eq!(
        cde::encode(&v2_with),
        cde::encode(&v2_without),
        "I7161: a later version's bytes are those of the record without it"
    );

    // An empty blob stays exactly as it was written before SEAT-1.
    let (_, pe) = founding(Some(serde_json::json!({})));
    assert_eq!(
        pe.get_text("policy"),
        Some(&Value::Map(vec![])),
        "I7161: an empty policy blob is written as before"
    );
}

/// **I7162 — the founding read back.**
#[test]
fn i7162_a_founding_reads_back_to_the_same_bytes() {
    let (gid, p) = founding(Some(serde_json::json!({
        DUTY_HOLDERS: { "moderate": [key(2), key(1)], "review": [key(1)] },
        "membership": "public",
    })));
    let view = roster_view(&gid, &p).expect("I7162: the founding reads as a roster");
    let record = record_of_roster(&view, String::new()).expect("I7162: the typed record");
    let GroupRecord::Community(c) = &record else {
        panic!("I7162: a community")
    };
    let want: DutyHolders = BTreeMap::from([
        ("moderate".to_owned(), BTreeSet::from([key(1), key(2)])),
        ("review".to_owned(), BTreeSet::from([key(1)])),
    ]);
    assert_eq!(
        duty_holders_of_blob(c.policy_blob.as_ref()),
        Some(want.clone()),
        "I7162: the typed record keeps the map in policy_blob"
    );
    assert_eq!(duty_holders_of(&p), Some(want), "I7162: the wire's map");
    let again = roster_payload(&record, 1, None, 2_000).expect("I7162: re-encoded");
    // `nonce` is the founding verb's own member, beside the record.
    assert_eq!(
        cde::encode(&again),
        cde::encode(&with_member(&p, "nonce", None)),
        "I7162: the record re-encodes to the founding's bytes"
    );
}

struct World {
    declared: BTreeSet<String>,
    listed: BTreeSet<String>,
    signers: BTreeSet<String>,
    kinds: BTreeMap<String, HolderKind>,
    owners: BTreeMap<String, String>,
}

impl World {
    fn new(listed: &[u8], signers: &[u8]) -> Self {
        Self {
            declared: declared_duties(None),
            listed: listed.iter().map(|n| key(*n)).collect(),
            signers: signers.iter().map(|n| key(*n)).collect(),
            kinds: BTreeMap::new(),
            owners: BTreeMap::new(),
        }
    }

    fn judge(
        &self,
        kind: GroupKind,
        version: u64,
        stated: Option<&DutyHolders>,
    ) -> Result<DutyHolders, F> {
        let kind_of = |k: &str| self.kinds.get(k).copied().unwrap_or(HolderKind::Person);
        let owner_of = |k: &str| self.owners.get(k).cloned();
        founding_duty_holders(&FoundingFacts {
            group_kind: kind,
            version,
            declared: &self.declared,
            listed: &self.listed,
            signers: &self.signers,
            stated,
            kind_of: &kind_of,
            owner_of: &owner_of,
        })
    }
}

fn holders(entries: &[(&str, &[u8])]) -> DutyHolders {
    entries
        .iter()
        .map(|(d, ks)| ((*d).to_owned(), ks.iter().map(|n| key(*n)).collect()))
        .collect()
}

/// **I7163 — the founding cases.**
#[test]
fn i7163_the_founding_cases() {
    use GroupKind::{Community as C, Family};
    let moderate = |ks: &[u8]| holders(&[("moderate", ks)]);

    // One person signs and names none: that person holds every declared
    // duty (moderate, and what policy.duties declares).
    let mut w = World::new(&[1, 2], &[1]);
    w.declared = declared_duties(Some(&serde_json::json!({ "duties": ["curate"] })));
    assert_eq!(
        w.judge(C, 1, None),
        Ok(holders(&[("curate", &[1][..]), ("moderate", &[1][..])])),
        "I7163: the lone signer holds every declared duty"
    );
    // Several persons sign and name none: refused.
    let w = World::new(&[1, 2], &[1, 2]);
    assert_eq!(w.judge(C, 1, None), Err(F::NoneNamedBySeveral), "I7163");
    // No person signs: seats none.
    let mut w = World::new(&[1], &[1]);
    w.kinds.insert(key(1), HolderKind::Node);
    assert_eq!(w.judge(C, 1, None), Err(F::NoPersonSigned), "I7163");

    // A named map that stands.
    let w = World::new(&[1, 2, 3], &[1, 2]);
    assert_eq!(
        w.judge(C, 1, Some(&moderate(&[2]))),
        Ok(moderate(&[2])),
        "I7163: a listed signer named for moderate holds it"
    );
    // A declared duty unheld.
    let mut w2 = World::new(&[1, 2], &[1, 2]);
    w2.declared = declared_duties(Some(&serde_json::json!({ "duties": ["curate"] })));
    assert_eq!(
        w2.judge(C, 1, Some(&moderate(&[1]))),
        Err(F::DutyUnheld("curate".into())),
        "I7163"
    );
    assert_eq!(
        w.judge(C, 1, Some(&holders(&[("curate", &[1][..])]))),
        Err(F::DutyUndeclared("curate".into())),
        "I7163: a duty the record does not declare"
    );
    assert_eq!(
        w.judge(C, 1, Some(&holders(&[("moderate", &[][..])]))),
        Err(F::DutyUnheld("moderate".into())),
        "I7163: an empty set holds nothing"
    );
    assert_eq!(
        w.judge(C, 1, Some(&moderate(&[4]))),
        Err(F::HolderNotListed {
            duty: "moderate".into(),
            key: key(4)
        }),
        "I7163"
    );
    assert_eq!(
        w.judge(C, 1, Some(&moderate(&[3]))),
        Err(F::HolderNotSigner {
            duty: "moderate".into(),
            key: key(3)
        }),
        "I7163: a listed member who did not sign"
    );
    let mut wn = World::new(&[1, 2], &[1, 2]);
    wn.kinds.insert(key(2), HolderKind::Node);
    assert_eq!(
        wn.judge(C, 1, Some(&moderate(&[2]))),
        Err(F::HolderNode {
            duty: "moderate".into(),
            key: key(2)
        }),
        "I7163"
    );
    // An agent: only where its owner signed.
    let mut wa = World::new(&[1, 2, 3], &[1, 2]);
    wa.kinds.insert(key(2), HolderKind::Agent);
    wa.owners.insert(key(2), key(3));
    assert_eq!(
        wa.judge(C, 1, Some(&moderate(&[2]))),
        Err(F::AgentOwnerUnsigned {
            duty: "moderate".into(),
            key: key(2)
        }),
        "I7163: the agent's owner did not sign"
    );
    wa.owners.insert(key(2), key(1));
    assert_eq!(
        wa.judge(C, 1, Some(&moderate(&[2]))),
        Ok(moderate(&[2])),
        "I7163: the agent's owner signed"
    );

    // Placement: a later version and a family's record.
    assert_eq!(
        w.judge(C, 2, Some(&moderate(&[1]))),
        Err(F::NotOnFirstVersion),
        "I7163"
    );
    assert_eq!(
        w.judge(Family, 1, Some(&moderate(&[1]))),
        Err(F::OnFamily),
        "I7163"
    );
    assert_eq!(
        w.judge(C, 2, None),
        Ok(DutyHolders::new()),
        "I7163: a later version seats no founding holder"
    );
    assert_eq!(
        w.judge(Family, 1, None),
        Ok(DutyHolders::new()),
        "I7163: a family seats none"
    );
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::founding_duty::DUTY_HOLDERS;
    use crate::federation::membership_acceptance_invariants::bodies::{found_room_with_blob, reg};
    use crate::federation::FederationDirectory;

    /// **I7164 — the founding through the door.**
    pub async fn i7164_a_founding_states_its_duty_holders(d: &dyn FederationDirectory, tag: &str) {
        let k = |n: &str| format!("i7164-{n}-{tag}");
        let (cid, alice, bob) = (k("room"), k("alice"), k("bob"));
        reg(d, &[&cid, &alice, &bob]).await;
        let room = found_room_with_blob(
            d,
            &cid,
            "majority",
            &[&alice, &bob],
            &[],
            Some(serde_json::json!({
                DUTY_HOLDERS: { "moderate": [alice.clone()] },
                "duties": ["curate"],
            })),
        )
        .await
        .expect("I7164: the founding lands");
        let heads = crate::federation::edition2::lineage::heads(d, &room)
            .await
            .unwrap();
        let [v1] = heads.as_slice() else {
            panic!("{tag} I7164: one head: {heads:?}")
        };
        let voices = d.edition2_voices(v1).await.unwrap();
        let view = crate::federation::edition2::group::roster_view_of_statement(
            voices.first().expect("I7164: a voice is held"),
        )
        .unwrap();
        let want = serde_json::json!({ "moderate": [e2::kid(&alice)] });
        let top = view
            .payload
            .get_text(DUTY_HOLDERS)
            .map(crate::federation::edition2::ingest::json_of);
        assert_eq!(
            top,
            Some(want.clone()),
            "{tag} I7164: the first version states duty_holders at the top level"
        );
        assert!(
            view.payload
                .get_text("policy")
                .and_then(|p| p.get_text(DUTY_HOLDERS))
                .is_none(),
            "{tag} I7164: never inside policy"
        );
        let held = d
            .lookup_community(&room)
            .await
            .unwrap()
            .expect("I7164: the record is held");
        let blob = held.policy_blob.expect("I7164: a policy blob");
        assert_eq!(
            blob.get(DUTY_HOLDERS),
            Some(&want),
            "{tag} I7164: the held record keeps the map in policy_blob"
        );
        assert_eq!(
            blob.get("duties"),
            Some(&serde_json::json!(["curate"])),
            "{tag} I7164: the rest of the policy is kept"
        );
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i7164_a_founding_states_its_duty_holders() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i7164_a_founding_states_its_duty_holders(
                        &d as &dyn FederationDirectory,
                        &format!("i7164-{}", super::suffix()),
                    )
                    .await
                }
            }
        };
    }

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
