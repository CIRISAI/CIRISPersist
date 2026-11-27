//! v62.0.0 (BIND-1; CC rc22 462260c rule `owner-binding`, Eric's
//! confirmation of `on_behalf_of`) — **I6620–I6626: placement is who may hold
//! the row; `on_behalf_of` is what counts an organisation.**
//!
//! Every leg runs for a NODE's binding and an AGENT's, through the real
//! statement door (the owner's statement and K's voice,
//! [`land_owner_binding`](super::fixture_switch::land_owner_binding); then
//! any affiliation member's voice), the verdict read by
//! [`row_state`](super::verdict::row_state).
//!
//! - **I6620** — placed at an ordinary room the owner is a member of
//!   (`cohort_scope: community`, `community_id`): lands on two voices.
//! - **I6621** — placed at a family the owner is a member of
//!   (`cohort_scope: family`, `family_id`): lands on two voices.
//! - **I6622** — placed at an AFFILIATION, no `on_behalf_of`: lands on two
//!   voices, no count.
//! - **I6623** — `on_behalf_of` an affiliation this node does not hold: held.
//! - **I6624** — `on_behalf_of` a held affiliation, the owner's and K's
//!   voices only: held `count_short`.
//! - **I6625** — with the affiliation's count at the roster head it names:
//!   lands.
//! - **I6626** — `on_behalf_of` a room that is no affiliation: held
//!   `owner_binding_not_an_affiliation`, concluding nothing.

use chrono::{TimeZone, Utc};

use super::fixture_switch as e2;
use super::fold::reason;
use super::group::GroupRecord;
use super::group_fixtures::{fixture_group_id, put_voices, roster_voices};
use super::names::RowId;
use super::verdict::{row_state, RowState};
use crate::federation::types::{
    cohort_scope as cs, identity_type, Attestation, Community, CommunityMember, Family,
    FamilyMember,
};
use crate::federation::FederationDirectory;

/// A group: its derived id and the row id of its founding roster version
/// (the head a binding on its behalf names).
struct Group {
    gid: String,
    head: RowId,
}

fn epoch(ms: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().expect("an instant")
}

/// A room of `members` (the first its founder) at `majority`; an
/// affiliation (`cohort_scope: affiliations`) when `affiliation`. Founded
/// through the door when `put`; else only its id and head are computed.
async fn room(
    d: &dyn FederationDirectory,
    alias: &str,
    members: &[&str],
    affiliation: bool,
    put: bool,
) -> Group {
    let rec = GroupRecord::Community(Community {
        community_key_id: e2::kid(alias),
        community_name: format!("{alias} room"),
        members: members
            .iter()
            .enumerate()
            .map(|(i, s)| CommunityMember {
                key_id: e2::kid(s),
                joined_at: epoch(1_000),
                role: (i == 0).then(|| "founder".to_owned()),
            })
            .collect(),
        founded_at: epoch(1_000),
        consensus_protocol: "majority".into(),
        policy_blob: affiliation.then(|| serde_json::json!({ "cohort_scope": "affiliations" })),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    found(d, &rec, members, put).await
}

/// A family of `members` (the first its founder) at `majority`.
async fn family(d: &dyn FederationDirectory, alias: &str, members: &[&str]) -> Group {
    let rec = GroupRecord::Family(Family {
        family_key_id: e2::kid(alias),
        family_name: format!("{alias} family"),
        members: members
            .iter()
            .enumerate()
            .map(|(i, s)| FamilyMember {
                key_id: e2::kid(s),
                joined_at: epoch(1_000),
                role: (i == 0).then(|| "founder".to_owned()),
            })
            .collect(),
        founded_at: epoch(1_000),
        consensus_protocol: "majority".into(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    found(d, &rec, members, true).await
}

async fn found(
    d: &dyn FederationDirectory,
    rec: &GroupRecord,
    members: &[&str],
    put: bool,
) -> Group {
    let gid = fixture_group_id(rec);
    let keys: Vec<_> = members.iter().map(|s| e2::signing_key(s)).collect();
    let signers: Vec<&_> = keys.iter().collect();
    let founding = roster_voices(rec, 1, None, 2_000, &signers);
    let head = RowId::of_statement(&founding[0]).expect("the roster head's row id");
    if put {
        put_voices(d, &founding)
            .await
            .unwrap_or_else(|e| panic!("the founding of {gid}: {e}"));
    }
    Group { gid, head }
}

/// Where a binding is placed, and on whose behalf.
struct Shape<'a> {
    cohort: &'a str,
    placement: Option<(&'a str, &'a str)>,
    on_behalf_of: Option<&'a Group>,
}

/// `owner`'s binding of `k` (an agent's when `agent`), shaped by `shape`:
/// the row, its statement and its row id.
fn binding(owner: &str, k: &str, agent: bool, shape: &Shape<'_>) -> (Attestation, Vec<u8>, RowId) {
    let mut a = crate::federation::tier_ingest::test_support::owner_binding_attestation(
        &uuid::Uuid::new_v4().to_string(),
        owner,
        k,
    );
    if agent {
        // An agent's binding: the agent dimension, no `scope` (BIND-1).
        a.attestation_envelope["dimension"] =
            serde_json::json!("ownership:responsible_party:agent:v1");
        if let Some(o) = a.attestation_envelope.as_object_mut() {
            o.remove("scope");
        }
    }
    shape.cohort.clone_into(&mut a.cohort_scope);
    if let Some((member, group)) = shape.placement {
        a.attestation_envelope[member] = serde_json::json!(group);
    }
    if let Some(g) = shape.on_behalf_of {
        a.attestation_envelope[crate::federation::admission::ON_BEHALF_OF_FIELD] =
            serde_json::json!(g.gid);
        a.attestation_envelope["refs"] = serde_json::json!({ "head": [2, [-16, g.head.hex()]] });
    }
    a.asserted_at = Utc::now() - chrono::Duration::minutes(5);
    a.scrub_timestamp = a.asserted_at;
    let row = e2::row_of(&a, owner);
    let st = e2::carried_statement(&row).expect("the binding's statement");
    let id = RowId::of_statement(&st).expect("a row id");
    (row, st, id)
}

async fn state(d: &dyn FederationDirectory, id: &RowId) -> RowState {
    row_state(d, id).await.expect("the verdict reads")
}

fn held_for(s: &RowState) -> Option<String> {
    s.held().map(|h| h.reason.clone())
}

/// The owner's statement and K's voice, through the door; the verdict.
async fn two_voices(
    d: &dyn FederationDirectory,
    row: &Attestation,
    id: &RowId,
    k: &str,
    what: &str,
) -> RowState {
    e2::land_owner_binding(d, row, k)
        .await
        .unwrap_or_else(|e| panic!("{what}: the owner's and K's voices are kept: {e}"));
    state(d, id).await
}

/// **I6620–I6626**, for K = a node, then K = an agent.
pub(crate) async fn i6620_placement_is_not_accountability(d: &dyn FederationDirectory, tag: &str) {
    let s = |n: &str| format!("ob-{n}-{tag}");
    let (owner, node, agent) = (s("owner"), s("node"), s("agent"));
    let m = [s("m1"), s("m2"), s("m3")];
    let _ = e2::put_key(d, &owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, &node, &[identity_type::NODE]).await;
    let _ = e2::put_key(d, &agent, &[identity_type::AGENT]).await;
    for x in &m {
        let _ = e2::put_key(d, x, &[identity_type::USER]).await;
    }
    let (o, m1, m2, m3) = (owner.as_str(), m[0].as_str(), m[1].as_str(), m[2].as_str());
    let plain = room(d, &s("room"), &[o, m1], false, true).await;
    let fam = family(d, &s("fam"), &[o, m1]).await;
    let aff = room(d, &s("aff"), &[o, m1, m2, m3], true, true).await;
    let absent = room(d, &s("absent"), &[m1, m2, m3], true, false).await;
    for (k, is_agent) in [(node.as_str(), false), (agent.as_str(), true)] {
        let who = if is_agent { "agent" } else { "node" };
        let shaped = |cohort, placement, on_behalf_of| Shape {
            cohort,
            placement,
            on_behalf_of,
        };
        // I6620 — placed at an ordinary room: two voices.
        let (row, _, id) = binding(
            o,
            k,
            is_agent,
            &shaped(
                cs::COMMUNITY,
                Some(("community_id", plain.gid.as_str())),
                None,
            ),
        );
        let v = two_voices(d, &row, &id, k, "I6620").await;
        assert!(
            v.is_concluded(),
            "[{tag}] I6620 {who}: placed at a room, two voices: {v:?}"
        );
        // I6621 — placed at a family: two voices.
        let (row, _, id) = binding(
            o,
            k,
            is_agent,
            &shaped(cs::FAMILY, Some(("family_id", fam.gid.as_str())), None),
        );
        let v = two_voices(d, &row, &id, k, "I6621").await;
        assert!(
            v.is_concluded(),
            "[{tag}] I6621 {who}: placed at a family, two voices: {v:?}"
        );
        // I6622 — placed at an affiliation, no on_behalf_of: no count.
        let (row, _, id) = binding(
            o,
            k,
            is_agent,
            &shaped(
                cs::AFFILIATIONS,
                Some(("community_id", aff.gid.as_str())),
                None,
            ),
        );
        let v = two_voices(d, &row, &id, k, "I6622").await;
        assert!(
            v.is_concluded(),
            "[{tag}] I6622 {who}: placed at an affiliation with no on_behalf_of, two voices \
             and no count: {v:?}"
        );
        // I6623 — on behalf of an affiliation not held: waits.
        let (row, _, id) = binding(o, k, is_agent, &shaped(cs::SELF, None, Some(&absent)));
        let v = two_voices(d, &row, &id, k, "I6623").await;
        assert!(
            matches!(
                held_for(&v).as_deref(),
                Some(reason::COUNT_SHORT | reason::LINK_UNHELD)
            ),
            "[{tag}] I6623 {who}: on behalf of an affiliation not held, it waits: {v:?}"
        );
        // I6624 — on behalf of a held affiliation, owner + K only: short.
        let (row, st, id) = binding(o, k, is_agent, &shaped(cs::SELF, None, Some(&aff)));
        let v = two_voices(d, &row, &id, k, "I6624").await;
        assert_eq!(
            held_for(&v).as_deref(),
            Some(reason::COUNT_SHORT),
            "[{tag}] I6624 {who}: the owner's and K's voices only, the count is short: {v:?}"
        );
        // I6625 — the affiliation's members voice it at the head it names.
        for x in [m1, m2, m3] {
            e2::put_statement(d, &e2::voice_of(&st, x))
                .await
                .unwrap_or_else(|e| panic!("[{tag}] I6625 {who}: member {x}'s voice: {e}"));
        }
        let v = state(d, &id).await;
        assert!(
            v.is_concluded(),
            "[{tag}] I6625 {who}: counted under the affiliation's protocol at its head: {v:?}"
        );
        // I6626 — on behalf of a room that is no affiliation: the token.
        let (row, _, id) = binding(o, k, is_agent, &shaped(cs::SELF, None, Some(&plain)));
        let v = two_voices(d, &row, &id, k, "I6626").await;
        assert_eq!(
            held_for(&v).as_deref(),
            Some(reason::gc1::OWNER_BINDING_NOT_AN_AFFILIATION),
            "[{tag}] I6626 {who}: on behalf of a room that is no affiliation, it concludes \
             nothing: {v:?}"
        );
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend as _;

    #[tokio::test]
    async fn i6620_placement_is_not_accountability_sqlite() {
        let d = SqliteBackend::open_in_memory().await.unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i6620_placement_is_not_accountability(&d, "sqlite")).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend as _;

    #[tokio::test]
    async fn i6620_placement_is_not_accountability_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = PostgresBackend::connect(&dsn).await.unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i6620_placement_is_not_accountability(&d, "postgres")).await;
    }
}
