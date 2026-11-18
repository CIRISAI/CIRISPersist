//! v62.0.0 (wave V1) — **a co-signature is a counted VOICE**, on sqlite and
//! postgres. In edition 2 a cosigner states the row's payload in its own
//! statement (same row id), kept in `ceg_statements`; the gates that counted
//! `additional_scrubs` count these voices (`edition2::voices`).
//!
//! - **I3280** the family quorum (`trust_root::family_quorum_holders_over`,
//!   the charter / config / rebind count): one member's voice is short of a
//!   2-of-3 majority; a second member's voice meets it; a stranger's voice
//!   is never counted.
//! - **I3281** the community quorum (`admission::community_quorum_cosigned_at`,
//!   the licence root and the affiliation owner-binding count): short with
//!   one voice of a 2-member majority room, met with both.
//! - **I3283** the owner seat (`admission::kernel_owner_selves`,
//!   `Cosign::Required`): an owner binding the node has not voiced seats
//!   nobody; once the node's own statement over it is held, the owner holds
//!   the seat.
//! - **I3289** (wave V1b) the counted-row hold
//!   (`edition2::voices::put_counted_row`) on an owner binding: the owner's
//!   voice alone is `Pending` (kept, no typed row; re-offered, `new: false`);
//!   a stranger's voice never lands it; the node's voice lands it as the
//!   owner's row (`Row`).
//! - **I3286** `voices_of_row` reads each held voice's `iss`, `kid` and
//!   `asserted_at` from the store, one per signer, the same instant for all.
//! - **I3292 / I3293** (wave V1b, CC 3.2 ruling (a)) an owner binding naming
//!   an affiliation is counted: `Pending` until the owner's, the bound key's
//!   and the affiliation quorum's voices (at `refs.head`) are all held, in
//!   either order; a non-member's voice never completes it; landed, the
//!   affiliation answers for the agent (`affiliation_of_binding`).
//! - **I3294 / I3295** (wave V1b, CC 4.4.3.12) an affiliation's officer
//!   appointment, a counted `self:delegates_to`: `Pending` until the quorum
//!   at its `refs.head`; landed, no seat without the officer's own
//!   `membership:acceptance`; both, the officer resolves to the authority.
//! - **I3296** (wave V1b, CC 2.4.1.1) the withdrawal of a counted
//!   appointment is counted at the affiliation's protocol over the head it
//!   names: a lone member's authored retraction is refused; the counted one
//!   is `Pending` until met (a non-member's voice never completes it); met,
//!   the officer's seat ends.
//! - **I3297** (wave V1b, CC 2.4.1.1, CLM-licence-contest) the group's
//!   withdrawal of a counted licence is counted at the authority community
//!   its dimension names: the licensee's own and a lone member's are
//!   refused; the counted one is `Pending` until the quorum, then lands, and
//!   the licence stops counting (`licensure::status_set_for` drops `issued`).
//! - **I3298** (wave V1b; E13) a withdrawn owner binding ends ownership at
//!   the edition-2 door: bind (`owner_of` = A), A's `withdraws` lands
//!   (`owner_of` = none, `nodes_owned_by(A)` drops the node), rebind to B
//!   (`owner_of` = B).
//! - **I3287** an earlier-form row (no statement) counts nobody once the
//!   earlier-form doors are shut (`counted_roster_signers`).
//!
//! The ownership-reclaim WA quorum (I3284, I3285) is witnessed beside its
//! gate in `ownership_reclaim.rs`, through [`found_family`] / [`counted_row`]
//! / [`add_voice`] here.

use std::collections::BTreeSet;

use super::fixture_switch as e2;
use super::group::GroupRecord;
use super::group_fixtures::{put_voices, roster_voices};
use super::ingest::StatementOutcome;
use super::voices;
use crate::federation::types::{
    identity_type, Attestation, Community, CommunityMember, Family, FamilyMember,
};
use crate::federation::{Error, FederationDirectory};

fn epoch(ms: i64) -> chrono::DateTime<chrono::Utc> {
    use chrono::TimeZone as _;
    chrono::Utc
        .timestamp_millis_opt(ms)
        .single()
        .expect("instant")
}

/// Found a family of `members` (seeds; each must be a live key) under
/// `protocol`, by every member's roster voice; the held record.
///
/// # Panics
/// The founding does not land.
pub(crate) async fn found_family(
    d: &dyn FederationDirectory,
    group_seed: &str,
    members: &[&str],
    protocol: &str,
) -> Family {
    let gid = e2::kid(group_seed);
    let rec = GroupRecord::Family(Family {
        family_key_id: gid.clone(),
        family_name: format!("v1 {group_seed}"),
        members: members
            .iter()
            .map(|s| FamilyMember {
                key_id: e2::kid(s),
                joined_at: epoch(1_000),
                role: None,
            })
            .collect(),
        founded_at: epoch(1_000),
        consensus_protocol: protocol.to_owned(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    let keys: Vec<_> = members.iter().map(|s| e2::signing_key(s)).collect();
    let signers: Vec<&_> = keys.iter().collect();
    put_voices(d, &roster_voices(&rec, 1, None, 2_000, &signers))
        .await
        .expect("V1: the family's founding voices");
    d.lookup_family(&gid)
        .await
        .unwrap()
        .expect("V1: the family landed")
}

/// Found a community (first member `founder`) under `protocol`, with
/// `policy_blob` (e.g. `cohort_scope: affiliations`).
async fn found_community(
    d: &dyn FederationDirectory,
    group_seed: &str,
    members: &[&str],
    protocol: &str,
    policy_blob: Option<serde_json::Value>,
) -> Community {
    let gid = e2::kid(group_seed);
    let rec = GroupRecord::Community(Community {
        community_key_id: gid.clone(),
        community_name: format!("v1 {group_seed}"),
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
        consensus_protocol: protocol.to_owned(),
        policy_blob,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    let keys: Vec<_> = members.iter().map(|s| e2::signing_key(s)).collect();
    let signers: Vec<&_> = keys.iter().collect();
    put_voices(d, &roster_voices(&rec, 1, None, 2_000, &signers))
        .await
        .expect("V1: the community's founding voices");
    d.lookup_community(&gid)
        .await
        .unwrap()
        .expect("V1: the community landed")
}

/// A counted row (a `scores` row) stated by `seed`, put through the
/// statement door; the row as stored (it carries its statement).
pub(crate) async fn counted_row(d: &dyn FederationDirectory, seed: &str) -> Attestation {
    let a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(seed),
    );
    // v62.0.0 (wave V1b) — a COUNTED statement (no `author`): the family
    // (`trust:{job}:{version}`) is counted under `act=group`, so a second
    // member's voice over it is admitted (an authored row's would be refused
    // `iss_not_in_role`).
    let row = e2::counted_row_of(&a, seed);
    e2::put_signed(d, &row)
        .await
        .expect("V1: the counted row's first voice");
    row
}

/// `seed`'s voice over the statement `row` carries, through the door.
///
/// # Errors
/// The door's refusals.
pub(crate) async fn add_voice(
    d: &dyn FederationDirectory,
    row: &Attestation,
    seed: &str,
) -> Result<StatementOutcome, Error> {
    let st = e2::carried_statement(row).expect("V1: the row carries its statement");
    e2::put_statement(d, &e2::voice_of(&st, seed)).await
}

async fn keys(d: &dyn FederationDirectory, seeds: &[&str], types: &[&str]) {
    for s in seeds {
        let _ = e2::put_key(d, s, types).await;
    }
}

fn kids(seeds: &[&str]) -> BTreeSet<String> {
    seeds.iter().map(|s| e2::kid(s)).collect()
}

/// I3280 + I3286: the family quorum by voices.
pub(crate) async fn family_quorum_body(d: &dyn FederationDirectory) {
    let (a, b, c, x) = ("v1-fq-a", "v1-fq-b", "v1-fq-c", "v1-fq-x");
    keys(d, &[a, b, c, x], &[identity_type::USER]).await;
    let family = found_family(d, "v1-fq-g", &[a, b, c], "majority").await;

    let row = counted_row(d, a).await;
    let (q, who) = crate::federation::trust_root::family_quorum_holders_over(d, &row, &family)
        .await
        .unwrap();
    assert_eq!(who, kids(&[a]), "I3280 the row's own voice counts");
    assert!(
        q.distinct_holders < q.required,
        "I3280 one voice of three is short of majority: {q:?}"
    );

    // A stranger's voice (held or refused) never counts.
    let _ = add_voice(d, &row, x).await;
    let (_, who) = crate::federation::trust_root::family_quorum_holders_over(d, &row, &family)
        .await
        .unwrap();
    assert_eq!(who, kids(&[a]), "I3280 a non-member's voice is not counted");

    let o = add_voice(d, &row, b).await.expect("I3280 b's voice");
    assert!(
        matches!(o, StatementOutcome::Voice { new: true, .. }),
        "I3280 b's voice joins the held row: {o:?}"
    );
    let (q, who) = crate::federation::trust_root::family_quorum_holders_over(d, &row, &family)
        .await
        .unwrap();
    assert_eq!(who, kids(&[a, b]), "I3280 the two members' voices");
    assert!(
        q.distinct_holders >= q.required,
        "I3280 two voices of three meet majority: {q:?}"
    );

    // I3286 — the held voices, read back as the store holds them.
    let row_id = voices::carried_row_id(&row).expect("I3286 a statement-carrying row");
    let held = voices::voices_of_row(d, &row_id).await.unwrap();
    let iss: BTreeSet<String> = held.iter().map(|v| v.iss.clone()).collect();
    assert!(
        iss.contains(&e2::kid(a)) && iss.contains(&e2::kid(b)),
        "I3286 both voices are held: {iss:?}"
    );
    for v in &held {
        let seed = [a, b, x]
            .into_iter()
            .find(|s| e2::kid(s) == v.iss)
            .expect("I3286 a known signer");
        assert_eq!(v.kid, e2::kid_digest(seed), "I3286 the voice's kid");
        assert_eq!(
            v.asserted_at_ms, held[0].asserted_at_ms,
            "I3286 one payload, one asserted_at"
        );
    }
}

/// I3281: the community quorum by voices.
pub(crate) async fn community_quorum_body(d: &dyn FederationDirectory) {
    let (a, b) = ("v1-cq-a", "v1-cq-b");
    keys(d, &[a, b], &[identity_type::USER]).await;
    let c = found_community(d, "v1-cq-g", &[a, b], "majority", None).await;
    let row = counted_row(d, a).await;
    let at = row.asserted_at;
    assert!(
        !crate::federation::admission::community_quorum_cosigned_at(d, &c, &row, at)
            .await
            .unwrap(),
        "I3281 one voice of two is short of majority"
    );
    add_voice(d, &row, b).await.expect("I3281 b's voice");
    assert!(
        crate::federation::admission::community_quorum_cosigned_at(d, &c, &row, at)
            .await
            .unwrap(),
        "I3281 both members' voices meet majority"
    );
}

/// I3283 + I3289: an owner binding is held `Pending` until the node voices
/// it, then lands and seats its owner.
pub(crate) async fn owner_seat_body(d: &dyn FederationDirectory) {
    let (owner, node, stranger) = ("v1-own-o", "v1-own-n", "v1-own-x");
    let _ = e2::put_key(d, owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, stranger, &[identity_type::USER]).await;
    let node_kid = e2::put_key(d, node, &[identity_type::NODE]).await;
    let row = owner_binding(owner, node);
    let id = voices::carried_row_id(&row)
        .expect("I3289 the binding carries its statement")
        .hex();
    let required = crate::kernel::owner::Cosign::Required;

    // I3289 — the owner's voice alone: kept, no typed row.
    let o = e2::put_signed(d, &row)
        .await
        .expect("I3289 the owner's voice is kept, not refused");
    assert!(
        matches!(o, StatementOutcome::Pending { new: true, .. }),
        "I3289 the binding waits for the node's voice: {o:?}"
    );
    assert!(
        d.get_attestation(&id).await.unwrap().is_none(),
        "I3289 no typed row for a binding the node never voiced"
    );
    assert!(
        crate::federation::admission::kernel_owner_selves(d, &node_kid, required)
            .await
            .unwrap()
            .is_empty(),
        "I3283 a binding the node has not voiced seats nobody"
    );
    // A re-offer of the same voice is the same hold.
    let o = e2::put_signed(d, &row).await.expect("I3289 re-offer");
    assert!(
        matches!(o, StatementOutcome::Pending { new: false, .. }),
        "I3289 a re-offered voice: {o:?}"
    );

    // A voice that is not the bound key's never completes it (refused by the
    // family's roles, or held and not counted).
    let st = e2::carried_statement(&row).expect("I3289 the binding's statement");
    let _ = e2::put_statement(d, &e2::voice_of(&st, stranger)).await;
    assert!(
        d.get_attestation(&id).await.unwrap().is_none(),
        "I3289 a stranger's voice does not land the binding"
    );

    // The node's voice lands it.
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("I3289 the node's voice over its binding");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3289 the node's voice lands the binding: {o:?}"
    );
    let held = d
        .get_attestation(&id)
        .await
        .unwrap()
        .expect("I3289 the typed row landed");
    assert_eq!(
        held.attesting_key_id,
        e2::kid(owner),
        "I3289 the row is the owner's (projected from the author's voice)"
    );
    assert_eq!(
        crate::federation::admission::kernel_owner_selves(d, &node_kid, required)
            .await
            .unwrap()
            .len(),
        1,
        "I3283 with the node's voice held, the owner holds the seat"
    );
}

/// An owner binding of `owner` over `agent` that names the affiliation `c`
/// at its held roster head (`refs.head`), as `owner`'s statement.
async fn affiliation_binding(
    d: &dyn FederationDirectory,
    owner: &str,
    agent: &str,
    c: &Community,
) -> Attestation {
    let (head, _) = super::group_fixtures::held_head(d, &c.community_key_id)
        .await
        .expect("I3292 the affiliation's roster head is held");
    let mut a = crate::federation::tier_ingest::test_support::owner_binding_attestation(
        &uuid::Uuid::new_v4().to_string(),
        owner,
        agent,
    );
    a.attestation_envelope["community_id"] = serde_json::json!(c.community_key_id);
    a.attestation_envelope["refs"] = serde_json::json!({ "head": [2, [-16, head.hex()]] });
    redate(&mut a);
    e2::row_of(&a, owner)
}

/// Now-relative (5 minutes back): the builder's fixed 2026-05-01 is outside
/// a node or agent key's default window, so the bound key's voice over it
/// would not verify (E13's finding).
fn redate(a: &mut Attestation) {
    a.asserted_at = chrono::Utc::now() - chrono::Duration::minutes(5);
    a.scrub_timestamp = a.asserted_at;
}

/// `owner`'s edition-2 owner binding over `node` (the owner's statement),
/// now-relative.
fn owner_binding(owner: &str, node: &str) -> Attestation {
    let mut a = crate::federation::tier_ingest::test_support::owner_binding_attestation(
        &uuid::Uuid::new_v4().to_string(),
        owner,
        node,
    );
    redate(&mut a);
    e2::row_of(&a, owner)
}

/// Bind `node` to `owner`: the owner's statement, then the node's own
/// voice, which lands it. The landed binding row.
async fn bind(d: &dyn FederationDirectory, owner: &str, node: &str) -> Attestation {
    let row = owner_binding(owner, node);
    let id = voices::carried_row_id(&row).expect("a statement").hex();
    let st = e2::carried_statement(&row).expect("the binding's statement");
    e2::put_signed(d, &row)
        .await
        .expect("the owner's statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("the node's voice over its binding");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "the node's voice lands the binding: {o:?}"
    );
    d.get_attestation(&id)
        .await
        .unwrap()
        .expect("the binding is held")
}

/// I3298: a WITHDRAWN owner binding ends the node's ownership at the
/// edition-2 door. Bound to A (`owner_of` = A, `nodes_owned_by(A)` ∋ node);
/// A's `withdraws` of the binding lands; `owner_of` = none and
/// `nodes_owned_by(A)` drops the node; bound again to B, `owner_of` = B.
pub(crate) async fn unbind_rebind_body(d: &dyn FederationDirectory) {
    use crate::federation::admission::{nodes_owned_by, owner_of};
    use crate::federation::types::attestation_type;
    let (a, b, node) = ("v1-ub-a", "v1-ub-b", "v1-ub-n");
    let _ = e2::put_key(d, a, &[identity_type::USER]).await;
    let _ = e2::put_key(d, b, &[identity_type::USER]).await;
    let node_kid = e2::put_key(d, node, &[identity_type::NODE]).await;

    let first = bind(d, a, node).await;
    assert_eq!(
        owner_of(d, &node_kid).await.unwrap(),
        Some(e2::kid(a)),
        "I3298 bound: the node's owner is A"
    );
    assert!(
        nodes_owned_by(d, &e2::kid(a))
            .await
            .unwrap()
            .contains(&node_kid),
        "I3298 bound: A owns the node"
    );

    // A withdraws its binding (rule 1: its own row).
    let unbind = e2::composer_of(attestation_type::WITHDRAWS, &first, a);
    let o = e2::put_signed(d, &unbind)
        .await
        .expect("I3298 the owner's withdraws of its binding is admitted");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3298 the withdraws lands: {o:?}"
    );
    assert_eq!(
        owner_of(d, &node_kid).await.unwrap(),
        None,
        "I3298 unbound: the node has no owner"
    );
    assert!(
        !nodes_owned_by(d, &e2::kid(a))
            .await
            .unwrap()
            .contains(&node_kid),
        "I3298 unbound: A no longer owns the node"
    );

    // Rebound to B.
    let _ = bind(d, b, node).await;
    assert_eq!(
        owner_of(d, &node_kid).await.unwrap(),
        Some(e2::kid(b)),
        "I3298 rebound: the node's owner is B"
    );
    assert!(
        !nodes_owned_by(d, &e2::kid(a))
            .await
            .unwrap()
            .contains(&node_kid),
        "I3298 rebound: A still does not own the node"
    );
}

fn pending(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Pending { .. })
}

/// I3292 + I3293: an owner binding naming an affiliation is COUNTED (CC 3.2
/// ruling (a), CC 2.4.1.3): held `Pending` until the owner's, the bound
/// key's AND the affiliation quorum's voices are all held, in either order;
/// then it lands and the affiliation answers for the agent
/// (`affiliation_of_binding`, the slashing / quarantine reach).
pub(crate) async fn affiliation_owner_binding_body(d: &dyn FederationDirectory) {
    let (owner, m1, m2, m3, x) = ("v1-ab-o", "v1-ab-m1", "v1-ab-m2", "v1-ab-m3", "v1-ab-x");
    keys(d, &[owner, m1, m2, m3, x], &[identity_type::USER]).await;
    let blob = serde_json::json!({
        "cohort_scope": "affiliations",
        "affiliation_config": { "licence_audiences": { "professional_full": "federation" } },
    });
    let c = found_community(d, "v1-ab-g", &[m1, m2, m3], "majority", Some(blob)).await;
    let reach = |agent_kid: String| async move {
        crate::federation::admission::affiliation_of_binding(d, &agent_kid)
            .await
            .unwrap()
    };

    // I3292 — owner, then the bound key, then the members.
    let agent = "v1-ab-a1";
    let agent_kid = e2::put_key(d, agent, &[identity_type::AGENT]).await;
    let row = affiliation_binding(d, owner, agent, &c).await;
    let id = voices::carried_row_id(&row)
        .expect("I3292 a statement")
        .hex();
    let st = e2::carried_statement(&row).expect("I3292 the binding's statement");
    let o = e2::put_signed(d, &row)
        .await
        .expect("I3292 the owner's voice");
    assert!(pending(&o), "I3292 the owner alone waits: {o:?}");
    let o = e2::put_statement(d, &e2::voice_of(&st, agent))
        .await
        .expect("I3292 the bound key's voice");
    assert!(
        pending(&o),
        "I3292 owner + bound key, no quorum, waits: {o:?}"
    );
    let o = e2::put_statement(d, &e2::voice_of(&st, m1))
        .await
        .expect("I3292 a member's voice is admitted (ruling (a))");
    assert!(pending(&o), "I3292 one of three members waits: {o:?}");
    // A non-member's voice never completes it.
    let _ = e2::put_statement(d, &e2::voice_of(&st, x)).await;
    assert!(
        d.get_attestation(&id).await.unwrap().is_none(),
        "I3292 no typed row short of the quorum (a non-member does not count)"
    );
    assert_eq!(
        reach(agent_kid.clone()).await,
        None,
        "I3292 a held binding reaches no affiliation"
    );
    let o = e2::put_statement(d, &e2::voice_of(&st, m2))
        .await
        .expect("I3292 the second member's voice");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3292 owner + bound key + 2 of 3 members lands it: {o:?}"
    );
    let held = d
        .get_attestation(&id)
        .await
        .unwrap()
        .expect("I3292 the typed row landed");
    assert_eq!(
        held.attesting_key_id,
        e2::kid(owner),
        "I3292 the owner's row"
    );
    assert_eq!(
        reach(agent_kid).await,
        Some(c.community_key_id.clone()),
        "I3292 slashing reaches the affiliation"
    );

    // I3293 — the quorum first: met without the bound key, it still waits.
    let agent = "v1-ab-a2";
    let agent_kid = e2::put_key(d, agent, &[identity_type::AGENT]).await;
    let row = affiliation_binding(d, owner, agent, &c).await;
    let id = voices::carried_row_id(&row)
        .expect("I3293 a statement")
        .hex();
    let st = e2::carried_statement(&row).expect("I3293 the binding's statement");
    let o = e2::put_signed(d, &row)
        .await
        .expect("I3293 the owner's voice");
    assert!(pending(&o), "I3293 {o:?}");
    for m in [m1, m2] {
        let o = e2::put_statement(d, &e2::voice_of(&st, m))
            .await
            .expect("I3293 a member's voice");
        assert!(
            pending(&o),
            "I3293 the quorum without the bound key waits: {o:?}"
        );
    }
    assert!(
        d.get_attestation(&id).await.unwrap().is_none(),
        "I3293 no typed row without the bound key's voice"
    );
    let o = e2::put_statement(d, &e2::voice_of(&st, agent))
        .await
        .expect("I3293 the bound key's voice");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3293 the bound key's voice completes it: {o:?}"
    );
    assert_eq!(
        reach(agent_kid).await,
        Some(c.community_key_id.clone()),
        "I3293 slashing reaches the affiliation"
    );
}

/// I3294 + I3295: an affiliation's officer appointment is a COUNTED
/// `self:delegates_to` (CC 4.4.3.12, the second ruling): held `Pending`
/// until the affiliation's quorum at its `refs.head` is met (a non-member's
/// voice never completes it); landed, the officer still holds no seat until
/// their own `membership:acceptance` of it is held ("two consents"); with
/// both, the officer resolves to the affiliation's authority.
pub(crate) async fn officer_appointment_body(d: &dyn FederationDirectory) {
    use crate::federation::admission::{
        emitter_resolves_to_authority, DELEGATION_SCOPE_LICENSE, DELEGATION_VALID_UNTIL_FIELD,
    };
    use crate::federation::types::{attestation_type, cohort_scope};
    let (m1, m2, m3, x, officer) = ("v1-oa-m1", "v1-oa-m2", "v1-oa-m3", "v1-oa-x", "v1-oa-o");
    keys(d, &[m1, m2, m3, x, officer], &[identity_type::USER]).await;
    let blob = serde_json::json!({
        "cohort_scope": "affiliations",
        "affiliation_config": { "licence_audiences": { "professional_full": "federation" } },
    });
    let c = found_community(d, "v1-oa-g", &[m1, m2, m3], "majority", Some(blob)).await;
    let aff = c.community_key_id.clone();
    let (head, _) = super::group_fixtures::held_head(d, &aff)
        .await
        .expect("I3294 the affiliation's roster head is held");
    let now = chrono::Utc::now();
    let officer_kid = e2::kid(officer);

    // The appointment: the affiliation's counted `self:delegates_to` to the
    // officer (no author), first voiced by m1.
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(m1),
    );
    a.attestation_type = attestation_type::DELEGATES_TO.to_owned();
    a.attested_key_id = officer_kid.clone();
    a.subject_key_ids = vec![officer_kid.clone()];
    a.weight = None;
    a.asserted_at = now - chrono::Duration::hours(1);
    a.scrub_timestamp = a.asserted_at;
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "scope": [DELEGATION_SCOPE_LICENSE],
        "community_id": aff,
        DELEGATION_VALID_UNTIL_FIELD: crate::federation::admission::render_signed_instant(
            now + chrono::Duration::days(1),
        ),
        "refs": { "head": [2, [-16, head.hex()]] },
    });
    let row = e2::counted_row_of(&a, m1);
    let id = voices::carried_row_id(&row)
        .expect("I3294 a statement")
        .hex();
    let st = e2::carried_statement(&row).expect("I3294 the appointment's statement");

    // I3294 — Pending until the quorum.
    let o = e2::put_signed(d, &row).await.expect("I3294 m1's voice");
    assert!(pending(&o), "I3294 one of three members waits: {o:?}");
    let _ = e2::put_statement(d, &e2::voice_of(&st, x)).await;
    assert!(
        d.get_attestation(&id).await.unwrap().is_none(),
        "I3294 a non-member's voice does not land the appointment"
    );
    let o = e2::put_statement(d, &e2::voice_of(&st, m2))
        .await
        .expect("I3294 m2's voice");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3294 two of three members land the appointment: {o:?}"
    );

    // I3295 — the quorum alone seats nobody: the officer has not consented.
    assert!(
        !emitter_resolves_to_authority(d, &officer_kid, &aff)
            .await
            .unwrap(),
        "I3295 a quorum appointment without the officer's acceptance is no seat"
    );
    let held = d
        .get_attestation(&id)
        .await
        .unwrap()
        .expect("I3295 the appointment is held");
    let mut answered = held.clone();
    answered.cohort_scope = cohort_scope::COMMUNITY.to_owned();
    answered.attestation_envelope["community_key_id"] = serde_json::json!(aff);
    let acceptance = crate::federation::membership_acceptance::test_support::acceptance_row(
        officer, &answered, now,
    );
    e2::put_signed(d, &acceptance)
        .await
        .expect("I3295 the officer's own acceptance of the appointment");
    assert!(
        emitter_resolves_to_authority(d, &officer_kid, &aff)
            .await
            .unwrap(),
        "I3295 both consents: the officer resolves to the affiliation's authority"
    );

    // I3296 — the affiliation's withdrawal of the appointment is itself
    // counted: a lone member's own (authored) retraction is refused, the
    // group's counted one waits until the quorum at the head it names, and a
    // non-member's voice never completes it; met, the seat ends.
    let lone = e2::composer_of(attestation_type::WITHDRAWS, &held, m3);
    assert!(
        e2::put_signed(d, &lone).await.is_err(),
        "I3296 a lone member's retraction of a counted appointment never lands"
    );
    let mut w = held.clone();
    w.attestation_type = attestation_type::WITHDRAWS.to_owned();
    w.attesting_key_id = e2::kid(m1);
    w.asserted_at = chrono::Utc::now();
    w.scrub_timestamp = w.asserted_at;
    w.expires_at = None;
    w.subject_key_ids = Vec::new();
    w.weight = None;
    w.cohort_scope = cohort_scope::FEDERATION.to_owned();
    w.attestation_envelope = serde_json::json!({
        "refs": {
            "target": [2, [-16, id]],
            "head": [2, [-16, head.hex()]],
        },
    });
    let family =
        ciris_verify_core::namespace_match::family_id(super::door::SELF_DELEGATES_TO_FAMILY_PREFIX);
    let wst = e2::counted_statement_of_family(&w, m1, &family);
    let wid = super::names::RowId::of_statement(&wst)
        .expect("I3296 a row statement")
        .hex();
    let o = e2::put_statement(d, &wst)
        .await
        .expect("I3296 m1's withdrawal voice");
    assert!(
        pending(&o),
        "I3296 one member's counted withdrawal waits: {o:?}"
    );
    let _ = e2::put_statement(d, &e2::voice_of(&wst, x)).await;
    assert!(
        d.get_attestation(&wid).await.unwrap().is_none(),
        "I3296 a non-member's voice does not land the withdrawal"
    );
    assert!(
        emitter_resolves_to_authority(d, &officer_kid, &aff)
            .await
            .unwrap(),
        "I3296 a held withdrawal does not end the seat"
    );
    let o = e2::put_statement(d, &e2::voice_of(&wst, m2))
        .await
        .expect("I3296 m2's withdrawal voice");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3296 two of three members land the withdrawal: {o:?}"
    );
    assert!(
        !emitter_resolves_to_authority(d, &officer_kid, &aff)
            .await
            .unwrap(),
        "I3296 the group's counted withdrawal ends the seat"
    );
}

/// What a licence counts for: is `issued` among the authority's live
/// statuses about the licensee (`licensure::status_set_for`, the licence
/// fold)?
async fn licence_issued(d: &dyn FederationDirectory, holder: &str, authority: &str) -> bool {
    crate::federation::licensure::status_set_for(d, holder, authority, chrono::Utc::now())
        .await
        .unwrap()
        .contains(&crate::federation::licensure::LicensureStatus::Issued)
}

/// I3297: the group's withdrawal of a COUNTED licence is itself counted, at
/// the protocol of the authority community its dimension names
/// (`licensure:{authority}`), over the head the withdrawal names. The
/// licensee's own withdrawal stays refused (CLM-licence-contest), as does a
/// lone member's authored one; the counted withdrawal is `Pending` until the
/// quorum, then lands with an admitted rule.
pub(crate) async fn licence_withdrawal_body(d: &dyn FederationDirectory) {
    use crate::federation::types::attestation_type;
    let (m1, m2, m3, x, holder) = ("v1-lw-m1", "v1-lw-m2", "v1-lw-m3", "v1-lw-x", "v1-lw-h");
    keys(d, &[m1, m2, m3, x, holder], &[identity_type::USER]).await;
    let blob = serde_json::json!({
        "cohort_scope": "affiliations",
        "affiliation_config": { "licence_audiences": { "professional_full": "federation" } },
    });
    let c = found_community(d, "v1-lw-g", &[m1, m2, m3], "majority", Some(blob)).await;
    let aff = c.community_key_id.clone();
    let (head, _) = super::group_fixtures::held_head(d, &aff)
        .await
        .expect("I3297 the authority's roster head is held");
    let now = chrono::Utc::now();
    let holder_kid = e2::kid(holder);

    // The counted licence: the authority's act, voiced by m1 and m2.
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(m1),
    );
    a.attested_key_id = holder_kid.clone();
    a.asserted_at = now - chrono::Duration::hours(1);
    a.scrub_timestamp = a.asserted_at;
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": format!("{}:v1", crate::federation::licensure::licensure_stem_of(&aff)),
        "status": "issued",
        "score": 1.0,
        "confidence": 0.9,
        "partner_record": {
            "license_id": a.attestation_id,
            "license_type": "professional_full",
            "capabilities_granted": [],
            "capabilities_denied": [],
            "max_autonomy_tier": "A2",
            "requires_supervisor": false,
            "geographic_restrictions": ["CA", "US"],
            "allowed_identity_templates": [],
            "deployment_limit": 10,
            "offline_grace_hours": 24,
            "revision": 1,
            "issued_at": "2026-10-01T00:00:00.000Z",
            "expires_at": "2027-10-01T00:00:00.000Z",
        },
        "refs": { "head": [2, [-16, head.hex()]] },
    });
    let lic = e2::counted_row_of(&a, m1);
    let lid = voices::carried_row_id(&lic)
        .expect("I3297 a statement")
        .hex();
    let lst = e2::carried_statement(&lic).expect("I3297 the licence's statement");
    let o = e2::put_signed(d, &lic)
        .await
        .expect("I3297 m1's licence voice");
    assert!(pending(&o), "I3297 one member's licence waits: {o:?}");
    let o = e2::put_statement(d, &e2::voice_of(&lst, m2))
        .await
        .expect("I3297 m2's licence voice");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3297 the quorum lands the licence: {o:?}"
    );
    let held = d
        .get_attestation(&lid)
        .await
        .unwrap()
        .expect("I3297 the licence is held");
    let family = e2::family_of(&held);
    assert!(
        licence_issued(d, &holder_kid, &aff).await,
        "I3297 the landed licence counts: the licensee holds it"
    );

    // A counted withdrawal of the licence, first voiced by `seed`.
    let withdrawal = |seed: &str| {
        let mut w = held.clone();
        w.attestation_type = attestation_type::WITHDRAWS.to_owned();
        w.attesting_key_id = e2::kid(seed);
        w.asserted_at = chrono::Utc::now();
        w.scrub_timestamp = w.asserted_at;
        w.expires_at = None;
        w.subject_key_ids = Vec::new();
        w.weight = None;
        w.attestation_envelope = serde_json::json!({
            "dimension": held.attestation_envelope["dimension"],
            "refs": {
                "target": [2, [-16, lid]],
                "head": [2, [-16, head.hex()]],
            },
        });
        e2::counted_statement_of_family(&w, seed, &family)
    };

    // The licensee's own withdrawal: refused, counted or authored.
    assert!(
        e2::put_statement(d, &withdrawal(holder)).await.is_err(),
        "I3297 the licensee's own counted withdrawal is refused (CLM-licence-contest)"
    );
    assert!(
        e2::put_signed(
            d,
            &e2::composer_of(attestation_type::WITHDRAWS, &held, holder)
        )
        .await
        .is_err(),
        "I3297 the licensee's own withdrawal is refused (CLM-licence-contest)"
    );
    // A lone member's authored withdrawal: refused.
    assert!(
        e2::put_signed(d, &e2::composer_of(attestation_type::WITHDRAWS, &held, m3))
            .await
            .is_err(),
        "I3297 a lone member's retraction of a counted licence never lands"
    );
    // The group's counted withdrawal: Pending, a non-member never completes
    // it, the quorum lands it.
    let wst = withdrawal(m1);
    let wid = super::names::RowId::of_statement(&wst)
        .expect("I3297 a row statement")
        .hex();
    let o = e2::put_statement(d, &wst)
        .await
        .expect("I3297 m1's withdrawal voice");
    assert!(
        pending(&o),
        "I3297 one member's counted withdrawal waits: {o:?}"
    );
    let _ = e2::put_statement(d, &e2::voice_of(&wst, x)).await;
    assert!(
        d.get_attestation(&wid).await.unwrap().is_none(),
        "I3297 a non-member's voice does not land the withdrawal"
    );
    assert!(
        licence_issued(d, &holder_kid, &aff).await,
        "I3297 a held withdrawal does not retire the licence"
    );
    let o = e2::put_statement(d, &e2::voice_of(&wst, m2))
        .await
        .expect("I3297 m2's withdrawal voice");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3297 two of three members land the withdrawal: {o:?}"
    );
    let landed = d
        .get_attestation(&wid)
        .await
        .unwrap()
        .expect("I3297 the withdrawal is held");
    assert!(
        matches!(landed.withdraws_admission_rule, Some(1 | 4)),
        "I3297 the counted withdrawal is admitted with a rule: {:?}",
        landed.withdraws_admission_rule
    );
    assert!(
        !licence_issued(d, &holder_kid, &aff).await,
        "I3297 the landed counted withdrawal retires the licence: it no longer counts"
    );
}

/// I3287: an earlier-form row counts nobody with the doors shut.
async fn earlier_form_shut_body(d: &dyn FederationDirectory) {
    let row = crate::federation::genesis::ordinary_scores_row("v1-earlier", "v1-earlier-key");
    let roster = vec!["v1-earlier-key".to_owned()];
    let counted =
        super::door::with_earlier_form_doors_shut(voices::counted_roster_signers(d, &row, &roster))
            .await
            .unwrap();
    assert!(
        counted.is_empty(),
        "I3287 an earlier-form row counts nobody once the doors are shut"
    );
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::empty_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3280_i3286_family_quorum_by_voices_sqlite() {
    Box::pin(family_quorum_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3280_i3286_family_quorum_by_voices_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(family_quorum_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3281_community_quorum_by_voices_sqlite() {
    Box::pin(community_quorum_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3281_community_quorum_by_voices_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(community_quorum_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3283_owner_seat_reads_the_node_voice_sqlite() {
    Box::pin(owner_seat_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3283_owner_seat_reads_the_node_voice_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(owner_seat_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3287_earlier_form_counts_nobody_when_shut_sqlite() {
    Box::pin(earlier_form_shut_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3287_earlier_form_counts_nobody_when_shut_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(earlier_form_shut_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3292_i3293_affiliation_owner_binding_counted_sqlite() {
    Box::pin(affiliation_owner_binding_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3292_i3293_affiliation_owner_binding_counted_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(affiliation_owner_binding_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3294_i3296_officer_appointment_two_consents_sqlite() {
    Box::pin(officer_appointment_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3294_i3296_officer_appointment_two_consents_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(officer_appointment_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3297_counted_licence_withdrawal_sqlite() {
    Box::pin(licence_withdrawal_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3297_counted_licence_withdrawal_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(licence_withdrawal_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3298_withdrawn_owner_binding_ends_ownership_sqlite() {
    Box::pin(unbind_rebind_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3298_withdrawn_owner_binding_ends_ownership_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(unbind_rebind_body(&b)).await;
}
