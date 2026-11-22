//! v62.0.0 (KR-fix17; CC 2.4.1.1) — **I4293–I4298: a retraction is placed
//! where its target is, and a host withdraws its own row with one verb.**
//!
//! Before KR-fix17 no `withdraws` placed at a room could land: the write-scope
//! gate read the room from the composer's own envelope, which carries none
//! (`P/KR-fix17-FINDING.md`). Every witness here goes through the host verbs
//! (`Engine::withdraw_statement`, `Engine::withdraw_statement_draft`), never a
//! hand-built row.
//!
//! - **I4293** a member withdraws their own membership proposal in a room.
//! - **I4294** the proposer's SECOND DEVICE withdraws it.
//! - **I4295** the proposer's NODE cannot retract it: whatever the door
//!   answers its withdrawal, the proposal still stands, and the answer is
//!   not a refusal of the row's shape or placement.
//! - **I4296** a non-member is refused; and a member of ANOTHER room cannot
//!   withdraw by naming that room (`composer_placed_apart_from_target`).
//! - **I4297** a withdrawal whose target is not held waits.
//! - **I4298** two nodes converge through the feed: the node that held the
//!   withdrawal first lands it when its target arrives.
//!
//! - **I4299** a NON-attester's retraction placed at `self` or the commons,
//!   naming no room, is refused by the withdraws admission rule; the
//!   attester's own, placed at the commons, lands.
//!
//! - **I4310** a FORMER member retracts their own room row (CC 2.4.1.1 rule 1:
//!   "the key that signed T … Condition: none"), and is served nothing back.
//! - **I4311** a COUNTED row is rule 0's: rules 1 to 4 do not reach it (not a
//!   voice of it, not a subject it names).
//! - **I4312** a subject takes back their OWN act (the consent they gave).
//!
//! sqlite and postgres.

use crate::federation::edition2::fixture_occurrence::{put_bind, BindOptions};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::membership_acceptance::{
    COMPOSER_PLACED_APART_FROM_TARGET, RULE_PROPOSAL_EXPIRED,
};
use crate::federation::membership_acceptance_invariants::bodies::{
    found_community, id_of, proposal, put_e2, reg, reply, rule_of, suffix, widen_community,
};
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::cohort_scope::COMMUNITY;
use crate::federation::types::{attestation_type, device_class};
use crate::federation::{Attestation, FederationDirectory};
use chrono::{Duration, Utc};

/// A room `cid` founded by `founder`, and the founder's proposal to `m`,
/// accepted by `m`. Returns `(room id, founder id, m id, the proposal)`.
async fn room_with_accepted_proposal(
    d: &dyn FederationDirectory,
    tag: &str,
    s: &str,
) -> (String, String, String, Attestation) {
    let (cid, founder, m) = (
        format!("{tag}-c-{s}"),
        format!("{tag}-f-{s}"),
        format!("{tag}-m-{s}"),
    );
    reg(d, &[&cid, &founder, &m]).await;
    let (cid, founder, m) = (id_of(&cid), id_of(&founder), id_of(&m));
    found_community(d, &cid, "quorum:1/1", &[&founder], &[])
        .await
        .expect("the founder founds the room");
    let now = Utc::now();
    let p = proposal(
        &founder,
        COMMUNITY,
        &cid,
        &m,
        None,
        now,
        Some(Duration::days(7)),
    );
    put_e2(d, &p).await.expect("the invitation");
    put_e2(d, &reply(&m, &m, &p, true, now))
        .await
        .expect("the invitee accepts");
    (cid, founder, m, p)
}

/// Does the room still grow on the accepted proposal? `Ok`: the proposal
/// stands. `Err`: the rule the growth was refused by.
async fn grows(
    d: &dyn FederationDirectory,
    cid: &str,
    founder: &str,
    m: &str,
) -> Result<(), &'static str> {
    widen_community(d, cid, &[founder], m, None, Utc::now())
        .await
        .map_err(|e| rule_of(&e))
}

/// The hold a withdrawal the signer may not make is kept under.
pub(crate) const NOT_ADMITTED: &str =
    crate::federation::edition2::fold::reason::WITHDRAWS_NOT_ADMITTED;
/// The hold a row written to a room by a non-member is kept under.
pub(crate) const WRITE_SCOPE_REFUSED: &str = "write_scope_refused";

/// KR-fix21 — **the withdrawal LANDED**: the verb answered `Seated`. Its row
/// id.
pub(crate) fn landed_id(
    out: crate::federation::edition2::second_signer_voice::VoiceOutcome,
    what: &str,
) -> String {
    assert!(out.is_seated(), "{what}: the withdrawal LANDED: {out:?}");
    out.row_id().to_owned()
}

/// KR-fix21 — **the withdrawal was KEPT and retracts NOTHING**: what makes a
/// forbidden-retraction witness fail if the retraction ever really lands.
///
/// - the verb's answer is `Waiting` under one of `reasons` (never `Seated`);
/// - no attestation row exists under the withdrawal's id, so it carries no
///   admission stamp (a stamp is written only on a landed row);
/// - the target is still held and no held composer naming it is this one;
/// - the retraction fold (`precedence::retired_ids`, what the Live listing
///   and the conferral readers apply) does not retire the target.
pub(crate) async fn held_not_landed(
    d: &dyn FederationDirectory,
    out: &crate::federation::edition2::second_signer_voice::VoiceOutcome,
    target_id: &str,
    reasons: &[&str],
    what: &str,
) {
    use crate::federation::edition2::second_signer_voice::VoiceOutcome;
    let VoiceOutcome::Waiting { row_id, reason, .. } = out else {
        panic!("{what}: the withdrawal LANDED ({out:?}): a retraction nobody may make took effect");
    };
    assert!(
        reasons.contains(&reason.as_str()),
        "{what}: held under one of {reasons:?}: {out:?}"
    );
    assert!(
        d.get_attestation(row_id).await.expect("reads").is_none(),
        "{what}: no withdrawal row landed, so no admission stamp exists"
    );
    let target = d
        .get_attestation(target_id)
        .await
        .expect("reads")
        .unwrap_or_else(|| panic!("{what}: the target is still held"));
    let composers = d
        .list_attestations_referencing(target_id)
        .await
        .expect("reads");
    assert!(
        composers.iter().all(|c| &c.attestation_id != row_id),
        "{what}: the kept withdrawal is not among the composers held against the target"
    );
    let rows: Vec<&Attestation> = std::iter::once(&target).chain(composers.iter()).collect();
    assert!(
        !crate::federation::precedence::retired_ids(&rows).contains(target_id),
        "{what}: the target is still LIVE by the retraction fold"
    );
}

/// KR-fix21 — **a retraction nobody may make did not take effect**: the door
/// either REFUSED it (`Err`, nothing kept) or KEPT it without admitting it
/// ([`held_not_landed`]); either way the target is still live.
pub(crate) async fn not_retracted(
    d: &dyn FederationDirectory,
    result: Result<
        crate::federation::edition2::second_signer_voice::VoiceOutcome,
        crate::federation::Error,
    >,
    target_id: &str,
    reasons: &[&str],
    what: &str,
) {
    match result {
        Ok(out) => held_not_landed(d, &out, target_id, reasons, what).await,
        Err(_) => {
            let target = d
                .get_attestation(target_id)
                .await
                .expect("reads")
                .unwrap_or_else(|| panic!("{what}: the target is still held"));
            let composers = d
                .list_attestations_referencing(target_id)
                .await
                .expect("reads");
            let rows: Vec<&Attestation> =
                std::iter::once(&target).chain(composers.iter()).collect();
            assert!(
                !crate::federation::precedence::retired_ids(&rows).contains(target_id),
                "{what}: refused, and the target is still LIVE by the retraction fold"
            );
        }
    }
}

/// **I4293.**
pub(crate) async fn i4293_a_member_withdraws_their_own_proposal(e: &crate::Engine) {
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let s = suffix();
    let founder_seed = format!("i4293-f-{s}");
    let (cid, founder, m, p) = room_with_accepted_proposal(d, "i4293", &s).await;
    let id = landed_id(
        e.withdraw_statement(&ts::local_signer(&founder_seed), &e2::rid(&p))
            .await
            .expect("I4293: the proposer withdraws their own proposal in the room"),
        "I4293",
    );
    let w = d
        .get_attestation(&id)
        .await
        .expect("I4293: reads")
        .expect("I4293: the withdrawal landed");
    assert_eq!(w.attestation_type, attestation_type::WITHDRAWS, "I4293");
    assert_eq!(w.attesting_key_id, founder, "I4293: the proposer's row");
    assert_eq!(
        w.cohort_scope, COMMUNITY,
        "I4293: placed where the proposal is"
    );
    assert_eq!(
        crate::federation::admission::envelope_cohort_target(&w.attestation_envelope)
            .expect("I4293: one room"),
        Some(cid.as_str()),
        "I4293: in the proposal's room"
    );
    assert_eq!(
        grows(d, &cid, &founder, &m).await,
        Err(RULE_PROPOSAL_EXPIRED),
        "I4293: a withdrawn proposal seats nobody"
    );
}

/// **I4294.**
pub(crate) async fn i4294_the_proposers_second_device_withdraws_it(e: &crate::Engine) {
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let s = suffix();
    let (founder_seed, device_seed) = (format!("i4294-f-{s}"), format!("i4294-d-{s}"));
    let (cid, founder, m, p) = room_with_accepted_proposal(d, "i4294", &s).await;
    reg(d, &[&device_seed]).await;
    put_bind(
        d,
        &founder_seed,
        &founder_seed,
        &device_seed,
        device_class::LAPTOP,
        &BindOptions::default(),
    )
    .await
    .expect("I4294: the proposer binds a second device");
    assert_eq!(
        d.active_identity_for_occurrence(&id_of(&device_seed))
            .await
            .expect("I4294: the device resolves"),
        founder,
        "I4294 premise: the device is the proposer's"
    );
    landed_id(
        e.withdraw_statement(&ts::local_signer(&device_seed), &e2::rid(&p))
            .await
            .expect("I4294: the proposer's second device withdraws the proposal"),
        "I4294",
    );
    assert_eq!(
        grows(d, &cid, &founder, &m).await,
        Err(RULE_PROPOSAL_EXPIRED),
        "I4294: withdrawn by the same person, from another of their keys"
    );
}

/// **I4295.**
pub(crate) async fn i4295_the_proposers_node_cannot_retract_it(e: &crate::Engine) {
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let s = suffix();
    let (founder_seed, node_seed) = (format!("i4295-f-{s}"), format!("i4295-n-{s}"));
    let (cid, founder, m, p) = room_with_accepted_proposal(d, "i4295", &s).await;
    let node = e2::put_key(d, &node_seed, &["node"]).await;
    crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
        d,
        &founder_seed,
        &node_seed,
    )
    .await;
    assert_eq!(
        crate::federation::admission::owner_of(d, &node)
            .await
            .expect("I4295: owner_of")
            .as_deref(),
        Some(founder.as_str()),
        "I4295 premise: the node is the proposer's"
    );
    // Whatever the door answers the node's withdrawal, it is judged on WHO
    // signed it: not refused for its shape or its placement.
    match e
        .withdraw_statement(&ts::local_signer(&node_seed), &e2::rid(&p))
        .await
    {
        Err(err) => {
            let t = err.to_string();
            assert!(
                !t.contains("edition2_family_invalid")
                    && !t.contains("authorship_undetermined")
                    && !t.contains(COMPOSER_PLACED_APART_FROM_TARGET),
                "I4295: the node's withdrawal is well formed and well placed; it is refused, \
                 if at all, for who signed it: {t}"
            );
        }
        // KR-fix21 — kept, it must not have landed: held for who signed it.
        Ok(out) => {
            held_not_landed(
                d,
                &out,
                &e2::rid(&p),
                &[NOT_ADMITTED, WRITE_SCOPE_REFUSED],
                "I4295: the proposer's NODE",
            )
            .await;
        }
    }
    assert_eq!(
        grows(d, &cid, &founder, &m).await,
        Ok(()),
        "I4295: a node's withdrawal does not retract its owner's proposal"
    );
}

/// **I4296.**
pub(crate) async fn i4296_a_non_member_cannot_withdraw(e: &crate::Engine) {
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let s = suffix();
    let (stranger_seed, other_room) = (format!("i4296-x-{s}"), format!("i4296-b-{s}"));
    let (cid, founder, m, p) = room_with_accepted_proposal(d, "i4296", &s).await;
    reg(d, &[&stranger_seed, &other_room]).await;
    let (stranger, other_room) = (id_of(&stranger_seed), id_of(&other_room));
    // The stranger has a room of their own.
    found_community(d, &other_room, "quorum:1/1", &[&stranger], &[])
        .await
        .expect("I4296: the stranger founds another room");

    // Through the verb: placed in the target's room, where they are no member.
    // KR-fix21 — the door KEEPS the statement and admits nothing (a refusal
    // that reads other rows is a hold); the witness requires it did not land.
    not_retracted(
        d,
        e.withdraw_statement(&ts::local_signer(&stranger_seed), &e2::rid(&p))
            .await,
        &e2::rid(&p),
        &[WRITE_SCOPE_REFUSED, NOT_ADMITTED],
        "I4296: a non-member of the target's room cannot withdraw in it",
    )
    .await;

    // By hand, naming THEIR room on a withdrawal of the other room's row:
    // refused by name, before membership in their own room is asked.
    let target = d
        .get_attestation(&e2::rid(&p))
        .await
        .expect("I4296: reads")
        .expect("I4296: the proposal landed");
    let target_id = e2::rid(&p);
    let draft = e
        .statement_draft(
            attestation_type::WITHDRAWS,
            &serde_json::json!({"cohort_scope": COMMUNITY, "community_id": other_room}),
            &stranger,
            &hex::encode(e2::kid_digest(&stranger_seed)),
            &target.attested_key_id,
            e2::ms(Utc::now()),
            Some(target_id.as_str()),
        )
        .await
        .expect("I4296: the draft");
    let statement = draft.assemble(
        e2::signing_key(&stranger_seed)
            .sign(&draft.sig_structure)
            .expect("I4296: signed"),
    );
    let err = e
        .submit_voice(&statement)
        .await
        .expect_err("I4296: a withdrawal naming another room than its target's");
    assert!(
        err.to_string().contains(COMPOSER_PLACED_APART_FROM_TARGET),
        "I4296: refused by name: {err}"
    );
    assert_eq!(
        grows(d, &cid, &founder, &m).await,
        Ok(()),
        "I4296: the proposal still stands"
    );
}

/// **I4299** (rev 2). The refusal of a retraction "placed apart" covers only
/// one that CLAIMS a room. What stops a NON-attester from retracting a
/// room-scoped row by placing the retraction at the commons or at `self`,
/// naming no room, is the withdraws admission rule
/// (`admission::resolve_withdraws_admission_rule_at`: the producer, a listed
/// subject, the named proxies): refused `federation_withdraws_not_admitted`,
/// and the proposal stands. And the converse: the row's OWN attester places
/// their retraction of that room-scoped row at the commons, naming no room,
/// and it lands (the placement rule does not touch it).
pub(crate) async fn i4299_a_retraction_placed_outside_any_room(e: &crate::Engine) {
    use crate::federation::types::cohort_scope::{FEDERATION, SELF};
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let s = suffix();
    let (founder_seed, stranger_seed) = (format!("i4299-f-{s}"), format!("i4299-x-{s}"));
    let (cid, founder, m, p) = room_with_accepted_proposal(d, "i4299", &s).await;
    reg(d, &[&stranger_seed]).await;
    let target = d
        .get_attestation(&e2::rid(&p))
        .await
        .expect("I4299: reads")
        .expect("I4299: the proposal landed");
    assert_eq!(
        target.cohort_scope, COMMUNITY,
        "I4299 premise: the target is a room-scoped row"
    );
    // A `withdraws` of the proposal placed at `scope`, naming no room.
    let outside = |scope: &'static str| {
        let mut input = crate::federation::EmitAttestationInput::with_envelope(
            attestation_type::WITHDRAWS,
            crate::federation::envelope::EnvelopeCore::from_value(
                crate::federation::withdraws_attestation_envelope(
                    &target.attestation_id,
                    &target.attestation_type,
                ),
            )
            .expect("I4299: the envelope"),
            scope,
        );
        input.attested_key_id = Some(target.attested_key_id.clone());
        input
    };
    // A third party: not the attester, not a subject, no member.
    for scope in [SELF, FEDERATION] {
        // KR-fix21 — the shared emit path answers `Ok(row id)` for a held
        // statement too: the row's state is read back.
        let result = match e
            .emit_attestation(&ts::local_signer(&stranger_seed), outside(scope))
            .await
        {
            Ok(id) => e.voice_status(&id).await,
            Err(err) => Err(err),
        };
        not_retracted(
            d,
            result,
            &target.attestation_id,
            &[NOT_ADMITTED],
            &format!(
                "I4299: a non-attester does not retract by placing at {scope}, outside the room"
            ),
        )
        .await;
    }
    assert_eq!(
        grows(d, &cid, &founder, &m).await,
        Ok(()),
        "I4299: the proposal still stands"
    );
    // (That growth seated M on the proposal; a fresh room for the converse.)
    let s2 = suffix();
    let founder2_seed = format!("i4299b-f-{s2}");
    let (cid2, founder2, m2, p2) = room_with_accepted_proposal(d, "i4299b", &s2).await;
    let target2 = d
        .get_attestation(&e2::rid(&p2))
        .await
        .expect("I4299: reads")
        .expect("I4299: the second proposal landed");
    let mut own = crate::federation::EmitAttestationInput::with_envelope(
        attestation_type::WITHDRAWS,
        crate::federation::envelope::EnvelopeCore::from_value(
            crate::federation::withdraws_attestation_envelope(
                &target2.attestation_id,
                &target2.attestation_type,
            ),
        )
        .expect("I4299: the envelope"),
        FEDERATION,
    );
    own.attested_key_id = Some(target2.attested_key_id.clone());
    e.emit_attestation(&ts::local_signer(&founder2_seed), own)
        .await
        .expect("I4299: the attester's own retraction, placed at the commons, lands");
    assert_eq!(
        grows(d, &cid2, &founder2, &m2).await,
        Err(RULE_PROPOSAL_EXPIRED),
        "I4299: and it retracts the proposal"
    );
    let _ = founder_seed;
}

/// A plain `scores` row by `by` about `subject`, placed in `room`
/// (`withdraws_order_roster_receipt_invariants`' shape).
fn room_row(by: &str, subject: &str, room: &str) -> Attestation {
    const PLAIN: &str = "expertise:cardiology:en:v1";
    let env = serde_json::json!({
        "dimension": PLAIN,
        "score": crate::federation::namespace::registry::in_class_score(PLAIN),
        "confidence": 0.9,
        "community_id": room,
        "community_key_id": room,
    });
    let mut r = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), by, by, &env);
    r.attestation_type = attestation_type::SCORES.into();
    r.weight = None;
    r.cohort_scope = COMMUNITY.into();
    r.subject_key_ids = vec![subject.to_owned()];
    ts::seal_row_in_place(by, &mut r);
    r
}

/// How many voices of row `id` `from` serves `requester`.
async fn served_of(from: &dyn FederationDirectory, requester: &str, id: &str) -> usize {
    use crate::federation::edition2::names::RowId;
    let (mut n, mut cursor) = (0, None);
    loop {
        let page = crate::federation::edition2::serve::statements_served_to(
            from,
            cursor.as_ref(),
            256,
            Some(requester),
        )
        .await
        .expect("the serve listing");
        n += page
            .statements
            .iter()
            .filter(|st| RowId::of_statement(&st.bytes).map(|r| r.hex()).as_deref() == Some(id))
            .count();
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    n
}

/// **I4310** (KR-fix17 rev 3; CC 2.4.1.1, the table's rule 1: "the key that
/// signed T (T.attesting_key_id) | Condition: none").
///
/// K joins a room, writes a row there, and LEAVES (a resignation). Then:
/// - K writing anything else to the room is refused, and nothing lands;
/// - K retracting SOMEONE ELSE's row in the room is refused;
/// - K retracts their OWN row with the host verb: it lands, placed in the
///   room (the target's scope and room), and names the row it retracts;
/// - the retraction's audience is the target's: a member (the founder) is
///   served it; a non-member is not;
/// - THE EDGE: K, no longer in the audience, is served NEITHER the room's
///   rows NOR their own retraction back. The node K submitted on keeps the
///   retraction (it holds what it admitted); a second node pulling AS K, or
///   as a stranger, receives no voice of the room's rows or the retraction.
///   Admission depended on nothing K would have to be served.
pub(crate) async fn i4310_a_former_member_retracts_their_own_row(
    e: &crate::Engine,
    other_node: &crate::Engine,
) {
    use crate::federation::open_admission_invariants::bodies::remove;
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let dir_b = other_node.federation_directory();
    let db: &dyn FederationDirectory = dir_b.as_dyn_directory();
    let s = suffix();
    let (k_seed, x_seed) = (format!("i4310-m-{s}"), format!("i4310-x-{s}"));
    // `room_with_accepted_proposal` names the invitee `{tag}-m-{s}`: K.
    let (cid, founder, k, _p) = room_with_accepted_proposal(d, "i4310", &s).await;
    reg(d, &[&x_seed]).await;
    let stranger = id_of(&x_seed);
    assert_eq!(grows(d, &cid, &founder, &k).await, Ok(()), "I4310: K joins");

    // While a member: K's own row in the room, and the founder's.
    let mine = room_row(&k, &founder, &cid);
    put_e2(d, &mine)
        .await
        .expect("I4310: a member's row in the room");
    let theirs = room_row(&founder, &founder, &cid);
    put_e2(d, &theirs)
        .await
        .expect("I4310: the founder's row in the room");

    // K leaves (a member's own act).
    let left = remove(d, &cid, &[&k], &k, Utc::now()).await;
    assert!(
        matches!(
            left,
            Ok(crate::federation::edition2::ingest::StatementOutcome::Row { .. })
        ),
        "I4310: K resigns: {left:?}"
    );
    assert!(
        !d.active_community_members(&cid)
            .await
            .expect("I4310: reads")
            .iter()
            .any(|m| m.key_id == k),
        "I4310 premise: K is a FORMER member"
    );
    let k_signer = ts::local_signer(&k_seed);

    // Anything else K writes to the room: refused, nothing lands.
    let late = room_row(&k, &founder, &cid);
    put_e2(d, &late)
        .await
        .expect_err("I4310: a former member writes nothing new to the room");
    assert!(
        d.get_attestation(&e2::rid(&late))
            .await
            .expect("I4310: reads")
            .is_none(),
        "I4310: the former member's new row did not land"
    );

    // Someone else's row: refused (the scope gate runs before the withdraws
    // admission rule, so either may name it).
    // KR-fix21 — kept and not landed: held for who they are in the room.
    not_retracted(
        d,
        e.withdraw_statement(&k_signer, &e2::rid(&theirs)).await,
        &e2::rid(&theirs),
        &[WRITE_SCOPE_REFUSED, NOT_ADMITTED],
        "I4310: a former member does not retract another's row",
    )
    .await;

    // Their OWN row: retracted, in the room.
    let wid = landed_id(
        e.withdraw_statement(&k_signer, &e2::rid(&mine))
            .await
            .expect("I4310: a former member retracts their own room row"),
        "I4310",
    );
    let w = d
        .get_attestation(&wid)
        .await
        .expect("I4310: reads")
        .expect("I4310: the retraction landed");
    assert_eq!(
        w.cohort_scope, COMMUNITY,
        "I4310: placed in the room's scope"
    );
    assert_eq!(
        crate::federation::admission::envelope_cohort_target(&w.attestation_envelope)
            .expect("I4310: one room"),
        Some(cid.as_str()),
        "I4310: in the row's own room"
    );
    assert!(
        d.list_attestations_referencing(&e2::rid(&mine))
            .await
            .expect("I4310: reads")
            .iter()
            .any(|r| r.attestation_id == wid),
        "I4310: the room's fold reads the row's retraction"
    );

    // Served to the room's audience, not outside it.
    assert!(
        served_of(d, &founder, &wid).await >= 1,
        "I4310: a member of the room is served the retraction"
    );
    assert_eq!(
        served_of(d, &stranger, &wid).await,
        0,
        "I4310: a non-member is not served it"
    );
    // The edge: the former member is served nothing of the room, their own
    // retraction included.
    let theirs_id = e2::rid(&theirs);
    assert_eq!(
        served_of(d, &k, &wid).await,
        0,
        "I4310: the former member is not served their own retraction back"
    );
    assert_eq!(
        served_of(d, &k, &theirs_id).await,
        0,
        "I4310: nor the room's rows"
    );
    // A second node pulling as the former member, then as a stranger.
    reg(db, &[&x_seed, &k_seed]).await;
    deliver(d, db, &k).await;
    deliver(d, db, &stranger).await;
    for (what, id) in [("the retraction", &wid), ("a room row", &theirs_id)] {
        let row = crate::federation::edition2::store::id_of_hex(id)
            .map(crate::federation::edition2::names::RowId)
            .expect("I4310: a row id");
        assert!(
            db.edition2_voices(&row)
                .await
                .expect("I4310: reads")
                .is_empty(),
            "I4310: a node pulling as the former member or a stranger holds no voice of {what}"
        );
    }
    // The node K submitted on keeps the retraction it admitted.
    assert!(
        d.get_attestation(&wid)
            .await
            .expect("I4310: reads")
            .is_some(),
        "I4310: the submitting node holds the retraction"
    );
}

/// **I4311** (KR-fix17 rev 3; CC 2.4.1.1 rule 0). A COUNTED row is a
/// quorum's act and has no author: the holder who signed its FIRST voice
/// cannot retract it alone. Two holders land a grant from the root; holder 1
/// drafts an authored withdrawal of it with the host verb
/// (`withdraw_statement_draft`), signs it and submits it: refused
/// `federation_withdraws_not_admitted`, and the grant still stands. The
/// row's "attester" is holder 1 (its first voice), which is exactly what the
/// author's rule must not read as authorship.
pub(crate) async fn i4311_one_voice_cannot_retract_a_counted_row(e: &crate::Engine) {
    use crate::federation::edition2::fixture_genesis as fg;
    use crate::federation::edition2::ingest::{put_statement, INGEST_TIER};
    use ciris_verify_core::cde::{self, Value};
    use ciris_verify_core::edition2::{row_ref, sign_row_statement};
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let c = fg::bundle_v2();
    let s = suffix();
    let (worker_seed, owner_seed) = (format!("i4311-w-{s}"), format!("i4311-o-{s}"));
    let worker = e2::put_key(d, &worker_seed, &["node"]).await;
    e2::put_key(d, &owner_seed, &["user"]).await;
    crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
        d,
        &owner_seed,
        &worker_seed,
    )
    .await;
    // From the bundle's own instant, never the wall clock.
    let at = c.asserted_at_ms + 120_000;
    let map = |members: Vec<(&str, Value)>| {
        let mut m: Vec<(Value, Value)> = members
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_owned()), v))
            .collect();
        m.sort_by_key(|(k, _)| cde::encode(k));
        Value::Map(m)
    };
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        (
            "dimension",
            Value::Text(crate::federation::trust_root::TRUST_CONFERS_DIMENSION.to_owned()),
        ),
        ("refs", map(vec![("head", row_ref(&c.object_id))])),
        (
            "scope",
            Value::Array(vec![Value::Text("infra:attest:build_manifest".to_owned())]),
        ),
    ]);
    let family = ciris_verify_core::namespace_match::family_id(
        crate::federation::edition2::typed::TRUST_PREFIX,
    );
    let mut grant_id = None;
    for i in 0..2 {
        let st = sign_row_statement(
            &c.holder_key(i),
            c.holder_identity_ref(i),
            &worker,
            attestation_type::DELEGATES_TO,
            &family,
            &payload,
            vec![],
        )
        .expect("I4311: a holder signs the grant");
        grant_id = crate::federation::edition2::names::RowId::of_statement(&st);
        put_statement(d, &st, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I4311: holder {}'s voice: {e}", i + 1));
    }
    let grant_id = grant_id.expect("I4311: a row id").hex();
    let grant = d
        .get_attestation(&grant_id)
        .await
        .expect("I4311: reads")
        .expect("I4311: two holders land the counted grant");
    assert!(
        crate::federation::admission::is_counted_row(&grant),
        "I4311 premise: the grant is a counted row (no author)"
    );
    assert_eq!(
        grant.attesting_key_id,
        c.holder_identity_ref(0),
        "I4311 premise: its attester is only the signer of its first voice"
    );
    // Holder 1, alone, by the author's rule.
    let draft = e
        .withdraw_statement_draft(
            &grant_id,
            c.holder_identity_ref(0),
            &hex::encode(fg::kid_of(fg::HOLDER_SEEDS[0])),
            at + 60_000,
        )
        .await
        .expect("I4311: the drafted withdrawal");
    let statement = draft.assemble(
        c.holder_key(0)
            .sign(&draft.sig_structure)
            .expect("I4311: holder 1 signs"),
    );
    // KR-fix21 — kept and not landed, by name.
    not_retracted(
        d,
        e.submit_voice(&statement).await,
        &grant_id,
        &[NOT_ADMITTED],
        "I4311: one voice of a counted row does not retract it alone",
    )
    .await;
    assert!(
        d.get_attestation(&grant_id)
            .await
            .expect("I4311: reads")
            .is_some(),
        "I4311: the counted grant still stands"
    );

    // Rev 5 — THE RULE ITSELF, for a counted row no earlier rule intercepts.
    // The door above refused through `check_root_grant_withdrawal`, which
    // runs before the producer rule. Asked directly, the producer rule
    // (`resolve_withdraws_admission_rule_at`, where any counted row an
    // earlier rule does not cover arrives) must not admit the signer of the
    // first voice either: before rev 5 its raw line `issuer ==
    // target.attesting_key_id` answered rule 1 for exactly this pair.
    for (who, issuer) in [
        ("the signer of the first voice", c.holder_identity_ref(0)),
        ("the signer of the second voice", c.holder_identity_ref(1)),
    ] {
        match crate::federation::admission::resolve_withdraws_admission_rule(d, issuer, &grant)
            .await
        {
            Err(err) => assert_eq!(
                err.kind(),
                "federation_withdraws_not_admitted",
                "I4311: {who}, by the producer rule: {err}"
            ),
            Ok(rule) => panic!(
                "I4311: {who} retracts a counted row alone, as rule {rule}: a counted target \
                 never reaches rule 1"
            ),
        }
    }
    // Rev 6 — nor a SUBJECT it names (rule 2), nor anyone by rules 3 or 4:
    // "Rules 1 to 4 do not reach T". The same counted row, read as naming a
    // subject S (the row as held, with `subject_key_ids` set: no fixture
    // lands a counted row that names a subject and that no earlier rule
    // intercepts, so the rule is asked directly). Before rev 6, S was rule 2.
    let subject = e2::put_key(d, &format!("i4311-s-{s}"), &["user"]).await;
    let mut about_s = grant.clone();
    about_s.subject_key_ids = vec![subject.clone()];
    let err = crate::federation::admission::resolve_withdraws_admission_rule(d, &subject, &about_s)
        .await
        .expect_err("I4311: a named subject does not undo a quorum's act alone");
    assert_eq!(
        err.kind(),
        "federation_withdraws_not_admitted",
        "I4311: the subject of a counted row, by the producer rule: {err}"
    );
    assert!(
        !crate::federation::admission::counted_row_is_one_keys_act(d, &grant)
            .await
            .expect("I4311: reads"),
        "I4311: a counted grant from the root is a quorum's act, not one key's"
    );
    // Control: an AUTHORED row's author is still rule 1.
    let (_cid, founder, _m, p) = room_with_accepted_proposal(d, "i4311", &suffix()).await;
    let authored = d
        .get_attestation(&e2::rid(&p))
        .await
        .expect("I4311: reads")
        .expect("I4311: the proposal landed");
    assert!(
        !crate::federation::admission::is_counted_row(&authored),
        "I4311 control premise: the proposal is authored"
    );
    assert_eq!(
        crate::federation::admission::resolve_withdraws_admission_rule(d, &founder, &authored)
            .await
            .expect("I4311 control: the author retracts their own row"),
        1,
        "I4311 control: rule 1 is unchanged for an authored row"
    );
}

/// **I4312** (KR-fix17 rev 6; CC 2.4.1.1). What a subject HAS is their own
/// acts. The consent a person gave is theirs to take back: K accepts an
/// invitation (K's own authored row), then withdraws that acceptance with
/// the host verb: admitted as the producer's own retraction, stamped rule 1
/// (`withdraws_admission_rule`, what CC 2.4.1.1 says a substrate SHOULD
/// record). The proposal K answered is the founder's and is untouched. (A
/// member's resignation, the other own act, is I4310's first leg.)
pub(crate) async fn i4312_a_subject_takes_back_their_own_act(e: &crate::Engine) {
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let s = suffix();
    let (cid, founder, k_seed) = (
        format!("i4312-c-{s}"),
        format!("i4312-f-{s}"),
        format!("i4312-k-{s}"),
    );
    reg(d, &[&cid, &founder, &k_seed]).await;
    let (cid, founder, k) = (id_of(&cid), id_of(&founder), id_of(&k_seed));
    found_community(d, &cid, "quorum:1/1", &[&founder], &[])
        .await
        .expect("I4312: the founder founds the room");
    let now = Utc::now();
    let p = proposal(
        &founder,
        COMMUNITY,
        &cid,
        &k,
        None,
        now,
        Some(Duration::days(7)),
    );
    put_e2(d, &p).await.expect("I4312: the invitation");
    let acceptance = reply(&k, &k, &p, true, now);
    put_e2(d, &acceptance).await.expect("I4312: K accepts");
    let wid = landed_id(
        e.withdraw_statement(&ts::local_signer(&k_seed), &e2::rid(&acceptance))
            .await
            .expect("I4312: K takes back the consent K gave"),
        "I4312",
    );
    let w = d
        .get_attestation(&wid)
        .await
        .expect("I4312: reads")
        .expect("I4312: the withdrawal landed");
    assert_eq!(
        w.withdraws_admission_rule,
        Some(1),
        "I4312: recorded as the producer's own retraction"
    );
    assert_eq!(w.attesting_key_id, k, "I4312: K's own row");
    assert!(
        d.get_attestation(&e2::rid(&p))
            .await
            .expect("I4312: reads")
            .is_some(),
        "I4312: the founder's proposal is untouched"
    );
}

/// Deliver `from`'s edition-2 plane to `to` as `requester` pulls it.
async fn deliver(from: &dyn FederationDirectory, to: &dyn FederationDirectory, requester: &str) {
    use crate::federation::edition2::ingest::{put_statement, INGEST_TIER};
    let mut cursor = None;
    loop {
        let page = crate::federation::edition2::serve::statements_served_to(
            from,
            cursor.as_ref(),
            256,
            Some(requester),
        )
        .await
        .expect("the serve listing");
        let Some(next) = page.next else { break };
        cursor = Some(next);
        for st in page.statements {
            let _ = put_statement(to, &st.bytes, None, INGEST_TIER).await;
        }
    }
}

/// **I4297 / I4298.** On node A the proposer drafts the withdrawal
/// (`withdraw_statement_draft`), signs it outside the Engine and submits it:
/// it lands. Node B is offered the same statement BEFORE it holds the
/// proposal: it does not land (it waits on its target, or is refused
/// retryably), and nothing reads as withdrawn. B then pulls A's feed as the
/// proposer; both nodes hold the landed withdrawal.
pub(crate) async fn i4297_i4298_the_target_unheld_wait_and_convergence(
    a: &crate::Engine,
    b: &crate::Engine,
) {
    use crate::federation::edition2::names::RowId;
    let (dir_a, dir_b) = (a.federation_directory(), b.federation_directory());
    let (da, db): (&dyn FederationDirectory, &dyn FederationDirectory) =
        (dir_a.as_dyn_directory(), dir_b.as_dyn_directory());
    let s = suffix();
    let founder_seed = format!("i4297-f-{s}");
    let (_cid, founder, _m, p) = room_with_accepted_proposal(da, "i4297", &s).await;
    let draft = a
        .withdraw_statement_draft(
            &e2::rid(&p),
            &founder,
            &hex::encode(e2::kid_digest(&founder_seed)),
            e2::ms(Utc::now()),
        )
        .await
        .expect("I4297: the drafted withdrawal");
    let statement = draft.assemble(
        e2::signing_key(&founder_seed)
            .sign(&draft.sig_structure)
            .expect("I4297: signed outside the Engine"),
    );
    let wid = RowId::of_statement(&statement).expect("I4297: a row id");

    // B knows the signer's key and nothing else: the target is not held.
    reg(db, &[&founder_seed]).await;
    match b.submit_voice(&statement).await {
        Ok(o) => assert!(!o.is_seated(), "I4297: it waits on its target: {o:?}"),
        Err(err) => assert_eq!(
            err.kind(),
            "federation_withdraws_target_unheld",
            "I4297: an unheld target is the retryable wait: {err}"
        ),
    }
    assert!(
        db.get_attestation(&wid.hex())
            .await
            .expect("I4297: reads")
            .is_none(),
        "I4297: nothing landed on B without the target"
    );

    // A: the drafted withdrawal lands.
    let o = a
        .submit_voice(&statement)
        .await
        .expect("I4298: the drafted withdrawal is admitted on A");
    assert!(o.is_seated(), "I4298: landed on A: {o:?}");

    // B pulls A's feed as the proposer (twice: the room and the proposal
    // first, then what waited on them).
    deliver(da, db, &founder).await;
    deliver(da, db, &founder).await;
    for (node, d) in [("A", da), ("B", db)] {
        assert!(
            d.get_attestation(&wid.hex())
                .await
                .expect("I4298: reads")
                .is_some(),
            "I4298: node {node} holds the landed withdrawal"
        );
    }
}

#[cfg(feature = "sqlite")]
async fn sqlite_engine(seed: &str) -> crate::Engine {
    crate::Engine::with_signer(ts::local_signer(seed), "sqlite::memory:")
        .await
        .expect("a sqlite Engine")
}

#[cfg(feature = "postgres")]
async fn pg_engine(seed: &str) -> Option<crate::Engine> {
    let dsn = crate::test_pg::isolated_dsn()?;
    Some(
        crate::Engine::with_signer(ts::local_signer(seed), &dsn)
            .await
            .expect("a postgres Engine"),
    )
}

macro_rules! on_one_engine {
    ($sqlite:ident, $postgres:ident, $body:ident, $seed:literal) => {
        #[cfg(feature = "sqlite")]
        #[tokio::test]
        async fn $sqlite() {
            Box::pin($body(&sqlite_engine($seed).await)).await;
        }

        #[cfg(feature = "postgres")]
        #[tokio::test]
        async fn $postgres() {
            let Some(e) = pg_engine($seed).await else {
                return;
            };
            Box::pin($body(&e)).await;
        }
    };
}

on_one_engine!(
    i4293_sqlite,
    i4293_postgres,
    i4293_a_member_withdraws_their_own_proposal,
    "i4293-engine"
);
on_one_engine!(
    i4294_sqlite,
    i4294_postgres,
    i4294_the_proposers_second_device_withdraws_it,
    "i4294-engine"
);
on_one_engine!(
    i4295_sqlite,
    i4295_postgres,
    i4295_the_proposers_node_cannot_retract_it,
    "i4295-engine"
);
on_one_engine!(
    i4299_sqlite,
    i4299_postgres,
    i4299_a_retraction_placed_outside_any_room,
    "i4299-engine"
);
on_one_engine!(
    i4296_sqlite,
    i4296_postgres,
    i4296_a_non_member_cannot_withdraw,
    "i4296-engine"
);

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4297_i4298_sqlite() {
    Box::pin(i4297_i4298_the_target_unheld_wait_and_convergence(
        &sqlite_engine("i4297-a").await,
        &sqlite_engine("i4297-b").await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4297_i4298_postgres() {
    let (Some(a), Some(b)) = (pg_engine("i4297-a").await, pg_engine("i4297-b").await) else {
        return;
    };
    Box::pin(i4297_i4298_the_target_unheld_wait_and_convergence(&a, &b)).await;
}

on_one_engine!(
    i4312_sqlite,
    i4312_postgres,
    i4312_a_subject_takes_back_their_own_act,
    "i4312-engine"
);
on_one_engine!(
    i4311_sqlite,
    i4311_postgres,
    i4311_one_voice_cannot_retract_a_counted_row,
    "i4311-engine"
);

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4310_sqlite() {
    Box::pin(i4310_a_former_member_retracts_their_own_row(
        &sqlite_engine("i4310-a").await,
        &sqlite_engine("i4310-b").await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4310_postgres() {
    let (Some(a), Some(b)) = (pg_engine("i4310-a").await, pg_engine("i4310-b").await) else {
        return;
    };
    Box::pin(i4310_a_former_member_retracts_their_own_row(&a, &b)).await;
}
