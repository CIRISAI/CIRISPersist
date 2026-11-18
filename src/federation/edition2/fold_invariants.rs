//! v62.0.0 (wave G0; CC 2.7.3) — witnesses of the held/concluded fold
//! ([`super::fold`]). Each store-facing body runs on sqlite and postgres.
//!
//! - **I3550** the reason tokens are pinned in append order, and a read key
//!   has one spelling per input.
//! - **I3551** the attempt: `hold` outside an attempt is the plain refusal;
//!   inside, the first marked condition and every declared read are recorded,
//!   and the offered voice is seen only by the attempt's own row.
//! - **I3552** the fold store round-trips on both backends: a held record,
//!   its reads as a dependency index, `since_us` kept while the reason is
//!   unchanged, a concluded record clears the hold and replaces the reads,
//!   and the held page is in row-id order.
//! - **I3553** `count_short` is one fold reason: an owner binding voiced by
//!   its owner alone is held with reason `count_short` (`why_held`), and the
//!   node's voice concludes it and clears the reason.
//! - **I3554** the owner exemplar (`check_config_self_or_owner_admission`),
//!   binding FIRST: the owner's `config:*` row about its node concludes; the
//!   owner's withdrawal of the binding UN-concludes it (no typed row, reason
//!   `owner_unseated`).
//! - **I3555** the owner exemplar, config row FIRST: held `owner_unseated`
//!   (never refused), still held while the binding is short of the node's
//!   voice, and concluded by the re-fold when the node's voice lands the
//!   binding. With I3554, the concluded set is the same in either arrival
//!   order.
//! - **I3556** the steward-binding exemplar
//!   (`check_user_target_steward_binding_admission`): a custody binding of a
//!   person whose age no witness proves is HELD with reason
//!   `steward_unproven`, not refused, and has no typed row.
//! - **I3558** (v4) a replicated membership change held `count_short`
//!   concludes on a later (local) voice under its stored REPLICATED arrival.
//! - **I3559** (v4) the steward-binding exemplar concludes when a witness
//!   proves the person a minor, and un-concludes when a later witness proves
//!   an adult.
//! - **I3557** (v2) an ambiguous owner (`AmbiguousNodeOwner`) holds the
//!   row that read it, reason `owner_ambiguous`, and the withdrawal of one
//!   binding concludes it by re-fold.

use super::fixture_switch as e2;
use super::fold::{self, reason, Dep, FoldRecord};
use super::ingest::StatementOutcome;
use super::names::RowId;
use crate::federation::types::{attestation_type, identity_type, Attestation};
use crate::federation::{Error, FederationDirectory};
use std::collections::BTreeSet;

fn rid(n: u8) -> RowId {
    RowId([n; 32])
}

/// I3550: the tokens, in append order, and the read-key spellings.
#[test]
fn i3550_reason_tokens_and_read_keys_are_pinned() {
    assert_eq!(
        reason::ALL,
        &[
            "count_short",
            "owner_unseated",
            "steward_unproven",
            "amendment_digest_mismatch",
            "refold_refused",
            "refolding",
            "owner_ambiguous",
        ],
        "I3550: the reason tokens are appended, never reordered"
    );
    assert_eq!(
        Dep::Row(rid(0xab)).read_key(),
        format!("row:{}", "ab".repeat(32)),
        "I3550: row:<hex>"
    );
    assert_eq!(Dep::key("k1").read_key(), "key:k1", "I3550: key:<id>");
    assert_eq!(
        Dep::Family("config:{scope}".to_owned()).read_key(),
        "family:config:{scope}",
        "I3550: family:<family>"
    );
}

/// I3551: the attempt's marks and reads.
#[tokio::test]
async fn i3551_attempt_records_the_first_hold_and_every_read() {
    // Outside an attempt: a plain refusal, nothing recorded anywhere.
    assert!(!fold::in_attempt(), "I3551: no attempt on a bare task");
    let e = fold::hold(reason::OWNER_UNSEATED, Error::InvalidArgument("x".into()));
    assert!(
        matches!(e, Error::InvalidArgument(ref m) if m == "x"),
        "I3551: hold returns the refusal unchanged"
    );
    fold::reads(Dep::key("ignored"));

    let voice = super::voices::Voice {
        iss: "iss".to_owned(),
        kid: [7; 32],
        asserted_at_ms: 1,
    };
    let (out, att) = fold::attempt(rid(1), Some(voice.clone()), async {
        assert!(fold::in_attempt(), "I3551: inside the attempt");
        assert_eq!(
            fold::offered_voice(&rid(1)),
            Some(voice.clone()),
            "I3551: the attempt's own row sees the offered voice"
        );
        assert_eq!(
            fold::offered_voice(&rid(2)),
            None,
            "I3551: another row never sees it"
        );
        fold::reads(Dep::key("owner-of-n"));
        let first = fold::hold(reason::OWNER_UNSEATED, Error::InvalidArgument("a".into()));
        let _second = fold::hold(reason::COUNT_SHORT, Error::InvalidArgument("b".into()));
        Err::<(), Error>(first)
    })
    .await;
    assert!(out.is_err(), "I3551: the gate's refusal comes back");
    let (r, d) = att.held.expect("I3551: the condition is recorded");
    assert_eq!(
        r,
        reason::OWNER_UNSEATED,
        "I3551: the FIRST marked condition"
    );
    assert!(
        d.contains('a'),
        "I3551: the detail is the refusal's text: {d}"
    );
    let want: BTreeSet<String> = [
        Dep::key("owner-of-n").read_key(),
        Dep::Row(rid(1)).read_key(),
    ]
    .into_iter()
    .collect();
    assert_eq!(att.reads, want, "I3551: the declared reads + the row's own");
    assert!(
        !fold::in_attempt(),
        "I3551: the attempt ends with its future"
    );
}

fn record(id: RowId, held: Option<(&str, &str)>, reads: &[&str]) -> FoldRecord {
    FoldRecord {
        row_id: id,
        family: "config:{scope}".to_owned(),
        tier: "federation".to_owned(),
        replicated: id == rid(0x22),
        plane: super::fold::plane::OCCURRENCE.to_owned(),
        slot: "occurrence:i|o".to_owned(),
        held: held.map(|(r, d)| (r.to_owned(), d.to_owned())),
        reads: reads.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// I3552: the fold store, both backends.
pub(crate) async fn fold_store_body(d: &dyn FederationDirectory) {
    let (a, b) = (rid(0x11), rid(0x22));
    d.put_fold_record(&record(
        a,
        Some((reason::OWNER_UNSEATED, "no owner")),
        &["key:n", "row:x"],
    ))
    .await
    .expect("I3552: a held record");
    d.put_fold_record(&record(
        b,
        Some((reason::COUNT_SHORT, "1 of 2")),
        &["key:n"],
    ))
    .await
    .expect("I3552: a second held record");

    let h = d
        .fold_held(&a)
        .await
        .unwrap()
        .expect("I3552: the hold reads back");
    assert_eq!(
        (h.reason.as_str(), h.detail.as_str(), h.tier.as_str()),
        (reason::OWNER_UNSEATED, "no owner", "federation"),
        "I3552: the reason, detail and tier"
    );
    assert_eq!(
        d.fold_dependents(&["key:n".to_owned()]).await.unwrap(),
        vec![a, b],
        "I3552: both rows read key:n, in row-id order"
    );
    assert_eq!(
        d.fold_dependents(&["row:x".to_owned(), "key:none".to_owned()])
            .await
            .unwrap(),
        vec![a],
        "I3552: only a read the record declared selects it"
    );

    // The same reason again keeps since_us; the detail follows.
    d.put_fold_record(&record(
        a,
        Some((reason::OWNER_UNSEATED, "still no owner")),
        &["key:n"],
    ))
    .await
    .unwrap();
    let h2 = d.fold_held(&a).await.unwrap().unwrap();
    assert_eq!(h2.since_us, h.since_us, "I3552: since_us is kept");
    assert_eq!(
        h2.detail, "still no owner",
        "I3552: the detail is the latest"
    );
    assert!(
        d.fold_dependents(&["row:x".to_owned()])
            .await
            .unwrap()
            .is_empty(),
        "I3552: the reads are REPLACED, not merged"
    );

    // Paging, in row-id order.
    let page = d.fold_held_page(None, 1).await.unwrap();
    assert_eq!(
        page.iter().map(|h| h.row_id).collect::<Vec<_>>(),
        vec![a],
        "I3552: the first page"
    );
    let page = d.fold_held_page(Some(&a), 10).await.unwrap();
    assert_eq!(
        page.iter().map(|h| h.row_id).collect::<Vec<_>>(),
        vec![b],
        "I3552: the page after a"
    );

    // Concluded: the hold leaves, the reads stay as recorded.
    d.put_fold_record(&record(a, None, &["key:m"]))
        .await
        .unwrap();
    assert!(
        d.fold_held(&a).await.unwrap().is_none(),
        "I3552: a concluded row has no hold"
    );
    assert_eq!(
        d.fold_dependents(&["key:m".to_owned()]).await.unwrap(),
        vec![a],
        "I3552: a concluded row's reads are indexed (it can un-conclude)"
    );
    assert_eq!(
        fold::held_rows(d, None, 10)
            .await
            .unwrap()
            .iter()
            .map(|h| h.row_id)
            .collect::<Vec<_>>(),
        vec![b],
        "I3552: the reason API lists only what concludes nothing"
    );

    // v4 — the state keeps the arrival, plane and slot of held AND concluded
    // rows; the slot read lists the concluded ones; the boot probe sees a
    // `refolding` row.
    let sa = d
        .fold_state(&a)
        .await
        .unwrap()
        .expect("I3552: a concluded row keeps its state");
    assert!(
        sa.held.is_none() && !sa.replicated,
        "I3552: concluded, local"
    );
    assert_eq!(
        (sa.plane.as_str(), sa.slot.as_str()),
        (super::fold::plane::OCCURRENCE, "occurrence:i|o"),
        "I3552: plane and slot"
    );
    let sb = d.fold_state(&b).await.unwrap().unwrap();
    assert!(
        sb.replicated && sb.held.as_ref().is_some_and(|h| h.replicated),
        "I3552: the replicated arrival is kept on a held row"
    );
    assert_eq!(
        d.fold_slot_rows("occurrence:i|o").await.unwrap(),
        vec![a],
        "I3552: the slot lists its CONCLUDED rows only"
    );
    assert!(
        !d.fold_any_refolding().await.unwrap(),
        "I3552: nothing is refolding"
    );
    d.put_fold_record(&record(b, Some((reason::REFOLDING, "x")), &[]))
        .await
        .unwrap();
    assert!(
        d.fold_any_refolding().await.unwrap(),
        "I3552: the boot probe sees an interrupted re-fold"
    );
}

fn id_of(row: &Attestation) -> RowId {
    super::voices::carried_row_id(row).expect("G0: the row carries its statement")
}

/// The owner binding of `owner` over `node` (the owner's statement).
fn owner_binding(owner: &str, node: &str) -> Attestation {
    crate::federation::tier_ingest::test_support::owner_binding_attestation(
        &uuid::Uuid::new_v4().to_string(),
        owner,
        node,
    )
}

/// The owner's `config:*` report about its node, as the owner's statement.
fn config_row(owner: &str, node: &str) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(owner),
    );
    a.attested_key_id = e2::kid(node);
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": "config:load:v1",
        "score": 1.0,
    });
    e2::row_of(&a, owner)
}

async fn concluded(d: &dyn FederationDirectory, row: &Attestation) -> bool {
    d.get_attestation(&id_of(row).hex())
        .await
        .unwrap()
        .is_some()
}

async fn held_reason(d: &dyn FederationDirectory, row: &Attestation) -> Option<String> {
    fold::why_held(d, &id_of(row))
        .await
        .unwrap()
        .map(|h| h.reason)
}

fn pending(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Pending { .. })
}

/// Land the owner binding: the owner's voice (held, `count_short`), then the
/// node's (concluded).
async fn land_binding(d: &dyn FederationDirectory, binding: &Attestation, node: &str) {
    let o = e2::put_signed(d, binding)
        .await
        .expect("G0: the owner's voice over the binding is kept");
    assert!(pending(&o), "G0: the binding waits for the node: {o:?}");
    let st = e2::carried_statement(binding).expect("G0: the binding's statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("G0: the node's voice over its binding");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "G0: the node's voice lands the binding: {o:?}"
    );
}

/// I3553: `count_short` is one fold reason.
pub(crate) async fn count_short_body(d: &dyn FederationDirectory) {
    let (owner, node) = ("g0-cs-o", "g0-cs-n");
    let _ = e2::put_key(d, owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, node, &[identity_type::NODE]).await;
    let binding = owner_binding(owner, node);
    let o = e2::put_signed(d, &binding).await.expect("I3553: kept");
    assert!(pending(&o), "I3553: held: {o:?}");
    assert_eq!(
        held_reason(d, &binding).await.as_deref(),
        Some(reason::COUNT_SHORT),
        "I3553: the binding concludes nothing for want of the node's voice"
    );
    let st = e2::carried_statement(&binding).expect("I3553: statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("I3553: the node's voice");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3553: concluded: {o:?}"
    );
    assert_eq!(
        held_reason(d, &binding).await,
        None,
        "I3553: a concluded row has no reason"
    );
}

/// I3554: binding first; the config row concludes; the binding's withdrawal
/// un-concludes it.
pub(crate) async fn owner_binding_first_body(d: &dyn FederationDirectory) {
    let (owner, node) = ("g0-ob1-o", "g0-ob1-n");
    let _ = e2::put_key(d, owner, &[identity_type::USER]).await;
    let node_kid = e2::put_key(d, node, &[identity_type::NODE]).await;
    let binding = owner_binding(owner, node);
    land_binding(d, &binding, node).await;
    assert_eq!(
        crate::federation::admission::owner_of(d, &node_kid)
            .await
            .unwrap()
            .as_deref(),
        Some(e2::kid(owner).as_str()),
        "I3554 precondition: the binding seats the owner"
    );

    let config = config_row(owner, node);
    let o = e2::put_signed(d, &config)
        .await
        .expect("I3554: the owner's config row");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3554: the owner speaks for its node: concluded: {o:?}"
    );
    assert!(concluded(d, &config).await, "I3554: the typed row is held");
    assert_eq!(held_reason(d, &config).await, None, "I3554: no reason");

    // The owner withdraws the binding: the seat empties, and the config row,
    // whose fold read it, is re-folded out of its typed table.
    let w = e2::composer_of(attestation_type::WITHDRAWS, &binding, owner);
    let o = e2::put_signed(d, &w)
        .await
        .expect("I3554: the owner's withdrawal of its binding");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3554: the withdrawal concludes: {o:?}"
    );
    assert_eq!(
        crate::federation::admission::owner_of(d, &node_kid)
            .await
            .unwrap(),
        None,
        "I3554 precondition: the withdrawn binding seats nobody"
    );
    assert!(
        !concluded(d, &config).await,
        "I3554: the config row is UN-concluded: no typed row"
    );
    assert_eq!(
        held_reason(d, &config).await.as_deref(),
        Some(reason::OWNER_UNSEATED),
        "I3554: held, and says why"
    );
    assert!(
        !d.edition2_voices(&id_of(&config)).await.unwrap().is_empty(),
        "I3554: its statement is still held"
    );
}

/// I3555: config row first; held, then concluded by the re-fold.
pub(crate) async fn config_first_body(d: &dyn FederationDirectory) {
    let (owner, node) = ("g0-ob2-o", "g0-ob2-n");
    let _ = e2::put_key(d, owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, node, &[identity_type::NODE]).await;

    let config = config_row(owner, node);
    let o = e2::put_signed(d, &config)
        .await
        .expect("I3555: an unseated owner's config row is HELD, never refused");
    assert!(pending(&o), "I3555: held: {o:?}");
    assert!(!concluded(d, &config).await, "I3555: no typed row");
    assert_eq!(
        held_reason(d, &config).await.as_deref(),
        Some(reason::OWNER_UNSEATED),
        "I3555: the reason"
    );

    // The owner's voice alone: the binding is short; the config row stays.
    let binding = owner_binding(owner, node);
    let o = e2::put_signed(d, &binding)
        .await
        .expect("I3555: owner voice");
    assert!(pending(&o), "I3555: the binding is held: {o:?}");
    assert!(
        !concluded(d, &config).await,
        "I3555: a held binding seats nobody: still held"
    );

    // The node's voice lands the binding; the re-fold concludes the config row.
    let st = e2::carried_statement(&binding).expect("I3555: statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("I3555: the node's voice");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3555: the binding concludes: {o:?}"
    );
    assert!(
        concluded(d, &binding).await && concluded(d, &config).await,
        "I3555: both rows are concluded, as when the binding came first (I3554)"
    );
    assert_eq!(held_reason(d, &config).await, None, "I3555: no reason left");
}

/// I3556: the steward-binding exemplar's hold.
pub(crate) async fn steward_unproven_body(d: &dyn FederationDirectory) {
    let (guardian, person) = ("g0-st-g", "g0-st-p");
    let _ = e2::put_key(d, guardian, &[identity_type::USER]).await;
    let _ = e2::put_key(d, person, &[identity_type::USER]).await;
    // A custody claim (the owner-binding marker) over a person no age
    // witness speaks for.
    let binding = owner_binding(guardian, person);
    let o = e2::put_signed(d, &binding)
        .await
        .expect("I3556: an unproven custody claim is HELD, never refused");
    assert!(pending(&o), "I3556: held: {o:?}");
    assert!(!concluded(d, &binding).await, "I3556: no typed row");
    assert_eq!(
        held_reason(d, &binding).await.as_deref(),
        Some(reason::STEWARD_UNPROVEN),
        "I3556: the steward-binding gate's own reason (it runs before the count)"
    );
}

/// I3557: an ambiguous owner is a fold reason, not an error. Two owner
/// bindings the node voiced both count (C557: the seat reads as unowned);
/// the first owner's `config:*` row is HELD `owner_ambiguous` (never the
/// `AmbiguousNodeOwner` error), and concludes by re-fold when the second
/// owner withdraws its binding.
pub(crate) async fn owner_ambiguous_body(d: &dyn FederationDirectory) {
    let (o1, o2, node) = ("g0-am-o1", "g0-am-o2", "g0-am-n");
    let _ = e2::put_key(d, o1, &[identity_type::USER]).await;
    let _ = e2::put_key(d, o2, &[identity_type::USER]).await;
    let node_kid = e2::put_key(d, node, &[identity_type::NODE]).await;
    let b1 = owner_binding(o1, node);
    land_binding(d, &b1, node).await;
    let b2 = owner_binding(o2, node);
    land_binding(d, &b2, node).await;
    assert!(
        matches!(
            crate::federation::admission::owner_of(d, &node_kid).await,
            Err(Error::AmbiguousNodeOwner { .. })
        ),
        "I3557 precondition: outside an attempt the seat is fail-closed"
    );

    let config = config_row(o1, node);
    let o = e2::put_signed(d, &config)
        .await
        .expect("I3557: an ambiguous owner HOLDS the row; it is not an error");
    assert!(pending(&o), "I3557: held: {o:?}");
    assert_eq!(
        held_reason(d, &config).await.as_deref(),
        Some(reason::OWNER_AMBIGUOUS),
        "I3557: the reason names the ambiguity"
    );

    let w = e2::composer_of(attestation_type::WITHDRAWS, &b2, o2);
    let o = e2::put_signed(d, &w)
        .await
        .expect("I3557: the second owner withdraws its binding");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3557: the withdrawal concludes: {o:?}"
    );
    assert!(
        concluded(d, &config).await,
        "I3557: one owner left: the re-fold concludes the config row"
    );
    assert_eq!(held_reason(d, &config).await, None, "I3557: no reason left");
}

/// I3558 (v4): a membership change first held through the REPLICATED door
/// keeps that arrival: the later voice (offered through the local door)
/// runs under the stored arrival, and the row concludes with its state still
/// `replicated`. A 3-member `majority` family: one voice is short.
pub(crate) async fn replicated_arrival_body(d: &dyn FederationDirectory) {
    use super::group::MembershipRecord;
    use crate::federation::membership_acceptance::test_support::{acceptance_row, proposal_row};
    use crate::federation::types::FamilyMembershipWidening;
    let (m1, m2, m3, joiner) = ("g0-ra-m1", "g0-ra-m2", "g0-ra-m3", "g0-ra-j");
    for s in [m1, m2, m3, joiner] {
        let _ = e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let family =
        super::voices_invariants::found_family(d, "g0-ra-g", &[m1, m2, m3], "majority").await;
    let gid = family.family_key_id.clone();
    let (head, _) = super::group_fixtures::held_head(d, &gid)
        .await
        .expect("I3558: the family's head is held");
    let t = crate::host::clock::now() - chrono::Duration::minutes(1);
    let p = proposal_row(m1, "family", &gid, &e2::kid(joiner), None, t);
    e2::put_signed(d, &p).await.expect("I3558: the proposal");
    let a = acceptance_row(joiner, &p, t);
    e2::put_signed(d, &a).await.expect("I3558: the acceptance");

    let record = MembershipRecord::FamilyWidening(FamilyMembershipWidening {
        family_key_id: gid.clone(),
        member_key_id: e2::kid(joiner),
        joined_at: t,
        effective_at: t,
        role: None,
        persist_row_hash: String::new(),
    });
    let (k1, k2) = (e2::signing_key(m1), e2::signing_key(m2));
    let voices = super::group_fixtures::membership_voices(&record, Some(&head), &[&k1, &k2]);
    let row_id = RowId::of_statement(&voices[0]).expect("I3558: a row statement");

    // m1's voice, offered by a peer under its id: held, count short.
    let o = super::ingest::apply_replicated_statement(d, &voices[0], &row_id.0)
        .await
        .expect("I3558: the replicated voice is kept");
    assert!(
        matches!(
            o,
            super::ingest::ReplicatedStatementOutcome::Admitted(StatementOutcome::Pending { .. })
        ),
        "I3558: held: {o:?}"
    );
    let st = d
        .fold_state(&row_id)
        .await
        .unwrap()
        .expect("I3558: the fold state");
    assert!(st.replicated, "I3558: the arrival is the replicated door");
    assert_eq!(
        st.held.as_ref().map(|h| h.reason.as_str()),
        Some(reason::COUNT_SHORT),
        "I3558: count short"
    );
    assert_eq!(
        st.plane,
        super::fold::plane::GROUP,
        "I3558: the group plane"
    );

    // m2's voice through the LOCAL door: the row is folded under its stored
    // (replicated) arrival and concludes.
    let o = e2::put_statement(d, &voices[1])
        .await
        .expect("I3558: the second voice");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3558: the count is met: {o:?}"
    );
    let st = d.fold_state(&row_id).await.unwrap().unwrap();
    assert!(
        st.held.is_none() && st.replicated,
        "I3558: concluded, and still under its replicated arrival"
    );
    assert_eq!(
        d.list_family_membership_widenings_for(&gid)
            .await
            .unwrap()
            .len(),
        1,
        "I3558: the widening is in its typed table"
    );
}

/// An `age_assurance:provider:{band}:v1` witness row by `witness` about
/// `subject`, stated `ago` before now.
fn age_witness(witness: &str, subject: &str, band: &str, ago: chrono::Duration) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(witness),
    );
    a.attested_key_id = e2::kid(subject);
    a.asserted_at = crate::host::clock::now() - ago;
    a.scrub_timestamp = a.asserted_at;
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": format!("age_assurance:provider:{band}:v1"),
        "score": 1.0,
    });
    e2::row_of(&a, witness)
}

/// I3559 (v4): the steward-binding exemplar's conclude and un-conclude legs.
/// A witness conferred `infra:attest:assurance` by a rooted trust root
/// proves the guardian adult; the guardian's custody binding over a person
/// is held `steward_unproven` until the witness proves the person a minor
/// (the re-fold concludes it), and un-concludes when a later witness row
/// proves the person an adult (the minor-guardianship path no longer
/// applies).
pub(crate) async fn steward_conclude_unconclude_body(d: &dyn FederationDirectory) {
    use super::fixture_trust_root::{confers_statement, rooted_trust_root};
    let (guardian, person, witness) = ("g0-sw-g", "g0-sw-p", "g0-sw-w");
    let r = rooted_trust_root(d, &super::fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let _ = e2::put_key(d, guardian, &[identity_type::USER]).await;
    let _ = e2::put_key(d, person, &[identity_type::USER]).await;
    let witness_kid = e2::put_key(d, witness, &[identity_type::WITNESS]).await;
    let grant = confers_statement(
        &r,
        &witness_kid,
        &[crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE],
        e2::ms(crate::host::clock::now() - chrono::Duration::minutes(5)),
    );
    e2::put_statement(d, &grant)
        .await
        .expect("I3559: the root confers assurance");
    e2::put_statement(d, &e2::voice_of(&grant, witness))
        .await
        .expect("I3559: the witness's own voice on the conferral");
    e2::put_signed(
        d,
        &age_witness(witness, guardian, "adult", chrono::Duration::minutes(4)),
    )
    .await
    .expect("I3559: the guardian is a proven adult");

    // The custody binding: held while the person's age is unproven.
    let binding = owner_binding(guardian, person);
    let o = e2::put_signed(d, &binding)
        .await
        .expect("I3559: the guardian's voice");
    assert!(pending(&o), "I3559: held: {o:?}");
    let st = e2::carried_statement(&binding).expect("I3559: statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, person))
        .await
        .expect("I3559: the person's voice");
    assert!(pending(&o), "I3559: still held: {o:?}");
    assert_eq!(
        held_reason(d, &binding).await.as_deref(),
        Some(reason::STEWARD_UNPROVEN),
        "I3559: unproven"
    );

    // The witness proves the person a minor: the re-fold concludes it.
    e2::put_signed(
        d,
        &age_witness(witness, person, "minor", chrono::Duration::minutes(3)),
    )
    .await
    .expect("I3559: the minor witness");
    assert!(
        concluded(d, &binding).await,
        "I3559: the minor's guardianship concludes on the witness"
    );
    assert_eq!(held_reason(d, &binding).await, None, "I3559: no reason");

    // A later witness row proves the person an adult: un-concluded.
    e2::put_signed(
        d,
        &age_witness(witness, person, "adult", chrono::Duration::minutes(1)),
    )
    .await
    .expect("I3559: the adult witness");
    assert!(
        !concluded(d, &binding).await,
        "I3559: an adult is not stewarded: the binding leaves its typed table"
    );
    assert_eq!(
        held_reason(d, &binding).await.as_deref(),
        Some(reason::STEWARD_UNPROVEN),
        "I3559: held again, and says why"
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

/// A backend whose node key is an E0 key (the rooted root's precondition).
#[cfg(feature = "sqlite")]
async fn sqlite_with_node() -> crate::store::sqlite::SqliteBackend {
    let b = sqlite().await;
    let node = e2::put_key(&b, "g0-node", &["node"]).await;
    b.set_node_key_id(node);
    b
}

#[cfg(feature = "postgres")]
async fn postgres_with_node() -> Option<crate::store::postgres::PostgresBackend> {
    let b = postgres().await?;
    let node = e2::put_key(&b, "g0-node", &["node"]).await;
    b.set_node_key_id(node);
    Some(b)
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

macro_rules! both {
    ($sq:ident, $pg:ident, $body:path) => {
        #[cfg(feature = "sqlite")]
        #[tokio::test]
        async fn $sq() {
            Box::pin($body(&sqlite().await)).await;
        }

        #[cfg(feature = "postgres")]
        #[tokio::test]
        async fn $pg() {
            let Some(b) = postgres().await else {
                return;
            };
            Box::pin($body(&b)).await;
        }
    };
}

both!(
    i3552_fold_store_round_trips_sqlite,
    i3552_fold_store_round_trips_postgres,
    fold_store_body
);
both!(
    i3553_count_short_is_one_fold_reason_sqlite,
    i3553_count_short_is_one_fold_reason_postgres,
    count_short_body
);
both!(
    i3554_owner_binding_first_then_withdrawn_sqlite,
    i3554_owner_binding_first_then_withdrawn_postgres,
    owner_binding_first_body
);
both!(
    i3555_config_first_concludes_on_the_binding_sqlite,
    i3555_config_first_concludes_on_the_binding_postgres,
    config_first_body
);
both!(
    i3556_steward_binding_unproven_is_held_sqlite,
    i3556_steward_binding_unproven_is_held_postgres,
    steward_unproven_body
);
both!(
    i3557_owner_ambiguous_is_held_sqlite,
    i3557_owner_ambiguous_is_held_postgres,
    owner_ambiguous_body
);
both!(
    i3558_replicated_arrival_is_replayed_sqlite,
    i3558_replicated_arrival_is_replayed_postgres,
    replicated_arrival_body
);

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3559_steward_binding_concludes_and_unconcludes_sqlite() {
    Box::pin(steward_conclude_unconclude_body(&sqlite_with_node().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3559_steward_binding_concludes_and_unconcludes_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(steward_conclude_unconclude_body(&b)).await;
}
