//! v62.0.0 (K2-fix4; CC 2.7.3 as ruled on I3545, CC 2.7.5 "a seat is two
//! consents", CC 2.6.1.9) — **I2845–I2846: an authored row whose family names
//! a second signer is held until every named role has voiced.** The roles
//! are the family model's (Verify's vendored `family_authorship.json`
//! through `WithVendored(&PersistCells)`), read from the row's own
//! statement by `door::second_signer_roles`; the gate is
//! `admission::check_second_signers_voiced`.
//!
//! - **I2845 (pure).** An owner binding's statement names exactly one role,
//!   `bound_node`, filled by its CWT `sub` (the bound key's identity-ref).
//! - **I2847 (pure).** The roles under the act selector (CC ruled A): an
//!   own-act `self:delegates_to` names `delegate` (sub) and `delegate_owner`
//!   (owner of sub); I3545's family names `delegate`; a group-act (counted)
//!   one names none.
//! - **I2848 (sqlite and postgres).** A delegation to a MACHINE (a node):
//!   by its owner, the node's voice seats it; by another key, it waits for
//!   the node AND the node's owner. While held it is in NO read surface
//!   (listed below and in K2-fix6.md); voiced, it is in every one.
//! - **I2849 (sqlite and postgres).** The statement-id wire index, the CC
//!   2.7.5 carry by a landed citing row, and Edge's `current_stewards`, for a
//!   held delegation (K2-fix7).
//! - The act=group carve-out on a store is I3294 (`voices_invariants`): an
//!   affiliation's counted appointment lands on its count with no second
//!   signer.
//! - **I2846 (sqlite and postgres; the negative case).** The owner's voice
//!   alone is `Pending`: no typed row, held with the core reason
//!   `count_short`, its detail naming the `bound_node` role. The bound key's
//!   voice over the same payload lands it (`Row`) and it is no longer held.
//!
//! The delegation case (`self:delegates_to:agent_occurrence`, role
//! `delegate`) is P8's **I3545** (`crossing_producer_invariants`), through
//! the production `self_at_login` path.

use crate::federation::edition2::door::{
    resolved_second_signer_roles, second_signer_roles, SecondSignerParty, SecondSignerRole,
};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::fold::{self, reason};
use crate::federation::edition2::ingest::StatementOutcome;
use crate::federation::edition2::names::RowId;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::identity_type;
use crate::federation::FederationDirectory;

/// **I2845** — the role list is the family model's.
#[test]
fn i2845_an_owner_binding_names_the_bound_node_role() {
    let row = ts::owner_binding_attestation("i2845-b", "i2845-owner", "i2845-node");
    let st = e2::carried_statement(&row).expect("I2845: an edition-2 binding");
    let roles = second_signer_roles(&st);
    assert_eq!(
        roles.len(),
        1,
        "I2845: ownership:* names one second signer: {roles:?}"
    );
    assert_eq!(roles[0].role, "bound_node", "I2845: {roles:?}");
    assert_eq!(
        roles[0].parties,
        vec![SecondSignerParty::Key(e2::kid("i2845-node"))],
        "I2845: the role is filled by the CWT sub, the bound key"
    );
    // A further voice of the same row reads the same roles (they are the
    // payload's and the family's, not the signer's).
    let voice = e2::voice_of(&st, "i2845-node");
    assert_eq!(
        second_signer_roles(&voice),
        roles,
        "I2845: per row, not per voice"
    );
    // Bytes that are no statement name no role.
    assert!(
        second_signer_roles(b"{}").is_empty(),
        "I2845: not a statement"
    );
}

/// **I2847** — the roles under the ACT SELECTOR (CC ruled A: CC 2.6.1.9,
/// P2:1147; authorship_text.tsv:43–44; the act=group carve-out,
/// count_text.tsv:40 / authorship_text.tsv:56):
/// - an OWN-act plain `self:delegates_to` names `delegate` (its `sub`) and
///   `delegate_owner` (the owner of its `sub`, resolved by the gate for a
///   machine sub);
/// - I3545's family (`self:delegates_to:agent_occurrence`) names `delegate`;
/// - a GROUP-act (counted, no `author`) `self:delegates_to`, an
///   affiliation's appointment, names none.
#[test]
fn i2847_roles_are_read_under_the_act_selector() {
    use crate::federation::edition2::emit::{AGENT_OCCURRENCE_FAMILY, DELEGATES_TO_FAMILY};
    let mut a = ts::bare_attestation(
        "i2847-d",
        "i2847-owner",
        "i2847-agent",
        &serde_json::json!({ "id": "i2847-d", "kind": "delegates_to" }),
    );
    a.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.to_owned();
    let sub = e2::kid("i2847-agent");
    let plain = second_signer_roles(&e2::statement_of_family(
        &a,
        "i2847-owner",
        DELEGATES_TO_FAMILY,
    ));
    assert!(
        plain
            .iter()
            .any(|r| r.role == "delegate" && r.parties == vec![SecondSignerParty::Key(sub.clone())]),
        "I2847: own act — the delegate, the row's sub, must voice: {plain:?}"
    );
    assert!(
        plain.iter().any(|r| r.role == "delegate_owner"
            && r.parties == vec![SecondSignerParty::OwnerOf(sub.clone())]),
        "I2847: own act — the owner of a machine sub must voice: {plain:?}"
    );
    let agent = second_signer_roles(&e2::statement_of_family(
        &a,
        "i2847-owner",
        AGENT_OCCURRENCE_FAMILY,
    ));
    assert!(
        agent
            .iter()
            .any(|r| r.role == "delegate" && r.parties == vec![SecondSignerParty::Key(sub.clone())]),
        "I2847: the agent-occurrence delegation waits for the agent: {agent:?}"
    );
    let group = second_signer_roles(&e2::counted_statement_of_family(
        &a,
        "i2847-owner",
        DELEGATES_TO_FAMILY,
    ));
    assert!(
        group.is_empty(),
        "I2847: group act (a counted appointment) — no second-signer role: {group:?}"
    );
}

/// **I2846** — held on the author's voice alone; landed by the second.
async fn i2846_body(d: &dyn FederationDirectory, s: &str) {
    let (owner, node) = (format!("i2846-owner-{s}"), format!("i2846-node-{s}"));
    e2::put_key(d, &owner, &[identity_type::USER]).await;
    e2::put_key(d, &node, &[identity_type::NODE]).await;
    let row = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &owner, &node);
    let st = e2::carried_statement(&row).expect("I2846: an edition-2 binding");
    let rid = e2::rid(&row);
    let row_id = RowId(e2::rid_digest(&row));

    let first = e2::put_signed(d, &row)
        .await
        .expect("I2846: the owner's voice is kept, not refused");
    assert!(
        matches!(first, StatementOutcome::Pending { .. }),
        "I2846: the author's voice alone never lands the row: {first:?}"
    );
    assert!(
        d.get_attestation(&rid).await.unwrap().is_none(),
        "I2846: no typed row while a named role has not voiced"
    );
    let why = fold::why_held(d, &row_id)
        .await
        .expect("I2846: read the hold")
        .expect("I2846: the row is held");
    assert_eq!(why.reason, reason::COUNT_SHORT, "I2846: {why:?}");
    assert!(
        why.detail.contains("bound_node"),
        "I2846: the hold names the missing role: {}",
        why.detail
    );

    let second = e2::put_statement(d, &e2::voice_of(&st, &node))
        .await
        .expect("I2846: the bound key's voice is admitted");
    assert!(
        matches!(second, StatementOutcome::Row { .. }),
        "I2846: the second voice lands the row: {second:?}"
    );
    assert!(
        d.get_attestation(&rid).await.unwrap().is_some(),
        "I2846: landed"
    );
    assert!(
        fold::why_held(d, &row_id)
            .await
            .expect("I2846: read the hold")
            .is_none(),
        "I2846: no longer held"
    );
}

/// What each read surface says of the delegation `rid` (`granter` →
/// `node`, scope `scope`): `true` = it counts or shows it.
#[derive(Debug, PartialEq, Eq)]
struct Surfaces {
    /// `FederationDirectory::get_attestation` (the typed point read).
    lookup: bool,
    /// `FederationDirectory::delegations_to(node)` (the delegation list view).
    listed: bool,
    /// `admission::reachable_under_scope(granter, node, scope)` (the scope read).
    reachable: bool,
    /// `admission::steward_bindings_of(node)` (the standing / custody read).
    standing: bool,
    /// `edition2::store::lookup_by_id("Row", rid)` (the anonymous point serve).
    point_served: bool,
    /// `edition2::serve::statements_served_to(.., None)` (the served /
    /// replicated listing): any statement of the row.
    listing_served: bool,
}

async fn surfaces(
    d: &dyn FederationDirectory,
    granter: &str,
    node: &str,
    scope: &str,
    rid: &str,
) -> Surfaces {
    use crate::federation::admission::{reachable_under_scope, steward_bindings_of};
    use crate::federation::edition2::serve::statements_served_to;
    use crate::federation::edition2::store::{lookup_by_id, ROW_KIND};
    let lookup = d.get_attestation(rid).await.unwrap().is_some();
    let listed = d
        .delegations_to(node)
        .await
        .unwrap()
        .iter()
        .any(|a| a.attestation_id == rid);
    let reachable = reachable_under_scope(d, granter, node, scope, 4)
        .await
        .unwrap();
    let standing = steward_bindings_of(d, node)
        .await
        .unwrap()
        .iter()
        .any(|k| k == granter);
    let point_served = matches!(lookup_by_id(d, ROW_KIND, rid).await.unwrap(), Some(Some(_)));
    let mut listing_served = false;
    let mut cursor = None;
    loop {
        let page = statements_served_to(d, cursor.as_ref(), 500, None)
            .await
            .unwrap();
        listing_served |= page
            .statements
            .iter()
            .any(|st| RowId::of_statement(&st.bytes).is_some_and(|id| id.hex() == rid));
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Surfaces {
        lookup,
        listed,
        reachable,
        standing,
        point_served,
        listing_served,
    }
}

/// A sealed own-act `delegates_to(granter → node)` carrying `scope`.
fn delegation(granter: &str, node: &str, scope: &str) -> crate::federation::Attestation {
    let id = uuid::Uuid::new_v4().to_string();
    let mut row = ts::bare_attestation(
        &id,
        granter,
        node,
        &serde_json::json!({ "id": id, "kind": "delegates_to", "scope": [scope] }),
    );
    row.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.to_owned();
    ts::seal_row_in_place(granter, &mut row);
    row
}

/// **I2848** — a delegation to a MACHINE key, under CC 2.6.1.9 (P2:1147)
/// and authorship_text.tsv:43–44.
async fn i2848_body(d: &dyn FederationDirectory, s: &str) {
    use crate::federation::admission::owner_of;
    use crate::federation::types::delegation_scope;
    let scope = delegation_scope::INFRA_SERVE;
    let (g, o, n) = (
        format!("i2848-granter-{s}"),
        format!("i2848-owner-{s}"),
        format!("i2848-node-{s}"),
    );
    e2::put_key(d, &g, &[identity_type::USER]).await;
    e2::put_key(d, &o, &[identity_type::USER]).await;
    e2::put_key(d, &n, &[identity_type::NODE]).await;
    let (gk, ok, nk) = (e2::kid(&g), e2::kid(&o), e2::kid(&n));

    // The node's owner: its binding lands with the node's voice.
    let binding = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &o, &n);
    let out = e2::land_owner_binding(d, &binding, &n)
        .await
        .expect("I2848: the owner binding");
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I2848: {out:?}"
    );
    assert_eq!(owner_of(d, &nk).await.unwrap(), Some(ok.clone()), "I2848");

    // (a) Own act, by the node's owner: the owner's role is the author's
    // voice; the delegate's (the node's) voice seats it.
    let by_owner = delegation(&o, &n, scope);
    let first = e2::put_signed(d, &by_owner).await.expect("I2848: kept");
    assert!(
        matches!(first, StatementOutcome::Pending { .. }),
        "I2848 (a): the delegator alone never seats a delegation: {first:?}"
    );
    let st = e2::carried_statement(&by_owner).expect("a statement");
    let out = e2::put_statement(d, &e2::voice_of(&st, &n))
        .await
        .expect("I2848 (a): the delegate's voice");
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I2848 (a): the delegate's voice seats it: {out:?}"
    );

    // (b) Machine sub, another delegator: the node AND its owner.
    let by_other = delegation(&g, &n, scope);
    let rid = e2::rid(&by_other);
    let row_id = RowId(e2::rid_digest(&by_other));
    let st = e2::carried_statement(&by_other).expect("a statement");
    // The ONE answer to who must voice it (`door::resolved_second_signer_roles`):
    // the delegate (the node) and the owner of the machine sub, resolved
    // from the live owner binding.
    let roles = resolved_second_signer_roles(d, &st).await.unwrap();
    assert_eq!(
        roles,
        vec![
            SecondSignerRole {
                role: "delegate".to_owned(),
                parties: vec![SecondSignerParty::Key(nk.clone())],
            },
            SecondSignerRole {
                role: "delegate_owner".to_owned(),
                parties: vec![SecondSignerParty::Key(ok.clone())],
            },
        ],
        "I2848 (b): the resolved roles"
    );
    // An UNOWNED machine sub: the owner role is reported unfillable (no party).
    let lone = format!("i2848-lone-{s}");
    e2::put_key(d, &lone, &[identity_type::NODE]).await;
    let to_lone = delegation(&g, &lone, scope);
    let lone_roles =
        resolved_second_signer_roles(d, &e2::carried_statement(&to_lone).expect("a statement"))
            .await
            .unwrap();
    assert!(
        lone_roles
            .iter()
            .any(|r| r.role == "delegate_owner" && r.parties.is_empty()),
        "I2848: an unowned machine sub's owner role is unfillable: {lone_roles:?}"
    );
    let first = e2::put_signed(d, &by_other).await.expect("I2848 (b): kept");
    assert!(
        matches!(first, StatementOutcome::Pending { .. }),
        "I2848 (b): {first:?}"
    );
    let held = Surfaces {
        lookup: false,
        listed: false,
        reachable: false,
        standing: false,
        point_served: false,
        listing_served: false,
    };
    assert_eq!(
        surfaces(d, &gk, &nk, scope, &rid).await,
        held,
        "I2848 (surfaces): a HELD delegation is in no read surface"
    );
    let out = e2::put_statement(d, &e2::voice_of(&st, &n))
        .await
        .expect("I2848 (b): the delegate's voice is kept");
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I2848 (b): a machine sub's owner must voice too: {out:?}"
    );
    let why = fold::why_held(d, &row_id)
        .await
        .expect("I2848: read the hold")
        .expect("I2848 (b): held");
    assert_eq!(why.reason, reason::COUNT_SHORT, "I2848 (b): {why:?}");
    assert!(
        why.detail.contains("delegate_owner"),
        "I2848 (b): the hold names the owner's role: {}",
        why.detail
    );
    assert_eq!(
        surfaces(d, &gk, &nk, scope, &rid).await,
        held,
        "I2848 (surfaces): still held, still in no read surface"
    );
    // I2031 (K2-fix12) — the door admits a voice in the `delegate_owner`
    // role from the statement alone (Verify cannot resolve `owner_of_sub`),
    // so the gate is what decides: a voice by a key that is NOT the node's
    // owner fills no role, and the row stays held for the owner.
    let stranger = format!("i2848-stranger-{s}");
    e2::put_key(d, &stranger, &[identity_type::USER]).await;
    let out = e2::put_statement(d, &e2::voice_of(&st, &stranger))
        .await
        .expect("I2031: a stranger's voice is kept, never refused at the door");
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I2031: a voice by a key that is not the machine sub's owner seats nothing: {out:?}"
    );
    let why = fold::why_held(d, &row_id)
        .await
        .expect("I2031: read the hold")
        .expect("I2031: still held");
    assert!(
        why.reason == reason::COUNT_SHORT && why.detail.contains("delegate_owner"),
        "I2031: still waiting for the owner's voice: {why:?}"
    );
    let out = e2::put_statement(d, &e2::voice_of(&st, &o))
        .await
        .expect("I2848 (b): the owner's voice");
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I2848 (b): the delegate's and the owner's voices seat it: {out:?}"
    );
    assert_eq!(
        surfaces(d, &gk, &nk, scope, &rid).await,
        Surfaces {
            lookup: true,
            listed: true,
            reachable: true,
            standing: true,
            point_served: true,
            listing_served: true,
        },
        "I2848 (surfaces): voiced, the delegation is in every read surface"
    );
}

/// The statement-id wire index (`list_wire_hashes_since("Statement")`), in
/// full.
async fn wire_index(d: &dyn FederationDirectory) -> Vec<String> {
    d.list_wire_hashes_since(
        crate::federation::edition2::store::STATEMENT_KIND,
        None,
        100_000,
    )
    .await
    .unwrap()
}

/// Edge's `StewardDirectory::current_stewards()` source:
/// `FederationDirectory::list_keys_by_identity_type("steward")`.
async fn current_stewards(d: &dyn FederationDirectory) -> Vec<String> {
    d.list_keys_by_identity_type(identity_type::STEWARD)
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.key_id)
        .collect()
}

/// **I2849** — the remaining serve paths and Edge's steward fan-out, for a
/// delegation HELD for its second signers (K2-fix7):
/// - the statement-id wire index and its point read do not serve the held
///   statement; once seated, both do;
/// - a LANDED row citing the held one (`refs.also.cites`, a CC 2.7.5 naming
///   role) does not carry it to the citer's audience
///   (`group_serve::carried_by_a_naming_row`, `serve::servable_to`, the
///   requester's listing); once seated it is served;
/// - `current_stewards` (Edge's high-priority fan-out) reads the KEY plane
///   (`federation_keys.identity_type = 'steward'`), never a delegation: a
///   steward-bind-shaped delegation is absent from it both held and seated.
async fn i2849_body(d: &dyn FederationDirectory, s: &str) {
    use super::door_invariants::fixture::{map, ref2};
    use crate::federation::edition2::group_serve::carried_by_a_naming_row;
    use crate::federation::edition2::serve::{servable_to, statements_served_to};
    use crate::federation::edition2::store::{lookup_by_id, STATEMENT_KIND};
    use crate::federation::types::delegation_scope;
    use ciris_verify_core::cde::Value;
    let scope = delegation_scope::INFRA_SERVE;
    let (g, o, n, p) = (
        format!("i2849-granter-{s}"),
        format!("i2849-owner-{s}"),
        format!("i2849-node-{s}"),
        format!("i2849-peer-{s}"),
    );
    for k in [&g, &o, &p] {
        e2::put_key(d, k, &[identity_type::USER]).await;
    }
    e2::put_key(d, &n, &[identity_type::NODE]).await;
    let (gk, ok, nk, pk) = (e2::kid(&g), e2::kid(&o), e2::kid(&n), e2::kid(&p));
    let binding = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &o, &n);
    let out = e2::land_owner_binding(d, &binding, &n)
        .await
        .expect("I2849: the owner binding");
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I2849: {out:?}"
    );

    // The held delegation (the granter's voice alone).
    let row = delegation(&g, &n, scope);
    let st = e2::carried_statement(&row).expect("a statement");
    let row_id = RowId(e2::rid_digest(&row));
    let stmt_id = hex::encode(
        crate::federation::edition2::receipts::statement_id_of(&st).expect("a statement id"),
    );
    let first = e2::put_signed(d, &row).await.expect("I2849: kept");
    assert!(
        matches!(first, StatementOutcome::Pending { .. }),
        "I2849: {first:?}"
    );
    let ours = [gk.clone(), ok.clone(), nk.clone()];

    // 1. The statement-id wire index and its point read.
    assert!(
        !wire_index(d).await.contains(&stmt_id),
        "I2849 (wire index): a held row's statement id is not advertised"
    );
    assert_eq!(
        lookup_by_id(d, STATEMENT_KIND, &stmt_id).await.unwrap(),
        Some(None),
        "I2849 (wire index): nor served by its statement id"
    );

    // 2. A landed row naming the held one does not carry it out.
    let pkey = e2::signing_key(&p);
    let at = e2::ms(crate::host::clock::now());
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(pk.clone())),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
        (
            "refs",
            map(vec![(
                "also",
                map(vec![("cites", Value::Array(vec![ref2(&row_id.0)]))]),
            )]),
        ),
    ]);
    let citer = ciris_verify_core::edition2::sign_row_statement(
        &pkey,
        &pk,
        &pk,
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
        &payload,
        vec![],
    )
    .expect("I2849: the citing row");
    let landed = e2::put_statement(d, &citer)
        .await
        .expect("I2849: the citing row is admitted");
    assert!(
        matches!(landed, StatementOutcome::Row { .. }),
        "I2849: the citing row LANDS (else the carry path is not exercised): {landed:?}"
    );
    assert!(
        !carried_by_a_naming_row(d, &st, Some(&pk)).await.unwrap(),
        "I2849 (carry): a concluded row naming a held one does not carry it out"
    );
    assert!(
        !servable_to(d, &st, Some(&pk)).await.unwrap(),
        "I2849 (carry): the held statement is kept, not served, to the citer"
    );
    let mut served_to_peer = false;
    let mut cursor = None;
    loop {
        let page = statements_served_to(d, cursor.as_ref(), 500, Some(&pk))
            .await
            .unwrap();
        served_to_peer |= page.statements.iter().any(|x| x.bytes == st);
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert!(
        !served_to_peer,
        "I2849 (carry): nor in the citer's listing (no travelling ancestor)"
    );

    // 3. Edge's steward fan-out.
    let stewards = current_stewards(d).await;
    assert!(
        !stewards.iter().any(|k| ours.contains(k)),
        "I2849 (current_stewards): a held steward-bind is absent: {stewards:?}"
    );

    // Seat it: the node's voice, then its owner's.
    e2::put_statement(d, &e2::voice_of(&st, &n))
        .await
        .expect("I2849: the delegate's voice");
    let out = e2::put_statement(d, &e2::voice_of(&st, &o))
        .await
        .expect("I2849: the owner's voice");
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I2849: seated: {out:?}"
    );
    assert!(
        wire_index(d).await.contains(&stmt_id),
        "I2849 (wire index): seated, its statement id is advertised"
    );
    assert_eq!(
        lookup_by_id(d, STATEMENT_KIND, &stmt_id).await.unwrap(),
        Some(Some(st.clone())),
        "I2849 (wire index): and served by its statement id"
    );
    assert!(
        servable_to(d, &st, Some(&pk)).await.unwrap(),
        "I2849 (carry): seated, it is served under its own rule"
    );
    let stewards = current_stewards(d).await;
    assert!(
        !stewards.iter().any(|k| ours.contains(k)),
        "I2849 (current_stewards): its source is the key plane, never a delegation, held \
         or seated: {stewards:?}"
    );
}

fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2846_held_until_the_second_signer_votes_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2846_body(&b, &suffix())).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2846_held_until_the_second_signer_votes_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2846_body(&b, &suffix())).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2848_a_machine_delegation_and_its_read_surfaces_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2848_body(&b, &suffix())).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2848_a_machine_delegation_and_its_read_surfaces_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2848_body(&b, &suffix())).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2849_wire_index_carry_and_stewards_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2849_body(&b, &suffix())).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2849_wire_index_carry_and_stewards_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i2849_body(&b, &suffix())).await;
}
