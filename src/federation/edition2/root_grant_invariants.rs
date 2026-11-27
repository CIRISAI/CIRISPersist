//! v62.0.0 (KR-fix2; CC 3.2 as ruled 2026-11-21, CC 4.4.3.19) — **a grant
//! from the root is a row counted over the holders of the bundle in force,
//! and it names the bundle it is counted over.**
//!
//! The root is the genesis bundle's lineage (no community, no key). Its
//! grant is a `delegates_to` of family `trust:{job}:{version}` at
//! `trust:confers:v1` with NO `author` (act = group), `sub` = the grantee,
//! `refs.head` = the bundle's object id (the encoding a halt lifecycle row
//! and a seat re-bind use), and `scope`. Its voices are the bundle's holders'
//! statements, counted at the accord's strict majority
//! (`admission::check_root_grant_counted`). The grantee's consent is a
//! separate `membership:acceptance:v1` at the federation scope naming the
//! grant; a `node` or `agent` grantee's is its OWNER's
//! (`membership_acceptance::check_root_grant_reply`).
//!
//! Every witness runs through the real statement door
//! (`ingest::put_statement`) on `install_v2`'s bundle (three holders), on
//! sqlite and postgres. The holders sign with their bundle keys; nothing here
//! is keyed to a root key or a community.
//!
//! - **I4200** — two of three holders grant `infra:attest:{family}` to a
//!   `node`-typed worker: one voice waits (`count_short`, nothing stored), a
//!   non-holder's voice counts nothing, the second holder lands it. It does
//!   not CONFER until the worker's OWNER accepts: the worker's own acceptance
//!   seats nothing; the owner's does.
//! - **I4201** — the other holder first: the count is over holders, in
//!   either order.
//! - **I4202** — a scope the named bundle's `charter.scope` does not cover is
//!   REFUSED by name (`conferral_outside_charter_scope`) at the first voice;
//!   nothing is kept or held.
//! - **I4203** — TWO NODES, opposite arrival orders, ONE verdict (CC rc22
//!   7b4a55e: only voices dated before the next held bundle count). Two
//!   grants name the first bundle: EARLY is dated before the later bundle,
//!   LATE after it. Node A receives both grants (both land: it holds no
//!   successor) and then the later bundle; node B holds the later bundle
//!   first. On BOTH nodes EARLY is held and LATE is not: LATE never lands on
//!   B and is un-concluded on A when the later bundle lands.
//! - **I4204** — the end: one holder's counted withdrawal waits and two land
//!   it; a stranger's authored withdrawal is not admitted, nor one holder's,
//!   nor (KR-fix18) the worker's owner's: the grant is the holders' consent
//!   and only their count undoes it.
//! - **I4205** — an `agent` grantee: the grant lands on the holders' count;
//!   the agent's own acceptance seats nothing; its owner's does.
//! - **I4206** — the acceptance BEFORE the grant: it waits (held), and once
//!   the holders land the grant it concludes and the grant confers.
//! - **I4208** — THE HOST VERBS, on four nodes, delivered only through the
//!   serve feed (`serve::statements_served_to` → `ingest::put_statement`).
//!   Holder 1's node drafts the grant with the generic draft
//!   (`emit::draft_from_envelope_in`, what `Engine::statement_draft` calls)
//!   and submits it: `Waiting`, `count_short`. Holder 2's node pulls it AS
//!   HOLDER 2 from a node that is not rooted, finds it with
//!   `held_rows_for(holder 2, "root_holder")`, drafts its voice and submits:
//!   `Seated`. The worker's node pulls the grant about itself; the worker's
//!   OWNER accepts with the real producer (`reply_input` →
//!   `attestation_emit::emit_statement`, what
//!   `Engine::reply_to_membership_proposal` calls). A fourth node pulls from
//!   the worker's node and `root_grants_for(worker)` reads the grant:
//!   `infra:attest:{family}`, accepted, conferring.
//! - **I4207** — a ROOTLESS node: a holder's voice is not a landed row (its
//!   key is no key this node holds: the door's retryable wait, or a hold);
//!   after the bundle is imported the same two voices land the grant.
//! - **I4322** (KR-fix20; the count always wins) — a holder's AUTHORED
//!   withdrawal of the counted grant, the first voice's or the second's, is
//!   refused `withdraws_never_retracts` with the grant held, or dropped when
//!   it waited for the grant: two nodes, both orders, nothing kept, the grant
//!   live; the holders' count still ends it.
//! - **I4323** (KR-fix24; CC 3.3.4) — a grant short of its count lapses on
//!   this node at first-held + 72 h (not before), its voice dropped, nothing
//!   refused; offered again it is held with a fresh window; a counted grant is
//!   never lapsed; the host verb's sweep does it at the node's clock.
//! - **I4328** (KR-fix28; CC 3.2) — a node re-bound from P1 to P2: an act
//!   under P1's binding stays under P1's acceptance; an act under P2's is
//!   not until P2 accepts; P1's later withdrawal changes nothing under P2.
//! - **I4329** (KR-fix27, KR-fix27b) — a Valid first bundle of ANOTHER
//!   family is another root (`other_roots`), not a fork; the root family is
//!   the PINNED anchor's whichever arrived first; with no pinned bundle among
//!   two families nothing is in force; the same family is a fork.
//! - **I4324** (KR-fix24) — two nodes that first held the voice at different
//!   instants lapse it at different instants.

use chrono::{DateTime, Utc};
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{row_ref, sign_row_statement, Digest32};
use ciris_verify_core::namespace_match;

use super::fixture_genesis::{
    bundle_v2, install_ceremony_v2, install_v2, later_v2, TestCeremonyV2, FAMILY_KEY_ID,
};
use super::fixture_switch as e2;
use super::genesis::genesis_in_force;
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::admission::{root_grant_of, CONFERRAL_OUTSIDE_CHARTER_SCOPE};
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::{attestation_type, cohort_scope};
use crate::federation::{Attestation, FederationDirectory};

/// The scope a CI worker is granted: a sub-scope of the charter's
/// `infra:attest`.
const ATTEST_BUILD: &str = "infra:attest:provenance:build_manifest";
/// A second sub-scope of `infra:attest` (a second grant, a second row id).
const ATTEST_EVIDENCE: &str = "infra:attest:safety_battery";
/// An `infra:*` scope the fixture charter (`infra:attest`, `infra:serve`)
/// does not cover.
const OUTSIDE: &str = "infra:detect";

fn trust_family() -> String {
    namespace_match::family_id(super::typed::TRUST_PREFIX)
}

/// A payload map in deterministic key order.
fn map(members: Vec<(&str, Value)>) -> Value {
    let mut m: Vec<(Value, Value)> = members
        .into_iter()
        .map(|(k, v)| (Value::Text(k.to_owned()), v))
        .collect();
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

fn row_of(statement: &[u8]) -> RowId {
    RowId::of_statement(statement).expect("a row statement")
}

fn pending(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Pending { .. })
}

/// **The grant's bytes**: one voice of the counted root grant of `scope` to
/// `grantee`, counted over the bundle `head`, signed by `key` as `iss`.
fn grant_voice(
    key: &CompositeSigningKey,
    iss: &str,
    grantee: &str,
    scope: &str,
    head: &Digest32,
    at_ms: u64,
) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(at_ms)),
        (
            "dimension",
            Value::Text(crate::federation::trust_root::TRUST_CONFERS_DIMENSION.to_owned()),
        ),
        ("refs", map(vec![("head", row_ref(head))])),
        ("scope", Value::Array(vec![Value::Text(scope.to_owned())])),
    ]);
    sign_row_statement(
        key,
        iss,
        grantee,
        attestation_type::DELEGATES_TO,
        &trust_family(),
        &payload,
        vec![],
    )
    .expect("sign a grant voice")
}

/// Holder `i` of `c`'s voice of the grant.
fn holder_grant(
    c: &TestCeremonyV2,
    i: usize,
    grantee: &str,
    scope: &str,
    head: &Digest32,
    at_ms: u64,
) -> Vec<u8> {
    grant_voice(
        &c.holder_key(i),
        c.holder_identity_ref(i),
        grantee,
        scope,
        head,
        at_ms,
    )
}

/// One voice of the root's COUNTED withdrawal of the grant `target` (a
/// composer: `asserted_at` and `refs` only), over the bundle `head`.
fn holder_withdrawal(
    c: &TestCeremonyV2,
    i: usize,
    grantee: &str,
    target: &RowId,
    head: &Digest32,
    at_ms: u64,
) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(at_ms)),
        (
            "refs",
            map(vec![
                ("head", row_ref(head)),
                ("target", row_ref(&target.0)),
            ]),
        ),
    ]);
    sign_row_statement(
        &c.holder_key(i),
        c.holder_identity_ref(i),
        grantee,
        attestation_type::WITHDRAWS,
        &trust_family(),
        &payload,
        vec![],
    )
    .expect("sign a counted withdrawal voice")
}

/// `seed`'s own AUTHORED withdrawal of the grant `target`.
fn authored_withdrawal(seed: &str, grantee: &str, target: &RowId, at_ms: u64) -> Vec<u8> {
    let iss = e2::kid(seed);
    let payload = map(vec![
        ("asserted_at", Value::Uint(at_ms)),
        ("author", Value::Text(iss.clone())),
        ("refs", map(vec![("target", row_ref(&target.0))])),
    ]);
    sign_row_statement(
        &e2::signing_key(seed),
        &iss,
        grantee,
        attestation_type::WITHDRAWS,
        &trust_family(),
        &payload,
        vec![],
    )
    .expect("sign an authored withdrawal")
}

fn ms_now() -> DateTime<Utc> {
    let t = crate::host::clock::now();
    DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms")
}

/// `signer`'s `membership:acceptance:v1` of the grant, attested to the
/// grantee, at the federation scope (the root grant's reply form).
fn acceptance(signer: &str, grant: &Attestation) -> Attestation {
    let env = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "dimension": crate::federation::membership_acceptance::ACCEPTANCE_DIMENSION,
        "references_attestation_id": grant.attestation_id,
        "proposal_hash": grant.original_content_hash,
    });
    let mut r = ts::bare_attestation(
        &uuid::Uuid::new_v4().to_string(),
        signer,
        &grant.attested_key_id,
        &env,
    );
    r.attestation_type = attestation_type::SCORES.into();
    r.weight = None;
    r.cohort_scope = cohort_scope::FEDERATION.into();
    r.asserted_at = ms_now();
    r.scrub_timestamp = r.asserted_at;
    r.expires_at = None;
    r.subject_key_ids = Vec::new();
    ts::seal_row_in_place(signer, &mut r);
    r
}

/// The instant a grant over the bundle in force is stated at: its newest
/// tip + 120 s (from the bundle, never the wall clock).
async fn grant_instant(d: &dyn FederationDirectory) -> u64 {
    genesis_in_force(d)
        .await
        .expect("the genesis in force")
        .tips()
        .iter()
        .map(|t| t.asserted_at)
        .max()
        .expect("a bundle in force")
        + 120_000
}

/// A `node`-typed worker `{tag}-worker` and its owner `{tag}-owner`, bound
/// (the node's voice included). Returns `(worker kid, owner seed)`.
async fn worker_with_owner(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
    let (worker_seed, owner_seed) = (format!("w-{tag}"), format!("o-{tag}"));
    let worker = e2::put_key(d, &worker_seed, &["node"]).await;
    e2::put_key(d, &owner_seed, &["user"]).await;
    crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
        d,
        &owner_seed,
        &worker_seed,
    )
    .await;
    (worker, owner_seed)
}

async fn held(d: &dyn FederationDirectory, id: &RowId) -> Option<Attestation> {
    d.get_attestation(&id.hex()).await.expect("get_attestation")
}

async fn why(d: &dyn FederationDirectory, id: &RowId) -> Option<String> {
    super::fold::why_held(d, id)
        .await
        .expect("why_held")
        .map(|h| h.reason)
}

/// Holders 0 and 1 of `c` land the grant of `scope` to `grantee` over
/// `head`; the landed row.
async fn land_grant(
    d: &dyn FederationDirectory,
    c: &TestCeremonyV2,
    grantee: &str,
    scope: &str,
    head: &Digest32,
    at_ms: u64,
    what: &str,
) -> Attestation {
    let v0 = holder_grant(c, 0, grantee, scope, head, at_ms);
    let id = row_of(&v0);
    for (i, v) in [v0, holder_grant(c, 1, grantee, scope, head, at_ms)]
        .iter()
        .enumerate()
    {
        put_statement(d, v, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("{what}: holder {i}'s voice: {e}"));
    }
    held(d, &id).await.unwrap_or_else(|| {
        panic!(
            "{what}: two of three holders land the grant; held: {:?}",
            id.hex()
        )
    })
}

/// **I4200.**
pub(crate) async fn i4200_two_holders_confer_on_a_node_worker(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4200: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, owner) = worker_with_owner(d, "i4200").await;
    let stranger = "s-i4200";
    e2::put_key(d, stranger, &["user"]).await;

    // One holder: it waits, nothing is stored.
    let v0 = holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at);
    let id = row_of(&v0);
    let o = put_statement(d, &v0, None, INGEST_TIER)
        .await
        .expect("I4200: one holder's voice is kept");
    assert!(pending(&o), "I4200: one of three holders waits: {o:?}");
    assert!(
        held(d, &id).await.is_none(),
        "I4200: nothing lands on one voice"
    );
    assert_eq!(
        why(d, &id).await.as_deref(),
        Some(super::fold::reason::COUNT_SHORT),
        "I4200: held, and says why"
    );
    // A non-holder's voice of the same row counts nothing.
    let by_stranger = grant_voice(
        &e2::signing_key(stranger),
        &e2::kid(stranger),
        &worker,
        ATTEST_BUILD,
        &head,
        at,
    );
    assert_eq!(row_of(&by_stranger), id, "I4200: one row, another voice");
    let _ = put_statement(d, &by_stranger, None, INGEST_TIER).await;
    assert!(
        held(d, &id).await.is_none(),
        "I4200: a non-holder's voice does not land the grant"
    );
    // The second holder lands it.
    let o = put_statement(
        d,
        &holder_grant(c, 1, &worker, ATTEST_BUILD, &head, at),
        None,
        INGEST_TIER,
    )
    .await
    .expect("I4200: the second holder's voice");
    assert!(!pending(&o), "I4200: two of three holders: {o:?}");
    let grant = held(d, &id).await.expect("I4200: the grant landed");
    assert_eq!(grant.attested_key_id, worker, "I4200: the grantee");

    // The reader's hook: the root, the bundle, not yet accepted.
    let read = |t: DateTime<Utc>| {
        let g = grant.clone();
        async move { root_grant_of(d, &g, t).await.expect("root_grant_of") }
    };
    let later = || ms_now() + chrono::Duration::seconds(1);
    let g = read(later()).await.expect("I4200: a counted root grant");
    assert_eq!(
        g.family_key_id, FAMILY_KEY_ID,
        "I4200: the root is the accord"
    );
    assert_eq!(g.bundle, head, "I4200: the bundle it names");
    assert!(g.bundle_in_force, "I4200: its bundle is in force");
    assert!(!g.accepted, "I4200: no acceptance, no conferral");

    // The worker's own acceptance seats nothing: a node's consent is its
    // owner's.
    let seed_of_worker = e2::seed_of(&worker);
    let _ = e2::put_signed(d, &acceptance(&seed_of_worker, &grant)).await;
    assert!(
        !read(later()).await.expect("I4200").accepted,
        "I4200: a node worker cannot accept for itself"
    );
    // A stranger's acceptance seats nothing either.
    let _ = e2::put_signed(d, &acceptance(stranger, &grant)).await;
    assert!(
        !read(later()).await.expect("I4200").accepted,
        "I4200: a stranger cannot accept for the worker"
    );
    // The owner accepts: conferred.
    let acc = acceptance(&owner, &grant);
    let o = e2::put_signed(d, &acc)
        .await
        .expect("I4200: the owner's acceptance is admitted");
    assert!(
        !pending(&o),
        "I4200: the owner's acceptance lands: {o:?}, held {:?}",
        why(d, &RowId(e2::rid_digest(&acc))).await
    );
    assert!(
        read(later()).await.expect("I4200").accepted,
        "I4200: counted by two holders and accepted by the owner: conferred"
    );
    // Before the acceptance's own instant it was not.
    assert!(
        !read(acc.asserted_at - chrono::Duration::seconds(1))
            .await
            .expect("I4200")
            .accepted,
        "I4200: not conferred before the acceptance"
    );
}

/// **I4201.**
pub(crate) async fn i4201_either_order_of_holders(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4201: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, _) = worker_with_owner(d, "i4201").await;
    let v2 = holder_grant(c, 2, &worker, ATTEST_BUILD, &head, at);
    let id = row_of(&v2);
    let o = put_statement(d, &v2, None, INGEST_TIER)
        .await
        .expect("I4201: holder 2 first");
    assert!(pending(&o), "I4201: one voice waits: {o:?}");
    // The same holder again is the same voice: still one.
    let _ = put_statement(d, &v2, None, INGEST_TIER).await;
    assert!(
        held(d, &id).await.is_none(),
        "I4201: one holder, twice, is one"
    );
    put_statement(
        d,
        &holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at),
        None,
        INGEST_TIER,
    )
    .await
    .expect("I4201: holder 0 second");
    assert!(
        held(d, &id).await.is_some(),
        "I4201: holders 2 then 0 land it, as 0 then 1 do"
    );
}

/// **I4202.**
pub(crate) async fn i4202_a_scope_outside_the_charter_is_refused(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4202: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, _) = worker_with_owner(d, "i4202").await;
    for i in 0..3 {
        let v = holder_grant(c, i, &worker, OUTSIDE, &head, at);
        let id = row_of(&v);
        let e = put_statement(d, &v, None, INGEST_TIER)
            .await
            .expect_err("I4202: a scope the charter does not cover");
        assert!(
            e.to_string().contains(CONFERRAL_OUTSIDE_CHARTER_SCOPE),
            "I4202: refused by name (voice {i}): {e}"
        );
        assert!(
            held(d, &id).await.is_none() && why(d, &id).await.is_none(),
            "I4202: nothing of it is kept or held (voice {i})"
        );
    }
    // The control: a sub-scope of the charter's `infra:attest` lands.
    land_grant(d, c, &worker, ATTEST_BUILD, &head, at, "I4202 control").await;
}

/// **I4203.** Two nodes, opposite arrival orders, one verdict (CC rc22
/// 7b4a55e: a grant counts only voices dated before the next held bundle).
pub(crate) async fn i4203_two_nodes_one_verdict(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
) {
    let first = bundle_v2();
    // A later bundle removes holder seed 3 and seats seed 4.
    let later = later_v2(first, &[1, 2, 4], &[11, 12], &[1, 2, 4]);
    let old = first.object_id;
    assert!(
        first.asserted_at_ms < later.asserted_at_ms,
        "I4203: the later bundle is asserted after the first"
    );
    // Both grants name the FIRST bundle and are voiced by two of its
    // holders. EARLY is dated before the later bundle's instant, LATE after.
    let early_at = first.asserted_at_ms + 1_000;
    let late_at = later.asserted_at_ms + 1_000;
    let voices = |worker: &str, scope: &str, at: u64| {
        [
            holder_grant(first, 0, worker, scope, &old, at),
            holder_grant(first, 1, worker, scope, &old, at),
        ]
    };

    // Node A: the first bundle, BOTH grants (no successor is held: every
    // voice counts, both land), THEN the later bundle.
    install_v2(a)
        .await
        .expect("I4203: A holds the first bundle");
    let (worker, _) = worker_with_owner(a, "i4203").await;
    let early = land_grant(
        a,
        first,
        &worker,
        ATTEST_BUILD,
        &old,
        early_at,
        "I4203 A early",
    )
    .await;
    let late = land_grant(
        a,
        first,
        &worker,
        ATTEST_EVIDENCE,
        &old,
        late_at,
        "I4203 A late",
    )
    .await;
    install_ceremony_v2(a, &later)
        .await
        .expect("I4203: A then holds the later bundle");

    // Node B: both bundles FIRST, then the same voices of both grants.
    install_v2(b)
        .await
        .expect("I4203: B holds the first bundle");
    install_ceremony_v2(b, &later)
        .await
        .expect("I4203: B holds the later bundle before either grant");
    let (worker_b, _) = worker_with_owner(b, "i4203").await;
    assert_eq!(worker, worker_b, "I4203: one worker key on both nodes");
    for v in voices(&worker, ATTEST_BUILD, early_at)
        .iter()
        .chain(voices(&worker, ATTEST_EVIDENCE, late_at).iter())
    {
        put_statement(b, v, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I4203: B keeps a holder's voice: {e}"));
    }

    let (early_id, late_id) = (row_of_id(&early), row_of_id(&late));
    for (node, d) in [("A", a), ("B", b)] {
        assert_eq!(
            genesis_in_force(d).await.unwrap().head.map(|p| p.object_id),
            Some(later.object_id),
            "I4203 node {node}: the later bundle is the head"
        );
        // EARLY: dated before the successor. It stands on both nodes.
        let row = held(d, &early_id).await.unwrap_or_else(|| {
            panic!(
                "I4203 node {node}: the grant dated before the later bundle is held; held {:?}",
                early_id.hex()
            )
        });
        let g = root_grant_of(d, &row, ms_now())
            .await
            .expect("root_grant_of")
            .unwrap_or_else(|| panic!("I4203 node {node}: a counted root grant"));
        assert_eq!(g.bundle, old, "I4203 node {node}: it names its bundle");
        assert!(
            !g.bundle_in_force,
            "I4203 node {node}: that bundle is no longer the one in force"
        );
        assert_eq!(
            g.family_key_id, FAMILY_KEY_ID,
            "I4203 node {node}: one accord"
        );
        // LATE: dated after the successor. Its voices do not count: it never
        // landed on B, and on A it is un-concluded when the later bundle
        // lands. One verdict.
        assert!(
            held(d, &late_id).await.is_none(),
            "I4203 node {node}: a grant under the first bundle dated AFTER the later bundle \
             counts no voice"
        );
        assert_eq!(
            why(d, &late_id).await.as_deref(),
            Some(super::fold::reason::COUNT_SHORT),
            "I4203 node {node}: kept, short of its count"
        );
        assert!(
            root_grant_of(d, &late, ms_now())
                .await
                .expect("root_grant_of")
                .is_none(),
            "I4203 node {node}: the reader counts it the same way: it confers nothing"
        );
    }
    // A grant naming the bundle IN FORCE, by two of ITS holders, lands.
    let at2 = grant_instant(a).await;
    land_grant(
        a,
        &later,
        &worker,
        ATTEST_EVIDENCE,
        &later.object_id,
        at2,
        "I4203 the bundle in force",
    )
    .await;
}

/// The row id of a held row.
fn row_of_id(row: &Attestation) -> RowId {
    let b: [u8; 32] = hex::decode(&row.attestation_id)
        .expect("a hex row id")
        .try_into()
        .expect("32 bytes");
    RowId(b)
}

/// **I4204.**
pub(crate) async fn i4204_the_end_of_a_grant(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4204: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, owner) = worker_with_owner(d, "i4204").await;
    let stranger = "s-i4204";
    e2::put_key(d, stranger, &["user"]).await;
    let by_root = land_grant(d, c, &worker, ATTEST_BUILD, &head, at, "I4204 a").await;
    let by_grantee = land_grant(d, c, &worker, ATTEST_EVIDENCE, &head, at, "I4204 b").await;
    let now = u64::try_from(ms_now().timestamp_millis()).expect("after 1970");

    // The root's counted withdrawal: one holder waits, two land it.
    let target = row_of_id(&by_root);
    let w0 = holder_withdrawal(c, 0, &worker, &target, &head, at + 60_000);
    let wid = row_of(&w0);
    let o = put_statement(d, &w0, None, INGEST_TIER)
        .await
        .expect("I4204: one holder's withdrawal voice is kept");
    assert!(pending(&o), "I4204: one holder's withdrawal waits: {o:?}");
    assert!(held(d, &wid).await.is_none(), "I4204: it has not landed");
    put_statement(
        d,
        &holder_withdrawal(c, 1, &worker, &target, &head, at + 60_000),
        None,
        INGEST_TIER,
    )
    .await
    .expect("I4204: the second holder's withdrawal voice");
    assert_eq!(
        held(d, &wid)
            .await
            .expect("I4204: two of three holders withdraw the grant")
            .withdraws_admission_rule,
        Some(crate::federation::admission::COUNT_UNDOES_COUNTED_RULE),
        "I4204: a count undoing a counted row is stamped rule 0 (KR-fix18.stamp)"
    );

    // A stranger's authored withdrawal is not admitted.
    let target = row_of_id(&by_grantee);
    let s = authored_withdrawal(stranger, &worker, &target, now);
    let sid = row_of(&s);
    let _ = put_statement(d, &s, None, INGEST_TIER).await;
    assert!(
        held(d, &sid).await.is_none(),
        "I4204: a stranger never withdraws the root's grant"
    );
    // One holder's AUTHORED withdrawal is not admitted either: the root's act
    // is never undone by one key. (Signed by a holder's bundle key.)
    let iss = c.holder_identity_ref(0).to_owned();
    let lone = sign_row_statement(
        &c.holder_key(0),
        &iss,
        &worker,
        attestation_type::WITHDRAWS,
        &trust_family(),
        &map(vec![
            ("asserted_at", Value::Uint(at + 90_000)),
            ("author", Value::Text(iss.clone())),
            ("refs", map(vec![("target", row_ref(&target.0))])),
        ]),
        vec![],
    )
    .expect("sign a holder's authored withdrawal");
    let lid = row_of(&lone);
    let _ = put_statement(d, &lone, None, INGEST_TIER).await;
    assert!(
        held(d, &lid).await.is_none(),
        "I4204: one holder alone never withdraws the root's grant"
    );
    // KR-fix18 — the worker's OWNER does not withdraw the GRANT either (the
    // leg that asserted "the grantee's own withdrawal lands on rule 3" is
    // deleted: that door is gone). The owner's consent is the acceptance;
    // I4313 withdraws that.
    let w = authored_withdrawal(&owner, &worker, &target, now + 1);
    let oid = row_of(&w);
    let _ = put_statement(d, &w, None, INGEST_TIER).await;
    assert!(
        held(d, &oid).await.is_none(),
        "I4204: the grantee's owner never withdraws the root's grant (KR-fix18)"
    );
    assert!(held(d, &target).await.is_some(), "I4204: the grant stands");
}

/// **I4219** (KR-fix8, as re-ruled for KR-fix18). NO single key gives up a
/// root grant: not a SIBLING node (another node bound to the same owner),
/// not a stranger, and (KR-fix18) not the grantee's own key nor its owner's
/// own key. The grant is the holders' consent; the grantee's is the
/// acceptance (I4313). The two legs that asserted "the grantee itself" and
/// "the grantee's owner" withdraw it on rule 3 are deleted; their setup is
/// kept here, asserting the refusal.
pub(crate) async fn i4219_who_gives_up_a_root_grant(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4219: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, owner) = worker_with_owner(d, "i4219").await;
    let (worker_seed, sibling_seed, stranger_seed) = ("w-i4219", "w2-i4219", "s-i4219");
    // A second node of the SAME owner; it is not the grantee.
    e2::put_key(d, sibling_seed, &["node"]).await;
    crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
        d,
        &owner,
        sibling_seed,
    )
    .await;
    e2::put_key(d, stranger_seed, &["user"]).await;
    let a = row_of_id(&land_grant(d, c, &worker, ATTEST_BUILD, &head, at, "I4219 a").await);
    let b = row_of_id(&land_grant(d, c, &worker, ATTEST_EVIDENCE, &head, at, "I4219 b").await);
    let now = u64::try_from(ms_now().timestamp_millis()).expect("after 1970");

    for (i, (who, seed)) in [
        ("a sibling node", sibling_seed),
        ("a stranger", stranger_seed),
        ("the grantee itself", worker_seed),
        ("the grantee's owner", owner.as_str()),
    ]
    .into_iter()
    .enumerate()
    {
        for (j, target) in [&a, &b].into_iter().enumerate() {
            let w = authored_withdrawal(seed, &worker, target, now + (i * 2 + j) as u64);
            let wid = row_of(&w);
            let out = put_statement(d, &w, None, INGEST_TIER).await;
            assert!(
                held(d, &wid).await.is_none(),
                "I4219: {who} never withdraws a root grant: {out:?}"
            );
            assert!(held(d, target).await.is_some(), "I4219: the grant stands");
        }
    }
}

/// **I4205.** An `agent` grantee.
pub(crate) async fn i4205_an_agent_grantee_accepts_through_its_owner(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4205: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (agent_seed, owner_seed) = ("a-i4205", "o-i4205");
    let agent = e2::put_key(d, agent_seed, &["agent"]).await;
    e2::put_key(d, owner_seed, &["user"]).await;
    // The owner binding is stated before the grant's own instant.
    e2::put_agent_owner_binding(d, owner_seed, agent_seed, at - 30_000).await;
    let grant = land_grant(d, c, &agent, ATTEST_BUILD, &head, at, "I4205").await;
    let accepted = |t: DateTime<Utc>| {
        let g = grant.clone();
        async move {
            root_grant_of(d, &g, t)
                .await
                .expect("root_grant_of")
                .expect("I4205: a counted root grant")
                .accepted
        }
    };
    let later = || ms_now() + chrono::Duration::seconds(1);
    assert!(!accepted(later()).await, "I4205: no acceptance yet");
    let _ = e2::put_signed(d, &acceptance(agent_seed, &grant)).await;
    assert!(
        !accepted(later()).await,
        "I4205: an agent cannot accept for itself"
    );
    e2::put_signed(d, &acceptance(owner_seed, &grant))
        .await
        .expect("I4205: the owner's acceptance is admitted");
    assert!(
        accepted(later()).await,
        "I4205: the agent's owner accepts for it"
    );
}

/// **I4206.** The acceptance before the grant.
pub(crate) async fn i4206_the_acceptance_before_the_grant(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4206: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, owner) = worker_with_owner(d, "i4206").await;
    // The grant as it WILL land, mapped in memory from holder 0's voice (its
    // row id and content hash are the row's, whichever voice projects it).
    let v0 = holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at);
    let _ = e2::register_foreign_key(&c.holder_key(0));
    let unlanded = e2::row_of_statement(&v0, INGEST_TIER);
    let id = row_of(&v0);
    assert_eq!(unlanded.attestation_id, id.hex(), "I4206: the row's own id");
    // The owner accepts FIRST: the reply waits for the grant it names.
    let acc = acceptance(&owner, &unlanded);
    let acc_id = RowId(e2::rid_digest(&acc));
    let o = e2::put_signed(d, &acc)
        .await
        .expect("I4206: an acceptance of an unheld grant is kept (held)");
    assert!(pending(&o), "I4206: it waits for the grant: {o:?}");
    assert!(
        held(d, &acc_id).await.is_none(),
        "I4206: a waiting acceptance concludes nothing"
    );
    // The holders land the grant: the acceptance re-folds and concludes.
    let grant = land_grant(d, c, &worker, ATTEST_BUILD, &head, at, "I4206").await;
    assert_eq!(
        grant.original_content_hash, unlanded.original_content_hash,
        "I4206: the content hash the acceptance bound is the landed row's"
    );
    assert!(
        held(d, &acc_id).await.is_some(),
        "I4206: the acceptance concludes once the grant lands; held {:?}",
        why(d, &acc_id).await
    );
    assert!(
        root_grant_of(d, &grant, ms_now() + chrono::Duration::seconds(1))
            .await
            .expect("root_grant_of")
            .expect("I4206: a counted root grant")
            .accepted,
        "I4206: accepted before, counted after: conferred"
    );
}

/// **I4207.** A rootless node, then the import.
pub(crate) async fn i4207_a_rootless_node_then_the_import(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = c.object_id;
    // The grant's instant, from the bundle (no bundle is held here yet).
    let at = c.spec.t0_ms + super::fixture_genesis::DAY_MS;
    let worker = e2::put_key(d, "w-i4207", &["node"]).await;
    let v0 = holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at);
    let v1 = holder_grant(c, 1, &worker, ATTEST_BUILD, &head, at);
    let id = row_of(&v0);
    // Rootless: the holder's key is no key this node holds. The voice is not
    // a landed row, whichever way the door says so (its retryable
    // unknown-signer wait keeps nothing; a hold keeps the voice).
    for v in [&v0, &v1] {
        match put_statement(d, v, None, INGEST_TIER).await {
            Err(_) => {}
            Ok(o) => assert!(
                pending(&o),
                "I4207: nothing lands on a rootless node: {o:?}"
            ),
        }
    }
    assert!(
        held(d, &id).await.is_none(),
        "I4207: a rootless node holds no grant from the root"
    );
    // The import, then the same two voices again (a peer re-offers them).
    assert_eq!(
        install_v2(d)
            .await
            .expect("I4207: the bundle installs")
            .object_id,
        head,
        "I4207: the bundle the voices name"
    );
    for v in [&v0, &v1] {
        put_statement(d, v, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I4207: a holder's voice after the import: {e}"));
    }
    assert!(
        held(d, &id).await.is_some(),
        "I4207: after the import the same voices land the grant; held {:?}",
        why(d, &id).await
    );
}

/// Deliver `from`'s edition-2 plane to `to` the way a peer pulls it: the
/// filtered serve listing for `requester`, cursor by cursor, each statement
/// through `to`'s one entry. Nothing is hand-copied: a statement `from` does
/// not serve to `requester` never arrives. A statement `to` cannot take yet
/// (it waits on a row not delivered) is skipped, as a puller retries.
async fn deliver(from: &dyn FederationDirectory, to: &dyn FederationDirectory, requester: &str) {
    let mut cursor = None;
    loop {
        let page = super::serve::statements_served_to(from, cursor.as_ref(), 256, Some(requester))
            .await
            .expect("the serve listing");
        let Some(next) = page.next else { break };
        cursor = Some(next);
        for st in page.statements {
            let _ = put_statement(to, &st.bytes, None, INGEST_TIER).await;
        }
    }
}

/// **I4208.** The host verbs on four nodes, through the serve feed. The
/// runner gave `n3` (the worker's node) the worker's key as its node key.
pub(crate) async fn i4208_host_verbs_across_four_nodes(
    n1: &dyn FederationDirectory,
    n2: &dyn FederationDirectory,
    n3: &dyn FederationDirectory,
    n4: &dyn FederationDirectory,
) {
    use super::second_signer_voice::{held_rows_for, submit_voice, voice_draft, VoiceOutcome};
    use crate::federation::admission::{root_grants_for, ROOT_HOLDER_ROLE};
    let c = bundle_v2();
    for d in [n1, n2, n3, n4] {
        install_v2(d)
            .await
            .expect("I4208: every node holds the bundle");
    }
    let head = c.object_id;
    let (h1, h2, h3) = (
        c.holder_identity_ref(0).to_owned(),
        c.holder_identity_ref(1).to_owned(),
        c.holder_identity_ref(2).to_owned(),
    );
    let (worker_seed, owner_seed) = ("w-i4208", "o-i4208");

    // The worker's node: the worker (its own node key), its owner, the
    // binding. It is ROOTED by today's rule (an accepted, rooted trust-root
    // community: W1b's fixture), so it serves federation rows to third
    // parties. (Part 1 re-points rootedness at the bundle.)
    let worker = e2::put_key(n3, worker_seed, &["node"]).await;
    e2::put_key(n3, owner_seed, &["user"]).await;
    crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
        n3,
        owner_seed,
        worker_seed,
    )
    .await;
    e2::rooted_trust_root(n3, &super::fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    // The holders' nodes learn the worker's key (key records are served to
    // anyone).
    deliver(n3, n1, &h1).await;
    deliver(n3, n2, &h2).await;

    // ── Holder 1's node: draft, sign elsewhere, submit ───────────────────
    let at = grant_instant(n1).await;
    let envelope = serde_json::json!({
        "dimension": crate::federation::trust_root::TRUST_CONFERS_DIMENSION,
        "scope": [ATTEST_BUILD],
        "head": hex::encode(head),
        // HEAD-4.rev2 — counted by its `author` (none), never by its head.
        "author": null,
    });
    let draft = super::emit::draft_from_envelope_in(
        n1,
        &super::fixture_genesis::kid_of(super::fixture_genesis::HOLDER_SEEDS[0]),
        &h1,
        &worker,
        attestation_type::DELEGATES_TO,
        &envelope,
        at,
        None,
    )
    .await
    .expect("I4208: the grant drafts");
    let first = draft.assemble(
        c.holder_key(0)
            .sign(&draft.sig_structure)
            .expect("I4208: holder 1 signs the draft"),
    );
    let id = row_of(&first);
    assert_eq!(
        id,
        row_of(&holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at)),
        "I4208: the drafted grant is the counted row, byte for byte (no author, refs.head)"
    );
    let o = submit_voice(n1, &first)
        .await
        .expect("I4208: holder 1's voice is kept");
    assert!(
        matches!(&o, VoiceOutcome::Waiting { reason, .. }
            if reason == super::fold::reason::COUNT_SHORT),
        "I4208: one holder's voice answers Waiting, count_short: {o:?}"
    );
    // While short: no grant is read; the row waits for the OTHER holders.
    let now = || ms_now() + chrono::Duration::seconds(1);
    assert!(
        root_grants_for(n1, &worker, now())
            .await
            .unwrap()
            .is_empty(),
        "I4208: a grant short of its count is not a grant"
    );
    assert!(
        held_rows_for(n1, &h1, Some(ROOT_HOLDER_ROLE), None, 10)
            .await
            .unwrap()
            .is_empty(),
        "I4208: holder 1 has voiced it"
    );
    assert_eq!(
        held_rows_for(n1, &h3, Some(ROOT_HOLDER_ROLE), None, 10)
            .await
            .unwrap()
            .len(),
        1,
        "I4208: it waits for holder 3 too"
    );

    // ── Holder 2's node: pull as holder 2, find it, voice it ─────────────
    // Node 1 is NOT rooted: the held voice reaches a holder of the bundle it
    // names (the serve rule's root-holder arm), and nobody else.
    deliver(n1, n4, "a-stranger").await;
    assert!(
        n4.edition2_voices(&id).await.unwrap().is_empty(),
        "I4208: a held root grant is not served to a stranger by an unrooted node"
    );
    deliver(n1, n2, &h2).await;
    let waiting = held_rows_for(n2, &h2, Some(ROOT_HOLDER_ROLE), None, 10)
        .await
        .unwrap();
    assert_eq!(
        waiting.len(),
        1,
        "I4208: holder 2 finds the grant: {waiting:?}"
    );
    assert_eq!(waiting[0].row_id, id.hex(), "I4208: the row");
    assert_eq!(waiting[0].role, ROOT_HOLDER_ROLE, "I4208: the role");
    assert_eq!(waiting[0].sub, worker, "I4208: the grantee");
    let d2 = voice_draft(&waiting[0].statement, &h2).expect("I4208: holder 2's voice drafts");
    let second = d2.assemble(
        c.holder_key(1)
            .sign(&d2.sig_structure)
            .expect("I4208: holder 2 signs"),
    );
    let o = submit_voice(n2, &second)
        .await
        .expect("I4208: holder 2's voice");
    assert!(o.is_seated(), "I4208: two of three holders seat it: {o:?}");
    assert!(
        held_rows_for(n2, &h3, Some(ROOT_HOLDER_ROLE), None, 10)
            .await
            .unwrap()
            .is_empty(),
        "I4208: a landed grant waits for nobody"
    );
    // Before the acceptance: counted, not conferring.
    let before = root_grants_for(n2, &worker, now()).await.unwrap();
    assert_eq!(before.len(), 1, "I4208: the counted grant is read");
    assert!(
        !before[0].accepted && !before[0].confers,
        "I4208: counted, not yet accepted: {:?}",
        before[0]
    );

    // ── The worker's node: pull the grant about itself; its OWNER accepts ─
    deliver(n2, n3, &worker).await;
    let grant = held(n3, &id)
        .await
        .expect("I4208: the worker's node holds the grant about it");
    let owner = ts::local_signer(owner_seed);
    crate::federation::attestation_emit::emit_statement(
        n3,
        &owner,
        crate::federation::membership_acceptance::reply_input(&grant, true),
        None,
    )
    .await
    .expect("I4208: the owner's acceptance is admitted");
    let mine = root_grants_for(n3, &worker, now()).await.unwrap();
    assert!(
        mine.len() == 1 && mine[0].accepted && mine[0].confers,
        "I4208: accepted on the worker's node: {mine:?}"
    );

    // ── A fourth node: pull from the worker's node, and read ─────────────
    deliver(n3, n4, "a-reader").await;
    let read = root_grants_for(n4, &worker, now()).await.unwrap();
    assert_eq!(
        read.len(),
        1,
        "I4208: the fourth node reads the grant: {read:?}"
    );
    let g = &read[0];
    assert_eq!(g.row_id, id.hex(), "I4208: the row");
    assert_eq!(g.grantee, worker, "I4208: the worker");
    assert_eq!(
        g.scope,
        vec![ATTEST_BUILD.to_owned()],
        "I4208: infra:attest:{{family}}"
    );
    assert_eq!(
        g.family_key_id, FAMILY_KEY_ID,
        "I4208: the root is the accord"
    );
    assert_eq!(g.bundle, hex::encode(head), "I4208: the bundle it names");
    assert!(
        g.bundle_in_force && g.accepted && !g.withdrawn && g.confers,
        "I4208: counted by two holders, accepted by the owner, conferring: {g:?}"
    );
}

/// What `from` serves `requester` of row `id`: how many of its voices are in
/// the filtered serve listing, and how many scanned statements the listing
/// withheld because `from` reaches no root (`ServedPage::waiting_for_rooted`).
async fn served_of(from: &dyn FederationDirectory, requester: &str, id: &RowId) -> (usize, u32) {
    let (mut voices, mut waiting, mut cursor) = (0, 0, None);
    loop {
        let page = super::serve::statements_served_to(from, cursor.as_ref(), 256, Some(requester))
            .await
            .expect("the serve listing");
        waiting += page.waiting_for_rooted;
        voices += page
            .statements
            .iter()
            .filter(|st| RowId::of_statement(&st.bytes) == Some(*id))
            .count();
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    (voices, waiting)
}

/// **I4210.** The serve rule's root-holder arm, both halves, on an UNROOTED
/// node (`group_serve::servable_without_row`). The node holds two bundles of
/// one lineage (holders {1,2,3}, then {1,2,4}) and ONE voice (holder 1's) of
/// a grant that names the FIRST. It serves that voice to a holder of the
/// NAMED bundle and to nobody else who is not a party of the row:
/// - holder 2 (both bundles) and holder 3 (the named bundle only): served;
/// - holder 4 (a holder of the LATER bundle only): not served;
/// - a stranger: not served, and the listing counts the row as waiting for
///   this node to reach a root (the node IS unrooted, and that is why);
/// - the row's own parties (the voice's signer, the grantee) are served by
///   the ordinary rule, as before.
///
/// What crosses is the grant's own held voice, and only a HOLDER's: a
/// non-holder's voice of a counted grant naming the bundle is kept short and
/// served to no holder (rev 7). The arm reads no other row.
pub(crate) async fn i4210_an_unrooted_node_serves_a_held_grant_to_the_named_holders(
    u: &dyn FederationDirectory,
) {
    let first = bundle_v2();
    let later = later_v2(first, &[1, 2, 4], &[11, 12], &[1, 2, 4]);
    install_v2(u)
        .await
        .expect("I4210: the first bundle installs");
    install_ceremony_v2(u, &later)
        .await
        .expect("I4210: the later bundle installs");
    let (worker, _) = worker_with_owner(u, "i4210").await;
    // Dated from the first bundle, before the later bundle's instant.
    let at = first.asserted_at_ms + 1_000;
    let voice = holder_grant(first, 0, &worker, ATTEST_BUILD, &first.object_id, at);
    let id = row_of(&voice);
    let o = put_statement(u, &voice, None, INGEST_TIER)
        .await
        .expect("I4210: holder 1's voice is kept");
    assert!(pending(&o), "I4210: one voice of three is short: {o:?}");
    assert!(
        held(u, &id).await.is_none(),
        "I4210: the grant is held, not landed"
    );

    let h = |c: &TestCeremonyV2, i: usize| c.holder_identity_ref(i).to_owned();
    let (h1, h2, h3) = (h(first, 0), h(first, 1), h(first, 2));
    let h4 = h(&later, 2);
    assert!(
        ![&h1, &h2, &h3].contains(&&h4),
        "I4210: holder 4 holds the later bundle only"
    );
    let stranger = e2::put_key(u, "s-i4210", &["user"]).await;

    // A stranger: withheld, because this node reaches no root.
    let (voices, waiting) = served_of(u, &stranger, &id).await;
    assert_eq!(voices, 0, "I4210: a stranger is not served the held grant");
    assert!(
        waiting >= 1,
        "I4210: the node is unrooted: the listing counts rows waiting for a root"
    );
    // A holder of a DIFFERENT bundle of the same lineage: not served.
    assert_eq!(
        served_of(u, &h4, &id).await.0,
        0,
        "I4210: a holder of the later bundle only is not a holder of the bundle the grant names"
    );
    // The holders of the NAMED bundle: served, from the unrooted node.
    for (name, holder) in [("holder 2", &h2), ("holder 3", &h3)] {
        assert_eq!(
            served_of(u, holder, &id).await.0,
            1,
            "I4210: {name} of the named bundle is served the one held voice"
        );
    }
    // The row's parties, by the ordinary rule.
    for (name, party) in [("its signer", &h1), ("the grantee", &worker)] {
        assert_eq!(
            served_of(u, party, &id).await.0,
            1,
            "I4210: {name} is served the row it is a party of"
        );
    }

    // A NON-holder's voice of a counted grant naming the same bundle (its own
    // row: another scope). KR-fix4: the door REFUSES it by name and keeps
    // nothing, so there is nothing of it to serve. (Before KR-fix4 it was
    // kept short and this leg asserted it was served to no holder; a
    // non-holder's voice kept before its bundle arrived is I4214's.)
    let pushed = grant_voice(
        &e2::signing_key("s-i4210"),
        &stranger,
        &worker,
        ATTEST_EVIDENCE,
        &first.object_id,
        at,
    );
    let pushed_id = row_of(&pushed);
    refused_not_a_holder(
        put_statement(u, &pushed, None, INGEST_TIER).await,
        "I4210: a non-holder's voice of a counted grant",
    );
    assert!(
        u.edition2_voices(&pushed_id)
            .await
            .expect("I4210: the voices")
            .is_empty(),
        "I4210: nothing of the non-holder's voice is kept"
    );
    for (name, holder) in [("holder 2", &h2), ("holder 3", &h3), ("holder 1", &h1)] {
        assert_eq!(
            served_of(u, holder, &pushed_id).await.0,
            0,
            "I4210: {name} is served nothing of it"
        );
    }
    // The holder's own voice is still served (the pushed row changed nothing).
    assert_eq!(
        served_of(u, &h2, &id).await.0,
        1,
        "I4210: holder 2 is still served holder 1's voice"
    );
}

/// The door refused a voice by name, `root_voice_not_a_holder`.
fn refused_not_a_holder(out: Result<StatementOutcome, crate::federation::Error>, what: &str) {
    match out {
        Err(e)
            if e.to_string()
                .contains(crate::federation::admission::ROOT_VOICE_NOT_A_HOLDER) => {}
        other => panic!("{what}: expected root_voice_not_a_holder, got {other:?}"),
    }
}

/// **I4213.** With the named bundle HELD, a non-holder's voice of a counted
/// grant from the root is refused by name and nothing is kept: on a row
/// nobody has voiced, on a row one holder has voiced (still short), and on a
/// landed row. The holders' own voices of the same row are untouched.
pub(crate) async fn i4213_a_non_holders_voice_is_refused(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    install_v2(d).await.expect("I4213: the bundle installs");
    let head = c.object_id;
    let (worker, _) = worker_with_owner(d, "i4213").await;
    let at = grant_instant(d).await;
    let stranger = e2::put_key(d, "s-i4213", &["user"]).await;
    // The stranger's voice is a voice of the SAME row the holders voice (one
    // payload, one row id).
    let pushed = grant_voice(
        &e2::signing_key("s-i4213"),
        &stranger,
        &worker,
        ATTEST_BUILD,
        &head,
        at,
    );
    let id = row_of(&pushed);
    assert_eq!(
        id,
        row_of(&holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at)),
        "I4213: one row"
    );
    let voices = || async {
        d.edition2_voices(&id)
            .await
            .expect("I4213: the voices")
            .len()
    };

    // Nobody has voiced it: refused, nothing kept, nothing held.
    refused_not_a_holder(
        put_statement(d, &pushed, None, INGEST_TIER).await,
        "I4213: a non-holder opens a counted root row",
    );
    assert_eq!(voices().await, 0, "I4213: nothing is kept");
    assert!(
        why(d, &id).await.is_none() && held(d, &id).await.is_none(),
        "I4213: no row is held and none landed"
    );

    // One holder has voiced it (short): the non-holder's voice is refused.
    let o = put_statement(
        d,
        &holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at),
        None,
        INGEST_TIER,
    )
    .await
    .expect("I4213: holder 1's voice is kept");
    assert!(pending(&o), "I4213: one of three: {o:?}");
    refused_not_a_holder(
        put_statement(d, &pushed, None, INGEST_TIER).await,
        "I4213: a non-holder joins a short row",
    );
    assert_eq!(voices().await, 1, "I4213: only holder 1's voice is kept");

    // Landed: still refused.
    put_statement(
        d,
        &holder_grant(c, 1, &worker, ATTEST_BUILD, &head, at),
        None,
        INGEST_TIER,
    )
    .await
    .expect("I4213: holder 2's voice");
    assert!(held(d, &id).await.is_some(), "I4213: two holders land it");
    refused_not_a_holder(
        put_statement(d, &pushed, None, INGEST_TIER).await,
        "I4213: a non-holder joins a landed row",
    );
    assert_eq!(voices().await, 2, "I4213: the two holders' voices only");
}

/// **I4214.** The other order: the voice arrives BEFORE the bundle it names.
/// A non-holder's voice cannot be judged yet. Either the door keeps nothing
/// (its retryable wait) or it holds the voice on the bundle. When the bundle
/// lands the row is judged: it does not land, it is no longer waiting on a
/// count (`refold_refused`, naming `root_voice_not_a_holder`), it is served
/// to no holder, and re-offering the voice is refused. The holders' own
/// voices of the same row then land it: a non-holder's early voice does not
/// take the row down.
pub(crate) async fn i4214_a_non_holders_voice_before_the_bundle(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = c.object_id;
    // From the bundle's own instant (no bundle is held here yet).
    let at = c.spec.t0_ms + super::fixture_genesis::DAY_MS;
    let worker = e2::put_key(d, "w-i4214", &["node"]).await;
    let stranger = e2::put_key(d, "s-i4214", &["user"]).await;
    let pushed = grant_voice(
        &e2::signing_key("s-i4214"),
        &stranger,
        &worker,
        ATTEST_BUILD,
        &head,
        at,
    );
    let id = row_of(&pushed);
    let kept = match put_statement(d, &pushed, None, INGEST_TIER).await {
        Err(_) => false,
        Ok(o) => {
            assert!(pending(&o), "I4214: nothing lands before the bundle: {o:?}");
            true
        }
    };
    assert_eq!(
        install_v2(d)
            .await
            .expect("I4214: the bundle installs")
            .object_id,
        head,
        "I4214: the bundle the voice names"
    );
    assert!(
        held(d, &id).await.is_none(),
        "I4214: a row only a non-holder voiced never lands"
    );
    if kept {
        let h = super::fold::why_held(d, &id)
            .await
            .expect("I4214: why_held")
            .expect("I4214: the kept row is held");
        assert_eq!(
            h.reason,
            super::fold::reason::REFOLD_REFUSED,
            "I4214: judged when the bundle landed, no longer waiting on a count: {h:?}"
        );
        assert!(
            h.detail
                .contains(crate::federation::admission::ROOT_VOICE_NOT_A_HOLDER),
            "I4214: refused by name: {h:?}"
        );
        for i in 0..3 {
            assert_eq!(
                served_of(d, c.holder_identity_ref(i), &id).await.0,
                0,
                "I4214: holder {} is not served a non-holder's voice",
                i + 1
            );
        }
    }
    // Re-offered after the bundle: refused by name, in either case.
    refused_not_a_holder(
        put_statement(d, &pushed, None, INGEST_TIER).await,
        "I4214: the non-holder's voice re-offered after the bundle",
    );
    // The holders' own voices of the same row land it.
    for i in 0..2 {
        put_statement(
            d,
            &holder_grant(c, i, &worker, ATTEST_BUILD, &head, at),
            None,
            INGEST_TIER,
        )
        .await
        .unwrap_or_else(|e| panic!("I4214: holder {}'s voice: {e}", i + 1));
    }
    assert!(
        held(d, &id).await.is_some(),
        "I4214: two holders land the row; held {:?}",
        why(d, &id).await
    );
}

/// Nothing is held under row `id`.
async fn no_voice_kept(d: &dyn FederationDirectory, id: &RowId) {
    assert!(
        d.edition2_voices(id).await.expect("the voices").is_empty(),
        "nothing of a non-holder's re-bind voice is kept"
    );
}

/// **I4216.** A held grant is served from a ROOTED node by the ordinary
/// commons rule (`serve::commons_servable`), not by the root-holder arm: the
/// node reaches a root (the runner gave it a node key; W1b's fixture roots
/// it), holder 1's voice is held short, and the listing serves it to holder 2
/// and to a third party alike, with nothing counted as waiting for a root.
/// (The unrooted half is I4210: only the named bundle's holders are served.)
pub(crate) async fn i4216_a_rooted_node_serves_a_held_grant(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    install_v2(d).await.expect("I4216: the bundle installs");
    e2::rooted_trust_root(d, &super::fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let (worker, _) = worker_with_owner(d, "i4216").await;
    let at = grant_instant(d).await;
    let voice = holder_grant(c, 0, &worker, ATTEST_BUILD, &c.object_id, at);
    let id = row_of(&voice);
    let o = put_statement(d, &voice, None, INGEST_TIER)
        .await
        .expect("I4216: holder 1's voice is kept");
    assert!(pending(&o), "I4216: one of three is short: {o:?}");
    assert!(held(d, &id).await.is_none(), "I4216: held, not landed");
    let stranger = e2::put_key(d, "s-i4216", &["user"]).await;
    for (name, requester) in [
        ("holder 2", c.holder_identity_ref(1).to_owned()),
        ("a third party", stranger),
    ] {
        let (voices, waiting) = served_of(d, &requester, &id).await;
        assert_eq!(
            voices, 1,
            "I4216: a rooted node serves the held grant to {name}"
        );
        assert_eq!(
            waiting, 0,
            "I4216: the node is rooted: nothing waits for a root ({name})"
        );
    }
}

/// **I4215.** The seat RE-BIND door, both orders: a non-holder's voice is
/// never kept. With the named bundle held it is refused
/// (`reserved_family_unseated`); before the bundle it is the retryable wait,
/// which keeps nothing, and after the bundle lands the same voice is refused.
pub(crate) async fn i4215_a_non_holders_rebind_voice(
    with: &dyn FederationDirectory,
    without: &dyn FederationDirectory,
) {
    use super::transport_rebind::{REBIND_FAMILY, REBIND_ROW_TYPE, TRANSIT_MEMBER};
    let c = bundle_v2();
    let seat = &c.seats[0];
    let mut rebound = seat.transit_xwing_pubkey.to_vec();
    rebound[0] ^= 0x2f;
    let payload = map(vec![
        ("asserted_at", Value::Uint(c.asserted_at_ms + 1_000)),
        ("refs", map(vec![("head", row_ref(&c.object_id))])),
        (TRANSIT_MEMBER, Value::Bytes(rebound)),
    ]);
    let pushed = |iss: &str| {
        sign_row_statement(
            &e2::signing_key("s-i4215"),
            iss,
            &seat.identity_ref,
            REBIND_ROW_TYPE,
            REBIND_FAMILY,
            &payload,
            vec![],
        )
        .expect("I4215: a non-holder signs a re-bind")
    };
    // The bundle held: refused.
    install_v2(with).await.expect("I4215: the bundle installs");
    let stranger = e2::put_key(with, "s-i4215", &["user"]).await;
    let v = pushed(&stranger);
    let id = row_of(&v);
    match put_statement(with, &v, None, INGEST_TIER).await {
        Err(e) if e.kind() != "federation_attester_key_unknown" => {}
        other => panic!("I4215: a non-holder's re-bind over a held bundle: {other:?}"),
    }
    no_voice_kept(with, &id).await;

    // The bundle not held: the retryable wait, nothing kept; then refused.
    let stranger = e2::put_key(without, "s-i4215", &["user"]).await;
    let v = pushed(&stranger);
    match put_statement(without, &v, None, INGEST_TIER).await {
        Err(e) if e.kind() == "federation_attester_key_unknown" => {}
        other => panic!("I4215: a re-bind over a bundle not held waits: {other:?}"),
    }
    no_voice_kept(without, &id).await;
    install_v2(without)
        .await
        .expect("I4215: the bundle installs");
    match put_statement(without, &v, None, INGEST_TIER).await {
        Err(e) if e.kind() != "federation_attester_key_unknown" => {}
        other => panic!("I4215: judged when the bundle is held: {other:?}"),
    }
    no_voice_kept(without, &id).await;
}

/// **I4212.** A holder on a SECOND node finds a pending seat re-bind and
/// voices it (`held_rows_for`, role `root_holder`), and both nodes agree.
/// Holder 1 voices a re-bind on node 1 (short). Node 2 pulls node 1's serve
/// feed as holder 2: a re-bind is a bootstrap kind, served by a rooted or an
/// unrooted node alike. On node 2, holder 2 finds the row through
/// `held_rows_for` (holder 1, who voiced it, and a stranger do not), drafts
/// its voice from the listed statement, signs and submits: seated. Node 1
/// pulls back. Then on both nodes the re-bind counts, `voice_status` is
/// seated, it waits for nobody, and it is the seat's live re-bind.
pub(crate) async fn i4212_a_holder_finds_a_pending_rebind_on_a_second_node(
    n1: &dyn FederationDirectory,
    n2: &dyn FederationDirectory,
) {
    use super::second_signer_voice::{held_rows_for, row_status, submit_voice, voice_draft};
    use super::transport_rebind::{
        rebind_counted, rebind_held_for, REBIND_FAMILY, REBIND_ROW_TYPE, TRANSIT_MEMBER,
    };
    use crate::federation::admission::ROOT_HOLDER_ROLE;
    let c = bundle_v2();
    for d in [n1, n2] {
        install_v2(d)
            .await
            .expect("I4212: both nodes hold the bundle");
    }
    let (h1, h2, h3) = (
        c.holder_identity_ref(0).to_owned(),
        c.holder_identity_ref(1).to_owned(),
        c.holder_identity_ref(2).to_owned(),
    );
    let seat = &c.seats[0];
    let mut rebound = seat.transit_xwing_pubkey.to_vec();
    rebound[0] ^= 0x2c;
    rebound[1200] ^= 0x2c;
    // Dated from the bundle, never the wall clock.
    let at = c.asserted_at_ms + 1_000;
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("refs", map(vec![("head", row_ref(&c.object_id))])),
        (TRANSIT_MEMBER, Value::Bytes(rebound.clone())),
    ]);
    let first = sign_row_statement(
        &c.holder_key(0),
        &h1,
        &seat.identity_ref,
        REBIND_ROW_TYPE,
        REBIND_FAMILY,
        &payload,
        vec![],
    )
    .expect("I4212: holder 1 signs the re-bind");
    let id = row_of(&first);

    // Node 1: holder 1's voice, short.
    let o = put_statement(n1, &first, None, INGEST_TIER)
        .await
        .expect("I4212: holder 1's voice is kept");
    assert!(pending(&o), "I4212: one holder of three is short: {o:?}");
    assert!(
        held_rows_for(n1, &h1, Some(ROOT_HOLDER_ROLE), None, 10)
            .await
            .unwrap()
            .is_empty(),
        "I4212: holder 1 has voiced it"
    );

    // Node 2 pulls as holder 2 and FINDS it.
    deliver(n1, n2, &h2).await;
    let stranger = e2::put_key(n2, "s-i4212", &["user"]).await;
    assert!(
        held_rows_for(n2, &stranger, None, None, 10)
            .await
            .unwrap()
            .iter()
            .all(|r| r.row_id != id.hex()),
        "I4212: a stranger is not asked to voice a re-bind"
    );
    let waiting = held_rows_for(n2, &h2, Some(ROOT_HOLDER_ROLE), None, 10)
        .await
        .unwrap();
    assert_eq!(
        waiting.len(),
        1,
        "I4212: holder 2 finds the pending re-bind on its own node: {waiting:?}"
    );
    assert_eq!(waiting[0].row_id, id.hex(), "I4212: the row");
    assert_eq!(waiting[0].role, ROOT_HOLDER_ROLE, "I4212: the role");
    assert_eq!(waiting[0].sub, seat.identity_ref, "I4212: the seat");
    assert_eq!(
        waiting[0].reason,
        super::fold::reason::COUNT_SHORT,
        "I4212: why it waits"
    );
    let d2 = voice_draft(&waiting[0].statement, &h2).expect("I4212: holder 2's voice drafts");
    let second = d2.assemble(
        c.holder_key(1)
            .sign(&d2.sig_structure)
            .expect("I4212: holder 2 signs"),
    );
    assert_eq!(row_of(&second), id, "I4212: a voice of the same row");
    let o = submit_voice(n2, &second)
        .await
        .expect("I4212: holder 2's voice");
    assert!(o.is_seated(), "I4212: two of three holders seat it: {o:?}");

    // Node 1 pulls back; both nodes agree.
    deliver(n2, n1, &h1).await;
    for (name, d) in [("node 1", n1), ("node 2", n2)] {
        assert_eq!(
            rebind_counted(d, &id).await.expect("I4212: reads"),
            Some(true),
            "I4212: {name}: the re-bind counts"
        );
        assert!(
            row_status(d, &id)
                .await
                .expect("I4212: voice_status")
                .is_seated(),
            "I4212: {name}: voice_status is seated"
        );
        assert!(
            held_rows_for(d, &h3, Some(ROOT_HOLDER_ROLE), None, 10)
                .await
                .unwrap()
                .is_empty(),
            "I4212: {name}: a counted re-bind waits for nobody"
        );
        let live = rebind_held_for(d, &seat.identity_ref)
            .await
            .expect("I4212: reads")
            .unwrap_or_else(|| panic!("I4212: {name}: no live re-bind"));
        assert_eq!(live.row_id, id, "I4212: {name}: the live re-bind");
        assert_eq!(
            live.transit_xwing_pubkey.to_vec(),
            rebound,
            "I4212: {name}: its key"
        );
    }
}

/// **I4211.** The host verbs THEMSELVES, on one Engine: `statement_draft`,
/// `submit_voice`, `voice_status`, `held_rows_for`, `voice_draft` and
/// `root_grants_for` (I4208 drives the functions under them, across nodes).
/// The Engine holds the test bundle from its boot.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn i4211_the_engine_verbs(e: &crate::Engine) {
    use super::second_signer_voice::VoiceOutcome;
    use crate::federation::admission::ROOT_HOLDER_ROLE;
    let c = bundle_v2();
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let head = genesis_in_force(d)
        .await
        .expect("I4211: the genesis in force")
        .head
        .as_ref()
        .map(|p| p.object_id)
        .expect("I4211: the Engine booted with the test bundle in force");
    assert_eq!(head, c.object_id, "I4211: the test bundle");
    let (h1, h2) = (
        c.holder_identity_ref(0).to_owned(),
        c.holder_identity_ref(1).to_owned(),
    );
    let (worker, owner_seed) = worker_with_owner(d, "i4211").await;
    let at = grant_instant(d).await;
    let now = || Some(ms_now() + chrono::Duration::seconds(1));

    // Holder 1 drafts the grant through the Engine verb, signs, submits.
    let envelope = serde_json::json!({
        "dimension": crate::federation::trust_root::TRUST_CONFERS_DIMENSION,
        "scope": [ATTEST_BUILD],
        "head": hex::encode(head),
        // HEAD-4.rev2 — counted by its `author` (none), never by its head.
        "author": null,
    });
    let draft = e
        .statement_draft(
            attestation_type::DELEGATES_TO,
            &envelope,
            &h1,
            &hex::encode(super::fixture_genesis::kid_of(
                super::fixture_genesis::HOLDER_SEEDS[0],
            )),
            &worker,
            at,
            None,
        )
        .await
        .expect("I4211: Engine::statement_draft drafts the grant");
    let first = draft.assemble(
        c.holder_key(0)
            .sign(&draft.sig_structure)
            .expect("I4211: holder 1 signs"),
    );
    let id = row_of(&first);
    assert_eq!(
        id,
        row_of(&holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at)),
        "I4211: the Engine's draft is the counted row (no author, refs.head)"
    );
    let waiting = |o: &VoiceOutcome| {
        matches!(o, VoiceOutcome::Waiting { reason, .. }
            if reason == super::fold::reason::COUNT_SHORT)
    };
    let o = e
        .submit_voice(&first)
        .await
        .expect("I4211: Engine::submit_voice keeps holder 1's voice");
    assert!(waiting(&o), "I4211: one voice is count_short: {o:?}");
    let o = e
        .voice_status(&id.hex())
        .await
        .expect("I4211: Engine::voice_status");
    assert!(waiting(&o), "I4211: voice_status while short: {o:?}");
    assert!(
        e.root_grants_for(&worker, now())
            .await
            .expect("I4211: Engine::root_grants_for")
            .is_empty(),
        "I4211: short of its count, root_grants_for reads no grant"
    );

    // Holder 2 finds it through the Engine, drafts its voice, submits.
    let rows = e
        .held_rows_for(Some(h2.as_str()), Some(ROOT_HOLDER_ROLE), None, 10)
        .await
        .expect("I4211: Engine::held_rows_for");
    assert_eq!(rows.len(), 1, "I4211: holder 2 finds the grant: {rows:?}");
    assert_eq!(rows[0].row_id, id.hex(), "I4211: the row");
    let d2 = e
        .voice_draft(&rows[0].row_id, &h2)
        .await
        .expect("I4211: Engine::voice_draft");
    let second = d2.assemble(
        c.holder_key(1)
            .sign(&d2.sig_structure)
            .expect("I4211: holder 2 signs"),
    );
    let o = e
        .submit_voice(&second)
        .await
        .expect("I4211: holder 2's voice");
    assert!(o.is_seated(), "I4211: two of three seat it: {o:?}");

    // Counted, not yet accepted.
    let before = e
        .root_grants_for(&worker, now())
        .await
        .expect("I4211: Engine::root_grants_for");
    assert_eq!(before.len(), 1, "I4211: the counted grant is read");
    assert!(
        before[0].row_id == id.hex()
            && before[0].bundle == hex::encode(head)
            && before[0].bundle_in_force
            && !before[0].accepted
            && !before[0].confers,
        "I4211: counted, not accepted: {:?}",
        before[0]
    );

    // The worker's OWNER accepts (its own signer, not the Engine's).
    let grant = held(d, &id).await.expect("I4211: the grant is held");
    crate::federation::attestation_emit::emit_statement(
        d,
        &ts::local_signer(&owner_seed),
        crate::federation::membership_acceptance::reply_input(&grant, true),
        None,
    )
    .await
    .expect("I4211: the owner's acceptance is admitted");
    let after = e
        .root_grants_for(&worker, now())
        .await
        .expect("I4211: Engine::root_grants_for");
    assert!(
        after.len() == 1 && after[0].accepted && after[0].confers && !after[0].withdrawn,
        "I4211: counted and accepted, conferring: {after:?}"
    );
}

/// **I4218** (KR-fix7). A seat re-bind produced end to end by the host
/// verbs, no software key in the Engine: holder 1 DRAFTS the first voice
/// (`Engine::statement_draft`), signs the draft outside the Engine, submits
/// (short); holder 2 finds it (`Engine::held_rows_for`, role `root_holder`),
/// drafts its voice (`Engine::voice_draft`), signs outside, submits: seated,
/// and it is the seat's live re-bind. The drafted first voice is the same
/// row a statement signed directly over the documented payload names.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn i4218_a_rebind_drafted_and_voiced_by_hardware_holders(e: &crate::Engine) {
    use super::second_signer_voice::VoiceOutcome;
    use super::transport_rebind::{REBIND_FAMILY, REBIND_ROW_TYPE, TRANSIT_MEMBER};
    use crate::federation::admission::ROOT_HOLDER_ROLE;
    use crate::federation::transport_rebind::REBIND_DIMENSION;
    let c = bundle_v2();
    let (h1, h2) = (
        c.holder_identity_ref(0).to_owned(),
        c.holder_identity_ref(1).to_owned(),
    );
    let seat = &c.seats[0];
    let mut rebound = seat.transit_xwing_pubkey.to_vec();
    rebound[0] ^= 0x31;
    rebound[1200] ^= 0x31;
    // Dated from the bundle, never the wall clock.
    let at = c.asserted_at_ms + 1_000;
    // The DIMENSION carries its version leaf (`transport:canonical_rebind:v1`);
    // it resolves to the family `transport:canonical_rebind`, which the direct
    // statement below names in its header. The bare family id is no dimension
    // (`family_for`: "resolves to no registered family").
    let envelope = serde_json::json!({
        "dimension": REBIND_DIMENSION,
        "head": hex::encode(c.object_id),
        TRANSIT_MEMBER: hex::encode(&rebound),
    });
    let draft = e
        .statement_draft(
            REBIND_ROW_TYPE,
            &envelope,
            &h1,
            &hex::encode(super::fixture_genesis::kid_of(
                super::fixture_genesis::HOLDER_SEEDS[0],
            )),
            &seat.identity_ref,
            at,
            None,
        )
        .await
        .expect("I4218: Engine::statement_draft drafts a re-bind");
    let first = draft.assemble(
        c.holder_key(0)
            .sign(&draft.sig_structure)
            .expect("I4218: holder 1 signs outside the Engine"),
    );
    let id = row_of(&first);
    let direct = sign_row_statement(
        &c.holder_key(0),
        &h1,
        &seat.identity_ref,
        REBIND_ROW_TYPE,
        REBIND_FAMILY,
        &map(vec![
            ("asserted_at", Value::Uint(at)),
            ("refs", map(vec![("head", row_ref(&c.object_id))])),
            (TRANSIT_MEMBER, Value::Bytes(rebound.clone())),
        ]),
        vec![],
    )
    .expect("I4218: the documented payload signs");
    assert_eq!(
        id,
        row_of(&direct),
        "I4218: the draft states exactly asserted_at, refs.head and the key (no author, no \
         dimension)"
    );
    let o = e
        .submit_voice(&first)
        .await
        .expect("I4218: holder 1's drafted voice is kept");
    assert!(
        matches!(&o, VoiceOutcome::Waiting { reason, .. }
            if reason == super::fold::reason::COUNT_SHORT),
        "I4218: one holder of three is short: {o:?}"
    );
    let rows = e
        .held_rows_for(Some(h2.as_str()), Some(ROOT_HOLDER_ROLE), None, 10)
        .await
        .expect("I4218: Engine::held_rows_for");
    assert_eq!(rows.len(), 1, "I4218: holder 2 finds the re-bind: {rows:?}");
    assert_eq!(rows[0].row_id, id.hex(), "I4218: the row");
    let d2 = e
        .voice_draft(&rows[0].row_id, &h2)
        .await
        .expect("I4218: Engine::voice_draft");
    let second = d2.assemble(
        c.holder_key(1)
            .sign(&d2.sig_structure)
            .expect("I4218: holder 2 signs outside the Engine"),
    );
    let o = e
        .submit_voice(&second)
        .await
        .expect("I4218: holder 2's voice");
    assert!(o.is_seated(), "I4218: two of three seat it: {o:?}");
    let live = e
        .rebind_held_for(&seat.identity_ref)
        .await
        .expect("I4218: Engine::rebind_held_for")
        .expect("I4218: a live re-bind");
    assert_eq!(live.row_id, id, "I4218: the live re-bind");
    assert_eq!(
        live.transit_xwing_pubkey.to_vec(),
        rebound,
        "I4218: its key"
    );
}

/// **I4217** (KR-fix6). The acceptance of a HARDWARE-held owner: drafted by
/// the Engine, signed outside it, submitted. The owner's key is one the
/// Engine does not hold (a fixture composite key): the test signs the
/// returned `sig_structure`, as a YubiKey would. The reply is admitted and
/// the grant confers. Before the acceptance nothing confers, and the WORKER's
/// own drafted acceptance (signed with the worker's key) confers nothing.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn i4217_a_hardware_held_owner_accepts_by_draft(e: &crate::Engine) {
    use crate::federation::membership_acceptance::reply_envelope;
    let c = bundle_v2();
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let head = c.object_id;
    let (worker, owner_seed) = worker_with_owner(d, "i4217").await;
    let worker_seed = "w-i4217";
    let grant = land_grant(
        d,
        c,
        &worker,
        ATTEST_BUILD,
        &head,
        grant_instant(d).await,
        "I4217",
    )
    .await;
    let now = || Some(ms_now() + chrono::Duration::seconds(1));
    let read = || async {
        e.root_grants_for(&worker, now())
            .await
            .expect("I4217: Engine::root_grants_for")
    };
    assert!(
        read().await.len() == 1 && !read().await[0].confers,
        "I4217: counted, not accepted"
    );
    let envelope = reply_envelope(&grant, true);
    let at_ms = u64::try_from(ms_now().timestamp_millis()).expect("ms");
    let drafted = |seed: &'static str| {
        let envelope = envelope.clone();
        let worker = worker.clone();
        async move {
            let draft = e
                .statement_draft(
                    attestation_type::SCORES,
                    &envelope,
                    &e2::kid(seed),
                    &hex::encode(e2::kid_digest(seed)),
                    &worker,
                    at_ms,
                    None,
                )
                .await
                .expect("I4217: Engine::statement_draft drafts the reply");
            draft.assemble(
                e2::signing_key(seed)
                    .sign(&draft.sig_structure)
                    .expect("I4217: signed outside the Engine"),
            )
        }
    };
    // The worker's own key: kept or refused, it confers nothing.
    let _ = e.submit_voice(&drafted(worker_seed).await).await;
    assert!(
        !read().await[0].confers,
        "I4217: a worker cannot accept its own grant by a draft either"
    );
    // The owner's key, held outside the Engine.
    let owner_seed: &'static str = Box::leak(owner_seed.into_boxed_str());
    let reply = drafted(owner_seed).await;
    let (_, payload) = super::liveness::statement_parts(&reply).expect("I4217: the reply reads");
    assert_eq!(
        super::names::names_of(&payload)
            .ok()
            .and_then(|n| super::names::single(&n, "target")),
        Some(row_of_id(&grant)),
        "I4217: the drafted reply names the grant in refs.target"
    );
    let o = e
        .submit_voice(&reply)
        .await
        .expect("I4217: the owner's drafted acceptance is admitted");
    assert!(o.is_seated(), "I4217: admitted: {o:?}");
    let after = read().await;
    assert!(
        after.len() == 1 && after[0].accepted && after[0].confers,
        "I4217: accepted by the hardware-held owner, conferring: {after:?}"
    );
}

/// **I4316** (KR-fix18.stamp; CC 2.4.1.1 rule 0). THE HOLDERS' COUNT RETIRES
/// THE GRANT ON READ, whoever voiced first. The grant's first voice is
/// holder 1's; the withdrawal's is holder 3's, then holder 2's. Before the
/// stamp fix that withdrawal was stamped 4 ("a delegate"), which was not
/// true of it; it did retire the grant, because a root grant is not a
/// carved-out target (`precedence::stamp_policy`: any stamp counts). No
/// witness read the retirement through the readers; this one does, and pins
/// the stamp. The carved-out case, where a 4 retired nothing, is a counted
/// licence: I3297.
///
/// - one holder's counted voice is not a count: it waits, nothing changes;
/// - at the count: stamped 0; the fold counts it
///   (`precedence::retraction_entitled`, and by its stamp alone under the
///   producer-side policy); `root_grants_for` reads
///   `withdrawn`, not conferring; `trust_root::live_conferral_rows` (the one
///   read behind the capability walk and peer rooting's delegation seat) no
///   longer returns the grant; the grant row is still held, as history.
pub(crate) async fn i4316_the_holders_count_retires_the_grant_on_read(d: &dyn FederationDirectory) {
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4316: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, owner) = worker_with_owner(d, "i4316").await;
    let grant = land_grant(d, c, &worker, ATTEST_BUILD, &head, at, "I4316").await;
    let target = row_of_id(&grant);
    e2::put_signed(d, &acceptance(&owner, &grant))
        .await
        .expect("I4316: the owner's acceptance is admitted");
    let later = || ms_now() + chrono::Duration::seconds(1);
    let view = || async {
        let mut v = crate::federation::admission::root_grants_for(d, &worker, later())
            .await
            .expect("I4316: root_grants_for");
        assert_eq!(v.len(), 1, "I4316: the grant is listed: {v:?}");
        v.remove(0)
    };
    let live = || async {
        crate::federation::trust_root::live_conferral_rows(d, &worker, ATTEST_BUILD, later())
            .await
            .expect("I4316: live_conferral_rows")
            .iter()
            .any(|r| r.attestation_id == grant.attestation_id)
    };
    assert!(
        view().await.confers && live().await,
        "I4316 premise: counted, accepted, conferring, a live conferral row"
    );

    // Holder 3 voices the withdrawal FIRST (the grant's first voice was
    // holder 1's). One voice is not a count.
    let w0 = holder_withdrawal(c, 2, &worker, &target, &head, at + 60_000);
    let wid = row_of(&w0);
    let o = put_statement(d, &w0, None, INGEST_TIER)
        .await
        .expect("I4316: one holder's withdrawal voice is kept");
    assert!(pending(&o), "I4316: one holder's voice waits: {o:?}");
    assert!(
        held(d, &wid).await.is_none() && view().await.confers && live().await,
        "I4316: a lone holder's voice is not a count: nothing changes"
    );

    put_statement(
        d,
        &holder_withdrawal(c, 1, &worker, &target, &head, at + 60_000),
        None,
        INGEST_TIER,
    )
    .await
    .expect("I4316: the second holder's withdrawal voice");
    let w = held(d, &wid)
        .await
        .expect("I4316: two of three holders land the withdrawal");
    assert_ne!(
        w.attesting_key_id, grant.attesting_key_id,
        "I4316 premise: the withdrawal's first voice is not the grant's"
    );
    assert_eq!(
        w.withdraws_admission_rule,
        Some(crate::federation::admission::COUNT_UNDOES_COUNTED_RULE),
        "I4316: a count undoing a counted row is stamped rule 0, never 1 or 4"
    );
    assert!(
        crate::federation::precedence::retraction_entitled(&w, &grant)
            && crate::federation::precedence::stamp_entitles(
                &w,
                crate::federation::precedence::StampPolicy::ProducerSide
            ),
        "I4316: the fold counts the holders' withdrawal, under the strictest stamp policy too"
    );
    let g = view().await;
    assert!(
        g.withdrawn && !g.confers,
        "I4316: root_grants_for reads the grant withdrawn: {g:?}"
    );
    assert!(
        !live().await,
        "I4316: the capability walk's and peer rooting's live conferral rows drop the grant"
    );
    assert!(
        held(d, &target).await.is_some(),
        "I4316: the grant row still stands, as history"
    );
}

/// Holder `i` of `c`'s own AUTHORED withdrawal of `target` (one key's
/// statement, signed with its bundle key: no count).
fn holder_authored_withdrawal(
    c: &TestCeremonyV2,
    i: usize,
    grantee: &str,
    target: &RowId,
    at_ms: u64,
) -> Vec<u8> {
    let iss = c.holder_identity_ref(i).to_owned();
    sign_row_statement(
        &c.holder_key(i),
        &iss,
        grantee,
        attestation_type::WITHDRAWS,
        &trust_family(),
        &map(vec![
            ("asserted_at", Value::Uint(at_ms)),
            ("author", Value::Text(iss.clone())),
            ("refs", map(vec![("target", row_ref(&target.0))])),
        ]),
        vec![],
    )
    .expect("sign a holder's authored withdrawal")
}

/// Put each of `voices` through the statement door, in order.
async fn put_voices_in_order(d: &dyn FederationDirectory, voices: &[Vec<u8>], what: &str) {
    for (i, v) in voices.iter().enumerate() {
        put_statement(d, v, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("{what} ({}): {e}", i + 1));
    }
}

/// The refusal [`i4322_a_withdrawal_that_is_no_count_is_refused_in_either_order`]
/// expects: `withdraws_never_retracts`, by the error's variant and token.
fn never_retracts(out: Result<StatementOutcome, crate::federation::Error>, what: &str) {
    match out {
        Err(crate::federation::Error::MalformedRow { plane, reason, .. }) => {
            assert_eq!(
                (plane, reason),
                (
                    crate::federation::admission::WITHDRAWS_PLANE,
                    crate::federation::malformed_row::WITHDRAWS_NEVER_RETRACTS
                ),
                "{what}: refused by name"
            );
        }
        other => panic!("{what}: refused withdraws_never_retracts, got {other:?}"),
    }
}

/// **I4322** (KR-fix20; CC 2.4.1.1 rule 0, CC 3.1.3; the Constitution's
/// ruling of 2026-11-22: "the count always wins"). A counted grant from the
/// root is reached only by a count, and a voice is never withdrawn: holder 1
/// (who signed the grant's FIRST voice) and holder 2 (its second) each sign
/// an AUTHORED withdrawal of it. Two nodes, opposite arrival orders:
///
/// - node A holds the grant first: each withdrawal is REFUSED at the door
///   (`withdraws_never_retracts`) and nothing is kept;
/// - node B holds the withdrawals first: each waits `link_unheld`; when the
///   grant lands it is refused on its re-fold and DROPPED (no statement, no
///   fold record).
///
/// The same answer on both: no statement of either withdrawal is held, no
/// fold record names it, the grant stands and is not withdrawn on read. A
/// re-offer is refused on both. Then the holders' COUNT still ends the grant
/// on both nodes (a count ending a count, stamped rule 0).
pub(crate) async fn i4322_a_withdrawal_that_is_no_count_is_refused_in_either_order(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
) {
    let c = bundle_v2();
    let head = install_v2(a)
        .await
        .expect("I4322: the bundle installs on A")
        .object_id;
    install_v2(b)
        .await
        .expect("I4322: the bundle installs on B");
    let at = grant_instant(a).await;
    let (worker, _) = worker_with_owner(a, "i4322").await;
    let (worker_b, _) = worker_with_owner(b, "i4322").await;
    assert_eq!(worker, worker_b, "I4322 premise: one worker on both nodes");
    let voices = [
        holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at),
        holder_grant(c, 1, &worker, ATTEST_BUILD, &head, at),
    ];
    let target = row_of(&voices[0]);
    let lone = [
        holder_authored_withdrawal(c, 0, &worker, &target, at + 60_000),
        holder_authored_withdrawal(c, 1, &worker, &target, at + 60_000),
    ];

    // Node A: the grant first, then each withdrawal: refused, nothing kept.
    put_voices_in_order(a, &voices, "I4322 A: a holder's grant voice").await;
    assert!(held(a, &target).await.is_some(), "I4322 A: the grant lands");
    for (i, w) in lone.iter().enumerate() {
        never_retracts(
            put_statement(a, w, None, INGEST_TIER).await,
            &format!(
                "I4322 A: holder {}'s authored withdrawal, grant held",
                i + 1
            ),
        );
    }

    // Node B: each withdrawal first: it waits for its target.
    for (i, w) in lone.iter().enumerate() {
        let o = put_statement(b, w, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I4322 B: holder {}'s withdrawal waits: {e}", i + 1));
        assert!(pending(&o), "I4322 B: held, the grant unheld: {o:?}");
        assert_eq!(
            why(b, &row_of(w)).await.as_deref(),
            Some(super::fold::reason::LINK_UNHELD),
            "I4322 B: holder {}'s withdrawal waits link_unheld",
            i + 1
        );
    }
    put_voices_in_order(b, &voices, "I4322 B: a holder's grant voice").await;

    // The same answer on both nodes.
    let later = || ms_now() + chrono::Duration::seconds(1);
    for (node, d) in [("A", a), ("B", b)] {
        for (i, w) in lone.iter().enumerate() {
            let wid = row_of(w);
            let what = format!("I4322 {node}: holder {}'s authored withdrawal", i + 1);
            assert!(held(d, &wid).await.is_none(), "{what}: no row landed");
            assert!(
                d.fold_state(&wid).await.expect("fold_state").is_none(),
                "{what}: no fold record (refused, or dropped when the grant arrived)"
            );
            assert!(
                d.edition2_voices(&wid)
                    .await
                    .expect("edition2_voices")
                    .is_empty(),
                "{what}: no statement kept"
            );
            never_retracts(
                put_statement(d, w, None, INGEST_TIER).await,
                &format!("{what}, offered again"),
            );
        }
        assert!(
            held(d, &target).await.is_some(),
            "I4322 {node}: the grant stands"
        );
        let v = crate::federation::admission::root_grants_for(d, &worker, later())
            .await
            .expect("I4322: root_grants_for");
        assert!(
            v.len() == 1 && !v[0].withdrawn,
            "I4322 {node}: the grant is not withdrawn on read: {v:?}"
        );
    }

    // Control: the holders' COUNT ends it on both nodes.
    let count = [
        holder_withdrawal(c, 0, &worker, &target, &head, at + 90_000),
        holder_withdrawal(c, 2, &worker, &target, &head, at + 90_000),
    ];
    let cid = row_of(&count[0]);
    for (node, d) in [("A", a), ("B", b)] {
        for v in &count {
            put_statement(d, v, None, INGEST_TIER)
                .await
                .unwrap_or_else(|e| panic!("I4322 {node}: a holder's counted voice: {e}"));
        }
        assert_eq!(
            held(d, &cid)
                .await
                .unwrap_or_else(|| panic!("I4322 {node}: the holders' count lands"))
                .withdraws_admission_rule,
            Some(crate::federation::admission::COUNT_UNDOES_COUNTED_RULE),
            "I4322 {node}: a count ends a count, stamped rule 0"
        );
    }
}

/// The instant `us` (POSIX µs) as a wall instant.
fn at_us(us: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp_micros(us).expect("an instant")
}

/// The earliest `first_held_us` of `row` on `d` (KR-fix24's "first held").
async fn first_held(d: &dyn FederationDirectory, row: &RowId) -> i64 {
    d.edition2_first_held_us(row)
        .await
        .expect("edition2_first_held_us")
        .expect("a voice of the row is held")
}

/// Does `d` keep any voice of `row`?
async fn kept(d: &dyn FederationDirectory, row: &RowId) -> bool {
    !d.edition2_voices(row)
        .await
        .expect("edition2_voices")
        .is_empty()
}

/// **I4323** (KR-fix24; CC 3.3.4 as ruled 2026-11-22). A counted root grant
/// SHORT of its count (one holder's voice, `count_short`) lapses on this node
/// when its hold window (72 h: the charter states none) has run since this
/// node first held its first voice: not a microsecond before, and at the
/// instant it does. Its kept voice, names and fold record are dropped and
/// nothing is refused: the same voice offered again is held anew, with a
/// fresh first-held instant and a fresh window. A grant that reached its
/// count is never touched. The host verb's body (`cosign::execute_due`,
/// what `Engine::execute_cosign_due` runs) lapses it through the clock seam.
pub(crate) async fn i4323_a_short_counted_row_lapses_at_its_window(d: &dyn FederationDirectory) {
    use super::fold::{hold_window_secs, lapse_short_counted_rows, DEFAULT_HOLD_WINDOW_SECS};
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4323: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, _) = worker_with_owner(d, "i4323").await;
    let v0 = holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at);
    let row = row_of(&v0);
    let o = put_statement(d, &v0, None, INGEST_TIER)
        .await
        .expect("I4323: one holder's voice is kept");
    assert!(pending(&o), "I4323 premise: short of its count: {o:?}");
    assert_eq!(
        why(d, &row).await.as_deref(),
        Some(super::fold::reason::COUNT_SHORT),
        "I4323 premise: held count_short"
    );
    // A grant that reached its count, beside it.
    let counted = row_of_id(&land_grant(d, c, &worker, ATTEST_EVIDENCE, &head, at, "I4323").await);

    let plane = d
        .fold_state(&row)
        .await
        .expect("fold_state")
        .expect("I4323: the row's fold record")
        .plane;
    let window = hold_window_secs(d, &row, &plane)
        .await
        .expect("I4323: the window");
    assert_eq!(
        window, DEFAULT_HOLD_WINDOW_SECS,
        "I4323: a root grant's window is the 72 h standing class"
    );
    assert_eq!(DEFAULT_HOLD_WINDOW_SECS, 259_200, "I4323: 72 hours");
    let first = first_held(d, &row).await;
    let due = first + window * 1_000_000;

    // One microsecond before the window has run: kept.
    let r = lapse_short_counted_rows(d, at_us(due - 1))
        .await
        .expect("I4323: the sweep");
    assert!(
        !r.lapsed.contains(&row),
        "I4323: it does not lapse early: {r:?}"
    );
    assert!(
        kept(d, &row).await,
        "I4323: the voice is kept before the window"
    );
    // At the window: dropped, nothing refused.
    let r = lapse_short_counted_rows(d, at_us(due))
        .await
        .expect("I4323: the sweep");
    assert!(
        r.lapsed.contains(&row),
        "I4323: the short row lapses at its window: {r:?}"
    );
    assert!(r.statements >= 1, "I4323: its voice is deleted: {r:?}");
    assert!(!kept(d, &row).await, "I4323: no voice kept");
    assert!(
        d.fold_state(&row).await.expect("fold_state").is_none(),
        "I4323: no fold record"
    );
    // The counted grant: untouched, at any instant.
    let r = lapse_short_counted_rows(d, at_us(due + 10 * window * 1_000_000))
        .await
        .expect("I4323: the sweep");
    assert!(
        !r.lapsed.contains(&counted)
            && held(d, &counted).await.is_some()
            && kept(d, &counted).await,
        "I4323: a row that reached its count is never lapsed"
    );

    // Offered again: held anew, a fresh first-held instant and window.
    let o = put_statement(d, &v0, None, INGEST_TIER)
        .await
        .expect("I4323: the lapse refused nothing: the voice is held again");
    assert!(pending(&o), "I4323: short again: {o:?}");
    let again = first_held(d, &row).await;
    assert!(
        again > first,
        "I4323: first_held_us is written anew ({again} > {first})"
    );
    let r = lapse_short_counted_rows(d, at_us(again + window * 1_000_000 - 1))
        .await
        .expect("I4323: the sweep");
    assert!(
        !r.lapsed.contains(&row) && kept(d, &row).await,
        "I4323: the fresh window has not run"
    );

    // The host verb's body, through the clock seam (nextest runs each test
    // in its own process; the clock is uninstalled on the way out).
    let fixed = std::sync::Arc::new(crate::host::clock::FixedClock::new(at_us(
        again + window * 1_000_000,
    )));
    crate::host::clock::install(fixed);
    let swept = crate::federation::cosign::execute_due(d).await;
    crate::host::clock::uninstall();
    swept.expect("I4323: the cosign sweep");
    assert!(
        !kept(d, &row).await,
        "I4323: Engine::execute_cosign_due's sweep lapses it at the node's clock"
    );
}

/// **I4324** (KR-fix24; CC 3.3.4: "each node counts from when IT first held
/// the pending row"). Two nodes hold the same short voice, B a little later
/// than A: at A's window A drops it and B keeps it; at B's window B drops it
/// too. Each decides only what it keeps.
pub(crate) async fn i4324_two_nodes_lapse_at_their_own_first_hold(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
) {
    use super::fold::{lapse_short_counted_rows, DEFAULT_HOLD_WINDOW_SECS};
    let c = bundle_v2();
    let head = install_v2(a)
        .await
        .expect("I4324: the bundle installs on A")
        .object_id;
    install_v2(b)
        .await
        .expect("I4324: the bundle installs on B");
    let at = grant_instant(a).await;
    let (worker, _) = worker_with_owner(a, "i4324").await;
    worker_with_owner(b, "i4324").await;
    let v0 = holder_grant(c, 0, &worker, ATTEST_BUILD, &head, at);
    let row = row_of(&v0);
    put_statement(a, &v0, None, INGEST_TIER)
        .await
        .expect("I4324: A holds the voice");
    let fa = first_held(a, &row).await;
    // B first holds it strictly later (its own clock, its own admission).
    while u64::try_from(crate::host::clock::now().timestamp_micros()).unwrap()
        <= u64::try_from(fa).unwrap() + 1_000
    {
        tokio::task::yield_now().await;
    }
    put_statement(b, &v0, None, INGEST_TIER)
        .await
        .expect("I4324: B holds the voice");
    let fb = first_held(b, &row).await;
    assert!(
        fb > fa,
        "I4324 premise: B first held it later ({fb} > {fa})"
    );
    let w = DEFAULT_HOLD_WINDOW_SECS * 1_000_000;

    let t = at_us(fa + w);
    for (node, d, lapses) in [("A", a, true), ("B", b, false)] {
        let r = lapse_short_counted_rows(d, t)
            .await
            .expect("I4324: the sweep");
        assert_eq!(
            r.lapsed.contains(&row),
            lapses,
            "I4324 {node}: at A's window only A drops it: {r:?}"
        );
        assert_eq!(kept(d, &row).await, !lapses, "I4324 {node}: what it keeps");
    }
    let r = lapse_short_counted_rows(b, at_us(fb + w))
        .await
        .expect("I4324: the sweep");
    assert!(
        r.lapsed.contains(&row),
        "I4324 B: at its own window B drops it: {r:?}"
    );
    assert!(!kept(b, &row).await, "I4324 B: nothing kept");
}

/// **I4328** (KR-fix28; CC 3.2, as the Constitution ruled 2026-11-22: a
/// machine grantee's acceptance is its owner's consent "as bound at the
/// acceptance's own instant"; a re-binding is a new owner-binding row, and
/// rows under it stand on the new owner, who has consented to nothing). A
/// node owned by P1; P1 accepts the counted root grant; the node is re-bound
/// to P2 (P1 withdraws its binding, P2 binds):
///
/// - an act dated between the acceptance and the re-binding is under the
///   grant (the acceptance is P1's, P1 was the owner then);
/// - an act dated after the re-binding is NOT: P1's acceptance does not
///   carry over, P2 has accepted nothing;
/// - P2 accepts the grant: a later act is under it again;
/// - P1 withdraws its old acceptance after the re-binding: nothing changes
///   for acts under P2, and the act under P1's binding keeps its standing.
///
/// "The binding an act names" is the binding in force at the act's instant
/// until the head rule is in this base (then the act's `refs.head`).
pub(crate) async fn i4328_a_rebound_node_needs_its_new_owners_acceptance(
    d: &dyn FederationDirectory,
) {
    use crate::federation::admission::{machine_owner_binding_at, root_grant_of, MachineOwner};
    let c = bundle_v2();
    let head = install_v2(d)
        .await
        .expect("I4328: the bundle installs")
        .object_id;
    let at = grant_instant(d).await;
    let (worker, p1) = worker_with_owner(d, "i4328").await;
    let worker_seed = "w-i4328";
    let p2 = "o2-i4328";
    e2::put_key(d, p2, &["user"]).await;
    let grant = land_grant(d, c, &worker, ATTEST_BUILD, &head, at, "I4328").await;
    let under = |t: DateTime<Utc>| {
        let g = grant.clone();
        async move {
            root_grant_of(d, &g, t)
                .await
                .expect("root_grant_of")
                .expect("I4328: a counted root grant")
                .accepted
        }
    };
    let ms = |m: i64| chrono::Duration::milliseconds(m);

    // P1 accepts.
    let acc1 = acceptance(&p1, &grant);
    e2::put_signed(d, &acc1)
        .await
        .expect("I4328: P1's acceptance is admitted");
    let acc1 = d
        .get_attestation(&e2::rid(&acc1))
        .await
        .expect("reads")
        .expect("I4328: P1's acceptance landed");
    let t_acc = acc1.asserted_at;
    let binding1 = match machine_owner_binding_at(d, &worker, t_acc)
        .await
        .expect("I4328: the binding reads")
    {
        MachineOwner::Bound { owner, bindings } => {
            assert_eq!(owner, e2::kid(&p1), "I4328 premise: P1 owns the node");
            bindings
        }
        other => panic!("I4328 premise: the node is bound: {other:?}"),
    };
    let t_mid = t_acc + ms(1);
    assert!(
        under(t_mid).await,
        "I4328: an act under P1's binding counts"
    );

    // Re-bind to P2: P1 withdraws its binding, then P2 binds, at stated instants.
    let b1 = d
        .get_attestation(&binding1[0])
        .await
        .expect("reads")
        .expect("I4328: P1's binding row");
    let t_w = t_acc + ms(2);
    let t_b2 = t_acc + ms(3);
    let t_after = t_acc + ms(4);
    let w = e2::composer_of_at(attestation_type::WITHDRAWS, &b1, &p1, t_w);
    e2::put_signed(d, &w)
        .await
        .expect("I4328: P1 withdraws its binding");
    assert!(
        d.get_attestation(&e2::rid(&w))
            .await
            .expect("reads")
            .is_some(),
        "I4328 premise: P1's withdrawal of its binding landed"
    );
    let mut b2 = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), p2, worker_seed);
    b2.asserted_at = t_b2;
    b2.scrub_timestamp = t_b2;
    ts::seal_row_in_place(p2, &mut b2);
    ts::put_sealed_owner_binding(d, &b2, worker_seed)
        .await
        .expect("I4328: P2 binds the node");
    match machine_owner_binding_at(d, &worker, t_after)
        .await
        .expect("I4328: the binding reads")
    {
        MachineOwner::Bound { owner, bindings } => {
            assert_eq!(owner, e2::kid(p2), "I4328 premise: P2 owns the node now");
            assert_ne!(bindings, binding1, "I4328 premise: a new binding row");
        }
        other => panic!("I4328 premise: the node is re-bound: {other:?}"),
    }
    assert!(
        !under(t_after).await,
        "I4328: an act under P2's binding is not under the grant: P2 accepted nothing"
    );
    assert!(
        under(t_mid).await,
        "I4328: the act under P1's binding keeps its standing"
    );

    // P2 accepts; a later act counts again.
    while crate::host::clock::now() <= t_after {
        tokio::task::yield_now().await;
    }
    let acc2 = acceptance(p2, &grant);
    e2::put_signed(d, &acc2)
        .await
        .expect("I4328: P2's acceptance is admitted");
    let acc2 = d
        .get_attestation(&e2::rid(&acc2))
        .await
        .expect("reads")
        .expect("I4328: P2's acceptance landed");
    assert!(
        under(acc2.asserted_at + ms(1)).await,
        "I4328: once P2 accepts, an act under P2's binding is under the grant"
    );

    // P1 withdraws its old acceptance after the re-binding.
    let t_l = acc2.asserted_at + ms(2);
    let wa = e2::composer_of_at(attestation_type::WITHDRAWS, &acc1, &p1, t_l);
    e2::put_signed(d, &wa)
        .await
        .expect("I4328: P1 withdraws its old acceptance");
    assert!(
        under(t_l + ms(1)).await,
        "I4328: P1's withdrawal changes nothing for acts under P2"
    );
    assert!(
        under(t_mid).await,
        "I4328: and the act under P1's binding still counts as of its instant"
    );
}

/// Offer the ceremony `c`'s bundle at the import door, under its anchor.
async fn offer_bundle(
    d: &dyn FederationDirectory,
    c: &TestCeremonyV2,
) -> Result<super::genesis::GenesisAdmission, crate::federation::Error> {
    super::genesis::add_test_attestation_root(super::fixture_genesis::mock_attestation_root_der());
    let mut statements: Vec<Vec<u8>> = c
        .rows_in_put_order()
        .into_iter()
        .map(|r| r.statement.clone())
        .collect();
    statements.extend(c.voices.iter().cloned());
    super::genesis::put_genesis_bundle(d, &statements, Some(&c.anchor())).await
}

/// The baked genesis offered at the import door under its PINNED anchor
/// (`genesis::baked_genesis_anchor`), whatever the store already holds (the
/// boot import, `import_baked_genesis`, offers it only to an empty store).
async fn offer_baked(d: &dyn FederationDirectory) {
    let (name, bytes) = super::genesis::BAKED_BUNDLES
        .first()
        .expect("I4329: a baked bundle");
    let statements = super::genesis::baked_statements(bytes)
        .unwrap_or_else(|| panic!("I4329: the baked bundle {name} decodes"));
    super::genesis::put_genesis_bundle(
        d,
        &statements,
        Some(&super::genesis::baked_genesis_anchor()),
    )
    .await
    .unwrap_or_else(|e| panic!("I4329: the baked bundle is placed: {e:?}"));
}

/// The pinned (baked) bundle's object id.
fn pinned_oid() -> Digest32 {
    let mut oid = [0u8; 32];
    hex::decode_to_slice(super::genesis::BAKED_GENESIS_OBJECT_ID, &mut oid).expect("64 hex");
    oid
}

/// **I4329** (KR-fix27, KR-fix27b; the Constitution's ruling of 2026-11-22:
/// one lineage per store is a v62.0 limit, and "a first bundle with a
/// DIFFERENT `family_key_id` is ANOTHER ROOT, not a fork"; the lead's
/// correction: the root family is the PINNED ANCHOR's, never arrival order).
///
/// - **Both orders converge:** store A holds a Valid first bundle of ANOTHER
///   family (`kr-i4329-another-root`) BEFORE the pinned baked genesis; store
///   B holds the baked genesis first, then the other. Both root in the
///   baked bundle's family, its bundle is the head, there is no fork, and
///   the other is `other_roots` and out of `valid`.
/// - **No pinned bundle, two families:** store C holds the fixture root and
///   the other family's bundle: no family is the root, nothing is in force
///   (no head, nothing `valid`), both are `other_roots`, no fork.
/// - **Control (unchanged):** store D, two first bundles of the SAME family:
///   a fork of the genesis (no head, `Fork::Genesis`), no other root.
pub(crate) async fn i4329_another_family_is_another_root_not_a_fork(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
    c_store: &dyn FederationDirectory,
    control: &dyn FederationDirectory,
) {
    use super::fixture_genesis::{ceremony_v2, CeremonySpec};
    let c = bundle_v2();
    let spec = CeremonySpec {
        family_key_id: "kr-i4329-another-root".to_owned(),
        ..c.spec.clone()
    };
    let other = ceremony_v2(&spec);
    let pinned = pinned_oid();
    assert_ne!(other.object_id, pinned, "I4329 premise: another bundle");

    // A: the other family FIRST, then the pinned bundle. B: the reverse.
    offer_bundle(a, &other)
        .await
        .expect("I4329 A: the other family's bundle is not refused");
    offer_baked(a).await;
    offer_baked(b).await;
    offer_bundle(b, &other)
        .await
        .expect("I4329 B: the other family's bundle is not refused");
    let mut families = Vec::new();
    for (node, d) in [("A", a), ("B", b)] {
        let g = genesis_in_force(d)
            .await
            .expect("I4329: the genesis in force");
        assert!(g.forks.is_empty(), "I4329 {node}: no fork: {:?}", g.forks);
        assert_eq!(
            g.head.as_ref().map(|h| h.object_id),
            Some(pinned),
            "I4329 {node}: the head is the pinned anchor's bundle, whichever arrived first"
        );
        assert_eq!(
            g.other_roots,
            vec![other.object_id],
            "I4329 {node}: the other family's first bundle is \"not a root this store holds\""
        );
        assert!(
            g.valid.iter().all(|p| p.object_id != other.object_id),
            "I4329 {node}: and is not in the store's Valid lineage"
        );
        families.push(g.family_key_id().map(str::to_owned));
    }
    assert_eq!(
        families[0], families[1],
        "I4329: both orders converge on one root family"
    );

    // C: two families, neither the pinned bundle: no root, nothing in force.
    install_v2(c_store)
        .await
        .expect("I4329 C: the fixture root installs");
    offer_bundle(c_store, &other)
        .await
        .expect("I4329 C: the other family's bundle is not refused");
    let g = genesis_in_force(c_store)
        .await
        .expect("I4329 C: the genesis in force");
    let mut both = vec![c.object_id, other.object_id];
    both.sort();
    assert!(
        g.head.is_none() && g.valid.is_empty() && g.forks.is_empty(),
        "I4329 C: no pinned bundle among two families: nothing in force, no fork: {g:?}"
    );
    assert_eq!(g.other_roots, both, "I4329 C: both are other roots");

    // D (control): the SAME family, another first bundle: a fork.
    install_v2(control)
        .await
        .expect("I4329 control: the fixture root installs");
    let sibling = ceremony_v2(&CeremonySpec::at(c.spec.t0_ms - 86_400_000));
    assert_ne!(sibling.object_id, c.object_id, "I4329 control premise");
    let _ = offer_bundle(control, &sibling).await;
    let g = genesis_in_force(control)
        .await
        .expect("I4329 control: the genesis in force");
    assert!(
        g.valid.iter().any(|p| p.object_id == sibling.object_id),
        "I4329 control: the same-family sibling is placed Valid: {g:?}"
    );
    assert!(
        g.head.is_none()
            && g.forks
                .iter()
                .any(|f| matches!(f, super::genesis::Fork::Genesis { .. })),
        "I4329 control: two first bundles of ONE family are a fork: {:?}",
        g.forks
    );
    assert!(g.other_roots.is_empty(), "I4329 control: no other root");
}

/// The statement `seed` signs outside the Engine over a draft.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
fn signed_outside(seed: &str, draft: &super::emit::Draft, what: &str) -> Vec<u8> {
    draft.assemble(
        e2::signing_key(seed)
            .sign(&draft.sig_structure)
            .unwrap_or_else(|e| panic!("{what}: signed outside the Engine: {e}")),
    )
}

/// The one grant `worker` holds, as the Engine reads it at `t`.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
async fn the_grant(
    e: &crate::Engine,
    worker: &str,
    t: DateTime<Utc>,
    what: &str,
) -> crate::federation::admission::RootGrantView {
    let mut v = e
        .root_grants_for(worker, Some(t))
        .await
        .unwrap_or_else(|e| panic!("{what}: Engine::root_grants_for: {e}"));
    assert_eq!(v.len(), 1, "{what}: the grant is listed: {v:?}");
    v.remove(0)
}

/// **I4313** (KR-fix18; CC 2.4.1.1 rule 1, as Constitution ruled
/// 2026-11-21). A conferral is two consents. The grantee's is the
/// ACCEPTANCE: a node worker's OWNER, with a software key, takes it back
/// with `Engine::withdraw_statement` on the acceptance row, and the conferral
/// ends: `root_grants_for` and `root_grant_of` (the one reader the capability
/// walk and peer rooting ask) read no consent. The grant row still stands
/// and still lists, as history, and is NOT `withdrawn`. The worker's OWN
/// (node) key cannot take the owner's acceptance back, before or after. A
/// later acceptance of the same standing grant confers AGAIN.
///
/// Ports the setup of I4204's and I4219's deleted "the grantee withdraws the
/// grant" legs.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn i4313_the_owner_withdraws_the_acceptance(e: &crate::Engine) {
    let c = bundle_v2();
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let head = c.object_id;
    let (worker, owner_seed) = worker_with_owner(d, "i4313").await;
    let worker_seed = "w-i4313";
    let grant = land_grant(
        d,
        c,
        &worker,
        ATTEST_BUILD,
        &head,
        grant_instant(d).await,
        "I4313",
    )
    .await;
    let later = || ms_now() + chrono::Duration::seconds(1);
    let accept = || async {
        crate::federation::attestation_emit::emit_statement(
            d,
            &ts::local_signer(&owner_seed),
            crate::federation::membership_acceptance::reply_input(&grant, true),
            None,
        )
        .await
    };
    accept()
        .await
        .expect("I4313: the owner's acceptance is admitted");
    let g = the_grant(e, &worker, later(), "I4313").await;
    assert!(g.accepted && g.confers, "I4313 premise: conferring: {g:?}");
    let first = g
        .acceptance_row_id
        .clone()
        .expect("I4313: the view names the acceptance that gives the consent");

    // The worker's own (node) key: a node gives no consent and takes none
    // back for its owner.
    // KR-fix21 — kept and NOT landed, held by name; the acceptance stands.
    crate::federation::withdraw_statement_invariants::not_retracted(
        d,
        e.withdraw_statement(&ts::local_signer(worker_seed), &first)
            .await,
        &first,
        &[crate::federation::withdraw_statement_invariants::NOT_ADMITTED],
        "I4313: the grantee node's own key cannot withdraw its owner's acceptance",
    )
    .await;
    let g = the_grant(e, &worker, later(), "I4313").await;
    assert!(
        g.confers && g.acceptance_row_id.as_deref() == Some(first.as_str()),
        "I4313: the node's refused withdrawal changed nothing: {g:?}"
    );

    // The owner takes the acceptance back.
    let wid = crate::federation::withdraw_statement_invariants::landed_id(
        e.withdraw_statement(&ts::local_signer(&owner_seed), &first)
            .await
            .expect("I4313: the owner withdraws the acceptance they gave"),
        "I4313",
    );
    let w = d
        .get_attestation(&wid)
        .await
        .expect("I4313: reads")
        .expect("I4313: the withdrawal landed");
    assert_eq!(
        w.withdraws_admission_rule,
        Some(1),
        "I4313: the producer's own retraction (rule 1)"
    );
    let g = the_grant(e, &worker, later(), "I4313").await;
    assert!(
        !g.accepted && !g.confers && g.acceptance_row_id.is_none(),
        "I4313: the acceptance withdrawn, no conferral: {g:?}"
    );
    assert!(
        !g.withdrawn && g.row_id == grant.attestation_id,
        "I4313: the GRANT is not withdrawn; it still lists, as history: {g:?}"
    );
    assert!(
        held(d, &row_of_id(&grant)).await.is_some(),
        "I4313: the grant row still stands"
    );
    assert!(
        !root_grant_of(d, &grant, later())
            .await
            .expect("I4313: root_grant_of")
            .expect("I4313: still a counted root grant")
            .accepted,
        "I4313: the reader the capability walk and peer rooting ask reads no consent"
    );

    // The node cannot re-accept for itself, nor undo the withdrawal.
    let _ = e
        .withdraw_statement(&ts::local_signer(worker_seed), &wid)
        .await;
    assert!(
        !the_grant(e, &worker, later(), "I4313").await.confers,
        "I4313: the node does not undo its owner's withdrawal"
    );

    // A re-acceptance of the same standing grant confers again.
    accept()
        .await
        .expect("I4313: the owner's second acceptance is admitted");
    let g = the_grant(e, &worker, later(), "I4313").await;
    let first_rid = RowId(
        hex::decode(&first)
            .expect("a hex row id")
            .try_into()
            .expect("32 bytes"),
    );
    // KR-fix29 — on a red, name the first acceptance's fold state (the
    // build of 01ba09cb lost it; see P/KR-red-4vt.md).
    assert!(
        g.accepted && g.confers,
        "I4313: a re-acceptance of the same grant confers again: {g:?}; the first acceptance: \
         row {:?}, fold state {:?}",
        d.get_attestation(&first).await.map(|r| r.is_some()),
        d.fold_state(&first_rid).await
    );
    let second = g.acceptance_row_id.expect("I4313: the second acceptance");
    assert_ne!(
        second, first,
        "I4313: the consent is the NEW acceptance, not the withdrawn one"
    );
}

/// **I4314** (KR-fix18). The same, for an owner whose key is HARDWARE (never
/// in the Engine): the acceptance and its withdrawal are drafted
/// (`Engine::statement_draft`, `Engine::withdraw_statement_draft`), signed
/// outside, and submitted (`Engine::submit_voice`), each at a STATED instant,
/// so the readings are exact:
///
/// - **from then on**: read at an instant before the withdrawal's own, the
///   acceptance still stands (an act taken under the grant before the
///   withdrawal verifies as of its own instant); at the withdrawal's instant
///   and after, it does not;
/// - the worker's own key, drafting the same withdrawal, is refused;
/// - a re-acceptance at a later instant confers from ITS instant on, and
///   does not reach back over the gap.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn i4314_a_hardware_owner_withdraws_the_acceptance_by_draft(e: &crate::Engine) {
    use crate::federation::membership_acceptance::reply_envelope;
    let c = bundle_v2();
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let head = c.object_id;
    let (worker, owner_seed) = worker_with_owner(d, "i4314").await;
    let worker_seed = "w-i4314";
    let grant = land_grant(
        d,
        c,
        &worker,
        ATTEST_BUILD,
        &head,
        grant_instant(d).await,
        "I4314",
    )
    .await;
    // After the owner binding (stated just now); every later instant is an
    // offset from this one.
    let base = u64::try_from(ms_now().timestamp_millis()).expect("after 1970");
    let at = |offset_ms: u64| {
        DateTime::<Utc>::from_timestamp_millis(i64::try_from(base + offset_ms).expect("i64"))
            .expect("an instant")
    };
    let envelope = reply_envelope(&grant, true);
    let accept_at = |offset_ms: u64| {
        let (envelope, worker, owner_seed) = (envelope.clone(), worker.clone(), owner_seed.clone());
        async move {
            let draft = e
                .statement_draft(
                    attestation_type::SCORES,
                    &envelope,
                    &e2::kid(&owner_seed),
                    &hex::encode(e2::kid_digest(&owner_seed)),
                    &worker,
                    base + offset_ms,
                    None,
                )
                .await
                .expect("I4314: Engine::statement_draft drafts the acceptance");
            let st = signed_outside(&owner_seed, &draft, "I4314");
            let o = e
                .submit_voice(&st)
                .await
                .expect("I4314: the owner's drafted acceptance is admitted");
            assert!(o.is_seated(), "I4314: the acceptance lands: {o:?}");
            row_of(&st).hex()
        }
    };
    let accepted_at = |t: DateTime<Utc>| {
        let g = grant.clone();
        async move {
            root_grant_of(d, &g, t)
                .await
                .expect("I4314: root_grant_of")
                .expect("I4314: a counted root grant")
                .accepted
        }
    };

    let first = accept_at(0).await;
    assert!(
        accepted_at(at(1_000)).await,
        "I4314 premise: accepted, conferring"
    );

    // The worker's own key drafts the withdrawal: refused.
    let by_node = e
        .withdraw_statement_draft(
            &first,
            &e2::kid(worker_seed),
            &hex::encode(e2::kid_digest(worker_seed)),
            base + 1_500,
        )
        .await
        .expect("I4314: the draft is only bytes");
    // KR-fix21 — kept and NOT landed, held by name.
    crate::federation::withdraw_statement_invariants::not_retracted(
        d,
        e.submit_voice(&signed_outside(worker_seed, &by_node, "I4314"))
            .await,
        &first,
        &[crate::federation::withdraw_statement_invariants::NOT_ADMITTED],
        "I4314: the grantee node's own key cannot withdraw its owner's acceptance",
    )
    .await;
    assert!(
        accepted_at(at(1_900)).await,
        "I4314: the node's refused withdrawal changed nothing"
    );

    // The hardware owner withdraws the acceptance, at base + 2 s.
    let draft = e
        .withdraw_statement_draft(
            &first,
            &e2::kid(&owner_seed),
            &hex::encode(e2::kid_digest(&owner_seed)),
            base + 2_000,
        )
        .await
        .expect("I4314: Engine::withdraw_statement_draft drafts the withdrawal");
    let st = signed_outside(&owner_seed, &draft, "I4314");
    let wid = row_of(&st);
    let o = e
        .submit_voice(&st)
        .await
        .expect("I4314: the owner's drafted withdrawal is admitted");
    assert!(o.is_seated(), "I4314: the withdrawal lands: {o:?}");
    assert_eq!(
        held(d, &wid)
            .await
            .expect("I4314: the withdrawal is held")
            .withdraws_admission_rule,
        Some(1),
        "I4314: the producer's own retraction (rule 1)"
    );

    // From then on, and not before.
    let first_rid = RowId(
        hex::decode(&first)
            .expect("a hex row id")
            .try_into()
            .expect("32 bytes"),
    );
    // KR-fix29 — on a red, name the acceptance's fold state.
    assert!(
        accepted_at(at(1_000)).await && accepted_at(at(1_999)).await,
        "I4314: as of an instant BEFORE the withdrawal the consent stood: an act taken under \
         the grant then still verifies; the acceptance: row {:?}, fold state {:?}",
        d.get_attestation(&first).await.map(|r| r.is_some()),
        d.fold_state(&first_rid).await
    );
    assert!(
        !accepted_at(at(2_000)).await && !accepted_at(at(3_000)).await,
        "I4314: from the withdrawal's own instant on, no consent"
    );
    let before = the_grant(e, &worker, at(1_000), "I4314").await;
    assert!(
        before.confers && before.acceptance_row_id.as_deref() == Some(first.as_str()),
        "I4314: Engine::root_grants_for as of before the withdrawal: {before:?}"
    );
    let after = the_grant(e, &worker, at(3_000), "I4314").await;
    assert!(
        !after.accepted && !after.confers && !after.withdrawn && after.acceptance_row_id.is_none(),
        "I4314: after: no conferral, and the GRANT is not withdrawn: {after:?}"
    );
    assert!(
        held(d, &row_of_id(&grant)).await.is_some(),
        "I4314: the grant row still stands, as history"
    );

    // A re-acceptance at base + 4 s confers again, from its own instant.
    let second = accept_at(4_000).await;
    assert_ne!(second, first, "I4314: a new acceptance row");
    assert!(
        accepted_at(at(5_000)).await,
        "I4314: a re-acceptance of the same standing grant confers again"
    );
    assert!(
        !accepted_at(at(3_000)).await,
        "I4314: and does not reach back over the gap"
    );
    let again = the_grant(e, &worker, at(5_000), "I4314").await;
    assert!(
        again.confers && again.acceptance_row_id.as_deref() == Some(second.as_str()),
        "I4314: the consent is the new acceptance: {again:?}"
    );
}

/// **I4315** (KR-fix18; CC 2.4.1.1 rule 0). The HOLDERS' consent is the
/// counted grant, and only a count undoes it. Through the Engine verbs: a
/// lone holder's authored withdrawal is refused; the grantee's own key and
/// its owner's are refused (the removed door); one holder's COUNTED voice
/// waits (`count_short`); the second lands it. Then the grant reads
/// `withdrawn`, confers nothing, and still stands as a held row, with the
/// grantee's acceptance untouched.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn i4315_only_the_holders_count_withdraws_the_grant(e: &crate::Engine) {
    use super::second_signer_voice::VoiceOutcome;
    let c = bundle_v2();
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let head = c.object_id;
    let (worker, owner_seed) = worker_with_owner(d, "i4315").await;
    let worker_seed = "w-i4315";
    let at = grant_instant(d).await;
    let grant = land_grant(d, c, &worker, ATTEST_BUILD, &head, at, "I4315").await;
    let target = row_of_id(&grant);
    let later = || ms_now() + chrono::Duration::seconds(1);
    crate::federation::attestation_emit::emit_statement(
        d,
        &ts::local_signer(&owner_seed),
        crate::federation::membership_acceptance::reply_input(&grant, true),
        None,
    )
    .await
    .expect("I4315: the owner's acceptance is admitted");
    assert!(
        the_grant(e, &worker, later(), "I4315").await.confers,
        "I4315 premise: conferring"
    );
    let kid_of_holder = |i: usize| {
        hex::encode(super::fixture_genesis::kid_of(
            super::fixture_genesis::HOLDER_SEEDS[i],
        ))
    };

    // One holder, alone, by an AUTHORED withdrawal.
    let lone = e
        .withdraw_statement_draft(
            &grant.attestation_id,
            c.holder_identity_ref(0),
            &kid_of_holder(0),
            at + 30_000,
        )
        .await
        .expect("I4315: the draft is only bytes");
    // KR-fix21 — kept and NOT landed, held by name; the grant is live.
    crate::federation::withdraw_statement_invariants::not_retracted(
        d,
        e.submit_voice(
            &lone.assemble(
                c.holder_key(0)
                    .sign(&lone.sig_structure)
                    .expect("I4315: holder 1 signs"),
            ),
        )
        .await,
        &grant.attestation_id,
        &[crate::federation::withdraw_statement_invariants::NOT_ADMITTED],
        "I4315: a lone holder cannot withdraw the counted grant",
    )
    .await;
    // The grantee's own key, and its owner: the removed door.
    for (who, seed) in [
        ("the grantee's own key", worker_seed),
        ("the grantee's owner", owner_seed.as_str()),
    ] {
        crate::federation::withdraw_statement_invariants::not_retracted(
            d,
            e.withdraw_statement(&ts::local_signer(seed), &grant.attestation_id)
                .await,
            &grant.attestation_id,
            &[crate::federation::withdraw_statement_invariants::NOT_ADMITTED],
            &format!("I4315: {who} does not withdraw the GRANT (they withdraw the acceptance)"),
        )
        .await;
    }
    assert!(
        the_grant(e, &worker, later(), "I4315").await.confers,
        "I4315: three refused withdrawals changed nothing"
    );

    // The holders' COUNT: the same envelope the withdrawal verb builds, plus
    // the bundle it is counted over (`head`), drafted per holder.
    let mut envelope = crate::federation::membership_acceptance::withdrawal_envelope_of(&grant)
        .expect("I4315: the withdrawal envelope");
    let o = envelope.as_object_mut().expect("I4315: an object");
    o.insert("head".to_owned(), serde_json::json!(hex::encode(head)));
    // HEAD-4.rev2 — the holders' count states no `author`.
    o.insert("author".to_owned(), serde_json::Value::Null);
    o.insert(
        "cohort_scope".to_owned(),
        serde_json::json!(grant.cohort_scope),
    );
    let voice = |i: usize| {
        let (envelope, worker, id) = (
            envelope.clone(),
            worker.clone(),
            grant.attestation_id.clone(),
        );
        async move {
            let draft = e
                .statement_draft(
                    attestation_type::WITHDRAWS,
                    &envelope,
                    c.holder_identity_ref(i),
                    &kid_of_holder(i),
                    &worker,
                    at + 60_000,
                    Some(id.as_str()),
                )
                .await
                .unwrap_or_else(|e| panic!("I4315: holder {}'s counted draft: {e}", i + 1));
            draft.assemble(
                c.holder_key(i)
                    .sign(&draft.sig_structure)
                    .expect("I4315: a holder signs"),
            )
        }
    };
    let v0 = voice(0).await;
    let wid = row_of(&v0);
    // KR-fix29 — the draft is judged by its SHAPE (no author, refs.head =
    // the bundle, refs.target = the grant), not against the fixture's bytes:
    // the Engine's withdrawal envelope carries members the fixture's
    // two-member payload does not, so the row ids differ without either
    // being wrong (the build of 01ba09cb: 20d166fc… against f66c62c3…).
    {
        let (_, payload) =
            super::liveness::statement_parts(&v0).expect("I4315: the draft is a statement");
        let names = super::names::names_of(&payload).expect("I4315: the draft's names");
        assert!(
            payload.get_text("author").is_none(),
            "I4315: the Engine's draft is COUNTED (no author)"
        );
        assert_eq!(
            super::names::single(&names, "head").map(|h| h.0),
            Some(head),
            "I4315: the draft names the bundle as refs.head"
        );
        assert_eq!(
            super::names::single(&names, "target"),
            Some(target),
            "I4315: the draft names the grant as refs.target"
        );
    }
    let o = e
        .submit_voice(&v0)
        .await
        .expect("I4315: one holder's counted voice is kept");
    assert!(
        matches!(&o, VoiceOutcome::Waiting { reason, .. }
            if reason == super::fold::reason::COUNT_SHORT),
        "I4315: one voice of three is count_short: {o:?}"
    );
    assert!(
        held(d, &wid).await.is_none() && the_grant(e, &worker, later(), "I4315").await.confers,
        "I4315: one holder's voice withdraws nothing"
    );
    let o = e
        .submit_voice(&voice(1).await)
        .await
        .expect("I4315: the second holder's voice");
    assert!(o.is_seated(), "I4315: two of three land it: {o:?}");
    let w = held(d, &wid)
        .await
        .expect("I4315: the counted withdrawal is held");
    assert_eq!(
        w.withdraws_admission_rule,
        Some(crate::federation::admission::COUNT_UNDOES_COUNTED_RULE),
        "I4315: the holders' count, stamped rule 0"
    );
    let g = the_grant(e, &worker, later(), "I4315").await;
    assert!(
        g.withdrawn && !g.confers,
        "I4315: the holders' count withdrew the grant: {g:?}"
    );
    assert!(
        g.accepted && g.acceptance_row_id.is_some(),
        "I4315: the grantee's acceptance is its own row, untouched: {g:?}"
    );
    assert!(
        held(d, &target).await.is_some(),
        "I4315: the grant row still stands, as history"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use crate::store::Backend as _;

    async fn store() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    macro_rules! on_one {
        ($name:ident, $body:ident) => {
            #[tokio::test]
            async fn $name() {
                Box::pin(super::$body(&store().await)).await;
            }
        };
    }

    on_one!(
        i4200_two_holders_confer_on_a_node_worker_sqlite,
        i4200_two_holders_confer_on_a_node_worker
    );
    on_one!(
        i4201_either_order_of_holders_sqlite,
        i4201_either_order_of_holders
    );
    on_one!(
        i4202_a_scope_outside_the_charter_is_refused_sqlite,
        i4202_a_scope_outside_the_charter_is_refused
    );
    on_one!(i4204_the_end_of_a_grant_sqlite, i4204_the_end_of_a_grant);
    on_one!(
        i4316_the_holders_count_retires_the_grant_on_read_sqlite,
        i4316_the_holders_count_retires_the_grant_on_read
    );
    on_one!(
        i4219_who_gives_up_a_root_grant_sqlite,
        i4219_who_gives_up_a_root_grant
    );
    on_one!(
        i4205_an_agent_grantee_accepts_through_its_owner_sqlite,
        i4205_an_agent_grantee_accepts_through_its_owner
    );
    on_one!(
        i4206_the_acceptance_before_the_grant_sqlite,
        i4206_the_acceptance_before_the_grant
    );
    on_one!(
        i4207_a_rootless_node_then_the_import_sqlite,
        i4207_a_rootless_node_then_the_import
    );

    on_one!(
        i4210_an_unrooted_node_serves_a_held_grant_to_the_named_holders_sqlite,
        i4210_an_unrooted_node_serves_a_held_grant_to_the_named_holders
    );

    #[tokio::test]
    async fn i4218_a_rebind_drafted_and_voiced_by_hardware_holders_sqlite() {
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4218-engine"),
            "sqlite::memory:",
        )
        .await
        .expect("I4218: a sqlite Engine");
        Box::pin(super::i4218_a_rebind_drafted_and_voiced_by_hardware_holders(&e)).await;
    }

    #[tokio::test]
    async fn i4217_a_hardware_held_owner_accepts_by_draft_sqlite() {
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4217-engine"),
            "sqlite::memory:",
        )
        .await
        .expect("I4217: a sqlite Engine");
        Box::pin(super::i4217_a_hardware_held_owner_accepts_by_draft(&e)).await;
    }

    #[tokio::test]
    async fn i4313_the_owner_withdraws_the_acceptance_sqlite() {
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4313-engine"),
            "sqlite::memory:",
        )
        .await
        .expect("I4313: a sqlite Engine");
        Box::pin(super::i4313_the_owner_withdraws_the_acceptance(&e)).await;
    }

    #[tokio::test]
    async fn i4314_a_hardware_owner_withdraws_the_acceptance_by_draft_sqlite() {
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4314-engine"),
            "sqlite::memory:",
        )
        .await
        .expect("I4314: a sqlite Engine");
        Box::pin(super::i4314_a_hardware_owner_withdraws_the_acceptance_by_draft(&e)).await;
    }

    #[tokio::test]
    async fn i4315_only_the_holders_count_withdraws_the_grant_sqlite() {
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4315-engine"),
            "sqlite::memory:",
        )
        .await
        .expect("I4315: a sqlite Engine");
        Box::pin(super::i4315_only_the_holders_count_withdraws_the_grant(&e)).await;
    }

    #[tokio::test]
    async fn i4211_the_engine_verbs_sqlite() {
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4211-engine"),
            "sqlite::memory:",
        )
        .await
        .expect("I4211: a sqlite Engine");
        Box::pin(super::i4211_the_engine_verbs(&e)).await;
    }

    #[tokio::test]
    async fn i4208_host_verbs_across_four_nodes_sqlite() {
        use crate::federation::edition2::fixture_switch as e2;
        let (n1, n2, n3, n4) = (store().await, store().await, store().await, store().await);
        n3.set_node_key_id(e2::put_key(&n3, "w-i4208", &["node"]).await);
        Box::pin(super::i4208_host_verbs_across_four_nodes(
            &n1, &n2, &n3, &n4,
        ))
        .await;
    }

    on_one!(
        i4213_a_non_holders_voice_is_refused_sqlite,
        i4213_a_non_holders_voice_is_refused
    );
    on_one!(
        i4214_a_non_holders_voice_before_the_bundle_sqlite,
        i4214_a_non_holders_voice_before_the_bundle
    );

    #[tokio::test]
    async fn i4216_a_rooted_node_serves_a_held_grant_sqlite() {
        use crate::federation::edition2::fixture_switch as e2;
        let n = store().await;
        n.set_node_key_id(e2::put_key(&n, "n-i4216", &["node"]).await);
        Box::pin(super::i4216_a_rooted_node_serves_a_held_grant(&n)).await;
    }

    #[tokio::test]
    async fn i4215_a_non_holders_rebind_voice_sqlite() {
        Box::pin(super::i4215_a_non_holders_rebind_voice(
            &store().await,
            &store().await,
        ))
        .await;
    }

    #[tokio::test]
    async fn i4212_a_holder_finds_a_pending_rebind_on_a_second_node_sqlite() {
        Box::pin(
            super::i4212_a_holder_finds_a_pending_rebind_on_a_second_node(
                &store().await,
                &store().await,
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn i4203_two_nodes_one_verdict_sqlite() {
        Box::pin(super::i4203_two_nodes_one_verdict(
            &store().await,
            &store().await,
        ))
        .await;
    }

    #[tokio::test]
    async fn i4329_another_family_is_another_root_not_a_fork_sqlite() {
        Box::pin(super::i4329_another_family_is_another_root_not_a_fork(
            &store().await,
            &store().await,
            &store().await,
            &store().await,
        ))
        .await;
    }

    on_one!(
        i4328_a_rebound_node_needs_its_new_owners_acceptance_sqlite,
        i4328_a_rebound_node_needs_its_new_owners_acceptance
    );
    on_one!(
        i4323_a_short_counted_row_lapses_at_its_window_sqlite,
        i4323_a_short_counted_row_lapses_at_its_window
    );

    #[tokio::test]
    async fn i4324_two_nodes_lapse_at_their_own_first_hold_sqlite() {
        Box::pin(super::i4324_two_nodes_lapse_at_their_own_first_hold(
            &store().await,
            &store().await,
        ))
        .await;
    }

    #[tokio::test]
    async fn i4322_a_withdrawal_that_is_no_count_is_refused_in_either_order_sqlite() {
        Box::pin(
            super::i4322_a_withdrawal_that_is_no_count_is_refused_in_either_order(
                &store().await,
                &store().await,
            ),
        )
        .await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use crate::store::Backend as _;

    async fn store() -> Option<crate::store::postgres::PostgresBackend> {
        let dsn = crate::test_pg::isolated_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    macro_rules! on_one {
        ($name:ident, $body:ident) => {
            #[tokio::test]
            async fn $name() {
                let Some(b) = store().await else { return };
                Box::pin(super::$body(&b)).await;
            }
        };
    }

    on_one!(
        i4200_two_holders_confer_on_a_node_worker_postgres,
        i4200_two_holders_confer_on_a_node_worker
    );
    on_one!(
        i4201_either_order_of_holders_postgres,
        i4201_either_order_of_holders
    );
    on_one!(
        i4202_a_scope_outside_the_charter_is_refused_postgres,
        i4202_a_scope_outside_the_charter_is_refused
    );
    on_one!(i4204_the_end_of_a_grant_postgres, i4204_the_end_of_a_grant);
    on_one!(
        i4316_the_holders_count_retires_the_grant_on_read_postgres,
        i4316_the_holders_count_retires_the_grant_on_read
    );
    on_one!(
        i4219_who_gives_up_a_root_grant_postgres,
        i4219_who_gives_up_a_root_grant
    );
    on_one!(
        i4205_an_agent_grantee_accepts_through_its_owner_postgres,
        i4205_an_agent_grantee_accepts_through_its_owner
    );
    on_one!(
        i4206_the_acceptance_before_the_grant_postgres,
        i4206_the_acceptance_before_the_grant
    );
    on_one!(
        i4207_a_rootless_node_then_the_import_postgres,
        i4207_a_rootless_node_then_the_import
    );

    #[tokio::test]
    async fn i4208_host_verbs_across_four_nodes_postgres() {
        use crate::federation::edition2::fixture_switch as e2;
        let (Some(n1), Some(n2), Some(n3), Some(n4)) =
            (store().await, store().await, store().await, store().await)
        else {
            return;
        };
        n3.set_node_key_id(e2::put_key(&n3, "w-i4208", &["node"]).await);
        Box::pin(super::i4208_host_verbs_across_four_nodes(
            &n1, &n2, &n3, &n4,
        ))
        .await;
    }

    on_one!(
        i4210_an_unrooted_node_serves_a_held_grant_to_the_named_holders_postgres,
        i4210_an_unrooted_node_serves_a_held_grant_to_the_named_holders
    );

    #[tokio::test]
    async fn i4218_a_rebind_drafted_and_voiced_by_hardware_holders_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4218-engine"),
            &dsn,
        )
        .await
        .expect("I4218: a postgres Engine");
        Box::pin(super::i4218_a_rebind_drafted_and_voiced_by_hardware_holders(&e)).await;
    }

    #[tokio::test]
    async fn i4217_a_hardware_held_owner_accepts_by_draft_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4217-engine"),
            &dsn,
        )
        .await
        .expect("I4217: a postgres Engine");
        Box::pin(super::i4217_a_hardware_held_owner_accepts_by_draft(&e)).await;
    }

    #[tokio::test]
    async fn i4313_the_owner_withdraws_the_acceptance_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4313-engine"),
            &dsn,
        )
        .await
        .expect("I4313: a postgres Engine");
        Box::pin(super::i4313_the_owner_withdraws_the_acceptance(&e)).await;
    }

    #[tokio::test]
    async fn i4314_a_hardware_owner_withdraws_the_acceptance_by_draft_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4314-engine"),
            &dsn,
        )
        .await
        .expect("I4314: a postgres Engine");
        Box::pin(super::i4314_a_hardware_owner_withdraws_the_acceptance_by_draft(&e)).await;
    }

    #[tokio::test]
    async fn i4315_only_the_holders_count_withdraws_the_grant_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4315-engine"),
            &dsn,
        )
        .await
        .expect("I4315: a postgres Engine");
        Box::pin(super::i4315_only_the_holders_count_withdraws_the_grant(&e)).await;
    }

    #[tokio::test]
    async fn i4211_the_engine_verbs_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i4211-engine"),
            &dsn,
        )
        .await
        .expect("I4211: a postgres Engine");
        Box::pin(super::i4211_the_engine_verbs(&e)).await;
    }

    on_one!(
        i4213_a_non_holders_voice_is_refused_postgres,
        i4213_a_non_holders_voice_is_refused
    );
    on_one!(
        i4214_a_non_holders_voice_before_the_bundle_postgres,
        i4214_a_non_holders_voice_before_the_bundle
    );

    #[tokio::test]
    async fn i4216_a_rooted_node_serves_a_held_grant_postgres() {
        use crate::federation::edition2::fixture_switch as e2;
        let Some(n) = store().await else { return };
        n.set_node_key_id(e2::put_key(&n, "n-i4216", &["node"]).await);
        Box::pin(super::i4216_a_rooted_node_serves_a_held_grant(&n)).await;
    }

    #[tokio::test]
    async fn i4215_a_non_holders_rebind_voice_postgres() {
        let (Some(a), Some(b)) = (store().await, store().await) else {
            return;
        };
        Box::pin(super::i4215_a_non_holders_rebind_voice(&a, &b)).await;
    }

    #[tokio::test]
    async fn i4212_a_holder_finds_a_pending_rebind_on_a_second_node_postgres() {
        let (Some(a), Some(b)) = (store().await, store().await) else {
            return;
        };
        Box::pin(super::i4212_a_holder_finds_a_pending_rebind_on_a_second_node(&a, &b)).await;
    }

    #[tokio::test]
    async fn i4203_two_nodes_one_verdict_postgres() {
        let (Some(a), Some(b)) = (store().await, store().await) else {
            return;
        };
        Box::pin(super::i4203_two_nodes_one_verdict(&a, &b)).await;
    }

    #[tokio::test]
    async fn i4329_another_family_is_another_root_not_a_fork_postgres() {
        let (Some(a), Some(b), Some(c), Some(d)) =
            (store().await, store().await, store().await, store().await)
        else {
            return;
        };
        Box::pin(super::i4329_another_family_is_another_root_not_a_fork(
            &a, &b, &c, &d,
        ))
        .await;
    }

    on_one!(
        i4328_a_rebound_node_needs_its_new_owners_acceptance_postgres,
        i4328_a_rebound_node_needs_its_new_owners_acceptance
    );
    on_one!(
        i4323_a_short_counted_row_lapses_at_its_window_postgres,
        i4323_a_short_counted_row_lapses_at_its_window
    );

    #[tokio::test]
    async fn i4324_two_nodes_lapse_at_their_own_first_hold_postgres() {
        let (Some(a), Some(b)) = (store().await, store().await) else {
            return;
        };
        Box::pin(super::i4324_two_nodes_lapse_at_their_own_first_hold(&a, &b)).await;
    }

    #[tokio::test]
    async fn i4322_a_withdrawal_that_is_no_count_is_refused_in_either_order_postgres() {
        let (Some(a), Some(b)) = (store().await, store().await) else {
            return;
        };
        Box::pin(super::i4322_a_withdrawal_that_is_no_count_is_refused_in_either_order(&a, &b))
            .await;
    }
}
