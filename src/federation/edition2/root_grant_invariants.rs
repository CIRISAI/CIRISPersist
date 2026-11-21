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
//!   it; a stranger's authored withdrawal is not admitted; the worker's
//!   owner's own withdrawal lands.
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
const ATTEST_BUILD: &str = "infra:attest:build_manifest";
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
    assert!(
        held(d, &wid).await.is_some(),
        "I4204: two of three holders withdraw the grant"
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
    // The worker's OWNER withdraws it: the grantee's own withdrawal.
    let w = authored_withdrawal(&owner, &worker, &target, now + 1);
    let oid = row_of(&w);
    put_statement(d, &w, None, INGEST_TIER)
        .await
        .expect("I4204: the owner's withdrawal is admitted");
    let stored = held(d, &oid)
        .await
        .expect("I4204: the grantee's own withdrawal (its owner's) lands");
    assert_eq!(
        stored.withdraws_admission_rule,
        Some(3),
        "I4204: admitted on the grantee's own rule"
    );
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
    let envelope = serde_json::json!({
        "dimension": REBIND_FAMILY,
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
}
