//! v62.0.0 (KR-fix3a; CC 4.4.3.19, CC 4.5.5, CC rc22 0faa695 / 87abd2d) —
//! **the capability walk resolves `infra:attest:{family}` to the root's
//! counted grant**, one hop.
//!
//! The root is the genesis bundle's lineage; its grant is KR-fix2's counted
//! row (two of three holders' voices over the named bundle), and it confers
//! only once the grantee accepts (a `node` worker through its OWNER). Every
//! store-facing witness runs the grant, the acceptance and this node's
//! `trust:accepts:v1` through the real statement door, on `install_v2`'s
//! bundle (charter scope `infra:attest`, `infra:serve`), on sqlite and
//! postgres. Exact-match scopes stay exact.
//!
//! - **I4220** (no store) — the scope an attestation needs is the matched
//!   registry family's prefix by its literal segments (a key-bearing bind
//!   included): `build:registered:id1:v1` needs
//!   `infra:attest:build:registered`; an unregistered or refused dimension
//!   is `capability_scope_family_unregistered`. The cover: `infra:attest`
//!   covers `infra:attest:F`; F covers neither G nor its parent; a shorter
//!   token (`infra`) covers nothing; `infra:serve` and the other scopes are
//!   exact.
//! - **I4221** — a grant of `infra:attest:build:registered` to a node worker:
//!   before the owner's acceptance it confers nothing; after it, the worker
//!   holds it for an attestation in that family (`ConferralPlane::BundleRoot`,
//!   root = the accord), but not for another family, not plain
//!   `infra:attest`, not `infra:serve`; an unregistered family is refused by
//!   name.
//! - **I4222** — a grant of plain `infra:attest` covers every family.
//! - **I4223** — a scope the bundle's charter does not cover
//!   (`infra:detect`) is refused at the door
//!   (`conferral_outside_charter_scope`) and confers nothing at the reader.
//! - **I4224** — the door form (`require_attest_scope_for`): a fold hold
//!   (`capability_scope_unconferred`) before the conferral, `Ok` after.
//! - **I4225** — a node that does not accept the root: the accepted, counted
//!   grant confers nothing to it.
//! - **I4226** — the BYPASS the root-grant exclusion closes: a counted root
//!   grant whose FIRST voice (its `attesting_key_id`) is a keyed trust root
//!   this node accepts, landed by two holders but NOT accepted by the
//!   grantee, confers nothing as a grant BY that key (the older delegation
//!   loop). After KR-fix4 (only holders voice a counted root row once its
//!   bundle is held) the shape is built in the one order still open: the
//!   keyed root's voice kept BEFORE the bundle (KR-fix3a-w1). Where the store
//!   does not keep it, the witness asserts the first voice is a holder's.

use chrono::{DateTime, Utc};
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{row_ref, sign_row_statement, Digest32};
use ciris_verify_core::namespace_match;

use super::fixture_genesis::{bundle_v2, install_v2, TestCeremonyV2, FAMILY_KEY_ID};
use super::fixture_switch as e2;
use super::genesis::genesis_in_force;
use super::ingest::{put_statement, INGEST_TIER};
use super::names::RowId;
use crate::federation::admission::CONFERRAL_OUTSIDE_CHARTER_SCOPE;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::trust_root::{
    attest_conferred_for, attest_scope_for_dimension, capability_roots_to_trusted_root,
    require_attest_scope_for, scope_confers, ConferralPlane, CAPABILITY_SCOPE_FAMILY_UNREGISTERED,
    CAPABILITY_SCOPE_UNCONFERRED,
};
use crate::federation::types::{attestation_type, cohort_scope};
use crate::federation::{Attestation, Error, FederationDirectory};

/// A dimension of family `build:registered:{target}` and the scope it needs.
const DIM_F: &str = "build:registered:id1:v1";
const SCOPE_F: &str = "infra:attest:build:registered";
/// A dimension of another family (`benchmark:he300:{category}:{version}`).
const DIM_G: &str = "benchmark:he300:sample:v1.0";
/// A dimension no registered family claims (open vocabulary).
const DIM_UNREGISTERED: &str = "no_such_family:leaf:v1";
/// An unmatched descendant beneath a closed family (the matcher refuses it).
const DIM_REFUSED: &str = "consent:totally:new:v1";

// ── fixtures (KR-fix2's shapes, written here: theirs are private) ────────

fn trust_family() -> String {
    namespace_match::family_id(super::typed::TRUST_PREFIX)
}

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

/// One voice of the counted root grant of `scope` to `grantee` over `head`.
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

fn ms_now() -> DateTime<Utc> {
    let t = crate::host::clock::now();
    DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms")
}

/// `signer`'s acceptance of `grant` (the root grant's reply form).
fn acceptance(signer: &str, grant: &Attestation) -> Attestation {
    let env = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "dimension": crate::federation::membership_acceptance::ACCEPTANCE_DIMENSION,
        "references_attestation_id": grant.attestation_id,
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

/// The bundle's newest tip + 120 s (never the wall clock).
pub(crate) async fn grant_instant(d: &dyn FederationDirectory) -> u64 {
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

/// A `node` worker and its owner, bound. Returns `(worker kid, owner seed)`.
pub(crate) async fn worker_with_owner(d: &dyn FederationDirectory, tag: &str) -> (String, String) {
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

/// Holders 0 and 1 land the grant; the landed row.
pub(crate) async fn land_grant(
    d: &dyn FederationDirectory,
    grantee: &str,
    scope: &str,
    head: &Digest32,
    at_ms: u64,
    what: &str,
) -> Attestation {
    let c = bundle_v2();
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
    landed(
        d,
        &id,
        &format!("{what}: two of three holders land the grant"),
    )
    .await
}

/// v62.0.0 (PX-fix4) — **the row LANDED**: a put that answers `Ok` may have
/// kept the row HELD (`Pending`, or a voice short of its count), and a
/// fixture that reads held as done hides the gate that holds it. Returns the
/// held row; otherwise panics naming the fold's hold reason and its detail.
async fn landed(d: &dyn FederationDirectory, id: &RowId, what: &str) -> Attestation {
    if let Some(row) = d.get_attestation(&id.hex()).await.expect("get_attestation") {
        return row;
    }
    let held = super::fold::why_held(d, id).await.expect("why_held");
    panic!(
        "{what}: did not land; held {:?}",
        held.map(|h| (h.reason, h.detail))
    )
}

/// The owner accepts `grant`.
pub(crate) async fn owner_accepts(
    d: &dyn FederationDirectory,
    owner: &str,
    grant: &Attestation,
    what: &str,
) {
    let acc = acceptance(owner, grant);
    e2::put_signed(d, &acc)
        .await
        .unwrap_or_else(|e| panic!("{what}: the owner's acceptance: {e}"));
    // PX-fix4 — `Ok(Pending)` is not an acceptance: it must land.
    landed(
        d,
        &RowId(e2::rid_digest(&acc)),
        &format!("{what}: the owner's acceptance"),
    )
    .await;
}

/// A node `seed` that accepts the bundle root (its `trust:accepts:v1` edge to
/// the accord, naming the bundle in force). Returns its kid.
pub(crate) async fn accepting_node(d: &dyn FederationDirectory, seed: &str) -> String {
    let node = e2::put_key(d, seed, &["node"]).await;
    let tip = hex::encode(
        genesis_in_force(d)
            .await
            .expect("the genesis in force")
            .tips()
            .first()
            .expect("a tip")
            .object_id,
    );
    let edge = super::fixture_trust_root::bundle_acceptance_statement(
        d,
        &e2::signing_key(seed),
        &node,
        &tip,
    )
    .await
    .expect("the acceptance edge signs");
    e2::put_statement(d, &edge)
        .await
        .expect("the acceptance edge is admitted");
    // PX-fix4 — a held edge accepts nothing: it must land.
    landed(
        d,
        &row_of(&edge),
        &format!("{seed}: the acceptance edge of the bundle root"),
    )
    .await;
    node
}

fn later() -> DateTime<Utc> {
    ms_now() + chrono::Duration::seconds(1)
}

fn refused_with(e: &Error, token: &str) -> bool {
    e.to_string().contains(token)
}

// ── I4220 (no store) ─────────────────────────────────────────────────────

/// **I4220.**
#[test]
fn i4220_the_family_scope_and_its_cover() {
    assert_eq!(
        attest_scope_for_dimension(DIM_F).unwrap(),
        SCOPE_F,
        "I4220 F"
    );
    assert_eq!(
        attest_scope_for_dimension(DIM_G).unwrap(),
        "infra:attest:benchmark:he300",
        "I4220 G"
    );
    let key = "A".repeat(43);
    assert_eq!(
        attest_scope_for_dimension(&format!("licensure:{key}:v1")).unwrap(),
        format!("infra:attest:licensure:{key}"),
        "I4220 a key-bearing family keeps its bound key"
    );
    for dim in [DIM_UNREGISTERED, DIM_REFUSED, ""] {
        let e = attest_scope_for_dimension(dim).expect_err("I4220 refused");
        assert!(
            refused_with(&e, CAPABILITY_SCOPE_FAMILY_UNREGISTERED),
            "I4220 {dim:?}: refused by name: {e}"
        );
    }
    let env = |scope: serde_json::Value| serde_json::json!({ "scope": scope });
    let confers =
        |held: &[&str], wanted: &str| scope_confers(&env(serde_json::json!(held)), wanted);
    assert!(
        confers(&["infra:attest"], SCOPE_F),
        "I4220 the parent covers F"
    );
    assert!(confers(&[SCOPE_F], SCOPE_F), "I4220 F covers F");
    assert!(
        confers(&["infra:attest:build"], SCOPE_F),
        "I4220 a family's literal ancestor covers it"
    );
    assert!(
        !confers(&["infra:attest:benchmark:he300"], SCOPE_F),
        "I4220 G never covers F"
    );
    assert!(
        !confers(&[SCOPE_F], "infra:attest"),
        "I4220 F never covers its parent"
    );
    assert!(
        !confers(
            &[&format!("infra:attest:licensure:{key}")],
            "infra:attest:licensure"
        ),
        "I4220 a bound family never widens to its unbound parent"
    );
    assert!(
        !confers(&["infra"], SCOPE_F),
        "I4220 a shorter token covers nothing"
    );
    assert!(
        !confers(&["infra:attest"], "infra:attest_assurance"),
        "I4220 the colon boundary holds"
    );
    assert!(
        !confers(&["infra"], "infra:serve") && confers(&["infra:serve"], "infra:serve"),
        "I4220 infra:serve stays exact"
    );
    assert!(
        !confers(&["infra:attest"], "infra:attest:"),
        "I4220 an empty family is no family"
    );
    // The bare-string form reads the same.
    assert!(scope_confers(
        &env(serde_json::json!("infra:attest")),
        SCOPE_F
    ));
}

// ── I4221–I4226 (sqlite + pg) ────────────────────────────────────────────

/// **I4221.**
pub(crate) async fn i4221_a_family_grant_confers_its_family(d: &dyn FederationDirectory) {
    let head = install_v2(d).await.expect("I4221: installs").object_id;
    let at = grant_instant(d).await;
    let node = accepting_node(d, "px-i4221-node").await;
    let (worker, owner) = worker_with_owner(d, "px-i4221").await;
    let grant = land_grant(d, &worker, SCOPE_F, &head, at, "I4221").await;

    let read = |dim: &'static str| {
        let (node, worker) = (node.clone(), worker.clone());
        async move { attest_conferred_for(d, &node, &worker, dim, later()).await }
    };
    assert!(
        read(DIM_F).await.expect("I4221 reads").is_none(),
        "I4221: counted but not accepted: nothing"
    );
    owner_accepts(d, &owner, &grant, "I4221").await;
    let g = read(DIM_F)
        .await
        .expect("I4221 reads")
        .expect("I4221: counted and accepted: the worker holds F");
    assert_eq!(g.conferral_plane, ConferralPlane::BundleRoot, "I4221 {g:?}");
    assert_eq!(
        g.root_key_id, FAMILY_KEY_ID,
        "I4221: the root is the accord"
    );
    assert_eq!(
        g.grant_attestation_id, grant.attestation_id,
        "I4221: the grant"
    );
    assert!(
        read(DIM_G).await.expect("I4221 reads").is_none(),
        "I4221: F does not reach G"
    );
    for scope in ["infra:attest", "infra:serve"] {
        assert!(
            capability_roots_to_trusted_root(d, &node, &worker, scope, later())
                .await
                .expect("I4221 reads")
                .is_none(),
            "I4221: F confers no {scope}"
        );
    }
    let e = read(DIM_UNREGISTERED).await.expect_err("I4221: refused");
    assert!(
        refused_with(&e, CAPABILITY_SCOPE_FAMILY_UNREGISTERED),
        "I4221: an unregistered family is refused by name: {e}"
    );
}

/// **I4222.**
pub(crate) async fn i4222_plain_attest_covers_every_family(d: &dyn FederationDirectory) {
    let head = install_v2(d).await.expect("I4222: installs").object_id;
    let at = grant_instant(d).await;
    let node = accepting_node(d, "px-i4222-node").await;
    let (worker, owner) = worker_with_owner(d, "px-i4222").await;
    let grant = land_grant(d, &worker, "infra:attest", &head, at, "I4222").await;
    owner_accepts(d, &owner, &grant, "I4222").await;
    for dim in [DIM_F, DIM_G] {
        assert!(
            attest_conferred_for(d, &node, &worker, dim, later())
                .await
                .expect("I4222 reads")
                .is_some(),
            "I4222: plain infra:attest covers {dim}"
        );
    }
}

/// **I4223.**
pub(crate) async fn i4223_outside_the_charter_confers_nothing(d: &dyn FederationDirectory) {
    let head = install_v2(d).await.expect("I4223: installs").object_id;
    let at = grant_instant(d).await;
    let node = accepting_node(d, "px-i4223-node").await;
    let (worker, _) = worker_with_owner(d, "px-i4223").await;
    let v0 = holder_grant(bundle_v2(), 0, &worker, "infra:detect", &head, at);
    let e = put_statement(d, &v0, None, INGEST_TIER)
        .await
        .expect_err("I4223: refused at the door");
    assert!(
        refused_with(&e, CONFERRAL_OUTSIDE_CHARTER_SCOPE),
        "I4223: refused by name: {e}"
    );
    assert!(
        capability_roots_to_trusted_root(d, &node, &worker, "infra:detect", later())
            .await
            .expect("I4223 reads")
            .is_none(),
        "I4223: nothing confers it"
    );
}

/// **I4224.**
pub(crate) async fn i4224_the_door_form_holds_then_admits(d: &dyn FederationDirectory) {
    let head = install_v2(d).await.expect("I4224: installs").object_id;
    let at = grant_instant(d).await;
    let node = accepting_node(d, "px-i4224-node").await;
    let (worker, owner) = worker_with_owner(d, "px-i4224").await;
    let e = require_attest_scope_for(d, &node, &worker, DIM_F, later())
        .await
        .expect_err("I4224: no grant yet");
    assert!(
        refused_with(&e, CAPABILITY_SCOPE_UNCONFERRED),
        "I4224: held by name: {e}"
    );
    let grant = land_grant(d, &worker, SCOPE_F, &head, at, "I4224").await;
    owner_accepts(d, &owner, &grant, "I4224").await;
    require_attest_scope_for(d, &node, &worker, DIM_F, later())
        .await
        .expect("I4224: conferred");
    let e = require_attest_scope_for(d, &node, &worker, DIM_REFUSED, later())
        .await
        .expect_err("I4224: refused");
    assert!(
        refused_with(&e, CAPABILITY_SCOPE_FAMILY_UNREGISTERED),
        "I4224: an unregistered family is terminal: {e}"
    );
}

/// **I4225.**
pub(crate) async fn i4225_a_node_that_does_not_accept_the_root(d: &dyn FederationDirectory) {
    let head = install_v2(d).await.expect("I4225: installs").object_id;
    let at = grant_instant(d).await;
    let stranger_node = e2::put_key(d, "px-i4225-node", &["node"]).await;
    let (worker, owner) = worker_with_owner(d, "px-i4225").await;
    let grant = land_grant(d, &worker, SCOPE_F, &head, at, "I4225").await;
    owner_accepts(d, &owner, &grant, "I4225").await;
    assert!(
        attest_conferred_for(d, &stranger_node, &worker, DIM_F, later())
            .await
            .expect("I4225 reads")
            .is_none(),
        "I4225: no acceptance of the root, no conferral"
    );
}

/// **I4226.** The directory's node key is set (the keyed root's fixture
/// needs it); `node` is that key.
///
/// v62.0.0 (KR-fix3a-w1, after KR-fix4) — KR-fix4 refuses a non-holder's
/// voice of a counted root row at the door once its bundle is held, so the
/// only order that can make a non-holder the row's first voice is the one
/// KR-fix4 leaves open: the voice arrives BEFORE the bundle (kept, then held
/// `refold_refused` when the bundle lands, served to no holder), and the
/// holders then land the same row (KR-fix4's I4214). The row's
/// `attesting_key_id` is its primary voice: the first held voice by
/// statement id that verifies (`voices::primary_voice`), so the grant's
/// instant is chosen so that the keyed root's statement id sorts before the
/// first holder's. Where the store keeps that early voice the bypass shape
/// is CONSTRUCTIBLE and is witnessed; where the door does not keep it (its
/// retryable wait), it is unreachable on that store and the witness asserts
/// that instead (the first voice is a holder's).
pub(crate) async fn i4226_an_unaccepted_root_grant_never_confers_by_its_first_voice(
    d: &dyn FederationDirectory,
    node: &str,
) {
    use super::fixture_genesis::{DAY_MS, HOLDER_SEEDS};
    use super::fixture_trust_root::ROOT_SEED;
    use super::receipts::statement_id_of;
    let c = bundle_v2();
    let head = c.object_id;
    let (worker_seed, owner_seed) = ("w-px-i4226", "o-px-i4226");
    let worker = e2::put_key(d, worker_seed, &["node"]).await;
    let root_key = e2::put_key(d, ROOT_SEED, &["user"]).await;
    // An instant whose keyed-root voice sorts before holder 1's by
    // statement id (deterministic: the bytes are the fixture's).
    let base = c.spec.t0_ms + DAY_MS;
    let (at, first) = (0..64u64)
        .map(|k| base + k)
        .find_map(|at| {
            let first = grant_voice(
                &e2::signing_key(ROOT_SEED),
                &root_key,
                &worker,
                SCOPE_F,
                &head,
                at,
            );
            let holder = holder_grant(c, 0, &worker, SCOPE_F, &head, at);
            (statement_id_of(&first) < statement_id_of(&holder)).then_some((at, first))
        })
        .expect("I4226: an instant at which the keyed root's voice sorts first");
    let id = row_of(&first);
    // Before the bundle: kept (held), or the door's retryable wait.
    let kept = put_statement(d, &first, None, INGEST_TIER).await.is_ok();
    assert_eq!(
        install_v2(d).await.expect("I4226: installs").object_id,
        head,
        "I4226: the bundle the voice names"
    );
    // A keyed trust root at that key, which THIS node accepts (W1b).
    let r = super::fixture_trust_root::try_rooted_trust_root(d, &HOLDER_SEEDS, "quorum:2/3")
        .await
        .expect("I4226: a keyed root this node accepts");
    assert_eq!(
        r.root, root_key,
        "I4226 premise: the root is the early voice's key"
    );
    assert!(
        crate::federation::trust_root::trust_root_valid(d, node, &r.root, later())
            .await
            .expect("I4226 reads")
            .valid,
        "I4226 premise: this node accepts the keyed root"
    );
    e2::put_key(d, owner_seed, &["user"]).await;
    crate::federation::admission::steward_liveness_test_support::bind_machine_owner(
        d,
        owner_seed,
        worker_seed,
    )
    .await;
    for i in 0..2 {
        put_statement(
            d,
            &holder_grant(c, i, &worker, SCOPE_F, &head, at),
            None,
            INGEST_TIER,
        )
        .await
        .unwrap_or_else(|e| panic!("I4226: holder {i}'s voice: {e}"));
    }
    let grant = landed(d, &id, "I4226: two holders land the grant").await;
    if kept {
        // CONSTRUCTIBLE: the bypass shape. Dropping the delegation-loop
        // exclusion would confer it as a grant BY the keyed root.
        assert_eq!(
            grant.attesting_key_id, r.root,
            "I4226: the early (kept) voice is the row's first voice"
        );
    } else {
        // UNREACHABLE on this store: no non-holder voice was kept, so the
        // first voice is a holder's (the exclusion stays, defence in depth).
        assert!(
            c.holder_identity_refs().contains(&grant.attesting_key_id),
            "I4226: with no non-holder voice kept, the first voice is a holder's: {}",
            grant.attesting_key_id
        );
    }
    // Not accepted: nothing confers, by no plane.
    for scope in [SCOPE_F, "infra:attest"] {
        assert!(
            capability_roots_to_trusted_root(d, node, &worker, scope, later())
                .await
                .expect("I4226 reads")
                .is_none(),
            "I4226: an unaccepted root grant confers no {scope} as a grant by its first voice"
        );
    }
    // Accepted: it confers through the bundle-root arm only, or not at all
    // (this node has not accepted the bundle root) — never as Delegation.
    owner_accepts(d, owner_seed, &grant, "I4226").await;
    if let Some(g) = capability_roots_to_trusted_root(d, node, &worker, SCOPE_F, later())
        .await
        .expect("I4226 reads")
    {
        assert_eq!(
            g.conferral_plane,
            ConferralPlane::BundleRoot,
            "I4226: a root grant confers only as the root's: {g:?}"
        );
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    async fn store() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
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
                let b = store().await;
                Box::pin(super::$body(&b)).await;
            }
        };
    }

    on_one!(i4221_sqlite, i4221_a_family_grant_confers_its_family);
    on_one!(i4222_sqlite, i4222_plain_attest_covers_every_family);
    on_one!(i4223_sqlite, i4223_outside_the_charter_confers_nothing);
    on_one!(i4224_sqlite, i4224_the_door_form_holds_then_admits);
    on_one!(i4225_sqlite, i4225_a_node_that_does_not_accept_the_root);

    #[tokio::test]
    async fn i4226_sqlite() {
        let b = store().await;
        let node = super::e2::put_key(&b, "px-i4226-node", &["node"]).await;
        b.set_node_key_id(node.clone());
        Box::pin(super::i4226_an_unaccepted_root_grant_never_confers_by_its_first_voice(&b, &node))
            .await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    async fn store() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
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

    on_one!(i4221_postgres, i4221_a_family_grant_confers_its_family);
    on_one!(i4222_postgres, i4222_plain_attest_covers_every_family);
    on_one!(i4223_postgres, i4223_outside_the_charter_confers_nothing);
    on_one!(i4224_postgres, i4224_the_door_form_holds_then_admits);
    on_one!(i4225_postgres, i4225_a_node_that_does_not_accept_the_root);

    #[tokio::test]
    async fn i4226_postgres() {
        let Some(b) = store().await else { return };
        let node = super::e2::put_key(&b, "px-i4226-node", &["node"]).await;
        b.set_node_key_id(node.clone());
        Box::pin(super::i4226_an_unaccepted_root_grant_never_confers_by_its_first_voice(&b, &node))
            .await;
    }
}
