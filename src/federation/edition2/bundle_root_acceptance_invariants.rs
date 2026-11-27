//! v62.0.0 (KB-fix4; CC 3.2 at rc22 `87abd2d`, T3) — **a fresh node imports
//! the genesis and accepts the root by `family_key_id`, then reads itself
//! rooted, all through HOST verbs** (`Engine::put_genesis_bundle`,
//! `Engine::accept_root`, `Engine::root_standing`), on sqlite and postgres:
//!
//! - **I2416** import FIRST, then accept: the edge names the bundle in force
//!   and lands; the node reads itself rooted under `"humanity-accord"`.
//!   Before either, it reads rootless with the plane that waits named
//!   (`federation_tier`).
//! - **I2417** accept FIRST, then import: v62.0.0 (R2-accept; the
//!   Constitution's `trust-accepts` rule, "a new edge without it is
//!   refused") the acceptance is REFUSED `trust_root_head_unnamed` (there is
//!   no bundle to name) and nothing is put; the node reads rootless; after
//!   the import the same act lands and the node reads itself rooted.
//! - **I2418** I2416 for an OWNED node whose owner accepts no root: its own
//!   acceptance is its chain (CC 3.2 T3).
//! - **I2464** (KB-fix5, ceremony step 8) the ceremony order on the seat's
//!   host: import → the OWNER's acceptance, drafted here
//!   (`Engine::accept_root_draft`), signed outside the Engine, self-checked
//!   (`check_root_acceptance_statement`, each fault by name), carried as
//!   bytes and submitted (`put_edition2_statement`) → the owner binding (the
//!   owner's drafted half, the node's voice) → the seat reads rooted
//!   THROUGH ITS OWNER (`root_standing`).
//! - **I2465** (KB-fix5, CC 3.2 T8) the switch-over: a node that accepted
//!   the root itself reads rooted `Own`, stays `Own` once owned by an owner
//!   who has signed no acceptance, reads `Owner` once that owner accepts,
//!   and reads ROOTLESS once the owner withdraws: the owner's first edge
//!   ended the node's own reading for good.

use super::fixture_genesis as fg;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::identity_type;

async fn engine(dsn: &str, alias: &str) -> crate::Engine {
    let e = crate::Engine::with_signer_pre_genesis(ts::local_signer(alias), dsn)
        .await
        .expect("a fresh engine opens");
    e.register_self_federation_key(identity_type::NODE, None, None)
        .await
        .expect("the node registers its own key");
    e
}

/// The ceremony's bundle, through the host's import door.
async fn import(e: &crate::Engine) {
    let c = fg::bundle_v2();
    super::genesis::add_test_attestation_root(fg::mock_attestation_root_der());
    let mut statements: Vec<Vec<u8>> = c
        .rows_in_put_order()
        .into_iter()
        .map(|r| r.statement.clone())
        .collect();
    statements.extend(c.voices.iter().cloned());
    e.put_genesis_bundle(&statements, Some(&c.anchor()))
        .await
        .expect("the import door places the bundle");
}

async fn rootless(e: &crate::Engine, what: &str) {
    let st = e.root_standing().await.expect("root_standing reads");
    assert_eq!(st.root, None, "{what}: rootless");
    assert_eq!(
        st.waiting,
        Some(crate::RootStanding::WAITING_PLANE),
        "{what}: the plane that waits is named"
    );
}

async fn rooted(e: &crate::Engine, what: &str) {
    let st = e.root_standing().await.expect("root_standing reads");
    assert_eq!(
        st.root.as_deref(),
        Some(fg::FAMILY_KEY_ID),
        "{what}: rooted: {st:?}"
    );
    assert_eq!(st.waiting, None, "{what}: nothing waits");
    assert!(
        e.serve_standing()
            .await
            .expect("serve_standing reads")
            .rooted,
        "{what}: the serve wait agrees"
    );
}

/// v62.0.0 (RL-fix18) — `owner` (a seed) owns the Engine's node, bound the
/// ceremony's way (`bind_owner`: the Engine's drafts, dated now). The
/// builder `ts::owner_binding_attestation` dates its binding inside a
/// DEFAULT node record's window (180 days back plus an offset), before the
/// record `register_self_federation_key` gave this node now: the node's
/// voice waited `AttesterKeyUnknown`.
async fn owned_by(e: &crate::Engine, alias: &str, owner_seed: &str) {
    let owner = super::fixture_switch::put_key(
        e.federation_directory().as_ref(),
        owner_seed,
        &[identity_type::USER],
    )
    .await;
    bind_owner(e, alias, &owner, owner_seed, "I2418").await;
}

/// I2416 / I2418: import, then accept.
pub(crate) async fn import_then_accept(dsn: &str, alias: &str, owner: Option<&str>) {
    let e = engine(dsn, alias).await;
    if let Some(o) = owner {
        owned_by(&e, alias, o).await;
    }
    rootless(&e, "I2416 fresh").await;
    import(&e).await;
    rootless(&e, "I2416 imported, not accepted").await;
    let a = e
        .accept_root(fg::FAMILY_KEY_ID)
        .await
        .expect("I2416: the node accepts the root");
    let tip = hex::encode(
        super::genesis::genesis_in_force(e.federation_directory().as_ref())
            .await
            .expect("I2416: the genesis reads")
            .tips()
            .first()
            .expect("I2416: a tip")
            .object_id,
    );
    assert!(
        a.landed && a.bundle == tip,
        "I2416: names the bundle in force and lands: {a:?}"
    );
    rooted(&e, "I2416").await;
}

/// I2417: accept (refused: no bundle to name), then import, then accept.
pub(crate) async fn accept_then_import(dsn: &str, alias: &str) {
    let e = engine(dsn, alias).await;
    let early = e.accept_root(fg::FAMILY_KEY_ID).await;
    assert!(
        matches!(
            early,
            Err(crate::federation::Error::TrustRootHeadUnnamed { .. })
        ),
        "I2417: no bundle held: the acceptance is refused by name: {early:?}"
    );
    rootless(&e, "I2417 refused").await;
    import(&e).await;
    rootless(&e, "I2417 imported: the refused act left nothing to land").await;
    let a = e
        .accept_root(fg::FAMILY_KEY_ID)
        .await
        .expect("I2417: after the import the node accepts the root");
    assert!(a.landed, "I2417: lands: {a:?}");
    rooted(&e, "I2417").await;
}

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).expect("after 1970")
}

/// The owner's acceptance of the root, drafted by `e` and signed OUTSIDE it
/// with `owner_seed`'s key; self-checked. The assembled statement.
async fn owner_acceptance(e: &crate::Engine, owner: &str, owner_seed: &str, tag: &str) -> Vec<u8> {
    use crate::federation::trust_root::{check_root_acceptance_statement, RootAcceptanceFault};
    let draft = e
        .accept_root_draft(
            fg::FAMILY_KEY_ID,
            owner,
            &hex::encode(super::fixture_switch::kid_digest(owner_seed)),
            now_ms(),
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] Engine::accept_root_draft: {e}"));
    let st = draft.assemble(
        super::fixture_switch::signing_key(owner_seed)
            .sign(&draft.sig_structure)
            .expect("the owner signs outside the Engine"),
    );
    let rec = e
        .federation_directory()
        .edition2_statements_about(ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY, owner)
        .await
        .expect("the owner's key record reads")
        .into_iter()
        .next()
        .expect("the owner's key record is held");
    check_root_acceptance_statement(&st, fg::FAMILY_KEY_ID, owner, &rec)
        .unwrap_or_else(|f| panic!("[{tag}] the self-check passes: {}", f.as_str()));
    assert_eq!(
        check_root_acceptance_statement(&st, "another-lineage", owner, &rec),
        Err(RootAcceptanceFault::NotTheRoot),
        "[{tag}] the self-check names a wrong root"
    );
    assert_eq!(
        check_root_acceptance_statement(&st, fg::FAMILY_KEY_ID, "someone-else", &rec),
        Err(RootAcceptanceFault::NotAuthoredByTheSigner),
        "[{tag}] the self-check names a wrong signer"
    );
    let mut forged = st.clone();
    if let Some(last) = forged.last_mut() {
        *last ^= 0x01;
    }
    assert_eq!(
        check_root_acceptance_statement(&forged, fg::FAMILY_KEY_ID, owner, &rec),
        Err(RootAcceptanceFault::SignatureDoesNotVerify),
        "[{tag}] the self-check verifies the signature"
    );
    st
}

/// The owner binding of `e`'s own node: the owner's half drafted and signed
/// outside, the node's voice by its own key (`alias`).
async fn bind_owner(e: &crate::Engine, alias: &str, owner: &str, owner_seed: &str, tag: &str) {
    use crate::federation::types::delegation_scope as ds;
    let node = super::fixture_switch::kid(alias);
    let scopes = vec![
        ds::INFRA_SERVE.to_owned(),
        ds::INFRA_NETWORK_PRESENCE.to_owned(),
    ];
    let draft = e
        .owner_binding_draft(
            &node,
            &scopes,
            owner,
            &hex::encode(super::fixture_switch::kid_digest(owner_seed)),
            now_ms(),
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] Engine::owner_binding_draft: {e}"));
    let half = draft.assemble(
        super::fixture_switch::signing_key(owner_seed)
            .sign(&draft.sig_structure)
            .expect("the owner signs"),
    );
    e.submit_voice(&half)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the owner's half: {e}"));
    let rows = e
        .held_rows_for(Some(node.as_str()), Some("bound_node"), None, 10)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] Engine::held_rows_for: {e}"));
    let vd = e
        .voice_draft(&rows[0].row_id, &node)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] Engine::voice_draft: {e}"));
    let voice = vd.assemble(
        super::fixture_switch::signing_key(alias)
            .sign(&vd.sig_structure)
            .expect("the node signs"),
    );
    let o = e
        .submit_voice(&voice)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the node's voice: {e}"));
    assert!(o.is_seated(), "[{tag}] the owner binding is seated: {o:?}");
}

/// **I2464** — the ceremony order on the seat's host.
pub(crate) async fn ceremony_order(dsn: &str, alias: &str, owner_seed: &str) {
    let tag = "I2464";
    let e = engine(dsn, alias).await;
    let owner = super::fixture_switch::put_key(
        e.federation_directory().as_ref(),
        owner_seed,
        &[identity_type::USER],
    )
    .await;
    import(&e).await;
    // Step 8 — the operator's own acceptance, carried to the seat's host as
    // bytes and submitted there.
    let st = owner_acceptance(&e, &owner, owner_seed, tag).await;
    let out = e
        .put_edition2_statement(&st, None)
        .await
        .expect("I2464: the owner's acceptance is admitted");
    assert!(
        matches!(out, super::ingest::StatementOutcome::Row { .. }),
        "I2464: the owner's acceptance lands: {out:?}"
    );
    rootless(&e, "I2464 before the owner binding").await;
    // Step 9 — the owner binding.
    bind_owner(&e, alias, &owner, owner_seed, tag).await;
    let s = e.root_standing().await.expect("root_standing reads");
    assert_eq!(
        s.root.as_deref(),
        Some(fg::FAMILY_KEY_ID),
        "I2464: rooted: {s:?}"
    );
    assert_eq!(
        s.through,
        Some(crate::RootedThrough::Owner(owner.clone())),
        "I2464: through its owner"
    );
}

/// **I2465** — the T8 switch-over.
pub(crate) async fn switch_over(dsn: &str, alias: &str, owner_seed: &str) {
    let tag = "I2465";
    let e = engine(dsn, alias).await;
    let dir = e.federation_directory();
    let owner =
        super::fixture_switch::put_key(dir.as_ref(), owner_seed, &[identity_type::USER]).await;
    import(&e).await;
    e.accept_root(fg::FAMILY_KEY_ID)
        .await
        .expect("I2465: the node accepts the root itself");
    let s = e.root_standing().await.expect("reads");
    assert_eq!(
        s.through,
        Some(crate::RootedThrough::Own),
        "I2465: own edge: {s:?}"
    );
    bind_owner(&e, alias, &owner, owner_seed, tag).await;
    let s = e.root_standing().await.expect("reads");
    assert_eq!(
        s.through,
        Some(crate::RootedThrough::Own),
        "I2465: owned, the owner has signed no acceptance: still its own: {s:?}"
    );
    let st = owner_acceptance(&e, &owner, owner_seed, tag).await;
    e.put_edition2_statement(&st, None)
        .await
        .expect("I2465: the owner's acceptance");
    let s = e.root_standing().await.expect("reads");
    assert_eq!(
        s.through,
        Some(crate::RootedThrough::Owner(owner.clone())),
        "I2465: the owner's edge governs: {s:?}"
    );
    let id = super::names::RowId::of_statement(&st).expect("a row id");
    let acceptance = dir
        .get_attestation(&id.hex())
        .await
        .expect("reads")
        .expect("the owner's acceptance is held");
    // v62.0.0 (RL-fix17) — the owner's `withdraws`, signed with the LITERAL
    // root as its `sub` (as its target's). v62.0.0 (PIN-fix4; CIRISVerify
    // 23.4.1): it states NO `dimension` (a `withdraws` carries none and is
    // refused `malformed:dimension` if it does; its leaf is its target's,
    // read from the held target). 23.4.0 needed it restated.
    // `e2::composer_of` ran the target's subject through the fixture codec
    // (`subject_of` → `kid_or_keep`), which reads "humanity-accord" as a SEED
    // and names a key of that name: the 4vh run's withdrawal was never of the
    // acceptance, and the witness never asserted it landed.
    let w = {
        use ciris_verify_core::cde::Value;
        let acc_ms = u64::try_from(acceptance.asserted_at.timestamp_millis()).unwrap_or(0);
        let at = now_ms().max(acc_ms + 1);
        let Value::Map(m) = super::typed::withdraws_payload(&owner, &id, at) else {
            panic!("I2465: a withdraws payload is a map");
        };
        assert!(
            !m.iter().any(|(k, _)| k.as_text() == Some("dimension")),
            "I2465: the withdrawal states no dimension"
        );
        ciris_verify_core::edition2::sign_row_statement(
            &super::fixture_switch::signing_key(owner_seed),
            &owner,
            fg::FAMILY_KEY_ID,
            crate::federation::types::attestation_type::WITHDRAWS,
            &ciris_verify_core::namespace_match::family_id("trust:{job}:{version}"),
            &Value::Map(m),
            vec![],
        )
        .expect("I2465: the withdrawal signs")
    };
    let out = super::ingest::put_statement(dir.as_ref(), &w, None, super::ingest::INGEST_TIER)
        .await
        .expect("I2465: the owner withdraws its acceptance");
    assert!(
        matches!(out, super::ingest::StatementOutcome::Row { .. }),
        "I2465: the withdrawal LANDED (not held, not shape-refused): {out:?}"
    );
    rootless(
        &e,
        "I2465 the owner withdrew; the node's own edge is never read again",
    )
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2464_the_ceremony_order_sqlite() {
    Box::pin(ceremony_order(
        "sqlite::memory:",
        "kb5-seat-sq",
        "kb5-op-sq",
    ))
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2465_the_t8_switch_over_sqlite() {
    Box::pin(switch_over("sqlite::memory:", "kb5-node-sq", "kb5-own-sq")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2464_the_ceremony_order_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    Box::pin(ceremony_order(&dsn, "kb5-seat-pg", "kb5-op-pg")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2465_the_t8_switch_over_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    Box::pin(switch_over(&dsn, "kb5-node-pg", "kb5-own-pg")).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2416_import_then_accept_sqlite() {
    Box::pin(import_then_accept("sqlite::memory:", "kb4-node-sq", None)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2417_accept_then_import_sqlite() {
    Box::pin(accept_then_import("sqlite::memory:", "kb4-early-sq")).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2418_an_owned_node_accepts_sqlite() {
    Box::pin(import_then_accept(
        "sqlite::memory:",
        "kb4-owned-sq",
        Some("kb4-owner-sq"),
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2416_import_then_accept_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    Box::pin(import_then_accept(&dsn, "kb4-node-pg", None)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2417_accept_then_import_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    Box::pin(accept_then_import(&dsn, "kb4-early-pg")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2418_an_owned_node_accepts_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    Box::pin(import_then_accept(
        &dsn,
        "kb4-owned-pg",
        Some("kb4-owner-pg"),
    ))
    .await;
}
