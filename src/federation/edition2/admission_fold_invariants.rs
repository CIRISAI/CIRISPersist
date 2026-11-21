//! v62.0.0 (wave GC1; CC 2.7.3) — witnesses of the `admission.rs` gates
//! converted to folds: a row is never refused for what ANOTHER row says; it
//! is HELD with a reason token, concludes when its input arrives, and
//! un-concludes when that input is withdrawn — with the same concluded set in
//! either arrival order. Each store-facing body runs on sqlite and postgres.
//!
//! - **I3670** (other-key existence) — a row about a subject this node holds
//!   no record of is HELD `link_unheld` (never refused) and
//!   concludes when the subject's key record lands; with the subject first
//!   it concludes at once. Same concluded set in either order.
//! - **I3671** (withdraws) — a `withdraws` whose target is held but not
//!   concluded WAITS: HELD `link_unheld`, and concludes (its
//!   rule stamped then) when the target concludes; target first, it
//!   concludes at once.
//! - **I3672** (other-key existence, refusal on presence) — an agency
//!   delegation to a key with no record is held (`count_short`: it waits for
//!   the recipient's voice, GC1-fix1); when the recipient's record
//!   lands as a NODE it stays held, now `node_agency_forbidden`; with the
//!   node's record first it is held `node_agency_forbidden` at once. Same
//!   (held, reason) in either order — the earlier door admitted it in one
//!   order and refused it in the other.
//! - **I3673** (a sibling row) — a node's second live `config:load` report
//!   (no `supersedes`) is HELD `config_renewal_unresolved` while the first is
//!   live, and concludes when the node withdraws the first. (At most one
//!   live row per (subject, attester, scope, leaf) is inherently first-wins:
//!   with the reports swapped, the other one is held.)
//! - **I3674** (pure) — a converted gate is a plain refusal outside a fold
//!   attempt and a HELD condition, with its read declared, inside one
//!   (`check_revocation_anti_rollback`); a gate that admits marks nothing.
//! - **I3676** (the lead's ruling on G0's gap (b)) — an edition-2 peer
//!   de-admission, which lands on T2's typed revocation plane
//!   (`federation_revocations`), is read by `check_peer_deadmission`: the
//!   peer's later write is refused outside a fold attempt and held
//!   `peer_deadmitted` inside one.
//! - **I3675** (pure) — the GC1 slice (`reason::gc1::ALL`): each token once,
//!   none a core token, each registered and snake_case.

use super::fixture_switch as e2;
use super::fold::{self, reason, Dep};
use super::ingest::StatementOutcome;
use super::names::RowId;
use crate::federation::types::{attestation_type, identity_type, Attestation};
use crate::federation::{Error, FederationDirectory};

/// A plain, unreserved, unconsented scored family about another key.
const PLAIN: &str = "expertise:cardiology:en:v1";

fn id_of(row: &Attestation) -> RowId {
    super::voices::carried_row_id(row).expect("GC1: the row carries its statement")
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

async fn statement_kept(d: &dyn FederationDirectory, row: &Attestation) -> bool {
    !d.edition2_voices(&id_of(row)).await.unwrap().is_empty()
}

fn pending(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Pending { .. })
}

fn row_landed(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Row { .. })
}

/// `author`'s `scores` row about `about` on `dimension`, as `author`'s
/// statement.
fn scores_about(author: &str, about: &str, dimension: &str) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(author),
    );
    a.attested_key_id = e2::kid(about);
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": dimension,
        "score": 1.0,
        "confidence": 0.9,
    });
    e2::row_of(&a, author)
}

/// I3670 + I3671: the subject, and a withdrawal's target, are waited for.
pub(crate) async fn subject_and_target_wait_body(d: &dyn FederationDirectory) {
    // Order 1 — the row (and its producer's withdrawal) before the subject.
    let (a, r) = ("gc1-sw1-a", "gc1-sw1-r");
    e2::put_key(d, a, &[identity_type::USER]).await;
    let row = scores_about(a, r, PLAIN);
    let o = e2::put_signed(d, &row)
        .await
        .expect("I3670: a row about an unheld subject is KEPT, never refused");
    assert!(pending(&o), "I3670: held: {o:?}");
    assert!(!concluded(d, &row).await, "I3670: no typed row");
    assert_eq!(
        held_reason(d, &row).await.as_deref(),
        Some(reason::LINK_UNHELD),
        "I3670: held, and says why"
    );
    let w = e2::composer_of(attestation_type::WITHDRAWS, &row, a);
    let o = e2::put_signed(d, &w)
        .await
        .expect("I3671: a withdrawal of a held, unconcluded row is KEPT");
    assert!(pending(&o), "I3671: held: {o:?}");
    assert_eq!(
        held_reason(d, &w).await.as_deref(),
        Some(reason::LINK_UNHELD),
        "I3671: it waits for its target to conclude"
    );
    // The subject's record lands: the row concludes, and so does the
    // withdrawal that waited on it (the re-fold cascades).
    e2::put_key(d, r, &[identity_type::AGENT]).await;
    assert!(
        concluded(d, &row).await,
        "I3670: the subject's arrival concludes the row"
    );
    assert_eq!(held_reason(d, &row).await, None, "I3670: no reason left");
    assert!(
        concluded(d, &w).await,
        "I3671: the target's conclusion concludes the withdrawal"
    );
    assert_eq!(held_reason(d, &w).await, None, "I3671: no reason left");

    // Order 2 — the subject first: both conclude at once.
    let (a2, r2) = ("gc1-sw2-a", "gc1-sw2-r");
    e2::put_key(d, a2, &[identity_type::USER]).await;
    e2::put_key(d, r2, &[identity_type::AGENT]).await;
    let row2 = scores_about(a2, r2, PLAIN);
    let o = e2::put_signed(d, &row2).await.expect("I3670: order 2");
    assert!(row_landed(&o), "I3670: the subject held: concluded: {o:?}");
    let w2 = e2::composer_of(attestation_type::WITHDRAWS, &row2, a2);
    let o = e2::put_signed(d, &w2).await.expect("I3671: order 2");
    assert!(
        row_landed(&o),
        "I3671: the target concluded: concluded: {o:?}"
    );
    assert!(
        concluded(d, &row2).await && concluded(d, &w2).await,
        "I3670/I3671: the same concluded set as order 1"
    );
}

/// I3672: agency on a node key, in either order.
pub(crate) async fn node_agency_either_order_body(d: &dyn FederationDirectory) {
    use crate::federation::tier_ingest::test_support::moderate_delegation_attestation;
    // Order 1 — the delegation before the recipient's record.
    let (a, r) = ("gc1-na1-a", "gc1-na1-r");
    e2::put_key(d, a, &[identity_type::USER]).await;
    let del = moderate_delegation_attestation(&uuid::Uuid::new_v4().to_string(), a, r);
    let o = e2::put_signed(d, &del)
        .await
        .expect("I3672: a delegation to an unheld key is KEPT");
    assert!(pending(&o), "I3672: held: {o:?}");
    // GC1-fix1 — a `self:delegates_to` also waits for its delegate's own
    // voice (K2-fix6, `check_second_signers_voiced`, CC 2.6.1.9). That gate
    // runs before the subject gate, so the first mark is `count_short`: the
    // row waits for the recipient's voice (and record).
    assert_eq!(
        held_reason(d, &del).await.as_deref(),
        Some(reason::COUNT_SHORT),
        "I3672: it waits for the recipient"
    );
    e2::put_key(d, r, &[identity_type::NODE]).await;
    assert!(
        !concluded(d, &del).await,
        "I3672: a node recipient never concludes an agency delegation"
    );
    assert_eq!(
        held_reason(d, &del).await.as_deref(),
        Some(reason::gc1::NODE_AGENCY_FORBIDDEN),
        "I3672: re-folded on the recipient's record: held, node_agency_forbidden"
    );
    assert!(
        statement_kept(d, &del).await,
        "I3672: its statement is kept"
    );

    // Order 2 — the node's record first.
    let (a2, r2) = ("gc1-na2-a", "gc1-na2-r");
    e2::put_key(d, a2, &[identity_type::USER]).await;
    e2::put_key(d, r2, &[identity_type::NODE]).await;
    let del2 = moderate_delegation_attestation(&uuid::Uuid::new_v4().to_string(), a2, r2);
    let o = e2::put_signed(d, &del2)
        .await
        .expect("I3672: never refused, in this order either");
    assert!(pending(&o), "I3672: held: {o:?}");
    assert!(!concluded(d, &del2).await, "I3672: no typed row");
    assert_eq!(
        held_reason(d, &del2).await.as_deref(),
        Some(reason::gc1::NODE_AGENCY_FORBIDDEN),
        "I3672: the same (held, reason) as order 1"
    );
}

/// A node's own `config:load` report about itself (CC 3.4.5 self-report).
fn config_self(node: &str) -> Attestation {
    scores_about(node, node, "config:load:v1")
}

/// I3673: a renewal held while its sibling is live concludes when the
/// sibling is withdrawn.
pub(crate) async fn config_renewal_body(d: &dyn FederationDirectory) {
    let n = "gc1-cr-n";
    e2::put_key(d, n, &[identity_type::NODE]).await;
    let c1 = config_self(n);
    let o = e2::put_signed(d, &c1)
        .await
        .expect("I3673: the first report");
    assert!(row_landed(&o), "I3673: concluded: {o:?}");
    let c2 = config_self(n);
    let o = e2::put_signed(d, &c2)
        .await
        .expect("I3673: a second live body is KEPT, never refused");
    assert!(pending(&o), "I3673: held: {o:?}");
    assert!(!concluded(d, &c2).await, "I3673: no typed row");
    assert_eq!(
        held_reason(d, &c2).await.as_deref(),
        Some(reason::gc1::CONFIG_RENEWAL_UNRESOLVED),
        "I3673: held, and says why"
    );
    assert!(statement_kept(d, &c2).await, "I3673: its statement is kept");
    // The node withdraws the first: the second's fold read the subject's
    // rows, so it is re-folded and concludes.
    let w = e2::composer_of(attestation_type::WITHDRAWS, &c1, n);
    let o = e2::put_signed(d, &w)
        .await
        .expect("I3673: the node withdraws its first report");
    assert!(row_landed(&o), "I3673: the withdrawal concludes: {o:?}");
    assert!(
        concluded(d, &c2).await,
        "I3673: the renewal concludes once its sibling is withdrawn"
    );
    assert_eq!(held_reason(d, &c2).await, None, "I3673: no reason left");
}

/// I3676: an edition-2 peer de-admission (the typed revocation plane) is
/// read by the de-admission gate. The caller installed `kid(node)` as this
/// node's identity and own key.
pub(crate) async fn deadmission_on_the_revocation_plane_body(
    d: &dyn FederationDirectory,
    node: &str,
) {
    use crate::federation::admission::{check_peer_deadmission, DELEGATION_SCOPE_SLASH};
    let (root, peer) = ("gc1-dr-root", "gc1-dr-peer");
    e2::put_key(d, node, &[identity_type::NODE]).await;
    e2::put_key(d, peer, &[identity_type::NODE]).await;
    // The node's `slash` conferral from a root it trusts (I3081's shape):
    // revoking another's key needs it (`check_revocation_authority`).
    //
    // RT-fix1 — the root is a ROOTED edition-2 trust root (the shared
    // conferral fixture: the bundle in force, an `infrastructure` community
    // founded by its holders, the charter, this node's acceptance), and the
    // grant carries the node's own voice (G0-fix4; CC 2.6.1.9) and its bound
    // owner's (a node key is a machine key, CC 4.4.3.19). The earlier body
    // chartered a bare `node` KEY root by hand, whose grant rooted nowhere.
    // The fixture returns only once the grant reaches the root through this
    // node.
    crate::federation::admission::r2_test_support::confer_scope_from_trusted_root(
        d,
        node,
        root,
        node,
        DELEGATION_SCOPE_SLASH,
    )
    .await;
    // A peer write is admitted before the de-admission.
    let from_peer = crate::federation::tier_ingest::test_support::bare_attestation(
        "gc1-dr-from-peer",
        &e2::kid(peer),
        &e2::kid(peer),
        &serde_json::json!({}),
    );
    check_peer_deadmission(d, &from_peer, &e2::kid(node), chrono::Utc::now())
        .await
        .expect("I3676: not de-admitted yet");
    // The node's edition-2 de-admission of the peer, through the one door.
    let now = chrono::Utc::now();
    let st = e2::revocation_statement(
        node,
        peer,
        "peer_admission",
        "deadmitted",
        now,
        now,
        None,
        e2::ms(now),
    );
    let o = e2::put_statement(d, &st)
        .await
        .expect("I3676: the node's de-admission lands on the revocation plane");
    assert!(row_landed(&o), "I3676: concluded: {o:?}");
    // Outside a fold attempt the peer's write is refused, as P1's I2927 asks.
    let later = now + chrono::Duration::seconds(1);
    let e = check_peer_deadmission(d, &from_peer, &e2::kid(node), later)
        .await
        .expect_err("I3676: the de-admitted peer's write is refused");
    assert!(
        e.to_string().contains("de-admitted"),
        "I3676: the de-admission gate answers: {e}"
    );
    // Inside one it is held `peer_deadmitted`, with the peer's key declared.
    let (out, att) = fold::attempt(RowId([0x76; 32]), None, async {
        check_peer_deadmission(d, &from_peer, &e2::kid(node), later).await
    })
    .await;
    assert!(out.is_err(), "I3676: the refusal comes back");
    assert_eq!(
        att.held.map(|(r, _)| r).as_deref(),
        Some(reason::gc1::PEER_DEADMITTED),
        "I3676: a fold condition"
    );
    assert!(
        att.reads.contains(&Dep::key(&e2::kid(peer)).read_key()),
        "I3676: the peer's key is declared: {:?}",
        att.reads
    );
}

/// I3674: a converted gate inside and outside a fold attempt.
#[tokio::test]
async fn i3674_a_converted_gate_holds_inside_an_attempt_and_refuses_outside() {
    use crate::federation::admission::check_revocation_anti_rollback;
    let later = chrono::Utc::now();
    let earlier = later - chrono::Duration::seconds(5);
    let digest = "ab".repeat(32);
    let e = check_revocation_anti_rollback(&digest, Some(later), earlier)
        .expect_err("I3674: outside an attempt, the plain refusal");
    assert!(
        matches!(e, Error::RevocationRollback { .. }),
        "I3674: unchanged: {e:?}"
    );
    let (out, att) = fold::attempt(RowId([0x36; 32]), None, async {
        check_revocation_anti_rollback(&digest, Some(later), earlier)
    })
    .await;
    assert!(out.is_err(), "I3674: the gate's refusal comes back");
    assert_eq!(
        att.held.map(|(r, _)| r).as_deref(),
        Some(reason::gc1::REVOCATION_ROLLBACK),
        "I3674: inside, a fold condition"
    );
    // Declared (G0 v5.1: a FINAL-plane gate declares its reads; they are
    // monotone there).
    assert!(
        att.reads.contains(&Dep::key(&digest).read_key()),
        "I3674: the read is declared: {:?}",
        att.reads
    );
    let (out, att) = fold::attempt(RowId([0x37; 32]), None, async {
        check_revocation_anti_rollback(&digest, Some(earlier), later)
    })
    .await;
    assert!(
        out.is_ok() && att.held.is_none(),
        "I3674: a gate that admits marks nothing"
    );
}

/// I3675: the GC1 slice of the registry.
#[test]
fn i3675_gc1_reason_tokens_are_registered_once() {
    let slice = reason::gc1::ALL;
    assert!(!slice.is_empty(), "I3675: GC1 registers its tokens");
    for t in slice {
        assert_eq!(
            slice.iter().filter(|r| *r == t).count(),
            1,
            "I3675: {t} appears once in the GC1 slice"
        );
        assert!(
            !reason::ALL.contains(t),
            "I3675: {t} is not a core token (a core token is used, not redefined)"
        );
        assert!(reason::is_registered(t), "I3675: {t} is in the registry");
        assert!(
            !t.is_empty()
                && t.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "I3675: {t} is a snake_case word"
        );
    }
    assert!(
        slice.contains(&reason::gc1::CONFIG_RENEWAL_UNRESOLVED)
            && slice.contains(&reason::gc1::NODE_AGENCY_FORBIDDEN)
            && slice.contains(&reason::gc1::REVOCATION_ROLLBACK),
        "I3675: the tokens the witnesses above read are registered"
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
    i3670_i3671_subject_and_target_wait_sqlite,
    i3670_i3671_subject_and_target_wait_postgres,
    subject_and_target_wait_body
);
both!(
    i3672_node_agency_either_order_sqlite,
    i3672_node_agency_either_order_postgres,
    node_agency_either_order_body
);

both!(
    i3673_config_renewal_concludes_on_the_withdrawal_sqlite,
    i3673_config_renewal_concludes_on_the_withdrawal_postgres,
    config_renewal_body
);

/// The node whose de-admission I3676 reads.
const DR_NODE: &str = "gc1-dr-node";

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3676_deadmission_on_the_revocation_plane_sqlite() {
    let b = sqlite().await;
    b.set_node_key_id(e2::kid(DR_NODE));
    b.set_self_key_id(Some(e2::kid(DR_NODE)));
    Box::pin(deadmission_on_the_revocation_plane_body(&b, DR_NODE)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3676_deadmission_on_the_revocation_plane_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    b.set_node_key_id(e2::kid(DR_NODE));
    b.set_self_key_id(Some(e2::kid(DR_NODE)));
    Box::pin(deadmission_on_the_revocation_plane_body(&b, DR_NODE)).await;
}
