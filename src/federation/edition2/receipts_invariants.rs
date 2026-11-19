//! v62.0.0 (P10, P10 fix1; CC rc21 2.7.11, RFC 9942) — witnesses of **the
//! SCITT receipt a host holds before it runs admitted code**. Each
//! store-facing body runs on sqlite and postgres. The host is `NODE`, owned
//! by `OWNER` (an owner binding, the node's voice cosigning); its trust is
//! `OWNER`'s own `trust:accepts` edges at `self` scope (CC ruling point 5).
//!
//! - **I4040** — an `admission:unit` row with no receipt held WAITS
//!   (`admission_receipt_missing`, `none`); an id with no such row is
//!   `admission_none` (`no_row`).
//! - **I4041** — a receipt from a Transparency Service this host does not
//!   trust WAITS (`untrusted_service`): no edge; the owner's edge listing
//!   another class; a stranger's `transparency` edge; the NODE's own edge
//!   (not the owner's); the owner's edge at `federation` scope.
//! - **I4042** — the CEG arm: a receipt from a trusted service (a CEG
//!   identity, its key from its `key:record`) runs, naming the service; a
//!   trusted service's receipt that does not verify (minted over another
//!   statement's leaf) WAITS `unverifiable`; the owner's withdrawal of its
//!   edge puts the unit back to `untrusted_service`.
//! - **I4043** — a receipt that arrives later MERGES: the held statement
//!   takes the union of its receipts (two services, two deliveries), one
//!   voice is held, a repeated receipt changes nothing, and a merge
//!   re-stamps the statement's admission position.
//! - **I4044** (pure) — receipts are outside the row id and the statement
//!   id: the ids, and the door's verdict, are the same with and without
//!   them.
//! - **I4045** — a peer is SERVED the receipts: the raw listing and the
//!   requester-filtered listing hand the statement out with them, and a
//!   second node that admits the served bytes holds them and runs the unit
//!   under its own owner's edge.
//! - **I4046** (pure) — header 394 never faults: the door's pure gates pass
//!   an empty array, a receipt that is no `COSE_Sign1`, a member that is no
//!   byte string, a non-array, more than `MAX_RECEIPTS` and a non-CDE item;
//!   what is held of each is only its `ceg-receipt` members (none, or the
//!   good one), at most `MAX_RECEIPTS`.
//! - **I4047** (pure) — RFC 9162 inclusion: every leaf of trees of 1..9
//!   leaves reconstructs the tree's root, and an index at or past the size,
//!   a wrong index or a truncated path does not.
//! - **I4048** (pure) — CC's `receipt_rule` cases (the generator's samples):
//!   two run, three wait, and a rule admitting any receipt is caught.
//! - **I4049** — a garbage header 394 (CC ruling point 4): the row is
//!   ADMITTED, nothing of the garbage is held (the held bytes are the
//!   statement without the parameter), and the code waits (`none`); beside a
//!   good receipt, only the good one is held.
//! - **I4050** — the COSE_Key arm, ES256: the owner's edge's `service_key`
//!   is a P-256 COSE_Key (alg -7) and the edge names its bare RFC 9679
//!   thumbprint; the service's
//!   ES256 receipt runs the unit, naming that identity-ref.
//! - **I4051** — the COSE_Key arm, EdDSA: the same over an OKP Ed25519 key
//!   (alg -8).
//! - **I4052** — the alg must match the key's: an EdDSA-signed receipt under
//!   the ES256 key's `kid` WAITS `unverifiable`; an edge whose subject is not
//!   its key's thumbprint trusts nothing (`untrusted_service`).
//! - **I4053** — the COSE_Key arm, ML-DSA-65 (AKP, alg -49): its receipt
//!   runs the unit; the same key's signature under alg -70100 waits
//!   `unverifiable`.
//! - **I4054** — the COSE_Key arm, the composite (AKP, alg -70100) for a key
//!   no `key:record` holds: the key's thumbprint is CEG's, and its receipt
//!   runs the unit.
//! - **I4055** — a stranger's (non-owner) transparency edge, in either arm,
//!   confers nothing: the unit still waits `untrusted_service`.
//! - **I4056** — the door skips the subject rule only for a thumbprint no
//!   CEG key has: a third-party key is self-certified; a COSE_Key carrying
//!   TS1's (a CEG key's) public key is not, and confers nothing.
//! - **I4057** — a COSE_Key without a `kid`: a verifying receipt under any
//!   kid runs; a failing one whose kid is some other key's is
//!   `untrusted_service` (a kid carries no weight); one naming the
//!   thumbprint's identity-ref as CWT `iss` is `unverifiable`.

use ciris_crypto::ClassicalSigner as _;
use ciris_verify_core::cde::{self, Value};

use super::fixture_switch as e2;
use super::liveness::HeldKeys;
use super::names::RowId;
use super::receipts::{
    self, admission_unit_runnable, receipts_of, with_receipts, AdmissionReceipt, ReceiptMissing,
    ReceiptReading,
};
use crate::federation::FederationDirectory;

/// The `admission:unit` signer (a person).
const PERSON: &str = "p10-person";
/// The host.
const NODE: &str = "p10-node";
/// The host's owner, whose edges decide.
const OWNER: &str = "p10-owner";
/// Two CEG Transparency Services.
const TS1: &str = "p10-ts-1";
const TS2: &str = "p10-ts-2";
/// A key that is not the owner.
const STRANGER: &str = "p10-stranger";
/// The third-party services' `kid`s.
const ES_KID: &[u8] = b"es-1";
const ED_KID: &[u8] = b"ed-1";

fn now_ms() -> u64 {
    e2::ms(crate::host::clock::now())
}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&t(k)));
    Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
}

/// An owner-alone `admission:unit` row of `PERSON` admitting `compute` for
/// the unit `[unit; 32]`, its lease open now for an hour.
fn unit_statement(unit: u8) -> Vec<u8> {
    let key = e2::signing_key(PERSON);
    let iss = e2::kid(PERSON);
    let at = now_ms() - 1_000;
    let payload = det_map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", t(&iss)),
        ("capabilities", Value::Array(vec![t("compute")])),
        ("cohort_scope", t("self")),
        ("dimension", t("admission:unit:v1")),
        (
            "unit",
            Value::Array(vec![Value::Nint(15), Value::Bytes(vec![unit; 32])]),
        ),
        ("valid_until", Value::Uint(at + 3_600_000)),
    ]);
    let sub = format!(
        "{}{}",
        super::payloads::ADMISSION_UNIT_SUB_PREFIX,
        hex::encode([unit; 32])
    );
    ciris_verify_core::edition2::sign_row_statement(
        &key,
        &iss,
        &sub,
        "scores",
        &ciris_verify_core::namespace_match::family_id(super::payloads::ADMISSION_UNIT_FAMILY),
        &payload,
        vec![],
    )
    .expect("P10: sign an admission:unit statement")
}

const OTHERS: [&[u8]; 2] = [b"leaf-a", b"leaf-b"];

fn others() -> Vec<Vec<u8>> {
    OTHERS.iter().map(|l| l.to_vec()).collect()
}

/// A CEG `service`'s receipt over `statement` (a tree of three leaves).
fn receipt(service: &str, statement: &[u8]) -> Vec<u8> {
    receipts::mint_receipt(
        &e2::signing_key(service),
        Some(&e2::kid(service)),
        statement,
        &others(),
        1,
    )
}

/// A third-party receipt over `statement`: protected `alg` and `kid`,
/// signed by `sign`.
fn cose_receipt(
    alg: i64,
    kid: &[u8],
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
    statement: &[u8],
) -> Vec<u8> {
    receipts::mint_receipt_with(
        vec![
            (Value::int(1), Value::int(alg)),
            (Value::int(4), Value::Bytes(kid.to_vec())),
        ],
        sign,
        statement,
        &others(),
        2,
    )
}

/// The ES256 service's signer (a fixed P-256 scalar).
fn p256() -> ciris_crypto::P256Signer {
    ciris_crypto::P256Signer::from_bytes(&[0x11; 32]).expect("P10: a P-256 scalar")
}

/// The EdDSA service's signer.
fn ed25519() -> ciris_crypto::Ed25519Signer {
    ciris_crypto::Ed25519Signer::from_seed(&[0x22; 32]).expect("P10: an Ed25519 seed")
}

/// The ES256 service's COSE_Key (EC2, P-256, alg -7, kid `es-1`).
fn p256_cose_key() -> Vec<u8> {
    let sec1 = p256().public_key().expect("P10: the P-256 public key");
    assert_eq!(sec1.len(), 65, "P10: SEC1 uncompressed");
    cde::encode(&Value::Map(vec![
        (Value::int(1), Value::Uint(2)),
        (Value::int(2), Value::Bytes(ES_KID.to_vec())),
        (Value::int(3), Value::int(receipts::ALG_ES256)),
        (Value::int(-1), Value::Uint(1)),
        (Value::int(-2), Value::Bytes(sec1[1..33].to_vec())),
        (Value::int(-3), Value::Bytes(sec1[33..65].to_vec())),
    ]))
}

/// The EdDSA service's COSE_Key (OKP, Ed25519, alg -8, kid `ed-1`).
fn ed25519_cose_key() -> Vec<u8> {
    let pk = ed25519().public_key().expect("P10: the Ed25519 public key");
    cde::encode(&Value::Map(vec![
        (Value::int(1), Value::Uint(1)),
        (Value::int(2), Value::Bytes(ED_KID.to_vec())),
        (Value::int(3), Value::int(receipts::ALG_EDDSA)),
        (Value::int(-1), Value::Uint(6)),
        (Value::int(-2), Value::Bytes(pk)),
    ]))
}

/// The ML-DSA-65 service's signer.
fn ml_dsa() -> ciris_crypto::MlDsa65Signer {
    ciris_crypto::MlDsa65Signer::from_seed(&[0x55; 32]).expect("P10: an ML-DSA-65 seed")
}

/// The composite service's key (no `key:record`: a service outside CEG's
/// key plane, carried on the edge).
fn composite() -> ciris_crypto::composite::CompositeSigningKey {
    ciris_crypto::composite::CompositeSigningKey::from_seeds(&[0x33; 32], &[0x44; 32])
}

/// An AKP COSE_Key (alg `alg`, kid `kid`) over `public`.
fn akp_cose_key(alg: i64, kid: &[u8], public: Vec<u8>) -> Vec<u8> {
    cde::encode(&Value::Map(vec![
        (Value::int(1), Value::Uint(7)),
        (Value::int(2), Value::Bytes(kid.to_vec())),
        (Value::int(3), Value::int(alg)),
        (Value::int(-1), Value::Bytes(public)),
    ]))
}

/// What a COSE_Key edge names: its RFC 9679 thumbprint as the BARE 43-char
/// base64url key segment (CC's answer), not the URN.
fn ref_of(cose_key: &[u8]) -> String {
    let k = receipts::parse_cose_key(cose_key).expect("P10: the COSE_Key parses");
    assert_eq!(k.subject.len(), 43, "P10: a bare 43-char segment");
    assert!(
        !k.subject.starts_with("urn:"),
        "P10: the subject is the bare segment, never the URN"
    );
    k.subject
}

/// The `service_key` of a COSE_Key edge.
fn cose_member(cose_key: &[u8]) -> Option<Value> {
    Some(Value::Bytes(cose_key.to_vec()))
}

fn attach(statement: &[u8], rs: &[Vec<u8>]) -> Vec<u8> {
    with_receipts(statement, rs).expect("P10: a COSE_Sign1")
}

/// The keys; `OWNER`'s owner binding of `NODE` (her statement, then the
/// node's voice) and the node's own self-occurrence, so `OWNER` is the host
/// owner (asserted).
async fn setup(d: &dyn FederationDirectory) {
    for k in [PERSON, OWNER, TS1, TS2, STRANGER] {
        e2::put_key(d, k, &["user"]).await;
    }
    e2::put_key(d, NODE, &["node"]).await;
    let bound_at = chrono::Utc::now() - chrono::Duration::minutes(1);
    for v in crate::federation::key_grant_invariants::two_node::owner_binding_voices(
        OWNER, NODE, bound_at,
    ) {
        put(d, &v).await;
    }
    // The node's OWN self-occurrence (author = identity = occurrence = the
    // node), as E3b's `own_node` and P5c/E13 bring a node up: the owner
    // relation reads the node as a live occurrence of itself.
    match Box::pin(e2::put_bind(
        d,
        NODE,
        NODE,
        NODE,
        crate::federation::types::device_class::SERVER,
        &e2::BindOptions::default(),
    ))
    .await
    {
        Ok(super::ingest::StatementOutcome::Row { .. }) => {}
        other => panic!("P10: the node's own self-occurrence: {other:?}"),
    }
    assert_eq!(
        crate::federation::admission::owner_of_unmarked(d, &e2::kid(NODE))
            .await
            .expect("P10: the owner relation reads"),
        Some(e2::kid(OWNER)),
        "P10 setup: OWNER is the host owner"
    )
}

async fn put(d: &dyn FederationDirectory, statement: &[u8]) {
    e2::put_statement(d, statement)
        .await
        .unwrap_or_else(|e| panic!("P10: the statement is kept: {e:?}"));
}

/// `granter`'s `trust:accepts` edge naming `subject` exactly (a CEG
/// identity-ref, or a COSE_Key's bare thumbprint), listing `classes` at
/// `scope`, its `service_key` member `member` when given.
async fn edge_with(
    d: &dyn FederationDirectory,
    granter: &str,
    subject: &str,
    classes: &[&str],
    scope: &str,
    member: Option<Value>,
) -> Vec<u8> {
    let st = edge_statement(granter, subject, classes, scope, member);
    put(d, &st).await;
    st
}

/// The statement [`edge_with`] puts.
fn edge_statement(
    granter: &str,
    subject: &str,
    classes: &[&str],
    scope: &str,
    member: Option<Value>,
) -> Vec<u8> {
    let classes: Vec<String> = classes.iter().map(|c| (*c).to_owned()).collect();
    let p = super::typed::trust_accepts_payload(
        &e2::kid(granter),
        &[crate::federation::trust_root::INFRA_SERVE_SCOPE],
        &classes,
        None,
        scope,
        now_ms(),
    );
    let p = match (p, member) {
        (Value::Map(mut m), Some(v)) => {
            m.push((t(receipts::SERVICE_KEY_MEMBER), v));
            m.sort_by_key(|(k, _)| cde::encode(k));
            Value::Map(m)
        }
        (p, _) => p,
    };
    // Signed directly: the subject is kept exactly (a bare segment is no
    // seed the fixtures may rewrite).
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(granter),
        &e2::kid(granter),
        subject,
        "delegates_to",
        &ciris_verify_core::namespace_match::family_id(super::typed::TRUST_PREFIX),
        &p,
        vec![],
    )
    .expect("P10: sign a trust:accepts edge")
}

/// The owner's `self`-scope transparency edge to the CEG service `seed`, its
/// `service_key` the service's identity-ref.
async fn trust(d: &dyn FederationDirectory, seed: &str) -> Vec<u8> {
    let iref = e2::kid(seed);
    edge_with(
        d,
        OWNER,
        &iref,
        &["transparency"],
        "self",
        Some(Value::Text(iref.clone())),
    )
    .await
}

async fn answer(d: &dyn FederationDirectory, statement: &[u8]) -> AdmissionReceipt {
    let id = RowId::of_statement(statement).expect("P10: a row statement");
    admission_unit_runnable(d, &id, crate::host::clock::now())
        .await
        .expect("P10: the receipt leg reads")
}

/// The one held voice of `statement`'s row.
async fn held_voice(d: &dyn FederationDirectory, statement: &[u8]) -> Vec<u8> {
    let id = RowId::of_statement(statement).expect("P10: a row statement");
    let voices = d.edition2_voices(&id).await.unwrap();
    assert_eq!(
        voices.len(),
        1,
        "P10: one voice is held, whatever its receipts"
    );
    voices.into_iter().next().unwrap()
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    v.sort();
    v
}

/// I4040 — no receipt waits `none`; no row is `no_row`.
pub(crate) async fn no_receipt_waits_body(d: &dyn FederationDirectory) {
    setup(d).await;
    trust(d, TS1).await;
    let st = unit_statement(0x40);
    put(d, &st).await;
    let a = answer(d, &st).await;
    assert_eq!(a, AdmissionReceipt::Waiting(ReceiptMissing::None), "I4040");
    assert_eq!(a.token(), Some(receipts::ADMISSION_RECEIPT_MISSING));
    assert_eq!(a.detail(), Some("none"));
    assert!(!a.is_runnable());
    let none = admission_unit_runnable(d, &RowId([0x4f; 32]), crate::host::clock::now())
        .await
        .unwrap();
    assert_eq!(none, AdmissionReceipt::NotHeld, "I4040 no row");
    assert_eq!(none.token(), Some(receipts::ADMISSION_NONE));
    assert_eq!(none.detail(), Some("no_row"));
}

/// I4041 — a service this host does not trust counts for nothing.
pub(crate) async fn untrusted_service_waits_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let st = unit_statement(0x41);
    put(d, &attach(&st, &[receipt(TS1, &st)])).await;
    let want = AdmissionReceipt::Waiting(ReceiptMissing::UntrustedService);
    assert_eq!(answer(d, &st).await, want, "I4041 no edge");
    edge_with(d, OWNER, &e2::kid(TS1), &["admission"], "self", None).await;
    assert_eq!(
        answer(d, &st).await,
        want,
        "I4041 the owner's edge lists another class"
    );
    edge_with(d, STRANGER, &e2::kid(TS1), &["transparency"], "self", None).await;
    assert_eq!(
        answer(d, &st).await,
        want,
        "I4041 a stranger's transparency edge"
    );
    edge_with(d, NODE, &e2::kid(TS1), &["transparency"], "self", None).await;
    assert_eq!(
        answer(d, &st).await,
        want,
        "I4041 the node's own edge: the trust is the owner's"
    );
    edge_with(
        d,
        OWNER,
        &e2::kid(TS1),
        &["transparency"],
        "federation",
        None,
    )
    .await;
    assert_eq!(
        answer(d, &st).await,
        want,
        "I4041 the owner's edge at federation scope: the host's trust is at self"
    );
}

/// I4042 — the CEG arm: a trusted service's receipt runs; an unverifiable
/// one waits; a withdrawn edge stops trusting.
pub(crate) async fn trusted_service_runs_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let edge = trust(d, TS1).await;
    // A receipt minted over ANOTHER statement's leaf, held on this one.
    let st = unit_statement(0x42);
    let other = unit_statement(0x43);
    put(d, &attach(&st, &[receipt(TS1, &other)])).await;
    assert_eq!(
        answer(d, &st).await,
        AdmissionReceipt::Waiting(ReceiptMissing::Unverifiable),
        "I4042 a trusted service's receipt that does not verify"
    );
    // The good receipt arrives: it runs.
    put(d, &attach(&st, &[receipt(TS1, &st)])).await;
    let a = answer(d, &st).await;
    assert!(a.is_runnable(), "I4042 runnable: {a:?}");
    let AdmissionReceipt::Runnable {
        service,
        statement_id,
    } = &a
    else {
        unreachable!()
    };
    assert_eq!(service, &e2::kid(TS1), "I4042 names the service");
    assert_eq!(
        Some(*statement_id),
        receipts::statement_id_of(&st),
        "I4042 names the voice"
    );
    assert_eq!(a.token(), None);
    // The owner withdraws its edge: the service is trusted no more.
    let w = super::typed_fixtures::trust_withdraws_statement(
        OWNER,
        TS1,
        &RowId::of_statement(&edge).unwrap(),
        now_ms() + 1,
    );
    put(d, &w).await;
    assert_eq!(
        answer(d, &st).await,
        AdmissionReceipt::Waiting(ReceiptMissing::UntrustedService),
        "I4042 a withdrawn edge"
    );
}

/// The cursor of `statement_id` in the raw listing.
async fn cursor_of(d: &dyn FederationDirectory, statement_id: &[u8; 32]) -> i64 {
    d.edition2_statements_since(None, 1000)
        .await
        .unwrap()
        .into_iter()
        .find(|s| &s.cursor.statement_id == statement_id)
        .expect("P10: the statement is listed")
        .cursor
        .admitted_us
}

/// I4043 — later receipts merge, never replace.
pub(crate) async fn later_receipts_merge_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let st = unit_statement(0x44);
    let sid = receipts::statement_id_of(&st).unwrap();
    put(d, &st).await;
    assert!(
        receipts_of(&held_voice(d, &st).await).is_empty(),
        "I4043 none yet"
    );
    let before = cursor_of(d, &sid).await;
    let (r1, r2) = (receipt(TS1, &st), receipt(TS2, &st));
    put(d, &attach(&st, std::slice::from_ref(&r1))).await;
    assert_eq!(
        receipts_of(&held_voice(d, &st).await),
        vec![r1.clone()],
        "I4043 r1"
    );
    let after_r1 = cursor_of(d, &sid).await;
    assert!(
        after_r1 > before,
        "I4043 a merge re-stamps: {before} -> {after_r1}"
    );
    // A copy carrying only r2 (another service, another delivery).
    put(d, &attach(&st, std::slice::from_ref(&r2))).await;
    let held = held_voice(d, &st).await;
    assert_eq!(
        receipts_of(&held),
        sorted(vec![r1.clone(), r2.clone()]),
        "I4043 the union, never a replacement"
    );
    // A repeated receipt, and a copy with none, change nothing.
    let at = cursor_of(d, &sid).await;
    put(d, &attach(&st, std::slice::from_ref(&r1))).await;
    put(d, &st).await;
    assert_eq!(
        held_voice(d, &st).await,
        held,
        "I4043 nothing new: the bytes stand"
    );
    assert_eq!(
        cursor_of(d, &sid).await,
        at,
        "I4043 nothing new: no re-stamp"
    );
    // I4044 at the store: the row and statement ids of the held bytes.
    assert_eq!(
        RowId::of_statement(&held),
        RowId::of_statement(&st),
        "I4044 row id"
    );
    assert_eq!(
        receipts::statement_id_of(&held),
        Some(sid),
        "I4044 statement id"
    );
}

/// I4045 — a peer is served the receipts, and holds them.
pub(crate) async fn peer_served_receipts_body(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
) {
    setup(a).await;
    setup(b).await;
    let st = unit_statement(0x45);
    let sid = receipts::statement_id_of(&st).unwrap();
    let (r1, r2) = (receipt(TS1, &st), receipt(TS2, &st));
    put(a, &st).await;
    put(a, &attach(&st, std::slice::from_ref(&r1))).await;
    put(a, &attach(&st, std::slice::from_ref(&r2))).await;
    let want = sorted(vec![r1, r2]);
    let raw = a
        .edition2_statements_since(None, 1000)
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.cursor.statement_id == sid)
        .expect("I4045 listed")
        .bytes;
    assert_eq!(
        receipts_of(&raw),
        want,
        "I4045 the raw listing carries them"
    );
    let author = e2::kid(PERSON);
    let served = super::serve::statements_served_to(a, None, 1000, Some(author.as_str()))
        .await
        .unwrap()
        .statements
        .into_iter()
        .find(|s| s.cursor.statement_id == sid)
        .expect("I4045 served to its author")
        .bytes;
    assert_eq!(
        receipts_of(&served),
        want,
        "I4045 the serve path carries them"
    );
    // The peer admits the served bytes and holds the receipts.
    trust(b, TS2).await;
    put(b, &served).await;
    assert_eq!(
        receipts_of(&held_voice(b, &st).await),
        want,
        "I4045 the peer holds them"
    );
    let ans = answer(b, &st).await;
    assert!(
        matches!(&ans, AdmissionReceipt::Runnable { service, .. } if *service == e2::kid(TS2)),
        "I4045 the peer runs it under its own owner's edge: {ans:?}"
    );
    // Node A's owner trusts neither service: the same receipts wait there.
    assert_eq!(
        answer(a, &st).await,
        AdmissionReceipt::Waiting(ReceiptMissing::UntrustedService),
        "I4045 trust is each host's own"
    );
}

/// `statement` with its unprotected label 394 set to `v` as it is.
fn with_raw_receipts(statement: &[u8], v: Value) -> Vec<u8> {
    let Value::Tag(18, inner) = cde::decode(statement).unwrap() else {
        panic!("P10: a tag-18 statement")
    };
    let Value::Array(mut parts) = *inner else {
        panic!("P10: four parts")
    };
    parts[1] = Value::Map(vec![(Value::int(receipts::RECEIPTS_LABEL), v)]);
    cde::encode(&Value::Tag(18, Box::new(Value::Array(parts))))
}

/// CC's own invalid sample `[bytes(4), {}, None, bytes(64)]`: untagged, no
/// vdp.
fn not_sign1() -> Vec<u8> {
    cde::encode(&Value::Array(vec![
        Value::Bytes(vec![0; 4]),
        Value::Map(vec![]),
        Value::Null,
        Value::Bytes(vec![0; 64]),
    ]))
}

/// An item not in the deterministic encoding (the uint 1 in a non-shortest
/// head).
fn not_cde() -> Vec<u8> {
    vec![0x18, 0x01]
}

/// Header 394 garbage: every item in it is ignored.
fn garbage() -> Value {
    Value::Array(vec![
        Value::Text("r".into()),
        Value::Bytes(not_cde()),
        Value::Bytes(not_sign1()),
        Value::Uint(7),
    ])
}

/// I4049 — a garbage header 394 never faults the row; nothing of it is held.
pub(crate) async fn garbage_header_body(d: &dyn FederationDirectory) {
    setup(d).await;
    trust(d, TS1).await;
    let st = unit_statement(0x49);
    put(d, &with_raw_receipts(&st, garbage())).await;
    assert_eq!(
        held_voice(d, &st).await,
        st,
        "I4049 nothing of the garbage is held: the statement without the parameter"
    );
    assert_eq!(
        answer(d, &st).await,
        AdmissionReceipt::Waiting(ReceiptMissing::None),
        "I4049 the code waits"
    );
    // A parameter that is not an array: the same.
    let st2 = unit_statement(0x4a);
    put(d, &with_raw_receipts(&st2, Value::Bytes(not_sign1()))).await;
    assert_eq!(
        held_voice(d, &st2).await,
        st2,
        "I4049 a non-array parameter"
    );
    // Garbage beside a good receipt: only the receipt is held, and it runs.
    let good = receipt(TS1, &st);
    let mut items = garbage();
    if let Value::Array(a) = &mut items {
        a.push(Value::Bytes(good.clone()));
    }
    put(d, &with_raw_receipts(&st, items)).await;
    assert_eq!(
        receipts_of(&held_voice(d, &st).await),
        vec![good],
        "I4049 only the receipt is held"
    );
    assert!(answer(d, &st).await.is_runnable(), "I4049 and it runs");
}

/// I4050 — the COSE_Key arm, ES256.
pub(crate) async fn cose_es256_runs_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let key = p256_cose_key();
    let service = ref_of(&key);
    edge_with(
        d,
        OWNER,
        &service,
        &["transparency"],
        "self",
        cose_member(&key),
    )
    .await;
    let st = unit_statement(0x50);
    let signer = p256();
    let r = cose_receipt(
        receipts::ALG_ES256,
        ES_KID,
        &|tbs| signer.sign(tbs).expect("P10: ES256 sign"),
        &st,
    );
    put(d, &attach(&st, &[r])).await;
    let a = answer(d, &st).await;
    assert!(
        matches!(&a, AdmissionReceipt::Runnable { service: s, .. } if *s == service),
        "I4050 an ES256 receipt under the owner's COSE_Key edge runs: {a:?}"
    );
}

/// I4051 — the COSE_Key arm, EdDSA.
pub(crate) async fn cose_eddsa_runs_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let key = ed25519_cose_key();
    let service = ref_of(&key);
    edge_with(
        d,
        OWNER,
        &service,
        &["transparency"],
        "self",
        cose_member(&key),
    )
    .await;
    let st = unit_statement(0x51);
    let signer = ed25519();
    let r = cose_receipt(
        receipts::ALG_EDDSA,
        ED_KID,
        &|tbs| signer.sign(tbs).expect("P10: EdDSA sign"),
        &st,
    );
    put(d, &attach(&st, &[r])).await;
    let a = answer(d, &st).await;
    assert!(
        matches!(&a, AdmissionReceipt::Runnable { service: s, .. } if *s == service),
        "I4051 an EdDSA receipt under the owner's COSE_Key edge runs: {a:?}"
    );
}

/// I4052 — the receipt's alg must match the key's; an edge must name its
/// own key.
pub(crate) async fn cose_alg_mismatch_waits_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let key = p256_cose_key();
    edge_with(
        d,
        OWNER,
        &ref_of(&key),
        &["transparency"],
        "self",
        cose_member(&key),
    )
    .await;
    // An EdDSA-signed receipt under the ES256 service's kid.
    let st = unit_statement(0x52);
    let signer = ed25519();
    let r = cose_receipt(
        receipts::ALG_EDDSA,
        ES_KID,
        &|tbs| signer.sign(tbs).expect("P10: EdDSA sign"),
        &st,
    );
    put(d, &attach(&st, &[r])).await;
    assert_eq!(
        answer(d, &st).await,
        AdmissionReceipt::Waiting(ReceiptMissing::Unverifiable),
        "I4052 an alg other than the key's never verifies"
    );
    // The Ed25519 key carried on an edge naming ANOTHER identity: it trusts
    // nothing, so the service's own receipt waits.
    let ed = ed25519_cose_key();
    edge_with(
        d,
        OWNER,
        &e2::kid(TS2),
        &["transparency"],
        "self",
        cose_member(&ed),
    )
    .await;
    let st2 = unit_statement(0x53);
    let ed_signer = ed25519();
    let r2 = cose_receipt(
        receipts::ALG_EDDSA,
        ED_KID,
        &|tbs| ed_signer.sign(tbs).expect("P10: EdDSA sign"),
        &st2,
    );
    put(d, &attach(&st2, &[r2])).await;
    assert_eq!(
        answer(d, &st2).await,
        AdmissionReceipt::Waiting(ReceiptMissing::UntrustedService),
        "I4052 an edge whose subject is not its key's thumbprint trusts nothing"
    );
}

/// The owner's COSE_Key edge to `key`'s service, a receipt in `alg` under
/// `kid` signed by `sign` over a fresh unit, and the answer.
async fn cose_arm(
    d: &dyn FederationDirectory,
    key: &[u8],
    alg: i64,
    kid: &[u8],
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
    unit: u8,
) -> (String, AdmissionReceipt) {
    let service = ref_of(key);
    edge_with(
        d,
        OWNER,
        &service,
        &["transparency"],
        "self",
        cose_member(key),
    )
    .await;
    let st = unit_statement(unit);
    put(d, &attach(&st, &[cose_receipt(alg, kid, sign, &st)])).await;
    (service, answer(d, &st).await)
}

/// I4053 — the COSE_Key arm, ML-DSA-65 (AKP, alg -49).
pub(crate) async fn cose_ml_dsa_runs_body(d: &dyn FederationDirectory) {
    use ciris_crypto::PqcSigner as _;
    setup(d).await;
    let signer = ml_dsa();
    let key = akp_cose_key(
        receipts::ALG_ML_DSA_65,
        b"ml-1",
        signer.public_key().expect("P10: the ML-DSA-65 public key"),
    );
    let (service, a) = cose_arm(
        d,
        &key,
        receipts::ALG_ML_DSA_65,
        b"ml-1",
        &|tbs| signer.sign(tbs).expect("P10: ML-DSA-65 sign"),
        0x54,
    )
    .await;
    assert!(
        matches!(&a, AdmissionReceipt::Runnable { service: s, .. } if *s == service),
        "I4053 an ML-DSA-65 receipt under the owner's COSE_Key edge runs: {a:?}"
    );
    // The same key under the composite alg: a mismatch, it waits.
    let st = unit_statement(0x55);
    let r = cose_receipt(
        receipts::ALG_COMPOSITE,
        b"ml-1",
        &|tbs| signer.sign(tbs).expect("P10: ML-DSA-65 sign"),
        &st,
    );
    put(d, &attach(&st, &[r])).await;
    assert_eq!(
        answer(d, &st).await,
        AdmissionReceipt::Waiting(ReceiptMissing::Unverifiable),
        "I4053 a receipt whose alg is not the key's waits"
    );
}

/// I4054 — the COSE_Key arm, the composite (AKP, alg -70100), for a key no
/// `key:record` holds; its thumbprint is the edge's subject.
pub(crate) async fn cose_composite_runs_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let signer = composite();
    let key = akp_cose_key(
        receipts::ALG_COMPOSITE,
        b"cp-1",
        signer.public_key().as_bytes().to_vec(),
    );
    assert_eq!(
        Some(ref_of(&key)),
        crate::federation::namespace::key_segment::segment_of(
            &ciris_verify_core::edition2::identity_ref(&ciris_verify_core::edition2::thumbprint(
                signer.public_key()
            ))
        ),
        "I4054 an AKP composite key's thumbprint is the CEG thumbprint, as its bare segment"
    );
    let (service, a) = cose_arm(
        d,
        &key,
        receipts::ALG_COMPOSITE,
        b"cp-1",
        &|tbs| signer.sign(tbs).expect("P10: composite sign"),
        0x56,
    )
    .await;
    assert!(
        matches!(&a, AdmissionReceipt::Runnable { service: s, .. } if *s == service),
        "I4054 a composite receipt under the owner's COSE_Key edge runs: {a:?}"
    );
}

/// I4055 — a stranger's (non-owner) transparency edge confers nothing, in
/// either arm: the edge is admitted (a COSE_Key edge naming its own
/// thumbprint passes the subject rule), and the unit still waits.
pub(crate) async fn stranger_edge_confers_nothing_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let key = p256_cose_key();
    let service = ref_of(&key);
    edge_with(
        d,
        STRANGER,
        &service,
        &["transparency"],
        "self",
        cose_member(&key),
    )
    .await;
    edge_with(
        d,
        STRANGER,
        &e2::kid(TS1),
        &["transparency"],
        "self",
        Some(Value::Text(e2::kid(TS1))),
    )
    .await;
    let st = unit_statement(0x57);
    let signer = p256();
    let es = cose_receipt(
        receipts::ALG_ES256,
        ES_KID,
        &|tbs| signer.sign(tbs).expect("P10: ES256 sign"),
        &st,
    );
    put(d, &attach(&st, &[es, receipt(TS1, &st)])).await;
    assert_eq!(
        answer(d, &st).await,
        AdmissionReceipt::Waiting(ReceiptMissing::UntrustedService),
        "I4055 a stranger's edges: the unit still waits, untrusted"
    );
}

/// I4056 — the door's skip of the subject rule is only for a thumbprint no
/// CEG key has: a COSE_Key carrying TS1's (a CEG key's) public key does not
/// dodge it, and confers nothing even on the owner's edge.
pub(crate) async fn ceg_key_thumbprint_takes_the_subject_rule_body(d: &dyn FederationDirectory) {
    setup(d).await;
    // The positive: an ES256 key no key:record holds is self-certified.
    let es = p256_cose_key();
    let es_edge = edge_statement(
        OWNER,
        &ref_of(&es),
        &["transparency"],
        "self",
        cose_member(&es),
    );
    let row = e2::row_of_statement(&es_edge, super::ingest::INGEST_TIER);
    assert!(
        receipts::is_self_certified_service_edge(d, &row)
            .await
            .unwrap(),
        "I4056 a third-party key's own thumbprint is self-certified"
    );
    // TS1's composite public key (its key:record is held) as a COSE_Key.
    let ts1 = e2::signing_key(TS1);
    let key = akp_cose_key(
        receipts::ALG_COMPOSITE,
        b"ts-1",
        ts1.public_key().as_bytes().to_vec(),
    );
    let st_edge = edge_statement(
        OWNER,
        &ref_of(&key),
        &["transparency"],
        "self",
        cose_member(&key),
    );
    let row = e2::row_of_statement(&st_edge, super::ingest::INGEST_TIER);
    assert!(
        !receipts::is_self_certified_service_edge(d, &row)
            .await
            .unwrap(),
        "I4056 a CEG key's thumbprint is never self-certified"
    );
    // Put through the door: the normal subject rule holds it (never refused
    // outright), so it is not a trust edge here.
    let _ = e2::put_statement(d, &st_edge).await;
    let st = unit_statement(0x58);
    let r = cose_receipt(
        receipts::ALG_COMPOSITE,
        b"ts-1",
        &|tbs| ts1.sign(tbs).expect("P10: composite sign"),
        &st,
    );
    put(d, &attach(&st, &[r])).await;
    assert_eq!(
        answer(d, &st).await,
        AdmissionReceipt::Waiting(ReceiptMissing::UntrustedService),
        "I4056 a COSE_Key carrying a CEG key's public key confers nothing"
    );
}

/// I4057 — a COSE_Key WITHOUT a kid: the receipt's own kid carries no weight
/// for it; a receipt is attributed to the key by its thumbprint (a CWT
/// `iss` naming the thumbprint's identity-ref) or by verifying under it.
pub(crate) async fn cose_key_without_kid_body(d: &dyn FederationDirectory) {
    setup(d).await;
    let signer = p256();
    let sec1 = signer.public_key().expect("P10: the P-256 public key");
    let key = cde::encode(&Value::Map(vec![
        (Value::int(1), Value::Uint(2)),
        (Value::int(3), Value::int(receipts::ALG_ES256)),
        (Value::int(-1), Value::Uint(1)),
        (Value::int(-2), Value::Bytes(sec1[1..33].to_vec())),
        (Value::int(-3), Value::Bytes(sec1[33..65].to_vec())),
    ]));
    let parsed = receipts::parse_cose_key(&key).unwrap();
    assert_eq!(parsed.kid, None);
    assert_eq!(
        ref_of(&key),
        ref_of(&p256_cose_key()),
        "I4057 the kid is no RFC 9679 required member: one thumbprint"
    );
    edge_with(
        d,
        OWNER,
        &ref_of(&key),
        &["transparency"],
        "self",
        cose_member(&key),
    )
    .await;
    // A valid ES256 receipt under ANY kid runs: it verifies under the key.
    let st = unit_statement(0x59);
    let ok = cose_receipt(
        receipts::ALG_ES256,
        b"whatever",
        &|tbs| signer.sign(tbs).expect("P10: ES256 sign"),
        &st,
    );
    put(d, &attach(&st, &[ok])).await;
    assert!(answer(d, &st).await.is_runnable(), "I4057 verifies: runs");
    // An EdDSA receipt with the ES256 kid-less key's would-be kid: the kid
    // carries no weight, so it is from no trusted service.
    let ed = ed25519();
    let st2 = unit_statement(0x5a);
    let bad = cose_receipt(
        receipts::ALG_EDDSA,
        ES_KID,
        &|tbs| ed.sign(tbs).expect("P10: EdDSA sign"),
        &st2,
    );
    put(d, &attach(&st2, &[bad])).await;
    assert_eq!(
        answer(d, &st2).await,
        AdmissionReceipt::Waiting(ReceiptMissing::UntrustedService),
        "I4057 a kid carries no weight for a kid-less key"
    );
    // The same failing receipt naming the thumbprint's identity-ref as its
    // CWT iss is the service's: unverifiable.
    let st3 = unit_statement(0x5b);
    let named = receipts::mint_receipt_with(
        vec![
            (Value::int(1), Value::int(receipts::ALG_EDDSA)),
            (
                Value::int(15),
                Value::Map(vec![(Value::int(1), Value::Text(parsed.identity_ref()))]),
            ),
        ],
        &|tbs| ed.sign(tbs).expect("P10: EdDSA sign"),
        &st3,
        &others(),
        0,
    );
    put(d, &attach(&st3, &[named])).await;
    assert_eq!(
        answer(d, &st3).await,
        AdmissionReceipt::Waiting(ReceiptMissing::Unverifiable),
        "I4057 attributed by the thumbprint: unverifiable"
    );
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid(NODE));
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
    b.set_node_key_id(e2::kid(NODE));
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
    i4040_no_receipt_waits_sqlite,
    i4040_no_receipt_waits_postgres,
    no_receipt_waits_body
);
both!(
    i4041_untrusted_service_waits_sqlite,
    i4041_untrusted_service_waits_postgres,
    untrusted_service_waits_body
);
both!(
    i4042_trusted_service_runs_sqlite,
    i4042_trusted_service_runs_postgres,
    trusted_service_runs_body
);
both!(
    i4043_i4044_later_receipts_merge_sqlite,
    i4043_i4044_later_receipts_merge_postgres,
    later_receipts_merge_body
);
both!(
    i4049_garbage_header_394_never_faults_sqlite,
    i4049_garbage_header_394_never_faults_postgres,
    garbage_header_body
);
both!(
    i4050_cose_key_es256_runs_sqlite,
    i4050_cose_key_es256_runs_postgres,
    cose_es256_runs_body
);
both!(
    i4051_cose_key_eddsa_runs_sqlite,
    i4051_cose_key_eddsa_runs_postgres,
    cose_eddsa_runs_body
);
both!(
    i4052_cose_key_alg_mismatch_waits_sqlite,
    i4052_cose_key_alg_mismatch_waits_postgres,
    cose_alg_mismatch_waits_body
);
both!(
    i4053_cose_key_ml_dsa_65_runs_sqlite,
    i4053_cose_key_ml_dsa_65_runs_postgres,
    cose_ml_dsa_runs_body
);
both!(
    i4054_cose_key_composite_runs_sqlite,
    i4054_cose_key_composite_runs_postgres,
    cose_composite_runs_body
);
both!(
    i4055_a_strangers_edge_confers_nothing_sqlite,
    i4055_a_strangers_edge_confers_nothing_postgres,
    stranger_edge_confers_nothing_body
);
both!(
    i4056_a_ceg_keys_thumbprint_takes_the_subject_rule_sqlite,
    i4056_a_ceg_keys_thumbprint_takes_the_subject_rule_postgres,
    ceg_key_thumbprint_takes_the_subject_rule_body
);
both!(
    i4057_cose_key_without_kid_sqlite,
    i4057_cose_key_without_kid_postgres,
    cose_key_without_kid_body
);

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4045_peer_served_receipts_sqlite() {
    let (a, b) = (sqlite().await, sqlite().await);
    Box::pin(peer_served_receipts_body(&a, &b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4045_peer_served_receipts_postgres() {
    let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
        return;
    };
    Box::pin(peer_served_receipts_body(&a, &b)).await;
}

/// I4044 — receipts are outside the row id and the statement id.
#[test]
fn i4044_receipts_are_outside_the_ids() {
    let st = unit_statement(0x46);
    let with = attach(&st, &[receipt(TS1, &st), receipt(TS2, &st)]);
    assert_ne!(with, st, "I4044 the bytes differ");
    assert_eq!(
        RowId::of_statement(&with),
        RowId::of_statement(&st),
        "I4044 row id"
    );
    assert_eq!(
        receipts::statement_id_of(&with),
        receipts::statement_id_of(&st),
        "I4044 statement id"
    );
    assert_eq!(
        receipts::leaf_of(&with),
        receipts::leaf_of(&st),
        "I4044 the leaf"
    );
    let (plain, carried) = (e2::admit(&st), e2::admit(&with));
    assert_eq!(plain.row_id, carried.row_id, "I4044 the door's row id");
    assert_eq!(
        plain.statement_id, carried.statement_id,
        "I4044 the door's statement id"
    );
    // Removing the receipts gives the statement back.
    assert_eq!(
        attach(&with, &[]),
        st,
        "I4044 with_receipts(.., []) strips them"
    );
}

fn gate(bytes: &[u8]) -> bool {
    super::door::pure_statement_gates(bytes, &HeldKeys::new()).is_ok()
}

/// I4046 — header 394 never faults at the door; only receipts are held.
#[test]
fn i4046_header_394_never_faults_and_holds_only_receipts() {
    let st = unit_statement(0x47);
    let good = receipt(TS1, &st);
    let many: Vec<Value> = (0..=receipts::MAX_RECEIPTS)
        .map(|i| {
            Value::Bytes(receipt(
                if i % 2 == 0 { TS1 } else { TS2 },
                &unit_statement(u8::try_from(i).unwrap()),
            ))
        })
        .collect();
    let cases: Vec<(&str, Value, usize)> = vec![
        ("an empty array", Value::Array(vec![]), 0),
        (
            "CC's untagged sample",
            Value::Array(vec![Value::Bytes(not_sign1())]),
            0,
        ),
        (
            "a member that is no byte string",
            Value::Array(vec![t("r")]),
            0,
        ),
        ("not an array", Value::Bytes(good.clone()), 0),
        (
            "a non-CDE item",
            Value::Array(vec![Value::Bytes(not_cde())]),
            0,
        ),
        (
            "garbage beside a receipt",
            {
                let mut g = garbage();
                if let Value::Array(a) = &mut g {
                    a.push(Value::Bytes(good.clone()));
                }
                g
            },
            1,
        ),
        (
            "more than MAX_RECEIPTS",
            Value::Array(many),
            receipts::MAX_RECEIPTS,
        ),
    ];
    assert!(gate(&st), "I4046 no parameter passes");
    for (what, v, held_n) in cases {
        let bytes = with_raw_receipts(&st, v);
        assert!(gate(&bytes), "I4046 {what}: the door's pure gates pass it");
        let held = receipts::held_bytes(&bytes);
        assert_eq!(
            receipts_of(&held).len(),
            held_n,
            "I4046 {what}: what is held"
        );
        assert_eq!(
            RowId::of_statement(&held),
            RowId::of_statement(&st),
            "I4046 {what}: the row id stands"
        );
        if held_n == 0 {
            assert_eq!(held, st, "I4046 {what}: nothing held, no parameter");
        }
    }
}

/// RFC 9162 MTH over leaf hashes (n >= 1).
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    use ciris_verify_core::transparency::hash_node;
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut k = 1;
    while k << 1 < leaves.len() {
        k <<= 1;
    }
    hash_node(&mth(&leaves[..k]), &mth(&leaves[k..]))
}

/// RFC 9162 PATH(m, D[n]), leaf to root.
fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let mut k = 1;
    while k << 1 < leaves.len() {
        k <<= 1;
    }
    let (mut p, sibling) = if m < k {
        (path(m, &leaves[..k]), mth(&leaves[k..]))
    } else {
        (path(m - k, &leaves[k..]), mth(&leaves[..k]))
    };
    p.push(sibling);
    p
}

/// I4047 — RFC 9162 section 2.1.3.2 over every leaf of small trees.
#[test]
fn i4047_rfc9162_inclusion() {
    use ciris_verify_core::transparency::hash_leaf;
    for n in 1usize..=9 {
        let leaves: Vec<[u8; 32]> = (0..n)
            .map(|i| hash_leaf(&[u8::try_from(i).unwrap()]))
            .collect();
        let root = mth(&leaves);
        let size = u64::try_from(n).unwrap();
        for (m, leaf) in leaves.iter().enumerate() {
            let p = path(m, &leaves);
            let index = u64::try_from(m).unwrap();
            assert_eq!(
                receipts::inclusion_root(leaf, index, size, &p),
                Some(root),
                "I4047 leaf {m} of {n}"
            );
            assert_eq!(
                receipts::inclusion_root(leaf, size, size, &p),
                None,
                "I4047 an index at the size fails"
            );
            if n > 1 {
                let wrong = (m + 1) % n;
                assert_ne!(
                    receipts::inclusion_root(leaf, u64::try_from(wrong).unwrap(), size, &p),
                    Some(root),
                    "I4047 leaf {m} of {n} at index {wrong}"
                );
                assert_ne!(
                    receipts::inclusion_root(leaf, index, size, &p[..p.len() - 1]),
                    Some(root),
                    "I4047 a truncated path"
                );
            }
        }
    }
}

/// I4048 — CC's receipt rule (the generator's five samples and its planted
/// break), with the services as identity-refs.
#[test]
fn i4048_cc_receipt_rule_samples() {
    let (ts1, ts9) = (e2::kid(TS1), e2::kid(TS2));
    let trusted: std::collections::BTreeSet<String> = [ts1.clone()].into_iter().collect();
    let r = |s: &str, v: bool| {
        (
            [0u8; 32],
            ReceiptReading {
                service: Some(s.to_owned()),
                verifies: v,
            },
        )
    };
    type Case<'a> = (
        &'a str,
        Vec<([u8; 32], ReceiptReading)>,
        Option<ReceiptMissing>,
    );
    let cases: Vec<Case<'_>> = vec![
        ("trusted", vec![r(&ts1, true)], None),
        ("two, one trusted", vec![r(&ts9, true), r(&ts1, true)], None),
        ("none", vec![], Some(ReceiptMissing::None)),
        (
            "trusted, not verifying",
            vec![r(&ts1, false)],
            Some(ReceiptMissing::Unverifiable),
        ),
        (
            "untrusted",
            vec![r(&ts9, true)],
            Some(ReceiptMissing::UntrustedService),
        ),
    ];
    for (what, readings, want) in &cases {
        let got = receipts::receipt_rule(readings, &trusted);
        match want {
            None => assert!(got.is_runnable(), "I4048 {what}: {got:?}"),
            Some(m) => assert_eq!(got, AdmissionReceipt::Waiting(*m), "I4048 {what}"),
        }
    }
    // The planted break: a rule admitting any receipt passes no sample set.
    let planted = |rs: &[([u8; 32], ReceiptReading)]| !rs.is_empty();
    assert!(
        !cases
            .iter()
            .all(|(_, rs, want)| planted(rs) == want.is_none()),
        "I4048 a rule admitting any receipt must fail a sample"
    );
}
