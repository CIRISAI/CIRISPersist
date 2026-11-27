//! v62.0.0 (AU-fix1; CC rc21 2.7.11, CC 2.6.1.9) — witnesses of **the
//! `admission:unit` count and the host's answer**. Every store-facing body
//! runs on sqlite and postgres. The host is `NODE`, owned by `OWNER` (an
//! owner binding, the node's voice cosigning); the Transparency Service `TS`
//! is trusted by `OWNER`'s `self` edge. Fixture instants sit inside the
//! keys' windows (a minute before now; leases of an hour). Every group is
//! KEYLESS: no key record is registered for its id, and the owner's
//! `admission` edge names the held group record.
//!
//! - **I2150** — one person's voice on a COUNTED row naming an effect is
//!   HELD (`count_short`), never a typed row, and is not runnable
//!   (`admission_count_unmet`); before AU-fix1 it landed concluded.
//! - **I2151** — a second member's voice concludes it (2 of 3, `majority`),
//!   in either arrival order; with the owner's `admission` edge to the group
//!   and a trusted receipt it is runnable, with the row's capabilities.
//! - **I2152** — a node key's and an agent key's voice are refused
//!   `admission_issuer_not_person` and never count: the row stays held.
//! - **I2153** — a group of ONE person whose protocol one voice meets is
//!   still held: never counted on fewer than two persons.
//! - **I2154** — one person's `self`-scope row naming no effect concludes
//!   alone; it runs when the person is the owner, or the owner's
//!   `admission` edge reaches them; a stranger the walk does not reach is
//!   `admission_issuer_not_reached` (`not_reached`).
//! - **I2155** — one person's effect row at `self` runs only on that
//!   person's own host: the owner's runs; another person's is
//!   `not_owner_host` even when the walk reaches them.
//! - **I2156** — the lease is read at the instant asked: before
//!   `asserted_at` `lease_not_open`, at or after `valid_until` `lease_ended`
//!   (both `admission_none`); inside it, runnable.
//! - **I2157** — the end: the author's own `withdraws` ends an authored row
//!   (`withdrawn`); a stranger's is never admitted. A counted row's group
//!   withdrawal with one voice is held and the unit still runs; with the
//!   count met it is `withdrawn`.
//! - **I2158** — a held counted row is listed for an eligible member by
//!   `held_rows_for` (role `member`), not for a non-member and not for the
//!   member who voiced it; the member's `voice_draft`, signed and
//!   submitted, seats it.
//! - **I2159** — a FAMILY's roster head counts as a community's does.
//! - **I2160** — no receipt: concluded and standing, the unit waits
//!   `admission_receipt_missing` (`none`); no row is `admission_none`
//!   (`no_row`).
//! - **I2164** — the model's order (`formal/admission/admission.py`
//!   `one()`): a counted row whose head is not held waits on the head
//!   (`admission_unit_held`, `head_unheld`); a group the owner does not reach
//!   is `admission_issuer_not_reached` before its count is read (one voice,
//!   no edge); the owner's edge to a group not held is held `link_unheld`,
//!   and admitted once the group is held (keyless).
//! - **I2165** — the host owner as a parameter (Server's `owner_key_id`):
//!   one person's effect row at `self` admits on that person's own host and
//!   is `not_owner_host` on another's.
//! - **I2166** — the lease from first held: a row held now whose signed lease
//!   runs past 24 hours from now ends 24 hours after this node first held it
//!   (`lease_ended`), inside its signed window; AU-fix3: re-offering the
//!   statement (a receipt merge, a plain re-put) never moves
//!   `ceg_statements.first_held_us`.
//! - **I2161** (AU-fix2) — the LIVE read `admission_unit_rows(sub, at)`:
//!   a concluded authored row is listed, a held counted row on the same unit
//!   never is; at the lease's end nothing is; after the author's withdrawal
//!   nothing is.
//! - **I2162** (AU-fix2) — the capsule: the `AdmissionUnitRows` op answers
//!   the direct read, the `AdmissionUnitRunnable` op the direct answer, and
//!   an instant out of range is an error, never an empty answer.
//! - **I2163** (AU-fix2) — the host-side draft: `draft_from_envelope` over
//!   JSON members resolves the family `admission:unit` from the `dimension`;
//!   a row naming `head` is counted (no `author`, `refs.head`), its
//!   capabilities a sorted set; signed elsewhere and assembled, it is held
//!   until a second member's voice; one naming no `head` is authored and
//!   concludes alone.
//! - **I2437** (PIN-fix9a; the Constitution's ruling of 2026-11-21, CC
//!   2.4.1) — a `supersedes` of a unit is a REPLACEMENT UNIT, judged by the
//!   verifier's pure rules as the unit is: one with no `capabilities` is
//!   refused `admission_capability_unknown`, as the same unit stated as an
//!   ordinary row is. PIN-fix9a.rev2: a CONFORMING one is refused
//!   `supersedes_unsupported` (the unit readers do not honour a replacement
//!   yet), never landed inert; the unit it names still runs. (A `withdraws`
//!   keeps its exemption: I2157.)

use ciris_verify_core::cde::{self, Value};

use super::admission_unit::{self as au, AdmissionAnswer};
use super::fixture_switch as e2;
use super::ingest::StatementOutcome;
use super::names::RowId;
use super::receipts;
use crate::federation::types::identity_type;
use crate::federation::FederationDirectory;

/// The host.
const NODE: &str = "au-node";
/// The host's owner.
const OWNER: &str = "au-owner";
/// The trusted Transparency Service.
const TS: &str = "au-ts";

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

fn text_set(xs: &[&str]) -> Value {
    let mut e: Vec<Value> = xs.iter().map(|x| t(x)).collect();
    e.sort_by_key(cde::encode);
    Value::Array(e)
}

fn sub_of(unit: u8) -> String {
    format!(
        "{}{}",
        super::payloads::ADMISSION_UNIT_SUB_PREFIX,
        hex::encode([unit; 32])
    )
}

fn family_id() -> String {
    ciris_verify_core::namespace_match::family_id(super::payloads::ADMISSION_UNIT_FAMILY)
}

/// The payload of an `admission:unit` row for `[unit; 32]`, its lease
/// `[at, at + 1h)`: authored by `author` at `scope`, or counted over `head`.
fn unit_payload(
    unit: u8,
    caps: &[&str],
    at: u64,
    author: Option<&str>,
    head: Option<&RowId>,
    scope: &str,
) -> Value {
    let mut m = vec![
        ("asserted_at", Value::Uint(at)),
        ("capabilities", text_set(caps)),
        ("cohort_scope", t(scope)),
        ("dimension", t("admission:unit:v1")),
        (
            "unit",
            Value::Array(vec![Value::Nint(15), Value::Bytes(vec![unit; 32])]),
        ),
        ("valid_until", Value::Uint(at + 3_600_000)),
    ];
    if let Some(a) = author {
        m.push(("author", t(&e2::kid(a))));
    }
    if let Some(h) = head {
        m.push((
            "refs",
            det_map(vec![("head", ciris_verify_core::edition2::row_ref(&h.0))]),
        ));
    }
    det_map(m)
}

/// `seed`'s statement of `payload` (row type `row_type`) about `[unit; 32]`.
fn sign(seed: &str, unit: u8, row_type: &str, payload: &Value) -> Vec<u8> {
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &e2::kid(seed),
        &sub_of(unit),
        row_type,
        &family_id(),
        payload,
        vec![],
    )
    .expect("AU: sign an admission:unit statement")
}

/// One person's row at `scope`.
fn authored(seed: &str, unit: u8, caps: &[&str], scope: &str, at: u64) -> Vec<u8> {
    sign(
        seed,
        unit,
        "scores",
        &unit_payload(unit, caps, at, Some(seed), None, scope),
    )
}

/// A counted row over `head`, first voiced by `seed`.
fn counted(seed: &str, unit: u8, caps: &[&str], head: &RowId, at: u64) -> Vec<u8> {
    sign(
        seed,
        unit,
        "scores",
        &unit_payload(unit, caps, at, None, Some(head), "federation"),
    )
}

fn id_of(st: &[u8]) -> RowId {
    RowId::of_statement(st).expect("AU: a row statement")
}

async fn put(d: &dyn FederationDirectory, st: &[u8]) -> StatementOutcome {
    e2::put_statement(d, st)
        .await
        .unwrap_or_else(|e| panic!("AU: the statement is kept: {e:?}"))
}

fn pending(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Pending { .. })
}

fn landed(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Row { .. })
}

/// The host: keys, `OWNER`'s owner binding of `NODE` and the node's own
/// self-occurrence (as `receipts_invariants::setup`), and `OWNER`'s trust in
/// `TS` (a `self`-scope `transparency` edge).
async fn setup(d: &dyn FederationDirectory, people: &[&str]) {
    for k in [OWNER, TS].iter().chain(people.iter()) {
        e2::put_key(d, k, &[identity_type::USER]).await;
    }
    e2::put_key(d, NODE, &[identity_type::NODE]).await;
    let bound_at = chrono::Utc::now() - chrono::Duration::minutes(1);
    for v in crate::federation::key_grant_invariants::two_node::owner_binding_voices(
        OWNER, NODE, bound_at,
    ) {
        put(d, &v).await;
    }
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
        Ok(StatementOutcome::Row { .. }) => {}
        other => panic!("AU: the node's own self-occurrence: {other:?}"),
    }
    assert_eq!(
        crate::federation::admission::owner_of_unmarked(d, &e2::kid(NODE))
            .await
            .expect("AU: the owner relation reads"),
        Some(e2::kid(OWNER)),
        "AU setup: OWNER is the host owner"
    );
    edge(d, OWNER, &e2::kid(TS), "transparency").await;
}

/// `granter`'s `self`-scope `trust:accepts` edge naming `subject`, listing
/// `class`.
async fn edge(d: &dyn FederationDirectory, granter: &str, subject: &str, class: &str) {
    let p = super::typed::trust_accepts_payload(
        &e2::kid(granter),
        &[crate::federation::trust_root::INFRA_SERVE_SCOPE],
        &[class.to_owned()],
        None,
        "self",
        now_ms() - 1_000,
    );
    let p = names_held_head(d, subject, p).await;
    let st = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(granter),
        &e2::kid(granter),
        subject,
        "delegates_to",
        &ciris_verify_core::namespace_match::family_id(super::typed::TRUST_PREFIX),
        &p,
        vec![],
    )
    .expect("AU: sign a trust:accepts edge");
    put(d, &st).await;
}

/// v62.0.0 (AU-fix4; CC 3.2 T4a, as `typed_fixtures::trust_accepts_edge`,
/// T2-fix6) — an acceptance edge to a community this node holds names the
/// lineage head it attaches on (`attached_head_digest`, the held head's row
/// hash as bytes); without it a new labelled edge is `TrustRootHeadUnnamed`.
/// An edge to a key (no held community) is `p` unchanged.
async fn names_held_head(d: &dyn FederationDirectory, subject: &str, p: Value) -> Value {
    let Some(c) = d
        .lookup_community(subject)
        .await
        .expect("AU: read the root the edge names")
    else {
        return p;
    };
    let Value::Map(mut m) = p else {
        unreachable!("trust_accepts_payload is a map")
    };
    m.push((
        Value::Text(crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST.to_owned()),
        Value::Bytes(
            hex::decode(&c.persist_row_hash).expect("AU: the held head's row hash is hex"),
        ),
    ));
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

/// `voice` again, carrying `TS`'s receipt over it (merged into the held
/// statement, `receipts_invariants` I4043).
async fn receipt_on(d: &dyn FederationDirectory, voice: &[u8]) {
    let r = receipts::mint_receipt(
        &e2::signing_key(TS),
        Some(&e2::kid(TS)),
        voice,
        &[b"leaf-a".to_vec(), b"leaf-b".to_vec()],
        1,
    );
    let with = receipts::with_receipts(voice, &[r]).expect("AU: a COSE_Sign1");
    let _ = e2::put_statement(d, &with).await;
}

async fn answer(d: &dyn FederationDirectory, st: &[u8]) -> AdmissionAnswer {
    answer_at(d, st, crate::host::clock::now()).await
}

async fn answer_at(
    d: &dyn FederationDirectory,
    st: &[u8],
    at: chrono::DateTime<chrono::Utc>,
) -> AdmissionAnswer {
    au::admission_unit_runnable(d, &id_of(st), at, None)
        .await
        .expect("AU: the answer reads")
}

fn says(a: &AdmissionAnswer, token: &str, detail: Option<&str>) -> bool {
    a.token() == Some(token) && detail.is_none_or(|w| a.detail().is_some_and(|d| d.contains(w)))
}

/// A community of `members` under `protocol`, and its held roster head.
async fn group(
    d: &dyn FederationDirectory,
    seed: &str,
    members: &[&str],
    protocol: &str,
) -> (String, RowId) {
    // KEYLESS: no key record is registered for the group id; the owner's
    // `admission` edge naming it is admitted on the held group record.
    let c = super::voices_invariants::found_community(d, seed, members, protocol, None).await;
    let (head, _) = super::group_fixtures::held_head(d, &c.community_key_id)
        .await
        .expect("AU: the group's roster head is held");
    (c.community_key_id, head)
}

/// I2150 + I2151 + I2152: the count, in both arrival orders.
pub(crate) async fn counted_row_body(d: &dyn FederationDirectory) {
    let (m1, m2, m3, x) = ("au-c-m1", "au-c-m2", "au-c-m3", "au-c-x");
    setup(d, &[m1, m2, m3, x]).await;
    let (machine, agent) = ("au-c-node2", "au-c-agent");
    e2::put_key(d, machine, &[identity_type::NODE]).await;
    e2::put_key(d, agent, &[identity_type::AGENT]).await;
    let (gid, head) = group(d, "au-c-g", &[m1, m2, m3], "majority").await;
    edge(d, OWNER, &gid, au::ADMISSION_CLASS).await;
    let at = now_ms() - 60_000;
    let caps = ["compute", "net_send", "sign"];

    for (unit, first, second) in [(0x50, m1, m2), (0x51, m2, m1)] {
        let st = counted(first, unit, &caps, &head, at);
        let id = id_of(&st);
        // I2150 — one person's voice: held, no typed row, not runnable.
        let o = put(d, &st).await;
        assert!(pending(&o), "I2150 one of three waits: {o:?}");
        assert!(
            d.get_attestation(&id.hex()).await.unwrap().is_none(),
            "I2150 no typed row on one voice"
        );
        assert_eq!(
            super::fold::why_held(d, &id)
                .await
                .unwrap()
                .map(|h| h.reason)
                .as_deref(),
            Some(super::fold::reason::COUNT_SHORT),
            "I2150 held count_short"
        );
        receipt_on(d, &st).await;
        let a = answer(d, &st).await;
        assert!(
            says(&a, au::ADMISSION_COUNT_UNMET, None) && !a.is_runnable(),
            "I2150 a held row is never runnable: {a:?}"
        );
        // I2152 — a program's key never voices it.
        for prog in [machine, agent] {
            let e = e2::put_statement(d, &e2::voice_of(&st, prog))
                .await
                .expect_err("I2152 a program key's voice is refused");
            assert!(
                matches!(
                    &e,
                    crate::federation::Error::MalformedRow { reason, .. }
                        if *reason == crate::federation::malformed_row::ADMISSION_ISSUER_NOT_PERSON
                ),
                "I2152 {prog}: {e:?}"
            );
        }
        // A non-member person's voice is kept and never counts.
        let _ = e2::put_statement(d, &e2::voice_of(&st, x)).await;
        assert!(
            d.get_attestation(&id.hex()).await.unwrap().is_none(),
            "I2152 a non-member's voice does not complete it"
        );
        // I2151 — the second member concludes it.
        let o = put(d, &e2::voice_of(&st, second)).await;
        assert!(
            landed(&o),
            "I2151 two of three land it ({first} first): {o:?}"
        );
        let a = answer(d, &st).await;
        let AdmissionAnswer::Runnable { row, .. } = &a else {
            panic!("I2151 concluded, standing and receipted runs: {a:?}");
        };
        assert!(!row.authored && row.group.as_deref() == Some(gid.as_str()));
        assert_eq!(row.capabilities.len(), 3, "I2151 the row's capabilities");
    }
}

/// I2153: never on fewer than two persons, whatever the protocol.
pub(crate) async fn two_person_floor_body(d: &dyn FederationDirectory) {
    let solo = "au-f-solo";
    setup(d, &[solo]).await;
    let (gid, head) = group(d, "au-f-g", &[solo], "majority").await;
    // AU-fix4 — the owner reaches the group, so the count is the leg that
    // answers (the model's order puts reach before the count, I2164).
    edge(d, OWNER, &gid, au::ADMISSION_CLASS).await;
    let st = counted(
        solo,
        0x52,
        &["compute", "actuate"],
        &head,
        now_ms() - 60_000,
    );
    let o = put(d, &st).await;
    assert!(
        pending(&o),
        "I2153 a one-person group's voice is short of two persons: {o:?}"
    );
    // AU-fix4 — the count's own words name the floor (`admission.rs`,
    // `admission_unit_count_at_head`); "two" was never in them.
    let floor = format!(
        "fewer than {} persons",
        crate::federation::admission::ADMISSION_UNIT_MIN_PERSONS
    );
    let a = answer(d, &st).await;
    assert!(
        says(&a, au::ADMISSION_COUNT_UNMET, Some(floor.as_str())),
        "I2153 a one-person group is short of the two-person floor: {:?} {:?}",
        a.token(),
        a.detail()
    );
}

/// I2154 + I2155: one person's row, and the host's standing.
pub(crate) async fn authored_standing_body(d: &dyn FederationDirectory) {
    let (p, s) = ("au-a-p", "au-a-stranger");
    setup(d, &[p, s]).await;
    let at = now_ms() - 60_000;
    // I2154 — the owner's compute row concludes alone and runs.
    let own = authored(OWNER, 0x53, &["compute", "read"], "federation", at);
    assert!(landed(&put(d, &own).await), "I2154 concludes alone");
    receipt_on(d, &own).await;
    assert!(answer(d, &own).await.is_runnable(), "I2154 the owner's own");
    // A stranger's compute row: concluded, not reached.
    let st = authored(s, 0x54, &["compute"], "self", at);
    assert!(landed(&put(d, &st).await), "I2154 concludes alone");
    receipt_on(d, &st).await;
    assert!(says(
        &answer(d, &st).await,
        au::ADMISSION_ISSUER_NOT_REACHED,
        Some(au::NOT_REACHED)
    ));
    // The owner's `admission` edge reaches p: p's compute row runs.
    edge(d, OWNER, &e2::kid(p), au::ADMISSION_CLASS).await;
    let pr = authored(p, 0x55, &["read"], "self", at);
    assert!(landed(&put(d, &pr).await));
    receipt_on(d, &pr).await;
    assert!(
        answer(d, &pr).await.is_runnable(),
        "I2154 reached by the walk"
    );
    // An edge listing another class reaches nothing.
    edge(d, OWNER, &e2::kid(s), "transparency").await;
    assert!(says(
        &answer(d, &st).await,
        au::ADMISSION_ISSUER_NOT_REACHED,
        Some(au::NOT_REACHED)
    ));
    // I2155 — one person's effect row at `self`: the owner's runs; p's,
    // reached by the walk, is not on p's own host.
    let oe = authored(OWNER, 0x56, &["compute", "net_send"], "self", at);
    assert!(landed(&put(d, &oe).await));
    receipt_on(d, &oe).await;
    assert!(
        answer(d, &oe).await.is_runnable(),
        "I2155 on the owner's host"
    );
    let pe = authored(p, 0x57, &["submit"], "self", at);
    assert!(landed(&put(d, &pe).await));
    receipt_on(d, &pe).await;
    assert!(says(
        &answer(d, &pe).await,
        au::ADMISSION_ISSUER_NOT_REACHED,
        Some(au::NOT_OWNER_HOST)
    ));
}

/// I2156: the lease at the instant asked.
pub(crate) async fn lease_body(d: &dyn FederationDirectory) {
    setup(d, &[]).await;
    let at = now_ms() - 60_000;
    let st = authored(OWNER, 0x58, &["compute"], "self", at);
    assert!(landed(&put(d, &st).await));
    receipt_on(d, &st).await;
    let instant = |ms: u64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(ms).unwrap()).unwrap()
    };
    assert!(
        answer_at(d, &st, instant(at)).await.is_runnable(),
        "I2156 opens"
    );
    assert!(says(
        &answer_at(d, &st, instant(at - 1)).await,
        au::ADMISSION_NONE,
        Some(au::LEASE_NOT_OPEN)
    ));
    for ms in [at + 3_600_000, at + 3_600_001] {
        assert!(
            says(
                &answer_at(d, &st, instant(ms)).await,
                au::ADMISSION_NONE,
                Some(au::LEASE_ENDED)
            ),
            "I2156 closed at {ms}"
        );
    }
}

/// I2157: the end.
pub(crate) async fn withdrawal_body(d: &dyn FederationDirectory) {
    let (m1, m2, m3, s) = ("au-w-m1", "au-w-m2", "au-w-m3", "au-w-s");
    setup(d, &[m1, m2, m3, s]).await;
    let at = now_ms() - 60_000;
    // An authored row: a stranger's withdraws is never admitted; the author's ends it.
    let st = authored(OWNER, 0x59, &["compute"], "self", at);
    assert!(landed(&put(d, &st).await));
    receipt_on(d, &st).await;
    let target = id_of(&st);
    let stranger = sign(
        s,
        0x59,
        "withdraws",
        &super::typed::withdraws_payload(&e2::kid(s), &target, at + 1_000),
    );
    let _ = e2::put_statement(d, &stranger).await;
    assert!(
        d.get_attestation(&id_of(&stranger).hex())
            .await
            .unwrap()
            .is_none(),
        "I2157 a stranger's withdraws is not admitted"
    );
    assert!(answer(d, &st).await.is_runnable(), "I2157 still runs");
    let own = sign(
        OWNER,
        0x59,
        "withdraws",
        &super::typed::withdraws_payload(&e2::kid(OWNER), &target, at + 1_000),
    );
    assert!(landed(&put(d, &own).await), "I2157 the author's withdraws");
    assert!(says(
        &answer(d, &st).await,
        au::ADMISSION_NONE,
        Some(au::WITHDRAWN)
    ));

    // A counted row: the group's counted withdrawal.
    let (gid, head) = group(d, "au-w-g", &[m1, m2, m3], "majority").await;
    edge(d, OWNER, &gid, au::ADMISSION_CLASS).await;
    let c = counted(m1, 0x5a, &["store_write"], &head, at);
    put(d, &c).await;
    assert!(landed(&put(d, &e2::voice_of(&c, m2)).await));
    receipt_on(d, &c).await;
    assert!(
        answer(d, &c).await.is_runnable(),
        "I2157 the counted row runs"
    );
    let w = sign(
        m1,
        0x5a,
        "withdraws",
        &det_map(vec![
            ("asserted_at", Value::Uint(at + 1_000)),
            (
                "refs",
                det_map(vec![
                    ("head", ciris_verify_core::edition2::row_ref(&head.0)),
                    ("target", ciris_verify_core::edition2::row_ref(&id_of(&c).0)),
                ]),
            ),
        ]),
    );
    assert!(
        pending(&put(d, &w).await),
        "I2157 one voice of the withdrawal waits"
    );
    assert!(
        answer(d, &c).await.is_runnable(),
        "I2157 a held withdrawal ends nothing"
    );
    assert!(
        landed(&put(d, &e2::voice_of(&w, m3)).await),
        "I2157 the count withdraws"
    );
    assert!(says(
        &answer(d, &c).await,
        au::ADMISSION_NONE,
        Some(au::WITHDRAWN)
    ));
}

/// I2158: the second person finds and voices it.
pub(crate) async fn voice_listing_body(d: &dyn FederationDirectory) {
    let (m1, m2, m3, x) = ("au-v-m1", "au-v-m2", "au-v-m3", "au-v-x");
    setup(d, &[m1, m2, m3, x]).await;
    let (_, head) = group(d, "au-v-g", &[m1, m2, m3], "majority").await;
    let st = counted(m1, 0x5b, &["actuate"], &head, now_ms() - 60_000);
    assert!(pending(&put(d, &st).await));
    let id = id_of(&st);
    let listed = |rows: Vec<super::second_signer_voice::HeldRow>| {
        rows.into_iter().any(|r| {
            r.row_id == id.hex()
                && r.role == crate::federation::admission::ADMISSION_UNIT_MEMBER_ROLE
        })
    };
    assert!(
        listed(
            d.held_rows_for(&e2::kid(m2), None, None, 100)
                .await
                .unwrap()
        ),
        "I2158 listed for an eligible member"
    );
    assert!(
        listed(
            d.held_rows_for(
                &e2::kid(m3),
                Some(crate::federation::admission::ADMISSION_UNIT_MEMBER_ROLE),
                None,
                100
            )
            .await
            .unwrap()
        ),
        "I2158 listed in the role `member`"
    );
    assert!(
        !listed(d.held_rows_for(&e2::kid(x), None, None, 100).await.unwrap()),
        "I2158 not for a non-member"
    );
    assert!(
        !listed(
            d.held_rows_for(&e2::kid(m1), None, None, 100)
                .await
                .unwrap()
        ),
        "I2158 not for the member who voiced it"
    );
    let draft =
        super::second_signer_voice::voice_draft(&st, &e2::kid(m2), None).expect("I2158 a draft");
    let sig = e2::signing_key(m2)
        .sign(&draft.sig_structure)
        .expect("I2158 sign the draft");
    let voice = draft.assemble(sig);
    let o = d.submit_voice(&voice).await.expect("I2158 submit");
    assert!(
        o.is_seated(),
        "I2158 the second person's voice seats it: {o:?}"
    );
}

/// I2159: a family's roster head.
pub(crate) async fn family_head_body(d: &dyn FederationDirectory) {
    let (a, b, c) = ("au-fa-a", "au-fa-b", "au-fa-c");
    setup(d, &[a, b, c]).await;
    let f = super::voices_invariants::found_family(d, "au-fa-g", &[a, b, c], "majority").await;
    let (head, _) = super::group_fixtures::held_head(d, &f.family_key_id)
        .await
        .expect("I2159 the family's head");
    let st = counted(a, 0x5c, &["sign"], &head, now_ms() - 60_000);
    assert!(pending(&put(d, &st).await), "I2159 one of three waits");
    assert!(
        landed(&put(d, &e2::voice_of(&st, b)).await),
        "I2159 two of three land it"
    );
}

/// I2160: the receipt leg stays; no row is no_row.
pub(crate) async fn receipt_and_no_row_body(d: &dyn FederationDirectory) {
    setup(d, &[]).await;
    let st = authored(OWNER, 0x5d, &["compute"], "self", now_ms() - 60_000);
    assert!(landed(&put(d, &st).await));
    assert!(says(
        &answer(d, &st).await,
        au::ADMISSION_RECEIPT_MISSING,
        Some("none")
    ));
    let none = au::admission_unit_runnable(d, &RowId([0x5e; 32]), crate::host::clock::now(), None)
        .await
        .unwrap();
    assert!(says(&none, au::ADMISSION_NONE, Some(au::NO_ROW)));
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
    i2150_i2151_i2152_the_count_sqlite,
    i2150_i2151_i2152_the_count_postgres,
    counted_row_body
);
both!(
    i2153_never_fewer_than_two_persons_sqlite,
    i2153_never_fewer_than_two_persons_postgres,
    two_person_floor_body
);
both!(
    i2154_i2155_one_person_and_standing_sqlite,
    i2154_i2155_one_person_and_standing_postgres,
    authored_standing_body
);
both!(
    i2156_the_lease_at_the_instant_sqlite,
    i2156_the_lease_at_the_instant_postgres,
    lease_body
);
both!(
    i2157_the_end_sqlite,
    i2157_the_end_postgres,
    withdrawal_body
);
both!(
    i2158_the_second_person_voices_sqlite,
    i2158_the_second_person_voices_postgres,
    voice_listing_body
);
both!(
    i2159_a_family_head_sqlite,
    i2159_a_family_head_postgres,
    family_head_body
);
both!(
    i2160_receipt_leg_and_no_row_sqlite,
    i2160_receipt_leg_and_no_row_postgres,
    receipt_and_no_row_body
);

/// I2164: the model's order.
pub(crate) async fn model_order_body(d: &dyn FederationDirectory) {
    let (m1, m2, m3) = ("au-o-m1", "au-o-m2", "au-o-m3");
    setup(d, &[m1, m2, m3]).await;
    let at = now_ms() - 60_000;
    // A head not held: waiting on the head.
    let unheld = counted(m1, 0x70, &["net_send"], &RowId([0x77; 32]), at);
    assert!(pending(&put(d, &unheld).await));
    receipt_on(d, &unheld).await;
    assert!(says(
        &answer(d, &unheld).await,
        au::ADMISSION_UNIT_HELD,
        Some(au::HEAD_UNHELD)
    ));
    // A group the owner does not reach: not reached, before the count.
    let (gid, head) = group(d, "au-o-g", &[m1, m2, m3], "majority").await;
    let st = counted(m1, 0x71, &["net_send"], &head, at);
    assert!(pending(&put(d, &st).await));
    receipt_on(d, &st).await;
    assert!(says(
        &answer(d, &st).await,
        au::ADMISSION_ISSUER_NOT_REACHED,
        Some(au::NOT_REACHED)
    ));
    // The owner's edge to the keyless group: admitted on the held record;
    // now the count is the answer.
    edge(d, OWNER, &gid, au::ADMISSION_CLASS).await;
    assert!(says(&answer(d, &st).await, au::ADMISSION_COUNT_UNMET, None));
    // An edge to a group NOT held is held link_unheld (no key record either).
    let ghost = e2::kid("au-o-ghost");
    let p = super::typed::trust_accepts_payload(
        &e2::kid(OWNER),
        &[crate::federation::trust_root::INFRA_SERVE_SCOPE],
        &[au::ADMISSION_CLASS.to_owned()],
        None,
        "self",
        now_ms() - 1_000,
    );
    let e = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(OWNER),
        &e2::kid(OWNER),
        &ghost,
        "delegates_to",
        &ciris_verify_core::namespace_match::family_id(super::typed::TRUST_PREFIX),
        &p,
        vec![],
    )
    .expect("I2164 an edge");
    let o = put(d, &e).await;
    assert!(
        pending(&o),
        "I2164 an edge to a group not held waits: {o:?}"
    );
    assert_eq!(
        super::fold::why_held(d, &id_of(&e))
            .await
            .unwrap()
            .map(|h| h.reason)
            .as_deref(),
        Some(super::fold::reason::LINK_UNHELD),
        "I2164 held link_unheld"
    );
}

/// I2165: the host owner as a parameter.
pub(crate) async fn owner_param_body(d: &dyn FederationDirectory) {
    let p = "au-op-p";
    setup(d, &[p]).await;
    let st = authored(p, 0x72, &["compute", "actuate"], "self", now_ms() - 60_000);
    assert!(landed(&put(d, &st).await));
    receipt_on(d, &st).await;
    let now = crate::host::clock::now();
    let own = au::admission_unit_runnable(d, &id_of(&st), now, Some(&e2::kid(p)))
        .await
        .unwrap();
    assert!(own.is_runnable(), "I2165 on the author's own host: {own:?}");
    let other = au::admission_unit_runnable(d, &id_of(&st), now, Some(&e2::kid(OWNER)))
        .await
        .unwrap();
    assert!(
        says(
            &other,
            au::ADMISSION_ISSUER_NOT_REACHED,
            Some(au::NOT_REACHED)
        ),
        "I2165 another owner reaches no stranger: {other:?}"
    );
    edge(d, OWNER, &e2::kid(p), au::ADMISSION_CLASS).await;
    let reached = au::admission_unit_runnable(d, &id_of(&st), now, Some(&e2::kid(OWNER)))
        .await
        .unwrap();
    assert!(
        says(
            &reached,
            au::ADMISSION_ISSUER_NOT_REACHED,
            Some(au::NOT_OWNER_HOST)
        ),
        "I2165 reached, but an effect needs ownership: {reached:?}"
    );
}

/// I2166: the lease from first held.
pub(crate) async fn first_held_lease_body(d: &dyn FederationDirectory) {
    setup(d, &[]).await;
    // Asserted a minute ahead (inside any skew allowance); its signed lease
    // runs to asserted_at + 24 h, past now + 24 h.
    let asserted = now_ms() + 60_000;
    let payload = {
        let mut m = vec![
            ("asserted_at", Value::Uint(asserted)),
            ("author", t(&e2::kid(OWNER))),
            ("capabilities", text_set(&["compute"])),
            ("cohort_scope", t("self")),
            ("dimension", t("admission:unit:v1")),
            (
                "unit",
                Value::Array(vec![Value::Nint(15), Value::Bytes(vec![0x73; 32])]),
            ),
        ];
        m.push((
            "valid_until",
            Value::Uint(asserted + super::payloads::UNIT_LEASE_MAX_MS),
        ));
        det_map(m)
    };
    let st = sign(OWNER, 0x73, "scores", &payload);
    assert!(landed(&put(d, &st).await));
    let first = d
        .edition2_first_held_us(&id_of(&st))
        .await
        .unwrap()
        .expect("I2166 first held");
    // AU-fix3 — a re-offer (with a receipt: the merge re-stamps the
    // statement's admission position) and a plain re-put never move it.
    receipt_on(d, &st).await;
    let _ = e2::put_statement(d, &st).await;
    assert_eq!(
        d.edition2_first_held_us(&id_of(&st)).await.unwrap(),
        Some(first),
        "I2166 re-offering the statement does not reset first_held_us"
    );
    let instant = |ms: u64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(ms).unwrap()).unwrap()
    };
    let inside = asserted + 1_000;
    assert!(
        answer_at(d, &st, instant(inside)).await.is_runnable(),
        "I2166 inside both bounds"
    );
    let past_first_held = now_ms() + super::payloads::UNIT_LEASE_MAX_MS + 30_000;
    assert!(past_first_held < asserted + super::payloads::UNIT_LEASE_MAX_MS);
    assert!(says(
        &answer_at(d, &st, instant(past_first_held)).await,
        au::ADMISSION_NONE,
        Some(au::LEASE_ENDED)
    ));
}

both!(
    i2164_the_models_order_sqlite,
    i2164_the_models_order_postgres,
    model_order_body
);
both!(
    i2165_the_host_owner_as_a_parameter_sqlite,
    i2165_the_host_owner_as_a_parameter_postgres,
    owner_param_body
);
both!(
    i2166_the_lease_from_first_held_sqlite,
    i2166_the_lease_from_first_held_postgres,
    first_held_lease_body
);

/// I2161: the live read.
pub(crate) async fn live_rows_body(d: &dyn FederationDirectory) {
    let (m1, m2) = ("au-l-m1", "au-l-m2");
    setup(d, &[m1, m2]).await;
    let (_, head) = group(d, "au-l-g", &[m1, m2, OWNER], "majority").await;
    let at = now_ms() - 60_000;
    let a = authored(OWNER, 0x60, &["compute"], "self", at);
    assert!(landed(&put(d, &a).await));
    let c = counted(m1, 0x60, &["sign"], &head, at);
    assert!(pending(&put(d, &c).await));
    let now = crate::host::clock::now();
    let rows = d
        .admission_unit_rows(&sub_of(0x60), now, None)
        .await
        .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.row_id.clone()).collect::<Vec<_>>(),
        vec![id_of(&a).hex()],
        "I2161 the concluded row only, never the held one"
    );
    assert!(rows[0].authored && rows[0].author.as_deref() == Some(e2::kid(OWNER).as_str()));
    assert_eq!(rows[0].unit, hex::encode([0x60u8; 32]));
    let after = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        i64::try_from(at + 3_600_000).unwrap(),
    )
    .unwrap();
    assert!(
        d.admission_unit_rows(&sub_of(0x60), after, None)
            .await
            .unwrap()
            .is_empty(),
        "I2161 nothing at the lease's end"
    );
    let w = sign(
        OWNER,
        0x60,
        "withdraws",
        &super::typed::withdraws_payload(&e2::kid(OWNER), &id_of(&a), at + 1_000),
    );
    assert!(landed(&put(d, &w).await));
    assert!(
        d.admission_unit_rows(&sub_of(0x60), now, None)
            .await
            .unwrap()
            .is_empty(),
        "I2161 nothing after the withdrawal"
    );
}

/// I2162: the capsule ops.
pub(crate) async fn capsule_body(d: &dyn FederationDirectory) {
    use crate::ffi::directory_capsule::{
        dispatch_directory_op, AdmissionUnitAnswerWire, DirectoryOp, DirectoryOpResult,
    };
    setup(d, &[]).await;
    let a = authored(OWNER, 0x61, &["compute"], "self", now_ms() - 60_000);
    assert!(landed(&put(d, &a).await));
    receipt_on(d, &a).await;
    let now = crate::host::clock::now();
    let at_ms = e2::ms(now);
    let direct = d
        .admission_unit_rows(&sub_of(0x61), now, None)
        .await
        .unwrap();
    match dispatch_directory_op(
        d,
        DirectoryOp::AdmissionUnitRows {
            sub: sub_of(0x61),
            at_ms,
            owner: None,
        },
    )
    .await
    {
        DirectoryOpResult::AdmissionUnitRows(v) => {
            assert_eq!(v, direct, "I2162 the op answers the direct read");
            assert_eq!(v.len(), 1, "I2162 the row");
        }
        other => panic!("I2162 AdmissionUnitRows: {other:?}"),
    }
    let answer = au::admission_unit_runnable(d, &id_of(&a), now, None)
        .await
        .unwrap();
    assert!(answer.is_runnable(), "I2162 runnable directly: {answer:?}");
    match dispatch_directory_op(
        d,
        DirectoryOp::AdmissionUnitRunnable {
            row_id: id_of(&a).0,
            at_ms,
            owner: None,
        },
    )
    .await
    {
        DirectoryOpResult::AdmissionUnitAnswer(w) => {
            assert_eq!(
                w,
                AdmissionUnitAnswerWire::of(&answer),
                "I2162 the same answer"
            )
        }
        other => panic!("I2162 AdmissionUnitRunnable: {other:?}"),
    }
    let out_of_range = dispatch_directory_op(
        d,
        DirectoryOp::AdmissionUnitRows {
            sub: sub_of(0x61),
            at_ms: u64::MAX,
            owner: None,
        },
    )
    .await;
    assert!(
        !matches!(out_of_range, DirectoryOpResult::AdmissionUnitRows(_)),
        "I2162 an instant out of range is an error, never an answer: {out_of_range:?}"
    );
}

/// I2163: the host-side draft, signed elsewhere.
pub(crate) async fn host_draft_body(d: &dyn FederationDirectory) {
    use super::emit::{draft_from_envelope, family_of_statement};
    let (m1, m2, m3) = ("au-d-m1", "au-d-m2", "au-d-m3");
    setup(d, &[m1, m2, m3]).await;
    let (_, head) = group(d, "au-d-g", &[m1, m2, m3], "majority").await;
    let at = now_ms() - 60_000;
    let until = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        i64::try_from(at + 3_600_000).unwrap(),
    )
    .unwrap()
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let envelope = |with_head: bool| {
        let mut e = serde_json::json!({
            "dimension": "admission:unit:v1",
            "unit": hex::encode([0x62u8; 32]),
            "capabilities": ["sign", "compute"],
            "valid_until": until,
            "cohort_scope": "self",
        });
        if with_head {
            e["head"] = serde_json::json!(head.hex());
            e["cohort_scope"] = serde_json::json!("federation");
        }
        e
    };
    let signed = |seed: &str, with_head: bool| {
        let kid = ciris_verify_core::edition2::thumbprint(e2::signing_key(seed).public_key());
        let draft = draft_from_envelope(
            &kid,
            &e2::kid(seed),
            &sub_of(0x62),
            "scores",
            &envelope(with_head),
            at,
            None,
        )
        .expect("I2163 a draft");
        let sig = e2::signing_key(seed)
            .sign(&draft.sig_structure)
            .expect("I2163 the pen signs");
        draft.assemble(sig)
    };
    let c = signed(m1, true);
    assert_eq!(
        family_of_statement(&c).map(|(f, _)| f).as_deref(),
        Some(super::payloads::ADMISSION_UNIT_FAMILY),
        "I2163 the family from the dimension"
    );
    let (_, payload) = super::liveness::statement_parts(&c).expect("I2163 a statement");
    assert!(
        payload.get_text("author").is_none(),
        "I2163 counted: no author"
    );
    assert_eq!(
        super::names::names_of(&payload)
            .ok()
            .and_then(|n| super::names::single(&n, "head")),
        Some(head),
        "I2163 refs.head"
    );
    assert_eq!(
        payload.get_text("capabilities"),
        Some(&text_set(&["compute", "sign"])),
        "I2163 a sorted set"
    );
    assert!(pending(&put(d, &c).await), "I2163 one voice waits");
    assert!(
        landed(&put(d, &e2::voice_of(&c, m2)).await),
        "I2163 the second member lands it"
    );
    let a = signed(OWNER, false);
    let (_, p) = super::liveness::statement_parts(&a).expect("I2163 a statement");
    assert_eq!(
        p.get_text("author").and_then(Value::as_text),
        Some(e2::kid(OWNER).as_str()),
        "I2163 authored: author = the signer"
    );
    assert!(
        landed(&put(d, &a).await),
        "I2163 one person's row concludes alone"
    );
}

both!(
    i2161_the_live_read_sqlite,
    i2161_the_live_read_postgres,
    live_rows_body
);
both!(
    i2162_the_capsule_ops_sqlite,
    i2162_the_capsule_ops_postgres,
    capsule_body
);
both!(
    i2163_the_host_side_draft_sqlite,
    i2163_the_host_side_draft_postgres,
    host_draft_body
);

/// `payload` naming `target` under `refs.target` (a `supersedes`'s payload).
fn naming_target(payload: &Value, target: &RowId) -> Value {
    let Value::Map(m) = payload else {
        panic!("AU: a payload is a map")
    };
    let mut m: Vec<(Value, Value)> = m.iter().filter(|(k, _)| k != &t("refs")).cloned().collect();
    m.push((
        t("refs"),
        det_map(vec![(
            "target",
            ciris_verify_core::edition2::row_ref(&target.0),
        )]),
    ));
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

fn refusal(e: &crate::federation::Error) -> &'static str {
    match e {
        crate::federation::Error::MalformedRow { reason, .. } => reason,
        other => other.kind(),
    }
}

/// I2437: a replacement unit meets the unit's rules.
pub(crate) async fn replacement_unit_body(d: &dyn FederationDirectory) {
    setup(d, &[]).await;
    let at = now_ms() - 60_000;
    let unit = 0x5c;
    let original = authored(OWNER, unit, &["read"], "self", at);
    assert!(landed(&put(d, &original).await), "I2437 the unit lands");
    let target = id_of(&original);
    // The same unit with no capabilities, as an ordinary row: refused.
    let empty = unit_payload(unit, &[], at + 1_000, Some(OWNER), None, "self");
    let plain = e2::put_statement(d, &sign(OWNER, unit, "scores", &empty))
        .await
        .expect_err("I2437 a unit with no capabilities is refused");
    assert_eq!(
        refusal(&plain),
        crate::federation::malformed_row::ADMISSION_CAPABILITY_UNKNOWN,
        "I2437 the ordinary row's refusal: {plain}"
    );
    // As a replacement of the held unit: the same refusal, nothing stored.
    let bad = sign(OWNER, unit, "supersedes", &naming_target(&empty, &target));
    let replacement = e2::put_statement(d, &bad)
        .await
        .expect_err("I2437 a replacement with no capabilities is refused");
    assert_eq!(
        refusal(&replacement),
        refusal(&plain),
        "I2437 the replacement's refusal is the unit's: {replacement}"
    );
    assert!(
        d.get_attestation(&id_of(&bad).hex())
            .await
            .unwrap()
            .is_none(),
        "I2437 the refused replacement is not stored"
    );
    // A conforming replacement is refused by name, never landed inert.
    let good = sign(
        OWNER,
        unit,
        "supersedes",
        &naming_target(
            &unit_payload(
                unit,
                &["compute", "read"],
                at + 1_000,
                Some(OWNER),
                None,
                "self",
            ),
            &target,
        ),
    );
    let e = e2::put_statement(d, &good)
        .await
        .expect_err("I2437 a conforming replacement unit is refused");
    assert_eq!(
        refusal(&e),
        crate::federation::malformed_row::SUPERSEDES_UNSUPPORTED,
        "I2437 refused as unsupported: {e}"
    );
    assert!(
        d.get_attestation(&id_of(&good).hex())
            .await
            .unwrap()
            .is_none(),
        "I2437 the refused replacement is not stored"
    );
    assert!(
        d.get_attestation(&target.hex()).await.unwrap().is_some(),
        "I2437 the unit it names is untouched"
    );
}

both!(
    i2437_a_replacement_unit_meets_the_units_rules_sqlite,
    i2437_a_replacement_unit_meets_the_units_rules_postgres,
    replacement_unit_body
);
