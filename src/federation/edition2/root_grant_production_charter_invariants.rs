//! v62.0.0 (KR-fix19) — **I4320: under the PRODUCTION charter a grant from
//! the root confers what the production doors check, end to end.**
//!
//! Every other root-grant witness uses the fixture bundle, whose charter
//! carries `infra:attest` and `infra:serve` only. The doors that gate a
//! worker's statements ask for `infra:detect`, `assure:age` (v62.0.0, D3; was
//! `infra:attest_assurance`),
//! `infra:record_hard_case` and `slash`, which that charter cannot confer,
//! so no witness put a real statement through a production door under a root
//! grant. This one does.
//!
//! The bundle is the fixture ceremony (same holders, seats, keys) with the
//! charter scope READ FROM THE BAKED GENESIS (`genesis::BAKED_BUNDLES`, the
//! bundle voice's `charter.scope`), not typed here
//! (`fixture_genesis::ceremony_v2_with_scope`). Two nodes A and B hold it and
//! accept its root; each is its own node identity. Two holders confer, by
//! counted grants over that bundle:
//!
//! - `infra:detect` and `assure:age` (D3) on a detector (an `agent`
//!   key; its OWNER accepts);
//! - `infra:serve` on a `node` worker (its OWNER accepts).
//!
//! Then, through the real statement door (`put_statement`):
//!
//! - the detector's `detection:{detector}` row (`infra:detect`) LANDS on A;
//! - its `age_assurance:provider:adult:v1` row (`assure:age`, which the
//!   baked charter carries beside `assure:capacity`)
//!   LANDS on A;
//! - the worker holds a delegation seat for peer rooting (`infra:serve`).
//!
//! The owner then withdraws both of the detector's acceptances (dated
//! `T0 + 2 s`). By the v62.0 interim rule (KR-fix19.doors: an act is judged
//! at its own `asserted_at`, inside W):
//!
//! - a detection dated AFTER the withdrawal is HELD, not landed, on A and B;
//! - node B, which receives the withdrawals FIRST and only then the two
//!   acts dated before them (late, inside W), ADMITS both, as A did: the two
//!   nodes agree whatever order the rows arrived in;
//! - the worker's seat, once its owner withdraws that acceptance, reads not
//!   rooted from the withdrawal's instant and rooted as of before it.
//!
//! "Delivered after W" cannot be driven through the door without moving the
//! node's clock; I4319 states it at the shared function.
//!
//! **I4326** (KR-fix25; CC 3.1.2.1) — a pipeline granted `infra:attest` by
//! the root and accepted by its owner has build-signing standing on the
//! delegation plane at its act's instant (`admission::pipeline_has_infra_attest_standing`,
//! which `namespace::is_trust_root` and `holdings_authority` read); its build
//! manifest lands; not before the acceptance, not for another capability,
//! not for an act after the acceptance's withdrawal.
//!
//! sqlite and postgres.
//!
//! - **I5711** (v62.0.0, FS-sig-b; CC 3.1.5.5, the rc22-pre3 family model's
//!   `evidence` signer cell, `seat_role(infra:attest)`) — on one node holding
//!   the fixture ceremony under the production charter scope (as I4320): an
//!   `evidence:*` row by the detector, conferred `infra:attest` by a counted
//!   grant its owner accepted (the parent covers the `evidence` family's
//!   scope, KR-fix25b), LANDS; the same row shape by a registered key with
//!   no conferral is HELD `reserved_prefix_emitter_mismatch`, no typed row.

use chrono::{DateTime, Duration, Utc};
use ciris_verify_core::cde::Value;

use super::fixture_genesis::{
    bundle_v2, ceremony_v2_with_scope, install_ceremony_v2, TestCeremonyV2,
};
use super::fixture_switch as e2;
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use super::peer_rooting::{peer_rooting, ClaimedKeyWire, PeerRooting};
use super::scope_resolution_invariants::{
    accepting_node, grant_instant, land_grant, owner_accepts, worker_with_owner,
};
use crate::derived::detection_row::detection_statement_parts;
use crate::derived::types::{ConformityVariant, DetectionSeverity};
use crate::derived::DetectionEvent;
use crate::federation::trust_root::INFRA_SERVE_SCOPE;
use crate::federation::types::attestation_type;
use crate::federation::types::delegation_scope::{
    ASSURE_AGE, ASSURE_CAPACITY, INFRA_ATTEST_ASSURANCE, INFRA_DETECT,
};
use crate::federation::{Attestation, FederationDirectory};

const DETECTOR_SEED: &str = "kr-i4320-det";
const DETECTOR_OWNER: &str = "kr-i4320-det-owner";
const SUBJECT: &str = "kr-i4320-subject";
const WORKER_TAG: &str = "kr-i4320";

/// The charter scope of the baked production genesis: the `charter.scope` of
/// the first bundle statement in [`super::genesis::BAKED_BUNDLES`].
fn production_charter_scope() -> Vec<String> {
    let (name, bytes) = super::genesis::BAKED_BUNDLES
        .first()
        .expect("I4320: a baked bundle");
    let statements = super::genesis::baked_statements(bytes)
        .unwrap_or_else(|| panic!("I4320: the baked bundle {name} decodes"));
    for st in &statements {
        let Some((_, payload)) = super::liveness::statement_parts(st) else {
            continue;
        };
        if let Some(Value::Array(scope)) = payload
            .get_text("charter")
            .and_then(|c| c.get_text("scope"))
        {
            return scope
                .iter()
                .filter_map(|v| v.as_text().map(str::to_owned))
                .collect();
        }
    }
    panic!("I4320: no statement of the baked bundle {name} carries charter.scope")
}

fn at(t: DateTime<Utc>) -> u64 {
    u64::try_from(t.timestamp_millis()).expect("after 1970")
}

/// A detection by the detector, its instant stated.
/// v62.0.0 (HEAD-fix1; Constitution's two-standings ruling) — signed, then
/// stated with its head as the producer states it (a root-grant act names
/// the bundle in force, `e2::with_head_resolved` over `d`).
async fn detection(d: &dyn FederationDirectory, ts: DateTime<Utc>) -> Vec<u8> {
    let st = detection_unheaded(ts);
    e2::with_head_resolved(d, &st, None)
        .await
        .expect("I4320: the detection's head")
}

fn detection_unheaded(ts: DateTime<Utc>) -> Vec<u8> {
    let ev = DetectionEvent {
        detection_id: uuid::Uuid::new_v4(),
        trace_id: format!("kr-i4320-trace-{}", uuid::Uuid::new_v4().simple()),
        body_sha256: vec![7u8; 32],
        detector: "hash_chain_integrity".into(),
        severity: DetectionSeverity::Warning,
        cohort_cell: serde_json::json!({"agent_role": "x"}),
        conformity_variant: ConformityVariant::Numeric,
        conformity_payload: serde_json::json!({"score": 0.25}),
        lens_core_version: "1.0.0".into(),
        ratchet_calibration_version: 3,
        canonical_bytes: b"{\"a\":1}".to_vec(),
        ed25519_sig: Vec::new(),
        ml_dsa_65_sig: Vec::new(),
        signing_key_id: e2::kid(DETECTOR_SEED),
        ts,
    };
    let (sub, family, payload) =
        detection_statement_parts(&ev, None).expect("I4320: the detection's parts");
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(DETECTOR_SEED),
        &sub,
        &sub,
        "scores",
        &family,
        &payload,
        vec![],
    )
    .expect("I4320: sign the detection")
}

/// An `age_assurance:provider:adult:v1` row by the detector about the
/// subject, its instant stated (an `infra:attest_assurance` family).
fn age_row(ts: DateTime<Utc>) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(DETECTOR_SEED),
    );
    a.attested_key_id = e2::kid(SUBJECT);
    a.asserted_at = ts;
    a.scrub_timestamp = ts;
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": "age_assurance:provider:adult:v1",
        "score": 1.0,
    });
    e2::row_of(&a, DETECTOR_SEED)
}

fn statement_of(row: &Attestation) -> Vec<u8> {
    e2::carried_statement(row).expect("I4320: the row carries its statement")
}

async fn landed(d: &dyn FederationDirectory, st: &[u8]) -> bool {
    let id = RowId::of_statement(st).expect("a row id");
    d.get_attestation(&id.hex())
        .await
        .expect("get_attestation")
        .is_some()
}

/// Why a statement is held (reason and detail), if it is.
async fn why(d: &dyn FederationDirectory, st: &[u8]) -> Option<(String, String)> {
    let id = RowId::of_statement(st).expect("a row id");
    super::fold::why_held(d, &id)
        .await
        .expect("why_held")
        .map(|h| (h.reason, h.detail))
}

/// Put `st` through the statement door and require it LANDED. A refusal or a
/// hold is reported in full: under the production charter these acts are
/// conferred, so anything else is a finding.
async fn must_land(d: &dyn FederationDirectory, st: &[u8], what: &str) {
    let out = put_statement(d, st, None, INGEST_TIER).await;
    assert!(
        landed(d, st).await,
        "{what}: NOT LANDED. The door answered {out:?}; held: {:?}",
        why(d, st).await
    );
}

/// [`must_land`] for a fixture row, at the row's own tier (`e2::put_signed`).
async fn must_land_row(d: &dyn FederationDirectory, row: &Attestation, what: &str) {
    let out = e2::put_signed(d, row).await;
    // v62.0.0 (HEAD-fix1) — the statement as put: its head stated.
    let st = e2::with_head_resolved(d, &statement_of(row), None)
        .await
        .expect("the row's head");
    assert!(
        landed(d, &st).await,
        "{what}: NOT LANDED. The door answered {out:?}; held: {:?}",
        why(d, &st).await
    );
}

async fn rooted(d: &dyn FederationDirectory, reader: &str, peer: &str, at_ms: u64) -> PeerRooting {
    let wire = ClaimedKeyWire::Kid(e2::kid_digest(&format!("w-{WORKER_TAG}")));
    let parsed = wire.composite().expect("I4320: a claim parses");
    let claim = wire.as_claim(parsed.as_ref()).expect("I4320: a claim");
    Box::pin(peer_rooting(d, reader, peer, claim, at_ms))
        .await
        .expect("I4320: peer_rooting reads")
}

/// The acceptance row that gives `grantee`'s consent to `grant` on `d`.
async fn acceptance_of(
    d: &dyn FederationDirectory,
    grantee: &str,
    grant: &Attestation,
) -> Attestation {
    let id = crate::federation::admission::root_grants_for(
        d,
        grantee,
        crate::host::clock::now() + Duration::seconds(1),
    )
    .await
    .expect("I4320: root_grants_for")
    .into_iter()
    .find(|g| g.row_id == grant.attestation_id)
    .and_then(|g| g.acceptance_row_id)
    .expect("I4320: the grant is accepted");
    d.get_attestation(&id)
        .await
        .expect("I4320: reads")
        .expect("I4320: the acceptance is held")
}

/// Everything a node holds before any grant: the production-charter bundle,
/// its own acceptance of the root, the detector with its owner, the subject,
/// the worker with its owner. Returns `(node, worker, worker's owner seed)`.
async fn stand_up(
    d: &dyn FederationDirectory,
    c: &TestCeremonyV2,
    node_seed: &str,
) -> (String, String, String) {
    install_ceremony_v2(d, c)
        .await
        .expect("I4320: the production-charter bundle installs");
    let node = accepting_node(d, node_seed).await;
    let grant_at = grant_instant(d).await;
    e2::put_key(d, DETECTOR_SEED, &["agent"]).await;
    e2::put_key(d, DETECTOR_OWNER, &["user"]).await;
    e2::put_agent_owner_binding(d, DETECTOR_OWNER, DETECTOR_SEED, grant_at - 30_000).await;
    e2::put_key(d, SUBJECT, &["user"]).await;
    let (worker, worker_owner) = worker_with_owner(d, WORKER_TAG).await;
    (node, worker, worker_owner)
}

/// **I4320.** The runner gave each store its node identity
/// (`set_node_key_id`), the key of `node_a` / `node_b`.
pub(crate) async fn i4320_the_production_charter_confers_what_the_doors_check(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
    node_a: &str,
    node_b: &str,
) {
    let scope = production_charter_scope();
    for needed in [INFRA_DETECT, ASSURE_AGE, ASSURE_CAPACITY, INFRA_SERVE_SCOPE] {
        assert!(
            scope.iter().any(|s| s == needed),
            "I4320 premise: the baked production charter carries {needed}: {scope:?}"
        );
    }
    // The fixture ceremony's own spec (the same holders and keys the grant
    // helpers sign with), under the production scope list.
    let c = ceremony_v2_with_scope(&bundle_v2().spec, &scope);
    let head = c.object_id;
    let (reader_a, worker, worker_owner) = stand_up(a, &c, node_a).await;
    let (reader_b, worker_b, _) = stand_up(b, &c, node_b).await;
    assert_eq!(worker_b, worker, "I4320: one worker key on both nodes");
    let detector = e2::kid(DETECTOR_SEED);
    let grant_at = grant_instant(a).await;

    // Two holders confer the three scopes on A; the owners accept.
    let detect = land_grant(a, &detector, INFRA_DETECT, &head, grant_at, "I4320 detect").await;
    let assure = land_grant(a, &detector, ASSURE_AGE, &head, grant_at, "I4320 assure").await;
    let serve = land_grant(
        a,
        &worker,
        INFRA_SERVE_SCOPE,
        &head,
        grant_at,
        "I4320 serve",
    )
    .await;
    owner_accepts(a, DETECTOR_OWNER, &detect, "I4320 detect").await;
    owner_accepts(a, DETECTOR_OWNER, &assure, "I4320 assure").await;
    owner_accepts(a, &worker_owner, &serve, "I4320 serve").await;
    let acc_detect = acceptance_of(a, &detector, &detect).await;
    let acc_assure = acceptance_of(a, &detector, &assure).await;
    let acc_serve = acceptance_of(a, &worker, &serve).await;
    // T0: every acceptance is stated by then.
    let t0 = acc_detect
        .asserted_at
        .max(acc_assure.asserted_at)
        .max(acc_serve.asserted_at);
    let live = t0 + Duration::seconds(1);
    let cut = t0 + Duration::seconds(2);
    let after = t0 + Duration::seconds(3);

    // ── A: the conferred acts, through the real door ───────────────────────
    let detection_live = detection(a, live).await;
    let age_live = age_row(live);
    must_land(
        a,
        &detection_live,
        "I4320 A: a detection by a detector conferred infra:detect by the root",
    )
    .await;
    must_land_row(
        a,
        &age_live,
        "I4320 A: an age_assurance row by a key conferred assure:age by the root",
    )
    .await;
    let v = rooted(a, &reader_a, &worker, at(live)).await;
    assert!(
        matches!(v, PeerRooting::Rooted { .. }),
        "I4320 A: the worker conferred infra:serve by the root holds a seat: {v:?}"
    );

    // ── The owners withdraw the acceptances, dated T0 + 2 s ───────────────
    let withdrawals = [
        e2::composer_of_at(
            attestation_type::WITHDRAWS,
            &acc_detect,
            DETECTOR_OWNER,
            cut,
        ),
        e2::composer_of_at(
            attestation_type::WITHDRAWS,
            &acc_assure,
            DETECTOR_OWNER,
            cut,
        ),
        e2::composer_of_at(attestation_type::WITHDRAWS, &acc_serve, &worker_owner, cut),
    ];
    for w in &withdrawals {
        must_land_row(a, w, "I4320 A: the owner's withdrawal of an acceptance").await;
    }

    // ── B: the same grants and acceptances, then the withdrawals FIRST, and
    // only then the acts dated before them (late, inside W) ────────────────
    for (g, scope, grantee, what) in [
        (&detect, INFRA_DETECT, &detector, "I4320 B detect"),
        (&assure, ASSURE_AGE, &detector, "I4320 B assure"),
        (&serve, INFRA_SERVE_SCOPE, &worker, "I4320 B serve"),
    ] {
        let on_b = land_grant(b, grantee, scope, &head, grant_at, what).await;
        assert_eq!(on_b.attestation_id, g.attestation_id, "{what}: one row");
    }
    for acc in [&acc_detect, &acc_assure, &acc_serve] {
        must_land_row(b, acc, "I4320 B: the owner's acceptance, as A holds it").await;
    }
    for w in &withdrawals {
        must_land_row(b, w, "I4320 B: the owner's withdrawal, before the acts").await;
    }
    must_land(
        b,
        &detection_live,
        "I4320 B: the detection signed while the conferral stood, delivered after its end \
         (inside W), is admitted as on A",
    )
    .await;
    must_land_row(
        b,
        &age_live,
        "I4320 B: the age_assurance row signed while the conferral stood, delivered late",
    )
    .await;

    // ── Both: an act dated AFTER the withdrawal is held, not landed ───────
    let detection_after = detection(a, after).await;
    for (who, d) in [("A", a), ("B", b)] {
        let out = put_statement(d, &detection_after, None, INGEST_TIER).await;
        assert!(
            !landed(d, &detection_after).await,
            "I4320 {who}: a detection dated after the withdrawal does not land: {out:?}"
        );
        assert!(
            matches!(out, Ok(StatementOutcome::Pending { .. })),
            "I4320 {who}: it is HELD, not refused: {out:?}"
        );
        let held = why(d, &detection_after).await;
        assert_eq!(
            held.as_ref().map(|(r, _)| r.as_str()),
            Some(super::fold::reason::gc1::RESERVED_FAMILY_UNSEATED),
            "I4320 {who}: under the door's own name for a signer with no conferral: {held:?}"
        );
        assert!(
            landed(d, &detection_live).await
                && landed(
                    d,
                    &e2::with_head_resolved(d, &statement_of(&age_live), None)
                        .await
                        .expect("the row's head"),
                )
                .await,
            "I4320 {who}: the acts signed while the conferral stood stay landed"
        );
    }

    // ── The seat: rooted as of before the withdrawal, not from it on ──────
    for (who, d, reader) in [("A", a, &reader_a), ("B", b, &reader_b)] {
        let before = rooted(d, reader, &worker, at(live)).await;
        let from = rooted(d, reader, &worker, at(after)).await;
        // KR-fix29 — on a red, name the serve acceptance's fold state.
        let acc_rid = RowId(e2::rid_digest(&acc_serve));
        assert!(
            matches!(before, PeerRooting::Rooted { .. }),
            "I4320 {who}: the seat as of before the withdrawal: {before:?}; the serve acceptance: \
             row {:?}, fold state {:?}",
            d.get_attestation(&acc_serve.attestation_id)
                .await
                .map(|r| r.is_some()),
            d.fold_state(&acc_rid).await
        );
        assert!(
            matches!(from, PeerRooting::NotRooted { .. }),
            "I4320 {who}: no seat from the withdrawal's instant on: {from:?}"
        );
    }
}

/// One voice of the holders' COUNTED withdrawal of the grant `target`, over
/// the bundle `c`, dated `at_ms` (a composer: `asserted_at` and `refs` only).
fn holder_withdrawal(
    c: &TestCeremonyV2,
    i: usize,
    grantee: &str,
    target: &Attestation,
    at_ms: u64,
) -> Vec<u8> {
    use ciris_verify_core::cde;
    use ciris_verify_core::edition2::row_ref;
    let map = |members: Vec<(&str, Value)>| {
        let mut m: Vec<(Value, Value)> = members
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_owned()), v))
            .collect();
        m.sort_by_key(|(k, _)| cde::encode(k));
        Value::Map(m)
    };
    let target_id: [u8; 32] = hex::decode(&target.attestation_id)
        .expect("I4321: a hex row id")
        .try_into()
        .expect("I4321: 32 bytes");
    let payload = map(vec![
        ("asserted_at", Value::Uint(at_ms)),
        (
            "refs",
            map(vec![
                ("head", row_ref(&c.object_id)),
                ("target", row_ref(&target_id)),
            ]),
        ),
    ]);
    ciris_verify_core::edition2::sign_row_statement(
        &c.holder_key(i),
        c.holder_identity_ref(i),
        grantee,
        attestation_type::WITHDRAWS,
        &ciris_verify_core::namespace_match::family_id(super::typed::TRUST_PREFIX),
        &payload,
        vec![],
    )
    .expect("I4321: sign a counted withdrawal voice")
}

/// `(confers, withdrawn)` of `grant` for `grantee`, as of `t`.
async fn conferring(
    d: &dyn FederationDirectory,
    grantee: &str,
    grant: &Attestation,
    t: DateTime<Utc>,
) -> (bool, bool) {
    crate::federation::admission::root_grants_for(d, grantee, t)
        .await
        .expect("I4321: root_grants_for")
        .into_iter()
        .find(|g| g.row_id == grant.attestation_id)
        .map(|g| (g.confers, g.withdrawn))
        .expect("I4321: the grant is listed")
}

/// **I4321** (KR-fix19.doors rev 2). ONE RULE FOR BOTH ENDS OF A ROOT
/// CONFERRAL: the holders' counted withdrawal of the GRANT ends it for acts
/// dated at or after the withdrawal's own instant, and not before, on both
/// nodes and in both arrival orders. Same production-charter bundle, same
/// detector, `infra:detect`; the acceptance is NOT withdrawn here.
///
/// - A: the act dated `T0 + 1 s` lands; THEN two holders withdraw the grant
///   (dated `T0 + 2 s`);
/// - B: the withdrawal lands FIRST; THEN the same act (dated before it,
///   inside W): it LANDS, as on A;
/// - both: an act dated `T0 + 3 s` is held, not landed; `root_grants_for`
///   reads the grant conferring as of `T0 + 1 s` and `withdrawn` as of
///   `T0 + 3 s`; one holder's voice alone changes nothing;
/// - the same act judged as received more than W later: `asserted_at_stale`
///   (at the shared function; the door's receipt clock cannot be moved).
pub(crate) async fn i4321_the_holders_withdrawal_ends_the_grant_from_its_instant(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
    node_a: &str,
    node_b: &str,
) {
    let scope = production_charter_scope();
    let c = ceremony_v2_with_scope(&bundle_v2().spec, &scope);
    let head = c.object_id;
    let (reader_a, _, _) = stand_up(a, &c, node_a).await;
    let (reader_b, _, _) = stand_up(b, &c, node_b).await;
    let detector = e2::kid(DETECTOR_SEED);
    let grant_at = grant_instant(a).await;
    let grant = land_grant(a, &detector, INFRA_DETECT, &head, grant_at, "I4321 A").await;
    owner_accepts(a, DETECTOR_OWNER, &grant, "I4321 A").await;
    let acc = acceptance_of(a, &detector, &grant).await;
    let on_b = land_grant(b, &detector, INFRA_DETECT, &head, grant_at, "I4321 B").await;
    assert_eq!(
        on_b.attestation_id, grant.attestation_id,
        "I4321: one grant row"
    );
    must_land_row(b, &acc, "I4321 B: the owner's acceptance, as A holds it").await;

    let t0 = acc.asserted_at;
    let live = t0 + Duration::seconds(1);
    let cut = t0 + Duration::seconds(2);
    let after = t0 + Duration::seconds(3);
    let detection_live = detection(a, live).await;
    let voices = [
        holder_withdrawal(&c, 0, &detector, &grant, at(cut)),
        holder_withdrawal(&c, 1, &detector, &grant, at(cut)),
    ];
    // A: the act first, then the holders' withdrawal.
    must_land(a, &detection_live, "I4321 A: the conferred detection").await;
    let _ = put_statement(a, &voices[0], None, INGEST_TIER).await;
    assert_eq!(
        conferring(a, &detector, &grant, after).await,
        (true, false),
        "I4321 A: one holder's voice is not a count"
    );
    must_land(a, &voices[1], "I4321 A: two holders withdraw the grant").await;

    // B: the withdrawal first, then the act dated before it.
    let _ = put_statement(b, &voices[0], None, INGEST_TIER).await;
    must_land(b, &voices[1], "I4321 B: two holders withdraw the grant").await;
    must_land(
        b,
        &detection_live,
        "I4321 B: a detection dated before the holders' withdrawal, delivered after it (inside \
         W), is admitted as on A",
    )
    .await;

    let detection_after = detection(a, after).await;
    for (who, d, reader) in [("A", a, &reader_a), ("B", b, &reader_b)] {
        assert_eq!(
            conferring(d, &detector, &grant, live).await,
            (true, false),
            "I4321 {who}: as of before the withdrawal the grant confers"
        );
        assert_eq!(
            conferring(d, &detector, &grant, after).await,
            (false, true),
            "I4321 {who}: from the withdrawal's instant on it is withdrawn"
        );
        let out = put_statement(d, &detection_after, None, INGEST_TIER).await;
        assert!(
            !landed(d, &detection_after).await
                && matches!(out, Ok(StatementOutcome::Pending { .. })),
            "I4321 {who}: a detection dated after the withdrawal is held, not landed: {out:?}"
        );
        assert!(
            landed(d, &detection_live).await,
            "I4321 {who}: the earlier act stays landed"
        );
        // Received more than W after its own instant, the conferral ended.
        let late = live
            + Duration::seconds(crate::federation::self_roster::PAST_FRESHNESS_W_SECS)
            + Duration::hours(1);
        let stale = crate::federation::trust_root::conferred_for_act(
            d,
            reader,
            &detector,
            INFRA_DETECT,
            live,
            late,
        )
        .await;
        assert!(
            stale
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("asserted_at_stale")),
            "I4321 {who}: outside W with the grant withdrawn: asserted_at_stale: {stale:?}"
        );
    }
}

/// A `provenance:build_manifest:{target}` Contribution by the pipeline
/// `seed` (CC 3.1.2.1: a `scores` row at `cohort_scope: federation`), its
/// instant stated.
fn build_manifest(seed: &str, ts: DateTime<Utc>) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(seed),
    );
    a.attested_key_id = e2::kid(seed);
    a.asserted_at = ts;
    a.scrub_timestamp = ts;
    a.cohort_scope = crate::federation::types::cohort_scope::FEDERATION.to_owned();
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": "provenance:build_manifest:ciris-agent-x86_64:v1",
        "score": 1.0,
    });
    e2::row_of(&a, seed)
}

/// v62.0.0 (HEAD-fix4; CC 3.1.2.1) — `manifest`'s statement as its pipeline
/// `seed` signs it under its root grant: the payload with its head stated by
/// the head rule (the bundle in force) and, given an `acceptance`,
/// `refs.also.stands_on` = that acceptance.
async fn manifest_standing_on(
    d: &dyn FederationDirectory,
    manifest: &Attestation,
    seed: &str,
    acceptance: Option<&Attestation>,
) -> Vec<u8> {
    let (_, payload) =
        super::liveness::statement_parts(&statement_of(manifest)).expect("I6137: a row statement");
    let Value::Map(mut m) = payload else {
        panic!("I6137: a payload is a map")
    };
    m.retain(|(k, _)| k.as_text() != Some("refs"));
    if let Some(acceptance) = acceptance {
        let text = |t: &str| Value::Text(t.to_owned());
        m.push((
            text("refs"),
            Value::Map(vec![(
                text("also"),
                Value::Map(vec![(
                    text("stands_on"),
                    Value::Array(vec![ciris_verify_core::edition2::row_ref(&e2::rid_digest(
                        acceptance,
                    ))]),
                )]),
            )]),
        ));
    }
    let family = ciris_verify_core::namespace_match::family_id(
        super::build_row::BUILD_MANIFEST_FAMILY_PREFIX,
    );
    let iss = e2::kid(seed);
    let payload = super::emit::sorted_map(m);
    // v62.0.0 (HEAD-fix6) — the producer now states `stands_on` itself (the
    // shared resolver). With an acceptance given, the head rule keeps it;
    // with none, the row is built by hand naming the bundle ALONE (the case
    // a producer refuses to sign), so the door's hold is what is witnessed.
    let payload = if acceptance.is_some() {
        super::head_rule::state_head(d, "scores", &family, &iss, payload)
            .await
            .expect("I6137: the head")
    } else {
        let bundle = super::genesis::bundle_head_in_force(d)
            .await
            .expect("I6137: the bundle read")
            .expect("I6137: a bundle is in force");
        super::head_rule::with_head(payload, &RowId(bundle)).expect("I6137: the head")
    };
    ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(seed),
        &iss,
        &iss,
        "scores",
        &family,
        &payload,
        vec![],
    )
    .expect("I6137: the manifest signs")
}

/// The build-manifest dimension I4326's pipelines sign. v62.0.0 (KR-fix33) —
/// with its version segment: the vendored registry row is
/// `provenance:build_manifest:{target}` and a dimension states
/// `{target}:v{n}` (namespace_match_vectors.json: `provenance:build_manifest:
/// id1:v1` resolves to the row; a versionless one is
/// `missing_version_segment`).
const MANIFEST_DIM: &str = "provenance:build_manifest:ciris-agent-x86_64:v1";

/// Does `key` hold `infra:attest` standing for `dimension`'s family at `t`
/// (KR-fix25's one predicate)?
async fn standing_for(
    d: &dyn FederationDirectory,
    key: &str,
    dimension: &str,
    t: DateTime<Utc>,
) -> bool {
    crate::federation::admission::pipeline_has_infra_attest_standing(d, key, dimension, t)
        .await
        .expect("KR-fix25: the standing reads")
}

/// [`standing_for`] a build manifest.
async fn standing(d: &dyn FederationDirectory, key: &str, t: DateTime<Utc>) -> bool {
    standing_for(d, key, MANIFEST_DIM, t).await
}

/// **I4326** (KR-fix25, KR-fix25b; CC 3.1.2.1, CC 4.5.5, as ruled
/// 2026-11-22: the family is part of the scope string,
/// `infra:attest:{dimension_family}`; a held parent covers its child). A
/// root grant (a counted `trust:confers:v1` grant over the bundle in force)
/// ACCEPTED by the grantee's owner is build-signing standing on the
/// delegation plane at the act's own instant when its scope covers
/// `infra:attest:provenance:build_manifest` (the exact string
/// `attest_scope_for_dimension` returns for a `provenance:build_manifest:*`
/// dimension):
///
/// - `infra:attest` (the parent) confers, for build manifests and for any
///   other attest family;
/// - `infra:attest:provenance:build_manifest` confers for build manifests
///   and for no other family;
/// - a sibling family (`infra:attest:detection`) does not;
/// - `infra:attest_assurance` does not, nor `infra:serve`.
///
/// The reader predicate says so, `namespace::is_trust_root` and
/// `holdings_authority` follow it, and the family-scoped pipeline's build
/// manifest lands through the real door. Not before the owner's acceptance;
/// not for an act dated after the owner withdrew it (an act dated before it
/// keeps its standing).
///
/// The bundle is the fixture ceremony with a charter of `infra:attest`,
/// `infra:attest_assurance` and `infra:serve`
/// (`fixture_genesis::ceremony_v2_with_scope`), so every grant here lies
/// inside it. There is no ceremony-plane arm to drive (KR-fix27: one grant
/// family; an edition-2 key record carries no role).
pub(crate) async fn i4326_a_root_grant_of_infra_attest_is_pipeline_standing(
    d: &dyn FederationDirectory,
    node_seed: &str,
) {
    use crate::federation::namespace::{holdings_authority, is_trust_root, AuthorityClass};
    use crate::federation::types::delegation_scope::INFRA_ATTEST;
    const FAMILY: &str = "infra:attest:provenance:build_manifest";
    const OTHER_DIM: &str = "build:registered:id1:v1";
    assert_eq!(
        crate::federation::trust_root::attest_scope_for_dimension(MANIFEST_DIM)
            .expect("I4326: the family scope"),
        FAMILY,
        "I4326 premise: the build-manifest family's scope string"
    );
    assert_ne!(
        crate::federation::trust_root::attest_scope_for_dimension(OTHER_DIM)
            .expect("I4326: another family's scope"),
        FAMILY,
        "I4326 premise: OTHER_DIM is another attest family"
    );
    let scope: Vec<String> = [INFRA_ATTEST, INFRA_ATTEST_ASSURANCE, INFRA_SERVE_SCOPE]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let c = ceremony_v2_with_scope(&bundle_v2().spec, &scope);
    install_ceremony_v2(d, &c)
        .await
        .expect("I4326: the bundle installs");
    accepting_node(d, node_seed).await;
    let head = c.object_id;
    let grant_at = grant_instant(d).await;
    // (tag, scope granted, standing for a build manifest, for another family)
    let cases = [
        ("kr-i4326-bare", INFRA_ATTEST, true, true),
        ("kr-i4326-ci", FAMILY, true, false),
        ("kr-i4326-sib", "infra:attest:detection", false, false),
        ("kr-i4326-assure", INFRA_ATTEST_ASSURANCE, false, false),
        ("kr-i4326-serve", INFRA_SERVE_SCOPE, false, false),
    ];
    let mut keys = Vec::new();
    for (tag, granted, _, _) in cases {
        let (key, owner) = worker_with_owner(d, tag).await;
        let grant = land_grant(d, &key, granted, &head, grant_at, tag).await;
        assert!(
            !standing(d, &key, crate::host::clock::now()).await,
            "I4326 {tag}: no standing before the grantee's owner accepts"
        );
        owner_accepts(d, &owner, &grant, tag).await;
        let acc = acceptance_of(d, &key, &grant).await;
        keys.push((key, owner, acc));
    }
    let t0 = keys
        .iter()
        .map(|(_, _, acc)| acc.asserted_at)
        .max()
        .expect("I4326: acceptances");

    // The four scopes, at the act's instant.
    for ((tag, granted, for_manifest, for_other), (key, _, _)) in cases.iter().zip(&keys) {
        assert_eq!(
            standing(d, key, t0).await,
            *for_manifest,
            "I4326 {tag}: a grant of {granted:?} for a build manifest"
        );
        assert_eq!(
            standing_for(d, key, OTHER_DIM, t0).await,
            *for_other,
            "I4326 {tag}: a grant of {granted:?} for another attest family"
        );
        assert_eq!(
            is_trust_root(d, key).await.expect("is_trust_root"),
            *for_manifest,
            "I4326 {tag}: is_trust_root asks the build-manifest family"
        );
    }

    // The family-scoped pipeline: its manifest lands; the readers follow.
    let (pipe, pipe_owner, acc) = &keys[1];
    let manifest = build_manifest("w-kr-i4326-ci", t0);
    // I6137 (HEAD-fix4; CC 3.1.2.1, rule `build-manifest-row`) — the row
    // names the bundle in `refs.head` AND the owner's acceptance of its grant
    // in `refs.also.stands_on`. Naming no acceptance it is KEPT and concludes
    // nothing, `build_row_stands_on_nothing`.
    let seed = "w-kr-i4326-ci";
    // I7103 (HEAD-fix6; "a root grant confers BY NAMING") — the PRODUCER
    // states the acceptance itself: the head rule over the manifest's payload
    // (no `refs`) names the bundle AND, through the shared resolver
    // (`conferral_naming::acceptance_to_stand_on`), the pipeline's owner's
    // acceptance of its grant.
    {
        let (_, p) = super::liveness::statement_parts(&statement_of(&manifest))
            .expect("I7103: a row statement");
        let Value::Map(mut m) = p else {
            panic!("I7103: a payload is a map")
        };
        m.retain(|(k, _)| k.as_text() != Some("refs"));
        let family = ciris_verify_core::namespace_match::family_id(
            super::build_row::BUILD_MANIFEST_FAMILY_PREFIX,
        );
        let stated = super::head_rule::state_head(
            d,
            "scores",
            &family,
            &e2::kid(seed),
            super::emit::sorted_map(m.clone()),
        )
        .await
        .expect("I7103: the producer states head and stands_on");
        let names = super::names::names_of(&stated).expect("I7103: names");
        assert!(super::head_rule::names_a_head(&stated), "I7103: the bundle");
        assert_eq!(
            super::names::single(&names, "also:stands_on"),
            Some(RowId(e2::rid_digest(acc))),
            "I7103: the acceptance the resolver picks is the owner's acceptance of the grant"
        );
        // A pipeline whose grant does not reach the family (the sibling
        // `infra:attest:detection` grant) holds nothing to stand on: the
        // producer does not sign; a fixture stating it as given names the
        // bundle alone.
        let (sib, _, _) = &keys[2];
        let refused = super::head_rule::state_head(
            d,
            "scores",
            &family,
            sib,
            super::emit::sorted_map(m.clone()),
        )
        .await
        .expect_err("I7103: no acceptance to stand on: not signed");
        assert!(
            refused.to_string().contains("stands_on:"),
            "I7103: the producer's refusal names it: {refused}"
        );
        let given = super::head_rule::state_head_as(
            d,
            "scores",
            &family,
            sib,
            super::emit::sorted_map(m),
            super::head_rule::StandsOnMissing::Omit,
        )
        .await
        .expect("I7103: as given");
        assert!(
            !super::head_rule::names_stands_on(&given),
            "I7103: stated as given, it stands on nothing"
        );
    }
    let bare = manifest_standing_on(d, &manifest, seed, None).await;
    let _ = put_statement(d, &bare, None, INGEST_TIER).await;
    assert!(
        !landed(d, &bare).await,
        "I6137: a build manifest standing on no acceptance does not land"
    );
    assert_eq!(
        why(d, &bare).await.map(|w| w.0).as_deref(),
        Some(super::build_row::BUILD_ROW_STANDS_ON_NOTHING),
        "I6137: it is held build_row_stands_on_nothing"
    );
    let on_acc = manifest_standing_on(d, &manifest, seed, Some(acc)).await;
    must_land(d, &on_acc, "I4326: the pipeline's build manifest").await;
    match super::build_row::evaluate_build_row_standing(d, &on_acc, crate::host::clock::now())
        .await
        .expect("I6137: the standing reads")
    {
        super::build_row::BuildRowStanding::Stands { acceptance, .. } => assert_eq!(
            acceptance,
            RowId(e2::rid_digest(acc)),
            "I6137: it stands on the owner's acceptance it names"
        ),
        other => panic!("I6137: the manifest stands on the bundle and the acceptance: {other:?}"),
    }
    // Standing on ANOTHER pipeline's acceptance: the door holds no wrong head
    // and admits it; the one reading says it stands on nothing.
    let (_, _, other_acc) = &keys[0];
    let on_other = manifest_standing_on(d, &manifest, seed, Some(other_acc)).await;
    let _ = put_statement(d, &on_other, None, INGEST_TIER).await;
    assert_eq!(
        super::build_row::evaluate_build_row_standing(d, &on_other, crate::host::clock::now())
            .await
            .expect("I6137: the standing reads"),
        super::build_row::BuildRowStanding::StandsOnNothing,
        "I6137: an acceptance of another grant is no standing for this row"
    );
    assert!(
        standing(d, pipe, manifest.asserted_at).await,
        "I4326: the manifest's signer had standing at its instant"
    );
    assert_eq!(
        holdings_authority(d, pipe)
            .await
            .expect("holdings_authority"),
        AuthorityClass::AccordCoScrub,
        "I4326: holdings_authority follows the predicate"
    );

    // The owner withdraws the acceptance, dated just after `t0`.
    let cut = t0 + Duration::milliseconds(1);
    let after = t0 + Duration::milliseconds(2);
    let w = e2::composer_of_at(attestation_type::WITHDRAWS, acc, pipe_owner, cut);
    must_land_row(d, &w, "I4326: the owner's withdrawal of the acceptance").await;
    while crate::host::clock::now() <= after {
        tokio::task::yield_now().await;
    }
    assert!(
        !standing(d, pipe, after).await,
        "I4326: an act dated after the withdrawal has no standing"
    );
    assert!(
        standing(d, pipe, t0).await,
        "I4326: an act dated before it keeps its standing"
    );
    assert!(
        !is_trust_root(d, pipe).await.expect("is_trust_root"),
        "I4326: and is_trust_root, read now, drops it"
    );
    assert_eq!(
        holdings_authority(d, pipe)
            .await
            .expect("holdings_authority"),
        AuthorityClass::ProducerSteward,
        "I4326: holdings_authority falls back to the negative default"
    );
}

/// An `evidence:safety_battery:capture:{cell}:0123456789abcdef:v1` row by
/// the key of `seed` about itself, its instant stated.
fn evidence_row(seed: &str, cell: &str, ts: DateTime<Utc>) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(seed),
    );
    a.attested_key_id = e2::kid(seed);
    a.asserted_at = ts;
    a.scrub_timestamp = ts;
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": format!("evidence:safety_battery:capture:{cell}:0123456789abcdef:v1"),
        "score": 1.0,
    });
    e2::row_of(&a, seed)
}

/// **I5711** — see the module header. The runner gave the store its node
/// identity (`set_node_key_id`), the key of `node`.
pub(crate) async fn i5711_an_evidence_row_needs_infra_attest(
    d: &dyn FederationDirectory,
    node: &str,
) {
    use crate::federation::types::delegation_scope::INFRA_ATTEST;
    let scope = production_charter_scope();
    assert!(
        scope.iter().any(|s| s == INFRA_ATTEST),
        "I5711 premise: the baked production charter carries infra:attest: {scope:?}"
    );
    let c = ceremony_v2_with_scope(&bundle_v2().spec, &scope);
    let head = c.object_id;
    let _ = stand_up(d, &c, node).await;
    let detector = e2::kid(DETECTOR_SEED);
    let grant_at = grant_instant(d).await;
    let grant = land_grant(d, &detector, INFRA_ATTEST, &head, grant_at, "I5711").await;
    owner_accepts(d, DETECTOR_OWNER, &grant, "I5711").await;
    let accepted = acceptance_of(d, &detector, &grant).await;
    let live = accepted.asserted_at + Duration::seconds(1);

    must_land_row(
        d,
        &evidence_row(DETECTOR_SEED, "c1", live),
        "I5711: an evidence row by a key conferred infra:attest by the root",
    )
    .await;

    let unconferred = evidence_row(SUBJECT, "c2", live);
    let _ = e2::put_signed(d, &unconferred).await;
    let st = statement_of(&unconferred);
    assert!(
        !landed(d, &st).await,
        "I5711: an evidence row by a key with no infra:attest does not land"
    );
    assert_eq!(
        why(d, &st).await.map(|(reason, _)| reason).as_deref(),
        Some(super::fold::reason::gc1::RESERVED_PREFIX_EMITTER_MISMATCH),
        "I5711: held, by name"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use crate::federation::edition2::fixture_switch as e2;

    async fn store(node_seed: &str) -> (crate::store::sqlite::SqliteBackend, String) {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let node = e2::put_key(&b, node_seed, &["node"]).await;
        b.set_node_key_id(node.clone());
        (b, node)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i4320_the_production_charter_confers_what_the_doors_check_sqlite() {
        let (a, _) = store("kr-i4320-node-a").await;
        let (b, _) = store("kr-i4320-node-b").await;
        Box::pin(
            super::i4320_the_production_charter_confers_what_the_doors_check(
                &a,
                &b,
                "kr-i4320-node-a",
                "kr-i4320-node-b",
            ),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i4326_a_root_grant_of_infra_attest_is_pipeline_standing_sqlite() {
        let (d, _) = store("kr-i4326-node").await;
        Box::pin(
            super::i4326_a_root_grant_of_infra_attest_is_pipeline_standing(&d, "kr-i4326-node"),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i5711_an_evidence_row_needs_infra_attest_sqlite() {
        let (a, _) = store("fs-i5711-node").await;
        Box::pin(super::i5711_an_evidence_row_needs_infra_attest(
            &a,
            "fs-i5711-node",
        ))
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i4321_the_holders_withdrawal_ends_the_grant_from_its_instant_sqlite() {
        let (a, _) = store("kr-i4321-node-a").await;
        let (b, _) = store("kr-i4321-node-b").await;
        Box::pin(
            super::i4321_the_holders_withdrawal_ends_the_grant_from_its_instant(
                &a,
                &b,
                "kr-i4321-node-a",
                "kr-i4321-node-b",
            ),
        )
        .await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use crate::federation::edition2::fixture_switch as e2;

    async fn store(node_seed: &str) -> Option<(crate::store::postgres::PostgresBackend, String)> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let node = e2::put_key(&b, node_seed, &["node"]).await;
        b.set_node_key_id(node.clone());
        Some((b, node))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i4320_the_production_charter_confers_what_the_doors_check_postgres() {
        let (Some((a, _)), Some((b, _))) = (
            store("kr-i4320-node-a").await,
            store("kr-i4320-node-b").await,
        ) else {
            return;
        };
        Box::pin(
            super::i4320_the_production_charter_confers_what_the_doors_check(
                &a,
                &b,
                "kr-i4320-node-a",
                "kr-i4320-node-b",
            ),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i4326_a_root_grant_of_infra_attest_is_pipeline_standing_postgres() {
        let Some((d, _)) = store("kr-i4326-node").await else {
            return;
        };
        Box::pin(
            super::i4326_a_root_grant_of_infra_attest_is_pipeline_standing(&d, "kr-i4326-node"),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i5711_an_evidence_row_needs_infra_attest_postgres() {
        let Some((a, _)) = store("fs-i5711-node").await else {
            return;
        };
        Box::pin(super::i5711_an_evidence_row_needs_infra_attest(
            &a,
            "fs-i5711-node",
        ))
        .await;
        eprintln!("i5711 postgres: RAN");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i4321_the_holders_withdrawal_ends_the_grant_from_its_instant_postgres() {
        let (Some((a, _)), Some((b, _))) = (
            store("kr-i4321-node-a").await,
            store("kr-i4321-node-b").await,
        ) else {
            return;
        };
        Box::pin(
            super::i4321_the_holders_withdrawal_ends_the_grant_from_its_instant(
                &a,
                &b,
                "kr-i4321-node-a",
                "kr-i4321-node-b",
            ),
        )
        .await;
    }
}
