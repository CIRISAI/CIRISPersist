//! v62.0.0 (KR-fix19) — **I4320: under the PRODUCTION charter a grant from
//! the root confers what the production doors check, end to end.**
//!
//! Every other root-grant witness uses the fixture bundle, whose charter
//! carries `infra:attest` and `infra:serve` only. The doors that gate a
//! worker's statements ask for `infra:detect`, `infra:attest_assurance`,
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
//! - `infra:detect` and `infra:attest_assurance` on a detector (an `agent`
//!   key; its OWNER accepts);
//! - `infra:serve` on a `node` worker (its OWNER accepts).
//!
//! Then, through the real statement door (`put_statement`):
//!
//! - the detector's `detection:{detector}` row (`infra:detect`) LANDS on A;
//! - its `age_assurance:provider:adult:v1` row (`infra:attest_assurance`)
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
//! sqlite and postgres.

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
use crate::federation::types::delegation_scope::{INFRA_ATTEST_ASSURANCE, INFRA_DETECT};
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
fn detection(ts: DateTime<Utc>) -> Vec<u8> {
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
    let st = statement_of(row);
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
    for needed in [INFRA_DETECT, INFRA_ATTEST_ASSURANCE, INFRA_SERVE_SCOPE] {
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
    let assure = land_grant(
        a,
        &detector,
        INFRA_ATTEST_ASSURANCE,
        &head,
        grant_at,
        "I4320 assure",
    )
    .await;
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
    let detection_live = detection(live);
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
        "I4320 A: an age_assurance row by a key conferred infra:attest_assurance by the root",
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
        (&assure, INFRA_ATTEST_ASSURANCE, &detector, "I4320 B assure"),
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
    let detection_after = detection(after);
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
            Some(super::fold::reason::gc1::RESERVED_PREFIX_EMITTER_MISMATCH),
            "I4320 {who}: under the door's own name for a signer with no conferral: {held:?}"
        );
        assert!(
            landed(d, &detection_live).await && landed(d, &statement_of(&age_live)).await,
            "I4320 {who}: the acts signed while the conferral stood stay landed"
        );
    }

    // ── The seat: rooted as of before the withdrawal, not from it on ──────
    for (who, d, reader) in [("A", a, &reader_a), ("B", b, &reader_b)] {
        let before = rooted(d, reader, &worker, at(live)).await;
        let from = rooted(d, reader, &worker, at(after)).await;
        assert!(
            matches!(before, PeerRooting::Rooted { .. }),
            "I4320 {who}: the seat as of before the withdrawal: {before:?}"
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
    let detection_live = detection(live);
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

    let detection_after = detection(after);
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
