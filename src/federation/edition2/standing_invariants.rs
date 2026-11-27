//! v62.0.0 (P4, CC rc20 3.4.7 / 3.4.7.1) — **standing is conferred, never
//! declared**: an edition-2 key's self-signed `key:record` may state any
//! `identity_type` (Verify's `check_key_record` takes an open vocabulary), and
//! no gate reads that statement to open a reserved family. On sqlite and
//! postgres.
//!
//! - **I3080** — a live self-signed `key:record` declaring `lenscore_detector`
//!   cannot emit a reserved `detection:*` row: the row is HELD (v62 GC1,
//!   CC 2.7.3) `reserved_prefix_emitter_mismatch`, naming the `infra:detect` delegation from
//!   a root this node trusts (the clause that decides, not the missing node
//!   identity before it), and nothing is stored. The projection still carries
//!   the label, so the refusal is not about the label's absence.
//! - **I3081** — a properly conferred detector is admitted: an `agent` key
//!   that declares NO `lenscore_detector` but holds `infra:detect` on a
//!   `delegates_to` chain from a root this node trusts emits the same row.
//!   (Uses E0's `fixture_switch` builders; see P4.md "assumed APIs".)
//! - **I3082** — a live self-signed `key:record` declaring `accord_holder`
//!   cannot emit an `accord:*` row: with no genesis bundle in force seating it,
//!   the row is HELD (v62 GC1) `accord_dimension_requires_accord_holder`, and
//!   nothing is concluded.
//! - **I3083** — a self-declared `accord_holder` is not a halt signer: its
//!   constitutional halt never reads Valid against the roster of the bundle in
//!   force (its kid is not placed: it waits), and the accord's active halt is
//!   not latched.
//! - **I3084** — a holder the bundle in force places (conferred by the
//!   accord's charter) IS a halt signer: its constitutional halt latches.
//! - **I3085** (pure) — accord standing is read from the bundle in force:
//!   nothing held seats nobody, whatever the signer states.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{iref, key, key_record, map};
use super::halt::{put_invocation, HaltRoster, FAMILY_CONSTITUTIONAL};
use super::ingest::{put_statement, INGEST_TIER};
use super::names::RowId;
use crate::federation::FederationDirectory;

const ACCORD: &str = "humanity-accord";

/// The node identity the detector runners set: a key this node is, holding no
/// trust edge, so the delegation walk runs and finds nothing.
fn node_key() -> CompositeSigningKey {
    key(90)
}

/// A `detection:hash_chain_integrity:v1` score by `k` about itself.
fn detection_row(k: &CompositeSigningKey, at: u64) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "dimension",
            Value::Text("detection:hash_chain_integrity:v1".into()),
        ),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        "detection:hash_chain_integrity",
        &payload,
        vec![],
    )
    .unwrap()
}

/// An `accord:human_dignity:v1` verdict by `k` about itself, naming
/// [`ACCORD`] as its `accord_root` (so `check_accord_root_binding` passes and
/// the standing clause is the one that decides).
fn accord_row(k: &CompositeSigningKey, at: u64) -> Vec<u8> {
    let payload = map(vec![
        ("accord_root", Value::Text(ACCORD.into())),
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        ("dimension", Value::Text("accord:human_dignity:v1".into())),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        "accord:human_dignity",
        &payload,
        vec![],
    )
    .unwrap()
}

/// A constitutional halt by `k`.
fn halt(k: &CompositeSigningKey, id: &str, nonce: u8, at: u64, until: u64) -> Vec<u8> {
    let m = map(vec![
        ("accord_root", Value::Text(ACCORD.into())),
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("invocation_id", Value::Text(id.into())),
        ("nonce", Value::Bytes(vec![nonce; 32])),
        ("valid_until", Value::Uint(until)),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        ACCORD,
        "scores",
        FAMILY_CONSTITUTIONAL,
        &m,
        vec![],
    )
    .unwrap()
}

async fn stored(d: &dyn FederationDirectory, statement: &[u8]) -> bool {
    let id = RowId::of_statement(statement).expect("a row id").hex();
    d.get_attestation(&id).await.unwrap().is_some()
}

/// I3080: the self-declared detector. The caller has set this node's identity
/// to [`node_key`].
pub(crate) async fn self_declared_detector_body(d: &dyn FederationDirectory) {
    let det = key(80);
    put_statement(
        d,
        &key_record(&det, &["lenscore_detector"], 0, None),
        None,
        INGEST_TIER,
    )
    .await
    .expect("I3080: the detector's own record is live");
    let projected = d
        .lookup_public_key(&iref(&det))
        .await
        .unwrap()
        .expect("I3080: the key is projected");
    assert!(
        projected.claims_role(crate::federation::types::identity_type::LENSCORE_DETECTOR),
        "I3080: the label is present ({}), so the refusal below is not about its absence",
        projected.identity_type
    );
    let row = detection_row(&det, 5_000);
    // v62.0.0 (wave GC1; CC 2.7.3) — the conferral is read from OTHER rows,
    // so the row is HELD `reserved_prefix_emitter_mismatch` (kept, concluding
    // nothing), never refused; it concludes if a conferral lands.
    let out = put_statement(d, &row, None, INGEST_TIER)
        .await
        .expect("I3080: a self-declared detector's detection:* row is kept, held");
    assert!(
        matches!(out, super::ingest::StatementOutcome::Pending { .. }),
        "I3080: held: {out:?}"
    );
    let h = super::fold::why_held(d, &RowId::of_statement(&row).expect("a row id"))
        .await
        .unwrap()
        .expect("I3080: held, and says why");
    assert_eq!(
        h.reason,
        super::fold::reason::gc1::RESERVED_PREFIX_EMITTER_MISMATCH,
        "I3080: the reserved-prefix fold decides"
    );
    assert!(
        h.detail.contains("detection:"),
        "I3080: the detection rule decides: {}",
        h.detail
    );
    assert!(
        h.detail
            .contains(crate::federation::types::delegation_scope::INFRA_DETECT)
            && h.detail.contains("from a root this node trusts"),
        "I3080: the hold names the missing conferral, not the node identity: {}",
        h.detail
    );
    assert!(!stored(d, &row).await, "I3080: nothing concluded");
}

/// I3081: the conferred detector. The caller has set this node's identity
/// to `e2::kid("p4-node")`.
///
/// P4-fix2 (round 6) — the root is a ROOTED edition-2 trust root (W1b's
/// `fixture_trust_root`: the bundle in force, an infrastructure community
/// founded by its holders, the root's charter and THIS node's acceptance).
/// A bare key's self-charter is not a root an edition-2 reader trusts, so the
/// walk found no conferral and the detection row was held (it was never
/// stored, while `try_put_row` returned `Ok` for the held row).
pub(crate) async fn conferred_detector_body(d: &dyn FederationDirectory) {
    use super::fixture_switch as e2;
    use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
    let (node, det) = ("p4-node", "p4-detector");
    e2::put_key(d, node, &["node"]).await;
    // The detector states only `agent`: the duty is the delegation's.
    e2::put_key(d, det, &["agent"]).await;
    let r = e2::rooted_trust_root(d, &super::fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    // The grant is stated after the root's own rows, at an instant derived
    // from the bundle in force (as `fixture_trust_root::put_conferral` does;
    // never the wall clock). The detector's `agent` window covers it.
    let tip = super::genesis::genesis_in_force(d)
        .await
        .expect("I3081: the genesis in force")
        .tips()
        .iter()
        .map(|t| t.asserted_at)
        .max()
        .expect("I3081: a bundle in force");
    let at = tip + 90_000;
    // FX-fix1 (CC 4.4.3.19) — the detector is a MACHINE key: a conferral on
    // it also waits for its owner's voice (`delegate_owner`), so it is given
    // an owner first, bound at the grant's instant, as the shared conferral
    // helper does (`r2_test_support::confer_scope_from_trusted_root_at`).
    // Without one the grant was held `count_short` for good.
    let at_instant = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        i64::try_from(at).expect("I3081: an instant"),
    )
    .expect("I3081: an instant");
    crate::federation::admission::r2_test_support::bind_owner_if_machine(d, det, at_instant).await;
    // LEAD-root1 — the grant is COUNTED over the bundle's holders; the
    // machine detector's OWNER accepts it.
    let owner = crate::federation::admission::r2_test_support::machine_owner_of(
        d,
        &e2::kid(det),
        at_instant,
    )
    .await
    .expect("I3081: the detector's owner is bound");
    let grant_id = super::fixture_trust_root::put_conferral_accepted_by(
        d,
        &r,
        det,
        &[crate::federation::types::delegation_scope::INFRA_DETECT],
        &e2::seed_of(&owner),
    )
    .await
    .expect("I3081: the root's grant and its acceptance");
    assert!(
        d.get_attestation(&grant_id.hex()).await.unwrap().is_some(),
        "I3081: the conferral concludes; held {:?}",
        super::fold::why_held(d, &grant_id)
            .await
            .unwrap()
            .map(|h| (h.reason, h.detail))
    );
    // RT-fix1 — and it reaches the root through THIS node (the K2-fix13
    // pattern): a conferral that roots nowhere stops at the fixture.
    let rooted = crate::federation::trust_root::capability_roots_to_trusted_root(
        d,
        &e2::kid(node),
        &e2::kid(det),
        crate::federation::types::delegation_scope::INFRA_DETECT,
        crate::host::clock::now(),
    )
    .await
    .expect("I3081: capability_roots_to_trusted_root");
    assert!(
        rooted.as_ref().is_some_and(|g| g.root_key_id == r.lineage),
        "I3081: the detector's infra:detect roots at {} through this node: {rooted:?}",
        r.lineage
    );
    let instant = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        i64::try_from(at + 60_000).expect("I3081: an instant"),
    )
    .expect("I3081: an instant");
    let detection = crate::federation::Attestation {
        attestation_id: String::new(),
        attesting_key_id: e2::kid(det),
        attested_key_id: e2::kid(det),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: Some(1.0),
        asserted_at: instant,
        expires_at: None,
        attestation_envelope: serde_json::json!({
            "dimension": "detection:hash_chain_integrity:v1",
            "score": 0.75,
            "confidence": 0.9,
        }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: e2::kid(det),
        scrub_timestamp: instant,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    let stored_row = e2::try_put_row(d, &detection, det)
        .await
        .unwrap_or_else(|e| panic!("I3081: a conferred detector emits detection:*: {e:?}"));
    let id = e2::rid_digest(&stored_row);
    assert!(
        d.get_attestation(&e2::rid(&stored_row))
            .await
            .unwrap()
            .is_some(),
        "I3081: stored under its row id; held {:?}",
        super::fold::why_held(d, &RowId(id))
            .await
            .unwrap()
            .map(|h| (h.reason, h.detail))
    );
}

/// I3082: the self-declared accord holder on the attestation door.
pub(crate) async fn self_declared_accord_holder_row_body(d: &dyn FederationDirectory) {
    let pretender = key(82);
    put_statement(
        d,
        &key_record(&pretender, &["accord_holder"], 0, None),
        None,
        INGEST_TIER,
    )
    .await
    .expect("I3082: the pretender's own record is live");
    let row = accord_row(&pretender, 5_000);
    // v62.0.0 (wave GC1; CC 2.7.3) — accord standing is read from OTHER rows
    // (the bundle in force): HELD `accord_dimension_requires_accord_holder`,
    // kept and concluding nothing.
    let out = put_statement(d, &row, None, INGEST_TIER)
        .await
        .expect("I3082: a self-declared accord holder's accord:* row is kept, held");
    assert!(
        matches!(out, super::ingest::StatementOutcome::Pending { .. }),
        "I3082: held: {out:?}"
    );
    assert_eq!(
        super::fold::why_held(d, &RowId::of_statement(&row).expect("a row id"))
            .await
            .unwrap()
            .map(|h| h.reason)
            .as_deref(),
        Some(super::fold::reason::gc1::ACCORD_DIMENSION_REQUIRES_ACCORD_HOLDER),
        "I3082: held, and says why"
    );
    assert!(!stored(d, &row).await, "I3082: nothing concluded");
}

/// I3083 + I3084: the halt door judges the signer against the bundle in force,
/// never its label.
pub(crate) async fn halt_signer_body(d: &dyn FederationDirectory) {
    let holder = key(83);
    let pretender = key(84);
    for k in [&holder, &pretender] {
        put_statement(
            d,
            &key_record(k, &["accord_holder"], 0, None),
            None,
            INGEST_TIER,
        )
        .await
        .expect("I3083: both records are live");
    }
    let projected = d
        .lookup_public_key(&iref(&pretender))
        .await
        .unwrap()
        .expect("I3083: the pretender is projected");
    assert!(
        projected.claims_role(crate::federation::types::identity_type::ACCORD_HOLDER),
        "I3083: the pretender states accord_holder ({})",
        projected.identity_type
    );
    // The bundle in force places ONE holder.
    let roster = HaltRoster::new(
        ACCORD,
        [0x5a; 32],
        // X2 build fix: Verify 23.3.0's roster takes `RosterHolder`s (C3).
        vec![ciris_verify_core::edition2::accord_halt::RosterHolder {
            identity_ref: iref(&holder),
            key: holder.public_key().clone(),
        }],
        None,
    );
    let e = put_invocation(
        d,
        &halt(&pretender, "p4-pretend", 0x41, 2_000_000, 3_000_000),
        Some(&roster),
    )
    .await
    .expect_err("I3083: a self-declared accord holder is not a halt signer");
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I3083: a key the bundle does not place waits; it is never admitted"
    );
    assert!(
        d.get_active_halt(ACCORD).await.unwrap().is_none(),
        "I3083: no halt latched"
    );
    // I3084: the placed holder's halt latches.
    let out = put_invocation(
        d,
        &halt(&holder, "p4-holder", 0x42, 2_000_000, 3_000_000),
        Some(&roster),
    )
    .await
    .expect("I3084: the placed holder's halt is admitted");
    assert!(out.new && out.latched, "I3084: latched");
    let active = d
        .get_active_halt(ACCORD)
        .await
        .unwrap()
        .expect("I3084: the active halt");
    assert_eq!(
        active.active_halt_id,
        hex::encode(out.invocation.row_id()),
        "I3084: the holder's invocation is the active halt"
    );
}

/// I3085: nothing held seats nobody.
#[test]
fn i3085_no_bundle_in_force_seats_no_accord_holder() {
    let none = super::genesis::GenesisInForce::default();
    assert!(
        !super::standing::accord_standing_in(&none, &iref(&key(85)), ACCORD),
        "I3085"
    );
}

/// I3080–I3084, one backend.
async fn all(d: &dyn FederationDirectory) {
    self_declared_detector_body(d).await;
    self_declared_accord_holder_row_body(d).await;
    halt_signer_body(d).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3080_i3082_i3083_i3084_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(iref(&node_key()));
    Box::pin(all(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3080_i3082_i3083_i3084_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(iref(&node_key()));
    Box::pin(all(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3081_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(super::fixture_switch::kid("p4-node"));
    Box::pin(conferred_detector_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3081_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(super::fixture_switch::kid("p4-node"));
    Box::pin(conferred_detector_body(&b)).await;
}
