//! v62.0.0 (F0-cp5b; the lead's ruling) — **the pipeline writer capability**,
//! `infra:pipeline_writer`, witnessed on sqlite AND postgres (I2889).
//!
//! The ruling these pin (`server::pipeline::authorize_pipeline_writer`):
//!
//! - an edge writes a `PipelineEnvelope` only under a LIVE
//!   `self:delegates_to` from THIS node's owner bearing
//!   `infra:pipeline_writer` (`trust_root::owner_granted_scope`);
//! - the grant is a delegation, seated only with the delegate's (the edge's)
//!   voice beside the owner's (CC 2.6.1.9): a grant held without it confers
//!   nothing;
//! - one scope, one meaning: `secrets:writer` does not cover it;
//! - every refusal is by name and final (`pipeline_writer_not_delegated`),
//!   never the 424 key wait.
//!
//! The fixture is P6's (`server::secrets::authz_invariants`): a `node` key
//! (this node's identity), a `user` owner whose owner binding over the node
//! carries the node's voice, and `node` edge keys.

use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::ingest::StatementOutcome;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::delegation_scope as ds;
use crate::federation::{admission, Attestation, FederationDirectory};

use super::pipeline::{authorize_pipeline_writer, WriterRefusal, KIND_WRITER_NOT_DELEGATED};

/// This node's identity key (seed).
pub(crate) const NODE: &str = "f0-cp5b-node";
/// The node's owner (seed): a `user` key, the only conferrer.
pub(crate) const OWNER: &str = "f0-cp5b-owner";

/// The owner's binding over the node, with the node's voice, re-dated to now.
/// The directory's `node_key_id` must already be `e2::kid(NODE)`.
pub(crate) async fn seat_owner<D: FederationDirectory + ?Sized>(d: &D) {
    e2::put_key(d, NODE, &["node"]).await;
    e2::put_key(d, OWNER, &["user"]).await;
    let mut binding = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), OWNER, NODE);
    let at = crate::host::clock::now() - chrono::Duration::minutes(5);
    binding.asserted_at = at;
    binding.scrub_timestamp = at;
    ts::reseal(&mut binding);
    e2::put_signed(d, &binding)
        .await
        .expect("fixture: the owner's binding over the node is admitted");
    let st = e2::carried_statement(&binding).expect("a flipped binding carries its statement");
    e2::put_statement(d, &e2::voice_of(&st, NODE))
        .await
        .expect("fixture: the node's voice on its owner binding is admitted");
    assert_eq!(
        admission::owner_of(d, &e2::kid(NODE))
            .await
            .expect("owner_of reads"),
        Some(e2::kid(OWNER)),
        "fixture: the owner holds the node's owner seat, else every leg below is vacuous"
    );
}

/// The owner's `trust:confers:v1` `self:delegates_to` to `grantee` bearing
/// `scopes`; with `voiced`, the grantee's own voice seats it (CC 2.6.1.9).
/// The outcome of the last put.
pub(crate) async fn grant<D: FederationDirectory + ?Sized>(
    d: &D,
    grantee: &str,
    scopes: &[&str],
    voiced: bool,
) -> StatementOutcome {
    let now = admission::truncate_to_substrate_resolution(
        crate::host::clock::now() - chrono::Duration::minutes(1),
    );
    let mut envelope = serde_json::json!({
        "dimension": crate::federation::trust_root::TRUST_CONFERS_DIMENSION,
        "scope": scopes,
    });
    admission::with_test_term(&mut envelope, now);
    let owner = e2::kid(OWNER);
    let att = Attestation {
        attestation_id: String::new(),
        attesting_key_id: owner.clone(),
        attested_key_id: e2::kid(grantee),
        attestation_type: crate::federation::types::attestation_type::DELEGATES_TO.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: owner,
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
        tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    let row = e2::row_of(&att, OWNER);
    assert_eq!(
        e2::family_of(&row),
        "self:delegates_to",
        "fixture: the writer grant is a self:delegates_to row"
    );
    if voiced {
        e2::put_with_voices(d, &row, &[grantee])
            .await
            .expect("fixture: the grant lands with the edge's voice")
    } else {
        e2::put_signed(d, &row)
            .await
            .expect("fixture: the owner's statement of the grant is accepted")
    }
}

async fn refused<D: FederationDirectory + ?Sized>(d: &D, edge: &str, what: &str) -> WriterRefusal {
    let Err(r) = authorize_pipeline_writer(d, edge).await else {
        panic!("I2889 {what}: refused");
    };
    assert_eq!(
        r.kind(),
        KIND_WRITER_NOT_DELEGATED,
        "I2889 {what}: by name: {r}"
    );
    r
}

/// **I2889** — the writer capability, both backends. `d`'s `node_key_id` is
/// `e2::kid(NODE)`.
async fn body(d: &dyn FederationDirectory) {
    seat_owner(d).await;

    // The edge with the seated scope is accepted.
    const SEATED: &str = "f0-cp5b-edge-seated";
    let seated = e2::put_key(d, SEATED, &["node"]).await;
    grant(d, SEATED, &[ds::INFRA_PIPELINE_WRITER], true).await;
    authorize_pipeline_writer(d, &seated)
        .await
        .unwrap_or_else(|r| panic!("I2889: the seated grant authorizes: {r}"));

    // An edge with no grant is refused by name (not the 424 key wait).
    const BARE: &str = "f0-cp5b-edge-bare";
    let bare = e2::put_key(d, BARE, &["node"]).await;
    refused(d, &bare, "no grant").await;

    // The grant held without the edge's voice confers nothing.
    const HELD: &str = "f0-cp5b-edge-held";
    let held = e2::put_key(d, HELD, &["node"]).await;
    let out = grant(d, HELD, &[ds::INFRA_PIPELINE_WRITER], false).await;
    assert!(
        !matches!(out, StatementOutcome::Row { .. }),
        "I2889: the owner's statement alone does not seat a delegation: {out:?}"
    );
    refused(d, &held, "held, unvoiced").await;

    // One scope, one meaning: a seated `secrets:writer` does not cover it.
    const SECRETS: &str = "f0-cp5b-edge-secrets";
    let secrets = e2::put_key(d, SECRETS, &["node"]).await;
    grant(d, SECRETS, &[ds::SECRETS_WRITER], true).await;
    refused(d, &secrets, "secrets:writer").await;
}

/// I2889 on sqlite.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2889_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid(NODE));
    Box::pin(body(&b)).await;
}

/// I2889 on postgres.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2889_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid(NODE));
    Box::pin(body(&b)).await;
}
