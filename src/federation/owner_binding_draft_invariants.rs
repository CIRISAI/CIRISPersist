//! v62.0.0 (KR-fix11; CC 3.2 "the first binding", CC 2.6.1.9, CC 3.1.3.2) —
//! **I4285–I4286: a canonical seat's owner binding, produced with the
//! owner's key outside the Engine.**
//!
//! - **I4285** the operator's own person key (not held by the Engine) signs
//!   the drafted owner binding (`Engine::owner_binding_draft`); the tool's
//!   self-check passes; submitted, it WAITS for the node's own voice; the
//!   node finds it (`held_rows_for`, role `bound_node`), voices it, and it is
//!   seated: `owner_of` names the operator and the binding is announced at
//!   federation scope (`serve_seat_owner_announced`), carrying
//!   `infra:attest`.
//! - **I4286** the draft and the software producer state ONE row: at the
//!   same instant, the drafted payload is byte-for-byte the payload
//!   `Engine::steward_bind`'s producer states.
//!
//! sqlite and postgres, through the Engine's own verbs.

use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::second_signer_voice::VoiceOutcome;
use crate::federation::self_at_login::{
    check_owner_binding_statement, owner_binding_delegates_to_envelope,
    owner_binding_draft_envelope,
};
use crate::federation::types::{attestation_type, cohort_scope, delegation_scope as ds};
use crate::federation::FederationDirectory;

fn scopes() -> Vec<String> {
    [
        ds::INFRA_SERVE,
        ds::INFRA_NETWORK_PRESENCE,
        ds::INFRA_ATTEST,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).expect("after 1970")
}

/// **I4285.**
pub(crate) async fn i4285_an_owner_binding_signed_outside_the_engine(e: &crate::Engine) {
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let (owner_seed, node_seed) = ("o-i4285", "n-i4285");
    let owner = e2::put_key(d, owner_seed, &["user"]).await;
    let node = e2::put_key(d, node_seed, &["node"]).await;
    assert_eq!(
        e.owner_of(&node).await.expect("I4285: owner_of"),
        None,
        "I4285: unowned before the binding"
    );

    // The owner's half: drafted by the Engine, signed OUTSIDE it.
    let draft = e
        .owner_binding_draft(
            &node,
            &scopes(),
            &owner,
            &hex::encode(e2::kid_digest(owner_seed)),
            now_ms(),
        )
        .await
        .expect("I4285: Engine::owner_binding_draft");
    let statement = draft.assemble(
        e2::signing_key(owner_seed)
            .sign(&draft.sig_structure)
            .expect("I4285: the owner signs outside the Engine"),
    );
    check_owner_binding_statement(
        &statement,
        &owner,
        &node,
        &[ds::INFRA_ATTEST, ds::INFRA_SERVE],
    )
    .expect("I4285: the tool's self-check passes");
    // The self-check catches what a tool would get wrong.
    check_owner_binding_statement(&statement, &node, &node, &[])
        .expect_err("I4285: the self-check names a wrong owner");
    check_owner_binding_statement(&statement, &owner, &owner, &[])
        .expect_err("I4285: the self-check names a wrong node");
    check_owner_binding_statement(&statement, &owner, &node, &["infra:detect"])
        .expect_err("I4285: the self-check names a missing scope");

    let o = e
        .submit_voice(&statement)
        .await
        .expect("I4285: the owner's half is kept");
    assert!(
        matches!(o, VoiceOutcome::Waiting { .. }),
        "I4285: it waits for the node's own voice: {o:?}"
    );
    assert_eq!(
        e.owner_of(&node).await.expect("I4285: owner_of"),
        None,
        "I4285: one voice binds nothing (CC 3.2: the node's own key cosigns)"
    );
    assert!(
        !e.serve_seat_owner_announced(&node)
            .await
            .expect("I4285: reads"),
        "I4285: not announced before the node's voice"
    );

    // The node's half: it finds the row and voices it.
    let rows = e
        .held_rows_for(Some(node.as_str()), Some("bound_node"), None, 10)
        .await
        .expect("I4285: Engine::held_rows_for");
    assert_eq!(rows.len(), 1, "I4285: the node finds its binding: {rows:?}");
    let d2 = e
        .voice_draft(&rows[0].row_id, &node)
        .await
        .expect("I4285: Engine::voice_draft");
    let voice = d2.assemble(
        e2::signing_key(node_seed)
            .sign(&d2.sig_structure)
            .expect("I4285: the node signs"),
    );
    let o = e
        .submit_voice(&voice)
        .await
        .expect("I4285: the node's voice");
    assert!(o.is_seated(), "I4285: both voices seat it: {o:?}");

    assert_eq!(
        e.owner_of(&node).await.expect("I4285: owner_of").as_deref(),
        Some(owner.as_str()),
        "I4285: the operator owns the node"
    );
    assert!(
        e.serve_seat_owner_announced(&node)
            .await
            .expect("I4285: reads"),
        "I4285: announced at federation scope"
    );
    let row = d
        .get_attestation(&rows[0].row_id)
        .await
        .expect("I4285: reads")
        .expect("I4285: the binding landed");
    assert_eq!(row.cohort_scope, cohort_scope::FEDERATION, "I4285: placed");
    assert_eq!(row.attesting_key_id, owner, "I4285: the owner's row");
    assert_eq!(row.attested_key_id, node, "I4285: about the node");
    let carried: Vec<&str> = row
        .attestation_envelope
        .get("scope")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
        .unwrap_or_default();
    assert!(
        carried.contains(&ds::INFRA_ATTEST) && carried.contains(&ds::INFRA_SERVE),
        "I4285: it carries infra:attest and infra:serve: {carried:?}"
    );
}

/// **I4286.**
pub(crate) async fn i4286_the_draft_states_the_software_producers_row(e: &crate::Engine) {
    use crate::federation::tier_ingest::test_support as ts;
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let (owner_seed, node_seed) = ("o-i4286", "n-i4286");
    let owner = e2::put_key(d, owner_seed, &["user"]).await;
    let node = e2::put_key(d, node_seed, &["node"]).await;
    // The software producer's row, as `Engine::steward_bind` builds it
    // (`grant_delegation_in`): not put, only produced.
    let mut input = crate::federation::EmitAttestationInput::with_envelope(
        attestation_type::DELEGATES_TO,
        crate::federation::envelope::EnvelopeCore::from_value(owner_binding_delegates_to_envelope(
            &node,
            &scopes(),
        ))
        .expect("I4286: the envelope"),
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(node.clone());
    let produced = crate::federation::attestation_emit::produce_row(
        d,
        &ts::local_signer(owner_seed),
        input,
        None,
    )
    .await
    .expect("I4286: the software producer states the binding");
    assert_eq!(
        produced.iss, owner,
        "I4286 premise: the software signer is the same owner key"
    );
    let draft = e
        .owner_binding_draft(
            &node,
            &scopes(),
            &owner,
            &hex::encode(e2::kid_digest(owner_seed)),
            produced.asserted_at_ms,
        )
        .await
        .expect("I4286: the draft");
    assert_eq!(
        draft.payload,
        ciris_verify_core::cde::encode(&produced.payload),
        "I4286: one row, whichever producer states it"
    );
    assert_eq!(produced.sub, node, "I4286: about the node");
    let _ = owner_binding_draft_envelope(&node, &[])
        .expect_err("I4286: an owner binding with no scope is not drafted");
    let _ = owner_binding_draft_envelope(&node, &["agent:act".to_owned()])
        .expect_err("I4286: a scope outside infra:* is not drafted");
}

#[cfg(feature = "sqlite")]
async fn sqlite_engine(seed: &str) -> crate::Engine {
    crate::Engine::with_signer(
        crate::federation::tier_ingest::test_support::local_signer(seed),
        "sqlite::memory:",
    )
    .await
    .expect("a sqlite Engine")
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4285_sqlite() {
    Box::pin(i4285_an_owner_binding_signed_outside_the_engine(
        &sqlite_engine("i4285-engine").await,
    ))
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4286_sqlite() {
    Box::pin(i4286_the_draft_states_the_software_producers_row(
        &sqlite_engine("i4286-engine").await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
async fn pg_engine(seed: &str) -> Option<crate::Engine> {
    let dsn = crate::test_pg::isolated_dsn()?;
    Some(
        crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(seed),
            &dsn,
        )
        .await
        .expect("a postgres Engine"),
    )
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4285_postgres() {
    let Some(e) = pg_engine("i4285-engine").await else {
        return;
    };
    Box::pin(i4285_an_owner_binding_signed_outside_the_engine(&e)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4286_postgres() {
    let Some(e) = pg_engine("i4286-engine").await else {
        return;
    };
    Box::pin(i4286_the_draft_states_the_software_producers_row(&e)).await;
}
