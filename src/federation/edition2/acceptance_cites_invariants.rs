//! v62.0.0 (DUTY-D7a; CC 3.2 "the owner's acceptance": "It names in
//! refs.also.cites the owner-binding it is made under"; Constitution's Q2
//! ruling 11-24: exactly ONE row, the binding placed where the acceptance is
//! placed) — **a root grant's acceptance cites the owner binding**, through
//! the producer (`membership_acceptance::root_grant_reply_input`):
//!
//! - **I6641** — an ANNOUNCED machine (its owner binding at `federation`):
//!   the default draft cites that binding, the acceptance lands, and the
//!   stored row projects the cite back (`owner_binding_ref`).
//! - **I6642** — an UNANNOUNCED machine (its only binding at `self`): the
//!   default draft is REFUSED; with the row named (`owner_binding_ref`) it
//!   cites it and lands.
//! - **I6643** — a PERSON grantee: the acceptance cites nothing.
//!
//! Where the acceptance STANDS (a stranger holding the federation row; a
//! reader without the cited row WAITS; the handover) is the reader's,
//! DUTY-D7.

use chrono::Utc;

use super::fixture_genesis::install_v2;
use super::fixture_occurrence::put_agent_owner_binding_placed;
use super::fixture_switch as e2;
use super::scope_resolution_invariants::land_grant;
use crate::federation::membership_acceptance::{
    root_grant_acceptance_cites, root_grant_reply_input,
};
use crate::federation::types::cohort_scope as cs;
use crate::federation::FederationDirectory;

const SCOPE: &str = "infra:attest:build:registered";

fn at_ms() -> u64 {
    u64::try_from((Utc::now() - chrono::Duration::minutes(5)).timestamp_millis())
        .expect("after 1970")
}

async fn grant_to(
    d: &dyn FederationDirectory,
    grantee: &str,
    what: &str,
) -> crate::federation::Attestation {
    let head = install_v2(d).await.expect("installs").object_id;
    let at = super::scope_resolution_invariants::grant_instant(d).await;
    land_grant(d, grantee, SCOPE, &head, at, what).await
}

async fn accept(
    d: &dyn FederationDirectory,
    owner_seed: &str,
    input: crate::federation::types::EmitAttestationInput,
    what: &str,
) -> crate::federation::Attestation {
    let signer = crate::federation::tier_ingest::test_support::local_signer(owner_seed);
    let out = crate::federation::attestation_emit::emit_with_local_signer(d, &signer, input)
        .await
        .unwrap_or_else(|e| panic!("{what}: the acceptance: {e}"));
    d.get_attestation(&out.attestation_id)
        .await
        .expect("reads")
        .unwrap_or_else(|| panic!("{what}: the acceptance LANDS"))
}

/// **I6641.**
pub(crate) async fn i6641_an_announced_machine_cites_its_federation_binding(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let _ = e2::put_key(d, "i6641-owner", &["user"]).await;
    let agent = e2::put_key(d, "i6641-agent", &["agent"]).await;
    let binding = put_agent_owner_binding_placed(
        d,
        "i6641-owner",
        "i6641-agent",
        at_ms(),
        cs::FEDERATION,
        None,
    )
    .await;
    let grant = grant_to(d, &agent, "I6641").await;
    let input = root_grant_reply_input(d, &grant, true, None)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6641: the default draft: {e}"));
    assert_eq!(
        input
            .attestation_envelope
            .extra
            .get(super::payloads::OWNER_BINDING_REF_MEMBER),
        Some(&serde_json::json!(binding.hex())),
        "[{tag}] I6641: the default draft cites the federation-placed binding"
    );
    let row = accept(d, "i6641-owner", input, "I6641").await;
    assert_eq!(
        row.attestation_envelope
            .get(super::payloads::OWNER_BINDING_REF_MEMBER),
        Some(&serde_json::json!(binding.hex())),
        "[{tag}] I6641: the stored acceptance projects its refs.also.cites back"
    );
}

/// **I6642.**
pub(crate) async fn i6642_an_unannounced_machine_names_its_row_or_is_refused(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let _ = e2::put_key(d, "i6642-owner", &["user"]).await;
    let agent = e2::put_key(d, "i6642-agent", &["agent"]).await;
    let binding =
        put_agent_owner_binding_placed(d, "i6642-owner", "i6642-agent", at_ms(), cs::SELF, None)
            .await;
    let grant = grant_to(d, &agent, "I6642").await;
    let refused = root_grant_reply_input(d, &grant, true, None).await;
    assert!(
        refused
            .as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("no federation-placed owner binding")),
        "[{tag}] I6642: the default draft for an unannounced machine is refused: {:?}",
        refused.map(|i| i.attestation_envelope.extra)
    );
    let input = root_grant_reply_input(d, &grant, true, Some(&binding.hex()))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6642: the named row: {e}"));
    let row = accept(d, "i6642-owner", input, "I6642").await;
    assert_eq!(
        row.attestation_envelope
            .get(super::payloads::OWNER_BINDING_REF_MEMBER),
        Some(&serde_json::json!(binding.hex())),
        "[{tag}] I6642: with the row named, the acceptance cites it and lands"
    );
    let stranger = e2::put_key(d, "i6642-stranger", &["user"]).await;
    assert!(
        root_grant_acceptance_cites(d, &agent, Some(&stranger))
            .await
            .is_err(),
        "[{tag}] I6642: a named row that is no owner binding over the grantee is refused"
    );
}

/// **I6643.**
pub(crate) async fn i6643_a_persons_acceptance_cites_nothing(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let person = e2::put_key(d, "i6643-person", &["user"]).await;
    assert_eq!(
        root_grant_acceptance_cites(d, &person, None)
            .await
            .expect("the read"),
        None,
        "[{tag}] I6643: a person's acceptance cites nothing"
    );
}

/// **I6644** (DUTY-D7a2, pure) — the hardware-pen draft
/// (`membership_acceptance::reply_envelope`) REFUSES a root-grant acceptance
/// for a machine grantee whose input carries no cite, drafts it with the
/// cite, and drafts a person's (no cite) and any non-root reply unchanged.
#[test]
fn i6644_the_hardware_pen_draft_refuses_an_uncited_machine_acceptance() {
    use crate::federation::envelope::EnvelopeCore;
    use crate::federation::membership_acceptance::{reply_envelope, ACCEPTANCE_DIMENSION};
    use crate::federation::types::{attestation_type, EmitAttestationInput};
    let input = |scope: &str, cite: bool| {
        let mut env = EnvelopeCore {
            dimension: Some(ACCEPTANCE_DIMENSION.to_owned()),
            references_attestation_id: Some("ab".repeat(32)),
            ..EnvelopeCore::default()
        };
        if cite {
            env.extra.insert(
                super::payloads::OWNER_BINDING_REF_MEMBER.to_owned(),
                serde_json::json!("cd".repeat(32)),
            );
        }
        EmitAttestationInput::with_envelope(attestation_type::SCORES, env, scope.to_owned())
    };
    assert!(
        reply_envelope(&input(cs::FEDERATION, false), true).is_err(),
        "I6644: a machine's uncited root-grant acceptance is refused"
    );
    let drafted = reply_envelope(&input(cs::FEDERATION, true), true).expect("I6644: cited");
    assert_eq!(
        drafted.get(super::payloads::OWNER_BINDING_REF_MEMBER),
        Some(&serde_json::json!("cd".repeat(32))),
        "I6644: the cite rides the draft"
    );
    assert!(
        reply_envelope(&input(cs::FEDERATION, false), false).is_ok(),
        "I6644: a person's acceptance cites nothing and drafts"
    );
    assert!(
        reply_envelope(&input(cs::COMMUNITY, false), true).is_ok(),
        "I6644: a group reply is not a root grant's acceptance"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use crate::store::Backend as _;

    async fn store() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i6641_an_announced_machine_cites_its_federation_binding_sqlite() {
        Box::pin(
            super::i6641_an_announced_machine_cites_its_federation_binding(
                &store().await,
                "sqlite",
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn i6642_an_unannounced_machine_names_its_row_or_is_refused_sqlite() {
        Box::pin(
            super::i6642_an_unannounced_machine_names_its_row_or_is_refused(
                &store().await,
                "sqlite",
            ),
        )
        .await;
    }

    #[tokio::test]
    async fn i6643_a_persons_acceptance_cites_nothing_sqlite() {
        Box::pin(super::i6643_a_persons_acceptance_cites_nothing(
            &store().await,
            "sqlite",
        ))
        .await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use crate::store::Backend as _;

    async fn store() -> Option<crate::store::postgres::PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i6641_an_announced_machine_cites_its_federation_binding_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::i6641_an_announced_machine_cites_its_federation_binding(&b, "postgres"))
            .await;
    }

    #[tokio::test]
    async fn i6642_an_unannounced_machine_names_its_row_or_is_refused_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::i6642_an_unannounced_machine_names_its_row_or_is_refused(&b, "postgres"))
            .await;
    }

    #[tokio::test]
    async fn i6643_a_persons_acceptance_cites_nothing_postgres() {
        let Some(b) = store().await else { return };
        Box::pin(super::i6643_a_persons_acceptance_cites_nothing(
            &b, "postgres",
        ))
        .await;
    }
}
