//! v62.0.0 (R2-delegation; CC 3.2 T2, Constitution 11-24 "CONSTITUTION RULED
//! THE DELEGATION ARM") — **the delegation plane at the capability walk**
//! (`trust_root::capability_roots_to_trusted_root` → `delegation_conferral` →
//! `kernel::delegation::stands`), through the real doors, on sqlite and
//! postgres. The root's counted grant to G (accepted) carries `infra:serve`;
//! G's edge to D and D's edge to E are authored `delegates_to` rows labelled
//! `trust:confers:v1`, each landed with its delegate's own voice.
//!
//! - **I6430** G's grant carries `sub_delegation`, G → D carries it too and a
//!   live term: D holds `infra:serve` on the DELEGATION plane, and so does E
//!   (two hops), each answered as the root's lineage and the grant's row.
//! - **I6431** a grant WITHOUT `sub_delegation`: its grantee's delegate holds
//!   nothing.
//! - **I6432** the term is persist's check: read after G → D's
//!   `delegation_valid_until`, neither D nor E holds anything (the kernel
//!   reads only the seating offer's own instants; persist drops the edge).
//! - **I6433** G withdraws its edge to D: D and E hold nothing.
//! - **I6438** (R2-delegation-b) peer rooting asks the delegation plane: D,
//!   seated through the live chain, reads ROOTED on `Plane::Delegation`.
//!
//! v62.0.0 (R2-delegation-b; Constitution 11-24, the skip REVERSED) — every
//! leg above runs under a TEST bundle whose charter carries
//! `sub_delegation` ([`deputizing_bundle`]: the production charter scope
//! plus the word), installed before the root is stood up. None passes by a
//! charter skip: the check is whole and per element.
//! - **I6437** under a charter WITHOUT the word (`bundle_v2_wide`, the
//!   production scope): a counted grant carrying `sub_delegation` lands and
//!   confers its covered duty on the grantee (CEREMONY plane), and NO onward
//!   hop stands.

use super::fixture_genesis as fg;
use super::fixture_switch as e2;
use crate::federation::trust_root::{ConferralPlane, INFRA_SERVE_SCOPE};
use crate::federation::types::{attestation_tier, attestation_type, Attestation};
use crate::federation::FederationDirectory;
use crate::kernel::delegation::SUB_DELEGATION;
use chrono::{DateTime, Duration, Utc};

/// The walk's answer for `subject` holding `infra:serve` at `at`, from THIS
/// node: the plane and the conferring row.
async fn conferring(
    d: &dyn FederationDirectory,
    subject: &str,
    at: DateTime<Utc>,
) -> Option<(ConferralPlane, String)> {
    let node = d.node_key_id().expect("the runner set the node key");
    crate::federation::trust_root::capability_roots_to_trusted_root(
        d,
        &node,
        subject,
        INFRA_SERVE_SCOPE,
        at,
    )
    .await
    .expect("the walk reads")
    .map(|g| (g.conferral_plane, g.grant_attestation_id))
}

/// `from_seed`'s authored `delegates_to` to `to` (a key), labelled
/// `trust:confers:v1`, carrying `scope` and, when given, a term ending at
/// `until`; landed with `to_seed`'s own voice. Returns the edge's statement.
async fn put_edge(
    d: &dyn FederationDirectory,
    from_seed: &str,
    to_seed: &str,
    scope: &[&str],
    until: Option<DateTime<Utc>>,
) -> Vec<u8> {
    let from = e2::kid(from_seed);
    let to = e2::kid(to_seed);
    let now = Utc::now();
    let mut envelope = serde_json::json!({
        "dimension": crate::federation::trust_root::TRUST_CONFERS_DIMENSION,
        "scope": scope,
        "author": from,
    });
    if let Some(u) = until {
        envelope["delegation_valid_until"] =
            serde_json::Value::String(u.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    }
    let a = Attestation {
        attestation_id: uuid::Uuid::new_v4().to_string(),
        attesting_key_id: from.clone(),
        attested_key_id: to,
        attestation_type: attestation_type::DELEGATES_TO.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: from,
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    let row = e2::row_of(&a, from_seed);
    let _ = e2::land_with_voices(d, &row, &[to_seed])
        .await
        .unwrap_or_else(|e| panic!("the edge {from_seed} -> {to_seed} lands: {e}"));
    assert!(
        d.get_attestation(&row.attestation_id)
            .await
            .expect("reads")
            .is_some(),
        "precondition: the edge {from_seed} -> {to_seed} concluded"
    );
    e2::carried_statement(&row).expect("the edge carries its statement")
}

/// `author_seed`'s `withdraws` of the row `edge` is a voice of.
async fn withdraw(d: &dyn FederationDirectory, author_seed: &str, edge: &[u8]) {
    use ciris_verify_core::cde::Value;
    let (protected, _) = super::liveness::statement_parts(edge).expect("a statement");
    let family = protected
        .get_int(-70002)
        .and_then(Value::as_text)
        .expect("a family")
        .to_owned();
    let sub = protected
        .get_int(15)
        .and_then(|c| c.get_int(2))
        .and_then(Value::as_text)
        .expect("sub")
        .to_owned();
    let target = super::group_fixtures::row_id_of(edge);
    let author = e2::kid(author_seed);
    let st = ciris_verify_core::edition2::sign_row_statement(
        &e2::signing_key(author_seed),
        &author,
        &sub,
        attestation_type::WITHDRAWS,
        &family,
        &super::typed::withdraws_payload(&author, &target, e2::ms(Utc::now())),
        vec![],
    )
    .expect("the withdraws signs");
    e2::put_statement(d, &st)
        .await
        .unwrap_or_else(|e| panic!("the edge's own signer withdraws it: {e}"));
}

/// The TEST bundle whose charter carries `sub_delegation`: `bundle_v2`'s
/// ceremony with the production charter scope plus the word (Eric decides
/// whether the successor production charter gains it).
fn deputizing_bundle() -> &'static fg::TestCeremonyV2 {
    static B: std::sync::OnceLock<fg::TestCeremonyV2> = std::sync::OnceLock::new();
    B.get_or_init(|| {
        let mut scope = fg::production_charter_scope();
        scope.push(SUB_DELEGATION.to_owned());
        fg::ceremony_v2_with_scope(&fg::CeremonySpec::standard(), &scope)
    })
}

/// I6430–I6433 and I6438, one body.
pub(crate) async fn delegation_plane_body(d: &dyn FederationDirectory, tag: &str) {
    fg::install_ceremony_v2(d, deputizing_bundle())
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the deputizing test bundle installs: {e}"));
    let r = super::fixture_trust_root::rooted_trust_root(d, &fg::HOLDER_SEEDS, "quorum:2/3").await;
    let (g, dd, ee) = (
        format!("dp-g-{tag}"),
        format!("dp-d-{tag}"),
        format!("dp-e-{tag}"),
    );
    for s in [&dd, &ee] {
        let _ = e2::put_key(d, s, &["user"]).await;
    }
    let grant =
        super::fixture_trust_root::put_conferral(d, &r, &g, &[INFRA_SERVE_SCOPE, SUB_DELEGATION])
            .await
            .expect(
                "I6430 precondition: the root's counted grant with sub_delegation lands, accepted",
            );
    let now = Utc::now();
    let until = now + Duration::hours(1);
    let g_to_d = put_edge(
        d,
        &g,
        &dd,
        &[INFRA_SERVE_SCOPE, SUB_DELEGATION],
        Some(until),
    )
    .await;
    let _ = put_edge(d, &dd, &ee, &[INFRA_SERVE_SCOPE], None).await;

    // I6430.
    let want = Some((ConferralPlane::Delegation, grant.hex()));
    assert_eq!(
        conferring(d, &e2::kid(&dd), now).await,
        want,
        "[{tag}] I6430: G's delegate holds infra:serve on the delegation plane"
    );
    assert_eq!(
        conferring(d, &e2::kid(&ee), now).await,
        want,
        "[{tag}] I6430: two hops down"
    );

    // I6438 — peer rooting reads the same chain.
    {
        use super::peer_rooting::{peer_rooting, ClaimedKeyWire, PeerRooting, Plane};
        let node = d.node_key_id().expect("the runner set the node key");
        let wire = ClaimedKeyWire::Composite(e2::signing_key(&dd).public_key().as_bytes().to_vec());
        let parsed = wire.composite().expect("a fixture claim parses");
        let claim = wire.as_claim(parsed.as_ref()).expect("a claim");
        let v = Box::pin(peer_rooting(d, &node, &e2::kid(&dd), claim, e2::ms(now)))
            .await
            .expect("peer_rooting reads");
        assert!(
            matches!(v, PeerRooting::Rooted { plane: Plane::Delegation, .. }),
            "[{tag}] I6438: a seat through a live chain reads rooted on the delegation plane: {v:?}"
        );
    }

    // I6431.
    let (g2, d2) = (format!("dp-g2-{tag}"), format!("dp-d2-{tag}"));
    let _ = e2::put_key(d, &d2, &["user"]).await;
    let _ = super::fixture_trust_root::put_conferral(d, &r, &g2, &[INFRA_SERVE_SCOPE])
        .await
        .expect("I6431 precondition: a grant without sub_delegation lands");
    let _ = put_edge(d, &g2, &d2, &[INFRA_SERVE_SCOPE], None).await;
    assert_eq!(
        conferring(d, &e2::kid(&d2), now).await,
        None,
        "[{tag}] I6431: no onward hop from a grant without sub_delegation"
    );

    // I6432.
    let later = until + Duration::minutes(1);
    assert_eq!(
        conferring(d, &e2::kid(&dd), later).await,
        None,
        "[{tag}] I6432: past G -> D's term, D holds nothing"
    );
    assert_eq!(
        conferring(d, &e2::kid(&ee), later).await,
        None,
        "[{tag}] I6432: and nothing below it stands (persist's own term check)"
    );

    // I6433.
    withdraw(d, &g, &g_to_d).await;
    let after = Utc::now() + Duration::seconds(1);
    for k in [&dd, &ee] {
        assert_eq!(
            conferring(d, &e2::kid(k), after).await,
            None,
            "[{tag}] I6433: G withdrew its edge to D: {k} holds nothing"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6430_i6433_the_delegation_plane_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .expect("sqlite");
    b.run_migrations().await.expect("migrations");
    b.set_node_key_id(e2::put_key(&b, "dp-node-sq", &["node"]).await);
    Box::pin(delegation_plane_body(&b, "sq")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6430_i6433_the_delegation_plane_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .expect("pg");
    b.run_migrations().await.expect("migrations");
    b.set_node_key_id(e2::put_key(&b, "dp-node-pg", &["node"]).await);
    Box::pin(delegation_plane_body(&b, "pg")).await;
}

/// I6437 — under the PRODUCTION charter scope (no `sub_delegation`).
pub(crate) async fn no_word_no_chain_body(d: &dyn FederationDirectory, tag: &str) {
    let r = super::fixture_trust_root::rooted_trust_root(d, &fg::HOLDER_SEEDS, "quorum:2/3").await;
    let (g, dd) = (format!("dp7-g-{tag}"), format!("dp7-d-{tag}"));
    let _ = e2::put_key(d, &dd, &["user"]).await;
    let grant =
        super::fixture_trust_root::put_conferral(d, &r, &g, &[INFRA_SERVE_SCOPE, SUB_DELEGATION])
            .await
            .expect("I6437: a grant whose covered duty the charter covers lands (per element)");
    let now = Utc::now();
    assert_eq!(
        conferring(d, &e2::kid(&g), now).await,
        Some((ConferralPlane::Ceremony, grant.hex())),
        "[{tag}] I6437: the covered duty confers on the grantee"
    );
    let _ = put_edge(
        d,
        &g,
        &dd,
        &[INFRA_SERVE_SCOPE],
        Some(now + Duration::hours(1)),
    )
    .await;
    assert_eq!(
        conferring(d, &e2::kid(&dd), now).await,
        None,
        "[{tag}] I6437: sub_delegation outside the charter starts no chain"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i6437_no_word_no_chain_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .expect("sqlite");
    b.run_migrations().await.expect("migrations");
    b.set_node_key_id(e2::put_key(&b, "dp7-node-sq", &["node"]).await);
    Box::pin(no_word_no_chain_body(&b, "sq")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i6437_no_word_no_chain_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .expect("pg");
    b.run_migrations().await.expect("migrations");
    b.set_node_key_id(e2::put_key(&b, "dp7-node-pg", &["node"]).await);
    Box::pin(no_word_no_chain_body(&b, "pg")).await;
}
