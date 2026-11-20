//! v62.0.0 (wave GC2; CC 2.7.3) — witnesses of the attestation door's fold
//! conversions: a gate that reads OTHER rows holds the row (kept, concluding
//! nothing, its refusal's token as the reason) instead of refusing it, and
//! re-folds when what it read changes. Store-facing bodies run on sqlite and
//! postgres.
//!
//! - **I3710** the reason tokens the wave appends are each the refusal token
//!   the gate raised before it held (so an adopter keyed on the refusal reads
//!   the same text as a reason), and the takedown authority maps exactly its
//!   two tokens to fold reasons.
//! - **I3711** the read-key spellings: `key:content:<hex>` and
//!   `key:blob:<hex>`; a row whose `evidence_refs` names a digest touches its
//!   content key in either spelling (the earlier form's bare hex, an
//!   edition-2 projection's `[-16, "<hex>"]`), and both spellings bind the
//!   content (`admission::envelope_binds_content`).
//! - **I3712** the takedown notice FIRST: a `dmca512` notice over content no
//!   held row binds is HELD (`Pending`, no typed row, reason
//!   `takedown_content_unbound`); its claimant's own row binding the content
//!   lands and the re-fold CONCLUDES the notice; the claimant withdraws the
//!   binding and the notice is UN-concluded (no typed row, held, reason
//!   `takedown_unauthorised`: the binding is held but retired).
//! - **I3713** the binding FIRST: the same notice concludes on arrival, the
//!   same concluded set as I3712 reached by the other arrival order.

use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::fold::{self, reason};
use crate::federation::edition2::ingest::StatementOutcome;
use crate::federation::edition2::names::RowId;
use crate::federation::types::{attestation_type, identity_type, Attestation};
use crate::federation::{Error, FederationDirectory};

/// I3710: each appended reason is the refusal token it replaces.
#[test]
fn i3710_reasons_are_the_refusal_tokens_they_replace() {
    use crate::federation::takedown_tombstone::token;
    assert_eq!(
        reason::COSIGN_SIGNATURE_IRREVOCABLE,
        crate::federation::cosign::COSIGN_SIGNATURE_IRREVOCABLE,
        "I3710: cosign"
    );
    assert_eq!(
        reason::TAKEDOWN_CONTENT_UNBOUND,
        token::CONTENT_UNBOUND,
        "I3710: takedown unbound"
    );
    assert_eq!(
        reason::TAKEDOWN_UNAUTHORISED,
        token::UNAUTHORISED,
        "I3710: takedown unauthorised"
    );
    assert_eq!(
        reason::CUSTODY_ACK_SCOPE_MISMATCH,
        crate::federation::holding_claim::CUSTODY_ACK_SCOPE_MISMATCH,
        "I3710: holding claim scope"
    );
    assert_eq!(
        reason::CARRIER_WITHOUT_ROSTER_QUORUM,
        crate::federation::malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM,
        "I3710: carrier"
    );
    assert_eq!(
        reason::TRUST_BELOW_THRESHOLD,
        Error::TrustBelowThreshold {
            key_id: "k".to_owned(),
            score: 0.0,
            threshold: 1.0,
        }
        .kind(),
        "I3710: trust threshold"
    );
    assert_eq!(
        reason::gc2::ALL,
        &[
            "cosign_signature_irrevocable",
            "federation_trust_below_threshold",
            "takedown_content_unbound",
            "takedown_unauthorised",
            "custody_ack_scope_mismatch",
            "carrier_without_roster_quorum",
            "genesis_record_rivals",
        ],
        "I3710: GC2's slice, appended, never reordered"
    );
    for r in reason::gc2::ALL {
        assert!(reason::is_registered(r), "I3710: {r} is in the registry");
    }
    assert!(
        reason::ALL.contains(&reason::SELF_ROSTER_NOT_LANDED),
        "I3710: the self-roster eviction uses the core token"
    );
    // A hold outside an attempt is the plain refusal (the earlier-form door
    // keeps its behaviour).
    let e = fold::hold(
        reason::TAKEDOWN_CONTENT_UNBOUND,
        Error::PurgeRefused {
            token: token::CONTENT_UNBOUND,
            body: serde_json::json!({}),
        },
    );
    assert_eq!(e.kind(), token::CONTENT_UNBOUND, "I3710: unchanged");
}

/// I3711: the read keys, and both `evidence_refs` spellings.
#[test]
fn i3711_content_and_blob_read_keys() {
    let hex = "ab".repeat(32);
    assert_eq!(
        crate::federation::takedown_tombstone::content_dep(&hex).read_key(),
        format!("key:content:{hex}"),
        "I3711: the content key"
    );
    assert_eq!(
        crate::federation::holding_claim::blob_dep(&[0xab; 32]).read_key(),
        format!("key:blob:{hex}"),
        "I3711: the blob key"
    );
    let mut row = crate::federation::genesis::ordinary_scores_row("i3711", "k");
    for refs in [
        serde_json::json!([hex.clone()]),
        serde_json::json!([[-16, hex.clone()]]),
    ] {
        row.attestation_envelope = serde_json::json!({
            "dimension": "config:load:v1",
            "score": 1.0,
            "evidence_refs": refs,
        });
        assert!(
            fold::touches_of_attestation(&row).contains(&format!("key:content:{hex}")),
            "I3711: the row touches its content ({refs})"
        );
        assert!(
            crate::federation::admission::envelope_binds_content(&row.attestation_envelope, &hex),
            "I3711: the row binds its content ({refs})"
        );
    }
}

fn id_of_statement(st: &[u8]) -> RowId {
    RowId::of_statement(st).expect("I3712: a statement's row id")
}

fn id_of_row(row: &Attestation) -> RowId {
    crate::federation::edition2::voices::carried_row_id(row)
        .expect("I3712: the row carries its statement")
}

/// The claimant's own row binding `sha_hex` (its `evidence_refs`), about
/// itself: a `config:*` self-report, the one row family whose only gate on a
/// self-report is free.
fn binding_row(claimant: &str, sha_hex: &str) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(claimant),
    );
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": "config:load:v1",
        "score": 1.0,
        "evidence_refs": [sha_hex],
    });
    e2::row_of(&a, claimant)
}

/// The claimant's `dmca512` notice over `sha`.
fn notice(claimant: &str, sha: &[u8; 32]) -> Vec<u8> {
    let now = crate::host::clock::now();
    crate::federation::edition2::typed_fixtures::takedown_statement(
        claimant,
        "dmca512",
        claimant,
        sha,
        &[claimant],
        now + chrono::Duration::days(7),
        e2::ms(now),
    )
}

async fn concluded(d: &dyn FederationDirectory, id: &RowId) -> bool {
    d.get_attestation(&id.hex()).await.unwrap().is_some()
}

async fn reason_of(d: &dyn FederationDirectory, id: &RowId) -> Option<String> {
    fold::why_held(d, id).await.unwrap().map(|h| h.reason)
}

fn is_row(o: &StatementOutcome) -> bool {
    matches!(o, StatementOutcome::Row { .. })
}

/// I3712: notice first; held, concluded by the binding, un-concluded by its
/// withdrawal.
pub(crate) async fn notice_first_body(d: &dyn FederationDirectory) {
    let claimant = "gc2-td1-c";
    let _ = e2::put_key(d, claimant, &[identity_type::USER]).await;
    let sha = [0x71; 32];
    let st = notice(claimant, &sha);
    let n = id_of_statement(&st);

    let o = e2::put_statement(d, &st)
        .await
        .expect("I3712: a notice over unbound content is HELD, never refused");
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "I3712: held: {o:?}"
    );
    assert!(!concluded(d, &n).await, "I3712: no typed row");
    assert_eq!(
        reason_of(d, &n).await.as_deref(),
        Some(reason::TAKEDOWN_CONTENT_UNBOUND),
        "I3712: the reason"
    );
    assert!(
        !d.edition2_voices(&n).await.unwrap().is_empty(),
        "I3712: its statement is kept"
    );

    // The claimant's row binding the content lands: the notice re-folds.
    let binding = binding_row(claimant, &hex::encode(sha));
    let o = e2::put_signed(d, &binding)
        .await
        .expect("I3712: the binding row");
    assert!(is_row(&o), "I3712: the binding concludes: {o:?}");
    assert!(
        concluded(d, &n).await,
        "I3712: the notice CONCLUDES once a held row binds the content to its signer"
    );
    assert_eq!(reason_of(d, &n).await, None, "I3712: no reason left");

    // The claimant withdraws the binding: the content is bound to nobody
    // live, and the notice is taken out of its typed table.
    let w = e2::composer_of(attestation_type::WITHDRAWS, &binding, claimant);
    let o = e2::put_signed(d, &w)
        .await
        .expect("I3712: the claimant's withdrawal of its binding");
    assert!(is_row(&o), "I3712: the withdrawal concludes: {o:?}");
    assert!(
        !concluded(d, &n).await,
        "I3712: the notice is UN-concluded: no typed row"
    );
    // The fold re-derives the notice from what is held now: no live row binds
    // the content to anyone, so the reason is the one it was first held for.
    assert_eq!(
        reason_of(d, &n).await.as_deref(),
        Some(reason::TAKEDOWN_CONTENT_UNBOUND),
        "I3712: held, and says why (the binding is retired: the content is bound to nobody)"
    );
    assert!(
        !d.edition2_voices(&n).await.unwrap().is_empty(),
        "I3712: its statement is still kept"
    );
    let _ = id_of_row(&binding);
}

/// I3713: binding first; the notice concludes on arrival.
pub(crate) async fn binding_first_body(d: &dyn FederationDirectory) {
    let claimant = "gc2-td2-c";
    let _ = e2::put_key(d, claimant, &[identity_type::USER]).await;
    let sha = [0x72; 32];
    let binding = binding_row(claimant, &hex::encode(sha));
    let o = e2::put_signed(d, &binding)
        .await
        .expect("I3713: the binding row");
    assert!(is_row(&o), "I3713: the binding concludes: {o:?}");

    let st = notice(claimant, &sha);
    let n = id_of_statement(&st);
    let o = e2::put_statement(d, &st)
        .await
        .expect("I3713: the notice over bound content");
    assert!(is_row(&o), "I3713: concluded on arrival: {o:?}");
    assert!(
        concluded(d, &n).await && concluded(d, &id_of_row(&binding)).await,
        "I3713: both rows concluded, as I3712 reached in the other order"
    );
    assert_eq!(reason_of(d, &n).await, None, "I3713: no reason");
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
    i3712_takedown_notice_first_held_concluded_unconcluded_sqlite,
    i3712_takedown_notice_first_held_concluded_unconcluded_postgres,
    notice_first_body
);
both!(
    i3713_takedown_binding_first_concludes_on_arrival_sqlite,
    i3713_takedown_binding_first_concludes_on_arrival_postgres,
    binding_first_body
);

/// I3714 (CC rc21 ruling 8, CC 4.5.3) — a tombstone is a deletion duty while
/// it STANDS: `takedown_tombstone::standing_tombstone` names the notice while
/// no admitted reversal lifts it, answers `None` once the review-holder's
/// `reversed` ruling is held (the record is taken again; the tombstone row
/// itself stays), and names it again when the ruling is withdrawn. The trace
/// door (`ingest.rs::refuse_named_traces`) and every keep/serve decision ask
/// this, never the bare tombstone row.
pub(crate) async fn standing_tombstone_body<D>(d: &D, tag: &str)
where
    D: FederationDirectory + Sync,
{
    use crate::federation::doors_takedown_invariants::bodies::{claimant, community_of, notice};
    use crate::federation::takedown_reversal_invariants::bodies::{
        bind_into, put, ruling, sha_hex, NODE,
    };
    use crate::federation::takedown_tombstone as td;
    use crate::federation::types::cohort_scope;
    let dir = d.as_dyn_directory();
    let moderator = claimant(0xb1);
    let comm = format!("i3714-comm-{tag}");
    community_of(dir, &comm, &moderator.id).await;
    let sha = sha_hex(&format!("i3714-{tag}"));
    assert_eq!(
        td::standing_tombstone(dir, "blob", &sha).await.unwrap(),
        None,
        "I3714: nothing tombstoned"
    );
    bind_into(dir, &moderator.id, &comm, &sha).await;
    let r = td::takedown_tombstone(dir, &notice(&moderator, &sha, "dmca512"), NODE)
        .await
        .expect("I3714: the moderator's takedown");
    let notice_row = r.notice_attestation_id.clone().expect("a notice row");
    assert_eq!(
        td::standing_tombstone(dir, "blob", &sha).await.unwrap(),
        Some(r.notice_id.clone()),
        "I3714: the tombstone stands"
    );
    let reversal = ruling(
        &moderator.id,
        &notice_row,
        "reversed",
        cohort_scope::COMMUNITY,
        &comm,
    );
    let reversal_id = reversal.attestation_id.clone();
    put(dir, reversal).await.expect("I3714: the reversal");
    assert_eq!(
        td::standing_tombstone(dir, "blob", &sha).await.unwrap(),
        None,
        "I3714: a reversal lifts the duty; the record is taken again"
    );
    assert!(
        dir.purge_tombstoned("blob", &sha).await.unwrap().is_some(),
        "I3714: the tombstone row itself stays"
    );
    crate::federation::tier_ingest::test_support::put_retraction(
        dir,
        &moderator.id,
        &moderator.id,
        &reversal_id,
        "withdraws",
    )
    .await
    .expect("I3714: the ruling's author withdraws it");
    assert_eq!(
        td::standing_tombstone(dir, "blob", &sha).await.unwrap(),
        Some(r.notice_id),
        "I3714: a withdrawn reversal lifts nothing"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3714_standing_tombstone_follows_its_reversal_sqlite() {
    let b = sqlite().await;
    crate::federation::hard_case::test_support::declare_node(
        &b,
        crate::federation::takedown_reversal_invariants::bodies::NODE,
    )
    .await;
    Box::pin(standing_tombstone_body(
        &b,
        &uuid::Uuid::new_v4().simple().to_string()[..8],
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3714_standing_tombstone_follows_its_reversal_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    crate::federation::hard_case::test_support::declare_node(
        &b,
        crate::federation::takedown_reversal_invariants::bodies::NODE,
    )
    .await;
    Box::pin(standing_tombstone_body(
        &b,
        &uuid::Uuid::new_v4().simple().to_string()[..8],
    ))
    .await;
}
