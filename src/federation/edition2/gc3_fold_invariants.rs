//! v62.0.0 (wave GC3; CC 2.7.3) — witnesses of GC3's conversions to the
//! held/concluded fold ([`super::fold`]). Each store-facing body runs on
//! sqlite and postgres. A gate-level body runs the gate as a fold attempt
//! (`fold::attempt`, the edition-2 door's tail) over a directory state
//! WITHOUT the input it reads, then WITH it, then without it again: held,
//! concluded, held — and the same answer whichever order the inputs land in.
//!
//! - **I3750** every reason GC3 holds a row with is registered (the core's
//!   `link_unheld` / `self_roster_not_landed`, or GC3's own `reason::gc3`
//!   slice), and the reclaim ceremony's refusals split into the
//!   fold ones (a reason) and the door/LOCAL ones (none).
//! - **I3751** a roster read of a community or family declares `key:<id>`
//!   and, because a caller swallows its unknown-group answer, marks nothing
//!   (G0 ruling 4).
//! - **I3752** a self-roster receipt for a proposal this node does not hold
//!   is held `self_roster_not_landed`, reading the proposal's `row:<id>`.
//! - **I3753** rival withdrawal tombstones under one key are a FOLD CHOICE,
//!   never a `Conflict`: the lower `(authority_decision_digest,
//!   superseded_by)` is the tombstone in either arrival order, on the
//!   canonical (V095) and the role (V104) table alike.
//! - **I3756** a rendition's placement reads the held original: it concludes
//!   while the original is not held or sits in the same crossing, is held
//!   `rendition_placement_mismatch` once the original lands elsewhere, and
//!   concludes again when it is gone; reading `key:<original digest>`.
//! - **I3757** a retraction of another device's custody report is held
//!   `custody_ack_withdraws_not_the_holder` (reading the report); the
//!   holder's own concludes.
//! - **I3758** a key id that is not its fingerprint, with no held family of
//!   that id, is held `key_id_fingerprint_mismatch`, reading `key:<id>`.
//!
//! I3760 (the reclaim ceremony under a fold attempt) lives in
//! `ownership_reclaim::test_support::exercise_reclaim_ceremony`; I3765 (the
//! revocation bound) in `register::bound_tests`.

use super::fold::{self, reason, Dep};
use super::names::RowId;
use crate::federation::{Error, FederationDirectory};

fn rid(n: u8) -> RowId {
    RowId([n; 32])
}

/// A per-run suffix, so a shared postgres test database never collides.
fn run_tag() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
}

/// I3750: the registry.
#[test]
fn i3750_gc3_reasons_are_registered() {
    use crate::federation::ownership_reclaim::ReclaimRefusal;
    // Core tokens GC3 uses (G0 v4.1 §A: one spelling each).
    for r in [reason::LINK_UNHELD, reason::SELF_ROSTER_NOT_LANDED] {
        assert!(reason::ALL.contains(&r), "I3750: {r} is a core token");
    }
    // GC3's own slice: every token registered, none repeated, none core.
    let mut seen = std::collections::BTreeSet::new();
    for r in reason::gc3::ALL {
        assert!(seen.insert(*r), "I3750: {r} is in GC3's slice once");
        assert!(reason::is_registered(r), "I3750: {r} is registered");
        assert!(!reason::ALL.contains(r), "I3750: {r} is not a core token");
    }
    for r in [
        reason::gc3::ROSTER_UNHELD,
        reason::gc3::KEY_ID_FINGERPRINT_MISMATCH,
        reason::gc3::BOUND_RAISED,
        reason::gc3::LINEAGE_HEAD_LAGS_ROSTER,
        reason::gc3::RENDITION_PLACEMENT_MISMATCH,
    ] {
        assert!(
            reason::gc3::ALL.contains(&r),
            "I3750: {r} is in GC3's slice"
        );
    }
    // The reclaim refusals: every fold reason is registered; the withdraws'
    // own bytes and the deployment pin stay refusals.
    for r in ReclaimRefusal::ALL {
        if let Some(t) = r.fold_reason() {
            assert!(
                reason::is_registered(t),
                "I3750: {r:?} -> {t} is registered"
            );
        }
    }
    for door in [
        ReclaimRefusal::NoDeploymentPolicy,
        ReclaimRefusal::AccordRosterIsNotWaAuthority,
        ReclaimRefusal::AbandonmentWindowBelowFloor,
        ReclaimRefusal::WaAdjudicationRefMissing,
        ReclaimRefusal::SingleActTransferAttempted,
    ] {
        assert_eq!(door.fold_reason(), None, "I3750: {door:?} stays a refusal");
    }
    assert_eq!(
        ReclaimRefusal::WaQuorumShort.fold_reason(),
        Some(reason::COUNT_SHORT),
        "I3750: a short WA quorum is the one shortfall reason"
    );
    // The token a reclaim holds with is the refusal's own token.
    assert_eq!(
        ReclaimRefusal::NotAWaFinding.fold_reason(),
        Some(ReclaimRefusal::NotAWaFinding.as_str())
    );
}

/// I3751: a roster read declares the group it reads, and (G0 ruling 4)
/// does NOT mark the attempt: `canonical_community` swallows the unknown
/// group's `InvalidArgument` for a birth being judged, so a mark here would
/// leak onto that birth.
pub(crate) async fn roster_unheld_body(d: &dyn FederationDirectory) {
    let tag = run_tag();
    let community = format!("gc3-c-{tag}");
    let family = format!("gc3-f-{tag}");

    let (out, att) = fold::attempt(rid(0x51), None, d.community_roster_signers(&community)).await;
    assert!(
        matches!(out, Err(Error::InvalidArgument(_))),
        "I3751: an unknown community has no roster"
    );
    assert!(
        att.held.is_none(),
        "I3751: the swallowed answer marks nothing"
    );
    assert!(
        att.reads.contains(&Dep::key(&community).read_key()),
        "I3751: the community is a fold read: {:?}",
        att.reads
    );

    let (out, att) = fold::attempt(rid(0x52), None, d.family_roster_signers(&family)).await;
    assert!(out.is_err(), "I3751: an unknown family has no roster");
    assert!(
        att.held.is_none(),
        "I3751: the family reader marks nothing either"
    );
    assert!(
        att.reads.contains(&Dep::key(&family).read_key()),
        "I3751: the family is a fold read"
    );
}

/// I3752: a receipt for an unheld proposal waits.
pub(crate) async fn self_roster_unheld_body(d: &dyn FederationDirectory) {
    let proposal = rid(0x53).hex();
    let (out, att) = fold::attempt(
        rid(0x54),
        None,
        d.note_self_roster_proposal(&proposal, "gc3-identity", chrono::Utc::now()),
    )
    .await;
    assert!(out.is_err(), "I3752: no receipt for an unheld proposal");
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::SELF_ROSTER_NOT_LANDED),
        "I3752: held, by its reason"
    );
    assert!(
        att.reads.contains(&Dep::Row(rid(0x53)).read_key()),
        "I3752: the proposal's row is a fold read (its arrival re-folds): {:?}",
        att.reads
    );
}

/// I3753: rival tombstones fold to one, in either order.
pub(crate) async fn withdrawal_fold_choice_body(d: &dyn FederationDirectory) {
    let tag = run_tag();
    let lo = "aa".repeat(32);
    // v62.0.0 (TR-fix2): the canonical half (V095) is DELETED with the
    // backend writer: a canonical is withdrawn only by a later genesis
    // bundle (CC rc21 4.2.1), and `record_canonical_withdrawal` refuses by
    // name on every backend.
    // Role (V104): the same choice, and `None` sorts below a successor.
    for (n, order) in [[Some("gc3-succ"), None], [None, Some("gc3-succ")]]
        .into_iter()
        .enumerate()
    {
        let key = format!("gc3-rw-{n}-{tag}");
        for succ in order {
            d.record_role_withdrawal("steward", &key, succ, &lo)
                .await
                .expect("I3753: a rival role tombstone is never refused");
        }
        let held = d
            .lookup_role_withdrawal("steward", &key)
            .await
            .expect("read")
            .expect("I3753: one role tombstone is held");
        assert_eq!(
            held.superseded_by, None,
            "I3753: the lower content (no successor) wins, arrival order {n}"
        );
    }
}

/// A tiny blob-scope oracle: the scope this "node" holds the original at.
struct HeldScope(Option<String>);

impl crate::federation::renditions::HeldBlobScope for HeldScope {
    fn held_blob_cohort_scope(
        &self,
        _sha256: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<Option<String>, Error>> + Send {
        let v = self.0.clone();
        async move { Ok(v) }
    }

    #[allow(clippy::manual_async_fn)] // the trait's `impl Future + Send` shape
    fn held_claim_scope(
        &self,
        _sha256: &[u8; 32],
    ) -> impl std::future::Future<
        Output = Result<Option<crate::federation::holding_claim::ClaimScope>, Error>,
    > + Send {
        async { Ok(None) }
    }
}

/// I3756: the rendition placement, held → concluded → held, order-free.
#[tokio::test]
async fn i3756_rendition_placement_is_held_until_the_original_agrees() {
    use crate::federation::renditions::check_rendition_placement;
    use crate::federation::types::cohort_scope;
    let original = "cd".repeat(32);
    let env = serde_json::json!({ "media": { "derived_from": original } });
    let run = |held: Option<&str>| {
        let scope = HeldScope(held.map(str::to_owned));
        let env = env.clone();
        async move {
            fold::attempt(rid(0x56), None, async move {
                check_rendition_placement(&scope, &env, cohort_scope::FEDERATION).await
            })
            .await
        }
    };
    // The original is not held: concludes, reading the original.
    let (out, att) = run(None).await;
    assert!(out.is_ok() && att.held.is_none(), "I3756: concludes");
    assert!(
        att.reads.contains(&Dep::key(&original).read_key()),
        "I3756: the original is a fold read: {:?}",
        att.reads
    );
    // The original lands in another crossing: held, never refused.
    let (out, att) = run(Some(cohort_scope::SELF)).await;
    assert!(out.is_err(), "I3756: the gate's verdict");
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::RENDITION_PLACEMENT_MISMATCH),
        "I3756: held, by its reason"
    );
    // The original in the same crossing: concludes.
    let (out, att) = run(Some(cohort_scope::FEDERATION)).await;
    assert!(out.is_ok() && att.held.is_none(), "I3756: concludes again");
}

/// I3757: only the report's own device retracts it; another device's
/// retraction is held, not refused.
#[tokio::test]
async fn i3757_a_foreign_custody_retraction_is_held() {
    use crate::federation::custody_ack::check_custody_withdraws_signer;
    use crate::federation::holding_claim::{holding_claim_row, ClaimScope};
    use crate::federation::types::cohort_scope::{self as cs, CryptoTier};
    let sc = ClaimScope::of_content(CryptoTier::Plaintext, cs::FEDERATION, None).unwrap();
    let claim_id = rid(0x57).hex();
    let claim =
        holding_claim_row(&[0x5a; 32], "holder", &claim_id, chrono::Utc::now(), 1, &sc).unwrap();
    let mut foreign = claim.clone();
    foreign.attestation_type = "withdraws".into();
    foreign.attesting_key_id = "moderator".into();
    let mut own = foreign.clone();
    own.attesting_key_id = "holder".into();

    let (out, att) = fold::attempt(rid(0x58), None, async {
        check_custody_withdraws_signer(&foreign, &claim)
    })
    .await;
    assert!(out.is_err(), "I3757: the gate's verdict");
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::CUSTODY_ACK_WITHDRAWS_NOT_THE_HOLDER),
        "I3757: held, by its reason"
    );
    assert!(
        att.reads.contains(&Dep::Row(rid(0x57)).read_key()),
        "I3757: the report is a fold read: {:?}",
        att.reads
    );
    let (out, att) = fold::attempt(rid(0x59), None, async {
        check_custody_withdraws_signer(&own, &claim)
    })
    .await;
    assert!(
        out.is_ok() && att.held.is_none(),
        "I3757: the holder's own retraction concludes"
    );
}

/// I3758: a fingerprint mismatch with no held family of the id is held.
pub(crate) async fn fingerprint_unvouched_body(d: &dyn FederationDirectory) {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let tag = run_tag();
    let now = chrono::Utc::now();
    let key_id = format!("gc3-fp-{tag}");
    let record = crate::federation::KeyRecord {
        key_id: key_id.clone(),
        pubkey_ed25519_base64: B64.encode([7u8; 32]),
        pubkey_ml_dsa_65_base64: None,
        algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
        identity_type: crate::federation::types::identity_type::USER.to_owned(),
        identity_ref: key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "id": key_id }),
        original_content_hash: "deadbeef".to_owned(),
        scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    let (out, att) = fold::attempt(
        rid(0x5a),
        None,
        crate::federation::register::check_key_id_fingerprint(d, &record),
    )
    .await;
    assert!(
        out.is_err(),
        "I3758: no fingerprint suffix, no vouching family"
    );
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::KEY_ID_FINGERPRINT_MISMATCH),
        "I3758: held, by its reason (a family's arrival re-folds it)"
    );
    assert!(
        att.reads.contains(&Dep::key(&key_id).read_key()),
        "I3758: the id is a fold read: {:?}",
        att.reads
    );
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
    i3751_a_roster_read_declares_and_does_not_mark_sqlite,
    i3751_a_roster_read_declares_and_does_not_mark_postgres,
    roster_unheld_body
);
both!(
    i3752_an_unheld_self_roster_proposal_waits_sqlite,
    i3752_an_unheld_self_roster_proposal_waits_postgres,
    self_roster_unheld_body
);
both!(
    i3753_rival_withdrawal_tombstones_fold_to_one_sqlite,
    i3753_rival_withdrawal_tombstones_fold_to_one_postgres,
    withdrawal_fold_choice_body
);
both!(
    i3758_an_unvouched_fingerprint_mismatch_is_held_sqlite,
    i3758_an_unvouched_fingerprint_mismatch_is_held_postgres,
    fingerprint_unvouched_body
);
