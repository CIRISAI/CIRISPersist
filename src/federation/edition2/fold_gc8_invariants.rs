//! v62.0.0 (wave GC8; CC 2.7.3) — witnesses of the CC 2.7 conversion of the
//! gates outside `admission.rs` (trust-root founders and counts, the key-grant
//! sealer rule, the genesis-root precondition, membership-change structure,
//! and the replicated attestation plane). Each store-facing body runs on
//! sqlite and postgres.
//!
//! The rule witnessed: a gate refuses only on the statement's own bytes and
//! its signer's key plane. A leg that reads OTHER rows marks the running fold
//! attempt with a registered reason token and declares what it read
//! (`edition2::fold`), so the row is HELD (kept, concluding nothing) and
//! re-folds when an input arrives or is withdrawn. Outside a fold attempt the
//! same leg is the plain refusal it was.
//!
//! - **I3950** `require_seated_accord_roster`: no holder's key record held →
//!   held `federation_no_constitutional_root_yet`, reading `key:<holder>`
//!   (no `family:` key); the record lands → the same attempt
//!   concludes. Either arrival order gives the same answer. Outside an attempt
//!   it is the plain refusal.
//! - **I3951** `check_founder_eligible`: a founder with no key record is held
//!   `founder_not_conferred`; once its (human) record lands the fold moves to
//!   the next leg, held `role_not_accord_conferred` (no accord conferral is
//!   held). Reads: `key:<founder>`, `key:<accord>`.
//! - **I3952** the key-grant sealer rule, epoch axis: a signer that is not the
//!   minter and holds no `grant` delegation is held `signer_not_minter`; the
//!   minter itself over a community this node does not hold is held
//!   `signer_not_active_member`. Reads name the signer, minter and community.
//! - **I3953** the trust-root count over voices: a root not held here answers
//!   `root_not_held` and marks the attempt with the same token, reading
//!   `key:<root>`.
//! - **I3954** membership-change structure: a member with no held key record
//!   marks `member_not_in_directory`; two members on one held key mark
//!   `duplicate_founder_key`; a change whose `supersedes` names another prior
//!   roster marks `prior_roster_mismatch`. Each declares the member keys read.
//! - **I3955** the replicated attestation plane carries an edition-2 row as
//!   its STATEMENT (`attestation_apply::apply_as_statement`): an owner's
//!   `config:*` row about a node it does not (yet) own arrives on
//!   `apply_replicated_attestation` FIRST and is held (`HeldEquivalent`, no
//!   typed row, reason `owner_unseated`), concludes when the owner binding
//!   lands, and un-concludes when the binding is withdrawn.
//! - **I3956** I3955 in the other arrival order: binding first, then the
//!   replicated row → `Inserted`, concluded. The concluded set is the same as
//!   I3955's after the binding landed.
//! - **I3957** (CC 2.7 rc21 ruling 11) `not_in_audience` is the one LOCAL
//!   decline among the replicated plane's reasons: never a verdict, always
//!   retryable.
//! - **I3958** (rc21 X6) a version of the reserved accord id that is not the
//!   held accord's head move, recovery or roster change is HELD
//!   (`federation_constitutional_family_reserved`, reading `key:<accord>`),
//!   and outside an attempt the plain refusal.
//! - **I3960** (rc21 ruling 10) is `tier_ingest::test_support::exercise_location_proof_authority`
//!   (sqlite and pg runners `location_proof_authority_is_the_subject_*_734`):
//!   a proof whose attester is not its subject is refused at the door, a live
//!   delegate included, whatever delegation rows arrive, in either order.

use super::fixture_switch as e2;
use super::fold::{self, reason, Dep};
use super::ingest::StatementOutcome;
use super::names::RowId;
use crate::federation::attestation_apply::ReplicatedAttestationOutcome;
use crate::federation::types::{attestation_type, identity_type, Attestation};
use crate::federation::{Error, FederationDirectory, SignedAttestation};

fn rid(n: u8) -> RowId {
    RowId([n; 32])
}

// ─────────────────────────────────────────────────────────────────────────
//  I3950 — the genesis-root precondition
// ─────────────────────────────────────────────────────────────────────────

/// I3950.
pub(crate) async fn no_root_yet_body(d: &dyn FederationDirectory) {
    let seed = "gc8-root-holder";
    let holder = e2::kid(seed);
    let roster = vec![holder.clone()];
    let check =
        || crate::federation::genesis::posture::require_seated_accord_roster(d, "gc8", &roster);

    // Outside an attempt: the plain refusal.
    assert!(
        matches!(check().await, Err(Error::NoConstitutionalRootYet { .. })),
        "I3950: outside a fold attempt the gate is the refusal it was"
    );
    // Inside: held, with its reason and its reads.
    let (out, att) = fold::attempt(rid(0x50), None, check()).await;
    assert!(out.is_err(), "I3950: the gate still answers its error");
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::NO_CONSTITUTIONAL_ROOT_YET),
        "I3950: held, never refused"
    );
    assert!(
        att.reads.contains(&Dep::key(&holder).read_key())
            && !att.reads.iter().any(|k| k.starts_with("family:")),
        "I3950: the holder's key is declared read, and no `family:` key (G0 v4): {:?}",
        att.reads
    );
    // The input arrives: the same gate concludes.
    let _ = e2::put_key(d, seed, &[identity_type::USER]).await;
    let (out, att) = fold::attempt(rid(0x50), None, check()).await;
    assert!(out.is_ok(), "I3950: the holder's record lands: concluded");
    assert_eq!(att.held, None, "I3950: no reason once concluded");
    // The other arrival order (record first) is the same answer.
    let seed_b = "gc8-root-holder-b";
    let _ = e2::put_key(d, seed_b, &[identity_type::USER]).await;
    let roster_b = vec![e2::kid(seed_b)];
    let (out_b, att_b) = fold::attempt(
        rid(0x51),
        None,
        crate::federation::genesis::posture::require_seated_accord_roster(d, "gc8", &roster_b),
    )
    .await;
    assert!(
        out_b.is_ok() && att_b.held.is_none(),
        "I3950: record first, then the row: the same conclusion"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  I3951 — trust-root founder eligibility
// ─────────────────────────────────────────────────────────────────────────

/// I3951.
pub(crate) async fn founder_eligibility_body(d: &dyn FederationDirectory) {
    use crate::federation::canonical_community::{accord_family_key_id, check_founder_eligible};
    let seed = "gc8-founder";
    let founder = e2::kid(seed);
    let now = chrono::Utc::now();
    let community = "gc8-trust-root";

    assert!(
        check_founder_eligible(d, community, &founder, now)
            .await
            .is_err(),
        "I3951: outside an attempt, the refusal it was"
    );
    let (out, att) = fold::attempt(
        rid(0x52),
        None,
        check_founder_eligible(d, community, &founder, now),
    )
    .await;
    assert!(out.is_err());
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::FOUNDER_NOT_CONFERRED),
        "I3951: a founder with no key record is held, not refused"
    );
    for k in [
        Dep::key(&founder).read_key(),
        Dep::key(accord_family_key_id()).read_key(),
    ] {
        assert!(
            att.reads.contains(&k),
            "I3951: {k} is declared read: {:?}",
            att.reads
        );
    }
    // The founder's human record lands: the fold moves on to the conferral
    // leg, which no held accord row satisfies — still held, a new reason.
    let _ = e2::put_key(d, seed, &[identity_type::USER]).await;
    let (out, att) = fold::attempt(
        rid(0x52),
        None,
        check_founder_eligible(d, community, &founder, now),
    )
    .await;
    assert!(
        matches!(out, Err(Error::RoleNotAccordConferred { .. })),
        "I3951: the conferral leg answers: {out:?}"
    );
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::ROLE_NOT_ACCORD_CONFERRED),
        "I3951: held on the next leg (re-folded with the new input)"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  I3952 — the key-grant sealer rule, epoch axis
// ─────────────────────────────────────────────────────────────────────────

/// I3952.
pub(crate) async fn sealer_epoch_body(d: &dyn FederationDirectory) {
    use crate::federation::key_grant::{check_sealer, KeyGrantAxis};
    let minter = e2::kid("gc8-minter");
    let signer = e2::kid("gc8-delegate");
    let community = "gc8-unheld-community".to_owned();
    let axis = KeyGrantAxis::Epoch {
        community_key_id: community.clone(),
        minter_key_id: minter.clone(),
        epoch: 0,
    };
    let now = chrono::Utc::now();

    // Not the minter, no delegation held.
    assert!(
        check_sealer(d, &signer, &axis, now, now).await.is_err(),
        "I3952: outside an attempt, the refusal it was"
    );
    let (out, att) =
        fold::attempt(rid(0x53), None, check_sealer(d, &signer, &axis, now, now)).await;
    assert!(out.is_err());
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::SIGNER_NOT_MINTER),
        "I3952: held signer_not_minter"
    );
    for k in [&signer, &minter, &community] {
        assert!(
            att.reads.contains(&Dep::key(k).read_key()),
            "I3952: key:{k} is declared read: {:?}",
            att.reads
        );
    }
    // The minter itself, over a community this node holds no roster for.
    let (out, att) =
        fold::attempt(rid(0x54), None, check_sealer(d, &minter, &axis, now, now)).await;
    assert!(out.is_err());
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::SIGNER_NOT_ACTIVE_MEMBER),
        "I3952: held signer_not_active_member (the roster is another row)"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  I3953 — the trust-root count
// ─────────────────────────────────────────────────────────────────────────

/// I3953.
pub(crate) async fn trust_root_count_body(d: &dyn FederationDirectory) {
    let root = "gc8-absent-root";
    let voices: std::collections::BTreeSet<String> = [e2::kid("gc8-voice")].into_iter().collect();
    let now = chrono::Utc::now();
    let (out, att) = Box::pin(fold::attempt(
        rid(0x55),
        None,
        crate::federation::canonical_community::trust_root_counts_voices(d, root, &voices, now),
    ))
    .await;
    let refusal = out.expect("I3953: a read, not a failure");
    assert_eq!(
        refusal.as_ref().err().map(|(t, _)| *t),
        Some(crate::federation::steward_purge::unauthorised_reason::ROOT_NOT_HELD),
        "I3953: the count answers its refusal pair"
    );
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::ROOT_NOT_HELD),
        "I3953: and marks the attempt with the same token"
    );
    assert!(
        att.reads.contains(&Dep::key(root).read_key()),
        "I3953: key:<root> is declared read: {:?}",
        att.reads
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  I3954 — membership-change structure (pure)
// ─────────────────────────────────────────────────────────────────────────

fn member(id: &str, ed: &str) -> ciris_verify_core::threshold::ThresholdMember {
    ciris_verify_core::threshold::ThresholdMember {
        member_id: id.into(),
        ed25519_public_key_base64: ed.into(),
        mldsa65_public_key_base64: None,
        role: None,
    }
}

fn prior() -> serde_json::Value {
    serde_json::json!({
        "family_key_id": "gc8-fam",
        "family_name": "F",
        "members": [{"key_id": "a", "role": "member"}],
        "consensus_protocol": "quorum:1/1",
        "consensus_protocol_entrenched": false,
    })
}

/// I3954.
#[tokio::test]
async fn i3954_membership_change_structure_marks_fold_reasons() {
    use crate::federation::group_membership_change::{
        build_membership_change, validate_membership_change_structure,
    };
    use ciris_verify_core::threshold::Role;
    let change = build_membership_change(
        &prior(),
        &["a".to_string(), "b".to_string()],
        Role::Member,
        false,
        Some("quorum:2/2"),
    );
    // "b" has no held record.
    let dir = [member("a", "KA")];
    let (out, att) = fold::attempt(rid(0x56), None, async {
        validate_membership_change_structure(&prior(), &change, &dir)
    })
    .await;
    assert!(out.is_err(), "I3954: still answers its error");
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::MEMBER_NOT_IN_DIRECTORY),
        "I3954: a member's missing record is a fold condition"
    );
    assert!(
        att.reads.contains(&Dep::key("b").read_key()),
        "I3954: the member's key is declared read: {:?}",
        att.reads
    );
    // Both held, on one key.
    let dir = [member("a", "SAME"), member("b", "SAME")];
    let (_, att) = fold::attempt(rid(0x57), None, async {
        validate_membership_change_structure(&prior(), &change, &dir)
    })
    .await;
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::DUPLICATE_FOUNDER_KEY),
        "I3954: one held key, two seats"
    );
    // The prior roster the change names is not the one held.
    let dir = [member("a", "KA"), member("b", "KB")];
    let mut other = prior();
    other["members"] = serde_json::json!([{"key_id": "b", "role": "member"}]);
    let (_, att) = fold::attempt(rid(0x58), None, async {
        validate_membership_change_structure(&other, &change, &dir)
    })
    .await;
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::PRIOR_ROSTER_MISMATCH),
        "I3954: the prior is the held head: a fold condition"
    );
    // All present and matching: concluded.
    let (out, att) = fold::attempt(rid(0x59), None, async {
        validate_membership_change_structure(&prior(), &change, &dir)
    })
    .await;
    assert!(out.is_ok() && att.held.is_none(), "I3954: concluded");
}

// ─────────────────────────────────────────────────────────────────────────
//  I3955 / I3956 — the replicated attestation plane carries the statement
// ─────────────────────────────────────────────────────────────────────────

fn id_of(row: &Attestation) -> RowId {
    super::voices::carried_row_id(row).expect("GC8: the row carries its statement")
}

fn owner_binding(owner: &str, node: &str) -> Attestation {
    // G0-fix3 — asserted now (the shared fixture's fixed 2026-05-01 is
    // before a node key's default window: the node's voice waited).
    super::fold_invariants::owner_binding(owner, node)
}

fn config_row(owner: &str, node: &str) -> Attestation {
    let mut a = crate::federation::genesis::ordinary_scores_row(
        &uuid::Uuid::new_v4().to_string(),
        &e2::kid(owner),
    );
    a.attested_key_id = e2::kid(node);
    a.attestation_envelope = serde_json::json!({
        "id": a.attestation_id,
        "dimension": "config:load:v1",
        "score": 1.0,
    });
    e2::row_of(&a, owner)
}

async fn concluded(d: &dyn FederationDirectory, row: &Attestation) -> bool {
    d.get_attestation(&id_of(row).hex())
        .await
        .unwrap()
        .is_some()
}

async fn held_reason(d: &dyn FederationDirectory, row: &Attestation) -> Option<String> {
    fold::why_held(d, &id_of(row))
        .await
        .unwrap()
        .map(|h| h.reason)
}

async fn replicate(d: &dyn FederationDirectory, row: &Attestation) -> ReplicatedAttestationOutcome {
    d.apply_replicated_attestation(SignedAttestation {
        attestation: row.clone(),
    })
    .await
    .expect("GC8: the replicated plane keeps a door-valid statement")
}

async fn land_binding(d: &dyn FederationDirectory, binding: &Attestation, node: &str) {
    let o = e2::put_signed(d, binding)
        .await
        .expect("GC8: the owner's voice over the binding is kept");
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "GC8: the binding waits for the node: {o:?}"
    );
    let st = e2::carried_statement(binding).expect("GC8: the binding's statement");
    let o = e2::put_statement(d, &e2::voice_of(&st, node))
        .await
        .expect("GC8: the node's voice over its binding");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "GC8: the node's voice lands the binding: {o:?}"
    );
}

/// I3955: the replicated row first.
pub(crate) async fn replicated_row_first_body(d: &dyn FederationDirectory) {
    let (owner, node) = ("gc8-ra-o", "gc8-ra-n");
    let _ = e2::put_key(d, owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, node, &[identity_type::NODE]).await;
    let config = config_row(owner, node);

    assert_eq!(
        replicate(d, &config).await,
        ReplicatedAttestationOutcome::HeldEquivalent,
        "I3955: an unseated owner's row on the replicated plane is HELD, never refused"
    );
    assert!(!concluded(d, &config).await, "I3955: no typed row");
    assert_eq!(
        held_reason(d, &config).await.as_deref(),
        Some(reason::OWNER_UNSEATED),
        "I3955: the reason"
    );
    // A re-offer of the held row changes nothing and refuses nothing.
    assert_eq!(
        replicate(d, &config).await,
        ReplicatedAttestationOutcome::HeldEquivalent,
        "I3955: a re-offer of a held row"
    );

    let binding = owner_binding(owner, node);
    land_binding(d, &binding, node).await;
    assert!(
        concluded(d, &config).await,
        "I3955: the binding's arrival re-folds the held row: concluded"
    );
    assert_eq!(held_reason(d, &config).await, None, "I3955: no reason left");

    // Withdrawn: the row un-concludes.
    let w = e2::composer_of(attestation_type::WITHDRAWS, &binding, owner);
    let o = e2::put_signed(d, &w)
        .await
        .expect("I3955: the owner's withdrawal of its binding");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I3955: the withdrawal concludes: {o:?}"
    );
    assert!(
        !concluded(d, &config).await,
        "I3955: the binding withdrawn: the row is UN-concluded"
    );
    assert_eq!(
        held_reason(d, &config).await.as_deref(),
        Some(reason::OWNER_UNSEATED),
        "I3955: held again, and says why"
    );
}

/// I3956: the binding first.
pub(crate) async fn binding_first_body(d: &dyn FederationDirectory) {
    let (owner, node) = ("gc8-rb-o", "gc8-rb-n");
    let _ = e2::put_key(d, owner, &[identity_type::USER]).await;
    let _ = e2::put_key(d, node, &[identity_type::NODE]).await;
    let binding = owner_binding(owner, node);
    land_binding(d, &binding, node).await;
    let config = config_row(owner, node);
    assert_eq!(
        replicate(d, &config).await,
        ReplicatedAttestationOutcome::Inserted,
        "I3956: the owner seated first: the replicated row concludes on arrival"
    );
    assert!(
        concluded(d, &config).await && concluded(d, &binding).await,
        "I3956: the same concluded set as I3955 after the binding landed"
    );
    assert_eq!(held_reason(d, &config).await, None, "I3956: no reason");
}

// ─────────────────────────────────────────────────────────────────────────
//  I3957 — the audience is a local decline (rc21 ruling 11)
// ─────────────────────────────────────────────────────────────────────────

/// I3957.
#[test]
fn i3957_not_in_audience_is_the_local_decline() {
    use crate::federation::attestation_apply::AttestationRefusalReason as R;
    for r in R::ALL {
        assert_eq!(
            r.is_local_decline(),
            *r == R::NotInAudience,
            "I3957: only the audience answer is a local decline: {r:?}"
        );
        if r.is_local_decline() {
            assert!(r.is_retryable(), "I3957: a declined row may be taken later");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  I3958 — the reserved accord family (rc21 X6)
// ─────────────────────────────────────────────────────────────────────────

/// I3958.
pub(crate) async fn reserved_accord_body(d: &dyn FederationDirectory) {
    let accord = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    let family: crate::federation::types::Family = serde_json::from_value(serde_json::json!({
        "family_key_id": accord,
        "family_name": "gc8 rival accord",
        "members": [],
        "founded_at": "2026-11-18T00:00:00Z",
        "consensus_protocol": "quorum:1/1",
        "persist_row_hash": "",
    }))
    .expect("I3958: a family record");
    let signed = crate::federation::tier_ingest::test_support::sign_family("gc8-rival", family);
    assert!(
        matches!(
            crate::federation::verify_family_admission(d, &signed).await,
            Err(Error::ConstitutionalFamilyReserved { .. })
        ),
        "I3958: outside an attempt, the refusal it was"
    );
    let (out, att) = fold::attempt(
        rid(0x5a),
        None,
        crate::federation::verify_family_admission(d, &signed),
    )
    .await;
    assert!(out.is_err());
    assert_eq!(
        att.held.as_ref().map(|(r, _)| r.as_str()),
        Some(reason::gc8::CONSTITUTIONAL_FAMILY_RESERVED),
        "I3958: an amendment the held accord does not admit concludes nothing"
    );
    assert!(
        att.reads.contains(&Dep::key(accord).read_key()),
        "I3958: the accord is declared read: {:?}",
        att.reads
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  Backends
// ─────────────────────────────────────────────────────────────────────────

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
    i3950_no_root_yet_is_held_and_concludes_sqlite,
    i3950_no_root_yet_is_held_and_concludes_postgres,
    no_root_yet_body
);
both!(
    i3951_founder_eligibility_is_held_sqlite,
    i3951_founder_eligibility_is_held_postgres,
    founder_eligibility_body
);
both!(
    i3952_sealer_epoch_arm_is_held_sqlite,
    i3952_sealer_epoch_arm_is_held_postgres,
    sealer_epoch_body
);
both!(
    i3953_trust_root_count_marks_its_token_sqlite,
    i3953_trust_root_count_marks_its_token_postgres,
    trust_root_count_body
);
both!(
    i3955_replicated_row_first_held_concludes_unconcludes_sqlite,
    i3955_replicated_row_first_held_concludes_unconcludes_postgres,
    replicated_row_first_body
);
both!(
    i3956_binding_first_same_concluded_set_sqlite,
    i3956_binding_first_same_concluded_set_postgres,
    binding_first_body
);
both!(
    i3958_reserved_accord_version_is_held_sqlite,
    i3958_reserved_accord_version_is_held_postgres,
    reserved_accord_body
);
