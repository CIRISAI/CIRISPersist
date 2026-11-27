//! v62.0.0 (VD-step1, VD-step1b) — **one row-state verdict**
//! ([`super::verdict::row_state`]), on sqlite and postgres, through the
//! statement door. Each leg is a place persist used to decide a row's state
//! for itself (FINDINGS F1, F2, F4, F5, F6 of P/VD-step1.md, P/VD-step1b.md):
//!
//! - **I6300** (F1) — a `supersedes` of an occurrence whose target is only a
//!   device's lone bind voice (kept, no hold recorded, nothing concluded)
//!   WAITS, held `link_unheld`; once the identity voices the target and it
//!   concludes, the replacement no longer waits on it.
//! - **I6301** (F2) — an agent occurrence key's own statement, held
//!   `agent_occurrence_unowned`, then re-folded to a kept voice when the
//!   owner binding lands (its hold CLEARED: no hold, still concluding
//!   nothing), is held again when a re-offer's door marks the hold after the
//!   binding is withdrawn: a cleared hold is not a FINAL conclusion.
//! - **I6303** (F4) — a roster version that has not concluded (short of its
//!   count, then held `membership_supersede_cannot_add`: it adds a member)
//!   lists no party: a membership change naming it is not served to the
//!   member only that version lists. Control: a member listed only by a
//!   CONCLUDED version is a party of a row naming it.
//! - **I6304** (F5) — a kept-but-HELD `withdraws` of an agent's owner
//!   binding (another family: held `composer_family_mismatch`) retracts
//!   nothing: the owner stands. The owner's admitted `withdraws` ends it.
//! - **I6306** (VD-step2) — `second_signer_voice::row_status`, the host's
//!   reading, follows the verdict: a concluded occurrence bind and a
//!   concluded group version (neither has an attestation row) read `Seated`
//!   (legs of I6300 and I6303).
//! - **I6307** (F9, VD-step1c; VD-witfix1.rev2) — a node-dimension owner
//!   binding naming an affiliation not held is HELD by the real door with
//!   both voices kept: the verdict says `Held` and it confers no owner and no
//!   affiliation; once the affiliation and its quorum voice it, it concludes
//!   and the affiliation answers for the agent.
//! - **I6308** (F8, VD-step1c) — a leg of I6301: the admitted withdrawal of
//!   the binding re-folds the agent key's kept statement and holds it again,
//!   with no re-offer.
//! - **I6309** (VD-step1e) — the JSON door (`put_attestation`, direct and
//!   through the capsule proxy's `PutAttestation`) answers a statement kept
//!   only as a voice with the held row's error
//!   (`attestation_admit::ROW_HELD_NOT_LANDED`), keeps it, and answers
//!   `AlreadyHeld` once the bind concludes; a landing row answers `Inserted`.
//! - **I6305** (F6) — a kept-but-HELD `withdraws` of an open self-roster
//!   proposal (another family) withdraws nothing; the proposer's admitted
//!   `withdraws` of the family closes it.
//!
//! F3 (`group_serve::carried_by_a_naming_row`) has no leg: no door keeps a
//! citer in a group room with neither a hold nor a conclusion (READ, the
//! survey in P/VD-step1b.md); its revert is caught by
//! `P/tools/no_inferred_conclusion.sh` (`fold_held`).

use chrono::{TimeZone, Utc};
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{iref, key, key_record, map, ref2};
use super::fold::reason;
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use super::occurrence::OCCURRENCE_FAMILY;
use super::verdict::{row_state, RowState};
use crate::federation::{malformed_row, Error, FederationDirectory};

type K = CompositeSigningKey;

/// A family no target here is of (composer_invariants' `SCORE_FAM`): a
/// composer under it is HELD `composer_family_mismatch`, kept.
const OTHER_FAMILY: &str = "evidence:.suite:.kind:.cell:.prefix";

/// A family a `user` key may author a score under, with a dimension of that
/// family (`coherence_standing:cab:v1`; VD-fix3: the `evidence` family is
/// signed only under a delegated `infra:attest:evidence` conferral, and a
/// score's dimension names its own family, else `dimension_family`).
const SCORE_FAM: &str = "coherence_standing:.cohort";

/// An agent key's window (CC 2.4.1.1: an agent key states an end).
const AGENT_UNTIL: u64 = 1_000 + 2_592_000_000;

async fn put(d: &dyn FederationDirectory, st: &[u8]) -> Result<StatementOutcome, Error> {
    Box::pin(put_statement(d, st, None, INGEST_TIER)).await
}

async fn held_reason(d: &dyn FederationDirectory, row: &RowId) -> Option<String> {
    super::fold::why_held(d, row)
        .await
        .expect("the fold state reads")
        .map(|h| h.reason)
}

async fn state(d: &dyn FederationDirectory, row: &RowId) -> RowState {
    row_state(d, row).await.expect("the verdict reads")
}

fn ownership_family() -> String {
    ciris_verify_core::namespace_match::family_id("ownership:{relation}:{target_kind}:{version}")
}

/// An `identity:occurrence` statement of `row_type` (`scores` for a bind,
/// `supersedes` for a replacement naming `target`), signed by `signer` as
/// `iss`, under the identity's current roster head.
#[allow(clippy::too_many_arguments)]
async fn occurrence_statement(
    d: &dyn FederationDirectory,
    signer: &K,
    row_type: &str,
    author: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    asserted_at: u64,
    target: Option<&RowId>,
) -> Vec<u8> {
    let head = super::occurrence::current_roster_head(d, identity)
        .await
        .expect("the roster head reads")
        .expect("the identity's key record is held");
    let mut refs = vec![("head", ref2(&head.0))];
    if let Some(t) = target {
        refs.push(("target", ref2(&t.0)));
    }
    let m = vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(author.to_owned())),
        ("identity_key_id", Value::Text(identity.to_owned())),
        ("occurrence_key_id", Value::Text(occurrence.to_owned())),
        ("device_class", Value::Text(device_class.to_owned())),
        ("refs", map(refs)),
    ];
    sign_row_statement(
        signer,
        &iref(signer),
        occurrence,
        row_type,
        OCCURRENCE_FAMILY,
        &map(m),
        vec![],
    )
    .expect("sign an occurrence statement")
}

/// A retraction (`withdraws`) by `k` of `target` under `family`, about `sub`.
fn withdraws(k: &K, family: &str, sub: &str, target: &RowId, at: u64) -> Vec<u8> {
    let m = vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iref(k))),
        ("refs", map(vec![("target", ref2(&target.0))])),
    ];
    sign_row_statement(k, &iref(k), sub, "withdraws", family, &map(m), vec![])
        .expect("sign a withdraws")
}

/// **I6300** (F1).
pub(crate) async fn i6300_a_supersedes_of_a_lone_voice_waits(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let (user, device) = (key(166), key(167));
    for k in [&user, &device] {
        put(d, &key_record(k, &["user"], 0, None))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I6300 a key record lands: {e}"));
    }
    let (u, k) = (iref(&user), iref(&device));
    let lone = occurrence_statement(d, &device, "scores", &u, &u, &k, "laptop", 22_000, None).await;
    let target = RowId::of_statement(&lone).expect("a row id");
    let out = put(d, &lone)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6300 the device's lone voice: {e}"));
    assert!(
        matches!(out, StatementOutcome::Voice { .. }),
        "[{tag}] I6300 the lone voice is kept as a voice: {out:?}"
    );
    assert_eq!(
        held_reason(d, &target).await,
        None,
        "[{tag}] I6300 no hold is recorded for the lone voice"
    );
    assert_eq!(
        state(d, &target).await,
        RowState::KeptUnconcluded,
        "[{tag}] I6300 the verdict: kept, NOT concluded (no hold is no conclusion)"
    );
    let replacement = occurrence_statement(
        d,
        &device,
        "supersedes",
        &u,
        &u,
        &k,
        "laptop",
        23_000,
        Some(&target),
    )
    .await;
    let s = RowId::of_statement(&replacement).expect("a row id");
    let out = put(d, &replacement)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6300 the replacement is held, never refused: {e}"));
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "[{tag}] I6300 a supersedes of a row that has not concluded WAITS: {out:?}"
    );
    assert_eq!(
        held_reason(d, &s).await.as_deref(),
        Some(reason::LINK_UNHELD),
        "[{tag}] I6300 it waits on its target (link_unheld)"
    );
    // The identity voices the target: it concludes, and the replacement is
    // re-folded and no longer waits on it.
    let author = occurrence_statement(d, &user, "scores", &u, &u, &k, "laptop", 22_000, None).await;
    let out = put(d, &author)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6300 the identity's voice: {e}"));
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "[{tag}] I6300 the identity's voice concludes the bind: {out:?}"
    );
    assert_eq!(
        state(d, &target).await,
        RowState::Concluded,
        "[{tag}] I6300 the verdict: concluded once the occurrence is held"
    );
    // I6306 (VD-step2) — the host's reading follows the verdict: a concluded
    // bind (no attestation row) is `Seated`, not `Waiting`.
    assert!(
        super::second_signer_voice::row_status(d, &target)
            .await
            .expect("the status reads")
            .is_seated(),
        "[{tag}] I6306 a concluded occurrence bind reads Seated"
    );
    assert_ne!(
        held_reason(d, &s).await.as_deref(),
        Some(reason::LINK_UNHELD),
        "[{tag}] I6300 the replacement no longer waits on its concluded target"
    );
}

/// **I6301** (F2) and **I6304** (F5), one agent: its occurrence key's own
/// statement, its owner binding, a held and an admitted retraction of it.
pub(crate) async fn i6301_i6304_agent_owner_binding(d: &dyn FederationDirectory, tag: &str) {
    use crate::federation::admission::agent_owner_of;
    let (owner, agent, agent_key) = (key(160), key(161), key(162));
    put(d, &key_record(&owner, &["user"], 0, None))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the owner's record: {e}"));
    for k in [&agent, &agent_key] {
        put(d, &key_record(k, &["agent"], 1_000, Some(AGENT_UNTIL)))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] an agent record: {e}"));
    }
    let (o, g, gk) = (iref(&owner), iref(&agent), iref(&agent_key));

    // I6301 — the agent occurrence key's own statement, before any owner
    // binding: held `agent_occurrence_unowned` (I3033's shape).
    let own =
        occurrence_statement(d, &agent_key, "scores", &o, &g, &gk, "agent", 11_500, None).await;
    let own_row = RowId::of_statement(&own).expect("a row id");
    let out = put(d, &own).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "[{tag}] I6301 the unowned agent's statement is held: {out:?}"
    );
    assert_eq!(
        held_reason(d, &own_row).await.as_deref(),
        Some(reason::AGENT_OCCURRENCE_UNOWNED),
        "[{tag}] I6301 held, agent_occurrence_unowned"
    );

    // The owner binding, through the door: the owner's statement, then the
    // agent's voice over the same payload (`bound_node`).
    let family = ownership_family();
    let payload = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        ("author", Value::Text(o.clone())),
        (
            "dimension",
            Value::Text("ownership:responsible_party:agent:v1".into()),
        ),
    ]);
    let voice = |k: &K| {
        sign_row_statement(k, &iref(k), &g, "delegates_to", &family, &payload, vec![])
            .expect("sign an owner binding voice")
    };
    let by_owner = voice(&owner);
    let binding = RowId::of_statement(&by_owner).expect("a row id");
    put(d, &by_owner)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the owner's binding statement: {e}"));
    let out = put(d, &voice(&agent))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the agent's voice: {e}"));
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "[{tag}] the owner binding lands with the agent's voice: {out:?}"
    );
    assert_eq!(
        agent_owner_of(d, &g, 20_000)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the owner reads: {e}")),
        Some(o.clone()),
        "[{tag}] the owner owns the agent"
    );
    // The binding re-folded the held statement: a kept voice now, its hold
    // CLEARED (fix3), and still concluding nothing.
    assert_eq!(
        held_reason(d, &own_row).await,
        None,
        "[{tag}] I6301 the owner binding held, the statement no longer holds"
    );
    assert_eq!(
        state(d, &own_row).await,
        RowState::KeptUnconcluded,
        "[{tag}] I6301 the verdict: a cleared hold is not a conclusion"
    );

    // I6304 — a kept-but-HELD retraction (another family) retracts nothing.
    let held_w = withdraws(&owner, OTHER_FAMILY, &g, &binding, 9_000);
    let held_id = RowId::of_statement(&held_w).expect("a row id");
    let out = put(d, &held_w).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "[{tag}] I6304 the mismatched withdraws is kept and held: {out:?}"
    );
    assert_eq!(
        held_reason(d, &held_id).await.as_deref(),
        Some(malformed_row::COMPOSER_FAMILY_MISMATCH),
        "[{tag}] I6304 held composer_family_mismatch"
    );
    assert!(
        matches!(state(d, &held_id).await, RowState::Held(_)),
        "[{tag}] I6304 the verdict: held"
    );
    assert_eq!(
        agent_owner_of(d, &g, 20_000)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the owner reads: {e}")),
        Some(o.clone()),
        "[{tag}] I6304 a HELD withdraws retracts nothing: the owner still owns the agent"
    );
    // The owner's admitted withdraws ends it.
    let landed_w = withdraws(&owner, &family, &g, &binding, 10_000);
    let landed_id = RowId::of_statement(&landed_w).expect("a row id");
    put(d, &landed_w)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6304 the owner's withdraws: {e}"));
    assert_eq!(
        state(d, &landed_id).await,
        RowState::Concluded,
        "[{tag}] I6304 the owner's withdraws is admitted"
    );
    assert_eq!(
        agent_owner_of(d, &g, 20_000)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the owner reads: {e}")),
        None,
        "[{tag}] I6304 the admitted withdraws ends the binding"
    );
    // I6308 (F8, VD-step1c) — the withdrawal re-folds what read the binding:
    // the agent key's kept statement (its hold cleared, concluding nothing)
    // is RE-RUN and held again, with no re-offer (before: a FINAL-plane row
    // with no hold was skipped as concluded).
    assert_eq!(
        held_reason(d, &own_row).await.as_deref(),
        Some(reason::AGENT_OCCURRENCE_UNOWNED),
        "[{tag}] I6308 the re-fold re-holds the cleared voice"
    );

    // I6301 — a re-offer of the agent key's statement: the owner gate marks
    // its hold again (no owner at 11 500 ms). A cleared hold is not a FINAL
    // conclusion, so the hold is RECORDED (before VD-step1b the door read
    // "no hold, final plane" as concluded and kept it as a bare voice).
    let out = put(d, &own).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "[{tag}] I6301 the re-offer is held again, not kept as a concluded voice: {out:?}"
    );
    assert_eq!(
        held_reason(d, &own_row).await.as_deref(),
        Some(reason::AGENT_OCCURRENCE_UNOWNED),
        "[{tag}] I6301 the hold is recorded"
    );
}

/// **I6307** (F9, VD-step1c; VD-witfix1.rev2) — an owner binding whose
/// voices are KEPT but which the door HOLDS concludes nothing and confers
/// nothing, through the real door that holds it: a NODE-dimension owner
/// binding of an agent naming an affiliation (CC 3.2 ruling (a), I3292's
/// shape), its owner's and agent's voices put while the affiliation is NOT
/// held. `admission::check_owner_binding_counted` holds it; the verdict says
/// `Held`; it confers no owner and no affiliation. The affiliation lands,
/// then its members' quorum voices the binding: it concludes, and the
/// affiliation answers for the agent (`affiliation_of_binding`).
///
/// `agent_owner_of` reads only the AGENT dimension (`ownership:…:agent:…`),
/// so on this binding it is `None` before and after: F9's own change is not
/// discriminated here; no door holds an agent-dimension binding once both
/// voices are in (P/VD-witfix1.rev2.md).
pub(crate) async fn i6307_a_held_binding_confers_nothing(d: &dyn FederationDirectory, tag: &str) {
    use super::fixture_switch as e2;
    use super::group_fixtures::{put_voices, roster_voices};
    use crate::federation::admission::{affiliation_of_binding, agent_owner_of};
    use crate::federation::types::{identity_type, Community, CommunityMember};
    let (owner, agent, m1, m2, m3) = ("vd7-o", "vd7-a", "vd7-m1", "vd7-m2", "vd7-m3");
    for s in [owner, m1, m2, m3] {
        let _ = e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let agent_kid = e2::put_key(d, agent, &[identity_type::AGENT]).await;
    // The affiliation's founding, built but NOT put yet: its roster head's
    // row id is what the binding names.
    let gid = e2::kid("vd7-g");
    let epoch = |ms: i64| Utc.timestamp_millis_opt(ms).single().expect("an instant");
    let rec = super::group::GroupRecord::Community(Community {
        community_key_id: gid.clone(),
        community_name: "vd7 affiliation".into(),
        members: [m1, m2, m3]
            .iter()
            .enumerate()
            .map(|(i, s)| CommunityMember {
                key_id: e2::kid(s),
                joined_at: epoch(1_000),
                role: (i == 0).then(|| "founder".to_owned()),
            })
            .collect(),
        founded_at: epoch(1_000),
        consensus_protocol: "majority".into(),
        policy_blob: Some(serde_json::json!({
            "cohort_scope": "affiliations",
            "affiliation_config": { "licence_audiences": { "professional_full": "federation" } },
        })),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    });
    let member_keys: Vec<_> = [m1, m2, m3].iter().map(|s| e2::signing_key(s)).collect();
    let signers: Vec<&_> = member_keys.iter().collect();
    let founding = roster_voices(&rec, 1, None, 2_000, &signers);
    let head = RowId::of_statement(&founding[0]).expect("the roster head's row id");
    // The binding (I3292's builder): the node dimension, naming the
    // affiliation and its roster head, now-relative.
    let mut a = crate::federation::tier_ingest::test_support::owner_binding_attestation(
        &uuid::Uuid::new_v4().to_string(),
        owner,
        agent,
    );
    a.attestation_envelope["community_id"] = serde_json::json!(gid);
    a.attestation_envelope["refs"] = serde_json::json!({ "head": [2, [-16, head.hex()]] });
    a.asserted_at = chrono::Utc::now() - chrono::Duration::minutes(5);
    a.scrub_timestamp = a.asserted_at;
    let row = e2::row_of(&a, owner);
    let st = e2::carried_statement(&row).expect("the binding's statement");
    let binding = RowId::of_statement(&st).expect("a row id");
    // Both voices, the affiliation absent: kept and HELD by the real door.
    let o = e2::put_signed(d, &row)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6307 the owner's voice is kept: {e}"));
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "[{tag}] I6307 the owner's voice waits: {o:?}"
    );
    let o = e2::put_statement(d, &e2::voice_of(&st, agent))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6307 the agent's voice is kept: {e}"));
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "[{tag}] I6307 the binding waits for its affiliation: {o:?}"
    );
    // VD-fix3 — pinned by name from the run (sqlite, CHECKED): the counted
    // gate notes the absent affiliation as a shortfall
    // (`owner_binding_counted_short`), held `count_short`.
    assert_eq!(
        held_reason(d, &binding).await.as_deref(),
        Some(reason::COUNT_SHORT),
        "[{tag}] I6307 held by the door for its absent affiliation"
    );
    assert_eq!(
        d.edition2_voices(&binding)
            .await
            .expect("the voices read")
            .len(),
        2,
        "[{tag}] I6307 both voices are kept"
    );
    assert!(
        matches!(state(d, &binding).await, RowState::Held(_)),
        "[{tag}] I6307 the verdict: held, both voices kept"
    );
    assert_eq!(
        agent_owner_of(d, &agent_kid, now_ms())
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the owner reads: {e}")),
        None,
        "[{tag}] I6307 a held binding confers no owner"
    );
    assert_eq!(
        affiliation_of_binding(d, &agent_kid)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the affiliation reads: {e}")),
        None,
        "[{tag}] I6307 a held binding confers no affiliation"
    );
    // The affiliation lands; its members' quorum voices the binding.
    put_voices(d, &founding)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6307 the affiliation's founding: {e}"));
    let mut last = None;
    for m in [m1, m2] {
        last = Some(
            e2::put_statement(d, &e2::voice_of(&st, m))
                .await
                .unwrap_or_else(|e| panic!("[{tag}] I6307 member {m}'s voice: {e}")),
        );
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. }))
            || state(d, &binding).await.is_concluded(),
        "[{tag}] I6307 the binding lands with the affiliation's quorum: {last:?}"
    );
    assert_eq!(
        state(d, &binding).await,
        RowState::Concluded,
        "[{tag}] I6307 the verdict: concluded"
    );
    assert_eq!(
        affiliation_of_binding(d, &agent_kid)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the affiliation reads: {e}")),
        // VD-fix3 — the affiliation answers under the id its founding
        // DERIVES (pass 10), the group its roster statement states.
        Some(
            super::group::roster_view_of_statement(&founding[0])
                .expect("the founding reads")
                .group
        ),
        "[{tag}] I6307 concluded: the affiliation answers for the agent"
    );
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).expect("after 1970")
}

/// **I6309** (VD-step1e; the JSON door, `route_into_statement_door`) — a row
/// put through the JSON door (`FederationDirectory::put_attestation`, the
/// path PyO3 `put_attestation` takes, and the capsule's `PutAttestation` op
/// through the consumer proxy) whose statement the door keeps only as a
/// VOICE (an `identity:occurrence` bind's device voice before its identity's)
/// does NOT answer `Inserted`: it answers the HELD row's error (kind
/// `federation_invalid_argument`, message
/// `attestation_admit::ROW_HELD_NOT_LANDED: VOICE_KEPT_AWAITING_OTHERS`), the
/// voice is kept, and once the second voice concludes the bind a re-put
/// answers `AlreadyHeld`. A concluded row answers `Inserted` on its first put.
pub(crate) async fn i6309_the_json_door_never_answers_inserted_for_a_voice(
    dir: std::sync::Arc<dyn FederationDirectory>,
    tag: &str,
) {
    use crate::federation::attestation_admit::{ROW_HELD_NOT_LANDED, VOICE_KEPT_AWAITING_OTHERS};
    use crate::federation::{AttestationOutcome, SignedAttestation};
    let proxy = crate::ffi::directory_capsule::test_proxy(dir.clone());
    let (d, p) = (dir.as_ref(), proxy.as_ref());
    // A statement mapped to the JSON door's row shape (it carries the
    // statement; the door admits it AS that statement).
    let row_of = |st: Vec<u8>| async move {
        let keys = super::ingest::held_keys_for(d, &st)
            .await
            .expect("the keys read");
        let admitted = super::door::admit_row(
            &st,
            &keys,
            None,
            ciris_verify_core::edition2::family::SelectContext::default(),
        )
        .expect("the statement admits");
        SignedAttestation {
            attestation: super::ingest::attestation_of(&admitted, INGEST_TIER)
                .expect("the row shape"),
        }
    };
    let (user, device) = (key(176), key(177));
    for k in [&user, &device] {
        put(d, &key_record(k, &["user"], 0, None))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I6309 a key record: {e}"));
    }
    let (u, k) = (iref(&user), iref(&device));
    let lone = occurrence_statement(d, &device, "scores", &u, &u, &k, "laptop", 22_000, None).await;
    let bind = RowId::of_statement(&lone).expect("a row id");
    let row = row_of(lone).await;
    for (via, dd) in [("direct", d), ("through the proxy", p)] {
        let e = dd
            .put_attestation(row.clone())
            .await
            .expect_err("I6309 a voice kept awaiting others is not Inserted");
        assert_eq!(
            e.kind(),
            "federation_invalid_argument",
            "[{tag}] I6309 ({via}) the held row's error kind: {e}"
        );
        assert!(
            e.to_string().contains(&format!(
                "{ROW_HELD_NOT_LANDED}: {VOICE_KEPT_AWAITING_OTHERS}"
            )),
            "[{tag}] I6309 ({via}) names the not-landed voice: {e}"
        );
    }
    assert_eq!(
        d.edition2_voices(&bind)
            .await
            .expect("the voices read")
            .len(),
        1,
        "[{tag}] I6309 the voice is KEPT (once, whichever door offered it)"
    );
    assert_eq!(
        state(d, &bind).await,
        RowState::KeptUnconcluded,
        "[{tag}] I6309 the verdict: kept, not concluded"
    );
    // The identity's voice concludes the bind.
    let author = occurrence_statement(d, &user, "scores", &u, &u, &k, "laptop", 22_000, None).await;
    assert!(
        matches!(put(d, &author).await, Ok(StatementOutcome::Row { .. })),
        "[{tag}] I6309 the identity's voice concludes the bind"
    );
    assert_eq!(
        state(d, &bind).await,
        RowState::Concluded,
        "[{tag}] I6309 concluded"
    );
    for (via, dd) in [("direct", d), ("through the proxy", p)] {
        assert_eq!(
            dd.put_attestation(row.clone())
                .await
                .unwrap_or_else(|e| panic!(
                    "[{tag}] I6309 ({via}) a re-put of a concluded row: {e}"
                )),
            AttestationOutcome::AlreadyHeld,
            "[{tag}] I6309 ({via}) the re-put of the concluded row's voice is the no-op answer"
        );
    }
    // A row that concludes on its first put answers `Inserted` (direct, and
    // a second row through the proxy).
    for (n, (via, dd)) in [("direct", d), ("through the proxy", p)]
        .into_iter()
        .enumerate()
    {
        let at = 30_000 + u64::try_from(n).expect("small");
        let score = sign_row_statement(
            &user,
            &u,
            &u,
            "scores",
            SCORE_FAM,
            &map(vec![
                ("asserted_at", Value::Uint(at)),
                ("author", Value::Text(u.clone())),
                ("score", Value::Uint(750_000)),
                ("confidence", Value::Uint(900_000)),
                ("dimension", Value::Text("coherence_standing:cab:v1".into())),
            ]),
            vec![],
        )
        .expect("sign a score");
        assert_eq!(
            dd.put_attestation(row_of(score).await)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] I6309 ({via}) a concluded row: {e}")),
            AttestationOutcome::Inserted,
            "[{tag}] I6309 ({via}) a row that lands answers Inserted on its first put"
        );
    }
}

/// **I6303** (F4).
pub(crate) async fn i6303_a_short_version_lists_no_party(d: &dyn FederationDirectory, tag: &str) {
    use super::group::{
        membership_payload, roster_payload, GroupRecord, MembershipRecord, GROUP_ROSTER_PREFIX,
        MEMBERSHIP_PREFIX,
    };
    use crate::federation::types::{Family, FamilyMember, FamilyMembershipRevocation};
    let at = |ms: i64| Utc.timestamp_millis_opt(ms).single().expect("an instant");
    let sign = |k: &K, sub: &str, prefix: &str, p: &Value| {
        sign_row_statement(
            k,
            &iref(k),
            sub,
            "scores",
            &ciris_verify_core::namespace_match::family_id(prefix),
            p,
            vec![],
        )
        .expect("sign a group statement")
    };
    let (a, b, c, outsider, g) = (key(168), key(169), key(170), key(171), key(172));
    for k in [&a, &b, &c, &outsider] {
        put(d, &key_record(k, &["user"], 0, None))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] a key record: {e}"));
    }
    let gid = iref(&g);
    let family = |members: &[&K]| {
        GroupRecord::Family(Family {
            family_key_id: gid.clone(),
            family_name: "vd-f4".into(),
            members: members
                .iter()
                .map(|k| FamilyMember {
                    key_id: iref(k),
                    joined_at: at(1_000),
                    role: None,
                })
                .collect(),
            founded_at: at(1_000),
            consensus_protocol: "majority".into(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        })
    };
    // GID-fixtures-sites — version 1 is founded under its DERIVED id (`gid`
    // was the room's name); version 2 names that id (`fixture_record`).
    let (gid, v1) = crate::federation::edition2::group_fixtures::fixture_founding(
        &family(&[&a, &b, &c]),
        2_000,
    );
    let mut head1 = None;
    for k in [&a, &b, &c] {
        if let Ok(StatementOutcome::Row { row_id, .. }) =
            put(d, &sign(k, &gid, GROUP_ROSTER_PREFIX, &v1)).await
        {
            head1 = Some(row_id);
        }
    }
    let head1 = head1.unwrap_or_else(|| panic!("[{tag}] I6303 version 1 lands"));
    // Version 2 lists the outsider; one voice of three: short of its count.
    let v2 = roster_payload(
        &crate::federation::edition2::group_fixtures::fixture_record(&family(&[
            &a, &b, &c, &outsider,
        ])),
        2,
        Some(&head1),
        3_000,
    )
    .expect("v2");
    let v2_by_a = sign(&a, &gid, GROUP_ROSTER_PREFIX, &v2);
    let head2 = RowId::of_statement(&v2_by_a).expect("a row id");
    let out = put(d, &v2_by_a)
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6303 version 2's first voice is kept: {e}"));
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "[{tag}] I6303 version 2 is short of its count: {out:?}"
    );
    assert!(
        !state(d, &head2).await.is_concluded(),
        "[{tag}] I6303 the verdict: version 2 has not concluded"
    );
    // A membership change naming version 2 as its head.
    let removal = MembershipRecord::FamilyRemoval(FamilyMembershipRevocation {
        family_key_id: gid.clone(),
        removed_identity_key_id: iref(&c),
        removed_at: at(4_000),
        effective_at: at(4_000),
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    });
    let mp = membership_payload(&removal, Some(&head2)).expect("a removal payload");
    let change = sign(&a, &iref(&c), MEMBERSHIP_PREFIX, &mp);
    let change: &[u8] = &change;
    let served = |who: &K| {
        let peer = iref(who);
        async move {
            super::serve::servable_to(d, change, Some(&peer))
                .await
                .expect("the serve rule reads")
        }
    };
    assert!(
        !served(&outsider).await,
        "[{tag}] I6303 a version kept short of its count lists no party: the outsider only it \
         lists is not served a row naming it"
    );
    assert!(
        served(&c).await,
        "[{tag}] I6303 the member the change names is served it"
    );
    // VD-fix1 — version 2 never concludes: a roster version may keep, re-list
    // or drop members but never ADD one (`membership_acceptance`'s supersede
    // rule, held `membership_supersede_cannot_add`); a member joins by a
    // widening. A second voice meets the count and it stays held.
    put(d, &sign(&b, &gid, GROUP_ROSTER_PREFIX, &v2))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6303 version 2's second voice is kept: {e}"));
    assert_eq!(
        held_reason(d, &head2).await.as_deref(),
        Some(reason::MEMBERSHIP_SUPERSEDE_CANNOT_ADD),
        "[{tag}] I6303 version 2 adds a member: held, it never concludes"
    );
    assert!(
        !served(&outsider).await,
        "[{tag}] I6303 still no party: the held version's outsider is not served"
    );
    // The control: a CONCLUDED version's listed members ARE parties. Remove
    // `c` through the door (a majority over version 1), then a change naming
    // version 1 is served to `c`, now off the live roster and listed only by
    // version 1.
    let removal_of = |k: &K, at_ms: i64| {
        MembershipRecord::FamilyRemoval(FamilyMembershipRevocation {
            family_key_id: gid.clone(),
            removed_identity_key_id: iref(k),
            removed_at: at(at_ms),
            effective_at: at(at_ms),
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        })
    };
    let mc = membership_payload(&removal_of(&c, 5_000), Some(&head1)).expect("a removal payload");
    let mut landed = false;
    for k in [&a, &b] {
        if let Ok(StatementOutcome::Row { .. }) =
            put(d, &sign(k, &iref(&c), MEMBERSHIP_PREFIX, &mc)).await
        {
            landed = true;
        }
    }
    assert!(
        landed,
        "[{tag}] I6303 the control removal of c lands with a majority"
    );
    let mb = membership_payload(&removal_of(&b, 6_000), Some(&head1)).expect("a removal payload");
    let naming_v1 = sign(&a, &iref(&b), MEMBERSHIP_PREFIX, &mb);
    assert!(
        super::serve::servable_to(d, &naming_v1, Some(&iref(&c)))
            .await
            .expect("the serve rule reads"),
        "[{tag}] I6303 a member listed by a CONCLUDED version is a party of a row naming it"
    );
    // I6306 (VD-step2) — a concluded group version (no attestation row) reads
    // `Seated` to a host.
    assert!(
        super::second_signer_voice::row_status(d, &head1)
            .await
            .expect("the status reads")
            .is_seated(),
        "[{tag}] I6306 a concluded group version reads Seated"
    );
}

/// **I6305** (F6).
pub(crate) async fn i6305_a_held_withdraws_closes_no_proposal(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    use super::occurrence::{carried_of_bind, proposal_withdrawn};
    let (user, d1, d2) = (key(163), key(164), key(165));
    for k in [&user, &d1, &d2] {
        put(d, &key_record(k, &["user"], 0, None))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] a key record: {e}"));
    }
    let u = iref(&user);
    // A first device lands (the genesis key's assent alone).
    for signer in [&d1, &user] {
        put(
            d,
            &occurrence_statement(
                d,
                signer,
                "scores",
                &u,
                &u,
                &iref(&d1),
                "laptop",
                10_000,
                None,
            )
            .await,
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I6305 the first device: {e}"));
    }
    // A second device: with two roster keys, one assent is a PROPOSAL.
    put(
        d,
        &occurrence_statement(d, &d2, "scores", &u, &u, &iref(&d2), "laptop", 12_000, None).await,
    )
    .await
    .unwrap_or_else(|e| panic!("[{tag}] I6305 the second device's own statement: {e}"));
    let assent = occurrence_statement(
        d,
        &user,
        "scores",
        &u,
        &u,
        &iref(&d2),
        "laptop",
        12_000,
        None,
    )
    .await;
    let proposal = RowId::of_statement(&assent).expect("a row id");
    let out = put(d, &assent).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "[{tag}] I6305 one assent of two is an open proposal: {out:?}"
    );
    let open = || {
        let u = u.clone();
        async move {
            d.list_open_edition2_roster_proposals(Some(u.as_str()))
                .await
                .expect("the open proposals read")
                .iter()
                .any(|r| r.proposal_id == proposal.hex())
        }
    };
    assert!(open().await, "[{tag}] I6305 the proposal is open");
    let carried = carried_of_bind(d, &proposal.hex())
        .await
        .expect("the proposal reads")
        .expect("a held proposal");

    // A kept-but-HELD withdraws by the proposer (another family).
    let held_w = withdraws(&user, OTHER_FAMILY, &iref(&d2), &proposal, 13_000);
    let held_id = RowId::of_statement(&held_w).expect("a row id");
    let out = put(d, &held_w).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "[{tag}] I6305 the mismatched withdraws is kept and held: {out:?}"
    );
    assert_eq!(
        held_reason(d, &held_id).await.as_deref(),
        Some(malformed_row::COMPOSER_FAMILY_MISMATCH),
        "[{tag}] I6305 held composer_family_mismatch"
    );
    assert!(
        !proposal_withdrawn(d, &carried)
            .await
            .expect("the withdrawal reads"),
        "[{tag}] I6305 a HELD withdraws closes nothing"
    );
    assert!(open().await, "[{tag}] I6305 the proposal is still open");

    // The proposer's admitted withdraws of the family closes it.
    let landed_w = withdraws(&user, OCCURRENCE_FAMILY, &iref(&d2), &proposal, 14_000);
    let landed_id = RowId::of_statement(&landed_w).expect("a row id");
    let out = put(d, &landed_w).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { .. })),
        "[{tag}] I6305 the proposer's withdraws is admitted: {out:?}"
    );
    assert_eq!(
        state(d, &landed_id).await,
        RowState::Concluded,
        "[{tag}] I6305 the verdict: a landed retraction of the family is concluded (it states \
         no occurrence)"
    );
    assert!(
        proposal_withdrawn(d, &carried)
            .await
            .expect("the withdrawal reads"),
        "[{tag}] I6305 the admitted withdraws closes the proposal"
    );
    assert!(
        !open().await,
        "[{tag}] I6305 the proposal is no longer open"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend as _;

    async fn fresh() -> SqliteBackend {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn i6300_a_supersedes_of_a_lone_voice_waits_sqlite() {
        let d = fresh().await;
        Box::pin(i6300_a_supersedes_of_a_lone_voice_waits(&d, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6301_i6304_a_held_withdraws_retracts_nothing_sqlite() {
        let d = fresh().await;
        Box::pin(i6301_i6304_agent_owner_binding(&d, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6307_a_held_binding_confers_nothing_sqlite() {
        let d = fresh().await;
        Box::pin(i6307_a_held_binding_confers_nothing(&d, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6309_the_json_door_never_answers_inserted_for_a_voice_sqlite() {
        let d = fresh().await;
        Box::pin(i6309_the_json_door_never_answers_inserted_for_a_voice(
            std::sync::Arc::new(d),
            "sqlite",
        ))
        .await;
    }

    #[tokio::test]
    async fn i6303_a_short_version_lists_no_party_sqlite() {
        let d = fresh().await;
        Box::pin(i6303_a_short_version_lists_no_party(&d, "sqlite")).await;
    }

    #[tokio::test]
    async fn i6305_a_held_withdraws_closes_no_proposal_sqlite() {
        let d = fresh().await;
        Box::pin(i6305_a_held_withdraws_closes_no_proposal(&d, "sqlite")).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::store::postgres::PostgresBackend;
    use crate::store::Backend as _;

    async fn fresh() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::empty_dsn()?;
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[tokio::test]
    async fn i6300_a_supersedes_of_a_lone_voice_waits_postgres() {
        let Some(d) = fresh().await else { return };
        Box::pin(i6300_a_supersedes_of_a_lone_voice_waits(&d, "postgres")).await;
    }

    #[tokio::test]
    async fn i6301_i6304_a_held_withdraws_retracts_nothing_postgres() {
        let Some(d) = fresh().await else { return };
        Box::pin(i6301_i6304_agent_owner_binding(&d, "postgres")).await;
    }

    #[tokio::test]
    async fn i6307_a_held_binding_confers_nothing_postgres() {
        let Some(d) = fresh().await else { return };
        Box::pin(i6307_a_held_binding_confers_nothing(&d, "postgres")).await;
    }

    #[tokio::test]
    async fn i6309_the_json_door_never_answers_inserted_for_a_voice_postgres() {
        let Some(d) = fresh().await else { return };
        Box::pin(i6309_the_json_door_never_answers_inserted_for_a_voice(
            std::sync::Arc::new(d),
            "postgres",
        ))
        .await;
    }

    #[tokio::test]
    async fn i6303_a_short_version_lists_no_party_postgres() {
        let Some(d) = fresh().await else { return };
        Box::pin(i6303_a_short_version_lists_no_party(&d, "postgres")).await;
    }

    #[tokio::test]
    async fn i6305_a_held_withdraws_closes_no_proposal_postgres() {
        let Some(d) = fresh().await else { return };
        Box::pin(i6305_a_held_withdraws_closes_no_proposal(&d, "postgres")).await;
    }
}
