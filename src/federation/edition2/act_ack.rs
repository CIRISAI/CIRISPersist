//! v62.0.0 (ACK-1, ACK-1b, ACK-2; CC v1.0-rc22-pre4 Part 3 l.208, Part 2
//! l.991–998, CC 2.4.1.1, CC 2.7.3; the Constitution's receipt rulings of
//! 2026-11-24, Q1 / Q2 / Q7 and their correction) — **the `act:ack` receipt:
//! its door rules and its draft.**
//!
//! A receipt acknowledges 1 to 256 acts under `refs.also.ack` and names no
//! head ("it is read by its causal past alone"); a receipt naming more is
//! refused `ack_names_too_many`. Its payload is OPEN (the `act-ack` CDDL ends
//! `* tstr => ceg-value`), so it has no closed member table in
//! `payloads::FAMILIES`: the common members are typed by the no-list path
//! and [`check_shape`] holds the `refs` rule.
//!
//! It is never withdrawn (CC 2.4.1.1 "Never withdrawn"):
//! [`crate::federation::key_plane::is_never_withdrawn`] (a held attestation
//! row) and the edition-2 kept check (`cosign::held_unretractable_target`).
//!
//! **The door** refuses only what the row itself shows (Q2, as corrected
//! 2026-11-24): more than 256 acts, or a head. It reads one other thing,
//! that every act it names is held: it WAITS for them (Q1; [`check_door`]).
//! A receipt by a node's key, by the signer of an act it names, or placed off
//! an act's scope is NOT refused (CC 2.7.3: "A row is never refused for what
//! another row says"): it LANDS and keeps nothing in force. Per act
//! ([`is_receipt_of`]): it is a receipt only of each act whose scope equals
//! its own placement. What a receipt keeps in force is read when it is used
//! (ACK-3, the kernel conferral adapter: its role read gives a node, an act's
//! own signer and a key with no role nothing), never here. A producer
//! acknowledges acts of ONE scope in one receipt ([`act_ack_draft`]).
//!
//! FINAL-PIN ITEM: Verify 23.6.0 carries `family_shapes::check_act_ack` and
//! `Invalid::AckNamesTooMany`; [`check_shape`] is replaced by it at that pin,
//! with the `ack` arm of `produce::check_refs`.

use ciris_verify_core::cde::Value;

use super::door::AdmittedRow;
use super::names::{names_of, Name, RowId};
use crate::federation::types::cohort_scope;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The family id (`namespace_match::family_id("act:ack")`: no parameter).
pub const ACT_ACK_FAMILY: &str = "act:ack";
/// The wire dimension.
pub const ACT_ACK_DIMENSION: &str = "act:ack:v1";
/// The `refs` role the acknowledged acts ride under (`refs.also.ack`).
pub const ACK_ROLE: &str = "also:ack";
/// The most acts one receipt names (CC Part 3 l.208).
pub const MAX_ACKED_ACTS: usize = super::produce::ACK_MAX;

fn refuse(token: &'static str, detail: impl Into<String>) -> Error {
    Error::malformed_row(super::door::PLANE, token, detail.into())
}

/// Is `row` an `act:ack` receipt (by its signed dimension)?
#[must_use]
pub fn is_act_ack_row(row: &crate::federation::Attestation) -> bool {
    row.attestation_type == crate::federation::types::attestation_type::SCORES
        && crate::federation::admission::envelope_dimension(&row.attestation_envelope)
            == Some(ACT_ACK_DIMENSION)
}

/// The acts a receipt's payload names under `refs.also.ack`.
#[must_use]
pub fn acked_acts(names: &[Name]) -> Vec<RowId> {
    names
        .iter()
        .filter(|n| n.role == ACK_ROLE)
        .map(|n| n.row)
        .collect()
}

/// **A row's placement**: its `cohort_scope` and the group it names
/// (`head_rule::group_of`). A row stating no `cohort_scope` but naming a
/// group by `group_kind` (`membership:{stage}`, `group:roster`) is placed at
/// that group; one stating neither reads `federation` (the envelope's
/// earlier default).
#[must_use]
pub fn placement_of(payload: &Value) -> (String, Option<String>) {
    let text = |k: &str| {
        payload
            .get_text(k)
            .and_then(Value::as_text)
            .filter(|s| !s.is_empty())
    };
    let scope = text("cohort_scope")
        .map(str::to_owned)
        .or_else(|| match text("group_kind") {
            Some(cohort_scope::FAMILY) => Some(cohort_scope::FAMILY.to_owned()),
            Some(_) => Some(cohort_scope::COMMUNITY.to_owned()),
            None => None,
        })
        .unwrap_or_else(|| cohort_scope::FEDERATION.to_owned());
    (scope, super::head_rule::group_of(payload))
}

/// **The receipt's shape, from the payload alone** (the door's pure gates):
/// `refs` names 1 to [`MAX_ACKED_ACTS`] acts under `also.ack`, and no
/// `head` or `further_heads`.
///
/// # Errors
/// [`malformed_row::ACK_NAMES_TOO_MANY`] past 256 acts;
/// [`malformed_row::EDITION2_PAYLOAD_INVALID`] for no act, a head, or a
/// `refs` that does not read.
pub fn check_shape(payload: &Value) -> Result<(), Error> {
    let names = names_of(payload).map_err(|e| {
        refuse(
            malformed_row::EDITION2_PAYLOAD_INVALID,
            format!("act:ack: refs: {e:?}"),
        )
    })?;
    if names
        .iter()
        .any(|n| n.role == "head" || n.role == "further_heads")
    {
        return Err(refuse(
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "act:ack: a receipt names no head (CC 3.1.3; it is read by its causal past alone)",
        ));
    }
    let acked = acked_acts(&names).len();
    if acked > MAX_ACKED_ACTS {
        return Err(refuse(
            malformed_row::ACK_NAMES_TOO_MANY,
            format!(
                "{}: a receipt names {acked} acts under refs.also.ack, at most {MAX_ACKED_ACTS} \
                 (CC 3.1.3)",
                malformed_row::ACK_NAMES_TOO_MANY
            ),
        ));
    }
    if acked == 0 {
        return Err(refuse(
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "act:ack: a receipt names 1 to 256 acts under refs.also.ack, and names none",
        ));
    }
    Ok(())
}

/// WAITS (`link_unheld`, a fold read of the act) while no statement of `act`
/// is held (Q1: "a receipt WAITS for the act it names").
async fn require_held_act<F>(dir: &F, row: &AdmittedRow, act: &RowId) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    super::fold::reads(super::fold::Dep::Row(*act));
    if dir.edition2_voices(act).await?.is_empty() {
        return Err(super::fold::hold(
            super::fold::reason::LINK_UNHELD,
            Error::WithdrawsTargetUnheld {
                attestation_id: row.row_id.hex(),
                target_attestation_id: act.hex(),
            },
        ));
    }
    Ok(())
}

/// **The receipt's door rule that reads the directory**: it WAITS for every
/// act it names (Q1; `link_unheld`, re-folded when the act lands). Nothing
/// else about another row is read here (CC 2.7.3: "A row is never refused for
/// what another row says"): a receipt by a node's key, by the signer of an
/// act it names, or placed off an act's scope LANDS and keeps nothing (the
/// Constitution's correction of 2026-11-24; ACK-1b). No-op for every other
/// family and for a retraction (`withdraws` / `recants`, which carry no
/// payload of the family).
///
/// # Errors
/// The wait (`link_unheld`); directory reads.
pub async fn check_door<F>(dir: &F, row: &AdmittedRow) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.family != ACT_ACK_FAMILY || super::emit::carries_no_dimension(&row.row_type) {
        return Ok(());
    }
    for act in acked_acts(&row.names) {
        require_held_act(dir, row, &act).await?;
    }
    Ok(())
}

/// **Is a receipt a receipt OF an act?** Per act (the Constitution's
/// placement ruling, 2026-11-24): a receipt is a receipt of each act it
/// names whose scope equals its own placement ([`placement_of`] of both
/// payloads), and of no other; it is kept either way. The reader's rule
/// (ACK-3 presents a receipt to the conferral read only for such acts).
#[must_use]
pub fn is_receipt_of(receipt_payload: &Value, act_payload: &Value) -> bool {
    placement_of(receipt_payload) == placement_of(act_payload)
}

/// v62.0.0 (ACK-2) — **a receipt's payload**: `author`, the `act:ack:v1`
/// dimension, `refs.also.ack` = `acts` as a sorted set with no duplicate,
/// `asserted_at`, and the placement given (`cohort_scope`; a group's
/// `community_id`, or `family_id` at `family`), as [`placement_of`] reads
/// it back. [`act_ack_draft`] takes the placement from the held acts.
///
/// # Errors
/// The shape refusals of [`check_shape`] (no act, more than 256).
pub fn act_ack_payload(
    acts: &[RowId],
    author: &str,
    placement: Option<&(String, Option<String>)>,
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    let t = |s: &str| Value::Text(s.to_owned());
    let mut set: Vec<Value> = acts
        .iter()
        .map(|a| ciris_verify_core::edition2::row_ref(&a.0))
        .collect();
    set.sort_by_key(ciris_verify_core::cde::encode);
    set.dedup();
    let refs = super::emit::sorted_map(vec![(
        t("also"),
        super::emit::sorted_map(vec![(t("ack"), Value::Array(set))]),
    )]);
    let mut members = vec![
        (t("asserted_at"), Value::Uint(asserted_at_ms)),
        (t("author"), t(author)),
        (t("dimension"), t(ACT_ACK_DIMENSION)),
        (t("refs"), refs),
    ];
    if let Some((scope, group)) = placement {
        if let Some(group) = group {
            let member = if scope == cohort_scope::FAMILY {
                "family_id"
            } else {
                "community_id"
            };
            members.push((t(member), t(group)));
        }
        members.push((t("cohort_scope"), t(scope)));
    }
    let payload = super::emit::sorted_map(members);
    check_shape(&payload)?;
    Ok(payload)
}

/// v62.0.0 (ACK-2) — **a receipt drafted for its signer's pen**: the AUTHORED
/// `act:ack:v1` scores row (`author` = `sub` = `signer_iss`) naming `acts`
/// under `refs.also.ack` (a sorted set, no duplicate; 1 to 256) and no head,
/// placed at the acts' own scope (Q7: `cohort_scope` and, for a group, its
/// `community_id` / `family_id`), at `asserted_at_ms`, in a protected header
/// naming `signer_iss` and the key it will sign with, `signer_kid` (stated by
/// the caller, as RESIGN-6 / RESIGN-7). Hosts reach the same bytes through
/// `statement_draft`; there is no Engine verb (the lead, ACK Q5).
///
/// # Errors
/// `InvalidArgument` for a `signer_iss` that is no identity-ref, an act this
/// node does not hold, or acts at different scopes (one receipt cannot be
/// placed at both); the shape refusals of [`check_shape`] (no act, more than
/// 256).
pub async fn act_ack_draft<F>(
    dir: &F,
    acts: &[RowId],
    signer_iss: &str,
    signer_kid: &super::Digest32,
    asserted_at_ms: u64,
) -> Result<super::emit::Draft, Error>
where
    F: FederationDirectory + ?Sized,
{
    if super::ingest::kid_of_identity_ref(signer_iss).is_none() {
        return Err(Error::InvalidArgument(format!(
            "act_ack_draft: {signer_iss} is not an identity-ref"
        )));
    }
    let mut placement: Option<(String, Option<String>)> = None;
    for act in acts {
        let Some(st) = super::head_rule::held_statement(dir, act).await? else {
            return Err(Error::InvalidArgument(format!(
                "act_ack_draft: the act {} is not held here: a receipt is placed at the scope of \
                 the acts it names",
                act.hex()
            )));
        };
        let at = super::liveness::statement_parts(&st)
            .map(|(_, p)| placement_of(&p))
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "act_ack_draft: the act {} does not read",
                    act.hex()
                ))
            })?;
        match &placement {
            None => placement = Some(at),
            Some(p) if *p == at => {}
            Some(p) => {
                return Err(Error::InvalidArgument(format!(
                    "act_ack_draft: the acts are placed at different scopes ({p:?}, {at:?}): one \
                     receipt is placed at the scope of the acts it names"
                )));
            }
        }
    }
    let payload = act_ack_payload(acts, signer_iss, placement.as_ref(), asserted_at_ms)?;
    super::emit::draft_row(
        signer_kid,
        signer_iss,
        signer_iss,
        "scores",
        &ciris_verify_core::namespace_match::family_id(ACT_ACK_FAMILY),
        &payload,
    )
    .map_err(|e| super::emit::produce_error("act_ack", e))
}
