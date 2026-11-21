//! v62.0.0 (v62 P8-fix5; CC 2.6.1.9, CC 2.7.3, CC 2.7.5, CC 4.4.3.19) —
//! **a second signer's voice over a held row, in any role.**
//!
//! An AUTHORED row whose family's model names second signers is HELD by the
//! door (`Pending`, core reason `count_short`) until each role has voiced
//! (K2's `admission::check_second_signers_voiced`). Who must voice is ONE
//! answer, K2's [`resolved_second_signer_roles`]: every role the gate counts
//! (`delegate`, `delegate_owner`, `bound_node`, `custodian`, ...), each party
//! a key, an owner read from the machine's live owner binding. This module
//! names no role of its own: it offers a key exactly the roles that answer
//! lists it in.
//!
//! - [`held_rows_for`]: the held rows waiting for a key's voice (optionally
//!   in one named role), each with the author's statement. Looked up BY THE
//!   AWAITED KEY, never by scanning the held set: the resolver declares the
//!   fold read `Dep::key(party)` for every party it names, so
//!   `ceg_fold_reads` (primary key `(read_key, row_id)`, both backends)
//!   indexes each held row under every key it waits for
//!   ([`FederationDirectory::fold_dependents`]).
//! - [`voice_draft`]: the voice drafted for a hardware or remote pen;
//! - [`voice_held_row`]: the voice signed by a local composite signer and put;
//! - [`submit_voice`]: a voice signed elsewhere, put;
//! - [`row_status`] / [`VoiceOutcome`]: `Seated`, or `Waiting` with the held
//!   reason (a host answers HTTP 424, never an error).
//!
//! A voice is the voicer's own statement over the author's payload, byte for
//! byte (same `sub`, row type, family and payload), so it names the same row
//! id and joins that row's fold (CC 2.6.1.9). Whether it fills a role is the
//! door's: a voice that fills none seats nothing.

use ciris_verify_core::cde::Value;
use serde::{Deserialize, Serialize};

use super::door::{resolved_second_signer_roles, SecondSignerParty};
use super::emit::{draft_row, family_of_statement, produce_error, Draft};
use super::fold::Dep;
use super::ingest::{kid_of_identity_ref, put_statement, StatementOutcome, INGEST_TIER};
use super::liveness::statement_parts;
use super::names::RowId;
use crate::federation::{Error, FederationDirectory};

/// One held row waiting for a key's voice in one role
/// (`(row, role, statement)`, with what a host shows beside them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldRow {
    /// The row id (hex): every voice names it.
    pub row_id: String,
    /// The row's family (header -70002).
    pub family: String,
    /// The row type (header -70001).
    pub row_type: String,
    /// The author (the authoring statement's `iss`).
    pub author: String,
    /// The row's `sub`.
    pub sub: String,
    /// The role the voice fills, as K2's resolver names it (`delegate`,
    /// `delegate_owner`, `bound_node`, `custodian`, ...).
    pub role: String,
    /// Every key that may fill the role (any one voicing fills it).
    pub parties: Vec<String>,
    /// The held reason token (`count_short` while a voice is missing).
    pub reason: String,
    /// The refusal the gate would have raised, as text.
    pub detail: String,
    /// The author's statement, as held (lowercase hex on JSON surfaces):
    /// what the voice signs over.
    #[serde(with = "hex_bytes")]
    pub statement: Vec<u8>,
}

impl HeldRow {
    /// The held row as JSON for a host surface (`statement` hex).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let t = String::deserialize(d)?;
        hex::decode(t).map_err(serde::de::Error::custom)
    }
}

/// The state of a row a voice concerns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VoiceOutcome {
    /// The row landed: every second signer has voiced it.
    Seated {
        /// The row id (hex).
        row_id: String,
    },
    /// The row is held, waiting for a voice (HTTP 424, Failed Dependency, on
    /// a host surface). Not an error: the voice may still arrive.
    Waiting {
        /// The row id (hex).
        row_id: String,
        /// The held reason token (`count_short`), empty when this node holds
        /// nothing under the id.
        reason: String,
        /// Which voice it waits for, as the gate words it.
        detail: String,
    },
}

impl VoiceOutcome {
    /// The row id (hex).
    #[must_use]
    pub fn row_id(&self) -> &str {
        match self {
            Self::Seated { row_id } | Self::Waiting { row_id, .. } => row_id,
        }
    }

    /// Did the row land?
    #[must_use]
    pub fn is_seated(&self) -> bool {
        matches!(self, Self::Seated { .. })
    }

    /// The HTTP status a host surface answers: 200 seated, 424 waiting.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        if self.is_seated() {
            200
        } else {
            424
        }
    }

    /// The outcome as JSON for a host surface (with `http_status`).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(m) = v.as_object_mut() {
            m.insert("http_status".into(), serde_json::json!(self.http_status()));
        }
        v
    }
}

/// **The state of row `row_id`**: `Seated` when the attestation plane holds
/// it, else `Waiting` with its held reason (`fold::why_held`), else `Waiting`
/// with an empty reason (nothing under the id has arrived).
///
/// # Errors
/// Directory reads.
pub async fn row_status<F>(dir: &F, row_id: &RowId) -> Result<VoiceOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let hex = row_id.hex();
    if dir.get_attestation(&hex).await?.is_some() {
        return Ok(VoiceOutcome::Seated { row_id: hex });
    }
    Ok(match super::fold::why_held(dir, row_id).await? {
        Some(h) => VoiceOutcome::Waiting {
            row_id: hex,
            reason: h.reason,
            detail: h.detail,
        },
        None => VoiceOutcome::Waiting {
            row_id: hex,
            reason: String::new(),
            detail: String::new(),
        },
    })
}

/// [`row_status`] after a statement door answered `outcome`.
///
/// # Errors
/// Directory reads.
pub async fn outcome_of<F>(dir: &F, outcome: &StatementOutcome) -> Result<VoiceOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let row_id = match outcome {
        StatementOutcome::Row { row_id, .. }
        | StatementOutcome::Voice { row_id, .. }
        | StatementOutcome::KeyPlane { row_id, .. }
        | StatementOutcome::Pending { row_id, .. } => *row_id,
    };
    row_status(dir, &row_id).await
}

/// A row statement's `(family, row type, sub, payload)`.
fn row_parts(statement: &[u8]) -> Result<(String, String, String, Value), Error> {
    let invalid = |m: &str| Error::InvalidArgument(format!("second-signer voice: {m}"));
    let (family, row_type) =
        family_of_statement(statement).ok_or_else(|| invalid("not a row statement"))?;
    let (protected, payload) = statement_parts(statement).ok_or_else(|| invalid("undecodable"))?;
    // CWT claims (header 15), `sub` (2).
    let sub = protected
        .get_int(15)
        .and_then(|c| c.get_int(2))
        .and_then(Value::as_text)
        .ok_or_else(|| invalid("no sub"))?
        .to_owned();
    Ok((family, row_type, sub, payload))
}

/// The CWT `iss` of a statement.
fn statement_iss(statement: &[u8]) -> Option<String> {
    let (protected, _) = statement_parts(statement)?;
    protected
        .get_int(15)
        .and_then(|c| c.get_int(1))
        .and_then(Value::as_text)
        .map(str::to_owned)
}

/// The author's statement among a row's held voices: the one whose `iss` is
/// the payload's `author`, else the first.
fn authoring_statement(voices: &[Vec<u8>]) -> Option<&Vec<u8>> {
    voices
        .iter()
        .find(|st| {
            statement_parts(st).is_some_and(|(_, p)| {
                p.get_text("author")
                    .and_then(Value::as_text)
                    .map(str::to_owned)
                    == statement_iss(st)
            })
        })
        .or_else(|| voices.first())
}

/// The most held rows one [`held_rows_for`] page returns.
pub const MAX_HELD_ROWS_PAGE: u32 = 1000;

/// **The held rows waiting for `key`'s voice** (only in `role`, when named),
/// after `after` (a held row id; `None` from the start), at most `limit`
/// (clamped to [`MAX_HELD_ROWS_PAGE`]); one entry per (row, role), in row-id
/// order.
///
/// The candidates are the rows whose last fold read `Dep::key(key)`
/// (`fold_dependents`, an index lookup on both backends): the gate's
/// resolver declares that read for every party it names, so every row
/// waiting for `key` is among them. Each candidate is kept when it is still
/// HELD (`fold_state`), `key` has not voiced it yet, and
/// [`resolved_second_signer_roles`] over its author's statement lists `key`
/// as a party of a role. Rows held for another reason that also read
/// `Dep::key(key)` are dropped by that last check. AU-fix1: a COUNTED
/// `admission:unit` row lists `key` in the role `member` when `key` is a
/// person of the roster version its `refs.head` names
/// (`admission::admission_unit_voice_parties`).
///
/// # Errors
/// Directory reads.
pub async fn held_rows_for<F>(
    dir: &F,
    key: &str,
    role: Option<&str>,
    after: Option<&RowId>,
    limit: u32,
) -> Result<Vec<HeldRow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let limit = usize::try_from(limit.min(MAX_HELD_ROWS_PAGE)).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    if limit == 0 {
        return Ok(out);
    }
    let candidates = dir.fold_dependents(&[Dep::key(key).read_key()]).await?;
    for row_id in candidates {
        if after.is_some_and(|a| row_id <= *a) {
            continue;
        }
        let Some(held) = dir.fold_state(&row_id).await?.and_then(|s| s.held) else {
            continue;
        };
        let voices = dir.edition2_voices(&row_id).await?;
        if voices
            .iter()
            .any(|v| statement_iss(v).as_deref() == Some(key))
        {
            continue;
        }
        let Some(st) = authoring_statement(&voices) else {
            continue;
        };
        let Ok((family, row_type, sub, _)) = row_parts(st) else {
            continue;
        };
        // AU-fix1 (CC 2.7.11, CC 2.6.1.9) — a COUNTED `admission:unit` row
        // has no second-signer role (a group act); every person of the
        // roster version its `refs.head` names may voice it, in the role
        // `member` (key_roles.json), and its count decides it
        // (`admission::check_admission_unit_counted`).
        if let Some(parties) =
            crate::federation::admission::admission_unit_voice_parties(dir.as_dyn_directory(), st)
                .await?
        {
            let member = crate::federation::admission::ADMISSION_UNIT_MEMBER_ROLE;
            if role.is_none_or(|want| want == member) && parties.iter().any(|p| p == key) {
                out.push(HeldRow {
                    row_id: row_id.hex(),
                    family: family.clone(),
                    row_type: row_type.clone(),
                    author: statement_iss(st).unwrap_or_default(),
                    sub: sub.clone(),
                    role: member.to_owned(),
                    parties,
                    reason: held.reason.clone(),
                    detail: held.detail.clone(),
                    statement: st.clone(),
                });
                if out.len() >= limit {
                    return Ok(out);
                }
            }
            continue;
        }
        for r in resolved_second_signer_roles(dir, st).await? {
            if role.is_some_and(|want| want != r.role) {
                continue;
            }
            let parties: Vec<String> = r
                .parties
                .iter()
                .filter_map(|p| match p {
                    SecondSignerParty::Key(k) => Some(k.clone()),
                    SecondSignerParty::OwnerOf(_) => None,
                })
                .collect();
            if !parties.iter().any(|p| p == key) {
                continue;
            }
            out.push(HeldRow {
                row_id: row_id.hex(),
                family: family.clone(),
                row_type: row_type.clone(),
                author: statement_iss(st).unwrap_or_default(),
                sub: sub.clone(),
                role: r.role.clone(),
                parties,
                reason: held.reason.clone(),
                detail: held.detail.clone(),
                statement: st.clone(),
            });
            if out.len() >= limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

/// The author's statement of a held row `row_id`, if any statement of it is
/// held here (the input of [`voice_draft`] by row id).
///
/// # Errors
/// Directory reads.
pub async fn held_statement<F>(dir: &F, row_id: &RowId) -> Result<Option<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let voices = dir.edition2_voices(row_id).await?;
    Ok(authoring_statement(&voices).cloned())
}

/// **The voice drafted for `signer_iss`'s pen** over a held row's
/// `statement` (the author's, or any voice: all share the payload): the same
/// `sub`, row type, family and payload, in a protected header naming
/// `signer_iss`. A hardware or remote signer signs `sig_structure` and
/// submits `Draft::assemble(signature)` ([`submit_voice`]).
///
/// # Errors
/// `InvalidArgument` for bytes that are no row statement, or a `signer_iss`
/// that is not an identity-ref.
pub fn voice_draft(statement: &[u8], signer_iss: &str) -> Result<Draft, Error> {
    let (family, row_type, sub, payload) = row_parts(statement)?;
    let kid = kid_of_identity_ref(signer_iss).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "second-signer voice: {signer_iss} is not an identity-ref"
        ))
    })?;
    draft_row(&kid, signer_iss, &sub, &row_type, &family, &payload)
        .map_err(|e| produce_error("second_signer_voice", e))
}

/// **Voice the held row `row_id` with `signer`**: its statement over the
/// author's payload (`edition2::produce::sign_row`, as itself), put through
/// the statement door; the row's resulting state.
///
/// # Errors
/// `InvalidArgument` when no statement of `row_id` is held;
/// `composite_signing_unavailable`; the door's refusals.
pub async fn voice_held_row<F>(
    dir: &F,
    signer: &crate::signing::LocalSigner,
    row_id: &RowId,
) -> Result<VoiceOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let st = held_statement(dir, row_id).await?.ok_or_else(|| {
        Error::InvalidArgument(format!(
            "second-signer voice: no statement of row {} is held",
            row_id.hex()
        ))
    })?;
    let (family, row_type, sub, payload) = row_parts(&st)?;
    let voice = super::produce::sign_row(signer, &sub, &row_type, &family, &payload)
        .await
        .map_err(|e| produce_error("second_signer_voice", e))?;
    let outcome = put_statement(dir, &voice, None, INGEST_TIER).await?;
    outcome_of(dir, &outcome).await
}

/// **Submit a voice signed elsewhere** (a [`voice_draft`] assembled) through
/// the statement door; the row's resulting state.
///
/// # Errors
/// The door's refusals.
pub async fn submit_voice<F>(dir: &F, statement: &[u8]) -> Result<VoiceOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let outcome = put_statement(dir, statement, None, INGEST_TIER).await?;
    outcome_of(dir, &outcome).await
}
