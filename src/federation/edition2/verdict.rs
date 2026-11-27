//! v62.0.0 (VD-step1; CC 2.7.3, CC 2.7.5) — **one row-state verdict.**
//!
//! "Is this row concluded?" is answered HERE and nowhere else. Three defects
//! came from code answering it for itself:
//!
//! - a device's lone `identity:occurrence` bind voice was served to an
//!   anonymous reader because "no fold hold recorded" was read as
//!   "concluded" (I2415, RL-fix23);
//! - a `supersedes` landed over a target whose statement was KEPT but had
//!   not concluded (PIN-fix9d);
//! - a withdrawal verb answered `Ok(row id)` for a held statement as for a
//!   landed one (KR-fix21).
//!
//! Neither "no hold is recorded" nor "a statement is kept" says a row is
//! concluded: a lone voice is kept with no hold (`StatementOutcome::Voice`),
//! a voice whose re-run answers `Voice` has its earlier hold CLEARED
//! (`ingest::put_admitted_row`, fix3), and a row never folded here has no
//! fold state at all. A row is concluded when its plane's typed projection
//! holds it, read per plane below ([`row_state`]).
//!
//! The hold's REASON stays the fold's ([`super::fold::why_held`]); that API
//! answers "why does it conclude nothing", never "is it concluded".
//! `P/tools/no_inferred_conclusion.sh` keeps a `fold_held(..)` read, or a
//! `None` hold read as a conclusion, out of every other file.

use super::fold::{plane, HeldReason};
use super::names::RowId;
use crate::federation::{Error, FederationDirectory};

/// The state of a row on this node, as one verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowState {
    /// Concluded: its plane's typed projection holds it (an attestation row,
    /// the key plane's statement, an occurrence bind in the occurrence read
    /// model, a counted re-bind, a group / typed-final row whose door
    /// recorded its conclusion).
    Concluded,
    /// The fold holds it: kept, concluding nothing, for this reason.
    Held(HeldReason),
    /// A statement is kept under the id, but nothing concluded and no hold
    /// is recorded: a lone voice (a device's bind voice before its
    /// identity's), a cosign voice, a row this node has not folded.
    /// NOT concluded, NOT in force.
    KeptUnconcluded,
    /// No statement under the id here.
    Absent,
}

impl RowState {
    /// Is the row concluded here? The ONLY "concluded / in force / landed"
    /// answer persist reads off a row's state.
    #[must_use]
    pub fn is_concluded(&self) -> bool {
        matches!(self, Self::Concluded)
    }

    /// Is a statement kept under the id (concluded, held or neither)?
    #[must_use]
    pub fn is_kept(&self) -> bool {
        !matches!(self, Self::Absent)
    }

    /// The hold, when the fold holds it.
    #[must_use]
    pub fn held(&self) -> Option<&HeldReason> {
        match self {
            Self::Held(h) => Some(h),
            _ => None,
        }
    }
}

/// **The state of `row_id` here** ([`RowState`]).
///
/// In order:
///
/// 1. a seat re-bind (`transport:canonical_rebind`): concluded when it
///    reaches its count NOW ([`super::transport_rebind::rebind_counted`]),
///    never by the fold's stored state (KR-fix2 rev 5); else the listed
///    hold ([`super::fold::why_held_listed`]);
/// 2. a recorded fold hold: [`RowState::Held`];
/// 3. an attestation row: concluded (the attestation, trust and typed
///    attestation planes' projection);
/// 4. no statement kept: a byte executor's row (plane `bytes`, no statement
///    of its own) with a fold state is concluded; anything else is
///    [`RowState::Absent`] (a purged row's statements are deleted with it);
/// 5. by the kept statement's family: a key-plane statement
///    (`key:record`, `key:revocation`) not held back is concluded (the key
///    plane's read model is exactly those); an `identity:occurrence` bind is
///    concluded when the occurrence it states is held in the occurrence read
///    model (its typed row; a lone voice is not; a retraction of the family
///    is not a bind and takes the next rule); any other family is
///    concluded when its door recorded the conclusion (a fold state with no
///    hold), else [`RowState::KeptUnconcluded`].
///
/// A genesis bundle OBJECT is not a row: its conclusion is Verify's
/// lineage reader's (`genesis::held_voices` hands it the voices).
///
/// # Errors
/// Directory reads.
pub async fn row_state<F>(dir: &F, row_id: &RowId) -> Result<RowState, Error>
where
    F: FederationDirectory + ?Sized,
{
    use ciris_verify_core::namespace_match::family_id;
    let voices = dir.edition2_voices(row_id).await?;
    let own = voices
        .iter()
        .find(|st| RowId::of_statement(st) == Some(*row_id))
        .or_else(|| voices.first());
    let family = own
        .and_then(|st| super::emit::family_of_statement(st.as_slice()))
        .map(|(f, _)| f);
    let is =
        |f: &str| family.as_deref() == Some(f) || family.as_deref() == Some(family_id(f).as_str());
    // 1. The re-bind plane: recomputed, never the stored state.
    if is(super::transport_rebind::REBIND_FAMILY) {
        if super::transport_rebind::rebind_counted(dir, row_id).await? == Some(true) {
            return Ok(RowState::Concluded);
        }
        return Ok(match super::fold::why_held_listed(dir, row_id).await? {
            Some(h) => RowState::Held(h),
            None => RowState::KeptUnconcluded,
        });
    }
    // 2. A recorded hold.
    let state = dir.fold_state(row_id).await?;
    if let Some(h) = state.as_ref().and_then(|s| s.held.clone()) {
        return Ok(RowState::Held(h));
    }
    // 3. The attestation planes' projection.
    if dir.get_attestation(&row_id.hex()).await?.is_some() {
        return Ok(RowState::Concluded);
    }
    // 4. Nothing kept.
    let Some(own) = own else {
        return Ok(match state {
            Some(s) if s.plane == plane::BYTES => RowState::Concluded,
            _ => RowState::Absent,
        });
    };
    // 5. By family.
    if is(ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY)
        || is(super::liveness::KEY_REVOCATION_FAMILY)
    {
        return Ok(RowState::Concluded);
    }
    // An occurrence BIND (not a retraction of this family: a proposer's
    // `withdraws` of its open proposal lands as its own row, recorded by the
    // door, and states no occurrence).
    let composer = super::emit::family_of_statement(own.as_slice())
        .is_some_and(|(_, row_type)| super::emit::carries_no_dimension(&row_type));
    if is(super::occurrence::OCCURRENCE_FAMILY) && !composer {
        return Ok(if occurrence_bind_held(dir, own).await? {
            RowState::Concluded
        } else {
            RowState::KeptUnconcluded
        });
    }
    Ok(if state.is_some() {
        RowState::Concluded
    } else {
        RowState::KeptUnconcluded
    })
}

/// v62.0.0 (RL-fix23, moved here by VD-step1) — **is the occurrence this
/// `identity:occurrence` bind states held in the occurrence read model?**
/// The bind's typed row is the occurrence row `(identity_key_id,
/// occurrence_key_id)` at the bind's own `asserted_at`; a lone device voice
/// never writes it. `false` for a statement that does not read as a bind.
///
/// # Errors
/// Directory reads.
async fn occurrence_bind_held<F>(dir: &F, statement: &[u8]) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    use ciris_verify_core::cde::Value;
    let Some((_, payload)) = super::liveness::statement_parts(statement) else {
        return Ok(false);
    };
    let text = |k: &str| payload.get_text(k).and_then(Value::as_text);
    let (Some(identity), Some(occurrence), Some(at)) = (
        text("identity_key_id"),
        text("occurrence_key_id"),
        payload.get_text("asserted_at").and_then(Value::as_u64),
    ) else {
        return Ok(false);
    };
    Ok(dir
        .list_identity_occurrences_by_occurrence_key(occurrence)
        .await?
        .iter()
        .any(|o| {
            o.identity_key_id == identity
                && u64::try_from(o.asserted_at.timestamp_millis()).ok() == Some(at)
        }))
}
