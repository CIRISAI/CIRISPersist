//! v47.2.0 (CIRISPersist#853, `FSD/BYTES_PLANE_TOMBSTONE.md` §3.2) — **CC 2.3
//! at the bytes plane**: are the bytes at a sha still established by a LIVE
//! row, or has every row binding them been retired by a `withdraws` whose
//! authority this node re-derives NOW, against the target it holds now?
//!
//! The operator's constraint (#853): the write door admits a `withdraws`
//! whose target is not local with `rule = None`, so authority is a read-side
//! concern. The read is the moment persist finally holds both rows, so the
//! read is where the rule is computed — `check_withdraws_admission` against
//! the local target — and the STORED `withdraws_admission_rule` is never
//! consulted. A fold that trusted it, or read `None` as anything but "not
//! retired", would turn replication into a remote-delete primitive.

use crate::federation::types::attestation_type;
use crate::federation::{Attestation, Error, FederationDirectory};

/// What the rows binding a blob say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingState {
    /// No row on this node binds these bytes. The read proceeds as before
    /// #853 — distinct from [`Self::Live`] so a witness can tell "no row"
    /// from "a live row".
    Unbound,
    /// At least one binding row is live. CC 2.3 is a subject's right to pull
    /// THEIR row; one withdrawn reference does not delete bytes another live
    /// row still establishes.
    Live,
    /// Every binding row is retired, each by a composer re-derived NOW.
    Withdrawn {
        /// The last live binding row.
        attestation_id: String,
        /// The composer that retired it.
        withdraws_id: String,
    },
}

/// The fold. Per binding row (`attestations_binding_content`, both reference
/// shapes since #862): gather the composers naming it from the same slice
/// every `retired_ids` caller folds over, REPLACE each retraction's stored
/// entitlement with the one re-derived now, and let §6.1 precedence decide.
pub async fn binding_state(
    directory: &dyn FederationDirectory,
    at_rest_sha256: &[u8; 32],
) -> Result<BindingState, Error> {
    let sha_hex = hex::encode(at_rest_sha256);
    let bindings = directory.attestations_binding_content(&sha_hex).await?;
    if bindings.is_empty() {
        return Ok(BindingState::Unbound);
    }
    let mut last_retired: Option<(String, String)> = None;
    for row in &bindings {
        match retiring_composer(directory, row).await? {
            None => return Ok(BindingState::Live),
            Some(w) => last_retired = Some((row.attestation_id.clone(), w)),
        }
    }
    let (attestation_id, withdraws_id) = last_retired.expect("bindings is non-empty");
    Ok(BindingState::Withdrawn {
        attestation_id,
        withdraws_id,
    })
}

/// The composer that retires `row` under §6.1 precedence, with every
/// `withdraws`/`recants` entitlement RE-DERIVED against `row` as this node
/// holds it now — or `None` if the row is live.
async fn retiring_composer(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<Option<String>, Error> {
    // The composers naming the row, found by REFERENCE: a subject's
    // withdraws is attested to the issuer, so neither the target's by-slice
    // nor its for-slice reaches it.
    let slice = directory
        .list_attestations_referencing(&row.attestation_id)
        .await?;
    let mut refs: Vec<Attestation> = Vec::with_capacity(slice.len() + 1);
    refs.push(row.clone());
    for g in slice {
        if g.attestation_id == row.attestation_id {
            continue;
        }
        let is_retraction = g.attestation_type == attestation_type::WITHDRAWS
            || g.attestation_type == attestation_type::RECANTS;
        if is_retraction {
            // THE CONSTRAINT: never the stored rule. `Ok(Some(_))` is the only
            // entitled verdict; `Ok(None)` (target absent at admission, or a
            // holds_bytes target) and `Err(WithdrawsNotAdmitted)` both mean
            // "this composer does not retire the bytes". The stored column is
            // overwritten with the re-derived one so `retraction_entitled`'s
            // arm 3 sees exactly what was proven now.
            let rederived = match crate::federation::admission::check_withdraws_admission(
                directory, &g,
            )
            .await
            {
                Ok(rule) => rule,
                Err(Error::WithdrawsNotAdmitted { .. }) => None,
                Err(e) => return Err(e),
            };
            // The re-derivation is the ONLY authority here. Rules 1 and 2
            // (the target's own attester / a subject) are among what
            // `check_withdraws_admission` derives, so re-spelling them from
            // the row's fields beside it would be a second predicate — and
            // one that hid the stored-rule mutant from the witness.
            let Some(rule) = rederived else {
                continue;
            };
            let mut g = g;
            g.withdraws_admission_rule = Some(rule);
            refs.push(g);
        } else {
            refs.push(g);
        }
    }
    let borrowed: Vec<&Attestation> = refs.iter().collect();
    let retired = crate::federation::precedence::retired_ids(&borrowed);
    if !retired.contains(&row.attestation_id) {
        return Ok(None);
    }
    // The row IS retired (decided above, by the one fold). Name the retiring
    // composer for the refusal: the §6.1 winner among the retractions that
    // survived re-derivation — and if precedence declines to rank them, the
    // most recent one. Naming can never flip the verdict back to live.
    let retractions: Vec<&Attestation> = borrowed
        .iter()
        .copied()
        .filter(|g| {
            g.attestation_id != row.attestation_id
                && (g.attestation_type == attestation_type::WITHDRAWS
                    || g.attestation_type == attestation_type::RECANTS)
        })
        .collect();
    let named = crate::federation::precedence::precedence_winner(&retractions)
        .or_else(|| retractions.iter().copied().max_by_key(|g| g.asserted_at))
        .map(|g| g.attestation_id.clone())
        .unwrap_or_else(|| "<retraction>".to_owned());
    Ok(Some(named))
}
