//! v62.0.0 (wave V1, CC 2.6.1.9) — **counting edition-2 voices**.
//!
//! In edition 2 a co-signature is not a member of the row's envelope: it is
//! a separate VOICE, an edition-2 statement over the same payload, so the
//! same row id, held in `ceg_statements`. A gate that counted the earlier
//! form's `additional_scrubs` (re-verified over the JSON envelope) counts 0
//! for an edition-2 row, and every quorum fails. The gates count here
//! instead.
//!
//! Every held voice was verified at its door before it was kept
//! ([`ingest::put_statement`](super::ingest::put_statement),
//! [`ingest::apply_replicated_statement`](super::ingest::apply_replicated_statement),
//! T1's group door), so nothing here re-verifies a signature: it reads the
//! signer's `iss`, `kid` and the payload's `asserted_at` from the held bytes.

use std::collections::BTreeSet;

use super::door::AdmittedRow;
use super::liveness::statement_parts;
use super::names::RowId;
use super::Digest32;
use crate::federation::types::Attestation;
use crate::federation::{Error, FederationDirectory};

/// One held voice of a row: one signer's edition-2 statement over the row's
/// payload, as `ceg_statements` holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Voice {
    /// The CWT `iss`: the signer's identity-ref (a person; a second device
    /// of the same person shares it).
    pub iss: String,
    /// The signing key's thumbprint (protected header label 4).
    pub kid: Digest32,
    /// The payload's `asserted_at`, POSIX ms (the same for every voice of
    /// one row id, since the payload is).
    pub asserted_at_ms: u64,
}

/// The voice a held statement states, if it is a row statement of exactly
/// `row_id`. Anything else held under the id (an object voice, bytes that do
/// not decode) is not a voice of the row and is skipped.
fn voice_of(statement: &[u8], row_id: &RowId) -> Option<Voice> {
    if RowId::of_statement(statement)? != *row_id {
        return None;
    }
    let (protected, payload) = statement_parts(statement)?;
    let iss = protected.get_int(15)?.get_int(1)?.as_text()?.to_owned();
    let kid = <[u8; 32]>::try_from(protected.get_int(4)?.as_bytes()?).ok()?;
    let asserted_at_ms = payload.get_text("asserted_at")?.as_u64()?;
    Some(Voice {
        iss,
        kid,
        asserted_at_ms,
    })
}

/// **Every held voice of `row_id`**, one per held statement, in
/// statement-id order (the backends' `ORDER BY statement_id`). A held
/// statement that is not a row statement of exactly `row_id` is skipped,
/// never counted.
///
/// # Errors
/// Directory read failures.
pub async fn voices_of_row<F>(dir: &F, row_id: &RowId) -> Result<Vec<Voice>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (wave G0) — a fold that counts these voices read this row:
    // a later voice of it re-folds that fold (`edition2::fold`).
    super::fold::reads(super::fold::Dep::Row(*row_id));
    let mut out: Vec<Voice> = dir
        .edition2_voices(row_id)
        .await?
        .iter()
        .filter_map(|st| voice_of(st, row_id))
        .collect();
    // v62.0.0 (wave V1b) — the voice the door is offering now, while it
    // re-runs a counted row's gates ([`put_counted_row`]): verified at the
    // door, counted with the held ones, kept only if the row lands or waits.
    // v62.0.0 (wave G0) — the attempt is the fold's (`fold::attempt`).
    if let Some(v) = super::fold::offered_voice(row_id) {
        out.push(v);
    }
    Ok(out)
}

/// The edition-2 row id of a row that carries its statement (it is stored
/// under its row id, as lowercase hex). `None` for an earlier-form row.
#[must_use]
pub fn carried_row_id(row: &Attestation) -> Option<RowId> {
    row.attestation_envelope
        .get(super::ingest::STATEMENT_MEMBER)?;
    let b = hex::decode(&row.attestation_id).ok()?;
    <[u8; 32]>::try_from(b.as_slice()).ok().map(RowId)
}

/// The voice of the statement `row` carries (its first voice, the one the
/// row was admitted on; the attestation door re-verified it through
/// [`ingest::verify_carried`](super::ingest::verify_carried)). `None` for an
/// earlier-form row.
///
/// The row's admission gates run BEFORE its first statement is kept in
/// `ceg_statements` (`ingest::put_admitted_row`), so a gate that counts a row
/// it is admitting reads this voice from the row, not from the store.
#[must_use]
pub fn carried_voice(row: &Attestation) -> Option<Voice> {
    let row_id = carried_row_id(row)?;
    let h = row
        .attestation_envelope
        .get(super::ingest::STATEMENT_MEMBER)?
        .as_str()?;
    voice_of(&hex::decode(h).ok()?, &row_id)
}

/// The DISTINCT signers (`iss`) among `row_id`'s voices that are members of
/// `roster` (identity-refs, as the typed group rows hold them).
///
/// # Errors
/// Directory read failures.
pub async fn roster_voices<F>(
    dir: &F,
    row_id: &RowId,
    roster: &[String],
) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(voices_of_row(dir, row_id)
        .await?
        .into_iter()
        .map(|v| v.iss)
        .filter(|iss| roster.iter().any(|m| m == iss))
        .collect())
}

/// **The one switch every co-signature-counting gate calls** for a row: how
/// many DISTINCT members of `roster` stand behind `row`?
///
/// - a row carrying its edition-2 statement: its voices
///   ([`roster_voices`]);
/// - an earlier-form row while the earlier-form doors are open: its
///   re-verified scrub set, unchanged
///   ([`count_distinct_roster_scrubs`](crate::federation::reverse_quorum::count_distinct_roster_scrubs));
///   F deletes this arm;
/// - an earlier-form row once the doors are shut: nobody.
///
/// # Errors
/// Directory read failures.
pub async fn counted_roster_signers<F>(
    dir: &F,
    row: &Attestation,
    roster: &[String],
) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if let Some(row_id) = carried_row_id(row) {
        let mut counted = roster_voices(dir, &row_id, roster).await?;
        // The row's own first voice, which a gate admitting the row reads
        // before the store keeps it.
        if let Some(v) = carried_voice(row) {
            if roster.contains(&v.iss) {
                counted.insert(v.iss);
            }
        }
        return Ok(counted);
    }
    if super::door::earlier_form_doors_shut() {
        return Ok(BTreeSet::new());
    }
    Ok(
        crate::federation::reverse_quorum::count_distinct_roster_scrubs(
            dir,
            &row.attestation_envelope,
            &row.scrubs(),
            roster,
        )
        .await,
    )
}

/// Every distinct signer (`iss`) of a statement-carrying `row`: its held
/// voices and its own carried voice, with no roster filter (the kernel's
/// owner seat reads the full voice set). Empty for an earlier-form row.
///
/// # Errors
/// Directory read failures.
pub async fn row_voice_issuers<F>(dir: &F, row: &Attestation) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(row_id) = carried_row_id(row) else {
        return Ok(BTreeSet::new());
    };
    let mut out: BTreeSet<String> = voices_of_row(dir, &row_id)
        .await?
        .into_iter()
        .map(|v| v.iss)
        .collect();
    if let Some(v) = carried_voice(row) {
        out.insert(v.iss);
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────
//  The counted-row hold (wave V1b)
// ─────────────────────────────────────────────────────────────────────────

/// **A gate found the row's voices short of its quorum.** Called by a gate,
/// structurally, right before it returns its shortfall refusal, so the door
/// keeps the voice and answers `Pending` instead of refusing it
/// ([`put_counted_row`]). A no-op outside the door's attempt (the earlier
/// form, a read, a replayed check): there the refusal stands.
///
/// v62.0.0 (wave G0) — one fold condition among others: the attempt is
/// held with reason [`count_short`](super::fold::reason::COUNT_SHORT).
pub(crate) fn note_short() {
    super::fold::note(super::fold::reason::COUNT_SHORT);
}

/// The voice that should project the typed row: the author's own voice for an
/// authored row (a second signer's consent never becomes the row's
/// attester), else the first held voice that is still admitted, else the
/// voice offered now. A held voice is re-admitted under the key plane as it
/// stands, so a signer revoked since never projects the row.
async fn primary_voice<F>(dir: &F, admitted: &AdmittedRow) -> Result<AdmittedRow, Error>
where
    F: FederationDirectory + ?Sized,
{
    if admitted.author.as_deref() == Some(admitted.iss.as_str()) {
        return Ok(admitted.clone());
    }
    for st in dir.edition2_voices(&admitted.row_id).await? {
        let Some(v) = voice_of(&st, &admitted.row_id) else {
            continue;
        };
        let wanted = match &admitted.author {
            Some(author) => v.iss == *author,
            None => true,
        };
        if !wanted {
            continue;
        }
        let keys = super::ingest::held_keys_for(dir, &st).await?;
        if let Ok(p) = super::door::admit_row(
            &st,
            &keys,
            Some(&admitted.row_id.0),
            ciris_verify_core::edition2::family::SelectContext::default(),
        ) {
            return Ok(p);
        }
    }
    Ok(admitted.clone())
}

/// v62.0.0 (wave V1b, CC 2.6.1.9) — **the store tail for a row through the
/// attestation gates, counted by its voices.** Every family that reaches the
/// attestation door (not T1's group planes, O1's occurrences, T2's typed
/// planes or the key plane, which route first):
///
/// - a row already held: this voice joins it (`Voice`);
/// - otherwise the row, projected from its primary voice ([`primary_voice`]),
///   runs the attestation gates with THIS voice counted beside the held ones
///   ([`voices_of_row`] reads it during the attempt):
///   - admitted: the typed row lands, and the voice is kept (`Row`);
///   - refused by a gate that found the voices SHORT of a quorum
///     ([`note_short`], structurally, never by the error's text): the voice is
///     kept in `ceg_statements`, no typed row is written (`Pending`), and a
///     later voice re-runs the gates over all of them;
///   - any other refusal: refused, nothing kept.
///
/// A voice from a signer that is no member of the counted roster is kept
/// like any verified voice but is never counted, so it never completes the
/// row; a duplicate signer's re-offer is the same statement (`new: false`)
/// or another voice of the same `iss`, which counts once.
///
/// # Errors
/// The attestation gates' refusals other than a shortfall; directory errors.
pub async fn put_counted_row<F>(
    dir: &F,
    admitted: &AdmittedRow,
    tier: &str,
    origin: crate::federation::replication::admission::WriteOrigin,
) -> Result<super::ingest::StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::ingest::StatementOutcome;
    if dir.get_attestation(&admitted.row_id.hex()).await?.is_some() {
        let new = dir.put_edition2_statement(admitted).await?;
        return Ok(StatementOutcome::Voice {
            row_id: admitted.row_id,
            new,
        });
    }
    let primary = primary_voice(dir, admitted).await?;
    let row = super::ingest::attestation_of(&primary, tier)?;
    let offered = Voice {
        iss: admitted.iss.clone(),
        kid: admitted.kid,
        asserted_at_ms: admitted.asserted_at_ms,
    };
    // v62.0.0 (wave G0; CC 2.7.3) — the gates run as a fold attempt: a gate
    // that finds a fold condition unmet (a count short, an owner not seated,
    // a binding not proven) marks it, and the row is HELD with that reason,
    // never refused; every input the gates read is recorded, so the row
    // re-folds when one changes (`edition2::fold`).
    let (out, att) = super::fold::attempt(
        admitted.row_id,
        Some(offered),
        dir.put_attestation_with_origin(
            crate::federation::SignedAttestation { attestation: row },
            origin,
        ),
    )
    .await;
    match (out, att.held) {
        (Ok(_), _) => {
            if primary.statement_id != admitted.statement_id {
                dir.put_edition2_statement(&primary).await?;
            }
            let new = dir.put_edition2_statement(admitted).await?;
            super::fold::record(
                dir,
                admitted.row_id,
                &admitted.family,
                tier,
                None,
                att.reads,
            )
            .await?;
            Ok(StatementOutcome::Row {
                row_id: admitted.row_id,
                new,
            })
        }
        (Err(e), Some((reason, detail))) => {
            let new = dir.put_edition2_statement(admitted).await?;
            let detail = if detail.is_empty() {
                e.to_string()
            } else {
                detail
            };
            tracing::debug!(
                row_id = %admitted.row_id.hex(),
                family = %admitted.family,
                reason = %reason,
                detail = %detail,
                "edition-2 row held: it concludes nothing until its condition holds"
            );
            super::fold::record(
                dir,
                admitted.row_id,
                &admitted.family,
                tier,
                Some((reason, detail)),
                att.reads,
            )
            .await?;
            Ok(StatementOutcome::Pending {
                row_id: admitted.row_id,
                new,
            })
        }
        (Err(e), None) => Err(e),
    }
}
