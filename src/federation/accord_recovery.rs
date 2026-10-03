//! v53.0.0 (CC 4.2.6, rc7 `fe459cf`/`5e89627`) — **an accord holder's
//! recovery.**
//!
//! Every holder carries a pre-committed recovery key, committed in the
//! accord's charter (`recovery_commitments`, a [`recovery_commitment`] over
//! the key's material). "A holder who has lost signing-key material, and only
//! that holder, rotates by a `supersedes` signed under the recovery key; the
//! rotation is a roster change by that holder about themselves and needs no
//! quorum."
//!
//! The rotation is a new version of the accord's family record (CC 3.2 T6: a
//! roster-affecting row produces a new version) that differs from the held
//! head in exactly one seat — the old signing key swapped for the new — and in
//! its head fields (`prev_head_digest` = the held head). It enters through the
//! accord's one door ([`verify_family_admission`](super::tier_ingest::verify_family_admission)),
//! as the second shape that door admits beside a quorum-proven head version:
//!
//! - its `supersede_proof.change_envelope` is the **recovery statement**
//!   ([`RECOVERY_STATEMENT_KIND`]): the family, the held head it replaces, the
//!   offered version's content hash, the old and new holder keys, the recovery
//!   key, and the commitment to the new key's own next recovery key;
//! - its one `quorum_signatures` entry is the recovery key's hybrid signature
//!   over that statement's JCS bytes, verified against the recovery key's
//!   STORED record;
//! - the commitment recomputed from that stored record must equal the old
//!   holder's commitment in force ([`recovery_commitment_in_force`]) — so a
//!   record registered under the committed id with other keys is refused;
//! - the record itself is signed by the NEW key (possession of the key that
//!   takes the seat).
//!
//! The statement is recorded as the superseded version's authorization, so the
//! version chain is the ledger: a recovery key that already rotated a seat is
//! spent (`accord_recovery_key_spent`), and a recovered holder's next recovery
//! commitment is the one its recovery statement named.

use super::canonical_community::{charter_in_force, HeadCharter};
use super::cohort::Cohort;
use super::trust_root::{recovery_commitment, CommittedKey};
use super::types::{Family, FamilyMember, SignedFamily};
use super::{Error, FederationDirectory};

/// The `kind` of a recovery statement.
pub const RECOVERY_STATEMENT_KIND: &str = "ciris.accord_recovery.v1";

fn refuse<T>(token: &str, detail: impl std::fmt::Display) -> Result<T, Error> {
    Err(Error::CharterInvalid {
        detail: format!("{token}: {detail}"),
    })
}

fn well_formed_commitment(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// What a host asks for: which seat, to which key, under which recovery key,
/// and the commitment to the new key's own recovery key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccordRecoveryRequest {
    /// The accord family (`humanity-accord`).
    pub family_key_id: String,
    /// The seat's lost signing key.
    pub old_holder_key_id: String,
    /// The new signing key (registered before the rotation).
    pub new_holder_key_id: String,
    /// The old holder's pre-committed recovery key (registered).
    pub recovery_key_id: String,
    /// The commitment ([`recovery_commitment`]) to the new key's recovery key.
    pub next_recovery_commitment: String,
    /// The new seat's `joined_at`, stamped once by the caller.
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

/// The bytes the two keys sign, and the version they produce.
#[derive(Debug, Clone, PartialEq)]
pub struct AccordRecoveryDraft {
    /// The offered version of the family record.
    pub next: Family,
    /// The recovery statement (the supersede proof's change envelope).
    pub statement: serde_json::Value,
    /// JCS of the statement: the recovery key signs these.
    pub statement_bytes: Vec<u8>,
    /// JCS of the offered record's signing envelope: the NEW key signs these.
    pub record_bytes: Vec<u8>,
}

/// **Draft a recovery** against the accord this node holds.
///
/// # Errors
///
/// No held accord; the old key holds no seat; the new key already does.
pub async fn draft_accord_recovery<F>(
    directory: &F,
    req: &AccordRecoveryRequest,
) -> Result<AccordRecoveryDraft, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = directory
        .lookup_family(&req.family_key_id)
        .await?
        .ok_or_else(|| Error::InvalidArgument(format!("no family {}", req.family_key_id)))?;
    let Some(seat) = held
        .members
        .iter()
        .find(|m| m.key_id == req.old_holder_key_id)
    else {
        return refuse(
            "accord_recovery_not_a_holder",
            format!(
                "{} holds no seat in {}",
                req.old_holder_key_id, req.family_key_id
            ),
        );
    };
    if held
        .members
        .iter()
        .any(|m| m.key_id == req.new_holder_key_id)
    {
        return refuse(
            "accord_recovery_seat_taken",
            format!("{} already holds a seat", req.new_holder_key_id),
        );
    }
    let role = seat.role.clone();
    let mut next = held.clone();
    next.persist_row_hash = String::new();
    next.prev_head_digest = held.persist_row_hash.clone();
    for m in &mut next.members {
        if m.key_id == req.old_holder_key_id {
            *m = FamilyMember {
                key_id: req.new_holder_key_id.clone(),
                joined_at: req.joined_at,
                role: role.clone(),
            };
        }
    }
    let statement = serde_json::json!({
        "kind": RECOVERY_STATEMENT_KIND,
        "family_key_id": req.family_key_id,
        "prior_persist_row_hash": held.persist_row_hash,
        "next_persist_row_hash": super::types::compute_persist_row_hash(&next)?,
        "old_holder_key_id": req.old_holder_key_id,
        "new_holder_key_id": req.new_holder_key_id,
        "recovery_key_id": req.recovery_key_id,
        "next_recovery_commitment": req.next_recovery_commitment,
    });
    let jcs = |v: &serde_json::Value| {
        crate::verify::canonical::ceg_produce_canonicalize(v)
            .map_err(|e| Error::InvalidArgument(format!("recovery canonicalize: {e}")))
    };
    Ok(AccordRecoveryDraft {
        statement_bytes: jcs(&statement)?,
        record_bytes: jcs(&next.signing_envelope())?,
        next,
        statement,
    })
}

/// **Rotate a holder's seat under their recovery key** (CC 4.2.6): the draft,
/// the recovery key's signature over `statement_bytes` and the new key's over
/// `record_bytes`, each `(Ed25519, ML-DSA-65 over bytes ‖ ed_sig)` base64.
/// No quorum. Returns the new version number.
///
/// # Errors
///
/// [`Error::CharterInvalid`] naming the refusal (`accord_recovery_*`), or the
/// write door's own refusals.
pub async fn recover_accord_holder<F>(
    directory: &F,
    draft: AccordRecoveryDraft,
    recovery_signature: (String, String),
    new_holder_signature: (String, String),
) -> Result<u32, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = directory
        .lookup_family(&draft.next.family_key_id)
        .await?
        .ok_or_else(|| Error::InvalidArgument(format!("no family {}", draft.next.family_key_id)))?;
    let signed = recovery_version(
        &held.persist_row_hash,
        &draft,
        recovery_signature,
        new_holder_signature,
    );
    // Judged here with its reason, then admitted by the accord's one door.
    verify_accord_recovery(directory, &signed).await?;
    let authorization = serde_json::json!({
        "change_envelope": draft.statement.clone(),
        "quorum_signatures": signed
            .supersede_proof
            .as_ref()
            .map(|p| p.quorum_signatures.clone())
            .unwrap_or_default(),
    });
    super::group_amendment::supersede_family_signed(directory, signed, Some(authorization)).await
}

/// **The signed recovery version** a draft and its two signatures form: the
/// record signed by the new key, the supersede proof carrying the statement
/// and the recovery key's signature, naming `held_head` as its prior. What
/// [`recover_accord_holder`] submits and what a peer receives.
#[must_use]
pub fn recovery_version(
    held_head: &str,
    draft: &AccordRecoveryDraft,
    recovery_signature: (String, String),
    new_holder_signature: (String, String),
) -> SignedFamily {
    let field = |k: &str| {
        draft
            .statement
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    SignedFamily {
        family: draft.next.clone(),
        authority_key_id: field("new_holder_key_id"),
        scrub_signature_classical: new_holder_signature.0,
        scrub_signature_pqc: Some(new_holder_signature.1),
        supersede_proof: Some(super::types::GroupSupersedeProof {
            prior_persist_row_hash: held_head.to_owned(),
            change_envelope: draft.statement.clone(),
            quorum_signatures: vec![ciris_verify_core::threshold::ThresholdSignature {
                member_id: field("recovery_key_id"),
                ed25519_signature_base64: recovery_signature.0,
                mldsa65_signature_base64: Some(recovery_signature.1),
            }],
        }),
        cosignatures: Vec::new(),
    }
}

/// The recovery statements this accord's version chain records, oldest first.
pub(crate) async fn recorded_statements<F>(
    directory: &F,
    family_key_id: &str,
) -> Result<Vec<serde_json::Value>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(directory
        .list_group_versions(Cohort::Family, family_key_id)
        .await?
        .into_iter()
        .filter_map(|v| v.authorization)
        .filter_map(|a| a.get("change_envelope").cloned())
        .filter(|e| e.get("kind").and_then(|k| k.as_str()) == Some(RECOVERY_STATEMENT_KIND))
        .collect())
}

/// **The recovery commitment in force for `holder`**: the one the latest
/// recovery that seated `holder` named, else the entry in the charter the
/// accord's head names ([`charter_in_force`]). `None` when neither names one.
///
/// # Errors
///
/// Directory read failures.
pub async fn recovery_commitment_in_force<F>(
    directory: &F,
    family_key_id: &str,
    holder: &str,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let seated_by_recovery = recorded_statements(directory, family_key_id)
        .await?
        .into_iter()
        .rev()
        .find(|s| s.get("new_holder_key_id").and_then(|v| v.as_str()) == Some(holder))
        .and_then(|s| {
            s.get("next_recovery_commitment")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        });
    if seated_by_recovery.is_some() {
        return Ok(seated_by_recovery);
    }
    let (charter_key, head) = charter_in_force(directory, family_key_id).await?;
    if !matches!(head, HeadCharter::Named(_)) {
        return Ok(None);
    }
    Ok(directory
        .list_attestations_for(&charter_key)
        .await?
        .iter()
        .find(|a| head.admits(a))
        .and_then(|a| {
            a.attestation_envelope
                .get(super::envelope::paths::RECOVERY_COMMITMENTS)
                .and_then(|m| m.get(holder))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        }))
}

/// **Is `signed` a valid recovery version of the held accord?** `Ok(None)`
/// when it is not shaped as one (no recovery statement); `Ok(Some(new
/// holder))` when it is and every check holds; `Err` naming the first check
/// that fails.
///
/// # Errors
///
/// [`Error::CharterInvalid`] with an `accord_recovery_*` token; directory read
/// failures.
pub async fn verify_accord_recovery<F>(
    directory: &F,
    signed: &SignedFamily,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // CC 4.2.6 is the accord's rule; no other family rotates a seat this way.
    if signed.family.family_key_id
        != ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
    {
        return Ok(None);
    }
    let Some(proof) = signed.supersede_proof.as_ref() else {
        return Ok(None);
    };
    let st = &proof.change_envelope;
    if st.get("kind").and_then(|k| k.as_str()) != Some(RECOVERY_STATEMENT_KIND) {
        return Ok(None);
    }
    let field = |k: &str| st.get(k).and_then(|v| v.as_str()).unwrap_or_default();
    let offered = &signed.family;
    let (old, new, recovery_key_id, next_commitment) = (
        field("old_holder_key_id"),
        field("new_holder_key_id"),
        field("recovery_key_id"),
        field("next_recovery_commitment"),
    );
    let Some(held) = directory.lookup_family(&offered.family_key_id).await? else {
        return refuse("accord_recovery_no_held_accord", &offered.family_key_id);
    };
    // The statement names this family, this held head and this version.
    if field("family_key_id") != offered.family_key_id
        || field("prior_persist_row_hash") != held.persist_row_hash
        || proof.prior_persist_row_hash != held.persist_row_hash
        || offered.prev_head_digest != held.persist_row_hash
        || field("next_persist_row_hash") != super::types::compute_persist_row_hash(offered)?
    {
        return refuse(
            "accord_recovery_statement_unbound",
            "the statement must name this family, the held head it replaces and the offered \
             version's content hash, and the version must name the held head",
        );
    }
    // Exactly one seat moves, old -> new; nothing else but the head.
    let mut expected = held.clone();
    expected.persist_row_hash = String::new();
    expected.prev_head_digest = held.persist_row_hash.clone();
    let Some(seat) = expected.members.iter_mut().find(|m| m.key_id == old) else {
        return refuse(
            "accord_recovery_not_a_holder",
            format!("{old} holds no seat"),
        );
    };
    if held.members.iter().any(|m| m.key_id == new) || new.is_empty() {
        return refuse(
            "accord_recovery_seat_taken",
            format!("{new} already holds a seat"),
        );
    }
    // v53.0.0 (CC 4.2.6) — the key taking the seat is an accord holder's key.
    if !super::accord_roster::is_accord_holder_key(directory, new).await? {
        return refuse(
            "accord_recovery_not_a_holder_key",
            format!("{new} is not an accord_holder key record (CC 4.2.6)"),
        );
    }
    let joined_at = offered
        .members
        .iter()
        .find(|m| m.key_id == new)
        .map(|m| m.joined_at)
        .unwrap_or(seat.joined_at);
    *seat = FamilyMember {
        key_id: new.to_owned(),
        joined_at,
        role: seat.role.clone(),
    };
    let mut bare = offered.clone();
    bare.persist_row_hash = String::new();
    if bare != expected {
        return refuse(
            "accord_recovery_changes_more_than_its_seat",
            "a recovery swaps the holder's own seat and changes nothing else (CC 4.2.6)",
        );
    }
    // The record is signed by the key that takes the seat.
    if signed.authority_key_id != new {
        return refuse(
            "accord_recovery_record_not_signed_by_new_key",
            format!(
                "the version is signed by {}, not {new}",
                signed.authority_key_id
            ),
        );
    }
    if !well_formed_commitment(next_commitment) {
        return refuse(
            "accord_recovery_next_commitment_malformed",
            "the new key's recovery commitment is not 64 lowercase hex",
        );
    }
    // The recovery key: its STORED material reproduces the old holder's
    // commitment in force, it has not rotated a seat before, and it signed.
    let Some(in_force) = recovery_commitment_in_force(directory, &held.family_key_id, old).await?
    else {
        return refuse(
            "accord_recovery_commitment_missing",
            format!("no recovery commitment is in force for {old}"),
        );
    };
    let Some(record) = directory.lookup_public_key(recovery_key_id).await? else {
        return refuse(
            "accord_recovery_key_unregistered",
            format!("recovery key {recovery_key_id} is not registered"),
        );
    };
    let presented = CommittedKey::from_record(&record)
        .and_then(|k| recovery_commitment(&k))
        .map_err(|e| Error::CharterInvalid {
            detail: format!("accord_recovery_key_mismatch: {e}"),
        })?;
    if presented != in_force {
        return refuse(
            "accord_recovery_key_mismatch",
            format!(
                "the stored keys of {recovery_key_id} do not reproduce {old}'s recovery \
                 commitment (an id that matches with other keys is not the committed key)"
            ),
        );
    }
    if next_commitment == in_force {
        return refuse(
            "accord_recovery_next_commitment_not_fresh",
            "the new key's recovery commitment repeats the spent one",
        );
    }
    let spent = recorded_statements(directory, &held.family_key_id)
        .await?
        .iter()
        .any(|s| s.get("recovery_key_id").and_then(|v| v.as_str()) == Some(recovery_key_id));
    if spent {
        return refuse(
            "accord_recovery_key_spent",
            format!("{recovery_key_id} already rotated a seat"),
        );
    }
    let [sig] = proof.quorum_signatures.as_slice() else {
        return refuse(
            "accord_recovery_signature",
            "a recovery carries exactly one signature: the recovery key's",
        );
    };
    if sig.member_id != recovery_key_id {
        return refuse(
            "accord_recovery_signature",
            format!("signed by {}, not the recovery key", sig.member_id),
        );
    }
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(st)
        .map_err(|e| Error::InvalidArgument(format!("recovery canonicalize: {e}")))?;
    crate::verify::hybrid::verify_hybrid(
        &bytes,
        &sig.ed25519_signature_base64,
        sig.mldsa65_signature_base64.as_deref(),
        &record.pubkey_ed25519_base64,
        record.pubkey_ml_dsa_65_base64.as_deref(),
        crate::verify::hybrid::HybridPolicy::Strict,
        None,
    )
    .map_err(|e| Error::CharterInvalid {
        detail: format!("accord_recovery_signature: {e}"),
    })?;
    Ok(Some(new.to_owned()))
}
