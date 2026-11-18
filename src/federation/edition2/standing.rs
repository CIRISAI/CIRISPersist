//! v62.0.0 (P4, CC rc20 3.4.7 / 3.4.7.1) — **standing is conferred, never
//! declared.**
//!
//! An edition-2 key becomes live through its OWN self-signed `key:record`, and
//! that record's `identity_type` is an open vocabulary (Verify's
//! `check_key_record` admits any sorted, non-empty text set). So the set is the
//! key's statement about itself, and CC rc20 3.4.7 rules: "No key declares
//! itself into a duty. `identity_type` on a key record is the key's own
//! statement about itself. No admission decision reads it to open a reserved
//! family." 3.4.7.1: "A conferral is not a label."
//!
//! Where CC names the conferral, persist reads it there:
//! - **accord-holder standing**: a holder of the genesis bundle in force for
//!   the accord ([`holds_accord_standing`]; CC 3.4.1, CC 4.2.1);
//! - **canonical standing**: a seat in `serve_nodes` of the bundle in force
//!   (`genesis::is_canonical_by_bundle`, ruling C);
//! - **a reserved duty** (`infra:detect` for `detection:*`, ...): the
//!   `delegates_to` chain from a root this node trusts
//!   (`trust_root::capability_roots_to_trusted_root`, CC 4.4.3.34's delegation
//!   plane);
//! - the halt: the holders the bundle in force places (`halt::HaltRoster`).
//!
//! The admission gates branch on [`carries_statement`]: a row carrying an
//! edition-2 statement is judged on the conferral plane
//! (`admission::EmitterStanding::Conferred`), an earlier-form row as before.

use crate::federation::types::Attestation;
use crate::federation::{Error, FederationDirectory};

/// Does `row` carry an edition-2 statement (the envelope member
/// [`super::ingest::STATEMENT_MEMBER`])? Tier 2 of the attestation plan
/// (`ingest::verify_carried`) has already checked that such a row is exactly
/// the projection of the statement it carries, so a peer cannot attach a
/// statement to an earlier-form row to change which plane judges it.
#[must_use]
pub fn carries_statement(row: &Attestation) -> bool {
    row.attestation_envelope
        .get(super::ingest::STATEMENT_MEMBER)
        .is_some()
}

/// Is `signer` (an identity-ref) a standing holder of the accord named
/// `accord_root`, in `in_force`: the accord's name is `accord_root` and every
/// tip of the bundle in force seats `signer` as a holder? Pure.
///
/// The identity-ref names the holder's genesis key and survives a rotation
/// (CC 4.2.1); the door's key-of-issuer check (`kid_not_of_iss`) has already
/// bound the signing key to `signer`.
#[must_use]
pub fn accord_standing_in(
    in_force: &super::genesis::GenesisInForce,
    signer: &str,
    accord_root: &str,
) -> bool {
    in_force.family_key_id() == Some(accord_root)
        && in_force.holders().iter().any(|h| h.identity_ref == signer)
}

/// v62.0.0 (P4, I3082) — **accord-holder standing, from the bundle in force.**
/// `false` with no bundle held, on a genesis fork, for another accord, or for
/// a signer the bundle does not seat. The signer's own `accord_holder` label is
/// never read (CC rc20 3.4.7: "The accord's holders are fixed by the accord's
/// charter, and no delegation confers that standing").
///
/// # Errors
/// Directory read failures.
pub async fn holds_accord_standing<F>(
    dir: &F,
    signer: &str,
    accord_root: &str,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let in_force = super::genesis::genesis_in_force(dir).await?;
    Ok(accord_standing_in(&in_force, signer, accord_root))
}
