//! v47.2.0 (CIRISPersist#853, `FSD/BYTES_PLANE_TOMBSTONE.md` §3.2) — **CC 2.3
//! at the bytes plane**: are the bytes at a sha still established by a LIVE
//! row, or has every row binding them been retired by a `withdraws` whose
//! authority this node re-derives now?

use crate::federation::{Error, FederationDirectory};

/// What the rows binding a blob say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingState {
    /// No row on this node binds these bytes. The read proceeds as before
    /// #853 — distinct from [`Self::Live`] so a witness can tell "no row"
    /// from "a live row".
    Unbound,
    /// At least one binding row is live.
    Live,
    /// Every binding row is retired, each by a `withdraws` re-derived NOW.
    Withdrawn {
        /// The last live binding row.
        attestation_id: String,
        /// The composer that retired it.
        withdraws_id: String,
    },
}

/// The fold. RED-CHECKPOINT STUB: answers [`BindingState::Unbound`] for every
/// sha, which is exactly the pre-#853 behaviour the witnesses must catch.
pub async fn binding_state<D>(
    directory: &D,
    at_rest_sha256: &[u8; 32],
) -> Result<BindingState, Error>
where
    D: FederationDirectory + ?Sized + Sync,
{
    let _ = (directory, at_rest_sha256);
    Ok(BindingState::Unbound)
}
