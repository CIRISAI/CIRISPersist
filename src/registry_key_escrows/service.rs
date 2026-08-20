//! The `KeyEscrowService` trait — the fold target for CIRISRegistry's
//! three PortalService escrow RPCs (CIRISPersist#752).

use std::future::Future;

use super::types::{EscrowStatus, KeyEscrowRow};
use super::Error;

/// Working-index operations for CC 4.4.3.2.8 `archive_custody` metadata.
///
/// Every write is idempotent for byte-identical re-puts and fail-secure for
/// differing claims on occupied keys (the #719 absorb-then-re-read
/// discipline — `DO NOTHING` alone silently accepts a differing concurrent
/// write, which is what these doors exist to refuse).
pub trait KeyEscrowService: Send + Sync {
    /// Create (or idempotently re-create) an escrow record. `escrow_id` is
    /// caller-minted — the registry slice owns id minting, exactly as the
    /// RPC did. `true` on first write, `false` on a byte-identical re-put;
    /// a DIFFERING row on an occupied id is `Error::Conflict`.
    ///
    /// The row's `status` must be `Active` — an escrow is born live; its
    /// terminal states are reached only through [`Self::set_escrow_status`],
    /// so the lifecycle has exactly one door.
    fn create_escrow(&self, row: &KeyEscrowRow)
        -> impl Future<Output = Result<bool, Error>> + Send;

    /// Point lookup by `escrow_id`.
    fn get_escrow(
        &self,
        escrow_id: &str,
    ) -> impl Future<Output = Result<Option<KeyEscrowRow>, Error>> + Send;

    /// Registry's `ListKeyEscrows`: every escrow for one org, ordered by
    /// `escrow_id` (the `idx_key_escrows_org` index).
    fn list_escrows_for_org(
        &self,
        org_id: &str,
    ) -> impl Future<Output = Result<Vec<KeyEscrowRow>, Error>> + Send;

    /// Every escrow naming one key (the `idx_key_escrows_key` index) —
    /// the recovery path's first question: "who holds copies of this key?"
    fn list_escrows_for_key(
        &self,
        key_id: &str,
    ) -> impl Future<Output = Result<Vec<KeyEscrowRow>, Error>> + Send;

    /// The lifecycle door. `Active → Recovered | Revoked | Expired` moves;
    /// a same-state re-assertion is an idempotent no-op (`Ok(false)`);
    /// any transition OUT of a terminal state is `Error::Conflict` — a
    /// custody outcome pins, it never flips. Missing row is `NotFound`.
    fn set_escrow_status(
        &self,
        escrow_id: &str,
        status: EscrowStatus,
    ) -> impl Future<Output = Result<bool, Error>> + Send;
}
