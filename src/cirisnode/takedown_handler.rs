//! Takedown-admission orchestration (CIRISPersist#134, v3.6.0; rebuilt on the
//! CC 2.3 tombstone in v55.0.0, CIRISPersist#1007; the notice is a row in
//! v60.0.0, CIRISPersist#803).
//!
//! A takedown notice is a `takedown_notice:{basis}:v1` row (CC 3.1.1): the
//! plane's put door admitted it under the duty-holder rule
//! (`takedown_tombstone::check_takedown_notice_row_admission`, CC 4.5.5).
//! [`process_takedown_admission`] executes a HELD notice row: the row goes
//! to [`Engine::takedown_tombstone`](crate::Engine::takedown_tombstone), which
//! re-verifies its hybrid signature, re-asks CC 4.5.5 of this node's state,
//! and writes ONE bytes-plane tombstone citing the row's `attestation_id`
//! (CC 4.5.3 step 2: one row shape for takedown and purge).
//!
//! The pre-v60 `takedown_notice_from_contribution` is gone with the
//! Contribution: a notice is not re-shaped from a typed envelope any more.

use crate::federation::takedown_tombstone::{is_notice_row, token, TakedownNotice};

/// v60.0.0 (CIRISPersist#803) — **execute a takedown** on `engine`: the notice
/// row `notice_attestation_id`, held here, through
/// [`Engine::takedown_tombstone`](crate::Engine::takedown_tombstone). Returns
/// what the tombstone door did (the notice id, whether the tombstone was
/// written, the settle, whether this node destroyed its bytes or retracted
/// its own claim).
///
/// # Errors
///
/// `takedown_unauthorised` when no notice row by that id is held (or the row
/// held is not a notice); the door's own refusals; directory and bytes-plane
/// errors.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub async fn process_takedown_admission(
    engine: &crate::Engine,
    notice_attestation_id: &str,
) -> Result<crate::federation::takedown_tombstone::TakedownReport, crate::federation::Error> {
    let refuse = |reason: &str| crate::federation::Error::PurgeRefused {
        token: token::UNAUTHORISED,
        body: serde_json::json!({
            "notice_id": notice_attestation_id,
            "reason": reason,
        }),
    };
    let dir = engine.federation_directory();
    let row = dir
        .get_attestation(notice_attestation_id)
        .await?
        .ok_or_else(|| refuse("no takedown notice row by this id is held here"))?;
    if !is_notice_row(&row) {
        return Err(refuse(
            "the row held under this id is not a takedown notice",
        ));
    }
    let notice = TakedownNotice::of_row(&row)?;
    engine.takedown_tombstone(&notice).await
}
