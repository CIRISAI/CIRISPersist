//! v59.0.0 (CIRISPersist#1106; CC 5.3.4, CC 3.3.6.2) — the earlier-form
//! serve-node re-bind row, **refused by name** since v62.0.0.
//!
//! v62.0.0 (C5-fix1; ceremony gap 1): the earlier re-bind machinery is
//! deleted with the baked v4 genesis bundle it read. "Seated serve node" was
//! the PINNED bundle's `serve_nodes`; a v62.0 node carries no pinned bundle,
//! so the earlier `is_seated_serve_node`, `rebind_held_for`,
//! `check_serve_rotation` / `refuse_own_serve_rotation` (the unilateral
//! rotation rule over the pinned transit pair) and the after-admission apply
//! of the carried row are gone. A seat and its X-Wing transit key come only
//! from the ingested `ceg-genesis-bundle/2` and an edition-2 re-bind counted
//! by its holders (`edition2::transport_rebind`).
//!
//! What stays is the refusal: an earlier-form row on [`REBIND_DIMENSION`] is
//! refused [`REBIND_WITHOUT_HOLDER_QUORUM`] at every `put_attestation`, so it
//! is never stored as an ordinary `scores` row and never gives a seat a key.

use super::types::{attestation_type, Attestation};
use super::Error;

/// The earlier re-bind row's dimension (persist-named; CC 5.3.4 names the act,
/// the holders' accord-signed canonical address update).
pub const REBIND_DIMENSION: &str = "transport:canonical_rebind:v1";
/// The refusal token of an earlier-form re-bind row (`Error::InvalidArgument`,
/// Python `ValueError`).
pub const REBIND_WITHOUT_HOLDER_QUORUM: &str = "transport_rebind_without_holder_quorum";

/// Is `row` an earlier-form re-bind (by its signed dimension)?
#[must_use]
pub fn is_rebind_row(row: &Attestation) -> bool {
    row.attestation_type == attestation_type::SCORES
        && super::admission::envelope_dimension(&row.attestation_envelope) == Some(REBIND_DIMENSION)
}

/// **The earlier re-bind row's admission rule** (run by `put_attestation` on
/// every backend; a no-op off the dimension): refused, always. No earlier-form
/// genesis seats a serve node, so no earlier-form row can count as a re-bind
/// (v62.0.0, C5-fix1).
///
/// # Errors
///
/// [`REBIND_WITHOUT_HOLDER_QUORUM`] for every row on [`REBIND_DIMENSION`].
pub fn check_rebind_admission(row: &Attestation) -> Result<(), Error> {
    if !is_rebind_row(row) {
        return Ok(());
    }
    Err(Error::InvalidArgument(format!(
        "{REBIND_WITHOUT_HOLDER_QUORUM}: re-bind row {}: an earlier-form re-bind seats no key — \
         a seat's transit key moves only by an edition-2 re-bind over the ingested \
         ceg-genesis-bundle/2 (CC 3.3.6.2, CIRISPersist#1106)",
        row.attestation_id
    )))
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::*;

    /// I2421 (v62.0.0, C5-fix1; ceremony gap 1) — **an earlier-form re-bind
    /// row is refused by name, whatever it carries**; a row off the dimension
    /// passes this gate untouched. Pure: the rule reads only the row.
    #[test]
    fn i2421_an_earlier_form_rebind_is_refused_by_name() {
        let mut row = crate::federation::genesis::ordinary_scores_row("i2421", "k");
        assert!(
            check_rebind_admission(&row).is_ok(),
            "I2421: off the dimension"
        );
        row.attestation_envelope["dimension"] = serde_json::json!(REBIND_DIMENSION);
        assert!(is_rebind_row(&row));
        match check_rebind_admission(&row) {
            Err(Error::InvalidArgument(m)) => assert!(
                m.starts_with(REBIND_WITHOUT_HOLDER_QUORUM),
                "I2421: refused by name: {m}"
            ),
            o => panic!("I2421: an earlier-form re-bind is refused, got {o:?}"),
        }
    }
}
