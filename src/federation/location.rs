//! v4.10.0 (CIRISPersist#154, CEG 0.8 §0.8 / §0.8.1 / §0.8.2) — H3
//! geospatial canonicalization, the §0.8.1 rough-only privacy gate, and
//! cell containment.
//!
//! # Mission alignment (MISSION.md §1.4)
//!
//! H3 is geospatial indexing, **not** crypto — the "never rolls its own
//! crypto" invariant is unaffected. We use the pure-Rust [`h3o`] crate
//! (no libh3 C bindings), so this cross-compiles to the iOS / Android /
//! wasm wheel targets like the rest of the tree.
//!
//! The load-bearing rule is §0.8.1 **rough-only**: a `location_proof`'s
//! `cell_resolution` MUST be ≤ 7. The substrate is the second line of
//! defense after client UI gating — a producer cannot over-share precise
//! location even if the client fails. `validate_location_cell` enforces
//! it at admission, before the row is written.

use std::str::FromStr;

use h3o::CellIndex;

use super::Error;

/// §0.8.1 — the maximum H3 resolution a `location_proof` may carry.
/// Finer than this over-shares; the substrate refuses it.
pub const MAX_LOCATION_PROOF_RESOLUTION: u8 = 7;

/// Parse + validate an H3 `cell_id` per CEG 0.8 §0.8:
///
/// 1. lowercase hex (the canonical wire form — uppercase is rejected),
/// 2. a valid H3 cell index (h3o parses the `u64` and checks structure),
/// 3. resolution-redundancy: the cell's own encoded resolution MUST equal
///    the asserted `cell_resolution`.
///
/// Returns the parsed [`CellIndex`] on success.
pub fn parse_canonical_cell(cell_id: &str, cell_resolution: u8) -> Result<CellIndex, Error> {
    // §0.8 rule 1 — lowercase hex only (canonical form). Reject uppercase
    // up front so two encodings of the same cell can't both admit.
    if cell_id.is_empty() || cell_id.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(Error::InvalidArgument(format!(
            "location_proof cell_id must be lowercase hex (got {cell_id:?})"
        )));
    }
    let raw = u64::from_str_radix(cell_id, 16).map_err(|_| {
        Error::InvalidArgument(format!("location_proof cell_id is not hex: {cell_id:?}"))
    })?;
    // §0.8 rule 2 — structurally valid H3 cell. (h3o validates the
    // mode/reserved bits + digit ranges; `from_str` also works but
    // requires the exact canonical string — go through the u64 so a
    // valid-but-non-15-char hex still resolves.)
    let cell = CellIndex::try_from(raw).map_err(|_| {
        Error::InvalidArgument(format!(
            "location_proof cell_id is not a valid H3 cell: {cell_id:?}"
        ))
    })?;
    // §0.8 rule 3 — resolution redundancy: the asserted resolution must
    // match the cell's own encoded resolution (no lying about coarseness).
    let actual = u8::from(cell.resolution());
    if actual != cell_resolution {
        return Err(Error::InvalidArgument(format!(
            "location_proof cell_resolution {cell_resolution} disagrees with cell_id's encoded \
             resolution {actual}"
        )));
    }
    Ok(cell)
}

/// Full §0.8 + §0.8.1 admission gate for a `location_proof`: canonical
/// form + resolution-redundancy ([`parse_canonical_cell`]) **and** the
/// rough-only bound (`cell_resolution <= 7`). Returns the violation as an
/// [`Error::InvalidArgument`] (the substrate's refusal IS the privacy
/// enforcement); callers may additionally emit the §7.8
/// `hard_case:location_proof_resolution_violation` telemetry.
pub fn validate_location_cell(cell_id: &str, cell_resolution: u8) -> Result<(), Error> {
    parse_canonical_cell(cell_id, cell_resolution)?;
    if cell_resolution > MAX_LOCATION_PROOF_RESOLUTION {
        return Err(Error::InvalidArgument(format!(
            "location_proof resolution {cell_resolution} exceeds the §0.8.1 rough-only bound \
             ({MAX_LOCATION_PROOF_RESOLUTION}) — over-precise location is refused"
        )));
    }
    Ok(())
}

/// CEG 0.8 §0.8.2 — is `contained` geographically inside `container`?
/// True iff `contained` is at the same or finer resolution and its
/// ancestor at the container's resolution IS the container cell. Invalid
/// cell strings → `false` (a malformed claim contains nothing). Used by
/// the geographic-subkind community admission predicate (#154 Ask 4) and
/// the `communities_containing(cell)` cascade read.
pub fn h3_cell_contained(contained_cell_id: &str, container_cell_id: &str) -> bool {
    let (Ok(contained), Ok(container)) = (
        CellIndex::from_str(contained_cell_id),
        CellIndex::from_str(container_cell_id),
    ) else {
        return false;
    };
    if contained.resolution() < container.resolution() {
        return false; // coarser than the container can't be inside it
    }
    contained.parent(container.resolution()) == Some(container)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A known-valid H3 res-7 cell + its res-1 ancestor, computed from h3o
    // so the test is self-consistent with the linked crate version.
    fn res7_cell() -> String {
        // lat/lng → res-7 cell, lowercased hex.
        let ll = h3o::LatLng::new(37.0, -122.0).unwrap();
        ll.to_cell(h3o::Resolution::Seven).to_string()
    }

    #[test]
    fn valid_res7_cell_admits() {
        let c = res7_cell();
        assert!(validate_location_cell(&c, 7).is_ok());
    }

    #[test]
    fn resolution_redundancy_mismatch_rejected() {
        let c = res7_cell();
        // Assert the wrong resolution for a res-7 cell.
        let err = validate_location_cell(&c, 5).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains("resolution")),
            "got: {err:?}"
        );
    }

    #[test]
    fn over_precise_resolution_refused() {
        // res-9 cell → fails the §0.8.1 rough-only bound (≤7).
        let ll = h3o::LatLng::new(37.0, -122.0).unwrap();
        let c9 = ll.to_cell(h3o::Resolution::Nine).to_string();
        let err = validate_location_cell(&c9, 9).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains("rough-only")),
            "got: {err:?}"
        );
    }

    #[test]
    fn uppercase_hex_rejected() {
        let c = res7_cell().to_uppercase();
        let err = validate_location_cell(&c, 7).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains("lowercase")),
            "got: {err:?}"
        );
    }

    #[test]
    fn garbage_cell_rejected() {
        assert!(validate_location_cell("not-hex", 7).is_err());
        assert!(validate_location_cell("ffffffffffffffff", 7).is_err());
    }

    #[test]
    fn containment_parent_child() {
        let ll = h3o::LatLng::new(37.0, -122.0).unwrap();
        let fine = ll.to_cell(h3o::Resolution::Seven).to_string();
        let coarse = ll.to_cell(h3o::Resolution::Three).to_string();
        assert!(
            h3_cell_contained(&fine, &coarse),
            "res7 inside its res3 parent"
        );
        assert!(!h3_cell_contained(&coarse, &fine), "coarse not inside fine");
        assert!(h3_cell_contained(&fine, &fine), "a cell contains itself");
    }

    #[test]
    fn containment_disjoint_cells() {
        let a = h3o::LatLng::new(37.0, -122.0)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        let b = h3o::LatLng::new(-33.8, 151.2) // Sydney — far from California
            .unwrap()
            .to_cell(h3o::Resolution::Three)
            .to_string();
        assert!(!h3_cell_contained(&a, &b));
    }

    #[test]
    fn containment_invalid_input_is_false() {
        assert!(!h3_cell_contained("garbage", &res7_cell()));
        assert!(!h3_cell_contained(&res7_cell(), "garbage"));
    }
}
