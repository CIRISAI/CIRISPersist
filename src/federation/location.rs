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

/// v4.11.0 (CIRISPersist#154 Ask 4) — read a geographic community's
/// containment cell from its `policy_blob`. Returns `Some(cell_id)` iff
/// `policy_blob.cohort_subkind == "geographic"` and a
/// `geographic_constraint.cell_id` string is present. `None` for any
/// non-geographic (or absent) policy — those admit on consensus_protocol
/// alone (the §8.1.13.2 dispatcher's default arm).
///
/// Shape: `{"cohort_subkind": "geographic",
///          "geographic_constraint": {"cell_id": "<h3>", "cell_resolution": N}}`.
pub fn geographic_constraint_cell(policy_blob: Option<&serde_json::Value>) -> Option<String> {
    let blob = policy_blob?;
    if blob.get("cohort_subkind").and_then(|v| v.as_str()) != Some("geographic") {
        return None;
    }
    blob.get("geographic_constraint")?
        .get("cell_id")?
        .as_str()
        .map(str::to_owned)
}

/// v4.11.0 (CIRISPersist#154 Ask 4 / §8.1.13.2 geographic predicate) —
/// is `member_proofs` sufficient to admit a member into a geographic
/// community bounded by `constraint_cell`? True iff the member has at
/// least one **in-force** (`withdrawn_at` unset), **unexpired**
/// (`valid_until` unset or `> now`) `location_proof` whose cell is
/// [`h3_cell_contained`] within `constraint_cell`. No valid contained
/// proof → not admissible (the §8.1.13.2 `return Ok(false)` path).
pub fn member_in_geographic_constraint(
    constraint_cell: &str,
    member_proofs: &[crate::federation::LocationProof],
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    member_proofs.iter().any(|p| {
        p.withdrawn_at.is_none()
            && p.valid_until.is_none_or(|vu| vu > now)
            && h3_cell_contained(&p.cell_id, constraint_cell)
    })
}

/// v4.11.0 (CIRISPersist#154 Ask 4, CEG 0.8 §8.1.13.2) — the geographic
/// `cohort_subkind` admission predicate, run on `put_community`. For a
/// geographic community (per [`geographic_constraint_cell`]), **every**
/// member of the submitted roster MUST hold an in-force, contained
/// `location_proof` ([`member_in_geographic_constraint`]) — else the
/// community is refused. Non-geographic communities pass through (admit
/// on `consensus_protocol` alone). Reads each member's proofs through the
/// directory, so it runs before the write on every backend.
pub async fn check_geographic_community_admission<D>(
    dir: &D,
    community: &crate::federation::Community,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    D: crate::federation::FederationDirectory + ?Sized,
{
    let Some(constraint_cell) = geographic_constraint_cell(community.policy_blob.as_ref()) else {
        return Ok(());
    };
    for m in &community.members {
        let proofs = dir.list_location_proofs_for(&m.key_id).await?;
        if !member_in_geographic_constraint(&constraint_cell, &proofs, now) {
            return Err(Error::InvalidArgument(format!(
                "geographic community member {} has no in-force location_proof contained in the \
                 constraint cell {constraint_cell} (CEG §8.1.13.2)",
                m.key_id
            )));
        }
    }
    Ok(())
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
    fn geographic_constraint_cell_reads_geographic_policy() {
        let geo = serde_json::json!({
            "cohort_subkind": "geographic",
            "geographic_constraint": {"cell_id": "abc", "cell_resolution": 3}
        });
        assert_eq!(
            geographic_constraint_cell(Some(&geo)),
            Some("abc".to_string())
        );
        // Non-geographic / absent → None (admit on consensus alone).
        let other = serde_json::json!({"cohort_subkind": "operator_defined"});
        assert_eq!(geographic_constraint_cell(Some(&other)), None);
        assert_eq!(geographic_constraint_cell(None), None);
    }

    #[test]
    fn member_admission_requires_in_force_contained_unexpired_proof() {
        use crate::federation::LocationProof;
        let ll = h3o::LatLng::new(37.0, -122.0).unwrap();
        let constraint = ll.to_cell(h3o::Resolution::Three).to_string();
        let inside7 = ll.to_cell(h3o::Resolution::Seven).to_string();
        let now: chrono::DateTime<chrono::Utc> = "2026-06-09T00:00:00Z".parse().unwrap();
        let proof =
            |cell: &str, withdrawn: Option<&str>, valid_until: Option<&str>| LocationProof {
                subject_key_id: "m".into(),
                cell_id: cell.into(),
                cell_resolution: 7,
                asserted_at: "2026-06-01T00:00:00Z".parse().unwrap(),
                valid_until: valid_until.map(|s| s.parse().unwrap()),
                attestation_evidence: None,
                withdrawn_at: withdrawn.map(|s| s.parse().unwrap()),
                persist_row_hash: String::new(),
            };
        // in-force, contained, unexpired → admit.
        assert!(member_in_geographic_constraint(
            &constraint,
            &[proof(&inside7, None, None)],
            now
        ));
        // withdrawn → not.
        assert!(!member_in_geographic_constraint(
            &constraint,
            &[proof(&inside7, Some("2026-06-05T00:00:00Z"), None)],
            now
        ));
        // expired → not.
        assert!(!member_in_geographic_constraint(
            &constraint,
            &[proof(&inside7, None, Some("2026-06-05T00:00:00Z"))],
            now
        ));
        // outside the constraint (Sydney res-7) → not.
        let outside = h3o::LatLng::new(-33.8, 151.2)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        assert!(!member_in_geographic_constraint(
            &constraint,
            &[proof(&outside, None, None)],
            now
        ));
        // no proofs → not.
        assert!(!member_in_geographic_constraint(&constraint, &[], now));
    }

    #[test]
    fn containment_invalid_input_is_false() {
        assert!(!h3_cell_contained("garbage", &res7_cell()));
        assert!(!h3_cell_contained(&res7_cell(), "garbage"));
    }
}
