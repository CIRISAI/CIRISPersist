//! **The `licensure:{authority_id}` status fold** (v42.0.0, CIRISPersist#814
//! part 2, CC 3.1.1 / CIRISConstitution#100 ask 3).
//!
//! Two normative semantics the registry row could already express and this
//! crate could not read:
//!
//! * **`revoked` is ABSORBING; `suspended` is reversible.** A later status row
//!   may lift a suspension; nothing lifts a revocation. A re-licence is a *new*
//!   licence under a new authority attestation, never a status transition. So
//!   once a live `revoked` exists for a `(subject, authority_id)`, the fold is
//!   exactly `{Revoked}` — no later `issued` can dilute it, and a consumer MUST
//!   NOT infer one status from another.
//! * **More than one status may be live at once.** `issued` + `probation` is
//!   two facts, not a blended state, so the fold produces a **set** and
//!   consumers compose it. A scalar would have to pick a winner, and every rule
//!   for picking one is a policy this substrate does not own.
//!
//! # Why a set rather than "latest wins"
//!
//! Latest-wins is the shape that looks obviously right and quietly discards a
//! fact. A licence carrying `issued` and `restricted` concurrently is a licence
//! that exists and is limited; collapsing to whichever row arrived last reports
//! either an unlimited licence or no licence at all, depending on arrival
//! order — and arrival order across a mesh is not a fact about the licence.

use std::collections::BTreeSet;

use super::{Attestation, Error, FederationDirectory};

/// The `licensure:` dimension prefix. A dimension is
/// `licensure:{authority_id}`, optionally with a `:v{n}` suffix.
pub const LICENSURE_DIMENSION_PREFIX: &str = "licensure:";

/// The CC 3.1.1 licensure status vocabulary, widened by
/// CIRISConstitution#100 ask 3.
///
/// Closed on purpose: an unrecognized status is NOT folded (see
/// [`status_set_for`]), because a status nobody has defined cannot be composed
/// against `revoked`'s absorption rule, and guessing would be the fail-open
/// direction on a plane that decides whether someone may practise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LicensureStatus {
    /// The licence exists and is unrestricted.
    Issued,
    /// Live, under heightened supervision.
    Probation,
    /// Live, with named limits on scope of practice.
    Restricted,
    /// Live but not currently exercisable — **reversible**. A later row may
    /// lift it.
    Suspended,
    /// **Terminal and absorbing.** Nothing lifts a revocation; a re-licence is
    /// a new licence under a new authority attestation.
    Revoked,
    /// Expired without renewal — an administrative end, not an adverse one.
    Lapsed,
    /// Voluntarily given up by the holder.
    Surrendered,
    /// Downgraded to a narrower class.
    Reduced,
}

impl LicensureStatus {
    /// The wire value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LicensureStatus::Issued => "issued",
            LicensureStatus::Probation => "probation",
            LicensureStatus::Restricted => "restricted",
            LicensureStatus::Suspended => "suspended",
            LicensureStatus::Revoked => "revoked",
            LicensureStatus::Lapsed => "lapsed",
            LicensureStatus::Surrendered => "surrendered",
            LicensureStatus::Reduced => "reduced",
        }
    }

    /// Inverse of [`Self::as_str`]. `None` for anything outside the closed set.
    #[must_use]
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "issued" => Some(LicensureStatus::Issued),
            "probation" => Some(LicensureStatus::Probation),
            "restricted" => Some(LicensureStatus::Restricted),
            "suspended" => Some(LicensureStatus::Suspended),
            "revoked" => Some(LicensureStatus::Revoked),
            "lapsed" => Some(LicensureStatus::Lapsed),
            "surrendered" => Some(LicensureStatus::Surrendered),
            "reduced" => Some(LicensureStatus::Reduced),
            _ => None,
        }
    }

    /// Every member, for exhaustive callers. Hand-written, and a test pins that
    /// it stays exhaustive — a consumer picking a subset by hand is the #637
    /// defect (a duty-conferral card shipped able to confer three of five).
    pub const ALL: &'static [LicensureStatus] = &[
        LicensureStatus::Issued,
        LicensureStatus::Probation,
        LicensureStatus::Restricted,
        LicensureStatus::Suspended,
        LicensureStatus::Revoked,
        LicensureStatus::Lapsed,
        LicensureStatus::Surrendered,
        LicensureStatus::Reduced,
    ];
}

/// The `authority_id` a `licensure:` dimension names, or `None` if the
/// dimension is not a licensure dimension or names an empty authority.
///
/// A trailing `:v{n}` is part of neither the prefix nor the authority: the
/// dimension `licensure:acme:v1` is authority `acme`.
#[must_use]
pub fn authority_of(dimension: &str) -> Option<&str> {
    let rest = dimension.strip_prefix(LICENSURE_DIMENSION_PREFIX)?;
    let authority = rest.split(':').next().unwrap_or("");
    (!authority.is_empty()).then_some(authority)
}

/// Read the envelope's declared status, if it is in the closed vocabulary.
fn status_of(row: &Attestation) -> Option<LicensureStatus> {
    row.attestation_envelope
        .get("status")
        .and_then(serde_json::Value::as_str)
        .and_then(LicensureStatus::parse_str)
}

/// **The fold**: every live status for `(subject_key_id, authority_id)`.
///
/// * Retired rows (superseded / withdrawn / recanted) are dropped through
///   [`precedence::retired_ids`](super::precedence::retired_ids) — the ONE
///   retirement fold, not a copy of it.
/// * A live `Revoked` **absorbs**: the result is exactly `{Revoked}`.
/// * Otherwise every live, recognized status is returned.
/// * An unrecognized status value is ignored rather than guessed at.
///
/// The empty set means "no live licensure statement from this authority", which
/// is NOT the same as `Lapsed` and must not be rendered as one.
pub async fn status_set_for(
    directory: &dyn FederationDirectory,
    subject_key_id: &str,
    authority_id: &str,
) -> Result<BTreeSet<LicensureStatus>, Error> {
    let rows = directory.list_attestations_for(subject_key_id).await?;
    let refs: Vec<&Attestation> = rows.iter().collect();
    let retired = super::precedence::retired_ids(&refs);

    let mut out = BTreeSet::new();
    for row in &rows {
        if retired.contains(&row.attestation_id) {
            continue;
        }
        let Some(dimension) = super::admission::envelope_dimension(&row.attestation_envelope)
        else {
            continue;
        };
        if authority_of(dimension) != Some(authority_id) {
            continue;
        }
        if let Some(status) = status_of(row) {
            out.insert(status);
        }
    }
    // `revoked` is absorbing — see the module docs. Applied AFTER collection so
    // a revocation anywhere in the live set wins regardless of arrival order.
    if out.contains(&LicensureStatus::Revoked) {
        return Ok(BTreeSet::from([LicensureStatus::Revoked]));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_wire_round_trip_is_total() {
        for s in LicensureStatus::ALL {
            assert_eq!(LicensureStatus::parse_str(s.as_str()), Some(*s));
        }
        assert_eq!(
            LicensureStatus::ALL.len(),
            8,
            "CC 3.1.1 widened the set to 8"
        );
        assert_eq!(LicensureStatus::parse_str("withdrawn"), None);
        assert_eq!(LicensureStatus::parse_str(""), None);
    }

    /// The vocabulary as LITERALS — CIRISConstitution#100 ask 3's list, copied
    /// by hand rather than derived from `ALL`, so a member silently dropped
    /// from the enum is a red here rather than a quietly shorter round-trip.
    #[test]
    fn the_cc_status_vocabulary_is_present_814() {
        for wire in [
            "issued",
            "probation",
            "restricted",
            "suspended",
            "revoked",
            "lapsed",
            "surrendered",
            "reduced",
        ] {
            assert!(
                LicensureStatus::parse_str(wire).is_some(),
                "CC 3.1.1 names {wire:?} as a licensure status and persist does not parse it"
            );
        }
    }

    #[test]
    fn authority_parsing_814() {
        assert_eq!(authority_of("licensure:acme"), Some("acme"));
        assert_eq!(authority_of("licensure:acme:v1"), Some("acme"));
        assert_eq!(authority_of("licensure:"), None, "empty authority");
        assert_eq!(authority_of("licensure"), None, "not a licensure dimension");
        assert_eq!(
            authority_of("licensure_board:acme"),
            None,
            "the prefix must end at the colon — a bare string prefix would \
             capture a different family"
        );
        assert_eq!(authority_of("scores:acme"), None);
    }
}
