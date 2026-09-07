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
/// * Withdrawn / recanted rows are dropped through
///   [`precedence::retired_ids`](super::precedence::retired_ids) — the ONE
///   retraction fold, not a copy of it. **Superseded rows are dropped
///   separately**, because `retired_ids` is a retraction fold and by its own
///   documentation does not filter `supersedes` (they rank below both
///   retraction forms in §6.1). Conflating the two is what left a lifted
///   suspension live.
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
    Ok(fold_status_set(&rows, authority_id))
}

/// The fold itself, over rows already read — **pure**, so it is testable
/// without standing up an authority.
///
/// Split out from [`status_set_for`] deliberately (v42.0.0): the write door
/// now requires a `registry`/`verify` attester for `licensure:` (CC 3.4.9), and
/// such a key needs accord-roster admission. An end-to-end witness for the
/// fold's ALGEBRA would therefore have to stand up a quorum to assert something
/// that is a pure function of rows. Separating I/O from the fold lets the
/// algebra be witnessed exhaustively here and the door be witnessed where it
/// belongs — rather than the algebra going untested because its fixture is
/// expensive, which is how `supersedes` lifting a suspension came to be
/// documented and never asserted.
#[must_use]
pub fn fold_status_set(rows: &[Attestation], authority_id: &str) -> BTreeSet<LicensureStatus> {
    let refs: Vec<&Attestation> = rows.iter().collect();
    let retired = super::precedence::retired_ids(&refs);

    // v42.0.0 (found by review) — `retired_ids` is a RETRACTION fold: it drops
    // a row only when the §6.1 precedence winner is `withdraws` or `recants`,
    // and its own docs say `supersedes` rows are deliberately not filtered
    // because they rank BELOW both retraction forms. So it does not answer
    // "was this replaced".
    //
    // That gap is load-bearing HERE specifically: `supersedes` is the CEG
    // replace-in-place primitive and therefore the natural way an authority
    // lifts a suspension. Without this pass a lifted suspension stays live
    // forever — `{Issued, Suspended}` — and any consumer testing
    // `contains(Suspended)` keeps the holder out of practice after the
    // authority formally reinstated them. This is the CIRISPersist#798 class
    // (type-keyed folds must resolve through the supersedes chain), handled
    // locally rather than left for the caller.
    let superseded: std::collections::HashSet<&str> = rows
        .iter()
        .filter(|r| {
            r.attestation_type == super::types::attestation_type::SUPERSEDES
                && !retired.contains(&r.attestation_id)
        })
        .filter_map(|r| {
            r.attestation_envelope
                .get(super::envelope::paths::REFERENCES_ATTESTATION_ID)
                .and_then(serde_json::Value::as_str)
        })
        .collect();

    let mut out = BTreeSet::new();
    for row in rows {
        if retired.contains(&row.attestation_id) || superseded.contains(row.attestation_id.as_str())
        {
            continue;
        }
        let Some(dimension) = super::admission::envelope_dimension(&row.attestation_envelope)
        else {
            continue;
        };
        if authority_of(dimension) != Some(authority_id) {
            continue;
        }
        // v42.0.0 — a RETRACTION carries no replacement body, so it must not
        // contribute a status even when its envelope still names the dimension.
        // A `supersedes` DOES carry one (that is what replace-in-place means),
        // so its status counts — which is how a lifted suspension becomes
        // `issued` rather than nothing. Found by the `withdraws` control test:
        // without this, a withdraws whose envelope carried `status` was folded
        // as a live status of its own.
        if row.attestation_type == super::types::attestation_type::WITHDRAWS
            || row.attestation_type == super::types::attestation_type::RECANTS
        {
            continue;
        }
        if let Some(status) = status_of(row) {
            out.insert(status);
        }
    }
    // `revoked` is absorbing — see the module docs. Applied AFTER collection so
    // a revocation anywhere in the live set wins regardless of arrival order.
    if out.contains(&LicensureStatus::Revoked) {
        return BTreeSet::from([LicensureStatus::Revoked]);
    }
    out
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

    /// Build a bare `licensure:` row for the pure fold. Not a wire-valid
    /// attestation — the fold reads only type, envelope and ids, and that is
    /// exactly why it can be tested without an authority.
    fn lic_row(id: &str, authority: &str, status: &str) -> Attestation {
        let now = chrono::Utc::now();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: "board".to_owned(),
            attested_key_id: "holder".to_owned(),
            attestation_type: super::super::types::attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": format!("licensure:{authority}:v1"),
                "status": status,
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "board".to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: super::super::types::cohort_scope::SELF.to_owned(),
            tier: super::super::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    fn composer(id: &str, kind: &str, target: &str) -> Attestation {
        let mut r = lic_row(id, "acme", "issued");
        r.attestation_type = kind.to_owned();
        r.attestation_envelope["references_attestation_id"] = serde_json::json!(target);
        r
    }

    /// v42.0.0 — **`supersedes` lifts a suspension.** THE arm the original
    /// witness documented as property (2) and never asserted, which is how
    /// `retired_ids`-only retirement shipped: that fold drops withdrawn and
    /// recanted rows and, by its own docs, deliberately does NOT filter
    /// `supersedes`. A suspension lifted by the CEG replace-in-place primitive
    /// stayed live forever, and a consumer testing `contains(Suspended)` would
    /// keep a reinstated holder out of practice.
    #[test]
    fn supersedes_lifts_a_suspension_814() {
        let rows = vec![
            lic_row("a", "acme", "suspended"),
            composer("b", super::super::types::attestation_type::SUPERSEDES, "a"),
        ];
        let got = fold_status_set(&rows, "acme");
        assert!(
            !got.contains(&LicensureStatus::Suspended),
            "a superseded suspension must not stay live — `suspended` is REVERSIBLE \
             (CC 3.1.1) and supersedes is how an authority lifts it; got {got:?}"
        );
        assert_eq!(got, BTreeSet::from([LicensureStatus::Issued]));
    }

    /// A `withdraws` retires its target — the control that proves the arm above
    /// is testing supersedes specifically and not retirement in general.
    #[test]
    fn withdraws_retires_its_target_814() {
        let rows = vec![
            lic_row("a", "acme", "suspended"),
            composer("b", super::super::types::attestation_type::WITHDRAWS, "a"),
        ];
        assert!(fold_status_set(&rows, "acme").is_empty());
    }

    #[test]
    fn revoked_absorbs_whatever_the_order_814() {
        for order in [vec!["revoked", "issued"], vec!["issued", "revoked"]] {
            let rows: Vec<Attestation> = order
                .iter()
                .enumerate()
                .map(|(i, st)| lic_row(&format!("r{i}"), "acme", st))
                .collect();
            assert_eq!(
                fold_status_set(&rows, "acme"),
                BTreeSet::from([LicensureStatus::Revoked]),
                "`revoked` is ABSORBING — arrival order across a mesh is not a fact \
                 about the licence"
            );
        }
    }

    #[test]
    fn concurrent_statuses_are_a_set_814() {
        let rows = vec![
            lic_row("a", "acme", "issued"),
            lic_row("b", "acme", "probation"),
        ];
        assert_eq!(
            fold_status_set(&rows, "acme"),
            BTreeSet::from([LicensureStatus::Issued, LicensureStatus::Probation])
        );
    }

    #[test]
    fn authorities_do_not_bleed_814() {
        let rows = vec![
            lic_row("a", "acme", "issued"),
            lic_row("b", "other", "revoked"),
        ];
        assert_eq!(
            fold_status_set(&rows, "acme"),
            BTreeSet::from([LicensureStatus::Issued]),
            "a revocation by a DIFFERENT authority must not absorb acme's set"
        );
    }

    #[test]
    fn an_unrecognized_status_is_ignored_not_guessed_814() {
        let rows = vec![
            lic_row("a", "acme", "issued"),
            lic_row("b", "acme", "probationary"),
        ];
        assert_eq!(
            fold_status_set(&rows, "acme"),
            BTreeSet::from([LicensureStatus::Issued]),
            "a status nobody has defined cannot be composed against the absorption \
             rule, so it is ignored rather than guessed at"
        );
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
