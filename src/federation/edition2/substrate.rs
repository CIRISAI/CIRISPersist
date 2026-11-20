//! v62.0.0 (JSON-cut slice F, F0-cp6) — **the CC 6.1.3 substrate planes, and
//! the ONE predicate that decides each.**
//!
//! One plane carries a signature persist chooses the form of: the audit
//! chain's entries (`audit::verify::verify_entry_signature`: an inner Ed25519
//! signature under `actor_id`; the plane's gate is the composite-signed tree
//! head). The calibration bundle crosses nodes and is composite only
//! (v62.0.0, F0-cp7: its own-form branch went with the bound-hybrid verify
//! family; `derived::calibration_admit`).
//!
//! CC 6.1.3 (corrected by CC, 2026-11-19): every CC 6.1 signed object
//! carries ONE composite signature over its own preimage; what 6.1 exempts is
//! the preimage form (no COSE), never the signature. A lone Ed25519 signature
//! is persist's choice only for bytes no other node ever verifies (CC 1.13.4).
//!
//! Each door asks [`substrate_form`] first. [`keeps_its_own_signature`]
//! answers per plane:
//!
//! - `false` — the plane's bytes cross nodes: the door requires ONE composite
//!   over the object's preimage and refuses a lone half or the earlier
//!   bound-hybrid pair by name ([`SubstrateForm::Composite`]);
//! - `true` — no other node verifies the signature: the door keeps the
//!   plane's own (earlier) form ([`SubstrateForm::OwnSignature`]).
//!
//! **The flip is that one line**: nothing else in the tree names a plane's
//! answer.
//!
//! The fountain manifest is not a plane here (F0-cp6d; CC's answer): the
//! fountain was cut from the Constitution, so `FountainManifestV1` is not a
//! CC object; fountain coding is node-local and a peer's manifest is refused
//! by name (`fountain::require_node_local_producer`).
//!
//! F0-cp6b findings (each line below):
//!
//! - the audit chain's entries do NOT cross nodes: what is served is the
//!   composite-signed tree head, row hashes and inclusion proofs
//!   (`federation::read`, `AuditChainProof`); no other node verifies an
//!   entry's inner Ed25519 signature — its own form.

use crate::federation::Error;

/// A plane whose objects carry their own signature form pending CC 6.1.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubstratePlane {
    /// An audit-chain entry (`AuditEntry`).
    AuditEntry,
}

impl SubstratePlane {
    /// Every plane.
    pub const ALL: [Self; 1] = [Self::AuditEntry];

    /// The plane name the refusal carries.
    #[must_use]
    pub const fn plane(self) -> &'static str {
        match self {
            Self::AuditEntry => "audit_entry",
        }
    }
}

/// How a substrate plane's door verifies its object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubstrateForm {
    /// The plane's own (earlier) signature form: only for bytes no other
    /// node verifies (CC 1.13.4).
    OwnSignature,
    /// ONE composite over the object's own preimage (CC 6.1.3); a lone half
    /// or the bound-hybrid pair refused by name.
    Composite,
}

/// **THE predicate.** Does this plane's object keep its own signature form
/// (true only while no other node verifies it, CC 1.13.4)? `false` requires
/// ONE composite over its preimage. One line per plane: CC's answer, or a
/// finding that a plane's bytes cross nodes, is a one-line flip.
#[must_use]
pub const fn keeps_its_own_signature(plane: SubstratePlane) -> bool {
    match plane {
        SubstratePlane::AuditEntry => true,
    }
}

/// The first call of each substrate plane's door: the form its object must
/// carry.
#[must_use]
pub const fn substrate_form(plane: SubstratePlane) -> SubstrateForm {
    if keeps_its_own_signature(plane) {
        SubstrateForm::OwnSignature
    } else {
        SubstrateForm::Composite
    }
}

/// The refusal a plane gives an object of the wrong form, by name: the
/// shared earlier-form refusal (`earlier_form_object`) for the plane. A
/// door whose plane has no composite path (the audit entry: no key a
/// composite would verify under) refuses with it under
/// [`SubstrateForm::Composite`].
///
/// # Errors
/// Always, once the earlier-form doors are shut.
pub fn refuse_own_form(plane: SubstratePlane) -> Result<(), Error> {
    super::door::refuse_earlier_form(plane.plane())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **I2886 — each plane's form is the predicate's, and the refusal is
    /// by name.** `false` means composite, never "refuse everything".
    #[test]
    fn i2886_the_substrate_form_is_the_predicate() {
        for p in SubstratePlane::ALL {
            assert_eq!(
                substrate_form(p) == SubstrateForm::OwnSignature,
                keeps_its_own_signature(p),
                "I2886 {p:?}"
            );
            match refuse_own_form(p) {
                Err(Error::MalformedRow { reason, .. }) => assert_eq!(
                    reason,
                    crate::federation::edition2::token::EARLIER_FORM_OBJECT,
                    "I2886 {p:?}"
                ),
                other => panic!("I2886 {p:?}: refused by name: {other:?}"),
            }
        }
        let names: std::collections::BTreeSet<_> =
            SubstratePlane::ALL.iter().map(|p| p.plane()).collect();
        assert_eq!(
            names.len(),
            SubstratePlane::ALL.len(),
            "I2886: distinct plane names"
        );
    }
}
