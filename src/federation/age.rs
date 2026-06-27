//! v11.5.0 (CIRISPersist#306, CC 3.3.12 / CC 1.15.6) — the **I1 age band**:
//! the substrate primitive that resolves a key's verified age band from its
//! incoming age attestations, so the CC 3.2 user-target steward-binding gate
//! and the minor-stewardship liveness predicate can be machine-checked.
//!
//! Age tokens travel as the **`attestation_type`** string (NOT the `scores`
//! envelope `dimension`):
//!
//! - `age_assurance:*` — the **witness** rung (provider/government). The
//!   `attestation_type` is reserved to a `witness`-role emitter at admission
//!   (see [`super::admission::check_reserved_prefix_admission`]). Authoritative.
//! - `age_self_declared:*` — the **self** rung (subject-signed onboarding
//!   "state your band"). A self-declared **adult is IGNORED** here — the
//!   one-way ratchet: a subject may self-declare MINOR to LOWER its own
//!   access, but may NEVER self-graduate to adult. Only a self-declared minor
//!   counts.
//!
//! **Resolution** (witness OUTRANKS self):
//!   1. the band of the most-recent live **witness**-rung age attestation
//!      that parses to a recognized band (Adult / Minor), if any; ELSE
//!   2. [`AgeBand::Minor`] if any live **self**-rung attestation declares
//!      minor; ELSE
//!   3. [`AgeBand::Unknown`] (no usable age token — the
//!      presumption-of-sovereignty default: a person with no age proof is
//!      NOT treated as a stewardable minor; CC 1.15.6).
//!
//! **Liveness** here is `expires_at`-only (skip rows with `expires_at <=
//! now`). Richer supersede/withdraw liveness for age is deferred to #309 — do
//! NOT build it. The three-valued band is exposed verbatim over FFI so #309
//! can layer a content-protective `unknown → minor` resolution on the CONTENT
//! axis without changing THIS primitive (the steward-binding axis keeps
//! `unknown` = non-minor = self-sovereign).

use super::{Error, FederationDirectory};

/// The I1 age band of a key (CC 3.3.12). Three-valued: a person with no
/// usable age attestation resolves to [`AgeBand::Unknown`], which the
/// steward-binding gate treats as NON-minor (un-stewardable —
/// presumption-of-sovereignty, CC 1.15.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeBand {
    /// A proven under-18 (a live witness `age_assurance:*:minor` OR a live
    /// self-declared `age_self_declared:*:minor`).
    Minor,
    /// A proven over-18 (a live witness `age_assurance:*:adult`). A
    /// self-declared adult does NOT confer this (the one-way ratchet).
    Adult,
    /// No usable age proof — treated as non-minor / self-sovereign on the
    /// steward-binding axis.
    Unknown,
}

impl AgeBand {
    /// The stable FFI/telemetry string token (`"minor"` / `"adult"` /
    /// `"unknown"`).
    pub fn as_str(self) -> &'static str {
        match self {
            AgeBand::Minor => "minor",
            AgeBand::Adult => "adult",
            AgeBand::Unknown => "unknown",
        }
    }
}

/// Parse an age **band** out of an age `attestation_type` token. Splits on
/// `':'` and recognizes exactly `adult` → [`AgeBand::Adult`] and `minor` →
/// [`AgeBand::Minor`] as a segment; returns `None` if neither is present.
///
/// Deliberately small + #309-extensible: #309 will add the 4-band
/// `under_13` / `13_15` / `16_17` → all map to [`AgeBand::Minor`]. For now we
/// recognize only the coarse `adult` / `minor` tokens both rungs use.
fn parse_age_band_token(attestation_type: &str) -> Option<AgeBand> {
    let mut found_adult = false;
    let mut found_minor = false;
    for seg in attestation_type.split(':') {
        match seg {
            "adult" => found_adult = true,
            "minor" => found_minor = true,
            _ => {}
        }
    }
    // Defensive: a malformed token carrying both → no clean band.
    match (found_adult, found_minor) {
        (true, false) => Some(AgeBand::Adult),
        (false, true) => Some(AgeBand::Minor),
        _ => None,
    }
}

/// Resolve the [`AgeBand`] of key `k` from its INCOMING age attestations
/// (attestations ABOUT `k`, i.e. `attested_key_id == k`). See the
/// module docs for the witness-outranks-self resolution + the
/// presumption-of-sovereignty `Unknown` default.
pub async fn age_band(directory: &dyn FederationDirectory, k: &str) -> Result<AgeBand, Error> {
    let now = chrono::Utc::now();
    // `list_attestations_for(k)` is ordered asserted_at DESC, so the first
    // matching witness row is the most recent.
    let mut self_says_minor = false;
    for r in directory.list_attestations_for(k).await? {
        // Liveness: an expired age attestation confers nothing (#309 will add
        // richer supersede/withdraw liveness; expires_at only here).
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        let at = r.attestation_type.as_str();
        if at.starts_with("age_assurance:") {
            // Witness rung — authoritative. The most recent one that parses
            // to a recognized band wins outright.
            if let Some(band) = parse_age_band_token(at) {
                return Ok(band);
            }
        } else if at.starts_with("age_self_declared:") {
            // Self rung — one-way ratchet: only a self-declared MINOR counts
            // (a self-declared adult is ignored). Remember it but keep
            // scanning for an authoritative witness row.
            if parse_age_band_token(at) == Some(AgeBand::Minor) {
                self_says_minor = true;
            }
        }
    }
    if self_says_minor {
        return Ok(AgeBand::Minor);
    }
    Ok(AgeBand::Unknown)
}
