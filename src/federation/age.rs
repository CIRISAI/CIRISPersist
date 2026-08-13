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
//!   v13.0.0 (CIRISPersist#368, CC 3.4.11/3.4.13): the row names its SUBJECT
//!   via `attested_key_id` — the same cross-subject edge shape `delegates_to`
//!   uses — so a witness graduates a **different** subject's band by emitting
//!   with [`EmitAttestationInput::attested_key_id`](super::EmitAttestationInput::attested_key_id)
//!   `= Some(subject)` (e.g. over [`crate::Engine::emit_attestation`]).
//!   A subject MUST NOT emit on `age_assurance:` — attester==attested is
//!   rejected at admission AND ignored here at read time (defense-in-depth),
//!   so nobody self-mints their own graduation.
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

/// v11.9.0 (CIRISPersist#309, CC 3.4.13 Q1) — the **four-band age
/// vocabulary** that rides the `{band}` slot of the `age_assurance:{level}:
/// {band}:v1` / `age_self_declared:{band}:v1` tokens. These are the finer
/// grain ABOVE the unchanged binary `minor`/`adult` wire predicate (CC
/// 3.4.13 Q1: "the four-band granularity is a policy/vocabulary layer above
/// the unchanged binary wire predicate, never a replacement of it"). `minor`
/// = the union of the three sub-18 bands.
///
/// Operator-approved defaults (CIRISPersist#309), documented as named
/// consts. The tokens use the existing underscore convention (matching
/// `age_self_declared:band:minor`).
pub mod band {
    /// Under-13 band (CC 3.4.13 Q1 "under-13"). The most protective minor
    /// band; the fail-secure default a CONTENT-axis consumer resolves an
    /// absent/declined/unknown assurance DOWN to (CC 3.4.13 Q1 fail-secure).
    pub const UNDER_13: &str = "under_13";
    /// Early-teen band (CC 3.4.13 Q1 "13–15").
    pub const EARLY_TEEN_13_15: &str = "13_15";
    /// Older-teen band (CC 3.4.13 Q1 "16–17"). CC 3.4.13 Q2 sets the
    /// self-consent floor at 16 (a policy layer above this substrate band).
    pub const OLDER_TEEN_16_17: &str = "16_17";
    /// Adult band (CC 3.4.13 Q1 "adult (18+)"). Same token as the binary
    /// `adult` wire predicate — an adult has no finer sub-band.
    pub const ADULT: &str = "adult";
    /// The coarse binary minor token (CC 3.2 / CC 3.4.11 wire predicate).
    /// Recognized as `minor` = the union of the three sub-18 bands.
    pub const MINOR: &str = "minor";
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.13 Q1) — the **finer** four-band age
/// vocabulary, the policy layer ABOVE the binary [`AgeBand`] wire predicate.
/// The three sub-18 variants all coarsen to [`AgeBand::Minor`]
/// ([`Self::is_minor`] / [`Self::coarsen`]); `Adult`/`Unknown` map through
/// unchanged. Resolved by [`age_band_fine`].
///
/// Like [`AgeBand`] this primitive is **three-axis-neutral**: it returns
/// [`AgeBandFine::Unknown`] verbatim when there is no usable proof. A
/// CONTENT-axis consumer floors `Unknown` DOWN to the most-protective
/// [`AgeBandFine::Under13`] (CC 3.4.13 Q1 fail-secure); the steward-binding
/// axis keeps `Unknown` = non-minor = self-sovereign (CC 1.15.6). The
/// primitive does NOT bake either policy in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeBandFine {
    /// Under-13 (most protective). Coarsens to [`AgeBand::Minor`].
    Under13,
    /// 13–15 early-teen. Coarsens to [`AgeBand::Minor`].
    EarlyTeen13_15,
    /// 16–17 older-teen. Coarsens to [`AgeBand::Minor`].
    OlderTeen16_17,
    /// 18+ adult. Coarsens to [`AgeBand::Adult`].
    Adult,
    /// No usable age proof. Coarsens to [`AgeBand::Unknown`].
    Unknown,
}

impl AgeBandFine {
    /// The stable FFI/telemetry token
    /// (`"under_13"` / `"13_15"` / `"16_17"` / `"adult"` / `"unknown"`).
    pub fn as_str(self) -> &'static str {
        match self {
            AgeBandFine::Under13 => band::UNDER_13,
            AgeBandFine::EarlyTeen13_15 => band::EARLY_TEEN_13_15,
            AgeBandFine::OlderTeen16_17 => band::OLDER_TEEN_16_17,
            AgeBandFine::Adult => band::ADULT,
            AgeBandFine::Unknown => "unknown",
        }
    }

    /// `minor` is derivable — any of the three sub-18 bands (CC 3.4.13 Q1
    /// "`minor` = the union of the three sub-bands").
    pub fn is_minor(self) -> bool {
        matches!(
            self,
            AgeBandFine::Under13 | AgeBandFine::EarlyTeen13_15 | AgeBandFine::OlderTeen16_17
        )
    }

    /// Coarsen to the binary [`AgeBand`] wire predicate (the three sub-18
    /// bands → [`AgeBand::Minor`]).
    pub fn coarsen(self) -> AgeBand {
        match self {
            _ if self.is_minor() => AgeBand::Minor,
            AgeBandFine::Adult => AgeBand::Adult,
            _ => AgeBand::Unknown,
        }
    }

    /// Protectiveness rank (LOWER = more protective). Used to take the
    /// most-protective of several self-declared minor sub-bands (self may
    /// only ratchet DOWN — CC 3.4.11 "`self` is unfalsifiable").
    fn protection_rank(self) -> u8 {
        match self {
            AgeBandFine::Under13 => 0,
            AgeBandFine::EarlyTeen13_15 => 1,
            AgeBandFine::OlderTeen16_17 => 2,
            AgeBandFine::Adult => 3,
            AgeBandFine::Unknown => 4,
        }
    }
}

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
/// v11.9.0 (CIRISPersist#309, CC 3.4.13 Q1): the 4-band vocabulary now rides
/// the `{band}` slot too — `under_13` / `13_15` / `16_17` all coarsen to
/// [`AgeBand::Minor`] (they are minors on the binary wire predicate), while
/// `adult` stays [`AgeBand::Adult`]. The binary predicate is UNCHANGED on the
/// wire; the sub-band tokens are simply recognized as `minor` here so the CC
/// 3.2 steward-binding gate keeps working when a producer stamps a finer
/// band. See [`parse_age_band_fine_token`] for the finer resolution.
fn parse_age_band_token(attestation_type: &str) -> Option<AgeBand> {
    parse_age_band_fine_token(attestation_type).map(AgeBandFine::coarsen)
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.13 Q1) — parse the finer [`AgeBandFine`]
/// out of an age `attestation_type` token. Splits on `':'` and recognizes
/// exactly one of the four bands (`under_13` / `13_15` / `16_17` / `adult`)
/// PLUS the coarse `minor` token (→ [`AgeBandFine::Under13`], the most
/// protective minor band — a bare `minor` carries no finer grain, so it
/// resolves to the fail-secure floor). Returns `None` if no recognized band
/// segment is present, or if the token is malformed (carries more than one
/// distinct band).
fn parse_age_band_fine_token(attestation_type: &str) -> Option<AgeBandFine> {
    let mut found: Option<AgeBandFine> = None;
    for seg in attestation_type.split(':') {
        let b = match seg {
            band::UNDER_13 => AgeBandFine::Under13,
            band::EARLY_TEEN_13_15 => AgeBandFine::EarlyTeen13_15,
            band::OLDER_TEEN_16_17 => AgeBandFine::OlderTeen16_17,
            band::ADULT => AgeBandFine::Adult,
            // A coarse `minor` token has no sub-grain → the most protective
            // minor band (fail-secure). Coarsens back to `Minor`.
            band::MINOR => AgeBandFine::Under13,
            _ => continue,
        };
        match found {
            None => found = Some(b),
            // Defensive: a malformed token carrying two DISTINCT bands → no
            // clean band. (`minor` + `under_13` both → Under13 is consistent.)
            Some(prev) if prev != b => return None,
            Some(_) => {}
        }
    }
    found
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
            // v13.0.0 (CIRISPersist#368, CC 3.4.11) — read-side
            // defense-in-depth: a SELF-emitted witness row (attester ==
            // attested) confers nothing. The admission gate
            // (`check_reserved_prefix_admission`) rejects the shape at
            // `put_attestation`, but a pre-gate legacy/replicated row must
            // not graduate its own emitter either.
            if r.attesting_key_id == r.attested_key_id {
                continue;
            }
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

/// v11.9.0 (CIRISPersist#309, CC 3.4.13 Q1) — resolve the finer
/// [`AgeBandFine`] of key `k` from its INCOMING age attestations, the policy
/// layer ABOVE [`age_band`]. Same witness-outranks-self one-way ratchet + the
/// `expires_at`-only liveness, but preserving the four-band grain:
///
///   1. the finer band of the most-recent live **witness**-rung age
///      attestation that parses to a recognized band, if any (this is the
///      ONLY way to graduate UP a band — CC 3.4.11 "`self` is unfalsifiable;
///      graduating up requires a witness-reserved `age_assurance:*` row");
///      ELSE
///   2. the **most-protective** (lowest) self-declared MINOR sub-band on
///      record (`self` may only ratchet DOWN — a self-declared adult is
///      ignored, and among several self-declared minor bands the most
///      protective wins); ELSE
///   3. [`AgeBandFine::Unknown`] (no usable proof — returned verbatim; a
///      CONTENT-axis consumer floors this to [`AgeBandFine::Under13`], the
///      steward-binding axis treats it as self-sovereign).
///
/// [`age_band`] is exactly `age_band_fine(..).coarsen()`; both are kept so a
/// consumer can pick the grain it needs without re-deriving liveness.
pub async fn age_band_fine(
    directory: &dyn FederationDirectory,
    k: &str,
) -> Result<AgeBandFine, Error> {
    let now = chrono::Utc::now();
    let mut best_self_minor: Option<AgeBandFine> = None;
    for r in directory.list_attestations_for(k).await? {
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        let at = r.attestation_type.as_str();
        if at.starts_with("age_assurance:") {
            // v13.0.0 (CIRISPersist#368, CC 3.4.11) — a self-emitted witness
            // row confers nothing (see `age_band`; same defense-in-depth).
            if r.attesting_key_id == r.attested_key_id {
                continue;
            }
            // Witness rung — authoritative; most-recent parse wins outright.
            if let Some(band) = parse_age_band_fine_token(at) {
                return Ok(band);
            }
        } else if at.starts_with("age_self_declared:") {
            // Self rung — one-way ratchet: only a self-declared MINOR band
            // counts (a self-declared adult is ignored). Keep the most
            // protective (self may only LOWER access).
            if let Some(b) = parse_age_band_fine_token(at) {
                if b.is_minor()
                    && best_self_minor
                        .map(|cur| b.protection_rank() < cur.protection_rank())
                        .unwrap_or(true)
                {
                    best_self_minor = Some(b);
                }
            }
        }
    }
    Ok(best_self_minor.unwrap_or(AgeBandFine::Unknown))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CIRISPersist#309 (CC 3.4.13 Q1) — four-band vocabulary ──────────

    #[test]
    fn fine_token_parses_four_bands_plus_coarse_minor() {
        assert_eq!(
            parse_age_band_fine_token("age_assurance:provider:under_13:v1"),
            Some(AgeBandFine::Under13)
        );
        assert_eq!(
            parse_age_band_fine_token("age_assurance:provider:13_15:v1"),
            Some(AgeBandFine::EarlyTeen13_15)
        );
        assert_eq!(
            parse_age_band_fine_token("age_self_declared:16_17:v1"),
            Some(AgeBandFine::OlderTeen16_17)
        );
        assert_eq!(
            parse_age_band_fine_token("age_assurance:government:adult:v1"),
            Some(AgeBandFine::Adult)
        );
        // A coarse `minor` token → the most protective minor band.
        assert_eq!(
            parse_age_band_fine_token("age_assurance:provider:minor:v1"),
            Some(AgeBandFine::Under13)
        );
        // No recognized band segment.
        assert_eq!(parse_age_band_fine_token("age_assurance:provider:v1"), None);
    }

    #[test]
    fn fine_token_two_distinct_bands_is_malformed() {
        assert_eq!(
            parse_age_band_fine_token("age_assurance:provider:under_13:adult:v1"),
            None
        );
        // `minor` + `under_13` are CONSISTENT (both → Under13) → not malformed.
        assert_eq!(
            parse_age_band_fine_token("age:minor:under_13"),
            Some(AgeBandFine::Under13)
        );
    }

    #[test]
    fn sub_band_tokens_coarsen_to_minor_on_binary_predicate() {
        // The binary wire predicate is UNCHANGED: every sub-18 band → Minor.
        for t in [
            "age_assurance:provider:under_13:v1",
            "age_assurance:provider:13_15:v1",
            "age_assurance:provider:16_17:v1",
            "age_assurance:provider:minor:v1",
        ] {
            assert_eq!(parse_age_band_token(t), Some(AgeBand::Minor), "{t}");
        }
        assert_eq!(
            parse_age_band_token("age_assurance:provider:adult:v1"),
            Some(AgeBand::Adult)
        );
    }

    #[test]
    fn fine_is_minor_and_coarsen() {
        assert!(AgeBandFine::Under13.is_minor());
        assert!(AgeBandFine::EarlyTeen13_15.is_minor());
        assert!(AgeBandFine::OlderTeen16_17.is_minor());
        assert!(!AgeBandFine::Adult.is_minor());
        assert!(!AgeBandFine::Unknown.is_minor());
        assert_eq!(AgeBandFine::Under13.coarsen(), AgeBand::Minor);
        assert_eq!(AgeBandFine::OlderTeen16_17.coarsen(), AgeBand::Minor);
        assert_eq!(AgeBandFine::Adult.coarsen(), AgeBand::Adult);
        assert_eq!(AgeBandFine::Unknown.coarsen(), AgeBand::Unknown);
    }

    #[test]
    fn fine_as_str_tokens_stable() {
        assert_eq!(AgeBandFine::Under13.as_str(), "under_13");
        assert_eq!(AgeBandFine::EarlyTeen13_15.as_str(), "13_15");
        assert_eq!(AgeBandFine::OlderTeen16_17.as_str(), "16_17");
        assert_eq!(AgeBandFine::Adult.as_str(), "adult");
        assert_eq!(AgeBandFine::Unknown.as_str(), "unknown");
    }
}
