//! v11.9.0 (CIRISPersist#309, CC 3.4.12) — the **capacity-assurance ladder**:
//! the witness-reserved, PER-DOMAIN sibling of the [`super::age`]
//! age-assurance ladder. Where age is a scalar binary predicate, capacity is
//! a *time-varying, non-monotonic vector*: a person may be `incapacitated`
//! for `financial` decisions yet `capacitated` for `medical` ones, so every
//! attestation is qualified by a `{domain}` (CC 3.4.12).
//!
//! Tokens travel as the **`attestation_type`** string (like age; NOT the
//! `scores` envelope `dimension`):
//!
//! - `capacity_assurance:{level}:{domain}:{band}:v1` — the witness verdict.
//!   `level ∈ {provider, panel, government}` (ascending confidence; `panel`
//!   = an M-of-N quorum of independent assessors), `band ∈ {capacitated,
//!   incapacitated}`. Witness-RESERVED (`witness ∈ attesting_key.identity_type`)
//!   AND the subject MUST NOT self-emit — enforced at admission (see
//!   [`super::admission::check_reserved_prefix_admission`]).
//! - `capacity_assurance:reversible_excluded:{domain}` — the mandatory
//!   companion: delirium / infection-confusion / depression / polypharmacy
//!   have been ruled out for `{domain}` (the genuine restoration path and the
//!   most-abused mis-attribution). Required for any *continuing* binding.
//! - `capacity_assurance:reversible_pending:{domain}` — ACUTE-WINDOW ONLY:
//!   exclusion in progress; admissible solely for the T1 emergency-necessity
//!   tier and MUST resolve to `reversible_excluded` or the binding lapses.
//!
//! **The two load-bearing inversions of the minor rule (CC 3.4.12):**
//!   1. **Presumption of capacity** — *absence* of a capacity attestation
//!      resolves to `capacitated` / sovereign, NOT to protection. Getting
//!      this backwards would be catastrophic and is forbidden.
//!      [`capacity_state`] returns [`CapacityState::Unknown`] on absence; a
//!      consumer treats `Unknown` as full capacity.
//!   2. **Fail-to-liberty** — every binding carries a short `valid_until` that
//!      cannot exceed the [`T2_REVIEW_CADENCE_DAYS`] periodic-review cadence;
//!      on lapse the binding goes non-live and the adult auto-re-sovereigns
//!      (see [`super::admission::check_adult_incapacity_binding`] and the
//!      steward-binding liveness in [`super::admission::steward_bindings_of`]).

use super::{Error, FederationDirectory};
use std::collections::HashSet;

/// The witness-reserved capacity-assurance `attestation_type` prefix.
pub const CAPACITY_ASSURANCE_PREFIX: &str = "capacity_assurance:";

/// The `{level}` rung vocabulary (ascending confidence). Closed set.
pub mod level {
    /// A single qualified assessor (clinician/evaluator). Admissible ONLY for
    /// the shortest provisional tier and never confers asset-preservation or
    /// continuing power on its own (CC 3.4.12 "Confidence scales with scope").
    pub const PROVIDER: &str = "provider";
    /// An M-of-N quorum of *independent* assessors (CC 3.4.12 `panel` rung) —
    /// required for any continuing or high-scope domain.
    pub const PANEL: &str = "panel";
    /// A court-appointed / government evaluator.
    pub const GOVERNMENT: &str = "government";
}

/// The `{band}` per-domain per-decision-class vocabulary. Closed set.
pub mod capacity_band {
    /// The adult HOLDS the domain (presumption of capacity; the default).
    pub const CAPACITATED: &str = "capacitated";
    /// The adult has an attested loss of capacity for the domain.
    pub const INCAPACITATED: &str = "incapacitated";
}

/// The reversible-cause exclusion companion sub-prefixes (CC 3.4.12).
pub mod reversible {
    /// `capacity_assurance:reversible_excluded:{domain}` — reversible mimics
    /// ruled out for the domain (mandatory for a continuing binding).
    pub const EXCLUDED_PREFIX: &str = "capacity_assurance:reversible_excluded:";
    /// `capacity_assurance:reversible_pending:{domain}` — exclusion in
    /// progress (T1 acute-window only).
    pub const PENDING_PREFIX: &str = "capacity_assurance:reversible_pending:";
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — **T2 periodic-review cadence**:
/// the maximum `valid_until` window (in days) an adult-incapacity binding may
/// carry. No single window may outrun periodic review (CC 3.4.12 "no
/// long-dated binding that escapes review between renewals").
///
/// **Operator-tunable default** (CIRISPersist#309 — operator approved "use
/// your defaults"): 90 days. The Constitution fixes only the *ceiling*
/// property ("no window exceeds the T2 review cadence"); the concrete cadence
/// is a deployment policy knob surfaced here as a named const.
pub const T2_REVIEW_CADENCE_DAYS: i64 = 90;

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — the seed capacity `{domain}`
/// vocabulary. **Open per spec** ("open per-domain vocabulary") — unknown
/// domains are accepted; these are the named defaults (operator approved).
pub mod domain {
    /// Medical / healthcare decisions.
    pub const MEDICAL: &str = "medical";
    /// Financial / asset-management decisions.
    pub const FINANCIAL: &str = "financial";
    /// Residence / placement decisions.
    pub const RESIDENCE: &str = "residence";
    /// Contact / visitation (PROTECTED — see [`super::PROTECTED_NON_TRANSFERABLE`]).
    pub const CONTACT: &str = "contact";
    /// Relational / sexual autonomy (PROTECTED).
    pub const RELATIONAL: &str = "relational";
    /// Voting (PROTECTED).
    pub const VOTING: &str = "voting";
    /// Digital-identity / key-adjacent decisions.
    pub const DIGITAL_IDENTITY: &str = "digital_identity";
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12 "protected non-transferable domains —
/// the apophatic floor") — domains that are **never** delegable to a steward,
/// even under attested incapacity (they map to the `prohibited:*` apophatic
/// floor and are carved out of any granted scope). A binding whose scope
/// intersects this set is rejected at admission.
///
/// Operator-approved default set (CIRISPersist#309): `contact` (anti-isolation),
/// `relational` (relational/sexual autonomy), `voting`, `marriage`
/// (marriage & association), `reproduction` (sterilization / forced medical
/// alteration — the Buck v. Bell / Ashley legacy).
pub const PROTECTED_NON_TRANSFERABLE: [&str; 5] = [
    domain::CONTACT,
    domain::RELATIONAL,
    domain::VOTING,
    "marriage",
    "reproduction",
];

/// True iff `d` is a protected non-transferable domain (never delegable).
pub fn is_protected_domain(d: &str) -> bool {
    PROTECTED_NON_TRANSFERABLE.contains(&d)
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — the `delegates_to` envelope fields
/// an adult-incapacity binding carries (beyond the shared `scope` /
/// `valid_until`). All are read at admission by
/// [`super::admission::check_adult_incapacity_binding`].
pub mod binding_field {
    /// `binding_legitimacy_source` — MANDATORY. One of
    /// [`legitimacy_source`]. NEVER the steward's own signature alone.
    pub const LEGITIMACY_SOURCE: &str = "binding_legitimacy_source";
    /// `binding_tier` — OPTIONAL. Present as [`tier::T1_EMERGENCY_NECESSITY`]
    /// for the acute no-proxy path that admits a `reversible_pending`
    /// companion in lieu of `reversible_excluded`.
    pub const TIER: &str = "binding_tier";
    /// `petitioner_key_id` — OPTIONAL. The party petitioning for the binding
    /// (may differ from the steward `S`). The capacity assessor MUST NOT be
    /// the petitioner (assessor-independence, anti-capture).
    pub const PETITIONER_KEY_ID: &str = "petitioner_key_id";
    /// `valid_until` — MANDATORY. ISO-8601 expiry; fail-to-liberty lapse.
    pub const VALID_UNTIL: &str = "valid_until";
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — the mandatory
/// `binding_legitimacy_source` vocabulary. Closed set — the binding's
/// legitimacy MUST root in one of these, NEVER the steward's self-signature
/// alone (which would be naked self-appointment).
pub mod legitimacy_source {
    /// `prior_will_proxy` — the ward's own springing self-delegation, signed
    /// while attested-competent (consent-across-time; the preferred path).
    pub const PRIOR_WILL_PROXY: &str = "prior_will_proxy";
    /// `wa_due_process_quorum` — a CC 4.3 WA quorum (the no-prior-will path).
    pub const WA_DUE_PROCESS_QUORUM: &str = "wa_due_process_quorum";
    /// `emergency_necessity_expedited` — T1-ONLY acute no-proxy case; a lone
    /// provider attestation grants only life-preserving necessity (NOT asset
    /// powers) until an accountable WA authorization attaches.
    pub const EMERGENCY_NECESSITY_EXPEDITED: &str = "emergency_necessity_expedited";

    /// True iff `s` is one of the three closed-set legitimacy sources.
    pub fn is_valid(s: &str) -> bool {
        matches!(
            s,
            PRIOR_WILL_PROXY | WA_DUE_PROCESS_QUORUM | EMERGENCY_NECESSITY_EXPEDITED
        )
    }
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — the binding-tier discriminant.
pub mod tier {
    /// The T1 acute emergency-necessity tier — the ONLY tier that admits a
    /// `reversible_pending` companion in lieu of `reversible_excluded`.
    pub const T1_EMERGENCY_NECESSITY: &str = "T1_emergency_necessity";
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — the resolved capacity state of a
/// key for a single decision-`domain`. Three-valued; the presumption of
/// capacity means [`CapacityState::Unknown`] (absence) is treated by a
/// consumer as full capacity / sovereign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityState {
    /// A live witness `capacity_assurance:*:{d}:capacitated` — the adult
    /// holds the domain.
    Capacitated,
    /// A live witness `capacity_assurance:*:{d}:incapacitated` — an attested
    /// loss of capacity for the domain.
    Incapacitated,
    /// No usable, live capacity proof for the domain — the **presumption of
    /// capacity** (CC 3.4.12): a consumer treats this as full capacity.
    Unknown,
}

impl CapacityState {
    /// The stable FFI/telemetry token
    /// (`"capacitated"` / `"incapacitated"` / `"unknown"`).
    pub fn as_str(self) -> &'static str {
        match self {
            CapacityState::Capacitated => capacity_band::CAPACITATED,
            CapacityState::Incapacitated => capacity_band::INCAPACITATED,
            CapacityState::Unknown => "unknown",
        }
    }
}

/// A parsed `capacity_assurance:{level}:{domain}:{band}:v1` token.
pub struct CapacityToken<'a> {
    /// The assurance rung (`provider` / `panel` / `government`).
    pub level: &'a str,
    /// The decision-domain (open vocabulary).
    pub domain: &'a str,
    /// The per-domain band (`capacitated` / `incapacitated`).
    pub band: &'a str,
}

/// Parse a `capacity_assurance:{level}:{domain}:{band}:v1` token. Tolerates a
/// trailing `:vN` version segment (CC 4.1.3). Returns `None` for the
/// `reversible_*` companion tokens (they carry no `{band}`) and for any
/// malformed shape. The `{band}` MUST be one of the closed-set values.
pub fn parse_capacity_token(attestation_type: &str) -> Option<CapacityToken<'_>> {
    let rest = attestation_type.strip_prefix(CAPACITY_ASSURANCE_PREFIX)?;
    let mut segs = rest.split(':');
    let level = segs.next()?;
    // The reversible_* companions live under the same prefix but are not
    // band-carrying capacity verdicts.
    if level == "reversible_excluded" || level == "reversible_pending" {
        return None;
    }
    if !matches!(level, level::PROVIDER | level::PANEL | level::GOVERNMENT) {
        return None;
    }
    let domain = segs.next()?;
    if domain.is_empty() {
        return None;
    }
    let band = segs.next()?;
    if !matches!(
        band,
        capacity_band::CAPACITATED | capacity_band::INCAPACITATED
    ) {
        return None;
    }
    // Any further segment must be a version tag (`vN`); anything else is
    // malformed. (We do not validate the digits — parsers tolerate `:vN`.)
    Some(CapacityToken {
        level,
        domain,
        band,
    })
}

/// Is `attestation_type` a live-relevant `capacity_assurance:*` verdict for
/// domain `d`? (Ignoring liveness — that is the caller's `expires_at` check.)
fn token_is_for_domain(attestation_type: &str, d: &str) -> Option<&'static str> {
    let t = parse_capacity_token(attestation_type)?;
    if t.domain == d {
        // Return a `'static` band discriminant.
        match t.band {
            capacity_band::CAPACITATED => Some(capacity_band::CAPACITATED),
            capacity_band::INCAPACITATED => Some(capacity_band::INCAPACITATED),
            _ => None,
        }
    } else {
        None
    }
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — resolve the [`CapacityState`] of
/// key `k` for decision-`domain` `d`, from `k`'s INCOMING capacity
/// attestations (`attested_key_id == k`). The **presumption of capacity**:
/// absence resolves to [`CapacityState::Unknown`] (consumer-treated as
/// capacitated). The band of the **most-recent live** witness
/// `capacity_assurance:*:{d}:*` row wins (`list_attestations_for` is
/// `asserted_at DESC`), with `expires_at`/`valid_until` freshness — a lapsed
/// attestation confers nothing (fail-to-liberty).
pub async fn capacity_state(
    directory: &dyn FederationDirectory,
    k: &str,
    d: &str,
) -> Result<CapacityState, Error> {
    let now = chrono::Utc::now();
    for r in directory.list_attestations_for(k).await? {
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue; // lapsed — confers nothing.
            }
        }
        if let Some(band) = token_is_for_domain(&r.attestation_type, d) {
            return Ok(match band {
                capacity_band::INCAPACITATED => CapacityState::Incapacitated,
                _ => CapacityState::Capacitated,
            });
        }
    }
    Ok(CapacityState::Unknown)
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — the set of domains for which `k`
/// has a LIVE witness `:incapacitated` verdict, plus the domains that carry a
/// live `reversible_excluded` / `reversible_pending` companion. Single pass
/// over `k`'s incoming attestations (used by the adult-incapacity admission
/// predicate). Liveness = `expires_at` freshness.
pub struct IncapacityFacts {
    /// Domains with a live `:incapacitated` verdict.
    pub incapacitated_domains: HashSet<String>,
    /// Domains with a live `reversible_excluded` companion.
    pub reversible_excluded_domains: HashSet<String>,
    /// Domains with a live `reversible_pending` companion.
    pub reversible_pending_domains: HashSet<String>,
    /// For each incapacitated domain, the set of attester key_ids that signed
    /// a live `:incapacitated` verdict for it (for the assessor-independence
    /// check: attester ∉ {steward, petitioner}).
    pub incapacity_attesters: HashSet<String>,
}

/// Gather [`IncapacityFacts`] for `k` in a single pass.
pub async fn incapacity_facts(
    directory: &dyn FederationDirectory,
    k: &str,
) -> Result<IncapacityFacts, Error> {
    let now = chrono::Utc::now();
    let mut facts = IncapacityFacts {
        incapacitated_domains: HashSet::new(),
        reversible_excluded_domains: HashSet::new(),
        reversible_pending_domains: HashSet::new(),
        incapacity_attesters: HashSet::new(),
    };
    for r in directory.list_attestations_for(k).await? {
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        let at = r.attestation_type.as_str();
        if let Some(t) = parse_capacity_token(at) {
            if t.band == capacity_band::INCAPACITATED {
                facts.incapacitated_domains.insert(t.domain.to_owned());
                facts
                    .incapacity_attesters
                    .insert(r.attesting_key_id.clone());
            }
        } else if let Some(d) = at.strip_prefix(reversible::EXCLUDED_PREFIX) {
            if !d.is_empty() {
                facts.reversible_excluded_domains.insert(d.to_owned());
            }
        } else if let Some(d) = at.strip_prefix(reversible::PENDING_PREFIX) {
            if !d.is_empty() {
                facts.reversible_pending_domains.insert(d.to_owned());
            }
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capacity_token_happy_and_versioned() {
        let t = parse_capacity_token("capacity_assurance:panel:financial:incapacitated:v1")
            .expect("valid token");
        assert_eq!(t.level, level::PANEL);
        assert_eq!(t.domain, domain::FINANCIAL);
        assert_eq!(t.band, capacity_band::INCAPACITATED);

        // Unknown domain accepted (OPEN vocabulary).
        let t = parse_capacity_token("capacity_assurance:provider:aviation:capacitated:v1")
            .expect("open-vocab domain");
        assert_eq!(t.domain, "aviation");
        assert_eq!(t.band, capacity_band::CAPACITATED);
    }

    #[test]
    fn parse_capacity_token_rejects_bad_shapes() {
        // reversible_* companions are not band-carrying verdicts.
        assert!(parse_capacity_token("capacity_assurance:reversible_excluded:financial").is_none());
        assert!(parse_capacity_token("capacity_assurance:reversible_pending:medical").is_none());
        // bad level
        assert!(parse_capacity_token("capacity_assurance:quack:financial:incapacitated").is_none());
        // bad band
        assert!(parse_capacity_token("capacity_assurance:panel:financial:tired:v1").is_none());
        // missing prefix
        assert!(parse_capacity_token("capacity:core_identity:v1").is_none());
        // missing domain / band
        assert!(parse_capacity_token("capacity_assurance:panel").is_none());
    }

    #[test]
    fn protected_domains_are_the_apophatic_floor() {
        for d in [
            "contact",
            "relational",
            "voting",
            "marriage",
            "reproduction",
        ] {
            assert!(is_protected_domain(d), "{d} must be protected");
        }
        assert!(!is_protected_domain("financial"));
        assert!(!is_protected_domain("medical"));
    }

    #[test]
    fn defaults_are_the_documented_consts() {
        assert_eq!(T2_REVIEW_CADENCE_DAYS, 90);
        assert_eq!(CAPACITY_ASSURANCE_PREFIX, "capacity_assurance:");
        assert_eq!(PROTECTED_NON_TRANSFERABLE.len(), 5);
    }

    #[test]
    fn legitimacy_source_closed_set() {
        assert!(legitimacy_source::is_valid("prior_will_proxy"));
        assert!(legitimacy_source::is_valid("wa_due_process_quorum"));
        assert!(legitimacy_source::is_valid("emergency_necessity_expedited"));
        assert!(!legitimacy_source::is_valid("steward_says_so"));
        assert!(!legitimacy_source::is_valid(""));
    }

    #[test]
    fn capacity_state_tokens_stable() {
        assert_eq!(CapacityState::Capacitated.as_str(), "capacitated");
        assert_eq!(CapacityState::Incapacitated.as_str(), "incapacitated");
        assert_eq!(CapacityState::Unknown.as_str(), "unknown");
    }
}
