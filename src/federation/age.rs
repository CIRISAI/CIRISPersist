//! v11.5.0 (CIRISPersist#306, CC 3.3.12 / CC 1.15.6) — the **I1 age band**:
//! the substrate primitive that resolves a key's verified age band from its
//! incoming age attestations, so the CC 3.2 user-target steward-binding gate
//! and the minor-stewardship liveness predicate can be machine-checked.
//!
//! Age tokens travel as the `dimension` of a `scores` row (CC 2.4 registers
//! both stems as dimension families), or — for rows written before v53.0.0
//! (CIRISPersist#975) — as the **`attestation_type`** string itself. Both
//! shapes resolve identically ([`super::row_type::claim_token`]):
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
//! **Resolution** (v62.0.0, K2-fix14: the CC 3.4.11 read-union,
//! `band_fine_of_rows`):
//!   1. among live witness-rung rows, the HIGHEST assurance level wins
//!      (government > provider); at that level the most protective band
//!      wins (CC 3.4.13 fail-secure);
//!   2. a live self-declared MINOR band LOWERS that reading, never raises it;
//!   3. [`AgeBand::Unknown`] when no usable age row is held (the
//!      presumption-of-sovereignty default: a person with no age proof is
//!      NOT treated as a stewardable minor; CC 1.15.6).
//!
//! **Liveness:** a retracted row (`withdraws` / `recants`, the one composer
//! precedence) never counts. [`age_band`] / [`age_band_fine`] judge expiry
//! by the reader's clock (a present-tense read); [`age_band_as_of`] judges
//! it at a stated instant, for folds. The three-valued band is exposed verbatim over FFI so #309
//! can layer a content-protective `unknown → minor` resolution on the CONTENT
//! axis without changing THIS primitive (the steward-binding axis keeps
//! `unknown` = non-minor = self-sovereign).

use super::attestation_query::{AttestationQuery, FOLD_PAGE};
use super::{Error, FederationDirectory};

/// v11.9.0 (CIRISPersist#309, CC 3.4.13 Q1) — the **four-band age
/// vocabulary** that rides the `{band}` slot of the `age_assurance:{level}:
/// {band}:v1` / `age_self_declared:band:{band}:v1` tokens. These are the finer
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
/// (attestations ABOUT `k`, i.e. `attested_key_id == k`): exactly
/// [`age_band_fine`]`(..).coarsen()`, the CC 3.4.11 read-union
/// (`band_fine_of_rows`), with the presumption-of-sovereignty `Unknown`
/// default when no age row is held.
///
/// A PRESENT-TENSE read: a row is live iff unexpired by the reader's own
/// clock and not retracted. A fold that must converge never asks this; it
/// asks [`age_band_as_of`] (v62.0.0, K2-fix14).
pub async fn age_band(directory: &dyn FederationDirectory, k: &str) -> Result<AgeBand, Error> {
    Ok(age_band_fine(directory, k).await?.coarsen())
}

/// v62.0.0 (K2-fix14; CC 2.7: a fold is a function of the held rows) —
/// [`age_band`] judged at an INSTANT, never the reader's clock, so two nodes
/// holding the same rows agree whenever they ask:
///
/// - `Some(t)`: the band AS OF `t`. A row counts only if asserted at or
///   before `t` and unexpired at `t` (`expires_at` absent or `> t`); a
///   retraction counts only if asserted at or before `t`. The delegation
///   walk's instant lens reads an edge the same way.
/// - `None`: the band as of the NEWEST held evidence about `k`: `t` = the
///   latest `asserted_at` among `k`'s age rows and the retractions naming
///   them (`evidence_instant`). An expiry before that instant counts; an
///   expiry after it does not, until a later row lands (which re-folds:
///   `key:<k>`). This is how an assured `minor` row that lapsed before a
///   later adult proof stops counting without the wall clock.
///
/// # Errors
/// Directory reads.
pub async fn age_band_as_of(
    directory: &dyn FederationDirectory,
    k: &str,
    as_of: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<AgeBand, Error> {
    super::edition2::fold::reads(super::edition2::fold::Dep::key(k));
    let rows = age_rows_about(directory, k).await?;
    Ok(band_as_of_rows(&rows, as_of).coarsen())
}

/// [`age_band_as_of`] over rows already read (newest first).
fn band_as_of_rows(
    rows: &[super::types::Attestation],
    as_of: Option<chrono::DateTime<chrono::Utc>>,
) -> AgeBandFine {
    let Some(t) = as_of.or_else(|| evidence_instant(rows)) else {
        return AgeBandFine::Unknown;
    };
    let retired = retired_age_rows(rows, Some(t));
    band_fine_of_rows(
        rows,
        &retired,
        |r| r.asserted_at <= t,
        |r| r.expires_at.is_none_or(|exp| exp > t),
    )
}

/// Is `r` an age row (`age_assurance:*` or `age_self_declared:*`, either
/// shape, [`super::row_type::claim_token`])?
fn is_age_row(r: &super::types::Attestation) -> bool {
    super::row_type::claim_token(r)
        .is_some_and(|t| t.starts_with("age_assurance:") || t.starts_with("age_self_declared:"))
}

/// v62.0.0 (K2-fix14) — the newest `asserted_at` among `rows`' age rows and
/// the retractions (`withdraws` / `recants`) that name one of them; `None`
/// when no age row is held. A function of the held rows alone.
fn evidence_instant(rows: &[super::types::Attestation]) -> Option<chrono::DateTime<chrono::Utc>> {
    use super::types::attestation_type::{RECANTS, WITHDRAWS};
    let age_ids: std::collections::HashSet<&str> = rows
        .iter()
        .filter(|r| is_age_row(r))
        .map(|r| r.attestation_id.as_str())
        .collect();
    rows.iter()
        .filter(|r| {
            is_age_row(r)
                || ((r.attestation_type == WITHDRAWS || r.attestation_type == RECANTS)
                    && super::precedence::references_attestation_id_from_envelope(
                        &r.attestation_envelope,
                    )
                    .is_some_and(|id| age_ids.contains(id)))
        })
        .map(|r| r.asserted_at)
        .max()
}

/// v62.0.0 (K2-fix14) — the ids of `rows` a retraction among `rows` retires
/// (`precedence::retired_ids`: the ONE composer precedence, with its
/// entitlement gate: a subject withdraws its own declaration, a witness its
/// own verdict). Under `Some(t)` only retractions asserted at or before `t`
/// count.
fn retired_age_rows(
    rows: &[super::types::Attestation],
    as_of: Option<chrono::DateTime<chrono::Utc>>,
) -> std::collections::HashSet<String> {
    let considered: Vec<&super::types::Attestation> = rows
        .iter()
        .filter(|r| as_of.is_none_or(|t| r.asserted_at <= t))
        .collect();
    super::precedence::retired_ids(&considered)
}

/// Every row about `k` (`attested_key_id == k`), newest first
/// (`asserted_at` DESC), walked in pages: a claim token rides either the
/// `scores` dimension or the legacy type slot (`row_type::claim_token`), so
/// no one narrowing holds both shapes. The retractions naming them are rows
/// about `k` too.
async fn age_rows_about(
    directory: &dyn FederationDirectory,
    k: &str,
) -> Result<Vec<super::types::Attestation>, Error> {
    let mut rows = Vec::new();
    let mut pages = AttestationQuery::to(k, FOLD_PAGE).pages();
    while let Some(page) = pages.next(directory).await? {
        rows.extend(page);
    }
    Ok(rows)
}

/// v62.0.0 (K2-fix14) — the assurance level of a witness token
/// (`age_assurance:{level}:…`), ascending confidence (CC 3.4.11 "self <
/// provider < government"): `government` = 2, anything else = 1 (a
/// `provider` row; an unregistered level is refused at the door, and a
/// legacy row is read at the lowest witness rank).
fn assurance_level_rank(token: &str) -> u8 {
    match token.split(':').nth(1) {
        Some("government") => 2,
        _ => 1,
    }
}

/// v62.0.0 (K2-fix15; CC 3.4.11 "the reading", CC 3.5.1: between one
/// holder's own rows the newest stands) — **own-series newest-wins for the
/// CURRENT band.** `true`: before the read-union, each signer's age rows
/// collapse to that signer's newest live, unretracted row: a subject's newer
/// self-declaration replaces its older one, and a witness's newer assurance
/// replaces its own earlier one. The lowering rule and the tie-to-minor rule
/// then apply only ACROSS different signers' current rows. A self-declared
/// `adult` still raises nothing. CC 3.4.11 / 3.5.1; confirmed 2026-11-20;
/// rc22 states it.
///
/// A compile-time constant on purpose: no runtime flag or env var, so two
/// nodes running one build never disagree. It governs the current-band
/// reads only ([`age_band`], [`age_band_fine`], [`age_band_as_of`], the
/// walk's suspension arm). The MINOR-VOID rule ([`duty_edge_void_for_minor`])
/// is a property of the appointment's history and never reads the collapsed
/// view: a minor row held, live or retracted, superseded or not, counts.
pub const AGE_OWN_SERIES_NEWEST_WINS: bool = true;

/// v62.0.0 (K2-fix14, K2-fix15) — the age rows of `rows` that take part in
/// the current band, each with its claim token and parsed band.
///
/// A row is a CANDIDATE when it `exists` at the instant read (asserted by
/// it), is not in `retired`, carries a recognised band of one of the two
/// age prefixes, and is not a self-emitted witness row (CC 3.4.11 read-side
/// defense-in-depth, v13.0.0 CIRISPersist#368).
///
/// Under [`AGE_OWN_SERIES_NEWEST_WINS`] (CC 3.5.1) each signer's NEWEST
/// candidate is that signer's current row (ties at one instant keep the more
/// protective band; chosen by `asserted_at`, never by position), and it
/// supersedes the older ones FOR GOOD: if it is not `unexpired`, the signer
/// has NO current row, and an older row never comes back (age only
/// increases: an expired newer `minor` must not resurrect an `adult` the
/// same witness corrected, nor an expired `adult` proof re-minor someone).
/// A RETRACTED row is different: a retraction un-says it, so it is no
/// candidate and the signer's next-newest non-retracted row is current.
///
/// With the const `false`, every candidate that is `unexpired` takes part
/// (the K2-fix14 reading).
fn current_age_rows<'r>(
    rows: &'r [super::types::Attestation],
    retired: &std::collections::HashSet<String>,
    exists: impl Fn(&super::types::Attestation) -> bool,
    unexpired: impl Fn(&super::types::Attestation) -> bool,
) -> Vec<(&'r super::types::Attestation, &'r str, AgeBandFine)> {
    let candidates = rows.iter().filter_map(|r| {
        if !exists(r) || retired.contains(&r.attestation_id) {
            return None;
        }
        let at = super::row_type::claim_token(r)?;
        if at.starts_with("age_assurance:") {
            if r.attesting_key_id == r.attested_key_id {
                return None;
            }
        } else if !at.starts_with("age_self_declared:") {
            return None;
        }
        let b = parse_age_band_fine_token(at)?;
        Some((r, at, b))
    });
    if !AGE_OWN_SERIES_NEWEST_WINS {
        return candidates.filter(|(r, _, _)| unexpired(r)).collect();
    }
    let mut newest: std::collections::BTreeMap<
        &'r str,
        (&'r super::types::Attestation, &'r str, AgeBandFine),
    > = std::collections::BTreeMap::new();
    for (r, at, b) in candidates {
        let replace = match newest.get(r.attesting_key_id.as_str()) {
            None => true,
            Some((cur, _, cur_b)) => {
                r.asserted_at > cur.asserted_at
                    || (r.asserted_at == cur.asserted_at
                        && b.protection_rank() < cur_b.protection_rank())
            }
        };
        if replace {
            newest.insert(r.attesting_key_id.as_str(), (r, at, b));
        }
    }
    // The supersession is permanent: an expired current row leaves its
    // signer with none.
    newest
        .into_values()
        .filter(|(r, _, _)| unexpired(r))
        .collect()
}

/// v62.0.0 (K2-fix14; CC 3.4.11 read-union, CC 3.4.13 fail-secure) — **the
/// ONE band resolution** over `rows`: each signer's current row
/// (`current_age_rows`: the rows that `exists`, not `retired`, collapsed per
/// signer, then dropped if not `unexpired`):
///
/// 0. v62.0.0 (K2-fix15) — the rows are each signer's CURRENT row
///    ([`AGE_OWN_SERIES_NEWEST_WINS`], `current_age_rows`), so rules 1 and 2
///    compare DIFFERENT signers; within one signer's series the newest
///    stands.
/// 1. **Witness rung** (`age_assurance:*`, not self-emitted): the HIGHEST
///    assurance level among the witnesses' current rows wins (government >
///    provider); at that level, disagreeing bands of different witnesses
///    resolve to the most protective (a `minor` band over `adult`; among
///    minor sub-bands the lowest).
/// 2. **Self rung** (`age_self_declared:*`): the subject's CURRENT
///    declaration, if a MINOR band, LOWERS the reading and never raises it,
///    whatever the witnesses say; a self-declared `adult` is ignored (the
///    one-way ratchet), and as the subject's current row it replaces an
///    older self-declared minor.
/// 3. No usable row: [`AgeBandFine::Unknown`].
///
/// Before K2-fix14 the newest witness row won outright and any witness row
/// silenced the self rung (K2-fix11 relied on it: "assured always outranks
/// self"); CC 3.4.11 says otherwise.
fn band_fine_of_rows(
    rows: &[super::types::Attestation],
    retired: &std::collections::HashSet<String>,
    exists: impl Fn(&super::types::Attestation) -> bool,
    unexpired: impl Fn(&super::types::Attestation) -> bool,
) -> AgeBandFine {
    let mut witness: Option<(u8, AgeBandFine)> = None;
    let mut self_minor: Option<AgeBandFine> = None;
    for (_, at, b) in current_age_rows(rows, retired, exists, unexpired) {
        if at.starts_with("age_assurance:") {
            let level = assurance_level_rank(at);
            witness = Some(match witness {
                Some((l, cur)) if l > level => (l, cur),
                Some((l, cur)) if l == level && cur.protection_rank() <= b.protection_rank() => {
                    (l, cur)
                }
                _ => (level, b),
            });
        } else if b.is_minor()
            && self_minor.is_none_or(|cur| b.protection_rank() < cur.protection_rank())
        {
            // The self rung (`current_age_rows` yields only the two prefixes).
            self_minor = Some(b);
        }
    }
    match (witness.map(|(_, b)| b), self_minor) {
        (Some(w), Some(s)) if w.protection_rank() < s.protection_rank() => w,
        (_, Some(s)) => s,
        (Some(w), None) => w,
        (None, None) => AgeBandFine::Unknown,
    }
}

/// v62.0.0 (K2-fix11; Eric's ruling: **an appointment made to a minor is
/// VOID**; if the person is later proven adult it is made again, never
/// revived) — **is the duty edge `edge` void for minority?** The ONE
/// predicate the write gate
/// (`admission::check_user_target_steward_binding_admission`) and the duty
/// walk (`admission::scoped_delegation_reach_at`) both ask.
///
/// `edge` is a `delegates_to` carrying ANY duty scope onto `T` (its
/// `attested_key_id`): a scope of the duty set in force for the edge's
/// `community_id` (`admission::duty_set_in_force`: the four core duties plus
/// any the community's record declares, CC 4.5.4; matched by
/// `admission::is_duty_scope`). It is VOID iff:
///
/// 1. a MINOR-band age row about `T` is held: an assurance rung
///    (`age_assurance:*`, not self-emitted) or a self-declaration
///    (`age_self_declared:*`), whatever its liveness (a retraction or an
///    expiry does not launder an appointment made during minority); AND
/// 2. no ASSURED-adult row about `T` (an `age_assurance:*` rung parsing to
///    adult; a self-declared adult never counts, the one-way ratchet) is
///    dated before `edge`'s `asserted_at` and unexpired AT that instant.
///    v62.0.0 (K2-fix14): the instant is `edge`'s own, never the reader's
///    clock (`void_over_rows`) — before this a proof that lapsed after
///    `edge` was made voided `edge` on a node that read after the lapse and
///    seated it on one that read before.
///
/// Why it converges (CC 2.7): it is a function of the held rows `{edge, T's
/// age rows}` alone, never of arrival order or of what this node saw first.
/// A node missing a row reads it when it lands: this declares the fold read
/// `key:<T>`. Why a backdate does not help (CC 2.6.7): an EARLIER
/// `asserted_at` can only make `edge` void; to seat, `edge` must post-date an
/// adult proof the WITNESS signed. A pure guardianship (no duty scope) is
/// never judged here. A minor row asserted after an assured-adult proof that
/// precedes `edge` leaves `edge` NOT void. (Whether it still seats is the
/// walk's [`duty_edge_standing`]: while T's band resolves `minor` from an
/// age row the edge is SUSPENDED, and it counts again, unrevived because it
/// was never void, once that reading lifts.)
///
/// # Errors
/// Directory reads.
pub async fn duty_edge_void_for_minor(
    directory: &dyn FederationDirectory,
    edge: &super::types::Attestation,
) -> Result<bool, Error> {
    if !is_duty_edge(directory, edge).await? {
        return Ok(false);
    }
    let t = edge.attested_key_id.as_str();
    super::edition2::fold::reads(super::edition2::fold::Dep::key(t));
    let rows = age_rows_about(directory, t).await?;
    Ok(void_over_rows(edge, &rows))
}

/// v62.0.0 (K2-fix14; CC 3.2 rc21 + CC 4.5.4 as ruled for rc22) — **the
/// standing of the duty edge `edge` onto T**, as the duty walk counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DutyEdgeStanding {
    /// Not a duty edge, or a duty edge that counts.
    Counted,
    /// VOID (`minor_appointment_void`, [`duty_edge_void_for_minor`]): a minor
    /// row about T is held and no assured-adult proof dated before `edge`
    /// was live at its `asserted_at`. A property of the edge, fixed by the
    /// held rows and the edge's own instant: it never seats and is never
    /// revived.
    Void,
    /// SUSPENDED: not void, but T's band RESOLVES `minor` FROM AN AGE ROW
    /// ([`age_band_as_of`] at the walk's instant). Not counted while that
    /// reading stands; counted again, with no re-appointment, once the
    /// minor row is retracted or outranked by a higher-level adult row. A
    /// person with NO age row is never suspended (the band is `Unknown`,
    /// not the CC 3.4.11 `under_13` default: Eric's ruling, rc22 4.5.4).
    Suspended,
}

/// v62.0.0 (K2-fix14) — [`DutyEdgeStanding`] of `edge` under the walk's
/// instant `as_of` (`Some(t)`: the instant lens; `None`: the timeless lens,
/// read as of the newest held age evidence, [`age_band_as_of`]). Neither
/// arm reads the reader's clock, so a fold that walked `edge` and a
/// read-time `is_named_moderator` over the same rows agree. Both declare
/// `key:<T>`, so a T age row or retraction landing re-folds the walk.
///
/// # Errors
/// Directory reads.
pub async fn duty_edge_standing(
    directory: &dyn FederationDirectory,
    edge: &super::types::Attestation,
    as_of: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<DutyEdgeStanding, Error> {
    if !is_duty_edge(directory, edge).await? {
        return Ok(DutyEdgeStanding::Counted);
    }
    let t = edge.attested_key_id.as_str();
    super::edition2::fold::reads(super::edition2::fold::Dep::key(t));
    let rows = age_rows_about(directory, t).await?;
    Ok(if void_over_rows(edge, &rows) {
        DutyEdgeStanding::Void
    } else if band_as_of_rows(&rows, as_of).is_minor() {
        DutyEdgeStanding::Suspended
    } else {
        DutyEdgeStanding::Counted
    })
}

/// v62.0.0 (K2-fix11, K2-fix14) — does `edge` (a `delegates_to`) carry a
/// duty of the duty set in force for its `community_id`
/// (`admission::duty_set_in_force`, matched by `admission::is_duty_scope`)?
/// Reads the community record (`key:<community_id>`) unless every scope is
/// `infra:*`.
async fn is_duty_edge(
    directory: &dyn FederationDirectory,
    edge: &super::types::Attestation,
) -> Result<bool, Error> {
    use super::admission::{delegation_scope_set, duty_set_in_force, is_duty_scope};
    if edge.attestation_type != super::types::attestation_type::DELEGATES_TO {
        return Ok(false);
    }
    let scopes = delegation_scope_set(&edge.attestation_envelope);
    // Only an `infra:*` (or empty) scope set skips the community read: no
    // record can make an `infra:*` scope a duty.
    if scopes
        .iter()
        .all(|s| s.starts_with(super::types::delegation_scope::INFRA_PREFIX))
    {
        return Ok(false);
    }
    let community_id = edge
        .attestation_envelope
        .get("community_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let duties = duty_set_in_force(directory, community_id).await?;
    Ok(scopes.iter().any(|s| is_duty_scope(s, &duties)))
}

/// v62.0.0 (K2-fix11, K2-fix14; CC 3.2 rc21) — the void rule over T's held
/// age `rows`, judged at `edge`'s OWN `asserted_at` `d` and never at the
/// reader's clock:
///
/// 1. a minor-band row is held (an assurance rung, not self-emitted, or a
///    self-declaration; any liveness: an expired or retracted minor row
///    still counts, CC 3.2 "live or retracted"); AND
/// 2. no ASSURED-adult row (`age_assurance:*` parsing to adult, not
///    self-emitted) is dated before `d` AND still unexpired at `d`
///    (`expires_at` absent or `> d`). A proof that had lapsed when `edge`
///    was made proved nothing at `d`; a proof that lapses AFTER `d` proved
///    what it had to, and its later lapse changes nothing.
fn void_over_rows(edge: &super::types::Attestation, rows: &[super::types::Attestation]) -> bool {
    let d = edge.asserted_at;
    let mut minor = false;
    let mut adult_before = false;
    for r in rows {
        let Some(token) = super::row_type::claim_token(r) else {
            continue;
        };
        if token.starts_with("age_assurance:") {
            if r.attesting_key_id == r.attested_key_id {
                continue;
            }
            match parse_age_band_token(token) {
                Some(AgeBand::Minor) => minor = true,
                Some(AgeBand::Adult)
                    if r.asserted_at < d && r.expires_at.is_none_or(|exp| exp > d) =>
                {
                    adult_before = true;
                }
                _ => {}
            }
        } else if token.starts_with("age_self_declared:")
            && parse_age_band_token(token) == Some(AgeBand::Minor)
        {
            minor = true;
        }
    }
    minor && !adult_before
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.13 Q1) — resolve the finer
/// [`AgeBandFine`] of key `k` from its INCOMING age attestations, the policy
/// layer ABOVE [`age_band`]. v62.0.0 (K2-fix14): the CC 3.4.11 read-union
/// of `band_fine_of_rows` (the highest witness level wins, the most
/// protective band at that level, a self-declared minor band lowers the
/// reading and never raises it), over the rows unexpired by the reader's
/// clock and not retracted. [`AgeBandFine::Unknown`] (no usable proof) is
/// returned verbatim; a CONTENT-axis consumer floors it to
/// [`AgeBandFine::Under13`], the steward-binding axis treats it as
/// self-sovereign.
///
/// [`age_band`] is exactly `age_band_fine(..).coarsen()`; both are kept so a
/// consumer can pick the grain it needs without re-deriving liveness.
pub async fn age_band_fine(
    directory: &dyn FederationDirectory,
    k: &str,
) -> Result<AgeBandFine, Error> {
    // v62.0.0 (wave G0; CC 2.7.3) — a fold reading k's age read every row
    // about k: a witness that lands or is withdrawn re-folds it.
    super::edition2::fold::reads(super::edition2::fold::Dep::key(k));
    // A PRESENT-TENSE read (the reader's clock judges expiry). v62.0.0
    // (K2-fix14): retractions now count, and the resolution is CC 3.4.11's
    // (`band_fine_of_rows`).
    let now = crate::host::clock::now();
    let rows = age_rows_about(directory, k).await?;
    let retired = retired_age_rows(&rows, None);
    Ok(band_fine_of_rows(
        &rows,
        &retired,
        |_| true,
        |r| r.expires_at.is_none_or(|exp| exp > now),
    ))
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
            parse_age_band_fine_token("age_self_declared:band:16_17:v1"),
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

    /// v62.0.0 (K2-fix14) — an age row `token` by `by` about `about` at
    /// `at` (the legacy type-slot shape: `claim_token` reads the type).
    fn row(
        id: &str,
        by: &str,
        about: &str,
        token: &str,
        at: chrono::DateTime<chrono::Utc>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> super::super::types::Attestation {
        let mut r = crate::federation::tier_ingest::test_support::bare_attestation(
            id,
            by,
            about,
            &serde_json::json!({}),
        );
        r.attestation_type = token.to_owned();
        r.asserted_at = at;
        r.expires_at = expires_at;
        r
    }

    /// v62.0.0 (K2-fix14; CC 3.4.11 read-union, CC 3.4.13 fail-secure) —
    /// **I2038: the band resolution's precedence**, pure (no backend): the
    /// highest witness level wins; at an equal level the more protective
    /// band wins; a self-declared minor lowers and never raises; a
    /// self-declared adult raises nothing; a retracted row never counts; the
    /// timeless read judges expiry at the newest held evidence.
    #[test]
    fn i2038_band_read_union_precedence() {
        use std::collections::HashSet;
        let t0 = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).expect("t0");
        let h = chrono::Duration::hours(1);
        let all = |_: &super::super::types::Attestation| true;
        let none: HashSet<String> = HashSet::new();
        // K2-fix15: distinct signers where a rule compares signers (`w`,
        // `w2`, `w3` are three witnesses; `t` is the subject).
        let pa = row("pa", "w", "t", "age_assurance:provider:adult:v1", t0, None);
        let pm2 = row(
            "pm2",
            "w2",
            "t",
            "age_assurance:provider:minor:v1",
            t0 + h,
            None,
        );
        let ga = row(
            "ga",
            "w3",
            "t",
            "age_assurance:government:adult:v1",
            t0 + h * 2,
            None,
        );
        let gm = row(
            "gm",
            "w3",
            "t",
            "age_assurance:government:minor:v1",
            t0,
            None,
        );
        let sm = row("sm", "t", "t", "age_self_declared:band:minor:v1", t0, None);
        let sa = row(
            "sa",
            "t",
            "t",
            "age_self_declared:band:adult:v1",
            t0 + h * 3,
            None,
        );
        let band = |rows: Vec<super::super::types::Attestation>, retired: &HashSet<String>| {
            band_fine_of_rows(&rows, retired, all, all).coarsen()
        };
        assert_eq!(band(vec![], &none), AgeBand::Unknown, "I2038: no row");
        assert_eq!(
            band(vec![sa.clone()], &none),
            AgeBand::Unknown,
            "I2038: self adult"
        );
        assert_eq!(
            band(vec![sm.clone(), pa.clone()], &none),
            AgeBand::Minor,
            "I2038: a self-declared minor lowers a witness adult"
        );
        assert_eq!(
            band(vec![pm2.clone(), pa.clone()], &none),
            AgeBand::Minor,
            "I2038: equal level, two witnesses disagree: the more protective wins"
        );
        assert_eq!(
            band(vec![ga.clone(), pm2.clone(), pa.clone()], &none),
            AgeBand::Adult,
            "I2038: the higher level wins"
        );
        assert_eq!(
            band(vec![gm.clone(), pa.clone()], &none),
            AgeBand::Minor,
            "I2038: a government minor outranks a provider adult"
        );
        let retired: HashSet<String> = std::iter::once("sm".to_owned()).collect();
        assert_eq!(
            band(vec![sm.clone(), pa.clone()], &retired),
            AgeBand::Adult,
            "I2038: a retracted self minor no longer lowers"
        );
        // K2-fix15 (AGE_OWN_SERIES_NEWEST_WINS): within ONE signer's series
        // the newest stands, whatever the slice order. (These rows pin the
        // `true` setting; flipping the const reds them, on purpose.)
        assert_eq!(
            band(vec![pa.clone(), sm.clone(), sa.clone()], &none),
            AgeBand::Adult,
            "I2038: the subject's newer self-declaration replaces its older minor one"
        );
        let wm = row(
            "wm",
            "w",
            "t",
            "age_assurance:provider:minor:v1",
            t0 - h,
            None,
        );
        assert_eq!(
            band(vec![wm.clone(), pa.clone()], &none),
            AgeBand::Adult,
            "I2038: the same witness's newer adult replaces its own earlier minor"
        );
        let wm_late = row(
            "wml",
            "w",
            "t",
            "age_assurance:provider:minor:v1",
            t0 + h,
            None,
        );
        assert_eq!(
            band(vec![pa.clone(), wm_late], &none),
            AgeBand::Minor,
            "I2038: ...and its newer minor replaces its own earlier adult"
        );
        assert_eq!(
            band(vec![ga.clone(), gm.clone(), pa.clone()], &none),
            AgeBand::Adult,
            "I2038: w3's newer government adult replaces its own government minor"
        );
        // K2-fix15 (permanent supersession): an EXPIRED newest row leaves its
        // signer with no current row; the older row never comes back.
        let w_adult = row("wa", "w", "t", "age_assurance:provider:adult:v1", t0, None);
        let w_minor_exp = row(
            "wme",
            "w",
            "t",
            "age_assurance:provider:minor:v1",
            t0 + h,
            Some(t0 + h * 2),
        );
        fn after(
            t: chrono::DateTime<chrono::Utc>,
        ) -> impl Fn(&super::super::types::Attestation) -> bool {
            move |r| r.expires_at.is_none_or(|exp| exp > t)
        }
        assert_eq!(
            band_fine_of_rows(
                &[w_adult.clone(), w_minor_exp.clone()],
                &none,
                all,
                after(t0 + h * 3)
            )
            .coarsen(),
            AgeBand::Unknown,
            "I2038: an expired newer minor does not resurrect the adult it superseded"
        );
        let w_minor = row("wmi", "w", "t", "age_assurance:provider:minor:v1", t0, None);
        let w_adult_exp = row(
            "wae",
            "w",
            "t",
            "age_assurance:provider:adult:v1",
            t0 + h,
            Some(t0 + h * 2),
        );
        assert_eq!(
            band_fine_of_rows(&[w_minor, w_adult_exp], &none, all, after(t0 + h * 3)).coarsen(),
            AgeBand::Unknown,
            "I2038: an expired adult proof does not re-minor the person"
        );
        // ...but a RETRACTED newest row is un-said: the previous row stands.
        let retired_wme: HashSet<String> = std::iter::once("wme".to_owned()).collect();
        assert_eq!(
            band_fine_of_rows(&[w_adult, w_minor_exp], &retired_wme, all, all).coarsen(),
            AgeBand::Adult,
            "I2038: a retracted newer row lets the previous one stand"
        );
        // The timeless read: an assured minor that lapsed before a later
        // adult proof is judged at the newest held evidence (the proof).
        let lapsed = row(
            "lm",
            "w",
            "t",
            "age_assurance:provider:minor:v1",
            t0,
            Some(t0 + h),
        );
        let later = row(
            "la",
            "w",
            "t",
            "age_assurance:provider:adult:v1",
            t0 + h * 2,
            Some(t0 + h * 3),
        );
        assert_eq!(
            evidence_instant(&[later.clone(), lapsed.clone()]),
            Some(t0 + h * 2),
            "I2038: the evidence instant is the newest age row"
        );
        assert_eq!(
            band_as_of_rows(&[later.clone(), lapsed.clone()], None).coarsen(),
            AgeBand::Adult,
            "I2038: timeless: the lapsed minor is out, the proof is live"
        );
        assert_eq!(
            band_as_of_rows(&[later, lapsed], Some(t0 + h * 4)).coarsen(),
            AgeBand::Unknown,
            "I2038: at an instant after both lapse, nothing is live"
        );
    }
}
