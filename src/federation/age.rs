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
//! **Liveness (v62.0.0 K2-fix16, the T8 pattern):** the reading is taken at
//! an instant t: each signer's newest non-retracted row dated at or before t,
//! counted only if it covers t (`asserted_at <= t < expires_at`); a
//! retraction counts from its own instant. [`age_band_as_of`] takes t from
//! the act being judged; [`age_band`] / [`age_band_fine`] are HOST-EDGE
//! reads at this node's clock (CC 2.7.9). The three-valued band is exposed verbatim over FFI so #309
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

/// v62.0.0 (K2-fix14, K2-fix16; the T8 pattern, CC 2.7.9) — the CURRENT age
/// band of `k` AS OF the signer-stamped instant `t`: the asserted_at of the
/// act being judged. Never the reader's clock, so two nodes holding the same
/// rows agree whenever they ask. Each signer's current row at `t` is its
/// newest non-retracted age row dated at or before `t`
/// (`current_age_rows`); it counts only if it COVERS `t` (half-open:
/// `asserted_at <= t < expires_at`, an absent `expires_at` covers every
/// later `t`); a retraction counts only if asserted at or before `t` (a
/// retraction is not retroactive, CC 2.4.1). Then the cross-signer read-union
/// (`band_fine_of_rows`).
///
/// A host display with no act to judge passes its own clock explicitly at
/// the edge (CC 2.7.9: such a reading means nothing beyond that node).
///
/// # Errors
/// Directory reads.
pub async fn age_band_as_of(
    directory: &dyn FederationDirectory,
    k: &str,
    t: chrono::DateTime<chrono::Utc>,
) -> Result<AgeBand, Error> {
    super::edition2::fold::reads(super::edition2::fold::Dep::key(k));
    let rows = age_rows_about(directory, k).await?;
    Ok(band_as_of_rows(&rows, t).coarsen())
}

/// v62.0.0 (K2-fix20; CC 3.5.1 rule 3, ruled 2026-11-20) — **the ONE
/// same-signer same-instant tie-break** of the current band: when one
/// signer holds two age rows with the same `asserted_at`, the row with the
/// LOWEST `attestation_id` is that signer's current row, whatever its band
/// (CC 3.5.1 rule 3 has no protective exception). `attestation_id` of an
/// edition-2 row is the lowercase hex of its 32-byte row id
/// (`edition2::names::RowId::hex`: SHA-256 over
/// `CDE(["CEG-row/2", type, family, sub, author, payload])`, CC 2.6.1.3), so
/// this `str` comparison is the byte-wise comparison of the digests, done
/// here in Rust over the fetched text on every backend (no collation). If a
/// protective tie-break is ever written into the text, it changes HERE only.
fn same_instant_tie_replaces(
    candidate: &super::types::Attestation,
    current: &super::types::Attestation,
) -> bool {
    candidate.attestation_id < current.attestation_id
}

/// v62.0.0 (K2-fix20; CC 5.4.6 as ruled for rc22, CC 3.4.13 Q5) — **may the
/// producing node publish a federation-scope `rendezvous:route` for
/// `key`?** The route's own key is a fresh per-period rendezvous key,
/// unlinkable to its person by design (CC 3.1.4), so no receiver can check
/// this and none needs to: publishing is the producing node's own present
/// act, judged against the rows it holds at publish time. It MUST NOT
/// publish one for a person a held row places in a minor band. `key` is the
/// person, a key that acts for them, or their node: the person is `key`,
/// its active identity, and (for a node) its RAW owner seat
/// (`kernel_owner_selves`, not `owner_of`, which already drops a minor
/// owner). Each is read with [`age_band_held`] (class 2: the held rows, no
/// instant, no expiry). A person with no age row may publish.
///
/// AUTHORING SIDE ONLY. There is no receive-side gate, and persist has no
/// local authoring door for route rows: the host (Edge) MUST call this
/// before it publishes (Engine `may_publish_federation_rendezvous`, PyO3
/// `may_publish_federation_rendezvous`, capsule
/// `DirectoryOp::MayPublishFederationRendezvous`).
///
/// # Errors
/// [`Error::WriteScopeRefused`]`(`[`crate::scope::ScopeRefusalReason::MinorRendezvousAtFederation`]`)`
/// (`scope_minor_rendezvous_at_federation`); directory reads.
pub async fn may_publish_federation_rendezvous(
    directory: &dyn FederationDirectory,
    key: &str,
) -> Result<(), Error> {
    let mut persons: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::from([key.to_owned()]);
    persons.insert(directory.active_identity_for_occurrence(key).await?);
    persons.extend(
        super::admission::kernel_owner_selves(
            directory,
            key,
            crate::kernel::owner::Cosign::Required,
        )
        .await?,
    );
    for p in &persons {
        if age_band_held(directory, p).await? == AgeBand::Minor {
            return Err(Error::WriteScopeRefused(
                crate::scope::ScopeRefusalReason::MinorRendezvousAtFederation,
            ));
        }
    }
    Ok(())
}

/// v62.0.0 (K2-fix17; CC 5.4.6, CC 3.2 l.961, CC 3.4.13 Q5) — **the
/// HELD-ROW band**, for a STANDING PROTECTION keyed to a minor band (class 2
/// of the three, K2-fix17.md): judged against the rows HELD NOW, for as long
/// as the minor row stands. Each signer's current row is its newest
/// non-retracted held row (`current_age_rows`, every retraction held
/// counting); `expires_at` is NOT consulted, so the reading is a function of
/// the held rows alone (a fold hold over it re-folds only when an age row or
/// a retraction about `k` lands: `key:<k>`), and it fails toward
/// protection: a minor row does not stop standing by lapsing. A later minor
/// row takes effect at once; its withdrawal, or being outranked, restores.
/// No age row reads `Unknown`, which no standing protection treats as minor.
///
/// Contrast [`age_band_as_of`] (class 1: an ACT judged at its own instant)
/// and [`duty_edge_void_for_minor`] (class 3: the appointment's history).
///
/// # Errors
/// Directory reads.
pub async fn age_band_held<F: FederationDirectory + ?Sized>(
    directory: &F,
    k: &str,
) -> Result<AgeBand, Error> {
    super::edition2::fold::reads(super::edition2::fold::Dep::key(k));
    let mut rows = Vec::new();
    let mut pages = AttestationQuery::to(k, FOLD_PAGE).pages();
    while let Some(page) = pages.next(directory).await? {
        rows.extend(page);
    }
    let retired = retired_age_rows(&rows, None);
    Ok(band_fine_of_rows(&rows, &retired, |_| true, |_| true).coarsen())
}

/// [`age_band_as_of`] over rows already read, at the finer grain.
fn band_as_of_rows(
    rows: &[super::types::Attestation],
    t: chrono::DateTime<chrono::Utc>,
) -> AgeBandFine {
    let retired = retired_age_rows(rows, Some(t));
    band_fine_of_rows(
        rows,
        &retired,
        |r| r.asserted_at <= t,
        |r| r.expires_at.is_none_or(|exp| exp > t),
    )
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
/// candidate is that signer's current row (chosen by `asserted_at`, never by
/// position; a tie at one instant goes to the lowest `attestation_id`, CC
/// 3.5.1 rule 3, `same_instant_tie_replaces`), and it
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
            Some((cur, _, _)) => {
                r.asserted_at > cur.asserted_at
                    || (r.asserted_at == cur.asserted_at && same_instant_tie_replaces(r, cur))
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
///    dated before `edge`'s `asserted_at`. v62.0.0 (K2-fix16; CC rc21 3.2
///    wording, CIRISKernel MinorVoid.tla): NO expiry appears. Age only
///    increases, so a proof's later lapse un-proves nothing; and an expiry
///    clause broke "backdating can only void" (an earlier D could dodge a
///    proof that had lapsed by a later D). Whether a RETRACTED proof still
///    lifts is [`RETRACTED_ADULT_PROOF_LIFTS_VOID`].
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
    /// row about T is held and no assured-adult proof is dated before
    /// `edge`'s `asserted_at`. A property of the edge, fixed by the held rows
    /// and two `asserted_at` values: it never seats and is never revived.
    Void,
    /// SUSPENDED: not void, but T's band RESOLVES `minor` FROM AN AGE ROW
    /// ([`age_band_as_of`] at the walk's instant). Not counted while that
    /// reading stands; counted again, with no re-appointment, once the
    /// minor row is retracted or outranked by a higher-level adult row. A
    /// person with NO age row is never suspended (the band is `Unknown`,
    /// not the CC 3.4.11 `under_13` default: Eric's ruling, rc22 4.5.4).
    Suspended,
}

/// v62.0.0 (K2-fix14, K2-fix16) — [`DutyEdgeStanding`] of `edge`, the seat
/// judged at `band_at`: the asserted_at of the act being judged (the T8
/// pattern; the walk's `band_at`, else its `as_of`). `Some(t)`: VOID, else
/// SUSPENDED iff T's band at `t` ([`age_band_as_of`]) is minor from a row,
/// else COUNTED. `None` (a walk that judges no act, e.g. a bare
/// reachability question): only VOID applies. Neither arm reads the
/// reader's clock. Both declare `key:<T>`, so a T age row or retraction
/// landing re-folds the walk.
///
/// # Errors
/// Directory reads.
pub async fn duty_edge_standing(
    directory: &dyn FederationDirectory,
    edge: &super::types::Attestation,
    band_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<DutyEdgeStanding, Error> {
    if !is_duty_edge(directory, edge).await? {
        return Ok(DutyEdgeStanding::Counted);
    }
    let t = edge.attested_key_id.as_str();
    super::edition2::fold::reads(super::edition2::fold::Dep::key(t));
    let rows = age_rows_about(directory, t).await?;
    Ok(if void_over_rows(edge, &rows) {
        DutyEdgeStanding::Void
    } else if band_at.is_some_and(|t| band_as_of_rows(&rows, t).is_minor()) {
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

/// v62.0.0 (K2-fix16; pending Eric — CC recommends `false`) — **does a
/// RETRACTED assured-adult proof dated before D still lift the void?**
/// `true` (today's behaviour): yes, a held proof counts whether or not its
/// witness withdrew it. `false` (the CC recommendation): no — a witness
/// withdrawing an adult assurance puts the adult fact itself in doubt, so
/// the rule fails toward protecting a possible minor. One compile-time
/// constant, no runtime flag: two nodes on one build never disagree. The
/// pure table `i2047_void_rule_table` witnesses BOTH values through
/// `void_over_rows_with`. Model: CIRISKernel MinorVoid.tla's
/// `RETRACTED_ADULT_LIFTS` (`TRUE` today; `FALSE` in
/// `MinorVoid_retracted_adult`).
pub const RETRACTED_ADULT_PROOF_LIFTS_VOID: bool = true;

/// v62.0.0 (K2-fix11, K2-fix14, K2-fix16; CC rc21 3.2) — the void rule over
/// T's held age `rows`, as `void_over_rows_with` under
/// [`RETRACTED_ADULT_PROOF_LIFTS_VOID`].
fn void_over_rows(edge: &super::types::Attestation, rows: &[super::types::Attestation]) -> bool {
    let retired = retired_age_rows(rows, None);
    void_over_rows_with(edge, rows, &retired, RETRACTED_ADULT_PROOF_LIFTS_VOID)
}

/// The void rule, the switch passed in (so a table can witness both
/// values). D (`edge`, `d` = its `asserted_at`) is void iff
///
/// 1. a minor-band row about T is held (an assurance rung, not
///    self-emitted, or a self-declaration), whatever its liveness,
///    retraction or supersession (CC 3.2 "live or retracted"; the
///    own-series newest-wins of the CURRENT band never applies here); AND
/// 2. no ASSURED-adult row (`age_assurance:*` parsing to adult, not
///    self-emitted) has `asserted_at < d` — expired or not; a RETRACTED one
///    (named in `retired`) counts only when `retracted_adult_lifts`.
///
/// It reads only held rows and two `asserted_at` values (no clock, no
/// expiry), so it is order-independent and node-agreeing; and it is
/// MONOTONE in `d`: the set of proofs dated before `d` only grows as `d`
/// grows, so an earlier (backdated) D can only be void.
fn void_over_rows_with(
    edge: &super::types::Attestation,
    rows: &[super::types::Attestation],
    retired: &std::collections::HashSet<String>,
    retracted_adult_lifts: bool,
) -> bool {
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
                    if r.asserted_at < d
                        && (retracted_adult_lifts || !retired.contains(&r.attestation_id)) =>
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
    // K2-fix16 — HOST EDGE (CC 2.7.9): no act is judged, so the reading is
    // taken at this node's own clock, explicitly, and means nothing beyond
    // this node. A fold or a gate asks `age_band_as_of` with the act's
    // instant instead.
    let now = crate::host::clock::now();
    let rows = age_rows_about(directory, k).await?;
    Ok(band_as_of_rows(&rows, now))
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
    /// self-declared adult raises nothing; a retracted row never counts.
    /// Instant cases: MinorSuspend.tla Inv_LaterRowsNotYet (a row dated after
    /// t is not yet the signer's word), Inv_RetractedOut (a retraction counts
    /// from its own instant) and Inv_SelfAdultAloneIsNone (self adult alone).
    /// K2-fix15/16: newest-per-signer applies to the CURRENT band only
    /// (`newest_per_signer_current_band_only`), and the reading is taken at
    /// an instant t (each signer's newest non-retracted row dated <= t that
    /// covers t).
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
        // K2-fix16 (T8): the reading is taken at an instant t: each signer's
        // newest non-retracted row dated <= t that COVERS t (half-open
        // asserted_at <= t < expires_at).
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
        let both = [later.clone(), lapsed.clone()];
        assert_eq!(
            band_as_of_rows(&both, t0 + h / 2).coarsen(),
            AgeBand::Minor,
            "I2038: at t0+30m the adult row is not yet the witness's word: minor"
        );
        assert_eq!(
            band_as_of_rows(&both, t0 + h + h / 2).coarsen(),
            AgeBand::Unknown,
            "I2038: at t0+90m the minor (newest at t) has lapsed: no current row"
        );
        assert_eq!(
            band_as_of_rows(&both, t0 + h * 2).coarsen(),
            AgeBand::Adult,
            "I2038: at t0+2h the adult row covers t (half-open: asserted_at <= t)"
        );
        assert_eq!(
            band_as_of_rows(&both, t0 + h * 3).coarsen(),
            AgeBand::Unknown,
            "I2038: at t0+3h it no longer covers (t < expires_at fails): no current row"
        );
        // A retraction counts only from its own instant (not retroactive).
        let mut wd = row(
            "wd",
            "w",
            "t",
            crate::federation::types::attestation_type::WITHDRAWS,
            t0 + h * 2 + h / 2,
            None,
        );
        wd.attestation_envelope = serde_json::json!({ "references_attestation_id": "la" });
        let with_wd = [wd, later, lapsed];
        assert_eq!(
            band_as_of_rows(&with_wd, t0 + h * 2).coarsen(),
            AgeBand::Adult,
            "I2038: before its retraction the adult row is current"
        );
        assert_eq!(
            band_as_of_rows(&with_wd, t0 + h * 2 + h / 2).coarsen(),
            AgeBand::Unknown,
            "I2038: retracted, the previous row (lapsed by then) stands: none covers t"
        );
    }

    /// v62.0.0 (K2-fix16; CC rc21 3.2) — the void rule checked against
    /// CIRISKernel's MinorVoid.tla (PR #7) properties, under ONE value of the
    /// retracted-adult-proof switch. Each section names the model property.
    fn void_table(lifts: bool) {
        use std::collections::HashSet;
        type A = super::super::types::Attestation;
        let t0 = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).expect("t0");
        let h = chrono::Duration::hours(1);
        let d_at = |at| row("d", "f", "t", "delegates_to", at, None);
        let d = d_at(t0 + h * 10);
        let none: HashSet<String> = HashSet::new();
        let void_at = |dd: &A, rows: &[A], retired: &HashSet<String>| {
            void_over_rows_with(dd, rows, retired, lifts)
        };
        let void = |rows: &[A], retired: &HashSet<String>| void_at(&d, rows, retired);
        let ids = |rows: &[A]| -> HashSet<String> {
            rows.iter().map(|r| r.attestation_id.clone()).collect()
        };
        let is_minor_row =
            |r: &A| parse_age_band_token(&r.attestation_type) == Some(AgeBand::Minor);
        let sm = row("sm", "t", "t", "age_self_declared:band:minor:v1", t0, None);
        let sa = row(
            "sa",
            "t",
            "t",
            "age_self_declared:band:adult:v1",
            t0 + h,
            None,
        );
        let wm = row(
            "wm",
            "w",
            "t",
            "age_assurance:provider:minor:v1",
            t0 + h * 2,
            None,
        );
        let pa = row(
            "pa",
            "w",
            "t",
            "age_assurance:provider:adult:v1",
            t0 + h * 5,
            None,
        );
        let pa_exp = row(
            "pae",
            "w",
            "t",
            "age_assurance:provider:adult:v1",
            t0 + h * 5,
            Some(t0 + h * 6),
        );
        let pa_late = row(
            "pal",
            "w",
            "t",
            "age_assurance:provider:adult:v1",
            t0 + h * 11,
            None,
        );
        let pa_self = row(
            "pas",
            "t",
            "t",
            "age_assurance:provider:adult:v1",
            t0 + h * 5,
            None,
        );
        let tag = if lifts { "lifts=true" } else { "lifts=false" };
        // The held sets the properties quantify over.
        let sets: Vec<Vec<A>> = vec![
            vec![],
            vec![sm.clone()],
            vec![wm.clone()],
            vec![sm.clone(), pa.clone()],
            vec![sm.clone(), pa_exp.clone()],
            vec![sm.clone(), pa_late.clone()],
            vec![sm.clone(), sa.clone()],
            vec![sm.clone(), pa_self.clone()],
            vec![wm.clone(), sa.clone(), pa.clone()],
            vec![sm.clone(), wm.clone(), sa.clone(), pa_late.clone()],
        ];
        let instants: Vec<chrono::DateTime<chrono::Utc>> = [0, 3, 5, 6, 10, 11, 20]
            .iter()
            .map(|n| t0 + h * *n)
            .collect();

        // The plain table.
        assert!(!void(&[], &none), "I2047 ({tag}): no age row: not void");
        assert!(
            void(std::slice::from_ref(&sm), &none),
            "I2047 ({tag}): a minor row: void"
        );
        assert!(
            !void(&[sm.clone(), pa.clone()], &none),
            "I2047 ({tag}): an assured adult dated before D lifts it"
        );
        assert!(
            void(&[sm.clone(), pa_self.clone()], &none),
            "I2047 ({tag}): a self-emitted assurance lifts nothing"
        );

        // Inv_NodesAgree: the verdict reads no clock. The only time-varying
        // field a row carries is `expires_at`; a proof expired long before D
        // gives the verdict an unexpired one gives, so a reader at any
        // instant gets the same answer.
        assert_eq!(
            void(&[sm.clone(), pa_exp.clone()], &none),
            void(&[sm.clone(), pa.clone()], &none),
            "I2047 ({tag}) Inv_NodesAgree: expiry never enters the verdict"
        );

        // Inv_Fold: kept incrementally in every arrival order, the verdict is
        // the verdict over the set (persist re-folds the held set on each
        // landing; every permutation's final verdict, and each prefix's,
        // equals the set's verdict over that prefix's rows).
        let base = [sm.clone(), wm.clone(), sa.clone(), pa.clone()];
        let mut perm = [0usize, 1, 2, 3];
        let want = void(&base, &none);
        loop {
            let ordered: Vec<A> = perm.iter().map(|i| base[*i].clone()).collect();
            for k in 0..=ordered.len() {
                let prefix = &ordered[..k];
                let mut sorted: Vec<A> = prefix.to_vec();
                sorted.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
                assert_eq!(
                    void(prefix, &none),
                    void(&sorted, &none),
                    "I2047 ({tag}) Inv_Fold: prefix {k} of {perm:?}"
                );
            }
            assert_eq!(
                void(&ordered, &none),
                want,
                "I2047 ({tag}) Inv_Fold: {perm:?}"
            );
            // next lexicographic permutation
            let Some(i) = (0..3).rev().find(|&i| perm[i] < perm[i + 1]) else {
                break;
            };
            let j = (i + 1..4).rev().find(|&j| perm[j] > perm[i]).expect("j");
            perm.swap(i, j);
            perm[i + 1..].reverse();
        }

        // Inv_BackdateOnlyVoids: D1.at < D2.at and void(D2) ⇒ void(D1).
        for set in &sets {
            for (x, a1) in instants.iter().enumerate() {
                for a2 in &instants[x + 1..] {
                    let (d1, d2) = (d_at(*a1), d_at(*a2));
                    assert!(
                        !void_at(&d2, set, &none) || void_at(&d1, set, &none),
                        "I2047 ({tag}) Inv_BackdateOnlyVoids: {a1} < {a2} over {:?}",
                        ids(set)
                    );
                }
            }
        }

        // Inv_RetractionChangesNothing: removing every retraction changes no
        // verdict (lifts = true). Under the pending value (lifts = false) it
        // weakens to: removing retractions of MINOR rows changes no verdict.
        for set in &sets {
            let retired: HashSet<String> = if lifts {
                ids(set)
            } else {
                set.iter()
                    .filter(|r| is_minor_row(r))
                    .map(|r| r.attestation_id.clone())
                    .collect()
            };
            assert_eq!(
                void(set, &retired),
                void(set, &none),
                "I2047 ({tag}) Inv_RetractionChangesNothing over {:?}",
                ids(set)
            );
        }
        // ...and the switch itself: a retracted assured adult proof dated
        // before D lifts the void iff `lifts`.
        let retired_pa: HashSet<String> = std::iter::once("pa".to_owned()).collect();
        assert_eq!(
            void(&[sm.clone(), pa.clone()], &retired_pa),
            !lifts,
            "I2047 ({tag}): RETRACTED_ADULT_PROOF_LIFTS_VOID"
        );

        // Inv_RetractedMinorCounts: a retracted minor row still voids D when
        // no assured proof is dated before D.at.
        let retired_sm: HashSet<String> = std::iter::once("sm".to_owned()).collect();
        assert!(
            void(std::slice::from_ref(&sm), &retired_sm),
            "I2047 ({tag}) Inv_RetractedMinorCounts"
        );
        assert!(
            void(&[sm.clone(), pa_late.clone()], &retired_sm),
            "I2047 ({tag}) Inv_RetractedMinorCounts: a later proof does not change it"
        );

        // Inv_SelfAdultLiftsNothing: removing every self-declared adult row
        // never turns void into not-void.
        for set in &sets {
            let without: Vec<A> = set
                .iter()
                .filter(|r| r.attestation_type != "age_self_declared:band:adult:v1")
                .cloned()
                .collect();
            assert!(
                !void(set, &none) || void(&without, &none),
                "I2047 ({tag}) Inv_SelfAdultLiftsNothing over {:?}",
                ids(set)
            );
            assert_eq!(
                void(set, &none),
                void(&without, &none),
                "I2047 ({tag}) Inv_SelfAdultLiftsNothing (equality) over {:?}",
                ids(set)
            );
        }

        // Inv_SupersededMinorStillVoids: a minor row superseded by its own
        // signer's newer adult row still voids D with no ASSURED proof
        // dated before D.at (the current-band newest-wins never applies).
        assert!(
            void(&[sa.clone(), sm.clone()], &none),
            "I2047 ({tag}) Inv_SupersededMinorStillVoids"
        );

        // Prop_LaterProofNoRevive: once void, an adult proof dated at or
        // after D.at never makes D not-void.
        for at in [t0 + h * 10, t0 + h * 11, t0 + h * 40] {
            let later = row(
                "lp",
                "w",
                "t",
                "age_assurance:government:adult:v1",
                at,
                None,
            );
            assert!(
                void(std::slice::from_ref(&sm), &none) && void(&[sm.clone(), later], &none),
                "I2047 ({tag}) Prop_LaterProofNoRevive: a proof at {at}"
            );
        }
    }

    /// v62.0.0 (K2-fix16) — **I2047: the void rule against MinorVoid.tla's
    /// properties** (Inv_NodesAgree, Inv_Fold, Inv_BackdateOnlyVoids,
    /// Inv_RetractionChangesNothing, Inv_RetractedMinorCounts,
    /// Inv_SelfAdultLiftsNothing, Inv_SupersededMinorStillVoids,
    /// Prop_LaterProofNoRevive), under BOTH values of
    /// [`RETRACTED_ADULT_PROOF_LIFTS_VOID`] (pending Eric; CC recommends
    /// `false`), so flipping the const needs no new test.
    #[test]
    fn i2047_void_rule_table() {
        void_table(true);
        void_table(false);
    }

    /// v62.0.0 (K2-fix19) — **I2054: the SUSPENSION read (the current band at
    /// an act's instant t, `band_as_of_rows`) against CIRISKernel's
    /// MinorSuspend.tla** (PR #7, df93bb1), pure. Each section names the
    /// model invariant it witnesses: Inv_NodesAgree, Inv_SeriesFold,
    /// Inv_Fold, Inv_LaterRowsNotYet, Inv_RetractedOut, Inv_SelfNeverRaises,
    /// Inv_SelfAdultAloneIsNone, Inv_SuspendedNeedsMinorRow.
    #[test]
    fn i2054_suspension_read_table() {
        type A = super::super::types::Attestation;
        let t0 = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).expect("t0");
        let h = chrono::Duration::hours(1);
        let wa = row("wa", "w", "t", "age_assurance:provider:adult:v1", t0, None);
        let wm = row(
            "wm",
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
            Some(t0 + h * 6),
        );
        let sm = row(
            "sm",
            "t",
            "t",
            "age_self_declared:band:minor:v1",
            t0 + h * 3,
            None,
        );
        let sa = row(
            "sa",
            "t",
            "t",
            "age_self_declared:band:adult:v1",
            t0 + h * 4,
            None,
        );
        let wm_self = row(
            "wm1",
            "w",
            "t",
            "age_assurance:provider:minor:v1",
            t0 + h * 3,
            None,
        );
        let retract = |x: &A, at| {
            let mut r = row(
                &format!("rx-{}", x.attestation_id),
                &x.attesting_key_id,
                "t",
                super::super::types::attestation_type::WITHDRAWS,
                at,
                None,
            );
            r.attestation_envelope =
                serde_json::json!({ "references_attestation_id": x.attestation_id });
            r
        };
        let instants: Vec<chrono::DateTime<chrono::Utc>> = [-1, 0, 1, 2, 3, 4, 5, 7]
            .iter()
            .map(|n| t0 + h * *n)
            .collect();
        let read = |rows: &[A], t| band_as_of_rows(rows, t).coarsen();
        let sets: Vec<Vec<A>> = vec![
            vec![],
            vec![wa.clone()],
            vec![wa.clone(), wm.clone()],
            vec![wa.clone(), wm.clone(), ga.clone()],
            vec![wa.clone(), sm.clone()],
            vec![wa.clone(), sm.clone(), sa.clone()],
            vec![wa.clone(), wm_self.clone()],
            vec![sa.clone()],
            vec![
                wm.clone(),
                ga.clone(),
                sm.clone(),
                sa.clone(),
                wm_self.clone(),
            ],
        ];

        // Inv_NodesAgree: the read takes the act's instant and the held rows,
        // and no clock (its signature is the witness); the same rows at the
        // same t give the same band however often, wherever, it is read.
        for set in &sets {
            for t in &instants {
                assert_eq!(read(set, *t), read(set, *t), "I2054 Inv_NodesAgree");
            }
        }

        // Inv_SeriesFold + Inv_Fold: rows arriving in any order give the
        // reading of the held set (every rotation and the reversal of the
        // widest set; every prefix equals the same prefix re-sorted).
        let widest = sets.last().expect("sets").clone();
        for t in &instants {
            let want = read(&widest, *t);
            for k in 0..widest.len() {
                let mut rot = widest.clone();
                rot.rotate_left(k);
                assert_eq!(
                    read(&rot, *t),
                    want,
                    "I2054 Inv_SeriesFold: rotation {k} at {t}"
                );
                let mut rev = rot.clone();
                rev.reverse();
                assert_eq!(
                    read(&rev, *t),
                    want,
                    "I2054 Inv_SeriesFold: reversed {k} at {t}"
                );
                let prefix = &rot[..k];
                let mut sorted = prefix.to_vec();
                sorted.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
                assert_eq!(
                    read(prefix, *t),
                    read(&sorted, *t),
                    "I2054 Inv_Fold: prefix {k}"
                );
            }
        }

        // Inv_LaterRowsNotYet: a row dated after t changes nothing at t.
        for set in &sets {
            for t in &instants {
                for later in [&wa, &wm, &ga, &sm, &sa, &wm_self] {
                    if later.asserted_at > *t {
                        let mut plus = set.clone();
                        plus.push(later.clone());
                        assert_eq!(
                            read(&plus, *t),
                            read(set, *t),
                            "I2054 Inv_LaterRowsNotYet: {} at {t}",
                            later.attestation_id
                        );
                    }
                }
            }
        }

        // Inv_RetractedOut: dropping a retracted row TOGETHER with its
        // retraction changes nothing. Witnessed for retractions dated at or
        // before t only: a retraction dated AFTER t is not counted at t by
        // persist (K2-fix19.md, difference (a), pending Constitution).
        for set in &sets {
            for x in [&wm, &sm, &ga, &wm_self] {
                for t in &instants {
                    if x.asserted_at > *t {
                        continue;
                    }
                    let mut with = set.clone();
                    if !with.iter().any(|r| r.attestation_id == x.attestation_id) {
                        with.push(x.clone());
                    }
                    with.push(retract(x, *t));
                    let without: Vec<A> = set
                        .iter()
                        .filter(|r| r.attestation_id != x.attestation_id)
                        .cloned()
                        .collect();
                    assert_eq!(
                        read(&with, *t),
                        read(&without, *t),
                        "I2054 Inv_RetractedOut: {} at {t}",
                        x.attestation_id
                    );
                }
            }
        }

        // Inv_SelfNeverRaises: when the witnesses alone read minor, the
        // person reads minor, whatever they declare.
        let witnesses_minor = vec![wa.clone(), wm.clone()];
        for t in &instants {
            if read(&witnesses_minor, *t) != AgeBand::Minor {
                continue;
            }
            for selfs in [
                vec![sa.clone()],
                vec![sm.clone()],
                vec![sm.clone(), sa.clone()],
            ] {
                let mut plus = witnesses_minor.clone();
                plus.extend(selfs);
                assert_eq!(
                    read(&plus, *t),
                    AgeBand::Minor,
                    "I2054 Inv_SelfNeverRaises at {t}"
                );
            }
        }

        // Inv_SelfAdultAloneIsNone: a self-declared adult row alone never
        // reads adult.
        for t in &instants {
            assert_ne!(
                read(std::slice::from_ref(&sa), *t),
                AgeBand::Adult,
                "I2054 Inv_SelfAdultAloneIsNone at {t}"
            );
        }

        // Inv_SuspendedNeedsMinorRow: with no minor-band row held, never minor
        // (no age row at all reads Unknown, never the under_13 default).
        for set in &sets {
            let any_minor = set
                .iter()
                .any(|r| parse_age_band_token(&r.attestation_type) == Some(AgeBand::Minor));
            if any_minor {
                continue;
            }
            for t in &instants {
                assert_ne!(
                    read(set, *t),
                    AgeBand::Minor,
                    "I2054 Inv_SuspendedNeedsMinorRow over {:?} at {t}",
                    set.iter()
                        .map(|r| r.attestation_id.as_str())
                        .collect::<Vec<_>>()
                );
            }
        }
        assert_eq!(
            read(&[], t0),
            AgeBand::Unknown,
            "I2054: no age row is Unknown"
        );
    }

    /// v62.0.0 (K2-fix21) — **I2058: MinorSuspend.tla Inv_TieLowestIdWins,
    /// pure** (the store witness is I2055): one signer, two age rows at ONE
    /// instant; the lowest `attestation_id` is the signer's current row
    /// whatever its band, in either slice order, at the witness and at the
    /// self rung; and Inv_NewestStands: a strictly newer row of the same
    /// signer wins over any id.
    #[test]
    fn i2058_tie_lowest_id_wins_table() {
        use std::collections::HashSet;
        let t0 = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).expect("t0");
        let none: HashSet<String> = HashSet::new();
        let all = |_: &super::super::types::Attestation| true;
        let band = |rows: &[super::super::types::Attestation]| {
            band_fine_of_rows(rows, &none, all, all).coarsen()
        };
        let minor = "age_assurance:provider:minor:v1";
        let adult = "age_assurance:provider:adult:v1";
        for (lo_tok, hi_tok, want) in [
            (minor, adult, AgeBand::Minor),
            (adult, minor, AgeBand::Adult),
        ] {
            let lo = row("0000aa", "w", "t", lo_tok, t0, None);
            let hi = row("ffff00", "w", "t", hi_tok, t0, None);
            assert_eq!(
                band(&[lo.clone(), hi.clone()]),
                want,
                "I2058 Inv_TieLowestIdWins: lower id {lo_tok}"
            );
            assert_eq!(
                band(&[hi.clone(), lo.clone()]),
                want,
                "I2058 Inv_TieLowestIdWins: other order, lower id {lo_tok}"
            );
            // Inv_NewestStands: the higher-id row one second LATER wins.
            let mut newer = hi.clone();
            newer.asserted_at = t0 + chrono::Duration::seconds(1);
            let want_newer = if hi_tok == minor {
                AgeBand::Minor
            } else {
                AgeBand::Adult
            };
            assert_eq!(
                band(&[lo, newer]),
                want_newer,
                "I2058 Inv_NewestStands: a newer row beats a lower id"
            );
        }
        // The self rung: the subject's two declarations at one instant.
        let sm = row(
            "0001",
            "t",
            "t",
            "age_self_declared:band:minor:v1",
            t0,
            None,
        );
        let sa = row(
            "0002",
            "t",
            "t",
            "age_self_declared:band:adult:v1",
            t0,
            None,
        );
        assert_eq!(
            band(&[sa.clone(), sm.clone()]),
            AgeBand::Minor,
            "I2058: self, minor id lower"
        );
        let sm2 = row(
            "0002",
            "t",
            "t",
            "age_self_declared:band:minor:v1",
            t0,
            None,
        );
        let sa2 = row(
            "0001",
            "t",
            "t",
            "age_self_declared:band:adult:v1",
            t0,
            None,
        );
        assert_eq!(
            band(&[sm2, sa2]),
            AgeBand::Unknown,
            "I2058: self, adult id lower: the self adult is current and raises nothing"
        );
    }
}
