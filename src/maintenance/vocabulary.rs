//! v25.1.0 (CIRISPersist#582) — **vocabulary tightening**: the reusable
//! one-time maintenance sweep that retires a non-conformant wire identifier
//! from stored attestations by SUPERSEDING the rows that carry it.
//!
//! # Why this is a primitive and not a script
//!
//! A ratification body periodically tightens a wire vocabulary: two spellings
//! of one construction collapse to one, a free-form string becomes a closed
//! enum, a version suffix is pinned. Every such tightening asks the substrate
//! the same three questions —
//!
//! 1. which stored rows carry the value that is no longer conformant?
//! 2. how is a signed row corrected without desyncing it from its signature?
//! 3. how does a second run know the first one already happened?
//!
//! …so the answer is written once, here, and each tightening is a
//! [`VocabularyTightening`] value passed to [`run_vocabulary_tightening`].
//! CC 5.1's snake_case key-grant identifier
//! ([`VocabularyTightening::key_grant_algorithm_v2`], CIRISVerify#234) is the
//! FIRST CALLER, not the feature.
//!
//! # SUPERSEDE, never UPDATE
//!
//! Stored attestations are signed over their canonical envelope bytes.
//! Rewriting a field in place would leave a row whose stored signature no
//! longer covers its stored content — the *preserve-set ≠ verified-set* class
//! this repo has already paid for (CIRISPersist#541). So a tightening never
//! mutates. For each affected row it emits **two** freshly-signed rows:
//!
//! 1. a **replacement** — the identical attestation with the one field
//!    tightened, re-canonicalized and re-signed, and
//! 2. a **`supersedes` composer** ([`attestation_type::SUPERSEDES`]) naming
//!    the original via `references_attestation_id`.
//!
//! The original row **survives, superseded, auditable** — CEG §6.1 precedence
//! (see [`crate::federation::precedence`]) makes the replacement the
//! consumer-visible head. No fourth retirement primitive is invented beside
//! `supersedes` / `withdraws` / `recants`.
//!
//! # CC 5.1 — exact match, NEVER normalize
//!
//! [`VocabularyTightening::non_conformant`] is compared to the stored value by
//! **byte equality**. The sweep does not fold separators, case, or whitespace
//! before comparing. For the key-grant identifier specifically, folding
//! `-` → `_` would make `x25519-mlkem768-…` and `x25519_mlkem768_…` compare
//! equal — which is precisely the ambiguity CC 5.1's single-identifier rule
//! exists to remove. Two distinct wire identifiers must stay distinct right up
//! to the moment one of them is superseded.
//!
//! # Fail-secure
//!
//! Anything ambiguous is **skipped and reported**, never guessed at. A row
//! attested by a key this node does not hold is not ours to supersede
//! ([`TighteningSkip::ForeignAttester`]); a row already retired by an existing
//! composer is left alone ([`TighteningSkip::AlreadyRetired`]); a row whose
//! envelope cannot be re-canonicalized is never re-signed
//! ([`TighteningSkip::EnvelopeNotTightenable`]). Every skip carries its reason
//! into the report.
//!
//! # Report, never silent
//!
//! [`run_vocabulary_tightening`] always returns a
//! [`VocabularyTighteningReport`] — a run that changed nothing is
//! distinguishable from a run that never happened, because the report carries
//! `started_at`, `examined`, and the per-reason skip histogram even when
//! `superseded == 0`. (The withhold-ledger inversion, CIRISEdge#433: silence
//! is not evidence of a no-op.)

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::federation::types::attestation_type;

/// Rows pulled per [`crate::federation::FederationDirectory::list_attestations_since`]
/// page during the scan.
const SCAN_PAGE: u32 = 2_000;

// ─── the target ────────────────────────────────────────────────────────────

/// Which `attestation_type`s a tightening looks at.
///
/// A tightening is scoped so a sweep cannot reach further than the
/// ratification that motivated it. [`Self::Any`] exists for genuinely
/// cross-family identifiers and should be paired with a narrow
/// [`VocabularyTightening::field_path`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum TighteningFamily {
    /// Exactly this `attestation_type`.
    Exact(String),
    /// Every `attestation_type` starting with this prefix (e.g. `"consent:"`).
    Prefix(String),
    /// Every `attestation_type`.
    Any,
}

impl TighteningFamily {
    /// Does `attestation_type` fall inside this family? Exact string
    /// comparison; no normalization (see the module's CC 5.1 note).
    #[must_use]
    pub fn matches(&self, attestation_type: &str) -> bool {
        match self {
            Self::Exact(t) => attestation_type == t,
            Self::Prefix(p) => attestation_type.starts_with(p.as_str()),
            Self::Any => true,
        }
    }

    /// Stable token for the report.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Exact(t) => format!("exact:{t}"),
            Self::Prefix(p) => format!("prefix:{p}"),
            Self::Any => "any".to_string(),
        }
    }
}

/// One vocabulary tightening: a single non-conformant value at a single
/// envelope field, over a single attestation family, and the conformant
/// replacement that retires it.
///
/// Construct with [`Self::new`] (validated) or with a named first-caller
/// constructor such as [`Self::key_grant_algorithm_v2`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabularyTightening {
    /// Stable identifier for this tightening — recorded in the emitted
    /// `supersedes` envelope and echoed in the report, so an auditor can ask
    /// "which ratification retired this row?" and get an answer from the row
    /// itself.
    pub tightening_id: String,
    /// The governing citation (e.g. `"CC 5.1 / CIRISVerify#234"`). Recorded
    /// alongside `tightening_id`.
    pub citation: String,
    /// Which `attestation_type`s to examine.
    pub family: TighteningFamily,
    /// Dot-separated path to the field inside the attestation envelope
    /// (e.g. `"wrap_algorithm"` or `"payload.wrap_algorithm"`). Every segment
    /// but the last must resolve to a JSON object.
    pub field_path: String,
    /// The value that is no longer conformant. Compared by **exact byte
    /// equality** — never normalized (CC 5.1).
    pub non_conformant: String,
    /// The conformant value the replacement row carries.
    pub conformant: String,
}

impl VocabularyTightening {
    /// Build a validated tightening.
    ///
    /// Rejects an empty `field_path` / `non_conformant` / `conformant`, and
    /// rejects `non_conformant == conformant` (a tightening that changes
    /// nothing would supersede every matching row with an identical copy of
    /// itself, forever).
    pub fn new(
        tightening_id: impl Into<String>,
        citation: impl Into<String>,
        family: TighteningFamily,
        field_path: impl Into<String>,
        non_conformant: impl Into<String>,
        conformant: impl Into<String>,
    ) -> Result<Self, super::Error> {
        let t = Self {
            tightening_id: tightening_id.into(),
            citation: citation.into(),
            family,
            field_path: field_path.into(),
            non_conformant: non_conformant.into(),
            conformant: conformant.into(),
        };
        t.validate()?;
        Ok(t)
    }

    /// **THE FIRST CALLER** (CC 5.1, CIRISVerify#234): the key-grant v2
    /// algorithm identifier, hyphenated → snake_case.
    ///
    /// The two values are taken from `ciris_crypto::key_grant` itself
    /// (`KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED` →
    /// `KEY_GRANT_ALGORITHM_V2`) rather than spelled here, so persist can
    /// never disagree with verify about what either form is. The caller
    /// supplies `field_path` / `family` because the substrate knows the
    /// *values*, while the deployment knows *where its producers put them*.
    ///
    /// The hyphenated form is a non-conformant alias that MUST NOT be
    /// normalized before comparison — this sweep compares exactly, and
    /// retires rather than rewrites.
    #[must_use]
    pub fn key_grant_algorithm_v2(field_path: impl Into<String>, family: TighteningFamily) -> Self {
        Self {
            tightening_id: "cc-5.1-key-grant-algorithm-v2-snake-case".to_string(),
            citation: "CC 5.1 (class rule CC 3.3.2) / CIRISVerify#234".to_string(),
            family,
            field_path: field_path.into(),
            non_conformant: ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED
                .to_string(),
            conformant: ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2.to_string(),
        }
    }

    /// Reject a target that cannot describe a real tightening.
    pub fn validate(&self) -> Result<(), super::Error> {
        let bad = |m: String| Err(super::Error::InvalidArgument(m));
        if self.tightening_id.trim().is_empty() {
            return bad("vocabulary tightening needs a non-empty tightening_id".into());
        }
        if self.field_path.trim().is_empty() {
            return bad("vocabulary tightening needs a non-empty field_path".into());
        }
        if self.field_path.split('.').any(|s| s.is_empty()) {
            return bad(format!(
                "field_path {:?} has an empty segment (expected `a` or `a.b.c`)",
                self.field_path
            ));
        }
        if self.non_conformant.is_empty() || self.conformant.is_empty() {
            return bad(
                "vocabulary tightening needs both a non_conformant and a conformant value".into(),
            );
        }
        if self.non_conformant == self.conformant {
            return bad(format!(
                "non_conformant and conformant are the same value {:?} — a tightening that \
                 changes nothing would supersede every matching row with a copy of itself",
                self.conformant
            ));
        }
        Ok(())
    }

    fn segments(&self) -> Vec<&str> {
        self.field_path.split('.').collect()
    }

    /// Read the targeted field out of `envelope`, if it is present AND a JSON
    /// string. `None` means "this row is not a candidate" — a missing path, a
    /// non-object on the way down, or a non-string leaf are all simply not the
    /// thing this tightening retires.
    fn read_field<'a>(&self, envelope: &'a serde_json::Value) -> Option<&'a str> {
        let segs = self.segments();
        let (last, parents) = segs.split_last()?;
        let mut cur = envelope;
        for p in parents {
            cur = cur.as_object()?.get(*p)?;
        }
        cur.as_object()?.get(*last)?.as_str()
    }

    /// Does this row carry the non-conformant value at the targeted field?
    /// **Exact byte equality** — see the module's CC 5.1 note.
    fn is_candidate(&self, attestation_type: &str, envelope: &serde_json::Value) -> bool {
        self.family.matches(attestation_type)
            && self.read_field(envelope) == Some(self.non_conformant.as_str())
    }

    /// The tightened envelope: `envelope` with the targeted field set to
    /// [`Self::conformant`] and every other byte untouched. Returns `None` if
    /// the path is not traversable (fail-secure: never fabricate structure).
    fn tighten_envelope(&self, envelope: &serde_json::Value) -> Option<serde_json::Value> {
        let segs = self.segments();
        let (last, parents) = segs.split_last()?;
        let mut out = envelope.clone();
        {
            let mut cur = out.as_object_mut()?;
            for p in parents {
                cur = cur.get_mut(*p)?.as_object_mut()?;
            }
            let slot = cur.get_mut(*last)?;
            if !slot.is_string() {
                return None;
            }
            *slot = serde_json::Value::String(self.conformant.clone());
        }
        Some(out)
    }
}

// ─── the report ────────────────────────────────────────────────────────────

/// Why a matching row was NOT superseded. Every variant is a deliberate
/// fail-secure refusal, not a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TighteningSkip {
    /// The row is attested by a key this node does not sign for. A
    /// `supersedes` from a different attester opens a SECOND CEG §6.1 chain
    /// rather than retiring the row (rule 4: cross-attester chains compose
    /// independently), so the substrate refuses to speak for someone else.
    ForeignAttester,
    /// An existing `supersedes` / `withdraws` / `recants` already names this
    /// row. **This is the idempotence hinge**: after the first run the
    /// original still carries the non-conformant value (it must — it is
    /// signed), so it still MATCHES; it is the composer emitted by the first
    /// run that keeps the second run from acting.
    AlreadyRetired,
    /// The row is itself a structural composer. Superseding a `supersedes` is
    /// ambiguous under CEG §6.1 precedence — refused.
    StructuralComposer,
    /// The row is not federation-tier, so the federation-tier emit path cannot
    /// produce a like-for-like replacement.
    NonFederationTier,
    /// The envelope could not be tightened or re-canonicalized (non-traversable
    /// path, non-object envelope, produce-gate rejection). Never re-signed on a
    /// guess.
    EnvelopeNotTightenable,
    /// The replacement row was refused by the write path (admission gate,
    /// backend error). The original is untouched and stays live.
    ReplacementRefused,
    /// The replacement landed but the `supersedes` composer was refused. The
    /// corpus is left with both rows live; a re-run resumes and emits only the
    /// missing composer (the replacement is detected by content, not re-emitted).
    SupersedeRefused,
}

impl TighteningSkip {
    /// Stable token used as the [`VocabularyTighteningReport::skipped_by_reason`]
    /// key and in structured logs.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::ForeignAttester => "foreign_attester",
            Self::AlreadyRetired => "already_retired",
            Self::StructuralComposer => "structural_composer",
            Self::NonFederationTier => "non_federation_tier",
            Self::EnvelopeNotTightenable => "envelope_not_tightenable",
            Self::ReplacementRefused => "replacement_refused",
            Self::SupersedeRefused => "supersede_refused",
        }
    }
}

/// What the sweep did to (or refused to do to) one matching row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum TighteningOutcome {
    /// Retired: `replacement_attestation_id` carries the conformant value and
    /// `supersedes_attestation_id` names the original.
    Superseded {
        /// The freshly-signed row carrying the conformant value.
        replacement_attestation_id: String,
        /// The `supersedes` composer naming the original.
        supersedes_attestation_id: String,
        /// `true` when a conformant replacement already existed (a previous
        /// run's replacement landed but its composer did not) and only the
        /// missing composer was emitted this run.
        resumed: bool,
    },
    /// Would be retired, but `dry_run` was set — nothing was written.
    Planned,
    /// Refused. See [`TighteningSkip`].
    Skipped {
        /// Why.
        reason: TighteningSkip,
        /// Free-form context (backend message, path detail). Never `None` for
        /// the `*_refused` reasons.
        detail: Option<String>,
    },
}

/// Per-row line item of a sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TighteningAction {
    /// The stored row carrying the non-conformant value.
    pub attestation_id: String,
    /// Its `attestation_type` (so a report is readable without a second query).
    pub attestation_type: String,
    /// What happened.
    pub outcome: TighteningOutcome,
}

/// v25.1.0 (CIRISPersist#582) — result of one
/// [`run_vocabulary_tightening`] pass. Mirrors the
/// [`MaintenanceReport`](super::types::MaintenanceReport) idiom: a plain serde
/// struct that crosses the PyO3 FFI as a JSON string, with per-phase counts
/// and wall-clock framing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabularyTighteningReport {
    /// Echo of [`VocabularyTightening::tightening_id`].
    pub tightening_id: String,
    /// Echo of [`VocabularyTightening::citation`].
    pub citation: String,
    /// Echo of [`TighteningFamily::describe`].
    pub family: String,
    /// Echo of [`VocabularyTightening::field_path`].
    pub field_path: String,
    /// Echo of [`VocabularyTightening::non_conformant`].
    pub non_conformant: String,
    /// Echo of [`VocabularyTightening::conformant`].
    pub conformant: String,
    /// The key the sweep signs as — the only attester whose rows it may retire.
    pub attester_key_id: String,
    /// `true` when the sweep examined and planned but wrote nothing.
    pub dry_run: bool,
    /// Federation-tier attestation rows scanned.
    pub examined: usize,
    /// Rows in-family carrying the non-conformant value at `field_path`.
    /// **Stays non-zero after a successful sweep** — the superseded original
    /// keeps its bytes (it is signed), so `matched > 0` with `superseded == 0`
    /// and `already_retired == matched` is the steady state.
    pub matched: usize,
    /// `supersedes` composers emitted this run.
    pub superseded: usize,
    /// Replacement rows emitted this run (equals `superseded` except on a
    /// resumed run, where a replacement already existed).
    pub replacements_emitted: usize,
    /// Matching rows deliberately left alone.
    pub skipped: usize,
    /// Skip histogram keyed by [`TighteningSkip::token`]. Present (empty) even
    /// when nothing was skipped, so a zero is a stated zero.
    pub skipped_by_reason: BTreeMap<String, usize>,
    /// One line per matching row.
    pub actions: Vec<TighteningAction>,
    /// `false` when the scan could not page past a single visibility
    /// timestamp shared by more than [`SCAN_PAGE`] rows — the report then
    /// covers a prefix of the corpus and says so rather than claiming
    /// completeness.
    pub scan_complete: bool,
    /// Wall-clock start of the sweep.
    pub started_at: DateTime<Utc>,
    /// Wall-clock elapsed time, in milliseconds.
    pub elapsed_ms: u32,
}

impl VocabularyTighteningReport {
    /// Did this run write anything? A `false` here on a corpus that still has
    /// `matched > 0` is the idempotent steady state, NOT a silent failure —
    /// check [`Self::skipped_by_reason`] for the reasons.
    #[must_use]
    pub fn wrote_nothing(&self) -> bool {
        self.superseded == 0 && self.replacements_emitted == 0
    }

    /// Count for one skip reason (0 when absent).
    #[must_use]
    pub fn skipped_count(&self, reason: TighteningSkip) -> usize {
        self.skipped_by_reason
            .get(reason.token())
            .copied()
            .unwrap_or(0)
    }
}

// ─── the sweep ─────────────────────────────────────────────────────────────

fn visible_at(a: &crate::federation::Attestation) -> DateTime<Utc> {
    a.promoted_at.unwrap_or(a.asserted_at)
}

/// Build the `supersedes` composer envelope for one retired row. Carries the
/// tightening provenance so the retirement explains itself from the row.
fn supersedes_envelope(
    target: &VocabularyTightening,
    original_attestation_id: &str,
    replacement_attestation_id: &str,
) -> crate::federation::envelope::EnvelopeCore {
    let mut extra = serde_json::Map::new();
    extra.insert(
        "vocabulary_tightening_id".to_string(),
        serde_json::Value::String(target.tightening_id.clone()),
    );
    extra.insert(
        "vocabulary_tightening_citation".to_string(),
        serde_json::Value::String(target.citation.clone()),
    );
    extra.insert(
        "tightened_field_path".to_string(),
        serde_json::Value::String(target.field_path.clone()),
    );
    extra.insert(
        "tightened_from".to_string(),
        serde_json::Value::String(target.non_conformant.clone()),
    );
    extra.insert(
        "tightened_to".to_string(),
        serde_json::Value::String(target.conformant.clone()),
    );
    extra.insert(
        "replacement_attestation_id".to_string(),
        serde_json::Value::String(replacement_attestation_id.to_string()),
    );
    crate::federation::envelope::EnvelopeCore {
        references_attestation_id: Some(original_attestation_id.to_string()),
        withdrawal_reason: Some(format!(
            "vocabulary tightening {} ({}): {:?} is non-conformant at {}",
            target.tightening_id, target.citation, target.non_conformant, target.field_path
        )),
        extra,
        ..Default::default()
    }
}

/// v25.1.0 (CIRISPersist#582) — run one vocabulary tightening over the
/// federation-tier attestation corpus.
///
/// Backend-generic (`memory` / `sqlite` / `postgres` all satisfy
/// [`FederationDirectory`](crate::federation::FederationDirectory)) and
/// **emitter-generic**: `emit` is the caller's real signed-emit path, so this
/// sweep never hand-rolls the canonicalize → sign → assemble → put recipe and
/// cannot drift from it. [`crate::Engine::tighten_vocabulary`] passes
/// [`crate::Engine::emit_attestation_self`].
///
/// `attester_key_id` is the DERIVED federation key_id the emitter signs as —
/// the sweep only retires rows attested by that key (see
/// [`TighteningSkip::ForeignAttester`]).
///
/// With `dry_run = true` the sweep examines and classifies but writes nothing;
/// every row that would be retired is reported as
/// [`TighteningOutcome::Planned`].
///
/// # Idempotence
///
/// A second run over an already-tightened corpus emits nothing: the first
/// run's `supersedes` composer puts every original into
/// [`TighteningSkip::AlreadyRetired`], and the conformant replacement does not
/// match the non-conformant value at all. See
/// [`VocabularyTighteningReport::wrote_nothing`].
pub async fn run_vocabulary_tightening<D, E, Fut>(
    dir: &D,
    attester_key_id: &str,
    target: &VocabularyTightening,
    dry_run: bool,
    mut emit: E,
) -> Result<VocabularyTighteningReport, super::Error>
where
    D: crate::federation::FederationDirectory + Sync + ?Sized,
    E: FnMut(crate::federation::EmitAttestationInput) -> Fut,
    Fut: std::future::Future<Output = Result<String, crate::federation::Error>>,
{
    target.validate()?;
    let started_at = Utc::now();
    let t0 = std::time::Instant::now();

    // ── scan ──────────────────────────────────────────────────────────────
    let mut rows: Vec<crate::federation::Attestation> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cursor: Option<DateTime<Utc>> = None;
    let mut scan_complete = true;
    loop {
        let page = dir
            .list_attestations_since(cursor, SCAN_PAGE)
            .await
            .map_err(|e| super::Error::Backend(format!("vocabulary tightening scan: {e}")))?;
        if page.is_empty() {
            break;
        }
        let full = page.len() as u32 >= SCAN_PAGE;
        let last_visible = visible_at(page.last().expect("non-empty page"));
        // The cursor is a TIMESTAMP and the filter is strict `>`, so advancing
        // it to the page's last visibility timestamp would silently skip any
        // row sharing that timestamp that the page's `limit` truncated away.
        // Advance instead to the last timestamp BOUNDARY strictly below it:
        // the trailing group is re-read next page and deduped by `seen`, and
        // no row can fall between two pages.
        let boundary = page
            .iter()
            .map(visible_at)
            .filter(|t| *t < last_visible)
            .max();
        for a in page {
            if seen.insert(a.attestation_id.clone()) {
                rows.push(a);
            }
        }
        if !full {
            break;
        }
        match boundary {
            // Strictly greater than the old cursor (every page row is), so the
            // loop always makes progress.
            Some(b) => cursor = Some(b),
            // A full page whose rows ALL share one visibility timestamp: there
            // may be more at that timestamp than a page can carry, and no
            // cursor value can reach them without skipping some. Stop rather
            // than spin or lie — the report SAYS the scan covered a prefix.
            None => {
                scan_complete = false;
                break;
            }
        }
    }

    // Every upstream id already named by ANY structural composer. A row named
    // by someone else's `withdraws` is still retired — re-tightening it would
    // resurrect content the graph has already retired.
    let mut retired: HashSet<&str> = HashSet::new();
    for a in &rows {
        if crate::federation::precedence::is_structural_composer(&a.attestation_type) {
            if let Some(up) = crate::federation::precedence::references_attestation_id_from_envelope(
                &a.attestation_envelope,
            ) {
                retired.insert(up);
            }
        }
    }

    let mut report = VocabularyTighteningReport {
        tightening_id: target.tightening_id.clone(),
        citation: target.citation.clone(),
        family: target.family.describe(),
        field_path: target.field_path.clone(),
        non_conformant: target.non_conformant.clone(),
        conformant: target.conformant.clone(),
        attester_key_id: attester_key_id.to_string(),
        dry_run,
        examined: rows.len(),
        matched: 0,
        superseded: 0,
        replacements_emitted: 0,
        skipped: 0,
        skipped_by_reason: BTreeMap::new(),
        actions: Vec::new(),
        scan_complete,
        started_at,
        elapsed_ms: 0,
    };

    // Classify first so the borrow of `rows` ends before we emit.
    enum Plan {
        Skip(TighteningSkip, Option<String>),
        Tighten {
            tightened: serde_json::Value,
            /// A conformant replacement already exists (previous run's
            /// composer never landed) — emit only the missing composer.
            existing_replacement: Option<String>,
        },
    }
    let mut planned: Vec<(crate::federation::Attestation, Plan)> = Vec::new();

    for row in &rows {
        if !target.is_candidate(&row.attestation_type, &row.attestation_envelope) {
            continue;
        }
        report.matched += 1;

        let plan = if crate::federation::precedence::is_structural_composer(&row.attestation_type) {
            Plan::Skip(TighteningSkip::StructuralComposer, None)
        } else if row.attesting_key_id != attester_key_id {
            Plan::Skip(
                TighteningSkip::ForeignAttester,
                Some(format!(
                    "attested by {:?}; this node signs as {attester_key_id:?}",
                    row.attesting_key_id
                )),
            )
        } else if row.tier != crate::federation::types::attestation_tier::FEDERATION {
            Plan::Skip(
                TighteningSkip::NonFederationTier,
                Some(format!("tier={:?}", row.tier)),
            )
        } else if retired.contains(row.attestation_id.as_str()) {
            Plan::Skip(TighteningSkip::AlreadyRetired, None)
        } else {
            match target.tighten_envelope(&row.attestation_envelope) {
                None => Plan::Skip(
                    TighteningSkip::EnvelopeNotTightenable,
                    Some(format!(
                        "field_path {:?} not traversable",
                        target.field_path
                    )),
                ),
                Some(tightened) => {
                    // Resume detection by CONTENT, not by a marker field: a
                    // replacement is a row from the same attester, same type,
                    // same subject and scope, whose envelope is byte-identical
                    // to the tightened envelope. No envelope pollution, and it
                    // cannot be faked by a coincidental id.
                    let existing_replacement = rows
                        .iter()
                        .find(|c| {
                            c.attestation_id != row.attestation_id
                                && c.attesting_key_id == row.attesting_key_id
                                && c.attested_key_id == row.attested_key_id
                                && c.attestation_type == row.attestation_type
                                && c.cohort_scope == row.cohort_scope
                                && c.attestation_envelope == tightened
                        })
                        .map(|c| c.attestation_id.clone());
                    Plan::Tighten {
                        tightened,
                        existing_replacement,
                    }
                }
            }
        };
        planned.push((row.clone(), plan));
    }
    drop(rows);

    // ── act ───────────────────────────────────────────────────────────────
    for (row, plan) in planned {
        match plan {
            Plan::Skip(reason, detail) => {
                record_skip(&mut report, &row, reason, detail);
            }
            Plan::Tighten {
                tightened,
                existing_replacement,
            } => {
                if dry_run {
                    report.actions.push(TighteningAction {
                        attestation_id: row.attestation_id.clone(),
                        attestation_type: row.attestation_type.clone(),
                        outcome: TighteningOutcome::Planned,
                    });
                    continue;
                }

                // 1. the replacement (skipped when a prior run already landed it)
                let (replacement_id, resumed) = match existing_replacement {
                    Some(id) => (id, true),
                    None => {
                        let envelope = match crate::federation::envelope::EnvelopeCore::from_value(
                            tightened,
                        ) {
                            Ok(e) => e,
                            Err(e) => {
                                record_skip(
                                    &mut report,
                                    &row,
                                    TighteningSkip::EnvelopeNotTightenable,
                                    Some(e.to_string()),
                                );
                                continue;
                            }
                        };
                        let mut input = crate::federation::EmitAttestationInput::with_envelope(
                            row.attestation_type.clone(),
                            envelope,
                            row.cohort_scope.clone(),
                        );
                        input.attested_key_id = Some(row.attested_key_id.clone());
                        input.subject_key_ids = row.subject_key_ids.clone();
                        input.expires_at = row.expires_at;
                        input.weight = row.weight;
                        match emit(input).await {
                            Ok(id) => {
                                report.replacements_emitted += 1;
                                (id, false)
                            }
                            Err(e) => {
                                record_skip(
                                    &mut report,
                                    &row,
                                    TighteningSkip::ReplacementRefused,
                                    Some(e.to_string()),
                                );
                                continue;
                            }
                        }
                    }
                };

                // 2. the `supersedes` composer naming the original
                let composer = crate::federation::EmitAttestationInput::with_envelope(
                    attestation_type::SUPERSEDES,
                    supersedes_envelope(target, &row.attestation_id, &replacement_id),
                    row.cohort_scope.clone(),
                );
                match emit(composer).await {
                    Ok(supersedes_id) => {
                        report.superseded += 1;
                        report.actions.push(TighteningAction {
                            attestation_id: row.attestation_id.clone(),
                            attestation_type: row.attestation_type.clone(),
                            outcome: TighteningOutcome::Superseded {
                                replacement_attestation_id: replacement_id,
                                supersedes_attestation_id: supersedes_id,
                                resumed,
                            },
                        });
                    }
                    Err(e) => {
                        record_skip(
                            &mut report,
                            &row,
                            TighteningSkip::SupersedeRefused,
                            Some(e.to_string()),
                        );
                    }
                }
            }
        }
    }

    report.elapsed_ms = u32::try_from(t0.elapsed().as_millis()).unwrap_or(u32::MAX);
    Ok(report)
}

fn record_skip(
    report: &mut VocabularyTighteningReport,
    row: &crate::federation::Attestation,
    reason: TighteningSkip,
    detail: Option<String>,
) {
    report.skipped += 1;
    *report
        .skipped_by_reason
        .entry(reason.token().to_string())
        .or_insert(0) += 1;
    report.actions.push(TighteningAction {
        attestation_id: row.attestation_id.clone(),
        attestation_type: row.attestation_type.clone(),
        outcome: TighteningOutcome::Skipped { reason, detail },
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> VocabularyTightening {
        VocabularyTightening::new(
            "t1",
            "CC x.y",
            TighteningFamily::Exact("scores".into()),
            "payload.wrap_algorithm",
            "a-b-c",
            "a_b_c",
        )
        .expect("valid")
    }

    #[test]
    fn family_matching_is_exact_or_prefix() {
        assert!(TighteningFamily::Exact("scores".into()).matches("scores"));
        assert!(!TighteningFamily::Exact("scores".into()).matches("scores:x"));
        assert!(TighteningFamily::Prefix("consent:".into()).matches("consent:replication:v1"));
        assert!(!TighteningFamily::Prefix("consent:".into()).matches("consentreplication"));
        assert!(TighteningFamily::Any.matches("anything"));
    }

    #[test]
    fn validate_rejects_degenerate_targets() {
        let bad = |fp: &str, from: &str, to: &str| {
            VocabularyTightening::new("t", "c", TighteningFamily::Any, fp, from, to).is_err()
        };
        assert!(bad("", "a", "b"), "empty field_path");
        assert!(bad("a..b", "a", "b"), "empty path segment");
        assert!(bad("f", "", "b"), "empty non_conformant");
        assert!(bad("f", "a", ""), "empty conformant");
        assert!(bad("f", "same", "same"), "no-op tightening");
    }

    /// **CC 5.1**: the hyphenated form is NON-CONFORMANT and MUST NOT be
    /// normalized before comparison. Folding `-` → `_` would make two distinct
    /// wire identifiers compare equal and defeat the single-identifier rule.
    #[test]
    fn comparison_is_exact_never_normalized() {
        let t = t();
        let env = |v: &str| serde_json::json!({"payload": {"wrap_algorithm": v}});
        assert!(t.is_candidate("scores", &env("a-b-c")));
        // The conformant form is NOT a candidate — nothing to do.
        assert!(!t.is_candidate("scores", &env("a_b_c")));
        // Case and whitespace are NOT folded either.
        assert!(!t.is_candidate("scores", &env("A-B-C")));
        assert!(!t.is_candidate("scores", &env(" a-b-c")));
        // Out of family.
        assert!(!t.is_candidate("delegates_to", &env("a-b-c")));
    }

    /// The PyO3 binding takes the target as JSON, so the wire shape IS the
    /// host contract — and the shape documented on
    /// `PyEngine::maintenance_tighten_vocabulary` must be the shape that
    /// actually decodes, or the capability is unreachable in practice
    /// (the AV-77 class, one level down).
    #[test]
    fn target_decodes_from_the_documented_ffi_json() {
        let json = serde_json::json!({
            "tightening_id": "cc-5.1-key-grant-algorithm-v2-snake-case",
            "citation": "CC 5.1 (class rule CC 3.3.2) / CIRISVerify#234",
            "family": {"kind": "prefix", "value": "key_grant:"},
            "field_path": "payload.wrap_algorithm",
            "non_conformant": "x25519-mlkem768-aes256-gcm-hkdf-sha256",
            "conformant": "x25519_mlkem768_aes256_gcm_hkdf_sha256",
        });
        let t: VocabularyTightening = serde_json::from_value(json).expect("documented shape");
        t.validate().expect("valid");
        assert_eq!(t.family, TighteningFamily::Prefix("key_grant:".into()));
        assert!(t.family.matches("key_grant:stream_epoch:v1"));

        // `any` carries no `value`, and `exact` round-trips.
        let any: TighteningFamily =
            serde_json::from_value(serde_json::json!({"kind": "any"})).expect("any");
        assert_eq!(any, TighteningFamily::Any);
        let exact = TighteningFamily::Exact("scores".into());
        assert_eq!(
            serde_json::to_value(&exact).unwrap(),
            serde_json::json!({"kind": "exact", "value": "scores"})
        );
    }

    #[test]
    fn reads_and_tightens_only_the_targeted_leaf() {
        let t = t();
        let env = serde_json::json!({
            "dimension": "d:v1",
            "payload": {"wrap_algorithm": "a-b-c", "other": "a-b-c"},
            "wrap_algorithm": "a-b-c",
        });
        assert_eq!(t.read_field(&env), Some("a-b-c"));
        let out = t.tighten_envelope(&env).expect("traversable");
        assert_eq!(out["payload"]["wrap_algorithm"], "a_b_c");
        // Sibling and top-level same-named fields are untouched — a tightening
        // rewrites ONE field, not every occurrence of a string.
        assert_eq!(out["payload"]["other"], "a-b-c");
        assert_eq!(out["wrap_algorithm"], "a-b-c");
        assert_eq!(out["dimension"], "d:v1");
    }

    #[test]
    fn non_traversable_paths_are_refused_not_fabricated() {
        let t = t();
        // Missing parent.
        assert!(t.tighten_envelope(&serde_json::json!({"x": 1})).is_none());
        // Parent is not an object.
        assert!(t
            .tighten_envelope(&serde_json::json!({"payload": 7}))
            .is_none());
        // Leaf is not a string.
        assert!(t
            .tighten_envelope(&serde_json::json!({"payload": {"wrap_algorithm": 7}}))
            .is_none());
        assert!(t
            .read_field(&serde_json::json!({"payload": {"wrap_algorithm": 7}}))
            .is_none());
    }

    #[test]
    fn skip_tokens_are_stable() {
        for (r, tok) in [
            (TighteningSkip::ForeignAttester, "foreign_attester"),
            (TighteningSkip::AlreadyRetired, "already_retired"),
            (TighteningSkip::StructuralComposer, "structural_composer"),
            (TighteningSkip::NonFederationTier, "non_federation_tier"),
            (
                TighteningSkip::EnvelopeNotTightenable,
                "envelope_not_tightenable",
            ),
            (TighteningSkip::ReplacementRefused, "replacement_refused"),
            (TighteningSkip::SupersedeRefused, "supersede_refused"),
        ] {
            assert_eq!(r.token(), tok);
        }
    }

    /// The FIRST CALLER takes both values from `ciris_crypto` so persist can
    /// never disagree with verify about either spelling — and the two forms
    /// differ only by separator, the exact shape a normalizing comparison
    /// would erase.
    #[test]
    fn key_grant_first_caller_pins_verifys_own_constants() {
        let t = VocabularyTightening::key_grant_algorithm_v2(
            "payload.wrap_algorithm",
            TighteningFamily::Any,
        );
        t.validate().expect("first caller is a valid tightening");
        assert_eq!(
            t.conformant,
            ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2
        );
        assert_eq!(
            t.non_conformant,
            ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED
        );
        assert!(!t.conformant.contains('-'), "CC 5.1 ratified snake_case");
        assert!(t.non_conformant.contains('-'));
        assert_eq!(
            t.non_conformant.replace('-', "_"),
            t.conformant,
            "the two forms differ ONLY by separator — which is exactly why the \
             sweep must never normalize before comparing"
        );
    }

    #[test]
    fn report_helpers_state_zeros_explicitly() {
        let r = VocabularyTighteningReport {
            tightening_id: "t".into(),
            citation: "c".into(),
            family: "any".into(),
            field_path: "f".into(),
            non_conformant: "a".into(),
            conformant: "b".into(),
            attester_key_id: "k".into(),
            dry_run: false,
            examined: 3,
            matched: 0,
            superseded: 0,
            replacements_emitted: 0,
            skipped: 0,
            skipped_by_reason: BTreeMap::new(),
            actions: Vec::new(),
            scan_complete: true,
            started_at: Utc::now(),
            elapsed_ms: 0,
        };
        assert!(r.wrote_nothing());
        assert_eq!(r.skipped_count(TighteningSkip::AlreadyRetired), 0);
        // A run that did nothing is still a RUN: it round-trips as JSON with
        // its framing intact, so a consumer can tell it from silence.
        let j: serde_json::Value = serde_json::to_value(&r).expect("serializes");
        assert_eq!(j["examined"], 3);
        assert!(j.get("started_at").is_some());
        assert!(j.get("skipped_by_reason").is_some());
    }
}

/// The end-to-end sweep, exercised on **every backend** through the same body.
///
/// The emitter is [`crate::federation::attestation_emit::emit_with_local_signer`]
/// — the real signed-emit recipe, the same one
/// [`crate::Engine::emit_attestation`] runs — so nothing here certifies a
/// path a host cannot reach (AV-77). A separate sqlite/postgres test drives
/// [`crate::Engine::tighten_vocabulary`] itself, closing the last inch.
#[cfg(test)]
mod sweep_tests {
    use super::*;
    use crate::federation::types::{attestation_type, cohort_scope};
    use crate::federation::FederationDirectory;

    const NON_CONFORMANT: &str = "x25519-mlkem768-aes256-gcm-hkdf-sha256";
    const CONFORMANT: &str = "x25519_mlkem768_aes256_gcm_hkdf_sha256";
    const FIELD: &str = "payload.wrap_algorithm";

    fn target() -> VocabularyTightening {
        VocabularyTightening::new(
            "cc-5.1-key-grant-algorithm-v2-snake-case",
            "CC 5.1 / CIRISVerify#234",
            TighteningFamily::Exact(attestation_type::SCORES.into()),
            FIELD,
            NON_CONFORMANT,
            CONFORMANT,
        )
        .expect("valid target")
    }

    /// A `federation_keys` row keyed by the signer's DERIVED id but carrying
    /// `alias`'s REAL deterministic hybrid pubkeys, so an emitted row both
    /// FK-resolves and hybrid-verifies at the ingest gate (the #247 floor).
    fn derived_key(derived: &str, alias: &str) -> crate::federation::SignedKeyRecord {
        let (ed_pk, mldsa_pk) = crate::federation::tier_ingest::test_support::hybrid_pubkeys(alias);
        crate::federation::SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: derived.into(),
                pubkey_ed25519_base64: ed_pk,
                pubkey_ml_dsa_65_base64: mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.into(),
                identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
                identity_ref: derived.into(),
                valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
                valid_until: None,
                registration_envelope: serde_json::json!({ "id": derived }),
                original_content_hash: "deadbeef".into(),
                scrub_signature_classical: "c2lnbmF0dXJl".into(),
                scrub_signature_pqc: None,
                scrub_key_id: derived.into(),
                scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        }
    }

    fn probe_input(id: &str, wrap_algorithm: &str) -> crate::federation::EmitAttestationInput {
        crate::federation::EmitAttestationInput::with_envelope(
            attestation_type::SCORES,
            crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
                "id": id,
                "dimension": "identity_binding:v1",
                "score": 1.0,
                "confidence": 0.9,
                "payload": {"wrap_algorithm": wrap_algorithm, "sibling": wrap_algorithm},
            }))
            .expect("envelope"),
            cohort_scope::FEDERATION,
        )
    }

    async fn all_rows<D>(dir: &D) -> Vec<crate::federation::Attestation>
    where
        D: FederationDirectory + Sync + ?Sized,
    {
        dir.list_attestations_since(None, 10_000)
            .await
            .expect("scan")
    }

    /// RED-FIRST, then green, then green-again:
    ///
    /// 1. witness the PRE-STATE — rows carrying the non-conformant value are
    ///    present and the sweep sees them,
    /// 2. run the sweep — supersedes exist, replacements carry the conformant
    ///    value, and **the old rows survive, superseded**,
    /// 3. re-run — zero written, and the report says why.
    async fn tighten_body<D>(
        dir: &D,
        signer: &crate::signing::LocalSigner,
        foreign: &crate::signing::LocalSigner,
        label: &str,
    ) where
        D: FederationDirectory + Sync + ?Sized,
    {
        let mine = signer.derived_key_id();
        let theirs = foreign.derived_key_id();
        dir.put_public_key(derived_key(&mine, &format!("vt-mine-{label}")))
            .await
            .expect("seed own key");
        dir.put_public_key(derived_key(&theirs, &format!("vt-theirs-{label}")))
            .await
            .expect("seed foreign key");

        // ── seed ──────────────────────────────────────────────────────────
        let a = crate::federation::attestation_emit::emit_with_local_signer(
            dir,
            signer,
            probe_input(&format!("vt-a-{label}"), NON_CONFORMANT),
        )
        .await
        .expect("seed a")
        .attestation_id;
        let b = crate::federation::attestation_emit::emit_with_local_signer(
            dir,
            signer,
            probe_input(&format!("vt-b-{label}"), NON_CONFORMANT),
        )
        .await
        .expect("seed b")
        .attestation_id;
        // Already conformant — must never be touched.
        let ok = crate::federation::attestation_emit::emit_with_local_signer(
            dir,
            signer,
            probe_input(&format!("vt-ok-{label}"), CONFORMANT),
        )
        .await
        .expect("seed ok")
        .attestation_id;
        // A row carrying the non-conformant value but attested by SOMEONE
        // ELSE. Not ours to supersede.
        let foreign_row = crate::federation::attestation_emit::emit_with_local_signer(
            dir,
            foreign,
            probe_input(&format!("vt-foreign-{label}"), NON_CONFORMANT),
        )
        .await
        .expect("seed foreign")
        .attestation_id;

        let target = target();
        let before = all_rows(dir).await.len();

        // ── (1) PRE-STATE: the non-conformant value really is at rest ─────
        let pre = all_rows(dir).await;
        let carriers: Vec<&str> = pre
            .iter()
            .filter(|r| target.is_candidate(&r.attestation_type, &r.attestation_envelope))
            .map(|r| r.attestation_id.as_str())
            .collect();
        assert_eq!(
            carriers.len(),
            3,
            "pre-state: a, b and the foreign row carry {NON_CONFORMANT:?}"
        );

        // A dry run must classify without writing a byte.
        let plan = run_vocabulary_tightening(dir, &mine, &target, true, |input| async move {
            crate::federation::attestation_emit::emit_with_local_signer(dir, signer, input)
                .await
                .map(|e| e.attestation_id)
        })
        .await
        .expect("dry run");
        assert!(plan.dry_run);
        assert_eq!(plan.matched, 3);
        assert_eq!(plan.superseded, 0, "a dry run writes nothing");
        assert_eq!(plan.replacements_emitted, 0);
        assert_eq!(
            plan.actions
                .iter()
                .filter(|a| matches!(a.outcome, TighteningOutcome::Planned))
                .count(),
            2,
            "two of ours are planned; the foreign row is not"
        );
        assert_eq!(
            all_rows(dir).await.len(),
            before,
            "dry run must not add a row"
        );

        // ── (2) the sweep ─────────────────────────────────────────────────
        let run1 = run_vocabulary_tightening(dir, &mine, &target, false, |input| async move {
            crate::federation::attestation_emit::emit_with_local_signer(dir, signer, input)
                .await
                .map(|e| e.attestation_id)
        })
        .await
        .expect("sweep");
        assert_eq!(run1.matched, 3);
        assert_eq!(run1.superseded, 2, "two of ours retired");
        assert_eq!(run1.replacements_emitted, 2);
        assert_eq!(run1.skipped, 1);
        assert_eq!(run1.skipped_count(TighteningSkip::ForeignAttester), 1);
        assert!(run1.scan_complete);
        assert!(!run1.wrote_nothing());

        // The ORIGINALS SURVIVE, byte-identical, still carrying the
        // non-conformant value — they are signed; rewriting them in place is
        // exactly what this primitive exists not to do.
        for id in [&a, &b] {
            let row = dir.get_attestation(id).await.unwrap().expect("original");
            assert_eq!(
                target.read_field(&row.attestation_envelope),
                Some(NON_CONFORMANT),
                "the superseded original keeps its own bytes"
            );
        }
        // The foreign row and the already-conformant row are untouched.
        assert!(dir.get_attestation(&foreign_row).await.unwrap().is_some());
        assert!(dir.get_attestation(&ok).await.unwrap().is_some());

        // Replacement + composer for each retired row.
        let mut retired: Vec<String> = Vec::new();
        for action in &run1.actions {
            if let TighteningOutcome::Superseded {
                replacement_attestation_id,
                supersedes_attestation_id,
                resumed,
            } = &action.outcome
            {
                assert!(!resumed, "first run emits its own replacement");
                retired.push(action.attestation_id.clone());
                let repl = dir
                    .get_attestation(replacement_attestation_id)
                    .await
                    .unwrap()
                    .expect("replacement row");
                assert_eq!(
                    target.read_field(&repl.attestation_envelope),
                    Some(CONFORMANT),
                    "the replacement carries the conformant value"
                );
                assert_eq!(
                    repl.attestation_envelope["payload"]["sibling"], NON_CONFORMANT,
                    "ONLY the targeted field moves — a tightening is not a find-and-replace"
                );
                assert_eq!(repl.attesting_key_id, mine);

                let comp = dir
                    .get_attestation(supersedes_attestation_id)
                    .await
                    .unwrap()
                    .expect("supersedes row");
                assert_eq!(comp.attestation_type, attestation_type::SUPERSEDES);
                assert_eq!(
                    crate::federation::precedence::references_attestation_id_from_envelope(
                        &comp.attestation_envelope
                    ),
                    Some(action.attestation_id.as_str()),
                    "the composer names the row it retires"
                );
                assert_eq!(
                    comp.attestation_envelope["vocabulary_tightening_id"],
                    target.tightening_id.as_str(),
                    "the retirement explains itself from the row"
                );
                assert_eq!(
                    comp.attestation_envelope["replacement_attestation_id"],
                    replacement_attestation_id.as_str()
                );
            }
        }
        retired.sort();
        let mut expected = vec![a.clone(), b.clone()];
        expected.sort();
        assert_eq!(retired, expected);

        // ── (3) IDEMPOTENCE: a second run writes nothing ──────────────────
        let after_run1 = all_rows(dir).await.len();
        assert_eq!(after_run1, before + 4, "2 replacements + 2 composers");

        let run2 = run_vocabulary_tightening(dir, &mine, &target, false, |input| async move {
            crate::federation::attestation_emit::emit_with_local_signer(dir, signer, input)
                .await
                .map(|e| e.attestation_id)
        })
        .await
        .expect("re-run");
        assert!(
            run2.wrote_nothing(),
            "a second run over an already-tightened corpus writes nothing: {run2:?}"
        );
        assert_eq!(run2.superseded, 0);
        assert_eq!(run2.replacements_emitted, 0);
        assert_eq!(
            all_rows(dir).await.len(),
            after_run1,
            "…and adds no row at all"
        );
        // …and it SAYS so. The originals still match (they keep their bytes);
        // what stops the second run is the composer the first one emitted.
        assert_eq!(run2.matched, 3, "the superseded originals still match");
        assert_eq!(run2.skipped_count(TighteningSkip::AlreadyRetired), 2);
        assert_eq!(run2.skipped_count(TighteningSkip::ForeignAttester), 1);
        assert!(
            run2.started_at >= run1.started_at,
            "a no-op run is still a RUN — it is framed and reportable, not silence"
        );
    }

    fn signers(
        label: &str,
    ) -> (
        std::sync::Arc<crate::signing::LocalSigner>,
        std::sync::Arc<crate::signing::LocalSigner>,
    ) {
        (
            crate::federation::tier_ingest::test_support::local_signer(&format!("vt-mine-{label}")),
            crate::federation::tier_ingest::test_support::local_signer(&format!(
                "vt-theirs-{label}"
            )),
        )
    }

    #[tokio::test]
    async fn tightening_supersedes_and_is_idempotent_memory() {
        let dir = crate::store::MemoryBackend::new();
        let (mine, theirs) = signers("mem");
        tighten_body(&dir, &mine, &theirs, "mem").await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn tightening_supersedes_and_is_idempotent_sqlite() {
        let (mine, theirs) = signers("sq");
        let engine = crate::Engine::with_signer(mine.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        tighten_body(&*sq, &mine, &theirs, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tightening_supersedes_and_is_idempotent_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let label = uuid::Uuid::new_v4().simple().to_string();
        let (mine, theirs) = signers(&label);
        let engine = crate::Engine::with_signer(mine.clone(), &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend").clone();
        tighten_body(&*pg, &mine, &theirs, &label).await;
    }

    /// **HOST-REACHABLE** (the AV-77 rule): the capability is not the free
    /// function, it is [`crate::Engine::tighten_vocabulary`] — what a host
    /// actually calls, signing with the engine's own composed signer. A
    /// feature no host can reach is not shipped.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn engine_entry_point_tightens_and_then_reports_zero() {
        let signer = crate::federation::tier_ingest::test_support::local_signer("vt-engine-host");
        let engine = crate::Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        let derived = engine.local_derived_key_id().await.expect("derived");
        sq.put_public_key(derived_key(&derived, "vt-engine-host"))
            .await
            .expect("seed key");

        let seeded = crate::federation::attestation_emit::emit_with_local_signer(
            &*sq,
            &signer,
            probe_input("vt-engine-host-1", NON_CONFORMANT),
        )
        .await
        .expect("seed")
        .attestation_id;

        let t = target();
        let r1 = engine
            .tighten_vocabulary(&t, false)
            .await
            .expect("engine sweep");
        assert_eq!(r1.superseded, 1);
        assert_eq!(r1.replacements_emitted, 1);
        assert_eq!(r1.attester_key_id, derived);

        // The original survives, superseded.
        let original = sq
            .get_attestation(&seeded)
            .await
            .unwrap()
            .expect("original");
        assert_eq!(
            t.read_field(&original.attestation_envelope),
            Some(NON_CONFORMANT)
        );

        let r2 = engine
            .tighten_vocabulary(&t, false)
            .await
            .expect("engine re-run");
        assert!(
            r2.wrote_nothing(),
            "idempotent through the host entry point"
        );
        assert_eq!(r2.skipped_count(TighteningSkip::AlreadyRetired), 1);
    }

    /// A tightening the substrate cannot express must be REFUSED, not
    /// approximated — `Error::InvalidArgument` reaches the caller as a
    /// permanent (MUST-NOT-retry) error through `translate_error_kind`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn engine_refuses_a_degenerate_target() {
        let signer = crate::federation::tier_ingest::test_support::local_signer("vt-engine-bad");
        let engine = crate::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let bogus = VocabularyTightening {
            tightening_id: "bogus".into(),
            citation: "none".into(),
            family: TighteningFamily::Any,
            field_path: "f".into(),
            non_conformant: "same".into(),
            conformant: "same".into(),
        };
        let err = engine
            .tighten_vocabulary(&bogus, true)
            .await
            .expect_err("a no-op tightening is refused");
        assert_eq!(err.kind(), "maintenance_invalid_argument");
    }
}
