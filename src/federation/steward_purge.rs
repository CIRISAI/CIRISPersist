//! v54.1.0 (CIRISPersist#1046, CIRISConstitution#165, CSD-108) — **the generic
//! steward purge door.**
//!
//! `evict_actor` / `evict_blob` (v3.5.0, v47.2.0) purge ONE plane — the bytes —
//! for one actor or one sha. This door extends that shape to any row
//! selection, authorised under GLOBAL TRUST-ROOT MODERATION, with an evidence
//! ledger. The constitutional reading is CIRISConstitution#165:
//!
//! 1. **Authorisation** is a cosigned `takedown_notice` (CC 3.3.2 shape) with
//!    the closed-set basis [`STEWARD_PURGE_BASIS`], `claimant_key_id` = the
//!    trust root's `community_key_id`, cosigned under that root's own
//!    `consensus_protocol`
//!    ([`trust_root_cosigners_over`](super::canonical_community::trust_root_cosigners_over)),
//!    naming the **selection digest**: SHA-256 over the JCS array of every
//!    purged record id, derived ids included, sorted ([`selection_digest`]).
//!    The door asks about the SIGNERS (their standing under the root's
//!    protocol) and binds the subject through the digest — never through a
//!    caller-supplied verdict. There is NO override path: a changed selection
//!    has a different digest, so the only way past a mismatch is a fresh
//!    dry-run and a fresh notice.
//! 2. **Execution** is a TOMBSTONE BY DIGEST per record, citing the notice —
//!    never a forged `withdraws` (the root is neither the author nor the
//!    subject; a purge says the row never belonged). A tombstoned record is
//!    refused at every admission door that could bring it back
//!    ([`token::TOMBSTONED`]) and is never served to a peer.
//! 3. **Replication**: the tombstone travels as a [`PurgeBundle`] — the notice,
//!    its WHOLE cosignature set and the record ids, never content — and the
//!    receiver re-verifies it against its OWN trust root and re-derives the
//!    digest ([`apply_replicated_purge`]).
//! 4. **Hard delete** happens only on the explicit second call
//!    [`purge_finalize`], after the settle dwell ([`PURGE_SETTLE_DWELL_SECS`]).
//!
//! Derived rows follow the reason: a `scores` row whose `evidence_refs`
//! resolve to a purged record (a trace id, a trace attestation id, an
//! attestation id) is in the SAME selection and ledger, transitively.
//!
//! The selection kinds are [`PurgeSelection`]: by actor, by explicit id
//! list, and the two classes the operator ruled on (#1040's mock-LLM traces,
//! #1043's rows the substrate would refuse to admit today). #1043's second
//! class (harness identities) was dropped by the operator's ruling: harness
//! rows on production stay, and Server selects by actor or by ids when it
//! needs a purge. A class is a pure row predicate
//! ([`PurgeSelection::selects_row`]) over ONE [`scan_attestations`] pass, plus
//! its seeds (an actor's traces, a model's traces); the derivation is
//! shared. A class like "rows of family F from issuer K in window W"
//! (CIRISServer#757's zero-scored `capacity:sustained_coherence:v1` rows) is
//! one more variant and one more predicate arm (dimension prefix, attester,
//! `asserted_at` window). It is NOT added here.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::types::{attestation_type, Attestation};
use super::{Error, FederationDirectory};

/// The closed set of refusal tokens this door raises, each the
/// [`Error::kind`] of an [`Error::PurgeRefused`].
pub mod token {
    /// The notice is absent, malformed, of another basis or kind, expired, or
    /// its cosigners do not meet the trust root's `consensus_protocol`
    /// (CIRISConstitution#165).
    pub const UNAUTHORISED: &str = "purge_unauthorised";
    /// The live selection's digest is not the one the notice names
    /// (CIRISConstitution#165). Body: `{expected, found}`.
    pub const SELECTION_DIGEST_MISMATCH: &str = "purge_selection_digest_mismatch";
    /// The live selection's count for a table is not the notice's
    /// (CIRISPersist#1046, CSD-108 §6 Q2). Body: `{table, expected, found}`.
    pub const SELECTION_COUNT_MISMATCH: &str = "purge_selection_count_mismatch";
    /// One record's retraction is not admissible; the door stopped there.
    /// Body: `{record_id, plane, index, total, reason}`. Everything before it
    /// stays retracted; a retry is idempotent.
    pub const RETRACTION_INADMISSIBLE: &str = "purge_retraction_inadmissible";
    /// `purge_finalize` before the retraction round settled. Body:
    /// `{notice_id, executed_at, settles_at}`.
    pub const NOT_SETTLED: &str = "purge_not_settled";
    /// `purge_finalize` / `purge_status` / ledger for a notice this node never
    /// executed or applied. Body: `{notice_id}`.
    pub const NOTICE_UNKNOWN: &str = "purge_notice_unknown";
    /// An admission door refused a record a steward purge tombstoned. Body:
    /// `{record_id, notice_id}`.
    pub const TOMBSTONED: &str = "purge_tombstoned";
    /// The selection or bundle itself is malformed (an unparseable record id,
    /// an unsorted or duplicated bundle id list). Body: `{reason}`.
    pub const SELECTION_MALFORMED: &str = "purge_selection_malformed";

    /// Every token, for the registry and the from-disk witnesses.
    pub const ALL: &[&str] = &[
        UNAUTHORISED,
        SELECTION_DIGEST_MISMATCH,
        SELECTION_COUNT_MISMATCH,
        RETRACTION_INADMISSIBLE,
        NOT_SETTLED,
        NOTICE_UNKNOWN,
        TOMBSTONED,
        SELECTION_MALFORMED,
    ];
}

/// The `takedown_notice` basis that authorises a steward purge (CC 3.3.2
/// `LegalBasis::StewardPurge`, CIRISConstitution rc8@9ce73e6).
pub const STEWARD_PURGE_BASIS: &str = "steward_purge";

/// The sample a dry run shows: the first N record ids in JCS order (CSD-108
/// §6 Q6). A VIEW of the ledger, which holds every id.
pub const SAMPLE_LEN: usize = 20;

/// How long after the tombstone the retraction round is taken as settled:
/// `W` = 72 h (259 200 s), the CC 2.6.7 / 4.2.6 "until everyone has heard"
/// constant (CIRISConstitution rc8@af6b436; operator-confirmed 2026-10-09).
/// NOT the 24 h lone-holder halt fuse, which is a different thing. There is
/// no peer-acknowledgement plane: settle is this stated dwell.
/// `purge_finalize` refuses before it ([`token::NOT_SETTLED`]). ONE named
/// constant, so a different ruling is a one-line change.
pub const PURGE_SETTLE_DWELL_SECS: i64 = 259_200;

/// The model id the agent's mock LLM reports (CIRISPersist#1040:
/// `ciris_adapters/mock_llm`). It is what identifies the mock traces already
/// held (they predate `run_kind`, CIRISAgent#1249), so the purge class keys
/// on it; ADMISSION keys on the signed `run_kind` ([`TRACE_RUN_KIND_MOCK`]).
pub const MOCK_LLM_MODEL: &str = "mock-model";

/// The page size of the attestation scan the selection classes resolve over.
const SCAN_PAGE: u32 = 256;

fn refused(token: &'static str, body: serde_json::Value) -> Error {
    Error::PurgeRefused { token, body }
}

// ── record ids ─────────────────────────────────────────────────────────────

/// The plane a purged record lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
///
/// There is NO key plane (operator ruling 2026-10-09: "We should not delete
/// any keys"; CC 2.4.1.1 at CIRISConstitution rc8@af6b436 — the root has no
/// path over a stranger's key). Deleting a key leaves every row it signed
/// unverifiable wherever it replicated; key retirement is `key:revocation`,
/// a separate act by the key's own authority.
pub enum PurgePlane {
    /// A `federation_attestations` row (the claims plane): traces' own
    /// `trace:complete:v1` attestations, scores, any claim. Id: the
    /// `attestation_id`.
    Attestation,
    /// A trace's node-local projection rows (`trace_events`,
    /// `trace_llm_calls`). Id: the `trace_id`.
    Trace,
    /// A `federation_blobs` row (the bytes plane). Id: the blob's sha256 hex.
    /// Hard-deleted through the bytes plane's own retract-then-delete
    /// (`Engine::evict_blob`, #1007's shape).
    Blob,
}

impl PurgePlane {
    /// Every plane, in finalize order.
    pub const ALL: [Self; 3] = [Self::Trace, Self::Attestation, Self::Blob];

    /// The wire spelling (the record id's prefix).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::Trace => "trace",
            Self::Blob => "blob",
        }
    }

    /// The table a count for this plane is reported against (CSD-108's
    /// `{table, expected, found}`). For [`Self::Trace`] the unit is a trace id
    /// (its `trace_events` / `trace_llm_calls` rows are reported beside it in
    /// [`PurgeDryRun::table_rows`]).
    #[must_use]
    pub const fn table(self) -> &'static str {
        match self {
            Self::Attestation => "federation_attestations",
            Self::Trace => "trace_events",
            Self::Blob => "federation_blobs",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "attestation" => Self::Attestation,
            "trace" => Self::Trace,
            "blob" => Self::Blob,
            _ => return None,
        })
    }
}

/// One purged record: its plane, its id on that plane, and (for a derived
/// record) the record id it follows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PurgeRecord {
    /// The plane.
    pub plane: PurgePlane,
    /// The id on that plane.
    pub id: String,
    /// The record id (`plane:id`) this record was selected through, when it
    /// is derived (a trace's own attestation, a score over purged evidence, a
    /// holder claim's bytes). Ledger-only: the digest is over ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,
}

impl PurgeRecord {
    /// The record id the digest and the tombstone carry: `"{plane}:{id}"`.
    #[must_use]
    pub fn record_id(&self) -> String {
        format!("{}:{}", self.plane.as_str(), self.id)
    }
}

/// Parse a `"{plane}:{id}"` record id.
///
/// # Errors
///
/// [`token::SELECTION_MALFORMED`] for an unknown plane (a key, by either
/// spelling, is refused by name: a purge never removes a key), an empty id,
/// or a malformed blob digest.
pub fn parse_record_id(record_id: &str) -> Result<PurgeRecord, Error> {
    let malformed = |why: &str| {
        refused(
            token::SELECTION_MALFORMED,
            serde_json::json!({"record_id": record_id, "reason": why}),
        )
    };
    let (plane, id) = record_id
        .split_once(':')
        .ok_or_else(|| malformed("a record id is \"{plane}:{id}\""))?;
    if matches!(plane, "key" | "federation_keys") {
        return Err(malformed(
            "a steward purge never deletes or tombstones a key (a deleted key leaves every row it \
             signed unverifiable); key retirement is key:revocation, a separate act by the key's \
             own authority",
        ));
    }
    let plane = PurgePlane::parse(plane).ok_or_else(|| malformed("unknown plane"))?;
    if id.is_empty() {
        return Err(malformed("empty id"));
    }
    if plane == PurgePlane::Blob
        && !(id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    {
        return Err(malformed("a blob id is 64 lowercase hex (its sha256)"));
    }
    Ok(PurgeRecord {
        plane,
        id: id.to_owned(),
        derived_from: None,
    })
}

/// **The selection digest** (CIRISConstitution#165 §1): SHA-256 over the JCS
/// serialization of the record ids as a sorted, de-duplicated JSON array of
/// strings, lowercase hex. The notice names exactly this; the ledger re-derives
/// it.
#[must_use]
pub fn selection_digest<S: AsRef<str>>(record_ids: &[S]) -> String {
    let sorted: BTreeSet<&str> = record_ids.iter().map(AsRef::as_ref).collect();
    let array = serde_json::Value::Array(
        sorted
            .into_iter()
            .map(|s| serde_json::Value::String(s.to_owned()))
            .collect(),
    );
    let bytes = ciris_verify_core::jcs::canonicalize(&array)
        .expect("a JSON array of strings always canonicalizes");
    hex::encode(sha2::Sha256::digest(bytes))
}

// ── selections ─────────────────────────────────────────────────────────────

/// What to purge. Serialized with a `kind` tag (the pyo3 / HTTP shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PurgeSelection {
    /// Every row `key_id` AUTHORED (`attesting_key_id`), every trace it
    /// signed, the bytes its `holds_bytes` claims name, and everything
    /// derived. NEVER its key, and never a row another key signed about it
    /// (operator ruling 2026-10-09). CSD-065 Descend moves onto this.
    ByActor {
        /// The actor's `key_id`.
        key_id: String,
    },
    /// An explicit `"{plane}:{id}"` list. Nothing is derived and nothing is
    /// withheld: a record whose retraction is inadmissible is refused AT THE
    /// DOOR ([`token::RETRACTION_INADMISSIBLE`]).
    ByIds {
        /// The record ids.
        ids: Vec<String>,
    },
    /// CIRISPersist#1040 — every trace with an LLM call whose `model` is
    /// `model` (the mock LLM reports [`MOCK_LLM_MODEL`]), its own
    /// `trace:complete:v1` attestation, and every score derived from them.
    MockModelTraces {
        /// The `trace_llm_calls.model` value.
        model: String,
    },
    /// CIRISPersist#1043 class 1 — every federation-tier attestation the
    /// apply door would refuse TODAY on a structural ground
    /// ([`refused_today`]: no signed `asserted_at` (#598), a typed instant or
    /// column diverging from the signed envelope (#643)), and everything
    /// derived from them.
    RefusedToday,
}

impl PurgeSelection {
    /// CIRISPersist#1040 — the mock-LLM class: every trace whose LLM calls
    /// report [`MOCK_LLM_MODEL`].
    #[must_use]
    pub fn mock_llm_traces() -> Self {
        Self::MockModelTraces {
            model: MOCK_LLM_MODEL.to_owned(),
        }
    }

    /// Does this selection pick `row` on the attestation scan, on its own
    /// facts? Pure. A class is this predicate plus its seeds (the actor's key
    /// and traces, the model's traces) and the derivation every class shares
    /// (a trace's own attestation, scores over purged evidence, a holder
    /// claim's bytes). A class like "rows of family F from issuer K in window
    /// W" is one more arm here — `attestation_type`/dimension, attester,
    /// `asserted_at` — with no new resolver.
    #[must_use]
    pub fn selects_row(&self, row: &Attestation) -> bool {
        match self {
            Self::ByActor { key_id } => row.attesting_key_id == *key_id,
            Self::RefusedToday => {
                row.tier == super::types::attestation_tier::FEDERATION
                    && refused_today(row).is_some()
            }
            Self::ByIds { .. } | Self::MockModelTraces { .. } => false,
        }
    }

    /// The parties this selection removes: the actor of a
    /// [`Self::ByActor`], nobody otherwise. A `delegates_to` is purgeable only
    /// with one of its parties ([`retraction_admissible`]).
    #[must_use]
    pub fn parties(&self) -> BTreeSet<String> {
        match self {
            Self::ByActor { key_id } => BTreeSet::from([key_id.clone()]),
            _ => BTreeSet::new(),
        }
    }
}

/// A record a selection class found but did not select, and why. A class
/// selects only records whose retraction is admissible, so its selection is
/// executable; the dry run shows what it left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withheld {
    /// The record id.
    pub record_id: String,
    /// Why its retraction is not admissible.
    pub reason: String,
}

/// A resolved selection: the records, sorted by record id and unique, plus
/// what was withheld.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSelection {
    /// The records, in JCS (record-id) order.
    pub records: Vec<PurgeRecord>,
    /// Records a class found and left out (never for [`PurgeSelection::ByIds`]).
    pub withheld: Vec<Withheld>,
    /// Records of a [`PurgeSelection::ByIds`] list whose retraction is not
    /// admissible TODAY — the door will refuse at them. A warning, never a
    /// filter.
    pub inadmissible: Vec<Withheld>,
}

impl ResolvedSelection {
    /// The record ids, in order.
    #[must_use]
    pub fn record_ids(&self) -> Vec<String> {
        self.records.iter().map(PurgeRecord::record_id).collect()
    }

    /// The selection digest of these records.
    #[must_use]
    pub fn digest(&self) -> String {
        selection_digest(&self.record_ids())
    }

    /// Per-table record counts — the counts the notice signs.
    #[must_use]
    pub fn counts(&self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for r in &self.records {
            *out.entry(r.plane.table().to_owned()).or_insert(0) += 1;
        }
        out
    }
}

/// CIRISPersist#1043 class 1 — **would the apply door refuse this row today,
/// on a ground the row alone decides?** `Some(reason)` when it would.
///
/// The two pure gates every attestation door runs: the instant binding
/// (`admission::check_instant_binding`, #598 — judged at the row's OWN signed
/// instant, so the clock-relative skew dual can never classify a row) and the
/// typed-column binding (`admission::check_row_column_binding`, #643). Pure:
/// no directory read, no clock, so the classification is stable — "downgrade
/// only a STRUCTURALLY detected refusal". The [`PurgeSelection::RefusedToday`]
/// class asks this ONE predicate. It is NOT a serve filter: the operator
/// ruled (#1043, 2026-10-09) that these rows are PURGED through this door,
/// never withheld in place.
#[must_use]
pub fn refused_today(row: &Attestation) -> Option<String> {
    if let Err(e) = super::admission::check_instant_binding(
        row,
        row.asserted_at,
        super::admission::DEFAULT_MAX_TOUCH_SKEW,
    ) {
        return Some(e.to_string());
    }
    if let Err(e) = super::admission::check_row_column_binding(row) {
        return Some(e.to_string());
    }
    None
}

/// Every attestation row, every tier, paged by `attestation_id`, handed to
/// `visit` one at a time (so a scan never holds the corpus in memory).
///
/// # Errors
///
/// The scan read's.
pub async fn scan_attestations<F, V>(directory: &F, visit: V) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
    V: FnMut(Attestation),
{
    scan_attestations_paged(directory, SCAN_PAGE, visit).await
}

/// [`scan_attestations`] at an explicit page size (the witness pages by one,
/// so a paging defect cannot hide below a full page).
pub(crate) async fn scan_attestations_paged<F, V>(
    directory: &F,
    page_size: u32,
    mut visit: V,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
    V: FnMut(Attestation),
{
    let mut after: Option<String> = None;
    loop {
        let page = directory
            .purge_scan_attestations(after.as_deref(), page_size)
            .await?;
        let n = page.len();
        if let Some(last) = page.last() {
            after = Some(last.attestation_id.clone());
        }
        for row in page {
            visit(row);
        }
        if n < page_size as usize {
            return Ok(());
        }
    }
}

fn evidence_refs(envelope: &serde_json::Value) -> Vec<String> {
    envelope
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One attestation row's facts the resolver needs, kept compact so a scan
/// never retains envelopes.
#[derive(Debug, Clone)]
struct RowFacts {
    id: String,
    accountability: Option<&'static str>,
    attesting: String,
    attested: String,
    exclusion: Option<super::migration::ExclusionClass>,
    references: Option<String>,
    is_scores: bool,
    refs: Vec<String>,
    holds_bytes_sha: Option<String>,
}

impl RowFacts {
    fn of(row: &Attestation) -> Self {
        let holds_bytes_sha = row
            .attestation_type
            .starts_with(super::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX)
            .then(|| super::first_evidence_ref(&row.attestation_envelope))
            .flatten()
            .filter(|s| is_hex64(s))
            .map(str::to_owned);
        Self {
            id: row.attestation_id.clone(),
            accountability: super::admission::envelope_dimension(&row.attestation_envelope)
                .and_then(accountability_family),
            attesting: row.attesting_key_id.clone(),
            attested: row.attested_key_id.clone(),
            exclusion: super::migration::is_exclusion_bearing(row),
            references: super::precedence::references_attestation_id_from_envelope(
                &row.attestation_envelope,
            )
            .map(str::to_owned),
            is_scores: row.attestation_type == attestation_type::SCORES,
            refs: evidence_refs(&row.attestation_envelope),
            holds_bytes_sha,
        }
    }
}

/// CLM-accountability-record-unpurgeable (CIRISConstitution rc8@af6b436) —
/// the dimension families the text names EXACTLY as the unpurgeable
/// accountability record. Matched by the purge's own check, not by widening
/// `migration::ExclusionClass`: its `moderation:` prefix does not reach
/// `moderation_track_record:*`, and it has no `key:revocation` arm.
pub const ACCOUNTABILITY_RECORD_PREFIXES: &[&str] = &[
    "revocation:",
    "key:revocation",
    "moderation:",
    "moderation_track_record:",
    "slashing:",
];

/// The accountability family `dimension` belongs to, if any.
fn accountability_family(dimension: &str) -> Option<&'static str> {
    ACCOUNTABILITY_RECORD_PREFIXES
        .iter()
        .copied()
        .find(|p| dimension.starts_with(p))
}

/// **Is this attestation's retraction admissible inside this selection?**
/// `Err(reason)` when not. The door's own gate (AV-9): the purge deletes what
/// the migration purge door (`migration::check_purge_admission`) protects, so
/// it re-asks the protecting question with the selection in view:
///
/// - an accountability record ([`ACCOUNTABILITY_RECORD_PREFIXES`]) → NEVER
///   admissible, whatever the selection;
/// - not exclusion-bearing → admissible;
/// - a structural composer (`withdraws` / `recants` / `supersedes`) →
///   admissible only when the row it retracts is in the selection too
///   (deleting a tombstone alone resurrects its target);
/// - a `delegates_to` → admissible only when its granter or grantee is a
///   party the selection removes ([`PurgeSelection::parties`]) — the purge
///   removes the party's rows, not a third party's grant;
/// - any other exclusion-bearing row (`revocation:*`, `moderation:*`,
///   `slashing:*`, an unreadable dimension, …) → NOT admissible.
fn retraction_admissible(
    facts: &RowFacts,
    selected_attestations: &BTreeSet<String>,
    parties: &BTreeSet<String>,
) -> Result<(), String> {
    use super::migration::ExclusionClass;
    if let Some(family) = facts.accountability {
        return Err(format!(
            "a `{family}` row is the accountability record, unpurgeable by any selection \
             (CLM-accountability-record-unpurgeable)"
        ));
    }
    match facts.exclusion {
        None => Ok(()),
        Some(ExclusionClass::StructuralComposer) => match &facts.references {
            Some(target) if selected_attestations.contains(target) => Ok(()),
            Some(target) => Err(format!(
                "a structural composer whose target {target} is not in the selection: purging it \
                 alone resurrects the row it retracts"
            )),
            None => Err("a structural composer naming no target".to_owned()),
        },
        Some(ExclusionClass::Delegation) => {
            if parties.contains(&facts.attesting) || parties.contains(&facts.attested) {
                Ok(())
            } else {
                Err(
                    "a delegates_to grant between keys neither of which is a party the selection \
                     removes: a purge removes a party's rows, not a third party's standing grant"
                        .to_owned(),
                )
            }
        }
        Some(class) => Err(class.why().to_owned()),
    }
}

/// Resolve a selection against this node's live state.
///
/// Classes select only records whose retraction is admissible (a fixpoint:
/// withholding a target makes its tombstone inadmissible in turn), and say
/// what they withheld; [`PurgeSelection::ByIds`] selects exactly its list and
/// reports inadmissible members as warnings — the door refuses at them.
///
/// # Errors
///
/// Directory reads; [`token::SELECTION_MALFORMED`] for a malformed id.
pub async fn resolve_selection<F>(
    directory: &F,
    selection: &PurgeSelection,
) -> Result<ResolvedSelection, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut records: BTreeMap<String, PurgeRecord> = BTreeMap::new();
    let add = |records: &mut BTreeMap<String, PurgeRecord>, r: PurgeRecord| {
        records.entry(r.record_id()).or_insert(r);
    };
    let mut facts: BTreeMap<String, RowFacts> = BTreeMap::new();
    let mut scores_with_refs: Vec<RowFacts> = Vec::new();
    let derive = !matches!(selection, PurgeSelection::ByIds { .. });

    match selection {
        PurgeSelection::ByIds { ids } => {
            for id in ids {
                let r = parse_record_id(id)?;
                add(&mut records, r);
            }
            for r in records.values() {
                if r.plane == PurgePlane::Attestation {
                    if let Some(row) = directory.get_attestation(&r.id).await? {
                        facts.insert(r.id.clone(), RowFacts::of(&row));
                    }
                }
            }
        }
        PurgeSelection::ByActor { key_id } => {
            for trace_id in directory.purge_trace_ids_signed_by(key_id).await? {
                add(
                    &mut records,
                    PurgeRecord {
                        plane: PurgePlane::Trace,
                        id: trace_id,
                        derived_from: None,
                    },
                );
            }
        }
        PurgeSelection::MockModelTraces { model } => {
            for trace_id in directory.purge_trace_ids_for_llm_model(model).await? {
                add(
                    &mut records,
                    PurgeRecord {
                        plane: PurgePlane::Trace,
                        id: trace_id,
                        derived_from: None,
                    },
                );
            }
        }
        PurgeSelection::RefusedToday => {}
    }

    if derive {
        // The class's own rows, and every score that may derive from the
        // selection, in ONE scan.
        scan_attestations(directory, |row| {
            let f = RowFacts::of(&row);
            if selection.selects_row(&row) {
                records
                    .entry(format!("attestation:{}", f.id))
                    .or_insert(PurgeRecord {
                        plane: PurgePlane::Attestation,
                        id: f.id.clone(),
                        derived_from: None,
                    });
                facts.insert(f.id.clone(), f);
            } else if f.is_scores && !f.refs.is_empty() {
                scores_with_refs.push(f);
            }
        })
        .await?;
        // A trace's own attestation follows the trace.
        let traces: Vec<String> = records
            .values()
            .filter(|r| r.plane == PurgePlane::Trace)
            .map(|r| r.id.clone())
            .collect();
        for trace_id in &traces {
            let att = crate::ingest::trace_attestation_id(trace_id);
            let present = match facts.get(&att) {
                Some(_) => true,
                None => match directory.get_attestation(&att).await? {
                    Some(row) => {
                        facts.insert(att.clone(), RowFacts::of(&row));
                        true
                    }
                    None => false,
                },
            };
            if present {
                add(
                    &mut records,
                    PurgeRecord {
                        plane: PurgePlane::Attestation,
                        id: att,
                        derived_from: Some(format!("trace:{trace_id}")),
                    },
                );
            }
        }
        // Scores over purged evidence follow it, transitively.
        loop {
            let mut evidence: BTreeMap<String, String> = BTreeMap::new();
            for r in records.values() {
                match r.plane {
                    PurgePlane::Trace | PurgePlane::Attestation => {
                        evidence.insert(r.id.clone(), r.record_id());
                    }
                    PurgePlane::Blob => {}
                }
            }
            let mut grew = false;
            for f in &scores_with_refs {
                let key = format!("attestation:{}", f.id);
                if records.contains_key(&key) {
                    continue;
                }
                if let Some(from) = f.refs.iter().find_map(|e| evidence.get(e)) {
                    records.insert(
                        key,
                        PurgeRecord {
                            plane: PurgePlane::Attestation,
                            id: f.id.clone(),
                            derived_from: Some(from.clone()),
                        },
                    );
                    facts.insert(f.id.clone(), f.clone());
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        // A holder claim's bytes follow the claim.
        let blobs: Vec<PurgeRecord> = records
            .values()
            .filter(|r| r.plane == PurgePlane::Attestation)
            .filter_map(|r| {
                let sha = facts.get(&r.id)?.holds_bytes_sha.clone()?;
                Some(PurgeRecord {
                    plane: PurgePlane::Blob,
                    id: sha,
                    derived_from: Some(r.record_id()),
                })
            })
            .collect();
        for b in blobs {
            add(&mut records, b);
        }
    }

    // Admissibility: a fixpoint for the classes, a warning list for ByIds.
    let key_ids = selection.parties();
    let mut withheld = Vec::new();
    let mut inadmissible = Vec::new();
    loop {
        let selected: BTreeSet<String> = records
            .values()
            .filter(|r| r.plane == PurgePlane::Attestation)
            .map(|r| r.id.clone())
            .collect();
        let mut out: Vec<(String, String)> = Vec::new();
        for r in records
            .values()
            .filter(|r| r.plane == PurgePlane::Attestation)
        {
            if let Some(f) = facts.get(&r.id) {
                if let Err(reason) = retraction_admissible(f, &selected, &key_ids) {
                    out.push((r.record_id(), reason));
                }
            }
        }
        if out.is_empty() {
            break;
        }
        if !derive {
            inadmissible.extend(
                out.into_iter()
                    .map(|(record_id, reason)| Withheld { record_id, reason }),
            );
            break;
        }
        for (record_id, reason) in out {
            records.remove(&record_id);
            withheld.push(Withheld { record_id, reason });
        }
    }
    withheld.sort_by(|a, b| a.record_id.cmp(&b.record_id));
    Ok(ResolvedSelection {
        records: records.into_values().collect(),
        withheld,
        inadmissible,
    })
}

// ── the dry run ────────────────────────────────────────────────────────────

/// What a dry run reports (CSD-108: counts → notice → quorum). Writes
/// NOTHING.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurgeDryRun {
    /// The selection as asked.
    pub selection: PurgeSelection,
    /// The digest the notice must name.
    pub selection_digest: String,
    /// Every record.
    pub record_count: u64,
    /// Per-table record counts — the notice signs these.
    pub counts: BTreeMap<String, u64>,
    /// Informational row counts behind the trace records
    /// (`trace_events`, `trace_llm_calls`).
    pub table_rows: BTreeMap<String, u64>,
    /// The first [`SAMPLE_LEN`] record ids in JCS order.
    pub sample: Vec<String>,
    /// What a class found and left out, and why.
    pub withheld: Vec<Withheld>,
    /// ByIds members the door will refuse at.
    pub inadmissible: Vec<Withheld>,
    /// The ledger, to be written to `evidence/purges/<date>-<digest>.tsv`
    /// BEFORE the notice is cosigned (its `evidence_refs` point at it).
    pub ledger_tsv: String,
    /// The `takedown_notice` payload (CC 3.3.2) to complete and cosign:
    /// `legal_basis`, `content_sha256` (the selection digest),
    /// `content_holder_key_ids` (empty: a purge names no holder) and
    /// `selection_counts` are filled; the proposer fills `claimant_key_id`,
    /// `claim_text`, `good_faith_statement`, `jurisdiction`, `evidence_refs`
    /// (the dry-run ledger), `asserted_at` and `expires_at`.
    pub notice_template: serde_json::Value,
}

/// Render a ledger. `header` carries the preimage fields the file claims
/// (digest, count, and — once executed — notice id, claimant, actor,
/// instant); every row carries the digest and notice id it belongs to.
fn render_ledger(header: &[(&str, String)], notice_id: &str, records: &[PurgeRecord]) -> String {
    let digest = selection_digest(
        &records
            .iter()
            .map(PurgeRecord::record_id)
            .collect::<Vec<_>>(),
    );
    let mut out =
        String::from("# steward purge ledger (CIRISPersist#1046, CIRISConstitution#165)\n");
    for (k, v) in header {
        out.push_str(&format!("# {k}\t{v}\n"));
    }
    out.push_str("selection_digest\tnotice_id\tordinal\tplane\trecord_id\tderived_from\n");
    for (i, r) in records.iter().enumerate() {
        out.push_str(&format!(
            "{digest}\t{notice_id}\t{i}\t{}\t{}\t{}\n",
            r.plane.as_str(),
            r.record_id(),
            r.derived_from.as_deref().unwrap_or("")
        ));
    }
    out
}

/// **Dry run**: resolve the selection, count it per table, digest it, sample
/// it, and render the ledger and the notice template. Read-only.
///
/// # Errors
///
/// Directory reads; a malformed selection.
pub async fn purge_dry_run<F>(
    directory: &F,
    selection: &PurgeSelection,
) -> Result<PurgeDryRun, Error>
where
    F: FederationDirectory + ?Sized,
{
    let resolved = resolve_selection(directory, selection).await?;
    let ids = resolved.record_ids();
    let digest = selection_digest(&ids);
    let counts = resolved.counts();
    let traces: Vec<String> = resolved
        .records
        .iter()
        .filter(|r| r.plane == PurgePlane::Trace)
        .map(|r| r.id.clone())
        .collect();
    let (events, calls) = directory.purge_trace_row_counts(&traces).await?;
    let mut table_rows = BTreeMap::new();
    table_rows.insert("trace_events".to_owned(), events);
    table_rows.insert("trace_llm_calls".to_owned(), calls);
    let ledger_tsv = render_ledger(
        &[
            ("selection_digest", digest.clone()),
            ("record_count", ids.len().to_string()),
            (
                "selection",
                serde_json::to_string(selection).expect("a selection serializes"),
            ),
            ("notice_id", "(dry run: no notice yet)".to_owned()),
        ],
        "",
        &resolved.records,
    );
    let notice_template = serde_json::json!({
        "legal_basis": STEWARD_PURGE_BASIS,
        "content_sha256": digest,
        "content_holder_key_ids": [],
        "selection_counts": counts,
    });
    Ok(PurgeDryRun {
        selection: selection.clone(),
        selection_digest: digest,
        record_count: ids.len() as u64,
        counts,
        table_rows,
        sample: ids.into_iter().take(SAMPLE_LEN).collect(),
        withheld: resolved.withheld,
        inadmissible: resolved.inadmissible,
        ledger_tsv,
        notice_template,
    })
}

// ── the notice ─────────────────────────────────────────────────────────────

/// The authorisation: a `takedown_notice` envelope and its WHOLE cosignature
/// set, each a hybrid signature over `JCS(envelope)`
/// (`accord_family_signing_bytes`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StewardPurgeNotice {
    /// The signed envelope.
    pub envelope: serde_json::Value,
    /// Every cosignature (Ed25519 + bound ML-DSA-65 per founder).
    pub cosignatures: Vec<ciris_verify_core::threshold::ThresholdSignature>,
}

/// The notice's signed members, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeTerms {
    /// `hex(sha256(JCS(envelope)))` — the notice id every tombstone cites.
    pub notice_id: String,
    /// The trust root's `community_key_id`.
    pub claimant_key_id: String,
    /// The digest the notice authorises.
    pub selection_digest: String,
    /// Per-table counts the notice authorises.
    pub selection_counts: BTreeMap<String, u64>,
    /// The notice's own instant.
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// When it stops authorising.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// The JCS bytes the cosigners sign (and the notice id hashes).
///
/// # Errors
///
/// [`token::UNAUTHORISED`] when the envelope does not canonicalize.
pub fn notice_signing_bytes(envelope: &serde_json::Value) -> Result<Vec<u8>, Error> {
    ciris_verify_core::accord_genesis::accord_family_signing_bytes(envelope).map_err(|e| {
        refused(
            token::UNAUTHORISED,
            serde_json::json!({"reason": format!("the notice envelope does not canonicalize: {e}")}),
        )
    })
}

/// Parse and shape-check the notice's signed members (CC 3.3.2 shape plus the
/// `steward_purge` members). Every failure is [`token::UNAUTHORISED`].
///
/// # Errors
///
/// [`token::UNAUTHORISED`] naming the member.
pub fn notice_terms(envelope: &serde_json::Value) -> Result<NoticeTerms, Error> {
    let bytes = notice_signing_bytes(envelope)?;
    let notice_id = hex::encode(sha2::Sha256::digest(&bytes));
    let unauth = |reason: String| {
        refused(
            token::UNAUTHORISED,
            serde_json::json!({"notice_id": notice_id, "reason": reason}),
        )
    };
    let s = |k: &str| -> Result<String, Error> {
        match envelope.get(k).and_then(serde_json::Value::as_str) {
            Some(v) if !v.trim().is_empty() => Ok(v.to_owned()),
            _ => Err(unauth(format!("the notice carries no non-empty `{k}`"))),
        }
    };
    let basis = s("legal_basis")?;
    if basis != STEWARD_PURGE_BASIS {
        return Err(unauth(format!(
            "legal_basis {basis:?} does not authorise a steward purge (only \
             `{STEWARD_PURGE_BASIS}` does, CIRISConstitution#165)"
        )));
    }
    let claimant_key_id = s("claimant_key_id")?;
    // CC 3.3.2: for `steward_purge`, `content_sha256` IS the selection digest.
    let selection_digest = s("content_sha256")?;
    if !is_hex64(&selection_digest) {
        return Err(unauth(
            "content_sha256 (the selection digest) is not 64 lowercase hex".to_owned(),
        ));
    }
    if !envelope
        .get("content_holder_key_ids")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|a| a.iter().all(serde_json::Value::is_string))
    {
        return Err(unauth(
            "content_holder_key_ids must be a string array (CC 3.3.2)".to_owned(),
        ));
    }
    s("claim_text")?;
    s("good_faith_statement")?;
    s("jurisdiction")?;
    let refs = envelope
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .filter(|a| !a.is_empty() && a.iter().all(serde_json::Value::is_string))
        .ok_or_else(|| {
            unauth("evidence_refs must name the dry-run ledger (a non-empty string array)".into())
        })?;
    let _ = refs;
    let selection_counts: BTreeMap<String, u64> = envelope
        .get("selection_counts")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| unauth("selection_counts must be an object of table -> count".into()))?;
    let instant = |k: &str| -> Result<chrono::DateTime<chrono::Utc>, Error> {
        let raw = s(k)?;
        chrono::DateTime::parse_from_rfc3339(&raw)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| unauth(format!("`{k}` is not RFC 3339: {e}")))
    };
    let asserted_at = instant("asserted_at")?;
    let expires_at = instant("expires_at")?;
    if expires_at <= asserted_at {
        return Err(unauth("expires_at must be after asserted_at".to_owned()));
    }
    Ok(NoticeTerms {
        notice_id,
        claimant_key_id,
        selection_digest,
        selection_counts,
        asserted_at,
        expires_at,
    })
}

/// **The authorisation gate.** The notice's shape, its window at `now`, and
/// its cosigners under the claimant trust root's own `consensus_protocol`
/// ([`trust_root_cosigners_over`](super::canonical_community::trust_root_cosigners_over)).
/// Returns the terms and the counted cosigners.
///
/// # Errors
///
/// [`token::UNAUTHORISED`]; directory reads.
pub async fn verify_purge_authorisation<F>(
    directory: &F,
    notice: &StewardPurgeNotice,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(NoticeTerms, BTreeSet<String>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let terms = notice_terms(&notice.envelope)?;
    let unauth = |reason: String| {
        refused(
            token::UNAUTHORISED,
            serde_json::json!({"notice_id": terms.notice_id, "reason": reason}),
        )
    };
    let skew = super::admission::DEFAULT_MAX_TOUCH_SKEW;
    if terms.asserted_at > now + skew {
        return Err(unauth(format!(
            "the notice is asserted at {}, in the future",
            terms.asserted_at.to_rfc3339()
        )));
    }
    if terms.expires_at <= now {
        return Err(unauth(format!(
            "the notice expired at {}",
            terms.expires_at.to_rfc3339()
        )));
    }
    match super::canonical_community::trust_root_cosigners_over(
        directory,
        &terms.claimant_key_id,
        &notice.envelope,
        &notice.cosignatures,
        now,
    )
    .await?
    {
        Ok(signers) => Ok((terms, signers)),
        Err(reason) => Err(unauth(reason)),
    }
}

// ── the stored plane ───────────────────────────────────────────────────────

/// Where an execution came from.
pub mod origin {
    /// This node ran `purge_rows`.
    pub const LOCAL: &str = "local";
    /// This node applied a peer's [`super::PurgeBundle`].
    pub const REPLICATED: &str = "replicated";
}

/// One executed (or applied) purge: the header row of the ledger. Carries
/// every preimage the ledger claims: the digest, the notice (its JCS bytes,
/// whose hash IS the notice id) and its whole cosignature set, the count, the
/// actor, the instant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeExecution {
    /// `hex(sha256(notice_jcs))`.
    pub notice_id: String,
    /// The digest the notice names and the tombstones re-derive.
    pub selection_digest: String,
    /// The notice's claimant: for `steward_purge`, the trust root that
    /// authorised it.
    pub claimant_key_id: String,
    /// The notice's `legal_basis` (CC 3.3.2). One tombstone row serves
    /// takedown and purge (CIRISConstitution rc8@9ce73e6, CC 4.5.3): the
    /// basis is what tells a `steward_purge` (cosigned, any plane, hard
    /// delete after settle) from a duty-holder takedown (bytes plane only;
    /// an immediate-removal basis destroys on receipt — the v55 door,
    /// CIRISPersist#1007).
    pub legal_basis: String,
    /// How many records the selection holds.
    pub record_count: u64,
    /// The notice envelope's JCS text, verbatim.
    pub notice_jcs: String,
    /// The cosignature set, JSON.
    pub cosignatures_json: String,
    /// The node that recorded it (its derived federation key id).
    pub executed_by: String,
    /// [`origin::LOCAL`] or [`origin::REPLICATED`].
    pub origin: String,
    /// The instant the recording node executed / applied it.
    pub executed_at: chrono::DateTime<chrono::Utc>,
    /// This node's serve position (stamped by the store on insert).
    pub admitted_at: chrono::DateTime<chrono::Utc>,
    /// When `purge_finalize` hard-deleted its records, if it has.
    pub finalized_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One tombstone: a record id under one notice, at its JCS ordinal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeTombstone {
    /// The notice it cites.
    pub notice_id: String,
    /// Its index in JCS order.
    pub ordinal: u64,
    /// The plane.
    pub plane: PurgePlane,
    /// The id on that plane.
    pub record_ref: String,
    /// The record id it was derived through, if any.
    pub derived_from: Option<String>,
}

impl PurgeTombstone {
    /// `"{plane}:{record_ref}"`.
    #[must_use]
    pub fn record_id(&self) -> String {
        format!("{}:{}", self.plane.as_str(), self.record_ref)
    }
}

// ── execution ──────────────────────────────────────────────────────────────

/// What `purge_rows` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeReport {
    /// The notice id every tombstone cites.
    pub notice_id: String,
    /// The digest executed.
    pub selection_digest: String,
    /// Every record in the selection.
    pub record_count: u64,
    /// Tombstones written by THIS call, per plane.
    pub tombstoned: BTreeMap<String, u64>,
    /// Tombstones a previous (interrupted) call had already written.
    pub already_tombstoned: u64,
    /// The founders whose cosignatures counted.
    pub cosigners: Vec<String>,
    /// The instant recorded.
    pub executed_at: chrono::DateTime<chrono::Utc>,
}

/// Is `record`'s retraction admissible now, inside `selected`? `None` when it
/// is. The per-record re-check at the door.
async fn record_inadmissible<F>(
    directory: &F,
    record: &PurgeRecord,
    selected_attestations: &BTreeSet<String>,
    parties: &BTreeSet<String>,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if record.plane != PurgePlane::Attestation {
        return Ok(None);
    }
    let Some(row) = directory.get_attestation(&record.id).await? else {
        return Ok(None);
    };
    Ok(retraction_admissible(&RowFacts::of(&row), selected_attestations, parties).err())
}

/// **`purge_rows(selection, notice, now)`** — the door.
///
/// In order, each a typed refusal and none an override:
/// 1. the notice authorises ([`verify_purge_authorisation`]) —
///    [`token::UNAUTHORISED`];
/// 2. the LIVE selection's per-table counts equal the notice's —
///    [`token::SELECTION_COUNT_MISMATCH`] `{table, expected, found}`;
/// 3. the live selection's digest is the notice's —
///    [`token::SELECTION_DIGEST_MISMATCH`];
/// 4. the header is recorded (idempotent on the notice id), then per record
///    in JCS order its retraction is re-checked and its tombstone written; an
///    inadmissible record STOPS the door —
///    [`token::RETRACTION_INADMISSIBLE`] `{record_id, plane, index, total}` —
///    with everything before it retracted and nothing after it touched. A
///    retry resumes; a tombstone is never written twice.
///
/// Nothing is deleted here: [`purge_finalize`] hard-deletes after the settle.
///
/// # Errors
///
/// The refusals above; directory reads and writes.
pub async fn purge_rows<F>(
    directory: &F,
    selection: &PurgeSelection,
    notice: &StewardPurgeNotice,
    executed_by: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PurgeReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (terms, signers) = verify_purge_authorisation(directory, notice, now).await?;
    let resolved = resolve_selection(directory, selection).await?;
    let live = resolved.counts();
    let tables: BTreeSet<&String> = live.keys().chain(terms.selection_counts.keys()).collect();
    for table in tables {
        let expected = terms.selection_counts.get(table).copied().unwrap_or(0);
        let found = live.get(table).copied().unwrap_or(0);
        if expected != found {
            return Err(refused(
                token::SELECTION_COUNT_MISMATCH,
                serde_json::json!({
                    "notice_id": terms.notice_id,
                    "table": table,
                    "expected": expected,
                    "found": found,
                }),
            ));
        }
    }
    let digest = resolved.digest();
    if digest != terms.selection_digest {
        return Err(refused(
            token::SELECTION_DIGEST_MISMATCH,
            serde_json::json!({
                "notice_id": terms.notice_id,
                "expected": terms.selection_digest,
                "found": digest,
            }),
        ));
    }
    let records = resolved.records;
    let total = records.len() as u64;
    let notice_jcs = String::from_utf8(notice_signing_bytes(&notice.envelope)?)
        .map_err(|e| Error::Backend(format!("notice JCS is not UTF-8: {e}")))?;
    let cosignatures_json = serde_json::to_string(&notice.cosignatures)
        .map_err(|e| Error::Backend(format!("cosignatures encode: {e}")))?;
    directory
        .purge_put_execution(&PurgeExecution {
            notice_id: terms.notice_id.clone(),
            selection_digest: digest.clone(),
            claimant_key_id: terms.claimant_key_id.clone(),
            legal_basis: STEWARD_PURGE_BASIS.to_owned(),
            record_count: total,
            notice_jcs,
            cosignatures_json,
            executed_by: executed_by.to_owned(),
            origin: origin::LOCAL.to_owned(),
            executed_at: now,
            admitted_at: now,
            finalized_at: None,
        })
        .await?;
    let selected_attestations: BTreeSet<String> = records
        .iter()
        .filter(|r| r.plane == PurgePlane::Attestation)
        .map(|r| r.id.clone())
        .collect();
    let key_ids = selection.parties();
    let mut tombstoned: BTreeMap<String, u64> = BTreeMap::new();
    let mut already = 0u64;
    for (index, record) in records.iter().enumerate() {
        if let Some(reason) =
            record_inadmissible(directory, record, &selected_attestations, &key_ids).await?
        {
            return Err(refused(
                token::RETRACTION_INADMISSIBLE,
                serde_json::json!({
                    "notice_id": terms.notice_id,
                    "record_id": record.record_id(),
                    "plane": record.plane.as_str(),
                    "index": index,
                    "total": total,
                    "reason": reason,
                }),
            ));
        }
        let inserted = directory
            .purge_put_tombstone(&PurgeTombstone {
                notice_id: terms.notice_id.clone(),
                ordinal: index as u64,
                plane: record.plane,
                record_ref: record.id.clone(),
                derived_from: record.derived_from.clone(),
            })
            .await?;
        if inserted {
            *tombstoned
                .entry(record.plane.as_str().to_owned())
                .or_insert(0) += 1;
        } else {
            already += 1;
        }
    }
    let executed_at = directory
        .purge_execution(&terms.notice_id)
        .await?
        .map_or(now, |e| e.executed_at);
    Ok(PurgeReport {
        notice_id: terms.notice_id,
        selection_digest: digest,
        record_count: total,
        tombstoned,
        already_tombstoned: already,
        cosigners: signers.into_iter().collect(),
        executed_at,
    })
}

// ── status, ledger ─────────────────────────────────────────────────────────

/// The CSD-108 state strip after execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurgeState {
    /// Tombstones written; the retraction round has not settled.
    Executed,
    /// The settle dwell has passed; `purge_finalize` may hard-delete.
    Settled,
    /// Hard-deleted.
    Finalized,
}

/// A purge's status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeStatus {
    /// The header.
    pub execution: PurgeExecution,
    /// Its state at `now`.
    pub state: PurgeState,
    /// When it settles (or settled).
    pub settles_at: chrono::DateTime<chrono::Utc>,
    /// Tombstones recorded, per plane.
    pub tombstones: BTreeMap<String, u64>,
}

async fn execution_or_unknown<F>(directory: &F, notice_id: &str) -> Result<PurgeExecution, Error>
where
    F: FederationDirectory + ?Sized,
{
    directory.purge_execution(notice_id).await?.ok_or_else(|| {
        refused(
            token::NOTICE_UNKNOWN,
            serde_json::json!({"notice_id": notice_id}),
        )
    })
}

fn settles_at(e: &PurgeExecution) -> chrono::DateTime<chrono::Utc> {
    e.executed_at + chrono::Duration::seconds(PURGE_SETTLE_DWELL_SECS)
}

/// **Status** of an executed purge at `now`.
///
/// # Errors
///
/// [`token::NOTICE_UNKNOWN`]; directory reads.
pub async fn purge_status<F>(
    directory: &F,
    notice_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PurgeStatus, Error>
where
    F: FederationDirectory + ?Sized,
{
    let execution = execution_or_unknown(directory, notice_id).await?;
    let mut tombstones = BTreeMap::new();
    for t in directory.purge_tombstones_of(notice_id).await? {
        *tombstones.entry(t.plane.as_str().to_owned()).or_insert(0) += 1;
    }
    let settles = settles_at(&execution);
    let state = if execution.finalized_at.is_some() {
        PurgeState::Finalized
    } else if now >= settles {
        PurgeState::Settled
    } else {
        PurgeState::Executed
    };
    Ok(PurgeStatus {
        execution,
        state,
        settles_at: settles,
        tombstones,
    })
}

/// **The ledger** of an executed purge, as TSV for
/// `evidence/purges/<date>-<selection-digest>.tsv`: a header carrying the
/// digest, notice id, claimant, count, actor and instant, then one row per
/// record in JCS order. The digest re-derives from the rows' record ids.
///
/// # Errors
///
/// [`token::NOTICE_UNKNOWN`]; directory reads.
pub async fn purge_ledger_tsv<F>(directory: &F, notice_id: &str) -> Result<String, Error>
where
    F: FederationDirectory + ?Sized,
{
    let e = execution_or_unknown(directory, notice_id).await?;
    let records = tombstone_records(directory, notice_id).await?;
    Ok(render_ledger(
        &[
            ("selection_digest", e.selection_digest.clone()),
            ("notice_id", e.notice_id.clone()),
            ("claimant_key_id", e.claimant_key_id.clone()),
            ("legal_basis", e.legal_basis.clone()),
            ("record_count", e.record_count.to_string()),
            ("executed_by", e.executed_by.clone()),
            ("origin", e.origin.clone()),
            ("executed_at", e.executed_at.to_rfc3339()),
            (
                "finalized_at",
                e.finalized_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            ),
            // The notice id's preimage and the WHOLE cosignature set, so the
            // ledger alone re-derives the id and re-verifies the quorum (JCS
            // and compact JSON are single-line).
            ("notice_jcs", e.notice_jcs.clone()),
            ("cosignatures_json", e.cosignatures_json.clone()),
        ],
        &e.notice_id,
        &records,
    ))
}

async fn tombstone_records<F>(directory: &F, notice_id: &str) -> Result<Vec<PurgeRecord>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut ts = directory.purge_tombstones_of(notice_id).await?;
    ts.sort_by_key(|t| t.ordinal);
    Ok(ts
        .into_iter()
        .map(|t| PurgeRecord {
            plane: t.plane,
            id: t.record_ref,
            derived_from: t.derived_from,
        })
        .collect())
}

// ── finalize ───────────────────────────────────────────────────────────────

/// The bytes plane's retract-then-delete, supplied by the host that holds a
/// signer (`Engine::evict_blob`). A directory with no bytes plane passes
/// `None`, and a purge holding blob records cannot finalize there.
#[async_trait::async_trait]
pub trait BytesEvictor: Send + Sync {
    /// Retract this node's holder claims on `sha256`, then delete the bytes.
    async fn evict(
        &self,
        sha256: &[u8; 32],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, String>;
}

/// What `purge_finalize` deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeReport {
    /// The notice.
    pub notice_id: String,
    /// `true` when an earlier call had already finalized it.
    pub already_finalized: bool,
    /// Attestation rows deleted.
    pub attestations_deleted: u64,
    /// `trace_events` rows deleted.
    pub trace_events_deleted: u64,
    /// `trace_llm_calls` rows deleted.
    pub trace_llm_calls_deleted: u64,
    /// Blobs evicted.
    pub blobs_evicted: u64,
}

/// **`purge_finalize(notice_id)`** — the hard delete, after settle (CSD-108
/// §6 Q4; CIRISConstitution#165 §3). A separate explicit call so the settled
/// state is visible before anything goes. Deletes only TOMBSTONED records
/// (each backend's delete door re-asks that), planes in [`PurgePlane::ALL`]
/// order. The tombstones and the header OUTLIVE the rows: they are what keeps
/// a replica from bringing a row back.
///
/// # Errors
///
/// [`token::NOTICE_UNKNOWN`], [`token::NOT_SETTLED`],
/// [`token::RETRACTION_INADMISSIBLE`] for a blob the bytes plane would not
/// retract (or a host with no bytes plane); directory writes.
pub async fn purge_finalize<F>(
    directory: &F,
    notice_id: &str,
    now: chrono::DateTime<chrono::Utc>,
    bytes: Option<&dyn BytesEvictor>,
) -> Result<FinalizeReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let e = execution_or_unknown(directory, notice_id).await?;
    let mut report = FinalizeReport {
        notice_id: notice_id.to_owned(),
        ..FinalizeReport::default()
    };
    if e.finalized_at.is_some() {
        report.already_finalized = true;
        return Ok(report);
    }
    let settles = settles_at(&e);
    if now < settles {
        return Err(refused(
            token::NOT_SETTLED,
            serde_json::json!({
                "notice_id": notice_id,
                "executed_at": e.executed_at.to_rfc3339(),
                "settles_at": settles.to_rfc3339(),
            }),
        ));
    }
    let records = tombstone_records(directory, notice_id).await?;
    let total = records.len();
    for plane in PurgePlane::ALL {
        for (index, r) in records.iter().enumerate().filter(|(_, r)| r.plane == plane) {
            match plane {
                PurgePlane::Trace => {
                    let (ev, calls) = directory.purge_delete_tombstoned_trace(&r.id).await?;
                    report.trace_events_deleted += ev;
                    report.trace_llm_calls_deleted += calls;
                }
                PurgePlane::Attestation => {
                    directory.purge_attestation_projections(&r.id).await?;
                    if directory.purge_delete_tombstoned_attestation(&r.id).await? {
                        report.attestations_deleted += 1;
                    }
                }
                PurgePlane::Blob => {
                    let mut sha = [0u8; 32];
                    let decoded = hex::decode_to_slice(&r.id, &mut sha).is_ok();
                    let outcome = match (bytes, decoded) {
                        (Some(ev), true) => ev.evict(&sha, now).await,
                        (None, _) => Err("this host has no bytes plane to evict through".into()),
                        (_, false) => Err("the blob id is not a sha256".into()),
                    };
                    match outcome {
                        Ok(true) => report.blobs_evicted += 1,
                        Ok(false) => {}
                        Err(reason) => {
                            return Err(refused(
                                token::RETRACTION_INADMISSIBLE,
                                serde_json::json!({
                                    "notice_id": notice_id,
                                    "record_id": r.record_id(),
                                    "plane": plane.as_str(),
                                    "index": index,
                                    "total": total,
                                    "reason": reason,
                                }),
                            ))
                        }
                    }
                }
            }
        }
    }
    directory.purge_mark_finalized(notice_id, now).await?;
    Ok(report)
}

// ── replication ────────────────────────────────────────────────────────────

/// The replicated tombstone (CIRISConstitution#165 §3): the notice, its WHOLE
/// cosignature set, and the record ids — digests and ids, never content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeBundle {
    /// The notice and cosignatures.
    pub notice: StewardPurgeNotice,
    /// Every record id, in JCS order.
    pub record_ids: Vec<String>,
    /// Per record, the record id it was derived through (`""` when none).
    /// Ledger-only; not covered by the digest.
    #[serde(default)]
    pub derived_from: Vec<String>,
    /// The serving node's position (resume cursor with the notice id).
    pub admitted_at: chrono::DateTime<chrono::Utc>,
}

/// **Serve** the tombstone plane: bundles since a `(admitted_at, notice_id)`
/// cursor, ordered by it.
///
/// # Errors
///
/// Directory reads; a stored notice that no longer parses.
pub async fn list_purge_bundles_since<F>(
    directory: &F,
    since: Option<(chrono::DateTime<chrono::Utc>, String)>,
    limit: u32,
) -> Result<Vec<PurgeBundle>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    for e in directory.list_purge_executions_since(since, limit).await? {
        let envelope: serde_json::Value = serde_json::from_str(&e.notice_jcs)
            .map_err(|err| Error::Backend(format!("stored notice {}: {err}", e.notice_id)))?;
        let cosignatures = serde_json::from_str(&e.cosignatures_json)
            .map_err(|err| Error::Backend(format!("stored cosignatures {}: {err}", e.notice_id)))?;
        let records = tombstone_records(directory, &e.notice_id).await?;
        out.push(PurgeBundle {
            notice: StewardPurgeNotice {
                envelope,
                cosignatures,
            },
            record_ids: records.iter().map(PurgeRecord::record_id).collect(),
            derived_from: records
                .iter()
                .map(|r| r.derived_from.clone().unwrap_or_default())
                .collect(),
            admitted_at: e.admitted_at,
        });
    }
    Ok(out)
}

/// What applying a bundle did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPurgeOutcome {
    /// The notice id.
    pub notice_id: String,
    /// Tombstones newly written.
    pub tombstoned: u64,
    /// Tombstones already held.
    pub already_tombstoned: u64,
}

/// **Apply** a peer's [`PurgeBundle`]. The receiver trusts nothing the sender
/// says: it re-verifies the notice against its OWN trust root at `now`
/// ([`verify_purge_authorisation`]), requires the ids to be well-formed,
/// sorted and unique, re-derives the digest and the per-table counts from
/// them, and only then records the header ([`origin::REPLICATED`]) and the
/// tombstones. Nothing is deleted: this node's own [`purge_finalize`] does
/// that after its own settle.
///
/// # Errors
///
/// [`token::UNAUTHORISED`], [`token::SELECTION_MALFORMED`],
/// [`token::SELECTION_DIGEST_MISMATCH`], [`token::SELECTION_COUNT_MISMATCH`];
/// directory writes.
pub async fn apply_replicated_purge<F>(
    directory: &F,
    bundle: &PurgeBundle,
    receiver_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ApplyPurgeOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (terms, _signers) = verify_purge_authorisation(directory, &bundle.notice, now).await?;
    let mut records = Vec::with_capacity(bundle.record_ids.len());
    for (i, id) in bundle.record_ids.iter().enumerate() {
        let mut r = parse_record_id(id)?;
        r.derived_from = bundle
            .derived_from
            .get(i)
            .filter(|s| !s.is_empty())
            .cloned();
        records.push(r);
    }
    if bundle.record_ids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(refused(
            token::SELECTION_MALFORMED,
            serde_json::json!({
                "notice_id": terms.notice_id,
                "reason": "the bundle's record ids are not sorted and unique",
            }),
        ));
    }
    let digest = selection_digest(&bundle.record_ids);
    if digest != terms.selection_digest {
        return Err(refused(
            token::SELECTION_DIGEST_MISMATCH,
            serde_json::json!({
                "notice_id": terms.notice_id,
                "expected": terms.selection_digest,
                "found": digest,
            }),
        ));
    }
    let resolved = ResolvedSelection {
        records: records.clone(),
        ..ResolvedSelection::default()
    };
    let live = resolved.counts();
    let tables: BTreeSet<&String> = live.keys().chain(terms.selection_counts.keys()).collect();
    for table in tables {
        let expected = terms.selection_counts.get(table).copied().unwrap_or(0);
        let found = live.get(table).copied().unwrap_or(0);
        if expected != found {
            return Err(refused(
                token::SELECTION_COUNT_MISMATCH,
                serde_json::json!({
                    "notice_id": terms.notice_id,
                    "table": table,
                    "expected": expected,
                    "found": found,
                }),
            ));
        }
    }
    let notice_jcs = String::from_utf8(notice_signing_bytes(&bundle.notice.envelope)?)
        .map_err(|e| Error::Backend(format!("notice JCS is not UTF-8: {e}")))?;
    let cosignatures_json = serde_json::to_string(&bundle.notice.cosignatures)
        .map_err(|e| Error::Backend(format!("cosignatures encode: {e}")))?;
    directory
        .purge_put_execution(&PurgeExecution {
            notice_id: terms.notice_id.clone(),
            selection_digest: digest,
            claimant_key_id: terms.claimant_key_id,
            legal_basis: STEWARD_PURGE_BASIS.to_owned(),
            record_count: records.len() as u64,
            notice_jcs,
            cosignatures_json,
            executed_by: receiver_key_id.to_owned(),
            origin: origin::REPLICATED.to_owned(),
            executed_at: now,
            admitted_at: now,
            finalized_at: None,
        })
        .await?;
    let (mut tombstoned, mut already) = (0u64, 0u64);
    for (i, r) in records.iter().enumerate() {
        if directory
            .purge_put_tombstone(&PurgeTombstone {
                notice_id: terms.notice_id.clone(),
                ordinal: i as u64,
                plane: r.plane,
                record_ref: r.id.clone(),
                derived_from: r.derived_from.clone(),
            })
            .await?
        {
            tombstoned += 1;
        } else {
            already += 1;
        }
    }
    Ok(ApplyPurgeOutcome {
        notice_id: terms.notice_id,
        tombstoned,
        already_tombstoned: already,
    })
}

// ── the admission gates a tombstone feeds ──────────────────────────────────

/// **A tombstoned record is refused at admission** ([`token::TOMBSTONED`]):
/// the tombstone is what keeps a replica holding the row from bringing it
/// back after the hard delete (CC 3.2 T4, "valid until revoked — by
/// tombstone").
///
/// # Errors
///
/// [`token::TOMBSTONED`]; the lookup's read error.
pub async fn refuse_if_tombstoned<F>(
    directory: &F,
    plane: PurgePlane,
    record_ref: &str,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    match directory.purge_tombstoned(plane.as_str(), record_ref).await {
        Ok(Some(notice_id)) => Err(refused(
            token::TOMBSTONED,
            serde_json::json!({
                "record_id": format!("{}:{record_ref}", plane.as_str()),
                "notice_id": notice_id,
            }),
        )),
        Ok(None) | Err(Error::Unsupported { .. }) => Ok(()),
        Err(e) => Err(e),
    }
}

/// The attestation door's gate: the row's id on the claims plane.
///
/// # Errors
///
/// See [`refuse_if_tombstoned`].
pub async fn refuse_if_tombstoned_attestation<F>(
    directory: &F,
    row: &Attestation,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    refuse_if_tombstoned(directory, PurgePlane::Attestation, &row.attestation_id).await
}

// ── #1040: the mock-run trace refusal (CC 3.1.5, CIRISConstitution#166) ──

/// CIRISConstitution#166 (rc8@9ce73e6) — the refusal token for a trace whose
/// signed `run_kind` is `mock`.
pub const TRACE_RUN_KIND_MOCK: &str = "trace_run_kind_mock";

/// The `run_kind` value a mock-LLM run declares (closed vocabulary
/// `production | qa | battery | mock`, CC 3.1.5).
pub const RUN_KIND_MOCK: &str = "mock";

/// A trace JSON's `run_kind` member, if it carries one. Pure. Traces carry it
/// from CIRISAgent#1249's schema bump; until then it is absent and nothing is
/// refused on this ground.
#[must_use]
pub fn trace_run_kind(trace: &serde_json::Value) -> Option<&str> {
    trace.get("run_kind").and_then(serde_json::Value::as_str)
}

/// CIRISConstitution#166 — the FEDERATION-tier attestation gate: a
/// `trace:complete:v1` attestation whose embedded trace declares `run_kind`
/// `mock` is refused ([`TRACE_RUN_KIND_MOCK`]). A local-tier row is untouched
/// (a node may keep its own QA traces). Pure.
///
/// # Errors
///
/// [`Error::PurgeRefused`] with [`TRACE_RUN_KIND_MOCK`].
pub fn refuse_mock_trace_attestation(row: &Attestation) -> Result<(), Error> {
    if row.tier != super::types::attestation_tier::FEDERATION {
        return Ok(());
    }
    if super::admission::envelope_dimension(&row.attestation_envelope)
        != Some(crate::ingest::TRACE_ATTESTATION_DIMENSION)
    {
        return Ok(());
    }
    match row
        .attestation_envelope
        .get("trace")
        .and_then(trace_run_kind)
    {
        Some(RUN_KIND_MOCK) => Err(refused(
            TRACE_RUN_KIND_MOCK,
            serde_json::json!({
                "attestation_id": row.attestation_id,
                "run_kind": RUN_KIND_MOCK,
                "reason": "a mock run attests nothing about any agent; the federation tier \
                           refuses it (CC 3.1.5, CIRISConstitution#166)",
            }),
        )),
        _ => Ok(()),
    }
}
