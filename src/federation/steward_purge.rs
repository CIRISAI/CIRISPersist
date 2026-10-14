//! v54.1.0 (CIRISPersist#1046, CIRISConstitution#165, CSD-108) — **the generic
//! steward purge door.**
//!
//! `evict_actor` / `evict_blob` (v3.5.0, v47.2.0) purge ONE plane — the bytes —
//! for one actor or one sha. This door extends that shape to any row
//! selection, authorised under GLOBAL TRUST-ROOT MODERATION, with an evidence
//! ledger. The constitutional reading is CIRISConstitution#165 as landed at
//! **rc8@8c8f536** (CC 2.4.1.1, CC 3.3.2, CC 4.5.3):
//!
//! 1. **Authorisation** is a cosigned `takedown_notice` (CC 3.3.2 shape) with
//!    the closed-set basis [`STEWARD_PURGE_BASIS`], `claimant_key_id` = the
//!    trust root's `community_key_id`, cosigned by distinct SEATS of the held
//!    root and counted under that root's own `consensus_protocol`
//!    ([`trust_root_cosigners_over`](super::canonical_community::trust_root_cosigners_over)),
//!    with `content_sha256` = the **selection digest**: SHA-256 over the JCS
//!    array of sorted, unique `"plane:id"` strings naming every purged
//!    record, derived included — a record is named by its plane identifier
//!    (`attestation_id`, `trace_id`, bytes by their sha256), never by content
//!    ([`selection_digest`]). An OPTIONAL `selection_counts` `{table: count}`
//!    lets the door refuse a drifted selection
//!    ([`token::SELECTION_COUNT_MISMATCH`]).
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
//!    [`purge_finalize`], after the settle: a stated dwell of `W` = 72 h
//!    after the tombstone ([`PURGE_SETTLE_DWELL_SECS`]), never a peer
//!    acknowledgement ([`token::NOT_SETTLED`]).
//! 5. **Reach**: never a key (no key plane; key retirement is
//!    `key:revocation`, a separate act) and never the accountability record
//!    ([`ACCOUNTABILITY_RECORD_PREFIXES`]). A purge binds only nodes rooted at
//!    the same trust root: it is not global erasure (CC 3.2 T3, 4.2.1).
//! 6. **INTERIM — no human subject** until the notice is an admitted row a
//!    `reconsideration:{grounds}` can target (CC 4.5.5; the
//!    `takedown_notice:{basis}:v1` row arrives with the rc8 vendor): every
//!    selection is checked per record by [`human_subject_records`], fail
//!    closed ([`token::HUMAN_SUBJECT_PENDING_NOTICE_ROW`]). Retired when the
//!    row lands.
//!
//! The door is inert without the operator's go: nothing runs until a purge
//! is explicitly requested on a notice the trust root's quorum cosigned.
//!
//! Derived rows follow the reason: a `scores` row whose `evidence_refs`
//! resolve to a purged record (a trace id, a trace attestation id, an
//! attestation id), a trace's own `trace:complete:v1` attestation, and the
//! bytes a purged holding claim holds are in the SAME selection, digest and
//! ledger, transitively. The dry run's sample is the first 20 ids in JCS
//! order, a view of the ledger. `purge_notice_unknown`,
//! `purge_selection_malformed` and `purge_execution_incomplete` are
//! persist-local tokens; the other six are in the CC registry.
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
    /// One record's retraction is not admissible: the purge ABORTS with
    /// nothing written — whole or not at all (CC 4.5.3). Body:
    /// `{record_id, plane, index, total, reason}`.
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
    /// INTERIM (CIRISConstitution rc8@8c8f536, CC session 2026-10-10): until
    /// the notice is an admitted row a `reconsideration:{grounds}` can target
    /// (CC 4.5.5, the `takedown_notice:{basis}:v1` family, which arrives with
    /// the rc8 vendor), a purge refuses a selection holding any record whose
    /// subject is a person, or cannot be shown not to be
    /// ([`human_subject_records`]). Persist-local. Body: `{records: [{record_id,
    /// subject, reason}]}`. Retired when the notice row lands.
    pub const HUMAN_SUBJECT_PENDING_NOTICE_ROW: &str = "purge_human_subject_pending_notice_row";
    /// v54.1.0 (Codex on PR #1057) — `purge_finalize` or the bundle serve
    /// read found an execution header whose stored tombstones are not its
    /// whole declared `record_count`. The header and its tombstones are one
    /// transaction ([`purge_put_execution`](super::FederationDirectory::purge_put_execution)),
    /// so this is a store that lost rows, never a state the door writes;
    /// re-running `purge_rows` (or re-applying the bundle) with the same
    /// notice completes it. Persist-local. Body: `{notice_id, record_count,
    /// tombstones}`.
    pub const EXECUTION_INCOMPLETE: &str = "purge_execution_incomplete";
    /// v55.0.0 (CIRISEdge v55) — bytes a tombstone withholds
    /// ([`purge_withheld`](super::purge_withheld)): the ONE token for "taken
    /// down", whether a byte door refuses them as
    /// [`BlobError::Purged`](crate::federation::BlobError::Purged) (whose
    /// `kind()` IS this constant) or a federation-plane door (the custody
    /// report's `here`) as [`Error::PurgeRefused`](crate::federation::Error::PurgeRefused).
    /// Body (the federation form): `{sha256_hex, notice_id, retryable: false}`.
    pub const BLOB_PURGED: &str = "blob_purged";

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
        HUMAN_SUBJECT_PENDING_NOTICE_ROW,
        EXECUTION_INCOMPLETE,
        BLOB_PURGED,
    ];
}

/// v55.0.0 (CIRISPersist#1055, from CIRISEdge's adopt of v54.1) — the closed
/// set of `reason` tokens a [`token::UNAUTHORISED`] body carries, so an adopter
/// maps an ORDERING GAP (retryable, capped) apart from a VERDICT (terminal)
/// without reading prose. The body is `{notice_id, reason, retryable,
/// detail}`: `reason` one of these, `retryable` = [`is_retryable`]`(reason)`,
/// `detail` the prose (before v55.0.0 the prose was `reason`).
///
/// A replicated bundle is judged against the receiver's OWN trust root: a
/// receiver that does not hold the claimant root's row (or a cosigner's key
/// record) YET refuses it, and the same bundle authorises once that row
/// lands. That is the gap; everything else is a verdict on the bytes or on
/// the root as this node holds it.
pub mod unauthorised_reason {
    /// No community row at the claimant id: the trust root is not held YET.
    /// **Retryable.**
    pub const ROOT_NOT_HELD: &str = "root_not_held";
    /// A row is held at the claimant id but does not root (its chain is not
    /// held whole, or it never passed the accord door). **Retryable**: an
    /// accord birth replaces a row that does not root.
    pub const ROOT_NOT_ROOTED: &str = "root_not_rooted";
    /// A cosigning seat's key record is not held YET. **Retryable.**
    pub const COSIGNER_KEY_NOT_HELD: &str = "cosigner_key_not_held";
    /// The notice is asserted beyond the clock-skew bound in this node's
    /// future: it authorises once this node's clock reaches it.
    /// **Retryable.**
    pub const NOT_YET_VALID: &str = "not_yet_valid";
    /// The held trust root is stalled (CC 3.2 T7): valid but non-admitting.
    /// Terminal.
    pub const STALLED: &str = "stalled";
    /// The notice's window has closed. Terminal.
    pub const EXPIRED: &str = "expired";
    /// A cosignature is not a seat on the held trust root. Terminal.
    pub const NOT_A_SEAT: &str = "not_a_seat";
    /// A seat signed twice. Terminal.
    pub const DUPLICATE_COSIGNER: &str = "duplicate_cosigner";
    /// A cosignature does not verify over the notice. Terminal.
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    /// The notice carries no cosignature. Terminal.
    pub const NO_COSIGNATURE: &str = "no_cosignature";
    /// The verified seats do not meet the root's `consensus_protocol`.
    /// Terminal.
    pub const QUORUM_NOT_MET: &str = "quorum_not_met";
    /// The root's `consensus_protocol` cannot be evaluated. Terminal.
    pub const PROTOCOL_UNEVALUABLE: &str = "protocol_unevaluable";
    /// The notice's `legal_basis` is not `steward_purge`. Terminal.
    pub const WRONG_BASIS: &str = "wrong_basis";
    /// The notice is missing a member, carries an ill-typed one, or does not
    /// canonicalize. Terminal.
    pub const NOTICE_MALFORMED: &str = "notice_malformed";

    /// Every token.
    pub const ALL: &[&str] = &[
        ROOT_NOT_HELD,
        ROOT_NOT_ROOTED,
        COSIGNER_KEY_NOT_HELD,
        NOT_YET_VALID,
        STALLED,
        EXPIRED,
        NOT_A_SEAT,
        DUPLICATE_COSIGNER,
        SIGNATURE_INVALID,
        NO_COSIGNATURE,
        QUORUM_NOT_MET,
        PROTOCOL_UNEVALUABLE,
        WRONG_BASIS,
        NOTICE_MALFORMED,
    ];

    /// The ordering gaps: a later row (or this node's clock) can turn the
    /// refusal into an authorisation, so a sender re-offers with a cap.
    pub const RETRYABLE: &[&str] = &[
        ROOT_NOT_HELD,
        ROOT_NOT_ROOTED,
        COSIGNER_KEY_NOT_HELD,
        NOT_YET_VALID,
    ];

    /// Is `reason` an ordering gap?
    #[must_use]
    pub fn is_retryable(reason: &str) -> bool {
        RETRYABLE.contains(&reason)
    }
}

/// A [`token::UNAUTHORISED`] refusal with its typed reason.
fn unauthorised(notice_id: Option<&str>, reason: &'static str, detail: String) -> Error {
    let mut body = serde_json::json!({
        "reason": reason,
        "retryable": unauthorised_reason::is_retryable(reason),
        "detail": detail,
    });
    if let Some(id) = notice_id {
        body["notice_id"] = serde_json::Value::String(id.to_owned());
    }
    refused(token::UNAUTHORISED, body)
}

/// The `takedown_notice` basis that authorises a steward purge (CC 3.3.2
/// `LegalBasis::StewardPurge`, CIRISConstitution rc8@8c8f536).
pub const STEWARD_PURGE_BASIS: &str = "steward_purge";

/// The sample a dry run shows: the first N record ids in JCS order (CSD-108
/// §6 Q6). A VIEW of the ledger, which holds every id.
pub const SAMPLE_LEN: usize = 20;

/// How long after the tombstone the retraction round is taken as settled:
/// `W` = 72 h (259 200 s), the CC 2.6.7 / 4.2.6 "until everyone has heard"
/// constant (CIRISConstitution rc8@8c8f536; operator-confirmed 2026-10-09).
/// NOT the 24 h lone-holder halt fuse, which is a different thing. There is
/// no peer-acknowledgement plane: settle is this stated dwell.
/// `purge_finalize` refuses before it ([`token::NOT_SETTLED`]). ONE named
/// constant, so a different ruling is a one-line change.
pub const PURGE_SETTLE_DWELL_SECS: i64 = 259_200;

/// **The purge's clock** (Codex round 2 on PR #1057): every instant the door
/// judges by — the notice's window, the execution's `executed_at`, the settle
/// — is THIS node's system clock, read once per door call. No public surface
/// takes an instant: a caller-chosen `now` skipped the 72 h dwell (execute,
/// then finalize at `now + 72 h`) or backdated the execution. A test sets
/// [`test_clock`] instead; outside `cfg(test)` there is no seam.
pub(crate) fn purge_clock() -> chrono::DateTime<chrono::Utc> {
    #[cfg(test)]
    if let Some(at) = test_clock::get() {
        return at;
    }
    chrono::Utc::now()
}

/// The `cfg(test)` clock seam: a thread-local instant [`purge_clock`] returns
/// while set (`#[tokio::test]` runs the door on the test's own thread).
#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;
    thread_local! {
        static AT: Cell<Option<chrono::DateTime<chrono::Utc>>> = const { Cell::new(None) };
    }
    /// Pin the purge clock to `at` (`None`: the system clock).
    pub(crate) fn set(at: Option<chrono::DateTime<chrono::Utc>>) {
        AT.with(|c| c.set(at));
    }
    pub(super) fn get() -> Option<chrono::DateTime<chrono::Utc>> {
        AT.with(Cell::get)
    }
}

/// The model id the agent's mock LLM reports (CIRISPersist#1040:
/// `ciris_adapters/mock_llm`). It is what identifies the mock traces already
/// held (they predate `run_kind`, CIRISAgent#1249), so the purge class keys
/// on it; ADMISSION keys on the signed `run_kind` ([`TRACE_RUN_KIND_MOCK`]).
pub const MOCK_LLM_MODEL: &str = "mock-model";

/// How a projection of a stored attestation leaves with the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionRemoval {
    /// `purge_attestation_projections` deletes its rows (every backend, from
    /// THIS list: the SQL backends iterate it).
    Helper,
    /// A foreign key `ON DELETE CASCADE` to `federation_attestations`.
    ForeignKeyCascade,
    /// A foreign key `ON DELETE SET NULL` to `federation_attestations`: the
    /// projection row is the key's, and only its link to the attestation goes.
    ForeignKeySetNull,
}

/// v54.1.0 (Codex round 4 on PR #1057) — **every table a stored attestation
/// projects into, keyed by the attestation id, and how the hard delete removes
/// it** (`table`, `column`, removal). `purge_attestation_projections` (run by
/// `purge_finalize` and by the reset/reaper door) deletes every
/// [`ProjectionRemoval::Helper`] row FROM THIS LIST, so a table added here is
/// purged on every SQL backend with no second edit; the memory backend mirrors
/// each by hand. The from-disk gate
/// `every_attestation_keyed_table_is_a_classified_projection` reads the
/// migrated schema and fails on any table with an `*attestation_id` column that
/// is in neither this list nor [`INDEPENDENT_ATTESTATION_ID_TABLES`].
///
/// `signed_wire_index` is keyed by `record_key`, not an id column, and is
/// deleted by the helper beside this list.
pub const ATTESTATION_PROJECTIONS: &[(&str, &str, ProjectionRemoval)] = &[
    (
        "attestation_subjects",
        "attestation_id",
        ProjectionRemoval::ForeignKeyCascade,
    ),
    (
        "consent_peer_set",
        "source_attestation_id",
        ProjectionRemoval::Helper,
    ),
    // Codex round 4: a steward-scoped grant outlived its hard delete here, and
    // `consent_peers_by_principals` kept authorising the peer.
    (
        "consent_peer_set_for",
        "source_attestation_id",
        ProjectionRemoval::Helper,
    ),
    (
        "blob_renditions",
        "source_attestation_id",
        ProjectionRemoval::Helper,
    ),
    (
        "federation_withdraws_admission_depths",
        "attestation_id",
        ProjectionRemoval::Helper,
    ),
    (
        "federation_trust_direction_held",
        "attestation_id",
        ProjectionRemoval::Helper,
    ),
    (
        "federation_key_grant_pending",
        "attestation_id",
        ProjectionRemoval::Helper,
    ),
    (
        "identity_canonical_binding",
        "binding_attestation_id",
        ProjectionRemoval::ForeignKeySetNull,
    ),
];

/// Tables with an `*attestation_id` column that are NOT projections of a
/// `federation_attestations` row: their own signed records whose identifier
/// is spelled `attestation_id` (`table`, why).
pub const INDEPENDENT_ATTESTATION_ID_TABLES: &[(&str, &str)] = &[
    ("federation_attestations", "the row itself"),
    (
        "federation_organizations",
        "its own signed organization record; the id is that record's",
    ),
    (
        "federation_org_memberships",
        "its own signed membership record; the id is that record's",
    ),
    (
        "federation_partner_records",
        "its own signed partner record; the id is that record's",
    ),
    (
        "cirisnode_promotion_attestations",
        "the cirisnode plane's own promotion records, written by src/cirisnode",
    ),
];

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
/// any keys"; CC 2.4.1.1 at CIRISConstitution rc8@8c8f536 — the root has no
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
    /// signed, the bytes its holding claims name (v55.0.0: its
    /// `custody:ack:v1` `here` rows, CIRISPersist#989), and everything
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
    holding_claim_sha: Option<String>,
}

impl RowFacts {
    fn of(row: &Attestation) -> Self {
        // v55.0.0 (CIRISPersist#989) — the holding claim is `custody:ack:v1`
        // `here`; a `none` report names bytes the signer does not hold.
        let holding_claim_sha = super::custody_ack::parse_custody_ack(row)
            .ok()
            .flatten()
            .filter(|a| a.state == super::custody_ack::CustodyState::Here)
            .map(|a| a.blob_sha256_hex)
            .filter(|s| is_hex64(s));
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
            holding_claim_sha,
        }
    }
}

use super::migration::accountability_record_family as accountability_family;
/// CLM-accountability-record-unpurgeable — the five families, now ONE list
/// both purge doors read (CIRISPersist#1054):
/// [`migration::ACCOUNTABILITY_RECORD_PREFIXES`](super::migration::ACCOUNTABILITY_RECORD_PREFIXES).
pub use super::migration::ACCOUNTABILITY_RECORD_PREFIXES;

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
/// **Whole or not at all** (CC 4.5.3, CIRISConstitution rc8@8c8f536: "A
/// retraction the door cannot admit aborts the purge … a purge is whole or
/// not at all, never a half-emptied selection"). The selection IS the id list
/// the notice's digest names. A class's withheld rows are not in that list:
/// the dry run surfaces them ([`PurgeDryRun::withheld`]) BEFORE the quorum
/// cosigns, so the quorum authorises exactly the admissible rows, and the
/// purge is whole for what it names. Nothing the digest names is ever
/// skipped: an id list holding an inadmissible record (an explicit list, or
/// a selection that drifted) aborts with nothing written.
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
                let sha = facts.get(&r.id)?.holding_claim_sha.clone()?;
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
        // Codex round 2 on PR #1057 — derivatives follow their evidence OUT
        // as they followed it in: a record selected only because it derives
        // from a withheld one is withheld too, transitively (a score over a
        // score over the withheld row). A score that cites another record
        // still selected stays, re-pointed at it.
        withhold_orphaned_derivatives(&mut records, &facts, &mut withheld);
    }
    withheld.sort_by(|a, b| a.record_id.cmp(&b.record_id));
    Ok(ResolvedSelection {
        records: records.into_values().collect(),
        withheld,
        inadmissible,
    })
}

/// Withhold, to a fixpoint, every DERIVED record whose evidence left the
/// selection: its `derived_from` record is gone and (for a score) none of its
/// `evidence_refs` names a record still selected. A score whose
/// `derived_from` left but which cites another selected record stays, its
/// `derived_from` re-pointed at that one. A record a class selected on its own
/// facts (`derived_from` = `None`) is never touched here.
fn withhold_orphaned_derivatives(
    records: &mut BTreeMap<String, PurgeRecord>,
    facts: &BTreeMap<String, RowFacts>,
    withheld: &mut Vec<Withheld>,
) {
    loop {
        let evidence: BTreeMap<String, String> = records
            .values()
            .filter(|r| r.plane != PurgePlane::Blob)
            .map(|r| (r.id.clone(), r.record_id()))
            .collect();
        let mut orphans: Vec<(String, String)> = Vec::new();
        let mut repoint: Vec<(String, String)> = Vec::new();
        for (key, r) in records.iter() {
            let Some(from) = &r.derived_from else {
                continue;
            };
            if records.contains_key(from) {
                continue;
            }
            let other = (r.plane == PurgePlane::Attestation)
                .then(|| facts.get(&r.id))
                .flatten()
                .filter(|f| f.is_scores)
                .and_then(|f| f.refs.iter().find_map(|e| evidence.get(e)));
            match other {
                Some(still) => repoint.push((key.clone(), still.clone())),
                None => orphans.push((key.clone(), from.clone())),
            }
        }
        for (key, still) in repoint {
            if let Some(r) = records.get_mut(&key) {
                r.derived_from = Some(still);
            }
        }
        if orphans.is_empty() {
            return;
        }
        for (record_id, from) in orphans {
            records.remove(&record_id);
            withheld.push(Withheld {
                record_id,
                reason: format!(
                    "derived from {from}, which is not in the selection: a derivative leaves with \
                     its evidence"
                ),
            });
        }
    }
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

// ── the interim no-human-subject gate ──────────────────────────────────────

/// One record the interim gate refuses, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanSubject {
    /// The record id.
    pub record_id: String,
    /// The subject key that is a person, or that could not be resolved (empty
    /// when the record's subjects themselves could not be read).
    pub subject: String,
    /// Why.
    pub reason: String,
}

/// The subjects of an attestation: its `subject_key_ids` and its
/// `attested_key_id` (the key the row is ABOUT). Not its author: an
/// attestation's subject is who it is about.
fn attestation_subjects(row: &Attestation) -> BTreeSet<String> {
    row.subject_key_ids
        .iter()
        .chain(std::iter::once(&row.attested_key_id))
        .filter(|k| !k.is_empty())
        .cloned()
        .collect()
}

/// **INTERIM — which records of `records` have a human subject?** CC session
/// 2026-10-10 (CIRISConstitution rc8@8c8f536): until the notice is an
/// admitted row that a `reconsideration:{grounds}` can target (CC 4.5.5), a
/// purge may touch only records with NO HUMAN SUBJECT, so the redress path
/// exists before the act. Per record:
///
/// - an **attestation**: its `subject_key_ids` and `attested_key_id`;
/// - a **trace**: the author and subjects of its own `trace:complete:v1`
///   attestation (every held trace has one, #473/#478) — the signing agent;
/// - a **blob**: the subjects of EVERY row held here that holds or binds it
///   (each `scores` row whose `evidence_refs` cite it — the holding claims,
///   `custody:ack:v1`, among them since v55.0.0), every tier, resolved LOCALLY
///   ([`blob_binding_subjects`]). Never the record's `derived_from`: on a
///   replicated bundle that is the sender's metadata, and a peer could point a
///   person's blob at a harmless row (Codex round 2 on PR #1057). A blob no
///   row held here holds or binds is not proven non-human and is refused, at
///   the receiver too.
///
/// - and, for a [`PurgeSelection::ByActor`], the ACTOR is a subject of every
///   record the selection holds (`parties`): a by-actor purge is about them.
///   A bundle does not carry its selection, so the receiver reads the
///   per-record subjects only.
///
/// A subject is a person when its key record's `identity_type` names
/// `user`. **Fail closed**: a subject key this node cannot resolve, a trace
/// with no own attestation, a blob nothing held here holds or binds, or an
/// attestation not held are NOT proven non-human, and are refused.
/// `skip_unheld` is the receiver's reading: it judges only what it holds.
///
/// # Errors
///
/// Directory reads.
pub async fn human_subject_records<F>(
    directory: &F,
    records: &[PurgeRecord],
    parties: &BTreeSet<String>,
    skip_unheld: bool,
) -> Result<Vec<HumanSubject>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    let mut kinds: BTreeMap<String, Option<bool>> = BTreeMap::new();
    let blob_shas: BTreeSet<String> = records
        .iter()
        .filter(|r| r.plane == PurgePlane::Blob)
        .map(|r| r.id.clone())
        .collect();
    let mut blob_subjects = blob_binding_subjects(directory, &blob_shas).await?;
    for record in records {
        let unresolved = |reason: &str| HumanSubject {
            record_id: record.record_id(),
            subject: String::new(),
            reason: reason.to_owned(),
        };
        let mut subjects = match record.plane {
            PurgePlane::Blob => match blob_subjects.remove(&record.id) {
                Some(subjects) => subjects,
                None => {
                    out.push(unresolved(
                        "no row held here holds or binds this blob: its subject cannot be read, \
                         so it is not proven non-human",
                    ));
                    continue;
                }
            },
            PurgePlane::Attestation | PurgePlane::Trace => {
                let row_id = if record.plane == PurgePlane::Trace {
                    crate::ingest::trace_attestation_id(&record.id)
                } else {
                    record.id.clone()
                };
                let Some(row) = directory.get_attestation(&row_id).await? else {
                    if !skip_unheld {
                        out.push(unresolved(
                            "the record's subject row is not held here: not proven non-human",
                        ));
                    }
                    continue;
                };
                let mut subjects = attestation_subjects(&row);
                if record.plane == PurgePlane::Trace {
                    subjects.insert(row.attesting_key_id.clone());
                }
                subjects
            }
        };
        subjects.extend(parties.iter().cloned());
        for subject in subjects {
            let human = match kinds.get(&subject) {
                Some(v) => *v,
                None => {
                    let v = directory
                        .lookup_public_key(&subject)
                        .await?
                        .map(|k| identity_type_is_person(&k.identity_type));
                    kinds.insert(subject.clone(), v);
                    v
                }
            };
            let reason = match human {
                Some(false) => continue,
                Some(true) => "the subject is a person (identity_type user)",
                None => "the subject key does not resolve here: not proven non-human",
            };
            out.push(HumanSubject {
                record_id: record.record_id(),
                subject,
                reason: reason.to_owned(),
            });
        }
    }
    Ok(out)
}

/// The subjects of the rows held HERE that hold or bind each blob in `shas`
/// (64-hex sha256): every `scores` row whose `evidence_refs` cite it, every
/// tier, in one attestation scan. v55.0.0 (CIRISPersist#989) — the holding
/// claim is a `scores` row on `custody:ack:v1` citing its blob, so it is one
/// of them; a retired `holds_bytes` row a node still holds is read by no fold
/// and names nothing here (a blob only it named is not proven non-human and
/// is refused, fail-closed). A sha no held row names is absent from the map.
/// Local state only: never a bundle's `derived_from`.
///
/// # Errors
///
/// The scan's.
async fn blob_binding_subjects<F>(
    directory: &F,
    shas: &BTreeSet<String>,
) -> Result<BTreeMap<String, BTreeSet<String>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if shas.is_empty() {
        return Ok(out);
    }
    scan_attestations(directory, |row| {
        let named: Vec<&String> = if row.attestation_type == attestation_type::SCORES {
            evidence_refs(&row.attestation_envelope)
                .iter()
                .filter_map(|e| shas.get(e.as_str()))
                .collect()
        } else {
            Vec::new()
        };
        for sha in named {
            out.entry(sha.clone())
                .or_default()
                .extend(attestation_subjects(&row));
        }
    })
    .await?;
    Ok(out)
}

/// The interim gate as a refusal: [`token::HUMAN_SUBJECT_PENDING_NOTICE_ROW`]
/// naming EVERY offending record, or `Ok`.
async fn refuse_human_subjects<F>(
    directory: &F,
    records: &[PurgeRecord],
    parties: &BTreeSet<String>,
    skip_unheld: bool,
    notice_id: Option<&str>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let found = human_subject_records(directory, records, parties, skip_unheld).await?;
    if found.is_empty() {
        return Ok(());
    }
    Err(refused(
        token::HUMAN_SUBJECT_PENDING_NOTICE_ROW,
        serde_json::json!({
            "notice_id": notice_id,
            "records": found,
            "reason": "until the notice is an admitted row a reconsideration can target (CC \
                       4.5.5; the takedown_notice row arrives with the rc8 vendor), a purge \
                       touches no record with a human subject",
        }),
    ))
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
    // INTERIM: the operator sees every human-subject record before anyone
    // cosigns.
    refuse_human_subjects(
        directory,
        &resolved.records,
        &selection.parties(),
        false,
        None,
    )
    .await?;
    let ids = resolved
        .records
        .iter()
        .map(PurgeRecord::record_id)
        .collect::<Vec<_>>();
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
    /// Per-table counts the notice authorises, when it carries the OPTIONAL
    /// `selection_counts` member (CC 3.3.2, CIRISConstitution rc8@8c8f536).
    /// Absent, the digest alone binds the selection.
    pub selection_counts: Option<BTreeMap<String, u64>>,
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
        unauthorised(
            None,
            unauthorised_reason::NOTICE_MALFORMED,
            format!("the notice envelope does not canonicalize: {e}"),
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
    let unauth = |detail: String| {
        unauthorised(
            Some(&notice_id),
            unauthorised_reason::NOTICE_MALFORMED,
            detail,
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
        return Err(unauthorised(
            Some(&notice_id),
            unauthorised_reason::WRONG_BASIS,
            format!(
                "legal_basis {basis:?} does not authorise a steward purge (only \
             `{STEWARD_PURGE_BASIS}` does, CIRISConstitution#165)"
            ),
        ));
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
    let selection_counts: Option<BTreeMap<String, u64>> = match envelope.get("selection_counts") {
        None => None,
        Some(v) => Some(serde_json::from_value(v.clone()).map_err(|_| {
            unauth("selection_counts, when present, must be an object of table -> count".into())
        })?),
    };
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

/// **The authorisation gate.** The notice's shape, its window at
/// [`purge_clock`], and
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
) -> Result<(NoticeTerms, BTreeSet<String>), Error>
where
    F: FederationDirectory + ?Sized,
{
    authorise_at(directory, notice, purge_clock()).await
}

/// [`verify_purge_authorisation`] at the instant the calling door read from
/// [`purge_clock`] (one reading per door call).
async fn authorise_at<F>(
    directory: &F,
    notice: &StewardPurgeNotice,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(NoticeTerms, BTreeSet<String>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let terms = notice_terms(&notice.envelope)?;
    let unauth =
        |reason: &'static str, detail: String| unauthorised(Some(&terms.notice_id), reason, detail);
    let skew = super::admission::DEFAULT_MAX_TOUCH_SKEW;
    if terms.asserted_at > now + skew {
        return Err(unauth(
            unauthorised_reason::NOT_YET_VALID,
            format!(
                "the notice is asserted at {}, in the future",
                terms.asserted_at.to_rfc3339()
            ),
        ));
    }
    if terms.expires_at <= now {
        return Err(unauth(
            unauthorised_reason::EXPIRED,
            format!("the notice expired at {}", terms.expires_at.to_rfc3339()),
        ));
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
        Err((reason, detail)) => Err(unauth(reason, detail)),
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
    /// takedown and purge (CIRISConstitution rc8@8c8f536, CC 4.5.3): the
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

/// The store door's own check on a header and its tombstone set: exactly
/// `record_count` tombstones, every one citing this notice. Every backend's
/// `purge_put_execution` asks it before writing, so no backend can store a
/// header with a partial set by being handed one.
///
/// # Errors
///
/// `Error::InvalidArgument` naming the mismatch.
pub(crate) fn check_purge_put_set(
    execution: &PurgeExecution,
    tombstones: &[PurgeTombstone],
) -> Result<(), Error> {
    if tombstones.len() as u64 != execution.record_count {
        return Err(Error::InvalidArgument(format!(
            "purge_put_execution: notice {} declares {} records but {} tombstones were given",
            execution.notice_id,
            execution.record_count,
            tombstones.len()
        )));
    }
    if let Some(t) = tombstones
        .iter()
        .find(|t| t.notice_id != execution.notice_id)
    {
        return Err(Error::InvalidArgument(format!(
            "purge_put_execution: tombstone {} cites notice {}, not {}",
            t.record_id(),
            t.notice_id,
            execution.notice_id
        )));
    }
    Ok(())
}

/// What one [`purge_put_execution`](super::FederationDirectory::purge_put_execution)
/// recorded: the header and its WHOLE tombstone set are one transaction
/// (Codex on PR #1057), so a header is never durable with part of its
/// `record_count`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgePutOutcome {
    /// `true` when the header was inserted, `false` when it was already held.
    pub header_inserted: bool,
    /// Per tombstone, in the order given: `true` when inserted, `false` when
    /// the notice already held it.
    pub tombstones_inserted: Vec<bool>,
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

/// The OPTIONAL count check: when the notice carries `selection_counts`, the
/// live per-table counts must equal them exactly
/// ([`token::SELECTION_COUNT_MISMATCH`] `{table, expected, found}`).
fn check_counts(terms: &NoticeTerms, live: &BTreeMap<String, u64>) -> Result<(), Error> {
    let Some(authorised) = &terms.selection_counts else {
        return Ok(());
    };
    let tables: BTreeSet<&String> = live.keys().chain(authorised.keys()).collect();
    for table in tables {
        let expected = authorised.get(table).copied().unwrap_or(0);
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
    Ok(())
}

/// **`purge_rows(selection, notice)`** — the door, at [`purge_clock`].
///
/// In order, each a typed refusal and none an override:
/// 1. the notice authorises ([`verify_purge_authorisation`]) —
///    [`token::UNAUTHORISED`];
/// 2. the LIVE selection's per-table counts equal the notice's —
///    [`token::SELECTION_COUNT_MISMATCH`] `{table, expected, found}`;
/// 3. the live selection's digest is the notice's —
///    [`token::SELECTION_DIGEST_MISMATCH`];
/// 4. every record's retraction is judged BEFORE anything is written; an
///    inadmissible one ABORTS the purge —
///    [`token::RETRACTION_INADMISSIBLE`] `{record_id, plane, index, total}` —
///    with nothing written (whole or not at all, CC 4.5.3, CIRISConstitution
///    rc8@8c8f536);
/// 5. the header and every tombstone, in JCS order, are recorded in ONE
///    transaction (idempotent on the notice id; Codex on PR #1057): a crash
///    leaves either nothing or the whole set, and a tombstone is never
///    written twice.
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
) -> Result<PurgeReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let now = purge_clock();
    let (terms, signers) = authorise_at(directory, notice, now).await?;
    let resolved = resolve_selection(directory, selection).await?;
    let live = resolved.counts();
    check_counts(&terms, &live)?;
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
    // Whole or not at all (CC 4.5.3, CIRISConstitution rc8@8c8f536): every
    // retraction is judged BEFORE anything is written, so an inadmissible one
    // aborts the purge with nothing tombstoned.
    let selected_attestations: BTreeSet<String> = records
        .iter()
        .filter(|r| r.plane == PurgePlane::Attestation)
        .map(|r| r.id.clone())
        .collect();
    let parties = selection.parties();
    for (index, record) in records.iter().enumerate() {
        if let Some(reason) =
            record_inadmissible(directory, record, &selected_attestations, &parties).await?
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
    }
    // INTERIM: no human subject until the notice is a row (nothing written).
    refuse_human_subjects(directory, &records, &parties, false, Some(&terms.notice_id)).await?;
    let notice_jcs = String::from_utf8(notice_signing_bytes(&notice.envelope)?)
        .map_err(|e| Error::Backend(format!("notice JCS is not UTF-8: {e}")))?;
    let cosignatures_json = serde_json::to_string(&notice.cosignatures)
        .map_err(|e| Error::Backend(format!("cosignatures encode: {e}")))?;
    let tombstones: Vec<PurgeTombstone> = records
        .iter()
        .enumerate()
        .map(|(index, record)| PurgeTombstone {
            notice_id: terms.notice_id.clone(),
            ordinal: index as u64,
            plane: record.plane,
            record_ref: record.id.clone(),
            derived_from: record.derived_from.clone(),
        })
        .collect();
    // Codex on PR #1057: the header and every tombstone are ONE transaction,
    // so a crash or a failed write never leaves a durable header holding part
    // of its declared `record_count`. A retry after an interrupted call that
    // predates this re-sends the whole set; the store inserts what is missing.
    let put = directory
        .purge_put_execution(
            &PurgeExecution {
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
            },
            &tombstones,
        )
        .await?;
    let mut tombstoned: BTreeMap<String, u64> = BTreeMap::new();
    let mut already = 0u64;
    for (record, inserted) in records.iter().zip(&put.tombstones_inserted) {
        if *inserted {
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
    /// The header's stored tombstones are not its whole `record_count`
    /// ([`token::EXECUTION_INCOMPLETE`]): finalize and serve refuse it until
    /// a re-run of the same notice completes it.
    Incomplete,
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
    /// Record ids whose tombstone is VOID: the row the id names arrived after
    /// the tombstone and is the accountability record
    /// ([`refuse_if_tombstoned_attestation`]), so it is admitted, served and
    /// never deleted.
    pub voided: Vec<String>,
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

/// v55.0.0 (CIRISPersist#1007) — the settle is the header's BASIS's: a
/// steward purge after `W`, a duty-holder takedown per its basis (one
/// tombstone row serves both, CC 4.5.3 step 2).
fn settles_at(e: &PurgeExecution) -> chrono::DateTime<chrono::Utc> {
    super::takedown_tombstone::settles_at(e)
}

/// **Status** of an executed purge, at [`purge_clock`].
///
/// # Errors
///
/// [`token::NOTICE_UNKNOWN`]; directory reads.
pub async fn purge_status<F>(directory: &F, notice_id: &str) -> Result<PurgeStatus, Error>
where
    F: FederationDirectory + ?Sized,
{
    let now = purge_clock();
    let execution = execution_or_unknown(directory, notice_id).await?;
    let mut tombstones = BTreeMap::new();
    let held = directory.purge_tombstones_of(notice_id).await?;
    let complete = held.len() as u64 == execution.record_count;
    let mut voided = Vec::new();
    for t in held {
        *tombstones.entry(t.plane.as_str().to_owned()).or_insert(0) += 1;
        let void = match t.plane {
            PurgePlane::Attestation => held_row_voided(directory, &t.record_ref).await?,
            PurgePlane::Trace => trace_voided(directory, &t.record_ref).await?,
            PurgePlane::Blob => false,
        };
        if void {
            voided.push(t.record_id());
        }
    }
    let settles = settles_at(&execution);
    let state = if execution.finalized_at.is_some() {
        PurgeState::Finalized
    } else if !complete {
        PurgeState::Incomplete
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
        voided,
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

/// The execution's tombstones as records, refusing a header whose stored
/// tombstones are not its whole `record_count`
/// ([`token::EXECUTION_INCOMPLETE`]): finalize must not delete, and serve must
/// not replicate, part of a selection the notice signed whole.
async fn complete_tombstone_records<F>(
    directory: &F,
    execution: &PurgeExecution,
) -> Result<Vec<PurgeRecord>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let records = tombstone_records(directory, &execution.notice_id).await?;
    if records.len() as u64 != execution.record_count {
        return Err(refused(
            token::EXECUTION_INCOMPLETE,
            serde_json::json!({
                "notice_id": execution.notice_id,
                "record_count": execution.record_count,
                "tombstones": records.len(),
            }),
        ));
    }
    Ok(records)
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
    /// Tombstoned record ids NOT deleted because the tombstone is void: the
    /// row arrived after it and is the accountability record
    /// ([`refuse_if_tombstoned_attestation`]).
    #[serde(default)]
    pub voided: Vec<String>,
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
/// [`token::EXECUTION_INCOMPLETE`], [`token::RETRACTION_INADMISSIBLE`] for a blob the bytes plane would not
/// retract (or a host with no bytes plane); directory writes.
pub async fn purge_finalize<F>(
    directory: &F,
    notice_id: &str,
    bytes: Option<&dyn BytesEvictor>,
) -> Result<FinalizeReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let now = purge_clock();
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
    let records = complete_tombstone_records(directory, &e).await?;
    let total = records.len();
    for plane in PurgePlane::ALL {
        for (index, r) in records.iter().enumerate().filter(|(_, r)| r.plane == plane) {
            match plane {
                PurgePlane::Trace => {
                    // INTERIM — a trace whose signer is a person arrived after
                    // the tombstone: never deleted (the door re-asks this too).
                    if trace_voided(directory, &r.id).await? {
                        report.voided.push(r.record_id());
                        continue;
                    }
                    let (ev, calls) = directory.purge_delete_tombstoned_trace(&r.id).await?;
                    report.trace_events_deleted += ev;
                    report.trace_llm_calls_deleted += calls;
                }
                PurgePlane::Attestation => {
                    // The accountability record, and (interim) a row a person
                    // is the subject of, is never deleted, whatever tombstone
                    // names it (the delete door re-asks both).
                    if held_row_voided(directory, &r.id).await? {
                        report.voided.push(r.record_id());
                        continue;
                    }
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
/// Directory reads; a stored notice that no longer parses;
/// [`token::EXECUTION_INCOMPLETE`] for a header missing part of its tombstones.
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
        let records = complete_tombstone_records(directory, &e).await?;
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
) -> Result<ApplyPurgeOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let now = purge_clock();
    let (terms, _signers) = authorise_at(directory, &bundle.notice, now).await?;
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
    check_counts(&terms, &live)?;
    // The receiver re-asks what no notice can lift, whole or not at all: the
    // accountability record and a composer without its target. A
    // `delegates_to` is the exception: the bundle does not carry the
    // selection's parties, and the quorum's digest binds the list.
    let selected_attestations: BTreeSet<String> = records
        .iter()
        .filter(|r| r.plane == PurgePlane::Attestation)
        .map(|r| r.id.clone())
        .collect();
    for (index, record) in records.iter().enumerate() {
        if record.plane != PurgePlane::Attestation {
            continue;
        }
        let Some(row) = directory.get_attestation(&record.id).await? else {
            continue;
        };
        let facts = RowFacts::of(&row);
        let verdict = match retraction_admissible(&facts, &selected_attestations, &BTreeSet::new())
        {
            Err(_)
                if facts.accountability.is_none()
                    && facts.exclusion == Some(super::migration::ExclusionClass::Delegation) =>
            {
                Ok(())
            }
            v => v,
        };
        if let Err(reason) = verdict {
            return Err(refused(
                token::RETRACTION_INADMISSIBLE,
                serde_json::json!({
                    "notice_id": terms.notice_id,
                    "record_id": record.record_id(),
                    "plane": record.plane.as_str(),
                    "index": index,
                    "total": records.len(),
                    "reason": reason,
                }),
            ));
        }
    }
    // INTERIM: the receiver applies the same gate to what it holds.
    refuse_human_subjects(
        directory,
        &records,
        &BTreeSet::new(),
        true,
        Some(&terms.notice_id),
    )
    .await?;
    let notice_jcs = String::from_utf8(notice_signing_bytes(&bundle.notice.envelope)?)
        .map_err(|e| Error::Backend(format!("notice JCS is not UTF-8: {e}")))?;
    let cosignatures_json = serde_json::to_string(&bundle.notice.cosignatures)
        .map_err(|e| Error::Backend(format!("cosignatures encode: {e}")))?;
    let tombstones: Vec<PurgeTombstone> = records
        .iter()
        .enumerate()
        .map(|(i, r)| PurgeTombstone {
            notice_id: terms.notice_id.clone(),
            ordinal: i as u64,
            plane: r.plane,
            record_ref: r.id.clone(),
            derived_from: r.derived_from.clone(),
        })
        .collect();
    // One transaction, as at `purge_rows` (Codex on PR #1057).
    let put = directory
        .purge_put_execution(
            &PurgeExecution {
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
            },
            &tombstones,
        )
        .await?;
    let tombstoned = put.tombstones_inserted.iter().filter(|b| **b).count() as u64;
    let already = put.tombstones_inserted.len() as u64 - tombstoned;
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

/// The accountability family `row` belongs to, if any
/// (CLM-accountability-record-unpurgeable, [`ACCOUNTABILITY_RECORD_PREFIXES`]).
#[must_use]
pub fn accountability_record_of(row: &Attestation) -> Option<&'static str> {
    super::admission::envelope_dimension(&row.attestation_envelope).and_then(accountability_family)
}

/// v54.1.0 (Codex round 4 on PR #1057) — **may a blob another purge's DAG
/// walk reaches be deleted at `now`?** `true` when at least one purge that
/// tombstoned `sha256` has FINALIZED or SETTLED (its 72 h dwell passed at
/// `now`) and every OTHER purge that tombstoned it has too: a shared chunk is
/// deleted only once no purge withholding it is still inside its retraction
/// round. An unsettled parent leaves the chunk held (and withheld, I824) for
/// its own finalize.
///
/// # Errors
///
/// The lookups' read errors.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn blob_purge_settled<F>(
    directory: &F,
    sha256: &[u8; 32],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let notices = directory
        .purge_tombstone_notices(PurgePlane::Blob.as_str(), &hex::encode(sha256))
        .await?;
    if notices.is_empty() {
        return Ok(false);
    }
    for notice_id in notices {
        let Some(e) = directory.purge_execution(&notice_id).await? else {
            return Ok(false);
        };
        if e.finalized_at.is_none() && now < settles_at(&e) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// v54.1.0 (Codex round 3 on PR #1057) — **is this blob withheld by a
/// purge?**
///
/// v55.0.0 (CIRISEdge v55) — **THE canonical, host-facing predicate for
/// "this blob is taken down"**: a steward purge or a takedown on the CC 2.3
/// tombstone (a counter-notice withholding, an executed immediate removal
/// whose rows linger). Every persist door that refuses, flags or skips
/// withheld bytes asks this one function (the write floors, the read and
/// serve doors, `emit_holding_claim`, the custody report, the durability
/// deficit, `blob_custody`, the holder reads); a host deciding whether to
/// repair, replicate or advertise a blob asks it too, never a re-derivation.
/// Refusals name it with [`token::BLOB_PURGED`]. `Some(notice_id)` when a steward purge tombstoned `sha256`, or
/// when it is a sealed-DAG child and EVERY manifest it belongs to is withheld
/// (transitively: a v3 child of a purged root). The byte doors refuse it from
/// EXECUTION onward; `purge_finalize`'s hard delete still waits for the settle.
/// A chunk any un-purged manifest relates is not withheld. The purge plane
/// absent from a backend (`Unsupported`) withholds nothing.
///
/// # Errors
///
/// The lookups' read errors.
pub async fn purge_withheld<F>(directory: &F, sha256: &[u8; 32]) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // Memoized per walk: a manifest reached twice (a diamond) answers the
    // same; one still being judged (a cycle, which a sealed DAG never has)
    // counts as not withheld.
    let mut memo: BTreeMap<[u8; 32], Option<String>> = BTreeMap::new();
    purge_withheld_walk(directory, *sha256, &mut memo).await
}

fn purge_withheld_walk<'a, F>(
    directory: &'a F,
    sha256: [u8; 32],
    memo: &'a mut BTreeMap<[u8; 32], Option<String>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<String>, Error>> + Send + 'a>>
where
    F: FederationDirectory + ?Sized,
{
    Box::pin(async move {
        if let Some(known) = memo.get(&sha256) {
            return Ok(known.clone());
        }
        memo.insert(sha256, None);
        let verdict = purge_withheld_judge(directory, sha256, memo).await?;
        memo.insert(sha256, verdict.clone());
        Ok(verdict)
    })
}

async fn purge_withheld_judge<F>(
    directory: &F,
    sha256: [u8; 32],
    memo: &mut BTreeMap<[u8; 32], Option<String>>,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    {
        match directory
            .purge_tombstoned(PurgePlane::Blob.as_str(), &hex::encode(sha256))
            .await
        {
            Ok(Some(notice_id)) => return Ok(Some(notice_id)),
            Ok(None) => {}
            Err(Error::Unsupported { .. }) => return Ok(None),
            Err(e) => return Err(e),
        }
        let manifests = directory.dag_manifests_of_chunk(&sha256).await?;
        let mut first = None;
        for m in manifests {
            match purge_withheld_walk(directory, m, memo).await? {
                Some(n) => {
                    first.get_or_insert(n);
                }
                None => return Ok(None),
            }
        }
        Ok(first)
    }
}

/// v55.0.0 (CIRISPersist#1007; operator ruling, v55 slice C) — **bytes a
/// tombstone took down never come back.** Every byte write floor asks this
/// for each address it is about to store (the one-shot and chunk DAG puts,
/// the plaintext and scoped puts, the local store, the adopt, the chunk
/// floor, the incremental DAG finalize): an address a steward purge or a
/// takedown tombstoned, or a DAG child every manifest of which is, is refused
/// [`BlobError::Purged`](super::BlobError::Purged) naming the notice — the
/// read doors' own answer ([`purge_withheld`]). A peer re-pushing taken-down
/// bytes is refused at receipt; retaining them withheld would be knowing
/// possession (CC 4.5.3 step 2). The from-disk gate I797 holds every floor
/// to it.
///
/// # Errors
///
/// [`BlobError::Purged`](super::BlobError::Purged); the lookup's read error.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn refuse_tombstoned_bytes<F>(
    directory: &F,
    sha256: &[u8; 32],
) -> Result<(), super::BlobError>
where
    F: FederationDirectory + ?Sized,
{
    match purge_withheld(directory, sha256).await {
        Ok(None) => Ok(()),
        Ok(Some(notice_id)) => Err(super::BlobError::Purged {
            sha256_hex: hex::encode(sha256),
            notice_id,
        }),
        Err(e) => Err(super::BlobError::Backend(format!(
            "tombstone plane at write: {e}"
        ))),
    }
}

/// **Is a key with this `identity_type` a person?** Its comma-separated
/// roles name `user`. THE predicate the interim no-human-subject rule asks,
/// in Rust ([`human_subject_records`], the arrival gates) and, rendered from
/// the same constant, in SQL ([`person_identity_sql`]).
#[must_use]
pub fn identity_type_is_person(identity_type: &str) -> bool {
    identity_type
        .split(',')
        .any(|t| t.trim() == super::types::identity_type::USER)
}

/// [`identity_type_is_person`] as a SQL predicate over the text column
/// `column` (SQLite and Postgres): the comma list with spaces removed, fenced
/// by commas, contains `,user,`. Rendered from the constant, never retyped.
#[must_use]
pub fn person_identity_sql(column: &str) -> String {
    format!(
        "((',' || replace(COALESCE({column}, ''), ' ', '') || ',') LIKE '%,{},%')",
        super::types::identity_type::USER.replace('\'', "''")
    )
}

/// v54.1.0 (Codex round 4 on PR #1057) — "the held attestation `fa` has a
/// subject that is a person" as SQL: its `attested_key_id` or any
/// `attestation_subjects` row resolves to a key [`person_identity_sql`]
/// accepts. `prefix` is the schema prefix (`""` for SQLite, `"cirislens."`
/// for Postgres). The serve read and the delete door ask this so a
/// person-subject row that arrived after a tombstone stays served and held.
#[must_use]
pub fn person_subject_sql(fa: &str, prefix: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM {prefix}federation_keys pk \
           WHERE (pk.key_id = {fa}.attested_key_id \
                  OR pk.key_id IN (SELECT ps.subject_key_id FROM {prefix}attestation_subjects ps \
                                   WHERE ps.attestation_id = {fa}.attestation_id)) \
             AND {})",
        person_identity_sql("pk.identity_type")
    )
}

/// The first subject of `row` (its `subject_key_ids` and `attested_key_id`)
/// that resolves HERE to a person, if any. A key this node cannot resolve is
/// not a person for this question: the void below is granted only on a
/// person PROVEN, so an unknown key cannot un-purge a row.
///
/// # Errors
///
/// Key lookups.
pub async fn person_subject_of<F>(directory: &F, row: &Attestation) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    for subject in attestation_subjects(row) {
        if directory
            .lookup_public_key(&subject)
            .await?
            .is_some_and(|k| identity_type_is_person(&k.identity_type))
        {
            return Ok(Some(subject));
        }
    }
    Ok(None)
}

/// v54.1.0 (Codex rounds 1 and 4 on PR #1057) — **why a tombstone on this
/// row's id is VOID, if it is.** Two things no purge may reach, whatever
/// replication order brought the tombstone first:
///
/// - the accountability record ([`accountability_record_of`],
///   CLM-accountability-record-unpurgeable);
/// - INTERIM, a row a person is the subject of ([`person_subject_of`]): a
///   receiver applies a bundle naming ids it does not hold (`skip_unheld`),
///   so the interim no-human-subject rule is re-asked when the row arrives.
///
/// A void row is admitted at arrival, served, never deleted, and listed in
/// [`PurgeStatus::voided`] / [`FinalizeReport::voided`].
///
/// # Errors
///
/// Key lookups.
pub async fn tombstone_void_reason<F>(
    directory: &F,
    row: &Attestation,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if let Some(family) = accountability_record_of(row) {
        return Ok(Some(format!(
            "a `{family}` row is the accountability record (CLM-accountability-record-unpurgeable)"
        )));
    }
    if let Some(person) = person_subject_of(directory, row).await? {
        return Ok(Some(format!(
            "its subject {person} is a person (interim: no purge reaches a human subject until \
             the notice is a row)"
        )));
    }
    Ok(None)
}

/// Is the tombstone on attestation `id` void — is the row it names held here
/// and [`tombstone_void_reason`] answers?
async fn held_row_voided<F>(directory: &F, id: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    match directory.get_attestation(id).await? {
        Some(row) => Ok(tombstone_void_reason(directory, &row).await?.is_some()),
        None => Ok(false),
    }
}

/// Is the tombstone on trace `trace_id` void — is the trace's own attestation
/// held here with a void reason (its signer, a subject of that attestation, is
/// a person)? The trace delete door re-asks the signer in its statement.
async fn trace_voided<F>(directory: &F, trace_id: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    held_row_voided(directory, &crate::ingest::trace_attestation_id(trace_id)).await
}

/// v54.1.0 (Codex round 4 sweep on PR #1057) — **a trace-keyed derived row
/// for a purged trace is refused** ([`token::TOMBSTONED`]), unless the
/// trace's tombstone is void (its own attestation is held with a
/// [`tombstone_void_reason`]). The detection-event door asks it: a detection
/// arriving after the purge would otherwise re-attach the purged trace's
/// linkage and content the finalize tombstoned.
///
/// # Errors
///
/// [`token::TOMBSTONED`]; the lookups' read errors.
pub async fn refuse_if_tombstoned_trace<F>(directory: &F, trace_id: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    match directory
        .purge_tombstoned(PurgePlane::Trace.as_str(), trace_id)
        .await
    {
        Ok(None) | Err(Error::Unsupported { .. }) => return Ok(()),
        Ok(Some(_)) => {}
        Err(e) => return Err(e),
    }
    if trace_voided(directory, trace_id).await? {
        return Ok(());
    }
    refuse_if_tombstoned(directory, PurgePlane::Trace, trace_id).await
}

/// The attestation door's gate: the row's id on the claims plane.
///
/// **A tombstone never reaches the accountability record** (Codex on PR
/// #1057; CLM-accountability-record-unpurgeable, "by the root or anyone"). A
/// bundle may name an id this node does not hold yet — that is legitimate,
/// and the receiver cannot judge a row it has not seen. When the row the id
/// names ARRIVES and it is a `revocation:*`, `key:revocation`,
/// `moderation:*`, `moderation_track_record:*` or `slashing:*` row, the
/// tombstone is VOID for it: the row is admitted, served, and never deleted
/// by `purge_finalize` ([`PurgeStatus::voided`] names it). Replication order
/// cannot do what no notice may. Every other row stays refused.
///
/// v54.1.0 (Codex round 4 on PR #1057) — and, INTERIM, a row a PROVEN person
/// is the subject of ([`tombstone_void_reason`]): the receiver applied the
/// tombstone without the row (`skip_unheld`), so the no-human-subject rule is
/// asked here, when the row is in hand.
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
    // Cheap first: an id nothing tombstoned needs no subject lookups.
    match directory
        .purge_tombstoned(PurgePlane::Attestation.as_str(), &row.attestation_id)
        .await
    {
        Ok(None) | Err(Error::Unsupported { .. }) => return Ok(()),
        Ok(Some(_)) => {}
        Err(e) => return Err(e),
    }
    if accountability_record_of(row).is_some() {
        return Ok(());
    }
    // INTERIM — a PROVEN person among the subjects voids the tombstone. A
    // subject whose key this node does not hold YET decides nothing: the
    // refusal is the RETRYABLE ordering gap (`federation_attester_key_unknown`,
    // plane `purge_tombstone_subject`), never the terminal `purge_tombstoned`,
    // so the sender re-offers the row once the key lands and the person check
    // decides then (Codex round 4 follow-up). An unknown key still never
    // un-purges a row: it is not admitted while the key is unknown.
    let mut unresolved: Option<String> = None;
    for subject in attestation_subjects(row) {
        match directory.lookup_public_key(&subject).await? {
            Some(k) if identity_type_is_person(&k.identity_type) => return Ok(()),
            Some(_) => {}
            None => {
                unresolved.get_or_insert(subject);
            }
        }
    }
    if let Some(subject) = unresolved {
        return Err(Error::unknown_signer(
            &subject,
            PURGE_TOMBSTONE_SUBJECT_PLANE,
        ));
    }
    refuse_if_tombstoned(directory, PurgePlane::Attestation, &row.attestation_id).await
}

/// The `plane` of the RETRYABLE [`Error::AttesterKeyUnknown`] the
/// tombstone gates raise for a row at a tombstoned id whose subject (or, for a
/// trace, signer) key this node does not hold yet: the interim person check
/// cannot be asked until it lands.
pub const PURGE_TOMBSTONE_SUBJECT_PLANE: &str = "purge_tombstone_subject";

// ── #1040: the mock-run trace refusal (CC 3.1.5, CIRISConstitution#166) ──

/// CIRISConstitution#166 (rc8@8c8f536) — the refusal token for a trace whose
/// signed `run_kind` is `mock`.
pub const TRACE_RUN_KIND_MOCK: &str = "trace_run_kind_mock";

/// The `run_kind` value a mock-LLM run declares (closed vocabulary
/// `schema::trace::RUN_KINDS`, CC 3.1.5).
pub const RUN_KIND_MOCK: &str = "mock";

/// A trace JSON's `run_kind` member, if it carries one. Pure. A SIGNED member
/// of the trace, read from either place a producer signs it: the top level
/// (`CompleteTrace::run_kind`, CIRISAgent#1249) or, from `trace_format`
/// v2.8.0, `deployment_profile.run_kind` (CIRISPersist#1089). Mirrors
/// [`crate::schema::CompleteTrace::signed_run_kind`]. On a manifest (which has
/// no profile) it reads the copied `manifest.run_kind`.
#[must_use]
pub fn trace_run_kind(trace: &serde_json::Value) -> Option<&str> {
    trace
        .get("run_kind")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            trace
                .get("deployment_profile")
                .and_then(|p| p.get("run_kind"))
                .and_then(serde_json::Value::as_str)
        })
}

/// A `trace:complete:v1` attestation envelope's `run_kind`, from EITHER
/// shape: the inline trace's own member (`trace.run_kind`) or the oversize
/// manifest's (`manifest.run_kind`, which the mint copies from the signed
/// trace; Codex on PR #1057). `None` when the shape carries none (a legacy
/// row, or a trace that predates `run_kind`). Pure.
#[must_use]
pub fn trace_attestation_run_kind(envelope: &serde_json::Value) -> Option<&str> {
    envelope
        .get("trace")
        .and_then(trace_run_kind)
        .or_else(|| envelope.get("manifest").and_then(trace_run_kind))
}

/// CIRISConstitution#166 — the FEDERATION-tier attestation gate: a
/// `trace:complete:v1` attestation whose `run_kind` is `mock`, in either
/// shape ([`trace_attestation_run_kind`]: the inline trace or the oversize
/// manifest), is refused ([`TRACE_RUN_KIND_MOCK`]). A local-tier row is
/// untouched (a node may keep its own QA traces). Pure.
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
    match trace_attestation_run_kind(&row.attestation_envelope) {
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
