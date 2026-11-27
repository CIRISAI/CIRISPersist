//! v62.0.0 (wave T1; CC 3.1.3, CC 3.1.3.2, CC 3.2 T6, CC 2.6.1.9, CC 2.7.8)
//! — **the group planes at the edition-2 door: one rule set, two codecs.**
//!
//! A `group:roster` statement (a family's or community's record at a
//! version) and a counted `membership:{stage}` statement (stages `widening`
//! and `removal`) land in persist's typed group tables:
//!
//! | family | lands in |
//! |---|---|
//! | `group:roster`, version 1 | `federation_families` / `federation_communities` |
//! | `group:roster`, a later version (`refs.head`) | the same row, the prior snapshotted into `federation_group_versions`; a fork held in `federation_group_tips` (K1) |
//! | `membership:{stage}`, `removal` | `federation_{family,community}_membership_revocations` |
//! | `membership:{stage}`, `widening` | `federation_{family,community}_membership_widenings` |
//!
//! # One rule set
//!
//! The statement is mapped onto the typed record it replaces
//! ([`record_of_roster`], [`membership_of`]): every payload member one to
//! one (`docs/EDITION2_PAYLOADS.md`). The typed record then goes through
//! the SAME door the JSON form runs (`put_family`, `put_community`,
//! `put_{family,community}_membership_{revocation,widening}`): authorship,
//! the founding rule (#955), the occupied-id route and the supersede proof
//! (#910.5, K1's tips), the roster authority at the group's
//! `consensus_protocol` (#908), the member's acceptance of a growth, the
//! trust-root, geographic, infrastructure and steward gates. No gate is
//! copied here.
//!
//! What the earlier form carried as signatures is now the row's voices
//! (CC 2.6.1.9): every held statement over the same payload, one per signer.
//! Each voice was verified by the edition-2 door when it arrived. The door's
//! signature checks read a **vouch** instead of a JSON scrub: while
//! [`put_group_statement`] runs the typed door, a task-local [`Vouch`] names
//! the one signing envelope the record maps to and, for each voice, its
//! signer and a marker (the voice's composite signature). The earlier-form
//! verifier admits exactly those signer/marker pairs over exactly that
//! envelope (`tier_ingest::verify_envelope_hybrid_signature`, deleted v62.0.0; now `vouched_envelope`), and the
//! supersede quorum counts exactly those signers over exactly the change
//! envelope built here (`FederationDirectory::verify_membership_quorum`).
//! Nothing else is vouched: a held row's own signature, read by any gate in
//! the same task, is verified as before.
//!
//! # Counted
//!
//! A row is counted at its group's protocol. Every voice is kept in
//! `ceg_statements` once the door has judged the row with it:
//! - **met**: the typed record lands ([`StatementOutcome::Row`]);
//! - **short** ([`StatementOutcome::Pending`]): the voices so far do not meet
//!   the protocol (the roster authority's shortfall, the supersede quorum's
//!   `Insufficient`, both noted structurally by the door that found them), or
//!   a founding roster some listed member has not signed yet
//!   (`membership_founding_member_unsigned`). The voice is kept; a later
//!   voice re-runs the door over all of them;
//! - **held** (v62.0.0, waves G0/GC5; CC 2.7.3; also [`StatementOutcome::Pending`]):
//!   a gate that reads ANOTHER row found its condition unmet (a named
//!   version not held yet, the held head, the roster planes, a member's
//!   location proof, the group's cohort). It marks the door's fold attempt
//!   (`edition2::fold::hold`): the voice is kept, the row concludes nothing
//!   with that reason (`fold::why_held`), and it re-folds when what it read
//!   changes;
//! - **refused**: a refusal of the statement's own bytes or its signer's
//!   key plane, and the voice is NOT kept.
//!
//! # A later version
//!
//! A roster version names the version it extends by `refs.head` (CC ruling;
//! P1's payload table). The earlier form's `prev_head_digest` is the
//! predecessor's typed `persist_row_hash`, which is a pure function of the
//! predecessor's own statement, so it is re-derived from the held chain
//! ([`prev_head_digest`]). A predecessor that is not held yet is a fold
//! condition (T1-fix2): the version is HELD (`link_unheld`), its voices
//! kept, and G0's write-time re-fold lands it when the predecessor arrives,
//! with no re-offer. The supersede proof's change envelope is the one
//! `build_membership_change_envelope` gives for the record from this node's
//! held state, and its signatures are the voices.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::namespace_match;
use sha2::Digest as _;

use super::door::AdmittedRow;
use super::fold::{self, reason, Dep};
use super::ingest::{json_of, StatementOutcome};
use super::liveness::statement_parts;
use super::names::{names_of, single, Name, RowId};
use crate::federation::cohort::Cohort;
use crate::federation::group_plane::GroupKind;
use crate::federation::types::{
    Community, CommunityMember, CommunityMembershipRevocation, CommunityMembershipWidening, Family,
    FamilyMember, FamilyMembershipRevocation, FamilyMembershipWidening, GroupSupersedeProof,
    RosterCosignature, SignedCommunity, SignedCommunityMembershipRevocation,
    SignedCommunityMembershipWidening, SignedFamily, SignedFamilyMembershipRevocation,
    SignedFamilyMembershipWidening,
};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The plane name this module's refusals carry.
pub const PLANE: &str = "edition2_group";

/// The roster family (header -70002), a family with no parameter.
pub const GROUP_ROSTER_PREFIX: &str = "group:roster";
/// The membership family's registry prefix; its header id is
/// `namespace_match::family_id` of it (`membership:.stage`).
pub const MEMBERSHIP_PREFIX: &str = "membership:{stage}";
/// The membership leaf a widening is.
pub const WIDENING_LEAF: &str = "widening";
/// The membership leaf a removal is.
pub const REMOVAL_LEAF: &str = "removal";
/// The `refs` role a later roster version names the version it extends by,
/// and the one a membership change names the roster it is counted over by.
pub const HEAD_ROLE: &str = "head";
/// v62.0.0 (wave T1; CC 2.6.1.9) — the `refs` role a merge names its further
/// tips by, beside `refs.head` (a set).
pub const FURTHER_HEADS_ROLE: &str = "further_heads";
/// The `refs.also` roles the charter in force may ride under: `cites` (CC's
/// closed registry, P1) and `charter` (the base table's spelling).
pub const CHARTER_ROLES: [&str; 2] = ["also:cites", "also:charter"];
/// How many predecessor versions [`prev_head_digest`] follows.
pub const MAX_ROSTER_CHAIN: usize = 4096;

/// Which group plane an edition-2 row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupPlane {
    /// `group:roster`: a family's or community's record at a version.
    Roster,
    /// `membership:{stage}`, leaf `widening`: a member added.
    Widening,
    /// `membership:{stage}`, leaf `removal`: a member removed.
    Removal,
}

/// v62.0.0 (RL-fix7, RL-fix19; CC 2.6.1.11, CC 4.2.6) — **a group-plane
/// statement about the accord is refused by name**: a roster version at the
/// accord's id, or a membership change of it (`sub` or the payload's
/// `group` is the accord's `family_key_id`). The accord's roster, seats and
/// recovery are the genesis bundle in force and no row; a change is a later
/// bundle at the import door. Pure (the statement's own bytes), so the
/// statement door runs it among its pure gates BEFORE the payload's shape
/// and the founding check: `humanity-accord` is no group-ref, so either
/// alone would answer a generic refusal and this name could never be
/// reached.
///
/// v62.0.0 (GID-prod; CIRISConstitution's answer of 2026-11-22) —
/// `humanity-accord` is a ROOT LINEAGE NAME, not a group: the genesis
/// bundle's `family_key_id` and `sub`, never founded by a `group:roster`
/// first version, outside the derived-id rule (which runs on `group:roster`
/// rows only). This refusal says so: a lineage, not a group. The baked
/// bundle and its import proof never pass this door (they enter at the
/// genesis import door), so neither moves.
///
/// # Errors
/// `accord_version_is_a_bundle`.
pub fn refuse_accord_group_statement(sub: &str, payload: &Value) -> Result<(), Error> {
    let accord = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    if sub == accord || payload.get_text("group").and_then(Value::as_text) == Some(accord) {
        return Err(Error::malformed_row(
            PLANE,
            malformed_row::ACCORD_VERSION_IS_A_BUNDLE,
            format!(
                "{}: a group-plane statement about {accord}; the accord's roster is the \
                 genesis bundle in force, changed by a later bundle at the import door \
                 (CC 2.6.1.11)",
                malformed_row::ACCORD_VERSION_IS_A_BUNDLE,
            ),
        ));
    }
    Ok(())
}

/// **Is this row a group plane's?** `group:roster`, or `membership:{stage}`
/// at a counted leaf (`widening`, `removal`; Verify's matcher binds the
/// leaf from `dimension`). A composer (`withdraws`, `recants`,
/// `supersedes`) carries its target's family but is not the target's plane:
/// `None`. Every other membership stage (`proposal`, `acceptance`, ...) is
/// an authored row of the attestation plane: `None`.
#[must_use]
pub fn group_plane_of(row_type: &str, family: &str, payload: &Value) -> Option<GroupPlane> {
    if super::emit::names_a_target(row_type) {
        return None;
    }
    if family == namespace_match::family_id(GROUP_ROSTER_PREFIX) {
        return Some(GroupPlane::Roster);
    }
    if family != namespace_match::family_id(MEMBERSHIP_PREFIX) {
        return None;
    }
    let dimension = payload.get_text("dimension").and_then(Value::as_text)?;
    let prefix = namespace_match::prefix_of_family_id(family)?;
    let leaf = namespace_match::bind_leaf(prefix, dimension).ok()?.leaf;
    match leaf.as_str() {
        WIDENING_LEAF => Some(GroupPlane::Widening),
        REMOVAL_LEAF => Some(GroupPlane::Removal),
        _ => None,
    }
}

/// The payload table (`edition2::payloads::FAMILIES`) a header family id is
/// the family of: the template whose `namespace_match::family_id` is it.
#[must_use]
pub fn payload_family_of(header_family: &str) -> Option<&'static str> {
    super::payloads::FAMILIES
        .iter()
        .map(|f| f.family)
        .find(|f| namespace_match::family_id(f) == header_family)
}

/// v62.0.0 (T1-fix2; ruling from K1's I2812, O1's self-roster rule, G0's
/// fold) — **a row naming a row not held yet is HELD, not refused.** The
/// named row is recorded as a read of the running fold attempt
/// (`row:<named>`), and the attempt is held with reason `link_unheld`; the
/// door keeps the voice and answers `Pending`. When the named row arrives,
/// G0's write-time re-fold re-runs this door over the held voices and the row
/// lands with no re-offer: the concluded set does not depend on arrival
/// order. Outside an attempt (a read, the earlier form) this is the plain,
/// retryable `federation_withdraws_target_unheld`.
fn unheld(row_id: &RowId, named: &RowId) -> Error {
    super::fold::reads(super::fold::Dep::Row(*named));
    super::fold::hold(
        super::fold::reason::LINK_UNHELD,
        Error::WithdrawsTargetUnheld {
            attestation_id: row_id.hex(),
            target_attestation_id: named.hex(),
        },
    )
}

fn invalid(message: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, malformed_row::EDITION2_PAYLOAD_INVALID, message)
}

// ─────────────────────────────────────────────────────────────────────────
//  The vouch
// ─────────────────────────────────────────────────────────────────────────

/// **What the edition-2 door vouches for** while a group statement's typed
/// record runs the typed door: the one signing envelope, each voice's signer
/// and marker, and the one change envelope a supersede quorum counts over.
#[derive(Debug)]
pub(crate) struct Vouch {
    /// SHA-256 (hex) of the record's canonical signing envelope.
    envelope_hash: String,
    /// Each voice's signer (identity-ref) → its marker (the composite
    /// signature, base64), the value placed in the record's signature
    /// columns.
    voices: BTreeMap<String, String>,
    /// The supersede proof's change envelope, for a later version.
    change_envelope: Option<serde_json::Value>,
    /// Set by the door that found the voices short of the protocol.
    short: AtomicBool,
}

tokio::task_local! {
    static VOUCH: Arc<Vouch>;
}

impl Vouch {
    /// v62.0.0 (wave T2) — **a vouch over one signing envelope**, with no
    /// change envelope: what the edition-2 door verified for a typed plane
    /// whose JSON door checks one envelope's signatures
    /// (`edition2::typed`: a `revocation:{entity_type}:{reason}` row's
    /// `put_revocation`). `voices` maps each signer to its marker.
    ///
    /// # Errors
    /// An envelope that does not canonicalize.
    pub(crate) fn over(
        envelope: &serde_json::Value,
        voices: BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            envelope_hash: envelope_hash(envelope)?,
            voices,
            change_envelope: None,
            short: AtomicBool::new(false),
        })
    }
}

/// Is a group statement's typed record running the typed door in this task?
/// The earlier-form refusal passes it (`door::refuse_earlier_form`), the
/// cosign hold returns its shortfall instead of holding an earlier-form
/// object (`cosign::hold_if_short`), and no earlier-form group-plane row is
/// minted for it (`group_plane::sync_group_row_offered`).
#[must_use]
pub(crate) fn vouched() -> bool {
    VOUCH.try_with(|_| ()).is_ok()
}

/// **The earlier-form verifier's vouch**: `key_id` signed the envelope whose
/// canonical SHA-256 is `envelope_hash`, with `classical` as its signature
/// column, exactly when the vouch in scope names that envelope and that
/// signer with that marker. `false` outside a vouch.
#[must_use]
pub(crate) fn vouched_signature(key_id: &str, envelope_hash: &str, classical: &str) -> bool {
    VOUCH
        .try_with(|v| {
            v.envelope_hash == envelope_hash && v.voices.get(key_id).is_some_and(|m| m == classical)
        })
        .unwrap_or(false)
}

/// v62.0.0 (F0-cp8; RULINGS "composite signatures only") — **the one
/// row-signature check left on an earlier-form plane**: the signature columns
/// `key_id` / `marker` over `envelope` are admitted exactly when the vouch in
/// scope names them ([`vouched_signature`]) — the edition-2 door verified
/// that voice's composite statement when it arrived. On success returns the
/// envelope's canonical SHA-256 (hex), the row's `original_content_hash`.
///
/// It replaces the earlier envelope verify (an Ed25519 half and an ML-DSA-65
/// half checked against the signer's registered component halves), deleted
/// with its 24 call sites: a signature that is not the door's vouch is the
/// earlier form, refused by name (`earlier_form_object`, `plane`), whatever
/// the switch says.
///
/// # Errors
/// [`Error::InvalidArgument`] for an envelope that does not canonicalize;
/// the earlier-form refusal for any unvouched signature.
pub(crate) fn vouched_envelope(
    key_id: &str,
    envelope: &serde_json::Value,
    marker: &str,
    plane: &'static str,
) -> Result<String, Error> {
    let hash = envelope_hash(envelope)?;
    if vouched_signature(key_id, &hash, marker) {
        Ok(hash)
    } else {
        Err(super::door::earlier_form_signature(plane))
    }
}

/// v62.0.0 (BH-fix1) — run `fut` under a vouch for `change_envelope` whose
/// voices are `signers`, as the edition-2 door's `put_roster_record` does
/// once it has verified each voice's composite statement. Test code only:
/// the witnesses of the vouch-only quorum counts (I2120, I2121).
#[cfg(test)]
pub(crate) async fn with_quorum_vouch<Fut>(
    change_envelope: serde_json::Value,
    signers: &[&str],
    fut: Fut,
) -> Fut::Output
where
    Fut: std::future::Future,
{
    let vouch = Vouch {
        envelope_hash: String::new(),
        voices: signers
            .iter()
            .map(|s| ((*s).to_owned(), String::new()))
            .collect(),
        change_envelope: Some(change_envelope),
        short: AtomicBool::new(false),
    };
    VOUCH.scope(Arc::new(vouch), fut).await
}

/// **The supersede quorum's vouch**: the voices' signers, when the vouch in
/// scope names exactly `change_envelope`. `None` otherwise (the quorum's
/// signatures are verified as before).
#[must_use]
pub(crate) fn vouched_quorum_signers(
    change_envelope: &serde_json::Value,
) -> Option<BTreeSet<String>> {
    VOUCH
        .try_with(|v| {
            (v.change_envelope.as_ref() == Some(change_envelope))
                .then(|| v.voices.keys().cloned().collect())
        })
        .ok()
        .flatten()
}

/// v62.0.0 (wave W1) — **the record's vouched voices**: each voice's signer
/// (identity-ref), when the vouch in scope names exactly `envelope` (the
/// record's signing envelope). `None` outside a vouch or for another record.
/// The trust-root door counts a version's voices through this while the
/// version's last voice is still at its door (`edition2::trust_root_group`).
#[must_use]
pub(crate) fn vouched_signers_for(envelope: &serde_json::Value) -> Option<BTreeSet<String>> {
    let hash = envelope_hash(envelope).ok()?;
    VOUCH
        .try_with(|v| (v.envelope_hash == hash).then(|| v.voices.keys().cloned().collect()))
        .ok()
        .flatten()
}

/// The door that found the vouched voices short of the protocol notes it
/// here (structurally, before it returns the shortfall). A no-op outside a
/// vouch.
pub(crate) fn note_short() {
    let _ = VOUCH.try_with(|v| v.short.store(true, Ordering::SeqCst));
    // v62.0.0 (wave G0 follow-up; CC 2.7.3) — the shortfall is a fold
    // condition: the running fold attempt (`put_group_statement`'s) is held
    // with reason `count_short`, its detail the refusal the door returns.
    super::fold::note(super::fold::reason::COUNT_SHORT);
}

/// SHA-256 (hex) of an envelope's canonical image, as the earlier-form
/// verifier computes it.
pub(crate) fn envelope_hash(envelope: &serde_json::Value) -> Result<String, Error> {
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(envelope).map_err(|e| {
        Error::InvalidArgument(format!("edition-2 group envelope canonicalize: {e}"))
    })?;
    Ok(hex::encode(sha2::Sha256::digest(&canonical)))
}

/// What the typed door did under a vouch.
pub(crate) enum Landing {
    /// The record landed (or was already held, or was held as a tip).
    Landed,
    /// The voices are short of the protocol; the door's refusal is kept for
    /// the log.
    Short(Error),
}

/// Run `door` with `vouch` in scope and read what it decided.
pub(crate) async fn run_vouched<Fut>(vouch: Vouch, door: Fut) -> Result<Landing, Error>
where
    Fut: std::future::Future<Output = Result<(), Error>> + Send,
{
    let vouch = Arc::new(vouch);
    let out = VOUCH.scope(vouch.clone(), door).await;
    match out {
        Ok(()) => Ok(Landing::Landed),
        Err(e) if vouch.short.load(Ordering::SeqCst) => Ok(Landing::Short(e)),
        Err(e) if is_founding_unsigned(&e) => Ok(Landing::Short(e)),
        Err(e) => Err(e),
    }
}

/// v52.0.0 (#955) — a founding roster admits only the members who signed it:
/// in edition 2 each signature is its own statement, so a founding some
/// listed member has not voiced yet is counted short, never refused.
/// Detected by the typed rule, not by text.
fn is_founding_unsigned(e: &Error) -> bool {
    matches!(
        e,
        Error::MembershipAcceptanceRefused { rule, .. }
            if *rule == crate::federation::membership_acceptance::RULE_FOUNDING_MEMBER_UNSIGNED
    )
}

// ─────────────────────────────────────────────────────────────────────────
//  Voices
// ─────────────────────────────────────────────────────────────────────────

/// A statement's composite signature (its fourth member), standard base64:
/// the marker a voice's signer is vouched with, and the value the typed
/// record's signature columns hold.
pub(crate) fn composite_signature_b64(statement: &[u8]) -> String {
    use base64::Engine as _;
    let sig = match cde::decode(statement) {
        Ok(Value::Tag(18, inner)) => inner
            .as_array()
            .and_then(|a| a.get(3))
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    base64::engine::general_purpose::STANDARD.encode(sig)
}

/// A statement's CWT `iss` (protected header label 15, claim 1).
fn statement_iss(statement: &[u8]) -> Option<String> {
    let (protected, _) = statement_parts(statement)?;
    protected
        .get_int(15)?
        .get_int(1)?
        .as_text()
        .map(str::to_owned)
}

/// The row's voices: each held statement over its payload, and the one now
/// offered, one per signer (the first held voice of a signer is its voice).
async fn voices_of<F>(dir: &F, row: &AdmittedRow) -> Result<BTreeMap<String, String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut voices = BTreeMap::new();
    for st in dir.edition2_voices(&row.row_id).await? {
        if let Some(iss) = statement_iss(&st) {
            voices
                .entry(iss)
                .or_insert_with(|| composite_signature_b64(&st));
        }
    }
    voices
        .entry(row.iss.clone())
        .or_insert_with(|| composite_signature_b64(&row.bytes));
    Ok(voices)
}

/// The record's signature columns from its voices: the primary is the
/// group key's own voice where it spoke (CC: "the group key's own
/// statement"), else the first signer in order; every other voice is a
/// co-signature. Deterministic in the set of voices, so every node that
/// holds the same voices judges the same record.
fn signature_columns(
    voices: &BTreeMap<String, String>,
    group: &str,
) -> (String, String, Vec<RosterCosignature>) {
    let primary = if voices.contains_key(group) {
        group.to_owned()
    } else {
        voices.keys().next().cloned().unwrap_or_default()
    };
    let marker = voices.get(&primary).cloned().unwrap_or_default();
    let cosignatures = voices
        .iter()
        .filter(|(k, _)| **k != primary)
        .map(|(k, m)| RosterCosignature {
            authority_key_id: k.clone(),
            scrub_signature_classical: m.clone(),
            scrub_signature_pqc: Some(m.clone()),
        })
        .collect();
    (primary, marker, cosignatures)
}

// ─────────────────────────────────────────────────────────────────────────
//  The payload readers (statement → typed record)
// ─────────────────────────────────────────────────────────────────────────

fn ms_instant(member: &str, ms: u64) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .ok_or_else(|| invalid(format!("`{member}` is out of range")))
}

fn text_of<'a>(p: &'a Value, member: &str) -> Option<&'a str> {
    p.get_text(member).and_then(Value::as_text)
}

fn req_text<'a>(p: &'a Value, member: &str) -> Result<&'a str, Error> {
    text_of(p, member).ok_or_else(|| invalid(format!("`{member}` is required text")))
}

fn opt_ms(p: &Value, member: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>, Error> {
    match p.get_text(member) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .ok_or_else(|| invalid(format!("`{member}` is not uint (ms)")))
            .and_then(|ms| ms_instant(member, ms))
            .map(Some),
    }
}

fn req_ms(p: &Value, member: &str) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    opt_ms(p, member)?.ok_or_else(|| invalid(format!("`{member}` is required (uint, ms)")))
}

fn group_kind_of(p: &Value) -> Result<GroupKind, Error> {
    match req_text(p, "group_kind")? {
        "family" => Ok(GroupKind::Family),
        "community" => Ok(GroupKind::Community),
        other => Err(invalid(format!(
            "`group_kind` {other:?} is neither \"family\" nor \"community\""
        ))),
    }
}

/// `reason`: a code of the closed registry (P1: uint) or the base table's
/// text, else `body.note` (P1's free text).
fn reason_of(p: &Value) -> Option<String> {
    match p.get_text("reason") {
        Some(Value::Uint(n)) => Some(n.to_string()),
        Some(Value::Text(t)) => Some(t.clone()),
        _ => p
            .get_text("body")
            .and_then(|b| b.get_text("note"))
            .and_then(Value::as_text)
            .map(str::to_owned),
    }
}

fn identity_refs_of(p: &Value, member: &str) -> Vec<String> {
    p.get_text(member)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_text)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// One roster's reading: what [`prev_head_digest`] and the record mapping
/// read from a `group:roster` statement.
#[derive(Clone, Debug)]
pub struct RosterView {
    /// Family or community.
    pub kind: GroupKind,
    /// The group's identity-ref (`group`, equal to `sub`).
    pub group: String,
    /// The version (a consistency check: one past its `refs.head`'s).
    pub version: u64,
    /// The version it extends (`refs.head`), absent on version 1.
    pub head: Option<RowId>,
    /// v62.0.0 (wave T1; CC 2.7.8, CC 2.6.1.9) — the further tips a MERGE
    /// names beside `refs.head` (`refs.further_heads`, a set): "a version
    /// naming the tips makes one head again". Empty on any other version.
    pub further_heads: Vec<RowId>,
    /// What its `refs` name.
    pub names: Vec<Name>,
    /// The payload.
    pub payload: Value,
    /// v62.0.0 (wave GC5; CC27 item 4, lead's ruling (b)) — for a
    /// GEOGRAPHIC group: the charter's row id, resolved ONCE from the chain
    /// head (the founding version's `refs.also.cites`, the cited row of the
    /// trust family) by [`resolve_geographic_charter`]. Every other row a
    /// geographic version cites is a location proof. `None` from the pure
    /// reader ([`roster_view`]) and for any other group.
    pub geographic_charter: Option<RowId>,
}

/// Read a `group:roster` payload whose CWT `sub` is `sub`.
///
/// # Errors
/// `edition2_payload_invalid` for a payload that does not read: no kind,
/// a `group` that is not `sub`, no version, unreadable `refs`.
pub fn roster_view(sub: &str, payload: &Value) -> Result<RosterView, Error> {
    let kind = group_kind_of(payload)?;
    let group = req_text(payload, "group")?.to_owned();
    if group != sub {
        return Err(invalid(format!(
            "group:roster: `group` {group:?} is not the row's subject {sub:?}"
        )));
    }
    let version = payload
        .get_text("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("group:roster: `version` is required (uint)"))?;
    let names = names_of(payload).map_err(|e| invalid(format!("group:roster: refs: {e:?}")))?;
    Ok(RosterView {
        kind,
        group,
        version,
        head: single(&names, HEAD_ROLE),
        further_heads: names
            .iter()
            .filter(|n| n.role == FURTHER_HEADS_ROLE)
            .map(|n| n.row)
            .collect(),
        names,
        payload: payload.clone(),
        geographic_charter: None,
    })
}

impl RosterView {
    /// Every version this one names as a head: `refs.head`, then each of
    /// `refs.further_heads`.
    #[must_use]
    pub fn parents(&self) -> Vec<RowId> {
        self.head
            .iter()
            .copied()
            .chain(self.further_heads.iter().copied())
            .collect()
    }

    /// Is this version a merge (it names further tips)?
    #[must_use]
    pub fn is_merge(&self) -> bool {
        !self.further_heads.is_empty()
    }
}

/// [`roster_view`] of a held statement's bytes.
///
/// # Errors
/// As [`roster_view`]; `edition2_payload_invalid` for bytes that are not a
/// `group:roster` row statement.
pub fn roster_view_of_statement(statement: &[u8]) -> Result<RosterView, Error> {
    let (protected, payload) =
        statement_parts(statement).ok_or_else(|| invalid("a held roster does not read"))?;
    let family = protected.get_int(-70002).and_then(Value::as_text);
    if family != Some(GROUP_ROSTER_PREFIX) {
        return Err(invalid(format!(
            "refs.head names a row of {family:?}, not a group:roster version"
        )));
    }
    let sub = protected
        .get_int(15)
        .and_then(|c| c.get_int(2))
        .and_then(Value::as_text)
        .ok_or_else(|| invalid("a held roster names no subject"))?;
    roster_view(sub, &payload)
}

fn roster_members(p: &Value) -> Result<Vec<CommunityMember>, Error> {
    let Some(arr) = p.get_text("members").and_then(Value::as_array) else {
        return Err(invalid("group:roster: `members` is required"));
    };
    arr.iter()
        .map(|m| {
            Ok(CommunityMember {
                key_id: req_text(m, "key")?.to_owned(),
                joined_at: req_ms(m, "joined_at")?,
                role: text_of(m, "role").map(str::to_owned),
            })
        })
        .collect()
}

/// The charter in force a roster names (`refs.also.cites`; the base table's
/// `refs.also:charter`), as the earlier record's hex `charter_digest`.
///
/// v62.0.0 (wave GC5; CC27 item 4, lead's ruling (b)) — a GEOGRAPHIC version
/// cites its members' location proofs under `refs.also.cites` beside its
/// charter, and a set of opaque row-refs cannot tell them apart purely. Its
/// charter is the row id resolved once from the chain head
/// ([`RosterView::geographic_charter`]), when the version cites it; no other
/// cited row ever reads as the charter.
fn charter_of(view: &RosterView) -> String {
    if is_geographic(&view.payload) {
        return view
            .geographic_charter
            .filter(|c| {
                view.names
                    .iter()
                    .any(|n| n.role == CHARTER_ROLES[0] && n.row == *c)
            })
            .map(|r| r.hex())
            .unwrap_or_default();
    }
    CHARTER_ROLES
        .iter()
        .find_map(|r| single(&view.names, r))
        .map(|r| r.hex())
        .unwrap_or_default()
}

/// v62.0.0 (wave GC5; CC27 item 4, lead's ruling (b)) — **a geographic
/// group's charter, resolved once at the chain head.** Follows `refs.head`
/// from `view` down to the founding version (each a named row), and reads
/// the founding's `refs.also.cites`: the cited row of the trust family is
/// the charter. `None` for a group that is not geographic, for a founding
/// that cites no trust row, and while a named version or cited row is not
/// held (the door's own reads hold the version `link_unheld` then). Every
/// read is the version's NAMED past (the group plane is FINAL).
///
/// # Errors
/// A named version that does not read; directory failures.
pub async fn resolve_geographic_charter<F>(
    dir: &F,
    view: &RosterView,
) -> Result<Option<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !is_geographic(&view.payload) {
        return Ok(None);
    }
    let mut root = view.clone();
    let mut steps = 0usize;
    while let Some(h) = root.head {
        steps += 1;
        if steps > MAX_ROSTER_CHAIN {
            return Ok(None);
        }
        fold::reads(Dep::Row(h));
        let Some(st) = dir.edition2_voices(&h).await?.into_iter().next() else {
            return Ok(None);
        };
        root = roster_view_of_statement(&st)?;
    }
    for n in root.names.iter().filter(|n| n.role == CHARTER_ROLES[0]) {
        fold::reads(Dep::Row(n.row));
        let Some(st) = dir.edition2_voices(&n.row).await?.into_iter().next() else {
            continue;
        };
        let trust = statement_parts(&st).is_some_and(|(protected, _)| {
            protected
                .get_int(-70002)
                .and_then(Value::as_text)
                .is_some_and(super::typed::is_trust_family)
        });
        if trust {
            return Ok(Some(n.row));
        }
    }
    Ok(None)
}

/// Does a roster payload declare the `geographic` subkind (top level, or in
/// its `policy`)?
fn is_geographic(p: &Value) -> bool {
    policy_blob_of(p).is_some_and(|b| {
        b.get("cohort_subkind").and_then(serde_json::Value::as_str)
            == Some(super::payloads::GEOGRAPHIC_SUBKIND)
    })
}

/// A community's `policy_blob`: the payload's `policy` map, with the CC 3.2
/// members P1 lifts beside it (`cohort_subkind`, `cohort_subkind_payload`,
/// `membership`) written back into it. `None` when none is present.
fn policy_blob_of(p: &Value) -> Option<serde_json::Value> {
    let mut blob = p.get_text("policy").map(json_of);
    for member in ["cohort_subkind", "cohort_subkind_payload", "membership"] {
        if let Some(v) = p.get_text(member) {
            let obj = blob.get_or_insert_with(|| serde_json::json!({}));
            if let Some(o) = obj.as_object_mut() {
                o.insert(member.to_owned(), json_of(v));
            }
        }
    }
    blob
}

/// The typed record a roster version maps to.
#[derive(Clone, Debug, PartialEq)]
pub enum GroupRecord {
    /// A family's record.
    Family(Family),
    /// A community's record.
    Community(Community),
}

impl GroupRecord {
    /// The record's `persist_row_hash`, as the typed door stamps it.
    ///
    /// # Errors
    /// Serialization failure.
    pub fn persist_row_hash(&self) -> Result<String, Error> {
        match self {
            Self::Family(f) => crate::federation::types::compute_persist_row_hash(f),
            Self::Community(c) => crate::federation::types::compute_persist_row_hash(c),
        }
    }
}

/// **The roster mapping**: a roster version as the typed record it
/// replaces, every member one to one, `prev_head_digest` given (the
/// predecessor's typed hash, empty on version 1).
///
/// # Errors
/// `edition2_payload_invalid` for a member that does not read.
pub fn record_of_roster(view: &RosterView, prev_head_digest: String) -> Result<GroupRecord, Error> {
    let p = &view.payload;
    let name = req_text(p, "name")?.to_owned();
    let members = roster_members(p)?;
    let founded_at = req_ms(p, "founded_at")?;
    let consensus_protocol = req_text(p, "consensus_protocol")?.to_owned();
    let charter_digest = charter_of(view);
    Ok(match view.kind {
        GroupKind::Family => GroupRecord::Family(Family {
            family_key_id: view.group.clone(),
            family_name: name,
            members: members
                .into_iter()
                .map(|m| FamilyMember {
                    key_id: m.key_id,
                    joined_at: m.joined_at,
                    role: m.role,
                })
                .collect(),
            founded_at,
            consensus_protocol,
            consensus_protocol_entrenched: matches!(
                p.get_text("consensus_protocol_entrenched"),
                Some(Value::Bool(true))
            ),
            dissolved_at: opt_ms(p, "dissolved_at")?,
            prev_head_digest,
            charter_digest,
            persist_row_hash: String::new(),
        }),
        GroupKind::Community => GroupRecord::Community(Community {
            community_key_id: view.group.clone(),
            community_name: name,
            members,
            founded_at,
            consensus_protocol,
            policy_blob: policy_blob_of(p),
            prev_head_digest,
            charter_digest,
            persist_row_hash: String::new(),
        }),
    })
}

/// A version of the held chain: its reading and its typed `persist_row_hash`.
type Chain = BTreeMap<RowId, (RosterView, String)>;

/// The `persist_row_hash`es this node's lineage of `group` holds: the head's
/// and every superseded version's (`federation_group_versions`).
async fn held_lineage<F>(dir: &F, view: &RosterView) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (cohort, head) = match view.kind {
        GroupKind::Family => (
            Cohort::Family,
            dir.lookup_family(&view.group)
                .await?
                .map(|f| f.persist_row_hash),
        ),
        GroupKind::Community => {
            let c = dir.lookup_community(&view.group).await?;
            let cohort = match &c {
                Some(c) => crate::federation::affiliation_config::declared_cohort(c)?,
                None => Cohort::Community,
            };
            (cohort, c.map(|c| c.persist_row_hash))
        }
    };
    let Some(head) = head else {
        return Ok(BTreeSet::new());
    };
    let mut out = BTreeSet::from([head]);
    for v in dir.list_group_versions(cohort, &view.group).await? {
        if let Some(h) = snapshot_hash(&v.snapshot) {
            out.insert(h);
        }
    }
    Ok(out)
}

/// **The `prev_head_digest` of a version** from its parents' typed hashes.
/// One parent: that parent's. A merge (CC 2.7.8) names several tips, and the
/// typed record names one: the named version this node's lineage holds as
/// the head (or held as the head before the merge superseded it), so the
/// supersede executor reads the merge as extending the head; when no named
/// version is in the lineage, `refs.head`'s.
fn chosen_prev(view: &RosterView, chain: &Chain, lineage: &BTreeSet<String>) -> String {
    let parents = view.parents();
    let hash = |id: &RowId| chain.get(id).map(|(_, h)| h.clone()).unwrap_or_default();
    if view.is_merge() {
        if let Some(h) = parents.iter().map(hash).find(|h| lineage.contains(h)) {
            return h;
        }
    }
    parents.first().map(hash).unwrap_or_default()
}

/// Load the held chain behind `start` into `chain`: each named version's
/// reading and typed hash, through every parent (`refs.head` and
/// `refs.further_heads`), down to version 1.
#[allow(clippy::map_entry)] // X2 build fix: an await sits between the check and the insert
async fn load_chain<F>(
    dir: &F,
    view: &RosterView,
    row_id: &RowId,
    start: &[RowId],
    lineage: &BTreeSet<String>,
    chain: &mut Chain,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut stack: Vec<RowId> = start.to_vec();
    let mut read: BTreeMap<RowId, RosterView> = BTreeMap::new();
    while let Some(id) = stack.last().copied() {
        if chain.contains_key(&id) {
            stack.pop();
            continue;
        }
        if read.len() > MAX_ROSTER_CHAIN {
            return Err(invalid(format!(
                "group:roster: the chain behind {} is longer than {MAX_ROSTER_CHAIN} versions",
                row_id.hex()
            )));
        }
        if !read.contains_key(&id) {
            // v62.0.0 (wave GC5; CC 2.7.3) — a named version is an input of
            // this row's fold: unheld, the row WAITS (held, re-folded when
            // the version lands); of another group, it concludes nothing.
            fold::reads(Dep::Row(id));
            let held = dir.edition2_voices(&id).await?;
            let Some(st) = held.first() else {
                return Err(unheld(row_id, &id));
            };
            let mut v = roster_view_of_statement(st)?;
            // v62.0.0 (wave GC5; ruling (b)) — one charter for the chain.
            v.geographic_charter = view.geographic_charter;
            if v.group != view.group || v.kind != view.kind {
                return Err(fold::hold(
                    reason::NAMES_ANOTHER_GROUP,
                    invalid(format!(
                        "group:roster: {} names a roster of another group ({:?})",
                        row_id.hex(),
                        v.group
                    )),
                ));
            }
            read.insert(id, v);
        }
        let v = &read[&id];
        let missing: Vec<RowId> = v
            .parents()
            .into_iter()
            .filter(|p| !chain.contains_key(p))
            .collect();
        if missing.is_empty() {
            let v = read.remove(&id).expect("read above");
            let hash = record_of_roster(&v, chosen_prev(&v, chain, lineage))?.persist_row_hash()?;
            chain.insert(id, (v, hash));
            stack.pop();
        } else {
            stack.extend(missing);
        }
    }
    Ok(())
}

/// **The version's `prev_head_digest`**: empty on version 1 (no
/// `refs.head`); otherwise the typed `persist_row_hash` of the version it
/// extends, re-derived from the held chain of predecessor statements back to
/// version 1 (every parent of a merge included). Checks the version is one
/// past the greatest version it names, and every named version is a roster
/// of the same group.
///
/// # Errors
/// - for a named version this node does not hold yet: HELD (`link_unheld`)
///   inside the door's fold attempt, so the voice is kept and lands when the
///   version arrives; the retryable `federation_withdraws_target_unheld`
///   outside one;
/// - `edition2_payload_invalid` for a version that does not follow what it
///   names (1 with no `refs.head`; `refs.further_heads` with no `refs.head`),
///   a named version of another group or kind, or a chain past
///   [`MAX_ROSTER_CHAIN`].
pub async fn prev_head_digest<F>(
    dir: &F,
    view: &RosterView,
    row_id: &RowId,
) -> Result<String, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(merge_reading(dir, view, row_id).await?.prev)
}

/// What a version names, read against this node's lineage.
pub struct MergeReading {
    /// The version's `prev_head_digest` ([`chosen_prev`]).
    pub prev: String,
    /// The typed hashes of the OTHER versions a merge names (empty on any
    /// other version): the tips the merge makes one head with.
    pub merged: Vec<String>,
}

/// [`prev_head_digest`] with the merged tips' typed hashes.
///
/// # Errors
/// As [`prev_head_digest`].
pub async fn merge_reading<F>(
    dir: &F,
    view: &RosterView,
    row_id: &RowId,
) -> Result<MergeReading, Error>
where
    F: FederationDirectory + ?Sized,
{
    let parents = view.parents();
    if view.head.is_none() {
        if view.is_merge() {
            return Err(invalid(
                "group:roster: refs.further_heads names tips beside no refs.head",
            ));
        }
        if view.version != 1 {
            return Err(invalid(format!(
                "group:roster: version {} names no refs.head (only version 1 has none)",
                view.version
            )));
        }
        return Ok(MergeReading {
            prev: String::new(),
            merged: Vec::new(),
        });
    }
    let lineage = held_lineage(dir, view).await?;
    let mut chain = Chain::new();
    load_chain(dir, view, row_id, &parents, &lineage, &mut chain).await?;
    let greatest = parents
        .iter()
        .filter_map(|p| chain.get(p).map(|(v, _)| v.version))
        .max()
        .unwrap_or(0);
    if view.version != greatest.saturating_add(1) {
        // v62.0.0 (wave GC5; CC 2.7.3) — the named versions' own numbers are
        // another row's content: the version concludes nothing.
        return Err(fold::hold(
            reason::VERSION_DOES_NOT_FOLLOW,
            invalid(format!(
                "group:roster: version {} does not follow the greatest version {greatest} it names",
                view.version
            )),
        ));
    }
    let prev = chosen_prev(view, &chain, &lineage);
    let merged = parents
        .iter()
        .filter_map(|p| chain.get(p).map(|(_, h)| h.clone()))
        .filter(|h| *h != prev)
        .collect();
    Ok(MergeReading { prev, merged })
}

/// One counted membership change's reading.
#[derive(Clone, Debug)]
pub struct MembershipView {
    /// Family or community.
    pub kind: GroupKind,
    /// The group's identity-ref.
    pub group: String,
    /// The member's identity-ref (equal to `sub`).
    pub member: String,
    /// The roster version the change is counted over (`refs.head`).
    pub head: Option<RowId>,
}

/// The typed membership record a counted change maps to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipRecord {
    /// A family removal.
    FamilyRemoval(FamilyMembershipRevocation),
    /// A community removal.
    CommunityRemoval(CommunityMembershipRevocation),
    /// A family widening.
    FamilyWidening(FamilyMembershipWidening),
    /// A community widening.
    CommunityWidening(CommunityMembershipWidening),
}

/// **The membership mapping**: a counted `membership:{stage}` payload whose
/// `sub` is `sub` as the typed record it replaces.
///
/// # Errors
/// `edition2_payload_invalid` for a payload that does not read: a `member`
/// that is not `sub`, a missing instant.
pub fn membership_of(
    plane: GroupPlane,
    sub: &str,
    payload: &Value,
) -> Result<(MembershipView, MembershipRecord), Error> {
    let p = payload;
    let kind = group_kind_of(p)?;
    let group = req_text(p, "group")?.to_owned();
    let member = req_text(p, "member")?.to_owned();
    if member != sub {
        return Err(invalid(format!(
            "membership: `member` {member:?} is not the row's subject {sub:?}"
        )));
    }
    let names = names_of(p).map_err(|e| invalid(format!("membership: refs: {e:?}")))?;
    let effective_at = req_ms(p, "effective_at")?;
    let record = match (plane, kind) {
        (GroupPlane::Removal, GroupKind::Family) => {
            MembershipRecord::FamilyRemoval(FamilyMembershipRevocation {
                family_key_id: group.clone(),
                removed_identity_key_id: member.clone(),
                removed_at: req_ms(p, "removed_at")?,
                effective_at,
                reason: reason_of(p),
                witness_set: identity_refs_of(p, "witness_set"),
                persist_row_hash: String::new(),
                record_row_id: None,
            })
        }
        (GroupPlane::Removal, GroupKind::Community) => {
            MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
                community_key_id: group.clone(),
                removed_identity_key_id: member.clone(),
                removed_at: req_ms(p, "removed_at")?,
                effective_at,
                reason: reason_of(p),
                witness_set: identity_refs_of(p, "witness_set"),
                persist_row_hash: String::new(),
                record_row_id: None,
            })
        }
        (GroupPlane::Widening, GroupKind::Family) => {
            MembershipRecord::FamilyWidening(FamilyMembershipWidening {
                family_key_id: group.clone(),
                member_key_id: member.clone(),
                joined_at: req_ms(p, "joined_at")?,
                effective_at,
                role: text_of(p, "role").map(str::to_owned),
                persist_row_hash: String::new(),
                record_row_id: None,
            })
        }
        (GroupPlane::Widening, GroupKind::Community) => {
            MembershipRecord::CommunityWidening(CommunityMembershipWidening {
                community_key_id: group.clone(),
                member_key_id: member.clone(),
                joined_at: req_ms(p, "joined_at")?,
                effective_at,
                role: text_of(p, "role").map(str::to_owned),
                persist_row_hash: String::new(),
                record_row_id: None,
            })
        }
        (GroupPlane::Roster, _) => {
            return Err(invalid("a group:roster row is not a membership change"));
        }
    };
    Ok((
        MembershipView {
            kind,
            group,
            member,
            head: single(&names, HEAD_ROLE),
        },
        record,
    ))
}

// ─────────────────────────────────────────────────────────────────────────
//  The door
// ─────────────────────────────────────────────────────────────────────────

/// **A group statement at the edition-2 door** (called by
/// `ingest::put_statement` once [`admit_row`](super::door::admit_row) admitted
/// it and [`group_plane_of`] named its plane). The payload is checked against
/// its table, mapped onto its typed record, and judged by the typed door with
/// every voice of the row ([`Vouch`]). `replicated` is the replicated door
/// (an offered id): the gates that bind only the local door are skipped, as
/// for a replicated group-plane row.
///
/// # Errors
/// `edition2_payload_invalid`; the typed door's refusals; the retryable
/// waits (an unheld predecessor or roster head, an unknown key).
pub async fn put_group_statement<F>(
    dir: &F,
    row: &AdmittedRow,
    plane: GroupPlane,
    replicated: bool,
    tier: &str,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    if let Some(table) = payload_family_of(&row.family) {
        super::payloads::check(table, &row.payload)?;
    }
    // v62.0.0 (RL-fix7; CC 2.6.1.11, CC 4.2.6) — the accord's roster, seats
    // and recovery are the genesis bundle in force and no row (the shared
    // rule, [`refuse_accord_group_statement`], which the statement door's
    // pure gates also run AHEAD of the payload shape, RL-fix19).
    refuse_accord_group_statement(&row.sub, &row.payload)?;
    // v62.0.0 (T1-fix2; G0.api "every door is already inside an attempt")
    // — the group door runs inside `ingest::put_admitted_row`'s ONE fold
    // attempt (no inner attempt: it would swallow the marks and reads the
    // outer records). The group's own reads are declared to it; the shared
    // readers declare theirs.
    {
        use super::fold::{reads, Dep};
        // The row's own voices, its subject (the group of a roster, the
        // member of a change), the group it changes, and every version it
        // names (`refs.head`, `refs.further_heads`).
        reads(Dep::Row(row.row_id));
        reads(Dep::key(&row.sub));
        if let Some(g) = row.payload.get_text("group").and_then(Value::as_text) {
            reads(Dep::key(g));
        }
        for n in &row.names {
            reads(Dep::Row(n.row));
        }
    }
    let voices = voices_of(dir, row).await?;
    // A refusal a gate MARKED as a fold condition (`link_unheld`: a named row
    // not held yet; a gate's `fold::hold`) returns as the error, and the
    // outer attempt keeps the voice and holds the row with that reason
    // (`Pending`). An unmarked refusal stays a refusal.
    let landing = match plane {
        GroupPlane::Roster => Box::pin(put_roster(dir, row, voices)).await?,
        GroupPlane::Widening | GroupPlane::Removal => {
            Box::pin(put_membership(dir, row, plane, voices, replicated)).await?
        }
    };
    let new = dir.put_edition2_statement(row).await?;
    Ok(match landing {
        Landing::Landed => StatementOutcome::Row {
            row_id: row.row_id,
            new,
        },
        Landing::Short(e) => {
            // Short of the count: a gate noted it (`fold::note(count_short)`,
            // through `note_short`), or the founding rule's typed refusal (a
            // listed member has not voiced yet). The outer attempt records
            // the hold (`count_short`) with every read.
            tracing::debug!(
                row_id = %row.row_id.hex(),
                family = %row.family,
                tier,
                reason = %e,
                "edition-2 group row held: short of its count"
            );
            StatementOutcome::Pending {
                row_id: row.row_id,
                new,
            }
        }
    })
}

/// A roster version: founding (version 1) or later (`refs.head`).
async fn put_roster<F>(
    dir: &F,
    row: &AdmittedRow,
    voices: BTreeMap<String, String>,
) -> Result<Landing, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut view = roster_view(&row.sub, &row.payload)?;
    view.geographic_charter = resolve_geographic_charter(dir, &view).await?;
    // v62.0.0 (wave GC5) — the group's held head, versions and tips are
    // inputs of this row: a version of the group (its `sub`) re-folds it;
    // so does a membership change of any member it lists (its `sub`).
    fold::reads(Dep::key(&view.group));
    // v62.0.0 (GID-tips) — a CONTESTED founding concludes nothing: another
    // first version (no `refs.head`) of this group held here, held or
    // concluded, makes every first version of it held. The read above
    // (`Dep::key(group)`) is the dependency: a rival first version's arrival
    // touches `key:<group>` (its `sub`), so a founding concluded before it
    // re-folds here and un-concludes; re-delivery of the SAME first version
    // is the same row id and no rival.
    if view.head.is_none() {
        check_founding_uncontested(dir, row, &view).await?;
    }
    let MergeReading { prev, merged } = merge_reading(dir, &view, &row.row_id).await?;
    let record = record_of_roster(&view, prev.clone())?;
    if let GroupRecord::Community(c) = &record {
        check_named_location_proofs(dir, row, &view, c).await?;
    }
    let offered_hash = record.persist_row_hash()?;
    let landing = Box::pin(put_roster_record(dir, row, &view, record, &prev, voices)).await?;
    // v62.0.0 (wave T1; CC 2.7.8) — a merge that became the head makes one
    // head again: the other tips it names leave `federation_group_tips`.
    if matches!(landing, Landing::Landed) && !merged.is_empty() {
        drop_merged_tips(dir, &view, &offered_hash, &merged).await?;
    }
    Ok(landing)
}

/// v62.0.0 (GID-tips) — refuse-as-HELD a first version of `view.group` when
/// another first version of it is held in the group's projection slot
/// (`ingest::fold_plane_of`: `group:<sub>`), `group_founding_contested`.
///
/// # Errors
/// The hold; directory reads.
async fn check_founding_uncontested<F>(
    dir: &F,
    row: &AdmittedRow,
    view: &RosterView,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let slot = format!("group:{}", row.sub);
    for other in dir.fold_slot_all_rows(&slot).await? {
        if other == row.row_id {
            continue;
        }
        let Some(statement) = dir.edition2_voices(&other).await?.into_iter().next() else {
            continue;
        };
        let Some((_, payload)) = statement_parts(&statement) else {
            continue;
        };
        let first = payload
            .get_text("refs")
            .and_then(|r| r.get_text("head"))
            .is_none();
        if first && payload.get_text("group").and_then(Value::as_text) == Some(view.group.as_str())
        {
            return Err(fold::hold(
                reason::GROUP_FOUNDING_CONTESTED,
                Error::InvalidArgument(format!(
                    "{}: {:?} has two first versions ({} and {}): its founders signed two \
                     foundings, so the group concludes nothing here (CC 2.7.8); found it anew \
                     under a new nonce",
                    reason::GROUP_FOUNDING_CONTESTED,
                    view.group,
                    row.row_id.hex(),
                    other.hex()
                )),
            ));
        }
    }
    Ok(())
}

/// The family id of a `location_proof:{version}` row (header -70002).
fn location_proof_family() -> String {
    namespace_match::family_id("location_proof:{version}")
}

/// v62.0.0 (wave GC5; CC rc21 3.2, CC27 item 4) — **a geographic version
/// names each new member's `location_proof`.** For a community whose
/// `policy_blob` declares the `geographic` subkind, the version cites under
/// `refs.also.cites` ([`super::payloads::LOCATION_PROOF_ROLE`]) one
/// `location_proof` row per member it adds (every member, on version 1;
/// against the versions it names, on a later one). Each cited row is read
/// by its family (the charter rides the same set and is skipped). The
/// version:
/// - WAITS for a cited row not held (held, `link_unheld`);
/// - concludes nothing (held, `geographic_member_unlocated`) while a new
///   member has no cited proof whose subject it is, whose cell is contained
///   in the constraint cell, and that is live at the version's own
///   `asserted_at` (stated at or before it; `valid_until`, if any, after
///   it).
///
/// The group plane is FINAL (G0 v4): this reads only what the version
/// names (the cited rows and the versions it extends), never current state
/// or the clock. A withdrawal of a cited proof after the version concluded
/// does not take the version back.
///
/// # Errors
/// The holds above; `edition2_payload_invalid` for a named version that does
/// not read; directory failures.
async fn check_named_location_proofs<F>(
    dir: &F,
    row: &AdmittedRow,
    view: &RosterView,
    community: &Community,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(cell) =
        crate::federation::location::geographic_constraint_cell(community.policy_blob.as_ref())
    else {
        return Ok(());
    };
    // The members the versions it extends already list.
    let mut prior: BTreeSet<String> = BTreeSet::new();
    for parent in view.parents() {
        fold::reads(Dep::Row(parent));
        if let Some(st) = dir.edition2_voices(&parent).await?.first() {
            let pv = roster_view_of_statement(st)?;
            if let GroupRecord::Community(pc) = record_of_roster(&pv, String::new())? {
                prior.extend(pc.members.into_iter().map(|m| m.key_id));
            }
        }
    }
    let new: BTreeSet<&str> = community
        .members
        .iter()
        .map(|m| m.key_id.as_str())
        .filter(|k| !prior.contains(*k))
        .collect();
    if new.is_empty() {
        return Ok(());
    }
    let family = location_proof_family();
    let mut located: BTreeSet<String> = BTreeSet::new();
    for n in view
        .names
        .iter()
        .filter(|n| n.role == super::payloads::LOCATION_PROOF_ROLE)
        .filter(|n| view.geographic_charter != Some(n.row))
    {
        fold::reads(Dep::Row(n.row));
        let held = dir.edition2_voices(&n.row).await?;
        let Some(st) = held.first() else {
            return Err(fold::hold(
                reason::LINK_UNHELD,
                Error::WithdrawsTargetUnheld {
                    attestation_id: row.row_id.hex(),
                    target_attestation_id: n.row.hex(),
                },
            ));
        };
        let Some((protected, payload)) = statement_parts(st) else {
            continue;
        };
        if protected.get_int(-70002).and_then(Value::as_text) != Some(family.as_str()) {
            continue;
        }
        let Some(subject) = protected
            .get_int(15)
            .and_then(|c| c.get_int(2))
            .and_then(Value::as_text)
        else {
            continue;
        };
        let stated = payload.get_text("asserted_at").and_then(Value::as_u64);
        let until = payload.get_text("valid_until").and_then(Value::as_u64);
        let live = stated.is_some_and(|t| t <= row.asserted_at_ms)
            && until.is_none_or(|u| u > row.asserted_at_ms);
        let contained = payload
            .get_text("cell_id")
            .and_then(Value::as_text)
            .is_some_and(|c| crate::federation::location::h3_cell_contained(c, &cell));
        if live && contained {
            located.insert(subject.to_owned());
        }
    }
    if let Some(missing) = new.iter().find(|k| !located.contains(**k)) {
        return Err(fold::hold(
            reason::GEOGRAPHIC_MEMBER_UNLOCATED,
            invalid(format!(
                "group:roster: geographic version {} names no live location_proof of new member \
                 {missing} contained in the constraint cell {cell} at its asserted_at (CC 3.2)",
                row.row_id.hex()
            )),
        ));
    }
    Ok(())
}

/// The tips a landed merge names leave the tip store, once the merge is the
/// head this node holds (a merge held as a tip itself merges nothing yet).
async fn drop_merged_tips<F>(
    dir: &F,
    view: &RosterView,
    offered_hash: &str,
    merged: &[String],
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let (cohort, head) = match view.kind {
        GroupKind::Family => (
            Cohort::Family,
            dir.lookup_family(&view.group)
                .await?
                .map(|f| f.persist_row_hash),
        ),
        GroupKind::Community => match dir.lookup_community(&view.group).await? {
            Some(c) => (
                crate::federation::affiliation_config::declared_cohort(&c)?,
                Some(c.persist_row_hash),
            ),
            None => (Cohort::Community, None),
        },
    };
    if head.as_deref() != Some(offered_hash) {
        return Ok(());
    }
    dir.drop_group_tips(cohort, &view.group, merged).await
}

/// The typed door for one roster version's record.
async fn put_roster_record<F>(
    dir: &F,
    row: &AdmittedRow,
    view: &RosterView,
    record: GroupRecord,
    prev: &str,
    voices: BTreeMap<String, String>,
) -> Result<Landing, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (primary, marker, cosignatures) = signature_columns(&voices, &view.group);
    match record {
        GroupRecord::Family(family) => {
            let proof = match view.head {
                None => None,
                Some(head) => Some(
                    supersede_proof(
                        dir,
                        Cohort::Family,
                        &family.family_key_id,
                        family.members.iter().map(|m| m.key_id.clone()).collect(),
                        family.consensus_protocol_entrenched,
                        &family.consensus_protocol,
                        family.dissolved_at,
                        prev,
                        row,
                        &head,
                    )
                    .await?,
                ),
            };
            let vouch = Vouch {
                envelope_hash: envelope_hash(&family.signing_envelope())?,
                voices,
                change_envelope: proof.as_ref().map(|p| p.change_envelope.clone()),
                short: AtomicBool::new(false),
            };
            let signed = SignedFamily {
                family,
                authority_key_id: primary,
                scrub_signature_classical: marker.clone(),
                scrub_signature_pqc: Some(marker),
                supersede_proof: proof,
                cosignatures,
            };
            run_vouched(vouch, dir.put_family(signed)).await
        }
        GroupRecord::Community(community) => {
            let mut proof = match view.head {
                None => None,
                Some(head) => Some(
                    supersede_proof(
                        dir,
                        Cohort::Community,
                        &community.community_key_id,
                        community.members.iter().map(|m| m.key_id.clone()).collect(),
                        false,
                        &community.consensus_protocol,
                        None,
                        prev,
                        row,
                        &head,
                    )
                    .await?,
                ),
            };
            // v62.0.0 (wave W1) — a trust-root community's version is a
            // founders' link (`canonical_community::verify_founders_link`):
            // its change envelope binds the founder roles, the version's
            // content and its instant (`bind_next_version`, at the version's
            // `asserted_at`), and it travels with the held chain it extends
            // (the payload carries no lineage: each prior version is its own
            // held row).
            let trust_root =
                crate::federation::canonical_community::is_trust_root_grade(&community);
            let mut lineage = Vec::new();
            if trust_root {
                if let Some(p) = proof.as_mut() {
                    let amended_at = i64::try_from(row.asserted_at_ms)
                        .ok()
                        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
                        .ok_or_else(|| invalid("group:roster: asserted_at is not an instant"))?;
                    crate::federation::canonical_community::bind_next_version(
                        &mut p.change_envelope,
                        &community,
                        amended_at,
                    )?;
                    if let Some(held) =
                        crate::federation::canonical_community::lookup_signed_community(
                            dir,
                            &community.community_key_id,
                        )
                        .await?
                    {
                        lineage = crate::federation::canonical_community::chain_of(&held);
                    }
                }
            }
            let vouch = Vouch {
                envelope_hash: envelope_hash(&community.signing_envelope())?,
                voices,
                change_envelope: proof.as_ref().map(|p| p.change_envelope.clone()),
                short: AtomicBool::new(false),
            };
            let signed = SignedCommunity {
                community,
                authority_key_id: primary,
                scrub_signature_classical: marker.clone(),
                scrub_signature_pqc: Some(marker),
                supersede_proof: proof,
                cosignatures,
                lineage,
            };
            run_vouched(vouch, dir.put_community(signed)).await
        }
    }
}

/// **A later version's supersede proof**: the version it extends
/// (`prior_persist_row_hash`, its typed hash) and the change envelope this
/// node's held state gives for the offered roster
/// (`build_membership_change_envelope`). Its signatures are the voices,
/// counted through the vouch. A group this node does not hold yet waits on
/// the version `refs.head` names.
///
/// A family version that dissolves the family (its payload's
/// `dissolved_at`, CIRISPersist#956) carries that instant in the change
/// envelope (`family_dissolution::DISSOLVED_AT_MEMBER`, RFC 3339 at ms), so
/// the door's own checks read it as the dissolution the voices signed:
/// `check_dissolution_matches_envelope` (the record's `dissolved_at` is the
/// signed one) and `check_dissolve_is_terminal_only` (nothing else changes).
#[allow(clippy::too_many_arguments)]
async fn supersede_proof<F>(
    dir: &F,
    cohort: Cohort,
    group: &str,
    member_key_ids: Vec<String>,
    entrenched: bool,
    consensus_protocol: &str,
    dissolved_at: Option<chrono::DateTime<chrono::Utc>>,
    prior: &str,
    row: &AdmittedRow,
    head: &RowId,
) -> Result<GroupSupersedeProof, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = match cohort {
        Cohort::Family => dir.lookup_family(group).await?.is_some(),
        _ => dir.lookup_community(group).await?.is_some(),
    };
    fold::reads(Dep::key(group));
    fold::reads(Dep::Row(*head));
    if !held {
        // The group lands with the version `refs.head` names (or its own
        // founding): a change to the group's rows re-folds this one.
        super::fold::reads(super::fold::Dep::key(group));
        return Err(unheld(&row.row_id, head));
    }
    let mut change_envelope = dir
        .build_membership_change_envelope(
            cohort,
            group,
            &member_key_ids,
            entrenched,
            Some(consensus_protocol),
        )
        .await?;
    if let (Some(at), Some(o)) = (dissolved_at, change_envelope.as_object_mut()) {
        o.insert(
            crate::federation::family_dissolution::DISSOLVED_AT_MEMBER.to_owned(),
            serde_json::Value::String(at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        );
    }
    Ok(GroupSupersedeProof {
        prior_persist_row_hash: prior.to_owned(),
        change_envelope,
        quorum_signatures: Vec::new(),
    })
}

/// The roster version a membership change names by `refs.head` must be a
/// held `group:roster` row of the same group (an unheld one waits).
async fn check_membership_head<F>(
    dir: &F,
    row: &AdmittedRow,
    view: &MembershipView,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(head) = view.head else {
        return Ok(());
    };
    // v62.0.0 (wave GC5; CC 2.7.3) — the named roster version is an input:
    // unheld, the change WAITS (held); of another group, it concludes
    // nothing.
    fold::reads(Dep::Row(head));
    let held = dir.edition2_voices(&head).await?;
    let Some(st) = held.first() else {
        return Err(unheld(&row.row_id, &head));
    };
    let roster = roster_view_of_statement(st)?;
    if roster.group != view.group || roster.kind != view.kind {
        return Err(fold::hold(
            reason::NAMES_ANOTHER_GROUP,
            invalid(format!(
                "membership: refs.head of {} names a roster of another group ({:?})",
                row.row_id.hex(),
                roster.group
            )),
        ));
    }
    Ok(())
}

/// A counted membership change: the typed membership door, under the vouch
/// (and the replicated marker on the replicated door).
async fn put_membership<F>(
    dir: &F,
    row: &AdmittedRow,
    plane: GroupPlane,
    voices: BTreeMap<String, String>,
    replicated: bool,
) -> Result<Landing, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (view, mut record) = membership_of(plane, &row.sub, &row.payload)?;
    // v62.0.0 (KR-fix34b; PRE4-V300-a) — the typed record carries the row id
    // of the counted change it projects (the V300 `record_row_id` column):
    // the id a reverse-quorum objection names in `refs.answers`.
    let record_row_id = Some(row.row_id.0);
    match &mut record {
        MembershipRecord::FamilyRemoval(r) => r.record_row_id = record_row_id,
        MembershipRecord::CommunityRemoval(r) => r.record_row_id = record_row_id,
        MembershipRecord::FamilyWidening(w) => w.record_row_id = record_row_id,
        MembershipRecord::CommunityWidening(w) => w.record_row_id = record_row_id,
    }
    // v62.0.0 (wave GC5) — the group's roster planes and head, and the
    // member's own rows (its acceptance, its steward binding), are inputs.
    fold::reads(Dep::key(&view.group));
    fold::reads(Dep::key(&view.member));
    check_membership_head(dir, row, &view).await?;
    // A membership change is proposed by a member, never by the group key:
    // the primary is the first signer in order.
    let (primary, marker, cosignatures) = signature_columns(&voices, "");
    let envelope = match &record {
        MembershipRecord::FamilyRemoval(r) => r.signing_envelope(),
        MembershipRecord::CommunityRemoval(r) => r.signing_envelope(),
        MembershipRecord::FamilyWidening(w) => w.signing_envelope(),
        MembershipRecord::CommunityWidening(w) => w.signing_envelope(),
    };
    let vouch = Vouch {
        envelope_hash: envelope_hash(&envelope)?,
        voices,
        change_envelope: None,
        short: AtomicBool::new(false),
    };
    let pqc = Some(marker.clone());
    let door = async move {
        match record {
            MembershipRecord::FamilyRemoval(r) => {
                dir.put_family_membership_revocation(SignedFamilyMembershipRevocation {
                    family_membership_revocation: r,
                    authority_key_id: primary,
                    scrub_signature_classical: marker,
                    scrub_signature_pqc: pqc,
                    cosignatures,
                })
                .await
            }
            MembershipRecord::CommunityRemoval(r) => {
                dir.put_community_membership_revocation(SignedCommunityMembershipRevocation {
                    community_membership_revocation: r,
                    authority_key_id: primary,
                    scrub_signature_classical: marker,
                    scrub_signature_pqc: pqc,
                    cosignatures,
                })
                .await
            }
            MembershipRecord::FamilyWidening(w) => {
                dir.put_family_membership_widening(SignedFamilyMembershipWidening {
                    family_membership_widening: w,
                    authority_key_id: primary,
                    scrub_signature_classical: marker,
                    scrub_signature_pqc: pqc,
                    cosignatures,
                })
                .await
            }
            MembershipRecord::CommunityWidening(w) => {
                dir.put_community_membership_widening(SignedCommunityMembershipWidening {
                    community_membership_widening: w,
                    authority_key_id: primary,
                    scrub_signature_classical: marker,
                    scrub_signature_pqc: pqc,
                    cosignatures,
                })
                .await
            }
        }
    };
    if replicated {
        run_vouched(
            vouch,
            crate::federation::group_plane::as_replicated_group_row(door),
        )
        .await
    } else {
        run_vouched(vouch, door).await
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The roster while the head is forked (CC 2.7.8)
// ─────────────────────────────────────────────────────────────────────────

/// A version snapshot's `persist_row_hash`: the bare record's, or the signed
/// wrapper's record's (`family` / `community`).
fn snapshot_hash(s: &serde_json::Value) -> Option<String> {
    let record = |k: &str| s.get(k).and_then(|r| r.get("persist_row_hash"));
    s.get("persist_row_hash")
        .or_else(|| record("family"))
        .or_else(|| record("community"))
        .and_then(serde_json::Value::as_str)
        .filter(|h| !h.is_empty())
        .map(str::to_owned)
}

/// A version snapshot's listed members' key ids (bare record or signed
/// wrapper).
fn snapshot_members(s: &serde_json::Value) -> BTreeSet<String> {
    let record = s.get("family").or_else(|| s.get("community")).unwrap_or(s);
    record
        .get("members")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|m| m.get("key_id").and_then(serde_json::Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// v62.0.0 (wave T1; CC 2.7.8, "Two versions of one head wait as tips. The
/// roster is then the members common to all tips, until a version naming
/// the tips makes one head again") — **the members the forked tips have in
/// common**, or `None` when the head is not forked.
///
/// The tips are the leaves of the held version graph: the head
/// (`head_hash`, which no held tip names) and each held tip
/// (`federation_group_tips`, K1) that descends from a held version (the
/// head, a version in `federation_group_versions`, or another such tip) and
/// that no other such tip names. A tip waiting on a version this node does
/// not hold is not in the graph yet and narrows nothing. The caller keeps,
/// of the head's own authorized roster, only the members in the returned
/// set: the roster is the members common to all tips.
///
/// v62.0.0 (PX-fix3) — a directory with no tip store (`list_group_tips`
/// `Unsupported`) is an ERROR, never "no fork": read as `None`, a forked
/// group's roster was the head's own (fail-open, through the capsule proxy
/// before it routed the read; I2190, I2191).
///
/// # Errors
/// Directory read failures.
pub async fn forked_tip_members<F>(
    dir: &F,
    cohort: Cohort,
    group: &str,
    head_hash: &str,
) -> Result<Option<BTreeSet<String>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let tips = dir.list_group_tips(cohort, group).await?;
    if tips.is_empty() {
        return Ok(None);
    }
    // A version naming none (`""`) is a root, as the head's own lineage is.
    let mut rooted: BTreeSet<String> = BTreeSet::from([head_hash.to_owned(), String::new()]);
    for v in dir.list_group_versions(cohort, group).await? {
        if let Some(h) = snapshot_hash(&v.snapshot) {
            rooted.insert(h);
        }
    }
    let mut in_graph: Vec<usize> = Vec::new();
    loop {
        let before = in_graph.len();
        for (i, t) in tips.iter().enumerate() {
            if !in_graph.contains(&i) && rooted.contains(&t.prev_head_digest) {
                rooted.insert(t.persist_row_hash.clone());
                in_graph.push(i);
            }
        }
        if in_graph.len() == before {
            break;
        }
    }
    let named: BTreeSet<&str> = in_graph
        .iter()
        .map(|&i| tips[i].prev_head_digest.as_str())
        .collect();
    let mut common: Option<BTreeSet<String>> = None;
    for &i in &in_graph {
        if named.contains(tips[i].persist_row_hash.as_str()) {
            continue;
        }
        let members = snapshot_members(&tips[i].snapshot);
        common = Some(match common {
            None => members,
            Some(c) => c.intersection(&members).cloned().collect(),
        });
    }
    Ok(common)
}

// ─────────────────────────────────────────────────────────────────────────
//  The payload writers (typed record → statement payload)
// ─────────────────────────────────────────────────────────────────────────

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// A deterministic map: entries sorted by their keys' encodings.
fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&text(k)));
    Value::Map(m.into_iter().map(|(k, v)| (text(k), v)).collect())
}

fn ms_of(member: &str, at: chrono::DateTime<chrono::Utc>) -> Result<Value, Error> {
    u64::try_from(at.timestamp_millis())
        .map(Value::Uint)
        .map_err(|_| invalid(format!("`{member}` is before the epoch")))
}

/// A JSON value as CBOR, for an open map member (`policy`). Text, integers,
/// booleans, null, arrays and text-keyed maps (sorted by key encoding);
/// a non-integer number is refused (CC 2.6.1.5: no floats).
///
/// # Errors
/// `edition2_payload_invalid` for a non-integer number.
pub fn cbor_of_json(v: &serde_json::Value) -> Result<Value, Error> {
    use serde_json::Value as J;
    Ok(match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::String(s) => Value::Text(s.clone()),
        J::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::Uint(u)
            } else if let Some(i) = n.as_i64() {
                // i < 0 here: CBOR's negative integer -1 - n.
                Value::Nint(i.unsigned_abs() - 1)
            } else {
                return Err(invalid(format!("{n} is not an integer (CC 2.6.1.5)")));
            }
        }
        J::Array(a) => Value::Array(a.iter().map(cbor_of_json).collect::<Result<_, _>>()?),
        J::Object(o) => {
            let mut m: Vec<(Value, Value)> = o
                .iter()
                .map(|(k, v)| Ok::<(Value, Value), Error>((text(k), cbor_of_json(v)?)))
                .collect::<Result<_, Error>>()?;
            m.sort_by_key(|(k, _)| cde::encode(k));
            Value::Map(m)
        }
    })
}

/// **The inverse of [`record_of_roster`]**: a typed group record as its
/// `group:roster` payload at `version`, extending `head` (none on version
/// 1), stated at `asserted_at_ms`. `prev_head_digest` and
/// `persist_row_hash` are not carried (the row id and `refs.head` replace
/// them); the charter rides `refs.also.cites`. For producers and fixtures.
///
/// # Errors
/// An instant before the epoch; a non-integer number in a community's
/// `policy_blob`.
pub fn roster_payload(
    record: &GroupRecord,
    version: u64,
    head: Option<&RowId>,
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    roster_payload_merging(record, version, head, &[], asserted_at_ms)
}

/// v62.0.0 (GID-prod.fix1) — **what a host states to found a community**:
/// everything of its first version EXCEPT the id (derived, never passed in:
/// a clean break, no ignored argument) and the server-computed fields.
#[derive(Debug, Clone)]
pub struct CommunityFounding {
    /// The community's name (human-readable, not unique, never an id).
    pub name: String,
    /// The founding members (their keys derive the id).
    pub members: Vec<crate::federation::types::CommunityMember>,
    /// The founding instant (derives the id).
    pub founded_at: chrono::DateTime<chrono::Utc>,
    /// The `consensus_protocol`.
    pub consensus_protocol: String,
    /// The `policy_blob` (an open map).
    pub policy_blob: Option<serde_json::Value>,
    /// The charter in force (`trust:charter:v1` row hash), empty for none.
    pub charter_digest: String,
}

/// v62.0.0 (GID-prod.fix1) — the family twin of [`CommunityFounding`].
#[derive(Debug, Clone)]
pub struct FamilyFounding {
    /// The family's name.
    pub name: String,
    /// The founding members (their keys derive the id).
    pub members: Vec<crate::federation::types::FamilyMember>,
    /// The founding instant (derives the id).
    pub founded_at: chrono::DateTime<chrono::Utc>,
    /// The `consensus_protocol`.
    pub consensus_protocol: String,
    /// `consensus_protocol_entrenched`.
    pub consensus_protocol_entrenched: bool,
    /// The charter in force, empty for none.
    pub charter_digest: String,
}

impl CommunityFounding {
    /// The first version's record, its id still empty (set by
    /// [`founding_payload`]).
    #[must_use]
    pub fn into_record(self) -> GroupRecord {
        GroupRecord::Community(crate::federation::types::Community {
            prev_head_digest: String::new(),
            charter_digest: self.charter_digest,
            community_key_id: String::new(),
            community_name: self.name,
            members: self.members,
            founded_at: self.founded_at,
            consensus_protocol: self.consensus_protocol,
            policy_blob: self.policy_blob,
            persist_row_hash: String::new(),
        })
    }
}

impl FamilyFounding {
    /// The first version's record, its id still empty (set by
    /// [`founding_payload`]).
    #[must_use]
    pub fn into_record(self) -> GroupRecord {
        GroupRecord::Family(crate::federation::types::Family {
            family_key_id: String::new(),
            family_name: self.name,
            members: self.members,
            founded_at: self.founded_at,
            consensus_protocol: self.consensus_protocol,
            consensus_protocol_entrenched: self.consensus_protocol_entrenched,
            dissolved_at: None,
            prev_head_digest: String::new(),
            charter_digest: self.charter_digest,
            persist_row_hash: String::new(),
        })
    }
}

/// v62.0.0 (GID-prod) — what a founding verb answers: the group's DERIVED id
/// (no caller passes one in) and the statement door's outcome.
#[derive(Debug)]
pub struct GroupFounding {
    /// The id the founding derives ([`super::group_id::derive_group_id`]).
    pub group_id: String,
    /// The door's outcome for the first version.
    pub outcome: super::ingest::StatementOutcome,
}

/// v62.0.0 (GID-prod; CIRISConstitution "THE DERIVED GROUP ID") — **the
/// FIRST version's payload, under its derived id.** The id is derived from
/// `record`'s kind, the key of EVERY member it lists, its `founded_at` and
/// `nonce` ([`super::group_id::derive_group_id`]); `record`'s id is set to
/// it (whatever it held), the payload is [`roster_payload`] at version 1
/// with no head, and it carries `nonce`. The founding verbs mint the nonce
/// ([`super::group_id::fresh_nonce`]); a fixture passes a fixed one.
///
/// # Errors
/// As [`roster_payload`]; a `founded_at` before the epoch.
pub fn founding_payload(
    record: &mut GroupRecord,
    nonce: &[u8; 32],
    asserted_at_ms: u64,
) -> Result<(String, Value), Error> {
    let (kind, founded_at, founders): (&str, _, Vec<String>) = match &*record {
        GroupRecord::Family(f) => (
            "family",
            f.founded_at,
            f.members.iter().map(|m| m.key_id.clone()).collect(),
        ),
        GroupRecord::Community(c) => (
            "community",
            c.founded_at,
            c.members.iter().map(|m| m.key_id.clone()).collect(),
        ),
    };
    let founded_ms = ms_of("founded_at", founded_at)?
        .as_u64()
        .ok_or_else(|| invalid("group:roster: `founded_at` is not a uint"))?;
    let refs: Vec<&str> = founders.iter().map(String::as_str).collect();
    let id = super::group_id::derive_group_id(kind, &refs, founded_ms, nonce);
    match record {
        GroupRecord::Family(f) => f.family_key_id.clone_from(&id),
        GroupRecord::Community(c) => c.community_key_id.clone_from(&id),
    }
    let mut payload = roster_payload(record, 1, None, asserted_at_ms)?;
    let Value::Map(m) = &mut payload else {
        return Err(invalid("group:roster: the payload is not a map"));
    };
    m.push((text("nonce"), Value::Bytes(nonce.to_vec())));
    m.sort_by_key(|(k, _)| cde::encode(k));
    Ok((id, payload))
}

/// [`roster_payload`] of a MERGE (CC 2.7.8): beside `refs.head` it names
/// the further tips it makes one head with, `refs.further_heads` (a set,
/// sorted by encoding, unique; CC 2.6.1.9). Empty `further` is
/// [`roster_payload`].
///
/// # Errors
/// As [`roster_payload`].
pub fn roster_payload_merging(
    record: &GroupRecord,
    version: u64,
    head: Option<&RowId>,
    further: &[RowId],
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    roster_payload_full(record, version, head, further, &[], asserted_at_ms)
}

/// v62.0.0 (wave GC5; CC rc21 3.2, CC27 item 4) — [`roster_payload`] of a
/// GEOGRAPHIC community's version naming each new member's
/// `location_proof` row under `refs.also.cites` (a set, its charter beside
/// them; ruling (b), [`charter_of`]). For producers and fixtures.
///
/// # Errors
/// As [`roster_payload`].
pub fn roster_payload_citing(
    record: &GroupRecord,
    version: u64,
    head: Option<&RowId>,
    proofs: &[RowId],
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    roster_payload_full(record, version, head, &[], proofs, asserted_at_ms)
}

fn roster_payload_full(
    record: &GroupRecord,
    version: u64,
    head: Option<&RowId>,
    further: &[RowId],
    proofs: &[RowId],
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    let member_entry = |key: &str, joined: chrono::DateTime<chrono::Utc>, role: Option<&str>| {
        let mut e = vec![
            ("key", text(key)),
            ("joined_at", ms_of("joined_at", joined)?),
        ];
        if let Some(r) = role {
            e.push(("role", text(r)));
        }
        Ok::<Value, Error>(det_map(e))
    };
    let (kind, group, name, members, founded_at, protocol, charter) = match record {
        GroupRecord::Family(f) => (
            "family",
            &f.family_key_id,
            &f.family_name,
            f.members
                .iter()
                .map(|m| member_entry(&m.key_id, m.joined_at, m.role.as_deref()))
                .collect::<Result<Vec<_>, _>>()?,
            f.founded_at,
            &f.consensus_protocol,
            &f.charter_digest,
        ),
        GroupRecord::Community(c) => (
            "community",
            &c.community_key_id,
            &c.community_name,
            c.members
                .iter()
                .map(|m| member_entry(&m.key_id, m.joined_at, m.role.as_deref()))
                .collect::<Result<Vec<_>, _>>()?,
            c.founded_at,
            &c.consensus_protocol,
            &c.charter_digest,
        ),
    };
    let mut members = members;
    // A roster's `members` is a SET (CC 2.6.1.2; P1's `Ty::RosterMembers`):
    // sorted by each ELEMENT's deterministic encoding, not by its `key`. A
    // member with a `role` is a 3-entry map and encodes after every 2-entry
    // one, so the two orders differ once roles are present.
    members.sort_by_key(cde::encode);
    members.dedup();
    let mut p = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("group_kind", text(kind)),
        ("group", text(group)),
        ("name", text(name)),
        ("version", Value::Uint(version)),
        ("members", Value::Array(members)),
        ("founded_at", ms_of("founded_at", founded_at)?),
        ("consensus_protocol", text(protocol)),
    ];
    match record {
        GroupRecord::Family(f) => {
            if f.consensus_protocol_entrenched {
                p.push(("consensus_protocol_entrenched", Value::Bool(true)));
            }
            if let Some(d) = f.dissolved_at {
                p.push(("dissolved_at", ms_of("dissolved_at", d)?));
            }
        }
        GroupRecord::Community(c) => {
            if let Some(b) = &c.policy_blob {
                p.push(("policy", cbor_of_json(b)?));
            }
        }
    }
    let mut refs: Vec<(&str, Value)> = Vec::new();
    if let Some(h) = head {
        refs.push((HEAD_ROLE, ciris_verify_core::edition2::row_ref(&h.0)));
    }
    if !further.is_empty() {
        let mut set: Vec<Value> = further
            .iter()
            .map(|r| ciris_verify_core::edition2::row_ref(&r.0))
            .collect();
        set.sort_by_key(cde::encode);
        set.dedup();
        refs.push((FURTHER_HEADS_ROLE, Value::Array(set)));
    }
    // v62.0.0 (wave GC5; ruling (b)) — the charter and a geographic
    // version's location proofs ride ONE `refs.also.cites` set (no wire
    // change); a reader tells the charter apart at the chain head
    // ([`resolve_geographic_charter`]).
    let mut cites: Vec<Value> = proofs
        .iter()
        .map(|r| ciris_verify_core::edition2::row_ref(&r.0))
        .collect();
    if !charter.is_empty() {
        let d: [u8; 32] = hex::decode(charter)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| invalid("charter_digest is not a 64-hex row id"))?;
        cites.push(ciris_verify_core::edition2::row_ref(&d));
    }
    // v62.0.0 (E13 fix1) — `refs.also.cites` is a SET of row-refs even
    // when it names one row (Verify 23.3 `check_refs`: `also` roles go
    // through `check_row_ref_set`; a bare row-ref is `malformed:also`).
    let mut also: Vec<(&str, Value)> = Vec::new();
    if !cites.is_empty() {
        cites.sort_by_key(cde::encode);
        cites.dedup();
        also.push(("cites", Value::Array(cites)));
    }
    if !also.is_empty() {
        refs.push(("also", det_map(also)));
    }
    if !refs.is_empty() {
        p.push(("refs", det_map(refs)));
    }
    Ok(det_map(p))
}

/// **The inverse of [`membership_of`]**: a typed membership record as its
/// counted `membership:{stage}` payload (dimension
/// `membership:{removal|widening}:v1`), counted over the roster version
/// `head`, stated at the record's `effective_at`. A `reason` that is a
/// decimal code rides `reason` (uint); any other text rides `body.note`.
///
/// # Errors
/// An instant before the epoch.
pub fn membership_payload(record: &MembershipRecord, head: Option<&RowId>) -> Result<Value, Error> {
    let mut p: Vec<(&str, Value)> = Vec::new();
    let (stage, kind, group, member, effective_at) = match record {
        MembershipRecord::FamilyRemoval(r) => (
            REMOVAL_LEAF,
            "family",
            &r.family_key_id,
            &r.removed_identity_key_id,
            r.effective_at,
        ),
        MembershipRecord::CommunityRemoval(r) => (
            REMOVAL_LEAF,
            "community",
            &r.community_key_id,
            &r.removed_identity_key_id,
            r.effective_at,
        ),
        MembershipRecord::FamilyWidening(w) => (
            WIDENING_LEAF,
            "family",
            &w.family_key_id,
            &w.member_key_id,
            w.effective_at,
        ),
        MembershipRecord::CommunityWidening(w) => (
            WIDENING_LEAF,
            "community",
            &w.community_key_id,
            &w.member_key_id,
            w.effective_at,
        ),
    };
    p.push(("asserted_at", ms_of("effective_at", effective_at)?));
    p.push(("dimension", text(&format!("membership:{stage}:v1"))));
    p.push(("group_kind", text(kind)));
    p.push(("group", text(group)));
    p.push(("member", text(member)));
    p.push(("effective_at", ms_of("effective_at", effective_at)?));
    fn removal(
        p: &mut Vec<(&str, Value)>,
        removed_at: chrono::DateTime<chrono::Utc>,
        reason: Option<&str>,
        witness_set: &[String],
    ) -> Result<(), Error> {
        p.push(("removed_at", ms_of("removed_at", removed_at)?));
        if let Some(r) = reason {
            match r.parse::<u64>() {
                Ok(code) => p.push(("reason", Value::Uint(code))),
                Err(_) => p.push(("body", det_map(vec![("note", text(r))]))),
            }
        }
        if !witness_set.is_empty() {
            let mut w: Vec<Value> = witness_set.iter().map(|k| text(k)).collect();
            w.sort_by_key(cde::encode);
            w.dedup();
            p.push(("witness_set", Value::Array(w)));
        }
        Ok(())
    }
    match record {
        MembershipRecord::FamilyRemoval(r) => {
            removal(&mut p, r.removed_at, r.reason.as_deref(), &r.witness_set)?;
        }
        MembershipRecord::CommunityRemoval(r) => {
            removal(&mut p, r.removed_at, r.reason.as_deref(), &r.witness_set)?;
        }
        MembershipRecord::FamilyWidening(w) => {
            p.push(("joined_at", ms_of("joined_at", w.joined_at)?));
            if let Some(r) = &w.role {
                p.push(("role", text(r)));
            }
        }
        MembershipRecord::CommunityWidening(w) => {
            p.push(("joined_at", ms_of("joined_at", w.joined_at)?));
            if let Some(r) = &w.role {
                p.push(("role", text(r)));
            }
        }
    }
    if let Some(h) = head {
        p.push((
            "refs",
            det_map(vec![(
                HEAD_ROLE,
                ciris_verify_core::edition2::row_ref(&h.0),
            )]),
        ));
    }
    Ok(det_map(p))
}

/// v62.0.0 (v62 P8) — **one voice of a counted removal (or widening),
/// drafted for a roster member's pen**: the [`membership_payload`] over the
/// roster version `head`, under `sub` = the member it changes, in family
/// [`MEMBERSHIP_PREFIX`], for the signer `signer_iss`. The member signs the
/// draft's `sig_structure` and submits `Draft::assemble(signature)` (to
/// `at_rest_cascade::orchestrate::rekey_community_member_revoke_voices`, or
/// the statement door).
///
/// # Errors
/// As [`membership_payload`]; `signer_iss` that is not an identity-ref.
pub fn removal_draft(
    record: &MembershipRecord,
    head: &RowId,
    signer_iss: &str,
) -> Result<super::emit::Draft, Error> {
    let member = match record {
        MembershipRecord::FamilyRemoval(r) => r.removed_identity_key_id.clone(),
        MembershipRecord::CommunityRemoval(r) => r.removed_identity_key_id.clone(),
        MembershipRecord::FamilyWidening(w) => w.member_key_id.clone(),
        MembershipRecord::CommunityWidening(w) => w.member_key_id.clone(),
    };
    let kid = super::ingest::kid_of_identity_ref(signer_iss).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "removal_draft: {signer_iss} is not an identity-ref"
        ))
    })?;
    let payload = membership_payload(record, Some(head))?;
    super::emit::draft_row(
        &kid,
        signer_iss,
        &member,
        "scores",
        &ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX),
        &payload,
    )
    .map_err(|e| super::emit::produce_error("membership", e))
}

/// v62.0.0 (HEAD-3; CC 2.4.1.1, "A count that ends a standing MAY state
/// `lifts`, and then only the count's own receipts keep an act in force") —
/// **[`removal_draft`] stating `lifts: true`**: the unseating is the
/// roster's COUNT (no `author`, counted over `head`), so it may lift single
/// receipts. `lifts` is a top-level payload member, present only as `true`
/// (`payloads::check_lifts`); a widening is no end and is refused it.
///
/// # Errors
/// As [`removal_draft`]; `edition2_payload_invalid` for a widening.
pub fn removal_draft_lifting(
    record: &MembershipRecord,
    head: &RowId,
    signer_iss: &str,
) -> Result<super::emit::Draft, Error> {
    let member = match record {
        MembershipRecord::FamilyRemoval(r) => r.removed_identity_key_id.clone(),
        MembershipRecord::CommunityRemoval(r) => r.removed_identity_key_id.clone(),
        MembershipRecord::FamilyWidening(_) | MembershipRecord::CommunityWidening(_) => {
            return Err(Error::InvalidArgument(
                "edition2_payload_invalid: a widening ends no standing: it states no `lifts`"
                    .into(),
            ));
        }
    };
    let kid = super::ingest::kid_of_identity_ref(signer_iss).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "removal_draft_lifting: {signer_iss} is not an identity-ref"
        ))
    })?;
    let payload = super::emit::with_member(
        membership_payload(record, Some(head))?,
        "lifts",
        Value::Bool(true),
    )
    .map_err(|e| super::emit::produce_error("membership", e))?;
    super::emit::draft_row(
        &kid,
        signer_iss,
        &member,
        "scores",
        &ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX),
        &payload,
    )
    .map_err(|e| super::emit::produce_error("membership", e))
}
