//! v62.0.0 (wave T2; CC 2.6.1, CC 2.6.1.9, CC 3.1.3, CC 3.1.3.3, CC 3.1.5,
//! CC 3.3.2, CC 3.3.6.4) — **the remaining edition-2 families in their
//! typed tables: one rule set, two codecs.**
//!
//! Cut A mapped every edition-2 row through [`super::ingest::attestation_of`]
//! into `federation_attestations`. For the families below that row is not
//! the typed row their gates and reads consult, so an edition-2 row of them
//! was never seen there. Each is routed here from
//! [`super::ingest::put_admitted_row`] to the JSON form's own door, with the
//! payload mapped one to one onto the typed struct
//! (`docs/EDITION2_PAYLOADS.md`), never an embedded signed object:
//!
//! | family | the door | lands in |
//! |---|---|---|
//! | `identity:occurrence_revocation` | (A) a node/agent identity: the carrier's single-signer rule; (B) a user self: the self-roster's two-path decision (`self_roster::gate_edition2`); then the projection write the carrier feeds | `federation_identity_occurrence_revocations` |
//! | `revocation:{entity_type}:{reason}` | `put_revocation` (`key_plane::plan_put_revocation`), under the vouch | `federation_revocations` |
//! | `takedown_notice:{basis}` | `put_attestation` (the takedown notice gate reads the projected envelope) | `federation_attestations` |
//! | `takedown_notice:steward_purge` | none: its row door is held shut (CIRISPersist#988); the purge door counts the stewards' voices | `ceg_statements` |
//! | `custody:{kind}` | `put_attestation` (the custody gate; the holding-claim fold reads the row) | `federation_attestations` |
//! | `key_grant:{axis}` | `put_attestation`, then the grant projection the typed doors run (`project_key_grant_row`) | `federation_attestations` + the grant tables |
//! | `delivery_receipt:{stream_id}` | the receipt door's JOIN and equivocation steps; the signed receipt row through `put_attestation` (`custody_ack::signed_receipt_at` reads it) | `federation_stream_delivery_receipts` + `federation_attestations` |
//! | `cosign:{state}` | none: the hold IS the counted row (CC 3.1.3; [`crate::federation::cosign`]) | `ceg_statements` |
//!
//! # Counted voices
//!
//! What the earlier form carried as a co-scrub is a further statement over
//! the same payload (CC 2.6.1.9): every voice of a row shares its row id.
//! - **`identity:occurrence_revocation`, a user self**: a roster change,
//!   decided by the self-roster's two-path decision
//!   (`self_roster::gate_edition2`, O1): the quorum path over the held
//!   voices signed as the self by live roster keys, else the lone path after
//!   `W_self`. Each voice is signed as the identity (the door's key-of-issuer
//!   check admits only its keys at the statement's instant). Short,
//!   the voice is kept ([`StatementOutcome::Pending`]); the decision lands
//!   the revocation.
//! - **`takedown_notice:steward_purge`**: every voice is kept
//!   ([`StatementOutcome::Pending`]); the notice is counted by the purge door
//!   under the trust root's protocol when the purge runs.
//!
//! # The envelope projection
//!
//! The attestation-backed families keep the JSON door's gates, which read
//! the earlier envelope's member names. [`project_envelope`], called by
//! [`super::ingest::attestation_of`], renames the edition-2 members back
//! (and states each hash digest as the 64 lowercase hex the gates read), so
//! the put, `verify_carried` and `check_carried_projection` read ONE
//! projection. The writers ([`custody_payload`], [`key_grant_payload`],
//! [`takedown_payload`], [`delivery_receipt_payload`],
//! [`revocation_payload`], [`occurrence_revocation_payload`]) are the
//! inverse, for producers and fixtures.

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{hash_digest_value, is_identity_ref};
use ciris_verify_core::namespace_match;
use sha2::Digest as _;

use super::door::AdmittedRow;
use super::group::{composite_signature_b64, run_vouched, Landing, Vouch};
use super::ingest::{attestation_of, json_of, StatementOutcome, COMPOSER_ROW_TYPES};
use super::names::{single, RowId};
use crate::federation::blobs::GrantWrap;
use crate::federation::custody_ack::CustodyState;
use crate::federation::key_grant::{KeyGrantAxis, KeyGrantRow};
use crate::federation::stream_receipt::DeliveryReceipt;
use crate::federation::types::{
    cohort_scope as cs, IdentityOccurrenceRevocation, Revocation, SignedAttestation,
    SignedRevocation,
};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The plane name this module's refusals carry.
pub const PLANE: &str = "edition2_typed";

/// `identity:occurrence_revocation` (a family with no parameter).
pub const OCCURRENCE_REVOCATION_PREFIX: &str = "identity:occurrence_revocation";
/// `cosign:{state}`.
pub const COSIGN_PREFIX: &str = "cosign:{state}";
/// `revocation:{entity_type}:{reason}`.
pub const REVOCATION_PREFIX: &str = "revocation:{entity_type}:{reason}";
/// `takedown_notice:{basis}`.
pub const TAKEDOWN_PREFIX: &str = "takedown_notice:{basis}";
/// `custody:{kind}`.
pub const CUSTODY_PREFIX: &str = "custody:{kind}";
/// `key_grant:{axis}`.
pub const KEY_GRANT_PREFIX: &str = "key_grant:{axis}";
/// `delivery_receipt:{stream_id}`.
pub const DELIVERY_RECEIPT_PREFIX: &str = "delivery_receipt:{stream_id}";

/// The `refs` role a cosign statement names the event it cosigns by.
pub const TARGET_ROLE: &str = "target";

/// v62.0.0 (wave T2; CC27 item 2) — the `refs` role an `identity:occurrence`
/// bind or `identity:occurrence_revocation` names the self-roster head it is
/// counted over by (REQUIRED: the last landed bind or eviction, or the
/// genesis key's own `key:record` row).
pub const SELF_ROSTER_HEAD_ROLE: &str = "head";

/// Which typed plane an edition-2 row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypedPlane {
    /// `identity:occurrence_revocation`.
    OccurrenceRevocation,
    /// `cosign:{state}` (`pending` | `signature`).
    Cosign,
    /// `revocation:{entity_type}:{reason}`.
    Revocation,
    /// `takedown_notice:{basis}`.
    Takedown,
    /// `custody:{kind}`.
    Custody,
    /// `key_grant:{axis}`.
    KeyGrant,
    /// `delivery_receipt:{stream_id}`.
    DeliveryReceipt,
}

/// Each typed plane's registry prefix.
pub const PLANES: [(&str, TypedPlane); 7] = [
    (
        OCCURRENCE_REVOCATION_PREFIX,
        TypedPlane::OccurrenceRevocation,
    ),
    (COSIGN_PREFIX, TypedPlane::Cosign),
    (REVOCATION_PREFIX, TypedPlane::Revocation),
    (TAKEDOWN_PREFIX, TypedPlane::Takedown),
    (CUSTODY_PREFIX, TypedPlane::Custody),
    (KEY_GRANT_PREFIX, TypedPlane::KeyGrant),
    (DELIVERY_RECEIPT_PREFIX, TypedPlane::DeliveryReceipt),
];

/// **Is this row one of the typed planes?** By its header family id
/// (label -70002, `namespace_match::family_id` of the registry prefix). A
/// composer (`withdraws`, `recants`, `supersedes`) carries its target's
/// family but is the attestation plane's: `None`.
#[must_use]
pub fn typed_plane_of(row_type: &str, family: &str) -> Option<TypedPlane> {
    if COMPOSER_ROW_TYPES.contains(&row_type) {
        return None;
    }
    PLANES
        .iter()
        .find(|(prefix, _)| namespace_match::family_id(prefix) == family)
        .map(|(_, plane)| *plane)
}

/// v62.0.0 (P1-fix4, E3's finding) — [`typed_plane_of`] for an admitted row:
/// a peer DE-ADMISSION (`revocation:peer_admission:{reason}:v1`) carries the
/// revocation family but is a `scores` denial about a peer, read by
/// `admission::check_peer_deadmission` from the attestation plane; it is no
/// entity revocation, so it rides no typed plane (no `revoked_at` to
/// project). Every other row as [`typed_plane_of`].
#[must_use]
pub fn typed_plane_of_row(row: &AdmittedRow) -> Option<TypedPlane> {
    let plane = typed_plane_of(&row.row_type, &row.family)?;
    if plane == TypedPlane::Revocation
        && row
            .payload
            .get_text("dimension")
            .and_then(Value::as_text)
            .is_some_and(crate::federation::admission::is_peer_deadmission_dimension)
    {
        return None;
    }
    Some(plane)
}

/// v62.0.0 (SL-fix1) — the `slashing:{outcome}` family, as CC's registry
/// spells it (CC 3.1.9.2): the header id its statements carry is
/// `namespace_match::family_id` of it.
const SLASHING_NAMESPACE_FAMILY: &str = "slashing:{outcome}";

/// v62.0.0 (K2-fix13, SL-fix1) — is `family` (a header family id) one of the
/// two `slash` duty families, `quarantine:{state}` or `slashing:{outcome}`?
/// CC's family model states ONE authorship cell for both (`group=affiliations
/// & seats=one => counted ; authored`), so the door supplies both the same
/// context.
fn is_slash_family(family: &str) -> bool {
    family == namespace_match::family_id(crate::federation::quarantine::NAMESPACE_FAMILY)
        || family == namespace_match::family_id(SLASHING_NAMESPACE_FAMILY)
}

/// v62.0.0 (T2-fix3) — **the selector keys a typed family's authorship cell
/// reads, from the statement's bytes alone**, for an admit that supplies
/// none (`door::door_context`; a key already `Some` is kept):
///
/// - `takedown_notice:{basis}`: `group` from the payload's `cohort_scope`
///   when it names a group scope; a notice at no group has no deciding seats
///   (`seats = 0`), so the affiliation arm reads false, not unknown.
/// - `identity:occurrence_revocation` (`identity=user => counted ;
///   authored`): a statement with no `author` is the user self's counted
///   row, `identity = {user}`; one with an `author` is authored (`identity
///   = {}`). The put door supplied the identity's TRUE types
///   ([`family_context`]) when the row was first admitted, and a counted row
///   carries no author by CC 2.6.1.3, so a re-admission of held bytes reaches
///   the verdict it was admitted under.
/// - `quarantine:{state}` and (v62.0.0, SL-fix1) `slashing:{outcome}`: an
///   AUTHORED statement is the authored arm's (`seats = 0`); a counted one
///   needs the held community ([`family_context`]).
pub fn fill_context_from_bytes(
    bytes: &[u8],
    ctx: &mut ciris_verify_core::edition2::family::SelectContext,
) {
    use ciris_verify_core::edition2::family::select::Group;
    let Some((protected, payload)) = super::liveness::statement_parts(bytes) else {
        return;
    };
    let Some(family) = protected.get_int(-70002).and_then(Value::as_text) else {
        return;
    };
    if family == namespace_match::family_id(TAKEDOWN_PREFIX) {
        if ctx.group.is_none() {
            ctx.group = match text_of(&payload, "cohort_scope") {
                Some(cs::FAMILY) => Some(Group::Family),
                Some(cs::COMMUNITY) => Some(Group::Community),
                Some(cs::AFFILIATIONS) => Some(Group::Affiliations),
                _ => None,
            };
        }
        if ctx.seats.is_none() && ctx.group.is_none() {
            ctx.seats = Some(0);
        }
    } else if is_slash_family(family)
        && ctx.group.is_none()
        && ctx.seats.is_none()
        && payload.get_text("author").is_some()
    {
        // v62.0.0 (K2-fix13) — a re-admission of a held AUTHORED marker,
        // with no directory: an `author` is the authored arm's own column
        // (the counted arm has none), so the one-seat-affiliation test reads
        // false. A counted marker's context needs the held community
        // ([`family_context`]).
        ctx.seats = Some(0);
    } else if family == namespace_match::family_id(OCCURRENCE_REVOCATION_PREFIX)
        && ctx.identity.is_none()
    {
        ctx.identity = Some(if payload.get_text("author").is_some() {
            Vec::new()
        } else {
            vec![crate::federation::types::identity_type::USER.to_owned()]
        });
    }
}

/// v62.0.0 (T2-fix1; CC 3.1.3) — **the selector context a typed family's
/// authorship cell reads**, which Verify's door cannot know from the bytes
/// alone (`SelectContext` keys left `None` read unknown, and an undecided
/// cell is `authorship_undetermined`):
///
/// - `identity:occurrence_revocation` (`identity=user => counted ;
///   authored`): `identity` = the identity_type set of the identity the row
///   concerns (`identity_key_id`), from its held key record. A key not held
///   yet waits (the retryable unknown signer, naming it).
/// - `takedown_notice:{basis}` (`leaf=steward_purge => counted ;
///   group=affiliations & seats=one => counted ; authored`): `group` from the
///   payload's `cohort_scope` when it names a group scope; a notice placed
///   at no group has no deciding seats (`seats = 0`), so the affiliation arm
///   reads false rather than unknown; an `affiliations` notice's seats are
///   the held head's members.
/// - v62.0.0 (K2-fix13) `quarantine:{state}` (the same cell as a takedown
///   notice's affiliation arm): `group` = the cohort of the held record of
///   the marker's `community_id`; `seats` = an affiliation's members; a
///   community not held reads `seats = 0`.
/// - v62.0.0 (SL-fix1) `slashing:{outcome}`: the same cell as the quarantine
///   marker's (CC's family model states both `group=affiliations &
///   seats=one => counted ; authored`), read the same way from the row's
///   `community_id`. Without it the cell's first arm reads unknown, and a
///   slashing statement is `authorship_undetermined` at the door.
/// - every other family: the default (the door derives `act`).
///
/// # Errors
/// The retryable unknown signer for an identity whose key is not held;
/// directory reads.
pub async fn family_context<F>(
    dir: &F,
    bytes: &[u8],
) -> Result<ciris_verify_core::edition2::family::SelectContext, Error>
where
    F: FederationDirectory + ?Sized,
{
    use ciris_verify_core::edition2::family::{select::Group, SelectContext};
    let mut ctx = SelectContext::default();
    let Some((protected, payload)) = super::liveness::statement_parts(bytes) else {
        return Ok(ctx);
    };
    let Some(family) = protected.get_int(-70002).and_then(Value::as_text) else {
        return Ok(ctx);
    };
    if family == namespace_match::family_id(OCCURRENCE_REVOCATION_PREFIX) {
        if let Some(identity) = text_of(&payload, "identity_key_id") {
            let Some(key) = dir.lookup_public_key(identity).await? else {
                return Err(Error::unknown_signer(identity, PLANE));
            };
            ctx.identity = Some(
                key.identity_type
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
                    .collect(),
            );
        }
    } else if family == namespace_match::family_id(TAKEDOWN_PREFIX) {
        let group = match text_of(&payload, "cohort_scope") {
            Some(cs::FAMILY) => Some(Group::Family),
            Some(cs::COMMUNITY) => Some(Group::Community),
            Some(cs::AFFILIATIONS) => Some(Group::Affiliations),
            _ => None,
        };
        ctx.group = group;
        ctx.seats = match group {
            None => Some(0),
            Some(Group::Affiliations) => match text_of(&payload, "community_id") {
                Some(c) => dir
                    .lookup_community(c)
                    .await?
                    .map(|head| u64::try_from(head.members.len()).unwrap_or(u64::MAX)),
                None => None,
            },
            Some(_) => None,
        };
    } else if is_slash_family(family) {
        // v62.0.0 (K2-fix13; CC rc21 family model, `quarantine:{state}`:
        // `group=affiliations & seats=one => counted ; authored`) — `group`
        // is the cohort the held record of the marker's `community_id`
        // declares, and `seats` an affiliation's members at that head. A
        // community this node does not hold is no group here: no deciding
        // seats (`seats = 0`), so the affiliation arm reads false, as for a
        // takedown notice placed at no group.
        let held = match text_of(&payload, crate::federation::quarantine::field::COMMUNITY_ID) {
            Some(c) => dir.lookup_community(c).await?,
            None => None,
        };
        match held {
            Some(head) => {
                let affiliations = crate::federation::affiliation_config::declared_cohort(&head)?
                    == crate::federation::cohort::Cohort::Affiliations;
                ctx.group = Some(if affiliations {
                    Group::Affiliations
                } else {
                    Group::Community
                });
                ctx.seats =
                    affiliations.then(|| u64::try_from(head.members.len()).unwrap_or(u64::MAX));
            }
            None => ctx.seats = Some(0),
        }
    }
    Ok(ctx)
}

fn invalid(message: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, malformed_row::EDITION2_PAYLOAD_INVALID, message)
}

// ─────────────────────────────────────────────────────────────────────────
//  Payload readers
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

fn req_u64(p: &Value, member: &str) -> Result<u64, Error> {
    p.get_text(member)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("`{member}` is required (uint)")))
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

/// RFC 3339 at ms, the text form CC 2.6.3 gives an instant outside a
/// payload (and the one [`super::ingest::attestation_of`] writes).
fn rfc3339(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// A `[-16, bstr .size 32]` hash digest's bytes.
fn digest_bytes(v: &Value) -> Option<[u8; 32]> {
    match v.as_array()? {
        [alg, d] if alg.as_i64() == Some(-16) => {
            d.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok())
        }
        _ => None,
    }
}

fn digest_hex(v: &Value) -> Option<String> {
    digest_bytes(v).map(hex::encode)
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

/// `body.note`, the free text a coded `reason` leaves (CC 2.6.1.10).
fn note_of(p: &Value) -> Option<String> {
    p.get_text("body")
        .and_then(|b| b.get_text("note"))
        .and_then(Value::as_text)
        .map(str::to_owned)
}

/// The `n`-th segment of the payload's `dimension` (0 is the stem).
fn dimension_segment(p: &Value, n: usize) -> Option<&str> {
    text_of(p, "dimension")?.split(':').nth(n)
}

// ─────────────────────────────────────────────────────────────────────────
//  CBOR writers
// ─────────────────────────────────────────────────────────────────────────

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// A map in the deterministic order (each key's encoding, CC 2.6.1.2).
fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&text(k)));
    Value::Map(m.into_iter().map(|(k, v)| (text(k), v)).collect())
}

/// A set of identity-refs: sorted by each element's encoding, unique.
fn identity_set(xs: &[String]) -> Value {
    let mut e: Vec<Value> = xs.iter().map(|x| text(x)).collect();
    e.sort_by_key(cde::encode);
    e.dedup();
    Value::Array(e)
}

fn ms_of(at: chrono::DateTime<chrono::Utc>) -> Result<Value, Error> {
    u64::try_from(at.timestamp_millis())
        .map(Value::Uint)
        .map_err(|_| invalid("an instant before 1970 has no uint (ms) form"))
}

/// The fixed-scale form of a real (CC 2.6.1.5): `±1.0` as `±10^6`.
fn fixed6(real_millionths: i64) -> Value {
    match u64::try_from(real_millionths) {
        Ok(n) => Value::Uint(n),
        Err(_) => Value::Nint(real_millionths.unsigned_abs() - 1),
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The envelope projection (called by `attestation_of`)
// ─────────────────────────────────────────────────────────────────────────

fn rename(o: &mut serde_json::Map<String, serde_json::Value>, from: &str, to: &str) {
    if let Some(v) = o.remove(from) {
        o.insert(to.to_owned(), v);
    }
}

fn put_digest_hex(row: &AdmittedRow, o: &mut serde_json::Map<String, serde_json::Value>, m: &str) {
    if let Some(h) = row.payload.get_text(m).and_then(digest_hex) {
        o.insert(m.to_owned(), serde_json::Value::String(h));
    }
}

fn put_digests_hex(row: &AdmittedRow, o: &mut serde_json::Map<String, serde_json::Value>, m: &str) {
    let hexes: Option<Vec<String>> = row
        .payload
        .get_text(m)
        .and_then(Value::as_array)
        .and_then(|a| a.iter().map(digest_hex).collect());
    if let Some(h) = hexes {
        o.insert(m.to_owned(), serde_json::json!(h));
    }
}

/// **The envelope projection of a typed plane's row**: the edition-2 member
/// names written back as the earlier envelope's names the JSON door's gates
/// read, each hash digest as 64 lowercase hex. Read from the PAYLOAD (never
/// the JSON being rewritten), so it is idempotent and order-free beside any
/// other projection [`super::ingest::attestation_of`] makes. A row of
/// another family is untouched.
///
/// - `takedown_notice`: `claimant` → `claimant_key_id`, `content_holders`
///   → `content_holder_key_ids`, `content_sha256` / `evidence_refs` as hex,
///   and the family's `subject_kind: takedown_notice` (CC 3.1.1: the
///   `scores` row whose envelope is the notice).
/// - `custody`: `evidence_refs` as hex; the CC 2.1 `family_id` →
///   `family_key_id`, the cohort-target alias the custody gate reads.
/// - `key_grant`: `community` → `community_key_id`, `minter` →
///   `minter_key_id`, `owner` → `owner_key_id`, `at_rest_sha256` as hex,
///   `wrapped_dek` as the verbatim wrap text (its UTF-8 bytes in edition
///   2), `family_id` → `family_key_id`.
/// - `delivery_receipt`: `chunk_root` as hex.
pub fn project_envelope(row: &AdmittedRow, o: &mut serde_json::Map<String, serde_json::Value>) {
    let Some(plane) = typed_plane_of_row(row) else {
        return;
    };
    match plane {
        TypedPlane::Takedown => {
            rename(o, "claimant", "claimant_key_id");
            rename(o, "content_holders", "content_holder_key_ids");
            put_digest_hex(row, o, "content_sha256");
            put_digests_hex(row, o, "evidence_refs");
            o.insert(
                "subject_kind".to_owned(),
                serde_json::Value::String(
                    crate::federation::takedown_tombstone::TAKEDOWN_NOTICE_SUBJECT_KIND.to_owned(),
                ),
            );
        }
        TypedPlane::Custody => {
            put_digests_hex(row, o, "evidence_refs");
            rename(o, "family_id", "family_key_id");
        }
        TypedPlane::KeyGrant => {
            rename(o, "community", "community_key_id");
            rename(o, "minter", "minter_key_id");
            rename(o, "owner", "owner_key_id");
            rename(o, "family_id", "family_key_id");
            put_digest_hex(row, o, "at_rest_sha256");
            if let Some(t) = row
                .payload
                .get_text("wrapped_dek")
                .and_then(Value::as_bytes)
                .and_then(|b| std::str::from_utf8(b).ok())
            {
                o.insert(
                    "wrapped_dek".to_owned(),
                    serde_json::Value::String(t.to_owned()),
                );
            }
        }
        TypedPlane::DeliveryReceipt => put_digest_hex(row, o, "chunk_root"),
        TypedPlane::OccurrenceRevocation | TypedPlane::Cosign | TypedPlane::Revocation => {}
    }
}

/// v62.0.0 (T2-fix2) — **the envelope projection's inverse**, for a producer
/// stating a typed plane's row from its earlier-form envelope
/// (`emit::payload_from_envelope`): the earlier member names become the
/// edition-2 names P1's payload list keys ([`project_envelope`] is the
/// other direction), so the statement keeps that list. Applied to the
/// payload map before it is sorted; a row of another family is untouched.
///
/// - `key_grant`: nothing here. Its producer states the row through
///   [`key_grant_payload`] (`key_grant::state_key_grant_row`, P8-fix2).
/// - `custody`: `family_key_id` → `family_id`.
/// - `takedown_notice`: `claimant_key_id` → `claimant`,
///   `content_holder_key_ids` → `content_holders` (a set: sorted, unique);
///   `subject_kind` is dropped (the family's own constant, restated by the
///   projection).
pub fn unproject_payload(family_id: &str, m: &mut Vec<(Value, Value)>) {
    let Some(plane) = PLANES
        .iter()
        .find(|(prefix, _)| namespace_match::family_id(prefix) == family_id)
        .map(|(_, plane)| *plane)
    else {
        return;
    };
    let renames: &[(&str, &str)] = match plane {
        TypedPlane::Custody => &[("family_key_id", "family_id")],
        TypedPlane::Takedown => &[
            ("claimant_key_id", "claimant"),
            ("content_holder_key_ids", "content_holders"),
        ],
        // A key grant is stated from its row by its own producer
        // (`key_grant::state_key_grant_row` → [`key_grant_payload`], P8), never
        // from the earlier envelope.
        TypedPlane::KeyGrant
        | TypedPlane::OccurrenceRevocation
        | TypedPlane::Cosign
        | TypedPlane::Revocation
        | TypedPlane::DeliveryReceipt => &[],
    };
    if plane == TypedPlane::Takedown {
        m.retain(|(k, _)| k.as_text() != Some("subject_kind"));
    }
    for (k, v) in m.iter_mut() {
        if let Some((_, to)) = k
            .as_text()
            .and_then(|name| renames.iter().find(|(from, _)| *from == name))
        {
            *k = text(to);
        }
        if let (TypedPlane::Takedown, Some("content_holders")) = (plane, k.as_text()) {
            if let Value::Array(a) = v {
                a.sort_by_key(cde::encode);
                a.dedup();
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The typed structs (statement → struct)
// ─────────────────────────────────────────────────────────────────────────

/// **An `identity:occurrence_revocation` statement as the revocation it
/// states**: `identity_key_id`, `occurrence_key_id` (the row's `sub`),
/// `revoked_at`, `effective_at`, the coded `reason` (or `body.note`), the
/// `witness_set`. `persist_row_hash` is the store's.
///
/// # Errors
/// `edition2_payload_invalid` for a missing or ill-typed member, or an
/// `occurrence_key_id` that is not the row's `sub`.
pub fn occurrence_revocation_of(row: &AdmittedRow) -> Result<IdentityOccurrenceRevocation, Error> {
    let p = &row.payload;
    let identity = req_text(p, "identity_key_id")?;
    let occurrence = req_text(p, "occurrence_key_id")?;
    if occurrence != row.sub {
        return Err(invalid(format!(
            "{OCCURRENCE_REVOCATION_PREFIX}: `occurrence_key_id` {occurrence:?} is not the row's \
             sub {:?}",
            row.sub
        )));
    }
    let reason = match p.get_text("reason") {
        Some(Value::Uint(n)) => Some(n.to_string()),
        _ => note_of(p),
    };
    Ok(IdentityOccurrenceRevocation {
        identity_key_id: identity.to_owned(),
        occurrence_key_id: occurrence.to_owned(),
        revoked_at: req_ms(p, "revoked_at")?,
        effective_at: req_ms(p, "effective_at")?,
        reason,
        witness_set: identity_refs_of(p, "witness_set"),
        persist_row_hash: String::new(),
    })
}

/// The payload instants of a revocation, written as RFC 3339 at ms in the
/// envelope (the earlier gates read text instants).
const REVOCATION_INSTANTS: [&str; 4] =
    ["asserted_at", "revoked_at", "effective_at", "revoked_after"];

/// **A `revocation:{entity_type}:{reason}` statement as the
/// [`Revocation`] it states**, for an entity with a key (the row's `sub`, an
/// identity-ref): the subject digest (`revoked_key_sha256_ed25519_raw`, the
/// sub's held Ed25519 half, read by the caller), the revoker (`iss`), the
/// instants, the reason (`body.note`, else the coded `{reason}` leaf). The
/// envelope is the payload's projection with the earlier binding stamped
/// in (`admission::bind_revocation_into_envelope`); the signature columns
/// hold the statement's composite (base64), which the vouch names.
///
/// # Errors
/// `edition2_payload_invalid` for a missing or ill-typed member; the
/// binding's refusal.
pub fn revocation_of(
    row: &AdmittedRow,
    revoked_key_sha256_ed25519_raw: &str,
) -> Result<Revocation, Error> {
    let p = &row.payload;
    let asserted_at = ms_instant("asserted_at", row.asserted_at_ms)?;
    let mut envelope = json_of(p);
    if let Some(o) = envelope.as_object_mut() {
        for member in REVOCATION_INSTANTS {
            if let Some(at) = opt_ms(p, member)? {
                o.insert(member.to_owned(), serde_json::Value::String(rfc3339(at)));
            }
        }
    }
    let reason = note_of(p).or_else(|| dimension_segment(p, 2).map(str::to_owned));
    let marker = composite_signature_b64(&row.bytes);
    let mut revocation = Revocation {
        revocation_id: row.row_id.hex(),
        revoked_key_id: Some(row.sub.clone()),
        revoked_key_sha256_ed25519_raw: revoked_key_sha256_ed25519_raw.to_owned(),
        revoking_key_id: row.iss.clone(),
        reason,
        revoked_at: req_ms(p, "revoked_at")?,
        effective_at: req_ms(p, "effective_at")?,
        revocation_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: marker.clone(),
        scrub_signature_pqc: Some(marker),
        scrub_key_id: row.iss.clone(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: Some(asserted_at),
        observed_region: crate::federation::verify_coord::region::US.to_owned(),
        revoked_after: opt_ms(p, "revoked_after")?,
        persist_row_hash: String::new(),
    };
    crate::federation::admission::bind_revocation_into_envelope(&mut revocation)?;
    let canonical =
        crate::verify::canonical::ceg_produce_canonicalize(&revocation.revocation_envelope)
            .map_err(|e| invalid(format!("revocation envelope canonicalize: {e}")))?;
    revocation.original_content_hash = hex::encode(sha2::Sha256::digest(&canonical));
    Ok(revocation)
}

/// v62.0.0 (VA-pair-carriers) — the statement's composite signature (its
/// fourth member), whole: ONE ML-DSA-65-Ed25519 composite (CC 2.6.1.7).
/// `None` when the bytes are not a statement or the signature is not a
/// composite (Verify's named layout, `composite::signature_halves`).
fn composite_signature(statement: &[u8]) -> Option<Vec<u8>> {
    let sig = match cde::decode(statement).ok()? {
        Value::Tag(18, inner) => inner.as_array()?.get(3)?.as_bytes()?.to_vec(),
        _ => return None,
    };
    super::composite::signature_halves(&sig)?;
    Some(sig)
}

/// **A `delivery_receipt:{stream_id}` statement as the [`DeliveryReceipt`]
/// it states**: `stream_id` (equal to the `{stream_id}` leaf), the
/// subscriber (`iss`, equal to `sub`), `epoch`, `k`, `chunk_root`. The
/// receipt carries the statement's composite signature WHOLE, as one field
/// (v62.0.0, VA-pair-carriers: no longer split into a `HybridSignature`'s
/// two halves beside the subscriber's two public keys). The edition-2 door
/// verified the statement; no inner signed object exists (CC 8.11.30 is
/// the earlier layout).
///
/// # Errors
/// `edition2_payload_invalid` for a missing or ill-typed member, a stream
/// that is not the leaf, a subscriber that is not the row's `sub`, or a
/// signature that is not a composite.
pub fn delivery_receipt_of(row: &AdmittedRow) -> Result<DeliveryReceipt, Error> {
    let p = &row.payload;
    let stream_id = req_text(p, "stream_id")?;
    if text_of(p, "dimension")
        != Some(crate::federation::custody_ack::delivery_receipt_dimension(stream_id).as_str())
    {
        return Err(invalid(format!(
            "{DELIVERY_RECEIPT_PREFIX}: `stream_id` {stream_id:?} is not the dimension's leaf"
        )));
    }
    if row.iss != row.sub {
        return Err(invalid(format!(
            "{DELIVERY_RECEIPT_PREFIX}: the subscriber {:?} is the row's sub, not {:?}",
            row.iss, row.sub
        )));
    }
    let chunk_root = p
        .get_text("chunk_root")
        .and_then(digest_bytes)
        .ok_or_else(|| invalid("`chunk_root` is required (a hash digest)"))?;
    let composite_signature = composite_signature(&row.bytes)
        .ok_or_else(|| invalid("the statement's signature is not a composite"))?;
    Ok(DeliveryReceipt {
        stream_id: stream_id.to_owned(),
        subscriber_key_id: row.iss.clone(),
        epoch: req_u64(p, "epoch")?,
        k: req_u64(p, "k")?,
        chunk_root,
        composite_signature,
    })
}

/// v62.0.0 (wave T2) — what an edition-2 holding claim (a
/// `custody:{kind}` statement, `custody_state` `here`) states, read from its
/// bytes UNVERIFIED: the blob door's pure pre-checks before it stores the
/// bytes. The statement is then judged by the edition-2 door and the custody
/// gate (`put_statement`), which verify it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldingClaimRead {
    /// The holder (`iss`, equal to `sub`).
    pub holder: String,
    /// The blob's address (the one `evidence_refs` digest).
    pub sha256: [u8; 32],
    /// The size it claims to hold.
    pub size: u64,
    /// The cohort it is placed at.
    pub cohort_scope: String,
    /// v62.0.0 (T2-fix11) — the cohort's target (the community / family a
    /// targeted scope names: `community_id` / `family_id`), `None` for an
    /// untargeted scope.
    pub target: Option<String>,
}

/// **Read an edition-2 holding claim** ([`HoldingClaimRead`]).
///
/// # Errors
/// `edition2_payload_invalid`: not a `custody:{kind}` statement, a holder
/// that is not the row's `sub`, a state other than `here`, no single blob
/// digest, no size, no `cohort_scope`.
pub fn holding_claim_of(statement: &[u8]) -> Result<HoldingClaimRead, Error> {
    let (protected, payload) = super::liveness::statement_parts(statement)
        .ok_or_else(|| invalid("a holding claim is an edition-2 statement"))?;
    let family = protected.get_int(-70002).and_then(Value::as_text);
    if family != Some(namespace_match::family_id(CUSTODY_PREFIX).as_str()) {
        return Err(invalid(format!(
            "a holding claim is a {CUSTODY_PREFIX} statement"
        )));
    }
    let claim = |n: i64| {
        protected
            .get_int(15)
            .and_then(|c| c.get_int(n))
            .and_then(Value::as_text)
            .map(str::to_owned)
    };
    let (Some(iss), Some(sub)) = (claim(1), claim(2)) else {
        return Err(invalid("a holding claim names its iss and sub"));
    };
    if iss != sub {
        return Err(invalid(
            "a holding claim is the holder's self-report: iss is its sub",
        ));
    }
    if text_of(&payload, "custody_state") != Some(CustodyState::Here.as_str()) {
        return Err(invalid("a holding claim's custody_state is `here`"));
    }
    let sha256 = match payload.get_text("evidence_refs").and_then(Value::as_array) {
        Some([d]) => digest_bytes(d),
        _ => None,
    }
    .ok_or_else(|| invalid("a holding claim names exactly one blob digest"))?;
    let cohort_scope = req_text(&payload, "cohort_scope")?.to_owned();
    let target = cohort_target_member(&cohort_scope)
        .and_then(|m| text_of(&payload, m))
        .map(str::to_owned);
    Ok(HoldingClaimRead {
        holder: iss,
        sha256,
        size: req_u64(&payload, "size")?,
        cohort_scope,
        target,
    })
}

// ─────────────────────────────────────────────────────────────────────────
//  The doors
// ─────────────────────────────────────────────────────────────────────────

/// **The typed planes' door** (module docs): one admitted statement of a
/// typed plane, from [`super::ingest::put_admitted_row`] (after the
/// composer check).
///
/// # Errors
/// The family's own door's refusals, exactly as the JSON door raises them;
/// the payload reader's `edition2_payload_invalid`; the retryable ordering
/// gaps (`federation_attester_key_unknown` for a subject or subscriber key
/// not held yet, `federation_withdraws_target_unheld` for a cosigned event
/// not held yet). A refused statement is not kept.
pub async fn put_typed_statement<F>(
    dir: &F,
    row: &AdmittedRow,
    plane: TypedPlane,
    tier: &str,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    match plane {
        TypedPlane::OccurrenceRevocation => Box::pin(put_occurrence_revocation(dir, row)).await,
        TypedPlane::Revocation => Box::pin(put_revocation_statement(dir, row)).await,
        TypedPlane::DeliveryReceipt => Box::pin(put_delivery_receipt(dir, row, tier)).await,
        TypedPlane::Cosign => Box::pin(put_cosign(dir, row)).await,
        TypedPlane::Takedown if is_steward_purge(row) => {
            let new = dir.put_edition2_statement(row).await?;
            Ok(StatementOutcome::Pending {
                row_id: row.row_id,
                new,
            })
        }
        TypedPlane::Takedown | TypedPlane::Custody => {
            Box::pin(put_attestation_row(dir, row, tier)).await
        }
        TypedPlane::KeyGrant => {
            let out = Box::pin(put_attestation_row(dir, row, tier)).await?;
            // The typed doors' grant projection (`attestation_apply`), run
            // for a held row as for a new one: the wrap rides the row.
            if let Some(stored) = dir.get_attestation(&row.row_id.hex()).await? {
                dir.project_key_grant_row(&stored).await?;
            }
            Ok(out)
        }
    }
}

/// `takedown_notice:steward_purge`: the `{basis}` leaf.
pub(crate) fn is_steward_purge(row: &AdmittedRow) -> bool {
    dimension_segment(&row.payload, 1)
        == Some(crate::federation::steward_purge::STEWARD_PURGE_BASIS)
}

/// The attestation-backed families: the mapped row (with
/// [`project_envelope`]'s names) through the JSON door's gates
/// (`put_attestation`), then the statement kept under its row id. A
/// further statement over a held row is a voice of it, as
/// [`super::ingest::put_admitted_row`]'s tail keeps one.
async fn put_attestation_row<F>(
    dir: &F,
    row: &AdmittedRow,
    tier: &str,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    if dir.get_attestation(&row.row_id.hex()).await?.is_some() {
        let new = dir.put_edition2_statement(row).await?;
        return Ok(StatementOutcome::Voice {
            row_id: row.row_id,
            new,
        });
    }
    let mapped = attestation_of(row, tier)?;
    dir.put_attestation(SignedAttestation {
        attestation: mapped,
    })
    .await?;
    let new = dir.put_edition2_statement(row).await?;
    Ok(StatementOutcome::Row {
        row_id: row.row_id,
        new,
    })
}

/// v62.0.0 (T2-fix4; CC rc21 7f94be1) — the `refs` role an
/// `identity:occurrence_revocation` cites its voices' keys under.
pub const CITES_ROLE: &str = "also:cites";

/// v62.0.0 (T2-fix4; CC rc21 7f94be1, CC 2.7.5) — **an eviction cites its
/// evicting keys.** Under `refs.also.cites` it names the `key:record` of
/// each of its voices and, for a voice whose key is not the identity's own,
/// that key's `identity:occurrence` binding under the identity. The cited
/// rows are its ancestors: they travel with it (`serve::statements_served_to`).
///
/// - no cite at all: Invalid (`edition2_payload_invalid`), a check of the
///   bytes;
/// - a cited row this node does not hold: the row WAITS (a fold hold,
///   `link_unheld`, re-folded when the row arrives);
/// - every cite held, but none is this voice's `key:record` (its kid), or
///   (for a non-genesis key) none is its binding under the identity:
///   Invalid.
///
/// # Errors
/// As above; directory reads.
async fn check_eviction_cites<F>(dir: &F, row: &AdmittedRow, identity: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let cites: Vec<RowId> = row
        .names
        .iter()
        .filter(|n| n.role == CITES_ROLE)
        .map(|n| n.row)
        .collect();
    if cites.is_empty() {
        return Err(invalid(format!(
            "{OCCURRENCE_REVOCATION_PREFIX}: an eviction cites, under refs.also.cites, the \
             key:record of each of its voices and that key's occurrence binding (CC rc21)"
        )));
    }
    let voice_key = ciris_verify_core::edition2::identity_ref(&row.kid);
    let mut held = Vec::with_capacity(cites.len());
    for c in &cites {
        super::fold::reads(super::fold::Dep::Row(*c));
        let voices = dir.edition2_voices(c).await?;
        let Some(first) = voices.into_iter().next() else {
            return Err(super::fold::hold(
                super::fold::reason::LINK_UNHELD,
                Error::WithdrawsTargetUnheld {
                    attestation_id: row.row_id.hex(),
                    target_attestation_id: c.hex(),
                },
            ));
        };
        held.push(first);
    }
    let mut record_cited = false;
    let mut bind_cited = false;
    for st in &held {
        let Some((protected, payload)) = super::liveness::statement_parts(st) else {
            continue;
        };
        let family = protected.get_int(-70002).and_then(Value::as_text);
        if family == Some(ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY)
            && super::liveness::recorded_kid(st) == Some(row.kid)
        {
            record_cited = true;
        }
        if family == Some(super::occurrence::OCCURRENCE_FAMILY)
            && text_of(&payload, "identity_key_id") == Some(identity)
            && text_of(&payload, "occurrence_key_id") == Some(voice_key.as_str())
        {
            bind_cited = true;
        }
    }
    if !record_cited {
        return Err(invalid(format!(
            "{OCCURRENCE_REVOCATION_PREFIX}: the voice's key:record ({voice_key}) is not cited \
             under refs.also.cites"
        )));
    }
    if voice_key != identity && !bind_cited {
        return Err(invalid(format!(
            "{OCCURRENCE_REVOCATION_PREFIX}: the voice's occurrence binding ({identity} -> \
             {voice_key}) is not cited under refs.also.cites"
        )));
    }
    Ok(())
}

/// v62.0.0 (T2-fix4; CC 2.7.5, rc21 7f94be1) — **the rows that travel with
/// a statement**: for an `identity:occurrence_revocation`, every held
/// statement of each row it cites (`refs.also.cites`: its voices' key
/// records and bindings). Empty for any other statement. The serve listing
/// serves them with it (`serve::statements_served_to`).
///
/// # Errors
/// Directory reads.
pub async fn travelling_ancestors<F>(dir: &F, statement: &[u8]) -> Result<Vec<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some((protected, payload)) = super::liveness::statement_parts(statement) else {
        return Ok(Vec::new());
    };
    if protected.get_int(-70002).and_then(Value::as_text)
        != Some(namespace_match::family_id(OCCURRENCE_REVOCATION_PREFIX).as_str())
    {
        return Ok(Vec::new());
    }
    let Ok(names) = super::names::names_of(&payload) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for n in names.iter().filter(|n| n.role == CITES_ROLE) {
        out.extend(dir.edition2_voices(&n.row).await?);
    }
    Ok(out)
}

/// v62.0.0 (T2-fix4) — **the cites an eviction by `voice_keys` states**:
/// for each key, its latest held `key:record` row and, when the key is not
/// the identity's own, its latest held `identity:occurrence` binding under
/// `identity`. For producers and fixtures; the door checks them
/// ([`check_eviction_cites`]).
///
/// # Errors
/// A key with no held `key:record`, or a non-genesis key with no held
/// binding (the retryable unknown signer, naming it); directory reads.
pub async fn eviction_cites<F>(
    dir: &F,
    identity: &str,
    voice_keys: &[String],
) -> Result<Vec<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let latest = |sts: Vec<Vec<u8>>, keep: &dyn Fn(&Value) -> bool| {
        sts.into_iter()
            .filter_map(|st| {
                let (_, p) = super::liveness::statement_parts(&st)?;
                if !keep(&p) {
                    return None;
                }
                let at = p.get_text("asserted_at").and_then(Value::as_u64)?;
                Some((at, RowId::of_statement(&st)?))
            })
            .max()
            .map(|(_, r)| r)
    };
    let mut out = Vec::new();
    for k in voice_keys {
        let records = dir
            .edition2_statements_about(ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY, k)
            .await?;
        let record = latest(records, &|_| true).ok_or_else(|| Error::unknown_signer(k, PLANE))?;
        out.push(record);
        if k != identity {
            let binds = dir
                .edition2_statements_about(super::occurrence::OCCURRENCE_FAMILY, k)
                .await?;
            let bind = latest(binds, &|p| text_of(p, "identity_key_id") == Some(identity))
                .ok_or_else(|| Error::unknown_signer(k, PLANE))?;
            out.push(bind);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// **`identity:occurrence_revocation`** (v62.0.0, wave T2 + O1's S1b): every
/// voice is signed AS the identity (refused otherwise, not kept), so the
/// door's key-of-issuer check has already admitted only a key of the
/// identity at the statement's instant; no current-roster read is made. (A) a node or agent identity lands on one
/// voice. (B) a user self's eviction is a roster change and runs the
/// self-roster's ONE two-path decision (`self_roster::gate_edition2` over
/// `occurrence::carried_of_bind`): the quorum path counts every held voice
/// signed as the self by a live roster key (and `objection:assent` answers
/// naming the row id); short of it the voice is kept
/// ([`StatementOutcome::Pending`], receipt noted) and the lone path lands it
/// later (`self_roster::execute_for` → `occurrence::land_held_eviction`,
/// which reads [`occurrence_revocation_of`]). A proposal no answer can mend
/// is `SelfRosterNotLanded` (the voice stays held: the gate counts held
/// voices, so it is stored first). Landing writes the revocation the carrier
/// feeds (`put_identity_occurrence_revocation_local`) unless the pair is
/// already revoked: the first route to land fixes the instants.
async fn put_occurrence_revocation<F>(dir: &F, row: &AdmittedRow) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::occurrence_revocation_carrier::is_single_signer_identity;
    let revocation = occurrence_revocation_of(row)?;
    let identity = revocation.identity_key_id.clone();
    // Every voice is signed AS the identity: the door's key-of-issuer check
    // then admits only a key of the identity at the statement's own instant
    // (its record, or a live occurrence seat). No current-roster read here
    // (G0's named-past rule): who COUNTS is the roster at the heads the row
    // names (`self_roster::gate_edition2` over `roster_at_heads`).
    if row.iss != identity {
        return Err(invalid(format!(
            "{OCCURRENCE_REVOCATION_PREFIX}: a voice is signed as the identity {identity:?}, \
             not as {:?}",
            row.iss
        )));
    }
    // v62.0.0 (T2-fix4; CC rc21 7f94be1) — the eviction cites its voices'
    // keys (their records and bindings): Invalid without them, waiting on a
    // cited row not held.
    check_eviction_cites(dir, row, &identity).await?;
    let single_signer = is_single_signer_identity(dir, &identity).await?;
    // Stored FIRST: the self-roster's gate counts the held voices.
    let new = dir.put_edition2_statement(row).await?;
    if !single_signer {
        let carried = super::occurrence::carried_of_bind(dir, &row.row_id.hex())
            .await?
            .ok_or_else(|| {
                invalid(format!(
                    "{OCCURRENCE_REVOCATION_PREFIX}: the held revocation {} is no roster \
                     proposal",
                    row.row_id.hex()
                ))
            })?;
        if !crate::federation::self_roster::gate_edition2(dir, carried).await? {
            return Ok(StatementOutcome::Pending {
                row_id: row.row_id,
                new,
            });
        }
    }
    let held = dir
        .list_identity_occurrence_revocations_for(&identity)
        .await?
        .iter()
        .any(|r| r.occurrence_key_id == revocation.occurrence_key_id);
    if !held {
        dir.put_identity_occurrence_revocation_local(revocation)
            .await?;
    }
    Ok(StatementOutcome::Row {
        row_id: row.row_id,
        new,
    })
}

/// **`revocation:{entity_type}:{reason}`**. An entity with a key (an
/// identity-ref `sub`): the [`Revocation`] it states ([`revocation_of`])
/// through `put_revocation`, the JSON door, under a vouch naming exactly
/// this envelope, the revoker and its marker. Every gate is the door's: the
/// subject binding, the subject digest, the revoker's authority (self, or a
/// slash conferral), the region, the skew, the anti-rollback and the bound.
/// A subject key not held yet waits (the retryable unknown signer, naming
/// it). An entity that is a row (no key: `refs.target` names it) is held in
/// `ceg_statements` only, once the row it names is held.
async fn put_revocation_statement<F>(dir: &F, row: &AdmittedRow) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !is_identity_ref(&row.sub) {
        let Some(target) = single(&row.names, TARGET_ROLE) else {
            return Err(invalid(format!(
                "{REVOCATION_PREFIX}: the entity {:?} has no key, and `refs.target` names no row",
                row.sub
            )));
        };
        require_held(dir, row, &target).await?;
        let new = dir.put_edition2_statement(row).await?;
        return Ok(StatementOutcome::Row {
            row_id: row.row_id,
            new,
        });
    }
    let Some(subject) = dir.lookup_public_key(&row.sub).await? else {
        return Err(Error::unknown_signer(&row.sub, PLANE));
    };
    let digest = crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
        &subject.pubkey_ed25519_base64,
    )
    .map_err(|e| Error::Backend(format!("subject {:?} Ed25519 half: {e}", row.sub)))?
    .to_hex();
    let revocation = revocation_of(row, &digest)?;
    let mut voices = BTreeMap::new();
    voices.insert(
        revocation.revoking_key_id.clone(),
        revocation.scrub_signature_classical.clone(),
    );
    let vouch = Vouch::over(&revocation.revocation_envelope, voices)?;
    // v62.0.0 (wave GC4; CC 2.6.1.9, 2.7.3) — a count short of its
    // authority is HELD `count_short` (the door's fold attempt keeps the
    // voice, `ingest::put_admitted_row`). It was returned as a plain error,
    // so the first voice was refused and the row could never gather its
    // count (G2 cluster 3). The door's own refusals (bytes, key plane) stay
    // refusals; a gate inside `put_revocation` that marks its condition
    // holds the row with its own reason.
    match run_vouched(vouch, dir.put_revocation(SignedRevocation { revocation })).await? {
        Landing::Landed => {}
        Landing::Short(e) => {
            return Err(super::fold::hold(super::fold::reason::COUNT_SHORT, e));
        }
    }
    let new = dir.put_edition2_statement(row).await?;
    Ok(StatementOutcome::Row {
        row_id: row.row_id,
        new,
    })
}

/// A row named by `refs` must be held (its statement in `ceg_statements`);
/// until it is, the naming row waits (a fold hold, `link_unheld`).
async fn require_held<F>(dir: &F, row: &AdmittedRow, target: &RowId) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (T2-fix2; CC 2.7.3) — the named row is a fold read: a row
    // naming one this node does not hold WAITS (held, kept, `Pending`) and is
    // re-folded when it arrives, as a composer's unheld target does
    // (`ingest::check_composer_target`). Never a refusal.
    super::fold::reads(super::fold::Dep::Row(*target));
    if dir.edition2_voices(target).await?.is_empty() {
        return Err(super::fold::hold(
            super::fold::reason::LINK_UNHELD,
            Error::WithdrawsTargetUnheld {
                attestation_id: row.row_id.hex(),
                target_attestation_id: target.hex(),
            },
        ));
    }
    Ok(())
}

/// **`delivery_receipt:{stream_id}`**: the subscriber's key (held, else the
/// retryable unknown signer), the receipt it states
/// ([`delivery_receipt_of`]) through the receipt door's JOIN and
/// equivocation steps (`put_delivery_receipt_edition2`), then the signed
/// receipt row through the attestation door (the custody fold reads it,
/// `custody_ack::signed_receipt_at`). A receipt the JOIN refuses is not
/// kept anywhere.
async fn put_delivery_receipt<F>(
    dir: &F,
    row: &AdmittedRow,
    tier: &str,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    // The subscriber's key is held (the retryable ordering gap otherwise).
    if dir.lookup_public_key(&row.iss).await?.is_none() {
        return Err(Error::unknown_signer(&row.iss, PLANE));
    }
    let receipt = delivery_receipt_of(row)?;
    // v62.0.0 (wave GC4; CC 2.7.3) — the receipt door's JOIN and
    // equivocation steps read other rows (the stream, the subscriber's other
    // receipts): they run inside the door's fold attempt
    // (`ingest::put_admitted_row`), so a step that marks its condition holds
    // the statement instead of losing it. (Their owner converts them.)
    dir.put_delivery_receipt_edition2(receipt).await?;
    put_attestation_row(dir, row, tier).await
}

/// **`cosign:{pending,signature}`**: the hold IS the counted row (CC 3.1.3,
/// `cosign`'s module doc), so a cosign statement is kept beside the event
/// it names (`refs.target`, held, else the retryable ordering gap) in
/// `ceg_statements` only, never mapped into `federation_attestations`
/// ([`StatementOutcome::Voice`]). The event's count is its own family's
/// (`edition2::group`, `cosign::edition2_voices`).
async fn put_cosign<F>(dir: &F, row: &AdmittedRow) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(target) = single(&row.names, TARGET_ROLE) else {
        return Err(invalid(format!(
            "{COSIGN_PREFIX}: a cosign statement names the event it cosigns by `refs.target`"
        )));
    };
    require_held(dir, row, &target).await?;
    let new = dir.put_edition2_statement(row).await?;
    Ok(StatementOutcome::Voice {
        row_id: row.row_id,
        new,
    })
}

// ─────────────────────────────────────────────────────────────────────────
//  Trust edges → the v1.3 trust plane (CC 3.2 T3, CC 4.4.3.34)
// ─────────────────────────────────────────────────────────────────────────

/// `trust:{job}:{version}`: the trust-root edges' family (charter, confers,
/// accepts). Its rows are `delegates_to` rows (and their composers).
pub const TRUST_PREFIX: &str = "trust:{job}:{version}";

/// The payload member an acceptance edge names its trust classes by (the
/// class list the trust-root walk intersects): the v1.3 `trust_domains`.
pub const TRUST_CLASSES_MEMBER: &str = "trust_classes";

/// Is `family` (a header family id) the trust edges' family?
#[must_use]
pub fn is_trust_family(family: &str) -> bool {
    namespace_match::family_id(TRUST_PREFIX) == family
}

/// Is `row` a held `trust:accepts` acceptance edge (a `delegates_to` at
/// [`crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION`])?
fn is_acceptance_edge(row: &crate::federation::types::Attestation) -> bool {
    row.attestation_type == crate::federation::types::attestation_type::DELEGATES_TO
        && crate::federation::admission::envelope_dimension(&row.attestation_envelope)
            == Some(crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION)
}

/// **A `trust:{job}:{version}` statement**: the edge (or its composer) goes
/// through the attestation door exactly as before (the trust-root walk reads
/// the same rows), then every key whose v1.3 trust row the statement can
/// change is re-derived ([`project_trust_for`]): an acceptance edge's
/// target (its row) and its granter (a reciprocal edge makes the granter's
/// row `partnered`); a composer's target edge's two ends.
///
/// # Errors
/// The attestation door's refusals; directory failures.
pub async fn put_trust_statement<F>(
    dir: &F,
    row: &AdmittedRow,
    tier: &str,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    // W1-fix2 (CC 2.6.1.9; W1.api.md v1.6) — a trust edge is a counted row
    // like any attestation: its store goes through the ONE shared voice path
    // (`voices::put_counted_row`). The row is projected from its author's
    // voice, and a second signer's voice (a `trust:confers:v1` grant's
    // `delegate: sub`) joins its count; it is never mapped as a row of its
    // own (which made the subject's voice a self-loop `delegates_to` the
    // charter gate refused). Short of its signers the row is held
    // (`count_short`); a held row's further voice is a `Voice`.
    let out = Box::pin(super::voices::put_counted_row(
        dir,
        row,
        tier,
        crate::federation::replication::admission::WriteOrigin::Wire,
    ))
    .await?;
    let edge = if COMPOSER_ROW_TYPES.contains(&row.row_type.as_str()) {
        match single(&row.names, TARGET_ROLE) {
            Some(t) => dir.get_attestation(&t.hex()).await?,
            None => None,
        }
    } else {
        dir.get_attestation(&row.row_id.hex()).await?
    };
    if let Some(edge) = edge.filter(is_acceptance_edge) {
        Box::pin(project_trust_for(dir, &edge.attested_key_id)).await?;
        Box::pin(project_trust_for(dir, &edge.attesting_key_id)).await?;
    }
    Ok(out)
}

/// The live (not retired) acceptance edges a query names, and the granters
/// of the retired ones.
pub(crate) async fn acceptance_edges<F>(
    dir: &F,
    query: crate::federation::attestation_query::AttestationQuery,
) -> Result<(Vec<crate::federation::types::Attestation>, BTreeSet<String>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut rows = Vec::new();
    let mut pages = query.pages();
    while let Some(page) = pages.next(dir).await? {
        rows.extend(page.into_iter().filter(is_acceptance_edge));
    }
    if rows.is_empty() {
        return Ok((rows, BTreeSet::new()));
    }
    let ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
    let composers = dir.list_composers_referencing_any(&ids, None, None).await?;
    let refs: Vec<&crate::federation::types::Attestation> =
        rows.iter().chain(composers.iter()).collect();
    let retired = crate::federation::precedence::retired_ids(&refs);
    let retired_granters = rows
        .iter()
        .filter(|r| retired.contains(&r.attestation_id))
        .map(|r| r.attesting_key_id.clone())
        .collect();
    rows.retain(|r| !retired.contains(&r.attestation_id));
    Ok((rows, retired_granters))
}

/// The instant an envelope member states (RFC 3339), if any.
fn envelope_instant(
    row: &crate::federation::types::Attestation,
    member: &str,
) -> Option<chrono::DateTime<chrono::Utc>> {
    row.attestation_envelope
        .get(member)
        .and_then(serde_json::Value::as_str)
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// **Re-derive `key`'s v1.3 trust row from its acceptance edges** (CC 3.2
/// T3, CC 4.4.3.34; CC's ruling on the v1.3 mapping). The latest live
/// `trust:accepts` edge naming `key` (by `asserted_at`, then id) is the
/// grant:
///
/// - `trusted_by` = the edge's granter (its `iss`);
/// - `trust_relationship`: `Registry` when the edge names a registry's root
///   (a community this node holds), else `Direct` (it names the key itself);
/// - `trust_domains` = the edge's `trust_classes` (a `Registry` grant's;
///   a `Direct` grant carries none, the v1.3 shape);
/// - `expires_at` = the edge's `valid_until`;
/// - `trust_type` has NO member; it is DERIVED from structure (CC):
///   `anonymous` for a `self`-scope edge, `partnered` when the reciprocal
///   edge (from `key` to the granter) is held and live, else `temporary`;
/// - `trusted_at` = the edge's `asserted_at` (the signer's instant).
///
/// No live edge: a projected row whose granter's edge was retired (its
/// `withdraws`) is expired now. A grant the v1.3 shape refuses (self-trust,
/// a `Registry` edge with no classes) is not projected; the edge still
/// stands for the trust-root walk.
///
/// # Errors
/// Directory failures.
pub async fn project_trust_for<F>(dir: &F, key: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    use crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION;
    use crate::federation::types::{TrustGrant, TrustRelationship, TrustRow, TrustType};
    let (live, retired_granters) = acceptance_edges(
        dir,
        AttestationQuery::to(key, FOLD_PAGE).dimension(TRUST_ACCEPTS_DIMENSION),
    )
    .await?;
    let Some(edge) = live
        .iter()
        .max_by(|a, b| (a.asserted_at, &a.attestation_id).cmp(&(b.asserted_at, &b.attestation_id)))
    else {
        if let Some(held) = dir.lookup_trust(key).await? {
            if retired_granters.contains(&held.trusted_by) {
                dir.retract_projected_trust(key, crate::host::clock::now())
                    .await?;
            }
        }
        return Ok(());
    };
    let granter = edge.attesting_key_id.clone();
    let trust_type = if edge.cohort_scope == cs::SELF {
        TrustType::Anonymous
    } else {
        let (reciprocal, _) = acceptance_edges(
            dir,
            AttestationQuery::to(&granter, FOLD_PAGE)
                .authored_by(key)
                .dimension(TRUST_ACCEPTS_DIMENSION),
        )
        .await?;
        if reciprocal.is_empty() {
            TrustType::Temporary
        } else {
            TrustType::Partnered
        }
    };
    let registry = dir.lookup_community(key).await?.is_some();
    let classes: Vec<String> = edge
        .attestation_envelope
        .get(TRUST_CLASSES_MEMBER)
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let grant = TrustGrant {
        key: key.to_owned(),
        trust_type,
        trust_relationship: if registry {
            TrustRelationship::Registry
        } else {
            TrustRelationship::Direct
        },
        trust_domains: registry.then_some(classes),
        trusted_by: granter,
        expires_at: envelope_instant(edge, "valid_until"),
    };
    if let Err(e) = crate::federation::consent_admit::validate_trust_grant(&grant) {
        tracing::debug!(key, reason = %e, "trust:accepts edge not projected into the v1.3 trust plane");
        return Ok(());
    }
    let projected = dir
        .store_projected_trust(TrustRow {
            key: grant.key,
            trust_type: grant.trust_type,
            trust_relationship: grant.trust_relationship,
            trust_domains: grant.trust_domains,
            trusted_by: grant.trusted_by,
            trusted_at: edge.asserted_at,
            expires_at: grant.expires_at,
        })
        .await?;
    if !projected {
        tracing::debug!(
            key,
            "trust:accepts edge names a key with no federation_keys row"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
//  Payload writers (struct → payload): the inverse, for producers and
//  fixtures
// ─────────────────────────────────────────────────────────────────────────

/// v62.0.0 (wave T2) — the role a self-roster row names the further tips
/// it merges by, beside [`SELF_ROSTER_HEAD_ROLE`] (T1's spelling for
/// `group:roster`).
pub const SELF_ROSTER_FURTHER_HEADS_ROLE: &str = "further_heads";

/// `refs` of a self-roster row: `head`, and `further_heads` (a set of
/// row-refs, sorted by encoding, unique) when it merges tips.
fn self_roster_refs(head: &RowId, further_heads: &[RowId], cites: &[RowId]) -> Value {
    let set = |rows: &[RowId]| {
        let mut set: Vec<Value> = rows
            .iter()
            .map(|r| ciris_verify_core::edition2::row_ref(&r.0))
            .collect();
        set.sort_by_key(cde::encode);
        set.dedup();
        Value::Array(set)
    };
    let mut refs = vec![(
        SELF_ROSTER_HEAD_ROLE,
        ciris_verify_core::edition2::row_ref(&head.0),
    )];
    if !further_heads.is_empty() {
        refs.push((SELF_ROSTER_FURTHER_HEADS_ROLE, set(further_heads)));
    }
    if !cites.is_empty() {
        refs.push(("also", det_map(vec![("cites", set(cites))])));
    }
    det_map(refs)
}

/// The `refs` map naming one row under `role`.
fn refs_naming(role: &str, row: &RowId) -> Value {
    det_map(vec![(role, ciris_verify_core::edition2::row_ref(&row.0))])
}

/// v62.0.0 (wave T2; CC 3.3.6.4, CC27 item 2) — **the payload of an
/// `identity:occurrence_revocation` row**: `author` is the identity for an
/// authored row (a node's or agent's), `None` for a user self's counted row
/// (CC 3.1.3); `cites` (rc21 7f94be1, REQUIRED by the door) are the
/// `key:record` of each voice and that key's occurrence binding when it has
/// one (`refs.also.cites`; [`eviction_cites`] computes them); every voice
/// states the same payload, naming the
/// self-roster head it is counted over (`refs.head`, REQUIRED by CC's
/// ruling): the identity's last landed bind or eviction, or the genesis
/// key's own `key:record` row before any. The proposal's thresholds are
/// counted over the roster at that head (`self_roster::roster_at_head`,
/// O1), never `roster_now`; a superseded head is the reader's call.
/// `further_heads` (optional, CC-confirmed for both occurrence families)
/// names the further tips the row merges beside `refs.head`
/// (`refs.further_heads`, a set: the union fold, O1).
///
/// # Errors
/// An instant before 1970.
pub fn occurrence_revocation_payload(
    revocation: &IdentityOccurrenceRevocation,
    author: Option<&str>,
    reason_code: Option<u64>,
    head: &RowId,
    further_heads: &[RowId],
    cites: &[RowId],
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("identity_key_id", text(&revocation.identity_key_id)),
        ("occurrence_key_id", text(&revocation.occurrence_key_id)),
        ("revoked_at", ms_of(revocation.revoked_at)?),
        ("effective_at", ms_of(revocation.effective_at)?),
        ("refs", self_roster_refs(head, further_heads, cites)),
    ];
    // CC 3.1.3 (`identity=user => counted ; authored`): a user self's
    // revocation is counted and carries no `author`; a node's or agent's is
    // authored (CC 2.6.1.3).
    if let Some(a) = author {
        m.push(("author", text(a)));
    }
    if let Some(code) = reason_code {
        m.push(("reason", Value::Uint(code)));
    }
    if !revocation.witness_set.is_empty() {
        m.push(("witness_set", identity_set(&revocation.witness_set)));
    }
    Ok(det_map(m))
}

/// The payload of a `revocation:{entity_type}:{reason}` row by `author`.
/// `note` rides `body.note` (the free text); `target` names a revoked row.
///
/// # Errors
/// An instant before 1970.
#[allow(clippy::too_many_arguments)]
pub fn revocation_payload(
    author: &str,
    entity_type: &str,
    reason: &str,
    revoked_at: chrono::DateTime<chrono::Utc>,
    effective_at: chrono::DateTime<chrono::Utc>,
    revoked_after: Option<chrono::DateTime<chrono::Utc>>,
    note: Option<&str>,
    target: Option<&RowId>,
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", text(author)),
        (
            "dimension",
            text(&format!("revocation:{entity_type}:{reason}:v1")),
        ),
        ("revoked_at", ms_of(revoked_at)?),
        ("effective_at", ms_of(effective_at)?),
    ];
    if let Some(after) = revoked_after {
        m.push(("revoked_after", ms_of(after)?));
    }
    if let Some(n) = note {
        m.push(("body", det_map(vec![("note", text(n))])));
    }
    if let Some(t) = target {
        m.push(("refs", refs_naming(TARGET_ROLE, t)));
    }
    Ok(det_map(m))
}

/// The members of a takedown notice beyond its claimant and content.
#[derive(Clone, Debug)]
pub struct NoticeText {
    /// `claim_text`.
    pub claim_text: String,
    /// `good_faith_statement`.
    pub good_faith_statement: String,
    /// `jurisdiction`.
    pub jurisdiction: String,
}

/// The payload of a `takedown_notice:{basis}` row: a `scores` row at `-1`
/// (the family's polarity). A `steward_purge` notice is counted and carries
/// no `author`; every other basis is authored by the claimant.
///
/// # Errors
/// An instant before 1970.
pub fn takedown_payload(
    basis: &str,
    claimant: &str,
    content_sha256: &[u8; 32],
    content_holders: &[String],
    notice: &NoticeText,
    expires_at_ms: u64,
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("dimension", text(&format!("takedown_notice:{basis}:v1"))),
        ("legal_basis", text(basis)),
        ("claimant", text(claimant)),
        ("content_sha256", hash_digest_value(content_sha256)),
        ("content_holders", identity_set(content_holders)),
        ("claim_text", text(&notice.claim_text)),
        ("good_faith_statement", text(&notice.good_faith_statement)),
        ("jurisdiction", text(&notice.jurisdiction)),
        ("expires_at", Value::Uint(expires_at_ms)),
        ("score", fixed6(-1_000_000)),
    ];
    if basis != crate::federation::steward_purge::STEWARD_PURGE_BASIS {
        m.push(("author", text(claimant)));
    }
    Ok(det_map(m))
}

/// The CC 2.1 cohort-target member a scope names its group by:
/// `community_id` at a room, `family_id` at a family, none otherwise.
fn cohort_target_member(scope: &str) -> Option<&'static str> {
    match scope {
        cs::COMMUNITY | cs::AFFILIATIONS => Some("community_id"),
        cs::FAMILY => Some("family_id"),
        _ => None,
    }
}

/// The payload of a `custody:{kind}` report (`custody:ack:v1`) by `device`
/// about one blob: `here` with its size, or `none`.
///
/// # Errors
/// `edition2_payload_invalid` for a `here` without a size, a `none` with
/// one, or a cohort target the scope does not name.
pub fn custody_payload(
    device: &str,
    blob_sha256: &[u8; 32],
    state: CustodyState,
    size: Option<u64>,
    cohort_scope: &str,
    target: Option<&str>,
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", text(device)),
        (
            "dimension",
            text(crate::federation::custody_ack::CUSTODY_ACK_DIMENSION),
        ),
        ("custody_state", text(state.as_str())),
        (
            "evidence_refs",
            Value::Array(vec![hash_digest_value(blob_sha256)]),
        ),
        ("cohort_scope", text(cohort_scope)),
        ("score", fixed6(1_000_000)),
        ("confidence", fixed6(1_000_000)),
    ];
    match (state, size) {
        (CustodyState::Here, Some(n)) => m.push(("size", Value::Uint(n))),
        (CustodyState::None, None) => {}
        _ => {
            return Err(invalid(
                "a `here` report carries the size; a `none` report none",
            ))
        }
    }
    match (cohort_target_member(cohort_scope), target) {
        (Some(member), Some(t)) => m.push((member, text(t))),
        (None, None) => {}
        _ => {
            return Err(invalid(format!(
                "a {cohort_scope} report names its cohort target exactly when the scope has one"
            )))
        }
    }
    Ok(det_map(m))
}

/// The payload of a `key_grant:{axis}` row by `signer` (one wrap for one
/// recipient, the row's `sub`). `wrapped_dek` is the wrap text's UTF-8
/// bytes; the axis members are the edition-2 names; the cohort target is
/// the CC 2.1 member.
///
/// # Errors
/// An axis member that is not of its type (a non-hex `at_rest_sha256`).
pub fn key_grant_payload(
    signer: &str,
    row: &KeyGrantRow,
    asserted_at_ms: u64,
) -> Result<Value, Error> {
    let GrantWrap {
        wrap_algorithm,
        wrapped_dek,
        ..
    } = &row.wrap;
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", text(signer)),
        ("dimension", text(row.axis.dimension())),
        ("axis", text(row.axis.token())),
        ("wrap_algorithm", text(wrap_algorithm)),
        ("wrapped_dek", Value::Bytes(wrapped_dek.as_bytes().to_vec())),
        ("cohort_scope", text(row.axis.emission_cohort_scope())),
        ("score", fixed6(1_000_000)),
        ("confidence", fixed6(1_000_000)),
    ];
    match &row.axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            epoch,
        } => {
            m.push(("community", text(community_key_id)));
            m.push(("community_id", text(community_key_id)));
            m.push(("minter", text(minter_key_id)));
            m.push(("epoch", Value::Uint(*epoch)));
        }
        KeyGrantAxis::Content {
            at_rest_sha256,
            cohort_scope,
            owner_key_id,
        } => {
            let d = hex::decode(at_rest_sha256)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| invalid("`at_rest_sha256` is not 64 hex"))?;
            m.push(("at_rest_sha256", hash_digest_value(&d)));
            m.push(("owner", text(owner_key_id)));
            if let Some(member) = cohort_target_member(cohort_scope) {
                m.push((member, text(owner_key_id)));
            }
        }
        KeyGrantAxis::Stream {
            stream_id,
            epoch,
            cohort_scope,
            owner_key_id,
        } => {
            m.push(("stream_id", text(stream_id)));
            m.push(("epoch", Value::Uint(*epoch)));
            m.push(("owner", text(owner_key_id)));
            if let Some(member) = cohort_target_member(cohort_scope) {
                m.push((member, text(owner_key_id)));
            }
        }
    }
    Ok(det_map(m))
}

/// The payload of a `delivery_receipt:{stream_id}` row by `subscriber`.
#[must_use]
pub fn delivery_receipt_payload(
    subscriber: &str,
    stream_id: &str,
    epoch: u64,
    k: u64,
    chunk_root: &[u8; 32],
    asserted_at_ms: u64,
) -> Value {
    det_map(vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", text(subscriber)),
        (
            "dimension",
            text(&crate::federation::custody_ack::delivery_receipt_dimension(
                stream_id,
            )),
        ),
        ("stream_id", text(stream_id)),
        ("epoch", Value::Uint(epoch)),
        ("k", Value::Uint(k)),
        ("chunk_root", hash_digest_value(chunk_root)),
    ])
}

/// The payload of a `cosign:{state}` statement naming the event it cosigns.
///
/// v62.0.0 (T2-fix5) — `cosign:{state}` is an AUTHORED family (Verify's
/// family model, `family_authorship.json`; CC 3.1.3's per-leaf rule:
/// `pending` is the event's primary signer, `signature` the member whose
/// signature it carries), so the payload carries `author`: the statement's
/// signer (`iss`). Without it the door refuses `author_column`.
#[must_use]
pub fn cosign_payload(author: &str, state: &str, event: &RowId, asserted_at_ms: u64) -> Value {
    det_map(vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", text(author)),
        ("dimension", text(&format!("cosign:{state}:v1"))),
        ("refs", refs_naming(TARGET_ROLE, event)),
    ])
}

/// The payload of a `trust:accepts:v1` acceptance edge (a `delegates_to`
/// from `granter` to the trusted key or root, the row's `sub`): the edge's
/// `scope`, its `trust_classes` (the v1.3 `trust_domains`), its
/// `valid_until` (the v1.3 `expires_at`), placed at `cohort_scope` (`self`
/// for an anonymous grant). `trust_type` is no member (CC: structure
/// carries it).
///
#[must_use]
pub fn trust_accepts_payload(
    granter: &str,
    scope: &[&str],
    trust_classes: &[String],
    valid_until_ms: Option<u64>,
    cohort_scope: &str,
    asserted_at_ms: u64,
) -> Value {
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", text(granter)),
        (
            "dimension",
            text(crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION),
        ),
        (
            "scope",
            Value::Array(scope.iter().map(|s| text(s)).collect()),
        ),
        ("cohort_scope", text(cohort_scope)),
    ];
    if !trust_classes.is_empty() {
        m.push((
            TRUST_CLASSES_MEMBER,
            Value::Array(trust_classes.iter().map(|c| text(c)).collect()),
        ));
    }
    if let Some(until) = valid_until_ms {
        m.push(("valid_until", Value::Uint(until)));
    }
    det_map(m)
}

/// The payload of a composer (`withdraws`) of a held row by `author`.
#[must_use]
pub fn withdraws_payload(author: &str, target: &RowId, asserted_at_ms: u64) -> Value {
    det_map(vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", text(author)),
        ("refs", refs_naming(TARGET_ROLE, target)),
    ])
}
