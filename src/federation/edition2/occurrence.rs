//! v62.0.0 (wave O1; CC 3.3.6, CC 3.3.6.2, CC 3.3.6.4, CC 3.1.3) — **the
//! edition-2 `identity:occurrence` bind, and the key-of-issuer check's
//! occurrence arm.**
//!
//! Every identity occurrence, a user's device or an agent, is one
//! `identity:occurrence` row (wire `identity:occurrence:v1`). Its payload
//! carries the members of the earlier `IdentityOccurrence` one to one
//! ([`super::payloads`], family `identity:occurrence`). The statements over
//! that one payload are the authority:
//!
//! - **the occurrence key's own statement** (`iss` = `sub` =
//!   `occurrence_key_id`, signed by that very key, role
//!   [`OCCURRENCE_KEY_ROLE`], stated by [`PersistCells`]): proof of
//!   possession, REQUIRED, as a rotation record carries its new key's voice. It is held when it arrives and
//!   lands nothing by itself.
//! - **the author's statement** (`iss` = `author` = `identity_key_id`): a
//!   live roster key of the identity, its genesis key or an admitted
//!   occurrence ([`crate::federation::admission::check_signer_acts_for`],
//!   the JSON door's rule). It is refused (retryable) until the occurrence
//!   key's own statement is held. For an agent, the author is the owner's
//!   roster key, and the agent key gives its own statement.
//! - **the self-roster door** (CC 3.3.6.4): a user-role key not yet on a
//!   user self's roster is a roster change. It lands at once by a strict
//!   majority of the live roster, the proposer counted; each roster key's
//!   approval is its own author statement over the same payload (a counted
//!   voice). The lone path (the window `W_self`) is not carried here (O1
//!   notes, "not done"). A node or agent occurrence is single-signer and
//!   lands on one author statement.
//!
//! When the bind lands it is written to the typed table the JSON door
//! writes (`federation_identity_occurrences`, its V161 history, and the
//! `transport_destinations` route it projects) by
//! [`crate::federation::FederationDirectory::put_identity_occurrence_edition2`].
//!
//! **The occurrence arm** (the rc21 rule, CC 3.1.3): a key admitted as a
//! live, unevicted `identity:occurrence` of `iss` is a key of `iss`. Without
//! it a user's second device is refused `kid_not_of_iss`.
//! [`occurrence_seats_for`] reads it for one statement at the statement's
//! signed instant, under the half-open record window
//! ([`crate::kernel::key_end::within_record`]) and the #421 revocation rule;
//! a key no longer live at receipt is held to the past-freshness bound W
//! (CC 3.3.6.4). [`super::liveness::HeldKeys::key_of`] answers `Yes` for a
//! seat it carries.

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::{
    FamilyModel, FamilyRule, RoleParty, RuleAnswer, SelectContext, VendoredFamilyModel,
};
use ciris_verify_core::edition2::{identity_ref, Digest32};

use super::door::AdmittedRow;
use super::ingest::{kid_of_identity_ref, statement_kid, StatementOutcome};
use super::liveness::statement_parts;
use super::names::{names_of, RowId};
use crate::federation::self_at_login::{
    check_xwing_halves, XWingKeyRole, XWingPublicKey, ONION_HOP_XWING_PUBKEY_MEMBER,
    TRANSIT_XWING_PUBKEY_MEMBER,
};
use crate::federation::types::{EncryptionPubkeys, IdentityOccurrence, OccurrenceTransportBinding};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The family id (header -70002) of an occurrence row.
pub const OCCURRENCE_FAMILY: &str = "identity:occurrence";

/// The role the occurrence key's own statement fills (CC 3.3.6, CC 3.3.6.4,
/// the rc21 second voice): CC names it `occurrence`, its party the member
/// [`OCCURRENCE_KEY_MEMBER`] (CIRISConstitution rc21 90d537b, after the
/// `v1.0-rc21-wire` tag). Stated by [`PersistCells`] until CIRISVerify
/// vendors it.
pub const OCCURRENCE_KEY_ROLE: &str = "occurrence";

/// The payload member naming the occurrence key, the party of
/// [`OCCURRENCE_KEY_ROLE`]: the occurrence key signs as itself.
pub const OCCURRENCE_KEY_MEMBER: &str = "occurrence_key_id";

/// The plane name this door's refusals carry.
pub const PLANE: &str = "identity_occurrence";

/// The five members of `transport_destination`, exactly (CC 3.3.6.2).
pub const TRANSPORT_MEMBERS: [&str; 5] = [
    "app_name",
    "aspects",
    "destination_hash",
    "reticulum_ed25519_pubkey",
    "reticulum_x25519_pubkey",
];

fn refuse(reason: &'static str, message: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, reason, message)
}

fn payload_invalid(message: impl Into<String>) -> Error {
    refuse(
        malformed_row::EDITION2_PAYLOAD_INVALID,
        format!("{OCCURRENCE_FAMILY}: {}", message.into()),
    )
}

// ─────────────────────────────────────────────────────────────────────────
//  The family model: the occurrence key's own voice
// ─────────────────────────────────────────────────────────────────────────

/// v62.0.0 (R1b; CIRISVerify 23.3.1) — **persist's own family cells**, read
/// BEFORE CC's vendored model: the door reads every row statement through
/// `WithVendored(&PersistCells)` (Verify's `edition2::family::WithVendored`:
/// a family this model does not register falls through to
/// `VendoredFamilyModel`).
///
/// v62.0.0 (K2-fix9) — and the `quarantine:{state}` rule, pinned (see
/// `quarantine_rule`; DROP AT 23.3.3).
///
/// One cell, `identity:occurrence`'s `second_signers`:
/// `[{role: occurrence, member: occurrence_key_id}]` (CC 3.3.6, CC 3.3.6.4;
/// CIRISConstitution rc21 90d537b, "An occurrence's proof of possession has a
/// role in the family model"). The occurrence key's own statement over its
/// occurrence row (`iss` = the payload's `occurrence_key_id`) is its proof of
/// possession; the vendored model at `v1.0-rc21-wire` (e6fd7c6) names no second
/// signer, so without this cell that statement is `iss_not_in_role`. The
/// authorship and every other member of the rule are CC's vendored answer for
/// the row, unchanged.
///
/// **DROP AT 23.3.2** (the CIRISVerify release that vendors CC past
/// 90d537b): delete this model and read `VendoredFamilyModel` at the door. It
/// replaces the earlier `WithOccurrenceRole` overlay (role `occurrence_key`,
/// party the CWT `sub`).
#[derive(Clone, Copy, Debug, Default)]
pub struct PersistCells;

/// CC's vendored rule for `identity:occurrence`, with the occurrence key's
/// own voice ([`PersistCells`]).
fn with_occurrence_voice(mut rule: FamilyRule) -> FamilyRule {
    if !rule.roles.iter().any(|(r, _)| r == OCCURRENCE_KEY_ROLE) {
        rule.roles.push((
            OCCURRENCE_KEY_ROLE.to_owned(),
            RoleParty::Member(OCCURRENCE_KEY_MEMBER.to_owned()),
        ));
    }
    rule
}

/// v62.0.0 (K2-fix9) — the `quarantine:{state}` family id
/// (`namespace_match::family_id("quarantine:{state}")`).
fn is_quarantine_family(family_id: &str) -> bool {
    family_id == ciris_verify_core::namespace_match::family_id("quarantine:{state}")
}

/// v62.0.0 (K2-fix9; CC rc21 family model, `quarantine:{state}`; **DROP AT
/// 23.3.3**, when CIRISVerify vendors these cells) — the quarantine family's
/// rule, pinned: its authorship is CC's vendored cell ("group=affiliations &
/// seats=one => counted ; authored", CC 4.4.3.12: authored by the slash-duty
/// holder, counted as `affiliation_member_action@subject_group` only in an
/// affiliation's one-voice seat), and its second signers are NONE
/// ([`crate::federation::quarantine::cells::SECOND_SIGNERS`]). The signer
/// rule (`seat_role(slash)`, CC 3.1.9.2 / CC 4.5.5), the signer kind
/// (agent / person, never a node key, CC 3.4.7.3 C and E) and the marker
/// plane's precedence (CC 3.1.9.2) are not family-rule fields; persist
/// applies them in `quarantine` (`quarantine::cells`).
fn quarantine_rule(mut rule: FamilyRule) -> FamilyRule {
    rule.roles.retain(|(r, _)| {
        crate::federation::quarantine::cells::SECOND_SIGNERS.contains(&r.as_str())
    });
    rule
}

impl FamilyModel for PersistCells {
    fn rule(&self, family_id: &str) -> Option<FamilyRule> {
        if is_quarantine_family(family_id) {
            return VendoredFamilyModel.rule(family_id).map(quarantine_rule);
        }
        if family_id != OCCURRENCE_FAMILY {
            return None;
        }
        VendoredFamilyModel
            .rule(family_id)
            .map(with_occurrence_voice)
    }

    fn rule_for(&self, family_id: &str, leaf: Option<&str>, ctx: &SelectContext) -> RuleAnswer {
        if is_quarantine_family(family_id) {
            return match VendoredFamilyModel.rule_for(family_id, leaf, ctx) {
                RuleAnswer::Rule(r) => RuleAnswer::Rule(quarantine_rule(r)),
                other => other,
            };
        }
        if family_id != OCCURRENCE_FAMILY {
            return RuleAnswer::Unregistered;
        }
        match VendoredFamilyModel.rule_for(family_id, leaf, ctx) {
            RuleAnswer::Rule(r) => RuleAnswer::Rule(with_occurrence_voice(r)),
            other => other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The occurrence arm of the key-of-issuer check (way (d))
// ─────────────────────────────────────────────────────────────────────────

/// The `(iss, kid)` pairs where `kid` is a live, unevicted occurrence of
/// the identity `iss` (an identity-ref) at the instant of the statement the
/// directory was loaded for ([`occurrence_seats_for`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OccurrenceSeats(BTreeSet<(String, Digest32)>);

impl OccurrenceSeats {
    /// No occurrence is a key of any identity here.
    #[must_use]
    pub fn none() -> Self {
        OccurrenceSeats::default()
    }

    /// These `(iss, kid)` pairs.
    #[must_use]
    pub fn live(pairs: impl IntoIterator<Item = (String, Digest32)>) -> Self {
        OccurrenceSeats(pairs.into_iter().collect())
    }

    /// Is `kid` a live occurrence of the identity `iss` (an identity-ref)?
    #[must_use]
    pub fn admits(&self, iss: &str, kid: &Digest32) -> bool {
        self.0.contains(&(iss.to_owned(), *kid))
    }
}

/// **Is an occurrence live at `at`** (POSIX ms; pure): some admitted
/// assertion `(asserted_at, valid_until)` of it covers `at` under the
/// half-open record window ([`crate::kernel::key_end::within_record`]), and
/// no revocation (its `effective_at`) in effect by `at` came at or after
/// that assertion (the #421 rule: a later assertion re-establishes, a
/// replayed older revocation is a no-op).
#[must_use]
pub fn occurrence_live_at(asserted: &[(u64, Option<u64>)], revocations: &[u64], at: u64) -> bool {
    asserted.iter().any(|(from, until)| {
        crate::kernel::key_end::within_record(at, *from, *until)
            && !revocations.iter().any(|e| *e <= at && *e >= *from)
    })
}

fn ms_of(t: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(t.timestamp_millis()).unwrap_or(0)
}

/// **Is `key` a live, unevicted occurrence of `identity`** for a statement
/// signed at `at_ms`? Live at `at_ms` ([`occurrence_live_at`] over every
/// admitted assertion of the pair, the V161 history and the held row, and
/// the pair's revocations); and, when it is no longer live at receipt,
/// `at_ms` within the past-freshness bound W of this node's clock (CC
/// 3.3.6.4: an evicted key can backdate by at most W).
///
/// # Errors
/// Directory read failures.
pub async fn occurrence_live<F>(
    dir: &F,
    identity: &str,
    key: &str,
    at_ms: u64,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut asserted: Vec<(u64, Option<u64>)> = dir
        .list_identity_occurrence_history_by_occurrence(key)
        .await?
        .into_iter()
        .filter(|h| h.identity_key_id == identity)
        .map(|h| (ms_of(h.asserted_at), h.valid_until.map(ms_of)))
        .collect();
    asserted.extend(
        dir.list_identity_occurrences_by_occurrence_key(key)
            .await?
            .into_iter()
            .filter(|o| o.identity_key_id == identity)
            .map(|o| (ms_of(o.asserted_at), o.valid_until.map(ms_of))),
    );
    if asserted.is_empty() {
        return Ok(false);
    }
    let revocations: Vec<u64> = dir
        .list_identity_occurrence_revocations_for(identity)
        .await?
        .into_iter()
        .filter(|r| r.occurrence_key_id == key)
        .map(|r| ms_of(r.effective_at))
        .collect();
    if !occurrence_live_at(&asserted, &revocations, at_ms) {
        return Ok(false);
    }
    let now = ms_of(crate::federation::self_roster::roster_clock());
    if occurrence_live_at(&asserted, &revocations, now) {
        return Ok(true);
    }
    let w_ms = crate::federation::self_roster::PAST_FRESHNESS_W_SECS.unsigned_abs() * 1000;
    Ok(at_ms.saturating_add(w_ms) >= now)
}

/// The `iss` of a statement (CWT label 1 under protected label 15).
pub(crate) fn statement_iss(statement: &[u8]) -> Option<String> {
    let (protected, _) = statement_parts(statement)?;
    protected
        .get_int(15)?
        .get_int(1)?
        .as_text()
        .map(str::to_owned)
}

/// The identity-type set of the held key `key` (its `federation_keys`
/// projection, from its edition-2 `key:record`); empty when not held.
async fn key_types<F>(dir: &F, key: &str) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::types::identity_type::parse_set;
    Ok(dir
        .lookup_public_key(key)
        .await?
        .map(|k| {
            parse_set(&k.identity_type)
                .into_iter()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default())
}

/// A person's identity set: `user` or `accord_holder` (CC 2.4.1.1).
fn is_person(types: &[String]) -> bool {
    use crate::federation::types::identity_type::{ACCORD_HOLDER, USER};
    types.iter().any(|t| t == USER || t == ACCORD_HOLDER)
}

/// A machine's identity set: `node` or `agent` (CC 2.4.1.1).
fn is_machine(types: &[String]) -> bool {
    use crate::federation::types::identity_type::{AGENT, NODE};
    types.iter().any(|t| t == NODE || t == AGENT)
}

/// **The identity-set exclusion** (CC 3.3.6 as corrected for rc21; the
/// RULINGS identity-set rule): an occurrence never binds a machine to a
/// person. Under a `user` / `accord_holder` identity, a `node` / `agent`
/// key, or `device_class: agent` (even when the key's type is not held),
/// is refused [`malformed_row::OCCURRENCE_BINDS_MACHINE_TO_PERSON`]. An
/// agent's occurrence binds the agent's own identity.
pub(crate) async fn check_identity_set_exclusion<F>(
    dir: &F,
    identity: &str,
    occurrence: &str,
    device_class: &str,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if occurrence == identity {
        return Ok(());
    }
    let identity_types = key_types(dir, identity).await?;
    // v62.0.0 (wave O1; E7) — the other direction of the same rule: a
    // person's key is never an occurrence of a machine identity (the sets
    // never cohabit), so a node cannot claim a person's key and with it the
    // person's vote.
    if is_machine(&identity_types) && is_person(&key_types(dir, occurrence).await?) {
        return Err(refuse(
            malformed_row::OCCURRENCE_BINDS_MACHINE_TO_PERSON,
            format!(
                "{OCCURRENCE_FAMILY}: {identity} is a machine's identity and {occurrence} is a \
                 person's key: an occurrence never binds a person's key to a node or agent \
                 (CC 3.3.6)"
            ),
        ));
    }
    if !is_person(&identity_types) {
        return Ok(());
    }
    let agent_class = device_class == crate::federation::types::device_class::AGENT;
    if agent_class || is_machine(&key_types(dir, occurrence).await?) {
        return Err(refuse(
            malformed_row::OCCURRENCE_BINDS_MACHINE_TO_PERSON,
            format!(
                "{OCCURRENCE_FAMILY}: {identity} is a person's identity and {occurrence} is \
                 a machine's key (device_class {device_class}): an occurrence never binds a \
                 node or agent key to a person; an agent's occurrence binds the agent's own \
                 identity (CC 3.3.6)"
            ),
        ));
    }
    Ok(())
}

/// **The occurrence seats for one statement** (way (d)): when its `kid` is
/// not the genesis key of its `iss`, and `kid` is a live, unevicted
/// occurrence of `iss` at the statement's `asserted_at`
/// ([`occurrence_live`]), the one pair `(iss, kid)`; else none.
///
/// # Errors
/// Directory read failures.
pub async fn occurrence_seats_for<F>(dir: &F, statement: &[u8]) -> Result<OccurrenceSeats, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (Some(kid), Some(iss)) = (statement_kid(statement), statement_iss(statement)) else {
        return Ok(OccurrenceSeats::none());
    };
    let Some(genesis) = kid_of_identity_ref(&iss) else {
        return Ok(OccurrenceSeats::none());
    };
    if genesis == kid {
        return Ok(OccurrenceSeats::none());
    }
    let Some(at) = statement_parts(statement)
        .and_then(|(_, p)| p.get_text("asserted_at").and_then(Value::as_u64))
    else {
        return Ok(OccurrenceSeats::none());
    };
    let key = identity_ref(&kid);
    // The identity-set exclusion: a machine's key is never a key of a
    // person, whatever occurrence row is held.
    if is_person(&key_types(dir, &iss).await?) && is_machine(&key_types(dir, &key).await?) {
        return Ok(OccurrenceSeats::none());
    }
    if occurrence_live(dir, &iss, &key, at).await? {
        Ok(OccurrenceSeats::live([(iss, kid)]))
    } else {
        Ok(OccurrenceSeats::none())
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The payload
// ─────────────────────────────────────────────────────────────────────────

fn text_member<'a>(p: &'a Value, name: &str) -> Result<&'a str, Error> {
    p.get_text(name)
        .and_then(Value::as_text)
        .ok_or_else(|| payload_invalid(format!("`{name}` is required text")))
}

fn bytes_of<'a>(v: &'a Value, what: &str, len: Option<usize>) -> Result<&'a [u8], Error> {
    let b = v
        .as_bytes()
        .ok_or_else(|| payload_invalid(format!("`{what}` is not bstr")))?;
    match len {
        Some(n) if b.len() != n => Err(payload_invalid(format!(
            "`{what}` is {} bytes, not {n}",
            b.len()
        ))),
        _ => Ok(b),
    }
}

fn instant(ms: u64, what: &str) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .ok_or_else(|| payload_invalid(format!("`{what}` is out of range")))
}

/// `transport_destination`: exactly the five members of CC 3.3.6.2, the
/// `destination_hash` derived from the two keys, `app_name` and `aspects`
/// (CC 3.3.6.3).
fn transport_of(v: &Value) -> Result<OccurrenceTransportBinding, Error> {
    let map = v
        .as_map()
        .ok_or_else(|| payload_invalid("`transport_destination` is not a map"))?;
    let all_known = map
        .iter()
        .all(|(k, _)| k.as_text().is_some_and(|k| TRANSPORT_MEMBERS.contains(&k)));
    if map.len() != TRANSPORT_MEMBERS.len() || !all_known {
        return Err(payload_invalid(format!(
            "`transport_destination` is a map of exactly {TRANSPORT_MEMBERS:?} (CC 3.3.6.2)"
        )));
    }
    let member = |m: &str| {
        v.get_text(m)
            .ok_or_else(|| payload_invalid(format!("`transport_destination.{m}` is required")))
    };
    let x25519 = bytes_of(
        member("reticulum_x25519_pubkey")?,
        "transport_destination.reticulum_x25519_pubkey",
        Some(32),
    )?;
    let ed25519 = bytes_of(
        member("reticulum_ed25519_pubkey")?,
        "transport_destination.reticulum_ed25519_pubkey",
        Some(32),
    )?;
    let dest = bytes_of(
        member("destination_hash")?,
        "transport_destination.destination_hash",
        Some(16),
    )?;
    let app_name = member("app_name")?
        .as_text()
        .ok_or_else(|| payload_invalid("`transport_destination.app_name` is not text"))?
        .to_owned();
    let aspects: Vec<String> = member("aspects")?
        .as_array()
        .and_then(|a| {
            a.iter()
                .map(|s| s.as_text().map(str::to_owned))
                .collect::<Option<Vec<String>>>()
        })
        .ok_or_else(|| payload_invalid("`transport_destination.aspects` is not [* tstr]"))?;
    let derived = ciris_verify_core::transport_binding::compute_destination_hash(
        &app_name, &aspects, x25519, ed25519,
    );
    if derived.as_ref().map(|d| d.as_slice()) != Some(dest) {
        return Err(payload_invalid(
            "`transport_destination.destination_hash` does not derive from its keys, app_name \
             and aspects (CC 3.3.6.3)",
        ));
    }
    Ok(OccurrenceTransportBinding {
        reticulum_x25519_pubkey_base64: B64.encode(x25519),
        reticulum_ed25519_pubkey_base64: B64.encode(ed25519),
        destination_hash_base64: B64.encode(dest),
        app_name,
        aspects,
    })
}

/// `encryption_pubkeys`: exactly `x25519` (32 bytes) and `ml_kem_768`
/// (1184 bytes).
fn encryption_of(v: &Value) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let map = v
        .as_map()
        .ok_or_else(|| payload_invalid("`encryption_pubkeys` is not a map"))?;
    if map.len() != 2 {
        return Err(payload_invalid(
            "`encryption_pubkeys` is a map of exactly `x25519` and `ml_kem_768`",
        ));
    }
    let member = |m: &str| {
        v.get_text(m)
            .ok_or_else(|| payload_invalid(format!("`encryption_pubkeys.{m}` is required")))
    };
    let x = bytes_of(member("x25519")?, "encryption_pubkeys.x25519", Some(32))?;
    let m = bytes_of(
        member("ml_kem_768")?,
        "encryption_pubkeys.ml_kem_768",
        Some(1184),
    )?;
    Ok((x.to_vec(), m.to_vec()))
}

/// The X-Wing keys at the payload's top level, each exactly 1216 bytes.
fn xwing_of(p: &Value, member: &'static str) -> Result<Option<XWingPublicKey>, Error> {
    let Some(v) = p.get_text(member) else {
        return Ok(None);
    };
    let b = v
        .as_bytes()
        .ok_or_else(|| payload_invalid(format!("`{member}` is not bstr")))?;
    XWingPublicKey::from_bytes(b).map(Some).ok_or_else(|| {
        refuse(
            malformed_row::XWING_PUBKEY_WRONG_LENGTH,
            format!(
                "`{member}` is {} bytes; an X-Wing public key is exactly 1216 (CC 3.3.6.2)",
                b.len()
            ),
        )
    })
}

/// **The payload of an occurrence row, read and checked** (pure):
/// an `author` is present, `occurrence_key_id` is the `sub`;
/// `device_class` in the closed set; `valid_until`, when present, later than
/// `asserted_at` (`valid_until_not_after_asserted_at`, the door's
/// `check_valid_until_after_asserted_at`);
/// `transport_destination` and `encryption_pubkeys` of their exact shapes,
/// the content KEM x25519 not the Reticulum link x25519 (CC 3.3.6.1);
/// `onion_relay`, when present, exactly `{"opt_out": true}`. The X-Wing keys'
/// in-row separation needs the signer's keys and is checked by the door.
///
/// # Errors
/// As above; `edition2_payload_invalid` for a shape fault;
/// `federation_device_class_rejected` for a device class outside the set.
pub fn read_payload(row: &AdmittedRow) -> Result<IdentityOccurrence, Error> {
    let p = &row.payload;
    let identity_key_id = text_member(p, "identity_key_id")?.to_owned();
    let occurrence_key_id = text_member(p, "occurrence_key_id")?.to_owned();
    // Who authors it (the identity itself, or an agent's owner) is the
    // door's: it needs the directory ([`put_occurrence_voice`]).
    if row.author.is_none() {
        return Err(payload_invalid(
            "an occurrence row is authored: `author` is required",
        ));
    }
    if row.sub != occurrence_key_id {
        return Err(payload_invalid("`occurrence_key_id` is the row's `sub`"));
    }
    let device_class = text_member(p, "device_class")?.to_owned();
    crate::federation::check_device_class(&device_class)?;
    let asserted_at_ms = row.asserted_at_ms;
    let valid_until_ms = match p.get_text("valid_until") {
        None => None,
        Some(v) => Some(
            v.as_u64()
                .ok_or_else(|| payload_invalid("`valid_until` is not uint (ms)"))?,
        ),
    };
    // The door's one window rule (K1): absent, indefinite; present, later
    // than `asserted_at`.
    super::door::check_valid_until_after_asserted_at(p)?;
    let hardware_attestation = match p.get_text("hardware_attestation") {
        None => None,
        Some(v) => Some(B64.encode(bytes_of(v, "hardware_attestation", None)?)),
    };
    let transport_binding = p
        .get_text("transport_destination")
        .map(transport_of)
        .transpose()?;
    let encryption = p
        .get_text("encryption_pubkeys")
        .map(encryption_of)
        .transpose()?;
    if let (Some((x, _)), Some(tb)) = (&encryption, &transport_binding) {
        if B64.encode(x) == tb.reticulum_x25519_pubkey_base64 {
            return Err(payload_invalid(
                "`encryption_pubkeys.x25519` is the Reticulum link x25519: the content KEM key \
                 is a fresh key (CC 3.3.6.1 key separation)",
            ));
        }
    }
    if let Some(r) = p.get_text("onion_relay") {
        let opt_out = r.as_map().is_some_and(|m| m.len() == 1)
            && matches!(r.get_text("opt_out"), Some(Value::Bool(true)));
        if !opt_out {
            return Err(payload_invalid(
                "`onion_relay` is exactly {\"opt_out\": true} (CC 3.3.6.2)",
            ));
        }
    }
    Ok(IdentityOccurrence {
        identity_key_id,
        occurrence_key_id,
        device_class,
        hardware_attestation,
        asserted_at: instant(asserted_at_ms, "asserted_at")?,
        valid_until: valid_until_ms
            .map(|u| instant(u, "valid_until"))
            .transpose()?,
        encryption_pubkeys: encryption.map(|(x, m)| EncryptionPubkeys {
            x25519_base64: B64.encode(x),
            ml_kem_768_base64: B64.encode(m),
        }),
        transport_binding,
        persist_row_hash: String::new(),
    })
}

/// The X-Wing keys' in-row separation (CC 3.3.6.2): each half of
/// `transit_xwing_pubkey` and `onion_hop_xwing_pubkey` differs from the
/// Reticulum link x25519 and transport ed25519, the content KEM keys, and
/// the signing key's two halves; the hop key from the transit key's halves
/// too. The same rule the transport door applies.
async fn check_xwing_in_row<F>(dir: &F, row: &AdmittedRow) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let transit = xwing_of(&row.payload, TRANSIT_XWING_PUBKEY_MEMBER)?;
    let hop = xwing_of(&row.payload, ONION_HOP_XWING_PUBKEY_MEMBER)?;
    if transit.is_none() && hop.is_none() {
        return Ok(());
    }
    let p = &row.payload;
    let mut keys: Vec<Vec<u8>> = Vec::new();
    if let Some(td) = p.get_text("transport_destination") {
        for m in ["reticulum_x25519_pubkey", "reticulum_ed25519_pubkey"] {
            keys.extend(td.get_text(m).and_then(Value::as_bytes).map(<[u8]>::to_vec));
        }
    }
    if let Some(enc) = p.get_text("encryption_pubkeys") {
        for m in ["x25519", "ml_kem_768"] {
            keys.extend(
                enc.get_text(m)
                    .and_then(Value::as_bytes)
                    .map(<[u8]>::to_vec),
            );
        }
    }
    if let Some(signer) = dir.lookup_public_key(&identity_ref(&row.kid)).await? {
        keys.extend(B64.decode(&signer.pubkey_ed25519_base64).ok());
        keys.extend(
            signer
                .pubkey_ml_dsa_65_base64
                .as_deref()
                .and_then(|s| B64.decode(s).ok()),
        );
    }
    let reuse = |r: crate::federation::self_at_login::XWingReuseRefusal, member: &str| {
        refuse(
            r.as_str(),
            format!(
                "{OCCURRENCE_FAMILY}: a half of `{member}` is another key on the same row; the \
                 X-Wing key must be key-separated (CC 3.3.6.2)"
            ),
        )
    };
    if let Some(t) = &transit {
        check_xwing_halves(XWingKeyRole::Transit, t, keys.iter().map(Vec::as_slice))
            .map_err(|r| reuse(r, TRANSIT_XWING_PUBKEY_MEMBER))?;
    }
    if let Some(h) = &hop {
        let mut with_transit: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        if let Some(t) = &transit {
            with_transit.push(t.ml_kem_768());
            with_transit.push(t.x25519());
        }
        check_xwing_halves(XWingKeyRole::OnionHop, h, with_transit)
            .map_err(|r| reuse(r, ONION_HOP_XWING_PUBKEY_MEMBER))?;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
//  The door
// ─────────────────────────────────────────────────────────────────────────

/// An admitted occurrence bind, ready for the typed table
/// ([`crate::federation::FederationDirectory::put_identity_occurrence_edition2`]).
#[derive(Clone, Debug)]
pub struct OccurrenceBind {
    /// The typed row (`persist_row_hash` is computed by the write).
    pub occurrence: IdentityOccurrence,
    /// The identity-ref of the key whose author statement landed it.
    pub author_key_id: String,
    /// The bind's row id.
    pub row_id: RowId,
    /// The bind's held statements, as received: the landing author
    /// statement first, then every other voice over the row.
    pub statements: Vec<Vec<u8>>,
}

impl OccurrenceBind {
    /// What the typed row keeps in `signed_envelope`: the row id, the
    /// landing author key, and the statements themselves, lowercase hex
    /// (`ceg_statement`: the author's; `ceg_statements`: every voice), the
    /// way a projected plane carries its statement (CC 2.6.3). `signature`
    /// is NULL; the signed listing serves this envelope
    /// ([`edition2_signature_placeholder`]).
    #[must_use]
    pub fn envelope(&self) -> serde_json::Value {
        let hexes: Vec<String> = self.statements.iter().map(hex::encode).collect();
        let mut env = serde_json::json!({
            "edition2_row_id": self.row_id.hex(),
            "author_key_id": self.author_key_id,
            "ceg_statements": hexes,
        });
        if let (Some(o), Some(first)) = (env.as_object_mut(), hexes.first()) {
            o.insert(
                super::ingest::STATEMENT_MEMBER.to_owned(),
                serde_json::Value::String(first.clone()),
            );
        }
        env
    }
}

/// The `signature` a signed occurrence listing reports for an edition-2
/// bind, which has none of the earlier form: empty, no ML-DSA half. Its
/// authority is the `ceg_statement` its `signed_envelope` carries; a
/// consumer verifies that statement, never this value.
#[must_use]
pub fn edition2_signature_placeholder() -> crate::federation::types::RetiredPairSignature {
    crate::federation::types::RetiredPairSignature {
        ed25519_signature_base64: String::new(),
        mldsa65_signature_base64: None,
    }
}

/// Is this held statement the occurrence key's own voice over its bind?
fn is_own_voice(statement: &[u8], occurrence: &str, occurrence_kid: &Digest32) -> bool {
    statement_kid(statement).as_ref() == Some(occurrence_kid)
        && statement_iss(statement).as_deref() == Some(occurrence)
}

/// **The `identity:occurrence` door** (module docs): one admitted statement
/// of the family, from [`super::ingest::put_statement`].
///
/// - the occurrence key's own statement is held:
///   [`StatementOutcome::Voice`];
/// - an author statement with the occurrence key's own statement held, by a
///   key that acts for the identity, is held; when the bind lands it is
///   written to the typed table: [`StatementOutcome::Row`]; while a roster
///   change waits on more roster keys: [`StatementOutcome::Voice`].
///
/// # Errors
/// - the payload's refusals ([`read_payload`], the X-Wing separation);
/// - `occurrence_voice_not_own_key`: a statement in the occurrence key's
///   role not signed by that key itself;
/// - the retryable `federation_attester_key_unknown`, naming the occurrence
///   key: an author statement before the occurrence key's own (nothing is
///   stored);
/// - `federation_signer_not_acting_for` (the JSON door's rule), a clock-skew
///   refusal for a future-dated bind; directory failures.
pub async fn put_occurrence_voice<F>(dir: &F, row: &AdmittedRow) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    // S1b — a composer of this family: the proposer withdrawing its own
    // open edition-2 proposal.
    if super::ingest::COMPOSER_ROW_TYPES.contains(&row.row_type.as_str()) {
        return withdraw_proposal(dir, row).await;
    }
    super::payloads::check(&row.family, &row.payload)?;
    let occurrence = read_payload(row)?;
    // CC 3.3.6.4 (the CC 2.7 ruling; P1 refuses it too): every roster row
    // names the roster it stands on, `refs.head` (the self's first, the
    // genesis key's own key:record row).
    if super::names::single(&row.names, "head").is_none() {
        return Err(payload_invalid(
            "`refs.head` is required: the roster row the bind stands on (CC 3.3.6.4)",
        ));
    }
    check_xwing_in_row(dir, row).await?;
    let identity = occurrence.identity_key_id.clone();
    let occ = occurrence.occurrence_key_id.clone();
    let occ_kid = kid_of_identity_ref(&occ)
        .ok_or_else(|| payload_invalid("`occurrence_key_id` is not an identity-ref"))?;
    check_identity_set_exclusion(dir, &identity, &occ, &occurrence.device_class).await?;
    let own_role = row.iss == occ && row.iss == row.sub;
    if own_role && row.kid != occ_kid {
        return Err(refuse(
            malformed_row::OCCURRENCE_VOICE_NOT_OWN_KEY,
            format!(
                "{OCCURRENCE_FAMILY}: the statement in the occurrence key's role is signed by {}, \
                 not by the occurrence key {occ} itself (proof of possession)",
                identity_ref(&row.kid)
            ),
        ));
    }
    // Who authors the bind: the identity itself; for an agent's identity,
    // the agent's OWNER (CC 3.3.6: "the author is the owner's roster key,
    // plus the agent key's own statement"), and no owner refuses it.
    let author = row.author.clone().unwrap_or_default();
    let bind_author = if key_types(dir, &identity)
        .await?
        .iter()
        .any(|t| t == crate::federation::types::identity_type::AGENT)
    {
        // v62.0.0 (wave GC7; CC 2.7.3) — the agent's owner is read from
        // ANOTHER row (its live owner binding): an absent or different owner
        // HOLDS the statement (kept, concluding nothing) and re-folds when a
        // binding about the agent lands or is withdrawn; never a refusal.
        let Some(owner) =
            crate::federation::admission::agent_owner_of(dir, &identity, row.asserted_at_ms)
                .await?
        else {
            super::fold::reads(super::fold::Dep::key(identity.as_str()));
            super::fold::reads(super::fold::Dep::key(author.as_str()));
            return Err(super::fold::hold(
                super::fold::reason::AGENT_OCCURRENCE_UNOWNED,
                refuse(
                    malformed_row::AGENT_OCCURRENCE_UNOWNED,
                    format!(
                        "{OCCURRENCE_FAMILY}: the agent {identity} has no live owner binding \
                         (`ownership:{{relation}}:agent:{{version}}`) at {}: its occurrence is \
                         authored by its owner (CC 3.3.6)",
                        row.asserted_at_ms
                    ),
                ),
            ));
        };
        if author != owner {
            super::fold::reads(super::fold::Dep::key(identity.as_str()));
            super::fold::reads(super::fold::Dep::key(author.as_str()));
            super::fold::reads(super::fold::Dep::key(owner.as_str()));
            return Err(super::fold::hold(
                super::fold::reason::AGENT_OCCURRENCE_NOT_OWNER_AUTHORED,
                refuse(
                    malformed_row::AGENT_OCCURRENCE_NOT_OWNER_AUTHORED,
                    format!(
                        "{OCCURRENCE_FAMILY}: the agent {identity}'s occurrence is authored by \
                         {author}, not by its owner {owner} (CC 3.3.6)"
                    ),
                ),
            ));
        }
        owner
    } else {
        if author != identity {
            return Err(payload_invalid(
                "`identity_key_id` is the row's `author`: the identity authors its own \
                 occurrence (an agent's owner authors the agent's)",
            ));
        }
        identity.clone()
    };
    let author_voice = row.iss == bind_author;
    if !author_voice {
        // The occurrence key's own statement: held; it lands nothing alone.
        let new = dir.put_edition2_statement(row).await?;
        return Ok(StatementOutcome::Voice {
            row_id: row.row_id,
            new,
        });
    }
    // An author statement. (For the self pair, identity = occurrence, the
    // genesis key's one statement is both voices.)
    let held = dir.edition2_voices(&row.row_id).await?;
    let possession = (own_role && row.kid == occ_kid)
        || (row.kid == occ_kid && identity == occ)
        || held.iter().any(|st| is_own_voice(st, &occ, &occ_kid));
    if !possession {
        return Err(Error::unknown_signer(&occ, PLANE));
    }
    let author_key = identity_ref(&row.kid);
    // The author's key is a live roster key of the author's identity (the
    // identity's, or the agent's owner's): the JSON door's rule.
    // v62.0.0 (wave GC7; CC 2.7.3) — whether the author's key acts for the
    // bind author reads the author's roster (other rows): a key not (yet) on
    // it HOLDS the statement, re-folded when the roster changes. Any other
    // error is returned as it was.
    match crate::federation::admission::check_signer_acts_for(dir, &author_key, &bind_author, PLANE)
        .await
    {
        Ok(()) => {}
        Err(e @ Error::SignerDoesNotActFor { .. }) => {
            super::fold::reads(super::fold::Dep::key(author_key.as_str()));
            super::fold::reads(super::fold::Dep::key(bind_author.as_str()));
            return Err(super::fold::hold(
                super::fold::reason::SIGNER_NOT_ACTING_FOR,
                e,
            ));
        }
        Err(e) => return Err(e),
    }
    crate::federation::operational::check_skew_bound(
        occurrence.asserted_at,
        crate::host::clock::now(),
    )?;
    let new = dir.put_edition2_statement(row).await?;
    // CC 3.3.6.4, the two paths (S1): THE self-roster gate, over a proposal
    // whose id is this row id. A change that does not land now is held
    // (this node's receipt starts its window); it lands later by an answer,
    // a further roster key's author statement, or the lone path
    // (`self_roster::execute_for`, which lands it from its held statements).
    // The proposer is the lowest statement id's key among the held author
    // statements (S1b); the head is the roster row the bind names.
    let Some(carried) = carried_of_bind(dir, &row.row_id.hex()).await? else {
        return Err(payload_invalid(
            "the bind names no roster row by `refs.head` (CC 3.3.6.4)",
        ));
    };
    if !crate::federation::self_roster::gate_edition2(dir, carried).await? {
        // Held, concluding nothing yet (T1's `Pending`): short of its count,
        // or waiting on a roster row it names. The fold re-plans it.
        return Ok(StatementOutcome::Pending {
            row_id: row.row_id,
            new,
        });
    }
    let mut statements = vec![row.bytes.clone()];
    statements.extend(held.into_iter().filter(|st| *st != row.bytes));
    dir.put_identity_occurrence_edition2(OccurrenceBind {
        occurrence,
        author_key_id: author_key,
        row_id: row.row_id,
        statements,
    })
    .await?;
    Ok(StatementOutcome::Row {
        row_id: row.row_id,
        new,
    })
}

// ─────────────────────────────────────────────────────────────────────────
//  The X-Wing keys a bind carries (E8's finding)
// ─────────────────────────────────────────────────────────────────────────

/// The X-Wing keys a held edition-2 bind of an occurrence carries at its
/// payload's top level (CC 3.3.6.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindXWing {
    /// `transit_xwing_pubkey`.
    pub transit: Option<XWingPublicKey>,
    /// `onion_hop_xwing_pubkey`.
    pub onion_hop: Option<XWingPublicKey>,
}

/// **The X-Wing keys of `occurrence_key_id`'s live edition-2 bind**, for a
/// node that is NOT a seat of the genesis bundle in force (a seat's keys are
/// the bundle binding's, moved only by a counted `transport:canonical_rebind`:
/// W1's rule, `transit_xwing_pubkey_for`). Read from the held statement the
/// typed row carries (`signed_envelope.ceg_statement`), for every identity
/// the key is a live occurrence of now ([`occurrence_live`]). `None` for a
/// seat, for no live bind, and when two live binds carry different keys.
///
/// # Errors
/// Directory read failures.
pub async fn bind_xwing_keys_for<F>(
    dir: &F,
    occurrence_key_id: &str,
) -> Result<Option<BindXWing>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if super::genesis::genesis_in_force(dir)
        .await?
        .seat(occurrence_key_id)
        .is_some()
    {
        return Ok(None);
    }
    let now = ms_of(crate::host::clock::now());
    let mut found: Option<BindXWing> = None;
    let mut identities: Vec<String> = dir
        .list_identity_occurrences_by_occurrence_key(occurrence_key_id)
        .await?
        .into_iter()
        .map(|o| o.identity_key_id)
        .collect();
    identities.sort();
    identities.dedup();
    for identity in identities {
        if !occurrence_live(dir, &identity, occurrence_key_id, now).await? {
            continue;
        }
        let signed = dir.list_signed_identity_occurrences_for(&identity).await?;
        let Some(statement) = signed
            .iter()
            .find(|s| s.identity_occurrence.occurrence_key_id == occurrence_key_id)
            .and_then(|s| s.signed_envelope.get(super::ingest::STATEMENT_MEMBER))
            .and_then(serde_json::Value::as_str)
            .and_then(|h| hex::decode(h).ok())
        else {
            continue;
        };
        let Some((_, payload)) = statement_parts(&statement) else {
            continue;
        };
        let (Ok(transit), Ok(onion_hop)) = (
            xwing_of(&payload, TRANSIT_XWING_PUBKEY_MEMBER),
            xwing_of(&payload, ONION_HOP_XWING_PUBKEY_MEMBER),
        ) else {
            continue;
        };
        let keys = BindXWing { transit, onion_hop };
        match &found {
            None => found = Some(keys),
            Some(k) if *k == keys => {}
            Some(_) => return Ok(None),
        }
    }
    Ok(found)
}

/// v62.0.0 (RL-fix4; CC 3.3.6.2 "The opt-out marker", part_3 l.1907; CC
/// 5.4.6 "Relay is offered by default on every owned node") — what the node's
/// OWN live edition-2 binds say about relaying for others.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindRelayOffer {
    /// A live bind carries `"onion_relay": {"opt_out": true}`: the node
    /// carries nobody (the marker is absent by default, so a live bind
    /// without it OFFERS relay).
    pub opted_out: bool,
    /// The earliest signed `valid_until` of the live binds read (the
    /// signer's own stamp), if any is bounded.
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// **The relay offer of `occurrence_key_id`'s live edition-2 binds**
/// ([`BindRelayOffer`]): `None` when no live bind of it is held. Read from
/// the held statements the typed rows carry, as [`bind_xwing_keys_for`] reads
/// them; the marker's shape (exactly `{"opt_out": true}`) was checked at
/// admission ([`read_payload`]).
///
/// # Errors
/// Directory read failures.
pub async fn bind_relay_offer_for<F>(
    dir: &F,
    occurrence_key_id: &str,
) -> Result<Option<BindRelayOffer>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let now = ms_of(crate::host::clock::now());
    let mut found: Option<BindRelayOffer> = None;
    let mut identities: Vec<String> = dir
        .list_identity_occurrences_by_occurrence_key(occurrence_key_id)
        .await?
        .into_iter()
        .map(|o| o.identity_key_id)
        .collect();
    identities.sort();
    identities.dedup();
    for identity in identities {
        if !occurrence_live(dir, &identity, occurrence_key_id, now).await? {
            continue;
        }
        let signed = dir.list_signed_identity_occurrences_for(&identity).await?;
        let Some(statement) = signed
            .iter()
            .find(|s| s.identity_occurrence.occurrence_key_id == occurrence_key_id)
            .and_then(|s| s.signed_envelope.get(super::ingest::STATEMENT_MEMBER))
            .and_then(serde_json::Value::as_str)
            .and_then(|h| hex::decode(h).ok())
        else {
            continue;
        };
        let Some((_, payload)) = statement_parts(&statement) else {
            continue;
        };
        let opted_out = payload.get_text("onion_relay").is_some();
        let until = payload
            .get_text("valid_until")
            .and_then(Value::as_u64)
            .and_then(|ms| i64::try_from(ms).ok())
            .and_then(|ms| chrono::TimeZone::timestamp_millis_opt(&chrono::Utc, ms).single());
        let entry = found.get_or_insert_with(BindRelayOffer::default);
        entry.opted_out |= opted_out;
        entry.valid_until = match (entry.valid_until, until) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    Ok(found)
}

/// **A non-seat node's transit X-Wing key from its edition-2 bind**
/// ([`bind_xwing_keys_for`]), passing the cross-row rule at use (a half
/// equal to any key on the node's current occurrence ⇒ `None`, CC 3.3.6.2).
/// `transit_xwing_pubkey_for`'s answer when no route-plane binding carries
/// one.
///
/// # Errors
/// Directory read failures.
pub async fn bind_transit_xwing_for<F>(
    dir: &F,
    occurrence_key_id: &str,
) -> Result<Option<XWingPublicKey>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(BindXWing {
        transit: Some(key), ..
    }) = bind_xwing_keys_for(dir, occurrence_key_id).await?
    else {
        return Ok(None);
    };
    let others =
        crate::federation::self_at_login::other_keys_of(dir, occurrence_key_id, &[]).await?;
    if check_xwing_halves(XWingKeyRole::Transit, &key, others.all()).is_err() {
        return Ok(None);
    }
    Ok(Some(key))
}

/// **The onion hop X-Wing key of `occurrence_key_id`** (CC 3.3.6.2, CC
/// 5.4.6): for a seat of the genesis bundle in force, its bundle binding's;
/// else its live edition-2 bind's ([`bind_xwing_keys_for`]), passing the
/// cross-row rule at use (also against the transit key's halves).
///
/// # Errors
/// Directory read failures.
pub async fn onion_hop_xwing_pubkey_for<F>(
    dir: &F,
    occurrence_key_id: &str,
) -> Result<Option<XWingPublicKey>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if let Some(seat) = super::genesis::genesis_in_force(dir)
        .await?
        .seat(occurrence_key_id)
    {
        return Ok(XWingPublicKey::from_bytes(&seat.onion_hop_xwing_pubkey));
    }
    let Some(BindXWing {
        transit,
        onion_hop: Some(key),
    }) = bind_xwing_keys_for(dir, occurrence_key_id).await?
    else {
        return Ok(None);
    };
    let others =
        crate::federation::self_at_login::other_keys_of(dir, occurrence_key_id, &[]).await?;
    let mut with_transit: Vec<&[u8]> = others.all().collect();
    if let Some(t) = &transit {
        with_transit.push(t.ml_kem_768());
        with_transit.push(t.x25519());
    }
    if check_xwing_halves(XWingKeyRole::OnionHop, &key, with_transit).is_err() {
        return Ok(None);
    }
    Ok(Some(key))
}

// ─────────────────────────────────────────────────────────────────────────
//  An occurrence's own agreement, in edition 2 (E7's finding)
// ─────────────────────────────────────────────────────────────────────────

/// Is `key` a person's key (`user` / `accord_holder` in its record's
/// identity-type set)?
///
/// # Errors
/// Directory read failures.
pub async fn is_person_key<F>(dir: &F, key: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(is_person(&key_types(dir, key).await?))
}

/// Is `key` a machine's key (`node` / `agent` in its record's identity-type
/// set)?
///
/// # Errors
/// Directory read failures.
pub async fn is_machine_key<F>(dir: &F, key: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(is_machine(&key_types(dir, key).await?))
}

/// **The instant `occurrence` itself first agreed to be an occurrence of
/// `identity`, in edition 2**: the earliest `asserted_at` of a held
/// statement over an `identity:occurrence` row about `occurrence` (CWT
/// `sub`) that the occurrence key gave itself (`iss` = `sub`, its own key,
/// the bind's required second voice) and whose payload names `identity`.
/// The earlier form's agreement (an assertion the occurrence signed as
/// attester) is the caller's, behind the earlier-form switch.
///
/// # Errors
/// Directory read failures.
pub async fn own_voice_agreed_from<F>(
    dir: &F,
    identity: &str,
    occurrence: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(occ_kid) = kid_of_identity_ref(occurrence) else {
        return Ok(None);
    };
    let mut first: Option<u64> = None;
    for st in dir
        .edition2_statements_about(OCCURRENCE_FAMILY, occurrence)
        .await?
    {
        if !is_own_voice(&st, occurrence, &occ_kid) {
            continue;
        }
        let Some((_, p)) = statement_parts(&st) else {
            continue;
        };
        if p.get_text("identity_key_id").and_then(Value::as_text) != Some(identity) {
            continue;
        }
        if let Some(a) = p.get_text("asserted_at").and_then(Value::as_u64) {
            first = Some(first.map_or(a, |f| f.min(a)));
        }
    }
    Ok(first
        .and_then(|a| i64::try_from(a).ok())
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis))
}

// ─────────────────────────────────────────────────────────────────────────
//  The self-roster door's edition-2 proposals (S1; CC 3.3.6.4)
// ─────────────────────────────────────────────────────────────────────────

/// The family id (header -70002) of an occurrence revocation (T2's
/// family; P1's payload): an eviction (CC 3.3.6.4).
pub const OCCURRENCE_REVOCATION_FAMILY: &str = "identity:occurrence_revocation";

/// v62.0.0 (wave O1, S1b) — a statement's id (CC 2.6.1.8: SHA-256 over
/// `["CEG-statement-id/2", protected, payload]`, the bytes as signed).
fn statement_id_of(statement: &[u8]) -> Option<Digest32> {
    let Value::Tag(18, inner) = ciris_verify_core::cde::decode(statement).ok()? else {
        return None;
    };
    let parts = inner.as_array()?;
    Some(ciris_verify_core::edition2::statement_id(
        parts.first()?.as_bytes()?,
        parts.get(2)?.as_bytes()?,
    ))
}

/// The held voice of `voices` signed as `iss` with the LOWEST statement id:
/// the proposal's proposer and its landing statement, the same on every node
/// whatever order the voices arrived in.
fn lowest_voice_as<'a>(voices: &'a [Vec<u8>], iss: &str) -> Option<&'a Vec<u8>> {
    voices
        .iter()
        .filter(|v| statement_iss(v).as_deref() == Some(iss))
        .filter_map(|v| statement_id_of(v).map(|id| (id, v)))
        .min_by_key(|(id, _)| *id)
        .map(|(_, v)| v)
}

/// v62.0.0 (O1 fix 3; T2's I3187) — **the proposer among the roster's
/// voices**: the key of the held voice of `row_id` signed as `iss` by a key
/// ON `roster` (the roster at the heads the row names) with the lowest
/// statement id. A voice by a key off that roster is kept and concludes
/// nothing: it is never the proposer (statement ids are random, so the
/// unfiltered lowest could be a stray voice that refuses the proposal for
/// good). Among the eligible voices a key in `avoid` (one with an open
/// proposal of its own ahead) is chosen only when no other is. `None` when no
/// voice is by a roster key.
///
/// # Errors
/// Directory read failures.
pub async fn proposer_on_roster<F>(
    dir: &F,
    row_id: &RowId,
    iss: &str,
    roster: &BTreeSet<String>,
    exclude: Option<&str>,
    avoid: &BTreeSet<String>,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(dir
        .edition2_voices(row_id)
        .await?
        .iter()
        .filter(|v| statement_iss(v).as_deref() == Some(iss))
        .filter_map(|v| {
            let key = identity_ref(&statement_kid(v)?);
            // O1 fix 8: an eviction's target never proposes it.
            if !roster.contains(&key) || exclude == Some(key.as_str()) {
                return None;
            }
            statement_id_of(v).map(|id| (id, key))
        })
        // O1 fix 12 (E3's I1134): prefer a key with no open proposal of its
        // own ahead (`avoid`), so `one_open_per_proposer` never blocks a row
        // a free roster voice can propose; then the lowest statement id.
        .min_by_key(|(id, k)| (avoid.contains(k), *id))
        .map(|(_, k)| k))
}

/// The key (identity-ref) of the held voice of `voices` signed as `iss`
/// with the lowest statement id, skipping `exclude`'s.
fn lowest_voice_key(voices: &[Vec<u8>], iss: &str, exclude: Option<&str>) -> Option<String> {
    voices
        .iter()
        .filter(|v| statement_iss(v).as_deref() == Some(iss))
        .filter_map(|v| {
            let key = identity_ref(&statement_kid(v)?);
            if exclude == Some(key.as_str()) {
                return None;
            }
            statement_id_of(v).map(|id| (id, key))
        })
        .min_by_key(|(id, _)| *id)
        .map(|(_, k)| k)
}

/// The held statements of the row `row_id`, with its family and payload:
/// `None` when none is held or it is neither an `identity:occurrence` nor
/// an `identity:occurrence_revocation` row.
async fn held_bind<F>(
    dir: &F,
    row_id: &RowId,
) -> Result<Option<(Vec<Vec<u8>>, String, Value)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let voices = dir.edition2_voices(row_id).await?;
    let Some((protected, payload)) = voices.first().and_then(|v| statement_parts(v)) else {
        return Ok(None);
    };
    let Some(family) = protected
        .get_int(-70002)
        .and_then(Value::as_text)
        .map(str::to_owned)
    else {
        return Ok(None);
    };
    if family != OCCURRENCE_FAMILY && family != OCCURRENCE_REVOCATION_FAMILY {
        return Ok(None);
    }
    Ok(Some((voices, family, payload)))
}

/// Who signs a held row's voices: its `author`, else (a counted row) the
/// self, `identity_key_id`.
fn voice_iss(payload: &Value) -> Option<String> {
    payload
        .get_text("author")
        .or_else(|| payload.get_text("identity_key_id"))
        .and_then(Value::as_text)
        .map(str::to_owned)
}

/// **The proposal a held edition-2 row is** (`self_roster::plan`, for a
/// receipt in `ceg_roster_proposals`): an `identity:occurrence` bind (an
/// addition) or an `identity:occurrence_revocation` (an eviction). From its
/// held statements: the self (`identity_key_id`), the key it adds or
/// evicts, its `asserted_at`, and the proposer: the key of the held voice
/// signed as the author (or, counted, as the self) with the LOWEST statement
/// id (S1b: every node names the same proposer). `None` when the row id is
/// not such a held row.
///
/// # Errors
/// Directory read failures.
pub async fn carried_of_bind<F>(
    dir: &F,
    row_id_hex: &str,
) -> Result<Option<crate::federation::self_roster::Carried>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::self_roster::Carried;
    let Some(row_id) = hex::decode(row_id_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .map(RowId)
    else {
        return Ok(None);
    };
    let Some((voices, family, payload)) = held_bind(dir, &row_id).await? else {
        return Ok(None);
    };
    let text = |m: &str| {
        payload
            .get_text(m)
            .and_then(Value::as_text)
            .map(str::to_owned)
    };
    let (Some(identity), Some(target), Some(iss)) = (
        text("identity_key_id"),
        text("occurrence_key_id"),
        voice_iss(&payload),
    ) else {
        return Ok(None);
    };
    // O1 fix 8 (E8's I3324/I3325) — an eviction's TARGET never proposes it
    // (two_path refuses `proposer_is_target`): among the voices, the lowest
    // statement id of a key other than the target; the target's own only
    // when it is the sole voice (the genesis key revoking its own pair).
    let exclude = (family == OCCURRENCE_REVOCATION_FAMILY).then_some(target.as_str());
    let Some(proposer) =
        lowest_voice_key(&voices, &iss, exclude).or_else(|| lowest_voice_key(&voices, &iss, None))
    else {
        return Ok(None);
    };
    let Some(asserted_at) = payload
        .get_text("asserted_at")
        .and_then(Value::as_u64)
        .and_then(|a| i64::try_from(a).ok())
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
    else {
        return Ok(None);
    };
    // CC 3.3.6.4 (the CC 2.7 ruling): the roster row it names, required;
    // and the other tips it merges (CC rc21), in the order named.
    let Ok(names) = names_of(&payload) else {
        return Ok(None);
    };
    let Some(head) = super::names::single(&names, "head") else {
        return Ok(None);
    };
    let further_heads: Vec<RowId> = names
        .iter()
        .filter(|n| n.role == "further_heads")
        .map(|n| n.row)
        .collect();
    Ok(Some(if family == OCCURRENCE_REVOCATION_FAMILY {
        Carried::Edition2Eviction {
            row_id,
            identity_key_id: identity,
            target_key_id: target,
            proposer,
            asserted_at,
            head,
            further_heads,
        }
    } else {
        Carried::Edition2Occurrence {
            row_id,
            identity_key_id: identity,
            target_key_id: target,
            proposer,
            asserted_at,
            head,
            further_heads,
        }
    }))
}

/// v62.0.0 (wave O1, S1b) — **has the proposer withdrawn this edition-2
/// proposal?** A held `withdraws` statement naming the proposal's row id by
/// `refs.target`, signed by the proposer's key.
///
/// # Errors
/// Directory read failures.
pub async fn proposal_withdrawn<F>(
    dir: &F,
    carried: &crate::federation::self_roster::Carried,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::self_roster::Carried;
    let (Carried::Edition2Occurrence { row_id, .. } | Carried::Edition2Eviction { row_id, .. }) =
        carried
    else {
        return Ok(false);
    };
    for c in dir.edition2_rows_naming(row_id, "target").await? {
        for v in dir.edition2_voices(&c).await? {
            let withdraws = statement_parts(&v).is_some_and(|(h, _)| {
                h.get_int(-70001).and_then(Value::as_text)
                    == Some(crate::federation::types::attestation_type::WITHDRAWS)
            });
            if withdraws
                && statement_kid(&v).map(|k| identity_ref(&k)).as_deref()
                    == Some(carried.proposer())
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The keys (identity-refs) of the held author statements over the bind
/// `row_id` signed as `identity`: each a roster key's assent (the two-path
/// fold counts only the live roster's).
///
/// # Errors
/// Directory read failures.
pub async fn author_voice_keys<F>(
    dir: &F,
    row_id: &RowId,
    identity: &str,
) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(dir
        .edition2_voices(row_id)
        .await?
        .iter()
        .filter(|v| statement_iss(v).as_deref() == Some(identity))
        .filter_map(|v| statement_kid(v))
        .map(|k| identity_ref(&k))
        .collect())
}

/// **Land a held bind** (the self-roster executor, when its proposal lands):
/// its author statement re-read through the door, its payload read, and the
/// bind written to the occurrence table
/// ([`FederationDirectory::put_identity_occurrence_edition2`]).
///
/// # Errors
/// No held author statement; the door's or the payload's refusal; storage
/// faults.
pub async fn land_held_bind<F>(dir: &F, row_id: &RowId) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let (admitted, statements) = landing_statement(dir, row_id, OCCURRENCE_FAMILY).await?;
    let occurrence = read_payload(&admitted)?;
    dir.put_identity_occurrence_edition2(OccurrenceBind {
        occurrence,
        author_key_id: identity_ref(&admitted.kid),
        row_id: *row_id,
        statements,
    })
    .await?;
    Ok(())
}

/// The held row's landing statement (the lowest-id voice signed as its
/// author, or counted, as the self) re-read through the door, and every
/// held voice, the landing one first.
async fn landing_statement<F>(
    dir: &F,
    row_id: &RowId,
    want_family: &str,
) -> Result<(AdmittedRow, Vec<Vec<u8>>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let unheld = || {
        Error::InvalidArgument(format!(
            "{want_family}: no row {} with a voice of its signer is held",
            row_id.hex()
        ))
    };
    let Some((voices, family, payload)) = held_bind(dir, row_id).await? else {
        return Err(unheld());
    };
    if family != want_family {
        return Err(unheld());
    }
    let iss = voice_iss(&payload).ok_or_else(unheld)?;
    let landing = lowest_voice_as(&voices, &iss).ok_or_else(unheld)?.clone();
    let keys = super::ingest::held_keys_for(dir, &landing).await?;
    // T2-fix1: Verify's cell for a user self's `identity:occurrence_revocation`
    // reads `identity` (counted), so the landing statement is admitted under
    // the family's context, as the door admits it.
    let ctx = super::typed::family_context(dir, &landing).await?;
    let admitted = super::door::admit_row(&landing, &keys, Some(&row_id.0), ctx)?;
    let mut statements = vec![landing.clone()];
    statements.extend(voices.into_iter().filter(|v| *v != landing));
    Ok((admitted, statements))
}

/// v62.0.0 (wave O1, S1b) — **land a held edition-2 eviction** (the
/// self-roster executor): the `identity:occurrence_revocation` read
/// (T2's `typed::occurrence_revocation_of`) and written as T2's door
/// writes it (`put_identity_occurrence_revocation_local`), unless the pair is
/// already revoked by it.
///
/// # Errors
/// No held voice; the door's or the reader's refusal; storage faults.
pub async fn land_held_eviction<F>(dir: &F, row_id: &RowId) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let (admitted, _) = landing_statement(dir, row_id, OCCURRENCE_REVOCATION_FAMILY).await?;
    let revocation = super::typed::occurrence_revocation_of(&admitted)?;
    let held = dir
        .list_identity_occurrence_revocations_for(&revocation.identity_key_id)
        .await?
        .iter()
        .any(|r| {
            r.occurrence_key_id == revocation.occurrence_key_id
                && r.effective_at == revocation.effective_at
        });
    if !held {
        dir.put_identity_occurrence_revocation_local(revocation)
            .await?;
    }
    Ok(())
}

/// v62.0.0 (wave O1, S1b) — **a proposer withdraws its own edition-2
/// proposal**: a `withdraws` statement of this family naming, by
/// `refs.target`, the row id of an OPEN edition-2 self-roster proposal (an
/// addition here; an eviction's withdrawal reaches T2's door) and signed by
/// the proposal's proposer key. The statement is held and this node's
/// receipt settled `withdrawn`; the change never lands. Anything else of
/// this kind is refused `occurrence_withdraws_not_proposer`.
async fn withdraw_proposal<F>(dir: &F, row: &AdmittedRow) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let refuse_it = |why: &str| {
        refuse(
            malformed_row::OCCURRENCE_WITHDRAWS_NOT_PROPOSER,
            format!(
                "{OCCURRENCE_FAMILY}: a {} by {}: {why}",
                row.row_type,
                identity_ref(&row.kid)
            ),
        )
    };
    if row.row_type != crate::federation::types::attestation_type::WITHDRAWS {
        return Err(refuse_it("only a withdraws of an open proposal is held"));
    }
    let Some(target) = super::names::single(&row.names, "target") else {
        return Err(refuse_it("it names no proposal by refs.target"));
    };
    let Some(carried) = carried_of_bind(dir, &target.hex()).await? else {
        return Err(refuse_it("the row it names is not a held proposal"));
    };
    let open = dir
        .list_open_edition2_roster_proposals(Some(carried.identity_key_id()))
        .await?
        .iter()
        .any(|r| r.proposal_id == target.hex());
    if !open {
        return Err(refuse_it("the proposal it names is not open on this node"));
    }
    if identity_ref(&row.kid) != carried.proposer() {
        return Err(refuse_it("only the proposal's proposer withdraws it"));
    }
    let new = dir.put_edition2_statement(row).await?;
    dir.settle_edition2_roster_proposal(
        &target.hex(),
        crate::federation::self_roster::WITHDRAWN_OUTCOME,
        crate::federation::self_roster::roster_clock(),
    )
    .await?;
    Ok(StatementOutcome::Row {
        row_id: row.row_id,
        new,
    })
}

/// v62.0.0 (wave O1; CC 3.3.6.4, the CC 2.7 ruling, CC rc21) — **the heads
/// a new roster row of `identity` names**, as this node holds them: the
/// TIPS of the self's landed roster rows (an `identity:occurrence` bind or
/// `identity:occurrence_revocation` of it, by this node's settled `lands_*`
/// receipts) that no other landed roster row names. The first is the
/// latest settled (`refs.head`), the rest the other tips
/// (`refs.further_heads`, a merge). With no landed roster row, the genesis
/// key's own `key:record` row (the lowest row id among the held records of
/// that key) and no further heads. `None` when neither is held. For
/// producers (Server) and the fixtures.
///
/// # Errors
/// Directory read failures.
pub async fn current_roster_heads<F>(
    dir: &F,
    identity: &str,
) -> Result<Option<(RowId, Vec<RowId>)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let settled = dir.list_settled_edition2_roster_proposals(identity).await?;
    let mut landed: Vec<(RowId, Vec<RowId>)> = Vec::new();
    for r in settled.iter().filter(|r| {
        r.outcome
            .as_deref()
            .is_some_and(|o| o == "lands_quorum" || o == "lands_lone")
    }) {
        if let Some(c) = carried_of_bind(dir, &r.proposal_id).await? {
            use crate::federation::self_roster::Carried;
            if let Carried::Edition2Occurrence {
                row_id,
                head,
                further_heads,
                ..
            }
            | Carried::Edition2Eviction {
                row_id,
                head,
                further_heads,
                ..
            } = c
            {
                let mut named = vec![head];
                named.extend(further_heads);
                landed.push((row_id, named));
            }
        }
    }
    let named: BTreeSet<RowId> = landed.iter().flat_map(|(_, n)| n.iter().copied()).collect();
    // Tips, latest settled first.
    let mut tips: Vec<RowId> = landed
        .iter()
        .rev()
        .map(|(r, _)| *r)
        .filter(|r| !named.contains(r))
        .collect();
    tips.dedup();
    if let Some((first, rest)) = tips.split_first() {
        let mut rest = rest.to_vec();
        rest.sort();
        return Ok(Some((*first, rest)));
    }
    let genesis = kid_of_identity_ref(identity);
    Ok(dir
        .edition2_statements_about(
            ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY,
            identity,
        )
        .await?
        .iter()
        .filter(|st| genesis.is_some() && super::liveness::recorded_kid(st) == genesis)
        .filter_map(|st| RowId::of_statement(st))
        .min()
        .map(|g| (g, Vec::new())))
}

/// The first of [`current_roster_heads`] (`refs.head`).
///
/// # Errors
/// Directory read failures.
pub async fn current_roster_head<F>(dir: &F, identity: &str) -> Result<Option<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(current_roster_heads(dir, identity).await?.map(|(h, _)| h))
}

//  v62.0.0 (v62 P8) — the producer: a signer's voice over a bind
// ─────────────────────────────────────────────────────────────────────────

/// v62.0.0 (v62 P8) — **what a producer binds** (CC 3.3.6): the payload
/// members of one `identity:occurrence` row, every key an identity-ref.
// v62.0.0 (CE-fix1) — `Default`: a construction site names the members it
// states and takes `..Default::default()` for the rest, so a member added
// later (as `cites` was) breaks no caller.
#[derive(Clone, Debug, Default)]
pub struct BindTerms {
    /// Who authors the bind: the identity itself, or an agent's owner.
    pub author: String,
    /// The identity the occurrence is bound under.
    pub identity_key_id: String,
    /// The occurrence key (the row's `sub`).
    pub occurrence_key_id: String,
    /// The device class (`phone` | `laptop` | `server` | `embedded` |
    /// `agent` | `service`).
    pub device_class: String,
    /// `asserted_at`, POSIX ms.
    pub asserted_at_ms: u64,
    /// `valid_until`, POSIX ms; `None` is indefinite.
    pub valid_until_ms: Option<u64>,
    /// The hardware attestation's bytes, if any.
    pub hardware_attestation: Option<Vec<u8>>,
    /// The content-KEM keys `(x25519, ml_kem_768)`, if any.
    pub encryption_pubkeys: Option<(Vec<u8>, Vec<u8>)>,
    /// The bind's transport members, if any (CC 3.3.6.2).
    pub transport: Option<BindTransport>,
    /// `refs.head`, REQUIRED by CC rc21: the identity's current self-roster
    /// head (the first bind names the genesis key's `key:record` row).
    /// Producers fill it with O1's [`current_roster_heads`].
    pub head: Option<RowId>,
    /// `refs.further_heads`, optional (a bind over a forked roster).
    pub further_heads: Vec<RowId>,
    /// v62.0.0 (CE-fix1; CC 2.6.1.11) — `refs.also.cites`, optional: the
    /// rows the bind cites. A genesis seat binding cites the seat's own
    /// `key:record` here (Verify's bundle reader: `binding_names_no_record`
    /// otherwise). Empty: no `also`.
    pub cites: Vec<RowId>,
}

/// v62.0.0 (v62 P8) — **a bind's transport members** (CC 3.3.6.2): the
/// Reticulum link keys, the app name and aspects (the
/// `transport_destination` map, whose `destination_hash` is DERIVED by
/// Verify's `compute_destination_hash`, CC 3.3.6.3), and the two X-Wing keys
/// at the payload's top level.
#[derive(Clone, Debug)]
pub struct BindTransport {
    /// The Reticulum link x25519 key (32 bytes).
    pub reticulum_x25519_pubkey: Vec<u8>,
    /// The Reticulum transport ed25519 key (32 bytes).
    pub reticulum_ed25519_pubkey: Vec<u8>,
    /// The Reticulum app name.
    pub app_name: String,
    /// The Reticulum aspects.
    pub aspects: Vec<String>,
    /// `transit_xwing_pubkey` (1216 bytes), if any.
    pub transit_xwing_pubkey: Option<Vec<u8>>,
    /// `onion_hop_xwing_pubkey` (1216 bytes), if any.
    pub onion_hop_xwing_pubkey: Option<Vec<u8>>,
}

/// v62.0.0 (v62 P8) — the payload of a bind (CC 2.6.1.3 deterministic map
/// order), the inverse of [`read_payload`].
///
/// # Errors
/// `edition2_payload_invalid` for transport keys whose destination hash
/// cannot be derived.
pub fn bind_payload(t: &BindTerms) -> Result<Value, Error> {
    let text = |s: &str| Value::Text(s.to_owned());
    let mut m: Vec<(Value, Value)> = vec![
        (text("asserted_at"), Value::Uint(t.asserted_at_ms)),
        (text("author"), text(t.author.as_str())),
        (text("identity_key_id"), text(t.identity_key_id.as_str())),
        (
            text("occurrence_key_id"),
            text(t.occurrence_key_id.as_str()),
        ),
        (text("device_class"), text(t.device_class.as_str())),
    ];
    if let Some(u) = t.valid_until_ms {
        m.push((text("valid_until"), Value::Uint(u)));
    }
    if let Some(h) = &t.hardware_attestation {
        m.push((text("hardware_attestation"), Value::Bytes(h.clone())));
    }
    if let Some((x, k)) = &t.encryption_pubkeys {
        let mut enc = vec![
            (text("x25519"), Value::Bytes(x.clone())),
            (text("ml_kem_768"), Value::Bytes(k.clone())),
        ];
        enc.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
        m.push((text("encryption_pubkeys"), Value::Map(enc)));
    }
    if let Some(tr) = &t.transport {
        let dest = ciris_verify_core::transport_binding::compute_destination_hash(
            &tr.app_name,
            &tr.aspects,
            &tr.reticulum_x25519_pubkey,
            &tr.reticulum_ed25519_pubkey,
        )
        .ok_or_else(|| {
            payload_invalid("`transport_destination`: the destination hash does not derive")
        })?;
        let mut td = vec![
            (
                text("reticulum_x25519_pubkey"),
                Value::Bytes(tr.reticulum_x25519_pubkey.clone()),
            ),
            (
                text("reticulum_ed25519_pubkey"),
                Value::Bytes(tr.reticulum_ed25519_pubkey.clone()),
            ),
            (text("app_name"), text(tr.app_name.as_str())),
            (
                text("aspects"),
                Value::Array(tr.aspects.iter().map(|a| text(a.as_str())).collect()),
            ),
            (text("destination_hash"), Value::Bytes(dest.to_vec())),
        ];
        td.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
        m.push((text("transport_destination"), Value::Map(td)));
        if let Some(x) = &tr.transit_xwing_pubkey {
            m.push((text(TRANSIT_XWING_PUBKEY_MEMBER), Value::Bytes(x.clone())));
        }
        if let Some(x) = &tr.onion_hop_xwing_pubkey {
            m.push((text(ONION_HOP_XWING_PUBKEY_MEMBER), Value::Bytes(x.clone())));
        }
    }
    let mut refs: Vec<(Value, Value)> = Vec::new();
    if let Some(h) = &t.head {
        refs.push((text("head"), ciris_verify_core::edition2::row_ref(&h.0)));
        if !t.further_heads.is_empty() {
            let mut further: Vec<Value> = t
                .further_heads
                .iter()
                .map(|r| ciris_verify_core::edition2::row_ref(&r.0))
                .collect();
            further.sort_by_key(ciris_verify_core::cde::encode);
            further.dedup();
            refs.push((text("further_heads"), Value::Array(further)));
        }
    }
    // v62.0.0 (CE-fix1) — `refs.also.cites`, a row-ref set (sorted by
    // encoding, no duplicate).
    if !t.cites.is_empty() {
        let mut cites: Vec<Value> = t
            .cites
            .iter()
            .map(|r| ciris_verify_core::edition2::row_ref(&r.0))
            .collect();
        cites.sort_by_key(ciris_verify_core::cde::encode);
        cites.dedup();
        refs.push((
            text("also"),
            Value::Map(vec![(text("cites"), Value::Array(cites))]),
        ));
    }
    if !refs.is_empty() {
        refs.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
        m.push((text("refs"), Value::Map(refs)));
    }
    m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    Ok(Value::Map(m))
}

/// v62.0.0 (v62 P8) — **one voice of a bind, drafted for an external
/// signer** (`signer_iss`: the occurrence key, or the author): what a device,
/// an agent or an owner's pen signs (`Draft::sig_structure`), then submits
/// as `Draft::assemble(signature)` through the statement door.
///
/// # Errors
/// As [`bind_payload`]; `signer_iss` that is not an identity-ref.
pub fn bind_draft(t: &BindTerms, signer_iss: &str) -> Result<super::emit::Draft, Error> {
    let kid = kid_of_identity_ref(signer_iss)
        .ok_or_else(|| payload_invalid(format!("{signer_iss} is not an identity-ref")))?;
    super::emit::draft_row(
        &kid,
        signer_iss,
        &t.occurrence_key_id,
        "scores",
        OCCURRENCE_FAMILY,
        &bind_payload(t)?,
    )
    .map_err(|e| super::emit::produce_error("identity_occurrence", e))
}

/// v62.0.0 (v62 P8) — what [`publish_bind`] did.
#[derive(Clone, Debug, Default)]
pub struct OccurrenceBindOutcome {
    /// The bind's row id (hex); every voice shares it.
    pub row_id: String,
    /// The typed row is written (the door answered `Row`).
    pub landed: bool,
    /// The occurrence key's own statement, when it was stated here.
    pub own_voice: Option<Vec<u8>>,
    /// The author's statement, when it was stated here.
    pub author_voice: Option<Vec<u8>>,
    /// The occurrence key's voice, drafted: its signer was not in hand.
    pub own_draft: Option<super::emit::Draft>,
    /// The author's voice, drafted: its signer was not in hand, or the
    /// occurrence key's own voice (which the door takes first) was not.
    pub author_draft: Option<super::emit::Draft>,
}

impl OccurrenceBindOutcome {
    /// The outcome as JSON for a host surface: `row_id`, `landed`, each voice
    /// stated here as lowercase hex (`null` when not), each draft as
    /// `Draft::to_json` (`null` when none).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "row_id": self.row_id,
            "landed": self.landed,
            "own_voice_hex": self.own_voice.as_ref().map(hex::encode),
            "author_voice_hex": self.author_voice.as_ref().map(hex::encode),
            "own_draft": self.own_draft.as_ref().map(super::emit::Draft::to_json),
            "author_draft": self.author_draft.as_ref().map(super::emit::Draft::to_json),
        })
    }
}

/// v62.0.0 (v62 P8; CC 3.3.6, CC 3.3.6.2) — **publish a bind**: the
/// occurrence key's own voice first (the proof of possession), then the
/// author's, each through [`state_bind_voice`] (`sign_row` →
/// `put_statement`) when its signer is in hand and DRAFTED
/// ([`bind_draft`]) when it is not. The self pair (author = identity =
/// occurrence) is one statement. Without the occurrence key's voice here,
/// the author's is drafted, never offered (the door takes the author's only
/// after the own voice over the SAME payload is held).
///
/// # Errors
/// A signer that is not the key it is offered as (`InvalidArgument`); the
/// door's refusals.
pub async fn publish_bind<F>(
    dir: &F,
    occurrence_signer: Option<&crate::signing::LocalSigner>,
    author_signer: Option<&crate::signing::LocalSigner>,
    terms: &BindTerms,
) -> Result<OccurrenceBindOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let check = |signer_iss: &str, as_key: &str, role: &str| {
        if signer_iss == as_key {
            Ok(())
        } else {
            Err(Error::InvalidArgument(format!(
                "{OCCURRENCE_FAMILY}: the {role} signer is {signer_iss}, not {as_key}"
            )))
        }
    };
    let self_pair =
        terms.author == terms.identity_key_id && terms.identity_key_id == terms.occurrence_key_id;
    let mut out = OccurrenceBindOutcome::default();
    let row_id_of = |st: &[u8]| RowId::of_statement(st).map(|r| r.hex()).unwrap_or_default();
    match occurrence_signer {
        Some(s) => {
            check(
                &s.federation_id().await,
                &terms.occurrence_key_id,
                "occurrence",
            )?;
            let stated = state_bind_voice(dir, s, terms).await?;
            out.row_id = row_id_of(&stated.statement);
            out.landed = matches!(stated.outcome, StatementOutcome::Row { .. });
            out.own_voice = Some(stated.statement);
        }
        None => {
            let d = bind_draft(terms, &terms.occurrence_key_id)?;
            out.row_id = row_id_of(&d.assemble(Vec::new()));
            out.own_draft = Some(d);
        }
    }
    if self_pair {
        return Ok(out);
    }
    match (author_signer, out.own_voice.is_some()) {
        (Some(a), true) => {
            check(
                a.federation_id().await.as_str(),
                terms.author.as_str(),
                "author",
            )?;
            let stated = state_bind_voice(dir, a, terms).await?;
            out.landed = matches!(stated.outcome, StatementOutcome::Row { .. });
            out.author_voice = Some(stated.statement);
        }
        _ => out.author_draft = Some(bind_draft(terms, &terms.author)?),
    }
    Ok(out)
}

/// The family id of an owner binding (`ownership:{relation}:{target_kind}:{version}`).
fn ownership_family() -> String {
    ciris_verify_core::namespace_match::family_id("ownership:{relation}:{target_kind}:{version}")
}

/// v62.0.0 (v62 P8; CC 3.3.6) — **an agent's owner binding**:
/// `delegates_to(owner → agent)` at `ownership:responsible_party:agent:v1`,
/// the owner's voice and the agent's own over one payload (author = the
/// owner), each signed through `sign_row` and offered through the statement
/// door. `admission::agent_owner_of` reads it; an agent identity's
/// occurrences are then owner-authored. O1's `put_agent_owner_binding`
/// shape, produced.
///
/// # Errors
/// `composite_signing_unavailable`; the door's refusals.
pub async fn state_agent_owner_binding<F>(
    dir: &F,
    owner: &crate::signing::LocalSigner,
    agent: &crate::signing::LocalSigner,
    asserted_at_ms: u64,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let producer = "agent_owner_binding";
    let unavailable = |e: crate::signing::LocalSignerError| {
        super::emit::composite_signing_unavailable(producer, &e.to_string())
    };
    let (_, owner_iss) = super::produce::signer_identity(owner)
        .await
        .map_err(unavailable)?;
    let (_, agent_iss) = super::produce::signer_identity(agent)
        .await
        .map_err(unavailable)?;
    let payload = agent_owner_binding_payload(&owner_iss, asserted_at_ms);
    let family = ownership_family();
    for signer in [owner, agent] {
        let st = super::produce::sign_row(signer, &agent_iss, "delegates_to", &family, &payload)
            .await
            .map_err(|e| super::emit::produce_error(producer, e))?;
        super::ingest::put_statement(dir, &st, None, super::ingest::INGEST_TIER).await?;
    }
    Ok(())
}

/// The payload of an agent's owner binding authored by `owner_iss` at
/// `asserted_at_ms` (one spelling for both producers).
fn agent_owner_binding_payload(owner_iss: &str, asserted_at_ms: u64) -> Value {
    let mut m = vec![
        (
            Value::Text("asserted_at".into()),
            Value::Uint(asserted_at_ms),
        ),
        (
            Value::Text("author".into()),
            Value::Text(owner_iss.to_owned()),
        ),
        (
            Value::Text("dimension".into()),
            Value::Text("ownership:responsible_party:agent:v1".into()),
        ),
    ];
    m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    Value::Map(m)
}

/// v62.0.0 (v62 P8-fix12; CC 3.3.6, CC 2.6.1.9) — **an agent's owner binding
/// when only the OWNER's pen is in hand** (the agent's key is hardware or
/// remote): the owner's statement, signed and put (the row is HELD for the
/// bound agent's voice, K2's `bound_node`), and the agent's voice DRAFTED over
/// the same payload (`second_signer_voice::voice_draft`) for the agent to sign
/// and submit. Until the agent voices it the agent has no owner, so a
/// delegation waiting for its `delegate_owner` waits too.
///
/// # Errors
/// `composite_signing_unavailable`; `agent_iss` not an identity-ref; the
/// door's refusals.
pub async fn state_agent_owner_binding_by_owner<F>(
    dir: &F,
    owner: &crate::signing::LocalSigner,
    agent_iss: &str,
    asserted_at_ms: u64,
) -> Result<super::emit::Draft, Error>
where
    F: FederationDirectory + ?Sized,
{
    let producer = "agent_owner_binding";
    let (_, owner_iss) = super::produce::signer_identity(owner)
        .await
        .map_err(|e| super::emit::composite_signing_unavailable(producer, &e.to_string()))?;
    let payload = agent_owner_binding_payload(&owner_iss, asserted_at_ms);
    let st = super::produce::sign_row(
        owner,
        agent_iss,
        "delegates_to",
        &ownership_family(),
        &payload,
    )
    .await
    .map_err(|e| super::emit::produce_error(producer, e))?;
    super::ingest::put_statement(dir, &st, None, super::ingest::INGEST_TIER).await?;
    super::second_signer_voice::voice_draft(&st, agent_iss)
}

/// v62.0.0 (v62 P8) — the author of a bind under `identity_key_id` at
/// `at_ms`: an agent's live owner ([`crate::federation::admission::agent_owner_of`]),
/// else the identity itself (CC 3.3.6).
///
/// # Errors
/// Directory reads; an ambiguous owner.
pub async fn bind_author<F>(dir: &F, identity_key_id: &str, at_ms: u64) -> Result<String, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(
        crate::federation::admission::agent_owner_of(dir, identity_key_id, at_ms)
            .await?
            .unwrap_or_else(|| identity_key_id.to_owned()),
    )
}

/// v62.0.0 (v62 P8) — what [`state_bind_voice`] stated and what the door did.
#[derive(Clone, Debug)]
pub struct StatedBindVoice {
    /// The statement, as signed.
    pub statement: Vec<u8>,
    /// The door's outcome: `Row` when the bind landed, `Voice` when the
    /// voice is held and the bind waits for its other voice.
    pub outcome: StatementOutcome,
}

/// v62.0.0 (v62 P8; replaces the earlier `LocalSelfSigner` producer on the
/// occurrence plane) — **state `signer`'s voice over a bind**: the bind's
/// payload ([`bind_payload`]) signed by `signer`'s composite key
/// (`edition2::produce::sign_row`; row type `scores`, family
/// [`OCCURRENCE_FAMILY`], `sub` the occurrence key) and offered through the
/// one statement door (`ingest::put_statement`), which runs this module's
/// occurrence door ([`put_occurrence_voice`]). The signer is the occurrence
/// key (its own voice, the proof of possession) or the author; for the self
/// pair (author = identity = occurrence) its one statement is both, and the
/// bind lands. Nothing is signed over a JCS image.
///
/// # Errors
/// `InvalidArgument` for a signer that is neither the occurrence key nor
/// the author; `composite_signing_unavailable` for a signer without its
/// ML-DSA-65 half; every refusal of the door (an author's voice offered
/// before the occurrence key's own is the retryable unknown-signer one).
pub async fn state_bind_voice<F>(
    dir: &F,
    signer: &crate::signing::LocalSigner,
    terms: &BindTerms,
) -> Result<StatedBindVoice, Error>
where
    F: FederationDirectory + ?Sized,
{
    let producer = "identity_occurrence";
    let (_kid, iss) = super::produce::signer_identity(signer)
        .await
        .map_err(|e| super::emit::composite_signing_unavailable(producer, &e.to_string()))?;
    if iss != terms.occurrence_key_id && iss != terms.author {
        return Err(Error::InvalidArgument(format!(
            "{OCCURRENCE_FAMILY}: the signer {iss} is neither the occurrence key {} nor the \
             bind's author {}",
            terms.occurrence_key_id, terms.author
        )));
    }
    let statement = super::produce::sign_row(
        signer,
        &terms.occurrence_key_id,
        "scores",
        OCCURRENCE_FAMILY,
        &bind_payload(terms)?,
    )
    .await
    .map_err(|e| super::emit::produce_error(producer, e))?;
    let outcome =
        super::ingest::put_statement(dir, &statement, None, super::ingest::INGEST_TIER).await?;
    Ok(StatedBindVoice { statement, outcome })
}

/// v62.0.0 (v62 P8) — a stated bind as the `SignedIdentityOccurrence` the
/// earlier producer returned: the typed row, `attesting_key_id` the signer,
/// `signed_envelope` carrying the statement (`ceg_statement`, the way
/// [`OccurrenceBind::envelope`] does) and the
/// [`edition2_signature_placeholder`] as its `signature`.
#[must_use]
pub fn signed_occurrence_of(
    terms: &BindTerms,
    signer_iss: &str,
    stated: &StatedBindVoice,
) -> crate::federation::SignedIdentityOccurrence {
    let row_id = match &stated.outcome {
        StatementOutcome::Row { row_id, .. }
        | StatementOutcome::Voice { row_id, .. }
        | StatementOutcome::KeyPlane { row_id, .. }
        | StatementOutcome::Pending { row_id, .. } => row_id.hex(),
    };
    let hexed = hex::encode(&stated.statement);
    let at = |ms: u64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(ms).unwrap_or(0))
            .unwrap_or_default()
    };
    crate::federation::SignedIdentityOccurrence {
        identity_occurrence: IdentityOccurrence {
            identity_key_id: terms.identity_key_id.clone(),
            occurrence_key_id: terms.occurrence_key_id.clone(),
            device_class: terms.device_class.clone(),
            hardware_attestation: terms.hardware_attestation.as_ref().map(|h| B64.encode(h)),
            asserted_at: at(terms.asserted_at_ms),
            valid_until: terms.valid_until_ms.map(at),
            encryption_pubkeys: terms
                .encryption_pubkeys
                .as_ref()
                .map(|(x, k)| EncryptionPubkeys {
                    x25519_base64: B64.encode(x),
                    ml_kem_768_base64: B64.encode(k),
                }),
            transport_binding: None,
            persist_row_hash: String::new(),
        },
        attesting_key_id: signer_iss.to_owned(),
        signed_envelope: serde_json::json!({
            "edition2_row_id": row_id,
            "author_key_id": terms.author,
            "ceg_statements": [hexed.clone()],
            (super::ingest::STATEMENT_MEMBER): hexed,
        }),
        signature: edition2_signature_placeholder(),
    }
}
