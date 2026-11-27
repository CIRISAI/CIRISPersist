//! v62.0.0 (JSON-cut slice B) — **the producers' shared step**: what every
//! MESH producer of this node does between "I have a row to state" and
//! [`produce::sign_row`](super::produce::sign_row).
//!
//! A producer of the earlier form built a JSON envelope, canonicalised it
//! (JCS), signed it hybrid, and stored the row. A v62 producer states the
//! same members as an edition-2 payload (CC 2.6.1), signs the row with this
//! node's composite key, and admits it through the one statement door
//! ([`put_statement`](super::ingest::put_statement)), exactly as a peer
//! would. So:
//!
//! - [`payload_from_envelope`]: the JSON members as CBOR, in the form the
//!   mapping ([`attestation_of`](super::ingest::attestation_of)) reads back:
//!   instants ([`INSTANT_MEMBERS`]) as POSIX ms, fixed-scale members
//!   ([`SCALED_MEMBERS`]) ×10⁶, maps in the deterministic order. A real
//!   outside the fixed-scale members, or an instant that is not RFC 3339, is
//!   refused (`edition2_payload_invalid`), never rounded.
//! - [`family_for`]: the family a row is stated under (header -70002). A
//!   `scores` row's family is the one its `dimension` resolves to; a
//!   `delegates_to` row's is CC's confirmed family for its relation; a
//!   composer (`withdraws` / `recants` / `supersedes`) carries its TARGET
//!   row's family (`CC-READING(next-edition)`), read from the target's own
//!   statement ([`family_of_statement`]).
//! - [`key_record_payload`]: a node's own `key:record` (CC 2.4.1.1).
//! - [`COMPOSITE_SIGNING_UNAVAILABLE`]: the refusal of an engine that holds
//!   no composite signer. A classical-only engine produces nothing on the
//!   mesh.
//!
//! `act` is derived by the reader from the statements; no producer here
//! writes it as a payload member (CC rc20, "act is derived").

use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{cose_key, row_ref, Digest32};

use super::ingest::{INSTANT_MEMBERS, SCALED_MEMBERS, STATEMENT_MEMBER};
use super::liveness::statement_parts;
use super::payloads::{body_number, is_body_member, is_digest_member, ref_members};
use super::produce::ProduceError;
use crate::federation::Error;

/// The refusal token of a producer on an engine that holds no composite
/// (ML-DSA-65 ‖ Ed25519) signer: no local signer, or one without its PQC
/// half. Raised as `InvalidArgument` (Python `ValueError`) whose message
/// starts with the token.
pub const COMPOSITE_SIGNING_UNAVAILABLE: &str = "composite_signing_unavailable";

/// The family of a capability, moderator, steward or guardianship
/// delegation (CC confirmed).
pub const DELEGATES_TO_FAMILY: &str = "self:delegates_to";
/// The family of an agent-occurrence delegation (CC confirmed).
pub const AGENT_OCCURRENCE_FAMILY: &str = "self:delegates_to:agent_occurrence";
/// The family of a `key:record` row.
pub const KEY_RECORD_FAMILY: &str = ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY;

/// The protected-header label of the family (-70002).
const H_FAMILY: i64 = -70002;
/// The protected-header label of the row type (-70001).
const H_ROW_TYPE: i64 = -70001;

/// The [`COMPOSITE_SIGNING_UNAVAILABLE`] refusal, naming the producer.
#[must_use]
pub fn composite_signing_unavailable(producer: &str, why: &str) -> Error {
    Error::InvalidArgument(format!(
        "{COMPOSITE_SIGNING_UNAVAILABLE}: {producer} produces edition-2 statements, which are \
         composite-signed (ML-DSA-65 + Ed25519, CC 2.6.1.7); this engine holds no composite \
         signer ({why})"
    ))
}

/// A [`ProduceError`] as the federation error a producer returns.
#[must_use]
pub fn produce_error(producer: &str, e: ProduceError) -> Error {
    match e {
        ProduceError::Payload(why) => {
            Error::InvalidArgument(format!("edition2_payload_invalid: {producer}: {why}"))
        }
        ProduceError::Signer(s) => composite_signing_unavailable(producer, &s.to_string()),
        // v62.0.0 (E2-fix10) — the door's own payload refusal, as raised.
        ProduceError::Rejected(why) => {
            Error::InvalidArgument(format!("edition2_payload_invalid: {producer}: {why}"))
        }
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// A deterministic map: entries sorted by their keys' encodings (CC 2.6.1,
/// CDE).
#[must_use]
pub fn sorted_map(mut m: Vec<(Value, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

fn cbor_of(v: &serde_json::Value) -> Result<Value, ProduceError> {
    use serde_json::Value as J;
    Ok(match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::Uint(u)
            } else if let Some(i) = n.as_i64() {
                // A negative integer is CBOR major type 1: -1 - k.
                Value::Nint(i.unsigned_abs() - 1)
            } else {
                return Err(ProduceError::Payload(
                    "a real outside the fixed-scale members (CC 2.6.1.5 has no floats)",
                ));
            }
        }
        J::String(s) => Value::Text(s.clone()),
        J::Array(a) => Value::Array(a.iter().map(cbor_of).collect::<Result<_, _>>()?),
        J::Object(o) => sorted_map(
            o.iter()
                .map(|(k, x)| Ok((text(k), cbor_of(x)?)))
                .collect::<Result<_, ProduceError>>()?,
        ),
    })
}

/// v62.0.0 (wave P1e; lead's ruling) — a free-form body subtree as CBOR:
/// as [`cbor_of`], except that every JSON number is stated by
/// [`body_number`] instead of a float being refused. A number whose exact
/// decimal cannot be stated is refused (`body_number_unrepresentable`).
fn body_cbor_of(v: &serde_json::Value) -> Result<Value, ProduceError> {
    use serde_json::Value as J;
    Ok(match v {
        J::Number(n) => body_number(n).map_err(|_| {
            ProduceError::Payload(
                "body_number_unrepresentable: a body number whose exact decimal cannot be stated",
            )
        })?,
        J::Array(a) => Value::Array(a.iter().map(body_cbor_of).collect::<Result<_, _>>()?),
        J::Object(o) => sorted_map(
            o.iter()
                .map(|(k, x)| Ok((text(k), body_cbor_of(x)?)))
                .collect::<Result<_, ProduceError>>()?,
        ),
        other => cbor_of(other)?,
    })
}

fn ms_of(v: &serde_json::Value) -> Result<u64, ProduceError> {
    let s = v
        .as_str()
        .ok_or(ProduceError::Payload("an instant member is not text"))?;
    let t = chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|_| ProduceError::Payload("an instant member is not RFC 3339"))?;
    u64::try_from(t.timestamp_millis())
        .map_err(|_| ProduceError::Payload("an instant before the epoch"))
}

/// A fixed-scale real ×10⁶ as a CBOR integer (CC 2.6.1.5).
fn scaled(real: f64) -> Result<Value, ProduceError> {
    if !real.is_finite() {
        return Err(ProduceError::Payload("a fixed-scale member is not finite"));
    }
    #[allow(clippy::cast_possible_truncation)]
    let n = (real * 1_000_000.0).round() as i64;
    Ok(if n >= 0 {
        Value::Uint(n.unsigned_abs())
    } else {
        Value::Nint(n.unsigned_abs() - 1)
    })
}

/// A 64-hex digest as `[-16, bstr32]` (CC 2.6.1 hash-digest).
fn digest_of_hex(v: &serde_json::Value) -> Result<Value, ProduceError> {
    v.as_str()
        .filter(|h| h.len() == 64 && !h.bytes().any(|b| b.is_ascii_uppercase()))
        .and_then(|h| hex::decode(h).ok())
        .map(|b| Value::Array(vec![Value::Nint(15), Value::Bytes(b)]))
        .ok_or(ProduceError::Payload(
            "a hash digest is not 64 lowercase hex",
        ))
}

/// v62.0.0 (wave P1e) — the row id(s) an earlier member names: one 64-hex
/// text, or an array of them.
fn row_ids_of(v: &serde_json::Value) -> Result<Vec<Digest32>, ProduceError> {
    let one = |x: &serde_json::Value| {
        x.as_str()
            .filter(|h| h.len() == 64 && !h.bytes().any(|b| b.is_ascii_uppercase()))
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or(ProduceError::Payload(
                "a member naming a row is not a 64-lowercase-hex row id",
            ))
    };
    match v {
        serde_json::Value::Array(a) => a.iter().map(one).collect(),
        other => Ok(vec![one(other)?]),
    }
}

/// v62.0.0 (wave P1e) — `refs` from role → row ids: an `also:{role}` is a
/// set under `also`, any other role one row-ref (a set when it names more).
fn refs_of(
    roles: &std::collections::BTreeMap<&str, std::collections::BTreeSet<Digest32>>,
) -> Value {
    let set = |ids: &std::collections::BTreeSet<Digest32>| {
        let mut v: Vec<Value> = ids.iter().map(row_ref).collect();
        v.sort_by_key(cde::encode);
        Value::Array(v)
    };
    let mut top: Vec<(Value, Value)> = Vec::new();
    let mut also: Vec<(Value, Value)> = Vec::new();
    for (role, ids) in roles {
        if let Some(r) = role.strip_prefix("also:") {
            also.push((text(r), set(ids)));
        } else if ids.len() == 1 {
            let only = ids.iter().next().map(row_ref).unwrap_or(Value::Null);
            top.push((text(role), only));
        } else {
            top.push((text(role), set(ids)));
        }
    }
    if !also.is_empty() {
        top.push((text("also"), sorted_map(also)));
    }
    sorted_map(top)
}

/// A hash-digest member: one digest, or a sequence of them (`evidence_refs`,
/// CC 2.6.1.4: "payload `evidence_refs`, a sequence"), kept in the order the
/// envelope gives, so the mapping reads back the same hex array.
fn digest_member(v: &serde_json::Value) -> Result<Value, ProduceError> {
    match v {
        serde_json::Value::Array(a) => Ok(Value::Array(
            a.iter().map(digest_of_hex).collect::<Result<Vec<_>, _>>()?,
        )),
        other => digest_of_hex(other),
    }
}

/// v62.0.0 — the earlier envelope members a composer (`withdraws`,
/// `recants`, `supersedes`) drops when it is stated: the target's id (stated
/// as `refs.target`), the row type restated as `kind`, and the target's
/// type. A composer's payload is the common members and `refs.target` only
/// (`payloads::check_composer`, CC 2.4.1.1).
pub const COMPOSER_EARLIER_MEMBERS: &[&str] = &[
    "references_attestation_id",
    "kind",
    "references_attestation_type",
];

/// v62.0.0 (PIN-fix2 rev 2; CIRISVerify 23.4.1, the Constitution's ruling of
/// 2026-11-21) — **the composers that carry no `dimension`**: a
/// `withdraws` / `recants` scores nothing; its leaf and authorship are its
/// target's (Verify refuses one that states a dimension,
/// `Malformed { member: "dimension" }`). Read from Verify's own list
/// (`edition2::is_composer`), the one source. A `supersedes` is a
/// REPLACEMENT statement (CC 2.4.1): it keeps its own `dimension` and leaf.
#[must_use]
pub fn carries_no_dimension(row_type: &str) -> bool {
    ciris_verify_core::edition2::is_composer(row_type)
}

/// v62.0.0 (FS-step1) — **the row types that NAME a target** (`refs.target`):
/// the two retractions ([`carries_no_dimension`]) and a `supersedes` (CC
/// 2.4.1: a full replacement statement, judged by its own family, that names
/// the row it replaces). This is the predicate the target-held wait, the
/// composer's placement and the family-equals-target check ask. It is NOT
/// [`carries_no_dimension`]: the two differ by exactly `supersedes`, and
/// asking one where the other is meant drops or adds it silently. One
/// definition each, here; no site spells either set.
#[must_use]
pub fn names_a_target(row_type: &str) -> bool {
    carries_no_dimension(row_type)
        || row_type == crate::federation::types::attestation_type::SUPERSEDES
}

/// **The JSON members of a row as its edition-2 payload.**
///
/// v62.0.0 (wave P1e) — `family` is the family id the row is stated under
/// (header -70002): every member [`is_digest_member`] names for it (every
/// family's `HASH_DIGEST_MEMBERS`, and the family's own digest members:
/// `content_sha256`, `at_rest_sha256`, `chunk_root`, `unit`,
/// `build_manifest_hash`, ...) is stated as a hash digest from its 64-hex
/// text, the inverse of the mapping's projection.
///
/// `envelope` is the row's JSON envelope. Its `row` mirror and any carried
/// statement ([`STATEMENT_MEMBER`]) are dropped: the statement binds the
/// row itself (CC 2.6.1.1). `asserted_at_ms` is written when the envelope
/// states none; `author` when the envelope names none and the family is
/// authored (`Some`). The members named in `drop` are left out (a producer
/// that restates them as `refs`).
///
/// # Errors
/// [`ProduceError::Payload`]: not an object; a real outside the fixed-scale
/// members; an instant that is not RFC 3339.
pub fn payload_from_envelope(
    envelope: &serde_json::Value,
    family: &str,
    asserted_at_ms: u64,
    author: Option<&str>,
    drop: &[&str],
) -> Result<Value, ProduceError> {
    let o = envelope
        .as_object()
        .ok_or(ProduceError::Payload("the envelope is not an object"))?;
    let mut m: Vec<(Value, Value)> = Vec::with_capacity(o.len() + 2);
    // v62.0.0 (wave P1e; CC rc21) — the earlier members that name a row are
    // stated under their `refs` role (`payloads::REF_MEMBERS`): an
    // amendment's `authorized_by` / `evidence_refs` under `also.cites`, a
    // response's `references_attestation_id` under `answers`. Read before
    // the `drop` list, which names `references_attestation_id` for every
    // producer.
    let ref_entries = ref_members(family);
    let mut roles: std::collections::BTreeMap<&'static str, std::collections::BTreeSet<Digest32>> =
        std::collections::BTreeMap::new();
    for (k, v) in o {
        if let Some(entry) = ref_entries.iter().find(|e| e.1 == k.as_str()) {
            let role: &'static str = entry.0;
            for id in row_ids_of(v)? {
                roles.entry(role).or_default().insert(id);
            }
            continue;
        }
        if k == STATEMENT_MEMBER || k == "row" || drop.contains(&k.as_str()) || v.is_null() {
            continue;
        }
        // v62.0.0 (KR-fix7; CC 3.4.7) — a seat re-bind
        // (`transport:canonical_rebind`) has no leaf: the `dimension` a host
        // names it by picks the family and is not a payload member, and its
        // key members are byte strings, stated from their hex text. So a
        // holder whose key is on hardware can draft the FIRST voice
        // (`Engine::statement_draft`) with the exact payload the door counts.
        if family == super::transport_rebind::REBIND_FAMILY {
            if k == "dimension" {
                continue;
            }
            if super::payloads::is_bstr_member(family, k) {
                let bytes =
                    v.as_str()
                        .and_then(|h| hex::decode(h).ok())
                        .ok_or(ProduceError::Payload(
                            "a re-bind's key member is not hex text",
                        ))?;
                m.push((text(k), Value::Bytes(bytes)));
                continue;
            }
        }
        let c = if INSTANT_MEMBERS.contains(&k.as_str()) {
            Value::Uint(ms_of(v)?)
        } else if is_digest_member(family, k) {
            digest_member(v)?
        } else if is_body_member(family, k) {
            // v62.0.0 (wave P1e; lead's ruling) — a free-form body: every
            // JSON number states by `payloads::body_number` (an integral one
            // a plain integer, a non-integral one a tag-4 decimal, exact).
            body_cbor_of(v)?
        } else if SCALED_MEMBERS.contains(&k.as_str()) {
            scaled(v.as_f64().ok_or(ProduceError::Payload(
                "a fixed-scale member is not a number",
            ))?)?
        } else {
            cbor_of(v)?
        };
        m.push((text(k), c));
    }
    if !roles.is_empty() {
        if m.iter().any(|(k, _)| k.as_text() == Some("refs")) {
            return Err(ProduceError::Payload(
                "the envelope states refs and a member that names a row",
            ));
        }
        m.push((text("refs"), refs_of(&roles)));
    }
    if !o.contains_key("asserted_at") {
        m.push((text("asserted_at"), Value::Uint(asserted_at_ms)));
    }
    if let Some(a) = author {
        if !o.contains_key("author") {
            m.push((text("author"), text(a)));
        }
    }
    // v62.0.0 (T2-fix2) — a typed plane's earlier member names are stated
    // as P1's payload list keys them (`typed::project_envelope`'s inverse):
    // a custody report's `family_id`, a takedown notice's `claimant` /
    // `content_holders`.
    super::typed::unproject_payload(family, &mut m);
    Ok(sorted_map(m))
}

/// Add (or replace) one member of a payload map, keeping the order.
///
/// # Errors
/// [`ProduceError::Payload`] for a payload that is not a map.
pub fn with_member(payload: Value, key: &str, value: Value) -> Result<Value, ProduceError> {
    let Value::Map(mut m) = payload else {
        return Err(ProduceError::Payload("the payload is not a map"));
    };
    m.retain(|(k, _)| k.as_text() != Some(key));
    m.push((text(key), value));
    Ok(sorted_map(m))
}

/// `refs` naming one target row (`{target: row-ref}`), the composers' and a
/// re-statement's name for the row they act on (CC 2.6.1.4).
#[must_use]
pub fn refs_target(target: &Digest32) -> Value {
    sorted_map(vec![(text("target"), row_ref(target))])
}

/// The family (header -70002) and row type (-70001) a statement states.
#[must_use]
pub fn family_of_statement(statement: &[u8]) -> Option<(String, String)> {
    let (protected, _) = statement_parts(statement)?;
    let family = protected.get_int(H_FAMILY)?.as_text()?.to_owned();
    let row_type = protected.get_int(H_ROW_TYPE)?.as_text()?.to_owned();
    Some((family, row_type))
}

/// The statement a held row carries (its [`STATEMENT_MEMBER`]), if it is an
/// edition-2 row.
#[must_use]
pub fn carried_statement(row: &crate::federation::types::Attestation) -> Option<Vec<u8>> {
    row.attestation_envelope
        .get(STATEMENT_MEMBER)?
        .as_str()
        .and_then(|h| hex::decode(h).ok())
}

/// The family a `dimension` resolves to (CC 3.1.7, the one matcher), as its
/// family id.
#[must_use]
pub fn family_of_dimension(dimension: &str) -> Option<String> {
    match ciris_verify_core::namespace_match::resolve(dimension) {
        Ok(ciris_verify_core::namespace_match::Resolved::Family { family_id, .. }) => {
            Some(family_id)
        }
        _ => None,
    }
}

/// **The family a produced row is stated under.**
///
/// - an explicit `family` wins (the producer knows it);
/// - a `dimension` resolves to its family (CC 3.1.7);
/// - a `delegates_to` row with no dimension is a `self:delegates_to`
///   (capability, moderator, steward, guardianship; CC confirmed), or
///   `self:delegates_to:agent_occurrence` for an agent occurrence;
/// - a composer's family is its target's ([`family_of_statement`] over the
///   target's carried statement), `CC-READING(next-edition)`.
///
/// # Errors
/// `edition2_payload_invalid` when no family can be named: a `scores` row
/// whose dimension resolves to none, or a composer whose target carries no
/// edition-2 statement.
pub fn family_for(
    row_type: &str,
    explicit: Option<&str>,
    envelope: &serde_json::Value,
    target_statement: Option<&[u8]>,
) -> Result<String, Error> {
    use crate::federation::types::attestation_type as t;
    if let Some(f) = explicit {
        return Ok(f.to_owned());
    }
    // v62.0.0 (PIN-fix2 rev 2; CIRISVerify 23.4.1) — a `withdraws` /
    // `recants` takes its family from its target and nothing else: a
    // dimension the host envelope still names is not read for it (the payload
    // drops it, [`carries_no_dimension`]). A `supersedes` keeps its own
    // dimension and resolves below like any row.
    if carries_no_dimension(row_type) {
        return target_statement
            .and_then(family_of_statement)
            .map(|(f, _)| f)
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "edition2_payload_invalid: a {row_type} carries its target's family \
                     (CC-READING(next-edition)), and its target is not an edition-2 row this \
                     node holds"
                ))
            });
    }
    if let Some(d) = envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
    {
        if let Some(f) = family_of_dimension(d) {
            return Ok(f);
        }
        if row_type != t::DELEGATES_TO {
            return Err(Error::InvalidArgument(format!(
                "edition2_payload_invalid: the dimension {d:?} resolves to no registered family \
                 (CC 3.1.7); an edition-2 row names its family in header -70002"
            )));
        }
    }
    match row_type {
        t::DELEGATES_TO => Ok(if envelope.get("agent_occurrence_key_id").is_some()
            || envelope.get("agent_occurrence_id").is_some()
        {
            AGENT_OCCURRENCE_FAMILY
        } else {
            DELEGATES_TO_FAMILY
        }
        .to_owned()),
        _ if names_a_target(row_type) => target_statement
            .and_then(family_of_statement)
            .map(|(f, _)| f)
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "edition2_payload_invalid: a {row_type} carries its target's family \
                     (CC-READING(next-edition)), and its target is not an edition-2 row this \
                     node holds"
                ))
            }),
        _ => Err(Error::InvalidArgument(format!(
            "edition2_payload_invalid: a {row_type} row with no dimension names no family"
        ))),
    }
}

/// **Is a row of `family` authored** (its payload carries `author`) or
/// counted? CC's vendored model, read with the row's leaf (its `dimension`
/// bound under the family) where its cell needs one; authored when the model
/// does not decide (the door then judges the row).
#[must_use]
pub fn family_is_authored(family: &str, dimension: Option<&str>) -> bool {
    use ciris_verify_core::edition2::family::{
        FamilyModel as _, RuleAnswer, SelectContext, VendoredFamilyModel,
    };
    let leaf = dimension.and_then(|d| {
        let prefix = ciris_verify_core::namespace_match::prefix_of_family_id(family)?;
        ciris_verify_core::namespace_match::bind_leaf(prefix, d)
            .ok()
            .map(|b| b.leaf)
    });
    !matches!(
        VendoredFamilyModel.rule_for(family, leaf.as_deref(), &SelectContext::default()),
        RuleAnswer::Rule(r) if !r.authored
    )
}

/// **A node's own `key:record` payload** (CC 2.4.1.1): its composite key as
/// one AKP `COSE_Key`, its identity set (sorted), `asserted_at`, the
/// `author` (itself), an optional end, and optional attestation evidence.
///
/// `evidence` is the earlier `attestation_evidence` object: its text
/// members as text, its `chain` (hex DER, leaf first) as byte strings.
///
/// # Errors
/// [`ProduceError::Payload`]: an empty identity set; evidence that is not an
/// object, or a chain entry that is not hex.
pub fn key_record_payload(
    key: &CompositePublicKey,
    identity_type: &[&str],
    author: &str,
    asserted_at_ms: u64,
    valid_until_ms: Option<u64>,
    evidence: Option<&serde_json::Value>,
) -> Result<Value, ProduceError> {
    let mut roles: Vec<Value> = identity_type
        .iter()
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
        .map(text)
        .collect();
    if roles.is_empty() {
        return Err(ProduceError::Payload("an empty identity set"));
    }
    roles.sort_by_key(cde::encode);
    roles.dedup();
    let mut m = vec![
        (text("key"), cose_key(key)),
        (text("identity_type"), Value::Array(roles)),
        (text("asserted_at"), Value::Uint(asserted_at_ms)),
        (text("author"), text(author)),
    ];
    if let Some(u) = valid_until_ms {
        m.push((text("valid_until"), Value::Uint(u)));
    }
    if let Some(ev) = evidence {
        let o = ev.as_object().ok_or(ProduceError::Payload(
            "attestation_evidence is not an object",
        ))?;
        let mut e = Vec::new();
        for (k, v) in o {
            match (k.as_str(), v) {
                (_, serde_json::Value::Null) => {}
                ("chain", serde_json::Value::Array(a)) => {
                    let certs = a
                        .iter()
                        .map(|c| {
                            c.as_str()
                                .and_then(|h| hex::decode(h).ok())
                                .map(Value::Bytes)
                                .ok_or(ProduceError::Payload(
                                    "an attestation_evidence chain entry is not hex DER",
                                ))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    e.push((text("chain"), Value::Array(certs)));
                }
                (_, other) => e.push((text(k), cbor_of(other)?)),
            }
        }
        m.push((text("attestation_evidence"), sorted_map(e)));
    }
    Ok(sorted_map(m))
}

/// v62.0.0 (CE-fix1) — **the end a self-signed `key:record` states** (CC
/// 2.4.1.1): the end asked for, else, for an identity set naming `node` or
/// `agent`, the longest a record may run
/// (`asserted_at + KEY_RECORD_MAX_SECS`); a `user` / `accord_holder` record
/// asked no end carries none. Pure: the instant is the caller's.
#[must_use]
pub fn key_record_end(
    identity_type: &[&str],
    asserted_at_ms: u64,
    valid_until_ms: Option<u64>,
) -> Option<u64> {
    use ciris_verify_core::edition2::keys::KEY_RECORD_MAX_SECS;
    let must_end = identity_type
        .iter()
        .any(|r| matches!(r.trim(), "node" | "agent"));
    match valid_until_ms {
        Some(u) => Some(u),
        None if must_end => Some(asserted_at_ms.saturating_add(KEY_RECORD_MAX_SECS * 1000)),
        None => None,
    }
}

/// v62.0.0 (CE-fix1) — **a key's own `key:record` payload**: authored by the
/// key's own identity-ref (`identity_ref(thumbprint(key))`), ending at
/// [`key_record_end`]. The one payload producer of
/// `Engine::register_self_federation_key` and of the offline ceremony
/// (`crate::ceremony`).
///
/// # Errors
/// As [`key_record_payload`].
pub fn self_key_record_payload(
    key: &CompositePublicKey,
    identity_type: &[&str],
    asserted_at_ms: u64,
    valid_until_ms: Option<u64>,
    evidence: Option<&serde_json::Value>,
) -> Result<Value, ProduceError> {
    let iref =
        ciris_verify_core::edition2::identity_ref(&ciris_verify_core::edition2::thumbprint(key));
    key_record_payload(
        key,
        identity_type,
        &iref,
        asserted_at_ms,
        key_record_end(identity_type, asserted_at_ms, valid_until_ms),
        evidence,
    )
}

/// v62.0.0 (CE-fix1) — **a key's own `key:record`, drafted** for the key
/// itself to sign (a node's local signer, or an offline / hardware signer):
/// row type `scores`, family `key:record`, `kid` the key's thumbprint, `iss`
/// and `sub` its identity-ref, over `payload` (a
/// [`self_key_record_payload`]).
///
/// # Errors
/// As [`draft_row`].
pub fn key_record_statement_draft(
    key: &CompositePublicKey,
    payload: &Value,
) -> Result<Draft, ProduceError> {
    let kid = ciris_verify_core::edition2::thumbprint(key);
    let iref = ciris_verify_core::edition2::identity_ref(&kid);
    draft_row(
        &kid,
        &iref,
        &iref,
        crate::federation::types::attestation_type::SCORES,
        KEY_RECORD_FAMILY,
        payload,
    )
}

/// v62.0.0 (CE-fix1) — [`self_key_record_payload`] then
/// [`key_record_statement_draft`]: a key's own `key:record`, drafted.
///
/// # Errors
/// As those two.
pub fn key_record_draft(
    key: &CompositePublicKey,
    identity_type: &[&str],
    asserted_at_ms: u64,
    valid_until_ms: Option<u64>,
    evidence: Option<&serde_json::Value>,
) -> Result<Draft, ProduceError> {
    let payload =
        self_key_record_payload(key, identity_type, asserted_at_ms, valid_until_ms, evidence)?;
    key_record_statement_draft(key, &payload)
}

/// v62.0.0 (JSON-cut slice B) — **a row drafted for an external signer**:
/// what a producer hands a holder (a WA member, a founder, a roster member)
/// to sign with its own composite key, in place of the earlier JSON envelope
/// and its JCS bytes.
///
/// The signer signs [`Self::sig_structure`] (COSE `Sig_structure`,
/// `["Signature1", protected, b"", payload]`, CC 2.6.1) and the statement is
/// [`Self::assemble`] over its signature. The protected header names the
/// signer (`kid`, `iss`), so a draft is per signer; a further voice over the
/// same row is a draft of the same payload by another signer (CC 2.6.1.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    /// The protected header, CDE-encoded.
    pub protected: Vec<u8>,
    /// The payload, CDE-encoded (deterministic map order).
    pub payload: Vec<u8>,
    /// The bytes the signer signs.
    pub sig_structure: Vec<u8>,
}

impl Draft {
    /// The tag-18 `COSE_Sign1` statement over `signature` (the signer's
    /// composite signature of [`Self::sig_structure`]).
    #[must_use]
    pub fn assemble(&self, signature: Vec<u8>) -> Vec<u8> {
        super::produce::assemble(self.protected.clone(), self.payload.clone(), signature)
    }

    /// The draft as JSON for a host surface: `protected`, `payload` and
    /// `sig_structure` as lowercase hex.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "protected": hex::encode(&self.protected),
            "payload": hex::encode(&self.payload),
            "sig_structure": hex::encode(&self.sig_structure),
        })
    }
}

/// **Draft a row** for the signer whose kid is `kid` and identity-ref `iss`.
///
/// # Errors
/// [`ProduceError::Payload`] for a payload that is not a map or carries no
/// `asserted_at`.
pub fn draft_row(
    kid: &Digest32,
    iss: &str,
    sub: &str,
    row_type: &str,
    family: &str,
    payload: &Value,
) -> Result<Draft, ProduceError> {
    let protected = super::produce::row_protected(kid, iss, sub, row_type, family, payload)?;
    let payload = cde::encode(payload);
    let sig_structure = ciris_verify_core::edition2::sig_structure(&protected, &payload);
    Ok(Draft {
        protected,
        payload,
        sig_structure,
    })
}

/// **Draft a row from its JSON members** (the earlier envelope a builder
/// returned): [`payload_from_envelope`] with `author` = `iss` for an authored
/// family, the family by [`family_for`], `refs.target` for a composer naming
/// `target_row` (its row id) of `target_family`.
///
/// # Errors
/// As [`payload_from_envelope`] / [`family_for`] / [`draft_row`].
pub fn draft_from_envelope(
    kid: &Digest32,
    iss: &str,
    sub: &str,
    row_type: &str,
    envelope: &serde_json::Value,
    asserted_at_ms: u64,
    target: Option<(&Digest32, &str)>,
) -> Result<Draft, Error> {
    draft_from_envelope_as(
        kid,
        iss,
        sub,
        row_type,
        envelope,
        asserted_at_ms,
        target,
        None,
    )
}

/// v62.0.0 (SL-fix3c; CC 4.4.3.12) — **[`draft_from_envelope`] against the
/// directory**: a floor family's act (a quarantine marker, a slashing verdict,
/// a takedown notice) is drafted COUNTED (no `author`: the seat's voice, to
/// be countersigned) exactly when [`floor_counted`] finds the one-seat
/// affiliation it is taken in at the draft's own instant, and AUTHORED
/// otherwise. Every other family is [`draft_from_envelope`]'s.
///
/// # Errors
/// As [`draft_from_envelope`]; directory reads.
#[allow(clippy::too_many_arguments)]
pub async fn draft_from_envelope_in<F>(
    dir: &F,
    kid: &Digest32,
    iss: &str,
    sub: &str,
    row_type: &str,
    envelope: &serde_json::Value,
    asserted_at_ms: u64,
    target: Option<(&Digest32, &str)>,
) -> Result<Draft, Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let family = family_for(row_type, target.map(|(_, f)| f), envelope, None)?;
    // v62.0.0 (DUTY-D7a3) — this draft holds the directory: an uncited
    // machine acceptance of a held root grant is refused here (the pure
    // `draft_from_envelope` cannot tell and does not guess).
    crate::federation::membership_acceptance::check_acceptance_cited(
        dir,
        "statement_draft",
        envelope,
        envelope
            .get("cohort_scope")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(crate::federation::types::cohort_scope::FEDERATION),
    )
    .await?;
    // v62.0.0 (PIN-fix9c; the Constitution's ruling of 2026-11-21, CC 2.4.1)
    // — only a retraction skips the floor reading: a `supersedes` of a floor
    // act IS the act again, drafted counted exactly when the act would be.
    let counted = if carries_no_dimension(row_type) {
        None
    } else {
        floor_counted(dir, &family, envelope, iss, asserted_at_ms).await?
    };
    let (family, payload) = draft_payload_as(
        row_type,
        envelope,
        asserted_at_ms,
        iss,
        target,
        counted.map(|c| !c),
    )?;
    // v62.0.0 (HEAD-1; CC 2.4.1.1, "an act names its head") — the head the
    // drafted act is at, resolved against this directory before the first
    // voice signs (`head_rule::state_head`); a head the envelope names is
    // kept. The undirected [`draft_from_envelope`] resolves none.
    let payload = super::head_rule::state_head(dir, row_type, &family, iss, payload).await?;
    // v62.0.0 (HEAD-3) — a drafted `withdraws` names the head it acts from,
    // read from its target (`head_rule::state_end_head`); the root's counted
    // withdrawal already names its bundle and keeps it.
    let payload = match target {
        Some((t, _)) if row_type == crate::federation::types::attestation_type::WITHDRAWS => {
            super::head_rule::state_end_head(dir, &super::names::RowId(*t), None, payload).await?
        }
        _ => payload,
    };
    draft_row(kid, iss, sub, row_type, &family, &payload).map_err(|e| produce_error("draft", e))
}

/// v62.0.0 (HEAD-3; CC 2.4.1.1) — [`draft_from_envelope`] naming `head` in
/// `refs.head` (joined, never replacing one the envelope names): for a sync
/// drafter that already knows the head it acts from (an end whose record is
/// its target, `ownership_reclaim::draft_reclaim_withdraws`).
///
/// # Errors
/// As [`draft_from_envelope`].
#[allow(clippy::too_many_arguments)]
pub fn draft_from_envelope_naming_head(
    kid: &Digest32,
    iss: &str,
    sub: &str,
    row_type: &str,
    envelope: &serde_json::Value,
    asserted_at_ms: u64,
    target: Option<(&Digest32, &str)>,
    head: &super::names::RowId,
) -> Result<Draft, Error> {
    let (family, payload) =
        draft_payload_as(row_type, envelope, asserted_at_ms, iss, target, None)?;
    let payload = super::head_rule::with_head(payload, head)?;
    draft_row(kid, iss, sub, row_type, &family, &payload).map_err(|e| produce_error("draft", e))
}

/// v62.0.0 (SL-fix3c; CC 4.4.3.12) — **is a floor family's act COUNTED
/// here?** `Some(true)` when `affiliation_config::floor_affiliation` finds the
/// one-seat affiliation the act named by `envelope` (its `community_id`, or a
/// takedown's `content_sha256` and `claimant_key_id`) is taken in, by `iss`,
/// at `asserted_at_ms`; `Some(false)` for a floor family it does not;
/// `None` for any other family (its cell is the vendored one). The same
/// function the door's authorship context and the countersign gates ask.
///
/// # Errors
/// Directory reads.
pub async fn floor_counted<F>(
    dir: &F,
    family: &str,
    envelope: &serde_json::Value,
    iss: &str,
    asserted_at_ms: u64,
) -> Result<Option<bool>, Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    use crate::federation::affiliation_config::{floor_affiliation, FloorAct};
    if !super::typed::is_floor_family(family) {
        return Ok(None);
    }
    let text = |k: &str| {
        envelope
            .get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    };
    let at = i64::try_from(asserted_at_ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .unwrap_or_else(crate::host::clock::now);
    let (act, actor) =
        if family == ciris_verify_core::namespace_match::family_id(super::typed::TAKEDOWN_PREFIX) {
            let claimant = match text("claimant_key_id") {
                "" => iss,
                c => c,
            };
            (
                FloorAct::Takedown {
                    content_sha256: text("content_sha256"),
                },
                claimant,
            )
        } else {
            (
                FloorAct::Slash {
                    community_id: text(crate::federation::quarantine::field::COMMUNITY_ID),
                },
                iss,
            )
        };
    Ok(Some(
        floor_affiliation(dir, act, actor, at).await?.is_some(),
    ))
}

/// v62.0.0 (KR-fix6; CC 2.6.1.3 "a member that names a row stands in `refs`")
/// — **the row a membership REPLY answers**: for an envelope whose
/// `dimension` is `membership:acceptance:v1` or `membership:decline:v1`, its
/// `references_attestation_id` as a row id. KR-fix32: it is stated under
/// `refs.answers` (`payloads::REF_MEMBERS`), and the reply gates read it back
/// from there (`ingest::attestation_of`'s `REF_MEMBERS` projection). `None`
/// for any other row, or a reply that names none.
///
/// # Errors
/// `edition2_payload_invalid`: the member is not 64 hex.
pub fn reply_target_of(envelope: &serde_json::Value) -> Result<Option<Digest32>, Error> {
    use crate::federation::membership_acceptance::{ACCEPTANCE_DIMENSION, DECLINE_DIMENSION};
    let dimension = envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str);
    if dimension != Some(ACCEPTANCE_DIMENSION) && dimension != Some(DECLINE_DIMENSION) {
        return Ok(None);
    }
    let Some(id) = envelope
        .get("references_attestation_id")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    hex::decode(id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(Some)
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "edition2_payload_invalid: a membership reply names the row it answers by row \
                 id, and {id:?} is not an edition-2 row id (64 lowercase hex)"
            ))
        })
}

/// v62.0.0 (KR-fix6) — **THE payload of a produced row**, from its JSON
/// envelope. The ONE builder behind the software producer
/// (`attestation_emit::produce_row`: `emit_statement`, the Engine's emit
/// verbs) and the draft a signer elsewhere signs ([`draft_from_envelope`]:
/// `Engine::statement_draft`), so the two cannot state a row differently:
///
/// - the envelope's members ([`payload_from_envelope`]), without the earlier
///   bookkeeping a row type restates as `refs` (a composer's
///   [`COMPOSER_EARLIER_MEMBERS`]; `references_attestation_id` otherwise);
/// - `author` when the caller says the row is authored;
/// - an `admission:unit` row's `capabilities` as a sorted, unique set;
/// - `refs.target`: the composer's `target`, JOINING the roles the
///   envelope already states under `refs` (`payloads::REF_MEMBERS`), never
///   replacing them. A membership reply names the row it answers under
///   `refs.answers` (KR-fix32, a `REF_MEMBERS` entry), validated first by
///   [`reply_target_of`].
///
/// Before KR-fix6 each producer had its own copy: the draft sorted
/// `capabilities` and joined `refs` and the software producer did neither;
/// neither stated a reply's target, and KR-fix5 taught only one of them.
///
/// # Errors
/// [`payload_from_envelope`]'s, as `edition2_payload_invalid`;
/// [`reply_target_of`]'s.
pub fn row_payload(
    producer: &'static str,
    row_type: &str,
    family: &str,
    envelope: &serde_json::Value,
    asserted_at_ms: u64,
    author: Option<&str>,
    target: Option<&Digest32>,
) -> Result<Value, Error> {
    let composer = names_a_target(row_type);
    // v62.0.0 (PIN-fix2 rev 2) — a `withdraws` / `recants` states no
    // `dimension` ([`carries_no_dimension`]); a `supersedes` keeps its own.
    let retraction_drop: Vec<&str> = COMPOSER_EARLIER_MEMBERS
        .iter()
        .copied()
        .chain(std::iter::once("dimension"))
        .collect();
    let drop: &[&str] = if carries_no_dimension(row_type) {
        &retraction_drop
    } else if composer {
        COMPOSER_EARLIER_MEMBERS
    } else {
        &["references_attestation_id"]
    };
    // v62.0.0 (KR-fix32) — a composer's `references_attestation_id` is its
    // TARGET (stated as `refs.target` below), never the `answers` a reply of
    // its family states it as (`payloads::REF_MEMBERS`): it is not read
    // through that table.
    let composer_envelope;
    let envelope = if composer {
        let mut e = envelope.clone();
        if let Some(o) = e.as_object_mut() {
            o.remove(super::ingest::REFERENCES_MEMBER);
        }
        composer_envelope = e;
        &composer_envelope
    } else {
        envelope
    };
    let mut payload = payload_from_envelope(envelope, family, asserted_at_ms, author, drop)
        .map_err(|e| produce_error(producer, e))?;
    // v62.0.0 (AU-fix2; CC 2.7.11) — `capabilities` is a deterministic set
    // (sorted by encoding, unique): stated so whatever order the host gave.
    if family == super::payloads::ADMISSION_UNIT_FAMILY {
        if let Some(Value::Array(caps)) = payload.get_text("capabilities") {
            let mut caps = caps.clone();
            caps.sort_by_key(cde::encode);
            caps.dedup();
            payload = with_member(payload, "capabilities", Value::Array(caps))
                .map_err(|e| produce_error(producer, e))?;
        }
    }
    // v62.0.0 (KR-fix32; the Constitution's ruling (A)) — a membership reply
    // names the row it answers under `refs.answers` (`payloads::REF_MEMBERS`,
    // stated by `payload_from_envelope` above), no longer `refs.target`:
    // `target` is the composer's alone. [`reply_target_of`] still validates
    // the named row id before anything is stated.
    if !composer && target.is_none() {
        let _ = reply_target_of(envelope)?;
    }
    if let Some(t) = target {
        // v62.0.0 (E2-fix9) — the target joins the roles the envelope already
        // states under `refs` (`payloads::REF_MEMBERS`: a reclaim withdraws's
        // `wa_adjudication_ref`); it never replaces them.
        let refs = match payload.get_text("refs").and_then(Value::as_map) {
            Some(roles) => {
                let mut m: Vec<(Value, Value)> = roles
                    .iter()
                    .filter(|(k, _)| k.as_text() != Some("target"))
                    .cloned()
                    .collect();
                m.push((text("target"), row_ref(t)));
                sorted_map(m)
            }
            None => refs_target(t),
        };
        payload = with_member(payload, "refs", refs).map_err(|e| produce_error(producer, e))?;
    }
    Ok(payload)
}

/// [`draft_from_envelope`] with the authorship decided by the caller when
/// `authored` is given (the directory's answer, [`draft_from_envelope_in`]).
#[allow(clippy::too_many_arguments)]
fn draft_from_envelope_as(
    kid: &Digest32,
    iss: &str,
    sub: &str,
    row_type: &str,
    envelope: &serde_json::Value,
    asserted_at_ms: u64,
    target: Option<(&Digest32, &str)>,
    authored_override: Option<bool>,
) -> Result<Draft, Error> {
    let (family, payload) = draft_payload_as(
        row_type,
        envelope,
        asserted_at_ms,
        iss,
        target,
        authored_override,
    )?;
    draft_row(kid, iss, sub, row_type, &family, &payload).map_err(|e| produce_error("draft", e))
}

/// v62.0.0 (HEAD-1) — the family and payload [`draft_from_envelope_as`]
/// signs: the authorship decided, then [`row_payload`]. Split out so the
/// directed draft ([`draft_from_envelope_in`]) states the head between the
/// two.
fn draft_payload_as(
    row_type: &str,
    envelope: &serde_json::Value,
    asserted_at_ms: u64,
    iss: &str,
    target: Option<(&Digest32, &str)>,
    authored_override: Option<bool>,
) -> Result<(String, Value), Error> {
    let family = family_for(row_type, target.map(|(_, f)| f), envelope, None)?;
    // v62.0.0 (HEAD-4; Constitution's ruling of 2026-11-22, CC 2.6.1.9) —
    // COUNTED vs AUTHORED is decided by whether the payload carries
    // `author`, NEVER by whether it names `refs.head` (an act names the head
    // it is at, CC 2.4.1.1). A draft's payload carries what the envelope
    // says: the envelope's own `author` stands (`"author": null` states a
    // counted row, `payload_from_envelope` keeps the key and drops the
    // null); with no `author` member, the caller's override
    // ([`floor_counted`]), else the family's vendored cell. Before HEAD-4 an
    // `admission:unit` or trust-family draft naming `head` was drafted
    // counted by that alone (AU-fix2, KR-fix2).
    //
    // Such a draft that names `head` and no `author` member is REFUSED, not
    // re-read: its authorship was signalled by the head, which the ruling
    // forbids, and silently drafting it authored would turn a host's counted
    // root grant or counted unit into one signer's row.
    let counted_by_head_family =
        family == super::payloads::ADMISSION_UNIT_FAMILY || super::typed::is_trust_family(&family);
    if counted_by_head_family && envelope.get("head").is_some() && envelope.get("author").is_none()
    {
        return Err(Error::InvalidArgument(format!(
            "edition2_payload_invalid: a {family} draft names `head` and no `author`: counted vs \
             authored is the payload's `author` (CC 2.6.1.9), never its head. State \
             `\"author\": null` for a counted row, or the author for an authored one"
        )));
    }
    let authored = envelope.get("author").map_or_else(
        || {
            authored_override.unwrap_or_else(|| {
                family_is_authored(
                    &family,
                    envelope
                        .get("dimension")
                        .and_then(serde_json::Value::as_str),
                )
            })
        },
        |a| !a.is_null(),
    );
    let payload = row_payload(
        "draft",
        row_type,
        &family,
        envelope,
        asserted_at_ms,
        authored.then_some(iss),
        target.map(|(t, _)| t),
    )?;
    Ok((family, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i2200_payload_from_envelope_is_the_mappings_inverse() {
        let env = serde_json::json!({
            "dimension": "consent:state:granted",
            "asserted_at": "2026-11-18T10:00:00.123Z",
            "score": 0.75,
            "weight": -0.5,
            "nested": {"b": 1, "a": [true, null, "x"]},
            "gone": null,
            "row": {"attestation_id": "x"},
            "ceg_statement": "00",
            "references_attestation_id": "t",
        });
        let p = payload_from_envelope(
            &env,
            "consent:state:.state",
            7,
            Some("me"),
            &["references_attestation_id"],
        )
        .expect("I2200: a JSON envelope states as a payload");
        assert_eq!(
            p.get_text("asserted_at").and_then(Value::as_u64),
            Some(1_794_996_000_123),
            "I2200: an instant is POSIX ms"
        );
        assert_eq!(p.get_text("score"), Some(&Value::Uint(750_000)));
        assert_eq!(p.get_text("weight"), Some(&Value::Nint(499_999)));
        assert_eq!(p.get_text("author"), Some(&text("me")), "I2200: author");
        for gone in ["row", "ceg_statement", "gone", "references_attestation_id"] {
            assert!(p.get_text(gone).is_none(), "I2200: {gone} is not stated");
        }
        // The deterministic order: the encoded map is CDE.
        assert_eq!(cde::decode(&cde::encode(&p)).unwrap(), p);
        // A real outside the scaled members is refused, never rounded.
        let bad = serde_json::json!({"ratio": 0.5});
        assert!(matches!(
            payload_from_envelope(&bad, "consent:state:.state", 7, None, &[]),
            Err(ProduceError::Payload(_))
        ));
        // An envelope's own author / asserted_at stand.
        let own = serde_json::json!({"author": "them", "asserted_at": "2026-11-18T10:00:00.000Z"});
        let p = payload_from_envelope(&own, "consent:state:.state", 7, Some("me"), &[]).unwrap();
        assert_eq!(p.get_text("author"), Some(&text("them")));
        assert_eq!(
            p.get_text("asserted_at").and_then(Value::as_u64),
            Some(1_794_996_000_000)
        );
    }

    #[test]
    fn i2201_family_for_names_ccs_families() {
        let none = serde_json::json!({});
        assert_eq!(
            family_for("delegates_to", None, &none, None).unwrap(),
            "self:delegates_to",
            "I2201: capability / moderator / steward / guardianship"
        );
        assert_eq!(
            family_for(
                "delegates_to",
                None,
                &serde_json::json!({"agent_occurrence_key_id": "o"}),
                None
            )
            .unwrap(),
            "self:delegates_to:agent_occurrence"
        );
        assert_eq!(
            family_for(
                "delegates_to",
                None,
                &serde_json::json!({"dimension": "ownership:responsible_party:node:v1"}),
                None
            )
            .unwrap(),
            "ownership:.relation:.target_kind:.version",
            "I2201: the owner binding's family is its dimension's"
        );
        assert!(
            family_for("scores", None, &none, None).is_err(),
            "I2201: a scores row with no dimension names no family"
        );
        assert!(
            family_for("withdraws", None, &none, None).is_err(),
            "I2201: a composer with no edition-2 target names no family"
        );
        assert_eq!(
            family_for("withdraws", Some("custody:.kind"), &none, None).unwrap(),
            "custody:.kind"
        );
    }

    #[test]
    fn i2207_a_draft_signed_externally_is_the_statement_the_door_admits() {
        use crate::federation::edition2::door_invariants::fixture::{iref, key, key_record};
        use ciris_verify_core::edition2::family::SelectContext;
        let k = key(91);
        let kid = ciris_verify_core::edition2::thumbprint(k.public_key());
        let me = iref(&k);
        let env = serde_json::json!({"dimension": "health:liveness:v1", "score": 0.5});
        let d = draft_from_envelope(&kid, &me, &me, "scores", &env, 9_000, None)
            .expect("I2207: drafted");
        let sig = k.sign(&d.sig_structure).unwrap();
        let st = d.assemble(sig);
        let mut keys = crate::federation::edition2::liveness::HeldKeys::new();
        keys.insert_record(key_record(&k, &["user"], 0, None));
        let row = crate::federation::edition2::door::admit_row(
            &st,
            &keys,
            None,
            SelectContext::default(),
        )
        .expect("I2207: the door admits the externally signed draft");
        assert_eq!(row.iss, me);
        assert_eq!(row.family, "health:liveness:.version");
        // A signature over anything else is refused.
        let bad = d.assemble(k.sign(b"not the sig_structure").unwrap());
        assert!(crate::federation::edition2::door::admit_row(
            &bad,
            &keys,
            None,
            SelectContext::default()
        )
        .is_err());
    }

    #[test]
    fn i2201_the_producers_dimensions_resolve_to_their_families() {
        for (d, f) in [
            ("self:delegates_to:v1", Some("self:delegates_to")),
            (
                "self:delegates_to:agent_occurrence:v1",
                Some("self:delegates_to:agent_occurrence"),
            ),
            // The agent-occurrence envelope's unversioned dimension resolves to
            // nothing: the family comes from the relation, and the dimension is
            // left out of the payload.
            ("self:delegates_to:agent_occurrence", None),
            ("custody:ack:v1", Some("custody:.kind")),
            ("key_grant:content:v1", Some("key_grant:.axis")),
            ("key_grant:stream:v1", Some("key_grant:.axis")),
            (
                "takedown_notice:steward_purge:v1",
                Some("takedown_notice:.basis"),
            ),
            (
                "wa_adjudication:petition:v1",
                Some("wa_adjudication:.state"),
            ),
            (
                "ownership:responsible_party:node:v1",
                Some("ownership:.relation:.target_kind:.version"),
            ),
            ("identity_binding:v1", None),
        ] {
            assert_eq!(family_of_dimension(d).as_deref(), f, "I2201: {d}");
        }
        assert!(
            !family_is_authored(
                "takedown_notice:.basis",
                Some("takedown_notice:steward_purge:v1")
            ),
            "I2201: a steward-purge notice is a counted row"
        );
        assert!(family_is_authored("custody:.kind", Some("custody:ack:v1")));
    }
}
