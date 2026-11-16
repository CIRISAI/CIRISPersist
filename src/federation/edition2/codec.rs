//! v62.0.0 (slice J0) — **the test codec**: an earlier-form-shaped row as an
//! edition-2 statement, and back. Shared by the JSON-cut slices, so their
//! fixtures sign one way.
//!
//! - [`statement_of`]: the inverse of `ingest::json_of` / `attestation_of`.
//!   The row's envelope (less `ceg_statement` and the `row` mirror) becomes
//!   the CBOR payload: the instants ([`INSTANT_MEMBERS`]) as POSIX ms, the
//!   fixed-scale members ([`SCALED_MEMBERS`]) ×10⁶, the members a family
//!   carries as bytes ([`BYTES_MEMBERS`], hex) as bstr; maps in the
//!   deterministic order. `row_type` is `attestation_type`, `sub` is
//!   `attested_key_id`, and `iss` is the signing key's identity-ref. The
//!   payload's `asserted_at` is the row's when the envelope states none, and
//!   its `author` the signer's when it names none.
//! - [`row_of`]: the statement through the door ([`admit_row`]) and the
//!   mapping ([`attestation_of`]), with the signer's own `key:record` held.
//! - [`key_for`] / [`kid`] / [`rid`]: the composite key a test key id
//!   names (its seed is the id's first 32 bytes, padded with `0x11`, both
//!   halves: the same keys as `tier_ingest::test_support::local_signer`), its
//!   identity-ref, and a row's id.
//!
//! I2011 witnesses the round trip, byte for byte.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::{identity_ref, sign_row_statement, thumbprint};

use super::door::admit_row;
use super::door_invariants::fixture::key_record;
use super::ingest::{attestation_of, INSTANT_MEMBERS, SCALED_MEMBERS, STATEMENT_MEMBER};
use super::liveness::HeldKeys;
use crate::federation::types::Attestation;
use crate::federation::Error;

/// The members a family carries as bytes, which the mapping writes as hex.
/// A slice that flips a family carrying bytes appends its members here.
pub(crate) const BYTES_MEMBERS: &[&str] = &[];

/// The composite key a test key id names: seed = the id's first 32 bytes,
/// padded with `0x11`, for both halves (`tier_ingest::test_support::seed_for`).
pub(crate) fn key_for(key_id: &str) -> CompositeSigningKey {
    let seed = crate::federation::tier_ingest::test_support::seed_for(key_id);
    CompositeSigningKey::from_seeds(&seed, &seed)
}

/// The identity-ref of [`key_for`]`(key_id)`: what an edition-2 test names
/// a key by.
pub(crate) fn kid(key_id: &str) -> String {
    identity_ref(&thumbprint(key_for(key_id).public_key()))
}

/// A row's id, as stored (`attestation_id`, lowercase hex).
pub(crate) fn rid(row: &Attestation) -> String {
    row.attestation_id.clone()
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// A JSON value as CBOR, maps in the deterministic order.
fn cbor_of(v: &serde_json::Value, member: Option<&str>) -> Value {
    use serde_json::Value as J;
    match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::Uint(u)
            } else if let Some(i) = n.as_i64() {
                // -1 - k for a negative i.
                Value::Nint(u64::try_from(-(i + 1)).expect("negative"))
            } else {
                panic!("codec: a real outside the fixed-scale members ({member:?}: {n})")
            }
        }
        J::String(s) => Value::Text(s.clone()),
        J::Array(a) => Value::Array(a.iter().map(|x| cbor_of(x, member)).collect()),
        J::Object(o) => {
            let mut m: Vec<(Value, Value)> = o
                .iter()
                .map(|(k, x)| (text(k), cbor_of(x, Some(k))))
                .collect();
            m.sort_by_key(|(k, _)| cde::encode(k));
            Value::Map(m)
        }
    }
}

fn ms_of(s: &str) -> u64 {
    u64::try_from(
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap_or_else(|e| panic!("codec: instant {s:?}: {e}"))
            .timestamp_millis(),
    )
    .expect("codec: an instant before the epoch")
}

/// The payload a row's envelope projects from (the inverse of the mapping).
pub(crate) fn payload_of(row: &Attestation, signer_iref: &str, bytes_members: &[&str]) -> Value {
    let mut env = row.attestation_envelope.clone();
    let o = env
        .as_object_mut()
        .expect("codec: the envelope is a JSON object");
    o.remove(STATEMENT_MEMBER);
    o.remove("row");
    let mut m: Vec<(Value, Value)> = Vec::new();
    for (k, v) in o.iter() {
        let c = if INSTANT_MEMBERS.contains(&k.as_str()) {
            Value::Uint(ms_of(v.as_str().expect("codec: an instant is text")))
        } else if SCALED_MEMBERS.contains(&k.as_str()) {
            let real = v.as_f64().expect("codec: a scaled member is a number");
            #[allow(clippy::cast_possible_truncation)]
            let scaled = (real * 1_000_000.0).round() as i64;
            if scaled >= 0 {
                Value::Uint(scaled.unsigned_abs())
            } else {
                Value::Nint(scaled.unsigned_abs() - 1)
            }
        } else if bytes_members.contains(&k.as_str()) {
            Value::Bytes(hex::decode(v.as_str().expect("codec: bytes are hex")).expect("hex"))
        } else {
            cbor_of(v, Some(k))
        };
        m.push((text(k), c));
    }
    if !o.contains_key("asserted_at") {
        let ms = u64::try_from(row.asserted_at.timestamp_millis()).expect("codec: asserted_at");
        m.push((text("asserted_at"), Value::Uint(ms)));
    }
    if !o.contains_key("author") {
        m.push((text("author"), text(signer_iref)));
    }
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

/// **An earlier-form-shaped row as an edition-2 statement**, of `family`,
/// signed by `key`.
pub(crate) fn statement_of(row: &Attestation, family: &str, key: &CompositeSigningKey) -> Vec<u8> {
    statement_of_with(row, family, key, BYTES_MEMBERS)
}

/// [`statement_of`] with a family's own bytes members.
pub(crate) fn statement_of_with(
    row: &Attestation,
    family: &str,
    key: &CompositeSigningKey,
    bytes_members: &[&str],
) -> Vec<u8> {
    let iref = identity_ref(&thumbprint(key.public_key()));
    let payload = payload_of(row, &iref, bytes_members);
    sign_row_statement(
        key,
        &iref,
        &row.attested_key_id,
        &row.attestation_type,
        family,
        &payload,
        vec![],
    )
    .expect("codec: sign")
}

/// **A statement as the typed row** the gates read: through the door, with
/// the signer's `key:record` (a `user` record from 0) held, mapped at `tier`.
///
/// # Errors
/// The door's refusals.
pub(crate) fn row_of(
    statement: &[u8],
    key: &CompositeSigningKey,
    tier: &str,
) -> Result<Attestation, Error> {
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record(key, &["user"], 0, None));
    let admitted = admit_row(statement, &keys, None, SelectContext::default())?;
    attestation_of(&admitted, tier)
}
