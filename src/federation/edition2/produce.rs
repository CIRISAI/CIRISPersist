//! v62.0.0 (slice J0, CIRISPersist#1274) — **producing edition-2 statements
//! with persist's own composite signer.**
//!
//! CIRISVerify publishes the reader and an in-memory minter
//! (`sign_row_statement`, over a `CompositeSigningKey`). A node signs with
//! its [`LocalSigner`], whose two halves may sit in a keyring or hardware, so
//! persist builds the protected header the way Verify's minter does, signs
//! Verify's `Sig_structure` with [`LocalSigner::sign_composite`] (slice D:
//! the keyring's FIPS 204 context-sign plus `composite::assemble_composite`),
//! and assembles the tag-18 `COSE_Sign1`.
//!
//! - [`sign_row`]: a `ceg-row/2` statement. Byte for byte what
//!   `sign_row_statement` mints for the same key (both halves are
//!   deterministic), so the door admits it (I2010).
//! - [`sign_object`]: a voice over a signed object that is not a row
//!   (`ceg-genesis-bundle/2`), the header E2a's object reader reads.
//!
//! The header labels are CC 2.6.1's (COSE `alg` 1, `cty` 3, `kid` 4, `CWT`
//! 15, `typ` 16; CIRIS `row_type` -70001, `family` -70002; CWT `iss` 1,
//! `sub` 2, `exp` 4, `nbf` 5, `iat` 6, `edition` -70003).

use ciris_crypto::composite::{CompositePublicKey, COSE_ALG};
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{
    identity_ref, sig_structure, thumbprint, Digest32, EDITION, ROW_CTY, ROW_TYP,
};

use crate::signing::{LocalSigner, LocalSignerError};

const H_ALG: i64 = 1;
const H_CTY: i64 = 3;
const H_KID: i64 = 4;
const H_CWT: i64 = 15;
const H_TYP: i64 = 16;
const H_ROW_TYPE: i64 = -70001;
const H_FAMILY: i64 = -70002;
const C_ISS: i64 = 1;
const C_SUB: i64 = 2;
const C_EXP: i64 = 4;
const C_NBF: i64 = 5;
const C_IAT: i64 = 6;
const C_EDITION: i64 = -70003;
const TAG_COSE_SIGN1: u64 = 18;

/// Why a statement could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum ProduceError {
    /// The payload is not a map, or carries no `asserted_at` (POSIX ms).
    #[error("edition2_payload_invalid: {0}")]
    Payload(&'static str),
    /// v62.0.0 (E2-fix10) — the door's own payload validator
    /// (`payloads::check_by_id`) refuses the payload: the producer never
    /// signs what its own door would refuse. The refusal's text as raised.
    #[error("{0}")]
    Rejected(String),
    /// The signer could not sign the composite (no PQC half, no
    /// context-sign, a half failed).
    #[error(transparent)]
    Signer(#[from] LocalSignerError),
}

/// The signer's composite public key (`mldsaPK || ed25519PK`).
///
/// # Errors
/// [`LocalSignerError::PqcNotConfigured`] without a PQC half; a key that
/// does not decode.
pub async fn composite_public_key(
    signer: &LocalSigner,
) -> Result<CompositePublicKey, LocalSignerError> {
    let pqc = signer
        .pqc_signer()
        .ok_or(LocalSignerError::PqcNotConfigured)?;
    let mldsa = pqc
        .public_key()
        .await
        .map_err(|e| LocalSignerError::PqcSign(format!("{e}")))?;
    CompositePublicKey::from_halves(&mldsa, &signer.classical_public_key_bytes())
        .map_err(|e| LocalSignerError::PqcSign(format!("composite public key: {e}")))
}

/// The signer's kid (its composite key's RFC 9679 thumbprint) and
/// identity-ref: what its statements carry as `kid` and `iss`.
///
/// # Errors
/// As [`composite_public_key`].
pub async fn signer_identity(signer: &LocalSigner) -> Result<(Digest32, String), LocalSignerError> {
    let kid = thumbprint(&composite_public_key(signer).await?);
    Ok((kid, identity_ref(&kid)))
}

/// v62.0.0 (E2-fix10; `signed_object_v2.cddl` `refs`, CC 2.6.1.3 / 2.6.1.2)
/// — **`refs` as Verify's reader checks it** (`edition2::check_refs`, run in
/// every `verify_row_statement` since 23.0.0), so a statement persist signs
/// is one the door admits. The members are closed (`head`, `prev`,
/// `answers`, `target` one row-ref; `further_heads`, `trusted_through`,
/// `further_prev` a row-ref-set; `also` a non-empty map over `ack` |
/// `cites`, each a row-ref-set), and every set is sorted by encoding with
/// no duplicate.
///
/// v62.0.0 (CONTENT-K2) — `further_prev` and the cap on
/// `trusted_through` ([`TRUSTED_THROUGH_MAX`]) are Verify 23.5.1's. Until
/// that pin the door (Verify 23.5.0's reader) refuses `further_prev` as
/// `unexpected:refs` and carries no cap. So no persist producer states
/// `further_prev` before the pin (CONTENT-K4 states `prev` alone). These
/// arms are deleted at the pin, with the rest of this copy.
/// The error is Verify's label, as `door::invalid_label` spells it:
/// `unexpected:refs`, `unexpected:also`, `malformed:<member>`,
/// `set_order:<member>`.
///
/// Replaced by a call to Verify's own refs reader once CIRISVerify exports
/// it (asked for 23.5.1; private at 23.5.0, FS-step3).
///
/// # Errors
/// The label of the first rule broken, in Verify's order.
pub fn check_refs(v: &Value) -> Result<(), &'static str> {
    let m = v
        .as_map()
        .filter(|m| !m.is_empty())
        .ok_or("malformed:refs")?;
    for (k, x) in m {
        match k.as_text() {
            Some("head") => row_ref_ok(x, "malformed:head")?,
            Some("prev") => row_ref_ok(x, "malformed:prev")?,
            Some("answers") => row_ref_ok(x, "malformed:answers")?,
            Some("target") => row_ref_ok(x, "malformed:target")?,
            Some("further_heads") => {
                row_ref_set_ok(x, "malformed:further_heads", "set_order:further_heads")?;
            }
            Some("trusted_through") => {
                row_ref_set_ok(x, "malformed:trusted_through", "set_order:trusted_through")?;
                // v62.0.0 (CONTENT-K2; DELETED AT THE VERIFY PIN: Verify
                // 23.5.1's public `check_refs` carries the cap for every row)
                // — at most [`TRUSTED_THROUGH_MAX`] tips.
                if x.as_array().is_some_and(|a| a.len() > TRUSTED_THROUGH_MAX) {
                    return Err(TRUSTED_THROUGH_TOO_MANY);
                }
            }
            // v62.0.0 (CONTENT-K2; DELETED AT THE VERIFY PIN, where Verify
            // 23.5.1's reader carries it) — a content row's further
            // predecessors (the author's other tips in the room), a
            // row-ref-set, allowed only beside `prev` (checked below).
            Some("further_prev") => {
                row_ref_set_ok(x, "malformed:further_prev", "set_order:further_prev")?;
            }
            Some("also") => {
                let roles = x
                    .as_map()
                    .filter(|r| !r.is_empty())
                    .ok_or("malformed:also")?;
                for (role, set) in roles {
                    match role.as_text() {
                        Some("ack" | "cites") => {
                            row_ref_set_ok(set, "malformed:also", "set_order:also")?;
                        }
                        _ => return Err("unexpected:also"),
                    }
                }
            }
            _ => return Err("unexpected:refs"),
        }
    }
    // v62.0.0 (CONTENT-K2; DELETED AT THE VERIFY PIN) — `further_prev` only
    // on a row that also names `prev`.
    let named = |role: &str| m.iter().any(|(k, _)| k.as_text() == Some(role));
    if named("further_prev") && !named("prev") {
        return Err("malformed:further_prev");
    }
    Ok(())
}

/// v62.0.0 (CONTENT-K2; the Constitution's room-content rule, R3) — the most
/// tips one `refs.trusted_through` names, on every row that carries it.
/// DELETED AT THE VERIFY PIN, with [`TRUSTED_THROUGH_TOO_MANY`] and the
/// `further_prev` arm of [`check_refs`]: Verify 23.5.1's public `check_refs`
/// carries all three.
pub const TRUSTED_THROUGH_MAX: usize = 64;

/// v62.0.0 (CONTENT-K2) — [`check_refs`]' label for a `refs.trusted_through`
/// of more than [`TRUSTED_THROUGH_MAX`] tips (Verify's token).
pub const TRUSTED_THROUGH_TOO_MANY: &str = "trusted_through_too_many";

/// `row-ref = [2, [-16, bstr .size 32]]` (Verify's `check_row_ref`).
fn row_ref_ok(v: &Value, malformed: &'static str) -> Result<(), &'static str> {
    match v.as_array() {
        Some([ed, id]) if ed.as_u64() == Some(EDITION) => match id.as_array() {
            Some([alg, d])
                if alg.as_i64() == Some(-16) && d.as_bytes().is_some_and(|b| b.len() == 32) =>
            {
                Ok(())
            }
            _ => Err(malformed),
        },
        _ => Err(malformed),
    }
}

/// A non-empty `row-ref-set`, sorted by encoding, no duplicate (Verify's
/// `check_row_ref_set`).
fn row_ref_set_ok(
    v: &Value,
    malformed: &'static str,
    set_order: &'static str,
) -> Result<(), &'static str> {
    let a = v.as_array().filter(|a| !a.is_empty()).ok_or(malformed)?;
    for r in a {
        row_ref_ok(r, malformed)?;
    }
    let enc: Vec<Vec<u8>> = a.iter().map(cde::encode).collect();
    if enc.windows(2).all(|w| w[0] < w[1]) {
        Ok(())
    } else {
        Err(set_order)
    }
}

/// The protected header of a row statement, as Verify's minter builds it:
/// `iat` / `nbf` / `exp` are the payload's `asserted_at` / `valid_from` /
/// `valid_until` in seconds.
///
/// # Errors
/// [`ProduceError::Payload`] for a payload with no `asserted_at`.
pub fn row_protected(
    kid: &Digest32,
    iss: &str,
    sub: &str,
    row_type: &str,
    family: &str,
    payload: &Value,
) -> Result<Vec<u8>, ProduceError> {
    if payload.as_map().is_none() {
        return Err(ProduceError::Payload("the payload is not a map"));
    }
    // v62.0.0 (E2-fix10) — never sign a statement Verify's reader refuses:
    // `refs` is checked as Verify checks it, with Verify's labels.
    if let Some(refs) = payload.get_text("refs") {
        check_refs(refs).map_err(ProduceError::Payload)?;
    }
    // ... and never what persist's own door refuses: the same payload
    // validator `door::pure_statement_gates` runs (`payloads::check_by_id`:
    // the family's closed map, or the composer rule), before signing.
    super::payloads::check_by_id(family, row_type, payload)
        .map_err(|e| ProduceError::Rejected(e.to_string()))?;
    let ms = |k: &str| payload.get_text(k).and_then(Value::as_u64);
    let asserted_at = ms("asserted_at").ok_or(ProduceError::Payload("no asserted_at"))?;
    let mut claims = vec![
        (Value::int(C_ISS), Value::Text(iss.into())),
        (Value::int(C_SUB), Value::Text(sub.into())),
        (Value::int(C_IAT), Value::Uint(asserted_at / 1000)),
        (Value::int(C_EDITION), Value::Uint(EDITION)),
    ];
    if let Some(v) = ms("valid_from") {
        claims.push((Value::int(C_NBF), Value::Uint(v / 1000)));
    }
    if let Some(v) = ms("valid_until") {
        claims.push((Value::int(C_EXP), Value::Uint(v / 1000)));
    }
    Ok(cde::encode(&Value::Map(vec![
        (Value::int(H_ALG), Value::int(COSE_ALG)),
        (Value::int(H_CTY), Value::Text(ROW_CTY.into())),
        (Value::int(H_KID), Value::Bytes(kid.to_vec())),
        (Value::int(H_CWT), Value::Map(claims)),
        (Value::int(H_TYP), Value::Text(ROW_TYP.into())),
        (Value::int(H_ROW_TYPE), Value::Text(row_type.into())),
        (Value::int(H_FAMILY), Value::Text(family.into())),
    ])))
}

/// The protected header of an object voice (`typ` one of Verify's
/// `OBJECT_TYPS`): `iss`, an optional `sub`, an optional `iat` (seconds),
/// the edition.
///
/// v62.0.0 (CE-fix4; Eric's ruling, RFC 9943: every Signed Statement has
/// `iss` and `sub`) — a `ceg-genesis-bundle/2` voice states `sub` = the
/// lineage's `family_key_id` (the payload's; Verify's reader refuses a
/// mismatch). Verify mints no object statement, so this is the one encoder
/// of an object header.
#[must_use]
pub fn object_protected(
    kid: &Digest32,
    iss: &str,
    sub: Option<&str>,
    typ: &str,
    iat: Option<u64>,
) -> Vec<u8> {
    let mut claims = vec![(Value::int(C_ISS), Value::Text(iss.into()))];
    if let Some(s) = sub {
        claims.push((Value::int(C_SUB), Value::Text(s.into())));
    }
    if let Some(i) = iat {
        claims.push((Value::int(C_IAT), Value::Uint(i)));
    }
    claims.push((Value::int(C_EDITION), Value::Uint(EDITION)));
    cde::encode(&Value::Map(vec![
        (Value::int(H_ALG), Value::int(COSE_ALG)),
        (Value::int(H_KID), Value::Bytes(kid.to_vec())),
        (Value::int(H_CWT), Value::Map(claims)),
        (Value::int(H_TYP), Value::Text(typ.into())),
    ]))
}

/// The tag-18 `COSE_Sign1` of a protected header, payload and signature,
/// with an empty unprotected map.
#[must_use]
pub fn assemble(protected: Vec<u8>, payload: Vec<u8>, signature: Vec<u8>) -> Vec<u8> {
    cde::encode(&Value::Tag(
        TAG_COSE_SIGN1,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(signature),
        ])),
    ))
}

/// **Sign a row** with persist's own composite signer: `iss` and the header
/// `kid` are the signer's own ([`signer_identity`]).
///
/// # Errors
/// [`ProduceError`].
pub async fn sign_row(
    signer: &LocalSigner,
    sub: &str,
    row_type: &str,
    family: &str,
    payload: &Value,
) -> Result<Vec<u8>, ProduceError> {
    let (kid, iss) = signer_identity(signer).await?;
    let protected = row_protected(&kid, &iss, sub, row_type, family, payload)?;
    let payload = cde::encode(payload);
    let sig = signer
        .sign_composite(&sig_structure(&protected, &payload))
        .await?;
    Ok(assemble(protected, payload, sig))
}

/// v62.0.0 (CE-fix4) — the CWT `sub` an object voice of `typ` states: for
/// a `ceg-genesis-bundle/2` voice, the payload's `family_key_id` (the
/// lineage); for any other object `typ`, none.
///
/// # Errors
/// [`ProduceError::Payload`] for a genesis bundle payload that names no
/// `family_key_id` (the producer never signs what the reader refuses).
pub fn object_sub<'a>(typ: &str, payload: &'a Value) -> Result<Option<&'a str>, ProduceError> {
    if typ != super::genesis::GENESIS_BUNDLE_TYP {
        return Ok(None);
    }
    payload
        .get_text("family_key_id")
        .and_then(Value::as_text)
        .map(Some)
        .ok_or(ProduceError::Payload(
            "a genesis bundle payload names its family_key_id (the voice's CWT sub)",
        ))
}

/// **Sign an object voice** (`ceg-genesis-bundle/2` and the other object
/// `typ`s) with persist's own composite signer.
///
/// # Errors
/// [`ProduceError`].
pub async fn sign_object(
    signer: &LocalSigner,
    typ: &str,
    payload: &Value,
    iat: Option<u64>,
) -> Result<Vec<u8>, ProduceError> {
    if payload.as_map().is_none() {
        return Err(ProduceError::Payload("the payload is not a map"));
    }
    let (kid, iss) = signer_identity(signer).await?;
    let sub = object_sub(typ, payload)?;
    let protected = object_protected(&kid, &iss, sub, typ, iat);
    let payload = cde::encode(payload);
    let sig = signer
        .sign_composite(&sig_structure(&protected, &payload))
        .await?;
    Ok(assemble(protected, payload, sig))
}
