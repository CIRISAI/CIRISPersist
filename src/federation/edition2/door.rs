//! The edition-2 door (CC 2.6.1, 2.6.1.8, 2.6.1.12).
//!
//! [`admit_row`] is the one place an edition-2 row statement is judged. Every
//! inbound path that carries one calls it: the attestation door, the key
//! door, replication and tier ingest. In order:
//!
//! 1. **Form** ([`input_form`]). Bytes that are not a tag-18 `COSE_Sign1` are
//!    refused [`token::EARLIER_FORM_OBJECT`]. That covers a JSON object of the
//!    earlier form, and bytes in no form. Nothing is parsed for standing.
//! 2. **Edition-1 row-refs.** A `row-ref` of edition 1 anywhere in `refs` is
//!    refused [`token::ROW_REF_EDITION_1`]. This is structural, so the
//!    answer does not depend on which keys are held. Verify's reader admits
//!    both editions of a row-ref; the refusal is persist's (CC 2.6.1.3).
//! 3. **Statement and family.** CIRISVerify's `verify_row_in_family_with` runs
//!    under CC's vendored family model. Invalid is
//!    [`token::STATEMENT_INVALID`] or [`token::FAMILY_INVALID`], and final.
//!    Waiting is the retryable `federation_attester_key_unknown`, naming the
//!    deepest missing key.
//!    Then **the key is of the identity** (v62.0.0, JSON-cut slice A, I2101;
//!    CC 2.6.1.7, CC-READING(next-edition)). `iss` names the signer's
//!    identity, the identity-ref of its genesis key; `kid` names the key
//!    that signed. The key `kid` resolves to must be a key OF `iss`: `iss`
//!    is `kid`'s own identity-ref, or a held record of `kid` reaches `iss`'s
//!    genesis record through rotations
//!    ([`super::liveness::KeyOwnership`]). A key whose records are of
//!    another identity is refused [`token::KID_NOT_OF_ISS`]; a missing link
//!    waits (the retryable `federation_attester_key_unknown`, naming it).
//! 4. **The row id, computed here.** SHA-256 over
//!    `CDE(["CEG-row/2", type, family, sub, author, payload])`, taken over the
//!    payload bytes as received. It must equal the reader's own id for the
//!    statement. An id the caller offers must equal it too, or the row is
//!    refused [`token::ROW_ID_MISMATCH`]. A row is never stored under a given
//!    id.
//! 5. **The key record's end rule** (family `key:record`):
//!    - `valid_until` must agree with the identity set, or the record is
//!      refused [`token::KEY_RECORD_OUT_OF_WINDOW`];
//!    - a set mixing a person's role with a machine's is refused as
//!      `IdentitySetMixesPersonAndMachine`;
//!    - `identity_type` must be a sorted CBOR array of text, or the record is
//!      refused [`token::STATEMENT_INVALID`].

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::{
    select::Act, verify_row_in_family_with, FamilyFault, FamilyVerdict, SelectContext,
    VendoredFamilyModel,
};
use ciris_verify_core::edition2::keys::{check_key_record, KeyRecordError, KEY_RECORD_FAMILY};
use ciris_verify_core::edition2::{identity_ref, Digest32, Invalid, MissingKey};

use super::liveness::{statement_parts, ChainMissing, KeyOf, KeyOwnership};
use super::names::{names_of, Name, NameError, RowId};
use super::token;
use crate::federation::Error;

/// The plane name the door's refusals carry.
pub const PLANE: &str = "edition2";

/// What the first bytes of an offered object are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputForm {
    /// A tag-18 CBOR item: a `COSE_Sign1` of this form, to be read.
    Statement,
    /// A JSON object or array: the earlier form (CC 8.11).
    EarlierForm,
    /// Bytes in no form.
    Unrecognized,
}

/// Classify offered bytes by their first item, without parsing.
#[must_use]
pub fn input_form(bytes: &[u8]) -> InputForm {
    match bytes.first() {
        // Major type 6, value 18: `0xd2`.
        Some(0xd2) => InputForm::Statement,
        _ => match bytes.iter().find(|b| !b.is_ascii_whitespace()) {
            Some(b'{' | b'[') => InputForm::EarlierForm,
            _ => InputForm::Unrecognized,
        },
    }
}

/// A row statement the door admitted: what the store keeps and the gates
/// read.
#[derive(Clone, Debug)]
pub struct AdmittedRow {
    /// The row id, computed by this node.
    pub row_id: RowId,
    /// This voice's statement id.
    pub statement_id: Digest32,
    /// The signing key's thumbprint.
    pub kid: Digest32,
    /// The CWT `iss`.
    pub iss: String,
    /// The CWT `sub`.
    pub sub: String,
    /// The row type (label -70001).
    pub row_type: String,
    /// The family id (label -70002).
    pub family: String,
    /// The payload's `author`, absent on a counted row.
    pub author: Option<String>,
    /// The payload's `asserted_at`, POSIX ms.
    pub asserted_at_ms: u64,
    /// The decoded payload.
    pub payload: Value,
    /// What the row names, from `refs` (edition 2 only).
    pub names: Vec<Name>,
    /// The role the signer filled when it is not the author.
    pub role: Option<String>,
    /// The statement as received: stored and forwarded as is (CC 2.6.1.2).
    pub bytes: Vec<u8>,
}

fn refuse(reason: &'static str, message: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, reason, message)
}

/// Verify's Invalid reason as a stable label for the refusal's message.
#[must_use]
pub fn invalid_label(i: &Invalid) -> String {
    match i {
        Invalid::NotDeterministic { part, .. } => format!("not_deterministic:{part}"),
        Invalid::NotCoseSign1 => "not_cose_sign1".into(),
        Invalid::Malformed { member } => format!("malformed:{member}"),
        Invalid::UnexpectedMember { within } => format!("unexpected:{within}"),
        Invalid::TimeDisagreement { claim } => format!("time:{claim}"),
        Invalid::SetOrder { member } => format!("set_order:{member}"),
        Invalid::KidMismatch => "kid_mismatch".into(),
        Invalid::BadSignature => "bad_signature".into(),
        Invalid::KeyNotValid => "key_not_valid".into(),
        Invalid::DisclosureUnmatched => "disclosure_unmatched".into(),
        Invalid::DuplicateDigest => "duplicate_digest".into(),
        Invalid::UnregisteredFamily => "unregistered_family".into(),
        Invalid::DimensionFamily => "dimension_family".into(),
        Invalid::DimensionRefused { token } => format!("dimension_refused:{token}"),
        Invalid::DimensionUnregistered => "dimension_unregistered".into(),
        other => format!("{other:?}"),
    }
}

fn fault_label(f: &FamilyFault) -> &'static str {
    match f {
        FamilyFault::UnregisteredFamily => "unregistered_family",
        FamilyFault::AuthorColumn => "author_column",
        FamilyFault::IssNotInRole => "iss_not_in_role",
        FamilyFault::DimensionMissing => "dimension_missing",
        FamilyFault::AuthorshipUndetermined => "authorship_undetermined",
        FamilyFault::NoArmHolds => "no_arm_holds",
        _ => "other",
    }
}

/// The waiting refusal: the retryable unknown-signer error naming the
/// deepest missing key by its identity reference.
fn waiting(missing: &[MissingKey]) -> Error {
    let named = missing
        .first()
        .map(|m| match m {
            MissingKey::Kid(k) => identity_ref(k),
            MissingKey::MlDsaHalf { kid, .. } => identity_ref(kid),
            other => format!("{other:?}"),
        })
        .unwrap_or_else(|| "<unnamed key>".to_owned());
    Error::unknown_signer(&named, PLANE)
}

/// Refuse an object that is not an edition-2 statement (step 1), naming
/// what it is.
///
/// # Errors
/// [`token::EARLIER_FORM_OBJECT`].
pub fn require_statement_form(bytes: &[u8]) -> Result<(), Error> {
    match input_form(bytes) {
        InputForm::Statement => Ok(()),
        InputForm::EarlierForm => Err(refuse(
            token::EARLIER_FORM_OBJECT,
            "an object of the earlier form (a JSON object, CC 8.11) at an edition-2 door: a \
             node of this form reads this form only (CC 2.6.1.12)",
        )),
        InputForm::Unrecognized => Err(refuse(
            token::EARLIER_FORM_OBJECT,
            "bytes in no form at an edition-2 door: not a tag-18 COSE_Sign1 (CC 2.6.1.1)",
        )),
    }
}

/// Refuse an edition-1 `row-ref` in a payload's `refs` (step 2).
///
/// # Errors
/// [`token::ROW_REF_EDITION_1`].
pub fn refuse_edition_one(payload: &Value) -> Result<(), Error> {
    match names_of(payload) {
        Err(NameError::EditionOne { role }) => Err(refuse(
            token::ROW_REF_EDITION_1,
            format!(
                "refs.{role} names an object of the earlier form by an edition-1 row-ref: no row \
                 of this form names an object of the earlier form (CC 2.6.1.3, 2.6.1.12)"
            ),
        )),
        // Every other shape is Verify's to judge.
        _ => Ok(()),
    }
}

/// The selector context the door supplies: `act` from the author column
/// (an authored row's payload carries `author`; a counted row's does not,
/// CC 2.6.1.3). Every other key is unknown unless the caller supplies it.
fn door_context(bytes: &[u8], mut ctx: SelectContext) -> SelectContext {
    if ctx.act.is_none() {
        ctx.act = statement_parts(bytes).map(|(_, p)| {
            if p.get_text("author").is_some() {
                Act::Own
            } else {
                Act::Group
            }
        });
    }
    ctx
}

/// Judge one edition-2 row statement at a door (steps 1 to 5).
///
/// `offered_id` is an id the carrier names the row by, if any. It is
/// compared with the computed one, and never used.
///
/// # Errors
/// The door's named refusals (module docs). A statement that waits on a key
/// is `Error::AttesterKeyUnknown` (retryable).
pub fn admit_row(
    bytes: &[u8],
    keys: &dyn KeyOwnership,
    offered_id: Option<&Digest32>,
    ctx: SelectContext,
) -> Result<AdmittedRow, Error> {
    require_statement_form(bytes)?;
    let Some((protected, payload)) = statement_parts(bytes) else {
        // Not even a decodable COSE_Sign1: Verify's reader names the fault.
        let why = match ciris_verify_core::edition2::verify_row_statement(bytes, keys) {
            ciris_verify_core::edition2::Verdict::Invalid(i) => invalid_label(&i),
            _ => "not_cose_sign1".to_owned(),
        };
        return Err(refuse(token::STATEMENT_INVALID, why));
    };
    let is_object = protected
        .get_int(16)
        .and_then(Value::as_text)
        .is_some_and(|t| ciris_verify_core::edition2::OBJECT_TYPS.contains(&t));
    if is_object {
        return Err(refuse(
            token::NOT_A_ROW,
            "a signed object that is not a row (its typ is an object's) at a row door \
             (CC 2.6.1.11)",
        ));
    }
    refuse_edition_one(&payload)?;

    let ctx = door_context(bytes, ctx);
    let (row, role) = match verify_row_in_family_with(bytes, keys, &VendoredFamilyModel, &ctx) {
        FamilyVerdict::Valid { row, role } => (row, role),
        FamilyVerdict::Invalid(i) => {
            return Err(refuse(token::STATEMENT_INVALID, invalid_label(&i)));
        }
        FamilyVerdict::FamilyInvalid(f) => {
            return Err(refuse(token::FAMILY_INVALID, fault_label(&f)));
        }
        FamilyVerdict::Waiting(missing) => return Err(waiting(&missing)),
    };
    // Step 3b: the key is of the identity it signs as.
    require_key_of_iss(keys, &row.kid, &row.iss)?;

    // Step 4: the row id, from the bytes as received.
    let payload_bytes = raw_payload(bytes)
        .ok_or_else(|| refuse(token::STATEMENT_INVALID, "not_cose_sign1: no payload bytes"))?;
    let computed = RowId::of_row(
        &row.row_type,
        &row.family,
        &row.sub,
        row.author.as_deref(),
        &payload_bytes,
    );
    if computed.0 != row.row_id {
        return Err(refuse(
            token::ROW_ID_MISMATCH,
            "the reader's row id is not the id computed over the bytes received",
        ));
    }
    if let Some(offered) = offered_id {
        if *offered != computed.0 {
            return Err(refuse(
                token::ROW_ID_MISMATCH,
                format!(
                    "the row was offered as {}, but its bytes name it {}: a row is stored under \
                     the id this node computes, never a given one (CC 2.6.1.3)",
                    hex::encode(offered),
                    computed.hex()
                ),
            ));
        }
    }

    // Step 5: the key record's end rule.
    if row.family == KEY_RECORD_FAMILY {
        if let Err(e) = check_key_record(&row.payload) {
            return Err(key_record_refusal(&row.sub, &row.payload, &e));
        }
    }

    let names = names_of(&row.payload)
        .map_err(|e| refuse(token::STATEMENT_INVALID, format!("refs: {e:?}")))?;
    Ok(AdmittedRow {
        row_id: computed,
        statement_id: row.statement_id,
        kid: row.kid,
        iss: row.iss,
        sub: row.sub,
        row_type: row.row_type,
        family: row.family,
        author: row.author,
        asserted_at_ms: row.asserted_at,
        payload: row.payload,
        names,
        role,
        bytes: bytes.to_vec(),
    })
}

/// Step 3b of the door: `kid` must be a key of `iss` (module docs). Every
/// place the door resolves a signer calls this after Verify's verdict: rows,
/// each counted voice, objects, the halt.
///
/// # Errors
/// [`token::KID_NOT_OF_ISS`]; the retryable unknown-signer error naming a
/// missing link.
pub fn require_key_of_iss(keys: &dyn KeyOwnership, kid: &Digest32, iss: &str) -> Result<(), Error> {
    let not_of = || {
        refuse(
            token::KID_NOT_OF_ISS,
            format!(
                "the signing key {} is not a key of the statement's iss {iss}: no held record of \
                 the key reaches that identity's genesis key (CC 2.6.1.7)",
                identity_ref(kid),
            ),
        )
    };
    let Some(genesis) = super::ingest::kid_of_identity_ref(iss) else {
        return Err(not_of());
    };
    if genesis == *kid {
        return Ok(());
    }
    match keys.key_of(kid, &genesis) {
        KeyOf::Yes => Ok(()),
        KeyOf::No => Err(not_of()),
        KeyOf::Waiting(missing) => Err(chain_waiting(&missing)),
    }
}

/// The waiting refusal for a missing key-chain link, naming it: a key by
/// its identity-ref, a record by `row:<hex>`.
fn chain_waiting(missing: &[ChainMissing]) -> Error {
    let named = missing.first().map_or_else(
        || "<unnamed link>".to_owned(),
        |m| match m {
            ChainMissing::Kid(k) => identity_ref(k),
            ChainMissing::Record(r) => format!("row:{}", hex::encode(r)),
            ChainMissing::Bundle => "ceg-genesis-bundle/2".to_owned(),
        },
    );
    Error::unknown_signer(&named, PLANE)
}

/// The refusal for a `key:record` payload that breaks its rule.
#[must_use]
pub fn key_record_refusal(sub: &str, payload: &Value, e: &KeyRecordError) -> Error {
    match e {
        KeyRecordError::MixedRoles => Error::IdentitySetMixesPersonAndMachine {
            key_id: sub.to_owned(),
            identity_type: payload
                .get_text("identity_type")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_text)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default(),
        },
        KeyRecordError::OutOfWindow => refuse(
            token::KEY_RECORD_OUT_OF_WINDOW,
            "a key record's valid_until breaks the end rule of its identity set (CC 2.4.1.1)",
        ),
        other => refuse(token::STATEMENT_INVALID, format!("key_record:{other:?}")),
    }
}

/// The payload bytes as signed (the third member of the `COSE_Sign1`).
#[must_use]
pub fn raw_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    use ciris_verify_core::cde;
    let cde::Value::Tag(18, inner) = cde::decode(bytes).ok()? else {
        return None;
    };
    inner.as_array()?.get(2)?.as_bytes().map(<[u8]>::to_vec)
}

/// v62.0.0 (JSON-cut slice A; CC 2.6.1.12, rc20 "nothing carries, clean
/// mesh") — **THE switch that shuts the earlier-form doors.** While it is
/// `false` every JSON door admits as before; slice F flips it to `true`, in
/// this one place, and every door wired to [`refuse_earlier_form`] refuses
/// an earlier-form object by name ([`token::EARLIER_FORM_OBJECT`]).
pub const EARLIER_FORM_DOORS_SHUT: bool = false;

#[cfg(test)]
tokio::task_local! {
    /// A test forces the switch on for the future it scopes
    /// ([`with_earlier_form_doors_shut`]), so a witness can assert each
    /// door's refusal before F flips [`EARLIER_FORM_DOORS_SHUT`].
    static FORCE_SHUT: bool;
}

/// Is the earlier form shut at this node's doors?
#[must_use]
pub fn earlier_form_doors_shut() -> bool {
    #[cfg(test)]
    if FORCE_SHUT.try_with(|f| *f).unwrap_or(false) {
        return true;
    }
    EARLIER_FORM_DOORS_SHUT
}

/// Test only: run `fut` with the switch forced on.
#[cfg(test)]
pub(crate) async fn with_earlier_form_doors_shut<T>(
    fut: impl std::future::Future<Output = T>,
) -> T {
    FORCE_SHUT.scope(true, fut).await
}

/// **The one shared refusal every earlier-form door calls** (v62.0.0,
/// JSON-cut slice A). `plane` names the door. It is inert until
/// [`EARLIER_FORM_DOORS_SHUT`] is `true`; then it refuses
/// [`token::EARLIER_FORM_OBJECT`] (`federation_malformed_row`, Python
/// `ValueError`), before any parse or verify of the object.
///
/// # Errors
/// [`token::EARLIER_FORM_OBJECT`] once the doors are shut.
pub fn refuse_earlier_form(plane: &'static str) -> Result<(), Error> {
    if earlier_form_doors_shut() {
        return Err(Error::malformed_row(
            plane,
            token::EARLIER_FORM_OBJECT,
            format!(
                "an object of the earlier form (a JSON object signed over its JCS image, CC 8.11) \
                 at the `{plane}` door: a node of this form reads this form only; offer the \
                 edition-2 statement (CC 2.6.1.12)"
            ),
        ));
    }
    Ok(())
}

/// [`refuse_earlier_form`] for a row at the attestation plane: a row that
/// carries its edition-2 statement (`ceg_statement`) is the edition-2 door's
/// mapping, never an earlier-form object, and passes.
///
/// # Errors
/// As [`refuse_earlier_form`].
pub fn refuse_earlier_form_row(
    plane: &'static str,
    row: &crate::federation::types::Attestation,
) -> Result<(), Error> {
    if row
        .attestation_envelope
        .get(super::ingest::STATEMENT_MEMBER)
        .is_some()
    {
        return Ok(());
    }
    refuse_earlier_form(plane)
}
