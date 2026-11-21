//! The edition-2 door (CC 2.6.1, 2.6.1.8, 2.6.1.12).
//!
//! [`admit_row`] is the one place an edition-2 row statement is judged. Every
//! inbound path that carries one calls it: the attestation door, the key
//! door, replication and tier ingest. In order:
//!
//! 1. **Form** ([`input_form`]). Bytes that are not a tag-18 `COSE_Sign1` are
//!    refused [`token::EARLIER_FORM_OBJECT`]. That covers a JSON object of the
//!    earlier form, and bytes in no form. Nothing is parsed for standing.
//!    v62.0.0 (wave P1c) — then **the size**: a statement over
//!    [`MAX_STATEMENT_BYTES`] is refused `federation_envelope_too_large`.
//!    Steps 1 and 2 are [`pure_statement_gates`]: a pure function of the
//!    bytes, which every door runs BEFORE its first directory read (the
//!    signer's key plane, a roster), as the JSON doors run their pure tier
//!    (AV-76). A statement that can never be admitted buys no read.
//! 2. **Edition-1 row-refs.** A `row-ref` of edition 1 anywhere in `refs` is
//!    refused [`token::ROW_REF_EDITION_1`]. This is structural, so the
//!    answer does not depend on which keys are held. Since CIRISVerify 23.3.0
//!    Verify's reader refuses one too (as a malformed member); persist
//!    names it first, by its own token (CC 2.6.1.3).
//! 3. **Statement and family.** CIRISVerify's `verify_row_in_family_with` runs
//!    under CC's vendored family model. Invalid is
//!    [`token::STATEMENT_INVALID`] or [`token::FAMILY_INVALID`], and final.
//!    Waiting is the retryable `federation_attester_key_unknown`, naming the
//!    deepest missing key.
//!    **The key is of the identity** (v62.0.0, JSON-cut slice A, I2101;
//!    CC 2.6.1.7). `iss` names the signer's identity, the identity-ref of
//!    its genesis key; `kid` names the key that signed. The key `kid`
//!    resolves to must be a key OF `iss`: `iss` is `kid`'s own identity-ref,
//!    or a held record of `kid` reaches `iss`'s genesis record through
//!    rotations. Since CIRISVerify 23.3.0 (slice C3) Verify's reader asks
//!    this itself, through the directory's `KeyDirectory::key_of`
//!    (persist's [`super::liveness::HeldKeys::key_of`]): its
//!    `Invalid::KidNotOfIss` is refused [`token::KID_NOT_OF_ISS`], and a
//!    missing link waits (the retryable `federation_attester_key_unknown`,
//!    naming it). [`require_key_of_iss`] asks the same directory again
//!    after the verdict (one answer; the objects' readers call it too).
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
use ciris_verify_core::edition2::{
    identity_ref, verify_row_statement, Digest32, Invalid, KeyDirectory, KeyOf, MissingKey, Verdict,
};

use super::liveness::statement_parts;
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
        Invalid::KidNotOfIss => "kid_not_of_iss".into(),
        // v62.0.0 (R1; CIRISVerify 23.3.1, CC 2.6.1.8 step 4) — Verify's own
        // token for a span that covers no instant.
        Invalid::ValidUntilNotAfterAssertedAt => "valid_until_not_after_asserted_at".into(),
        // v62.0.0 (R1-v2332; CIRISVerify 23.3.2, CC rc21 cddl 87–91) — a
        // body number outside CBOR's integer range.
        Invalid::BodyNumberUnrepresentable => "body_number_unrepresentable".into(),
        // v62.0.0 (CE-fix3; CIRISVerify 23.3.3) — a known dial-hint type with a
        // bad body: Verify's token.
        Invalid::DialHintMalformed => "dial_hint_malformed".into(),
        other => format!("{other:?}"),
    }
}

/// Verify's family fault as a stable label for the refusal's message.
#[must_use]
pub fn fault_label(f: &FamilyFault) -> &'static str {
    // v62.0.0 (PIN-fix2; CIRISVerify 23.4.1) — Verify's own stable token
    // (`FamilyFault::token`, incl. `target_mismatch`): one name per fault.
    f.token()
}

/// The waiting refusal: the retryable unknown-signer error naming the
/// first missing link: a key by its identity reference (also a key held
/// with no record covering the instant), a record by `row:<hex>`.
fn waiting(missing: &[MissingKey]) -> Error {
    let named = missing
        .first()
        .map(|m| match m {
            MissingKey::Kid(k) | MissingKey::CoveringRecord { kid: k, .. } => identity_ref(k),
            MissingKey::Record(r) => format!("row:{}", hex::encode(r)),
            // v62.0.0 (R1; CIRISVerify 23.3.1, CC 2.6.1.9) — a voice of a
            // held row that is not held: the statement by `kid` over `row`.
            // Named by the key whose statement is missing, as a key is.
            MissingKey::Voice { kid, .. } => identity_ref(kid),
            // v62.0.0 (R1; CIRISVerify 23.3.1, CC 2.6.1.7 way (c)) — the
            // bundle in force a seat waits on, by its object id (the halt
            // door's spelling, `halt::waiting_error`).
            MissingKey::Bundle(b) => format!(
                "{}:{}",
                ciris_verify_core::edition2::genesis::GENESIS_BUNDLE_TYP,
                hex::encode(b)
            ),
            // A composer's unheld target never reaches here from the row
            // door ([`waiting_at`] holds it as a target wait); named by id if
            // another caller passes one.
            MissingKey::Row(r) => format!("row:{}", hex::encode(r)),
            other => format!("{other:?}"),
        })
        .unwrap_or_else(|| "<unnamed key>".to_owned());
    Error::unknown_signer(&named, PLANE)
}

/// v62.0.0 (PIN-fix5b; CIRISVerify 23.4.1) — **the row door's wait**: a
/// `withdraws` / `recants` whose TARGET row is not held (Verify's
/// `MissingKey::Row`) waits on that row, not on a key. It is HELD with the
/// target-unheld reason (`link_unheld`, `federation_withdraws_target_unheld`,
/// the same wait `ingest::check_composer_target` and the dimension gate give
/// it), declares the target row as its read so the target's landing re-folds
/// it, and names the row. Any other missing link is [`waiting`]'s retryable
/// unknown-signer error.
fn waiting_at(bytes: &[u8], missing: &[MissingKey]) -> Error {
    if let Some(MissingKey::Row(r)) = missing.iter().find(|m| matches!(m, MissingKey::Row(_))) {
        super::fold::reads(super::fold::Dep::Row(RowId(*r)));
        return super::fold::hold(
            super::fold::reason::LINK_UNHELD,
            Error::WithdrawsTargetUnheld {
                attestation_id: RowId::of_statement(bytes)
                    .map_or_else(|| "<unread row>".to_owned(), |id| id.hex()),
                target_attestation_id: hex::encode(r),
            },
        );
    }
    waiting(missing)
}

/// The refusal of a key that is not a key of the statement's `iss`.
fn kid_not_of_iss(kid: Option<&Digest32>, iss: &str) -> Error {
    refuse(
        token::KID_NOT_OF_ISS,
        format!(
            "the signing key {} is not a key of the statement's iss {iss}: no held record of \
             the key reaches that identity's genesis key (CC 2.6.1.7)",
            kid.map_or_else(|| "<unread kid>".to_owned(), identity_ref),
        ),
    )
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
    // v62.0.0 (T2-fix3) — the keys a typed family's authorship cell reads,
    // from the bytes, for every admit that supplies none: a re-admission of
    // a held statement (the fold's re-fold, a voice fold, the fixtures'
    // `admit`) reaches the same verdict it was admitted under. A caller
    // with the directory supplies the true context first
    // (`typed::family_context`, the put door), and only keys left `None`
    // are filled here.
    super::typed::fill_context_from_bytes(bytes, &mut ctx);
    ctx
}

/// v62.0.0 (wave P1c) — the largest edition-2 statement a door reads, in
/// bytes: [`MAX_ATTESTATION_ENVELOPE_BYTES`](crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES),
/// the attestation plane's one size cap. The signed thing is the sized
/// thing (CC#38's rule): the bytes as received, which the store keeps and
/// forwards as they are.
pub const MAX_STATEMENT_BYTES: usize = crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES;

/// v62.0.0 (wave P1c) — **the door's pure gates** (steps 1 and 2), a function
/// of the bytes alone: no directory read and no signature check. In order:
///
/// 1. the form ([`require_statement_form`]);
/// 2. the size: over [`MAX_STATEMENT_BYTES`] is `federation_envelope_too_large`;
/// 3. the decode: bytes that are no `COSE_Sign1` are
///    [`token::STATEMENT_INVALID`], named by Verify's reader over `keys` (the
///    decode fault does not depend on which keys are held);
/// 4. a signed object that is not a row is [`token::NOT_A_ROW`];
/// 5. an edition-1 row-ref is [`token::ROW_REF_EDITION_1`];
/// 6. v62.0.0 (wave P1d) — the payload of a family with a member list
///    ([`super::payloads`], by the header's family id) keeps that list:
///    `edition2_payload_invalid` otherwise;
/// 7. v62.0.0 (wave P1e) — an `admission:unit` payload keeps the verifier's
///    pure rules ([`super::payloads::check_admission_unit`], their own
///    tokens).
///
/// [`super::ingest::put_statement`] runs these before it reads the signer's
/// key plane or a roster (AV-76: a statement that can never be admitted
/// buys no directory read); [`admit_row`] runs them again at its head.
/// Verify's verdict (step 3) and everything after it are unchanged.
///
/// # Errors
/// The refusals above.
pub fn pure_statement_gates(bytes: &[u8], keys: &dyn KeyDirectory) -> Result<(), Error> {
    require_statement_form(bytes)?;
    if bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Error::EnvelopeTooLarge {
            bytes: bytes.len(),
            cap: MAX_STATEMENT_BYTES,
        });
    }
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
    // v62.0.0 (kernel pass 2, K1; CC ruling) — a stated window must cover
    // some instant: read from the statement alone, before any key is asked.
    check_valid_until_after_asserted_at(&payload)?;
    // v62.0.0 (wave P1d) — the family's closed payload map
    // (`edition2::payloads`), for a family that has one: an unknown member, a
    // missing required one, a wrong type, a closed value or leaf broken is
    // `edition2_payload_invalid`. A family with no list passes as before.
    let Some(family) = protected.get_int(-70002).and_then(Value::as_text) else {
        // No family in the header: Verify's verdict names that fault.
        return Ok(());
    };
    // v62.0.0 (wave P1e) — a composer carries its target's family but its
    // own payload shape: the row type (-70001) selects the composer rule.
    let row_type = protected
        .get_int(-70001)
        .and_then(Value::as_text)
        .unwrap_or_default();
    // v62.0.0 (RL-fix19; CC 2.6.1.11) — a group-plane statement about the
    // accord is refused BY NAME before its shape is judged (the accord's id
    // is no identity-ref: the shape check would name it payload-invalid).
    if super::group::group_plane_of(row_type, family, &payload).is_some() {
        let sub = protected
            .get_int(15)
            .and_then(|c| c.get_int(2))
            .and_then(Value::as_text)
            .unwrap_or_default();
        super::group::refuse_accord_group_statement(sub, &payload)?;
    }
    super::payloads::check_by_id(family, row_type, &payload)?;
    // v62.0.0 (wave P1e; CC rc21 CC 2.7.11) — the verifier's pure rules over
    // an `admission:unit` payload, each with its own token.
    // (A composer of an admission row carries the family, not the payload.)
    if family == super::payloads::ADMISSION_UNIT_FAMILY
        && !super::payloads::COMPOSER_ROW_TYPES.contains(&row_type)
    {
        let sub = protected
            .get_int(15)
            .and_then(|c| c.get_int(2))
            .and_then(Value::as_text)
            .unwrap_or_default();
        super::payloads::check_admission_unit(sub, &payload)?;
    }
    Ok(())
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
    keys: &dyn KeyDirectory,
    offered_id: Option<&Digest32>,
    ctx: SelectContext,
) -> Result<AdmittedRow, Error> {
    // Steps 1 and 2: the pure gates. A door that reads the directory runs
    // them first itself; repeated here, they cost a decode, and keep this
    // function whole for every caller.
    pure_statement_gates(bytes, keys)?;
    // The header, for the key-of-issuer refusal's names (the pure gates have
    // decoded it already, so this cannot fail; it is not unwrapped).
    let Some((protected, _)) = statement_parts(bytes) else {
        return Err(refuse(token::STATEMENT_INVALID, "not_cose_sign1"));
    };

    let ctx = door_context(bytes, ctx);
    // v62.0.0 (VA-cc-cut; CIRISVerify 23.3.3, CC v1.0-rc21 b016df4) — CC's
    // vendored model, read directly: it now names the occurrence key's own
    // voice on `identity:occurrence` (the cell persist's `PersistCells`
    // overlay stated until 23.3.3).
    let model = VendoredFamilyModel;
    let (row, role) = match verify_row_in_family_with(bytes, keys, &model, &ctx) {
        FamilyVerdict::Valid { row, role } => (row, role),
        // Verify's own key-of-issuer check (23.3.0), through `keys.key_of`
        // (23.3.1: `keys.key_of_at` at the statement's instant; persist's
        // directories keep the provided default, which answers `key_of`).
        FamilyVerdict::Invalid(Invalid::KidNotOfIss) => {
            let kid = protected
                .get_int(4)
                .and_then(Value::as_bytes)
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            let iss = protected
                .get_int(15)
                .and_then(|c| c.get_int(1))
                .and_then(Value::as_text)
                .unwrap_or("<unread iss>")
                .to_owned();
            return Err(kid_not_of_iss(kid.as_ref(), &iss));
        }
        // v62.0.0 (R1; CIRISVerify 23.3.1, CC 2.6.1.8 step 4) — Verify's
        // reader now refuses a span that covers no instant itself. The pure
        // gate ([`check_valid_until_after_asserted_at`]) refuses it first at
        // this door; a caller that reaches Verify's verdict without the pure
        // gate gets persist's token, not `edition2_statement_invalid`.
        FamilyVerdict::Invalid(Invalid::ValidUntilNotAfterAssertedAt) => {
            return Err(refuse(
                crate::federation::malformed_row::VALID_UNTIL_NOT_AFTER_ASSERTED_AT,
                "valid_until is not after asserted_at: the window [asserted_at, \
                 valid_until) covers no instant (CC 2.6.1.8 step 4)",
            ));
        }
        // v62.0.0 (R1-v2332; CIRISVerify 23.3.2) — Verify's reader refuses a
        // body number outside CBOR's integer range itself; the pure gate
        // (`payloads::check_body_numbers`) refuses it first at this door, by
        // the same token. A caller reaching Verify's verdict without the pure
        // gate gets persist's token, not `edition2_statement_invalid`.
        FamilyVerdict::Invalid(Invalid::BodyNumberUnrepresentable) => {
            return Err(refuse(
                crate::federation::malformed_row::BODY_NUMBER_UNREPRESENTABLE,
                "a body number outside CBOR's integer range (CC 2.6.1.4)",
            ));
        }
        FamilyVerdict::Invalid(i) => {
            return Err(refuse(token::STATEMENT_INVALID, invalid_label(&i)));
        }
        // v62.0.0 (wave V1b; R1b) — CC's COUNT cell for an owner binding
        // (CIRISConstitution v1.0-rc21-wire `formal/derivation/count_text.tsv`
        // rows 44–45, `ownership:{relation}:{target_kind}:{version}`:
        // `act=group & group=affiliations` → `cosigned_act@subject_group`,
        // else `none`; CC 3.2): a binding that names an affiliation is cosigned under that
        // affiliation's protocol, so the members' voices are the count and the
        // steward stays the author; CC 2.6.1.3 accepts a voice of the count on
        // an authored row. CIRISVerify 23.3.1 applies only the authorship and
        // `second_signers` cells, so it reads a member's voice
        // `iss_not_in_role`, and a `FamilyModel` cannot state this cell for it
        // (`RoleParty` is `Sub` or a payload member naming `iss`; a roster
        // member is neither). So the count voice is admitted here: the
        // statement itself must be Valid, and persist's counted rule
        // (`admission::check_owner_binding_counted`) counts only the roster at
        // the head the binding names. This arm implements CC's count cell; it
        // is not an override of a ruled model (ruled 2026-11-18). Drop when
        // Verify applies count cells.
        FamilyVerdict::FamilyInvalid(FamilyFault::IssNotInRole)
            if names_an_affiliation_on_the_bond(bytes) =>
        {
            match verify_row_statement(bytes, keys) {
                Verdict::Valid(row) => (row, Some(AFFILIATION_MEMBER_ROLE.to_owned())),
                Verdict::Invalid(i) => {
                    return Err(refuse(token::STATEMENT_INVALID, invalid_label(&i)));
                }
                Verdict::Waiting { missing } => return Err(waiting_at(bytes, &missing)),
            }
        }
        // v62.0.0 (R1; CIRISVerify 23.3.1, CC 4.4.3.12 "two consents") —
        // an affiliation's officer appointment (a `self:delegates_to` with no
        // `author`) reads counted under rc21-wire's vendored arm
        // `act=group => counted` ([`door_context`] derives `act` from
        // `author`), so Verify's verdict is `Valid { role: None }` and the
        // persist-side `author_column` override is gone. The counted rule
        // (`admission::check_officer_appointment_counted`) still counts it.
        // v62.0.0 (K2-fix12; CC 2.6.1.9, authorship_text.tsv:44, CC
        // 4.4.3.19) — the `delegate_owner` role of an own-act delegation onto
        // a MACHINE sub is `owner_of_sub`: the owner the sub's live owner
        // binding names. Verify 23.3.1 drops that member as unresolvable from
        // the row (`family::UNRESOLVED_MEMBERS`), and a `FamilyModel` cannot
        // state it (`RoleParty` is `Sub` or a payload member), so the owner's
        // voice reads `iss_not_in_role`. Who the owner is reads another row
        // (CC 2.7.3: a fold, never a door refusal), so the door admits a
        // Valid voice on a statement whose own roles name `owner_of_sub`, in
        // that role; the gate (`admission::check_second_signers_voiced`)
        // counts it only when its issuer IS the resolved owner
        // ([`resolved_second_signer_roles`]). Any other issuer's voice is
        // kept and fills no role. Drop when Verify resolves `owner_of_sub`.
        FamilyVerdict::FamilyInvalid(FamilyFault::IssNotInRole)
            if owner_of_sub_role(bytes).is_some() =>
        {
            let Some(owner_role) = owner_of_sub_role(bytes) else {
                return Err(refuse(
                    token::FAMILY_INVALID,
                    fault_label(&FamilyFault::IssNotInRole),
                ));
            };
            match verify_row_statement(bytes, keys) {
                Verdict::Valid(row) => (row, Some(owner_role)),
                Verdict::Invalid(i) => {
                    return Err(refuse(token::STATEMENT_INVALID, invalid_label(&i)));
                }
                Verdict::Waiting { missing } => return Err(waiting_at(bytes, &missing)),
            }
        }
        // v62.0.0 (SL-fix3c; CC 4.4.3.12) — a floor family's act stated in
        // the wrong form for the room it is taken in names the form the door
        // wants, so a host whose view of the room was stale knows what to
        // re-draft.
        FamilyVerdict::FamilyInvalid(FamilyFault::AuthorColumn)
            if protected
                .get_int(-70002)
                .and_then(Value::as_text)
                .is_some_and(super::typed::is_floor_family) =>
        {
            let wants = if ctx.seats == Some(1)
                && ctx.group
                    == Some(ciris_verify_core::edition2::family::select::Group::Affiliations)
            {
                "this act is COUNTED here (an affiliation with one deciding seat, CC \
                 4.4.3.12): state it with no `author`, as the seat's voice, and have a \
                 designated official add its voice over the same payload"
            } else {
                "this act is AUTHORED here (no one-seat affiliation floor applies): state it \
                 with `author` = its signer"
            };
            return Err(refuse(
                token::FAMILY_INVALID,
                format!("{}: {wants}", fault_label(&FamilyFault::AuthorColumn)),
            ));
        }
        FamilyVerdict::FamilyInvalid(f) => {
            return Err(refuse(token::FAMILY_INVALID, fault_label(&f)));
        }
        // v62.0.0 (PIN-fix5b; CIRISVerify 23.4.1) — a `withdraws` / `recants`
        // waiting ONLY on its TARGET row (`MissingKey::Row`: its leaf, and so
        // its authorship, are the target's, which is not held). The statement
        // itself must be Valid; it is admitted pending its target, and the
        // put door's FIRST gate (`ingest::check_composer_target`, inside the
        // fold attempt) holds it `link_unheld`, statement kept, reading the
        // target row: when the target lands the row re-folds and is admitted
        // again WITH its target (`SelectContext.target`), Verify's full
        // verdict. Never a missing signer key.
        FamilyVerdict::Waiting(missing)
            if !missing.is_empty() && missing.iter().all(|m| matches!(m, MissingKey::Row(_))) =>
        {
            match verify_row_statement(bytes, keys) {
                Verdict::Valid(row) => (row, None),
                Verdict::Invalid(i) => {
                    return Err(refuse(token::STATEMENT_INVALID, invalid_label(&i)));
                }
                Verdict::Waiting { missing } => return Err(waiting_at(bytes, &missing)),
            }
        }
        FamilyVerdict::Waiting(missing) => return Err(waiting_at(bytes, &missing)),
    };
    // Step 3b: the key is of the identity it signs as. Verify's reader has
    // asked the same directory already (23.3.0); this is the same answer.
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
        check_identity_set_exclusive(&row.sub, &row.payload)?;
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

/// v62.0.0 (wave V1b) — the role a member of the affiliation an owner
/// binding names fills when it voices the binding (CC 3.2 ruling (a)).
/// CC's count cell names the door `cosigned_act@subject_group`; this role
/// name is persist's (drop with the arm in `admit_row` when Verify applies
/// count cells).
pub const AFFILIATION_MEMBER_ROLE: &str = "affiliation_member";

/// v62.0.0 (wave V1b) — is `bytes` an owner binding (`ownership:*`) whose
/// payload names a community (`community_id` or one of its aliases): the
/// binding counted over the affiliation's roster (CC 3.2 ruling (a))? Read
/// from the bytes only; whether the community is an affiliation, and who is
/// on its roster, is the counted rule's (`admission::check_owner_binding_counted`).
#[must_use]
pub fn names_an_affiliation_on_the_bond(bytes: &[u8]) -> bool {
    let Some((protected, payload)) = statement_parts(bytes) else {
        return false;
    };
    let ownership = protected
        .get_int(-70002)
        .and_then(Value::as_text)
        .and_then(ciris_verify_core::namespace_match::prefix_of_family_id)
        .is_some_and(|p| p.starts_with("ownership:"));
    ownership
        && crate::federation::admission::COHORT_TARGET_ENVELOPE_FIELDS
            .iter()
            .any(|f| payload.get_text(f).and_then(Value::as_text).is_some())
}

/// v62.0.0 (K2-fix6; CC 2.6.1.9) — who fills a second-signer role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondSignerParty {
    /// This identity-ref: the CWT `sub`, or one a payload member names.
    Key(String),
    /// The owner of this key, when it is a MACHINE key (`node` / `agent`):
    /// the owner the live owner binding of the key names (`owner_of_sub`,
    /// CC 4.4.3.19, authorship_text.tsv:44). For a person's key the role does
    /// not apply. Resolved by the gate
    /// (`admission::check_second_signers_voiced`), which holds the directory.
    OwnerOf(String),
}

/// v62.0.0 (K2-fix4, K2-fix6; CC 2.7.3, CC 2.6.1.9) — one second-signer role
/// of a row, and the parties that may fill it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondSignerRole {
    /// The role's name in the family model (`bound_node`, `delegate`,
    /// `delegate_owner`, `custodian`, ...).
    pub role: String,
    /// The parties that fill it; any one of them voicing fills the role. A
    /// role naming a payload member that is absent has none: it cannot be
    /// filled, and the row waits.
    pub parties: Vec<SecondSignerParty>,
}

/// v62.0.0 (WD-fix1) — the composer row types that RETRACT their target
/// (CC 2.4.1.1): each concludes on its own author's voice and takes no
/// second-signer role from the target's family ([`second_signer_roles`]).
/// The third composer, `supersedes`, restates content and keeps the roles.
pub const RETRACTION_ROW_TYPES: &[&str] = &["withdraws", "recants"];

/// v62.0.0 (K2-fix4, K2-fix6; CC 2.6.1.9 (P2:1147): "The second consent of a
/// scoped delegates_to is a second statement over the same payload, signed
/// by the delegate, the row's sub. A scoped delegation seats only with that
/// statement."; CC 2.7.3) — **the second-signer roles of this row
/// statement, read UNDER THE ACT SELECTOR** as Verify's reader reads them
/// (`family::select::second_signers` over the vendored entries, with the
/// row's leaf and the door's context: `act` from the bytes, the typed keys).
///
/// - **act = own** (the payload carries `author`): the entries whose `when`
///   holds. `self:delegates_to` gives `delegate` = `sub`
///   (authorship_text.tsv:43) and `delegate_owner` = `owner_of_sub`
///   (authorship_text.tsv:44, [`SecondSignerParty::OwnerOf`]: Verify's model
///   drops it as unresolvable from the row; persist resolves it from the live
///   owner binding).
/// - **act = group** (no `author`: a counted row, an affiliation's counted
///   appointment, count_text.tsv:40 / authorship_text.tsv:56): no role. Its
///   own count decides it, and an appointee's consent is a separate
///   `membership:acceptance` row.
/// - a `subject` family, a family the model leaves undecided, a cell whose
///   `when` is unknown: no role. A `gap` / `target` member is not resolved.
/// - A family the vendored model registers with no `second_signers` entry
///   reads its rule's roles. (v62.0.0 VA-cc-cut: persist's own cells,
///   `occurrence::PersistCells`, are deleted; at CC b016df4
///   `identity:occurrence` lists `occurrence` / `occurrence_key_id` in the
///   vendored entries, so its role is the model's.)
#[must_use]
pub fn second_signer_roles(bytes: &[u8]) -> Vec<SecondSignerRole> {
    second_signer_roles_with(bytes, None)
}

/// v62.0.0 (PIN-fix2; CIRISVerify 23.4.1, CC rc22) — [`second_signer_roles`]
/// with a composer's TARGET: a composer (Verify's `is_composer`: `withdraws`
/// / `recants`) carries no `dimension`, so its leaf is its target's (`ciris_verify_core::edition2::family::dimension_leaf`
/// over the held target's family and payload). `None` for a composer leaves
/// the leaf unknown (a leaf-conditioned cell then names no role).
#[must_use]
pub fn second_signer_roles_with(
    bytes: &[u8],
    target: Option<&ciris_verify_core::edition2::family::TargetRow>,
) -> Vec<SecondSignerRole> {
    use ciris_verify_core::edition2::family::{
        select::{second_signers, Signers},
        vendored_family, FamilyModel as _, RoleParty, RuleAnswer, AUTHOR_IS_SUBJECT,
    };
    let Some((protected, payload)) = statement_parts(bytes) else {
        return Vec::new();
    };
    let Some(family) = protected.get_int(-70002).and_then(Value::as_text) else {
        return Vec::new();
    };
    let sub = protected
        .get_int(15)
        .and_then(|c| c.get_int(2))
        .and_then(Value::as_text)
        .map(str::to_owned);
    // v62.0.0 (PIN-fix2) — a composer's leaf is its target's, never a
    // dimension of its own (CIRISVerify 23.4.1 refuses one).
    let composer = protected
        .get_int(-70001)
        .and_then(Value::as_text)
        .is_some_and(ciris_verify_core::edition2::is_composer);
    let leaf = if composer {
        target.and_then(|t| {
            ciris_verify_core::edition2::family::dimension_leaf(&t.family_id, &t.payload)
        })
    } else {
        payload
            .get_text("dimension")
            .and_then(Value::as_text)
            .and_then(|d| {
                let prefix = ciris_verify_core::namespace_match::prefix_of_family_id(family)?;
                ciris_verify_core::namespace_match::bind_leaf(prefix, d)
                    .ok()
                    .map(|b| b.leaf)
            })
    };
    // v62.0.0 (WD-fix1; CC 2.4.1.1 / CC 3.2.3 rules 1–4) — a RETRACTION
    // composer (`withdraws`, `recants`) carries its TARGET's family and sub
    // but is its own author's act: it takes NO second-signer role from the
    // target's family. WHO may author it is the withdraws admission rules'
    // (the producer, a listed subject, the consent-revocation proxies, a
    // holder's resignation), never the target family's voice roles. A
    // COUNTED withdrawal (no author, act = group) is untouched: it falls to
    // the group carve-out below and keeps its count (`check_counted_withdrawal`).
    // `supersedes` is a composer too but restates content, so it keeps the
    // family's roles.
    let row_type = protected.get_int(-70001).and_then(Value::as_text);
    if row_type.is_some_and(|t| RETRACTION_ROW_TYPES.contains(&t)) {
        return Vec::new();
    }
    let ctx = door_context(bytes, SelectContext::default());
    // CC's carve-out: a group act (a counted row) has no second signer.
    if ctx.act != Some(Act::Own) {
        return Vec::new();
    }
    let model = VendoredFamilyModel;
    let RuleAnswer::Rule(rule) = model.rule_for(family, leaf.as_deref(), &ctx) else {
        return Vec::new();
    };
    if !rule.authored
        || rule
            .roles
            .iter()
            .any(|(r, p)| r == AUTHOR_IS_SUBJECT && *p == RoleParty::Sub)
    {
        return Vec::new();
    }
    // (role, member): the vendored entries under the selector, else the
    // rule's own roles.
    let entries: Vec<(String, String)> = match vendored_family(family) {
        Some(f) => match second_signers(&f.second_signers, leaf.as_deref(), &ctx) {
            Signers::Roles(rs) => rs
                .into_iter()
                .map(|e| (e.role.clone(), e.member.clone()))
                .collect(),
            Signers::Unknown => Vec::new(),
        },
        None => rule
            .roles
            .iter()
            .map(|(r, p)| {
                let m = match p {
                    RoleParty::Sub => "sub".to_owned(),
                    RoleParty::Member(m) => m.clone(),
                };
                (r.clone(), m)
            })
            .collect(),
    };
    let named = |m: &str| -> Vec<SecondSignerParty> {
        match payload.get_text(m) {
            Some(Value::Text(t)) => vec![SecondSignerParty::Key(t.clone())],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_text)
                .map(|t| SecondSignerParty::Key(t.to_owned()))
                .collect(),
            _ => Vec::new(),
        }
    };
    entries
        .into_iter()
        .filter_map(|(role, member)| {
            let parties = match member.as_str() {
                "sub" => sub
                    .clone()
                    .map(SecondSignerParty::Key)
                    .into_iter()
                    .collect(),
                "owner_of_sub" => sub
                    .clone()
                    .map(SecondSignerParty::OwnerOf)
                    .into_iter()
                    .collect(),
                // Not resolvable by the row's statement and not asked of
                // persist by CC: never required here.
                "gap" | "target" => return None,
                m => named(m),
            };
            Some(SecondSignerRole { role, parties })
        })
        .collect()
}

/// v62.0.0 (K2-fix12; CC 2.6.1.9, authorship_text.tsv:44) — the name of
/// the role of `bytes` filled by the owner of its machine sub
/// ([`SecondSignerParty::OwnerOf`]; `delegate_owner` on `self:delegates_to`),
/// read from the statement alone ([`second_signer_roles`]). `None` when the
/// row's roles name no `owner_of_sub`.
#[must_use]
pub fn owner_of_sub_role(bytes: &[u8]) -> Option<String> {
    second_signer_roles(bytes)
        .into_iter()
        .find(|r| {
            r.parties
                .iter()
                .any(|p| matches!(p, SecondSignerParty::OwnerOf(_)))
        })
        .map(|r| r.role)
}

/// v62.0.0 (K2-fix6; CC 2.6.1.9, authorship_text.tsv:43–44, CC 4.4.3.19)
/// — **THE answer to "who must voice this row"**: [`second_signer_roles`]
/// with every party RESOLVED to an identity-ref. It is the one source of
/// truth: the gate (`admission::check_second_signers_voiced`) counts against
/// it, and a producer or fixture voices exactly these roles.
///
/// - `Key(k)` stays `k`.
/// - `OwnerOf(sub)` (`delegate_owner = owner_of_sub`, REQUIRED for a
///   machine-key sub by CC :44): for a `node` / `agent` sub, the owner of
///   its LIVE owner binding: an agent's from its edition-2 agent owner
///   binding at the row's `asserted_at` (`admission::agent_owner_of`, the
///   owner P8's delegate-voice listing names too), else `admission::owner_of`. No owner,
///   or an ambiguous one, leaves the role with NO party: reported
///   unfillable, and the row holds. A person's sub has no owner role, so the
///   role is not listed.
///
/// Declares the fold read `key:<sub>`, so a held row re-folds when an owner
/// binding about its sub lands or is withdrawn (a no-op outside a fold
/// attempt).
///
/// # Errors
/// Directory reads.
pub async fn resolved_second_signer_roles<F>(
    dir: &F,
    bytes: &[u8],
) -> Result<Vec<SecondSignerRole>, Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let asserted_at_ms = statement_parts(bytes)
        .and_then(|(_, p)| p.get_text("asserted_at").and_then(Value::as_u64))
        .unwrap_or(u64::MAX);
    let mut out = Vec::new();
    // v62.0.0 (PIN-fix2) — a composer's roles read its held target's leaf.
    let target = super::typed::held_target_row(dir, bytes).await?;
    for r in second_signer_roles_with(bytes, target.as_ref()) {
        let mut parties = Vec::new();
        let mut applies = r.parties.is_empty();
        for p in r.parties {
            match p {
                SecondSignerParty::Key(k) => {
                    applies = true;
                    parties.push(SecondSignerParty::Key(k));
                }
                SecondSignerParty::OwnerOf(sub) => {
                    if !super::occurrence::is_machine_key(dir, &sub).await? {
                        continue;
                    }
                    applies = true;
                    super::fold::reads(super::fold::Dep::key(&sub));
                    // K2-fix7 — the same owner P8's delegate-voice listing
                    // names (one answer): an AGENT's owner from its
                    // edition-2 agent owner binding at the row's instant
                    // (`agent_owner_of`), else (a node, or an agent bound the
                    // node way) the live owner binding (`owner_of`).
                    let owner = match agent_owner(dir, &sub, asserted_at_ms).await {
                        Ok(Some(o)) => Ok(Some(o)),
                        Ok(None) => crate::federation::admission::owner_of(dir, &sub).await,
                        Err(e) => Err(e),
                    };
                    match owner {
                        Ok(Some(owner)) => parties.push(SecondSignerParty::Key(owner)),
                        Ok(None) | Err(Error::AmbiguousNodeOwner { .. }) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        if applies {
            // v62.0.0 (P8-fix5) — every party it names is a fold read: the
            // held row re-folds when a row by or about that key lands (its
            // voice), and `ceg_fold_reads` indexes the row under each key it
            // waits for, so `second_signer_voice::held_rows_for` finds it by
            // the awaited key, never by a scan of the held set.
            for p in &parties {
                if let SecondSignerParty::Key(k) = p {
                    super::fold::reads(super::fold::Dep::key(k));
                }
            }
            out.push(SecondSignerRole {
                role: r.role,
                parties,
            });
        }
    }
    Ok(out)
}

/// K2-fix7 — `admission::agent_owner_of` for an `agent` key, else `None`.
async fn agent_owner<F>(dir: &F, key: &str, at_ms: u64) -> Result<Option<String>, Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    use crate::federation::types::identity_type;
    let is_agent = dir
        .lookup_public_key(key)
        .await?
        .is_some_and(|k| identity_type::set_contains(&k.identity_type, identity_type::AGENT));
    if !is_agent {
        return Ok(None);
    }
    crate::federation::admission::agent_owner_of(dir, key, at_ms).await
}

/// The family of a `delegates_to` that is not an owner binding or another
/// purpose-specific family (RULINGS, *delegates_to families*).
pub const SELF_DELEGATES_TO_FAMILY_PREFIX: &str = "self:delegates_to";

/// Step 3b of the door: `kid` must be a key of `iss` (module docs). Every
/// place the door resolves a signer calls this after Verify's verdict: rows,
/// each counted voice, objects, the halt. It asks the directory's
/// `KeyDirectory::key_of`, the question Verify's row reader asks itself
/// (CIRISVerify 23.3.0), so the two give one answer; an object statement is
/// not asked by Verify, and is asked here.
///
/// # Errors
/// [`token::KID_NOT_OF_ISS`]; the retryable unknown-signer error naming a
/// missing link.
pub fn require_key_of_iss(keys: &dyn KeyDirectory, kid: &Digest32, iss: &str) -> Result<(), Error> {
    let Some(genesis) = super::ingest::kid_of_identity_ref(iss) else {
        return Err(kid_not_of_iss(Some(kid), iss));
    };
    if genesis == *kid {
        return Ok(());
    }
    match keys.key_of(kid, &genesis) {
        KeyOf::Yes => Ok(()),
        KeyOf::Waiting(missing) => Err(waiting(&missing)),
        // `No`, and any answer a later Verify adds: fail closed.
        _ => Err(kid_not_of_iss(Some(kid), iss)),
    }
}

/// The roles of a `key:record` payload's `identity_type` (text members).
fn identity_roles(payload: &Value) -> Vec<String> {
    payload
        .get_text("identity_type")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_text)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// v62.0.0 (JSON-cut slice A; CC 2.4.1.1, CC 4.5.8) — **the identity-set
/// exclusion on an edition-2 `key:record`**, the same rule the earlier
/// doors keep (`register::check_node_identity_exclusive`): `node` never
/// cohabits with `agent` or `user` ([`Error::NodeIdentityNotExclusive`]),
/// and `user` / `accord_holder` never with `node` / `agent`
/// ([`Error::IdentitySetMixesPersonAndMachine`]). Verify's end rule refuses
/// only a person-with-machine mix; `node` with `agent` is persist's.
///
/// # Errors
/// As above.
pub fn check_identity_set_exclusive(sub: &str, payload: &Value) -> Result<(), Error> {
    use crate::federation::types::identity_type as it;
    let roles = identity_roles(payload);
    let has = |t: &str| roles.iter().any(|r| r == t);
    let joined = || roles.join(",");
    if has(it::NODE) && (has(it::AGENT) || has(it::USER)) {
        return Err(Error::NodeIdentityNotExclusive {
            key_id: sub.to_owned(),
            identity_type: joined(),
        });
    }
    if (has(it::USER) || has(it::ACCORD_HOLDER)) && (has(it::NODE) || has(it::AGENT)) {
        return Err(Error::IdentitySetMixesPersonAndMachine {
            key_id: sub.to_owned(),
            identity_type: joined(),
        });
    }
    Ok(())
}

/// v62.0.0 (kernel pass 2, K1; CC ruling: a record covers `t` when
/// `asserted_at <= t < valid_until`, half-open everywhere) — **a stated
/// window covers some instant.** A payload of any family (`key:record` and
/// every family carrying a `valid_until` member) that states `valid_until`
/// at or before its own `asserted_at` is refused
/// `valid_until_not_after_asserted_at`
/// ([`crate::federation::malformed_row::VALID_UNTIL_NOT_AFTER_ASSERTED_AT`]).
/// A payload that states no `valid_until`, or no readable `asserted_at`,
/// is not judged here (its family's own member rules are).
///
/// # Errors
/// The malformed-row refusal above.
pub fn check_valid_until_after_asserted_at(payload: &Value) -> Result<(), Error> {
    let at = payload.get_text("asserted_at").and_then(Value::as_u64);
    let until = payload.get_text("valid_until").and_then(Value::as_u64);
    match (at, until) {
        (Some(at), Some(until)) if until <= at => Err(refuse(
            crate::federation::malformed_row::VALID_UNTIL_NOT_AFTER_ASSERTED_AT,
            format!(
                "valid_until {until} is not after asserted_at {at}: the window \
                 [asserted_at, valid_until) covers no instant"
            ),
        )),
        _ => Ok(()),
    }
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
/// mesh") — **THE switch that shuts the earlier-form doors.** Slice F
/// flipped it to `true`, in this one place: every door wired to
/// [`refuse_earlier_form`] refuses an earlier-form object by name
/// ([`token::EARLIER_FORM_OBJECT`]), before any parse or verify
/// (I2870–I2873). `scripts/earlier_form_doors.py` holds the wiring from
/// disk: a write door that takes an object and does not reach the refusal
/// is red.
pub const EARLIER_FORM_DOORS_SHUT: bool = true;

/// Is the earlier form shut at this node's doors? v62.0.0 (slice F): always,
/// in this edition. The test-only scope that forced it on before the flip
/// (`with_earlier_form_doors_shut`) is deleted with the open state it
/// overrode.
#[must_use]
pub fn earlier_form_doors_shut() -> bool {
    EARLIER_FORM_DOORS_SHUT
}

/// v62.0.0 (F0-cp7; RULINGS "composite signatures only, no standalone
/// component signers") — **the refusal of an earlier-form, bound-hybrid
/// signature** (an Ed25519 half plus an ML-DSA-65 half over `msg ‖
/// ed25519_sig`, verified against a key's registered component halves). The
/// bound-hybrid verify family (`verify_hybrid`, `verify_hybrid_via_directory`,
/// `verify_hybrid_with_policy`) is DELETED; a door that still receives such a
/// signature answers this, by name (`earlier_form_object`), whatever the
/// switch says. A signature is ONE composite under a LIVE edition-2 key
/// (`composite_verify`), or a CC 6.1 composite over its own preimage
/// (`verify::sig19`).
#[must_use]
pub fn earlier_form_signature(plane: &'static str) -> Error {
    Error::malformed_row(
        plane,
        token::EARLIER_FORM_OBJECT,
        format!(
            "an earlier-form (bound-hybrid Ed25519 + ML-DSA-65) signature at the `{plane}` \
             door: v62 verifies ONE composite signature under a live edition-2 key and no \
             standalone component signature (RULINGS); offer the edition-2 statement \
             (CC 2.6.1.12)"
        ),
    )
}

/// v62.0.0 (BH-fix2; Verify's ruling) — the plane name of the skill-import
/// manifest refusal ([`skill_import_manifest_refusal`]).
pub const SKILL_IMPORT_PLANE: &str = "skill_import";

/// v62.0.0 (BH-fix2; RULINGS "composite signatures only"; Verify's ruling) —
/// **the refusal of a skill-import manifest.** Verify's `SkillImportManifest`
/// is the earlier bound-pair form: an Ed25519 signature plus an ML-DSA-65
/// signature over its JSON, checked against a steward key pair the caller
/// passes in. It has no composite successor: in edition 2 a skill import is
/// a ROW, family `provenance:skill_import:{source}`, ONE composite
/// `COSE_Sign1` statement through the statement door. The host verb
/// (`verify_skill_import_manifest_b64`) stays, refusing with this by name
/// (`earlier_form_object`), so a caller gets a named error rather than a
/// missing method.
#[must_use]
pub fn skill_import_manifest_refusal() -> Error {
    Error::malformed_row(
        SKILL_IMPORT_PLANE,
        token::EARLIER_FORM_OBJECT,
        "a skill_import manifest is the earlier bound-pair form (a separate Ed25519 + \
         ML-DSA-65 signature over its JSON): v62 verifies no separate pair; edition 2 carries a \
         skill import as a provenance:skill_import:{source} row, one composite COSE_Sign1 \
         statement (CC 3.1.2, CC 2.6.1.12)",
    )
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
    // v62.0.0 (wave T1) — a group statement's typed record running the typed
    // door under the edition-2 door's vouch is no earlier-form object: its
    // proof is its statements (`edition2::group`).
    if earlier_form_doors_shut() && !super::group::vouched() {
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
