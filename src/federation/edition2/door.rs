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
    select::Act, verify_row_in_family_with, FamilyFault, FamilyVerdict, SelectContext, WithVendored,
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
        other => format!("{other:?}"),
    }
}

/// Verify's family fault as a stable label for the refusal's message.
#[must_use]
pub fn fault_label(f: &FamilyFault) -> &'static str {
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
            other => format!("{other:?}"),
        })
        .unwrap_or_else(|| "<unnamed key>".to_owned());
    Error::unknown_signer(&named, PLANE)
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
    // v62.0.0 (wave O1; R1b, CIRISVerify 23.3.1) — persist's own cells first
    // (`occurrence::PersistCells`: the occurrence key's own voice on
    // `identity:occurrence`, CC rc21 90d537b; drop at 23.3.2), then CC's
    // vendored model (`WithVendored`).
    let model = WithVendored(&super::occurrence::PersistCells);
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
                Verdict::Waiting { missing } => return Err(waiting(&missing)),
            }
        }
        // v62.0.0 (R1; CIRISVerify 23.3.1, CC 4.4.3.12 "two consents") —
        // an affiliation's officer appointment (a `self:delegates_to` with no
        // `author`) reads counted under rc21-wire's vendored arm
        // `act=group => counted` ([`door_context`] derives `act` from
        // `author`), so Verify's verdict is `Valid { role: None }` and the
        // persist-side `author_column` override is gone. The counted rule
        // (`admission::check_officer_appointment_counted`) still counts it.
        FamilyVerdict::FamilyInvalid(f) => {
            return Err(refuse(token::FAMILY_INVALID, fault_label(&f)));
        }
        FamilyVerdict::Waiting(missing) => return Err(waiting(&missing)),
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
