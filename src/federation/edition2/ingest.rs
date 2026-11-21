//! The edition-2 statement at persist's doors: **one rule set, two codecs**
//! (slice E2a, CIRISPersist#1274, the coordinator's Q1 ruling).
//!
//! An edition-2 row statement is judged by the edition-2 door
//! ([`super::door::admit_row`]): its form, its edition-2 names, Verify's
//! verdict, the node-computed row id and the key record's end rule. It is
//! then MAPPED onto persist's typed [`Attestation`] ([`attestation_of`]), and
//! that row meets exactly the admission gates the JSON door runs
//! (`plan_put_attestation`). No gate is copied. The mapped row carries its
//! statement in the envelope member [`STATEMENT_MEMBER`]. Wherever the gates
//! would read the earlier form's proof, they read the carried statement's
//! instead:
//! - **tier 2** reads the signer's `identity_type` from its live edition-2
//!   `key:record` ([`carried_identity_type`]), never from `federation_keys`.
//!   An edition-2 key has no row there: the earlier store gives it no
//!   standing (CC 2.6.1.12).
//! - **tier 3** re-verifies the carried statement and checks that the mapped
//!   row is exactly its projection ([`verify_carried`]). An envelope that
//!   names a statement it is not the projection of is refused
//!   `typed_diverges_from_envelope`.
//! - **the stored id**: `attestation_id` and `persist_row_hash` are both the
//!   row id this node computed. A row is never stored under a given id.
//!
//! A key's own rows (`key:record`, `key:revocation`) are the edition-2 key
//! plane. They are kept in `ceg_statements`, and every edition-2 gate reads
//! them from there ([`held_keys_for`]). v62.0.0 (slice J0): each is then
//! PROJECTED into the earlier store as a read model
//! ([`super::projection`]): the key into `federation_keys` (`edition = 2`),
//! its honoured revocations into `federation_revocations`. The projection is
//! what the attestation signer FKs and the earlier-form readers
//! (`revocations_for`, `lookup_public_key`) see; no edition-2 gate reads it.
//!
//! [`put_statement`] is the one entry for a statement, local or replicated:
//! the Engine's `put_edition2_statement`, replication and tier ingest all
//! call it.

use std::collections::{BTreeSet, VecDeque};

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY;
use ciris_verify_core::edition2::{identity_ref, Digest32};
use sha2::Digest as _;

use super::door::{admit_row, AdmittedRow, PLANE};
use super::liveness::{statement_parts, HeldKeys, Liveness, KEY_REVOCATION_FAMILY};
use crate::federation::types::{attestation_tier, Attestation};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The envelope member a mapped row carries its statement under: the
/// statement's bytes as received, lowercase hex (CC 2.6.3).
pub const STATEMENT_MEMBER: &str = "ceg_statement";

/// The envelope member the earlier gates read a composer's target from.
pub const REFERENCES_MEMBER: &str = "references_attestation_id";

/// The composer row types (CC 2.4.1.1): each names its target by
/// `refs.target` and carries the target's family.
pub const COMPOSER_ROW_TYPES: [&str; 3] = ["withdraws", "recants", "supersedes"];

/// v62.0.0 (JSON-cut slice A, I2105) — **a composer's target.** A
/// `withdraws` / `recants` / `supersedes` row names its target by
/// `refs.target`. The target must be held (else the retryable
/// `WithdrawsTargetUnheld`: an ordering gap), and the composer must carry
/// the target's family (else `composer_family_mismatch`;
/// CC-READING(next-edition)). The target's family is read from its own
/// held statement.
///
/// # Errors
/// As above; directory failures.
pub async fn check_composer_target<F>(dir: &F, row: &AdmittedRow) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if !COMPOSER_ROW_TYPES.contains(&row.row_type.as_str()) {
        return Ok(());
    }
    let Some(target) = super::names::single(&row.names, "target") else {
        // Verify's reader requires the composer's target; nothing to bind.
        return Ok(());
    };
    // v62.0.0 (wave G0 v5.1; GC1's door gap) — the target is another row:
    // an unheld one is WAITED for, never refused (CC 2.7.3); its arrival
    // re-folds this composer.
    super::fold::reads(super::fold::Dep::Row(target));
    let held = dir.edition2_voices(&target).await?;
    let family = held.iter().find_map(|st| {
        statement_parts(st).and_then(|(h, _)| {
            h.get_int(-70002)
                .and_then(Value::as_text)
                .map(str::to_owned)
        })
    });
    let Some(family) = family else {
        return Err(super::fold::hold(
            super::fold::reason::LINK_UNHELD,
            Error::WithdrawsTargetUnheld {
                attestation_id: row.row_id.hex(),
                target_attestation_id: target.hex(),
            },
        ));
    };
    if family != row.family {
        // Held too: read from another row, so the verdict must not depend
        // on whether the target arrived first.
        return Err(super::fold::hold(
            super::fold::reason::COMPOSER_FAMILY_MISMATCH,
            Error::malformed_row(
                PLANE,
                malformed_row::COMPOSER_FAMILY_MISMATCH,
                format!(
                    "the {} row {} carries family `{}`, but its target {} is of `{family}`: a \
                 composer carries its target's family",
                    row.row_type,
                    row.row_id.hex(),
                    row.family,
                    target.hex()
                ),
            ),
        ));
    }
    Ok(())
}

/// The payload's instant members (CC 2.6.2), projected as RFC 3339 text.
pub const INSTANT_MEMBERS: &[&str] = &[
    "asserted_at",
    "valid_from",
    "valid_until",
    "expires_at",
    "revoked_after",
];

/// The payload's fixed-scale members (CC 2.6.1.5), projected as reals.
pub const SCALED_MEMBERS: &[&str] = &["score", "confidence", "weight"];

/// v62.0.0 (JSON-cut slice B; wave P1) — the payload's hash-digest members
/// (CC 2.6.1: `[-16, bstr .size 32]`, SHA-256), projected as the
/// 64-lowercase-hex text the earlier gates read: `evidence_refs` is a
/// sequence of them, the others one. The list is
/// [`super::payloads::HASH_DIGEST_MEMBERS`] (slice A owns member typing); it
/// carries `amendment_digest` (`deferral:response:approved`,
/// `identity_amendment`), whose hex the identity-amendment gate compares.
pub use super::payloads::HASH_DIGEST_MEMBERS;

/// How far a chain of key records is followed when loading a signer's keys.
const MAX_KEY_HOPS: usize = 8;

/// The `kid` a statement names in its protected header (label 4).
#[must_use]
pub fn statement_kid(bytes: &[u8]) -> Option<Digest32> {
    let (protected, _) = statement_parts(bytes)?;
    <[u8; 32]>::try_from(protected.get_int(4)?.as_bytes()?).ok()
}

/// The edition-2 key plane a statement's signer resolves through: every
/// held `key:record` and `key:revocation` about its kid, and about the kid
/// of each key that signed one of those, to [`MAX_KEY_HOPS`].
///
/// # Errors
/// Directory read failures.
pub async fn held_keys_for<F>(dir: &F, statement: &[u8]) -> Result<HeldKeys, Error>
where
    F: FederationDirectory + ?Sized,
{
    match statement_kid(statement) {
        Some(kid) => {
            let held = held_keys_for_kid(dir, &kid).await?;
            // v62.0.0 (wave O1, I3020; the rc21 rule) — the key-of-issuer
            // check's occurrence arm: the signer as a live occurrence of its
            // `iss` at the statement's instant.
            let seats = super::occurrence::occurrence_seats_for(dir, statement).await?;
            Ok(held.with_occurrences(seats))
        }
        None => Ok(HeldKeys::new()),
    }
}

/// The edition-2 key plane of one key: every held `key:record` and
/// `key:revocation` about `kid`, and about the kid of each key that signed
/// one of those (a revoker's own records, so its revocation can be read), to
/// [`MAX_KEY_HOPS`].
///
/// # Errors
/// Directory read failures.
pub async fn held_keys_for_kid<F>(dir: &F, first: &Digest32) -> Result<HeldKeys, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut held = HeldKeys::new();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([*first]);
    while let Some(kid) = queue.pop_front() {
        if !seen.insert(kid) || seen.len() > MAX_KEY_HOPS {
            continue;
        }
        let subject = identity_ref(&kid);
        for st in dir
            .edition2_statements_about(KEY_RECORD_FAMILY, &subject)
            .await?
        {
            // v62.0.0 (wave G0 fix2) — a `key:record` is the signer's own
            // key plane: a DOOR input, never held by the fold, so none is
            // skipped here (only a held-back revocation is, below).
            if let Some(signer) = statement_kid(&st) {
                if signer != kid {
                    queue.push_back(signer);
                }
            }
            // v62.0.0 (JSON-cut slice A, I2101) — a record naming a
            // predecessor's record: the other records naming it are loaded
            // too, so a rival rotation of the same predecessor is seen
            // (`HeldKeys::key_of`, rule 5).
            if let Some(target) = record_target(&st) {
                for rival in dir.edition2_rows_naming(&target, "target").await? {
                    for v in dir.edition2_voices(&rival).await? {
                        if is_key_record(&v) && !held.holds(&v) {
                            held.insert_record(v);
                        }
                    }
                }
            }
            held.insert_record(st);
        }
        for st in dir
            .edition2_statements_about(KEY_REVOCATION_FAMILY, &subject)
            .await?
        {
            // v62.0.0 (wave G0 v4) — a held-back revocation does not count
            // in liveness until it concludes.
            if super::fold::is_held_back(dir, &st).await? {
                continue;
            }
            if let Some(signer) = statement_kid(&st) {
                if signer != kid {
                    queue.push_back(signer);
                }
            }
            held.insert_revocation(st);
        }
    }
    Ok(held)
}

/// The record a `key:record` statement names by `refs.target`, if any.
fn record_target(statement: &[u8]) -> Option<super::names::RowId> {
    let (_, payload) = statement_parts(statement)?;
    super::names::single(&super::names::names_of(&payload).ok()?, "target")
}

/// Is this statement of the family `key:record`?
pub(crate) fn is_key_record(statement: &[u8]) -> bool {
    statement_parts(statement)
        .is_some_and(|(p, _)| p.get_int(-70002).and_then(Value::as_text) == Some(KEY_RECORD_FAMILY))
}

/// The kid an identity-ref names (RFC 9679 §5.7: the base64url thumbprint
/// after the prefix). `None` for text that is not an identity-ref.
#[must_use]
pub fn kid_of_identity_ref(s: &str) -> Option<Digest32> {
    use base64::Engine as _;
    if !ciris_verify_core::edition2::is_identity_ref(s) {
        return None;
    }
    let t = s.strip_prefix(ciris_verify_core::edition2::IDENTITY_REF_PREFIX)?;
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(t)
        .ok()?;
    <[u8; 32]>::try_from(b.as_slice()).ok()
}

/// A CBOR payload value as the JSON the earlier-form gates read: text as a
/// string, integers as numbers, bytes as lowercase hex (CC 2.6.3), arrays
/// and text-keyed maps as themselves.
#[must_use]
pub fn json_of(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Uint(n) => J::from(*n),
        Value::Nint(n) => i64::try_from(*n)
            .ok()
            .and_then(|n| n.checked_add(1))
            .map_or_else(|| J::String(format!("-1-{n}")), |n| J::from(-n)),
        Value::Bytes(b) => J::String(hex::encode(b)),
        Value::Text(t) => J::String(t.clone()),
        Value::Array(a) => J::Array(a.iter().map(json_of).collect()),
        Value::Map(m) => J::Object(
            m.iter()
                .map(|(k, v)| {
                    let key = match k {
                        Value::Text(t) => t.clone(),
                        other => format!("{other:?}"),
                    };
                    (key, json_of(v))
                })
                .collect(),
        ),
        Value::Bool(b) => J::Bool(*b),
        Value::Null => J::Null,
        // v62.0.0 (wave P1e; lead's ruling; P1-fix6) — a normalised tag-4
        // decimal (a body number: a ledger balance, a free-form body's real)
        // reads back as its EXACT JSON number
        // (`payloads::json_number_of_decimal`), so the earlier readers (the
        // ledger projection's `as_f64`) see a number; any other tag keeps the
        // tagged form.
        Value::Tag(4, _) if super::payloads::json_number_of_decimal(v).is_some() => {
            super::payloads::json_number_of_decimal(v).map_or(J::Null, J::Number)
        }
        Value::Tag(t, inner) => serde_json::json!({ "tag": t, "value": json_of(inner) }),
        Value::Simple(s) => serde_json::json!({ "simple": s }),
    }
}

/// A fixed6 payload member (CC 2.6.1.5: the value times 10^6, an integer)
/// as the real the earlier form's gates and the typed columns read.
fn fixed6_real(payload: &Value, member: &str) -> Option<f64> {
    let n = payload.get_text(member).and_then(Value::as_i64)?;
    #[allow(clippy::cast_precision_loss)]
    let real = n as f64 / 1_000_000.0;
    Some(real)
}

fn ms_instant(ms: u64) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .ok_or_else(|| {
            Error::malformed_row(
                PLANE,
                malformed_row::EDITION2_STATEMENT_INVALID,
                "malformed:asserted_at (out of range)",
            )
        })
}

/// **The mapping**: an admitted edition-2 row as persist's typed row, the
/// one the JSON door's gates read.
///
/// - `attestation_id` and `persist_row_hash` are the node-computed row id
///   (hex).
/// - `attesting_key_id` / `scrub_key_id` are `iss`; `attested_key_id` is
///   `sub`; `attestation_type` is the row type.
/// - `asserted_at` / `scrub_timestamp` come from `asserted_at` (ms), and
///   `expires_at` from `expires_at`; `weight` from the fixed6 `weight`
///   (`None` when absent).
/// - the envelope is the payload's projection ([`json_of`]) plus the
///   statement under [`STATEMENT_MEMBER`]. `original_content_hash` is the
///   SHA-256 of the envelope's JCS image, as every row's is.
/// - `scrub_signature_classical` holds the statement's composite signature
///   (base64), for the earlier store's `federation ⟹ signed` check. The
///   proof is the carried statement.
///
/// # Errors
/// An instant out of range; an envelope that does not canonicalize.
pub fn attestation_of(row: &AdmittedRow, tier: &str) -> Result<Attestation, Error> {
    let mut envelope = json_of(&row.payload);
    if let Some(o) = envelope.as_object_mut() {
        // Instants are POSIX ms in the payload (CC 2.6.2); the gates read the
        // text form CC 2.6.3 gives an instant outside a payload:
        // `YYYY-MM-DDTHH:MM:SS.sssZ`.
        for member in INSTANT_MEMBERS {
            if let Some(ms) = row.payload.get_text(member).and_then(Value::as_u64) {
                o.insert(
                    (*member).to_owned(),
                    serde_json::Value::String(
                        ms_instant(ms)?.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    ),
                );
            }
        }
        // v62.0.0 (wave P1e, E10's finding) — hash digests (`[-16, h'..']`)
        // read back as the 64-lowercase-hex text every earlier-form reader
        // reads (`steward_purge`'s `evidence_refs`, the blob bindings, ...):
        // one digest as its hex, a sequence of them as an array of hex. The
        // members are every family's `HASH_DIGEST_MEMBERS` and the family's
        // own digest members (`payloads::is_digest_member`), so the mapping
        // has one list, the door's.
        if let Some(members) = row.payload.as_map() {
            for (k, v) in members {
                let Some(k) = k.as_text() else { continue };
                if super::payloads::is_digest_member(&row.family, k) {
                    if let Some(j) = super::payloads::digest_json(v) {
                        o.insert(k.to_owned(), j);
                    }
                }
            }
        }
        // Scores, confidences and weights are integers at the fixed scale of
        // 10^6 (CC 2.6.1.5); the earlier form's gates read the real value.
        for member in SCALED_MEMBERS {
            if let Some(real) = fixed6_real(&row.payload, member) {
                o.insert((*member).to_owned(), serde_json::json!(real));
            }
        }
        // v62.0.0 (JSON-cut slice A) — the row a composer (or any row)
        // names by `refs.target` is the earlier gates'
        // `references_attestation_id`: the node-computed row id, never a
        // peer's string.
        if let Some(target) = super::names::single(&row.names, "target") {
            o.insert(
                REFERENCES_MEMBER.to_owned(),
                serde_json::Value::String(target.hex()),
            );
        }
        // v62.0.0 (wave P1e; CC rc21) — the members that name a row live under
        // a `refs` role (`payloads::REF_MEMBERS`): the earlier gates read
        // each back as its earlier member, the node-computed row id(s) as
        // lowercase hex (an amendment's `authorized_by` / `evidence_refs`
        // from `refs.also.cites`; a deferral response's
        // `references_attestation_id` from `refs.answers`).
        for (role, member, shape) in super::payloads::ref_members(&row.family) {
            let ids: Vec<String> = row
                .names
                .iter()
                .filter(|n| n.role == role)
                .map(|n| n.row.hex())
                .collect();
            if ids.is_empty() {
                continue;
            }
            let v = match shape {
                super::payloads::RefShape::One if ids.len() == 1 => {
                    serde_json::Value::String(ids[0].clone())
                }
                // A set where one row is expected is left unprojected: the
                // door refuses it (the family's prose rule), and nothing
                // reads a guessed one.
                super::payloads::RefShape::One => continue,
                super::payloads::RefShape::Many => serde_json::json!(ids),
            };
            o.insert(member.to_owned(), v);
        }
        // v62.0.0 (wave T2) — a typed plane's row reads back under the
        // earlier envelope's member names its JSON door's gates read
        // (`edition2::typed::project_envelope`); every other row is untouched.
        super::typed::project_envelope(row, o);
        o.insert(
            STATEMENT_MEMBER.to_owned(),
            serde_json::Value::String(hex::encode(&row.bytes)),
        );
    }
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| Error::InvalidArgument(format!("edition-2 envelope canonicalize: {e}")))?;
    let asserted_at = ms_instant(row.asserted_at_ms)?;
    let expires_at = row
        .payload
        .get_text("expires_at")
        .and_then(Value::as_u64)
        .map(ms_instant)
        .transpose()?;
    let subject_key_ids: Vec<String> = row
        .payload
        .get_text("subject_key_ids")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_text)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut v = serde_json::json!({
        "attestation_id": row.row_id.hex(),
        "attesting_key_id": row.iss,
        "attested_key_id": row.sub,
        "attestation_type": row.row_type,
        "asserted_at": asserted_at,
        "attestation_envelope": envelope,
        "original_content_hash": hex::encode(sha2::Sha256::digest(&canonical)),
        "scrub_signature_classical": composite_signature_b64(&row.bytes),
        "scrub_key_id": row.iss,
        "scrub_timestamp": asserted_at,
        "persist_row_hash": row.row_id.hex(),
        "tier": tier,
    });
    if let Some(e) = expires_at {
        v["expires_at"] = serde_json::json!(e);
    }
    if !subject_key_ids.is_empty() {
        v["subject_key_ids"] = serde_json::json!(subject_key_ids);
    }
    if let Some(c) = row
        .payload
        .get_text("cohort_scope")
        .and_then(Value::as_text)
    {
        v["cohort_scope"] = serde_json::json!(c);
    }
    let mut a: Attestation = serde_json::from_value(v)
        .map_err(|e| Error::InvalidArgument(format!("edition-2 mapping: {e}")))?;
    // v62.0.0 (wave P1c, E1's finding) — the typed `weight` column is the
    // payload's fixed6 `weight` (CC 2.6.1.5), as the envelope's real; `None`
    // when the payload carries none. Before this every edition-2 row stored
    // NULL, and the weighted folds (`topology`, `trust_scoring`:
    // `weight.unwrap_or(1.0)`) read every edge at 1.0.
    a.weight = fixed6_real(&row.payload, "weight");
    // The earlier form's `row` mirror (CIRISPersist#643) is what its gates
    // read to bind the columns. An edition-2 statement binds them itself: its
    // protected header and payload ARE the row (CC 2.6.1.1, "no mirror of the
    // row inside the bytes"). So the projection writes the mirror from the
    // verified statement, and `verify_carried` checks it equals.
    let mut mirror = serde_json::json!({
        "attestation_id": a.attestation_id,
        "attesting_key_id": a.attesting_key_id,
        "attestation_type": a.attestation_type,
        "attested_key_id": a.attested_key_id,
        "cohort_scope": a.cohort_scope,
    });
    if !a.subject_key_ids.is_empty() {
        mirror["subject_key_ids"] = serde_json::json!(a.subject_key_ids);
    }
    // The mirror binds `weight` both ways (absent ⇔ column `None`,
    // `admission`'s mirror gate, compared numerically).
    if let Some(w) = a.weight {
        mirror["weight"] = serde_json::json!(w);
    }
    if let Some(o) = a.attestation_envelope.as_object_mut() {
        o.insert("row".to_owned(), mirror);
    }
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&a.attestation_envelope)
        .map_err(|e| Error::InvalidArgument(format!("edition-2 envelope canonicalize: {e}")))?;
    a.original_content_hash = hex::encode(sha2::Sha256::digest(&canonical));
    Ok(a)
}

/// The statement's composite signature (its fourth member), standard
/// base64: what the earlier store's signature column holds for a mapped row
/// (its `federation ⟹ signed` check). The row's proof stays the carried
/// statement; no gate verifies this column for an edition-2 row.
fn composite_signature_b64(statement: &[u8]) -> String {
    use base64::Engine as _;
    let sig = match ciris_verify_core::cde::decode(statement) {
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

/// The statement a mapped row carries, if any.
fn carried_bytes(row: &Attestation) -> Option<Result<Vec<u8>, Error>> {
    let h = row.attestation_envelope.get(STATEMENT_MEMBER)?;
    Some(h.as_str().and_then(|s| hex::decode(s).ok()).ok_or_else(|| {
        Error::malformed_row(
            PLANE,
            malformed_row::ENVELOPE_MEMBER_INVALID,
            format!("`{STATEMENT_MEMBER}` is not lowercase hex"),
        )
    }))
}

/// **Re-verify a mapped row's carried statement** and check the row is
/// exactly its projection. `Ok(None)` for a row that carries none (an
/// earlier-form row, which the JSON gates judge as before).
///
/// # Errors
/// The edition-2 door's refusals; `typed_diverges_from_envelope` for a row
/// that is not the projection of the statement it carries.
pub async fn verify_carried<F>(dir: &F, row: &Attestation) -> Result<Option<AdmittedRow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(bytes) = carried_bytes(row) else {
        return Ok(None);
    };
    let bytes = bytes?;
    // v62.0.0 (wave P1c, AV-76) — the pure gates before the key-plane read.
    super::door::pure_statement_gates(&bytes, &HeldKeys::new())?;
    // v62.0.0 (wave O1; CC 4.2.6) — a recovery key signs no row: refused
    // after the pure gates, before any key lookup.
    Box::pin(super::recovery_signer::refuse_recovery_key_signer(
        dir, &bytes,
    ))
    .await?;
    let keys = held_keys_for(dir, &bytes).await?;
    let offered = offered_row_id(row)?;
    // v62.0.0 (T2-fix1) — the context the family's authorship cell reads.
    let ctx = super::typed::family_context(dir, &bytes).await?;
    let admitted = admit_row(&bytes, &keys, Some(&offered), ctx)?;
    require_admission_signer_is_person(&keys, &admitted)?;
    let expected = attestation_of(&admitted, &row.tier)?;
    require_projection(&expected, row)?;
    Ok(Some(admitted))
}

/// v62.0.0 (wave P1e; CC rc21 CC 2.7.11) — every signer of an
/// `admission:unit` row is a person: the signing key's live record (at the
/// row's instant) holds `user` or `accord_holder` in its `identity_type`.
/// Otherwise the statement is refused `admission_issuer_not_person` (an
/// authored row is Invalid; on a counted row this voice alone is refused).
/// A no-op for every other family. Read after Verify's verdict, over the
/// held key plane the door already loaded.
///
/// # Errors
/// `admission_issuer_not_person`.
pub fn require_admission_signer_is_person(keys: &HeldKeys, row: &AdmittedRow) -> Result<(), Error> {
    if row.family != super::payloads::ADMISSION_UNIT_FAMILY {
        return Ok(());
    }
    let person = match keys.liveness(&row.kid, row.asserted_at_ms) {
        Liveness::Live(r) => r
            .identity_type
            .iter()
            .any(|t| t == "user" || t == "accord_holder"),
        _ => false,
    };
    if person {
        return Ok(());
    }
    Err(Error::malformed_row(
        super::payloads::PLANE,
        malformed_row::ADMISSION_ISSUER_NOT_PERSON,
        format!(
            "admission:unit: the signer {} is not a person's key (identity_type holds neither \
             user nor accord_holder): no program's key admits a unit (CC 2.7.11)",
            row.iss
        ),
    ))
}

/// The row id a carrying row is stored under: 32 bytes of lowercase hex.
fn offered_row_id(row: &Attestation) -> Result<Digest32, Error> {
    hex::decode(&row.attestation_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            Error::malformed_row(
                PLANE,
                malformed_row::EDITION2_ROW_ID_MISMATCH,
                format!(
                    "a row carrying an edition-2 statement is stored under its row id, not `{}`",
                    row.attestation_id
                ),
            )
        })
}

/// `row` is exactly `expected`, the projection of the statement it carries:
/// every typed column the mapping writes, and the envelope.
fn require_projection(expected: &Attestation, row: &Attestation) -> Result<(), Error> {
    let same = expected.attestation_id == row.attestation_id
        && expected.attesting_key_id == row.attesting_key_id
        && expected.attested_key_id == row.attested_key_id
        && expected.attestation_type == row.attestation_type
        && expected.asserted_at == row.asserted_at
        && expected.subject_key_ids == row.subject_key_ids
        // v62.0.0 (wave P1c) — the weight column is the statement's too.
        && expected.weight == row.weight
        // Last: the one comparison whose cost scales with the envelope.
        && same_envelope(&expected.attestation_envelope, &row.attestation_envelope);
    if same {
        return Ok(());
    }
    Err(Error::malformed_row(
        PLANE,
        malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
        format!(
            "row {} is not the projection of the edition-2 statement it carries",
            row.attestation_id
        ),
    ))
}

/// v62.0.0 (wave P1c) — **the carried-projection pre-check**, a pure
/// function of the row: no directory read, no signature check, and no
/// canonicalization of the offered envelope. For a row carrying an edition-2
/// statement (`ceg_statement`), the row must be exactly what that statement
/// derives ([`attestation_of`]); otherwise it is refused as
/// [`verify_carried`] refuses it (`typed_diverges_from_envelope`,
/// `edition2_row_id_mismatch`, or the door's pure statement gates). `Ok`
/// for a row that carries none (an earlier-form row).
///
/// The attestation door runs it FIRST (`attestation_admit::plan_put_attestation`):
/// a carrying row's envelope is not size-capped as an earlier-form envelope
/// is (it is the statement's projection, bounded by the statement's cap), so
/// a forged envelope beside a small valid statement must be refused before
/// any gate pays for it. The derivation reads only the statement's bytes,
/// already capped by the pure gates. [`verify_carried`] still runs at tier 3
/// and checks the statement's signature and key; this is not a verdict.
///
/// # Errors
/// As above.
pub fn check_carried_projection(row: &Attestation) -> Result<(), Error> {
    let Some(bytes) = carried_bytes(row) else {
        return Ok(());
    };
    let bytes = bytes?;
    super::door::pure_statement_gates(&bytes, &HeldKeys::new())?;
    let derived = unverified_row(&bytes).ok_or_else(|| {
        Error::malformed_row(
            PLANE,
            malformed_row::EDITION2_STATEMENT_INVALID,
            "the carried statement has no row header (type, family, iss, sub) or payload",
        )
    })?;
    let offered = offered_row_id(row)?;
    if offered != derived.row_id.0 {
        return Err(Error::malformed_row(
            PLANE,
            malformed_row::EDITION2_ROW_ID_MISMATCH,
            format!(
                "row {} carries a statement whose row id is {}",
                row.attestation_id,
                derived.row_id.hex()
            ),
        ));
    }
    let expected = attestation_of(&derived, &row.tier)?;
    require_projection(&expected, row)
}

/// The statement's row as its header and payload state it, UNVERIFIED: the
/// inputs [`attestation_of`] reads, for [`check_carried_projection`]'s
/// equality check only (never stored, never a verdict). `statement_id` and
/// `role` are not read by the mapping and are left empty.
fn unverified_row(bytes: &[u8]) -> Option<AdmittedRow> {
    let (protected, payload) = statement_parts(bytes)?;
    let text = |v: Option<&Value>| v.and_then(Value::as_text).map(str::to_owned);
    let row_type = text(protected.get_int(-70001))?;
    let family = text(protected.get_int(-70002))?;
    let claims = protected.get_int(15)?;
    let iss = text(claims.get_int(1))?;
    let sub = text(claims.get_int(2))?;
    let kid = <[u8; 32]>::try_from(protected.get_int(4)?.as_bytes()?).ok()?;
    let author = text(payload.get_text("author"));
    let asserted_at_ms = payload.get_text("asserted_at").and_then(Value::as_u64)?;
    let names = super::names::names_of(&payload).ok()?;
    let row_id = super::names::RowId::of_statement(bytes)?;
    Some(AdmittedRow {
        row_id,
        statement_id: [0; 32],
        kid,
        iss,
        sub,
        row_type,
        family,
        author,
        asserted_at_ms,
        payload,
        names,
        role: None,
        bytes: bytes.to_vec(),
    })
}

/// The signer's `identity_type` for a row carrying a statement: from its
/// live edition-2 `key:record` at the row's instant, as the comma-joined set
/// the gates read. `Ok(None)` for a row that carries none.
///
/// # Errors
/// As [`verify_carried`]; the retryable unknown-signer error when no
/// record of the signer covers the instant.
pub async fn carried_identity_type<F>(dir: &F, row: &Attestation) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(admitted) = verify_carried(dir, row).await? else {
        return Ok(None);
    };
    let keys = held_keys_for(dir, &admitted.bytes).await?;
    match keys.liveness(&admitted.kid, admitted.asserted_at_ms) {
        Liveness::Live(r) => Ok(Some(r.identity_type.join(","))),
        _ => Err(Error::unknown_signer(&admitted.iss, PLANE)),
    }
}

/// cut-B: two envelopes are the same projection when their canonical (JCS)
/// images are equal. A stored envelope reads back through its at-rest JCS
/// form, where an integral real (`score: 1.0`) is the integer `1`, so a
/// `serde_json::Value` comparison would call one row two.
fn same_envelope(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use crate::verify::canonical::ceg_produce_canonicalize as jcs;
    a == b || matches!((jcs(a), jcs(b)), (Ok(x), Ok(y)) if x == y)
}

/// What [`put_statement`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementOutcome {
    /// A key-plane row (`key:record`, `key:revocation`), kept in
    /// `ceg_statements`. `new` is false for a statement already held.
    KeyPlane {
        /// The row id.
        row_id: super::names::RowId,
        /// Was it new.
        new: bool,
    },
    /// A further voice of a row already held: kept beside its row, counted
    /// by the row's fold.
    Voice {
        /// The row id (the event's `event_row_id`).
        row_id: super::names::RowId,
        /// Was the statement new.
        new: bool,
    },
    /// A row admitted through the attestation gates and kept under its row id.
    Row {
        /// The row id.
        row_id: super::names::RowId,
        /// Was the statement new.
        new: bool,
    },
    /// v62.0.0 (wave T1, CC 2.6.1.9) — a voice of a COUNTED group row
    /// (`group:roster`, `membership:{stage}` at `widening` / `removal`),
    /// kept: the row's voices so far are short of its group's
    /// `consensus_protocol`, or a founding roster lists a member who has not
    /// voiced it yet. Nothing is in the typed table yet; a later voice
    /// re-runs the door over all of them ([`super::group`]). APPENDED.
    Pending {
        /// The row id.
        row_id: super::names::RowId,
        /// Was the statement new.
        new: bool,
    },
}

/// **The one entry for an edition-2 statement**, local or replicated.
///
/// `offered_id` is the id the carrier names it by, if any: it must be the
/// computed one. `tier` is the row's tier (`federation` for what
/// replication and tier ingest deliver).
///
/// # Errors
/// The edition-2 door's refusals, then every refusal of the attestation
/// gates, exactly as the JSON door raises them.
pub async fn put_statement<F>(
    dir: &F,
    bytes: &[u8],
    offered_id: Option<&Digest32>,
    tier: &str,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    put_statement_with_origin(
        dir,
        bytes,
        offered_id,
        tier,
        crate::federation::replication::admission::WriteOrigin::Wire,
    )
    .await
}

/// v62.0.0 (JSON-cut slice B) — [`put_statement`] with the mapped row's
/// write origin: `Authored` for a statement THIS node produced and signed
/// in-process (`edition2::emit`), so its own producers are metered as local
/// authorship (CIRISPersist#804), never as a stranger's wire write.
///
/// # Errors
/// As [`put_statement`].
pub async fn put_statement_with_origin<F>(
    dir: &F,
    bytes: &[u8],
    offered_id: Option<&Digest32>,
    tier: &str,
    origin: crate::federation::replication::admission::WriteOrigin,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (wave P1c, AV-76) — the pure gates (form, size, decode, not an
    // object, no edition-1 name) run BEFORE the first directory read below
    // (the accord's roster, the signer's key plane): a statement that can
    // never be admitted buys no read. They need no key; an empty key set
    // only names a decode fault, which no key changes.
    super::door::pure_statement_gates(bytes, &HeldKeys::new())?;
    // v62.0.0 (wave O1; CC 4.2.6) — a recovery key signs no row: refused
    // finally by its key material, nothing held. A directory read: it runs
    // AFTER the pure statement gates (P1c's `pure_statement_gates` replaces
    // the form check above) and BEFORE the halt roster read and every key
    // lookup.
    Box::pin(super::recovery_signer::refuse_recovery_key_signer(
        dir, bytes,
    ))
    .await?;
    // v62.0.0 (JSON-cut slice A) — an accord invocation is judged against
    // the holders of the bundle in force for its accord, never the key
    // plane (`edition2::halt`).
    if super::halt::is_invocation(bytes) {
        let accord = super::halt::named_accord_root(bytes).unwrap_or_default();
        let roster = super::halt::roster_in_force(dir, &accord).await?;
        let out = super::halt::put_invocation(dir, bytes, roster.as_ref()).await?;
        let row_id = super::names::RowId(*out.invocation.row_id());
        // v62.0.0 (wave GC4; CC 2.7.3) — a replayed invocation is kept and
        // concludes nothing (`edition2::halt`): the held outcome.
        return Ok(if out.held {
            StatementOutcome::Pending {
                row_id,
                new: out.new,
            }
        } else {
            StatementOutcome::Row {
                row_id,
                new: out.new,
            }
        });
    }
    // v62.0.0 (C2-fix, ceremony gap 8; CC 4.2.1.3) — a counted accord
    // lifecycle row (`confirmed`, `active`) is judged against the holders of
    // the bundle its `refs.head` names, never the key plane
    // (`edition2::halt::put_lifecycle`).
    if super::halt::is_lifecycle(bytes) {
        return Ok(match super::halt::put_lifecycle(dir, bytes).await? {
            super::halt::LifecycleOutcome::Pending { row_id, new } => {
                StatementOutcome::Pending { row_id, new }
            }
            super::halt::LifecycleOutcome::Applied { row_id, new, .. }
            | super::halt::LifecycleOutcome::Unchanged { row_id, new } => {
                StatementOutcome::Row { row_id, new }
            }
        });
    }
    let mut keys = held_keys_for(dir, bytes).await?;
    // v62.0.0 (slice J0) — a key-plane statement already held was judged when
    // it arrived. Its re-put is read over the records alone, so a revoke-all
    // revocation does not make its own bytes unreadable on the way back in
    // (idempotence); it then re-projects.
    let already_held = keys.holds(bytes);
    // A key record is signed by its own key (CC 2.4.1.1: "Each key's own
    // holder signs its record"): offered, it is its own key source. It gives
    // liveness only through its own verification.
    keys.insert_record(bytes.to_vec());
    // v62.0.0 (T2-fix1) — the context a family's authorship cell reads
    // (`identity`, `group`, `seats`; CC 3.1.3), supplied by the door so a
    // family whose cell reads it is never `authorship_undetermined`.
    let ctx = super::typed::family_context(dir, bytes).await?;
    let admitted = if already_held {
        admit_row(bytes, &keys.without_revocations(), offered_id, ctx)?
    } else {
        admit_row(bytes, &keys, offered_id, ctx)?
    };
    // v62.0.0 (wave P1e) — an admission row's signer is a person.
    require_admission_signer_is_person(&keys, &admitted)?;
    let out = put_admitted_row(dir, &admitted, tier, offered_id.is_some(), origin).await?;
    // v62.0.0 (wave G0; CC 2.7.3) — the fold: a plane's hold is recorded with
    // its reason, and every held or concluded row whose fold read what this
    // statement touches is re-folded, so the concluded set never depends on
    // arrival order (`edition2::fold`).
    Box::pin(super::fold::after_statement(dir, &admitted, tier, &out)).await?;
    Ok(out)
}

/// v62.0.0 (slice C1; CC ruling (a): "a row is the same row inside a bundle
/// and alone") — **the store tail of [`put_statement`]** for a row its door
/// has admitted: the composer target, then the key plane (with its
/// projection), a further voice, or the row through the attestation gates.
///
/// [`put_statement`] admits under the held key plane, then stores through
/// this. (The genesis door no longer calls it: C1 writes a bundle's named
/// rows in one transaction, `FederationDirectory::put_edition2_genesis`.)
///
/// `replicated` is whether a peer offered the statement under an id (the
/// replicated door): the group planes' membership door reads it. `origin`
/// is the mapped row's write origin ([`put_statement_with_origin`]).
///
/// # Errors
/// As [`put_statement`] after admission.
///
/// v62.0.0 (BF22, pass 4m4) — returns a `dyn Future + Send`, not an `async
/// fn`'s opaque type. Every row store passes through here, and so do the
/// fold's re-conclusions, the voice and affiliation walks and the key-grant
/// projection that call back into a store door, which reaches here again:
/// with an opaque future, proving a store door (or a store open) `Send`
/// walked that whole cycle and overflowed the compiler's recursion depth
/// (E0275), in persist and in any host that `tokio::spawn`s it. The type
/// ends at this box.
pub fn put_admitted_row<'a, F>(
    dir: &'a F,
    admitted: &'a AdmittedRow,
    tier: &'a str,
    replicated: bool,
    origin: crate::federation::replication::admission::WriteOrigin,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StatementOutcome, Error>> + Send + 'a>>
where
    F: FederationDirectory + ?Sized,
{
    Box::pin(put_admitted_row_body(
        dir, admitted, tier, replicated, origin,
    ))
}

/// [`put_admitted_row`]'s body.
async fn put_admitted_row_body<F>(
    dir: &F,
    admitted: &AdmittedRow,
    tier: &str,
    replicated: bool,
    origin: crate::federation::replication::admission::WriteOrigin,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::fold::{plane, Arrival};
    // v62.0.0 (wave G0 v4) — the row is folded under its ORIGINAL arrival:
    // a later voice, or a re-fold, of a row first held through the
    // replicated door runs the replicated door's gates (T1), at the tier it
    // first arrived at.
    let state = dir.fold_state(&admitted.row_id).await?;
    let (tier, replicated): (String, bool) = match &state {
        Some(s) => (s.tier.clone(), s.replicated),
        None => (tier.to_owned(), replicated),
    };
    let was_held = state.as_ref().is_some_and(|s| s.held.is_some());
    // G0-fix6 — a row already CONCLUDED on a FINAL plane never un-concludes,
    // on ANY path (a re-offered voice, a re-run): a hold its re-run marks is
    // not recorded, and the row stays concluded (CC 2.7.5).
    let concluded_final = state
        .as_ref()
        .is_some_and(|s| s.held.is_none() && super::fold::plane_for(&s.plane).is_final());
    let (plane_name, slot) = fold_plane_of(admitted);
    let arrival = Arrival {
        row_id: admitted.row_id,
        replicated,
        tier: tier.clone(),
        plane: plane_name,
        slot,
    };
    super::fold::arriving(arrival, async {
        // v62.0.0 (wave G0; CC 2.7.3) — EVERY door below (the group planes,
        // the occurrence door, the typed families, the re-bind, the key
        // plane, the attestation gates) runs as one fold attempt: a gate that
        // marks a fold condition (`fold::hold`) holds the row with its
        // reason, its statement kept and nothing concluded, never refused.
        // The attestation tail opens its own inner attempt
        // (`voices::put_counted_row`), which records its own reads.
        let offered = super::voices::Voice {
            iss: admitted.iss.clone(),
            kid: admitted.kid,
            asserted_at_ms: admitted.asserted_at_ms,
        };
        let (out, att) = super::fold::attempt(
            admitted.row_id,
            Some(offered),
            Box::pin(put_admitted_row_doors(
                dir, admitted, &tier, replicated, origin,
            )),
        )
        .await;
        // v62.0.0 (wave G0 v5.1) — a FINAL-plane hold must declare what it
        // waits for; its declared reads only ever conclude it (monotone).
        super::fold::enforce_final_plane(plane_name, admitted, att.held.as_ref(), &att.reads);
        let out = match (out, att.held) {
            (Ok(o), mark) => {
                match &o {
                    // A plane that answered `Pending` (T1's count, O1's,
                    // W1's). fix2 — recorded on EVERY hold, not only the
                    // first: the reason is this attempt's (its mark, else the
                    // count), and the reads are this attempt's, so a row
                    // held first on A and then on B re-folds when B arrives.
                    // fix3 — NOT on the attestation tail: `voices::put_counted_row`
                    // already recorded this hold with its gate's reason and its
                    // inner attempt's reads (the outer attempt is shadowed
                    // there and saw neither). fix2's record overwrote both
                    // with `count_short` and the outer reads.
                    // G0-fix8 — nor on the trust plane: since W1-fix2 its rows
                    // store through `voices::put_counted_row` too, which records
                    // its own hold (reason + inner reads); this would overwrite
                    // them with `count_short` and the outer reads.
                    StatementOutcome::Pending { row_id, .. }
                        if !records_itself(plane_name) && !concluded_final =>
                    {
                        super::fold::record_pending(
                            dir,
                            *row_id,
                            &admitted.family,
                            &tier,
                            mark,
                            att.reads.clone(),
                        )
                        .await?;
                    }
                    // fix3 — a held row whose re-run now answers `Voice` (O1's
                    // occurrence-key statement, held on the owner gate before
                    // the owner binding landed): its statement is a kept voice
                    // that waits on nothing the fold reads (the author's
                    // statement, when it arrives, runs the door itself). Its
                    // stale hold is cleared, its reads kept.
                    StatementOutcome::Voice { row_id, .. }
                        if was_held && !records_itself(plane_name) =>
                    {
                        dir.put_fold_reason(row_id, None).await?;
                    }
                    // Concluded on a plane other than the attestation tail
                    // (which records its own, with its inner reads): the
                    // conclusion and what it read, so a later input change
                    // can un-conclude it.
                    // W1-fix2 — the trust plane's rows store through
                    // `voices::put_counted_row` too, which records its own.
                    StatementOutcome::Row { row_id, .. }
                    | StatementOutcome::KeyPlane { row_id, .. }
                        if !records_itself(plane_name) =>
                    {
                        super::fold::record(
                            dir,
                            *row_id,
                            &admitted.family,
                            &tier,
                            None,
                            att.reads.clone(),
                        )
                        .await?;
                    }
                    _ => {}
                }
                o
            }
            // v62.0.0 (wave G0 fix2) — a `key:record` is the signer's own key
            // plane (a door input): it never holds. A mark set during its
            // route does not keep it; its refusal stands.
            (Err(e), Some(_)) if admitted.family == KEY_RECORD_FAMILY => return Err(e),
            // G0-fix6 — concluded and FINAL: the voice is kept, nothing is
            // held (the general form of O1-fix7's `landed_here`).
            (Err(_), Some(_)) if concluded_final => {
                let new = dir.put_edition2_statement(admitted).await?;
                StatementOutcome::Voice {
                    row_id: admitted.row_id,
                    new,
                }
            }
            (Err(e), Some((r, detail))) => {
                let new = dir.put_edition2_statement(admitted).await?;
                let detail = if detail.is_empty() {
                    e.to_string()
                } else {
                    detail
                };
                super::fold::record(
                    dir,
                    admitted.row_id,
                    &admitted.family,
                    &tier,
                    Some((r, detail)),
                    att.reads,
                )
                .await?;
                StatementOutcome::Pending {
                    row_id: admitted.row_id,
                    new,
                }
            }
            (Err(e), None) => return Err(e),
        };
        // The key plane's read model skips held-back statements
        // (`held_keys_for_kid`): re-derive it once the fold state of a key
        // statement changed (held now, or held before).
        if plane_name == plane::KEY && (was_held || matches!(out, StatementOutcome::Pending { .. }))
        {
            if let Some(kid) = key_statement_about(admitted) {
                super::projection::project_key(dir, &kid).await?;
            }
        }
        Ok(out)
    })
    .await
}

/// G0-fix8 — the planes whose door is `voices::put_counted_row`, which
/// records its own fold state (reason and inner reads): the attestation tail
/// and, since W1-fix2, the trust plane. `put_admitted_row`'s bookkeeping
/// never writes over them.
fn records_itself(plane_name: &str) -> bool {
    plane_name == super::fold::plane::ATTESTATION || plane_name == super::fold::plane::TRUST
}

/// The key a key-plane statement is about: a record's own key, a
/// revocation's subject.
fn key_statement_about(admitted: &AdmittedRow) -> Option<Digest32> {
    if admitted.family == KEY_RECORD_FAMILY {
        super::liveness::recorded_kid(&admitted.bytes)
    } else {
        kid_of_identity_ref(&admitted.sub)
    }
}

/// v62.0.0 (wave G0 v4) — **the fold plane and projection slot of a row**,
/// in the same order [`put_admitted_row`] routes it (keep the two in step).
#[must_use]
pub fn fold_plane_of(admitted: &AdmittedRow) -> (&'static str, String) {
    use super::fold::plane;
    use super::typed::TypedPlane;
    let own = || format!("row:{}", admitted.row_id.hex());
    // No wildcard: a new `Route` or `TypedPlane` fails to compile here.
    match route_of(admitted) {
        Route::Group(_) => (plane::GROUP, format!("group:{}", admitted.sub)),
        Route::Occurrence => match super::fold::occurrence_pair(admitted) {
            Some((identity, occurrence)) => (
                plane::OCCURRENCE,
                format!("occurrence:{identity}|{occurrence}"),
            ),
            None => (plane::OCCURRENCE, own()),
        },
        Route::Trust => (plane::TRUST, own()),
        // v4 — a holding claim folds into its blob's slot, so its bytes are
        // kept-but-not-served while it is held (`fold::bytes_servable`).
        Route::Typed(TypedPlane::Custody) => {
            match super::typed::holding_claim_of(&admitted.bytes) {
                Ok(claim) => (
                    plane::TYPED_ATTESTATION,
                    super::fold::blob_slot(&claim.sha256),
                ),
                Err(_) => (plane::TYPED_ATTESTATION, own()),
            }
        }
        Route::Typed(TypedPlane::Takedown) if super::typed::is_steward_purge(admitted) => {
            (plane::TYPED_FINAL, own())
        }
        Route::Typed(TypedPlane::Takedown | TypedPlane::KeyGrant) => {
            (plane::TYPED_ATTESTATION, own())
        }
        Route::Typed(
            TypedPlane::OccurrenceRevocation
            | TypedPlane::Cosign
            | TypedPlane::Revocation
            | TypedPlane::DeliveryReceipt,
        ) => (plane::TYPED_FINAL, own()),
        Route::Rebind => (plane::REBIND, format!("rebind:{}", admitted.sub)),
        Route::Key => match key_statement_about(admitted) {
            Some(kid) => (plane::KEY, format!("key:{}", hex::encode(kid))),
            None => (plane::KEY, own()),
        },
        Route::Attestation => (plane::ATTESTATION, own()),
    }
}

/// The routing [`put_admitted_row`] runs inside its fold attempt.
async fn put_admitted_row_doors<F>(
    dir: &F,
    admitted: &AdmittedRow,
    tier: &str,
    replicated: bool,
    origin: crate::federation::replication::admission::WriteOrigin,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let bytes: &[u8] = &admitted.bytes;
    // A composer names a held row of its own family (every plane).
    check_composer_target(dir, admitted).await?;
    // v62.0.0 (wave G0 v5) — ONE routing (`route_of`), matched without a
    // wildcard here and in `fold_plane_of`: a new route fails to compile
    // until both the door and the fold's plane map name it.
    match route_of(admitted) {
        // v62.0.0 (wave T1) — the group planes: a `group:roster` version or
        // a counted membership change lands in its typed table through the
        // typed door, counted over every voice of the row (`edition2::group`).
        Route::Group(plane) => {
            Box::pin(super::group::put_group_statement(
                dir, admitted, plane, replicated, tier,
            ))
            .await
        }
        // v62.0.0 (wave O1; CC 3.3.6) — an occurrence bind's voices: held,
        // and the bind written to the occurrence table when it lands
        // (`edition2::occurrence`), never an attestation row.
        Route::Occurrence => Box::pin(super::occurrence::put_occurrence_voice(dir, admitted)).await,
        // v62.0.0 (wave T2; CC 3.2 T3) — a trust edge (or its composer) keeps
        // the attestation door and re-derives the v1.3 trust plane's row of
        // the keys it touches (`edition2::typed::project_trust_for`).
        Route::Trust => Box::pin(super::typed::put_trust_statement(dir, admitted, tier)).await,
        // v62.0.0 (wave T2) — the remaining families with a typed table (an
        // occurrence revocation, a revocation, a takedown notice, a custody
        // report, a key grant, a delivery receipt, a cosign state) land there
        // through the JSON form's own door (`edition2::typed`).
        Route::Typed(plane) => {
            Box::pin(super::typed::put_typed_statement(
                dir, admitted, plane, tier,
            ))
            .await
        }
        // v62.0.0 (wave W1; CC 3.1.3, 3.4.7) — a seat's counted re-bind: held
        // in the statement store, counted by the holders of the genesis
        // bundle in force (`edition2::transport_rebind`), never an
        // attestation row.
        Route::Rebind => Box::pin(super::transport_rebind::put_rebind_voice(dir, admitted)).await,
        Route::Key => {
            let new = dir.put_edition2_statement(admitted).await?;
            // v62.0.0 (slice J0) — the read models: the key this statement
            // is about, projected into `federation_keys` and its honoured
            // revocations into `federation_revocations`, re-derived from the
            // held key plane every time (`projection::project_key`).
            let about = if admitted.family == KEY_RECORD_FAMILY {
                super::liveness::recorded_kid(bytes)
            } else {
                kid_of_identity_ref(&admitted.sub)
            };
            if let Some(kid) = about {
                super::projection::project_key(dir, &kid).await?;
            }
            Ok(StatementOutcome::KeyPlane {
                row_id: admitted.row_id,
                new,
            })
        }
        Route::Attestation => {
            // A further voice of a row already held (a counted row, CC 2.6.1.9): the
            // row is admitted, and this voice joins its fold under `event_row_id`
            // (`cosign::edition2_voices`), never a second row. v62.0.0 (wave V1b) —
            // a row not held yet runs the attestation gates counted by ALL its
            // voices, this one included; a gate that finds them short keeps the
            // voice and answers `Pending` (`edition2::voices::put_counted_row`).
            Box::pin(super::voices::put_counted_row(dir, admitted, tier, origin)).await
        }
    }
}

/// v62.0.0 (wave G0 v5) — **the one routing** of an admitted row, in the
/// order `put_admitted_row` has always applied it. Both the door
/// (`put_admitted_row_doors`) and the fold's plane map ([`fold_plane_of`])
/// match it exhaustively, with no wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// T1's group planes.
    Group(super::group::GroupPlane),
    /// O1's occurrence bind.
    Occurrence,
    /// T2's trust edges.
    Trust,
    /// T2's typed families.
    Typed(super::typed::TypedPlane),
    /// W1's counted re-bind.
    Rebind,
    /// The key plane.
    Key,
    /// Everything else: the attestation gates (`voices::put_counted_row`).
    Attestation,
}

/// The [`Route`] of an admitted row.
#[must_use]
pub fn route_of(admitted: &AdmittedRow) -> Route {
    if let Some(plane) =
        super::group::group_plane_of(&admitted.row_type, &admitted.family, &admitted.payload)
    {
        return Route::Group(plane);
    }
    if admitted.family == super::occurrence::OCCURRENCE_FAMILY {
        return Route::Occurrence;
    }
    if super::typed::is_trust_family(&admitted.family) {
        return Route::Trust;
    }
    if let Some(plane) = super::typed::typed_plane_of_row(admitted) {
        return Route::Typed(plane);
    }
    if admitted.family == super::transport_rebind::REBIND_FAMILY {
        return Route::Rebind;
    }
    if admitted.family == KEY_RECORD_FAMILY || admitted.family == KEY_REVOCATION_FAMILY {
        return Route::Key;
    }
    Route::Attestation
}

/// The tier replication and tier ingest deliver at.
pub const INGEST_TIER: &str = attestation_tier::FEDERATION;

/// v62.0.0 (JSON-cut slice A) — what [`apply_replicated_statement`] did with
/// one statement a peer offered. A `Refused` is a policy outcome that
/// ADVANCES the replication cursor (the lost-race `StoreConflict`, fail
/// closed, safe to re-offer); a waiting statement is never an outcome: it is
/// the retryable `federation_attester_key_unknown` error, and the cursor
/// stays where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplicatedStatementOutcome {
    /// The statement was new here and is kept ([`StatementOutcome`] says
    /// where).
    Admitted(StatementOutcome),
    /// This node already held the statement byte for byte: nothing changed.
    Unchanged(StatementOutcome),
    /// The statement was not kept and the store is untouched.
    Refused {
        /// Which branch refused.
        reason: crate::federation::attestation_apply::AttestationRefusalReason,
    },
}

impl ReplicatedStatementOutcome {
    /// Does this outcome advance the sender's cursor? Every outcome does;
    /// only an `Err` (a statement waiting on a key, a backend failure) holds
    /// it. Spelled out for the replication loop.
    #[must_use]
    pub const fn advances_cursor(&self) -> bool {
        true
    }
}

/// v62.0.0 (JSON-cut slice A) — **the replicated statement door**: one
/// edition-2 statement as a peer delivered it, under the id the peer offered
/// it as (`offered_id`), at tier `federation` ([`INGEST_TIER`]), through
/// [`put_statement`] and so through every gate the local door runs.
///
/// - an id the bytes do not name is `row_id_mismatch` (terminal);
/// - a statement whose signer's key record is not held waits:
///   `federation_attester_key_unknown`, retryable, and the cursor must NOT
///   advance past it;
/// - a key conflict the plan did not see (a duplicate key in the store, a
///   key-record conflict) is `Refused { StoreConflict }`: fail closed, the
///   held rows untouched, safe to re-offer;
/// - every other gate refusal keeps its typed [`Error`].
///
/// v62.0.0 (LF-fix2, T5) — runs as ONE directory call,
/// [`FederationDirectory::replicated_statement_door`]: over a backend, this
/// door at `WriteOrigin::Wire`; over the capsule proxy (`OpsDirectory`), the
/// `ApplyReplicatedStatement` op, so the whole door runs on the host's store
/// and nothing composes it over the proxy's reads.
///
/// # Errors
/// As above.
pub async fn apply_replicated_statement<F>(
    dir: &F,
    bytes: &[u8],
    offered_id: &Digest32,
) -> Result<ReplicatedStatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.replicated_statement_door(bytes, offered_id).await
}

/// v62.0.0 (LF-fix1; CIRISPersist#916, `FSD/SECOND_DEVICE.md` §3) — **the
/// receive door's re-wrap, on the edition-2 wire.** An owner-binding
/// `delegates_to(owner → device)` arriving from a peer is the moment a minter
/// learns a member has a device: this node re-wraps its OWN epochs to it
/// ([`FederationDirectory::rewrap_own_epochs_for_device`], through
/// [`rewrap_after_admission`](crate::federation::rewrap_after_admission)).
///
/// The hook ran in the typed replicated attestation door
/// (`attestation_apply::apply_planned`, on an inserted row). An edition-2
/// binding never reaches that plan: it is offered here as its statements and
/// concludes when the bound node's voice completes it
/// ([`StatementOutcome::Row`]: the typed row was written by THIS call; a
/// further voice of a landed row is `Voice`, a row still short is `Pending`).
/// So the receive door that is open asks, once the row has concluded and
/// every voice is stored (the owner seat counts the bound node's voice). The
/// plain statement door ([`put_statement`]) does not: as before, a host's
/// local write re-wraps through its own door.
///
/// The row stands whatever happens here: a failed read or re-wrap is logged
/// and left to the pending-`KeyGrant` sweep, as on the typed door. The row is
/// read back only for a `delegates_to` statement, so no other row pays a read.
async fn rewrap_for_a_received_owner_binding<F>(dir: &F, bytes: &[u8], out: &StatementOutcome)
where
    F: FederationDirectory + ?Sized,
{
    let StatementOutcome::Row { row_id, .. } = out else {
        return;
    };
    let is_delegation = super::emit::family_of_statement(bytes).is_some_and(|(_, row_type)| {
        row_type == crate::federation::types::attestation_type::DELEGATES_TO
    });
    if !is_delegation {
        return;
    }
    match dir.get_attestation(&row_id.hex()).await {
        Ok(Some(row)) => {
            if let Some((owner, device)) = crate::federation::owner_binding_of(&row) {
                crate::federation::rewrap_after_admission(dir, &owner, &device).await;
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(
            error = %e,
            row_id = %row_id.hex(),
            "a received delegation concluded; reading it back for the owner-binding re-wrap \
             failed, and the re-wrap is left to the pending-KeyGrant sweep (#916)"
        ),
    }
}

/// v62.0.0 (RL-fix1, lead ruling (B)) — [`apply_replicated_statement`] with
/// the host's FEED POSITION of the offered statement: an accord row this node
/// cannot judge (no genesis bundle held) answers
/// `Refused { AccordRootNotHeld }` as it does there, the cursor advances, and
/// the first such skip on `(feed.plane, feed.peer)` is recorded as a
/// watermark ([`super::accord_rescan::note_skip`]); the host re-pulls from it
/// once [`super::accord_rescan::rescan_needed`] names it. Every other
/// outcome is [`apply_replicated_statement`]'s.
///
/// # Errors
/// As [`apply_replicated_statement`]; a feed field empty or too long; the
/// watermark store.
pub async fn apply_replicated_statement_at_feed<F>(
    dir: &F,
    bytes: &[u8],
    offered_id: &Digest32,
    feed: &super::accord_rescan::FeedPosition,
) -> Result<ReplicatedStatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::attestation_apply::AttestationRefusalReason;
    let out = Box::pin(apply_replicated_statement(dir, bytes, offered_id)).await?;
    if matches!(
        out,
        ReplicatedStatementOutcome::Refused {
            reason: AttestationRefusalReason::AccordRootNotHeld
        }
    ) {
        Box::pin(super::accord_rescan::note_skip(dir, feed)).await?;
    }
    Ok(out)
}

/// v62.0.0 (E6-fix9; CIRISPersist#804) — [`apply_replicated_statement`]
/// under the CALL's write origin. The privileged sync door
/// (`put_attestation_synced`, `WriteOrigin::Sync { peer_key_id }`) reaches
/// the statement door through `attestation_apply::apply_as_statement`, and
/// the origin is what decides WHICH budget a fresh row is metered against
/// (the cohort question stays inside the write door). Dropping it to `Wire`
/// metered a cohort mate's sync as a wire stranger and opened a peer bucket.
///
/// # Errors
/// As [`apply_replicated_statement`].
pub async fn apply_replicated_statement_with_origin<F>(
    dir: &F,
    bytes: &[u8],
    offered_id: &Digest32,
    origin: crate::federation::replication::admission::WriteOrigin,
) -> Result<ReplicatedStatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::attestation_apply::AttestationRefusalReason;
    // v62.0.0 (RL-fix1, lead ruling (B); CC 5.4: a node "carries none it
    // cannot verify") — an accord row at a node holding no genesis bundle is
    // not kept and does not hold the sender's cursor: a bundle never arrives
    // down a feed. `apply_replicated_statement_at_feed` records where the
    // feed skipped it, for the re-pull once a bundle is in force.
    if Box::pin(super::accord_rescan::accord_root_not_held(dir, bytes)).await? {
        return Ok(ReplicatedStatementOutcome::Refused {
            reason: AttestationRefusalReason::AccordRootNotHeld,
        });
    }
    match put_statement_with_origin(dir, bytes, Some(offered_id), INGEST_TIER, origin).await {
        Ok(out) => {
            rewrap_for_a_received_owner_binding(dir, bytes, &out).await;
            let new = match &out {
                StatementOutcome::KeyPlane { new, .. }
                | StatementOutcome::Voice { new, .. }
                | StatementOutcome::Row { new, .. }
                | StatementOutcome::Pending { new, .. } => *new,
            };
            Ok(if new {
                ReplicatedStatementOutcome::Admitted(out)
            } else {
                ReplicatedStatementOutcome::Unchanged(out)
            })
        }
        Err(Error::Conflict(_) | Error::KeyRecordConflict { .. }) => {
            Ok(ReplicatedStatementOutcome::Refused {
                reason: AttestationRefusalReason::StoreConflict,
            })
        }
        Err(e) => Err(e),
    }
}
