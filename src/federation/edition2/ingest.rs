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
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY;
use ciris_verify_core::edition2::{identity_ref, Digest32};
use sha2::Digest as _;

use super::door::{admit_row, AdmittedRow, PLANE};
use super::liveness::{statement_parts, HeldKeys, Liveness, KEY_REVOCATION_FAMILY};
use crate::federation::types::{attestation_tier, Attestation, SignedAttestation};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The envelope member a mapped row carries its statement under: the
/// statement's bytes as received, lowercase hex (CC 2.6.3).
pub const STATEMENT_MEMBER: &str = "ceg_statement";

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

/// v62.0.0 (JSON-cut slice B) — the payload's hash-digest members (CC 2.6.1:
/// `[-16, bstr .size 32]`, SHA-256), projected as the 64-lowercase-hex text
/// the earlier gates read: `evidence_refs` is a set of them, the others one.
// cut-B: moves into edition2::payloads (slice A owns member typing) at the merge.
pub const HASH_DIGEST_MEMBERS: &[&str] = &["evidence_refs", "carried", "seat_commitment"];

/// A `[-16, bstr32]` hash digest as lowercase hex.
fn digest_hex(v: &Value) -> Option<String> {
    match v.as_array()? {
        [alg, d] if alg.as_i64() == Some(-16) => {
            d.as_bytes().filter(|b| b.len() == 32).map(hex::encode)
        }
        _ => None,
    }
}

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
        Some(kid) => held_keys_for_kid(dir, &kid).await,
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
            if let Some(signer) = statement_kid(&st) {
                if signer != kid {
                    queue.push_back(signer);
                }
            }
            held.insert_record(st);
        }
        for st in dir
            .edition2_statements_about(KEY_REVOCATION_FAMILY, &subject)
            .await?
        {
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
        Value::Tag(t, inner) => serde_json::json!({ "tag": t, "value": json_of(inner) }),
        Value::Simple(s) => serde_json::json!({ "simple": s }),
    }
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
///   `expires_at` from `expires_at`.
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
        // Hash digests (`[-16, h'…']`) read back as the hex the gates read.
        for member in HASH_DIGEST_MEMBERS {
            match row.payload.get_text(member) {
                Some(Value::Array(a)) if *member == "evidence_refs" => {
                    let hexes: Option<Vec<String>> = a.iter().map(digest_hex).collect();
                    if let Some(h) = hexes {
                        o.insert((*member).to_owned(), serde_json::json!(h));
                    }
                }
                Some(v) => {
                    if let Some(h) = digest_hex(v) {
                        o.insert((*member).to_owned(), serde_json::Value::String(h));
                    }
                }
                None => {}
            }
        }
        // Scores, confidences and weights are integers at the fixed scale of
        // 10^6 (CC 2.6.1.5); the earlier form's gates read the real value.
        for member in SCALED_MEMBERS {
            if let Some(n) = row.payload.get_text(member).and_then(Value::as_i64) {
                #[allow(clippy::cast_precision_loss)]
                let real = n as f64 / 1_000_000.0;
                o.insert((*member).to_owned(), serde_json::json!(real));
            }
        }
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
    let keys = held_keys_for(dir, &bytes).await?;
    let offered: Option<Digest32> = hex::decode(&row.attestation_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
    let Some(offered) = offered else {
        return Err(Error::malformed_row(
            PLANE,
            malformed_row::EDITION2_ROW_ID_MISMATCH,
            format!(
                "a row carrying an edition-2 statement is stored under its row id, not `{}`",
                row.attestation_id
            ),
        ));
    };
    let admitted = admit_row(&bytes, &keys, Some(&offered), SelectContext::default())?;
    let expected = attestation_of(&admitted, &row.tier)?;
    let same = expected.attestation_id == row.attestation_id
        && expected.attesting_key_id == row.attesting_key_id
        && expected.attested_key_id == row.attested_key_id
        && expected.attestation_type == row.attestation_type
        && expected.asserted_at == row.asserted_at
        && same_envelope(&expected.attestation_envelope, &row.attestation_envelope)
        && expected.subject_key_ids == row.subject_key_ids;
    if !same {
        return Err(Error::malformed_row(
            PLANE,
            malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
            format!(
                "row {} is not the projection of the edition-2 statement it carries",
                row.attestation_id
            ),
        ));
    }
    Ok(Some(admitted))
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
    super::door::require_statement_form(bytes)?;
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
    let admitted = if already_held {
        admit_row(
            bytes,
            &keys.without_revocations(),
            offered_id,
            SelectContext::default(),
        )?
    } else {
        admit_row(bytes, &keys, offered_id, SelectContext::default())?
    };
    if admitted.family == KEY_RECORD_FAMILY || admitted.family == KEY_REVOCATION_FAMILY {
        let new = dir.put_edition2_statement(&admitted).await?;
        // v62.0.0 (slice J0) — the read models: the key this statement is
        // about, projected into `federation_keys` and its honoured
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
        return Ok(StatementOutcome::KeyPlane {
            row_id: admitted.row_id,
            new,
        });
    }
    // A further voice of a row already held (a counted row, CC 2.6.1.9): the
    // row is admitted, and this voice joins its fold under `event_row_id`
    // (`cosign::edition2_voices`), never a second row.
    if dir.get_attestation(&admitted.row_id.hex()).await?.is_some() {
        let new = dir.put_edition2_statement(&admitted).await?;
        return Ok(StatementOutcome::Voice {
            row_id: admitted.row_id,
            new,
        });
    }
    let row = attestation_of(&admitted, tier)?;
    dir.put_attestation_with_origin(SignedAttestation { attestation: row }, origin)
        .await?;
    let new = dir.put_edition2_statement(&admitted).await?;
    Ok(StatementOutcome::Row {
        row_id: admitted.row_id,
        new,
    })
}

/// The tier replication and tier ingest deliver at.
pub const INGEST_TIER: &str = attestation_tier::FEDERATION;
