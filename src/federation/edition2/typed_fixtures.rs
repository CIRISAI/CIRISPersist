//! v62.0.0 (wave T2) — **the edition-2 twins of the remaining typed-plane
//! builders** (`edition2::typed`): each takes the typed struct (or the
//! earlier builder's inputs) and returns the statement it is, signed by an
//! E0 seed (`fixture_switch`'s model: a seed, or an identity-ref E0 minted;
//! the statement carries `kid_or_keep(..)` of every key id, and the signer
//! signs with `signing_key(..)`). Store a twin with `e2::put_statement(d,
//! &st)`; its row lands in the typed table of its family.
//!
//! | earlier builder / struct | twin |
//! |---|---|
//! | `fed_revocation` / a `SignedRevocation` (an entity with a key) | [`revocation_statement`] |
//! | `FramedOccurrenceRevocation` / a carrier row (`carrier_row`) | [`occurrence_revocation_voice`], one per roster key |
//! | a `takedown_notice:{basis}:v1` scores row | [`takedown_statement`] |
//! | `custody_ack_envelope` + an emitted `custody:ack:v1` row | [`custody_statement`] |
//! | `KeyGrantRow::emit_input` | [`key_grant_statement`] |
//! | a `DeliveryReceipt` literal (`put_delivery_receipt`) | [`delivery_receipt_statement`] |
//! | a `cosign:{pending,signature}:v1` row | none: the family is retired (PRE4-cosign); [`retired_cosign_statement`] builds the statement a peer still sends, to see it refused |

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::{identity_ref, sign_row_statement, thumbprint};
use ciris_verify_core::namespace_match;

use super::fixture_switch::{kid_or_keep, signing_key};
use super::names::RowId;
use super::typed::{
    custody_payload, delivery_receipt_payload, key_grant_payload, occurrence_revocation_payload,
    revocation_payload, takedown_payload, trust_accepts_payload, withdraws_payload, NoticeText,
    CUSTODY_PREFIX, DELIVERY_RECEIPT_PREFIX, KEY_GRANT_PREFIX, OCCURRENCE_REVOCATION_PREFIX,
    REVOCATION_PREFIX, TAKEDOWN_PREFIX, TRUST_PREFIX,
};
use crate::federation::blobs::GrantWrap;
use crate::federation::custody_ack::CustodyState;
use crate::federation::key_grant::{KeyGrantAxis, KeyGrantRow};
use crate::federation::types::IdentityOccurrenceRevocation;

/// Sign `payload` as `seed`'s statement under the family `family_prefix`
/// (row type `scores`). `iss` is `kid_or_keep(iss)` when given (a key
/// signing as an identity it is a seat of: an occurrence key as its
/// identity), else the signer's own identity-ref. `sub` is
/// `kid_or_keep(sub)`.
///
/// # Panics
/// A payload with no `asserted_at`.
#[must_use]
pub fn typed_statement(
    seed: &str,
    iss: Option<&str>,
    sub: &str,
    family_prefix: &str,
    payload: &Value,
) -> Vec<u8> {
    let key = signing_key(seed);
    let iss = iss.map_or_else(|| identity_ref(&thumbprint(key.public_key())), kid_or_keep);
    sign_row_statement(
        &key,
        &iss,
        &kid_or_keep(sub),
        "scores",
        &namespace_match::family_id(family_prefix),
        payload,
        vec![],
    )
    .expect("typed_fixtures: sign a typed-plane statement")
}

/// The ms of an instant (fixtures never sign before 1970).
fn ms(at: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(at.timestamp_millis()).expect("typed_fixtures: an instant after 1970")
}

/// One voice of an `identity:occurrence_revocation` row: `seed` signs the
/// payload, as the identity (`iss` = `identity_key_id`, the counted voice of
/// a roster key: CC 3.3.6.4) when `as_identity`, else as itself. Every
/// voice states the same payload, authored by the identity, naming the
/// self-roster `head` it is counted over (`refs.head`, REQUIRED, CC27 item
/// 2). `head: None` names the identity's CURRENT head on `dir`
/// and tips (`occurrence::current_roster_heads`, O1 v8: the latest LANDED
/// roster row(s), else the genesis key's `key:record` row); a test of an older or unheld head
/// passes it. `further_heads` names the further tips the row merges
/// (`refs.further_heads`; empty for none). `voices` are ALL the keys that
/// will voice the eviction (seeds or kids; empty: every key on the roster
/// at the named heads, plus this signer): it cites
/// each one's `key:record` and binding (`typed::eviction_cites`, CC rc21). The occurrence is the row's `sub`; the struct's key ids are
/// seeds or E0 kids.
///
/// # Panics
/// An instant before 1970, or a current head that cannot be read (a
/// fixture).
#[allow(clippy::too_many_arguments)] // a fixture mirroring the payload members
pub async fn occurrence_revocation_voice<D: crate::federation::FederationDirectory + ?Sized>(
    dir: &D,
    seed: &str,
    as_identity: bool,
    rev: &IdentityOccurrenceRevocation,
    head: Option<&RowId>,
    further_heads: &[RowId],
    voices: &[&str],
    asserted_at_ms: u64,
) -> Vec<u8> {
    let identity = kid_or_keep(&rev.identity_key_id);
    // `None`: the identity's CURRENT tips on `dir` (O1 v8
    // `occurrence::current_roster_heads`: the head and, when the roster is
    // forked, the further tips the row merges).
    let (head, further_heads): (RowId, Vec<RowId>) = match head {
        Some(h) => (*h, further_heads.to_vec()),
        None => {
            let (h, tips) = super::occurrence::current_roster_heads(dir, &identity)
                .await
                .expect("typed_fixtures: read the identity's current self-roster heads")
                .expect("typed_fixtures: the identity has a self-roster head (its genesis record)");
            let further = if further_heads.is_empty() {
                tips
            } else {
                further_heads.to_vec()
            };
            (h, further)
        }
    };
    let mut r = rev.clone();
    r.identity_key_id = identity.clone();
    r.occurrence_key_id = kid_or_keep(&rev.occurrence_key_id);
    r.witness_set = rev.witness_set.iter().map(|w| kid_or_keep(w)).collect();
    // A user self's revocation is counted (no `author`); a node's or
    // agent's is authored by the identity (CC 3.1.3).
    let user = dir
        .lookup_public_key(&identity)
        .await
        .expect("typed_fixtures: read the identity's key")
        .is_some_and(|k| {
            crate::federation::types::identity_type::set_contains(
                &k.identity_type,
                crate::federation::types::identity_type::USER,
            )
        });
    let author = (!user).then_some(identity.as_str());
    // v62.0.0 (T2-fix4; CC rc21 7f94be1) — the eviction cites every voice's
    // key:record and binding. `voices` names the keys that will voice it
    // (seeds or kids). Empty: every key on the roster at the named heads,
    // plus this signer, so every roster key's voice states the SAME payload
    // (one row) and each is cited.
    let voice_keys: Vec<String> = if voices.is_empty() {
        let mut heads = vec![head];
        heads.extend(further_heads.iter().copied());
        let mut keys: Vec<String> =
            crate::federation::self_roster::roster_at_heads(dir, &identity, &heads)
                .await
                .expect("typed_fixtures: the roster at the named heads")
                .into_iter()
                .collect();
        let me = kid_or_keep(seed);
        if !keys.contains(&me) {
            keys.push(me);
        }
        keys
    } else {
        voices.iter().map(|v| kid_or_keep(v)).collect()
    };
    // T2-fix5 — a voice with no binding under the identity (a stranger, a
    // key the witness means the door to refuse) cites what is held of it:
    // its key:record. The fixture states the row; the DOOR judges the cites
    // (`typed::check_eviction_cites`), so a stranger's voice reaches the
    // door's refusal instead of panicking here.
    let mut cites = Vec::new();
    for k in &voice_keys {
        match super::typed::eviction_cites(dir, &identity, std::slice::from_ref(k)).await {
            Ok(c) => cites.extend(c),
            Err(_) => {
                let record = dir
                    .edition2_statements_about(
                        ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY,
                        k,
                    )
                    .await
                    .expect("typed_fixtures: read the voice's key:records")
                    .iter()
                    .filter_map(|st| RowId::of_statement(st))
                    .next()
                    .unwrap_or_else(|| {
                        panic!("typed_fixtures: the voice {k} has no key:record held")
                    });
                cites.push(record);
            }
        }
    }
    cites.sort();
    cites.dedup();
    let p = occurrence_revocation_payload(
        &r,
        author,
        None,
        &head,
        &further_heads,
        &cites,
        asserted_at_ms,
    )
    .expect("typed_fixtures: occurrence revocation payload");
    typed_statement(
        seed,
        as_identity.then_some(identity.as_str()),
        &r.occurrence_key_id,
        OCCURRENCE_REVOCATION_PREFIX,
        &p,
    )
}

/// A `revocation:{entity_type}:{reason}:v1` statement by `revoker` about
/// the key `subject` (seeds or E0 kids), authored by the revoker.
///
/// # Panics
/// An instant before 1970.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn revocation_statement(
    revoker: &str,
    subject: &str,
    entity_type: &str,
    reason: &str,
    revoked_at: chrono::DateTime<chrono::Utc>,
    effective_at: chrono::DateTime<chrono::Utc>,
    revoked_after: Option<chrono::DateTime<chrono::Utc>>,
    asserted_at_ms: u64,
) -> Vec<u8> {
    let p = revocation_payload(
        &kid_or_keep(revoker),
        entity_type,
        reason,
        revoked_at,
        effective_at,
        revoked_after,
        None,
        None,
        asserted_at_ms,
    )
    .expect("typed_fixtures: revocation payload");
    typed_statement(revoker, None, subject, REVOCATION_PREFIX, &p)
}

/// A `takedown_notice:{basis}:v1` statement by `signer` (the claimant for
/// a legal basis; one founder's voice for `steward_purge`, whose claimant is
/// the trust root `claimant`). `holders` are seeds or E0 kids.
///
/// # Panics
/// An instant before 1970.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn takedown_statement(
    signer: &str,
    basis: &str,
    claimant: &str,
    content_sha256: &[u8; 32],
    holders: &[&str],
    expires_at: chrono::DateTime<chrono::Utc>,
    asserted_at_ms: u64,
) -> Vec<u8> {
    let holders: Vec<String> = holders.iter().map(|h| kid_or_keep(h)).collect();
    let notice = NoticeText {
        claim_text: "the content infringes the claimant's work".to_owned(),
        good_faith_statement: "stated in good faith".to_owned(),
        jurisdiction: "US".to_owned(),
    };
    let claimant = kid_or_keep(claimant);
    let p = takedown_payload(
        basis,
        &claimant,
        content_sha256,
        &holders,
        &notice,
        ms(expires_at),
        asserted_at_ms,
    )
    .expect("typed_fixtures: takedown payload");
    typed_statement(signer, None, &claimant, TAKEDOWN_PREFIX, &p)
}

/// A `custody:ack:v1` report by `device` about `blob_sha256` (`here` with
/// `size`, `none` without), placed at `cohort_scope` (`target` its group
/// where the scope has one). The device is the row's `sub`.
///
/// # Panics
/// A size/state or scope/target mismatch.
#[must_use]
pub fn custody_statement(
    device: &str,
    blob_sha256: &[u8; 32],
    size: Option<u64>,
    cohort_scope: &str,
    target: Option<&str>,
    asserted_at_ms: u64,
) -> Vec<u8> {
    let state = if size.is_some() {
        CustodyState::Here
    } else {
        CustodyState::None
    };
    let target = target.map(kid_or_keep);
    let p = custody_payload(
        &kid_or_keep(device),
        blob_sha256,
        state,
        size,
        cohort_scope,
        target.as_deref(),
        asserted_at_ms,
    )
    .expect("typed_fixtures: custody payload");
    typed_statement(device, None, device, CUSTODY_PREFIX, &p)
}

/// A `key_grant:{axis}:v1` statement by `signer`: `row`'s wrap to its
/// recipient (the row's `sub`). Every key id in `row` (the axis's group,
/// owner, minter, the recipient) is a seed or an E0 kid.
///
/// # Panics
/// An `at_rest_sha256` that is not 64 hex.
#[must_use]
pub fn key_grant_statement(signer: &str, row: &KeyGrantRow, asserted_at_ms: u64) -> Vec<u8> {
    let axis = match &row.axis {
        KeyGrantAxis::Epoch {
            community_key_id,
            minter_key_id,
            epoch,
        } => KeyGrantAxis::Epoch {
            community_key_id: kid_or_keep(community_key_id),
            minter_key_id: kid_or_keep(minter_key_id),
            epoch: *epoch,
        },
        KeyGrantAxis::Content {
            at_rest_sha256,
            cohort_scope,
            owner_key_id,
        } => KeyGrantAxis::Content {
            at_rest_sha256: at_rest_sha256.clone(),
            cohort_scope: cohort_scope.clone(),
            owner_key_id: kid_or_keep(owner_key_id),
        },
        KeyGrantAxis::Stream {
            stream_id,
            epoch,
            cohort_scope,
            owner_key_id,
        } => KeyGrantAxis::Stream {
            stream_id: stream_id.clone(),
            epoch: *epoch,
            cohort_scope: cohort_scope.clone(),
            owner_key_id: kid_or_keep(owner_key_id),
        },
    };
    let recipient = kid_or_keep(&row.wrap.recipient_key_id);
    let flipped = KeyGrantRow {
        axis,
        wrap: GrantWrap {
            recipient_key_id: recipient.clone(),
            wrap_algorithm: row.wrap.wrap_algorithm.clone(),
            wrapped_dek: row.wrap.wrapped_dek.clone(),
        },
    };
    let p = key_grant_payload(&kid_or_keep(signer), &flipped, asserted_at_ms)
        .expect("typed_fixtures: key grant payload");
    typed_statement(signer, None, &recipient, KEY_GRANT_PREFIX, &p)
}

/// A `delivery_ack:{stream_id}:v1` statement by `subscriber` (the
/// row's `sub`).
#[must_use]
pub fn delivery_receipt_statement(
    subscriber: &str,
    stream_id: &str,
    epoch: u64,
    k: u64,
    chunk_root: &[u8; 32],
    asserted_at_ms: u64,
) -> Vec<u8> {
    let p = delivery_receipt_payload(
        &kid_or_keep(subscriber),
        stream_id,
        epoch,
        k,
        chunk_root,
        asserted_at_ms,
    );
    typed_statement(subscriber, None, subscriber, DELIVERY_RECEIPT_PREFIX, &p)
}

/// PRE4-rename (CC v1.0-rc22-pre4) — the family's EARLIER wire name, which
/// no alias admits. Only the refusal witnesses (I6401) offer it.
pub const EARLIER_DELIVERY_RECEIPT_PREFIX: &str = "delivery_receipt:{stream_id}";

/// A receipt statement under the EARLIER family name and dimension
/// (`delivery_receipt:{stream_id}`, `delivery_receipt:<stream_id>:v1`), every
/// other member as [`delivery_receipt_statement`] states it: what a node that
/// has not moved to CC v1.0-rc22-pre4 would send.
#[must_use]
pub fn earlier_delivery_receipt_statement(
    subscriber: &str,
    stream_id: &str,
    epoch: u64,
    k: u64,
    chunk_root: &[u8; 32],
    asserted_at_ms: u64,
) -> Vec<u8> {
    let mut p = delivery_receipt_payload(
        &kid_or_keep(subscriber),
        stream_id,
        epoch,
        k,
        chunk_root,
        asserted_at_ms,
    );
    if let Value::Map(entries) = &mut p {
        for (key, v) in entries.iter_mut() {
            if matches!(key, Value::Text(t) if t == "dimension") {
                *v = Value::Text(format!("delivery_receipt:{stream_id}:v1"));
            }
        }
    }
    typed_statement(
        subscriber,
        None,
        subscriber,
        EARLIER_DELIVERY_RECEIPT_PREFIX,
        &p,
    )
}

/// PRE4-cosign (CC v1.0-rc22-pre4) — the retired family's registry prefix,
/// which no producer of this node writes any more.
pub const RETIRED_COSIGN_PREFIX: &str = "cosign:{state}";

/// A `cosign:{state}:v1` statement by `signer` naming `event` (its row id)
/// by `refs.target`, `sub` the event's group, in the shape a node before CC
/// v1.0-rc22-pre4 sent it (`author`, `dimension`, `refs`, `asserted_at`).
/// The family is retired: only the refusal witnesses (I6403) offer it.
#[must_use]
pub fn retired_cosign_statement(
    signer: &str,
    state: &str,
    sub: &str,
    event: &RowId,
    asserted_at_ms: u64,
) -> Vec<u8> {
    let text = |s: &str| Value::Text(s.to_owned());
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        (
            "author",
            text(&identity_ref(&thumbprint(signing_key(signer).public_key()))),
        ),
        ("dimension", text(&format!("cosign:{state}:v1"))),
        (
            "refs",
            Value::Map(vec![(
                text(super::typed::TARGET_ROLE),
                ciris_verify_core::edition2::row_ref(&event.0),
            )]),
        ),
    ];
    m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(&text(*k)));
    let payload = Value::Map(m.into_iter().map(|(k, v)| (text(k), v)).collect());
    typed_statement(signer, None, sub, RETIRED_COSIGN_PREFIX, &payload)
}

/// [`typed_statement`] at a row type other than `scores`.
///
/// # Panics
/// A payload with no `asserted_at`.
#[must_use]
pub fn typed_statement_as(
    seed: &str,
    row_type: &str,
    sub: &str,
    family_prefix: &str,
    payload: &Value,
) -> Vec<u8> {
    let key = signing_key(seed);
    let iss = identity_ref(&thumbprint(key.public_key()));
    sign_row_statement(
        &key,
        &iss,
        &kid_or_keep(sub),
        row_type,
        &namespace_match::family_id(family_prefix),
        payload,
        vec![],
    )
    .expect("typed_fixtures: sign a typed-plane statement")
}

/// `granter`'s `trust:accepts:v1` edge to `key` (seeds or E0 kids): the
/// edition-2 twin of `grant_trust(SignedTrustGrant)`. `classes` are the
/// v1.3 `trust_domains` (a Registry grant's); `valid_until` its
/// `expires_at`; `cohort_scope` `self` makes it anonymous. Scope
/// `infra:serve`, as the trust-root fixtures' acceptance edges.
#[must_use]
pub fn trust_accepts_statement(
    granter: &str,
    key: &str,
    classes: &[&str],
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    cohort_scope: &str,
    asserted_at_ms: u64,
) -> Vec<u8> {
    let classes: Vec<String> = classes.iter().map(|c| (*c).to_owned()).collect();
    let p = trust_accepts_payload(
        &kid_or_keep(granter),
        &[crate::federation::trust_root::INFRA_SERVE_SCOPE],
        &classes,
        valid_until.map(ms),
        cohort_scope,
        asserted_at_ms,
    );
    typed_statement_as(granter, "delegates_to", key, TRUST_PREFIX, &p)
}

/// v62.0.0 (T2-fix6; CC 3.2 T4a) — [`trust_accepts_statement`] as THIS
/// directory's door reads it: an edge to a community root `dir` holds names
/// the lineage head it attaches on (`attached_head_digest`, the held head's
/// row hash as bytes, as W1's `fixture_trust_root::put_acceptance` states
/// it). Without it a new labelled acceptance edge to a held root is
/// `TrustRootHeadUnnamed`. An edge to a key (no held community) is
/// [`trust_accepts_statement`] unchanged.
///
/// # Panics
/// A directory read failure, or a held head whose row hash is not hex.
pub async fn trust_accepts_edge<D: crate::federation::FederationDirectory + ?Sized>(
    dir: &D,
    granter: &str,
    key: &str,
    classes: &[&str],
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    cohort_scope: &str,
    asserted_at_ms: u64,
) -> Vec<u8> {
    let head = dir
        .lookup_community(&kid_or_keep(key))
        .await
        .expect("typed_fixtures: read the root the edge names")
        .map(|c| {
            hex::decode(&c.persist_row_hash)
                .expect("typed_fixtures: the held head's row hash is hex")
        });
    let Some(head) = head else {
        return trust_accepts_statement(
            granter,
            key,
            classes,
            valid_until,
            cohort_scope,
            asserted_at_ms,
        );
    };
    let classes: Vec<String> = classes.iter().map(|c| (*c).to_owned()).collect();
    let p = trust_accepts_payload(
        &kid_or_keep(granter),
        &[crate::federation::trust_root::INFRA_SERVE_SCOPE],
        &classes,
        valid_until.map(ms),
        cohort_scope,
        asserted_at_ms,
    );
    let Value::Map(mut m) = p else {
        unreachable!("trust_accepts_payload is a map")
    };
    m.push((
        Value::Text(crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST.to_owned()),
        Value::Bytes(head),
    ));
    m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    typed_statement_as(granter, "delegates_to", key, TRUST_PREFIX, &Value::Map(m))
}

/// `granter`'s `withdraws` of its held edge `edge` to `key`: the edition-2
/// twin of `revoke_trust(SignedTrustRevocation)`.
#[must_use]
pub fn trust_withdraws_statement(
    granter: &str,
    key: &str,
    edge: &RowId,
    asserted_at_ms: u64,
) -> Vec<u8> {
    let p = withdraws_payload(&kid_or_keep(granter), edge, asserted_at_ms);
    typed_statement_as(granter, "withdraws", key, TRUST_PREFIX, &p)
}
