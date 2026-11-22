//! v62.0.0 (wave T2) — **the typed planes at the edition-2 door**, on sqlite
//! and postgres. Every statement goes through the one entry
//! (`ingest::put_statement`); every typed row is read back through the
//! directory's own readers.
//!
//! - **I3150** a user self's occurrence revocation is a roster change, run
//!   by the self-roster's two-path decision (O1's `gate_edition2`): one roster
//!   key's voice is `Pending` and nothing is in
//!   `federation_identity_occurrence_revocations`; the voice that meets the
//!   strict majority lands it; a re-put is `Row { new: false }`.
//! - **I3151** an `occurrence_key_id` that is not the row's `sub` is
//!   `edition2_payload_invalid`, and the voice is not kept.
//! - **I3152** a stranger's voice is refused, and not kept.
//! - Every bind and revocation names its head (REQUIRED); the chain starts
//!   at the genesis key's own `key:record` row.
//! - **I3185** (CC27 item 2, CC 2.7.8) a revocation naming H1 after its
//!   successor H2 landed here is VOID: every voice (all three roster keys)
//!   is kept and `Pending`, nothing is revoked, and the receipt settles
//!   `void_superseded`.
//! - **I3186** a revocation naming a head this node does not hold WAITS: its
//!   voices are kept `Pending`, never refused; delivering the head re-plans
//!   it at write time (no manual executor call) and it lands.
//! - **I3187** an evicted key's voice (signed before its eviction took
//!   effect) is admitted but not counted at the head after the eviction;
//!   the same revocation naming the pre-eviction head is VOID
//!   (`void_superseded`).
//! - **I3188** (CC rc21 7f94be1) an eviction with no `refs.also.cites`, or
//!   whose cites miss the voice's own key:record and binding, is
//!   `edition2_payload_invalid` and not kept.
//! - **I3189** a cited row this node does not hold: the eviction WAITS
//!   (`Pending`, kept), nothing is revoked.
//! - **I3190** with every voice's key record and binding cited, the counted
//!   eviction lands.
//! - **I3191** served from a cursor just before it, the eviction's page
//!   carries every cited row's statements: they travel with it (CC 2.7.5).
//! - **I3153** a revocation of a key by itself lands in
//!   `federation_revocations` (`revocations_for_subject`), through
//!   `put_revocation`.
//! - **I3154** a revocation of another's key with no slash conferral is
//!   refused by the revocation door's authority rule, and not kept.
//! - **I3155** a revocation whose `revoked_at` is text is `edition2_payload_invalid`.
//! - **I3156** a revocation of a key not held waits (the retryable
//!   `federation_attester_key_unknown`).
//! - **I3157** a custody report lands in `federation_attestations`, read by
//!   `parse_custody_ack`.
//! - **I3158** a custody report about another device is refused
//!   (`custody_ack_not_self_report`).
//! - **I3159** a custody report with `expires_at` is `edition2_payload_invalid`.
//! - **I2439** (PIN-fix9c; the Constitution's ruling of 2026-11-21, CC
//!   2.4.1) a `supersedes` of a custody report rides the custody plane: one
//!   about another device is refused `custody_ack_not_self_report`, as the
//!   report itself is, and not held; a conforming one lands in
//!   `federation_attestations` and is READ as a custody report (its own
//!   size) by the gate's own parse.
//! - **I2441** (PIN-fix9c.rev2; the Constitution's ruling of 2026-11-22, CC
//!   2.4.1.1) a `supersedes` of a cosignature, a key grant, an entity
//!   revocation, an occurrence revocation or a `key:revocation` (a family
//!   that is never withdrawn) is refused `supersedes_not_a_replacement` from
//!   its bytes, and nothing is kept.
//! - **I3160** a content key grant lands and is projected (the pending index
//!   a grant admitted before its bytes waits in).
//! - **I3161** a key grant with a text `wrapped_dek` is `edition2_payload_invalid`.
//! - **I3162** a delivery receipt of an unpublished root WAITS for the
//!   publication (v62.0.0 wave GC7, CC 2.7.3): kept, `Pending`, held with
//!   reason `receipt_root_unpublished`, and no receipt row.
//! - **I3163** against a published root it lands in
//!   `federation_stream_delivery_receipts` and as its signed row.
//! - **I3164** a second root at the same `k` is kept and concludes nothing
//!   (held, `receipt_equivocation`; v62.0.0 wave GC7), the first receipt
//!   standing.
//! - **I3165** a cosign statement is kept beside its event in
//!   `ceg_statements` only (`Voice`), never in `federation_attestations`.
//! - **I3166** a cosign of an event not held WAITS: kept and `Pending`
//!   (a fold hold, `link_unheld`), never refused.
//! - **I3167** a `steward_purge` notice is kept, voice by voice, `Pending`,
//!   never as an attestation row.
//! - **I3168** a `dmca512` notice passes the notice shape on its projected
//!   envelope and meets the takedown authority (unbound content): v62 wave
//!   GC2, it is HELD (`Pending`, kept, no typed row) with reason
//!   `takedown_content_unbound`.
//! - **I3169** the purge door's count reads the notice's voices: with none
//!   held it is `no_cosignature`; with two founders' voices held, the fold
//!   (`cosign::edition2_voices`) is exactly their issuers and the count
//!   reaches the trust root (`root_not_held` here).
//! - **I3170** `put_blob` stores the bytes and admits the edition-2
//!   holding claim; the holder directory (`list_holders_of`) names the
//!   holder.
//! - **I3171** a claim naming another blob is refused before any byte is
//!   stored.
//! - **I3178** a claim the statement door refuses after the bytes landed
//!   reaps the bytes that call stored: a refused claim leaves no bytes.
//! - **I3181** the reap is conditional (one transaction): a blob a `here`
//!   claim names is kept; unclaimed local bytes are reaped.
//! - **I3192** this node's own `here` claim about bytes it does not hold
//!   waits (`blob_not_held`) and concludes when the bytes land; another
//!   holder's claim is not judged by this node's holding.
//! - **I3193** the eviction window: an own claim admitted between the
//!   eviction's retraction and its commit is taken out by the eviction's
//!   re-fold (held `blob_not_held`).
//! - **I3197** (T2-fix11; CC 6.1.3) the put door's stored claim is the
//!   holder's composite statement (its row id, no PQC half), and
//!   `put_blob_with_scope` refuses a claim placed at another scope
//!   (`custody_ack_scope_mismatch`) before anything is written.
//! - **I3172** a `trust:accepts:v1` edge projects into the v1.3 trust plane
//!   (`lookup_trust`): `trusted_by` = its granter, `Direct`, `valid_until`
//!   as `expires_at`, and `trust_type` DERIVED `temporary`.
//! - **I3173** the reciprocal edge makes both rows `partnered`.
//! - **I3174** the granter's `withdraws` expires the row, and the other end
//!   is re-derived `temporary`.
//! - **I3175** a `self`-scope edge is `anonymous`.
//! - **I3176** the purge count over a trust root's head: one voice of three
//!   is `quorum_not_met`; a voice holding no seat is `not_a_seat`.
//! - **I3177** two voices of three meet the head's `majority`: the counted
//!   signers are exactly the voices.
//! - **I3179** an edition-2 purge bundle carries the notice's statements: a
//!   second node admits them through its own door (it then holds both
//!   voices) and counts them by the edition-2 count (`root_not_held` with no
//!   root held: the end-to-end rooted replication waits on W1's root).
//! - **I3180** a carried statement the receiver's door refuses refuses the
//!   bundle (the tampered statement is not held); statements naming two rows
//!   are `notice_malformed`.

use chrono::{TimeZone, Utc};
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;
use ciris_verify_core::namespace_match::family_id;

use super::door_invariants::fixture::{iref, key, key_record, map};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use super::typed::{
    cosign_payload,
    custody_payload,
    delivery_receipt_payload,
    key_grant_payload,
    occurrence_revocation_payload,
    revocation_payload,
    takedown_payload,
    // X2 build fix: the trust:accepts witnesses (T2, after the import list was cut).
    trust_accepts_payload,
    withdraws_payload,
    NoticeText,
    COSIGN_PREFIX,
    CUSTODY_PREFIX,
    DELIVERY_RECEIPT_PREFIX,
    KEY_GRANT_PREFIX,
    OCCURRENCE_REVOCATION_PREFIX,
    REVOCATION_PREFIX,
    TAKEDOWN_PREFIX,
    TRUST_PREFIX,
};
use crate::federation::blobs::GrantWrap;
use crate::federation::custody_ack::{parse_custody_ack, CustodyState};
use crate::federation::key_grant::{KeyGrantAxis, KeyGrantRow};
use crate::federation::types::IdentityOccurrenceRevocation;
use crate::federation::{malformed_row, BlobStorage, Error, FederationDirectory};

type K = CompositeSigningKey;

fn at(ms: u64) -> chrono::DateTime<Utc> {
    Utc.timestamp_millis_opt(i64::try_from(ms).unwrap())
        .single()
        .unwrap()
}

fn now_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap()
}

fn sign_as(k: &K, iss: &str, sub: &str, prefix: &str, p: &Value) -> Vec<u8> {
    sign_row_statement(k, iss, sub, "scores", &family_id(prefix), p, vec![]).unwrap()
}

fn sign(k: &K, sub: &str, prefix: &str, p: &Value) -> Vec<u8> {
    sign_as(k, &iref(k), sub, prefix, p)
}

fn rid(st: &[u8]) -> RowId {
    RowId::of_statement(st).unwrap()
}

/// `p` with `member` set to `v` (the map re-sorted).
fn with_member(p: &Value, member: &str, v: Value) -> Value {
    let mut m: Vec<(String, Value)> = p
        .as_map()
        .unwrap()
        .iter()
        .filter_map(|(k, v)| k.as_text().map(|k| (k.to_owned(), v.clone())))
        .filter(|(k, _)| k != member)
        .collect();
    m.push((member.to_owned(), v));
    map(m.iter().map(|(k, v)| (k.as_str(), v.clone())).collect())
}

async fn register<D: FederationDirectory + ?Sized>(d: &D, keys: &[&K]) {
    for k in keys {
        put_statement(d, &key_record(k, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
}

async fn put<D: FederationDirectory + ?Sized>(d: &D, st: &[u8]) -> Result<StatementOutcome, Error> {
    put_statement(d, st, None, INGEST_TIER).await
}

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

async fn kept<D: FederationDirectory + ?Sized>(d: &D, st: &[u8]) -> bool {
    !d.edition2_voices(&rid(st)).await.unwrap().is_empty()
}

/// The self-roster chain's first link for `k` (CC27 item 2): its own
/// `key:record` row (the statement [`register`] put).
fn genesis_head(k: &K) -> RowId {
    rid(&key_record(k, &["user"], 0, None))
}

/// Bind `occ` as an occurrence of `identity` with a roster of one (O1's
/// door: the occurrence key's own statement, then the identity's), naming
/// the genesis head. Returns the bind's row id (the next head).
async fn bind<D: FederationDirectory + ?Sized>(d: &D, identity: &K, occ: &K) -> RowId {
    bind_at(d, identity, occ, &genesis_head(identity), &[identity]).await
}

async fn is_revoked<D: FederationDirectory + ?Sized>(d: &D, identity: &str, occ: &str) -> bool {
    d.list_identity_occurrence_revocations_for(identity)
        .await
        .unwrap()
        .iter()
        .any(|r| r.occurrence_key_id == occ)
}

/// The cites an eviction voiced by `keys` states (CC rc21 7f94be1): each
/// key's `key:record` and binding (`typed::eviction_cites`).
async fn cites_of<D: FederationDirectory + ?Sized>(
    d: &D,
    identity: &str,
    keys: &[&String],
) -> Vec<RowId> {
    let keys: Vec<String> = keys.iter().map(|k| (*k).clone()).collect();
    super::typed::eviction_cites(d, identity, &keys)
        .await
        .expect("the voices' key records and bindings are held")
}

async fn occurrence_revocation_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (alice, phone, mallory) = (key(110), key(111), key(112));
    register(d, &[&alice, &phone, &mallory]).await;
    let h1 = bind(d, &alice, &phone).await;
    let (a, ph) = (iref(&alice), iref(&phone));
    let t = now_ms();
    // The revocation takes effect a second after its voices are signed, so
    // phone's voice (signed at `t`) is the live key's: a re-put of it after
    // the landing is the held statement again, not a revoked key's.
    let rev = IdentityOccurrenceRevocation {
        identity_key_id: a.clone(),
        occurrence_key_id: ph.clone(),
        revoked_at: at(t),
        effective_at: at(t + 1_000),
        reason: None,
        witness_set: vec![],
        persist_row_hash: String::new(),
    };
    let cites = cites_of(d, &a, &[&a, &ph]).await;
    let p = occurrence_revocation_payload(&rev, None, None, &h1, &[], &cites, t).unwrap();

    // I3152 — a stranger's voice.
    let stranger = sign_as(&mallory, &a, &ph, OCCURRENCE_REVOCATION_PREFIX, &p);
    assert!(put(d, &stranger).await.is_err(), "I3152 refused");
    assert!(!kept(d, &stranger).await, "I3152 not kept");

    // I3151 — the occurrence is the row's sub.
    let bad = occurrence_revocation_payload(
        &IdentityOccurrenceRevocation {
            occurrence_key_id: iref(&mallory),
            ..rev.clone()
        },
        None,
        None,
        &h1,
        &[],
        &cites,
        t,
    )
    .unwrap();
    let bad = sign(&alice, &ph, OCCURRENCE_REVOCATION_PREFIX, &bad);
    let e = put(d, &bad).await.unwrap_err();
    assert_eq!(reason(&e), malformed_row::EDITION2_PAYLOAD_INVALID, "I3151");
    assert!(!kept(d, &bad).await, "I3151 not kept");

    // I3150 — counted at the roster's strict majority ({alice, phone}: 2).
    let v1 = sign(&alice, &ph, OCCURRENCE_REVOCATION_PREFIX, &p);
    let out = put(d, &v1).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Pending { new: true, .. }),
        "I3150 one of two is short: {out:?}"
    );
    assert!(!is_revoked(d, &a, &ph).await, "I3150 nothing lands short");
    let v2 = sign_as(&phone, &a, &ph, OCCURRENCE_REVOCATION_PREFIX, &p);
    assert_eq!(rid(&v1), rid(&v2), "I3150 one row, two voices");
    let out = put(d, &v2).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "I3150 the majority lands it: {out:?}"
    );
    assert!(is_revoked(d, &a, &ph).await, "I3150 in the typed table");
    let out = put(d, &v2).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: false, .. }),
        "I3150 a re-put: {out:?}"
    );
}

/// Bind `occ` under `identity` naming the self-roster head `head`; the
/// author statements are one per key of `voices`, each signed AS the
/// identity. Returns the bind's row id (the next head).
async fn bind_at<D: FederationDirectory + ?Sized>(
    d: &D,
    identity: &K,
    occ: &K,
    head: &RowId,
    voices: &[&K],
) -> RowId {
    // A minute back: a later statement asserted before a later eviction
    // still finds the occurrence live (I3187).
    let mut m = vec![
        ("asserted_at", Value::Uint(now_ms() - 60_000)),
        ("author", Value::Text(iref(identity))),
        ("identity_key_id", Value::Text(iref(identity))),
        ("occurrence_key_id", Value::Text(iref(occ))),
        ("device_class", Value::Text("phone".into())),
    ];
    m.push((
        "refs",
        map(vec![(
            "head",
            ciris_verify_core::edition2::row_ref(&head.0),
        )]),
    ));
    let p = map(m);
    let own = sign(occ, &iref(occ), "identity:occurrence", &p);
    put(d, &own).await.expect("the occurrence key's own voice");
    let mut last = None;
    for v in voices {
        last = Some(
            put(
                d,
                &sign_as(v, &iref(identity), &iref(occ), "identity:occurrence", &p),
            )
            .await
            .expect("an author voice"),
        );
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "bound: {last:?}"
    );
    rid(&own)
}

/// I3185 (CC27 item 2, CC 2.7.8): an occurrence revocation naming a head
/// whose successor this node has landed is VOID: kept, Pending, settled
/// `void_superseded`, never landed.
async fn named_head_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (alice, phone, tablet) = (key(210), key(211), key(212));
    register(d, &[&alice, &phone, &tablet]).await;
    let (a, ph) = (iref(&alice), iref(&phone));
    // H1: {alice, phone}. H2 (naming H1, counted over it): {alice, phone, tablet}.
    let h1 = bind_at(d, &alice, &phone, &genesis_head(&alice), &[&alice]).await;
    bind_at(d, &alice, &tablet, &h1, &[&alice, &phone]).await;
    let t = now_ms();
    let rev = |occ: &str| IdentityOccurrenceRevocation {
        identity_key_id: a.clone(),
        occurrence_key_id: occ.to_owned(),
        revoked_at: at(t),
        effective_at: at(t),
        reason: None,
        witness_set: vec![],
        persist_row_hash: String::new(),
    };

    // I3185 (CC 2.7.8, O1 v8) — phone's revocation names H1, whose successor
    // H2 this node has landed: the row is VOID here. Every voice is kept and
    // answers Pending, nothing is revoked (not even with all three of the
    // roster's keys voicing it), and the receipt settles `void_superseded`.
    let cites = cites_of(d, &a, &[&a, &ph, &iref(&tablet)]).await;
    let p =
        occurrence_revocation_payload(&rev(ph.as_str()), None, None, &h1, &[], &cites, t).unwrap();
    let mut row = None;
    for v in [&alice, &tablet, &phone] {
        let st = sign_as(v, &a, &ph, OCCURRENCE_REVOCATION_PREFIX, &p);
        row = Some(rid(&st));
        let out = put(d, &st)
            .await
            .expect("I3185 a superseded head is never refused");
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I3185 a row on a superseded head is VOID: {out:?}"
        );
        assert!(kept(d, &st).await, "I3185 the voice is kept");
    }
    assert!(
        !is_revoked(d, &a, &ph).await,
        "I3185 a VOID row revokes nothing"
    );
    let receipt = d
        .edition2_roster_proposal(&row.expect("a row").hex())
        .await
        .unwrap()
        .expect("I3185 the proposal's receipt");
    assert_eq!(
        receipt.outcome.as_deref(),
        Some(crate::federation::self_roster::VOID_OUTCOME),
        "I3185 settled void_superseded"
    );

    // I3186 has its own body (`waiting_head_body`).
}

/// The two statements of a bind of `occ` under `identity` naming `head`,
/// voiced by `voices` (each AS the identity), NOT put: [own, authors..].
fn bind_statements(identity: &K, occ: &K, head: &RowId, voices: &[&K]) -> Vec<Vec<u8>> {
    let p = map(vec![
        ("asserted_at", Value::Uint(now_ms() - 60_000)),
        ("author", Value::Text(iref(identity))),
        ("identity_key_id", Value::Text(iref(identity))),
        ("occurrence_key_id", Value::Text(iref(occ))),
        ("device_class", Value::Text("phone".into())),
        (
            "refs",
            map(vec![(
                "head",
                ciris_verify_core::edition2::row_ref(&head.0),
            )]),
        ),
    ]);
    let mut out = vec![sign(occ, &iref(occ), "identity:occurrence", &p)];
    out.extend(
        voices
            .iter()
            .map(|v| sign_as(v, &iref(identity), &iref(occ), "identity:occurrence", &p)),
    );
    out
}

/// I3186 (the lead's correction): a revocation naming a head this node does
/// not hold WAITS (kept, `Pending`, never refused), and lands once the head
/// arrives.
async fn waiting_head_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (carol, phone, tablet) = (key(230), key(231), key(232));
    register(d, &[&carol, &phone, &tablet]).await;
    let (c, ph) = (iref(&carol), iref(&phone));
    let h1 = bind_at(d, &carol, &phone, &genesis_head(&carol), &[&carol]).await;
    // H2: tablet's bind (naming H1, voiced by carol and phone), signed but
    // NOT yet delivered here.
    let h2_statements = bind_statements(&carol, &tablet, &h1, &[&carol, &phone]);
    let h2 = rid(&h2_statements[0]);
    let t = now_ms();
    let rev = IdentityOccurrenceRevocation {
        identity_key_id: c.clone(),
        occurrence_key_id: ph.clone(),
        revoked_at: at(t),
        effective_at: at(t),
        reason: None,
        witness_set: vec![],
        persist_row_hash: String::new(),
    };
    let cites = cites_of(d, &c, &[&c, &ph]).await;
    let p = occurrence_revocation_payload(&rev, None, None, &h2, &[], &cites, t).unwrap();
    let voices = [
        sign(&carol, &ph, OCCURRENCE_REVOCATION_PREFIX, &p),
        sign_as(&phone, &c, &ph, OCCURRENCE_REVOCATION_PREFIX, &p),
    ];
    for v in &voices {
        let out = put(d, v)
            .await
            .expect("I3186 a row naming an unheld head is never refused");
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I3186 it waits on its head: {out:?}"
        );
        assert!(kept(d, v).await, "I3186 the voice is kept");
    }
    assert!(
        !is_revoked(d, &c, &ph).await,
        "I3186 nothing lands while H2 is absent"
    );
    // The head arrives (tablet's bind lands over H1: carol + phone, 2 of 2).
    let mut last = None;
    for st in &h2_statements {
        last = Some(put(d, st).await.expect("H2 is delivered"));
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "H2 landed: {last:?}"
    );
    // No manual step: the head's arrival re-plans the waiting proposal at
    // write time (O1 declares the head read, `fold::reads(row:<head>)`, and
    // G0's write-time re-fold re-runs it). carol + phone are 2 of 3 over H2.
    assert!(
        is_revoked(d, &c, &ph).await,
        "I3186 the row lands as soon as its head is delivered, with no manual re-plan"
    );
}

/// I3188–I3191 (CC rc21 7f94be1): an eviction cites its voices' keys; the
/// cited rows travel with it.
async fn eviction_cites_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (dave, phone) = (key(240), key(241));
    register(d, &[&dave, &phone]).await;
    let (dv, ph) = (iref(&dave), iref(&phone));
    let h1 = bind(d, &dave, &phone).await;
    let t = now_ms();
    let rev = IdentityOccurrenceRevocation {
        identity_key_id: dv.clone(),
        occurrence_key_id: ph.clone(),
        revoked_at: at(t),
        effective_at: at(t + 1_000),
        reason: None,
        witness_set: vec![],
        persist_row_hash: String::new(),
    };
    let payload = |cites: &[RowId], at_ms: u64| {
        occurrence_revocation_payload(&rev, None, None, &h1, &[], cites, at_ms).unwrap()
    };

    // I3188 — no cite: Invalid at the door, not kept.
    let st = sign(
        &dave,
        &ph,
        OCCURRENCE_REVOCATION_PREFIX,
        &payload(&[] as &[RowId], t),
    );
    let e = put(d, &st).await.unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I3188 no cites"
    );
    assert!(!kept(d, &st).await, "I3188 not kept");
    // A voice whose own key:record (and binding) is not among the cites:
    // Invalid, not kept.
    let only_dave = cites_of(d, &dv, &[&dv]).await;
    let st = sign_as(
        &phone,
        &dv,
        &ph,
        OCCURRENCE_REVOCATION_PREFIX,
        &payload(only_dave.as_slice(), t + 1),
    );
    let e = put(d, &st).await.unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I3188 the voice's key is not cited"
    );
    assert!(!kept(d, &st).await, "I3188 not kept");

    // I3189 — a cited row this node does not hold: the eviction WAITS.
    let mut with_ghost = cites_of(d, &dv, &[&dv, &ph]).await;
    with_ghost.push(RowId([5; 32]));
    let st = sign(
        &dave,
        &ph,
        OCCURRENCE_REVOCATION_PREFIX,
        &payload(with_ghost.as_slice(), t + 2),
    );
    let out = put(d, &st)
        .await
        .expect("I3189 an unheld cite is never a refusal");
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I3189 it waits for the cited row: {out:?}"
    );
    assert!(kept(d, &st).await, "I3189 kept while it waits");
    assert!(!is_revoked(d, &dv, &ph).await, "I3189 nothing lands");

    // I3190 — the full set: dave's voice (1 of 2) waits on the count; phone's
    // (as dave) lands it.
    let full = cites_of(d, &dv, &[&dv, &ph]).await;
    let p = payload(full.as_slice(), t + 3);
    let v_dave = sign(&dave, &ph, OCCURRENCE_REVOCATION_PREFIX, &p);
    let out = put(d, &v_dave).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I3190 one of two: {out:?}"
    );
    let out = put(
        d,
        &sign_as(&phone, &dv, &ph, OCCURRENCE_REVOCATION_PREFIX, &p),
    )
    .await
    .unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I3190 the cited, counted eviction lands: {out:?}"
    );
    assert!(is_revoked(d, &dv, &ph).await, "I3190 revoked");

    // I3191 — served from a cursor just before the eviction, the page also
    // carries every cited row's statements (they were admitted earlier, so
    // only their travelling with it puts them in the page).
    let all = d.edition2_statements_since(None, 1_000).await.unwrap();
    let pos = all
        .iter()
        .position(|s| s.bytes == v_dave)
        .expect("the eviction is held");
    assert!(pos > 0, "the cited rows were admitted before the eviction");
    let cursor = all[pos - 1].cursor;
    let page = super::serve::statements_served_to(d, Some(&cursor), 1_000, None)
        .await
        .unwrap();
    for c in &full {
        for st in d.edition2_voices(c).await.unwrap() {
            assert!(
                page.statements.iter().any(|s| s.bytes == st),
                "I3191 the cited row {} travels with the eviction",
                c.hex()
            );
        }
    }
}

/// I3187 (CC's ruling on refs.head; CC 2.7.8): an evicted key's voice is
/// not counted at the head after its eviction, and a revocation naming the
/// pre-eviction head is VOID once this node has landed its successor.
async fn evicted_voice_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (bob, phone, tablet) = (key(220), key(221), key(222));
    register(d, &[&bob, &phone, &tablet]).await;
    let (b, ph, tb) = (iref(&bob), iref(&phone), iref(&tablet));
    let h1 = bind_at(d, &bob, &phone, &genesis_head(&bob), &[&bob]).await;
    let h2 = bind_at(d, &bob, &tablet, &h1, &[&bob, &phone]).await;
    let t1 = now_ms();
    let rev = |occ: &str, at_ms: u64| IdentityOccurrenceRevocation {
        identity_key_id: b.clone(),
        occurrence_key_id: occ.to_owned(),
        revoked_at: at(at_ms),
        effective_at: at(at_ms),
        reason: None,
        witness_set: vec![],
        persist_row_hash: String::new(),
    };
    // H3: phone evicted (named H2; bob + tablet are 2 of 3).
    let evict_cites = cites_of(d, &b, &[&b, &tb]).await;
    let evict = occurrence_revocation_payload(
        &rev(ph.as_str(), t1),
        None,
        None,
        &h2,
        &[],
        &evict_cites,
        t1,
    )
    .unwrap();
    put(d, &sign(&bob, &ph, OCCURRENCE_REVOCATION_PREFIX, &evict))
        .await
        .unwrap();
    let out = put(
        d,
        &sign_as(&tablet, &b, &ph, OCCURRENCE_REVOCATION_PREFIX, &evict),
    )
    .await
    .unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I3187 phone evicted: {out:?}"
    );
    // The tablet's revocation names the CURRENT head H3 = {bob, tablet} and
    // was signed BEFORE the eviction took effect, so phone's voice passes
    // the door (its seat was live then) but phone is not on H3: it is not
    // counted. bob alone is 1 of 2.
    let h3 = rid(&sign(&bob, &ph, OCCURRENCE_REVOCATION_PREFIX, &evict));
    let t0 = t1 - 5_000;
    let tablet_cites = cites_of(d, &b, &[&b, &ph, &tb]).await;
    let p = occurrence_revocation_payload(
        &rev(tb.as_str(), t0),
        None,
        None,
        &h3,
        &[],
        &tablet_cites,
        t0,
    )
    .unwrap();
    for v in [&phone, &bob] {
        let out = put(d, &sign_as(v, &b, &tb, OCCURRENCE_REVOCATION_PREFIX, &p))
            .await
            .expect("I3187 an evicted key's voice is a statement, never a refusal");
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I3187 the evicted key is not counted at the head after its eviction: {out:?}"
        );
    }
    assert!(!is_revoked(d, &b, &tb).await, "I3187 nothing lands");
    let out = put(
        d,
        &sign_as(&tablet, &b, &tb, OCCURRENCE_REVOCATION_PREFIX, &p),
    )
    .await
    .unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "I3187 bob + tablet are 2 of 2 over H3: {out:?}"
    );

    // The same revocation naming the superseded H2 is VOID (CC 2.7.8): even
    // bob + tablet do not land it; it is kept and settled void_superseded.
    // T2-fix13 — signed just BEFORE tablet's eviction takes effect (t0):
    // after it, tablet's seat is gone and the door's key-of-issuer check
    // refuses its voice (`kid_not_of_iss`) before the VOID rule is reached.
    let stale = occurrence_revocation_payload(
        &rev(tb.as_str(), t0 - 1),
        None,
        None,
        &h2,
        &[],
        &evict_cites,
        t0 - 1,
    )
    .unwrap();
    let mut row = None;
    for v in [&bob, &tablet] {
        let st = sign_as(v, &b, &tb, OCCURRENCE_REVOCATION_PREFIX, &stale);
        row = Some(rid(&st));
        let out = put(d, &st).await.unwrap();
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "I3187 a row on the superseded H2 is VOID: {out:?}"
        );
    }
    let receipt = d
        .edition2_roster_proposal(&row.expect("a row").hex())
        .await
        .unwrap()
        .expect("I3187 the stale proposal's receipt");
    assert_eq!(
        receipt.outcome.as_deref(),
        Some(crate::federation::self_roster::VOID_OUTCOME),
        "I3187 settled void_superseded"
    );
}

async fn revocation_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (subj, other) = (key(120), key(121));
    register(d, &[&subj, &other]).await;
    let (s, o) = (iref(&subj), iref(&other));
    let t = now_ms();
    let payload = |author: &str| {
        revocation_payload(
            author,
            "agent",
            "compromise",
            at(t),
            at(t),
            None,
            None,
            None,
            t,
        )
        .unwrap()
    };

    // I3154 — another's key, no slash conferral.
    let st = sign(&other, &s, REVOCATION_PREFIX, &payload(&o));
    let e = put(d, &st).await.unwrap_err();
    assert!(
        [
            "federation_delegated_scope_unauthorized",
            "federation_node_identity_unset"
        ]
        .contains(&e.kind()),
        "I3154 the revocation door's authority rule: {e:?}"
    );
    assert!(!kept(d, &st).await, "I3154 not kept");

    // I3155 — a missing member.
    let bad = sign(
        &subj,
        &s,
        REVOCATION_PREFIX,
        &with_member(&payload(&s), "revoked_at", Value::Text("x".into())),
    );
    assert_eq!(
        reason(&put(d, &bad).await.unwrap_err()),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I3155"
    );

    // I3156 — a subject not held waits.
    let unheld = iref(&key(122));
    let st = sign(&subj, &unheld, REVOCATION_PREFIX, &payload(&s));
    assert_eq!(
        put(d, &st).await.unwrap_err().kind(),
        "federation_attester_key_unknown",
        "I3156"
    );

    // I3153 — the key revokes itself.
    let st = sign(&subj, &s, REVOCATION_PREFIX, &payload(&s));
    let out = put(d, &st).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "I3153 {out:?}"
    );
    let key_row = d.lookup_public_key(&s).await.unwrap().unwrap();
    let digest = crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
        &key_row.pubkey_ed25519_base64,
    )
    .unwrap()
    .to_hex();
    let held = d.revocations_for_subject(&digest).await.unwrap();
    assert!(
        held.iter()
            .any(|r| r.revocation_id == rid(&st).hex() && r.revoking_key_id == s),
        "I3153 in federation_revocations: {held:?}"
    );
}

async fn custody_cosign_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (dev, other) = (key(130), key(131));
    register(d, &[&dev, &other]).await;
    let di = iref(&dev);
    let t = now_ms();
    let blob = [0x5c; 32];
    let p = custody_payload(
        &di,
        &blob,
        CustodyState::Here,
        Some(4096),
        "federation",
        None,
        t,
    )
    .unwrap();

    // I3159 — the custody map is closed.
    let bad = sign(
        &dev,
        &di,
        CUSTODY_PREFIX,
        &with_member(&p, "expires_at", Value::Uint(t + 1)),
    );
    assert_eq!(
        reason(&put(d, &bad).await.unwrap_err()),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I3159"
    );

    // I3158 — about another device.
    let st = sign(&dev, &iref(&other), CUSTODY_PREFIX, &p);
    let e = put(d, &st).await.unwrap_err();
    assert!(
        e.to_string().contains("custody_ack_not_self_report"),
        "I3158 {e:?}"
    );
    assert!(
        d.get_attestation(&rid(&st).hex()).await.unwrap().is_none(),
        "I3158 not held"
    );

    // I3157 — lands, read by the gate's own parse.
    let st = sign(&dev, &di, CUSTODY_PREFIX, &p);
    let out = put(d, &st).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "I3157 {out:?}"
    );
    let a = d
        .get_attestation(&rid(&st).hex())
        .await
        .unwrap()
        .expect("I3157 in federation_attestations");
    let ack = parse_custody_ack(&a)
        .unwrap()
        .expect("I3157 a custody report");
    assert_eq!(ack.blob_sha256_hex, hex::encode(blob), "I3157");
    assert_eq!(ack.size, Some(4096), "I3157");

    // I3166 — a cosign of an event not held WAITS (CC 2.7.3): kept,
    // `Pending`, never refused.
    let ghost = RowId([7; 32]);
    let c = sign(
        &other,
        &di,
        COSIGN_PREFIX,
        &cosign_payload(&iref(&other), "signature", &ghost, t),
    );
    let out = put(d, &c)
        .await
        .expect("I3166 a row naming an unheld row is never refused");
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I3166 it waits for the event: {out:?}"
    );
    assert!(kept(d, &c).await, "I3166 kept while it waits");

    // I3165 — a cosign is kept beside its event only.
    let c = sign(
        &other,
        &di,
        COSIGN_PREFIX,
        &cosign_payload(&iref(&other), "signature", &rid(&st), t),
    );
    let out = put(d, &c).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Voice { new: true, .. }),
        "I3165 {out:?}"
    );
    assert!(kept(d, &c).await, "I3165 in ceg_statements");
    assert!(
        d.get_attestation(&rid(&c).hex()).await.unwrap().is_none(),
        "I3165 never an attestation row"
    );
}

/// I2439: a replacement custody report is judged by the custody plane.
async fn replacement_custody_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (dev, other) = (key(132), key(133));
    register(d, &[&dev, &other]).await;
    let di = iref(&dev);
    let t = now_ms();
    let blob = [0x5d; 32];
    let report = |size: u64, at: u64| {
        custody_payload(
            &di,
            &blob,
            CustodyState::Here,
            Some(size),
            "federation",
            None,
            at,
        )
        .unwrap()
    };
    let original = sign(&dev, &di, CUSTODY_PREFIX, &report(4096, t));
    assert!(
        matches!(put(d, &original).await, Ok(StatementOutcome::Row { .. })),
        "I2439 the report it replaces lands"
    );
    let replacing = |p: Value| {
        with_member(
            &p,
            "refs",
            map(vec![(
                "target",
                ciris_verify_core::edition2::row_ref(&rid(&original).0),
            )]),
        )
    };
    // About another device: the report's own refusal.
    let plain = put(
        d,
        &sign(&dev, &iref(&other), CUSTODY_PREFIX, &report(8192, t + 1)),
    )
    .await
    .unwrap_err();
    assert!(
        plain.to_string().contains("custody_ack_not_self_report"),
        "I2439 the report about another device: {plain:?}"
    );
    let bad = sign_typed(
        &dev,
        "supersedes",
        &iref(&other),
        CUSTODY_PREFIX,
        &replacing(report(8192, t + 1)),
    );
    let e = put(d, &bad).await.unwrap_err();
    assert!(
        e.to_string().contains("custody_ack_not_self_report"),
        "I2439 the replacement about another device is refused as the report is: {e:?}"
    );
    assert!(
        d.get_attestation(&rid(&bad).hex()).await.unwrap().is_none(),
        "I2439 not held"
    );
    // A conforming replacement lands.
    let good = sign_typed(
        &dev,
        "supersedes",
        &di,
        CUSTODY_PREFIX,
        &replacing(report(8192, t + 2)),
    );
    let out = put(d, &good).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { .. })),
        "I2439 a conforming replacement lands: {out:?}"
    );
    let a = d
        .get_attestation(&rid(&good).hex())
        .await
        .unwrap()
        .expect("I2439 in federation_attestations");
    let ack = parse_custody_ack(&a)
        .unwrap()
        .expect("I2439 the replacement is read as a custody report");
    assert_eq!(ack.size, Some(8192), "I2439 the replacement's own size");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2439_a_replacement_custody_report_rides_the_plane_sqlite() {
    Box::pin(replacement_custody_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2439_a_replacement_custody_report_rides_the_plane_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(replacement_custody_body(&b)).await;
}

/// I2441: a family that is never withdrawn is never replaced.
async fn never_replaced_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (k, other) = (key(134), key(135));
    register(d, &[&k, &other]).await;
    let (ki, oi) = (iref(&k), iref(&other));
    let t = now_ms();
    let target = RowId([0x6e; 32]);
    let p = map(vec![
        ("asserted_at", Value::Uint(t)),
        ("author", Value::Text(ki.clone())),
        (
            "refs",
            map(vec![(
                "target",
                ciris_verify_core::edition2::row_ref(&target.0),
            )]),
        ),
    ]);
    for (prefix, sub) in [
        (COSIGN_PREFIX, oi.as_str()),
        (KEY_GRANT_PREFIX, oi.as_str()),
        (REVOCATION_PREFIX, oi.as_str()),
        (OCCURRENCE_REVOCATION_PREFIX, oi.as_str()),
        ("key:revocation", oi.as_str()),
    ] {
        let st = sign_typed(&k, "supersedes", sub, prefix, &p);
        let e = put(d, &st).await.unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::SUPERSEDES_NOT_A_REPLACEMENT,
            "I2441 a supersedes of {prefix}: {e}"
        );
        assert!(!kept(d, &st).await, "I2441 {prefix}: nothing is kept");
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2441_a_never_withdrawn_family_is_never_replaced_sqlite() {
    Box::pin(never_replaced_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2441_a_never_withdrawn_family_is_never_replaced_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(never_replaced_body(&b)).await;
}

async fn takedown_body<D: FederationDirectory + ?Sized>(d: &D) {
    let (root, f1, f2, claimant) = (key(140), key(141), key(142), key(143));
    register(d, &[&root, &f1, &f2, &claimant]).await;
    let t = now_ms();
    let exp = t + 7 * 24 * 3_600_000;
    let notice = NoticeText {
        claim_text: "a claim".into(),
        good_faith_statement: "in good faith".into(),
        jurisdiction: "US".into(),
    };
    let holders = vec![iref(&f1)];

    // I3167 — a steward purge is counted by the purge door: kept, Pending.
    let p = takedown_payload(
        "steward_purge",
        &iref(&root),
        &[0x44; 32],
        &holders,
        &notice,
        exp,
        t,
    )
    .unwrap();
    let v1 = sign(&f1, &iref(&root), TAKEDOWN_PREFIX, &p);
    let v2 = sign(&f2, &iref(&root), TAKEDOWN_PREFIX, &p);
    let purge_reason = |e: Error| match e {
        Error::PurgeRefused { body, .. } => body["reason"].as_str().unwrap_or_default().to_owned(),
        other => panic!("I3169 a purge refusal, not {other:?}"),
    };
    assert_eq!(
        purge_reason(
            crate::federation::steward_purge::verify_purge_authorisation_edition2(d, &rid(&v1))
                .await
                .unwrap_err()
        ),
        crate::federation::steward_purge::unauthorised_reason::NO_COSIGNATURE,
        "I3169 no voice held, nothing to count"
    );
    for v in [&v1, &v2] {
        let out = put(d, v).await.unwrap();
        assert!(
            matches!(out, StatementOutcome::Pending { new: true, .. }),
            "I3167 {out:?}"
        );
    }
    assert_eq!(rid(&v1), rid(&v2), "I3167 one notice");
    assert_eq!(
        d.edition2_voices(&rid(&v1)).await.unwrap().len(),
        2,
        "I3167 both voices kept"
    );
    assert!(
        d.get_attestation(&rid(&v1).hex()).await.unwrap().is_none(),
        "I3167 never an attestation row (its row door is held shut)"
    );
    assert_eq!(
        crate::federation::cosign::edition2_voices(d, &rid(&v1))
            .await
            .unwrap(),
        [iref(&f1), iref(&f2)]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "I3169 the purge count's input is the notice's voices"
    );
    assert_eq!(
        purge_reason(
            crate::federation::steward_purge::verify_purge_authorisation_edition2(d, &rid(&v1))
                .await
                .unwrap_err()
        ),
        crate::federation::steward_purge::unauthorised_reason::ROOT_NOT_HELD,
        "I3169 the voices reach the trust root's count (no root is held here)"
    );
    assert_eq!(
        purge_reason(
            crate::federation::steward_purge::purge_rows_edition2(
                d,
                &crate::federation::steward_purge::PurgeSelection::mock_llm_traces(),
                &rid(&v1),
                "t2-node",
            )
            .await
            .unwrap_err()
        ),
        crate::federation::steward_purge::unauthorised_reason::ROOT_NOT_HELD,
        "I3169 purge_rows_edition2 runs the voice count before any selection"
    );

    // I3168 — a legal basis meets the takedown authority on its projection.
    let ci = iref(&claimant);
    let p = takedown_payload("dmca512", &ci, &[0x45; 32], &holders, &notice, exp, t).unwrap();
    let st = sign(&claimant, &ci, TAKEDOWN_PREFIX, &p);
    // v62.0.0 (wave GC2; CC 2.7.3) — the authority reads OTHER rows (the
    // content's binding): the notice is HELD, concluding nothing, with the
    // refusal's token as its reason (it concludes when a binding lands:
    // `attestation_fold_invariants` I3710–I3713).
    let out = put(d, &st)
        .await
        .expect("I3168 the shape passed; the notice is held");
    assert!(
        matches!(out, StatementOutcome::Pending { new: true, .. }),
        "I3168 held, concluding nothing: {out:?}"
    );
    assert!(kept(d, &st).await, "I3168 kept");
    assert!(
        d.get_attestation(&rid(&st).hex()).await.unwrap().is_none(),
        "I3168 no typed row"
    );
    assert_eq!(
        super::fold::why_held(d, &rid(&st))
            .await
            .unwrap()
            .map(|h| h.reason)
            .as_deref(),
        Some("takedown_content_unbound"),
        "I3168 the authority's token is the reason"
    );
}

async fn key_grant_body<B: FederationDirectory + BlobStorage + Sync>(d: &B) {
    let (alice, phone) = (key(150), key(151));
    register(d, &[&alice, &phone]).await;
    let _h1 = bind(d, &alice, &phone).await;
    let (a, ph) = (iref(&alice), iref(&phone));
    let sha = [0x62; 32];
    let row = KeyGrantRow {
        axis: KeyGrantAxis::Content {
            at_rest_sha256: hex::encode(sha),
            cohort_scope: "self".into(),
            owner_key_id: a.clone(),
        },
        wrap: GrantWrap {
            recipient_key_id: ph.clone(),
            wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.to_owned(),
            wrapped_dek: "{\"v\":2,\"ct\":\"AAAA\"}".to_owned(),
        },
    };
    let p = key_grant_payload(&a, &row, now_ms()).unwrap();

    // I3161 — the wrap is bytes.
    let bad = sign(
        &alice,
        &ph,
        KEY_GRANT_PREFIX,
        &with_member(&p, "wrapped_dek", Value::Text("not bytes".into())),
    );
    assert_eq!(
        reason(&put(d, &bad).await.unwrap_err()),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I3161"
    );

    // I3160 — lands, and the grant projection ran.
    let st = sign(&alice, &ph, KEY_GRANT_PREFIX, &p);
    let out = put(d, &st).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "I3160 {out:?}"
    );
    let held = d
        .get_attestation(&rid(&st).hex())
        .await
        .unwrap()
        .expect("I3160 in federation_attestations");
    assert_eq!(KeyGrantRow::from_attestation(&held).unwrap(), row, "I3160");
    let pending = d.key_grant_pending_list(&sha, "self").await.unwrap();
    assert!(
        pending
            .iter()
            .any(|(id, signer)| *id == rid(&st).hex() && *signer == a),
        "I3160 projected (pending its bytes): {pending:?}"
    );
}

/// I3192 (T2-fix7; E8-fix2's residual, BLOB_ENCRYPTION_AT_REST §11.5) —
/// THIS node's own `here` claim about bytes it does not hold WAITS
/// (`Pending`, kept, held `blob_not_held`, no attestation row); when the
/// bytes land (the edition-2 blob door, whose store touches the blob) it
/// concludes. Another holder's claim about bytes this node does not hold is
/// not judged by this node's holding (it lands).
async fn own_claim_body<B>(d: &B, node: &K)
where
    B: FederationDirectory + BlobStorage + crate::federation::blob_admit::BlobWriteStore + Sync,
{
    use sha2::Digest as _;
    let other = key(251);
    register(d, &[node, &other]).await;
    let (ni, oi) = (iref(node), iref(&other));
    let bytes = b"t2 own claim, bytes not held yet".to_vec();
    let sha: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let size = bytes.len() as u64;
    let claim = |k: &K, kid: &str, at: u64| {
        sign(
            k,
            kid,
            CUSTODY_PREFIX,
            &custody_payload(
                kid,
                &sha,
                CustodyState::Here,
                Some(size),
                "federation",
                None,
                at,
            )
            .unwrap(),
        )
    };
    let t = now_ms() - 10_000;
    let early = claim(node, &ni, t);
    let out = put(d, &early)
        .await
        .expect("I3192 an own claim about bytes not held is never refused");
    assert!(
        matches!(out, StatementOutcome::Pending { .. }),
        "I3192 it waits for the bytes: {out:?}"
    );
    assert!(kept(d, &early).await, "I3192 kept while it waits");
    assert!(
        d.get_attestation(&rid(&early).hex())
            .await
            .unwrap()
            .is_none(),
        "I3192 no claim row while the bytes are not held"
    );
    let why = super::fold::why_held(d, &rid(&early))
        .await
        .unwrap()
        .map(|h| h.reason);
    assert_eq!(
        why.as_deref(),
        Some(super::fold::reason::BLOB_NOT_HELD),
        "I3192 the reason"
    );
    // Another holder's claim about the same (unheld) bytes: not this node's
    // holding to judge.
    let theirs = claim(&other, &oi, t);
    assert!(
        matches!(put(d, &theirs).await.unwrap(), StatementOutcome::Row { .. }),
        "I3192 another holder's claim lands"
    );
    // The bytes land (with a later claim): the early claim concludes.
    d.put_blob(
        &sha,
        crate::federation::BlobBody::Inline(bytes.clone()),
        None,
        &claim(node, &ni, t + 1_000),
    )
    .await
    .expect("I3192 the bytes land");
    assert!(
        d.get_attestation(&rid(&early).hex())
            .await
            .unwrap()
            .is_some(),
        "I3192 the waiting claim concluded when its bytes landed"
    );
}

/// I3193 (T2-fix8; E8-fix2's residual) — the eviction window: the community
/// epoch eviction retracts this node's own claims, then (paused there) a NEW
/// own `here` claim is admitted while the bytes are still held, then the
/// eviction commits. Its post-commit touch (`refold_on_blob`) re-folds the
/// claim: it is taken out (no attestation row) and held `blob_not_held`, so
/// no claim names bytes this node no longer holds.
async fn eviction_window_body<B>(d: &B)
where
    B: FederationDirectory
        + BlobStorage
        + Sync
        + crate::store::test_hooks::ArmEvictPause
        + crate::federation::canonical_community_invariants::bodies::SetNodeKey,
{
    use crate::federation::community_dek::lifecycle_support as ls;
    use crate::federation::community_dek::orchestrate::{
        encrypt_and_cascade_community, sweep_rotated_epochs,
    };
    use crate::federation::holding_claim::{emit_holding_claim, HoldingClaimOutcome};
    let run = uuid::Uuid::new_v4().simple().to_string();
    let comm = format!("t2-win-comm-{run}");
    let alice = format!("t2-win-alice-{run}");
    let alice_occ = format!("t2-win-alice-occ-{run}");
    let node = format!("t2-win-node-{run}");
    let signer = ls::seed_community_with_node(d, &comm, &[(&alice, &alice_occ)], &node).await;
    let comm = ls::id_of(&comm);
    d.set_node_key(signer.federation_id().await);
    // T2-fix13 — the minter is the key the sweep reads the epochs under
    // (`sweep_rotated_epochs`: `signer.federation_id()`). The derived id named
    // another (community, minter) pointer, so the sweep found no past epoch,
    // evicted nothing and never reached the window (`Elapsed`).
    let minter = signer.federation_id().await;
    let sealed =
        encrypt_and_cascade_community(d, &comm, b"t2 eviction window", None, Some(&minter))
            .await
            .expect("I3193 the sealed bytes");
    let sha = sealed.at_rest_sha256;
    d.community_dek_bump_epoch(&comm, &minter).await.unwrap();
    d.community_dek_set_retain_past_epochs(&comm, &minter, Some(0))
        .await
        .unwrap();
    let pause = d.arm_evict_pause();
    let sweep = sweep_rotated_epochs(d, &comm, &signer, crate::host::clock::now());
    let window = async {
        tokio::time::timeout(crate::store::test_hooks::PAUSE_CEILING, pause.reached())
            .await
            .expect("I3193 the eviction reaches its window");
        let out = emit_holding_claim(d, &signer, &sha, crate::host::clock::now()).await;
        pause.resume();
        out
    };
    let (report, claimed) = tokio::join!(sweep, window);
    let report = report.expect("I3193 the sweep");
    assert_eq!(
        report.evicted_objects, 1,
        "I3193 the old epoch's object is evicted"
    );
    let claimed = claimed.expect("I3193 the claim in the window (bytes still held)");
    let HoldingClaimOutcome::Emitted { attestation_id, .. } = claimed else {
        panic!("I3193 precondition: this node claims the held bytes: {claimed:?}");
    };
    assert!(
        d.blob_head(&sha).await.unwrap().is_none(),
        "I3193 the bytes are gone"
    );
    assert!(
        d.get_attestation(&attestation_id).await.unwrap().is_none(),
        "I3193 the claim admitted in the window is taken out by the eviction's re-fold"
    );
    let id: [u8; 32] = hex::decode(&attestation_id)
        .expect("a row id")
        .try_into()
        .expect("32 bytes");
    let why = super::fold::why_held(d, &RowId(id))
        .await
        .unwrap()
        .map(|h| h.reason);
    assert_eq!(
        why.as_deref(),
        Some(super::fold::reason::BLOB_NOT_HELD),
        "I3193 held, the bytes not held"
    );
}

async fn blob_body<B>(d: &B)
where
    B: FederationDirectory + BlobStorage + crate::federation::blob_admit::BlobWriteStore + Sync,
{
    use sha2::Digest as _;
    let h = key(170);
    register(d, &[&h]).await;
    let hi = iref(&h);
    let bytes = b"t2 edition-2 blob".to_vec();
    let sha: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let size = bytes.len() as u64;
    let claim = |sha: &[u8; 32]| {
        sign(
            &h,
            &hi,
            CUSTODY_PREFIX,
            &custody_payload(
                &hi,
                sha,
                CustodyState::Here,
                Some(size),
                "federation",
                None,
                now_ms(),
            )
            .unwrap(),
        )
    };

    // I3171 — a claim naming another blob stores nothing.
    let e = d
        .put_blob(
            &sha,
            crate::federation::BlobBody::Inline(bytes.clone()),
            None,
            &claim(&[0x01; 32]),
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("names blob"), "I3171 {e:?}");
    assert!(d.blob_head(&sha).await.unwrap().is_none(), "I3171 no bytes");

    // I3178 — a claim the statement door refuses (its signer's key is not
    // held) after the bytes landed: the bytes this call stored are reaped.
    let stranger = key(171);
    let si = iref(&stranger);
    let other = b"t2 bytes of a refused claim".to_vec();
    let other_sha: [u8; 32] = sha2::Sha256::digest(&other).into();
    let refused = sign(
        &stranger,
        &si,
        CUSTODY_PREFIX,
        &custody_payload(
            &si,
            &other_sha,
            CustodyState::Here,
            Some(other.len() as u64),
            "federation",
            None,
            now_ms(),
        )
        .unwrap(),
    );
    assert!(
        d.put_blob(
            &other_sha,
            crate::federation::BlobBody::Inline(other),
            None,
            &refused
        )
        .await
        .is_err(),
        "I3178 the claim is refused"
    );
    assert!(
        d.blob_head(&other_sha).await.unwrap().is_none(),
        "I3178 a refused claim leaves no bytes"
    );
    assert!(!kept(d, &refused).await, "I3178 nor its statement");

    // I3170 — the bytes and the claim; the holder directory reads it.
    let st = claim(&sha);
    d.put_blob(
        &sha,
        crate::federation::BlobBody::Inline(bytes.clone()),
        Some("text/plain"),
        &st,
    )
    .await
    .expect("I3170 the edition-2 blob door");
    assert!(
        matches!(
            d.get_blob(&sha).await.unwrap(),
            Some(crate::federation::BlobBody::Inline(ref b)) if *b == bytes
        ),
        "I3170 the bytes"
    );
    assert!(kept(d, &st).await, "I3170 the claim statement");
    let holders = crate::federation::holding_claim::list_holders_of(d, &sha)
        .await
        .unwrap();
    assert!(
        holders.contains(&hi),
        "I3170 the holder directory: {holders:?}"
    );
    // I3197 (T2-fix11; CC 6.1.3) — the claim row the put door stored is the
    // holder's composite statement: its row id is the statement's, and it
    // carries no bound-hybrid PQC half.
    let row = d
        .get_attestation(&rid(&st).hex())
        .await
        .unwrap()
        .expect("I3197 the claim row, under its row id");
    assert!(
        crate::federation::edition2::fixture_switch::carried_statement(&row).is_some(),
        "I3197 the claim row carries its statement"
    );
    assert!(
        row.scrub_signature_pqc.is_none(),
        "I3197 one composite signature, no bound-hybrid PQC half"
    );
    // I3197 — `put_blob_with_scope` judges the claim's placement before
    // anything is written: a claim placed at `self` for a commons write is
    // refused `custody_ack_scope_mismatch`, and stores nothing.
    let placed = b"t2 fix11 misplaced claim".to_vec();
    let placed_sha: [u8; 32] = sha2::Sha256::digest(&placed).into();
    let misplaced = sign(
        &h,
        &hi,
        CUSTODY_PREFIX,
        &custody_payload(
            &hi,
            &placed_sha,
            CustodyState::Here,
            Some(placed.len() as u64),
            crate::federation::types::cohort_scope::SELF,
            None,
            now_ms(),
        )
        .unwrap(),
    );
    let e = d
        .put_blob_with_scope(
            None,
            &placed_sha,
            crate::federation::BlobBody::Inline(placed),
            None,
            &misplaced,
            crate::federation::types::cohort_scope::FEDERATION,
            crate::federation::StorageFloor::resolved(
                crate::federation::types::cohort_scope::CryptoTier::Plaintext,
            ),
            None,
        )
        .await
        .expect_err("I3197 a misplaced claim is refused");
    assert!(
        e.to_string().contains("custody_ack_scope_mismatch"),
        "I3197 by name: {e}"
    );
    assert!(
        d.blob_head(&placed_sha).await.unwrap().is_none(),
        "I3197 nothing is written"
    );

    // I3181 — the reap is conditional, in one transaction: bytes a `here`
    // claim names are kept (a concurrent writer whose claim landed keeps
    // them); unclaimed bytes are reaped.
    assert!(
        !d.delete_blob_unless_claimed(&sha).await.unwrap(),
        "I3181 a claimed blob is not reaped"
    );
    assert!(
        d.blob_head(&sha).await.unwrap().is_some(),
        "I3181 its bytes stay"
    );
    let loose = b"t2 unclaimed local bytes".to_vec();
    let loose_sha: [u8; 32] = sha2::Sha256::digest(&loose).into();
    // A commons write names its scope as the constant (I14: a commons door
    // reaches the floor only by naming a commons scope literally).
    d.store_blob_local(
        &loose_sha,
        crate::federation::BlobBody::Inline(loose),
        None,
        crate::federation::types::cohort_scope::FEDERATION,
        crate::federation::StorageFloor::resolved(
            crate::federation::types::cohort_scope::CryptoTier::Plaintext,
        ),
        None,
        None,
    )
    .await
    .expect("local bytes");
    assert!(
        d.delete_blob_unless_claimed(&loose_sha).await.unwrap(),
        "I3181 unclaimed bytes are reaped"
    );
    assert!(
        d.blob_head(&loose_sha).await.unwrap().is_none(),
        "I3181 gone"
    );
}

fn sign_typed(k: &K, row_type: &str, sub: &str, prefix: &str, p: &Value) -> Vec<u8> {
    sign_row_statement(k, &iref(k), sub, row_type, &family_id(prefix), p, vec![]).unwrap()
}

fn accepts(granter: &K, key: &str, scope: &str, until: Option<u64>, t: u64) -> Vec<u8> {
    let p = trust_accepts_payload(
        &iref(granter),
        &[crate::federation::trust_root::INFRA_SERVE_SCOPE],
        &[],
        until,
        scope,
        t,
    );
    sign_typed(granter, "delegates_to", key, TRUST_PREFIX, &p)
}

async fn trust_body<D: FederationDirectory + ?Sized>(d: &D) {
    use crate::federation::types::{TrustRelationship, TrustType};
    let (a, b, c) = (key(180), key(181), key(182));
    register(d, &[&a, &b, &c]).await;
    let (ai, bi, ci) = (iref(&a), iref(&b), iref(&c));
    let t = now_ms();
    let until = t + 24 * 3_600_000;

    // I3172 — temporary: one edge, A accepts B.
    let ab = accepts(&a, &bi, "federation", Some(until), t);
    assert!(
        matches!(put(d, &ab).await.unwrap(), StatementOutcome::Row { .. }),
        "I3172"
    );
    let row = d
        .lookup_trust(&bi)
        .await
        .unwrap()
        .expect("I3172 B's trust row");
    assert_eq!(row.trusted_by, ai, "I3172 the granter is the edge's iss");
    assert_eq!(
        row.trust_type,
        TrustType::Temporary,
        "I3172 derived: temporary"
    );
    assert_eq!(row.trust_relationship, TrustRelationship::Direct, "I3172");
    assert_eq!(row.trust_domains, None, "I3172");
    assert_eq!(row.expires_at, Some(at(until)), "I3172 valid_until");

    // I3173 — partnered: the reciprocal edge, B accepts A.
    let ba = accepts(&b, &ai, "federation", Some(until), t + 1);
    put(d, &ba).await.unwrap();
    assert_eq!(
        d.lookup_trust(&ai)
            .await
            .unwrap()
            .expect("I3173")
            .trust_type,
        TrustType::Partnered,
        "I3173 A is partnered"
    );
    assert_eq!(
        d.lookup_trust(&bi)
            .await
            .unwrap()
            .expect("I3173")
            .trust_type,
        TrustType::Partnered,
        "I3173 B is re-derived partnered when the reciprocal arrives"
    );

    // I3174 — B withdraws its edge: A's row expires; B is temporary again.
    let w = sign_typed(
        &b,
        "withdraws",
        &ai,
        TRUST_PREFIX,
        &withdraws_payload(&bi, &rid(&ba), t + 2),
    );
    put(d, &w).await.expect("I3174 the granter's withdraws");
    let row = d
        .lookup_trust(&ai)
        .await
        .unwrap()
        .expect("I3174 the row stays");
    assert!(
        row.expires_at.is_some_and(|e| e <= Utc::now()),
        "I3174 expired by the withdraws: {row:?}"
    );
    assert_eq!(
        d.lookup_trust(&bi)
            .await
            .unwrap()
            .expect("I3174")
            .trust_type,
        TrustType::Temporary,
        "I3174 B re-derived temporary when the reciprocal is withdrawn"
    );

    // I3175 — anonymous: a self-scope edge.
    let ac = accepts(&a, &ci, "self", None, t + 3);
    put(d, &ac).await.expect("I3175 a self-scope edge");
    assert_eq!(
        d.lookup_trust(&ci)
            .await
            .unwrap()
            .expect("I3175")
            .trust_type,
        TrustType::Anonymous,
        "I3175 derived: anonymous"
    );
}

/// I3176–I3177: the purge door's count over voices against a trust root's
/// head (handed in: no edition-2 path seats a ROOTED trust root yet).
async fn purge_quorum_body<D: FederationDirectory + ?Sized>(d: &D) {
    use crate::federation::canonical_community::counts_voices_over_head;
    use crate::federation::steward_purge::unauthorised_reason as why;
    use crate::federation::types::{Community, CommunityMember, SignedCommunity};
    let (f1, f2, f3, x) = (key(190), key(191), key(192), key(193));
    register(d, &[&f1, &f2, &f3, &x]).await;
    let head = SignedCommunity {
        community: Community {
            community_key_id: iref(&key(194)),
            community_name: "t2 root".into(),
            members: [&f1, &f2, &f3]
                .iter()
                .map(|k| CommunityMember {
                    key_id: iref(k),
                    joined_at: at(1_000),
                    role: Some("founder".into()),
                })
                .collect(),
            founded_at: at(1_000),
            consensus_protocol: "majority".into(),
            policy_blob: None,
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        },
        authority_key_id: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        supersede_proof: None,
        cosignatures: vec![],
        lineage: vec![],
    };
    fn set(ks: &[&K]) -> std::collections::BTreeSet<String> {
        ks.iter().map(|k| iref(k)).collect()
    }
    let now = Utc::now();
    let one = counts_voices_over_head(d, &head, &set(&[&f1]), now)
        .await
        .unwrap();
    assert_eq!(
        one.map_err(|(r, _)| r),
        Err(why::QUORUM_NOT_MET),
        "I3176 one voice of three is short of the root's majority"
    );
    let stranger = counts_voices_over_head(d, &head, &set(&[&f1, &x]), now)
        .await
        .unwrap();
    assert_eq!(
        stranger.map_err(|(r, _)| r),
        Err(why::NOT_A_SEAT),
        "I3176 a voice that holds no seat is a refusal, not a discount"
    );
    let two = counts_voices_over_head(d, &head, &set(&[&f1, &f2]), now)
        .await
        .unwrap();
    assert_eq!(
        two.map_err(|(r, _)| r),
        Ok(set(&[&f1, &f2])),
        "I3177 two voices of three meet the root's majority"
    );
}

/// I3179–I3180: an edition-2 purge bundle replicated to a second node.
async fn purge_replication_body<D: FederationDirectory + ?Sized>(a: &D, b: &D) {
    use crate::federation::steward_purge::{
        self as sp, unauthorised_reason as why, PurgeBundle, StewardPurgeNotice,
    };
    let (root, f1, f2) = (key(200), key(201), key(202));
    for n in [a, b] {
        register(n, &[&root, &f1, &f2]).await;
    }
    let t = now_ms();
    let notice = NoticeText {
        claim_text: "a claim".into(),
        good_faith_statement: "in good faith".into(),
        jurisdiction: "US".into(),
    };
    let p = takedown_payload(
        "steward_purge",
        &iref(&root),
        &[0x46; 32],
        &[iref(&f1)],
        &notice,
        t + 7 * 24 * 3_600_000,
        t,
    )
    .unwrap();
    let v1 = sign(&f1, &iref(&root), TAKEDOWN_PREFIX, &p);
    let v2 = sign(&f2, &iref(&root), TAKEDOWN_PREFIX, &p);
    for v in [&v1, &v2] {
        put(a, v).await.unwrap();
    }
    fn bundle(statements: &[Vec<u8>]) -> PurgeBundle {
        PurgeBundle {
            notice: StewardPurgeNotice {
                envelope: sp::edition2_notice_envelope(statements),
                cosignatures: vec![],
            },
            record_ids: vec![],
            derived_from: vec![],
            admitted_at: Utc::now(),
        }
    }
    let reason_of = |e: Error| match e {
        Error::PurgeRefused { body, .. } => body["reason"].as_str().unwrap_or_default().to_owned(),
        other => other.kind().to_owned(),
    };

    // I3180 — a carried statement the receiver's door refuses refuses the
    // bundle, and the tampered statement is not held there.
    let mut tampered = v2.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let e = sp::apply_replicated_purge(b, &bundle(&[v1.clone(), tampered.clone()]), "node-b")
        .await
        .unwrap_err();
    assert_ne!(
        reason_of(e),
        why::ROOT_NOT_HELD,
        "I3180 refused before the count"
    );
    assert_eq!(
        crate::federation::cosign::edition2_voices(b, &rid(&v1))
            .await
            .unwrap()
            .len(),
        1,
        "I3180 only the untampered voice is held on the receiver"
    );
    // Statements naming two rows are no one notice.
    let other_row = sign(
        &f2,
        &iref(&root),
        TAKEDOWN_PREFIX,
        &takedown_payload(
            "steward_purge",
            &iref(&root),
            &[0x47; 32],
            &[],
            &notice,
            t + 1_000_000,
            t,
        )
        .unwrap(),
    );
    let e = sp::apply_replicated_purge(b, &bundle(&[v1.clone(), other_row]), "node-b")
        .await
        .unwrap_err();
    assert_eq!(
        reason_of(e),
        why::NOTICE_MALFORMED,
        "I3180 one notice per bundle"
    );

    // I3179 — the bundle carries the notice's statements; the receiver admits
    // them through its own door and counts them by the edition-2 count (no
    // root is held here, so the count reaches the root and stops).
    let e = sp::apply_replicated_purge(b, &bundle(&[v1.clone(), v2.clone()]), "node-b")
        .await
        .unwrap_err();
    assert_eq!(
        reason_of(e),
        why::ROOT_NOT_HELD,
        "I3179 the edition-2 count ran"
    );
    assert_eq!(
        crate::federation::cosign::edition2_voices(b, &rid(&v1))
            .await
            .unwrap(),
        [iref(&f1), iref(&f2)]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "I3179 the receiver holds and re-verified both voices"
    );
    assert!(
        b.purge_execution(&rid(&v1).hex()).await.unwrap().is_none(),
        "I3179 nothing recorded without the root's quorum"
    );
}

const STREAM: &str = "t2-receipt-stream";
const ROOT: [u8; 32] = [0x3a; 32];
const ROOT_B: [u8; 32] = [0x3b; 32];

/// I3162, before any STH is published.
async fn receipt_refused_body<B: FederationDirectory + BlobStorage + Sync>(d: &B) {
    let s = key(160);
    register(d, &[&s]).await;
    let si = iref(&s);
    let st = sign(
        &s,
        &si,
        DELIVERY_RECEIPT_PREFIX,
        &delivery_receipt_payload(&si, STREAM, 0, 2, &ROOT, now_ms()),
    );
    let out = put(d, &st).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "I3162 the JOIN waits: {out:?}"
    );
    assert_eq!(
        super::fold::why_held(d, &rid(&st))
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(super::fold::reason::RECEIPT_ROOT_UNPUBLISHED.to_owned()),
        "I3162 held, reason receipt_root_unpublished"
    );
    assert!(kept(d, &st).await, "I3162 kept");
    assert!(
        d.list_delivery_receipts_for(STREAM, 10)
            .await
            .unwrap()
            .is_empty(),
        "I3162 no receipt"
    );
}

/// I3163–I3164 (and I2128, the receipt is its composite), with `ROOT`
/// published at tree size 3 and `ROOT_B` at 4.
async fn receipt_lands_body<B: FederationDirectory + BlobStorage + Sync>(d: &B) {
    let s = key(160);
    let si = iref(&s);
    let st = sign(
        &s,
        &si,
        DELIVERY_RECEIPT_PREFIX,
        &delivery_receipt_payload(&si, STREAM, 0, 2, &ROOT, now_ms()),
    );
    let out = put(d, &st).await.unwrap();
    assert!(
        matches!(out, StatementOutcome::Row { new: true, .. }),
        "I3163 {out:?}"
    );
    let listed = d.list_delivery_receipts_for(STREAM, 10).await.unwrap();
    assert_eq!(listed.len(), 1, "I3163");
    assert_eq!(listed[0].chunk_root, ROOT, "I3163");
    assert_eq!(listed[0].subscriber_key_id, si, "I3163");
    assert_eq!(listed[0].k, 2, "I3163");
    assert!(
        d.get_attestation(&rid(&st).hex()).await.unwrap().is_some(),
        "I3163 the signed receipt row"
    );
    // v62.0.0 (VA-receipt-composite, I2128) — the receipt carries the
    // statement's ONE composite, whole, as stored and as listed; it verifies
    // as a composite under the subscriber's live key record over the
    // statement's Sig_structure; and no pair-shaped member is served.
    {
        let Ok(Value::Tag(18, inner)) = ciris_verify_core::cde::decode(&st) else {
            panic!("I2128: a tag-18 COSE_Sign1");
        };
        let parts = inner.as_array().expect("I2128: the COSE_Sign1 array");
        let (protected, payload, signature) = (
            parts[0].as_bytes().expect("I2128: protected"),
            parts[2].as_bytes().expect("I2128: payload"),
            parts[3].as_bytes().expect("I2128: signature"),
        );
        assert_eq!(
            listed[0].composite_signature.as_slice(),
            signature,
            "I2128: the listed receipt carries the statement's composite, whole"
        );
        assert_eq!(
            listed[0].composite_signature.len(),
            ciris_crypto::composite::SIGNATURE_LEN,
            "I2128: one composite"
        );
        let tbs = ciris_verify_core::edition2::sig_structure(protected, payload);
        super::composite_verify::verify_composite_via_directory(
            d,
            &tbs,
            &si,
            &listed[0].composite_signature,
            super::composite_verify::now_ms(),
        )
        .await
        .unwrap_or_else(|e| panic!("I2128: verifies as a composite under the key record: {e}"));
        let stored = d
            .list_stored_delivery_receipts_for(STREAM, 10)
            .await
            .unwrap();
        assert_eq!(
            stored[0].receipt.composite_signature, listed[0].composite_signature,
            "I2128: stored as the composite"
        );
        let json = serde_json::to_value(&stored[0]).unwrap();
        assert!(
            json.get("composite_signature")
                .is_some_and(serde_json::Value::is_string),
            "I2128: one base64 member"
        );
        assert!(
            json.get("signature").is_none(),
            "I2128: no pair-shaped member is served"
        );
    }
    let equivocal = sign(
        &s,
        &si,
        DELIVERY_RECEIPT_PREFIX,
        &delivery_receipt_payload(&si, STREAM, 0, 2, &ROOT_B, now_ms()),
    );
    let out = put(d, &equivocal).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Pending { .. })),
        "I3164 kept, concluding nothing: {out:?}"
    );
    assert_eq!(
        super::fold::why_held(d, &rid(&equivocal))
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(super::fold::reason::RECEIPT_EQUIVOCATION.to_owned()),
        "I3164 held, reason receipt_equivocation"
    );
    assert!(kept(d, &equivocal).await, "I3164 kept");
    let listed = d.list_delivery_receipts_for(STREAM, 10).await.unwrap();
    assert_eq!(listed.len(), 1, "I3164 the first receipt stands alone");
    assert_eq!(listed[0].chunk_root, ROOT, "I3164");
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::empty_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
fn sqlite_publish(b: &crate::store::sqlite::SqliteBackend, tree_size: i64, root: [u8; 32]) {
    let conn = b.conn_handle();
    let conn = conn.lock();
    conn.execute(
        "INSERT INTO federation_stream_sth (\
            stream_id, tree_size, epoch, root_hash, signed_at, \
            producer_key_id, signature_blob, witness_signatures\
         ) VALUES (?1, ?2, 0, ?3, '2026-01-01T00:00:00Z', \
                  'producer-key', x'00', '[]')",
        rusqlite::params![STREAM, tree_size, root.to_vec()],
    )
    .expect("seed federation_stream_sth");
}

#[cfg(feature = "postgres")]
async fn pg_publish(b: &crate::store::postgres::PostgresBackend, tree_size: i64, root: [u8; 32]) {
    let client = b.get_client().await.unwrap();
    let root = root.to_vec();
    client
        .execute(
            "INSERT INTO cirislens.federation_stream_sth (\
                stream_id, tree_size, epoch, root_hash, signed_at, \
                producer_key_id, signature_blob, witness_signatures\
             ) VALUES ($1, $2, 0, $3, '2026-01-01T00:00:00Z', \
                      'producer-key', '\\x00', '[]'::jsonb) \
             ON CONFLICT (stream_id, tree_size) DO NOTHING",
            &[&STREAM, &tree_size, &root],
        )
        .await
        .expect("seed federation_stream_sth");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3150_i3152_occurrence_revocation_sqlite() {
    Box::pin(occurrence_revocation_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3150_i3152_occurrence_revocation_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(occurrence_revocation_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3153_i3156_revocation_sqlite() {
    Box::pin(revocation_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3153_i3156_revocation_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(revocation_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3157_i3159_i3165_i3166_custody_cosign_sqlite() {
    Box::pin(custody_cosign_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3157_i3159_i3165_i3166_custody_cosign_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(custody_cosign_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3192_own_claim_waits_for_its_bytes_sqlite() {
    let b = sqlite().await;
    let node = key(250);
    b.set_node_key_id(iref(&node));
    Box::pin(own_claim_body(&b, &node)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3192_own_claim_waits_for_its_bytes_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    let node = key(250);
    b.set_node_key_id(iref(&node));
    Box::pin(own_claim_body(&b, &node)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3193_eviction_window_sqlite() {
    Box::pin(eviction_window_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3193_eviction_window_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(eviction_window_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3167_i3168_takedown_sqlite() {
    Box::pin(takedown_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3167_i3168_takedown_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(takedown_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3160_i3161_key_grant_sqlite() {
    Box::pin(key_grant_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3160_i3161_key_grant_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(key_grant_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3162_i3164_delivery_receipt_sqlite() {
    let b = sqlite().await;
    Box::pin(receipt_refused_body(&b)).await;
    sqlite_publish(&b, 3, ROOT);
    sqlite_publish(&b, 4, ROOT_B);
    Box::pin(receipt_lands_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3162_i3164_delivery_receipt_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(receipt_refused_body(&b)).await;
    pg_publish(&b, 3, ROOT).await;
    pg_publish(&b, 4, ROOT_B).await;
    Box::pin(receipt_lands_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3170_i3171_blob_sqlite() {
    Box::pin(blob_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3170_i3171_blob_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(blob_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3172_i3175_trust_sqlite() {
    Box::pin(trust_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3172_i3175_trust_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(trust_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3176_i3177_purge_quorum_sqlite() {
    Box::pin(purge_quorum_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3176_i3177_purge_quorum_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(purge_quorum_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3179_i3180_purge_replication_sqlite() {
    let (a, b) = (sqlite().await, sqlite().await);
    Box::pin(purge_replication_body(&a, &b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3179_i3180_purge_replication_postgres() {
    let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
        return;
    };
    Box::pin(purge_replication_body(&a, &b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3185_named_head_sqlite() {
    Box::pin(named_head_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3185_named_head_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(named_head_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3187_evicted_voice_sqlite() {
    Box::pin(evicted_voice_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3187_evicted_voice_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(evicted_voice_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3186_waiting_head_sqlite() {
    Box::pin(waiting_head_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3186_waiting_head_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(waiting_head_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3188_i3191_eviction_cites_sqlite() {
    Box::pin(eviction_cites_body(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3188_i3191_eviction_cites_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(eviction_cites_body(&b)).await;
}
