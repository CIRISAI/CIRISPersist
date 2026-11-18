//! v62.0.0 (wave W1) — **edition-2 witnesses for properties whose earlier
//! tests were deleted** with the earlier canonical and accord records (rc6,
//! `test_ceremony_1106`, remint, `accord_lineage`; E7's property map,
//! "Update 9"). Each runs on sqlite and postgres through the one edition-2
//! entry (`edition2::ingest::put_statement`).
//!
//! - **I3230** (was I356, CC 3.2 T4a "a new edge that names no head is
//!   refused with `trust_root_head_unnamed` in every mode, witnessed mode off
//!   included") — a NEW `trust:accepts:v1` acceptance edge to a group root
//!   this node holds, naming no head, is refused `trust_root_head_unnamed` and
//!   not stored.
//! - **I3231** (was I194 / I359) — the same consumer's edge naming the head
//!   this node holds (`attached_head_digest` = the family's
//!   `persist_row_hash`) is admitted and stored.
//! - **I3232** (was I357 / I372 / I373; CC 3.2 T4 "an attached root stays
//!   valid until revoked", T4a "a new edge that names a head other than the
//!   one it must name concludes nothing; it is never refused for that") —
//!   after the root's head moves (a counted version 2), the attached edge
//!   re-put is not re-judged (kept, not new), and a NEW edge naming the
//!   superseded head is not refused.
//! - **I3233** (was I195b; CC 3.2 T7 "founding at N = M is non-conformant")
//!   — an infrastructure community founded at N = M (`quorum:2/2`, two
//!   founders) is refused `liveness_margin_at_founding` when its last founder
//!   voices it, and nothing lands; the same shape at N = M + 1
//!   (`quorum:2/3`, three founders) is never refused for the margin.
//! - **I3234** (was I1874/I1875, `tests/xwing_rebind_1274.rs`; CC 3.3.6.2 "a
//!   node takes a seat's `transit_xwing_pubkey` from the bundle or from such a
//!   re-bind, and a seat's own binding that carries another key is not
//!   honoured"; RULINGS "a seat publishing one alone is not live") — the seat
//!   of the bundle in force has its bundle-bound X-Wing transit key, and its
//!   own later binding carrying another key does not make that key live.
//! - **I3235** (was I195's birth; CC 2.7.5, CC 3.2 T2) — a trust-root
//!   community founded by holders of the genesis bundle in force is counted
//!   against a strict majority of those holders: short of it each voice is
//!   `Pending` and nothing lands; met, it lands Rooted and live.
//! - **I3236** (was I195; CC 3.2 T7 "a resignation that leaves exactly `M`
//!   founders stalls the root … declared") — one founder's resignation (a
//!   removal voiced by that founder alone) stalls it: `Stalled`, not live,
//!   `community_liveness_stalled` declared exactly once.
//! - **I3237** (was I195; CC 3.2 T7 recovery) — a founders' amendment that
//!   seats another holder in the resigned seat, counted by the remaining
//!   founders (short: `Pending`), roots it again: `Rooted`, live,
//!   `community_liveness_restored` declared once.
//! - **I3238** (CC 3.1.3 / 3.3.6.2, a COUNTED `transport:canonical_rebind`) —
//!   one holder's re-bind voice is `Pending` and the seat's key stays the
//!   bundle's; the voice that meets a strict majority of the holders lands it
//!   and the re-bound key is live.
//! - **I3239** (CC 3.4.7) — a re-bind voice signed by the seat itself, or
//!   about an identity that is not a seat, is refused
//!   `reserved_family_unseated`.
//! - **I3240** (CC ruling: counted "over the `refs.head` naming that
//!   bundle") — a re-bind naming no bundle is refused
//!   `edition2_payload_invalid`; naming a bundle not held, it waits
//!   (`federation_attester_key_unknown`); naming a held bundle no longer in
//!   force, it is refused; over the bundle in force it is kept.
//! - **I3241** (CC ruling: the re-seat path stands) — a later bundle that
//!   re-seats the seat on new X-Wing keys makes the new key live, and a
//!   re-bind counted over the earlier bundle no longer applies.
//!
//! - **I3242** (W1b; CC 3.2 T2/T3, CC 4.4.3.34) — a root founded by the
//!   bundle's holders through `group:roster` voices, chartered by its own key
//!   (`trust:charter:v1` self-edge) and accepted by THIS node
//!   (`trust:accepts:v1`) is `Rooted`, its founders the holders.
//! - **I3243** (W1b; CC 3.2 T3 "un-trust is one row") — the same chain is
//!   `NotRooted` for a node that never accepted it and once this node
//!   withdraws its acceptance; an id never founded is `Absent`.
//! - **I3244** (W1b) — end to end, `purge_rows_edition2` under the rooted
//!   root: one founder's voice is `quorum_not_met`, two of three execute and
//!   are the report's cosigners.
//!
//! - **I3245–I3247** (W1b; RULINGS "a conformant infrastructure record
//!   rooted in THIS node's trust set") — the root itself and a room citing
//!   the root's charter are authorized infrastructure rooms here; a room
//!   nothing reaches is not, nor either once the node withdraws its
//!   acceptance; a node member is exempt from the steward binding only in an
//!   authorized room, an agent member never.
//!
//! - **I3248 / I3249** (W1b; CC 3.2 T3) — `trust_root_valid(node, root)` is
//!   valid for the rooted edition-2 root, read at the root's own id; a
//!   `trust:confers:v1` capability from it reaches it in
//!   `capability_roots_to_trusted_root`; `rooted_trust_root` is idempotent;
//!   the node's withdrawal un-trusts both.
//!
//! - **I3250** (W1b; the `trust:confers` path) — a room nothing reaches is
//!   authorized once the rooted root confers on it, the room's own key
//!   co-signing the grant (Verify's `delegate: sub`).
//!
//! - **I3251** (W1b; ruling C) — canonical serve standing is a seat of the
//!   bundle in force: a listed serve node is `Canonical`, an unlisted node
//!   key is not.
//!
//! - **I3252** (W1b; CC 2.6.1.11) — `duty_holders_for_federation` is the
//!   holders of the genesis bundle in force; none held, it refuses.
//!
//! - **I3253** (W1b; E9 finding 3) — a community root whose count goes short
//!   is not valid by name on the community arm (never the key arm at its
//!   identity-ref); the walk and transit eligibility follow.
//!
//! - **I3254** (CC rc21) — a re-bind counts at a strict majority of the
//!   holders of the bundle in force: with four holders, two voices are
//!   `Pending`, the third lands.
//!
//! Not witnessed here, and why (W1.md): the witnessed-mode legs of T4a (I194's
//! `trust_root_head_stale` / unwitnessed, I375) have no edition-2 form (wave 3
//! rule 4: `lineage_head` cosign has no forward form).

use ciris_verify_core::cde::Value;

use crate::federation::edition2::fixture_genesis;
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::group::GroupRecord;
use crate::federation::edition2::group_fixtures::{put_voices, roster_voices, row_id_of};
use crate::federation::edition2::ingest::StatementOutcome;
use crate::federation::types::{
    attestation_type, Community, CommunityMember, Family, FamilyMember,
};
use crate::federation::{Error, FederationDirectory};

fn at(ms: i64) -> chrono::DateTime<chrono::Utc> {
    use chrono::TimeZone as _;
    chrono::Utc.timestamp_millis_opt(ms).single().unwrap()
}

/// Live `user` keys (records from 0, no end): they cover every fixed
/// instant below.
async fn users(d: &dyn FederationDirectory, seeds: &[&str]) {
    for s in seeds {
        e2::put_key(d, s, &["user"]).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  (a) The acceptance edge on a group root (CC 3.2 T4a)
// ─────────────────────────────────────────────────────────────────────────

const ROOT: &str = "w1-root";
const MEMBERS: [&str; 3] = ["w1-ra", "w1-rb", "w1-rc"];

fn root_family(name: &str) -> GroupRecord {
    GroupRecord::Family(Family {
        family_key_id: e2::kid(ROOT),
        family_name: name.into(),
        members: MEMBERS
            .iter()
            .map(|s| FamilyMember {
                key_id: e2::kid(s),
                joined_at: at(1_000),
                role: None,
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: "majority".into(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    })
}

/// The root family, founded by all three members' voices (a founding roster
/// lands when its last listed member voices it). Returns the version's row
/// id.
async fn found_root(d: &dyn FederationDirectory) -> crate::federation::edition2::names::RowId {
    users(d, &MEMBERS).await;
    let keys: Vec<_> = MEMBERS.iter().map(|s| e2::signing_key(s)).collect();
    let refs: Vec<_> = keys.iter().collect();
    let voices = roster_voices(&root_family("w1 root"), 1, None, 2_000, &refs);
    let o = put_voices(d, &voices)
        .await
        .expect("the root family founds");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "the root family lands on its last voice: {o:?}"
    );
    row_id_of(&voices[0])
}

/// The head this node holds for the root (what an edge names).
async fn held_root_head(d: &dyn FederationDirectory) -> String {
    d.lookup_family(&e2::kid(ROOT))
        .await
        .unwrap()
        .expect("the root family is held")
        .persist_row_hash
}

/// `consumer`'s `trust:accepts:v1` edge to the root, naming `head` when
/// given, as the consumer's edition-2 statement.
fn acceptance_edge(consumer: &str, head: Option<&str>) -> Vec<u8> {
    let mut env = serde_json::json!({
        "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
        "scope": [crate::federation::trust_root::INFRA_SERVE_SCOPE],
    });
    if let Some(h) = head {
        env["attached_head_digest"] = serde_json::Value::String(h.to_owned());
    }
    let mut a = crate::federation::tier_ingest::test_support::bare_attestation(
        "ignored-as-an-id",
        consumer,
        &e2::kid(ROOT),
        &env,
    );
    a.attestation_type = attestation_type::DELEGATES_TO.to_owned();
    e2::statement_of(&a, consumer)
}

async fn stored(d: &dyn FederationDirectory, statement: &[u8]) -> bool {
    d.get_attestation(&row_id_of(statement).hex())
        .await
        .unwrap()
        .is_some()
}

/// **I3230 / I3231** — a new headless edge is refused by name; the edge
/// naming the held head is admitted.
pub(crate) async fn i3230_i3231_a_new_edge_names_its_head(d: &dyn FederationDirectory) {
    found_root(d).await;
    let consumer = "w1-consumer";
    users(d, &[consumer]).await;

    // I3230 — witnessed mode off (the root's charter is silent): still refused.
    let headless = acceptance_edge(consumer, None);
    match e2::put_statement(d, &headless).await {
        Err(e) if e.kind() == "trust_root_head_unnamed" => {}
        other => panic!("I3230: a new headless acceptance edge, got {other:?}"),
    }
    assert!(
        !stored(d, &headless).await,
        "I3230: the refused edge is not stored"
    );

    // I3231 — naming the head this node holds: admitted.
    let head = held_root_head(d).await;
    let named = acceptance_edge(consumer, Some(&head));
    let o = e2::put_statement(d, &named)
        .await
        .expect("I3231: the edge naming the held head attaches");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3231: {o:?}"
    );
    assert!(stored(d, &named).await, "I3231: the edge is stored");
}

/// **I3232** — after the head moves: the attached edge is not re-judged,
/// and a new edge naming the superseded head is not refused for it.
pub(crate) async fn i3232_attached_stays_attached(d: &dyn FederationDirectory) {
    let v1 = found_root(d).await;
    let v1_head = held_root_head(d).await;
    let (early, late) = ("w1-early", "w1-late");
    users(d, &[early, late]).await;
    let edge = acceptance_edge(early, Some(&v1_head));
    e2::put_statement(d, &edge)
        .await
        .expect("I3232: attaches on version 1");

    // The root's head moves: version 2, counted at majority (two of three).
    let keys: Vec<_> = MEMBERS[..2].iter().map(|s| e2::signing_key(s)).collect();
    let refs: Vec<_> = keys.iter().collect();
    let o = put_voices(
        d,
        &roster_voices(&root_family("w1 root v2"), 2, Some(&v1), 3_000, &refs),
    )
    .await
    .expect("I3232: version 2");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3232: version 2 is the head: {o:?}"
    );
    assert_ne!(held_root_head(d).await, v1_head, "I3232: the head moved");

    // T4 — the attached edge re-offered is not re-judged against the new head.
    let o = e2::put_statement(d, &edge)
        .await
        .expect("I3232: the attached edge re-put");
    assert!(
        matches!(
            o,
            StatementOutcome::Row { new: false, .. } | StatementOutcome::Voice { new: false, .. }
        ),
        "I3232: held, not new: {o:?}"
    );
    assert!(stored(d, &edge).await, "I3232: attached stays attached");

    // T4a — a NEW edge naming the superseded head concludes nothing, and is
    // never refused for that.
    let stale = acceptance_edge(late, Some(&v1_head));
    e2::put_statement(d, &stale)
        .await
        .expect("I3232: a new edge naming another head is not refused for it");
}

// ─────────────────────────────────────────────────────────────────────────
//  (b) The liveness margin at founding (CC 3.2 T7)
// ─────────────────────────────────────────────────────────────────────────

fn infrastructure_room(group: &str, founders: &[&str], protocol: &str) -> GroupRecord {
    GroupRecord::Community(Community {
        community_key_id: e2::kid(group),
        community_name: format!("{group} room"),
        members: founders
            .iter()
            .map(|s| CommunityMember {
                key_id: e2::kid(s),
                joined_at: at(1_000),
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect(),
        founded_at: at(1_000),
        consensus_protocol: protocol.into(),
        policy_blob: Some(serde_json::json!({
            "cohort_subkind": crate::federation::canonical_community::COHORT_SUBKIND_INFRASTRUCTURE,
            "cohort_subkind_payload": {
                "infrastructure_constraint": {
                    "admission_quorum_basis":
                        crate::federation::canonical_community::ADMISSION_QUORUM_BASIS_FOUNDERS,
                },
            },
            "consensus_protocol_entrenched": true,
        })),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    })
}

fn is_margin_refusal(e: &Error) -> bool {
    matches!(
        e,
        Error::CommunityConsensusProtocolViolation { rule, .. }
            if *rule == crate::federation::admission::INFRA_RULE_LIVENESS_MARGIN_AT_FOUNDING
    )
}

/// Every founder voices the founding, in order; the first refusal, if any.
async fn found_room(
    d: &dyn FederationDirectory,
    group: &str,
    founders: &[&str],
    protocol: &str,
) -> Option<Error> {
    users(d, founders).await;
    let keys: Vec<_> = founders.iter().map(|s| e2::signing_key(s)).collect();
    let refs: Vec<_> = keys.iter().collect();
    let room = infrastructure_room(group, founders, protocol);
    for v in roster_voices(&room, 1, None, 2_000, &refs) {
        if let Err(e) = e2::put_statement(d, &v).await {
            return Some(e);
        }
    }
    None
}

/// **I3233** — founding at N = M is refused for the margin; N = M + 1 is not.
pub(crate) async fn i3233_founding_needs_a_margin(d: &dyn FederationDirectory) {
    let refused = found_room(d, "w1-room-nm", &["w1-f1", "w1-f2"], "quorum:2/2").await;
    match &refused {
        Some(e) if is_margin_refusal(e) => {}
        other => panic!("I3233: founding at N = M, got {other:?}"),
    }
    assert!(
        d.lookup_community(&e2::kid("w1-room-nm"))
            .await
            .unwrap()
            .is_none(),
        "I3233: nothing lands"
    );
    // The control: one founder more is never refused for the margin (it may
    // be refused for a later leg, e.g. its founders' conferral).
    let control = found_room(d, "w1-room-nm1", &["w1-g1", "w1-g2", "w1-g3"], "quorum:2/3").await;
    assert!(
        !control.as_ref().is_some_and(is_margin_refusal),
        "I3233: N = M + 1 meets the margin: {control:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  (c) A seat's transit key (CC 3.3.6.2): only the bundle or a counted re-bind
// ─────────────────────────────────────────────────────────────────────────

/// The seat's own binding re-signed with `transit` as its X-Wing transit key,
/// stated at `asserted_at_ms` (every other member as the bundle's binding).
fn seat_rebinding_itself(
    seat: &fixture_genesis::SeatV2,
    key: &ciris_crypto::composite::CompositeSigningKey,
    transit: &[u8],
    asserted_at_ms: u64,
) -> Vec<u8> {
    let (protected, payload) =
        crate::federation::edition2::liveness::statement_parts(&seat.binding.statement)
            .expect("the bundle binding is a statement");
    let text = |label: i64| {
        protected
            .get_int(label)
            .and_then(Value::as_text)
            .expect("the binding's header")
            .to_owned()
    };
    let (row_type, family) = (text(-70001), text(-70002));
    let members: Vec<(Value, Value)> = payload
        .as_map()
        .expect("the binding's payload is a map")
        .iter()
        .map(|(k, v)| {
            let v = match k.as_text() {
                Some("transit_xwing_pubkey") => Value::Bytes(transit.to_vec()),
                Some("asserted_at") => Value::Uint(asserted_at_ms),
                _ => v.clone(),
            };
            (k.clone(), v)
        })
        .collect();
    ciris_verify_core::edition2::sign_row_statement(
        key,
        &seat.identity_ref,
        &seat.identity_ref,
        &row_type,
        &family,
        &Value::Map(members),
        vec![],
    )
    .expect("the seat signs its binding")
}

async fn live_transit_key(d: &dyn FederationDirectory, seat: &str) -> Option<Vec<u8>> {
    crate::federation::self_at_login::transit_xwing_pubkey_for(d, seat)
        .await
        .unwrap()
        .map(|k| k.as_bytes().to_vec())
}

/// **I3234** — the seat's transit key is the bundle's until a counted
/// re-bind; the seat's own binding alone does not move it.
pub(crate) async fn i3234_a_seat_alone_does_not_move_its_transit_key(d: &dyn FederationDirectory) {
    fixture_genesis::install_v2(d)
        .await
        .expect("I3234: the test ceremony installs");
    let ceremony = fixture_genesis::bundle_v2();
    let seat = &ceremony.seats[0];
    let bundle_key = seat.transit_xwing_pubkey.to_vec();
    assert_eq!(
        live_transit_key(d, &seat.identity_ref).await,
        Some(bundle_key.clone()),
        "I3234: live from the genesis binding"
    );
    // A different X-Wing key: both halves (pk_M 0..1184, pk_X 1184..1216) changed.
    let mut other = seat.transit_xwing_pubkey;
    other[0] ^= 0xff;
    other[1200] ^= 0xff;
    let now_ms = u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap();
    let own = seat_rebinding_itself(seat, &ceremony.serve_node_key(0), &other, now_ms);
    e2::put_statement(d, &own)
        .await
        .expect("I3234: the seat's own binding is held");
    let live = live_transit_key(d, &seat.identity_ref).await;
    assert_ne!(
        live,
        Some(other.to_vec()),
        "I3234: a seat publishing a transit key alone is not live"
    );
    assert_eq!(
        live,
        Some(bundle_key),
        "I3234: the bundle's key stays live until a counted transport:canonical_rebind"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  (c, continued) The counted re-bind (CC 3.1.3, 3.4.7)
// ─────────────────────────────────────────────────────────────────────────

/// One voice of a `transport:canonical_rebind` about `seat`, signed by `key`
/// under `iss`, carrying `transit`.
fn rebind_voice(
    key: &ciris_crypto::composite::CompositeSigningKey,
    iss: &str,
    seat: &str,
    transit: &[u8],
    asserted_at_ms: u64,
    head: Option<&ciris_verify_core::edition2::Digest32>,
) -> Vec<u8> {
    use crate::federation::edition2::transport_rebind::{
        REBIND_FAMILY, REBIND_ROW_TYPE, TRANSIT_MEMBER,
    };
    let mut members = vec![
        (
            Value::Text("asserted_at".into()),
            Value::Uint(asserted_at_ms),
        ),
        (
            Value::Text(TRANSIT_MEMBER.into()),
            Value::Bytes(transit.to_vec()),
        ),
    ];
    if let Some(h) = head {
        members.push((
            Value::Text("refs".into()),
            Value::Map(vec![(
                Value::Text("head".into()),
                ciris_verify_core::edition2::row_ref(h),
            )]),
        ));
    }
    members.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    ciris_verify_core::edition2::sign_row_statement(
        key,
        iss,
        seat,
        REBIND_ROW_TYPE,
        REBIND_FAMILY,
        &Value::Map(members),
        vec![],
    )
    .expect("a holder signs a re-bind")
}

fn other_key(k: &[u8; ciris_verify_core::edition2::genesis::XWING_PUBKEY_LEN], n: u8) -> Vec<u8> {
    let mut o = *k;
    o[0] ^= n;
    o[1200] ^= n;
    o.to_vec()
}

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
}

/// **I3238** — a re-bind is counted by the holders.
pub(crate) async fn i3238_a_rebind_is_counted(d: &dyn FederationDirectory) {
    fixture_genesis::install_v2(d)
        .await
        .expect("I3238: the test ceremony installs");
    let c = fixture_genesis::bundle_v2();
    let seat = &c.seats[0];
    let bundle_key = seat.transit_xwing_pubkey.to_vec();
    let rebound = other_key(&seat.transit_xwing_pubkey, 0x5a);
    let at = now_ms();
    let first = rebind_voice(
        &c.holder_key(0),
        c.holder_identity_ref(0),
        &seat.identity_ref,
        &rebound,
        at,
        Some(&c.object_id),
    );
    let o = e2::put_statement(d, &first)
        .await
        .expect("I3238: a holder's voice is kept");
    assert!(
        matches!(o, StatementOutcome::Pending { new: true, .. }),
        "I3238: one of three holders is short: {o:?}"
    );
    assert_eq!(
        live_transit_key(d, &seat.identity_ref).await,
        Some(bundle_key),
        "I3238: a short re-bind moves nothing"
    );
    let second = rebind_voice(
        &c.holder_key(1),
        c.holder_identity_ref(1),
        &seat.identity_ref,
        &rebound,
        at,
        Some(&c.object_id),
    );
    assert_eq!(
        row_id_of(&first),
        row_id_of(&second),
        "I3238: two voices of one row"
    );
    let o = e2::put_statement(d, &second)
        .await
        .expect("I3238: the second holder's voice");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3238: two of three holders meet the count: {o:?}"
    );
    assert_eq!(
        live_transit_key(d, &seat.identity_ref).await,
        Some(rebound),
        "I3238: the counted re-bind's key is live"
    );
}

fn is_unseated(e: &Error) -> bool {
    matches!(
        e,
        Error::MalformedRow { reason, .. }
            if *reason == crate::federation::malformed_row::RESERVED_FAMILY_UNSEATED
    )
}

/// **I3239** — only the holders re-bind, and only a seat.
pub(crate) async fn i3239_only_holders_rebind_a_seat(d: &dyn FederationDirectory) {
    fixture_genesis::install_v2(d)
        .await
        .expect("I3239: the test ceremony installs");
    let c = fixture_genesis::bundle_v2();
    let seat = &c.seats[0];
    let rebound = other_key(&seat.transit_xwing_pubkey, 0x33);
    let own = rebind_voice(
        &c.serve_node_key(0),
        &seat.identity_ref,
        &seat.identity_ref,
        &rebound,
        now_ms(),
        Some(&c.object_id),
    );
    match e2::put_statement(d, &own).await {
        Err(e) if is_unseated(&e) => {}
        other => panic!("I3239: the seat's own re-bind voice, got {other:?}"),
    }
    let not_a_seat = rebind_voice(
        &c.holder_key(0),
        c.holder_identity_ref(0),
        c.holder_identity_ref(1),
        &rebound,
        now_ms(),
        Some(&c.object_id),
    );
    match e2::put_statement(d, &not_a_seat).await {
        Err(e) if is_unseated(&e) => {}
        other => panic!("I3239: a re-bind about a holder (not a seat), got {other:?}"),
    }
    assert_eq!(
        live_transit_key(d, &seat.identity_ref).await,
        Some(seat.transit_xwing_pubkey.to_vec()),
        "I3239: nothing moved"
    );
}

fn is_payload_invalid(e: &Error) -> bool {
    matches!(
        e,
        Error::MalformedRow { reason, .. }
            if *reason == crate::federation::malformed_row::EDITION2_PAYLOAD_INVALID
    )
}

/// **I3240** — a re-bind is counted over the bundle in force, named by
/// `refs.head`: none is refused, an unheld bundle waits, a bundle no longer
/// in force is refused.
pub(crate) async fn i3240_a_rebind_names_the_bundle_in_force(d: &dyn FederationDirectory) {
    fixture_genesis::install_v2(d)
        .await
        .expect("I3240: the test ceremony installs");
    let c = fixture_genesis::bundle_v2();
    let seat = &c.seats[0];
    let rebound = other_key(&seat.transit_xwing_pubkey, 0x21);
    let voice = |head: Option<&ciris_verify_core::edition2::Digest32>| {
        rebind_voice(
            &c.holder_key(0),
            c.holder_identity_ref(0),
            &seat.identity_ref,
            &rebound,
            now_ms(),
            head,
        )
    };
    match e2::put_statement(d, &voice(None)).await {
        Err(e) if is_payload_invalid(&e) => {}
        other => panic!("I3240: a re-bind naming no bundle, got {other:?}"),
    }
    match e2::put_statement(d, &voice(Some(&[0xab; 32]))).await {
        Err(e) if e.kind() == "federation_attester_key_unknown" => {}
        other => panic!("I3240: a re-bind over a bundle not held waits, got {other:?}"),
    }
    // A later bundle (the same parties) is now in force.
    let later = fixture_genesis::later_v2(
        c,
        &fixture_genesis::HOLDER_SEEDS,
        &fixture_genesis::SERVE_NODE_SEEDS,
        &fixture_genesis::HOLDER_SEEDS[..2],
    );
    fixture_genesis::install_ceremony_v2(d, &later)
        .await
        .expect("I3240: the later bundle installs");
    match e2::put_statement(d, &voice(Some(&c.object_id))).await {
        Err(e) if is_payload_invalid(&e) => {}
        other => panic!("I3240: a re-bind over a bundle no longer in force, got {other:?}"),
    }
    let o = e2::put_statement(d, &voice(Some(&later.object_id)))
        .await
        .expect("I3240: over the bundle in force, kept");
    assert!(
        matches!(o, StatementOutcome::Pending { new: true, .. }),
        "I3240: {o:?}"
    );
}

/// **I3241** — a later bundle that re-seats the seat on new X-Wing keys makes
/// the new key live, and a re-bind counted over the earlier bundle no longer
/// applies.
pub(crate) async fn i3241_a_reseat_by_a_later_bundle_is_live(d: &dyn FederationDirectory) {
    fixture_genesis::install_v2(d)
        .await
        .expect("I3241: the test ceremony installs");
    let c = fixture_genesis::bundle_v2();
    let seat = &c.seats[0];
    let rebound = other_key(&seat.transit_xwing_pubkey, 0x44);
    let at = now_ms();
    for i in 0..2 {
        e2::put_statement(
            d,
            &rebind_voice(
                &c.holder_key(i),
                c.holder_identity_ref(i),
                &seat.identity_ref,
                &rebound,
                at,
                Some(&c.object_id),
            ),
        )
        .await
        .expect("I3241: a holder's re-bind voice");
    }
    assert_eq!(
        live_transit_key(d, &seat.identity_ref).await,
        Some(rebound.clone()),
        "I3241: the counted re-bind is live first"
    );
    let reseat =
        fixture_genesis::reseat_xwing_v2(c, seat.seed, 1, &fixture_genesis::HOLDER_SEEDS[..2]);
    fixture_genesis::install_ceremony_v2(d, &reseat)
        .await
        .expect("I3241: the re-seating bundle installs");
    let new_key = reseat.seats[0].transit_xwing_pubkey.to_vec();
    assert_ne!(
        new_key,
        seat.transit_xwing_pubkey.to_vec(),
        "I3241: new keys"
    );
    assert_eq!(
        live_transit_key(d, &seat.identity_ref).await,
        Some(new_key),
        "I3241: the re-seat's key is live; the re-bind over the earlier bundle no longer applies"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  (b, continued) The stalled and restored legs (CC 3.2 T7)
// ─────────────────────────────────────────────────────────────────────────

const TR_ROOM: &str = "w1-trust-root-room";

/// Four holders (seeds 1–4), so one can be seated in a resigned seat.
fn four_holders() -> fixture_genesis::TestCeremonyV2 {
    let mut spec = fixture_genesis::CeremonySpec::standard();
    spec.holders = vec![1, 2, 3, 4];
    fixture_genesis::ceremony_v2(&spec)
}

fn trust_root_room(
    c: &fixture_genesis::TestCeremonyV2,
    founders: &[usize],
    founded_at_ms: i64,
) -> GroupRecord {
    let mut room = infrastructure_room(TR_ROOM, &[], "quorum:2/3");
    if let GroupRecord::Community(r) = &mut room {
        r.founded_at = at(founded_at_ms);
        r.members = founders
            .iter()
            .map(|i| CommunityMember {
                key_id: c.holder_identity_ref(*i).to_owned(),
                joined_at: at(founded_at_ms),
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect();
    }
    room
}

async fn hard_cases(d: &dyn FederationDirectory, kind: &str) -> usize {
    d.list_hard_case_events(crate::federation::hard_case::HardCaseFilter {
        kind: Some(kind.to_owned()),
        since: None,
        emitter_key_id: None,
    })
    .await
    .unwrap()
    .len()
}

async fn standing(
    d: &dyn FederationDirectory,
) -> crate::federation::canonical_community::StoredStanding {
    // W1b: the CHAIN verdict (T7 is a property of the chain; the read
    // verdict also needs this node's own T3 chain, witnessed in I3242).
    crate::federation::canonical_community::chain_standing_at(
        d,
        &e2::kid(TR_ROOM),
        crate::host::clock::now(),
    )
    .await
    .unwrap()
}

/// **I3235 / I3236 / I3237** — born over the bundle, stalled by a
/// resignation, restored by the founders' amendment.
pub(crate) async fn i3235_i3237_the_trust_root_liveness_margin(d: &dyn FederationDirectory) {
    use crate::federation::canonical_community::StoredStanding;
    use crate::federation::edition2::group::MembershipRecord;
    use crate::federation::edition2::group_fixtures::membership_voices;
    use crate::federation::hard_case::kind;
    use crate::federation::types::CommunityMembershipRevocation;

    let c = four_holders();
    fixture_genesis::install_ceremony_v2(d, &c)
        .await
        .expect("I3235: four holders install");
    let gid = e2::kid(TR_ROOM);
    let base = crate::host::clock::now().timestamp_millis() - 2 * 3_600_000;
    let ms = |offset: i64| u64::try_from(base + offset).unwrap();

    // I3235 — the birth: three holder founders, quorum:2/3 (M + 1 = 3).
    let v1 = trust_root_room(&c, &[0, 1, 2], base);
    let keys: Vec<_> = (0..4).map(|i| c.holder_key(i)).collect();
    let voices: Vec<Vec<u8>> = (0..3)
        .map(|i| roster_voices(&v1, 1, None, ms(60_000), &[&keys[i]]).remove(0))
        .collect();
    for v in &voices[..2] {
        let o = e2::put_statement(d, v)
            .await
            .expect("I3235: a holder's voice");
        assert!(
            matches!(o, StatementOutcome::Pending { new: true, .. }),
            "I3235: short of a strict majority of four holders: {o:?}"
        );
        assert!(d.lookup_community(&gid).await.unwrap().is_none(), "I3235");
    }
    let o = e2::put_statement(d, &voices[2])
        .await
        .expect("I3235: the third holder founder");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3235: three of four holders: {o:?}"
    );
    let v1_id = row_id_of(&voices[0]);
    let StoredStanding::Rooted(signed) = standing(d).await else {
        panic!("I3235: born over the bundle in force, Rooted");
    };
    assert!(
        crate::federation::canonical_community::is_live(d, &signed, crate::host::clock::now())
            .await
            .unwrap(),
        "I3235: three founders at quorum:2/3 are live"
    );
    assert_eq!(hard_cases(d, kind::COMMUNITY_LIVENESS_STALLED).await, 0);

    // I3236 — the third founder resigns, alone.
    let resignation = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
        community_key_id: gid.clone(),
        removed_identity_key_id: c.holder_identity_ref(2).to_owned(),
        removed_at: at(base + 600_000),
        effective_at: at(base + 600_000),
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    });
    let o = put_voices(
        d,
        &membership_voices(&resignation, Some(&v1_id), &[&keys[2]]),
    )
    .await
    .expect("I3236: a founder resigns alone");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3236: a resignation is one voice: {o:?}"
    );
    let StoredStanding::Stalled { held, .. } = standing(d).await else {
        panic!("I3236: stalled at M founders");
    };
    assert!(
        !crate::federation::canonical_community::is_live(d, &held, crate::host::clock::now())
            .await
            .unwrap(),
        "I3236: not live"
    );
    let _ = standing(d).await;
    assert_eq!(
        hard_cases(d, kind::COMMUNITY_LIVENESS_STALLED).await,
        1,
        "I3236: declared exactly once"
    );

    // I3237 — the founders seat the fourth holder in the resigned seat.
    let v2 = trust_root_room(&c, &[0, 1, 3], base);
    let v2_voices: Vec<Vec<u8>> = [0usize, 3, 1]
        .iter()
        .map(|i| roster_voices(&v2, 2, Some(&v1_id), ms(1_200_000), &[&keys[*i]]).remove(0))
        .collect();
    for v in &v2_voices[..2] {
        let o = e2::put_statement(d, v)
            .await
            .expect("I3237: a voice of the amendment");
        assert!(
            matches!(o, StatementOutcome::Pending { new: true, .. }),
            "I3237: one counted founder of the two needed: {o:?}"
        );
    }
    let o = e2::put_statement(d, &v2_voices[2])
        .await
        .expect("I3237: the second remaining founder");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3237: the remaining founders meet quorum:2/3: {o:?}"
    );
    let StoredStanding::Rooted(signed) = standing(d).await else {
        panic!("I3237: restored, Rooted");
    };
    assert!(
        crate::federation::canonical_community::is_live(d, &signed, crate::host::clock::now())
            .await
            .unwrap(),
        "I3237: live again"
    );
    assert_eq!(hard_cases(d, kind::COMMUNITY_LIVENESS_RESTORED).await, 1);
    assert_eq!(hard_cases(d, kind::COMMUNITY_LIVENESS_STALLED).await, 1);
}

// ─────────────────────────────────────────────────────────────────────────
//  (W1b) A ROOTED edition-2 trust root (CC 3.2 T2/T3, CC 4.4.3.34)
// ─────────────────────────────────────────────────────────────────────────

const W1B_NODE: &str = "w1b-node";
const W1B_OTHER_NODE: &str = "w1b-other-node";

async fn read_standing(
    d: &dyn FederationDirectory,
    root: &str,
) -> crate::federation::canonical_community::StoredStanding {
    crate::federation::canonical_community::stored_standing(d, root)
        .await
        .unwrap()
}

/// **I3242** — a root founded by the bundle's holders, chartered by its own
/// key and accepted by this node is ROOTED; both T3 legs hold.
pub(crate) async fn i3242_a_rooted_edition2_trust_root(d: &dyn FederationDirectory) {
    use crate::federation::canonical_community::StoredStanding;
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    assert_eq!(
        r.root,
        e2::kid(crate::federation::edition2::fixture_trust_root::ROOT_SEED)
    );
    let own = crate::federation::trust_root::own_chain_to(d, &r.root, crate::host::clock::now())
        .await
        .unwrap();
    assert!(
        own.accepted && own.chartered,
        "I3242: both T3 legs: {own:?}"
    );
    let StoredStanding::Rooted(head) = read_standing(d, &r.root).await else {
        panic!("I3242: rooted");
    };
    let mut founders: Vec<String> =
        crate::federation::canonical_community::founders(&head.community)
            .into_iter()
            .map(str::to_owned)
            .collect();
    founders.sort();
    let mut expected = r.founders.clone();
    expected.sort();
    assert_eq!(
        founders, expected,
        "I3242: the bundle's holders are its founders"
    );
}

/// **I3243** — the same chain is NOT rooted for a node that has not accepted
/// it, nor once this node withdraws its acceptance; an id never founded has
/// no standing.
pub(crate) async fn i3243_unrooted_without_this_nodes_acceptance(
    d: &dyn FederationDirectory,
    set_node: &(dyn Fn(String) + Sync),
) {
    use crate::federation::canonical_community::StoredStanding;
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    let node = e2::kid(W1B_NODE);
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    assert!(matches!(
        read_standing(d, &r.root).await,
        StoredStanding::Rooted(_)
    ));
    assert!(
        matches!(
            read_standing(d, &e2::kid("w1b-never-founded")).await,
            StoredStanding::Absent
        ),
        "I3243: no standing for an id never founded"
    );
    // Another node, which accepted nothing: the chain holds, the root does not.
    set_node(e2::put_key(d, W1B_OTHER_NODE, &["node"]).await);
    assert!(
        matches!(
            crate::federation::canonical_community::chain_standing_at(
                d,
                &r.root,
                crate::host::clock::now()
            )
            .await
            .unwrap(),
            StoredStanding::Rooted(_)
        ),
        "I3243: the chain still verifies"
    );
    assert!(
        matches!(
            read_standing(d, &r.root).await,
            StoredStanding::NotRooted { .. }
        ),
        "I3243: not rooted for a node that never accepted it"
    );
    // Back to the accepting node; it withdraws its edge: not rooted.
    set_node(node.clone());
    assert!(matches!(
        read_standing(d, &r.root).await,
        StoredStanding::Rooted(_)
    ));
    let w = e2::trust_withdraws_statement(&node, &r.root, &r.acceptance, now_ms());
    e2::put_statement(d, &w)
        .await
        .expect("I3243: the node withdraws its acceptance");
    assert!(
        matches!(
            read_standing(d, &r.root).await,
            StoredStanding::NotRooted { .. }
        ),
        "I3243: un-trust is one row (CC 3.2 T3)"
    );
}

fn purge_reason(e: Error) -> String {
    match e {
        Error::PurgeRefused { body, .. } => body["reason"].as_str().unwrap_or_default().to_owned(),
        other => panic!("a purge refusal, not {other:?}"),
    }
}

/// **I3244** — end to end: a steward purge notice under the rooted root is
/// short with one founder's voice and executes with two of three.
pub(crate) async fn i3244_a_purge_under_a_rooted_root(d: &dyn FederationDirectory) {
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    use crate::federation::edition2::group_fixtures::sign_group_payload;
    use crate::federation::edition2::typed::{takedown_payload, NoticeText, TAKEDOWN_PREFIX};
    use crate::federation::steward_purge::{
        purge_rows_edition2, selection_digest_bytes, unauthorised_reason, PurgeSelection,
    };
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let selection = PurgeSelection::mock_llm_traces();
    let digest = selection_digest_bytes::<&str>(&[]);
    let t = now_ms();
    let p = takedown_payload(
        "steward_purge",
        &r.root,
        &digest,
        &r.founders,
        &NoticeText {
            claim_text: "mock-LLM traces".into(),
            good_faith_statement: "stated in good faith".into(),
            jurisdiction: "US".into(),
        },
        t + 7 * 24 * 3_600_000,
        t,
    )
    .unwrap();
    let voice = |i: usize| sign_group_payload(&r.founder_key(i), &r.root, TAKEDOWN_PREFIX, &p);
    let first = voice(0);
    e2::put_statement(d, &first)
        .await
        .expect("I3244: founder 1's voice is kept");
    let notice = row_id_of(&first);
    assert_eq!(
        purge_reason(
            purge_rows_edition2(d, &selection, &notice, W1B_NODE)
                .await
                .unwrap_err()
        ),
        unauthorised_reason::QUORUM_NOT_MET,
        "I3244: one of three founders is short of quorum:2/3"
    );
    e2::put_statement(d, &voice(1))
        .await
        .expect("I3244: founder 2's voice is kept");
    let report = purge_rows_edition2(d, &selection, &notice, W1B_NODE)
        .await
        .expect("I3244: two of three founders meet quorum:2/3");
    let mut cosigners = report.cosigners.clone();
    cosigners.sort();
    let mut expected = r.founders[..2].to_vec();
    expected.sort();
    assert_eq!(cosigners, expected, "I3244: the counted founders");
    assert_eq!(
        report.notice_id,
        notice.hex(),
        "I3244: the notice is the row"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  (W1b) The infrastructure carve-out: rooted in THIS node's trust set
// ─────────────────────────────────────────────────────────────────────────

/// An infrastructure room founded by holders 1–3 at `quorum:2/3`, citing
/// `charter` (a root's `trust:charter:v1` row) when given.
async fn found_infra_room(
    d: &dyn FederationDirectory,
    seed: &str,
    charter: Option<&crate::federation::edition2::names::RowId>,
) -> crate::federation::types::Community {
    let mut rec = infrastructure_room(seed, &[], "quorum:2/3");
    let t = now_ms();
    if let GroupRecord::Community(c) = &mut rec {
        let founded = at(i64::try_from(t).unwrap() - 60_000);
        c.founded_at = founded;
        c.members = fixture_genesis::HOLDER_SEEDS
            .iter()
            .map(|h| CommunityMember {
                key_id: fixture_genesis::identity_ref_of(*h),
                joined_at: founded,
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect();
        if let Some(rid) = charter {
            c.charter_digest = rid.hex();
        }
    }
    let keys: Vec<_> = fixture_genesis::HOLDER_SEEDS
        .iter()
        .map(|h| fixture_genesis::test_key(*h))
        .collect();
    let refs: Vec<_> = keys.iter().collect();
    let o = put_voices(d, &roster_voices(&rec, 1, None, t, &refs))
        .await
        .expect("an infrastructure room founds");
    assert!(matches!(o, StatementOutcome::Row { .. }), "founded: {o:?}");
    d.lookup_community(&e2::kid(seed))
        .await
        .unwrap()
        .expect("the room is held")
}

async fn authorized(
    d: &dyn FederationDirectory,
    room: &crate::federation::types::Community,
) -> bool {
    crate::federation::admission::is_authorized_infrastructure_community(d, room)
        .await
        .unwrap()
}

fn with_member(
    room: &crate::federation::types::Community,
    key: &str,
) -> crate::federation::types::Community {
    let mut probe = room.clone();
    probe.members.push(CommunityMember {
        key_id: key.to_owned(),
        joined_at: room.founded_at,
        role: None,
    });
    probe
}

/// **I3245 / I3246 / I3247** — a room reached by this node's trust walk (the
/// root itself, or a room citing the root's charter) is an authorized
/// infrastructure room; a room nothing reaches is not, nor any once this
/// node withdraws its acceptance; a node member is exempt from the steward
/// binding only in an authorized room, an agent member never.
pub(crate) async fn i3245_i3247_infrastructure_rooted_here(d: &dyn FederationDirectory) {
    use crate::federation::admission::check_community_membership_steward_binding;
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    use crate::federation::types::identity_type;
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let root = d
        .lookup_community(&r.root)
        .await
        .unwrap()
        .expect("the root is held");

    // I3245 — reached: the root itself, and a room citing its charter.
    assert!(
        authorized(d, &root).await,
        "I3245: the rooted root is infrastructure here"
    );
    let shared = found_infra_room(d, "w1b-shared-room", Some(&r.charter)).await;
    assert!(
        authorized(d, &shared).await,
        "I3245: a room under the root's charter is infrastructure here"
    );

    // I3246 — unreached: a conformant room no root of this node reaches.
    let lone = found_infra_room(d, "w1b-lone-room", None).await;
    assert!(!authorized(d, &lone).await, "I3246: nothing reaches it");

    // I3247 — the carve-out exempts NODE members only, and only where authorized.
    let member_node = e2::put_key(d, "w1b-member-node", &["node"]).await;
    let member_agent = e2::put_key(d, "w1b-member-agent", &["agent"]).await;
    check_community_membership_steward_binding(d, &with_member(&shared, &member_node))
        .await
        .expect("I3247: a node member of an authorized room needs no steward");
    match check_community_membership_steward_binding(d, &with_member(&shared, &member_agent)).await
    {
        Err(Error::UnstewardedCommunityMember { member_role, .. })
            if member_role == identity_type::AGENT => {}
        other => panic!("I3247: an agent member is never exempt, got {other:?}"),
    }
    match check_community_membership_steward_binding(d, &with_member(&lone, &member_node)).await {
        Err(Error::UnstewardedCommunityMember { member_role, .. })
            if member_role == identity_type::NODE => {}
        other => panic!("I3247: no exemption in an unreached room, got {other:?}"),
    }

    // I3246 — un-trust is one row: the node withdraws its acceptance.
    let node = d.node_key_id().expect("the runner set the node key");
    let w = e2::trust_withdraws_statement(&node, &r.root, &r.acceptance, now_ms());
    e2::put_statement(d, &w)
        .await
        .expect("I3246: the node withdraws its acceptance");
    assert!(
        !authorized(d, &root).await,
        "I3246: the root is no longer reached"
    );
    assert!(
        !authorized(d, &shared).await,
        "I3246: nor the room under its charter"
    );
}

/// **I3248 / I3249** — `trust_root_valid` reads the edition-2 root at its own
/// id (its charter self-edge, this node's acceptance edge), and a capability
/// the root confers reaches it in the walk; the fixture is idempotent; the
/// node's withdrawal un-trusts both.
pub(crate) async fn i3248_i3249_trust_root_valid_and_the_walk(d: &dyn FederationDirectory) {
    use crate::federation::edition2::fixture_trust_root::{put_conferral, rooted_trust_root};
    use crate::federation::trust_root::{
        capability_roots_to_trusted_root, trust_root_valid, RootKind, INFRA_SERVE_SCOPE,
    };
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let again = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    assert_eq!(
        (again.birth, again.charter, again.acceptance),
        (r.birth, r.charter, r.acceptance),
        "I3248: rooted_trust_root is idempotent per directory"
    );
    let node = d.node_key_id().expect("the runner set the node key");

    // I3248 — trust_root_valid.
    let v = trust_root_valid(d, &node, &r.root).await.unwrap();
    assert!(
        v.edge_exists && v.root_self_declares && v.charter_has_recovery,
        "I3248: every leg at the root's own id: {v:?}"
    );
    assert!(
        v.holders_hardware_attested,
        "I3248: the founders' custody evidence (CC 4.2.2.1) is attested: {v:?}"
    );
    assert!(v.valid, "I3248: valid: {v:?}");
    assert_eq!(v.root_kind, RootKind::Community, "I3248: the community arm");

    // I3249 — a capability the root confers reaches it.
    let subject_seed = "w1b-cap-subject";
    let subject = e2::kid(subject_seed);
    let grant = put_conferral(d, &r, subject_seed, &[INFRA_SERVE_SCOPE])
        .await
        .expect("I3249: the root confers, the subject co-signs");
    let found = capability_roots_to_trusted_root(d, &node, &subject, INFRA_SERVE_SCOPE)
        .await
        .unwrap()
        .expect("I3249: the walk reaches a trusted root");
    assert_eq!(found.root_key_id, r.root, "I3249: the edition-2 root");
    assert_eq!(
        found.grant_attestation_id,
        // X2 build fix: W1b's `put_conferral` returns the row id itself.
        grant.hex(),
        "I3249: by its grant"
    );

    // Un-trust is one row.
    let w = e2::trust_withdraws_statement(&node, &r.root, &r.acceptance, now_ms());
    e2::put_statement(d, &w)
        .await
        .expect("I3249: the node withdraws its acceptance");
    assert!(
        !trust_root_valid(d, &node, &r.root).await.unwrap().valid,
        "I3249: not valid without the edge"
    );
    assert!(
        capability_roots_to_trusted_root(d, &node, &subject, INFRA_SERVE_SCOPE)
            .await
            .unwrap()
            .is_none(),
        "I3249: and the walk reaches nothing"
    );
}

/// **I3250** — the `trust:confers` path: an infrastructure room no charter
/// reaches is not authorized until the rooted root confers on it (the room's
/// own key co-signing the grant, as Verify's `confers` rule asks); then it
/// is, and a node member of it needs no steward.
pub(crate) async fn i3250_a_conferred_room_is_reached(d: &dyn FederationDirectory) {
    use crate::federation::admission::check_community_membership_steward_binding;
    use crate::federation::edition2::fixture_trust_root::{put_conferral, rooted_trust_root};
    use crate::federation::trust_root::INFRA_SERVE_SCOPE;
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let seed = "w1b-conferred-room";
    let room = found_infra_room(d, seed, None).await;
    assert!(!authorized(d, &room).await, "I3250: nothing reaches it yet");
    put_conferral(d, &r, seed, &[INFRA_SERVE_SCOPE])
        .await
        .expect("I3250: the root confers on the room, the room co-signs");
    assert!(
        authorized(d, &room).await,
        "I3250: the conferral reaches it from this node's trust walk"
    );
    let member_node = e2::put_key(d, "w1b-conferred-member", &["node"]).await;
    check_community_membership_steward_binding(d, &with_member(&room, &member_node))
        .await
        .expect("I3250: a node member of the reached room needs no steward");
}

/// **I3251** (W1b; ruling C, CC 2.6.1.11) — `resolve_serve_tier`'s canonical
/// rung is a seat of the genesis bundle in force: a listed serve node is
/// `Canonical`; a node key the bundle does not list is not. v62 P5-fix1 — and
/// the seat serves only once its owner announced it (the v62 security
/// ruling, CC rc20 5.4.6): an unannounced seat is not `Canonical`.
pub(crate) async fn i3251_canonical_is_a_bundle_seat(d: &dyn FederationDirectory) {
    use crate::federation::trust_root::{resolve_serve_tier, ServeTier};
    fixture_genesis::install_v2(d)
        .await
        .expect("I3251: the test ceremony installs");
    let resolver = d.node_key_id().expect("the runner set the node key");
    let seat = fixture_genesis::bundle_v2()
        .serve_node_identity_ref(0)
        .to_owned();
    assert_ne!(
        resolve_serve_tier(d, &seat, &resolver).await.unwrap(),
        ServeTier::Canonical,
        "I3251: a seat whose owner never announced it does not serve under it"
    );
    crate::federation::serve_seat_owner_invariants::bodies::announce_seat(d, 0, "w1b-seat-owner")
        .await;
    assert_eq!(
        resolve_serve_tier(d, &seat, &resolver).await.unwrap(),
        ServeTier::Canonical,
        "I3251: a serve node of the bundle in force, owner announced, is canonical"
    );
    let unlisted = e2::put_key(d, "w1b-unlisted-node", &["node"]).await;
    assert_ne!(
        resolve_serve_tier(d, &unlisted, &resolver).await.unwrap(),
        ServeTier::Canonical,
        "I3251: a node the bundle does not list is not"
    );
}

/// **I3252** (W1b; CC 2.6.1.11) — the federation-scope duty-holders are the
/// holders of the genesis bundle in force: with none held the resolver
/// refuses (never an empty set); once `bundle_v2` is installed they are
/// exactly its holders' identity-refs.
pub(crate) async fn i3252_federation_duty_holders_are_the_bundles(d: &dyn FederationDirectory) {
    use crate::federation::admission::{duty_holders_for_federation, DELEGATION_SCOPE_SLASH};
    let e = duty_holders_for_federation(d, DELEGATION_SCOPE_SLASH)
        .await
        .expect_err("I3252: no bundle held, refused");
    assert_eq!(e.kind(), "federation_invalid_argument", "I3252: {e}");
    fixture_genesis::install_v2(d)
        .await
        .expect("I3252: the test ceremony installs");
    let got = duty_holders_for_federation(d, DELEGATION_SCOPE_SLASH)
        .await
        .expect("I3252: the bundle's holders");
    let want: std::collections::HashSet<String> = fixture_genesis::bundle_v2()
        .holder_identity_refs()
        .into_iter()
        .collect();
    assert_eq!(
        got, want,
        "I3252: exactly the holders of the bundle in force"
    );
}

/// **I3253** (W1b; E9 finding 3, security) — a community root whose count
/// goes short (a later bundle seats other holders, so the birth's voices
/// no longer reach a strict majority of the holders in force) reads NOT
/// valid, by name, on the COMMUNITY arm: it never falls back to the key arm
/// at its own identity-ref (which holds a charter self-edge and this node's
/// acceptance). The capability walk and transit eligibility follow.
pub(crate) async fn i3253_no_key_arm_for_a_community_root(d: &dyn FederationDirectory) {
    use crate::federation::canonical_community::{chain_standing_at, StoredStanding};
    use crate::federation::edition2::fixture_trust_root::{
        put_acceptance, put_conferral, rooted_trust_root,
    };
    use crate::federation::trust_root::{
        capability_roots_to_trusted_root, resolve_transit_eligibility, trust_root_valid, RootKind,
        INFRA_SERVE_SCOPE,
    };
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let node = d.node_key_id().expect("the runner set the node key");
    let subject_seed = "w1b-short-subject";
    put_conferral(d, &r, subject_seed, &[INFRA_SERVE_SCOPE])
        .await
        .expect("I3253: the root confers");
    let subject = e2::kid(subject_seed);
    // The positive control: valid, and the walk reaches it.
    assert!(
        trust_root_valid(d, &node, &r.root).await.unwrap().valid,
        "I3253: valid first"
    );
    assert!(
        capability_roots_to_trusted_root(d, &node, &subject, INFRA_SERVE_SCOPE)
            .await
            .unwrap()
            .is_some(),
        "I3253: reached first"
    );
    // Transit's own positive control: bundle seat 0 is a node, offers
    // transport (its live transit key, CC 3.3.6.2) and accepts the same root,
    // so it is an eligible hop for this node while the root roots.
    let ceremony = fixture_genesis::bundle_v2();
    let peer = ceremony.serve_node_identity_ref(0).to_owned();
    put_acceptance(d, &r, &ceremony.serve_node_key(0), &peer)
        .await
        .expect("I3253: the seat accepts the root");
    assert!(
        resolve_transit_eligibility(d, &node, &peer)
            .await
            .unwrap()
            .eligible,
        "I3253: transit-eligible while the root roots"
    );
    // A later bundle seats holders 1, 4–7 (2 and 3 leave): the root's birth
    // voices {1, 2, 3} hold one of five; a strict majority is three.
    let later = fixture_genesis::later_v2(
        fixture_genesis::bundle_v2(),
        &[1, 4, 5, 6, 7],
        &fixture_genesis::SERVE_NODE_SEEDS,
        &[1, 2, 4, 5, 6, 7],
    );
    fixture_genesis::install_ceremony_v2(d, &later)
        .await
        .expect("I3253: the later bundle installs");
    assert!(
        matches!(
            chain_standing_at(d, &r.root, crate::host::clock::now())
                .await
                .unwrap(),
            StoredStanding::NotRooted { .. }
        ),
        "I3253: the community chain no longer roots"
    );
    let v = trust_root_valid(d, &node, &r.root).await.unwrap();
    assert!(!v.valid, "I3253: not valid: {v:?}");
    assert_eq!(
        v.root_kind,
        RootKind::Community,
        "I3253: judged on the community arm, never the key arm: {v:?}"
    );
    assert!(v.not_rooted.is_some(), "I3253: not valid BY NAME: {v:?}");
    assert!(
        capability_roots_to_trusted_root(d, &node, &subject, INFRA_SERVE_SCOPE)
            .await
            .unwrap()
            .is_none(),
        "I3253: the walk reaches nothing"
    );
    assert!(
        !resolve_transit_eligibility(d, &node, &peer)
            .await
            .unwrap()
            .eligible,
        "I3253: the same hop is not eligible once the count is short"
    );
}

/// **I3254** (W1b; CC rc21: `transport:canonical_rebind` counts at a STRICT
/// MAJORITY of the holders of the bundle in force) — with FOUR holders in
/// force the majority is three, so two voices (majority − 1, and also ⌈n/2⌉,
/// the count a half-rule would accept) are `Pending` and move nothing; the
/// third lands and the re-bound key is live.
pub(crate) async fn i3254_rebind_counts_a_strict_majority(d: &dyn FederationDirectory) {
    let c = four_holders();
    fixture_genesis::install_ceremony_v2(d, &c)
        .await
        .expect("I3254: four holders install");
    let seat = &c.seats[0];
    let bundle_key = seat.transit_xwing_pubkey.to_vec();
    let rebound = other_key(&seat.transit_xwing_pubkey, 0x6c);
    let at = now_ms();
    let voice = |i: usize| {
        rebind_voice(
            &c.holder_key(i),
            c.holder_identity_ref(i),
            &seat.identity_ref,
            &rebound,
            at,
            Some(&c.object_id),
        )
    };
    for i in 0..2 {
        let o = e2::put_statement(d, &voice(i))
            .await
            .expect("I3254: a holder's voice is kept");
        assert!(
            matches!(o, StatementOutcome::Pending { new: true, .. }),
            "I3254: {} of four holders is short of three: {o:?}",
            i + 1
        );
        assert_eq!(
            live_transit_key(d, &seat.identity_ref).await,
            Some(bundle_key.clone()),
            "I3254: a short re-bind moves nothing"
        );
    }
    let o = e2::put_statement(d, &voice(2))
        .await
        .expect("I3254: the third holder's voice");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3254: three of four holders is a strict majority: {o:?}"
    );
    assert_eq!(
        live_transit_key(d, &seat.identity_ref).await,
        Some(rebound),
        "I3254: the counted re-bind's key is live"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  Runners: sqlite and postgres
// ─────────────────────────────────────────────────────────────────────────

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
#[tokio::test]
async fn i3230_i3231_sqlite() {
    Box::pin(i3230_i3231_a_new_edge_names_its_head(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3230_i3231_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3230_i3231_a_new_edge_names_its_head(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3232_sqlite() {
    Box::pin(i3232_attached_stays_attached(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3232_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3232_attached_stays_attached(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3233_sqlite() {
    Box::pin(i3233_founding_needs_a_margin(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3233_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3233_founding_needs_a_margin(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3234_sqlite() {
    Box::pin(i3234_a_seat_alone_does_not_move_its_transit_key(
        &sqlite().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3234_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3234_a_seat_alone_does_not_move_its_transit_key(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3235_i3237_sqlite() {
    // The stalled/restored declarations are hard_case rows this node attests
    // (`attestation_admit::hard_case_attester`): no node key, nothing is
    // recorded (`record_observation` drops it with a warning).
    Box::pin(i3235_i3237_the_trust_root_liveness_margin(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3235_i3237_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3235_i3237_the_trust_root_liveness_margin(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3238_sqlite() {
    Box::pin(i3238_a_rebind_is_counted(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3238_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3238_a_rebind_is_counted(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3239_sqlite() {
    Box::pin(i3239_only_holders_rebind_a_seat(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3239_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3239_only_holders_rebind_a_seat(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3240_sqlite() {
    Box::pin(i3240_a_rebind_names_the_bundle_in_force(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3240_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3240_a_rebind_names_the_bundle_in_force(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3241_sqlite() {
    Box::pin(i3241_a_reseat_by_a_later_bundle_is_live(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3241_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3241_a_reseat_by_a_later_bundle_is_live(&b)).await;
}

#[cfg(feature = "sqlite")]
async fn sqlite_with_node() -> crate::store::sqlite::SqliteBackend {
    let b = sqlite().await;
    let node = e2::put_key(&b, W1B_NODE, &["node"]).await;
    b.set_node_key_id(node);
    b
}

#[cfg(feature = "postgres")]
async fn postgres_with_node() -> Option<crate::store::postgres::PostgresBackend> {
    let b = postgres().await?;
    let node = e2::put_key(&b, W1B_NODE, &["node"]).await;
    b.set_node_key_id(node);
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3242_sqlite() {
    Box::pin(i3242_a_rooted_edition2_trust_root(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3242_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3242_a_rooted_edition2_trust_root(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3243_sqlite() {
    let b = sqlite_with_node().await;
    let set = |k: String| b.set_node_key_id(k);
    Box::pin(i3243_unrooted_without_this_nodes_acceptance(&b, &set)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3243_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    let set = |k: String| b.set_node_key_id(k);
    Box::pin(i3243_unrooted_without_this_nodes_acceptance(&b, &set)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3244_sqlite() {
    Box::pin(i3244_a_purge_under_a_rooted_root(&sqlite_with_node().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3244_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3244_a_purge_under_a_rooted_root(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3245_i3247_sqlite() {
    Box::pin(i3245_i3247_infrastructure_rooted_here(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3245_i3247_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3245_i3247_infrastructure_rooted_here(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3248_i3249_sqlite() {
    Box::pin(i3248_i3249_trust_root_valid_and_the_walk(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3248_i3249_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3248_i3249_trust_root_valid_and_the_walk(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3250_sqlite() {
    Box::pin(i3250_a_conferred_room_is_reached(&sqlite_with_node().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3250_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3250_a_conferred_room_is_reached(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3251_sqlite() {
    Box::pin(i3251_canonical_is_a_bundle_seat(&sqlite_with_node().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3251_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3251_canonical_is_a_bundle_seat(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3252_sqlite() {
    Box::pin(i3252_federation_duty_holders_are_the_bundles(
        &sqlite().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3252_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3252_federation_duty_holders_are_the_bundles(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3253_sqlite() {
    Box::pin(i3253_no_key_arm_for_a_community_root(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3253_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3253_no_key_arm_for_a_community_root(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3254_sqlite() {
    Box::pin(i3254_rebind_counts_a_strict_majority(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3254_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3254_rebind_counts_a_strict_majority(&b)).await;
}
