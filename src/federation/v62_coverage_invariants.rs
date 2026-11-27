//! v62.0.0 (wave W1) — **edition-2 witnesses for properties whose earlier
//! tests were deleted** with the earlier canonical and accord records (rc6,
//! `test_ceremony_1106`, remint, `accord_lineage`; E7's property map,
//! "Update 9"). Each runs on sqlite and postgres through the one edition-2
//! entry (`edition2::ingest::put_statement`).
//!
//! - **I3230** (was I356; v62.0.0 R2-accept2, the three kinds) — a NEW
//!   `trust:accepts:v1` acceptance of the LINEAGE, naming no bundle, is
//!   refused `trust_root_head_unnamed` and not stored; the same headless edge
//!   to a held GROUP (kind C) lands.
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
//! - **I3253** (v62.0.0 R2-valid; CC 3.2 T5) — a key carrying a complete
//!   charter self-edge, accepted by this node, is no root, by name, and its
//!   own conferral roots nothing; the bundle's lineage beside it does.
//!
//! - **I3254** (CC rc21) — a re-bind counts at a strict majority of the
//!   holders of the bundle in force: with four holders, two voices are
//!   `Pending`, the third lands.
//!
//! - **I3255** (W1-fix5; was I157, CC 4.2.2.1) — custody evidence on an
//!   edition-2 `key:record` is checked for its shape where the record lands:
//!   a hex-text chain is refused `edition2_statement_invalid` (nothing
//!   stored), the same key's byte-string chain lands, no evidence lands and
//!   projects none, and a chain lifted from another key lands but is refused
//!   where custody is judged.
//!
//! - **I3256** (W1-fix5; was I185's holder-hardware leg) — every holder of a
//!   rooted edition-2 root reports the measured class and a walked chain.
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
//  (a) The acceptance edge (CC 3.2 T4a): kind A on the lineage, kind C on a
//      group (R2-accept2)
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

/// The newest tip of the lineage in force, hex.
async fn lineage_tip(d: &dyn FederationDirectory) -> String {
    hex::encode(
        crate::federation::edition2::genesis::genesis_in_force(d)
            .await
            .expect("the genesis reads")
            .tips()
            .iter()
            .max_by_key(|t| t.asserted_at)
            .expect("a tip")
            .object_id,
    )
}

/// `consumer`'s `trust:accepts:v1` edge to the lineage, naming `head`.
fn lineage_acceptance(consumer: &str, head: Option<&str>, at: u64) -> Vec<u8> {
    crate::federation::edition2::fixture_trust_root::root_acceptance_statement(
        &e2::signing_key(consumer),
        &e2::kid(consumer),
        fixture_genesis::FAMILY_KEY_ID,
        head,
        at,
    )
    .expect("the acceptance signs")
}

/// **I3230 / I3231** — v62.0.0 (R2-accept2; the three kinds of
/// `trust-accepts`, pre4: "A reader that holds a lineage of the name in sub
/// refuses a new edge without it, trust_root_head_unnamed") — on the
/// LINEAGE: a new headless acceptance is refused by name and not stored; the
/// edge naming the held tip is admitted. And kind C: the same headless edge
/// to a GROUP this node holds (an admission walk's subject, never a root)
/// lands: T4a gates kind A only. (The earlier I3230 / I3231 read a group as a
/// root.)
pub(crate) async fn i3230_i3231_a_new_edge_names_its_head(d: &dyn FederationDirectory) {
    fixture_genesis::install_v2(d)
        .await
        .expect("the ceremony installs");
    found_root(d).await;
    let consumer = "w1-consumer";
    users(d, &[consumer]).await;
    let at = now_ms();

    // I3230 — headless, on the lineage: refused.
    let headless = lineage_acceptance(consumer, None, at);
    match e2::put_statement(d, &headless).await {
        Err(e) if e.kind() == "trust_root_head_unnamed" => {}
        other => panic!("I3230: a new headless acceptance of the lineage, got {other:?}"),
    }
    assert!(
        !stored(d, &headless).await,
        "I3230: the refused edge is not stored"
    );

    // I3231 — naming the tip this node holds: admitted.
    let named = lineage_acceptance(consumer, Some(&lineage_tip(d).await), at);
    let o = e2::put_statement(d, &named)
        .await
        .expect("I3231: the edge naming the held tip attaches");
    assert!(
        matches!(o, StatementOutcome::Row { new: true, .. }),
        "I3231: {o:?}"
    );
    assert!(stored(d, &named).await, "I3231: the edge is stored");

    // Kind C — a headless edge to a held GROUP lands (no root, no T4a).
    let group_edge = acceptance_edge(consumer, None);
    e2::put_statement(d, &group_edge)
        .await
        .expect("I3230 (kind C): a headless edge to a held group is not refused");
    assert!(
        stored(d, &group_edge).await,
        "I3230 (kind C): the group edge is stored"
    );
}

/// **I3232** — v62.0.0 (R2-accept2) on the LINEAGE (CC 3.2 T4 "an attached
/// root stays valid until revoked"; T4a, judged on first admission only):
/// after a later bundle of the lineage is imported, the attached edge
/// re-offered is not re-judged (held, not new), and a NEW edge naming the
/// superseded bundle (a held valid bundle of the lineage) is not refused.
pub(crate) async fn i3232_attached_stays_attached(d: &dyn FederationDirectory) {
    fixture_genesis::install_v2(d)
        .await
        .expect("the ceremony installs");
    let v1 = lineage_tip(d).await;
    let (early, late) = ("w1-early", "w1-late");
    users(d, &[early, late]).await;
    let at = now_ms();
    let edge = lineage_acceptance(early, Some(&v1), at);
    e2::put_statement(d, &edge)
        .await
        .expect("I3232: attaches on bundle 1");

    let later = fixture_genesis::later_v2(
        fixture_genesis::bundle_v2(),
        &[1, 2, 4],
        &[11, 12],
        &[1, 2, 4],
    );
    fixture_genesis::install_ceremony_v2(d, &later)
        .await
        .expect("I3232: the later bundle installs");
    assert_ne!(lineage_tip(d).await, v1, "I3232: the tip moved");

    // T4 — the attached edge re-offered is not re-judged.
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

    // T4a — a NEW edge naming the superseded (held, valid) bundle lands.
    let stale = lineage_acceptance(late, Some(&v1), at);
    e2::put_statement(d, &stale)
        .await
        .expect("I3232: a new edge naming an earlier bundle of the lineage is not refused");
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

fn is_m_refusal(e: &Error) -> bool {
    matches!(
        e,
        Error::CommunityConsensusProtocolViolation { rule, .. }
            if *rule == crate::federation::admission::INFRA_RULE_QUORUM_M_NOT_STRICT_MAJORITY
    )
}

/// **I4104** (IM-fix1; Eric's ruling 2026-11-21, CC 3.2) — **a trust-root-
/// grade room's `M` is the strict majority of its founder count**, judged by
/// the trust-root shape (the first gate a trust-root row meets, at its birth
/// and at every link). `quorum:3/3` over three founders, and `quorum:2/5` and
/// `quorum:4/5` over five, are refused `quorum_m_not_strict_majority` and
/// nothing lands. Before this cut `3/3` and `4/5` were refused for the
/// founding margin only, and `2/5` passed the shape and the margin. The
/// controls `quorum:2/3` and `quorum:3/5` are never refused for it (they may
/// be refused for a later leg, e.g. their founders' conferral).
pub(crate) async fn i4104_a_trust_root_m_is_the_strict_majority(d: &dyn FederationDirectory) {
    // Each room has its own founders (seeds distinct in their first bytes).
    let founders_of =
        |room: &str, n: usize| -> Vec<String> { (1..=n).map(|i| format!("f{i}-{room}")).collect() };
    for (room, n, protocol) in [
        ("im-room-33", 3, "quorum:3/3"),
        ("im-room-25", 5, "quorum:2/5"),
        ("im-room-45", 5, "quorum:4/5"),
    ] {
        let founders = founders_of(room, n);
        let refs: Vec<&str> = founders.iter().map(String::as_str).collect();
        let refused = found_room(d, room, &refs, protocol).await;
        assert!(
            refused.as_ref().is_some_and(is_m_refusal),
            "I4104: {protocol} over {n} founders, got {refused:?}"
        );
        assert!(
            d.lookup_community(&e2::kid(room)).await.unwrap().is_none(),
            "I4104: {protocol}: nothing lands"
        );
    }
    for (room, n, protocol) in [
        ("im-room-23", 3, "quorum:2/3"),
        ("im-room-35", 5, "quorum:3/5"),
    ] {
        let founders = founders_of(room, n);
        let refs: Vec<&str> = founders.iter().map(String::as_str).collect();
        let control = found_room(d, room, &refs, protocol).await;
        assert!(
            !control.as_ref().is_some_and(is_m_refusal),
            "I4104: {protocol} over {n} founders is the strict majority: {control:?}"
        );
    }
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

/// **I3240** — a re-bind names the bundle it is counted over (`refs.head`):
/// none is refused, an unheld bundle waits, and over an EARLIER bundle of the
/// lineage only the voices dated before its successor count (KR-fix2 rev 3;
/// CC rc22 7b4a55e).
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
    // v62.0.0 (KR-fix2 rev 3; Constitution's ruling, CC rc22 7b4a55e) — a
    // re-bind is judged against the bundle it NAMES, and counts only voices
    // whose own `asserted_at` is before the next held bundle's. (Before: a
    // re-bind over a superseded bundle was held `rebind_head_not_in_force`,
    // whatever its instant, which made the outcome depend on arrival order.)
    //
    // Dated NOW, after the later bundle's instant: kept, and it counts
    // nothing, from one holder or from two.
    let stale = voice(Some(&c.object_id));
    for (i, v) in [
        stale.clone(),
        rebind_voice(
            &c.holder_key(1),
            c.holder_identity_ref(1),
            &seat.identity_ref,
            &rebound,
            {
                let (_, p) = crate::federation::edition2::liveness::statement_parts(&stale)
                    .expect("I3240: the stale voice reads");
                p.get_text("asserted_at")
                    .and_then(ciris_verify_core::cde::Value::as_u64)
                    .expect("I3240: its instant")
            },
            Some(&c.object_id),
        ),
    ]
    .iter()
    .enumerate()
    {
        match e2::put_statement(d, v).await {
            Ok(StatementOutcome::Pending { .. }) => {}
            other => panic!(
                "I3240: voice {i} of a re-bind over the earlier bundle, dated after its \
                 successor, counts nothing: {other:?}"
            ),
        }
    }
    assert_eq!(
        live_transit_key(d, &seat.identity_ref).await,
        Some(seat.transit_xwing_pubkey.to_vec()),
        "I3240: two holders' voices dated after the successor move nothing"
    );
    // Dated BEFORE the later bundle's instant, over the same earlier bundle:
    // two holders' voices count, whichever arrived first, the re-bind or the
    // later bundle.
    let before = later.spec.t0_ms + fixture_genesis::DAY_MS / 2 + 1_000;
    let early = other_key(&seat.transit_xwing_pubkey, 0x22);
    let mut last = None;
    for i in 0..2 {
        last = Some(
            e2::put_statement(
                d,
                &rebind_voice(
                    &c.holder_key(i),
                    c.holder_identity_ref(i),
                    &seat.identity_ref,
                    &early,
                    before,
                    Some(&c.object_id),
                ),
            )
            .await
            .expect("I3240: a voice dated before the successor is kept"),
        );
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "I3240: two holders' voices dated before the successor count over the bundle they \
         name: {last:?}"
    );
    let o = e2::put_statement(d, &voice(Some(&later.object_id)))
        .await
        .expect("I3240: over the bundle in force, kept");
    assert!(
        matches!(o, StatementOutcome::Pending { new: true, .. }),
        "I3240: {o:?}"
    );
}

/// **I4209** (KR-fix2 rev 5; CC rc22 7b4a55e) — **two nodes that hold the
/// same re-bind and the same bundles LIST it alike, whichever arrived
/// first.** Two holders voice a re-bind over the first bundle, dated AFTER
/// the later bundle's `asserted_at`. Node A receives the voices and then the
/// later bundle (its door answered `Row`: no successor was held, and the
/// re-bind plane is final, so A's stored fold state says concluded). Node B
/// receives the later bundle and then the voices (`Pending`: stored held).
/// The verdict readers already agreed (the seat's live key is the binding's
/// on both). The host listings now agree too: `voice_status` is `Waiting` /
/// `count_short` on both, `why_held_listed` gives the same reason on both,
/// and the held-rows page lists the re-bind on neither.
pub(crate) async fn i4209_a_rebind_lists_alike_in_either_order(
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
) {
    use crate::federation::edition2::fold;
    use crate::federation::edition2::names::RowId;
    use crate::federation::edition2::second_signer_voice::{row_status, VoiceOutcome};
    use crate::federation::edition2::transport_rebind::{rebind_counted, rebind_held_for};
    let c = fixture_genesis::bundle_v2();
    let later = fixture_genesis::later_v2(
        c,
        &fixture_genesis::HOLDER_SEEDS,
        &fixture_genesis::SERVE_NODE_SEEDS,
        &fixture_genesis::HOLDER_SEEDS[..2],
    );
    let seat = &c.seats[0];
    let rebound = other_key(&seat.transit_xwing_pubkey, 0x29);
    // Dated from the later bundle's own instant, never the wall clock.
    let late = later.asserted_at_ms + 1_000;
    let voices: Vec<Vec<u8>> = (0..2)
        .map(|i| {
            rebind_voice(
                &c.holder_key(i),
                c.holder_identity_ref(i),
                &seat.identity_ref,
                &rebound,
                late,
                Some(&c.object_id),
            )
        })
        .collect();
    let rid = RowId::of_statement(&voices[0]).expect("I4209: a row id");

    // A: the first bundle, the voices, then the later bundle.
    fixture_genesis::install_v2(a)
        .await
        .expect("I4209: A installs the first bundle");
    let mut last = None;
    for v in &voices {
        last = Some(
            e2::put_statement(a, v)
                .await
                .expect("I4209: A keeps the voice"),
        );
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "I4209: with no successor held, A's door counts both voices: {last:?}"
    );
    assert_eq!(
        rebind_counted(a, &rid).await.expect("I4209: A reads"),
        Some(true),
        "I4209: before the later bundle, the re-bind counts on A"
    );
    fixture_genesis::install_ceremony_v2(a, &later)
        .await
        .expect("I4209: A installs the later bundle");

    // B: both bundles, then the voices.
    fixture_genesis::install_v2(b)
        .await
        .expect("I4209: B installs the first bundle");
    fixture_genesis::install_ceremony_v2(b, &later)
        .await
        .expect("I4209: B installs the later bundle");
    for v in &voices {
        match e2::put_statement(b, v).await {
            Ok(StatementOutcome::Pending { .. }) => {}
            other => panic!("I4209: dated after the successor B holds, got {other:?}"),
        }
    }

    // The stored fold state differs (this is what the listings must not
    // show): concluded on A, held on B.
    assert!(
        fold::why_held(a, &rid)
            .await
            .expect("I4209: A's stored state")
            .is_none(),
        "I4209: A stores the re-bind as concluded (the final plane never un-concludes it)"
    );
    assert_eq!(
        fold::why_held(b, &rid)
            .await
            .expect("I4209: B's stored state")
            .map(|h| h.reason),
        Some(fold::reason::COUNT_SHORT.to_owned()),
        "I4209: B stores it as held"
    );

    // Every reader a host has gives one answer on both nodes.
    for (name, d) in [("A", a), ("B", b)] {
        assert_eq!(
            rebind_counted(d, &rid).await.expect("I4209: reads"),
            Some(false),
            "I4209: {name}: the re-bind does not count"
        );
        assert_eq!(
            rebind_held_for(d, &seat.identity_ref)
                .await
                .expect("I4209: reads"),
            None,
            "I4209: {name}: no re-bind is live for the seat"
        );
        assert_eq!(
            live_transit_key(d, &seat.identity_ref).await,
            Some(seat.transit_xwing_pubkey.to_vec()),
            "I4209: {name}: the seat's key is its binding's"
        );
        match row_status(d, &rid).await.expect("I4209: voice_status") {
            VoiceOutcome::Waiting { reason, .. } => assert_eq!(
                reason,
                fold::reason::COUNT_SHORT,
                "I4209: {name}: voice_status"
            ),
            other => panic!("I4209: {name}: voice_status says {other:?}"),
        }
        let listed = fold::why_held_listed(d, &rid)
            .await
            .expect("I4209: why_held_listed")
            .unwrap_or_else(|| panic!("I4209: {name}: the listing says concluded"));
        assert_eq!(
            (listed.reason.as_str(), listed.plane.as_str()),
            (fold::reason::COUNT_SHORT, fold::plane::REBIND),
            "I4209: {name}: why_held_listed"
        );
        let page = fold::held_rows_listed(d, None, fold::MAX_HELD_PAGE)
            .await
            .expect("I4209: held_rows_listed");
        assert!(
            page.iter().all(|h| h.plane != fold::plane::REBIND),
            "I4209: {name}: the held-rows page lists no re-bind"
        );
    }
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
        leaf: crate::federation::types::RevocationLeaf::Resignation,
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

// LEAD-root1 (CC 3.2 T5) — I3242 (a root community chartered by its own key and accepted is ROOTED; both T3 legs) DELETED: no row is a charter and no community is a root. The node's acceptance of the bundle is peer_rooting / root_grant_invariants (accepting_node).

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
        read_standing(d, &r.lineage).await,
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
                &r.lineage,
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
            read_standing(d, &r.lineage).await,
            StoredStanding::NotRooted { .. }
        ),
        "I3243: not rooted for a node that never accepted it"
    );
    // Back to the accepting node; it withdraws its edge: not rooted.
    set_node(node.clone());
    assert!(matches!(
        read_standing(d, &r.lineage).await,
        StoredStanding::Rooted(_)
    ));
    let w = e2::trust_withdraws_statement(&node, &r.lineage, &r.acceptance, now_ms());
    e2::put_statement(d, &w)
        .await
        .expect("I3243: the node withdraws its acceptance");
    assert!(
        matches!(
            read_standing(d, &r.lineage).await,
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
        &r.lineage,
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
    let voice = |i: usize| sign_group_payload(&r.founder_key(i), &r.lineage, TAKEDOWN_PREFIX, &p);
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
        .lookup_community(&r.lineage)
        .await
        .unwrap()
        .expect("the root is held");

    // I3245 — reached: the root itself, and a room citing its charter.
    assert!(
        authorized(d, &root).await,
        "I3245: the rooted root is infrastructure here"
    );
    // LEAD-root1 — no row is a charter: the room cites none.
    let shared = found_infra_room(d, "w1b-shared-room", None).await;
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
    let w = e2::trust_withdraws_statement(&node, &r.lineage, &r.acceptance, now_ms());
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

/// **I4290** (KR-fix13; CC 3.1.3.2 "A node gives no acceptance", CC 4.4.3.19;
/// the ceremony's step 10) — **a canonical install is seated in the
/// infrastructure room by the founders' count alone.** An infrastructure room
/// under the rooted root's charter is founded by the holders' voices ONLY;
/// its roster lists a serve SEAT of the genesis bundle in force as a member
/// with no role. It lands: no voice of the node, no acceptance row from the
/// node or from an owner (the seat has none), and the node is on the roster,
/// not a founder (it holds no vote). KR-fix10's consent rule is not asked.
///
/// v62.0.0 (KR-fix23; CC 4.4.3.19 as written: "seated by the founders' count
/// alone, for the canonical room with the bundle's conferral") — the same
/// room listing a `node` key that is NO seat of the bundle ALSO lands on the
/// holders' voices alone (any infrastructure room seats a node by the
/// founders' count; before KR-fix23 it did not land). Only THE CANONICAL room
/// (`ciris-canonical`) asks for the bundle's conferral: the one predicate
/// answers no for that node there, yes for the seat.
pub(crate) async fn i4290_a_bundle_seat_is_seated_without_acceptance(d: &dyn FederationDirectory) {
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    use crate::federation::membership_acceptance::node_seated_without_acceptance;
    let _r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let seat = fixture_genesis::bundle_v2().seats[0].identity_ref.clone();
    let stray = e2::put_key(d, "i4290-stray-node", &["node"]).await;
    assert!(
        crate::federation::edition2::genesis::is_canonical_by_bundle(d, &seat)
            .await
            .unwrap(),
        "I4290 premise: the seat is a serve seat of the bundle in force"
    );
    // A room under the root's charter, founded by the three holders, listing
    // `member` (no role) besides them. Only the holders voice it.
    let found = |seed: &'static str, member: String| async move {
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
                .chain(std::iter::once(CommunityMember {
                    key_id: member,
                    joined_at: founded,
                    role: None,
                }))
                .collect();
            // LEAD-root1 — no row is a charter: the room cites none.
        }
        let keys: Vec<_> = fixture_genesis::HOLDER_SEEDS
            .iter()
            .map(|h| fixture_genesis::test_key(*h))
            .collect();
        let refs: Vec<_> = keys.iter().collect();
        let voices = roster_voices(&rec, 1, None, t, &refs);
        let row = row_id_of(&voices[0]);
        (put_voices(d, &voices).await, row)
    };

    // The seat: lands on the founders' voices alone.
    let (out, rec) = found("i4290-canonical-room", seat.clone()).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { .. })),
        "I4290: the room listing a bundle seat lands on the holders' voices alone: {out:?}"
    );
    let cid = e2::kid("i4290-canonical-room");
    let room = d
        .lookup_community(&cid)
        .await
        .unwrap()
        .expect("I4290: the room is held");
    let listed = room
        .members
        .iter()
        .find(|m| m.key_id == seat)
        .expect("I4290: the seat is on the roster");
    assert_eq!(listed.role, None, "I4290: a member, not a founder: no vote");
    assert!(
        d.active_community_members(&cid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == seat),
        "I4290: the seat is an active member"
    );
    assert!(
        node_seated_without_acceptance(d, &room, &seat, room.founded_at)
            .await
            .unwrap(),
        "I4290: the one predicate: a bundle seat needs no acceptance in an infrastructure room"
    );
    // Nothing the seat or an owner signed: the seat authored no row at all,
    // and no membership reply is about it.
    assert!(
        d.list_attestations_by(&seat)
            .await
            .unwrap()
            .iter()
            .all(|a| crate::federation::membership_acceptance::membership_row(a).is_none()),
        "I4290: the seat signed no acceptance"
    );
    assert_eq!(
        d.edition2_voices(&rec).await.unwrap().len(),
        fixture_genesis::HOLDER_SEEDS.len(),
        "I4290: only the holders voiced the founding (the seat's voice is not among them)"
    );
    assert!(
        d.list_attestations_for(&seat)
            .await
            .unwrap()
            .iter()
            .all(|a| crate::federation::membership_acceptance::membership_row(a).is_none()),
        "I4290: no proposal, acceptance or decline is about the seat"
    );
    assert_eq!(
        crate::federation::admission::owner_of(d, &seat)
            .await
            .unwrap(),
        None,
        "I4290: and it has no owner yet (the founding seats it before any owner binding)"
    );

    // KR-fix23 — a node that is no seat of the bundle, in an infrastructure
    // room that is not the canonical one: seated by the founders' count too.
    let (out, _) = found("i4290-stray-room", stray.clone()).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { .. })),
        "I4290 (KR-fix23): any node is seated by the founders' count in an infrastructure \
         room: {out:?}"
    );
    let stray_cid = e2::kid("i4290-stray-room");
    let stray_room = d
        .lookup_community(&stray_cid)
        .await
        .unwrap()
        .expect("I4290 (KR-fix23): that room landed");
    assert!(
        d.active_community_members(&stray_cid)
            .await
            .unwrap()
            .iter()
            .any(|m| m.key_id == stray && m.role.is_none()),
        "I4290 (KR-fix23): the node is an active member, with no vote"
    );
    assert!(
        node_seated_without_acceptance(d, &stray_room, &stray, stray_room.founded_at)
            .await
            .unwrap(),
        "I4290 (KR-fix23): the one predicate answers yes for it there"
    );
    // The canonical room asks for the bundle's conferral: the same record
    // under the reserved id seats the bundle's seat and not that node.
    let mut canonical = stray_room.clone();
    canonical.community_key_id =
        crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID.to_owned();
    assert!(
        !node_seated_without_acceptance(d, &canonical, &stray, canonical.founded_at)
            .await
            .unwrap(),
        "I4290 (KR-fix23): in the canonical room a node that is no bundle seat is not seated so"
    );
    assert!(
        node_seated_without_acceptance(d, &canonical, &seat, canonical.founded_at)
            .await
            .unwrap(),
        "I4290 (KR-fix23): in the canonical room the bundle's seat is"
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
        (again.head, again.acceptance),
        (r.head, r.acceptance),
        "I3248: rooted_trust_root is idempotent per directory"
    );
    let node = d.node_key_id().expect("the runner set the node key");

    // I3248 — trust_root_valid.
    let v = trust_root_valid(d, &node, &r.lineage, crate::host::clock::now())
        .await
        .unwrap();
    assert!(
        v.edge_exists && v.root_self_declares && v.charter_has_recovery,
        "I3248: every leg at the root's own id: {v:?}"
    );
    assert!(
        v.holders_hardware_attested,
        "I3248: the founders' custody evidence (CC 4.2.2.1) is attested: {v:?}"
    );
    assert!(v.valid, "I3248: valid: {v:?}");
    assert_eq!(
        v.root_kind,
        RootKind::Family,
        "I3248 (R2-valid): the root is the bundle's lineage, the one kind"
    );

    // I3249 — a capability the root confers reaches it.
    let subject_seed = "w1b-cap-subject";
    let subject = e2::kid(subject_seed);
    let grant = put_conferral(d, &r, subject_seed, &[INFRA_SERVE_SCOPE])
        .await
        .expect("I3249: the root confers, the subject co-signs");
    let found = capability_roots_to_trusted_root(
        d,
        &node,
        &subject,
        INFRA_SERVE_SCOPE,
        crate::host::clock::now(),
    )
    .await
    .unwrap()
    .expect("I3249: the walk reaches a trusted root");
    assert_eq!(found.root_key_id, r.lineage, "I3249: the edition-2 root");
    assert_eq!(
        found.grant_attestation_id,
        // X2 build fix: W1b's `put_conferral` returns the row id itself.
        grant.hex(),
        "I3249: by its grant"
    );

    // Un-trust is one row.
    let w = e2::trust_withdraws_statement(&node, &r.lineage, &r.acceptance, now_ms());
    e2::put_statement(d, &w)
        .await
        .expect("I3249: the node withdraws its acceptance");
    assert!(
        !trust_root_valid(d, &node, &r.lineage, crate::host::clock::now())
            .await
            .unwrap()
            .valid,
        "I3249: not valid without the edge"
    );
    assert!(
        capability_roots_to_trusted_root(
            d,
            &node,
            &subject,
            INFRA_SERVE_SCOPE,
            crate::host::clock::now()
        )
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

/// **I3253** — v62.0.0 (R2-valid; CC 3.2 T5, "A key that signs a charter
/// about itself is no root") — a KEY carrying a complete `trust:charter:v1`
/// self-edge (`infra:serve` + `infra:attest`, a well-formed pre-rotation
/// commitment) and THIS node's own `trust:accepts:v1` edge to it is NOT a
/// root, by name: `trust_root_valid` reads it not valid with `not_rooted`
/// set, and a conferral the key signs roots nothing in the walk. The
/// positive control is the bundle's lineage on the same directory. (The
/// earlier I3253, "a community root whose count goes short is judged on the
/// community arm, never the key arm", is replaced: both arms are deleted.)
pub(crate) async fn i3253_a_self_chartered_key_is_no_root(d: &dyn FederationDirectory) {
    use crate::federation::edition2::fixture_trust_root::{put_conferral, rooted_trust_root};
    use crate::federation::operational::test_support::e2_trust_edge;
    use crate::federation::trust_root::{
        capability_roots_to_trusted_root, trust_root_valid, CHARTER_PRE_ROTATION_FIELD,
        INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE, TRUST_CHARTER_DIMENSION, TRUST_CONFERS_DIMENSION,
    };
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let node = d.node_key_id().expect("the runner set the node key");
    let subject_seed = "r2v-keyed-subject";
    let subject = e2::kid(subject_seed);
    put_conferral(d, &r, subject_seed, &[INFRA_SERVE_SCOPE])
        .await
        .expect("I3253: the lineage confers (the control)");
    assert!(
        trust_root_valid(d, &node, &r.lineage, crate::host::clock::now())
            .await
            .unwrap()
            .valid,
        "I3253 CONTROL: the lineage is a valid root"
    );

    // The keyed shape: a key, its complete charter self-edge, this node's
    // acceptance of it, and a conferral it signs on a second subject.
    let key_seed = "r2v-self-chartered-key";
    let key = e2::put_key(d, key_seed, &["user"]).await;
    let successor = e2::signing_key(&format!("{key_seed}-successor"));
    let commitment = ciris_verify_core::edition2::recovery::recovery_commitment(&[successor
        .public_key()
        .clone()]);
    let at = now_ms();
    let charter = e2_trust_edge(
        key_seed,
        &key,
        &key,
        vec![
            ("author", Value::Text(key.clone())),
            ("asserted_at", Value::Uint(at)),
            ("dimension", Value::Text(TRUST_CHARTER_DIMENSION.to_owned())),
            (
                "scope",
                Value::Array(vec![
                    Value::Text(INFRA_SERVE_SCOPE.to_owned()),
                    Value::Text(INFRA_ATTEST_SCOPE.to_owned()),
                ]),
            ),
            (
                CHARTER_PRE_ROTATION_FIELD,
                Value::Bytes(commitment.to_vec()),
            ),
        ],
    );
    // R2-valid's READ (lead's ruling 4): the charter door
    // (`check_trust_charter_admission`) still ADMITS a complete self-charter;
    // no validity reader takes it as a charter any more (it is inert here).
    e2::put_statement(d, &charter)
        .await
        .expect("I3253: the complete self-charter is admitted (inert)");
    e2::put_statement(
        d,
        &e2::trust_accepts_statement(
            &node,
            &key,
            &[],
            None,
            crate::federation::types::cohort_scope::FEDERATION,
            at,
        ),
    )
    .await
    .expect("I3253: this node's edge to the key lands (it names no lineage)");
    let keyed_seed = "r2v-keyed-grantee";
    let keyed = e2::put_key(d, keyed_seed, &["user"]).await;
    let grant = e2_trust_edge(
        key_seed,
        &key,
        &keyed,
        vec![
            ("author", Value::Text(key.clone())),
            ("asserted_at", Value::Uint(at)),
            ("dimension", Value::Text(TRUST_CONFERS_DIMENSION.to_owned())),
            (
                "scope",
                Value::Array(vec![Value::Text(INFRA_SERVE_SCOPE.to_owned())]),
            ),
        ],
    );
    let _ = e2::put_statement(d, &grant).await;
    let _ = e2::put_statement(d, &e2::voice_of(&grant, keyed_seed)).await;

    let v = trust_root_valid(d, &node, &key, crate::host::clock::now())
        .await
        .unwrap();
    assert!(
        !v.valid && !v.root_self_declares && v.not_rooted.is_some(),
        "I3253: a self-chartered key, accepted by this node, is no root, by name: {v:?}"
    );
    assert!(
        capability_roots_to_trusted_root(
            d,
            &node,
            &keyed,
            INFRA_SERVE_SCOPE,
            crate::host::clock::now()
        )
        .await
        .unwrap()
        .is_none(),
        "I3253: the key's own conferral roots nothing"
    );
    // The asking node's own id is no root either.
    assert!(
        trust_root_valid(d, &node, &node, crate::host::clock::now())
            .await
            .unwrap()
            .not_rooted
            .is_some(),
        "I3253: the node's own id is no root"
    );
    // The lineage still roots its own grant.
    assert!(
        capability_roots_to_trusted_root(
            d,
            &node,
            &subject,
            INFRA_SERVE_SCOPE,
            crate::host::clock::now()
        )
        .await
        .unwrap()
        .is_some(),
        "I3253 CONTROL: the lineage's counted grant still roots"
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
//  (W1-fix5) Custody evidence on an edition-2 `key:record` (CC 4.2.2.1)
// ─────────────────────────────────────────────────────────────────────────

/// A deterministic CBOR map (members sorted by their encodings).
fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(&Value::Text((*k).to_owned())));
    Value::Map(
        m.into_iter()
            .map(|(k, v)| (Value::Text(k.to_owned()), v))
            .collect(),
    )
}

/// The CC 4.2.2.1 custody evidence a `key:record` states: a YubiKey PIV
/// class, `removable_offline`, and `chain` as given.
fn custody_evidence(chain: Vec<Value>) -> Value {
    det_map(vec![
        ("hardware_class", Value::Text("YubiKey_5_FIPS".to_owned())),
        ("pq_custody", Value::Text("removable_offline".to_owned())),
        ("chain", Value::Array(chain)),
    ])
}

/// The A1 holder's REAL slot-9c chain (C4-fix's fixture), leaf first, hex.
fn real_a1_chain_hex() -> Vec<String> {
    use crate::federation::edition2::fixture_genesis_real_custody::{REAL_CHAIN_HEX, REAL_HOLDERS};
    std::iter::once(REAL_HOLDERS[0].leaf_9c_hex)
        .chain(REAL_CHAIN_HEX)
        .map(str::to_lowercase)
        .collect()
}

/// A `key:record` of `seed` (`user`) carrying `evidence`.
fn record_with_evidence(seed: &str, evidence: Value) -> Vec<u8> {
    e2::key_record_with(
        seed,
        &["user"],
        &e2::KeyRecordOptions {
            extra: vec![("attestation_evidence".to_owned(), evidence)],
            ..Default::default()
        },
    )
}

/// **I3255** (was I157 "replicated records are checked where they land",
/// restated on the edition-2 `key:record`; CC 4.2.2.1) — custody evidence is
/// checked for its SHAPE where a record lands, through the one entry every
/// replicated row takes (`put_statement`, tier `federation`):
/// - the chain stated as hex TEXT (not byte strings) is refused
///   `edition2_statement_invalid` and the key is not stored; the SAME key's
///   record with the same certificates as byte strings lands, so the refusal
///   was for the evidence's shape;
/// - a record with no evidence lands and projects none;
/// - a well-formed chain that attests ANOTHER key (the A1 holder's real
///   chain, lifted onto a test key) lands (the door reads shape only; the
///   custody gate takes no challenge input, C4-fix I2391) and projects the
///   chain leaf first, and the custody walk where a holder is judged refuses
///   it (it names A1's key, not this record's).
pub(crate) async fn i3255_key_record_evidence_is_checked_where_it_lands(
    d: &dyn FederationDirectory,
) {
    use crate::federation::edition2::token;
    use crate::federation::hardware_attestation::record_ed25519;
    use crate::federation::HardwareAttestationPolicy;

    let chain_hex = real_a1_chain_hex();
    let as_bytes: Vec<Value> = chain_hex
        .iter()
        .map(|h| Value::Bytes(hex::decode(h).expect("fixture hex")))
        .collect();
    let as_text: Vec<Value> = chain_hex.iter().map(|h| Value::Text(h.clone())).collect();

    // The chain as hex text: refused for the shape, nothing stored.
    let lifted = "w1f5-lifted-chain";
    let lifted_kid = e2::kid(lifted);
    match e2::put_statement(d, &record_with_evidence(lifted, custody_evidence(as_text))).await {
        Err(Error::MalformedRow { reason, .. }) => assert_eq!(
            reason,
            token::STATEMENT_INVALID,
            "I3255: a text chain is refused by the statement door's token"
        ),
        other => panic!("I3255: a text chain must be refused, got {other:?}"),
    }
    assert!(
        d.lookup_public_key(&lifted_kid).await.unwrap().is_none(),
        "I3255: a refused record leaves no key"
    );

    // No evidence: lands, projects none.
    let bare = e2::put_key(d, "w1f5-no-evidence", &["user"]).await;
    let rec = d
        .lookup_public_key(&bare)
        .await
        .unwrap()
        .expect("I3255: a record with no evidence lands");
    assert!(
        rec.attestation_evidence
            .as_ref()
            .is_none_or(serde_json::Value::is_null),
        "I3255: no evidence projects none: {:?}",
        rec.attestation_evidence
    );

    // The same key, the chain as byte strings: lands (shape only).
    match e2::put_statement(d, &record_with_evidence(lifted, custody_evidence(as_bytes))).await {
        Ok(StatementOutcome::KeyPlane { .. }) => {}
        other => panic!("I3255: a well-formed custody body lands at the key plane, got {other:?}"),
    }
    let rec = d
        .lookup_public_key(&lifted_kid)
        .await
        .unwrap()
        .expect("I3255: the well-formed record is the key's");
    let ev = rec
        .attestation_evidence
        .clone()
        .expect("I3255: the custody body is projected");
    let projected: Vec<String> = ev["chain"]
        .as_array()
        .expect("I3255: the chain is projected")
        .iter()
        .map(|c| c.as_str().expect("hex").to_lowercase())
        .collect();
    assert_eq!(projected, chain_hex, "I3255: the chain, leaf first");
    assert_eq!(ev["hardware_class"], "YubiKey_5_FIPS", "I3255: the class");

    // Where a holder is judged, the lifted chain is refused: it names A1's
    // key, not this record's.
    let judged = HardwareAttestationPolicy::default().check_structure(
        &rec.key_id,
        record_ed25519(&rec).as_deref(),
        rec.attestation_evidence.as_ref(),
    );
    assert!(
        judged.is_err(),
        "I3255: a chain lifted from another key is refused where custody is judged: {judged:?}"
    );
}

/// **I3256** (was I185's holder-hardware leg, restated on edition-2 custody;
/// CC 4.2.2.1) — every holder of a rooted edition-2 root reports the
/// MEASURED class (`ExternalSecureElement`, a YubiKey PIV chain) and a PASSED
/// chain walk (`layer_b: Some(true)`) against its own record's key, never
/// Layer-A-only: `trust_root_valid` over `rooted_trust_root`, whose founders
/// are the genesis bundle's holders with their custody chains.
pub(crate) async fn i3256_a_holder_reports_the_measured_class_and_a_walked_chain(
    d: &dyn FederationDirectory,
) {
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    use crate::federation::trust_root::trust_root_valid;
    use ciris_keyring::HardwareType;

    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let node = d.node_key_id().expect("the runner set the node key");
    let v = trust_root_valid(d, &node, &r.lineage, crate::host::clock::now())
        .await
        .unwrap();
    assert!(
        v.valid && v.holders_hardware_attested,
        "I3256: the rooted root is valid and attested: {v:?}"
    );
    let mut judged: Vec<String> = v
        .holders_hardware
        .iter()
        .map(|h| h.key_id.clone())
        .collect();
    judged.sort();
    let mut founders = r.founders.clone();
    founders.sort();
    assert_eq!(judged, founders, "I3256: every founder is judged");
    for h in &v.holders_hardware {
        assert_eq!(
            (h.class, h.layer_a, h.layer_b, h.refusal.as_deref()),
            (
                Some(HardwareType::ExternalSecureElement),
                true,
                Some(true),
                None
            ),
            "I3256: {} reports the measured class and a walked chain: {h:?}",
            h.key_id
        );
    }
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
async fn i4104_sqlite() {
    Box::pin(i4104_a_trust_root_m_is_the_strict_majority(&sqlite().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4104_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i4104_a_trust_root_m_is_the_strict_majority(&b)).await;
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
async fn i4209_sqlite() {
    Box::pin(i4209_a_rebind_lists_alike_in_either_order(
        &sqlite().await,
        &sqlite().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4209_postgres() {
    let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
        return;
    };
    Box::pin(i4209_a_rebind_lists_alike_in_either_order(&a, &b)).await;
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

// LEAD-root1 — runner of a deleted root-community witness.

// LEAD-root1 — runner of a deleted root-community witness.

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
async fn i4290_sqlite() {
    Box::pin(i4290_a_bundle_seat_is_seated_without_acceptance(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4290_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i4290_a_bundle_seat_is_seated_without_acceptance(&b)).await;
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
    Box::pin(i3253_a_self_chartered_key_is_no_root(
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
    Box::pin(i3253_a_self_chartered_key_is_no_root(&b)).await;
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

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3255_sqlite() {
    Box::pin(i3255_key_record_evidence_is_checked_where_it_lands(
        &sqlite().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3255_postgres() {
    let Some(b) = postgres().await else {
        return;
    };
    Box::pin(i3255_key_record_evidence_is_checked_where_it_lands(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3256_sqlite() {
    Box::pin(
        i3256_a_holder_reports_the_measured_class_and_a_walked_chain(&sqlite_with_node().await),
    )
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3256_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i3256_a_holder_reports_the_measured_class_and_a_walked_chain(&b)).await;
}

// ─────────────────────────────────────────────────────────────────────────
//  (TR-fix1) The standing machine in line with CC rc21 3.2 T7 / T8
// ─────────────────────────────────────────────────────────────────────────

const TR5_ROOM: &str = "tr-fix1-five-founder-root";

/// Five holders (seeds 1–5): a root founded by all five at `quorum:3/5`.
fn five_holders() -> fixture_genesis::TestCeremonyV2 {
    let mut spec = fixture_genesis::CeremonySpec::standard();
    spec.holders = vec![1, 2, 3, 4, 5];
    fixture_genesis::ceremony_v2(&spec)
}

/// **I2225 / I2226 / I2227** (TR-fix1; CC rc21 3.2 T7 l.1232 "live while its
/// active founder set holds at least M + 1 signers and stalled when it holds
/// M or fewer"; T8 l.1257) — the margin, not "a founder stopped counting":
///
/// - I2225: five holder founders at `quorum:3/5` are Rooted and live (5 ≥ 4).
/// - I2226: one resigns, 4 active = M + 1: still **Rooted** (before TR-fix1
///   this read Stalled because a recorded founder stopped counting).
/// - I2227: a second resigns, 3 active = M: **Stalled**, not live; and the
///   stalled root still authorises a purge (`trust_root_head` is its head:
///   T7 l.1240, non-admitting is only the founders' roster count and a
///   ceremony conferral).
pub(crate) async fn i2225_i2227_the_t7_margin(d: &dyn FederationDirectory) {
    use crate::federation::canonical_community::{founder_liveness, StoredStanding};
    use crate::federation::edition2::group::MembershipRecord;
    use crate::federation::edition2::group_fixtures::membership_voices;
    use crate::federation::types::CommunityMembershipRevocation;

    let c = five_holders();
    fixture_genesis::install_ceremony_v2(d, &c)
        .await
        .expect("I2225: five holders install");
    let gid = e2::kid(TR5_ROOM);
    let base = crate::host::clock::now().timestamp_millis() - 2 * 3_600_000;
    let ms = |offset: i64| u64::try_from(base + offset).unwrap();
    let now = crate::host::clock::now();

    let mut room = infrastructure_room(TR5_ROOM, &[], "quorum:3/5");
    if let GroupRecord::Community(r) = &mut room {
        r.founded_at = at(base);
        r.members = (0..5)
            .map(|i| CommunityMember {
                key_id: c.holder_identity_ref(i).to_owned(),
                joined_at: at(base),
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect();
    }
    let keys: Vec<_> = (0..5).map(|i| c.holder_key(i)).collect();
    let voices: Vec<Vec<u8>> = (0..5)
        .map(|i| roster_voices(&room, 1, None, ms(60_000), &[&keys[i]]).remove(0))
        .collect();
    for v in &voices {
        e2::put_statement(d, v)
            .await
            .expect("I2225: a holder founder's voice");
    }
    let v1_id = row_id_of(&voices[0]);
    let StoredStanding::Rooted(signed) =
        crate::federation::canonical_community::chain_standing_at(d, &gid, now)
            .await
            .unwrap()
    else {
        panic!("I2225: five founders at quorum:3/5 are Rooted");
    };
    assert_eq!(
        founder_liveness(d, &signed, now).await.unwrap(),
        (5, 3),
        "I2225: five active, M = 3"
    );

    let resign = |i: usize, offset: i64| {
        let r = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
            community_key_id: gid.clone(),
            removed_identity_key_id: c.holder_identity_ref(i).to_owned(),
            removed_at: at(base + offset),
            effective_at: at(base + offset),
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
            leaf: crate::federation::types::RevocationLeaf::Resignation,
        });
        membership_voices(&r, Some(&v1_id), &[&keys[i]])
    };

    // I2226 — 4 = M + 1: Rooted.
    put_voices(d, &resign(4, 600_000))
        .await
        .expect("I2226: a founder resigns alone");
    let StoredStanding::Rooted(signed) =
        crate::federation::canonical_community::chain_standing_at(d, &gid, now)
            .await
            .unwrap()
    else {
        panic!("I2226: four active founders at quorum:3/5 (M + 1) stay Rooted (CC 3.2 T7)");
    };
    assert_eq!(
        founder_liveness(d, &signed, now).await.unwrap(),
        (4, 3),
        "I2226: four active"
    );

    // I2227 — 3 = M: Stalled, valid, and it still authorises a purge.
    put_voices(d, &resign(3, 700_000))
        .await
        .expect("I2227: a second founder resigns");
    let StoredStanding::Stalled { held, .. } =
        crate::federation::canonical_community::chain_standing_at(d, &gid, now)
            .await
            .unwrap()
    else {
        panic!("I2227: three active founders at quorum:3/5 (= M) are Stalled");
    };
    assert_eq!(
        founder_liveness(d, &held, now).await.unwrap(),
        (3, 3),
        "I2227: three active"
    );
    assert!(
        !crate::federation::canonical_community::is_live(d, &held, now)
            .await
            .unwrap(),
        "I2227: not live"
    );
}

// LEAD-root1 (CC 3.2 T5) — I2227b (a root COMMUNITY stalled by a founder's resignation still authorises a purge) DELETED with the root community.

/// **I2228** (TR-fix1; CC rc21 3.2 T4, T8 (ii) "a lapsed timer never moves
/// Rooted or Stalled to NotRooted"; T8 l.1251 "t is a signer-stamped instant,
/// never the evaluating clock") — `trust_root_valid` and
/// `capability_roots_to_trusted_root` are judged at the caller's instant: the
/// rooted root and a conferral from it read the same at `t` and 200 days
/// later, with no drill or heartbeat row ever held (the drill band red).
pub(crate) async fn i2228_v_at_a_signer_stamped_instant(d: &dyn FederationDirectory) {
    use crate::federation::edition2::fixture_trust_root::{put_conferral, rooted_trust_root};
    use crate::federation::trust_root::{
        capability_roots_to_trusted_root, trust_root_valid, DrillFreshness, INFRA_SERVE_SCOPE,
    };
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let node = d.node_key_id().expect("the runner set the node key");
    put_conferral(d, &r, "tr-fix1-subject", &[INFRA_SERVE_SCOPE])
        .await
        .expect("I2228: the root confers");
    let t = crate::host::clock::now();
    let later = t + chrono::Duration::days(200);
    let v = trust_root_valid(d, &node, &r.lineage, t).await.unwrap();
    let w = trust_root_valid(d, &node, &r.lineage, later).await.unwrap();
    assert!(
        v.valid && w.valid,
        "I2228: valid at t and t + 200d: {v:?} / {w:?}"
    );
    assert_eq!(
        w.drill_freshness,
        DrillFreshness::Red,
        "I2228: no drill: red"
    );
    for at in [t, later] {
        assert!(
            capability_roots_to_trusted_root(
                d,
                &node,
                &e2::kid("tr-fix1-subject"),
                INFRA_SERVE_SCOPE,
                at
            )
            .await
            .unwrap()
            .is_some_and(|g| g.root_key_id == r.lineage),
            "I2228: the conferral reaches the root at {at}"
        );
    }
}

/// **I2229** (TR-fix1; CC rc21 3.2 T8 l.1255 "Holder custody … is an
/// admission gate at the seating row, never a leg of V") — with a hostile
/// custody policy (no hardware type, no custody tier and a foreign Yubico
/// root accepted), the rooted root's verdict is the edge ∧ charter ∧
/// recovery conjunction, and valid: custody is reported, not ANDed.
pub(crate) async fn i2229_custody_is_not_a_leg(
    d: &dyn FederationDirectory,
    set_policy: &dyn Fn(std::sync::Arc<crate::federation::HardwareAttestationPolicy>),
) {
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    use crate::federation::trust_root::trust_root_valid;
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let node = d.node_key_id().expect("the runner set the node key");
    let hostile = crate::federation::HardwareAttestationPolicy {
        accepted_hardware_types: std::collections::HashSet::new(),
        accepted_custody_tiers: std::collections::HashSet::new(),
        yubico_root_der: std::borrow::Cow::Borrowed(&[0x30, 0x00]),
        ..crate::federation::HardwareAttestationPolicy::default()
    };
    set_policy(std::sync::Arc::new(hostile));
    let v = trust_root_valid(d, &node, &r.lineage, crate::host::clock::now())
        .await
        .unwrap();
    set_policy(std::sync::Arc::new(
        crate::federation::HardwareAttestationPolicy::default(),
    ));
    assert_eq!(
        v.valid,
        v.edge_exists && v.root_self_declares && v.charter_has_recovery,
        "I2229: valid is the edge, charter and recovery legs only: {v:?}"
    );
    assert!(v.valid, "I2229: valid whatever custody reads: {v:?}");
}

/// **I2230 / I2231** (TR-fix1; CC rc21 3.1.3.2 "For `ciris-canonical` the
/// conferral is instead the accord's genesis bundle, whose count seats the
/// node"; CC 4.2.2.1 custody at seating) — the canonical conferral is a
/// serve seat of the bundle in force, whose holders carry valid edition-2
/// custody (the bundle reader's gate seated them): the seat holds it; a
/// holder and an ordinary node do not; `canonical_servers_among` returns the
/// seat alone. A bundle with a holder whose custody fails is not placed at
/// all (genesis_store_invariants I2393), so it seats nobody.
pub(crate) async fn i2230_i2231_canonical_is_the_bundle_seat(d: &dyn FederationDirectory) {
    use crate::federation::admission::{canonical_conferral_coscrub, canonical_servers_among};
    let c = fixture_genesis::bundle_v2();
    let seat = c.serve_node_identity_ref(0).to_owned();
    let holder = c.holder_identity_ref(0).to_owned();
    let plain = e2::put_key(d, "tr-fix1-plain-node", &["node"]).await;
    let record = |k: String| async move {
        d.lookup_public_key(&k)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("I2230: a key record for {k}"))
    };
    let p = record(plain.clone()).await;
    assert!(
        canonical_conferral_coscrub(d, &p, &[]).await.is_err(),
        "I2230: pre-genesis nothing is canonical"
    );
    fixture_genesis::install_v2(d)
        .await
        .expect("I2230: the bundle installs");
    for (k, want) in [
        (seat.clone(), true),
        (holder.clone(), false),
        (plain.clone(), false),
    ] {
        let rec = record(k.clone()).await;
        assert_eq!(
            canonical_conferral_coscrub(d, &rec, &[]).await.is_ok(),
            want,
            "I2230: {k} canonical = {want}"
        );
    }
    let got = canonical_servers_among(d, vec![seat.clone(), holder, plain])
        .await
        .unwrap();
    assert_eq!(
        got.iter().map(|r| r.key_id.clone()).collect::<Vec<_>>(),
        vec![seat],
        "I2231: the bundle's seat is the one canonical server"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2225_i2227_sqlite() {
    Box::pin(i2225_i2227_the_t7_margin(&sqlite_with_node().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2225_i2227_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i2225_i2227_the_t7_margin(&b)).await;
}

// LEAD-root1 — runner of a deleted root-community witness.

// LEAD-root1 — runner of a deleted root-community witness.

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2228_sqlite() {
    Box::pin(i2228_v_at_a_signer_stamped_instant(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2228_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i2228_v_at_a_signer_stamped_instant(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2229_sqlite() {
    let b = sqlite_with_node().await;
    let set = |p| b.set_hardware_attestation_policy(p);
    Box::pin(i2229_custody_is_not_a_leg(&b, &set)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2229_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    let set = |p| b.set_hardware_attestation_policy(p);
    Box::pin(i2229_custody_is_not_a_leg(&b, &set)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2230_i2231_sqlite() {
    Box::pin(i2230_i2231_canonical_is_the_bundle_seat(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2230_i2231_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i2230_i2231_canonical_is_the_bundle_seat(&b)).await;
}

/// **I2232** (TR-fix1; CC rc21 4.2.1, CC 2.6.1.11: a canonical changes only by
/// a later genesis bundle) — with the bundle in force, no store write can
/// un-seat a canonical (the withdraw and supersede doors and, TR-fix2, the
/// backend writer are deleted; `record_canonical_withdrawal` refuses by name): the seat stays canonical (`is_canonical_effective`,
/// `canonical_servers_among`, `serves_under_seat`'s seat leg). A later bundle
/// (an amend by a strict majority of the holders) that lists only the second
/// seat un-seats the first, and only it does.
pub(crate) async fn i2232_only_a_later_bundle_reseats(d: &dyn FederationDirectory) {
    use crate::federation::admission::{canonical_servers_among, is_canonical_effective};
    let c = fixture_genesis::bundle_v2();
    fixture_genesis::install_v2(d)
        .await
        .expect("I2232: the bundle installs");
    let (s0, s1) = (
        c.serve_node_identity_ref(0).to_owned(),
        c.serve_node_identity_ref(1).to_owned(),
    );
    assert!(
        is_canonical_effective(d, &s0).await.unwrap(),
        "I2232: seated"
    );
    // TR-fix2: the backend writer is retired; it refuses by name.
    assert!(
        matches!(
            d.record_canonical_withdrawal(&s0, None, &"11".repeat(32))
                .await,
            Err(crate::federation::Error::Unsupported { .. })
        ),
        "I2232: no store write un-seats a canonical"
    );
    assert!(
        is_canonical_effective(d, &s0).await.unwrap(),
        "I2232: a tombstone does not un-seat a bundle seat"
    );
    assert_eq!(
        canonical_servers_among(d, vec![s0.clone(), s1.clone()])
            .await
            .unwrap()
            .len(),
        2,
        "I2232: both seats are canonical servers"
    );
    let later = fixture_genesis::later_v2(
        c,
        &fixture_genesis::HOLDER_SEEDS,
        &fixture_genesis::SERVE_NODE_SEEDS[1..],
        &fixture_genesis::HOLDER_SEEDS[..2],
    );
    fixture_genesis::install_ceremony_v2(d, &later)
        .await
        .expect("I2232: the later bundle installs at two of three holders");
    assert!(
        !is_canonical_effective(d, &s0).await.unwrap(),
        "I2232: the later bundle un-seats the first seat"
    );
    assert!(
        is_canonical_effective(d, &s1).await.unwrap(),
        "I2232: and keeps the second"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2232_sqlite() {
    Box::pin(i2232_only_a_later_bundle_reseats(&sqlite_with_node().await)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2232_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i2232_only_a_later_bundle_reseats(&b)).await;
}

/// A statement by holder seed `seed`'s own key under its identity: a
/// `key:revocation` (`revoked_after`) or a later `key:record` of the same key
/// carrying `identity_type`.
fn holder_self_statement(seed: u8, family: &str, members: Vec<(&str, Value)>) -> Vec<u8> {
    let k = fixture_genesis::test_key(seed);
    let iref = fixture_genesis::identity_ref_of(seed);
    let mut m: Vec<(Value, Value)> = members
        .into_iter()
        .map(|(n, v)| (Value::Text(n.to_owned()), v))
        .collect();
    m.push((Value::Text("author".into()), Value::Text(iref.clone())));
    m.sort_by_key(|(n, _)| ciris_verify_core::cde::encode(n));
    ciris_verify_core::edition2::sign_row_statement(
        &k,
        &iref,
        &iref,
        "scores",
        family,
        &Value::Map(m),
        vec![],
    )
    .expect("a holder signs")
}

async fn w1b_standing(
    d: &dyn FederationDirectory,
    root: &str,
) -> crate::federation::canonical_community::StoredStanding {
    crate::federation::canonical_community::chain_standing_at(d, root, crate::host::clock::now())
        .await
        .unwrap()
}

/// **I2233** (TR-fix2; CC rc21 3.2 T7, the active founder set, condition
/// three: "t < the effective revoked_after of f's key") — W1b's root (holders
/// 1, 2, 3 founding at `quorum:2/3`) is Rooted; holder 3's own revocation of
/// its key with `revoked_after` in the past takes it out of the active set:
/// 2 = M, Stalled. Being a holder of the bundle in force does not stand in.
pub(crate) async fn i2233_a_revoked_holder_is_not_an_active_founder(d: &dyn FederationDirectory) {
    use crate::federation::canonical_community::StoredStanding;
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    assert!(
        matches!(w1b_standing(d, &r.lineage).await, StoredStanding::Rooted(_)),
        "I2233: three holder founders, Rooted"
    );
    let now = u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap();
    let rev = holder_self_statement(
        3,
        crate::federation::edition2::liveness::KEY_REVOCATION_FAMILY,
        vec![
            ("asserted_at", Value::Uint(now - 60_000)),
            ("revoked_after", Value::Uint(now - 60_000)),
        ],
    );
    e2::put_statement(d, &rev)
        .await
        .expect("I2233: holder 3 revokes its key");
    assert!(
        matches!(
            w1b_standing(d, &r.lineage).await,
            StoredStanding::Stalled { .. }
        ),
        "I2233: a founder past its key's revoked_after is not active: 2 = M, Stalled"
    );
}

/// **I2234** (TR-fix2; CC rc21 3.2 T7, condition four, and "a later key
/// record that adds `node` is a resignation at that record's `asserted_at`")
/// — holder 2's later record of the same key, `identity_type` {node}, takes
/// it out of the active set from its `asserted_at`: 2 = M, Stalled. (A MIXED
/// set {accord_holder, node} is refused at the key door, CC 2.4.1.1, I1870,
/// so a holder's seating record is never node-bearing.)
pub(crate) async fn i2234_a_node_bearing_holder_is_not_a_founder(d: &dyn FederationDirectory) {
    use crate::federation::canonical_community::StoredStanding;
    use crate::federation::edition2::fixture_trust_root::rooted_trust_root;
    let r = rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    assert!(
        matches!(w1b_standing(d, &r.lineage).await, StoredStanding::Rooted(_)),
        "I2234: Rooted"
    );
    let now = u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap();
    let k = fixture_genesis::test_key(2);
    let types = Value::Array(
        ["node"]
            .iter()
            .map(|t| Value::Text((*t).to_owned()))
            .collect(),
    );
    let rec = holder_self_statement(
        2,
        ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY,
        vec![
            ("key", ciris_verify_core::edition2::cose_key(k.public_key())),
            ("asserted_at", Value::Uint(now - 60_000)),
            // a `node` record ends (CC 2.4.1.1's node-key window)
            (
                "valid_until",
                Value::Uint(now + 30 * fixture_genesis::DAY_MS),
            ),
            ("identity_type", types),
        ],
    );
    e2::put_statement(d, &rec)
        .await
        .expect("I2234: holder 2's node-bearing record lands");
    assert!(
        matches!(
            w1b_standing(d, &r.lineage).await,
            StoredStanding::Stalled { .. }
        ),
        "I2234: a node-bearing founder does not count: 2 = M, Stalled"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2233_sqlite() {
    Box::pin(i2233_a_revoked_holder_is_not_an_active_founder(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2233_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i2233_a_revoked_holder_is_not_an_active_founder(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2234_sqlite() {
    Box::pin(i2234_a_node_bearing_holder_is_not_a_founder(
        &sqlite_with_node().await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2234_postgres() {
    let Some(b) = postgres_with_node().await else {
        return;
    };
    Box::pin(i2234_a_node_bearing_holder_is_not_a_founder(&b)).await;
}
