//! **I3037–I3039, I3042–I3043** (wave O1; E8's findings; CC 3.3.6, CC 3.3.6.2): an
//! occurrence's route and X-Wing keys, on sqlite and postgres.
//!
//! - I3037 (expiry): an occurrence past its `valid_until` keeps no live
//!   route. Its bind projects none at write, and a projection of it held
//!   anyway (as one written before this fix) is not listed by
//!   `list_transport_destinations_for` (the half-open window, read). A bind
//!   with no end keeps its route (the control).
//! - I3038 (a non-seat node): its transit and onion hop X-Wing keys resolve
//!   from its held edition-2 bind (`transit_xwing_pubkey_for`,
//!   `occurrence::onion_hop_xwing_pubkey_for`).
//! - I3042 (displacement): an expired route displaces nothing: with two
//!   node keys tied to one owner on one destination, the expired newer
//!   projection leaves the older live route listed.
//! - I3043 (the self roster): an occurrence past its `valid_until` is not a
//!   roster key (`self_roster::roster_now`), so a further device lands on the
//!   owner's one voice.
//! - I3039 (a seat): a seat's own later bind carrying another transit key
//!   is held but not resolved: the seat's keys are the genesis bundle's
//!   (W1's rule), and the bind resolver gives nothing for a seat.
//!
//! **I2110–I2113** (SR-fix1; CC 3.3.6.2): a seat's dial address after a
//! genesis import, on sqlite and postgres. CIRISEdge dials a seat from
//! `list_transport_destinations_for(<the seat's identity reference>)`.
//!
//! - I2110 (reads back): after the import, every seat of the bundle in force
//!   has exactly one live route, at its own identity reference, whose
//!   destination is the lowercase hex of the `destination_hash` its named
//!   binding states.
//! - I2111 (re-offer restores): with a seat's route row gone (the projection
//!   runs after the bundle's commit, so a failure or a crash there leaves the
//!   bundle held and no route), offering the same bundle again projects it.
//! - I2112 (no regress): a re-offer does not replace a newer route held at
//!   the seat's key.
//! - I2113 (the occurrence door): the same holds for a bind landed through
//!   the statement door: its route row gone, the same statement put again
//!   projects it.
//! - I2109 (the binding first): a seat's key record and binding put alone
//!   through the statement door before the bundle, then the bundle
//!   imported: the seat's occurrence row is held and its route is projected,
//!   as for every other seat (whatever the statement door answered alone).
//! - I2118 (a re-keyed seat): a seat rotated to a new signing key by a
//!   `key:record` chain (the predecessor's voice, then the new key's, through
//!   the statement door). Its binding signed by the NEW key, put alone, is
//!   refused `occurrence_voice_not_own_key` and nothing is kept: no
//!   statement, no fold hold, the seat's occurrence row and route unchanged.
//!   So a seat binding is never held back, and the import's skip of a stored
//!   named row is a skip of a landed one. The later bundle that seats the
//!   new key is then imported: it is in force with the seat at the new key,
//!   the seat's occurrence row is the new binding's, and its one live route
//!   is the new binding's destination.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{iref, key, key_record, map};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::occurrence::{bind_xwing_keys_for, onion_hop_xwing_pubkey_for, OCCURRENCE_FAMILY};
use crate::federation::self_at_login::{transit_xwing_pubkey_for, XWingPublicKey};
use crate::federation::FederationDirectory;

const APP: &str = "ciris.federation";
const ASPECT: &str = "serve";

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
}

/// A `transport_destination` member (CC 3.3.6.2) for Reticulum keys
/// `[x; 32]`, `[e; 32]`, its `destination_hash` derived (CC 3.3.6.3).
fn transport(x: u8, e: u8) -> Value {
    let (rx, re) = (vec![x; 32], vec![e; 32]);
    let dh = ciris_verify_core::transport_binding::compute_destination_hash(
        APP,
        &[ASPECT.to_owned()],
        &rx,
        &re,
    )
    .unwrap();
    map(vec![
        ("reticulum_x25519_pubkey", Value::Bytes(rx)),
        ("reticulum_ed25519_pubkey", Value::Bytes(re)),
        ("app_name", Value::Text(APP.into())),
        ("aspects", Value::Array(vec![Value::Text(ASPECT.into())])),
        ("destination_hash", Value::Bytes(dh.to_vec())),
    ])
}

/// One statement over a bind payload carrying `extra` members.
#[allow(clippy::too_many_arguments)]
async fn bind_with(
    d: &dyn FederationDirectory,
    signer: &CompositeSigningKey,
    iss: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    asserted_at: u64,
    valid_until: Option<u64>,
    extra: Vec<(&str, Value)>,
) -> Vec<u8> {
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(identity.to_owned())),
        ("identity_key_id", Value::Text(identity.to_owned())),
        ("occurrence_key_id", Value::Text(occurrence.to_owned())),
        ("device_class", Value::Text(device_class.to_owned())),
    ];
    if let Some(u) = valid_until {
        m.push(("valid_until", Value::Uint(u)));
    }
    // CC 3.3.6.4: the roster row the bind stands on.
    let head = super::occurrence::current_roster_head(d, identity)
        .await
        .unwrap()
        .expect("the identity's key record is held");
    m.push((
        "refs",
        map(vec![(
            "head",
            ciris_verify_core::edition2::row_ref(&head.0),
        )]),
    ));
    m.extend(extra);
    sign_row_statement(
        signer,
        iss,
        occurrence,
        "scores",
        OCCURRENCE_FAMILY,
        &map(m),
        vec![],
    )
    .unwrap()
}

async fn put(d: &dyn FederationDirectory, st: &[u8]) -> StatementOutcome {
    Box::pin(put_statement(d, st, None, INGEST_TIER))
        .await
        .unwrap()
}

/// Bind `device` under `owner` (both user keys): its own voice, then the
/// owner's.
async fn bind_device(
    d: &dyn FederationDirectory,
    owner: &CompositeSigningKey,
    device: &CompositeSigningKey,
    asserted_at: u64,
    valid_until: Option<u64>,
    extra: Vec<(&str, Value)>,
) {
    let (u, k) = (iref(owner), iref(device));
    put(
        d,
        &bind_with(
            d,
            device,
            &k,
            &u,
            &k,
            "laptop",
            asserted_at,
            valid_until,
            extra.clone(),
        )
        .await,
    )
    .await;
    let out = put(
        d,
        &bind_with(
            d,
            owner,
            &u,
            &u,
            &k,
            "laptop",
            asserted_at,
            valid_until,
            extra,
        )
        .await,
    )
    .await;
    assert!(
        matches!(out, StatementOutcome::Row { .. }),
        "the bind lands: {out:?}"
    );
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let owner = key(110);
    let expired = key(111);
    let lasting = key(112);
    let node = key(113);
    // A second owner: under the first, the expired bind still counts on the
    // self roster (`roster_now` reads revocations, not ends), so a further
    // device there would be a roster change needing two voices.
    let owner2 = key(114);
    let third = key(115);
    for k in [&owner, &owner2, &expired, &lasting, &third] {
        put(d, &key_record(k, &["user"], 0, None)).await;
    }
    let t = now_ms();
    // A node key live now (a node record states an end).
    put(
        d,
        &key_record(&node, &["node"], t - 86_400_000, Some(t + 200 * 86_400_000)),
    )
    .await;

    // I3037: a bind whose window has ended.
    bind_device(
        d,
        &owner,
        &expired,
        15_000,
        Some(16_000),
        vec![("transport_destination", transport(1, 2))],
    )
    .await;
    let k = iref(&expired);
    assert!(
        d.list_transport_destinations_for(&k)
            .await
            .unwrap()
            .is_empty(),
        "I3037: an expired bind projects no route"
    );
    // A projection of it held anyway (written before the fix): not live.
    let occ = d
        .list_identity_occurrences_by_occurrence_key(&k)
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("I3037: the bind is held");
    let stale = occ
        .transport_binding
        .as_ref()
        .expect("I3037: its transport binding")
        .project_route(&k, occ.asserted_at)
        .unwrap();
    d.put_transport_destination(&stale).await.unwrap();
    assert!(
        d.list_transport_destinations_for(&k)
            .await
            .unwrap()
            .is_empty(),
        "I3037: a projection of an expired occurrence is not listed"
    );

    // I3043: the expired occurrence is not on `owner`'s self roster, so a
    // further device lands on the owner's one voice (with it counted, the
    // roster would be two keys and the add would wait on a second).
    let roster = crate::federation::self_roster::roster_now(d, &iref(&owner))
        .await
        .unwrap();
    assert!(
        !roster.contains(&k),
        "I3043: an occurrence past its valid_until is not a roster key: {roster:?}"
    );
    bind_device(d, &owner, &third, 17_000, None, Vec::new()).await;
    // The control: no end, a live route.
    bind_device(
        d,
        &owner2,
        &lasting,
        15_000,
        None,
        vec![("transport_destination", transport(3, 4))],
    )
    .await;
    assert_eq!(
        d.list_transport_destinations_for(&iref(&lasting))
            .await
            .unwrap()
            .len(),
        1,
        "I3037: a bind with no end keeps its route"
    );

    // I3038: a non-seat node's X-Wing keys from its bind (the self pair).
    let n = iref(&node);
    let (transit, hop) = (vec![5u8; 1216], vec![6u8; 1216]);
    let st = bind_with(
        d,
        &node,
        &n,
        &n,
        &n,
        "server",
        t - 3_600_000,
        None,
        vec![
            ("transport_destination", transport(7, 8)),
            ("transit_xwing_pubkey", Value::Bytes(transit.clone())),
            ("onion_hop_xwing_pubkey", Value::Bytes(hop.clone())),
        ],
    )
    .await;
    assert!(
        matches!(put(d, &st).await, StatementOutcome::Row { .. }),
        "I3038: the node's own bind lands"
    );
    assert_eq!(
        transit_xwing_pubkey_for(d, &n).await.unwrap(),
        XWingPublicKey::from_bytes(&transit),
        "I3038: the transit key resolves from the bind"
    );
    assert_eq!(
        onion_hop_xwing_pubkey_for(d, &n).await.unwrap(),
        XWingPublicKey::from_bytes(&hop),
        "I3038: the onion hop key resolves from the bind"
    );
}

/// I3042 on one backend: an expired route displaces nothing. Two node keys
/// with one live owner (the I1122-B setup) share a destination; the newer
/// route is the projection of an occurrence already past its end. The older
/// live route stays listed, and the expired one is not.
async fn displacement_body(d: &dyn FederationDirectory) {
    use crate::federation::self_at_login::{BindingProvenance, TransportDestination};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{IdentityOccurrence, OccurrenceTransportBinding};
    use base64::Engine as _;
    let tag = format!("o1d{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let (owner, old_node, new_node) = (
        format!("{tag}-owner"),
        format!("{tag}-oldnode"),
        format!("{tag}-newnode"),
    );
    ts::register_identity_key(d, &owner, USER).await;
    for k in [&old_node, &new_node] {
        ts::register_identity_key(d, k, NODE).await;
    }
    ts::put_owner_binding(d, &owner, &old_node).await;
    ts::put_owner_binding(d, &owner, &new_node).await;
    // v62 (O1 fix 11): an edition-2 key, its owner binding, its occurrence
    // and its route are all named by its kid (E0's `put_key`), not its seed.
    let kid = super::fixture_switch::kid;
    let (old_node, new_node) = (kid(&old_node), kid(&new_node));
    // The tie that lets a newer route displace (the control: without it the
    // witness could not tell).
    let (a, b) = (
        crate::federation::admission::owner_of(d, &old_node)
            .await
            .unwrap(),
        crate::federation::admission::owner_of(d, &new_node)
            .await
            .unwrap(),
    );
    assert!(
        a.is_some() && a == b,
        "I3042: the two node keys share one owner"
    );
    let raw = [0xab_u8; 16];
    let dest = hex::encode(raw);
    let older = TransportDestination {
        occurrence_key_id: old_node.clone(),
        transport_kind: "reticulum".into(),
        destination: dest.clone(),
        asserted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(10_000).unwrap(),
        last_seen_at: None,
        transport_ed25519_pubkey_base64: None,
        transport_x25519_pubkey_base64: None,
        binding_provenance: BindingProvenance::Rooted,
        epoch: 0,
        retired_at: None,
    };
    d.put_transport_destination(&older).await.unwrap();
    // The newer key's occurrence, ended at 21 000 ms; its projection held.
    let b64 = base64::engine::general_purpose::STANDARD;
    let occ = IdentityOccurrence {
        identity_key_id: new_node.clone(),
        occurrence_key_id: new_node.clone(),
        device_class: "server".into(),
        hardware_attestation: None,
        asserted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(20_000).unwrap(),
        valid_until: Some(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(21_000).unwrap()),
        encryption_pubkeys: None,
        transport_binding: Some(OccurrenceTransportBinding {
            reticulum_x25519_pubkey_base64: b64.encode([1u8; 32]),
            reticulum_ed25519_pubkey_base64: b64.encode([2u8; 32]),
            destination_hash_base64: b64.encode(raw),
            app_name: APP.into(),
            aspects: vec![ASPECT.into()],
        }),
        persist_row_hash: String::new(),
    };
    d.test_seam_put_identity_occurrence(occ.clone())
        .await
        .unwrap();
    let stale = occ
        .transport_binding
        .as_ref()
        .unwrap()
        .project_route(&new_node, occ.asserted_at)
        .unwrap();
    d.put_transport_destination(&stale).await.unwrap();
    let listed: Vec<String> = d
        .list_transport_destinations_by_destination(&dest)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.occurrence_key_id)
        .collect();
    assert_eq!(
        listed,
        vec![old_node.clone()],
        "I3042: the older live route stays; the expired one displaces nothing and is not listed"
    );
    assert_eq!(
        d.list_transport_destinations_for(&old_node)
            .await
            .unwrap()
            .len(),
        1,
        "I3042: the older key keeps its route"
    );
}

/// I3039 on one backend: a seat's solo bind is held, never resolved.
async fn seat_body(d: &dyn FederationDirectory) {
    use super::fixture_genesis::{bundle_v2, install_v2, test_key};
    install_v2(d).await.unwrap();
    let seat = &bundle_v2().seats[0];
    let k = test_key(seat.seed);
    let s = seat.identity_ref.clone();
    let solo = vec![9u8; 1216];
    let st = bind_with(
        d,
        &k,
        &s,
        &s,
        &s,
        "server",
        now_ms() - 60_000,
        None,
        vec![
            ("transport_destination", transport(10, 11)),
            ("transit_xwing_pubkey", Value::Bytes(solo.clone())),
            ("onion_hop_xwing_pubkey", Value::Bytes(vec![12u8; 1216])),
        ],
    )
    .await;
    assert!(
        matches!(put(d, &st).await, StatementOutcome::Row { .. }),
        "I3039: the seat's own bind is held"
    );
    assert_ne!(
        transit_xwing_pubkey_for(d, &s).await.unwrap(),
        XWingPublicKey::from_bytes(&solo),
        "I3039: a seat's solo transit key is not live"
    );
    assert_eq!(
        bind_xwing_keys_for(d, &s).await.unwrap(),
        None,
        "I3039: the bind resolver reads nothing for a seat"
    );
    assert_eq!(
        onion_hop_xwing_pubkey_for(d, &s).await.unwrap(),
        XWingPublicKey::from_bytes(&seat.onion_hop_xwing_pubkey),
        "I3039: a seat's hop key is its bundle binding's"
    );
}

/// The `destination_hash` a binding statement states in its
/// `transport_destination`, read from the statement's own bytes.
fn stated_destination_hash(statement: &[u8]) -> Vec<u8> {
    let Value::Tag(18, inner) = ciris_verify_core::cde::decode(statement).unwrap() else {
        panic!("a row statement is a COSE_Sign1");
    };
    let parts = inner.as_array().expect("a COSE_Sign1 is an array");
    let payload =
        ciris_verify_core::cde::decode(parts[2].as_bytes().expect("its payload is bytes")).unwrap();
    payload
        .get_text("transport_destination")
        .and_then(|td| td.get_text("destination_hash"))
        .and_then(Value::as_bytes)
        .expect("the binding states a destination hash")
        .to_vec()
}

/// I2110–I2112 on one backend: a seat's dial address after a genesis import
/// (the fixture's dates are the bundle's own window).
async fn seat_route_body(d: &dyn FederationDirectory) {
    use super::fixture_genesis::{bundle_v2, install_v2};
    use super::genesis::{genesis_in_force, put_genesis_bundle};
    use crate::federation::self_at_login::TransportDestination;
    use crate::federation::types::OccurrenceTransportBinding;
    install_v2(d).await.unwrap();
    let c = bundle_v2();
    // Each seat of the bundle in force, with the destination its named
    // binding states.
    let in_force = genesis_in_force(d).await.unwrap();
    let seats: Vec<(String, String)> = in_force
        .seats()
        .iter()
        .map(|placed| {
            let minted = c
                .seats
                .iter()
                .find(|s| s.binding.row_id == placed.binding)
                .expect("I2110: the placed seat's binding is the fixture's");
            (
                placed.identity_ref.clone(),
                hex::encode(stated_destination_hash(&minted.binding.statement)),
            )
        })
        .collect();
    assert_eq!(
        seats.len(),
        c.seats.len(),
        "I2110: every minted seat is a seat of the bundle in force"
    );
    assert!(!seats.is_empty(), "I2110: the bundle seats a serve node");

    // I2110: one live route per seat, at its identity reference, to the
    // destination its binding states.
    let mut projected: Vec<TransportDestination> = Vec::new();
    for (seat, destination) in &seats {
        let routes = d.list_transport_destinations_for(seat).await.unwrap();
        assert_eq!(
            routes.len(),
            1,
            "I2110: a seat has exactly one live route after the import: {routes:?}"
        );
        let r = &routes[0];
        assert_eq!(&r.occurrence_key_id, seat, "I2110: at the seat's key");
        assert_eq!(
            r.transport_kind,
            OccurrenceTransportBinding::TRANSPORT_KIND,
            "I2110: a Reticulum route"
        );
        assert_eq!(
            &r.destination, destination,
            "I2110: the destination is the hex of the binding's destination_hash"
        );
        assert!(r.retired_at.is_none(), "I2110: the route is live");
        projected.push(r.clone());
    }

    let mut statements: Vec<Vec<u8>> = c
        .rows_in_put_order()
        .into_iter()
        .map(|r| r.statement.clone())
        .collect();
    statements.extend(c.voices.iter().cloned());
    let anchor = c.anchor();

    // I2111: every seat's route row gone (the missed projection), then the
    // same bundle offered again.
    for (seat, destination) in &seats {
        assert!(
            d.remove_transport_destination(
                seat,
                OccurrenceTransportBinding::TRANSPORT_KIND,
                destination
            )
            .await
            .unwrap(),
            "I2111: the route row is removed"
        );
        assert!(
            d.list_transport_destinations_for(seat)
                .await
                .unwrap()
                .is_empty(),
            "I2111: the control: no route is held"
        );
    }
    Box::pin(put_genesis_bundle(d, &statements, Some(&anchor)))
        .await
        .expect("I2111: the held bundle offered again is not refused");
    for ((seat, _), was) in seats.iter().zip(&projected) {
        assert_eq!(
            d.list_transport_destinations_for(seat).await.unwrap(),
            vec![was.clone()],
            "I2111: the re-offer projects the missing route again"
        );
    }

    // I2112: a newer route at the first seat's key (one second after the
    // binding's own instant) is not replaced by a further re-offer.
    let (seat, _) = &seats[0];
    let newer = TransportDestination {
        destination: hex::encode([0xcd_u8; 16]),
        asserted_at: projected[0].asserted_at + chrono::Duration::seconds(1),
        ..projected[0].clone()
    };
    d.put_transport_destination(&newer).await.unwrap();
    assert_eq!(
        d.list_transport_destinations_for(seat).await.unwrap(),
        vec![newer.clone()],
        "I2112: the control: the newer route is the seat's route"
    );
    Box::pin(put_genesis_bundle(d, &statements, Some(&anchor)))
        .await
        .expect("I2112: the held bundle offered again is not refused");
    assert_eq!(
        d.list_transport_destinations_for(seat).await.unwrap(),
        vec![newer],
        "I2112: a re-offer does not replace a newer route"
    );
    for ((other, _), was) in seats.iter().zip(&projected).skip(1) {
        assert_eq!(
            d.list_transport_destinations_for(other).await.unwrap(),
            vec![was.clone()],
            "I2112: the other seats keep their routes"
        );
    }
}

/// I2113 on one backend: a node's own bind landed through the statement
/// door; its route row gone, the same statement put again projects it. The
/// dates are the standard ceremony's window (`t0`: the record's start; the
/// bind half a day later, in the past).
async fn reput_route_body(d: &dyn FederationDirectory) {
    use super::fixture_genesis::{CeremonySpec, DAY_MS, YEAR_MS};
    use crate::federation::types::OccurrenceTransportBinding;
    let t0 = CeremonySpec::standard().t0_ms;
    let node = key(116);
    let n = iref(&node);
    put(d, &key_record(&node, &["node"], t0, Some(t0 + YEAR_MS))).await;
    let st = bind_with(
        d,
        &node,
        &n,
        &n,
        &n,
        "server",
        t0 + DAY_MS / 2,
        None,
        vec![
            ("transport_destination", transport(13, 14)),
            ("transit_xwing_pubkey", Value::Bytes(vec![15u8; 1216])),
            ("onion_hop_xwing_pubkey", Value::Bytes(vec![16u8; 1216])),
        ],
    )
    .await;
    assert!(
        matches!(put(d, &st).await, StatementOutcome::Row { .. }),
        "I2113: the node's own bind lands"
    );
    let before = d.list_transport_destinations_for(&n).await.unwrap();
    assert_eq!(
        before.len(),
        1,
        "I2113: the bind projects one route: {before:?}"
    );
    assert!(
        d.remove_transport_destination(
            &n,
            OccurrenceTransportBinding::TRANSPORT_KIND,
            &before[0].destination
        )
        .await
        .unwrap(),
        "I2113: the route row is removed"
    );
    assert!(
        d.list_transport_destinations_for(&n)
            .await
            .unwrap()
            .is_empty(),
        "I2113: the control: no route is held"
    );
    assert!(
        matches!(put(d, &st).await, StatementOutcome::Row { .. }),
        "I2113: the same statement put again is the landed row"
    );
    assert_eq!(
        d.list_transport_destinations_for(&n).await.unwrap(),
        before,
        "I2113: the re-put projects the missing route again"
    );
}

/// Every seat of `c`: an occurrence row at its identity reference carrying
/// a transport binding, and exactly one live route to the destination its
/// binding states.
async fn assert_seats_reachable(
    d: &dyn FederationDirectory,
    c: &super::fixture_genesis::TestCeremonyV2,
    tag: &str,
) {
    for seat in &c.seats {
        let id = &seat.identity_ref;
        let held = d
            .list_identity_occurrences_by_occurrence_key(id)
            .await
            .unwrap();
        assert!(
            held.iter()
                .any(|o| &o.identity_key_id == id && o.transport_binding.is_some()),
            "{tag}: the seat's occurrence row is held with its transport binding: {held:?}"
        );
        let routes = d.list_transport_destinations_for(id).await.unwrap();
        assert_eq!(
            routes.len(),
            1,
            "{tag}: the seat has exactly one live route: {routes:?}"
        );
        assert_eq!(
            routes[0].destination,
            hex::encode(stated_destination_hash(&seat.binding.statement)),
            "{tag}: the destination is the hex of the binding's destination_hash"
        );
    }
}

/// I2109 on one backend: the first seat's key record and binding arrive
/// alone, ahead of the bundle. What the statement door answers alone is
/// printed, not asserted: the invariant is the state after the import.
async fn binding_first_body(d: &dyn FederationDirectory) {
    use super::fixture_genesis::{bundle_v2, install_v2};
    let c = bundle_v2();
    let seat = &c.seats[0];
    let record = Box::pin(put_statement(d, &seat.record.statement, None, INGEST_TIER)).await;
    let binding = Box::pin(put_statement(d, &seat.binding.statement, None, INGEST_TIER)).await;
    eprintln!("I2109: alone, the record: {record:?}; the binding: {binding:?}");
    install_v2(d).await.unwrap();
    assert_seats_reachable(d, c, "I2109").await;
}

/// I2118 on one backend: a re-keyed seat's binding alone, then its bundle.
/// The dates are the bundles' own (the rotation and the new binding one
/// second before the later bundle).
async fn rekeyed_seat_body(d: &dyn FederationDirectory) {
    use super::fixture_genesis::{
        bundle_v2, install_ceremony_v2, install_v2, kid_of, rekey_seat_v2, HOLDER_SEEDS,
    };
    use super::genesis::genesis_in_force;
    use super::names::RowId;
    use crate::federation::{malformed_row, Error};
    /// A key seed no fixture party uses.
    const NEW_KEY_SEED: u8 = 21;
    install_v2(d).await.unwrap();
    let c1 = bundle_v2();
    let old = &c1.seats[0];
    let seat = &old.identity_ref;
    let (c2, by_predecessor) = rekey_seat_v2(c1, old.seed, NEW_KEY_SEED, &HOLDER_SEEDS[..2]);
    let new = &c2.seats[0];
    let old_destination = hex::encode(stated_destination_hash(&old.binding.statement));
    let new_destination = hex::encode(stated_destination_hash(&new.binding.statement));
    assert_ne!(
        old_destination, new_destination,
        "I2118: the control: the new binding states another destination"
    );
    let occurrences_before = d
        .list_identity_occurrences_by_occurrence_key(seat)
        .await
        .unwrap();
    let routes_before = d.list_transport_destinations_for(seat).await.unwrap();
    assert_eq!(
        routes_before.len(),
        1,
        "I2118: the control: the seat's first route is held"
    );

    // The rotation, through the statement door: the predecessor's voice,
    // then the new key's (the new key's alone waits on the predecessor's).
    Box::pin(put_statement(d, &by_predecessor, None, INGEST_TIER))
        .await
        .expect("I2118: the predecessor's voice over the rotation record");
    Box::pin(put_statement(d, &new.record.statement, None, INGEST_TIER))
        .await
        .expect("I2118: the new key's voice: the rotation stands");

    // The new key's binding, alone: refused by name, nothing kept.
    let refusal = Box::pin(put_statement(d, &new.binding.statement, None, INGEST_TIER))
        .await
        .expect_err("I2118: a re-keyed seat's binding alone is refused");
    assert!(
        matches!(
            &refusal,
            Error::MalformedRow { reason, .. }
                if *reason == malformed_row::OCCURRENCE_VOICE_NOT_OWN_KEY
        ),
        "I2118: refused `occurrence_voice_not_own_key`: {refusal:?}"
    );
    let binding_row = RowId(new.binding.row_id);
    assert!(
        d.edition2_voices(&binding_row).await.unwrap().is_empty(),
        "I2118: no statement of the refused binding is kept"
    );
    assert!(
        d.fold_held(&binding_row).await.unwrap().is_none(),
        "I2118: the refused binding is not held back"
    );
    assert_eq!(
        d.list_identity_occurrences_by_occurrence_key(seat)
            .await
            .unwrap(),
        occurrences_before,
        "I2118: the seat's occurrence row is unchanged"
    );
    assert_eq!(
        d.list_transport_destinations_for(seat).await.unwrap(),
        routes_before,
        "I2118: the seat's route is unchanged"
    );

    // The later bundle that seats the new key.
    install_ceremony_v2(d, &c2)
        .await
        .expect("I2118: the bundle that re-seats the seat at its new key is placed");
    let in_force = genesis_in_force(d).await.unwrap();
    assert_eq!(
        in_force.seat(seat).map(|s| s.kid),
        Some(kid_of(NEW_KEY_SEED)),
        "I2118: the bundle in force seats the new key for the seat"
    );
    let landed = d
        .list_identity_occurrences_by_occurrence_key(seat)
        .await
        .unwrap();
    assert_ne!(
        landed, occurrences_before,
        "I2118: the import wrote the new binding's occurrence row"
    );
    let routes = d.list_transport_destinations_for(seat).await.unwrap();
    assert_eq!(
        routes.len(),
        1,
        "I2118: the re-keyed seat has exactly one live route: {routes:?}"
    );
    assert_eq!(
        routes[0].destination, new_destination,
        "I2118: the route is the new binding's destination"
    );
    // The other seat keeps its route.
    for other in c2.seats.iter().skip(1) {
        assert_eq!(
            d.list_transport_destinations_for(&other.identity_ref)
                .await
                .unwrap()
                .len(),
            1,
            "I2118: the other seats keep their routes"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2118_rekeyed_seat_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(rekeyed_seat_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2118_rekeyed_seat_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(rekeyed_seat_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2109_binding_before_bundle_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(binding_first_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2109_binding_before_bundle_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(binding_first_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2110_to_i2113_seat_route_sqlite() {
    use crate::store::Backend as _;
    for which in 0..2 {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        match which {
            0 => Box::pin(seat_route_body(&b)).await,
            _ => Box::pin(reput_route_body(&b)).await,
        }
    }
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2110_to_i2113_seat_route_postgres() {
    use crate::store::Backend as _;
    for which in 0..2 {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        match which {
            0 => Box::pin(seat_route_body(&b)).await,
            _ => Box::pin(reput_route_body(&b)).await,
        }
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3037_to_i3039_sqlite() {
    use crate::store::Backend as _;
    for which in 0..3 {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        match which {
            0 => Box::pin(body(&b)).await,
            1 => Box::pin(displacement_body(&b)).await,
            _ => Box::pin(seat_body(&b)).await,
        }
    }
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3037_to_i3039_postgres() {
    use crate::store::Backend as _;
    for which in 0..3 {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        match which {
            0 => Box::pin(body(&b)).await,
            1 => Box::pin(displacement_body(&b)).await,
            _ => Box::pin(seat_body(&b)).await,
        }
    }
}
