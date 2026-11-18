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
    d.put_identity_occurrence_local(occ.clone()).await.unwrap();
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
