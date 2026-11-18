//! v61.4.0 — I1800–I1802, **one emission, one fold: the key-grant burst is
//! linear in rows, and judges every row exactly as the per-row gate does.**
//!
//! A minter seating a 50-member x 3-device room emitted its 150 epoch-axis
//! rows in 14.9 s (sqlite) / 52.8 s (postgres): every row re-folded the
//! roster and listed every member's occurrences, in the planner and again in
//! the admission gate. v61.4.0 judges the rows of ONE emission against ONE
//! fold ([`EmissionFold`](crate::federation::key_grant::EmissionFold): the
//! sealer rule at the emission's one signed instant, the audience read once)
//! and shares the roster READS across the emission's gates
//! ([`with_roster_read_memo`](crate::federation::with_roster_read_memo)), each
//! gate still folding at its own instant. These witnesses hold the new path
//! to the old one, over a room with a removed member, a keyless member and a
//! device-revoked occurrence:
//!
//! - **I1800** (sqlite, postgres) — the GATE: for every candidate row (each
//!   wrap holder, the removed member's device, the revoked device, the
//!   keyless member's occurrence, a stranger, and a non-minter's row), the
//!   verdict inside the emission fold's scope is the per-row verdict outside
//!   it, refusal reason included, and the fold (not the per-row path) gave
//!   it for every row of the emission's own signer and instant; a row of
//!   another signer or another instant is never answered by the fold.
//! - **I1801** (sqlite, postgres) — the EMISSION: the folded emission emits
//!   to exactly the wraps the per-row audience rule admits and withholds the
//!   rest, every row at one signed instant, and a re-emission emits nothing
//!   (every emitted recipient `already_emitted`).
//! - **I1802** (sqlite, postgres) — the ROSTER READ MEMO: inside one memo
//!   scope the roster folded at an instant before a removal still seats the
//!   removed member and one after does not, exactly as unmemoized.

//!
//! v62.0.0 (E3b) — the room is edition 2: keys are `kid(seed)`, the roster
//! is ONE `group:roster` version (T1 voices), the removal is
//! `membership:removal` voices, and the MINTER node is alice's by the OWNER
//! RELATION (CC rc21 way (d): a node key is never bound under a person,
//! `occurrence_binds_machine_to_person`): her owner binding (her statement
//! plus the node's voice) and the node's OWN self-occurrence `(node, node)`
//! carrying its class and content-KEM keys (O1 `put_bind`; P5c: the owner
//! gives WHO, the self-occurrence WHAT KIND). The person devices stay on the
//! trusted-local occurrence door (user keys), keyed by kids. Every device
//! seed LEADS with its distinguishing part (`d0-{bob}`): a test signer seeds
//! from a key id's first 32 bytes.

#![cfg(test)]

use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::ingest::StatementOutcome;
use crate::federation::key_grant::{
    check_key_grant_row_admission, emit_key_grant_axis_with_local_signer, recipient_may_hold_key,
    EmissionFold, KeyGrantAxis, KeyGrantRow,
};
use crate::federation::key_grant_invariants::two_node::{
    community_removal_voices, encryption_member, node, node_as, owner_binding_voices,
    sign_row_unstored_at, Node,
};
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::identity_type::{NODE, USER};
use crate::federation::types::{CommunityMember, IdentityOccurrence, IdentityOccurrenceRevocation};
use crate::federation::{BlobStorage, Error, FederationDirectory, GrantWrap};

/// The verdict as a comparable token: `ok`, or the typed refusal's reason.
fn verdict(r: &Result<(), Error>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(Error::KeyGrantRefused { reason, .. }) => (*reason).to_owned(),
        Err(Error::SignerDoesNotActFor { .. }) => "signer_not_acting_for".into(),
        Err(e) => format!("other: {e}"),
    }
}

/// A PERSON's device (both user keys): `occ`'s key live, and the
/// trusted-local occurrence `(kid(ident), kid(occ))`, keyed with the node's
/// content-KEM pubkeys when `keyed`. Both arguments are seeds.
pub(crate) async fn occurrence<B>(n: &Node<'_, B>, ident: &str, occ: &str, keyed: bool)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    ts::register_hybrid_key_as(n.backend, occ, occ, USER).await;
    n.backend
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: e2::kid(ident),
            occurrence_key_id: e2::kid(occ),
            device_class: crate::federation::types::device_class::LAPTOP.into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: keyed.then(|| n.kem.clone()),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("occurrence {occ} of {ident}: {e}"));
}

/// v62.0.0 (E3b) — **the minter node is `owner`'s**, by the owner relation:
/// `owner`'s owner binding for the node (her `delegates_to` statement,
/// re-dated a minute back so the node-typed key's own record covers it,
/// then the node's own voice: `owner_of` requires it), and the node's OWN
/// self-occurrence (author = identity = occurrence = the node; one
/// statement), `server` class, carrying the node's content-KEM keys so a
/// fan-out can wrap to it. `node_seed` is the alias `n` was brought up from
/// (`node_as(.., NODE)`); `owner` is a seed.
pub(crate) async fn own_node<B>(n: &Node<'_, B>, node_seed: &str, owner: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    assert_eq!(
        e2::kid(node_seed),
        n.key,
        "fixture: the node's key is its alias's identity-ref"
    );
    let bound_at = chrono::Utc::now() - chrono::Duration::minutes(1);
    for v in owner_binding_voices(owner, node_seed, bound_at) {
        e2::put_statement(n.backend, &v)
            .await
            .unwrap_or_else(|e| panic!("{owner}'s owner binding for {node_seed}: {e}"));
    }
    let opts = e2::BindOptions {
        extra: vec![encryption_member(&n.kem)],
        ..e2::BindOptions::default()
    };
    match e2::put_bind(
        n.backend,
        node_seed,
        node_seed,
        node_seed,
        crate::federation::types::device_class::SERVER,
        &opts,
    )
    .await
    {
        Ok(StatementOutcome::Row { .. }) => {}
        other => panic!("{node_seed}'s own self-occurrence: {other:?}"),
    }
}

/// v62.0.0 (E3b) — **found the community `comm`** (a seed, its key live) as
/// ONE `group:roster` version (T1): the authority's statement and every
/// listed member's voice, founded at `founded_at` (user keys only, so a
/// past instant is the author's to state). `members` are seeds; the stored
/// roster names their kids.
pub(crate) async fn found_room<B>(
    n: &Node<'_, B>,
    comm: &str,
    name: &str,
    members: &[&str],
    founded_at: chrono::DateTime<chrono::Utc>,
) where
    B: BlobStorage + FederationDirectory + Sync,
{
    let founded_at = crate::federation::admission::truncate_to_substrate_resolution(founded_at);
    let signed = ts::sign_community(
        comm,
        crate::federation::types::Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: comm.to_owned(),
            community_name: name.to_owned(),
            members: members
                .iter()
                .map(|k| CommunityMember {
                    key_id: (*k).to_owned(),
                    joined_at: founded_at,
                    role: None,
                })
                .collect(),
            founded_at,
            consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY.to_owned(),
            policy_blob: None,
            persist_row_hash: String::new(),
        },
    );
    match e2::put_voices(
        n.backend,
        &e2::community_voices(&signed, 1, None, e2::ms(founded_at)),
    )
    .await
    {
        Ok(StatementOutcome::Row { .. }) => {}
        other => panic!("found {comm}: {other:?}"),
    }
}

/// v62.0.0 (E3b) — **`who` leaves `comm`**, effective `at`: the
/// `membership:removal` voices naming the held head, `who`'s own among
/// `signers` (seeds; enough of the roster to meet the majority outright).
/// Asserts the removal landed.
pub(crate) async fn leave<B>(
    n: &Node<'_, B>,
    comm: &str,
    who: &str,
    at: chrono::DateTime<chrono::Utc>,
    signers: &[&str],
) where
    B: BlobStorage + FederationDirectory + Sync,
{
    let voices = community_removal_voices(n.backend, comm, who, at, at, signers).await;
    match e2::put_voices(n.backend, &voices).await {
        Ok(StatementOutcome::Row { .. }) => {}
        other => panic!("{who} leaves {comm}: {other:?}"),
    }
}

/// The fixture room, sealed once (so every keyed occurrence holds a wrap),
/// THEN a member removed and a device revoked: the wraps stay, the audience
/// moves. Every id is a kid.
pub(crate) struct Room {
    pub comm: String,
    pub axis: KeyGrantAxis,
    /// Live member devices (each holds a wrap and stays in the audience).
    pub live: Vec<String>,
    /// The removed member's device (holds a wrap, left the audience).
    pub removed_dev: String,
    /// The revoked device of a live member (holds a wrap, left the audience).
    pub revoked_dev: String,
    /// The keyless member's occurrence (no wrap: excluded fail-secure).
    pub keyless_occ: String,
    /// The removed member's identity.
    pub removed: String,
    /// When the removal took effect.
    pub removed_at: chrono::DateTime<chrono::Utc>,
}

/// The fold room on the minter `n` (brought up from `node_seed` as a NODE).
pub(crate) async fn seed_room<B>(n: &Node<'_, B>, node_seed: &str, tag: &str) -> Room
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let run = uuid::Uuid::new_v4().simple().to_string();
    let comm = format!("{tag}-comm-{run}");
    let alice = format!("{tag}-alice-{run}"); // the minter's owner
    let bob = format!("{tag}-bob-{run}");
    let eve = format!("{tag}-eve-{run}"); // a device revoked
    let rex = format!("{tag}-rex-{run}"); // removed
    let kay = format!("{tag}-kay-{run}"); // keyless
    ts::register_hybrid_key_as(n.backend, &comm, &comm, USER).await;
    for m in [&alice, &bob, &eve, &rex, &kay] {
        ts::register_hybrid_key_as(n.backend, m, m, USER).await;
    }
    let (b0, b1) = (format!("d0-{bob}"), format!("d1-{bob}"));
    let (e0, e1) = (format!("d0-{eve}"), format!("d1-{eve}"));
    let r0 = format!("d0-{rex}");
    let k0 = format!("d0-{kay}");
    own_node(n, node_seed, &alice).await;
    for (m, o) in [
        (&bob, &b0),
        (&bob, &b1),
        (&eve, &e0),
        (&eve, &e1),
        (&rex, &r0),
    ] {
        occurrence(n, m, o, true).await;
    }
    occurrence(n, &kay, &k0, false).await;
    found_room(
        n,
        &comm,
        "fold room",
        &[&alice, &bob, &eve, &rex, &kay],
        chrono::Utc::now() - chrono::Duration::hours(1),
    )
    .await;
    let comm_id = e2::kid(&comm);
    let sealed = encrypt_and_cascade_community(n.backend, &comm_id, b"x", None, Some(&n.key))
        .await
        .unwrap();
    let (b0, b1, e0, e1, r0, k0) = (
        e2::kid(&b0),
        e2::kid(&b1),
        e2::kid(&e0),
        e2::kid(&e1),
        e2::kid(&r0),
        e2::kid(&k0),
    );
    for o in [&n.key, &b0, &b1, &e0, &e1, &r0] {
        assert!(
            sealed.granted.contains(o),
            "{tag}: {o} wrapped: {:?}",
            sealed.granted
        );
    }
    assert!(
        !sealed.granted.contains(&k0),
        "{tag}: the keyless occurrence is excluded fail-secure"
    );
    // Now the audience moves under the wraps: rex leaves (his own voice and
    // three more members', a majority of five outright), eve revokes d1.
    let removed_at = crate::federation::admission::truncate_to_substrate_resolution(
        chrono::Utc::now() - chrono::Duration::seconds(2),
    );
    leave(n, &comm, &rex, removed_at, &[&rex, &alice, &bob, &eve]).await;
    n.backend
        .put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: e2::kid(&eve),
            occurrence_key_id: e1.clone(),
            // After the occurrence was asserted (a revocation older than the
            // occurrence it names is re-established past), in effect now.
            revoked_at: chrono::Utc::now(),
            effective_at: chrono::Utc::now(),
            reason: None,
            witness_set: vec![e2::kid(&eve)],
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("{tag}: eve revokes d1: {e}"));
    Room {
        axis: KeyGrantAxis::Epoch {
            community_key_id: comm_id.clone(),
            minter_key_id: n.key.clone(),
            epoch: sealed.epoch,
        },
        comm: comm_id,
        live: vec![n.key.clone(), b0, b1, e0],
        removed_dev: r0,
        revoked_dev: e1,
        keyless_occ: k0,
        removed: e2::kid(&rex),
        removed_at,
    }
}

/// The minter node of a fold witness: `{tag}-minter`, a NODE key (an owner
/// binding targets only a node, #851).
async fn minter<'a, B>(backend: &'a B, tag: &str) -> (Node<'a, B>, String)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let alias = format!("{tag}-minter");
    (node_as(backend, &alias, NODE).await, alias)
}

fn row_to(axis: &KeyGrantAxis, recipient: &str) -> KeyGrantRow {
    KeyGrantRow {
        axis: axis.clone(),
        wrap: GrantWrap {
            recipient_key_id: recipient.to_owned(),
            wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.to_owned(),
            wrapped_dek: "d3JhcA".to_owned(),
        },
    }
}

/// I1800 — the gate, folded vs per row.
pub(crate) async fn i1800_the_fold_judges_as_the_gate<B>(backend: &B, tag: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let (n, alias) = minter(backend, tag).await;
    let room = seed_room(&n, &alias, tag).await;
    let stranger_seed = format!("{tag}-stranger-{}", uuid::Uuid::new_v4().simple());
    ts::register_hybrid_key_as(backend, &stranger_seed, &stranger_seed, USER).await;
    let stranger = e2::kid(&stranger_seed);
    let mut candidates: Vec<String> = room.live.clone();
    candidates.extend([
        room.removed_dev.clone(),
        room.revoked_dev.clone(),
        room.keyless_occ.clone(),
        stranger.clone(),
    ]);
    let names: Vec<&str> = candidates.iter().map(String::as_str).collect();
    let at = crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
    let fold = std::sync::Arc::new(
        EmissionFold::for_witness(backend, &n.key, &room.axis, at, &names)
            .await
            .unwrap_or_else(|e| panic!("{tag} I1800: the minter is the sealer: {e}")),
    );
    // The minter's rows at the fold's instant: the fold answers each.
    let mut rows = Vec::new();
    for r in &candidates {
        rows.push(sign_row_unstored_at(&n.signer, &row_to(&room.axis, r), at).await);
    }
    // A row the fold must NOT answer: another signer's (the per-row path
    // refuses it `signer_not_minter`; the fold, asked, would admit it).
    let other = node(backend, &format!("{tag}-other")).await;
    let foreign = sign_row_unstored_at(&other.signer, &row_to(&room.axis, &room.live[1]), at).await;
    let dir = backend.as_dyn_directory();
    let mut expect = Vec::new();
    for r in rows.iter().chain([&foreign]) {
        expect.push(verdict(
            &check_key_grant_row_admission(dir, &r.attestation).await,
        ));
    }
    // The per-row oracle is the rule itself: the live devices admit, every
    // device that left (or never joined) the audience is refused by it.
    let want: Vec<&str> = vec![
        "ok",
        "ok",
        "ok",
        "ok",
        "recipient_not_in_audience",
        "recipient_not_in_audience",
        "ok", // keyless: the audience rule reads no keys; the wrap fan-out does
        "recipient_not_in_audience",
        "signer_not_minter",
    ];
    assert_eq!(expect, want, "{tag} I1800: the per-row oracle");
    let got = Box::pin(fold.clone().scope(async {
        let mut got = Vec::new();
        for r in rows.iter().chain([&foreign]) {
            got.push(verdict(
                &check_key_grant_row_admission(dir, &r.attestation).await,
            ));
        }
        got
    }))
    .await;
    assert_eq!(
        got, expect,
        "{tag} I1800: inside the emission fold every row gets the per-row verdict"
    );
    assert_eq!(
        fold.served(),
        rows.len(),
        "{tag} I1800: the fold answered every row of its own signer and instant, and not \
         the foreign signer's"
    );
    // The instant guard, against a fold that (wrongly) admits the stranger:
    // the minter's row at the fold's instant IS answered by it (the control:
    // the fold's answer is the one returned), the same row at another instant
    // is not.
    let mut corrupt = EmissionFold::for_witness(backend, &n.key, &room.axis, at, &names)
        .await
        .unwrap();
    corrupt.judged_mut().insert(stranger.clone(), true);
    let corrupt = std::sync::Arc::new(corrupt);
    let at_fold = sign_row_unstored_at(&n.signer, &row_to(&room.axis, &stranger), at).await;
    let elsewhen = sign_row_unstored_at(
        &n.signer,
        &row_to(&room.axis, &stranger),
        at + chrono::Duration::milliseconds(7),
    )
    .await;
    let (control, guarded) = Box::pin(corrupt.clone().scope(async {
        (
            verdict(&check_key_grant_row_admission(dir, &at_fold.attestation).await),
            verdict(&check_key_grant_row_admission(dir, &elsewhen.attestation).await),
        )
    }))
    .await;
    assert_eq!(
        control, "ok",
        "{tag} I1800 control: a row of the fold's signer and instant takes the fold's answer"
    );
    assert_eq!(
        guarded, "recipient_not_in_audience",
        "{tag} I1800: a row at another instant is judged per row, never by the fold"
    );
    assert_eq!(
        corrupt.served(),
        1,
        "{tag} I1800: the fold answered only the control"
    );
}

/// I1801 — the folded emission vs the per-row audience rule.
pub(crate) async fn i1801_the_emission_admits_what_the_rule_admits<B>(backend: &B, tag: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let (n, alias) = minter(backend, tag).await;
    let room = seed_room(&n, &alias, tag).await;
    let set = crate::federation::key_grant::build_set_for_axis(backend, &room.axis)
        .await
        .unwrap()
        .expect("wraps held");
    let mut want_emit = std::collections::BTreeSet::new();
    let mut want_withheld = std::collections::BTreeSet::new();
    for w in &set.wraps {
        if recipient_may_hold_key(backend, "community", &room.comm, &w.recipient_key_id)
            .await
            .unwrap()
        {
            want_emit.insert(w.recipient_key_id.clone());
        } else {
            want_withheld.insert(w.recipient_key_id.clone());
        }
    }
    assert_eq!(
        want_emit,
        room.live.iter().cloned().collect(),
        "{tag} I1801: the per-row rule admits the live devices"
    );
    assert_eq!(
        want_withheld,
        [room.removed_dev.clone(), room.revoked_dev.clone()]
            .into_iter()
            .collect(),
        "{tag} I1801: and withholds the removed member's and the revoked device"
    );
    let out = emit_key_grant_axis_with_local_signer(backend, &n.signer, &room.axis)
        .await
        .unwrap()
        .expect("emission");
    let mut emitted = std::collections::BTreeSet::new();
    let mut instants = std::collections::BTreeSet::new();
    for id in &out.attestation_ids {
        let a = backend.get_attestation(id).await.unwrap().expect("stored");
        emitted.insert(a.attested_key_id.clone());
        instants.insert(a.asserted_at);
    }
    assert_eq!(
        emitted, want_emit,
        "{tag} I1801: emitted exactly the admitted"
    );
    assert_eq!(
        out.withheld
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        want_withheld,
        "{tag} I1801: withheld exactly the refused"
    );
    assert_eq!(
        instants.len(),
        1,
        "{tag} I1801: one emission, one signed instant"
    );
    let again = emit_key_grant_axis_with_local_signer(backend, &n.signer, &room.axis)
        .await
        .unwrap()
        .expect("re-emission");
    assert!(
        again.attestation_ids.is_empty(),
        "{tag} I1801: idempotent: {again:?}"
    );
    assert_eq!(
        again
            .already_emitted
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        want_emit,
        "{tag} I1801: every emitted recipient is already_emitted on the second pass"
    );
}

/// I1802 — the roster read memo folds at each call's own instant.
pub(crate) async fn i1802_the_memo_keeps_each_instant<B>(backend: &B, tag: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let (n, alias) = minter(backend, tag).await;
    let room = seed_room(&n, &alias, tag).await;
    let c = backend
        .lookup_community(&room.comm)
        .await
        .unwrap()
        .expect("held");
    let before = room.removed_at - chrono::Duration::seconds(1);
    let after = chrono::Utc::now();
    let seated = |v: &Vec<CommunityMember>| v.iter().any(|m| m.key_id == room.removed);
    let plain = (
        crate::federation::authorized_community_roster_at(backend, &c, before)
            .await
            .unwrap(),
        crate::federation::authorized_community_roster_at(backend, &c, after)
            .await
            .unwrap(),
    );
    assert!(
        seated(&plain.0) && !seated(&plain.1),
        "{tag} I1802: the oracle"
    );
    for order in [[before, after], [after, before]] {
        let memo = crate::federation::with_roster_read_memo(async {
            let mut out = Vec::new();
            for t in order {
                out.push(
                    crate::federation::authorized_community_roster_at(backend, &c, t)
                        .await
                        .unwrap(),
                );
            }
            out
        })
        .await;
        let (b, a) = if order[0] == before {
            (&memo[0], &memo[1])
        } else {
            (&memo[1], &memo[0])
        };
        assert_eq!(
            (b, a),
            (&plain.0, &plain.1),
            "{tag} I1802: one memo, two instants, the unmemoized rosters (order {order:?})"
        );
    }
}

macro_rules! runners {
    ($m:ident, $fresh:expr) => {
        mod $m {
            fn suffix() -> String {
                uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
            }
            #[tokio::test]
            async fn i1800() {
                let Some(b) = $fresh.await else { return };
                super::i1800_the_fold_judges_as_the_gate(&b, &format!("i1800-{}", suffix())).await
            }
            #[tokio::test]
            async fn i1801() {
                let Some(b) = $fresh.await else { return };
                super::i1801_the_emission_admits_what_the_rule_admits(
                    &b,
                    &format!("i1801-{}", suffix()),
                )
                .await
            }
            #[tokio::test]
            async fn i1802() {
                let Some(b) = $fresh.await else { return };
                super::i1802_the_memo_keeps_each_instant(&b, &format!("i1802-{}", suffix())).await
            }
        }
    };
}

#[cfg(feature = "sqlite")]
runners!(sqlite, async {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
});

#[cfg(feature = "postgres")]
runners!(postgres, async {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return None;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
});
