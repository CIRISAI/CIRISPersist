//! The test ceremony and the pre-genesis boot (JSON-cut slice C,
//! CC 2.6.1.11, CC 4.2.2.1, CC 5.3.4).
//!
//! - **I2330**: the fixture's bundle/2 replays Valid through Verify's own
//!   reader under its anchor and the MOCK attestation root. The placement
//!   seats exactly the spec's holders and seats, each seat with the X-Wing
//!   keys of its binding; a seat is canonical and a holder is not.
//! - **I2331**: with no anchor, or an anchor of other keys, the same bundle
//!   roots nothing (`genesis_bundle_not_anchored`). With a root the reader
//!   does not trust, no holder is seated (`genesis_holder_custody`).
//! - **I2332**: a fixed `t0` gives the same bytes every time. The standard
//!   ceremony is asserted in the past, and its seat records stay live for
//!   most of a year from today: the fixture does not decay on a date.
//! - **I2333**: a later bundle counts a strict majority of its
//!   predecessor's holders (2 of 3 counts; 1 of 3 concludes nothing,
//!   `genesis_bundle_count_unmet`). A seat it drops is not canonical under
//!   it.
//! - **I2339**: `recover_v2` is a recovery Verify's reader counts on its one
//!   statement (the holder's committed recovery key, the key's record
//!   named): the holder keeps its identity, is re-seated on its new key and
//!   commits the next recovery key; the first commitment is spent; the other
//!   holders and the seats are unchanged. A later bundle over it counts the
//!   recovered holder under its new key. On the store, the recovery
//!   installs over the installed genesis and is the head.
//! - **I2340** (CC 4.2.6: a spent recovery commitment never returns): over
//!   a recovered lineage, a second recovery under the spent recovery key,
//!   a second recovery that commits the spent key again, and a roster
//!   bundle re-committing it each conclude nothing
//!   (`genesis_bundle_count_unmet`, `recovery_commitment_spent`). The
//!   controls, a second recovery under the committed key and a roster
//!   re-commit to a fresh key, are Valid. On the store, the import door
//!   refuses each and the recovery stays the head.
//! - **I2341** (CC 4.2.6: a recovery key is refused as a signing key, by
//!   its public key material): a recovery seating the recovery key itself
//!   as the holder's signing key is `genesis_bundle_malformed`
//!   (`recovery_key_is_signing_key`). On the store, the door refuses it,
//!   and a row signed by a recovery key's material under the holder's
//!   identity is refused finally (never the retryable unknown-signer wait),
//!   with no voice and no row held.
//! - **I2334**: a custody chain exists for every holder seed the fixture
//!   accepts, and a holder seed outside them is refused at minting.
//! - **I2335**: a fresh node boots pre-genesis: it holds no bundle and no
//!   seat is canonical (sqlite and postgres).
//! - **I2336**: `install_v2` puts the rows and the voices through the real
//!   doors; the bundle is then held and in force, its seats canonical and
//!   its holders not. A second install changes nothing.
//! - **I2337**: in lib unit tests every constructor but
//!   `with_signer_pre_genesis` boots holding `bundle_v2`.
//! - **I2338** (from disk): `engine.rs`'s production code seeds no earlier
//!   genesis, and installs the test ceremony only under `cfg(test)` or
//!   `test-anchor`.

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::edition2::genesis::{
    read_genesis_bundles, Anchor, GenesisInput, GenesisPlacement, GenesisVerdict, Inconclusive,
    Predecessor,
};
use ciris_verify_core::edition2::Digest32;
use ciris_verify_core::trust_anchor_store::TrustAnchorStore;

use super::fixture_genesis::*;
use super::fixture_genesis_custody::CHAIN_SEEDS;

/// A fixed records' instant: 2026-06-01T00:00:00Z.
const T: u64 = 1_780_272_000_000;

/// Read `c` alone with Verify's reader.
fn read(
    c: &TestCeremonyV2,
    anchor: Option<&Anchor>,
    predecessors: &[Predecessor<'_>],
    roots: &TrustAnchorStore,
) -> GenesisVerdict {
    let rows = c.rows();
    let reading = read_genesis_bundles(&GenesisInput {
        statements: &c.voices,
        rows: &rows,
        anchor,
        predecessors,
        attestation_roots: roots,
    });
    assert!(reading.refused.is_empty(), "{:?}", reading.refused);
    assert_eq!(reading.bundles.len(), 1, "one object");
    let b = &reading.bundles[0];
    assert_eq!(b.object_id, c.object_id, "the object id is the fixture's");
    assert!(b.refused.is_empty(), "{:?}", b.refused);
    b.verdict.clone()
}

fn valid(v: GenesisVerdict) -> GenesisPlacement {
    match v {
        GenesisVerdict::Valid(p) => *p,
        other => panic!("not Valid: {other:?}"),
    }
}

fn nothing(v: &GenesisVerdict) -> &Inconclusive {
    match v {
        GenesisVerdict::Nothing(i) => i,
        other => panic!("not Nothing: {other:?}"),
    }
}

#[test]
fn i2330_the_ceremony_replays_valid_through_verifys_reader() {
    let c = ceremony_v2(&CeremonySpec::at(T));
    let p = valid(read(&c, Some(&c.anchor()), &[], &attestation_roots()));
    assert_eq!(
        (p.version, p.prev, p.family_key_id.as_str()),
        (1, None, FAMILY_KEY_ID),
        "I2330"
    );
    let holders: BTreeSet<String> = p.holders.iter().map(|h| h.identity_ref.clone()).collect();
    assert_eq!(
        holders,
        c.holder_identity_refs()
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "I2330: the holders seated"
    );
    let seats: BTreeMap<String, _> = p
        .seats
        .iter()
        .map(|s| (s.identity_ref.clone(), s))
        .collect();
    assert_eq!(seats.len(), c.seats.len(), "I2330: the seats seated");
    for s in &c.seats {
        let placed = seats.get(&s.identity_ref).expect("I2330: seat placed");
        assert_eq!(placed.kid, s.kid, "I2330");
        assert_eq!(placed.record, s.record.row_id, "I2330: record");
        assert_eq!(placed.binding, s.binding.row_id, "I2330: binding");
        assert_eq!(
            (placed.transit_xwing_pubkey, placed.onion_hop_xwing_pubkey),
            (s.transit_xwing_pubkey, s.onion_hop_xwing_pubkey),
            "I2330: the binding's X-Wing keys"
        );
        assert!(
            p.is_canonical(&s.identity_ref),
            "I2330: a seat is canonical"
        );
    }
    for h in &c.holders {
        assert!(
            !p.is_canonical(&h.identity_ref),
            "I2330: a holder is not canonical"
        );
        assert_eq!(
            p.charter.recovery_commitments.get(&h.identity_ref),
            Some(&h.recovery_commitment),
            "I2330: the commitment"
        );
    }
}

#[test]
fn i2331_without_its_anchor_or_root_nothing_roots() {
    let c = ceremony_v2(&CeremonySpec::at(T));
    let roots = attestation_roots();
    for (what, anchor) in [
        ("no anchor", None),
        (
            "other keys",
            Some(Anchor::Thumbprints(
                [kid_of(4), kid_of(5), kid_of(6)].into(),
            )),
        ),
        ("another object", Some(Anchor::ObjectId([7u8; 32]))),
    ] {
        let v = read(&c, anchor.as_ref(), &[], &roots);
        assert_eq!(
            nothing(&v).token(),
            "genesis_bundle_not_anchored",
            "I2331 {what}"
        );
    }
    let v = read(&c, Some(&c.anchor()), &[], &TrustAnchorStore::new());
    assert_eq!(
        nothing(&v).token(),
        "genesis_holder_custody",
        "I2331: an untrusted root seats no holder"
    );
    // The pinned object id roots it too.
    let pinned = Anchor::ObjectId(c.object_id);
    valid(read(&c, Some(&pinned), &[], &roots));
}

#[test]
fn i2332_fixed_bytes_and_no_calendar_decay() {
    let (a, b) = (
        ceremony_v2(&CeremonySpec::at(T)),
        ceremony_v2(&CeremonySpec::at(T)),
    );
    assert_eq!((a.object_id, &a.voices), (b.object_id, &b.voices), "I2332");
    assert_eq!(a.rows(), b.rows(), "I2332");
    assert_ne!(
        ceremony_v2(&CeremonySpec::at(T + DAY_MS)).object_id,
        a.object_id,
        "I2332: t0 is in the bytes"
    );
    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
    let s = bundle_v2();
    assert!(s.asserted_at_ms <= now, "I2332: asserted in the past");
    assert!(
        s.spec.t0_ms + YEAR_MS > now + 300 * DAY_MS,
        "I2332: seat records live for most of a year from today"
    );
    assert_eq!(s.spec.holders, HOLDER_SEEDS.to_vec());
    assert_eq!(s.spec.serve_nodes, SERVE_NODE_SEEDS.to_vec());
    valid(read(s, Some(&s.anchor()), &[], &attestation_roots()));
}

#[test]
fn i2333_a_later_bundle_counts_a_strict_majority() {
    let first = ceremony_v2(&CeremonySpec::at(T));
    let roots = attestation_roots();
    let p1 = valid(read(&first, Some(&first.anchor()), &[], &roots));
    let pre = [Predecessor::Valid(&p1)];
    let dropped = SERVE_NODE_SEEDS[1];
    let two = later_v2(
        &first,
        &HOLDER_SEEDS,
        &SERVE_NODE_SEEDS[..1],
        &HOLDER_SEEDS[..2],
    );
    assert_eq!((two.version, two.prev), (2, Some(first.object_id)), "I2333");
    let p2 = valid(read(&two, None, &pre, &roots));
    assert!(
        p2.is_canonical(two.serve_node_identity_ref(0)),
        "I2333: a kept seat"
    );
    assert!(
        !p2.is_canonical(&identity_ref_of(dropped)),
        "I2333: a dropped seat is not canonical under the later bundle"
    );
    let one = later_v2(
        &first,
        &HOLDER_SEEDS,
        &SERVE_NODE_SEEDS[..1],
        &HOLDER_SEEDS[..1],
    );
    let v = read(&one, None, &pre, &roots);
    assert_eq!(
        nothing(&v).token(),
        "genesis_bundle_count_unmet",
        "I2333: one of three concludes nothing"
    );
}

#[test]
fn i2334_every_accepted_holder_seed_has_a_chain() {
    let accepted: Vec<u8> = HOLDER_SEED_RANGE.collect();
    assert_eq!(accepted, CHAIN_SEEDS.to_vec(), "I2334");
    let spec = CeremonySpec {
        holders: vec![1, 5, 7],
        serve_nodes: vec![20, 21, 22],
        ..CeremonySpec::at(T)
    };
    let c = ceremony_v2(&spec);
    valid(read(&c, Some(&c.anchor()), &[], &attestation_roots()));
    let refused = std::panic::catch_unwind(|| {
        ceremony_v2(&CeremonySpec {
            holders: vec![1, 2, 8],
            ..CeremonySpec::at(T)
        })
    });
    assert!(refused.is_err(), "I2334: seed 8 carries no chain");
}

#[test]
fn i2339_a_recovery_counts_on_its_one_statement() {
    let first = ceremony_v2(&CeremonySpec::at(T));
    let roots = attestation_roots();
    let p1 = valid(read(&first, Some(&first.anchor()), &[], &roots));
    let pre = [Predecessor::Valid(&p1)];
    let r = recover_v2(&first, HOLDER_SEEDS[0]);
    assert_eq!(r.voices.len(), 1, "I2339: one statement");
    assert_eq!(r.recovered.as_deref(), Some(first.holder_identity_ref(0)));
    let pr = valid(read(&r, None, &pre, &roots));
    assert_eq!(
        pr.recovered.as_deref(),
        Some(first.holder_identity_ref(0)),
        "I2339"
    );
    let placed = pr
        .holders
        .iter()
        .find(|h| h.identity_ref == first.holder_identity_ref(0))
        .expect("I2339: the holder keeps its identity");
    assert_eq!(
        placed.kid,
        kid_of(HOLDER_SEEDS[0] + RECOVERED_SEED_OFFSET),
        "I2339: re-seated on its new key"
    );
    assert_ne!(placed.kid, first.holders[0].kid, "I2339");
    assert_eq!(
        pr.charter
            .recovery_commitments
            .get(first.holder_identity_ref(0)),
        Some(&r.holders[0].recovery_commitment),
        "I2339: the next commitment"
    );
    assert_ne!(
        r.holders[0].recovery_commitment, first.holders[0].recovery_commitment,
        "I2339"
    );
    assert!(
        pr.spent_commitments
            .contains(&first.holders[0].recovery_commitment),
        "I2339: the first commitment is spent"
    );
    for (h0, h1) in first.holders.iter().zip(&r.holders).skip(1) {
        assert_eq!(
            (h0.kid, h0.recovery_commitment),
            (h1.kid, h1.recovery_commitment),
            "I2339"
        );
    }
    for sref in first.serve_node_identity_refs() {
        assert!(pr.is_canonical(&sref), "I2339: the seats are unchanged");
    }
    // The recovered holder speaks under its new key in the next bundle.
    let pre2 = [Predecessor::Valid(&pr)];
    let next = later_v2(&r, &HOLDER_SEEDS, &SERVE_NODE_SEEDS, &HOLDER_SEEDS[..2]);
    valid(read(&next, None, &pre2, &roots));
}

/// A verdict's token and detail.
fn outcome(v: &GenesisVerdict) -> (&'static str, Option<&'static str>) {
    match v {
        GenesisVerdict::Valid(_) => ("valid", None),
        GenesisVerdict::Invalid(m) => ("genesis_bundle_malformed", Some(m.reason())),
        GenesisVerdict::Waiting(_) => ("waiting", None),
        GenesisVerdict::Nothing(i) => (i.token(), i.detail()),
    }
}

const SPENT: (&str, Option<&str>) = (
    "genesis_bundle_count_unmet",
    Some("recovery_commitment_spent"),
);

#[test]
fn i2340_a_spent_recovery_commitment_never_returns() {
    let n = HOLDER_SEEDS[0];
    let first = ceremony_v2(&CeremonySpec::at(T));
    let roots = attestation_roots();
    let p1 = valid(read(&first, Some(&first.anchor()), &[], &roots));
    let r = recover_v2(&first, n);
    let pr = valid(read(&r, None, &[Predecessor::Valid(&p1)], &roots));
    let pre = [Predecessor::Valid(&pr)];
    let spent_key = n + RECOVERY_SEED_OFFSET;
    let cases = [
        (
            "a second recovery under the spent key",
            recover_v2_with(
                &r,
                n,
                spent_key,
                n + SECOND_RECOVERED_SEED_OFFSET,
                n + SECOND_NEXT_RECOVERY_SEED_OFFSET,
            ),
        ),
        (
            "a second recovery committing the spent key again",
            recover_v2_with(
                &r,
                n,
                n + NEXT_RECOVERY_SEED_OFFSET,
                n + SECOND_RECOVERED_SEED_OFFSET,
                spent_key,
            ),
        ),
        (
            "a roster bundle re-committing the spent key",
            recommit_v2(&r, n, spent_key, &HOLDER_SEEDS[..2]),
        ),
    ];
    for (what, b) in &cases {
        assert_eq!(
            outcome(&read(b, None, &pre, &roots)),
            SPENT,
            "I2340: {what}"
        );
    }
    // The controls: the same shapes under a key no commitment has spent.
    let second = recover_v2(&r, n);
    valid(read(&second, None, &pre, &roots));
    valid(read(
        &recommit_v2(&r, n, 91, &HOLDER_SEEDS[..2]),
        None,
        &pre,
        &roots,
    ));
}

#[test]
fn i2341_a_recovery_key_is_refused_as_a_signing_key() {
    let n = HOLDER_SEEDS[0];
    let first = ceremony_v2(&CeremonySpec::at(T));
    let roots = attestation_roots();
    let p1 = valid(read(&first, Some(&first.anchor()), &[], &roots));
    let pre = [Predecessor::Valid(&p1)];
    let rk = n + RECOVERY_SEED_OFFSET;
    let onto_rk = recover_v2_with(&first, n, rk, rk, n + NEXT_RECOVERY_SEED_OFFSET);
    assert_eq!(
        outcome(&read(&onto_rk, None, &pre, &roots)),
        (
            "genesis_bundle_malformed",
            Some("recovery_key_is_signing_key")
        ),
        "I2341"
    );
    // The control: the same recovery onto a key no commitment names.
    valid(read(&recover_v2(&first, n), None, &pre, &roots));
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
mod store {
    use std::sync::Arc;

    use ciris_verify_core::cde::Value;
    use ciris_verify_core::edition2::sign_row_statement;

    use super::super::genesis::{genesis_in_force, is_canonical_by_bundle, GENESIS_BUNDLE_TYP};
    use super::super::ingest::{put_statement, INGEST_TIER};
    use super::super::names::RowId;
    use super::*;
    use crate::federation::{malformed_row, Error, FederationDirectory};
    use crate::signing::LocalSigner;
    use crate::Engine;

    fn signer() -> Arc<LocalSigner> {
        Arc::new(LocalSigner::from_parts(
            ed25519_dalek::SigningKey::from_bytes(&[0x2c; 32]),
            "c2-boot-node".to_owned(),
            None,
            None,
        ))
    }

    /// The Valid bundles held (object id, version) and the count of held
    /// bundle voices.
    async fn held(d: &dyn FederationDirectory) -> (Vec<(Digest32, u32)>, usize) {
        let state = genesis_in_force(d).await.unwrap();
        let valid = state
            .valid
            .iter()
            .map(|p| (p.object_id, p.version))
            .collect();
        let voices = d.edition2_objects(GENESIS_BUNDLE_TYP).await.unwrap().len();
        (valid, voices)
    }

    fn reason(e: &Error) -> &'static str {
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => other.kind(),
        }
    }

    async fn head(d: &dyn FederationDirectory) -> Option<Digest32> {
        genesis_in_force(d).await.unwrap().head.map(|h| h.object_id)
    }

    /// I2340 and I2341 through the import door, on one backend.
    async fn recovery_body(dsn: &str) {
        let n = HOLDER_SEEDS[0];
        let s = bundle_v2();
        let node = Engine::with_signer_pre_genesis(signer(), dsn)
            .await
            .unwrap();
        let d = node.federation_directory();
        install_v2(d.as_ref()).await.unwrap();
        let r = recover_v2(s, n);
        install_ceremony_v2(d.as_ref(), &r).await.unwrap();
        assert_eq!(head(d.as_ref()).await, Some(r.object_id), "I2340");
        let spent_key = n + RECOVERY_SEED_OFFSET;
        for (what, b, want) in [
            (
                "I2340: a second recovery under the spent key",
                recover_v2_with(
                    &r,
                    n,
                    spent_key,
                    n + SECOND_RECOVERED_SEED_OFFSET,
                    n + SECOND_NEXT_RECOVERY_SEED_OFFSET,
                ),
                malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
            ),
            (
                "I2340: a roster bundle re-committing the spent key",
                recommit_v2(&r, n, spent_key, &HOLDER_SEEDS[..2]),
                malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
            ),
            (
                "I2341: a recovery seating the recovery key itself",
                recover_v2_with(
                    &r,
                    HOLDER_SEEDS[1],
                    HOLDER_SEEDS[1] + RECOVERY_SEED_OFFSET,
                    HOLDER_SEEDS[1] + RECOVERY_SEED_OFFSET,
                    HOLDER_SEEDS[1] + NEXT_RECOVERY_SEED_OFFSET,
                ),
                malformed_row::GENESIS_BUNDLE_MALFORMED,
            ),
        ] {
            let e = install_ceremony_v2(d.as_ref(), &b).await.expect_err(what);
            assert_eq!(reason(&e), want, "{what}: {e:?}");
            assert_eq!(
                head(d.as_ref()).await,
                Some(r.object_id),
                "{what}: the recovery stays the head"
            );
        }
        // I2341: the spent recovery key's record is held (the recovery named
        // it). A row signed by that key's material under the holder's
        // identity is not admitted, whichever refusal the door names.
        let iref = s.holder_identity_ref(0).to_owned();
        let at = r.asserted_at_ms + 1000;
        let payload = Value::Map(vec![
            (Value::Text("author".into()), Value::Text(iref.clone())),
            (Value::Text("asserted_at".into()), Value::Uint(at)),
        ]);
        let row = sign_row_statement(
            &test_key(spent_key),
            &iref,
            &iref,
            "scores",
            "key:revocation",
            &payload,
            vec![],
        )
        .unwrap();
        // A FINAL refusal (CC 4.2.6: refused by its public key material),
        // never the retryable wait for an unknown signer, nor a storage
        // fault: the key's record is held, so a wait would admit the row the
        // moment the door looked again. The token is not pinned.
        let e = put_statement(d.as_ref(), &row, None, INGEST_TIER)
            .await
            .expect_err("I2341: a row signed by a recovery key's material was admitted");
        assert!(
            !matches!(e, Error::AttesterKeyUnknown { .. } | Error::Backend(_)),
            "I2341: a recovery key's material must be refused finally, not waited on: {e:?}"
        );
        let id = RowId::of_statement(&row).expect("a row id");
        assert!(
            d.edition2_voices(&id).await.unwrap().is_empty(),
            "I2341: no voice of it is held"
        );
        assert!(
            d.get_attestation(&id.hex()).await.unwrap().is_none(),
            "I2341: no row of it is held"
        );
        // The control: a second recovery under the committed key installs.
        let second = recover_v2(&r, n);
        install_ceremony_v2(d.as_ref(), &second).await.unwrap();
        assert_eq!(head(d.as_ref()).await, Some(second.object_id), "I2340");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2340_i2341_sqlite() {
        Box::pin(recovery_body("sqlite::memory:")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2340_i2341_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        Box::pin(recovery_body(&dsn)).await;
    }

    /// I2335 and I2336 on one backend.
    async fn body(dsn: &str) {
        let s = bundle_v2();
        let fresh = Engine::with_signer_pre_genesis(signer(), dsn)
            .await
            .unwrap();
        let d = fresh.federation_directory();
        assert_eq!(
            held(d.as_ref()).await,
            (vec![], 0),
            "I2335: a fresh node holds no bundle"
        );
        for iref in s
            .serve_node_identity_refs()
            .iter()
            .chain(s.holder_identity_refs().iter())
        {
            assert!(
                !is_canonical_by_bundle(d.as_ref(), iref).await.unwrap(),
                "I2335: nothing is canonical before a bundle"
            );
        }
        let installed = install_v2_engine(&fresh).await.unwrap();
        assert_eq!(
            (installed.object_id, installed.version),
            (s.object_id, 1),
            "I2336"
        );
        let one = (vec![(s.object_id, 1u32)], s.voices.len());
        assert_eq!(
            held(d.as_ref()).await,
            one,
            "I2336: one bundle, every voice"
        );
        for iref in s.serve_node_identity_refs() {
            assert!(
                is_canonical_by_bundle(d.as_ref(), &iref).await.unwrap(),
                "I2336: a seat is canonical"
            );
        }
        for iref in s.holder_identity_refs() {
            assert!(
                !is_canonical_by_bundle(d.as_ref(), &iref).await.unwrap(),
                "I2336: a holder is not"
            );
        }
        install_v2_engine(&fresh)
            .await
            .expect("I2336: a second install is a no-op");
        assert_eq!(held(d.as_ref()).await, one, "I2336: unchanged");
        let r = recover_v2(s, HOLDER_SEEDS[0]);
        install_ceremony_v2(d.as_ref(), &r)
            .await
            .expect("I2339: the recovery installs over the genesis");
        let state = genesis_in_force(d.as_ref()).await.unwrap();
        assert_eq!(
            state.head.as_ref().map(|h| h.object_id),
            Some(r.object_id),
            "I2339: the recovery is the head"
        );
    }

    /// I2337 on one backend.
    async fn boots_holding(dsn: &str) {
        let s = bundle_v2();
        let booted = Engine::with_signer(signer(), dsn).await.unwrap();
        let d = booted.federation_directory();
        assert_eq!(
            held(d.as_ref()).await,
            (vec![(s.object_id, 1u32)], s.voices.len()),
            "I2337: a lib-test Engine boots holding bundle_v2"
        );
        assert!(
            is_canonical_by_bundle(d.as_ref(), s.serve_node_identity_ref(0))
                .await
                .unwrap(),
            "I2337"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2335_i2336_sqlite() {
        Box::pin(body("sqlite::memory:")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2337_sqlite() {
        Box::pin(boots_holding("sqlite::memory:")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2335_i2336_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        Box::pin(body(&dsn)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2337_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            return;
        };
        Box::pin(boots_holding(&dsn)).await;
    }
}

/// `engine.rs` up to its test module, with `//` comment lines removed.
fn engine_production_code() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine.rs");
    let s = std::fs::read_to_string(path).unwrap();
    let end = s
        .find("\n#[cfg(test)]\nmod tests {")
        .expect("engine.rs has its test module");
    s[..end]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn i2338_engine_boot_seeds_no_earlier_genesis() {
    let code = engine_production_code();
    for name in [
        "seed_genesis_accord_holders",
        "seed_family_and_canonical",
        "effective_accord_holder_records",
        "canonical_genesis_bundle",
        "classify_genesis_seed",
        "seed_genesis",
    ] {
        assert!(
            !code.contains(name),
            "I2338: engine.rs production code names `{name}`"
        );
    }
    // The test ceremony is reached only from the two test-gated fns.
    assert_eq!(
        code.matches("fixture_genesis::install_v2_engine(").count(),
        2,
        "I2338"
    );
    let lines: Vec<&str> = code.lines().map(str::trim).collect();
    let hooks: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains(".install_test_genesis_at_boot().await;"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hooks.len(), 3, "I2338: the three seeding constructors");
    for i in hooks {
        assert_eq!(lines[i - 1], "#[cfg(test)]", "I2338: the hook is cfg(test)");
    }
    let pre = code
        .find("pub async fn with_signer_pre_genesis(")
        .expect("the pre-genesis constructor");
    let body_end = code[pre..]
        .find("\n    }\n")
        .map(|e| pre + e)
        .expect("its body");
    assert!(
        !code[pre..body_end].contains("install_test_genesis_at_boot"),
        "I2338: the pre-genesis constructor never installs"
    );
}
