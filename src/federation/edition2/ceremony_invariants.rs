//! v62.0.0 (CE-fix1) — **the offline ceremony builders** (`crate::ceremony`)
//! witnessed. A fixed-seed composite key ([`test_key`]) stands in for each
//! hardware signer: it signs each draft's `sig_structure`, and the assembled
//! statement goes through the reading production uses.
//!
//! - I2280 (pure): the builders reproduce the test ceremony
//!   (`fixture_genesis::ceremony_v2`, whose key records and bindings are
//!   minted independently through Verify's `sign_row_statement`) BYTE FOR
//!   BYTE: every holder's and seat's `key:record`, every seat binding, the
//!   bundle payload, its object id and every holder's voice.
//! - I2281 (pure): the offline set passes [`c::check_genesis_offer`] (the
//!   import door's reading on a fresh node) under the thumbprint anchor and
//!   under the object-id anchor; the placement seats every seat with the
//!   X-Wing keys its binding states.
//! - I2282 (pure): the offer check refuses what the door refuses: a holder's
//!   voice missing (`genesis_bundle_count_unmet`), another anchor
//!   (`genesis_bundle_not_anchored`), a binding that cites no record; and
//!   the seat-binding builder refuses a binding without both X-Wing keys.
//! - I2283 (pure): each step's own self-check: [`c::check_key_record`] reads
//!   back each record (kid, identity set, end, custody chain);
//!   [`c::check_seat_binding`] returns the binding's two X-Wing keys and
//!   refuses one citing no record (`binding_names_no_record`).
//! - I2284 (pure): the pre-signed halt: [`c::check_halt`] reads each
//!   holder's sealed halt Valid under the bundle's placement; a seat's
//!   "halt" waits (its key is no holder's); a holder's key under another
//!   holder's `iss` is `iss_not_holder`; a window covering no instant is
//!   refused.
//! - I2285 (pure): the manifest preimages are the signing-domain framing
//!   (84 bytes for the accord manifest); a holder's composite verifies under
//!   its key in hand, and not under another size, key or domain.
//! - I2286 (pure): the `key:record` end rule the Engine and the ceremony
//!   share ([`key_record_end`]).
//! - I2287 (sqlite + postgres): the offline-built set imports through
//!   `put_genesis_bundle`; `genesis_in_force` lists the seats with their
//!   transit keys; `list_transport_destinations_for(seat)` returns each
//!   seat's Reticulum route; a sealed halt offered before the genesis waits
//!   and is not latched, and after it latches through the statement door.
//! - I2288 (sqlite): the ceremony's final gate,
//!   [`c::import_offer_into_throwaway`]: the same offline set (with one
//!   sealed halt) through the real doors of a throwaway in-memory node reads
//!   back every holder, every seat with its X-Wing keys and its Reticulum
//!   route, and the latched halt. The mock custody root is installed through
//!   the test seam `edition2::genesis::add_test_attestation_root` (cfg(test)
//!   / test-anchor only; a production build judges against Verify's baked
//!   roots). One voice short, the gate refuses (`genesis_bundle_count_unmet`).
//! - I2289 (pure; CE-fix2): CEREMONY step 3 before step 4.
//!   [`c::check_offer_with_halts`] passes with exactly one sealed halt per
//!   listed holder, and the coverage names each holder's halt.
//! - I2305 (pure): one holder's halt missing refuses
//!   (`ceremony_halt_missing`) naming THAT holder; a second halt for one
//!   holder refuses (`ceremony_halt_duplicate`); a drill in place of a halt
//!   is `ceremony_halt_invalid` and leaves the holder missing.
//! - I2306 (pure): a halt signed for a DIFFERENT bundle (another ceremony's
//!   holders) refuses (`ceremony_halt_not_a_holder`), even when every listed
//!   holder's halt is present.
//! - I2307 (sqlite): the final gate reports the coverage, never requires it:
//!   with no halt the throwaway import still places the bundle and reports
//!   every holder missing; with all halts it is complete; another bundle's
//!   halt is reported and not offered to the statement door.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::recovery::recovery_commitment;
use ciris_verify_core::edition2::Digest32;

use super::emit::key_record_end;
use super::fixture_genesis::{
    ceremony_v2, mock_attestation_root_der, recovery_key, test_key, CeremonySpec, TestCeremonyV2,
    DAY_MS, FAMILY_KEY_ID, YEAR_MS,
};
use super::fixture_genesis_custody::HOLDER_CHAINS_HEX;
use super::genesis::add_test_attestation_root;
use super::liveness::statement_parts;
use crate::ceremony::{self as c, Anchor, BindTransport, BundleTerms, CustodyEvidence, Draft};
use crate::federation::{malformed_row, Error};

/// A fixed instant (deterministic bytes): 2026-09-21T13:46:40Z.
const T0: u64 = 1_790_000_000_000;

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

/// The hardware stand-in: one composite signature over the draft.
fn sign(k: &CompositeSigningKey, d: &Draft) -> Vec<u8> {
    d.assemble(k.sign(&d.sig_structure).expect("a fixed-seed key signs"))
}

fn holder_chain(seed: u8) -> Vec<Vec<u8>> {
    HOLDER_CHAINS_HEX
        .iter()
        .find(|(n, _)| *n == seed)
        .map(|(_, chain)| {
            chain
                .iter()
                .map(|h| hex::decode(h).expect("a chain is hex"))
                .collect()
        })
        .expect("a custody chain for the holder seed")
}

/// The transport a fixture binding states (its Reticulum keys, app, aspects
/// and X-Wing keys), as the ceremony's seat would supply it.
fn transport_of(binding: &[u8]) -> BindTransport {
    let (_, p) = statement_parts(binding).expect("a binding statement");
    let td = p.get_text("transport_destination").expect("a destination");
    let bytes = |v: &Value, m: &str| -> Vec<u8> {
        v.get_text(m)
            .and_then(Value::as_bytes)
            .unwrap_or_else(|| panic!("{m} is bytes"))
            .to_vec()
    };
    BindTransport {
        reticulum_x25519_pubkey: bytes(td, "reticulum_x25519_pubkey"),
        reticulum_ed25519_pubkey: bytes(td, "reticulum_ed25519_pubkey"),
        app_name: td
            .get_text("app_name")
            .and_then(Value::as_text)
            .expect("app_name")
            .to_owned(),
        aspects: td
            .get_text("aspects")
            .and_then(Value::as_array)
            .expect("aspects")
            .iter()
            .map(|a| a.as_text().expect("an aspect is text").to_owned())
            .collect(),
        transit_xwing_pubkey: Some(bytes(&p, "transit_xwing_pubkey")),
        onion_hop_xwing_pubkey: Some(bytes(&p, "onion_hop_xwing_pubkey")),
    }
}

/// One seat, built offline.
struct Seat {
    key: CompositeSigningKey,
    record: Vec<u8>,
    record_id: Digest32,
    binding: Vec<u8>,
    transport: BindTransport,
}

/// The ceremony, built offline by the production builders over the
/// fixture's parties (seeds, instants, transports).
struct Offline {
    holders: Vec<(CompositeSigningKey, Vec<u8>)>,
    seats: Vec<Seat>,
    terms: BundleTerms,
    voices: Vec<Vec<u8>>,
    halts: Vec<Vec<u8>>,
}

impl Offline {
    fn statements(&self) -> Vec<Vec<u8>> {
        self.holders
            .iter()
            .map(|(_, r)| r.clone())
            .chain(self.seats.iter().map(|s| s.record.clone()))
            .chain(self.seats.iter().map(|s| s.binding.clone()))
            .chain(self.voices.iter().cloned())
            .collect()
    }

    fn anchor(&self) -> Anchor {
        let keys: Vec<&c::CompositePublicKey> =
            self.holders.iter().map(|(k, _)| k.public_key()).collect();
        c::thumbprint_anchor(&keys)
    }
}

fn offline(fx: &TestCeremonyV2) -> Offline {
    let t0 = fx.spec.t0_ms;
    // Step 1: each holder's record.
    let holders: Vec<(CompositeSigningKey, Vec<u8>)> = fx
        .spec
        .holders
        .iter()
        .map(|s| {
            let k = test_key(*s);
            let ev = CustodyEvidence::yubikey_5_fips(holder_chain(*s));
            let d = c::holder_key_record_draft(k.public_key(), t0, &ev).expect("a holder record");
            let st = sign(&k, &d);
            (k, st)
        })
        .collect();
    // Step 2: each seat's record and binding.
    let seats: Vec<Seat> = fx
        .spec
        .serve_nodes
        .iter()
        .zip(&fx.seats)
        .map(|(s, fs)| {
            let key = test_key(*s);
            let d = c::seat_key_record_draft(key.public_key(), t0, None).expect("a seat record");
            let record_id = c::row_id_of(&d).expect("a record draft has a row id");
            let record = sign(&key, &d);
            let transport = transport_of(&fs.binding.statement);
            let b = c::seat_binding_draft(key.public_key(), &record_id, t0, transport.clone())
                .expect("a seat binding");
            let binding = sign(&key, &b);
            Seat {
                key,
                record,
                record_id,
                binding,
                transport,
            }
        })
        .collect();
    // Step 4: the bundle and its voices.
    let id = |st: &[u8]| {
        super::names::RowId::of_statement(st)
            .expect("a row statement")
            .0
    };
    let terms = BundleTerms {
        version: 1,
        prev: None,
        asserted_at_ms: t0 + DAY_MS / 2,
        family_key_id: FAMILY_KEY_ID.to_owned(),
        holders: holders
            .iter()
            .map(|(k, _)| c::identity_ref_of(k.public_key()))
            .collect(),
        serve_nodes: seats
            .iter()
            .map(|s| c::identity_ref_of(s.key.public_key()))
            .collect(),
        cites: holders
            .iter()
            .map(|(_, r)| id(r))
            .chain(seats.iter().map(|s| s.record_id))
            .chain(seats.iter().map(|s| id(&s.binding)))
            .collect(),
        recovery_commitments: fx
            .spec
            .holders
            .iter()
            .map(|s| {
                (
                    c::identity_ref_of(test_key(*s).public_key()),
                    recovery_commitment(&[recovery_key(*s).public_key().clone()]),
                )
            })
            .collect(),
        scope: vec!["infra:attest".to_owned(), "infra:serve".to_owned()],
        halt_fuse_secs: Some(86_400),
    };
    let voices = holders
        .iter()
        .map(|(k, _)| sign(k, &c::bundle_voice_draft(k.public_key(), &terms)))
        .collect();
    // Step 3: each holder's sealed halt, signed after its record.
    let halts = holders
        .iter()
        .enumerate()
        .map(|(i, (k, _))| {
            let n = u8::try_from(i).expect("few holders");
            let d = c::halt_draft(
                k.public_key(),
                FAMILY_KEY_ID,
                &format!("ce-fix1-halt-{i}"),
                [0x40 + n; 32],
                t0 + 1_000,
                t0 + 30 * DAY_MS,
            )
            .expect("a halt");
            sign(k, &d)
        })
        .collect();
    Offline {
        holders,
        seats,
        terms,
        voices,
        halts,
    }
}

fn fixed() -> (TestCeremonyV2, Offline) {
    let fx = ceremony_v2(&CeremonySpec::at(T0));
    let off = offline(&fx);
    (fx, off)
}

/// The instant the pure checks run at: after every statement of [`fixed`].
const CHECK_AT: u64 = T0 + 2 * DAY_MS;

/// **I2280** — the production builders reproduce the test ceremony byte for
/// byte.
#[test]
fn i2280_builders_reproduce_the_test_ceremony() {
    let (fx, off) = fixed();
    for (i, (_, r)) in off.holders.iter().enumerate() {
        assert_eq!(
            r, &fx.holders[i].record.statement,
            "I2280: holder {i}'s key:record is the test ceremony's"
        );
    }
    for (i, s) in off.seats.iter().enumerate() {
        assert_eq!(
            s.record, fx.seats[i].record.statement,
            "I2280: seat {i}'s key:record is the test ceremony's"
        );
        assert_eq!(
            s.record_id, fx.seats[i].record.row_id,
            "I2280: the draft's row id is the signed record's"
        );
        assert_eq!(
            s.binding, fx.seats[i].binding.statement,
            "I2280: seat {i}'s binding is the test ceremony's"
        );
    }
    assert_eq!(
        c::bundle_payload(&off.terms),
        fx.payload,
        "I2280: the bundle payload"
    );
    assert_eq!(
        c::bundle_object_id(&off.terms),
        fx.object_id,
        "I2280: the bundle's object id"
    );
    assert_eq!(off.voices, fx.voices, "I2280: every holder's voice");
}

/// **I2281** — the offline set passes the import door's reading on a fresh
/// node, under either anchor.
#[test]
fn i2281_the_offline_set_passes_the_offer_check() {
    add_test_attestation_root(mock_attestation_root_der());
    let (_, off) = fixed();
    let oid = c::bundle_object_id(&off.terms);
    for anchor in [off.anchor(), Anchor::ObjectId(oid)] {
        let placed = c::check_genesis_offer(&off.statements(), &anchor, CHECK_AT)
            .expect("I2281: the offline genesis is placed");
        assert_eq!(placed.len(), 1, "I2281: one bundle");
        let p = &placed[0];
        assert_eq!(p.object_id, oid, "I2281: the bundle's object id");
        assert_eq!(p.version, 1, "I2281: version 1");
        assert!(p.prev.is_none(), "I2281: no prev");
        let mut placed_holders: Vec<String> =
            p.holders.iter().map(|h| h.identity_ref.clone()).collect();
        let mut want = off.terms.holders.clone();
        placed_holders.sort();
        want.sort();
        assert_eq!(placed_holders, want, "I2281: the holders");
        assert_eq!(p.seats.len(), off.seats.len(), "I2281: every seat");
        for s in &off.seats {
            let iref = c::identity_ref_of(s.key.public_key());
            let ps = p
                .seats
                .iter()
                .find(|x| x.identity_ref == iref)
                .expect("I2281: the seat is placed");
            assert_eq!(
                Some(ps.transit_xwing_pubkey.to_vec()),
                s.transport.transit_xwing_pubkey,
                "I2281: the seat's transit key"
            );
            assert_eq!(
                Some(ps.onion_hop_xwing_pubkey.to_vec()),
                s.transport.onion_hop_xwing_pubkey,
                "I2281: the seat's onion-hop key"
            );
            assert_eq!(ps.record, s.record_id, "I2281: the seat's record");
            assert!(p.is_canonical(&iref), "I2281: the seat is canonical");
        }
        assert_eq!(p.charter.halt_fuse_secs, Some(86_400), "I2281: the fuse");
    }
}

/// **I2282** — the offer check refuses what the door refuses.
#[test]
fn i2282_the_offer_check_refuses_what_the_door_refuses() {
    add_test_attestation_root(mock_attestation_root_der());
    let (_, off) = fixed();
    let anchor = off.anchor();

    // A holder's voice missing: the count is unmet.
    let mut short = off.statements();
    short.pop();
    let e = c::check_genesis_offer(&short, &anchor, CHECK_AT).expect_err("I2282: short");
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
        "I2282: one holder short is count_unmet: {e:?}"
    );

    // Another anchor: the seats' thumbprints root nothing.
    let seat_keys: Vec<&c::CompositePublicKey> =
        off.seats.iter().map(|s| s.key.public_key()).collect();
    let e = c::check_genesis_offer(
        &off.statements(),
        &c::thumbprint_anchor(&seat_keys),
        CHECK_AT,
    )
    .expect_err("I2282: another anchor");
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_NOT_ANCHORED,
        "I2282: another anchor is not_anchored: {e:?}"
    );

    // No statement at all is a bundle voice.
    let rows_only: Vec<Vec<u8>> = off.holders.iter().map(|(_, r)| r.clone()).collect();
    let e = c::check_genesis_offer(&rows_only, &anchor, CHECK_AT).expect_err("I2282: no voice");
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_MALFORMED,
        "I2282: rows alone are no_voice: {e:?}"
    );

    // A binding without both X-Wing keys is not drafted.
    let s = &off.seats[0];
    let mut no_onion = s.transport.clone();
    no_onion.onion_hop_xwing_pubkey = None;
    let e = c::seat_binding_draft(s.key.public_key(), &s.record_id, T0, no_onion)
        .expect_err("I2282: no onion-hop key");
    assert!(
        e.to_string().contains("edition2_payload_invalid"),
        "I2282: a seat binding carries both X-Wing keys: {e}"
    );

    // A binding that cites no record, in a bundle that names it: refused.
    let mut terms =
        c::seat_binding_terms(s.key.public_key(), &s.record_id, T0, s.transport.clone());
    terms.cites.clear();
    let uncited = sign(
        &s.key,
        &super::occurrence::bind_draft(&terms, &terms.occurrence_key_id).expect("drafted"),
    );
    let mut bt = off.terms.clone();
    let old = super::names::RowId::of_statement(&s.binding).unwrap().0;
    let new = super::names::RowId::of_statement(&uncited).unwrap().0;
    for x in &mut bt.cites {
        if *x == old {
            *x = new;
        }
    }
    let mut st: Vec<Vec<u8>> = off
        .holders
        .iter()
        .map(|(_, r)| r.clone())
        .chain(off.seats.iter().map(|x| x.record.clone()))
        .chain(off.seats.iter().skip(1).map(|x| x.binding.clone()))
        .collect();
    st.push(uncited);
    st.extend(
        off.holders
            .iter()
            .map(|(k, _)| sign(k, &c::bundle_voice_draft(k.public_key(), &bt))),
    );
    assert!(
        c::check_genesis_offer(&st, &anchor, CHECK_AT).is_err(),
        "I2282: a bundle whose seat binding cites no record is not placed"
    );
}

/// **I2283** — each step's own self-check.
#[test]
fn i2283_each_step_checks_itself() {
    let (_, off) = fixed();
    for (k, r) in &off.holders {
        let rec = c::check_key_record(r).expect("I2283: a holder record reads");
        assert_eq!(rec.kid, c::kid_of(k.public_key()), "I2283: the kid");
        assert_eq!(rec.identity_type, vec![c::ACCORD_HOLDER.to_owned()]);
        assert_eq!(rec.valid_until, None, "I2283: a holder record has no end");
        assert_eq!(rec.chain.len(), 2, "I2283: the custody chain, leaf first");
        assert_eq!(rec.hardware_class.as_deref(), Some(c::YUBIKEY_5_FIPS));
    }
    for s in &off.seats {
        let rec = c::check_key_record(&s.record).expect("I2283: a seat record reads");
        assert_eq!(rec.identity_type, vec![c::NODE.to_owned()]);
        assert_eq!(
            rec.valid_until,
            Some(T0 + YEAR_MS),
            "I2283: a node record asked no end ends 365 days out"
        );
        let (transit, onion) = c::check_seat_binding(&s.binding, s.key.public_key(), &s.record_id)
            .expect("I2283: the seat binding reads");
        assert_eq!(Some(transit.to_vec()), s.transport.transit_xwing_pubkey);
        assert_eq!(Some(onion.to_vec()), s.transport.onion_hop_xwing_pubkey);
        // The binding checked against another record cites none.
        let other = off
            .seats
            .iter()
            .find(|x| x.record_id != s.record_id)
            .unwrap();
        let e = c::check_seat_binding(&s.binding, s.key.public_key(), &other.record_id)
            .expect_err("I2283: the binding cites its own record only");
        assert!(
            e.to_string().contains("binding_names_no_record"),
            "I2283: binding_names_no_record: {e}"
        );
    }
    // A seat's binding is not a key:record.
    assert!(c::check_key_record(&off.seats[0].binding).is_err());
}

/// **I2284** — the pre-signed halt reads Valid under the bundle it will
/// meet, and only from a holder.
#[test]
fn i2284_the_sealed_halt_reads_valid_under_the_bundle() {
    add_test_attestation_root(mock_attestation_root_der());
    let (_, off) = fixed();
    let placed =
        c::check_genesis_offer(&off.statements(), &off.anchor(), CHECK_AT).expect("the genesis");
    let p = &placed[0];
    for (i, h) in off.halts.iter().enumerate() {
        let inv = c::check_halt(h, p).expect("I2284: the holder's halt is Valid");
        assert_eq!(inv.kind(), c::InvokeKind::Constitutional);
        assert_eq!(inv.author(), off.terms.holders[i], "I2284: its holder");
        assert_eq!(inv.invocation_id(), format!("ce-fix1-halt-{i}"));
    }
    // A seat's key is no holder's: the halt waits on it (never refused).
    let seat = &off.seats[0].key;
    let d = c::halt_draft(
        seat.public_key(),
        FAMILY_KEY_ID,
        "ce-seat",
        [7; 32],
        T0,
        T0 + DAY_MS,
    )
    .unwrap();
    let e = c::check_halt(&sign(seat, &d), p).expect_err("I2284: a seat is no holder");
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I2284: it waits on the key: {e:?}"
    );
    // Holder 0's key under holder 1's iss.
    let (k0, _) = &off.holders[0];
    let d = c::invocation_draft(
        k0.public_key(),
        &c::InvocationTerms {
            kind: c::InvokeKind::Constitutional,
            holder: off.terms.holders[1].clone(),
            accord_root: FAMILY_KEY_ID.to_owned(),
            invocation_id: "ce-swap".to_owned(),
            nonce: [9; 32],
            asserted_at_ms: T0,
            valid_until_ms: T0 + DAY_MS,
            payload_digest: None,
        },
    )
    .unwrap();
    let e = c::check_halt(&sign(k0, &d), p).expect_err("I2284: another holder's iss");
    assert_eq!(reason(&e), malformed_row::ISS_NOT_HOLDER, "I2284: {e:?}");
    // A window covering no instant: refused, by the producer or the reading.
    if let Ok(d) = c::halt_draft(k0.public_key(), FAMILY_KEY_ID, "ce-empty", [11; 32], T0, T0) {
        assert!(
            c::check_halt(&sign(k0, &d), p).is_err(),
            "I2284: valid_until not after asserted_at is refused"
        );
    }
}

/// **I2285** — the manifest preimages, and a holder's composite under its
/// key in hand.
#[test]
fn i2285_the_manifest_preimages_and_their_verify() {
    let k0 = test_key(1);
    let k1 = test_key(2);
    let (i0, i1) = (
        c::identity_ref_of(k0.public_key()),
        c::identity_ref_of(k1.public_key()),
    );
    let sha = "6649ce53".repeat(8);
    let pre = c::accord_manifest_v2_preimage(&sha, 4096, &i0).unwrap();
    assert_eq!(pre.len(), 84, "I2285: 24 + 4 + 24 + 32 bytes");
    assert_eq!(
        pre,
        c::domain_preimage(
            c::SigningDomain::AccordManifest,
            &c::accord_manifest_v2_message(&sha, 4096, &i0).unwrap()
        ),
        "I2285: the domain framing over the 32-byte message"
    );
    let sig = k0.sign(&pre).unwrap();
    c::verify_accord_manifest_v2_with_key(k0.public_key(), &sha, 4096, &i0, &sig)
        .expect("I2285: the holder's signature verifies");
    assert!(
        c::verify_accord_manifest_v2_with_key(k0.public_key(), &sha, 4097, &i0, &sig).is_err(),
        "I2285: another size"
    );
    assert!(
        c::verify_accord_manifest_v2_with_key(k1.public_key(), &sha, 4096, &i1, &sig).is_err(),
        "I2285: another holder's key"
    );
    assert!(
        c::verify_accord_manifest_v2_with_key(k1.public_key(), &sha, 4096, &i0, &sig).is_err(),
        "I2285: a key that is not the signer_identity's"
    );
    let template = b"identity-template-manifest-bytes";
    let tsig = k0.sign(&c::identity_template_preimage(template)).unwrap();
    c::verify_domain_composite(
        k0.public_key(),
        c::SigningDomain::IdentityTemplate,
        template,
        &tsig,
    )
    .expect("I2285: the template signature verifies in its domain");
    assert!(
        c::verify_domain_composite(
            k0.public_key(),
            c::SigningDomain::AccordManifest,
            template,
            &tsig
        )
        .is_err(),
        "I2285: and not in another domain"
    );
    assert!(
        k0.public_key().verify(template, &tsig).is_err(),
        "I2285: nor as a raw signature over the message"
    );
}

/// **I2286** — the end rule the Engine and the ceremony share.
#[test]
fn i2286_the_key_record_end_rule() {
    let max = 31_536_000_000;
    assert_eq!(key_record_end(&["node"], T0, None), Some(T0 + max));
    assert_eq!(key_record_end(&["agent"], T0, None), Some(T0 + max));
    assert_eq!(key_record_end(&["accord_holder"], T0, None), None);
    assert_eq!(key_record_end(&["user"], T0, None), None);
    assert_eq!(key_record_end(&["node"], T0, Some(T0 + 5)), Some(T0 + 5));
    assert_eq!(
        key_record_end(&["accord_holder"], T0, Some(T0 + 5)),
        Some(T0 + 5)
    );
}

/// **I2287** — the offline-built set imports through the production doors.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
async fn body_import(d: &dyn crate::federation::FederationDirectory) {
    use super::genesis::{genesis_in_force, put_genesis_bundle};
    use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};

    add_test_attestation_root(mock_attestation_root_der());
    let fx = ceremony_v2(&CeremonySpec::standard());
    let off = offline(&fx);

    // Sealed until published: before the genesis, a halt waits and is not
    // latched (nor kept).
    let early = put_statement(d, &off.halts[0], None, INGEST_TIER)
        .await
        .expect_err("I2287: a halt before the genesis waits");
    assert_eq!(
        e_kind(&early),
        "federation_attester_key_unknown",
        "{early:?}"
    );
    assert!(d.get_active_halt(FAMILY_KEY_ID).await.unwrap().is_none());

    let admission = put_genesis_bundle(d, &off.statements(), Some(&off.anchor()))
        .await
        .expect("I2287: the offline genesis imports");
    assert_eq!(admission.placed.len(), 1, "I2287: placed");
    let g = genesis_in_force(d).await.unwrap();
    assert!(g.is_held(), "I2287: the genesis is in force");
    assert_eq!(g.seats().len(), off.seats.len(), "I2287: every seat");
    for s in &off.seats {
        let iref = c::identity_ref_of(s.key.public_key());
        let seat = g.seat(&iref).expect("I2287: the seat is listed");
        assert_eq!(
            Some(seat.transit_xwing_pubkey.to_vec()),
            s.transport.transit_xwing_pubkey,
            "I2287: the seat's transit key"
        );
        let dest = ciris_verify_core::transport_binding::compute_destination_hash(
            &s.transport.app_name,
            &s.transport.aspects,
            &s.transport.reticulum_x25519_pubkey,
            &s.transport.reticulum_ed25519_pubkey,
        )
        .expect("a destination");
        let routes = d.list_transport_destinations_for(&iref).await.unwrap();
        assert!(
            routes
                .iter()
                .any(|r| r.transport_kind == "reticulum" && r.destination == hex::encode(dest)),
            "I2287: the seat's route is listed: {routes:?}"
        );
    }
    for (i, h) in off.halts.iter().enumerate().take(1) {
        let out = put_statement(d, h, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("I2287: holder {i}'s sealed halt is admitted: {e:?}"));
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I2287: the halt is a row: {out:?}"
        );
    }
    assert!(
        d.get_active_halt(FAMILY_KEY_ID).await.unwrap().is_some(),
        "I2287: the published halt latches"
    );
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn e_kind(e: &Error) -> &'static str {
    e.kind()
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2287_the_offline_set_imports_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body_import(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2287_the_offline_set_imports_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body_import(&b)).await;
}

/// **I2288** — the final gate: the offer through the real doors of a
/// throwaway node.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2288_the_final_gate_imports_into_a_throwaway_node() {
    add_test_attestation_root(mock_attestation_root_der());
    let fx = ceremony_v2(&CeremonySpec::standard());
    let off = offline(&fx);
    let mut statements = off.statements();
    statements.push(off.halts[0].clone());
    let imported = Box::pin(c::import_offer_into_throwaway(&statements, &off.anchor()))
        .await
        .expect("I2288: the offer imports");
    assert_eq!(imported.placed.len(), 1, "I2288: one bundle placed");
    let mut holders = imported.holders.clone();
    let mut want = off.terms.holders.clone();
    holders.sort();
    want.sort();
    assert_eq!(holders, want, "I2288: the holders in force");
    assert_eq!(imported.seats.len(), off.seats.len(), "I2288: every seat");
    for s in &off.seats {
        let iref = c::identity_ref_of(s.key.public_key());
        let seat = imported
            .seats
            .iter()
            .find(|x| x.identity_ref == iref)
            .expect("I2288: the seat is held");
        assert_eq!(
            Some(seat.transit_xwing_pubkey.to_vec()),
            s.transport.transit_xwing_pubkey,
            "I2288: transit"
        );
        assert_eq!(
            Some(seat.onion_hop_xwing_pubkey.to_vec()),
            s.transport.onion_hop_xwing_pubkey,
            "I2288: onion hop"
        );
        let dest = ciris_verify_core::transport_binding::compute_destination_hash(
            &s.transport.app_name,
            &s.transport.aspects,
            &s.transport.reticulum_x25519_pubkey,
            &s.transport.reticulum_ed25519_pubkey,
        )
        .expect("a destination");
        assert!(
            seat.routes
                .iter()
                .any(|r| r.transport_kind == "reticulum" && r.destination == hex::encode(dest)),
            "I2288: the seat's route: {:?}",
            seat.routes
        );
    }
    assert_eq!(imported.invocations.len(), 1, "I2288: the halt was offered");
    assert!(
        matches!(
            imported.invocations[0],
            super::ingest::StatementOutcome::Row { .. }
        ),
        "I2288: the halt is a row: {:?}",
        imported.invocations[0]
    );
    assert!(imported.halt_latched, "I2288: the sealed halt latches");

    // One voice short: the final gate refuses (the door holds it short and
    // places nothing).
    let mut short = off.statements();
    short.pop();
    let e = Box::pin(c::import_offer_into_throwaway(&short, &off.anchor()))
        .await
        .expect_err("I2288: one voice short is not placed");
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
        "I2288: {e:?}"
    );
}

fn with_halts(off: &Offline, halts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut st = off.statements();
    st.extend(halts.iter().cloned());
    st
}

/// **I2289** — every listed holder's sealed halt present: the whole
/// ceremony passes.
#[test]
fn i2289_every_holders_halt_present_passes() {
    add_test_attestation_root(mock_attestation_root_der());
    let (_, off) = fixed();
    let (p, cov) =
        c::check_offer_with_halts(&with_halts(&off, &off.halts), &off.anchor(), CHECK_AT)
            .expect("I2289: every holder's halt is present");
    assert_eq!(p.object_id, c::bundle_object_id(&off.terms));
    assert!(cov.is_complete(), "I2289: {:?}", cov.faults);
    assert_eq!(cov.holders.len(), off.holders.len());
    for h in &cov.holders {
        assert_eq!(h.halts.len(), 1, "I2289: exactly one halt for {}", h.holder);
    }
    // The bundle check alone keeps its meaning: no halt is required there.
    c::check_genesis_offer(&off.statements(), &off.anchor(), CHECK_AT)
        .expect("I2289: check_genesis_offer requires no halt");
}

/// **I2305** — a missing, a doubled, or a non-halt invocation refuses,
/// naming the holder.
#[test]
fn i2305_a_missing_or_doubled_halt_refuses_naming_the_holder() {
    add_test_attestation_root(mock_attestation_root_der());
    let (_, off) = fixed();
    let anchor = off.anchor();
    let missing = c::identity_ref_of(off.holders[1].0.public_key());

    // Holder 1's halt missing.
    let halts = vec![off.halts[0].clone(), off.halts[2].clone()];
    let e = c::check_offer_with_halts(&with_halts(&off, &halts), &anchor, CHECK_AT)
        .expect_err("I2305: a holder's halt missing");
    let msg = e.to_string();
    assert!(
        msg.contains(&format!("{}: holder {missing}", c::CEREMONY_HALT_MISSING)),
        "I2305: the refusal names the missing holder: {msg}"
    );
    for (i, (k, _)) in off.holders.iter().enumerate() {
        if i != 1 {
            assert!(
                !msg.contains(&format!(
                    "holder {} has no",
                    c::identity_ref_of(k.public_key())
                )),
                "I2305: only the missing holder is named missing: {msg}"
            );
        }
    }

    // Holder 0 seals two halts.
    let (k0, _) = &off.holders[0];
    let second = sign(
        k0,
        &c::halt_draft(
            k0.public_key(),
            FAMILY_KEY_ID,
            "ce-fix2-second",
            [0x77; 32],
            T0 + 2_000,
            T0 + 30 * DAY_MS,
        )
        .unwrap(),
    );
    let mut doubled = off.halts.clone();
    doubled.push(second);
    let e = c::check_offer_with_halts(&with_halts(&off, &doubled), &anchor, CHECK_AT)
        .expect_err("I2305: two halts for one holder");
    assert!(
        e.to_string().starts_with(c::CEREMONY_HALT_DUPLICATE)
            || e.to_string().contains(c::CEREMONY_HALT_DUPLICATE),
        "I2305: {e}"
    );

    // A drill in place of holder 2's halt.
    let (k2, _) = &off.holders[2];
    let drill = sign(
        k2,
        &c::invocation_draft(
            k2.public_key(),
            &c::InvocationTerms {
                kind: c::InvokeKind::Drill,
                holder: c::identity_ref_of(k2.public_key()),
                accord_root: FAMILY_KEY_ID.to_owned(),
                invocation_id: "ce-fix2-drill".to_owned(),
                nonce: [0x78; 32],
                asserted_at_ms: T0 + 3_000,
                valid_until_ms: T0 + 30 * DAY_MS,
                payload_digest: None,
            },
        )
        .unwrap(),
    );
    let halts = vec![off.halts[0].clone(), off.halts[1].clone(), drill];
    let p = &c::check_genesis_offer(&off.statements(), &anchor, CHECK_AT).unwrap()[0];
    let cov = c::halt_coverage(p, &halts);
    let tokens: Vec<&str> = cov.faults.iter().map(c::HaltFault::token).collect();
    assert!(
        tokens.contains(&c::CEREMONY_HALT_INVALID) && tokens.contains(&c::CEREMONY_HALT_MISSING),
        "I2305: a drill is no halt, and its holder stays missing: {:?}",
        cov.faults
    );
}

/// **I2306** — a halt signed for a different bundle refuses.
#[test]
fn i2306_a_halt_for_another_bundle_refuses() {
    add_test_attestation_root(mock_attestation_root_der());
    let (_, off) = fixed();
    let other = offline(&ceremony_v2(&CeremonySpec {
        holders: vec![4, 5, 6],
        ..CeremonySpec::at(T0)
    }));
    let mut halts = off.halts.clone();
    halts.push(other.halts[0].clone());
    let e = c::check_offer_with_halts(&with_halts(&off, &halts), &off.anchor(), CHECK_AT)
        .expect_err("I2306: another bundle's halt");
    assert!(
        e.to_string().contains(c::CEREMONY_HALT_NOT_A_HOLDER),
        "I2306: {e}"
    );
    // Only the other bundle's halts: every listed holder missing too.
    let e = c::check_offer_with_halts(&with_halts(&off, &other.halts), &off.anchor(), CHECK_AT)
        .expect_err("I2306: only another bundle's halts");
    let msg = e.to_string();
    assert!(msg.contains(c::CEREMONY_HALT_NOT_A_HOLDER), "I2306: {msg}");
    for (k, _) in &off.holders {
        assert!(
            msg.contains(&format!(
                "{}: holder {}",
                c::CEREMONY_HALT_MISSING,
                c::identity_ref_of(k.public_key())
            )),
            "I2306: every listed holder is missing: {msg}"
        );
    }
}

/// **I2307** — the final gate reports the coverage and never requires it.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2307_the_final_gate_reports_halt_coverage() {
    add_test_attestation_root(mock_attestation_root_der());
    let fx = ceremony_v2(&CeremonySpec::standard());
    let off = offline(&fx);

    // No halt: the bundle still imports; every holder is reported missing.
    let none = Box::pin(c::import_offer_into_throwaway(
        &off.statements(),
        &off.anchor(),
    ))
    .await
    .expect("I2307: a bundle imports with no halt");
    assert_eq!(none.placed.len(), 1);
    assert!(!none.halt_latched);
    assert_eq!(
        none.halt_coverage
            .faults
            .iter()
            .filter(|f| f.token() == c::CEREMONY_HALT_MISSING)
            .count(),
        off.holders.len(),
        "I2307: every holder reported missing"
    );

    // Every halt: complete, and latched.
    let all = Box::pin(c::import_offer_into_throwaway(
        &with_halts(&off, &off.halts),
        &off.anchor(),
    ))
    .await
    .expect("I2307: imports with every halt");
    assert!(
        all.halt_coverage.is_complete(),
        "{:?}",
        all.halt_coverage.faults
    );
    assert_eq!(all.invocations.len(), off.halts.len());
    assert!(all.halt_latched);

    // Another bundle's halt: reported, not offered.
    let other = offline(&ceremony_v2(&CeremonySpec {
        holders: vec![4, 5, 6],
        ..CeremonySpec::standard()
    }));
    let mut halts = off.halts.clone();
    halts.push(other.halts[0].clone());
    let mixed = Box::pin(c::import_offer_into_throwaway(
        &with_halts(&off, &halts),
        &off.anchor(),
    ))
    .await
    .expect("I2307: another bundle's halt does not fail the import");
    assert!(
        mixed
            .halt_coverage
            .faults
            .iter()
            .any(|f| f.token() == c::CEREMONY_HALT_NOT_A_HOLDER),
        "{:?}",
        mixed.halt_coverage.faults
    );
    assert_eq!(
        mixed.invocations.len(),
        off.halts.len(),
        "I2307: not offered"
    );
}
