//! **I2874–I2876** (v62.0.0, JSON-cut slice F; CC 4.2.6, CC 4.2.1.1): an
//! accord holder's recovery in edition 2, and the halt it voids, on sqlite
//! and postgres.
//!
//! In edition 2 a holder's recovery is a later genesis bundle carrying the
//! holder's ONE recovery voice, judged by Verify's bundle reader against the
//! recovery commitment the genesis pre-committed for that holder (I2339). It
//! is not an m-of-n act: the pre-commitment is the safeguard.
//!
//! - I2874: the recovery bundle is placed through the import door
//!   (`put_genesis_bundle`), and the halt roster in force is the recovery
//!   bundle's, with the holder still seated (by identity-ref) on a new key.
//! - I2875: a constitutional halt signed by the holder's OLD key, offered
//!   after the recovery, is not admitted: the roster no longer places that
//!   key, so it WAITS by name (`federation_attester_key_unknown`, the
//!   reader's unplaced-key reading, CC 4.2.1.1), and no halt latches. The
//!   same holder's halt under its new key latches (the control). An old-key
//!   halt that latched here would be a hole, not a reading.
//! - I2876: a lone earlier-form recovery, a `SignedFamily` for the accord
//!   carrying a recovery-shaped supersede proof, is refused
//!   `earlier_form_object` by name at both family doors (`put_family`,
//!   `supersede_family`), and the accord's family record is unchanged.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::map;
use super::fixture_genesis::{
    bundle_v2, install_ceremony_v2, install_v2, recover_v2, DAY_MS, FAMILY_KEY_ID, HOLDER_SEEDS,
};
use super::halt::{put_invocation, roster_in_force, FAMILY_CONSTITUTIONAL};
use crate::federation::types::{GroupSupersedeProof, SignedFamily};
use crate::federation::{malformed_row, Error, FederationDirectory};

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

/// A constitutional halt of the accord by `holder` (its identity-ref, the
/// statement's `iss` and `author`), signed by `k`.
fn halt(
    k: &ciris_crypto::composite::CompositeSigningKey,
    holder: &str,
    id: &str,
    nonce: u8,
    at: u64,
) -> Vec<u8> {
    let m = map(vec![
        ("accord_root", Value::Text(FAMILY_KEY_ID.into())),
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(holder.into())),
        ("invocation_id", Value::Text(id.into())),
        ("nonce", Value::Bytes(vec![nonce; 32])),
        ("valid_until", Value::Uint(at + DAY_MS)),
    ]);
    sign_row_statement(
        k,
        holder,
        FAMILY_KEY_ID,
        "scores",
        FAMILY_CONSTITUTIONAL,
        &m,
        vec![],
    )
    .unwrap()
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let first = bundle_v2();
    install_v2(d).await.expect("the genesis is installed");
    let holder = first.holder_identity_ref(0).to_owned();
    let old_key = first.holder_key(0);

    // I2874 — the holder's ONE recovery voice, as a later bundle.
    let r = recover_v2(first, HOLDER_SEEDS[0]);
    assert_eq!(r.voices.len(), 1, "I2874: one recovery statement");
    install_ceremony_v2(d, &r)
        .await
        .expect("I2874: the recovery bundle is placed");
    let new_key = r.holder_key(0);
    let roster = roster_in_force(d, FAMILY_KEY_ID)
        .await
        .unwrap()
        .expect("I2874: a halt roster is in force");
    assert_eq!(
        roster.bundle(),
        &r.object_id,
        "I2874: the halt roster in force is the recovery bundle's"
    );
    assert!(
        roster.holders().any(|h| h == holder),
        "I2874: the holder keeps its seat (its identity-ref) across the recovery"
    );
    assert_ne!(
        ciris_verify_core::edition2::thumbprint(new_key.public_key()),
        ciris_verify_core::edition2::thumbprint(old_key.public_key()),
        "I2874: re-seated on a new key (I2875 reads which key the roster places)"
    );

    // I2875 — the old key's halt, offered after the recovery.
    let at = r.asserted_at_ms + 1_000;
    let stale = halt(&old_key, &holder, "f0-old-key-halt", 0x61, at);
    match put_invocation(d, &stale, Some(&roster)).await {
        Ok(out) => panic!(
            "I2875: HOLE — a halt under the recovered holder's OLD key was admitted \
             (latched: {}); report it, never bless it",
            out.latched
        ),
        Err(e) => assert_eq!(
            e.kind(),
            "federation_attester_key_unknown",
            "I2875: the old key waits by name (the roster does not place it): {e:?}"
        ),
    }
    assert!(
        d.get_active_halt(FAMILY_KEY_ID).await.unwrap().is_none(),
        "I2875: no halt latched under the old key"
    );
    // The control: the same holder under its new key.
    let fresh = halt(&new_key, &holder, "f0-new-key-halt", 0x62, at);
    let out = put_invocation(d, &fresh, Some(&roster))
        .await
        .expect("I2875: the recovered holder's halt under its new key is admitted");
    assert!(out.new && out.latched, "I2875: latched under the new key");

    // I2876 — a lone earlier-form recovery at the family doors.
    let before = d.lookup_family(FAMILY_KEY_ID).await.unwrap();
    let family = crate::federation::genesis::accord_family_genesis_record_for(
        FAMILY_KEY_ID,
        "quorum:2/3",
        first.holder_identity_refs().iter().map(String::as_str),
        "",
    );
    let lone = SignedFamily {
        family,
        authority_key_id: holder.clone(),
        scrub_signature_classical: "c2ln".to_owned(),
        scrub_signature_pqc: Some("c2ln".to_owned()),
        supersede_proof: Some(GroupSupersedeProof {
            prior_persist_row_hash: String::new(),
            change_envelope: serde_json::json!({
                "kind": crate::federation::accord_recovery::RECOVERY_STATEMENT_KIND,
                "family_key_id": FAMILY_KEY_ID,
                "old_holder_key_id": holder,
            }),
            quorum_signatures: vec![crate::federation::types::RetiredMemberPairSignature {
                member_id: "i2876-recovery-key".to_owned(),
                ed25519_signature_base64: "c2ln".to_owned(),
                mldsa65_signature_base64: Some("c2ln".to_owned()),
            }],
        }),
        cosignatures: Vec::new(),
    };
    let e = d
        .put_family(lone.clone())
        .await
        .expect_err("I2876: the earlier-form recovery at put_family");
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_EARLIER_FORM_OBJECT,
        "I2876: put_family refuses by name: {e:?}"
    );
    let e = d
        .supersede_family(lone, None)
        .await
        .expect_err("I2876: the earlier-form recovery at supersede_family");
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_EARLIER_FORM_OBJECT,
        "I2876: supersede_family refuses by name: {e:?}"
    );
    assert_eq!(
        d.lookup_family(FAMILY_KEY_ID)
            .await
            .unwrap()
            .map(|f| f.persist_row_hash),
        before.map(|f| f.persist_row_hash),
        "I2876: the accord's family record is unchanged"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2874_to_i2876_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2874_to_i2876_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}
