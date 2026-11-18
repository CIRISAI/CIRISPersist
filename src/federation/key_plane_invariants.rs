//! v58.0.0 (CIRISPersist#991 plane 1; CC 3.1.3, CC 3.3.6, CC 2.4.1.1;
//! `CLM-planes-as-rows`) — **I975–I980: the key plane is rows, on every
//! backend.**
//!
//! - **I975 (`key:record:v1`, the projection gate)** — a record that proves
//!   possession is a `key:record:v1` row (attester = attested = the key, its
//!   object the record), and `federation_keys` is its from-rows rebuild; a
//!   record whose base scrub is a held signer's (the pre-rc8 conferral shape)
//!   is a row too. RED legs: a key held without a row (an unsigned
//!   registration), and (sqlite, postgres) one projection column edited.
//! - **I976 (proof of possession)** — a record carrying a key's pubkeys but
//!   signed by another key's private key is refused by the plan, and its row
//!   is refused at the attestation door; a genuine row replicates to a fresh
//!   node through `apply_replicated_attestation` and lands the key.
//! - **I977 (the order rule)** — a row signed by a key the node does not hold
//!   is refused with the retryable `AttesterKeyUnknown`; once the key's own
//!   `key:record:v1` row arrives, the same row is admitted.
//! - **I978 (`key:revocation:v1`)** — a revocation is a row attested by the
//!   revoker; the subject's bound is the minimum over its held revocations
//!   (a raising one is kept and loses the merge, CC rc21 item 18; a lowering
//!   one admitted); an Ed25519-only revocation is
//!   refused; a `withdraws` or `recants` naming the row is refused; the
//!   projection is its rebuild (RED on an edited column, sqlite and
//!   postgres).
//! - **I979 (`identity:occurrence:v1`)** — a signed occurrence is a row
//!   attested by its signer about the identity; its revocation is a
//!   `withdraws` on that row by the identity (admitted, the projection fed),
//!   never by an unrelated key; the projection is its rebuild.
//! - **I980 (the rehome, sqlite and postgres)** — a pre-V198 key record
//!   that proves possession gets its row when a fresh backend opens (v58:
//!   at its first key-plane write; v59.0.0: eager, at `run_migrations`),
//!   asserted at its own `scrub_timestamp`; one that cannot stays held
//!   without a row and the gate names it.

/// The pure fixtures `bodies` and the backend-free unit tests share.
#[cfg(test)]
pub(crate) mod pure {
    use crate::federation::register::test_support::authority_signed_record;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{identity_type, KeyRecord};

    /// A record of `key_id` that proves possession (signed by the key itself).
    pub(crate) fn pop_record(key_id: &str) -> KeyRecord {
        let (ed, mldsa) = ts::hybrid_pubkeys(key_id);
        authority_signed_record(key_id, identity_type::USER, &ed, mldsa.as_deref(), key_id)
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::types::identity_type;

    // v62 (E4): I975 (`key:record:v1` rows + the `federation_keys` gate), I976
    // (proof of possession over the earlier `registration_envelope`), I977
    // (the order rule over the JSON key plane), I978 (`key:revocation:v1`
    // rows, the Ed25519-only refusal) are deleted: each asserts the earlier
    // form's key plane, which the cut replaces with `key:record` /
    // `key:revocation` statements and their projection. Their intents are
    // witnessed on the edition-2 plane by `edition2::projection_invariants`
    // (I2000–I2009: the projection is the reading, its rebuild is red on an
    // edited column, a stranger's revocation is held but not honoured),
    // `edition2::liveness_invariants` and `edition2::ingest_invariants`
    // (an unknown signer waits as `federation_attester_key_unknown`).

    /// I979 (bind half) — v62 (E4, wave 4; O1): a person's occurrence is an
    /// edition-2 `identity:occurrence` bind authored by the identity (O1
    /// `put_bind`), and the occurrence listing holds it under the identity's
    /// identity-ref. The earlier JSON-plane assertions (a `identity:occurrence:v1`
    /// row, its from-rows rebuild) are gone with that plane.
    pub(crate) async fn i979_occurrences<B: AttestationStore>(b: &B, tag: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest::StatementOutcome;
        let id = format!("i979-id-{tag}");
        let occ = format!("i979-occ-{tag}");
        for k in [&id, &occ] {
            e2::put_key(b, k, &[identity_type::USER]).await;
        }
        let out = e2::put_bind(b, &id, &id, &occ, "phone", &e2::BindOptions::default())
            .await
            .expect("I979: the identity's occurrence bind lands");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I979: the bind landed: {out:?}"
        );
        let held = b
            .list_identity_occurrences_for(&e2::kid(&id))
            .await
            .unwrap();
        assert!(
            held.iter().any(|o| o.occurrence_key_id == e2::kid(&occ)),
            "I979: the occurrence is held under the identity: {held:?}"
        );
    }

    /// I979b (revocation half) — v62 (E4, wave 5; T2): the identity's own
    /// `identity:occurrence_revocation` voice (`as_identity`, its one roster
    /// key) lands and feeds the revocation projection; a stranger's voice
    /// lands nothing. (Per the CC 2.7 heads-up the stranger's refusal token is
    /// not pinned: it is refused or held, and nothing is projected.)
    pub(crate) async fn i979b_occurrence_revocation<B: AttestationStore>(b: &B, tag: &str) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest::StatementOutcome;
        use crate::federation::types::IdentityOccurrenceRevocation;
        let id = e2::kid(&format!("i979b-id-{tag}"));
        let occ = e2::kid(&format!("i979b-occ-{tag}"));
        let stranger = e2::kid(&format!("i979b-stranger-{tag}"));
        for k in [&id, &occ, &stranger] {
            e2::put_key(b, k, &[identity_type::USER]).await;
        }
        e2::put_bind(b, &id, &id, &occ, "phone", &e2::BindOptions::default())
            .await
            .expect("I979b: the identity's occurrence bind lands");
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let at = u64::try_from(now.timestamp_millis()).expect("ms");
        let rev = IdentityOccurrenceRevocation {
            identity_key_id: id.clone(),
            occurrence_key_id: occ.clone(),
            revoked_at: now,
            effective_at: now,
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        };
        // A stranger's voice: refused or held, never projected.
        let r = e2::put_statement(
            b,
            &e2::occurrence_revocation_voice(b, &stranger, false, &rev, None, &[], at).await,
        )
        .await;
        assert!(
            !matches!(r, Ok(StatementOutcome::Row { .. })),
            "I979b: an unrelated key cannot revoke the occurrence: {r:?}"
        );
        assert!(b
            .list_identity_occurrence_revocations_for(&id)
            .await
            .unwrap()
            .is_empty());
        // The identity's own voice.
        let voice = e2::occurrence_revocation_voice(b, &id, true, &rev, None, &[], at).await;
        let out = e2::put_statement(b, &voice)
            .await
            .expect("I979b: the identity revokes its occurrence");
        assert!(
            matches!(out, StatementOutcome::Row { .. }),
            "I979b: the revocation lands: {out:?}"
        );
        let revs = b
            .list_identity_occurrence_revocations_for(&id)
            .await
            .unwrap();
        assert_eq!(revs.len(), 1, "I979b: the revocation fed the projection");
        assert_eq!(revs[0].occurrence_key_id, occ);
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    use super::bodies;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::store::Backend as _;

    fn tag(n: &str) -> String {
        format!("{n}-{}", uuid::Uuid::new_v4().simple())
    }

    // ── sqlite ─────────────────────────────────────────────────────────
    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i979_sqlite() {
        bodies::i979_occurrences(&sqlite().await, &tag("i979s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i979b_sqlite() {
        let b = sqlite().await;
        bodies::i979b_occurrence_revocation(&b, &tag("i979bs")).await;
    }

    // ── postgres ───────────────────────────────────────────────────────
    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("key_plane postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return None;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i979_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i979_occurrences(&b, &tag("i979p")).await;
        eprintln!("i979_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i979b_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i979b_occurrence_revocation(&b, &tag("i979bp")).await;
    }
}
