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
//!   revoker; `revoked_after` only ever lowers (a raising one is refused
//!   `bound_raised`, a lowering one admitted); an Ed25519-only revocation is
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

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::key_plane::{self, KeyPlaneFamily};
    use crate::federation::register::test_support::authority_signed_record;
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type, Attestation, KeyRecord};
    use crate::federation::{FederationDirectory, SignedAttestation, SignedKeyRecord};

    /// A record of `key_id` that proves possession (signed by the key itself).
    pub(crate) fn pop_record(key_id: &str) -> KeyRecord {
        let (ed, mldsa) = ts::hybrid_pubkeys(key_id);
        authority_signed_record(key_id, identity_type::USER, &ed, mldsa.as_deref(), key_id)
    }

    /// Every row on the plane of `family`.
    pub(crate) async fn rows_of(
        d: &dyn FederationDirectory,
        family: KeyPlaneFamily,
    ) -> Vec<Attestation> {
        d.list_attestations_since(None, 100_000)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.attestation)
            .filter(|a| KeyPlaneFamily::of_row(a) == Some(family))
            .collect()
    }

    /// The key's own `key:record:v1` row, if on the plane.
    pub(crate) async fn key_row(d: &dyn FederationDirectory, key_id: &str) -> Option<Attestation> {
        rows_of(d, KeyPlaneFamily::KeyRecord)
            .await
            .into_iter()
            .find(|a| key_plane::key_record_of_row(a).is_some_and(|r| r.key_id == key_id))
    }

    /// A sealed structural composer (`withdraws` / `recants`) by `signer`
    /// naming `target`.
    pub(crate) fn composer(verb: &str, signer: &str, attested: &str, target: &str) -> Attestation {
        let mut env = serde_json::json!({
            "references_attestation_id": target,
            "dimension": "key:revocation:v1",
        });
        match verb {
            attestation_type::WITHDRAWS => env["withdrawal_reason"] = "changed my mind".into(),
            _ => {
                env["recantation_reason"] = "it was false".into();
                env["what_was_false"] = "the revocation".into();
            }
        }
        let mut row =
            ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), signer, attested, &env);
        row.attestation_type = verb.to_owned();
        row.weight = None;
        ts::reseal(&mut row);
        row
    }

    /// I975 — the key plane's rows and the `federation_keys` gate.
    pub(crate) async fn i975_key_records_are_rows<B: AttestationStore>(b: &B, tag: &str) {
        let k1 = format!("i975-k1-{tag}");
        let k2 = format!("i975-k2-{tag}");
        b.put_public_key(SignedKeyRecord {
            record: pop_record(&k1),
        })
        .await
        .expect("I975: a record that proves possession is admitted");
        let row = key_row(b.as_dyn_directory(), &k1)
            .await
            .expect("I975: the record is a key:record:v1 row");
        assert_eq!(row.attesting_key_id, k1, "I975: attester = the key");
        assert_eq!(row.attested_key_id, k1, "I975: attested = the key");
        assert_eq!(row.attestation_type, attestation_type::SCORES);
        assert_eq!(row.scrub_key_id, k1, "I975: the key's own signature");
        assert_eq!(
            row.asserted_at,
            crate::federation::admission::truncate_to_substrate_resolution(
                b.lookup_public_key(&k1)
                    .await
                    .unwrap()
                    .unwrap()
                    .scrub_timestamp
            ),
            "I975: the row's instant is the record's own"
        );
        // The pre-rc8 conferral shape: k1 scrubs k2's registration.
        let (ed2, mldsa2) = ts::hybrid_pubkeys(&k2);
        b.put_public_key(SignedKeyRecord {
            record: authority_signed_record(&k2, identity_type::USER, &ed2, mldsa2.as_deref(), &k1),
        })
        .await
        .expect("I975: an authority-scrubbed record is admitted");
        let row2 = key_row(b.as_dyn_directory(), &k2)
            .await
            .expect("I975: a record scrubbed by a held signer is a row too");
        assert_eq!(
            row2.attesting_key_id, k2,
            "I975: the row is still the key's claim"
        );
        assert_eq!(row2.scrub_key_id, k1, "I975: signed by the held signer");
        let rebuild = check_projection_rebuild(b, SiloProjection::FederationKeys)
            .await
            .expect("I975: federation_keys is its rows' rebuild");
        assert_eq!(rebuild.live.len(), 2, "I975: both keys, no other");
    }

    /// I975 RED — a key held without a row (an unsigned registration).
    pub(crate) async fn i975_red_on_a_key_without_a_row<B: AttestationStore>(b: &B, tag: &str) {
        ts::register_hybrid_key(b, &format!("i975-unsigned-{tag}")).await;
        assert!(
            check_projection_rebuild(b, SiloProjection::FederationKeys)
                .await
                .is_err(),
            "I975: a key held without its row is red"
        );
    }

    /// I976 — proof of possession, at the plan and at the attestation door;
    /// a genuine row replicates to a fresh node.
    pub(crate) async fn i976_proof_of_possession<B: AttestationStore>(a: &B, fresh: &B, tag: &str) {
        let x = format!("i976-x-{tag}");
        let y = format!("i976-y-{tag}");
        // x's pubkeys, y's private key, claiming x as the signer.
        let (edx, mldsax) = ts::hybrid_pubkeys(&x);
        let mut forged =
            authority_signed_record(&x, identity_type::USER, &edx, mldsax.as_deref(), &y);
        forged.scrub_key_id = x.clone();
        let refused = key_plane::plan_key_record_row(&forged, &None)
            .expect_err("I976: a record the carried keys did not sign is refused");
        assert_eq!(
            refused.kind(),
            "federation_signature_invalid",
            "I976: {refused}"
        );
        // Its row, built past the plan, is refused at the attestation door.
        let forged_row = key_plane::plane_row(
            KeyPlaneFamily::KeyRecord,
            &x,
            &x,
            key_plane::key_record_object(&forged).unwrap(),
            forged.scrub_timestamp,
            key_plane::PlaneSignature {
                scrub_key_id: x.clone(),
                classical: forged.scrub_signature_classical.clone(),
                pqc: forged.scrub_signature_pqc.clone(),
                scrub_timestamp: forged.scrub_timestamp,
                pqc_completed_at: forged.pqc_completed_at,
            },
        )
        .unwrap();
        let e = fresh
            .apply_replicated_attestation(SignedAttestation {
                attestation: forged_row,
            })
            .await
            .expect_err("I976: the forged row is refused at the door");
        assert_eq!(e.kind(), "federation_signature_invalid", "I976: {e}");
        assert!(
            fresh.lookup_public_key(&x).await.unwrap().is_none(),
            "I976: nothing landed"
        );
        // A genuine row crosses through the ordinary replicated door.
        a.put_public_key(SignedKeyRecord {
            record: pop_record(&x),
        })
        .await
        .unwrap();
        let genuine = key_row(a.as_dyn_directory(), &x).await.expect("A's row");
        let out = fresh
            .apply_replicated_attestation(SignedAttestation {
                attestation: genuine.clone(),
            })
            .await
            .expect("I976: the genuine row is admitted");
        assert_eq!(
            out,
            crate::federation::attestation_apply::ReplicatedAttestationOutcome::Inserted
        );
        assert!(fresh.lookup_public_key(&x).await.unwrap().is_some());
        assert_eq!(
            key_row(fresh.as_dyn_directory(), &x)
                .await
                .map(|r| r.attestation_id),
            Some(genuine.attestation_id.clone()),
            "I976: the same row on both nodes"
        );
        // A re-offer settles.
        assert_eq!(
            fresh
                .apply_replicated_attestation(SignedAttestation {
                    attestation: genuine
                })
                .await
                .unwrap(),
            crate::federation::attestation_apply::ReplicatedAttestationOutcome::Unchanged
        );
    }

    /// I977 — the order rule: retryable until the signer's key row is held.
    pub(crate) async fn i977_order_rule<B: AttestationStore>(a: &B, fresh: &B, tag: &str) {
        let k = format!("i977-k-{tag}");
        a.put_public_key(SignedKeyRecord {
            record: pop_record(&k),
        })
        .await
        .unwrap();
        let env = serde_json::json!({
            "dimension": "trust:i977:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        let mut row = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), &k, &k, &env);
        row.attestation_type = attestation_type::SCORES.to_owned();
        ts::reseal(&mut row);
        let e = fresh
            .apply_replicated_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .expect_err("I977: a row before its signer's key row is refused");
        assert_eq!(
            e.kind(),
            "federation_attester_key_unknown",
            "I977: the refusal is the retryable ordering gap: {e}"
        );
        let key_row = key_row(a.as_dyn_directory(), &k)
            .await
            .expect("the key's row");
        fresh
            .apply_replicated_attestation(SignedAttestation {
                attestation: key_row,
            })
            .await
            .expect("I977: the key's own row lands by possession");
        fresh
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await
            .expect("I977: the same row is admitted once its signer's key row is held");
    }

    fn revocation(
        revoker: &str,
        subject: &str,
        at: chrono::DateTime<chrono::Utc>,
        revoked_after: Option<chrono::DateTime<chrono::Utc>>,
    ) -> crate::federation::Revocation {
        let mut r = crate::federation::Revocation {
            revocation_id: uuid::Uuid::new_v4().to_string(),
            revoked_key_id: Some(subject.to_owned()),
            revoked_key_sha256_ed25519_raw: ts::subject_digest_of(subject),
            revoking_key_id: revoker.to_owned(),
            reason: Some("i978".to_owned()),
            revoked_at: at,
            effective_at: at,
            revocation_envelope: serde_json::json!({ "revokes": subject }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: revoker.to_owned(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.to_owned(),
            revoked_after,
            persist_row_hash: String::new(),
        };
        if let Some(t) = revoked_after {
            r.revocation_envelope[crate::federation::register::REVOKED_AFTER_ENVELOPE_FIELD] = t
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                .into();
        }
        ts::seal_revocation(r)
    }

    /// I978 — the revocation plane.
    pub(crate) async fn i978_revocations<B: AttestationStore>(b: &B, tag: &str) {
        let k = format!("i978-k-{tag}");
        ts::register_hybrid_key(b, &k).await;
        let ms = |s: i64| {
            let t = chrono::Utc::now() - chrono::Duration::seconds(s);
            chrono::DateTime::<chrono::Utc>::from_timestamp_micros(t.timestamp_micros()).unwrap()
        };
        let put = |r: crate::federation::Revocation| async move {
            b.put_revocation(crate::federation::SignedRevocation { revocation: r })
                .await
        };
        // (a) the first revocation, bounded at t-300.
        let r1 = revocation(&k, &k, ms(60), Some(ms(300)));
        put(r1.clone())
            .await
            .expect("I978: a revocation is admitted");
        let rows = rows_of(b.as_dyn_directory(), KeyPlaneFamily::KeyRevocation).await;
        let row1 = rows
            .iter()
            .find(|a| {
                key_plane::revocation_of_row(a).is_some_and(|r| r.revocation_id == r1.revocation_id)
            })
            .expect("I978: the revocation is a key:revocation:v1 row")
            .clone();
        assert_eq!(row1.attesting_key_id, k, "I978: attested by the revoker");
        // (b) a later revocation RAISING the bound is refused.
        let e = put(revocation(&k, &k, ms(50), Some(ms(200))))
            .await
            .expect_err("I978: a raised bound is refused");
        assert!(
            e.to_string().contains("bound_raised"),
            "I978: refused bound_raised: {e}"
        );
        // (c) a LOWERING one supersedes.
        put(revocation(&k, &k, ms(40), Some(ms(400))))
            .await
            .expect("I978: a lowered bound is admitted");
        // (d) Ed25519-only: refused at the door.
        let mut ed_only = revocation(&k, &k, ms(30), Some(ms(500)));
        ed_only.scrub_signature_pqc = None;
        let e = put(ed_only)
            .await
            .expect_err("I978: an Ed25519-only revocation is refused");
        assert_eq!(e.kind(), "federation_signature_invalid", "I978: {e}");
        // (e, f) never withdrawn, never recanted — by its own revoker.
        for verb in [attestation_type::WITHDRAWS, attestation_type::RECANTS] {
            let e = b
                .put_attestation(SignedAttestation {
                    attestation: composer(verb, &k, &k, &row1.attestation_id),
                })
                .await
                .expect_err("I978: a key:revocation:v1 row is never retracted");
            assert!(
                e.to_string().contains("never withdrawn"),
                "I978: {verb} refused by the family rule: {e}"
            );
        }
        check_projection_rebuild(b, SiloProjection::FederationRevocations)
            .await
            .expect("I978: federation_revocations is its rows' rebuild");
    }

    /// I979 — the occurrence plane and its revocation as a `withdraws`.
    pub(crate) async fn i979_occurrences<B: AttestationStore>(b: &B, tag: &str) {
        let id = format!("i979-id-{tag}");
        let occ = format!("i979-occ-{tag}");
        let stranger = format!("i979-stranger-{tag}");
        // v59.0.0 (#1099) — the occurrence is an AGENT key, not a roster key:
        // the identity's withdrawal of it lands at once (the two-key roster
        // rule is held by `self_roster_invariants`).
        for k in [&id, &stranger] {
            ts::register_identity_key(b, k, identity_type::USER).await;
        }
        ts::register_identity_key(b, &occ, identity_type::AGENT).await;
        let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            (chrono::Utc::now() - chrono::Duration::seconds(120)).timestamp_millis(),
        )
        .unwrap();
        b.put_identity_occurrence(ts::signed_content_only_occurrence(&id, &id, &occ, at).await)
            .await
            .expect("I979: the identity's signed occurrence is admitted");
        let rows = rows_of(b.as_dyn_directory(), KeyPlaneFamily::IdentityOccurrence).await;
        assert_eq!(rows.len(), 1, "I979: one identity:occurrence:v1 row");
        assert_eq!(rows[0].attesting_key_id, id, "I979: attested by its signer");
        assert_eq!(rows[0].attested_key_id, id, "I979: about the identity");
        check_projection_rebuild(b, SiloProjection::IdentityOccurrences)
            .await
            .expect("I979: the signed occurrences are their rows' rebuild");
        // A stranger cannot revoke it.
        let e = b
            .put_attestation(
                ts::occurrence_withdrawal(b, &stranger, &id, &occ, chrono::Utc::now()).await,
            )
            .await
            .expect_err("I979: an unrelated key cannot withdraw the occurrence");
        assert_eq!(e.kind(), "federation_signer_not_acting_for", "I979: {e}");
        assert!(b
            .list_identity_occurrence_revocations_for(&id)
            .await
            .unwrap()
            .is_empty());
        // The identity can.
        b.put_attestation(ts::occurrence_withdrawal(b, &id, &id, &occ, chrono::Utc::now()).await)
            .await
            .expect("I979: the identity withdraws its occurrence");
        let revs = b
            .list_identity_occurrence_revocations_for(&id)
            .await
            .unwrap();
        assert_eq!(revs.len(), 1, "I979: the withdrawal fed the projection");
        assert_eq!(revs[0].occurrence_key_id, occ);
    }
}

#[cfg(test)]
mod run {
    use super::bodies;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::federation::FederationDirectory;
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use crate::store::Backend as _;

    fn tag(n: &str) -> String {
        format!("{n}-{}", uuid::Uuid::new_v4().simple())
    }

    // ── memory ─────────────────────────────────────────────────────────
    #[tokio::test(flavor = "multi_thread")]
    async fn i975_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        bodies::i975_key_records_are_rows(&b, &tag("i975m")).await;
        bodies::i975_red_on_a_key_without_a_row(&b, &tag("i975m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i976_memory() {
        let (a, f) = (
            crate::store::memory::MemoryBackend::new(),
            crate::store::memory::MemoryBackend::new(),
        );
        bodies::i976_proof_of_possession(&a, &f, &tag("i976m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i977_memory() {
        let (a, f) = (
            crate::store::memory::MemoryBackend::new(),
            crate::store::memory::MemoryBackend::new(),
        );
        bodies::i977_order_rule(&a, &f, &tag("i977m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i978_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        bodies::i978_revocations(&b, &tag("i978m")).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn i979_memory() {
        let b = crate::store::memory::MemoryBackend::new();
        bodies::i979_occurrences(&b, &tag("i979m")).await;
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
    async fn i975_sqlite() {
        let b = sqlite().await;
        let t = tag("i975s");
        bodies::i975_key_records_are_rows(&b, &t).await;
        // RED: one column of one live projection row moved.
        b.test_execute(&format!(
            "UPDATE federation_keys SET identity_ref = 'tampered' WHERE key_id = 'i975-k1-{t}'"
        ))
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::FederationKeys)
                .await
                .is_err(),
            "I975 sqlite: a moved column is red"
        );
        let b = sqlite().await;
        bodies::i975_key_records_are_rows(&b, &t).await;
        bodies::i975_red_on_a_key_without_a_row(&b, &t).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i976_sqlite() {
        bodies::i976_proof_of_possession(&sqlite().await, &sqlite().await, &tag("i976s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i977_sqlite() {
        bodies::i977_order_rule(&sqlite().await, &sqlite().await, &tag("i977s")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i978_sqlite() {
        let b = sqlite().await;
        bodies::i978_revocations(&b, &tag("i978s")).await;
        b.test_execute("UPDATE federation_revocations SET reason = 'tampered'")
            .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::FederationRevocations)
                .await
                .is_err(),
            "I978 sqlite: a moved column is red"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i979_sqlite() {
        let b = sqlite().await;
        bodies::i979_occurrences(&b, &tag("i979s")).await;
        b.test_execute(
            "UPDATE federation_identity_occurrences SET hardware_attestation = 'tampered'",
        )
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::IdentityOccurrences)
                .await
                .is_err(),
            "I979 sqlite: a moved column is red"
        );
    }

    /// I980 — the rehome on sqlite: a pre-V198 state (rows deleted, pointers
    /// NULL) on a file database, reopened by a fresh backend. v59.0.0
    /// (sealed-transport floor): the rehome is EAGER, at open — the provable
    /// record has its row before any write.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i980_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("i980.db").to_string_lossy().to_string();
        let t = tag("i980s");
        let (k, unsigned) = (format!("i980-k-{t}"), format!("i980-unsigned-{t}"));
        let scrub_ts = {
            let b = crate::store::sqlite::SqliteBackend::open(path.clone())
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            b.put_public_key(crate::federation::SignedKeyRecord {
                record: bodies::pop_record(&k),
            })
            .await
            .unwrap();
            crate::federation::tier_ingest::test_support::register_hybrid_key(&b, &unsigned).await;
            // As a v57 node left it: no row, no pointer.
            b.test_execute(
                "UPDATE federation_keys SET attestation_id = NULL; \
                 DELETE FROM federation_attestations WHERE dimension = 'key:record:v1'",
            )
            .await;
            FederationDirectory::lookup_public_key(&b, &k)
                .await
                .unwrap()
                .unwrap()
                .scrub_timestamp
        };
        let b = crate::store::sqlite::SqliteBackend::open(path)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        // v59.0.0 — no write in between: the open rehomed it.
        let row = bodies::key_row(b.as_dyn_directory(), &k)
            .await
            .expect("I980: the provable legacy record is rehomed at open");
        assert_eq!(
            row.asserted_at,
            crate::federation::admission::truncate_to_substrate_resolution(scrub_ts),
            "I980: at the record's own instant"
        );
        assert!(bodies::key_row(b.as_dyn_directory(), &unsigned)
            .await
            .is_none());
        let red = check_projection_rebuild(&b, SiloProjection::FederationKeys)
            .await
            .expect_err("I980: the unprovable legacy key is named");
        assert!(red.to_string().contains("federation_keys"), "I980: {red}");
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
    async fn i975_postgres() {
        let Some(b) = postgres().await else { return };
        let t = tag("i975p");
        bodies::i975_key_records_are_rows(&b, &t).await;
        b.test_execute(&format!(
            "UPDATE cirislens.federation_keys SET identity_ref = 'tampered' \
             WHERE key_id = 'i975-k1-{t}'"
        ))
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::FederationKeys)
                .await
                .is_err(),
            "I975 postgres: a moved column is red"
        );
        let Some(b) = postgres().await else { return };
        bodies::i975_key_records_are_rows(&b, &t).await;
        bodies::i975_red_on_a_key_without_a_row(&b, &t).await;
        eprintln!("i975_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i976_postgres() {
        let (Some(a), Some(f)) = (postgres().await, postgres().await) else {
            return;
        };
        bodies::i976_proof_of_possession(&a, &f, &tag("i976p")).await;
        eprintln!("i976_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i977_postgres() {
        let (Some(a), Some(f)) = (postgres().await, postgres().await) else {
            return;
        };
        bodies::i977_order_rule(&a, &f, &tag("i977p")).await;
        eprintln!("i977_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i978_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i978_revocations(&b, &tag("i978p")).await;
        b.test_execute("UPDATE cirislens.federation_revocations SET reason = 'tampered'")
            .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::FederationRevocations)
                .await
                .is_err(),
            "I978 postgres: a moved column is red"
        );
        eprintln!("i978_postgres: RAN");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i979_postgres() {
        let Some(b) = postgres().await else { return };
        bodies::i979_occurrences(&b, &tag("i979p")).await;
        b.test_execute(
            "UPDATE cirislens.federation_identity_occurrences SET hardware_attestation = 'tampered'",
        )
        .await;
        assert!(
            check_projection_rebuild(&b, SiloProjection::IdentityOccurrences)
                .await
                .is_err(),
            "I979 postgres: a moved column is red"
        );
        eprintln!("i979_postgres: RAN");
    }

    /// I980 on postgres: the pre-V198 state on the same database, read by a
    /// fresh backend; v59.0.0, rehomed at open.
    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i980_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let t = tag("i980p");
        let (k, unsigned) = (format!("i980-k-{t}"), format!("i980-unsigned-{t}"));
        let scrub_ts = {
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            b.put_public_key(crate::federation::SignedKeyRecord {
                record: bodies::pop_record(&k),
            })
            .await
            .unwrap();
            crate::federation::tier_ingest::test_support::register_hybrid_key(&b, &unsigned).await;
            b.test_execute(
                "UPDATE cirislens.federation_keys SET attestation_id = NULL; \
                 DELETE FROM cirislens.federation_attestations WHERE dimension = 'key:record:v1'",
            )
            .await;
            FederationDirectory::lookup_public_key(&b, &k)
                .await
                .unwrap()
                .unwrap()
                .scrub_timestamp
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        // v59.0.0 — no write in between: the open rehomed it.
        let row = bodies::key_row(b.as_dyn_directory(), &k)
            .await
            .expect("I980: the provable legacy record is rehomed at open");
        assert_eq!(
            row.asserted_at,
            crate::federation::admission::truncate_to_substrate_resolution(scrub_ts),
            "I980: at the record's own instant"
        );
        assert!(bodies::key_row(b.as_dyn_directory(), &unsigned)
            .await
            .is_none());
        assert!(check_projection_rebuild(&b, SiloProjection::FederationKeys)
            .await
            .is_err());
        eprintln!("i980_postgres: RAN");
    }
}
