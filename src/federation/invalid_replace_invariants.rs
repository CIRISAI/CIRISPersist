//! CIRISPersist#1044 (CIRISEdge#858) — witnesses for the `InvalidReplaced`
//! arm: a stored Key row that FAILS `verify_key_registration` is replaced in
//! place by an incoming record with the same pubkeys and the same claim that
//! PASSES it. One body per invariant over `&dyn FederationDirectory`, run by
//! memory, sqlite and postgres; the local `Engine::rebind_key_record` door on
//! sqlite.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::register::{self, KeyRefusalReason, ReplicatedKeyOutcome};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::types::KeyReplacementKind;
    use crate::federation::{Error, FederationDirectory, KeyRecord, SignedKeyRecord};

    pub fn signed(r: KeyRecord) -> SignedKeyRecord {
        SignedKeyRecord { record: r }
    }

    /// A self-signed, subject-bound record for `k` (passes verification).
    pub fn valid(k: &str, nonce: &str) -> KeyRecord {
        ts::replicated_key_record(k, USER, k, k, nonce)
    }

    /// CIRISServer's legacy fallback shape: the registration envelope and its
    /// hash are right (steps 1–4 pass), the scrub signatures cover OTHER bytes
    /// (step 5, the hybrid verify, fails).
    pub fn failing(k: &str, nonce: &str) -> KeyRecord {
        let mut r = valid(k, nonce);
        let other = ts::sign_envelope(k, &serde_json::json!({ "owner_binding": k }));
        r.scrub_signature_classical = other.1;
        r.scrub_signature_pqc = other.2;
        r
    }

    /// Seed `r` through the raw door (as the canonical's fallback did) and
    /// assert it fails verification structurally.
    pub async fn seed_failing(d: &dyn FederationDirectory, r: KeyRecord) -> KeyRecord {
        d.put_public_key(signed(r.clone()))
            .await
            .expect("the raw door stores an unverified row");
        let held = d.lookup_public_key(&r.key_id).await.unwrap().unwrap();
        assert!(
            matches!(
                register::verify_key_registration(d, &held).await,
                Err(Error::SignatureInvalid(_))
            ),
            "precondition: the stored row fails verify_key_registration (hybrid step)"
        );
        held
    }

    /// **I616 — the arm, and every refusal around it.** A stored row that
    /// fails verification is replaced by a passing record with the same
    /// pubkeys and claim (`InvalidReplaced`); the row then verifies, is
    /// re-served past a cursor that had passed it, and the history row names
    /// the replaced row's hash and the kind. A VALID stored row is never
    /// replaced (`conflicting_version`, unchanged — the load-bearing clause);
    /// a different pubkey is `pubkey_swap`; a changed claim is not replaced;
    /// an incoming record that also fails is refused with its own verdict.
    pub async fn i616_invalid_stored_row_is_replaced(d: &dyn FederationDirectory, s: &str) {
        // A VALID stored row: the arm does not fire.
        let kv = format!("i616-v-{s}");
        d.put_public_key(signed(valid(&kv, "a"))).await.unwrap();
        let before_v = d.lookup_public_key(&kv).await.unwrap().unwrap();
        let out = d
            .apply_replicated_key_record(signed(valid(&kv, "b")))
            .await
            .unwrap();
        assert_eq!(
            out,
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::ConflictingVersion
            },
            "I616: a stored row that VERIFIES is never replaced"
        );
        assert_eq!(
            d.lookup_public_key(&kv)
                .await
                .unwrap()
                .unwrap()
                .persist_row_hash,
            before_v.persist_row_hash,
            "I616: the valid row is untouched"
        );
        assert!(d
            .list_key_registration_history(&kv)
            .await
            .unwrap()
            .is_empty());

        // An INVALID stored row.
        let k = format!("i616-k-{s}");
        let held = seed_failing(d, failing(&k, "a")).await;
        let served = crate::federation::key_plane::test_support::served_key_records(
            d.as_dyn_directory(),
            None,
            10_000,
        )
        .await
        .unwrap();
        // v58.0.0 (CIRISPersist#991) — a record that does not verify is held
        // without a `key:record:v1` row: it is not on the plane, so it is not
        // served.
        assert!(
            served.iter().all(|r| r.record.key_id != k),
            "I616: the failing row is held without a row, not served"
        );

        // Different pubkeys: a different identity.
        let mut swap = valid(&k, "b");
        swap.pubkey_ml_dsa_65_base64 = ts::hybrid_pubkeys(&format!("other-{k}")).1;
        assert_eq!(
            d.apply_replicated_key_record(signed(swap)).await.unwrap(),
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::PubkeySwap
            },
            "I616: pubkey swap"
        );
        // A changed claim.
        let changed = ts::replicated_key_record(&k, AGENT, &k, &k, "b");
        let out = d
            .apply_replicated_key_record(signed(changed))
            .await
            .unwrap();
        assert!(
            matches!(out, ReplicatedKeyOutcome::Refused { .. }),
            "I616: a changed claim is not replaced: {out:?}"
        );
        // The incoming record fails too: its own verdict, row untouched.
        assert_eq!(
            d.apply_replicated_key_record(signed(failing(&k, "c")))
                .await
                .unwrap(),
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::UnverifiableSignature
            },
            "I616: an incoming record that also fails is refused"
        );
        assert_eq!(
            d.lookup_public_key(&k)
                .await
                .unwrap()
                .unwrap()
                .persist_row_hash,
            held.persist_row_hash,
            "I616: every refusal leaves the row"
        );

        // The repair: the holder's re-signed registration.
        let out = d
            .apply_replicated_key_record(signed(valid(&k, "d")))
            .await
            .unwrap();
        assert_eq!(out, ReplicatedKeyOutcome::InvalidReplaced, "I616: the arm");
        let after = d.lookup_public_key(&k).await.unwrap().unwrap();
        register::verify_key_registration(d, &after)
            .await
            .expect("I616: the stored row verifies now");
        assert_eq!(after.pubkey_ed25519_base64, held.pubkey_ed25519_base64);
        assert_eq!(after.pubkey_ml_dsa_65_base64, held.pubkey_ml_dsa_65_base64);
        assert_eq!(after.identity_type, held.identity_type);
        assert_eq!(after.valid_from, held.valid_from);
        assert_ne!(after.persist_row_hash, held.persist_row_hash);
        assert!(
            crate::federation::key_plane::test_support::served_key_records(
                d.as_dyn_directory(),
                None,
                10_000
            )
            .await
            .unwrap()
            .iter()
            .any(|r| r.record.key_id == k),
            "I616: the repaired record verifies, so its row is on the plane and served"
        );
        let history = d.list_key_registration_history(&k).await.unwrap();
        assert_eq!(history.len(), 1, "I616: one audit row");
        let h = &history[0];
        assert_eq!(h.replacement, KeyReplacementKind::InvalidReplaced);
        assert_eq!(h.replacement.as_str(), "invalid_replaced");
        assert_eq!(
            h.replaced_row_hash.as_deref(),
            Some(held.persist_row_hash.as_str()),
            "I616: the audit row names the replaced row"
        );
        assert_eq!(h.replaced_by_hash, after.persist_row_hash);
        assert_eq!(h.scrub_signature_classical, held.scrub_signature_classical);
        assert_eq!(h.original_content_hash, held.original_content_hash);

        // Idempotent.
        assert_eq!(
            d.apply_replicated_key_record(signed(valid(&k, "d")))
                .await
                .unwrap(),
            ReplicatedKeyOutcome::Unchanged
        );
        // And now that the row verifies, a further re-signing is first-seen-wins.
        assert_eq!(
            d.apply_replicated_key_record(signed(valid(&k, "e")))
                .await
                .unwrap(),
            ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::ConflictingVersion
            }
        );
        assert_eq!(d.list_key_registration_history(&k).await.unwrap().len(), 1);
    }

    /// **I617 — the store step re-asserts the rule, and the anchored case.**
    /// Called directly, past the plan, the store step refuses a stored row
    /// that VERIFIES (`Conflict`, row untouched). A stored ANCHOR-scrubbed row
    /// that fails (its scrubber known, its signature over other bytes) is
    /// replaced by the holder's self-signed passing record — the case that
    /// read as `downgrade`; the audit row keeps the old scrubber.
    pub async fn i617_store_step_and_anchored_case(d: &dyn FederationDirectory, s: &str) {
        let kv = format!("i617-v-{s}");
        d.put_public_key(signed(valid(&kv, "a"))).await.unwrap();
        let held_v = d.lookup_public_key(&kv).await.unwrap().unwrap();
        let r = d
            .store_invalid_replaced_key_record(signed(valid(&kv, "b")))
            .await;
        assert!(
            matches!(r, Err(Error::Conflict(_))),
            "I617: the store step refuses to replace a row that verifies: {r:?}"
        );
        assert_eq!(
            d.lookup_public_key(&kv)
                .await
                .unwrap()
                .unwrap()
                .persist_row_hash,
            held_v.persist_row_hash
        );

        let anchor = format!("i617-anchor-{s}");
        ts::register_identity_key(d, &anchor, NODE).await;
        let k = format!("i617-k-{s}");
        let mut anchored = ts::replicated_key_record(&k, USER, &anchor, &anchor, "a");
        let other = ts::sign_envelope(&anchor, &serde_json::json!({ "owner_binding": k }));
        anchored.scrub_signature_classical = other.1;
        anchored.scrub_signature_pqc = other.2;
        let held = seed_failing(d, anchored).await;
        assert_eq!(held.scrub_key_id, anchor);
        let out = d
            .apply_replicated_key_record(signed(valid(&k, "b")))
            .await
            .unwrap();
        assert_eq!(
            out,
            ReplicatedKeyOutcome::InvalidReplaced,
            "I617: a failing anchor-scrubbed row is replaced, not a downgrade refusal"
        );
        let after = d.lookup_public_key(&k).await.unwrap().unwrap();
        assert_eq!(after.scrub_key_id, k, "I617: the passing record's scrubber");
        let h = d.list_key_registration_history(&k).await.unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(
            h[0].scrub_key_id, anchor,
            "I617: the audit keeps the old scrubber"
        );
        assert_eq!(h[0].replacement, KeyReplacementKind::InvalidReplaced);
    }

    /// **I618 — the rebind door keeps its kind.** A #864 rebind writes
    /// `replacement = rebind` and the replaced row's hash (V186).
    pub async fn i618_rebind_history_names_its_kind(d: &dyn FederationDirectory, s: &str) {
        let k = format!("i618-k-{s}");
        let legacy = super::super::key_rebind_invariants::bodies::legacy_record(&k, USER);
        d.put_public_key(signed(legacy)).await.unwrap();
        let held = d.lookup_public_key(&k).await.unwrap().unwrap();
        let out = d
            .apply_replicated_key_record(signed(valid(&k, "r1")))
            .await
            .unwrap();
        assert_eq!(out, ReplicatedKeyOutcome::Rebound);
        let h = d.list_key_registration_history(&k).await.unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].replacement, KeyReplacementKind::Rebind);
        assert_eq!(
            h[0].replaced_row_hash.as_deref(),
            Some(held.persist_row_hash.as_str())
        );
    }

    /// **I620 — the replacement's SIGNER.** A failing row scrubbed by anchor
    /// `A`, offered a record with the same pubkeys and claim that a STRANGER
    /// `B` scrubbed (registered, so `verify_key_registration` passes): not
    /// replaced, at the plan and at the store step, and the row is untouched.
    /// The same record re-signed by `A` (the stored scrubber) is replaced.
    pub async fn i620_the_replacement_is_signed_by_the_key_or_its_scrubber(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let a = format!("i620-a-{s}");
        let b = format!("i620-b-{s}");
        ts::register_identity_key(d, &a, NODE).await;
        ts::register_identity_key(d, &b, NODE).await;
        let k = format!("i620-k-{s}");
        let mut stored = ts::replicated_key_record(&k, USER, &a, &a, "a");
        let other = ts::sign_envelope(&a, &serde_json::json!({ "owner_binding": k }));
        stored.scrub_signature_classical = other.1;
        stored.scrub_signature_pqc = other.2;
        let held = seed_failing(d, stored).await;

        let by_stranger = ts::replicated_key_record(&k, USER, &b, &b, "b");
        register::verify_key_registration(d, &by_stranger)
            .await
            .expect("precondition: the stranger's record verifies on its own");
        let out = d
            .apply_replicated_key_record(signed(by_stranger.clone()))
            .await
            .unwrap();
        assert!(
            matches!(out, ReplicatedKeyOutcome::Refused { .. }),
            "I620: a stranger's signature does not replace the row: {out:?}"
        );
        let r = d
            .store_invalid_replaced_key_record(signed(by_stranger))
            .await;
        assert!(
            matches!(r, Err(Error::Conflict(_))),
            "I620: the store step refuses the stranger's signature: {r:?}"
        );
        let now = d.lookup_public_key(&k).await.unwrap().unwrap();
        assert_eq!(
            now.persist_row_hash, held.persist_row_hash,
            "I620: row untouched"
        );
        assert_eq!(
            now.scrub_key_id, a,
            "I620: the stranger is not the scrubber"
        );
        assert!(d
            .list_key_registration_history(&k)
            .await
            .unwrap()
            .is_empty());

        // The stored scrubber re-signs: replaced.
        let by_scrubber = ts::replicated_key_record(&k, USER, &a, &a, "c");
        assert_eq!(
            d.apply_replicated_key_record(signed(by_scrubber))
                .await
                .unwrap(),
            ReplicatedKeyOutcome::InvalidReplaced,
            "I620: the stored scrubber's re-signing replaces the row"
        );
        assert_eq!(
            d.lookup_public_key(&k).await.unwrap().unwrap().scrub_key_id,
            a
        );
    }
}

#[cfg(test)]
mod run {
    pub(super) fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i616() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i616_invalid_stored_row_is_replaced(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i617() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i617_store_step_and_anchored_case(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i618() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i618_rebind_history_names_its_kind(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i620() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i620_the_replacement_is_signed_by_the_key_or_its_scrubber(
                        &b,
                        &super::suffix(),
                    )
                    .await
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
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    /// **I619 — the local door.** `Engine::rebind_key_record` (Python
    /// `rebind_key_record`) runs the same plan: a holder re-signing a record
    /// this node stores but that fails verification gets
    /// `{"outcome":"invalid_replaced"}`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i619_engine_rebind_door_replaces_an_invalid_row() {
        use super::bodies::{failing, seed_failing, valid};
        use crate::federation::register::RebindOutcome;
        use crate::federation::SignedKeyRecord;
        let s = suffix();
        let local =
            crate::federation::tier_ingest::test_support::local_signer(&format!("i619-{s}"));
        let engine = crate::Engine::with_signer_pre_genesis(local, "sqlite::memory:")
            .await
            .unwrap();
        let b = engine.sqlite_backend().unwrap().clone();
        let k = format!("i619-k-{s}");
        seed_failing(b.as_ref(), failing(&k, "a")).await;
        let out = engine
            .rebind_key_record(SignedKeyRecord {
                record: valid(&k, "b"),
            })
            .await
            .unwrap();
        assert_eq!(out, RebindOutcome::InvalidReplaced, "I619");
        assert_eq!(
            serde_json::to_value(out).unwrap(),
            serde_json::json!({ "outcome": "invalid_replaced" })
        );
    }

    /// **I621 — a role-gated row is not this door's.** The predicate refuses a
    /// canonical / infra:attest claim on either side, and a third-party
    /// signer; it admits the key's own signature and the stored scrubber's.
    #[test]
    fn i621_admissibility_predicate() {
        use crate::federation::register::invalid_replace_admissible;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::{CANONICAL, USER};
        let k = "i621-k";
        let stored = ts::replicated_key_record(k, USER, "anchor", "anchor", "a");
        let self_signed = ts::replicated_key_record(k, USER, k, k, "b");
        let by_scrubber = ts::replicated_key_record(k, USER, "anchor", "anchor", "c");
        let by_stranger = ts::replicated_key_record(k, USER, "stranger", "stranger", "d");
        assert_eq!(invalid_replace_admissible(&stored, &self_signed), Ok(()));
        assert_eq!(invalid_replace_admissible(&stored, &by_scrubber), Ok(()));
        assert!(invalid_replace_admissible(&stored, &by_stranger).is_err());
        let canonical = ts::replicated_key_record(k, CANONICAL, "anchor", "anchor", "a");
        let canonical_self = ts::replicated_key_record(k, CANONICAL, k, k, "b");
        assert!(invalid_replace_admissible(&canonical, &canonical_self).is_err());
        let mut attest = stored.clone();
        attest.capability_roles = vec!["infra:attest".to_owned()];
        let mut attest_self = self_signed.clone();
        attest_self.capability_roles = vec!["infra:attest".to_owned()];
        assert!(invalid_replace_admissible(&attest, &attest_self).is_err());
    }

    /// **I621 — through the plan and the store step.** A role-gated row that
    /// fails `verify_key_registration` (seeded past `put_public_key`'s
    /// production-roster gate, which is the only way a test can hold one) is
    /// NOT replaced by the holder's self-signed passing record: the plan's own
    /// refusal stands and the store step is `Conflict`. On sqlite only, through
    /// the below-the-door seed fixture: the clause lives in `register`, which
    /// every backend calls, and no door can hold the row without the
    /// production roster.
    #[tokio::test]
    #[cfg(feature = "sqlite")]
    async fn i621_a_role_gated_row_is_not_replaced() {
        use super::bodies::signed;
        use crate::federation::register::ReplicatedKeyOutcome;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::{CANONICAL, NODE};
        use crate::federation::FederationDirectory as _;
        let d = crate::store::test_backend::test_backend();
        let s = suffix();
        let a = format!("i621-a-{s}");
        ts::register_identity_key(&d, &a, NODE).await;
        let k = format!("i621-k-{s}");
        let mut stored = ts::replicated_key_record(&k, CANONICAL, &a, &a, "a");
        let other = ts::sign_envelope(&a, &serde_json::json!({ "owner_binding": k }));
        stored.scrub_signature_classical = other.1;
        stored.scrub_signature_pqc = other.2;
        d.seed_key_row_unchecked_for_test(stored.clone());
        let held = d.lookup_public_key(&k).await.unwrap().unwrap();
        assert!(
            crate::federation::register::stored_record_fails_verification(&d, &held)
                .await
                .unwrap(),
            "precondition: the stored canonical row fails verify_key_registration"
        );
        let incoming = ts::replicated_key_record(&k, CANONICAL, &k, &k, "b");
        let out = d
            .apply_replicated_key_record(signed(incoming.clone()))
            .await
            .unwrap();
        assert!(
            matches!(out, ReplicatedKeyOutcome::Refused { .. }),
            "I621: a role-gated row is not replaced: {out:?}"
        );
        let r = d.store_invalid_replaced_key_record(signed(incoming)).await;
        assert!(
            matches!(r, Err(crate::federation::Error::Conflict(_))),
            "I621: the store step refuses a role-gated row: {r:?}"
        );
        assert_eq!(
            d.lookup_public_key(&k)
                .await
                .unwrap()
                .unwrap()
                .persist_row_hash,
            held.persist_row_hash
        );
    }
}
