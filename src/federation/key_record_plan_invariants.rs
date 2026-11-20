//! v60.0.0 (CIRISPersist#934 step 3; CC 3.1.3, CC 3.4.7.1–3) — **I1183–I1191:
//! the key-record write doors decide in ONE plan
//! (`key_plane::plan_key_record_write`), and every backend stores exactly the
//! plan's verdict through its one executor
//! (`KeyPlaneStore::store_planned_key_record`).**
//!
//! Each body runs on memory, sqlite and postgres, so a mutation of the
//! shared plan is red on every backend, and a mutation of one backend's
//! executor is red on that backend.
//!
//! - **I1183 (the insert door)** — a fresh record lands with its
//!   `key:record:v1` row and a self-consistent `persist_row_hash`; an
//!   identical re-offer settles (same row); a differing one is `Conflict` and
//!   the held record does not move; a non-hybrid algorithm, a non-hex content
//!   hash and an unknown `consent_role` are refused and nothing is stored;
//!   the stored-form `'unregistered'` is the wire `None` (the hash is over
//!   what the read surface returns); CC 3.4.7.3 Clause A refuses a fused
//!   `node` key at a local mint.
//! - **I1184 (the genesis seed)** — a baked record lands with its row and its
//!   whole scrub set (`additional_scrubs`); a second seed of the same
//!   `key_id` keeps the held record; a non-hybrid or fused record is refused.
//! - **I1185 (the scrub upgrade)** — a self-signed row is re-rooted to the
//!   anchor-scrubbed record (its row follows, `consent_role` is kept); the
//!   same record again is `AlreadyAdopted`; a differing anchored record, a
//!   self-signed incoming record, a pubkey change, an absent row, a fused
//!   record and a `node` move are each refused, and the held record does not
//!   move.
//! - **I1186 (the replicated apply)** — a first sight is `Inserted`, a
//!   re-offer `Unchanged`, an anchored record over a self-signed row
//!   `Upgraded` (memory included, v60), and a fused `node` key minted
//!   elsewhere is admitted (Clause A gates minting only).
//! - **I1187 (the executor's atomic re-assertion)** — a plan made against a
//!   row that changed before the write stores nothing and is refused with
//!   the plan's wording, for every write shape: the upgrade's self-signed
//!   guard, the supersede's anchored-version guard, the replace's hash guard (and no history row), the hybrid
//!   completion's not-yet-complete guard, the scrub rehydrate's empty-set
//!   guard; an insert over a differing held row is `Conflict`, over an
//!   identical one, it stands.
//! - **I1189** — deleted in v62.0.0 (json-cut C5) with the bundle/1 re-anchor
//!   door it witnessed.
//! - **I1190 (the canonical supersede's own decisions)** — over an anchored
//!   incumbent (the #656 fixture): a byte-identical re-offer settles before
//!   any verify (`Unchanged`); a successor whose ML-DSA key alone differs is
//!   the pubkey-change refusal; a successor the supersede policy refuses
//!   (not canonical-scoped, its signed `valid_from` older) is `Conflict`
//!   naming the policy; nothing moves.
//! - **I1191** — deleted in v62.0.0 (json-cut C5) with the bundle/1 bake door.
//! - **I1188 (the row step, unit)** — `key_record_row_step` keeps a row the
//!   pointer already names, replaces any other, and drops the rows of an
//!   unverifiable or absent record; `PlannedKeyRecord::raced` /
//!   `insert_held` word every lost race the way the three backends did.
//!
//! v62.0.0 (JSON cut, E7; accepted by the coordinator) — I1183, I1184,
//! I1185, I1186, I1187, I1189, I1190 and I1191 are deleted with the JSON key
//! plan: an edition-2 key never reaches `plan_key_record_write` (it is
//! projected by `edition2::projection`), and `put_public_key` of a JSON
//! `SignedKeyRecord` is a shut door. Only I1188 (the pure row step) remains,
//! for F0 to delete with `key_record_row_step`.

#[cfg(test)]
mod unit {
    use crate::federation::key_plane::{
        key_record_row_step, KeyRecordRowStep, OnHeld, PlannedKeyRecord, RewriteGuard,
    };
    use crate::federation::key_plane_invariants::pure::pop_record;
    use crate::federation::types::{compute_persist_row_hash, KeyRecord, KeyReplacementKind};
    use crate::federation::Error;

    fn hashed(key_id: &str) -> KeyRecord {
        let mut r = pop_record(key_id);
        r.persist_row_hash = compute_persist_row_hash(&r).unwrap();
        r
    }

    /// I1188 — the row step.
    #[test]
    fn i1188_the_row_step() {
        let r = hashed("i1188-row-step-key-aaaaaaaaaaaaaaaa");
        let KeyRecordRowStep::Replace(Some(row)) = key_record_row_step(Some(&r), None, &None)
        else {
            panic!("I1188: a record that proves possession plans its row");
        };
        assert_eq!(
            key_record_row_step(Some(&r), Some(&row.attestation_id), &None),
            KeyRecordRowStep::Keep,
            "I1188: the pointer already names it"
        );
        assert_eq!(
            key_record_row_step(Some(&r), Some("another-row"), &None),
            KeyRecordRowStep::Replace(Some(row)),
            "I1188: any other row is replaced"
        );
        assert_eq!(
            key_record_row_step(None, Some("a-gone-key's-row"), &None),
            KeyRecordRowStep::Replace(None),
            "I1188: a gone key's rows leave"
        );
        let mut forged = r.clone();
        forged.scrub_key_id = "i1188-unheld-signer-bbbbbbbbbbbbbbbb".to_owned();
        assert_eq!(
            key_record_row_step(Some(&forged), Some("its-old-row"), &None),
            KeyRecordRowStep::Replace(None),
            "I1188: an unverifiable record is held without a row"
        );
    }

    /// I1188 — every lost race in the plan's one wording.
    #[test]
    fn i1188_the_race_wording() {
        let r = hashed("i1188-race-wording-key-cccccccccccc");
        let rewrite = |guard| PlannedKeyRecord::Rewrite {
            record: r.clone(),
            guard,
        };
        let conflict = |p: &PlannedKeyRecord, needle: &str| match p.raced(0) {
            Some(Error::Conflict(m)) => {
                assert!(m.contains(needle) && m.contains(&r.key_id), "I1188: {m}")
            }
            o => panic!("I1188: {needle}: Conflict, got {o:?}"),
        };
        let shapes = [
            (rewrite(RewriteGuard::SelfSigned), "adopt_scrub_upgrade"),
            (
                rewrite(RewriteGuard::Anchored {
                    prior_hash: "h".to_owned(),
                }),
                "supersede_canonical_record",
            ),
            (
                PlannedKeyRecord::Replace {
                    record: r.clone(),
                    existing_hash: "h".to_owned(),
                    kind: KeyReplacementKind::Rebind,
                },
                "rebind key registration",
            ),
            (
                PlannedKeyRecord::RehydrateScrubs { record: r.clone() },
                "rehydrate_dropped_key_scrubs",
            ),
        ];
        for (p, needle) in &shapes {
            conflict(p, needle);
            assert!(p.raced(1).is_none(), "I1188: {needle}: one row landed");
            assert!(p.raced(2).is_none(), "I1188: {needle}: rows landed");
        }
        let insert = |on_held| PlannedKeyRecord::Insert {
            record: r.clone(),
            on_held,
        };
        assert!(insert(OnHeld::Conflict).raced(0).is_none());
        assert!(insert(OnHeld::Conflict).insert_held(None).is_ok());
        assert!(insert(OnHeld::Conflict)
            .insert_held(Some(&r.persist_row_hash))
            .is_ok());
        assert!(matches!(
            insert(OnHeld::Conflict).insert_held(Some("other")),
            Err(Error::Conflict(m)) if m.contains("different content")
        ));
        for p in shapes.iter().map(|(p, _)| p) {
            assert!(p.insert_held(Some("other")).is_ok(), "I1188: not an insert");
        }
    }
}
