# Brief: project edition-2 keys and revocations into the earlier store (from slice E2a)

**Goal.** Project each verified edition-2 key into `federation_keys`, and each edition-2 revocation into `federation_revocations`, as read models. Refuse cross-form standing by name. The edition-2 gates keep reading `HeldKeys`, never the projection.

**Depends on E2b's columns** on `federation_keys`: `edition SMALLINT NOT NULL DEFAULT 1`, `record_row_id` (32 bytes), `kid` (32 bytes). E2b also restores the two signer FKs on `federation_attestations`.

## Order of work

1. **The projection** (`edition2::ingest`, new `project_key(dir, kid)`):
   - Re-derive from `held_keys_for` plus `HeldKeys::liveness`.
   - Columns:
     - `key_id` = identity-ref;
     - pubkeys = the composite split (ML-DSA-65 1952 B, Ed25519 32 B);
     - `identity_type` = the comma-joined set;
     - `valid_from` = the record's `asserted_at`, `valid_until` = the greatest covering end;
     - `registration_envelope` = projection plus statement;
     - `scrub_signature_classical` = composite in base64;
     - `edition` = 2, `record_row_id`, `kid`;
     - `attestation_evidence` = the payload's `{hardware_class, pq_custody, chain}` as JSON, chain as hex DER, leaf first.
   - Write with an upsert through the unchecked executor. Today `put_public_key` errors on a changed record, so add `upsert_edition2_key_projection` to `FederationDirectory`, implemented in `store/sqlite.rs` (use `write_tx`) and `store/postgres.rs`.
   - Call it from `put_statement` after every `key:record` or `key:revocation`.
   - Register the new fns in `SQLITE_CONN_CLASSES` and `parity::CALL_CLASSES`.
2. **The revocation read model.**
   - Project each `key:revocation` that `HeldKeys::revoked` honours (the key itself, or `RevokerStanding`) into `federation_revocations`: `revoked_key_id` = identity-ref; `revoked_key_sha256_ed25519_raw` from the Ed25519 half; `effective_at` = `revoked_after`, or the revocation's `asserted_at` when absent.
   - Write through an unchecked insert executor, not `put_revocation`, whose JSON verify would refuse.
   - About 30 readers depend on this: `revocations_for` / `revocations_for_subject` in `admission.rs` (10), `register.rs` (4), `key_plane.rs` (2), `wire_index.rs`, `lineage_witness.rs`, `migration.rs`, `directory_double.rs`, `envelope_bytes.rs`, `mod.rs`, `ffi/pyo3.rs` (2), `ffi/directory_capsule.rs` (2), and the backends (sqlite 7, postgres 4). Don't fork the fold: the projection must be what those readers see.
3. **The cross-form refusal** `earlier_form_signer_is_edition2` (a new `malformed_row` reason, appended to `ALL`). Refuse any earlier-form verification whose signer's row has `edition = 2`, at these choke points:
   - `tier_ingest::verify_row_hybrid_signature`, after the carried arm;
   - `register::verify_key_registration` and `verify_registration_signature`;
   - `key_plane::verify_plane_row`, `group_plane::verify_plane_row`, `self_roster::verify_proposal_row`, `cosign::verify_row`, `occurrence_revocation_carrier::verify_carrier_row`;
   - `admission::verify_consent_record_transit_ingest`.
4. **Remove** the TODO(baseline-merge) FK-drop emulation in `edition2/ingest_invariants.rs` once the FKs are restored.

## Witness classes, both backends

1. **Projection equals reading.** After record, renewal, renewal-after-end and revocation, `lookup_public_key(iref)` matches `HeldKeys::liveness`: `valid_until` is the greatest end, and the revoked state is reflected.
2. **The FK holds.** An edition-2 row inserts with the signer FK restored; a stranger's row still fails the FK.
3. **Cross-form refusal.** A JSON row signed with an edition-2 key's material is refused `earlier_form_signer_is_edition2` at each choke point. Mutation-test each site.
4. **Revocation readers.** An edition-2 self-revocation is seen by `revocations_for`, the key-plane read, an attestation gate's revoked check, and an owner/steward check (one per reader class).
5. **Revocation authority.** A stranger's `key:revocation` projects nothing; an owner's projects only with `RevokerStanding`.
6. **One fold.** The edition-2 gates never read the projection: corrupt the projected `valid_until` in a test, and edition-2 admission is unchanged.
7. **Idempotence and re-derivation.** Re-putting a record or revocation leaves a byte-identical projection; a renewal re-projects it.
