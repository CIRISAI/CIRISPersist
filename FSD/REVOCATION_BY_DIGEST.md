# Revocation by digest — the subject without its label (CIRISPersist#784, v52.0.0)

## 1. The problem

`key_id = <label>-<fingerprint>` (`ciris_verify_core::fedcode::derive_key_id`): the label is the holder's keystore alias in cleartext. A revocation that names a `key_id` replicates federation-wide and publishes that label to every node, with no directory body needed. Federation-tier identity promotion makes those rows travel further still.

## 2. The identifier

`federation::key_digest::Sha256Ed25519Raw`: SHA-256 over the **raw 32-byte Ed25519 public key**, spelled as exactly 64 lowercase hex digits. It is the digest `derive_key_id` truncates into its suffix. It is stable for the life of the key, carries no label, and makes evasion cost a new key. There is one preimage: nothing hashes base64 text. The old text-digest helper is renamed `sha256_of_pubkey_base64_text` and serves only as a rotation-collision diagnostic.

SQL: postgres `encode(sha256(decode(pubkey_ed25519_base64,'base64')),'hex')`; sqlite `ciris_sha256_ed25519_raw(pubkey_ed25519_base64)`, a deterministic function registered on every backend connection and used in queries only, never in a migration file (migrations must run on a bare connection).

## 3. The revocation plane

| Member | Rule |
|---|---|
| `revoked_key_sha256_ed25519_raw` | REQUIRED, bound, the subject. Malformed → `revocation_subject_digest_malformed`. |
| `revoked_key_id` | OPTIONAL, bound (`null` when absent). If present: held here, same digest; else `revocation_subject_digest_mismatch` / `revocation_subject_unresolved` (retryable). |

The binding (`admission::revocation_binding`) has 8 members. The check is `admission::check_revocation_subject`, inside `tier_ingest::verify_revocation_admission`, which every backend's put and apply share.

**D1 — digest-only, unheld subject: ADMITTED.** Authority is the revoker's (slash conferral, or self). The row bites when a key with that digest is held. This relaxes V004's FK invariant; V163 drops the FK.

**Self-revocation** is recognised by digest: the revoker's held key digests to the subject.

## 4. Readers

- `revocations_for(key_id)` (provided) → the held key's digest → `revocations_for_subject(digest)` (per backend). An unheld key returns none.
- Anti-rollback floor and ceiling: per subject digest.
- Wire index locator: `(revoked_key_sha256_ed25519_raw, revocation_id)`.
- Key listing `revoked` filter, read-API `revoked_key_id` filter, key deletion: digest via SQL.
- `register::fold_key_statement_standing(key_id, subject, …)` / `resolve_key_statement_standing`.

## 5. Migration V163

- **Postgres:** drop the FK and NOT NULL on `revoked_key_id`; add the column; backfill by join; `SET NOT NULL`; shape CHECK; index `(digest, effective_at DESC)`.
- **SQLite:** staged rebuild under the final name (V141 recipe, `federation_revocation_quorum_state` staged); the column is NULLable. `SqliteBackend::backfill_revocation_subject_digests` runs at open, after migrations and before any read, and REFUSES the open if a row stays NULL. Declared in `schema_parity::NULLABILITY_DIVERGENCES`.

## 6. Moderation (D2, additive)

`moderation:*` scores may carry `subject_sha256_ed25519_raw`. `admission::moderation_subject_digest` is the one reading. A present malformed value is refused in `check_delegated_duty_scores_admission`. Label-bearing rows are not refused in v52.

## 7. Deliberately not changed

Room-roster removal rows (`removed_identity_key_id`, community and family) reach exactly the holders of a roster that lists every member's `key_id`. Digest-addressing them hides nothing from their audience. That waits for label-free rosters.

## 8. Witnesses

I220–I227 and I229 (see CHANGELOG [52.0.0] `### #784`). I228 is reserved for the de-admission planes.
