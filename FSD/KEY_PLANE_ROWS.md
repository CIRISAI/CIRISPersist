# The key plane as rows: id domains and admission rules

Status: shipped in v58.0.0 (CIRISPersist#991, CC 3.1.3 / 3.3.6 / 2.4.1.1,
`CLM-planes-as-rows`); carrier added in v59.0.0 (CIRISPersist#1104, CC 3.1.5
rc9 `c901645`, `CLM-occurrence-revocation-carrier`). Code:
`src/federation/key_plane.rs`, `src/federation/occurrence_revocation_carrier.rs`.

This page is for a second implementation. It must derive the same row ids and
reach the same admission verdicts as persist.

## The minted row

Persist mints each key-plane row from a signed object it has verified.
Producers do not sign rows.

| member | value |
|---|---|
| `attestation_type` | `scores` |
| `tier`, `cohort_scope` | `federation`, `federation` (global reach: no consent gate, no subject pull) |
| `weight`, `expires_at`, `subject_key_ids` | absent / empty |
| envelope | `{dimension, score, confidence: 1, <member>: object}`, plus the signed-instant row mirror |
| signature columns | the object's own signature (`scrub_key_id`, `scrub_signature_classical`, `scrub_signature_pqc`, `scrub_timestamp`, `pqc_completed_at`) |
| `attestation_id` | the first 16 bytes of `sha256(domain ‖ JCS(object))`, rendered as a UUID |

A receiver re-derives the row from the object the row carries. It refuses any
column that differs, as `federation_malformed_row` / `typed_diverges_from_envelope`.

## Families

| dimension | member | score | id domain | attester | admitted when |
|---|---|---|---|---|---|
| `key:record:v1` | `key_record` | +1 | `ciris:key:record:v1:` | the key | proof of possession over the registration envelope (and, from v59, the key id ends in `-<fp>`, CC 2.6.8) |
| `key:revocation:v1` | `revocation` | −1 | `ciris:key:revocation:v1:` | the revoker | hybrid signature over the revocation envelope; never withdrawn |
| `identity:occurrence:v1` | `identity_occurrence` | +1 | `ciris:identity:occurrence:v1:` | the occurrence's signer | `signer_acts_for` (for a user self, the two-path roster door, CC 3.3.6.3) |
| `identity:occurrence_revocation:v1` | `occurrence_revocation` | −1 | `ciris:identity:occurrence_revocation:v1:` | the revoker | the structural rule below; never withdrawn |

## `identity:occurrence_revocation:v1`: the carrier of a legacy revocation

The carrier gives a replicable row to a framed occurrence revocation signed
before v59. On a v59 node such a revocation is a local `legacy_framed`
projection row (V200).

- **Object**: `{attesting_key_id, signed_envelope, signature}`.
  - `signed_envelope` is the exact envelope the revoker signed. It holds
    `attesting_key_id`, `identity_key_id`, `occurrence_key_id`, `revoked_at`
    and `effective_at`.
  - `signature` is the detached hybrid signature over `JCS(signed_envelope)`:
    Ed25519, then ML-DSA-65 over `bytes ‖ ed25519_sig`.
- **Row**: attester = the revoker; attested = `identity_key_id`.
  - The signature columns are the object's signature. Its instant is
    `revoked_at`.
  - `attestation_id = uuid(sha256("ciris:identity:occurrence_revocation:v1:" ‖ JCS(object))[..16])`.
- **Cosignatures**: `additional_scrubs` is the one member outside the
  derivation. Each entry is a hybrid signature by a roster key over
  `JCS(row envelope)`.
- **Admission is structural and never reads an instant.** The object's
  instant is chosen by the signer, so "signed before the door" cannot be
  verified. A thief could backdate.
  1. The object's hybrid signature verifies against the revoker's held keys,
     and the revoker acts for the identity now (`signer_acts_for`).
  2. **(A)** The identity is a `node` or `agent`: admitted.
  3. **(B)** Otherwise (a user self): admitted only when the revoker (if it is
     on the roster) and the valid cosigners together make up
     `strict_majority(|roster|)` of the self's **current live roster**. The
     live roster is the genesis key unless evicted, plus the active user-role
     occurrences. Below that, the carrier is refused as
     `federation_malformed_row` / `carrier_without_roster_quorum`.
- **Effect**: an admitted carrier projects the revocation, as a `withdraws`
  of the occurrence row does. It replicates as an ordinary row.
- **Migration (open)**: each held `legacy_framed` row is offered as its
  carrier.
  - The admitted ones are counted.
  - A user self's revocation without a quorum stays a local legacy row. The
    open's count line names it by `(identity, occurrence)`, so its owner can
    re-propose it through the two-path door.

## The one predicate

`key_plane::occurrence_revoked_by(dir, row) -> Option<(identity, occurrence)>`
answers whether a row revokes an occurrence, and which one. It recognises both
a `withdraws` whose target is a held `identity:occurrence:v1` row and a
carrier. Whether the row is *admitted* is decided by the door.
