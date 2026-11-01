# The signed instant form (CC 2.6.2)

**Normative anchors:** CC **2.6.2** (every signed datetime is `YYYY-MM-DDTHH:MM:SS.sssZ`: literal uppercase `Z`, exactly three fractional digits; producers MUST emit it, consumers MUST reject any other form when verifying a signature), CC **2.6.1.7** (the signed object's member table: which members are `rfc3339-ms`), CC **2.4.1.1** (the key revocation envelope binds `revoked_at`, `effective_at`, `scrub_timestamp`, `revoked_after`), CC **3.2 T3** and **6.1.7** (a revocation the holder keeps stays in force).

**The steward's ruling (v61):** only the canonical form verifies. There is no cut-over instant and no normalising reader. A row another producer signed over another form is refused at read. A revocation refused for its form alone never un-revokes. Persist re-signs the rows its own node key signed.

---

## 1. The predicate

`admission::signed_instant_form_violation(row)` is the one predicate. It reads the attestation envelope's `rfc3339-ms` members from CC 2.6.1.7 (`admission::SIGNED_INSTANT_MEMBERS`):

| member | placement |
|---|---|
| `asserted_at`, `expires_at`, `widened_at` | signed:envelope |
| `valid_until`, `claimed_at`, `delegation_valid_from`, `delegation_valid_until`, `window_from`, `window_to` | signed:envelope-extra |
| `additional_scrubs[].cosigned_at` | beside:cosign |

When one of them is present as a string and is not exactly `.sssZ` (validated by `verify::canonical_validation::validate_canonical_datetime`), the predicate names the member and the value. The list is typed: an envelope also carries nested signed objects (`group_record`, `revocation`, `widening`) whose own bytes this rule must not judge, and free-text members whose content is not an instant.

## 2. Admission

| door | refusal |
|---|---|
| every attestation door: put, replication, the mint, promotion (`check_envelope_member_shapes`) | `federation_malformed_row` / `envelope_member_invalid`, naming the member |
| the local write (`plan_write_local_attestation`) | the same |
| the key revocation envelope (`check_revocation_envelope_binding`): `revoked_at`, `effective_at`, `scrub_timestamp` compared as the canonical render, and a column finer than a millisecond refused | `RevocationEnvelopeUnbound` naming the member |
| `revoked_after` (`check_revocation_bound`) | `RevocationBoundRefusal::BoundNotRfc3339` |
| the key record's signed `valid_until` (`verify_envelope_binds_subject`), compared as bytes against the canonical render | the binding refusal, naming the form |
| the identity occurrence's `asserted_at` / `valid_until` (`same_instant_ms`) | the occurrence's divergence refusal |
| the signed transport destination's `asserted_at` / `retired_at` | `envelope_member_invalid` |
| the touch claim's `fresh_as_of` | `envelope_member_invalid` |

CC's `refuse_timestamp_form` signed-object vector is refused `envelope_member_invalid` on both backends (I1494).

## 3. Stored rows: the open-time pass

`federation::instant_form::run_pass`, called by every `Engine` constructor that opens a store (`settle_instant_forms_at_boot`), reads the whole attestation corpus (every tier, keyset on `attestation_id`) and settles each row the predicate refuses:

| the row | disposition |
|---|---|
| signed by this node's key; `scores`, `delegates_to` or `supersedes`; federation tier; no co-signatures; not expired | **re-stated**: a `supersedes` of it through the ordinary emit door, every instant re-rendered `.sssZ` (the same instant at the millisecond), `references_attestation_id` naming it, the claim's own `asserted_at` kept so a family window measured from it holds. The original stays where it is: its successor cites it. |
| signed by this node's key, any other case (a composer, a co-signed row, a local-tier row, an expired row) | left where it is, counted `own_left` |
| signed by another producer, and it takes something away: every structural composer, every `delegates_to` (the exclusion acts hang off the delegation plane), `revocation:*`, `quarantine:*`, `moderation:*`, `reconsideration:*`, `slashing:*`, `objection:*`, the accountability record (`key:revocation`, `moderation_track_record:*`, `hard_case:*`), an unreadable dimension, `membership:removal:*`, `membership:resignation:*`, `consent:state:revoked` (`instant_form::keeps_force`) | **kept in force** where it is |
| signed by another producer, any other row | **refused at read**: its projections removed and the row removed, and the refusal recorded in the ledger `federation_attestations_form_refused` (V211: id, attester, row hash, member, value, instant; no row body). Every read path refuses it by absence on both backends, nothing serves it onward, and no copy of its content is kept where an erasure door cannot reach it. A peer that offers it again is refused at admission. |

The pass is idempotent: a re-stated row already has a `supersedes` by this node naming it (`already_healed`), and a refused row is no longer in `federation_attestations`. A refusal at the emit door is counted (`heal_refused`), logged, and retried at the next open. The pass never aborts a boot. `Engine::settle_instant_forms` returns the counts.

The key plane's revocations are never re-judged once held: a revocation this node stores stays in force. Its peers refuse a re-offer in another form.

## 4. Preimages

Every signed preimage persist builds or verifies that carries an instant, in three classes.

**A. CC objects.** CC specifies the bytes. Persist emits the canonical form and verifies only the canonical form.

| preimage | instants | v61 |
|---|---|---|
| attestation envelope, JCS (CC 2.6.1.7) | the §1 members | minted `.sssZ` (`render_signed_instant`); refused otherwise |
| key revocation `revocation_envelope` (CC 2.4.1.1) | `revoked_at`, `effective_at`, `scrub_timestamp`, `revoked_after` | `bind_revocation_into_envelope` renders `.sssZ`; the binding compares the canonical render |
| key record `registration_envelope` | `valid_until` (the signed twin) | bound `.sssZ` by `register_self_federation_key` and the rebind door |
| identity occurrence and signed transport destination envelopes | `asserted_at`, `valid_until`, `retired_at` | persist's producer renders `.sssZ`; the doors refuse any other form |

**B. Persist-own domain preimages.** Persist names the domain. The canonical form is a new domain; the old one still verifies as itself.

| preimage | v1 | v2 (minted from v61) |
|---|---|---|
| trust grant, `admission::trust_grant_signing_bytes` | `ciris.trust.grant.v1`: `grant.expires_at` as serde writes it | `ciris.trust.grant.v2`: `expires_at` `.sssZ`, a sub-millisecond instant refused |
| trust revocation, `admission::trust_revocation_signing_bytes` | `ciris.trust.revocation.v1`: `revoked_at` with six fractional digits | `ciris.trust.revocation.v2`: `revoked_at` `.sssZ`, a sub-millisecond instant refused |
| trace scrub signature, `ingest::scrub_preimage` (#690) | no `domain` member; `scrub_timestamp` by `to_rfc3339()` (`scrub_preimage_v1`) | `domain: ciris.scrub_envelope.v2`; `scrub_timestamp` `.sssZ`, truncated to the millisecond before signing |

The two trust doors verify a signature over v2, else over v1 (`verify_trust_plane_signature`). A verifier of a trace scrub signature rebuilds v2 for a v61 envelope and v1 for an older one. The trace scrub preimage is not CC 2.6.1.7's `scrub_signature`: CC rc14 does not name its members.

**C. Envelope copies of an instant persist signs inside another object.** These carry the instant in the canonical form.

| member | where |
|---|---|
| `revoked_after` | the key revocation envelope's copy of the history bound (§2) |
| `valid_until` | `mesh_config_envelope` (`mesh_config:*` rows) |
| `effective_at` | the `hard_case` membership-change detail (added and removed) |
| `amended_at` | the founders' change envelope (`canonical_community::bind_next_version`) |
| `fresh_as_of` | the touch claim's signing envelope |
| a rounded instant | the transform algebra's `round` on an instant |

**Not moved in v61.** These preimages are re-derived by their verifiers from typed fields through serde (chrono's own fractional digits). Changing the rendering in place would break every stored signature, so each needs a new domain and a re-sign, and two touch the baked genesis:

| preimage | instants |
|---|---|
| `signing_envelope()` of Family, Community, the two membership revocations, the two widenings, LocationProof | `founded_at`, `joined_at`, `dissolved_at`, `removed_at`, `effective_at`, `asserted_at`, `valid_until`, `withdrawn_at` |
| `compute_persist_row_hash` (cited inside signed objects: `prev_head_digest`, `charter_digest`, `NEXT_PERSIST_ROW_HASH`, the recovery statement, the lineage cosign head digest) | every serde instant of the row |
| the genesis bundle's `authorization_digest` (CIRISVerify) | `produced_at` and the nested records' instants |
| the audit chain (`canonical_bytes_for_entry`, Merkle leaves) | `recorded_at` |
| cirisnode `PromotionAttestation`; the pipeline's edge signature | `attested_at`; `batch_timestamp`, `consent_timestamp` |
