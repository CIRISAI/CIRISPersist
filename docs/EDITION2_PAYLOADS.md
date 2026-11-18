# Edition-2 payload members (persist's reading for CC)

**Status: CC-READING(next-edition).** CC adopted this reading (`FSD/v62_docs/RULINGS.md`, "Families and payloads"): each family's edition-2 payload carries the earlier record's members one to one, in the deterministic encoding (CDE, CC 2.6.1.2), with no embedded signed object. The statements are the authority. What the earlier form carried as a co-signature (a co-scrub, a roster cosignature, a quorum or threshold signature set) is now a further statement over the same payload: a counted voice (CC 2.6.1.9), never a payload member.

The tables below are rendered from `ciris_persist::federation::edition2::payloads::FAMILIES`, the member lists persist's door checks (`payloads::check`, refusal `edition2_payload_invalid`). A witness (I2102) keeps this file equal to them.

## Conventions

- **Common members**, carried by every row and not repeated below (CC 2.6.1.3):
  - `asserted_at`: `uint (ms)`, required;
  - `author`: `identity-ref`, present on an authored family only;
  - `dimension`: `tstr`, the family instance, required where the family id has a parameter (for example `membership:widening:v1` under `membership:{stage}`). A member marked "required when `dimension` is `x`" is required when `x` is a segment of `dimension`;
  - `refs`: a map of `row-ref`s; the roles each family carries are listed as `refs.<role>` rows.
- **Conversions**, everywhere:
  - an instant (RFC 3339 text) becomes `uint (ms)` (CC 2.6.2);
  - a key id becomes an `identity-ref` (CC 2.6.1.1);
  - a reference to a held row (`persist_row_hash`, `attestation_id`, a `*_digest`) becomes a `row-ref` under `refs`, computed by the node (CC 2.6.1.3);
  - a SHA-256 digest carried as hex becomes `bstr .size 32`;
  - a set (`[* …]`) is sorted by each element's deterministic encoding and has no duplicates;
  - `persist_row_hash`, `original_content_hash`, the `scrub_*` members, `scrub_key_id`, `scrub_timestamp`, `pqc_completed_at` and `observed_region` are gone: the row id and the statements replace them.
- **`bool`** (`consensus_protocol_entrenched`) is the one member outside uint / bstr / tstr / identity-ref / row-ref. Absent reads as `false`.

## Families

<!-- BEGIN rendered from federation::edition2::payloads -->
### `group:roster`

- **Replaces:** SignedFamily / Family, SignedCommunity / Community, a federation_group_versions row
- **Authorship:** counted
- **`sub`:** the group's identity-ref (family_key_id / community_key_id)
- **Lands in:** federation_families / federation_communities (+ federation_group_versions)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `group_kind` | `tstr` | required | the record's kind: "family" \| "community" |
| `group` | `identity-ref` | required | Family.family_key_id / Community.community_key_id (equals sub) |
| `name` | `tstr` | required | Family.family_name / Community.community_name |
| `version` | `uint` | required | federation_group_versions.version |
| `members` | `[* roster-member]` | required | Family.members / Community.members |
| `founded_at` | `uint (ms)` | required | founded_at |
| `consensus_protocol` | `tstr` | required | consensus_protocol |
| `consensus_protocol_entrenched` | `bool` | optional | Family.consensus_protocol_entrenched (absent: false) |
| `dissolved_at` | `uint (ms)` | optional | Family.dissolved_at |
| `policy` | `map` | optional | Community.policy_blob (cohort_scope among its members) |
| `refs.prev` | `row-ref` | optional | prev_head_digest (the predecessor version's persist_row_hash); absent on version 1 |
| `refs.also:charter` | `row-ref` | optional | charter_digest (the trust:charter:v1 row in force) |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_classical / scrub_signature_pqc under authority_key_id | the group key's own statement |
| cosignatures (RosterCosignature) | one statement per listed member over the same payload |
| supersede_proof.quorum_signatures (ThresholdSignature) | the predecessor roster's holders' statements, counted at its consensus_protocol |
| SignedCommunity.lineage | nothing carried: each prior version is its own held row, named by refs.prev |

### `membership:{stage}`

- **Replaces:** Signed{Family,Community}MembershipRevocation (stage `removal`), Signed{Family,Community}MembershipWidening (stage `widening`)
- **Authorship:** counted (stages widening, removal)
- **`sub`:** the member's identity-ref
- **Lands in:** federation_{family,community}_membership_{revocations,widenings}

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `group_kind` | `tstr` | required | "family" \| "community" (which struct) |
| `group` | `identity-ref` | required | family_key_id / community_key_id |
| `member` | `identity-ref` | required | removal: removed_identity_key_id; widening: member_key_id (equals sub) |
| `removed_at` | `uint (ms)` | required when `dimension` is `removal` | MembershipRevocation.removed_at |
| `joined_at` | `uint (ms)` | required when `dimension` is `widening` | MembershipWidening.joined_at |
| `effective_at` | `uint (ms)` | required | effective_at |
| `reason` | `tstr` | optional | MembershipRevocation.reason |
| `role` | `tstr` | optional | MembershipWidening.role |
| `witness_set` | `[* identity-ref]` | optional | MembershipRevocation.witness_set (vouching key ids, not signatures) |
| `refs.head` | `row-ref` | optional | the roster version the change is counted over (earlier: the signed instant) |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_* under authority_key_id | the proposer's statement |
| cosignatures (RosterCosignature) | the roster members' statements, counted at the group's consensus_protocol |

### `identity:occurrence_revocation`

- **Replaces:** FramedOccurrenceRevocation / IdentityOccurrenceRevocation (an identity:occurrence_revocation:v1 row)
- **Authorship:** counted for a user self (identity=user), else authored
- **`sub`:** the occurrence's identity-ref
- **Lands in:** federation_identity_occurrence_revocations

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `identity` | `identity-ref` | required | identity_key_id |
| `occurrence` | `identity-ref` | required | occurrence_key_id (equals sub) |
| `revoked_at` | `uint (ms)` | required | revoked_at |
| `effective_at` | `uint (ms)` | required | effective_at (may be later than asserted_at) |
| `reason` | `tstr` | optional | reason |
| `witness_set` | `[* identity-ref]` | optional | witness_set |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| FramedOccurrenceRevocation.signature (TransportBindingSignature) under attesting_key_id | the revoker's statement |
| the row's additional_scrubs (roster cosigs, user self) | the roster members' statements, a strict majority counted |

### `cosign:{state}`

- **Replaces:** LineageHeadCosign (state `lineage_head`); cosign:pending:v1 / cosign:signature:v1 rows
- **Authorship:** authored
- **`sub`:** the lineage's identity-ref (lineage_head); the group's (pending, signature)
- **Lands in:** federation_lineage_head_cosigns (lineage_head); ceg_statements only (pending, signature)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `lineage` | `identity-ref` | required when `dimension` is `lineage_head` | LineageHeadCosign.lineage_key_id |
| `head_asserted_at` | `uint (ms)` | required when `dimension` is `lineage_head` | LineageHeadCosign.head_asserted_at |
| `event_family` | `tstr` | required when `dimension` is `pending` | cosign event_family |
| `group_kind` | `tstr` | required when `dimension` is `pending` | cosign group_kind |
| `refs.head` | `row-ref` | required when `dimension` is `lineage_head` | head_digest_sha256_hex (the head's persist_row_hash) |
| `refs.prev` | `row-ref` | optional | prior_head_digest_sha256_hex |
| `refs.target` | `row-ref` | required when `dimension` is `pending` | pending: the event (embedded `event`, now named); signature: quorum_key (the pending row) |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| signature_classical / signature_pqc under witness_key_id | the witness's statement (iss); signed_at is asserted_at |
| cosign:signature row's scrub + additional_scrubs | a further statement over the event's own row (CC 2.6.1.9); the signature state carries no member of its own |

### `revocation:{entity_type}:{reason}`

- **Replaces:** SignedRevocation / Revocation (a key revocation is key:revocation instead)
- **Authorship:** authored
- **`sub`:** the revoked entity's identity-ref (an entity with a key)
- **Lands in:** federation_revocations (an entity with a key); ceg_statements only otherwise

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `revoked_at` | `uint (ms)` | required | revoked_at |
| `effective_at` | `uint (ms)` | required | effective_at |
| `revoked_after` | `uint (ms)` | optional | revoked_after |
| `reason` | `tstr` | optional | reason (free text; the {reason} leaf is the coded one) |
| `refs.target` | `row-ref` | optional | the revoked row, when the entity is a row (no earlier field: revoked_key_id named keys only) |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_* under scrub_key_id / revoking_key_id | the revoker's statement (iss = author) |

### `takedown_notice:{basis}`

- **Replaces:** StewardPurgeNotice (envelope members, notice_terms)
- **Authorship:** counted for leaf steward_purge, else authored
- **`sub`:** the claimant's identity-ref
- **Lands in:** ceg_statements (the notice; its id is the row id); purge_executions when the purge runs

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `legal_basis` | `tstr` | required | legal_basis (also the {basis} leaf) |
| `claimant` | `identity-ref` | required | claimant_key_id |
| `content_sha256` | `bstr .size 32` | required | content_sha256 (the selection digest) |
| `content_holders` | `[* identity-ref]` | required | content_holder_key_ids |
| `claim_text` | `tstr` | required | claim_text |
| `good_faith_statement` | `tstr` | required | good_faith_statement |
| `jurisdiction` | `tstr` | required | jurisdiction |
| `evidence_refs` | `[* bstr .size 32]` | optional | evidence_refs (the dry-run ledger digests) |
| `selection_counts` | `map` | optional | selection_counts |
| `expires_at` | `uint (ms)` | optional | expires_at |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| cosignatures (ThresholdSignature, one per founder) | the stewards' statements, counted |

### `custody:{kind}`

- **Replaces:** custody:ack:v1 envelope (CustodyAck)
- **Authorship:** authored
- **`sub`:** the device's identity-ref (equals iss)
- **Lands in:** federation_attestations (custody:ack) and the holding-claim fold

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `custody_state` | `tstr` | required | custody_state: "here" \| "none" |
| `evidence_refs` | `[* bstr .size 32]` | required | evidence_refs (blob sha256) |
| `size` | `uint` | required when `custody_state` is `here` | size |
| `cohort` | `identity-ref` | required | community_id / family_key_id |
| `expires_at` | `uint (ms)` | required | the row's expires_at (asserted_at + 72 h) |

Co-signatures now counted voices: none (the author's statement alone).

### `key_grant:{axis}`

- **Replaces:** SignedKeyGrantRow (envelope)
- **Authorship:** authored
- **`sub`:** the recipient's identity-ref (attested_key_id / GrantWrap.recipient_key_id)
- **Lands in:** federation_attestations (key_grant) + federation_blob_key_grants / federation_stream_dek_grants

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `axis` | `tstr` | required | axis: "epoch" \| "content" \| "stream" (also the {axis} leaf) |
| `wrap_algorithm` | `tstr` | required | GrantWrap.wrap_algorithm |
| `wrapped_dek` | `bstr` | required | GrantWrap.wrapped_dek |
| `community` | `identity-ref` | required when `axis` is `epoch` | community_key_id |
| `community_id` | `tstr` | optional | community_id |
| `minter` | `identity-ref` | required when `axis` is `epoch` | minter_key_id |
| `epoch` | `uint` | optional | epoch (epoch and stream axes) |
| `at_rest_sha256` | `bstr .size 32` | required when `axis` is `content` | at_rest_sha256 |
| `owner` | `identity-ref` | optional | owner_key_id (content and stream axes) |
| `stream_id` | `tstr` | required when `axis` is `stream` | stream_id |
| `cohort` | `identity-ref` | optional | the cohort target (community_id / family_key_id) |

Co-signatures now counted voices: none (the author's statement alone).

### `delivery_receipt:{stream_id}`

- **Replaces:** DeliveryReceipt
- **Authorship:** authored
- **`sub`:** the subscriber's identity-ref (subscriber_key_id; equals iss)
- **Lands in:** federation_stream_delivery_receipts

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `stream_id` | `tstr` | required | stream_id (also the {stream_id} leaf) |
| `epoch` | `uint` | required | epoch |
| `k` | `uint` | required | k (the chunk index acknowledged) |
| `chunk_root` | `bstr .size 32` | required | chunk_root |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| signature (HybridSignature over the binary receipt bytes) | the subscriber's composite statement; the receipt store's HybridSignature is filled from its two halves |

### `roster-member` (an entry of `group:roster`'s `members`)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `key` | `identity-ref` | required | FamilyMember/CommunityMember.key_id |
| `joined_at` | `uint (ms)` | required | FamilyMember/CommunityMember.joined_at |
| `role` | `tstr` | optional | FamilyMember/CommunityMember.role |
<!-- END rendered -->
