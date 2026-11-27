# Edition-2 payload members (persist's reading for CC)

**Status: CC-READING(next-edition).** CC adopted this reading (`FSD/v62_docs/RULINGS.md`, "Families and payloads"): each family's edition-2 payload carries the earlier record's members one to one, in the deterministic encoding (CDE, CC 2.6.1.2), with no embedded signed object. The statements are the authority. What the earlier form carried as a co-signature (a co-scrub, a roster cosignature, a quorum or threshold signature set) is now a further statement over the same payload: a counted voice (CC 2.6.1.9), never a payload member.

**CC's corrections (v62.0.0).** CC checked these nine families against its text (`manifests/family_payloads_v2.cddl`, read with `signed_object_v2.cddl`). Where the text differed from this table, the text won:

- a roster version names the version it extends by `refs.head`, not `refs.prev` (which is a signer's own series);
- the charter rides `refs.also.cites`: the `also` roles are a closed registry of two, `ack` and `cites`;
- `consensus_protocol_entrenched` is a `bool`, and absent reads `false`;
- `group:roster` gains `cohort_subkind`, `cohort_subkind_payload` and `membership` (`private` | `public`, absent reads public);
- the membership stages this table maps are the counted leaves, `widening` and `removal`, each counted over `refs.head` (required); the other four stages' forward payloads are OPEN;
- `reason` is a uint code from a closed registry, never text; free text rides `body.note`;
- the cosign states are `pending` | `signature`, closed, and neither carries a member of its own. There is no `lineage_head` state: the lineage-head cosignature is no row (CC 3.4.10, CC 5.3.1), and its edition-2 form is OPEN;
- a takedown's `legal_basis` is CC 3.3.2's closed set of eleven and equals the leaf, and `perceptual_hash` and `counter_notice_channel` join it;
- a custody report carries no `expires_at` member, and one that carries it is refused even though the envelope admits the member on other families (it is live 72 hours from its instant, CC 3.1.3.3). It carries no `cohort` member either: its scope is the CC 2.1 members `community_id` / `family_id`. Its `evidence_refs` holds exactly one digest;
- a key grant's `owner` is required on content and stream, its `epoch` on epoch and stream, and its `wrap_algorithm` is the v2 wire string only. Its target alias is the CC 2.1 member, not a family member;
- a delivery receipt carries no inner signed object: the length-prefixed preimage the subscriber signed is the earlier form's (CC 8.11.30);
- `identity:occurrence_revocation` names its two keys `identity_key_id` and `occurrence_key_id`, the occurrence record's own names, one to one (CC's naming ruling);
- `amendment_digest` (on `deferral:response:approved` and `identity_amendment`) is a hash digest, `[-16, bstr .size 32]`.

**CC rc21 (kernel admission, CC 2.7.11; v62.0.0 wave P1e).** Three additions:

- a new family, `admission:unit` (wire `admission:unit:v1`, row type `scores`), the code scope. One person's (authored) row that names an effect is at `cohort_scope: self` and admits only on a host that person owns; any other row may be at any scope its signers choose (CC 2.7.11; AU-fix1). Its verifier's rules are refused with their own tokens (`admission_unit_malformed`, `admission_capability_unknown`, `admission_lease_out_of_window`, `admission_owner_row_not_self`, `admission_issuer_not_person`). A counted row is held (`count_short`, answered `admission_count_unmet`) until its count is met at the head it names. The host's tokens (`admission_issuer_not_reached`, `admission_count_unmet`, `admission_none`, `admission_capability_not_admitted`, `admission_capability_not_held`, `admission_halted`) are answers, and no row is refused for them;
- `identity_amendment` gains `refs.prev`, the link it follows (the profile scope; the link with no `prev` is the base);
- `deferral:response:approved` gains `call_fingerprint` (the action scope), beside `amendment_digest`.
- **rc21 member homes:** an `identity_amendment`'s approval stands under `refs.also.cites` (exactly one; no `authorized_by` member, no `evidence_refs`). A `deferral:response:*` names its request under `refs.answers` (never `refs.target`) and carries `deferral_id` (REQUIRED: it correlates on it) and never `reason_digest`. A `deferral:request` REQUIRES `deferral_id` and `reason_digest` (FINAL, CC ruling). Both route by `community_id`, the pair room (a two-person community record); there is no `room` member (FINAL, CC). No payload carries Server's envelope uuid `id`: the row id is computed.
- **The self-roster head (CC 2.7 rulings item 2):** `identity:occurrence` and `identity:occurrence_revocation` REQUIRE `refs.head`, the identity's last landed self-roster row (a new identity's first bind names its genesis key's own `key:record` row), and take an optional `refs.further_heads`. An `identity:occurrence_revocation` also REQUIRES `refs.also.cites`: the `key:record` of each voice, plus that key's occurrence binding when it has one (CC rc21 7f94be1). The per-voice coverage is T2's door; the list checks only that the cites are present.

The action review record is node-local (carried in the trace) and is no row, so it has no table here.

A payload that breaks any of these is refused `edition2_payload_invalid`. v62.0.0 (wave P1d): the edition-2 door enforces these lists, with its pure gates and before any directory read, on the local and the replicated door alike (`door::pure_statement_gates` → `payloads::check_by_id`, by the header's family id).

The tables below are rendered from `ciris_persist::federation::edition2::payloads::FAMILIES` and its rule tables (`LEAVES`, `CLOSED_VALUES`, `PROSE_RULES`, `COMMON`, `HASH_DIGEST_MEMBERS`). They are the member lists persist's door checks (`payloads::check`, refusal `edition2_payload_invalid`). A witness (I2102) keeps this file equal to them.

## Conventions

- **Common members**, which any row may carry and which are not repeated below (CC 2.6.1.3, the CDDL's `attestation-envelope`, and the CC 2.1 members that CC 2.6.1.4 maps to "payload members of the same names"):
  - `asserted_at`: `uint (ms)`, required;
  - `author`: `identity-ref`, present on an authored family only;
  - `dimension`: `tstr`, the family instance, required where the family id has a parameter (for example `membership:widening:v1` under `membership:{stage}`). A member marked "required when `dimension` is `x`" is required when `x` is a segment of `dimension`;
  - `refs`: a map of `row-ref`s; the roles each family carries are listed as `refs.<role>` rows, and `refs.also.<role>` takes only `ack` or `cites`;
  - `reason`: `uint`, a code from a closed registry (0 = unspecified);
  - `body`: a map; its `note` is the one free-text member, at most 2048 bytes;
  - `evidence_refs`: `[+ hash-digest]`, a sequence in the order signed;
  - `valid_from`, `valid_until`, `expires_at`: `uint (ms)`;
  - `cohort_scope`, `community_id`, `family_id`, `subject_key_ids`, `delivery_mode`: the CC 2.1 visibility, revocability and delivery axes;
  - the envelope's `seat_commitment`, `score`, `confidence`, `weight`, `passed`, `total` and `salt`.
- **Conversions**, everywhere:
  - an instant (RFC 3339 text) becomes `uint (ms)` (CC 2.6.2);
  - a key id becomes an `identity-ref` (CC 2.6.1.1);
  - a reference to a held row (`persist_row_hash`, `attestation_id`, a `*_digest`) becomes a `row-ref` under `refs`, computed by the node (CC 2.6.1.3);
  - a SHA-256 digest carried as hex becomes a hash digest, `[-16, bstr .size 32]` (the form Verify's door reads; the earlier gates' 64-hex strings are its projection, for the members listed under "Hash-digest members");
  - a set (`[* …]`) is sorted by each element's deterministic encoding and has no duplicates; a sequence (`[+ …]`) keeps its signed order;
  - `persist_row_hash`, `original_content_hash`, the `scrub_*` members, `scrub_key_id`, `scrub_timestamp`, `pqc_completed_at` and `observed_region` are gone: the row id and the statements replace them.
- **`bool`** (`consensus_protocol_entrenched`) is the one member outside uint / bstr / tstr / identity-ref / row-ref. Absent reads as `false`.
- **`ceg-value`** marks a member whose type the text leaves OPEN (`perceptual_hash`).
- **Numbers in free-form bodies** (CC ruling): an integral value is a plain CBOR integer; a non-integral value is CBOR tag 4 `[exponent, mantissa]`, normalised (negative exponent, mantissa not divisible by 10), from the EXACT decimal of the source text (`payloads::body_number`). A mantissa outside i64 is refused `body_number_unrepresentable`, and a non-normalised tag 4 anywhere in a payload is refused `edition2_payload_invalid` at the door. Fixed-scale members stay fixed6 integers.

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
| `version` | `uint` | required | federation_group_versions.version (a consistency check only) |
| `members` | `[* roster-member]` | required | Family.members / Community.members (a set) |
| `founded_at` | `uint (ms)` | required | founded_at |
| `consensus_protocol` | `tstr` | required | consensus_protocol |
| `consensus_protocol_entrenched` | `bool` | optional | Family.consensus_protocol_entrenched (absent reads false) |
| `dissolved_at` | `uint (ms)` | optional | Family.dissolved_at |
| `policy` | `map` | optional | Community.policy_blob (an open map) |
| `cohort_subkind` | `tstr` | optional | a community's discriminator (CC 3.2; earlier: policy_blob.cohort_subkind) |
| `cohort_subkind_payload` | `map` | optional | a community's Option<SubkindPayload> (CC 3.2) |
| `membership` | `tstr` | optional | a community's founding row: "private" \| "public" (CC 3.1.3.2; absent reads public) |
| `refs.head` | `row-ref` | optional | prev_head_digest: the version this one extends (CC 3.2 T6); absent on version 1, present on every later one |
| `refs.also.cites` | `row-ref` | optional | charter_digest: the trust:charter row in force; and, for a geographic community (rc21, CC 3.2), each NEW member's location_proof:v1 row. A reader places each cited row by its family |

Rules beyond the list (refused `edition2_payload_invalid`):

- `membership` is one of `private`, `public`
- `refs.head` is absent on version 1 and present on every later version
- a `geographic` community names each new member's `location_proof:v1` row under `refs.also.cites` (CC 3.2, rc21): a founding version (every member new) cites at least as many rows as it lists members; the fold waits for the proofs and concludes nothing unless each is contained in the constraint and live at `asserted_at`

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_classical / scrub_signature_pqc under authority_key_id | the group key's own statement |
| cosignatures (RosterCosignature) | one statement per listed member over the same payload |
| supersede_proof.quorum_signatures (ThresholdSignature) | the predecessor roster's holders' statements, counted at its consensus_protocol |
| SignedCommunity.lineage | nothing carried: each prior version is its own held row, named by refs.head |

### `membership:{stage}`

- **Replaces:** Signed{Family,Community}MembershipRevocation (stage `removal`), Signed{Family,Community}MembershipWidening (stage `widening`)
- **Authorship:** counted (stages widening, removal)
- **`sub`:** the member's identity-ref
- **Lands in:** federation_{family,community}_membership_{revocations,widenings}
- **Leaves mapped:** `widening`, `removal` (another leaf's payload is OPEN, not this table's)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `group_kind` | `tstr` | required | "family" \| "community" (which struct) |
| `group` | `identity-ref` | required | family_key_id / community_key_id |
| `member` | `identity-ref` | required | removal: removed_identity_key_id; widening: member_key_id (equals sub) |
| `removed_at` | `uint (ms)` | required when `dimension` is `removal` | MembershipRevocation.removed_at |
| `joined_at` | `uint (ms)` | required when `dimension` is `widening` | MembershipWidening.joined_at |
| `effective_at` | `uint (ms)` | required | effective_at |
| `valid_until` | `uint (ms)` | optional | a time-boxed guest's widening (CC 3.3.4) |
| `reason` | `uint` | optional | MembershipRevocation.reason, as a code of the closed registry (free text: body.note) |
| `role` | `tstr` | optional | MembershipWidening.role |
| `witness_set` | `[* identity-ref]` | optional | MembershipRevocation.witness_set (vouching key ids, not signatures) |
| `refs.head` | `row-ref` | required | the roster version the change is counted over (CC 2.6.1.9; earlier: the signed instant) |
| `refs.also.cites` | `row-ref` | optional | a widening: the acceptance it spends (CC 3.1.3.2); a node's widening has none |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_* under authority_key_id | the proposer's statement |
| cosignatures (RosterCosignature) | the roster members' statements, counted at the group's consensus_protocol |

### `identity:occurrence`

- **Replaces:** SignedIdentityOccurrence / IdentityOccurrence (an identity:occurrence:v1 row)
- **Authorship:** authored (by a live roster key of the identity); the occurrence key's own statement is a second voice, role occurrence_key (party sub)
- **`sub`:** the occurrence key's identity-ref (occurrence_key_id)
- **Lands in:** federation_identity_occurrences (+ federation_identity_occurrence_history, transport_destinations)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `identity_key_id` | `identity-ref` | required | identity_key_id (equals author) |
| `occurrence_key_id` | `identity-ref` | required | occurrence_key_id (equals sub) |
| `device_class` | `tstr` | required | device_class: phone \| laptop \| server \| embedded \| agent \| service |
| `hardware_attestation` | `bstr` | optional | hardware_attestation (base64 in the earlier form) |
| `transport_destination` | `map` | optional | transport_destination: exactly reticulum_x25519_pubkey (bstr 32), reticulum_ed25519_pubkey (bstr 32), app_name (tstr), aspects ([* tstr]), destination_hash (bstr 16, derived per CC 3.3.6.3) |
| `transit_xwing_pubkey` | `bstr` | optional | transport_destination's transit_xwing_pubkey: 1216 bytes, at the top level (CC 3.3.6.2) |
| `onion_hop_xwing_pubkey` | `bstr` | optional | transport_destination's onion_hop_xwing_pubkey: 1216 bytes, at the top level (CC 3.3.6.2) |
| `dial_hints` | `ceg-value` | optional | dial hints, most preferred first: [1*8 [type (uint, at most 255), body (bstr, 0..255 bytes, the FedCode hint body)]]; hints only, no transport identity; a genesis serve seat needs one tcp hint (shape and rule judged by Verify's reader, 23.4.0) |
| `onion_relay` | `map` | optional | exactly {"opt_out": true}, on a node that opts out of relaying (CC 3.3.6.2) |
| `encryption_pubkeys` | `map` | optional | encryption_pubkeys: exactly x25519 (bstr 32) and ml_kem_768 (bstr 1184) |
| `build_manifest_hash` | `hash-digest [-16, bstr .size 32]` | optional | build_manifest_hash |
| `valid_until` | `uint (ms)` | optional | valid_until (absent: indefinite; present: later than asserted_at) |
| `refs.head` | `row-ref` | required | the last landed self-roster row of the identity (CC 2.7 rulings item 2); the first bind of a new identity names the genesis key's own key:record row |
| `refs.further_heads` | `row-ref` | optional | the other self-roster tips this row merges, as group:roster's |
| `refs.also.cites` | `row-ref` | optional | build_manifest_ref: the provenance:build_manifest:{target} row |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| SignedIdentityOccurrence.signature (TransportBindingSignature) under attesting_key_id | the author's statement: a live roster key of the identity (iss = identity_key_id) |
| none (the earlier form carried no proof of possession) | the occurrence key's own statement over the same payload (iss = sub), required before the author's |
| the self-roster door's assent rows (objection:assent:v1) | further roster keys' statements as the identity over the same payload, a strict majority of the live roster counted |

### `identity:occurrence_revocation`

- **Replaces:** IdentityOccurrenceRevocation (an identity:occurrence_revocation:v1 row; no framed object is embedded)
- **Authorship:** counted for a user self (identity=user), else authored
- **`sub`:** the occurrence's identity-ref
- **Lands in:** federation_identity_occurrence_revocations

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `identity_key_id` | `identity-ref` | required | identity_key_id (the occurrence record's own name, CC ruling v62) |
| `occurrence_key_id` | `identity-ref` | required | occurrence_key_id (equals sub) |
| `revoked_at` | `uint (ms)` | required | revoked_at |
| `effective_at` | `uint (ms)` | required | effective_at (may be later than asserted_at) |
| `reason` | `uint` | optional | reason, as a code of the closed registry (free text: body.note) |
| `witness_set` | `[* identity-ref]` | optional | witness_set |
| `refs.head` | `row-ref` | required | the last landed self-roster row of the identity (CC 2.7 rulings item 2); the first bind of a new identity names the genesis key's own key:record row |
| `refs.further_heads` | `row-ref` | optional | the other self-roster tips this row merges, as group:roster's |
| `refs.also.cites` | `row-ref` | required | the key:record of each voice, and that key's occurrence binding when it has one (CC rc21 7f94be1); REQUIRED: the per-voice coverage is T2's door |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| FramedOccurrenceRevocation.signature (TransportBindingSignature) under attesting_key_id | the revoker's statement (the statement's signer) |
| the row's additional_scrubs (roster cosigs, user self) | the roster members' statements, a strict majority counted |

### `cosign:{state}`

- **Replaces:** cosign:pending:v1 / cosign:signature:v1 rows (the states are closed: pending \| signature)
- **Authorship:** authored
- **`sub`:** the event's sub (the group's identity-ref)
- **Lands in:** ceg_statements only
- **Leaves (closed):** `pending`, `signature`
- **Payload:** the event's own; its members are checked under the event's family

Members of its own: none.

| earlier-form co-signature (not a payload member) | now |
|---|---|
| cosign:pending row's embedded event and the primary's signature over its signing bytes | the primary's statement over the event's own payload and header, named by the event's row id; no member of its own |
| cosign:signature row's scrub + additional_scrubs | a further statement over the event's own payload (CC 2.6.1.9); no member of its own |
| LineageHeadCosign (signature_classical / signature_pqc under witness_key_id) | no row and no state of this family: the ciris.lineage_head_cosign.v1 object (CC 3.4.10, CC 5.3.1), its edition-2 form OPEN |

### `revocation:{entity_type}:{reason}`

- **Replaces:** SignedRevocation / Revocation (a key revocation is key:revocation instead)
- **Authorship:** authored
- **`sub`:** the revoked entity's identity-ref (an entity with a key)
- **Lands in:** federation_revocations (an entity with a key); ceg_statements only otherwise
- **Leaves not mapped:** `peer_admission` (that leaf's payload is not this table's)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `revoked_at` | `uint (ms)` | required | revoked_at |
| `effective_at` | `uint (ms)` | required | effective_at |
| `revoked_after` | `uint (ms)` | optional | revoked_after |
| `refs.target` | `row-ref` | optional | the revoked row, when the entity is a row (no earlier field: revoked_key_id named keys only) |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_* under scrub_key_id / revoking_key_id | the revoker's statement (iss = author) |

### `takedown_notice:{basis}`

- **Replaces:** StewardPurgeNotice (envelope members, notice_terms)
- **Authorship:** authored, but counted for leaf steward_purge and for group=affiliations & seats=one (CC 4.4.3.12)
- **`sub`:** the claimant's identity-ref
- **Lands in:** ceg_statements (the notice; its id is the row id); purge_executions when the purge runs
- **Leaves (closed):** `dmca512`, `dsa_article16`, `tvec_terrorist`, `ncmec_csam`, `gifct_cip`, `community_standards`, `perceptual_hash_csam`, `osa_illegal_content`, `avmsd_age_inappropriate`, `court_order`, `steward_purge`

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `legal_basis` | `tstr` | required | legal_basis (CC 3.3.2's closed set; equals the {basis} leaf) |
| `claimant` | `identity-ref` | required | claimant_key_id |
| `content_sha256` | `hash-digest [-16, bstr .size 32]` | required | content_sha256 (the selection digest) |
| `content_holders` | `[* identity-ref]` | required | content_holder_key_ids |
| `claim_text` | `tstr` | required | claim_text |
| `good_faith_statement` | `tstr` | required | good_faith_statement |
| `jurisdiction` | `tstr` | required | jurisdiction |
| `evidence_refs` | `[+ hash-digest]` | optional | evidence_refs (the dry-run ledger digests; a URI reference is OPEN) |
| `perceptual_hash` | `ceg-value` | optional | perceptual_hash (CC 3.3.2; its type is OPEN) |
| `counter_notice_channel` | `tstr` | optional | counter_notice_channel (CC 3.3.2) |
| `selection_counts` | `map` | optional | selection_counts |
| `expires_at` | `uint (ms)` | optional | expires_at |

Rules beyond the list (refused `edition2_payload_invalid`):

- `legal_basis` is one of `dmca512`, `dsa_article16`, `tvec_terrorist`, `ncmec_csam`, `gifct_cip`, `community_standards`, `perceptual_hash_csam`, `osa_illegal_content`, `avmsd_age_inappropriate`, `court_order`, `steward_purge`
- `legal_basis` equals the `{basis}` leaf of `dimension`
- a `steward_purge` notice is counted: it carries no `author`

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
| `evidence_refs` | `[+ hash-digest]` | required | evidence_refs: exactly one, the blob's address digest |
| `size` | `uint` | required when `custody_state` is `here` | size |

Rules beyond the list (refused `edition2_payload_invalid`):

- `custody_state` is one of `here`, `none`
- `evidence_refs` holds exactly one digest, the blob's address
- `expires_at` is not a member: a report is live 72 hours from its `asserted_at` (CC 3.1.3.3)

Co-signatures now counted voices: none (the author's statement alone).

### `key_grant:{axis}`

- **Replaces:** SignedKeyGrantRow (envelope)
- **Authorship:** authored
- **`sub`:** the recipient's identity-ref (attested_key_id / GrantWrap.recipient_key_id)
- **Lands in:** federation_attestations (key_grant) + federation_blob_key_grants / federation_stream_dek_grants

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `axis` | `tstr` | required | axis: "epoch" \| "content" \| "stream" (also the {axis} leaf) |
| `wrap_algorithm` | `tstr` | required | GrantWrap.wrap_algorithm (the v2 wire string only) |
| `wrapped_dek` | `bstr` | required | GrantWrap.wrapped_dek |
| `community` | `identity-ref` | required when `axis` is `epoch` | community_key_id |
| `minter` | `identity-ref` | required when `axis` is `epoch` | minter_key_id |
| `epoch` | `uint` | required when `axis` is `epoch` or `stream` | epoch |
| `at_rest_sha256` | `hash-digest [-16, bstr .size 32]` | required when `axis` is `content` | at_rest_sha256 |
| `owner` | `identity-ref` | required when `axis` is `content` or `stream` | owner_key_id (the axis identity, CC 3.3.2) |
| `stream_id` | `tstr` | required when `axis` is `stream` | stream_id |

Rules beyond the list (refused `edition2_payload_invalid`):

- `wrap_algorithm` is one of `x25519_mlkem768_aes256_gcm_hkdf_sha256`

Co-signatures now counted voices: none (the author's statement alone).

### `delivery_receipt:{stream_id}`

- **Replaces:** DeliveryReceipt
- **Authorship:** authored
- **`sub`:** the subscriber's identity-ref (subscriber_key_id; equals iss)
- **Lands in:** federation_stream_delivery_acks

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `stream_id` | `tstr` | required | stream_id (also the {stream_id} leaf) |
| `epoch` | `uint` | required | epoch |
| `k` | `uint` | required | K (the chunk index acknowledged; CBOR member names are lowercase) |
| `chunk_root` | `hash-digest [-16, bstr .size 32]` | required | chunk_root |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| signature (HybridSignature over the length-prefixed ciris-delivery-receipt/v1 bytes) | the subscriber's composite statement over the payload; no inner signed object (the earlier layout is CC 8.11.30); the receipt store's HybridSignature is filled from its two halves |

### `admission:unit`

- **Replaces:** nothing: new in rc21 (CC 2.7.11, the code scope of kernel admission; wire admission:unit:v1, row type scores)
- **Authorship:** counted where the payload carries no author (act = group; it names its roster head in refs.head), authored otherwise (naming no head); one person's (authored) row naming an effect is at cohort_scope self and admits only on a host that person owns; every signer a person (identity_type holds user or accord_holder); no delegate role
- **`sub`:** the unit digest as tagged text, canonical:sha256:{hex} (not an identity-ref)
- **Lands in:** ceg_statements + federation_attestations (the mapped scores row), held count_short until a counted row's count is met; no typed plane: the host's answer (admission_unit_runnable) reads the conclusion, the lease, the withdrawal, the standing and the receipt

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `unit` | `hash-digest [-16, bstr .size 32]` | required | SHA-256 over the unit's bytes as the host loads them (a multi-file unit: its manifest's digest) |
| `capabilities` | `[* tstr]` | required | the admitted capabilities: compute, read, net_send, submit, sign, store_write, actuate |
| `valid_until` | `uint (ms)` | required | the lease closes (asserted_at opens it) |
| `refs.head` | `row-ref` | optional | counted only: the roster head the count is over |

Verifier rules (each refused with its own token):

- `admission_unit_malformed`: `author` and `refs.head` are not both present or both absent; `sub` is `canonical:sha256:{hex}` of `unit`
- `admission_capability_unknown`: `capabilities` is non-empty and within the closed set
- `admission_lease_out_of_window`: `asserted_at < valid_until <= asserted_at + unit_lease_max_secs * 1000` (86400 s)
- `admission_owner_row_not_self`: one person's (authored) row that names an effect capability (`net_send`, `submit`, `sign`, `store_write`, `actuate`) is at `cohort_scope: self`
- `admission_issuer_not_person`: every signer's key record holds `user` or `accord_holder` (the statement alone is refused)

| earlier-form co-signature (not a payload member) | now |
|---|---|
| none (a new family) | counted: one statement per voice over one payload, counted over the members at refs.head by the group's cosigned_act protocol, never fewer than two persons; a shortfall is held, never refused |

### `identity_amendment`

- **Replaces:** the identity_amendment:v1 envelope (CC 3.1.5; rc21: authorized_by under refs.also.cites, no evidence_refs)
- **Authorship:** authored (the agent's occurrence key)
- **`sub`:** the agent identity's identity-ref
- **Lands in:** federation_attestations (identity_amendment:v1, gated identity_amendment_unauthorized)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `amendment_digest` | `hash-digest [-16, bstr .size 32]` | required | amendment_digest (earlier: hex64); on the base link (no refs.prev), the base template manifest's digest |
| `refs.prev` | `row-ref` | optional | the identity_amendment this link follows (rc21, CC 2.7.11); absent on the base link |
| `refs.also.cites` | `row-ref` | required | authorized_by (rc21): the approving deferral:response:approved row, exactly one; evidence_refs is dropped |

Rules beyond the list (refused `edition2_payload_invalid`):

- `refs.also.cites` names exactly one row, the approving response; the amendment carries no `evidence_refs` (rc21)

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_* under the agent's occurrence key | the agent occurrence's statement |

### `deferral:request`

- **Replaces:** the deferral:request:v1 envelope (CC 3.1.5; rc21 CC ruling)
- **Authorship:** authored (the deferring agent's occurrence key)
- **`sub`:** the agent identity's identity-ref
- **Lands in:** federation_attestations (answered by a deferral:response; routed by community_id, the pair room: a two-person community record, CC FINAL)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `deferral_id` | `tstr` | required | deferral_id (rc21, CC ruling): the deferral, as the agent names it; its response correlates on it |
| `reason_digest` | `hash-digest [-16, bstr .size 32]` | required | reason_digest (rc21, CC ruling): the digest of the agent's reason text (the text stays off the row) |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_* under the agent's occurrence key | the deferring agent's statement |

### `deferral:response:{outcome}`

- **Replaces:** the deferral:response:{approved,rejected}:v1 envelope (CC 3.1.5; rc21: the request under refs.answers)
- **Authorship:** authored (the Wise Authority)
- **`sub`:** the agent identity's identity-ref
- **Lands in:** federation_attestations (read by the identity_amendment gate)
- **Leaves (closed):** `approved`, `rejected`

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `amendment_digest` | `hash-digest [-16, bstr .size 32]` | optional | approved only: the digest of the exact text approved (CIRISServer#1365) |
| `call_fingerprint` | `hash-digest [-16, bstr .size 32]` | optional | approved only: the call approved, SHA-256(CDE(["CEG-call/2", verb, tool, arguments, channel])) (rc21, CC 2.7.11) |
| `deferral_id` | `tstr` | required | deferral_id (rc21, CC ruling): the deferral answered, as the agent named it; the response correlates on it |
| `refs.answers` | `row-ref` | required | the deferral:request answered (rc21; earlier references_attestation_id, never refs.target). The pair room rides community_id (FINAL, CC: a two-person community record; no room member) |

Rules beyond the list (refused `edition2_payload_invalid`):

- `amendment_digest` and `call_fingerprint` ride an `approved` response only
- the request answered stands under `refs.answers`, never `refs.target` (rc21)
- a response carries `deferral_id` (required) and never `reason_digest` (the request's own, CC ruling)

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_* under the WA's key | the Wise Authority's statement |

### `location_proof:{version}`

- **Replaces:** the location_proof subject_kind (CC 3.3.3; wire location_proof:v1, a scores row)
- **Authorship:** authored by the subject alone (subject-only: iss = sub, CC 4.5.9)
- **`sub`:** the subject's identity-ref (earlier subject_key_id; equals iss)
- **Lands in:** federation_attestations (read by a geographic roster version that cites it, CC 3.2)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `cell_id` | `tstr` | required | cell_id: the H3 cell, lowercase hex (CC 2.6.6) |
| `cell_resolution` | `uint` | required | cell_resolution: at most 7, rough-only (CC 2.6.6.1) |
| `attestation_evidence` | `bstr` | optional | attestation_evidence (earlier base64): a hardware-attested location claim |

Rules beyond the list (refused `edition2_payload_invalid`):

- `cell_resolution` is at most 7 (rough-only, CC 2.6.6.1); `cell_id` is lowercase hex

| earlier-form co-signature (not a payload member) | now |
|---|---|
| scrub_signature_* under the subject's key | the subject's statement |

### `transport:canonical_rebind`

- **Replaces:** the transport:canonical_rebind:v1 scores row (its additional_scrubs, and the carried SignedTransportDestination under transport_destination)
- **Authorship:** counted (the accord's holders: a strict majority of the holders of the genesis bundle in force that refs.head names, each at its placed key; refused reserved_family_unseated otherwise, CC 3.4.7)
- **`sub`:** the seat's identity-ref (a serve node of the genesis bundle in force)
- **Lands in:** ceg_statements (no typed table; the seat's live transit key is read from the counted voices)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `transit_xwing_pubkey` | `bstr` | required | the carried row's transit_xwing_pubkey: 1216 bytes, pk_M then pk_X (CC 3.3.6.2) |
| `onion_hop_xwing_pubkey` | `bstr` | optional | the carried row's onion_hop_xwing_pubkey: 1216 bytes (CC 3.3.6.2) |
| `transport_destination` | `map` | optional | the carried row's transport_destination, as identity:occurrence's |
| `refs.head` | `row-ref` | required | none (new): the genesis bundle in force the re-bind is counted over, by its object id |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| authority scrub + additional_scrubs by accord holders over the canonical envelope | one statement per holder over the same payload, counted at a strict majority of the holders of the bundle in force |

### `trace:{form}:{version}`

- **Replaces:** the trace:complete:v1 local mint and the bound-hybrid CompleteTrace signature (signature + signature_ml_dsa_65)
- **Authorship:** authored (the agent: self-emitted, CC 3.4.5)
- **`sub`:** the agent's identity-ref (equals iss, author and the one subject_key_ids entry)
- **Lands in:** federation_attestations (the row); the trace blob in federation_blobs; trace_events projected at ingest from the blob

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `trace_id` | `tstr` | required | CompleteTrace.trace_id (non-empty) |
| `agent_id_hash` | `tstr` | required | CompleteTrace.agent_id_hash (non-empty) |
| `manifest` | `map` | required | trace_manifest:v1: schema, content_hash (sha256: + 64 lowercase hex over the trace blob's bytes as stored), byte_len, component_count, run_kind; the trace itself is a blob named by evidence_refs, never inline |

| earlier-form co-signature (not a payload member) | now |
|---|---|
| signature (Ed25519) and signature_ml_dsa_65 bound over the trace's canonical bytes | the agent's statement over the manifest |

### `roster-member` (an entry of `group:roster`'s `members`)

| member | CBOR type | presence | maps from |
|---|---|---|---|
| `key` | `identity-ref` | required | FamilyMember/CommunityMember.key_id |
| `joined_at` | `uint (ms)` | required | FamilyMember/CommunityMember.joined_at |
| `role` | `tstr` | optional | FamilyMember/CommunityMember.role |

### Every mapped family

- **Common members** (any family): `asserted_at`, `author`, `body`, `cohort_scope`, `community_id`, `confidence`, `delivery_mode`, `dimension`, `evidence_refs`, `expires_at`, `family_id`, `passed`, `reason`, `refs`, `salt`, `score`, `seat_commitment`, `subject_key_ids`, `total`, `valid_from`, `valid_until`, `weight`
- **Hash-digest members** (any family; the earlier gates read each as 64 hex): `evidence_refs`, `carried`, `seat_commitment`, `amendment_digest`, `call_fingerprint`, `attached_head_digest`
- every `refs.also` role is `ack` or `cites` (a closed registry, CC 2.6.1.3)
- `body.note`, when present, is text of at most 2048 bytes
- a composer (`withdraws`, `recants`, `supersedes`) carries its target's family but its own payload: the common members and `refs.target`, never the target family's list
<!-- END rendered -->
