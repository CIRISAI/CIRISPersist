# P2b — a key in a family name is its bare thumbprint segment (CC rc21, CC 3.1)

**Ruling implemented:** the FINAL CC ruling. A key in a family name or scope token is the bare 43-char base64url thumbprint (zero trailing bits). Segment parsing stays plain `:`. `licensure:{authority_id}` and `moderation_track_record:{community_key_id}` are key-ONLY. Strict refusal of non-segments starts at CP2. Scope caveats `infra:attest:licensure:{authority_id}` carry the segment too.

This implements the FINAL ruling: the bare base64url thumbprint, in one module, `namespace::key_segment`. Segment parsing stays plain `:`-splitting. P2b.patch REPLACES the earlier identity-ref-segment draft; nothing of that draft remains (`key_param.rs` is gone, and scope_covers, the matcher and the ledger parser are untouched).

Worktree `/home/emoore/CIRISPersist-wp-P2b`, branch `v62-p-P2b`, base `v62-syn0` @ 8f33957f.
- Nothing was built, so every claim here is BELIEVED; "read-checked" means I confirmed it by reading.
- P2b.patch applies on top of P2.patch (`git apply --check` in the P2 worktree; tested).
- API: `P2b.api.md`.

## The -70002 question (read-checked): the codec is correct; no fix needed

- **`edition2::codec`** is `#[cfg(test)] pub(crate) mod codec` (edition2/mod.rs:44). `statement_of`/`statement_of_with` take `family` from the CALLER and write it to -70002 unchanged. The codec never derives a family from the dimension.
- Its only callers are in `produce_invariants.rs`, with non-parameterised families: `EVIDENCE_ROWS`, `key:revocation`.
- **`edition2::produce::sign_row` / `row_protected`** also take `family` as a parameter (produce.rs:97, 124, 169). No production caller exists on v62-syn0 outside produce.rs and its tests (grepped).
- **The fixture path** is E0's `family_of(row)`. Per E0.api.md it is Verify's `namespace_match::resolve(dimension).family_id`, which is the TEMPLATE (`licensure:.authority_id`).
- **Verify's decode** (ciris-verify-core 23.1.3 `edition2/mod.rs:676–690`, read):
  - It checks `is_registered_family_id(-70002)`.
  - It then resolves the payload's `dimension` and requires `family_id == -70002`; otherwise the row is refused `DimensionFamily` (`dimension_family`).
  - A bare 43-char thumbprint is a verbatim, case-preserving value segment, so `licensure:<thumb>:v1` resolves to `licensure:.authority_id`.
- **Consequence:** a dimension carrying the URN (`licensure:urn:ietf:…:v1`) fails `dimension_family` at Verify for an edition-2 row, because the arity is wrong. The persist gate below also refuses it as a malformed row on every door, including the JSON doors.

## Changes, file by file

### `src/federation/namespace/key_segment.rs` (NEW): the one encoder, decoder and gate

- The three published functions are `segment_of`, `identity_ref_of` and `is_key_segment`.
  - A key segment is exactly 43 chars of `[A-Za-z0-9_-]` whose last char is in `AEIMQUYcgkosw048`, i.e. zero trailing bits.
  - `segment_of` requires Verify's `is_identity_ref`.
- `family_param_of(key_id)` writes a key id as a family param: an identity-ref becomes its segment, and an earlier-form id is returned unchanged.
- `key_id_of_param(segment)` is the inverse: a segment becomes its identity-ref, and anything else is returned unchanged.
- **`check_dimension_key_segments(envelope)` is the admission gate.** It is pure. It raises `Error::MalformedRow` with reason **`envelope_member_invalid`** (`malformed_row::ENVELOPE_MEMBER_INVALID`), the existing token, so **no new token is needed**. It refuses:
  1. a `dimension` that contains `IDENTITY_REF_PREFIX` anywhere: a URN written into a family name, in any family;
  2. in a key-bearing position (`KEY_BEARING_STEMS` = `licensure:`, `moderation_track_record:`), a 43-char base64url segment with non-zero trailing bits, which is a second spelling of a key;
  3. **only once `edition2::door::EARLIER_FORM_DOORS_SHUT` is true:** in a key-bearing position, any segment that is not a key segment (wrong length, hex, an earlier-form id). While the JSON doors are open, an earlier-form key id there is still a key id. **See open question 1.**

### `src/federation/licensure.rs` (production + tests)

- **`authority_of(dimension) -> Option<Cow<'_, str>>`** (it was `Option<&str>`; an in-crate signature change). It reads the plain `:` segment through `key_id_of_param`, so a v62 key authority comes back as its **identity-ref**.
- Decision ("convert one side, consistently"): **persist's authority ids are key ids** (identity-refs for v62 keys). They compare by equality with `attesting_key_id`, `lookup_public_key`/`lookup_community` keys, and every `authority_id: &str` API parameter (`status_set_for`, `licence_authority_set`, …). The dimension spelling is converted only at this boundary and in `licensure_stem_of`.
- **`licensure_stem_of(authority_id) -> String`** (NEW) returns `"licensure:" + family_param_of(authority_id)`. Queries and producers use it to WRITE the stem.
- `fold_status_set`: `authority_of(..).as_deref() != Some(authority_id)`.
- The old `authority_parsing_814` assertions are adapted to `.as_deref()`, with the same values.

### `src/federation/admission.rs` (production + 1 test)

Every `authority_of` site was adapted:
- 5291 (`licences_issued_under`): `.as_deref() ==`.
- 5364 (`check_licensure_delegator_is_authority`): shadowed `let authority_id: &str = &authority_id;`.
- 5487 (`check_partner_record_revision`): shadowed.
- 5512: `.as_deref() !=`.
- 5624 (`check_licence_audience`): shadowed.
- 5658: `.as_deref() !=`.
- 18437 (reconsideration): `licence_authority_set(directory, &authority_id)`.

Other changes:
- The two `dimension_prefix` stems (old lines 5275 and 5500) are built by `licensure_stem_of(authority_id)`, so a query for a v62 authority asks for `licensure:<segment>`.
- Promotion chokepoint (`check_promotion_admission`, after `check_licence_payload`): calls `check_dimension_key_segments`.
- `scope_covers` is UNCHANGED (plain segments; a key segment has no colon).

### `src/federation/attestation_admit.rs` (foreign hunk; K2 touches this file at other lines)

`check_dimension_key_segments` is called in tier 1:
- of `plan_put_attestation`, right after `check_licence_payload` (~line 770). This covers the put door and, through `apply_planned`, the replicated door and the edition-2 ingest (which ends in `put_attestation`);
- at the local door after `check_media_source` (~line 1541).

### `src/store/parity.rs` (foreign hunk)

`("check_dimension_key_segments", Class::Gate)` sits after `check_media_source`. That anchor was chosen away from K2's hunk at -906.

### `src/federation/namespace/mod.rs` (foreign hunk, E6 owns the tests there): `pub mod key_segment;`

### `src/federation/key_segment_invariants.rs` (NEW, test-only) and `src/federation/mod.rs` (foreign hunk)

The `mod` line sits after `directory_double_1232_invariants`, away from P2's hunk.

## Tests (block I2960–I2989; used I2960–I2966)

| Inv | Where | What |
|---|---|---|
| I2960 | `key_segment::tests` | `is_key_segment`: accepted: 43 chars with zero trailing bits (fills Q, `-`, `_`). Refused: 42 chars, 44 chars, trailing bits, `=` padding, standard `+`, the URN, 64 hex, `acme`, empty. |
| I2961 | `key_segment::tests` | `segment_of` and `identity_ref_of` are inverse. They agree with Verify's `is_identity_ref` and round-trip Verify's own `identity_ref(&thumb)`. `family_param_of` and `key_id_of_param` are inverse; earlier-form ids pass through unchanged. |
| I2962 | `key_segment::tests` | The gate, on `dimension` AND `scope` tokens. A bare segment admits (licensure and track record). Malformed: a URN (licensure, and credits), and trailing bits. `licensure:acme` follows `EARLIER_FORM_DOORS_SHUT`. Other families and rows with no dimension are untouched. |
| I2963 | `licensure::tests` | `authority_of(licensure:<seg>[:v1])` is the identity-ref, and `licensure_stem_of` writes the segment (they are inverse). A URN dimension reads `urn` (and the door refuses it). The fold, asked by key id, matches a v62 kid's segment rows and not another's; asked by the bare segment, it matches nothing. |
| I2964 | admission tests, next to the 814 scope tests | **`scope_covers` directionality over a key segment.** The root and parent cover the caveat; the caveat covers itself and its sub-caveat. A child covers neither its parent nor the root. Another key's caveat, and a caveat on a prefix of the segment, are not covered. The relation is antisymmetric. |
| I2965 | `key_segment_invariants::tests::i2965_{sqlite,postgres}` | A board whose key id is an identity-ref, its licences on `licensure:<segment>:v1`: (a) its own licence admits and folds when asked by key id; (b) its `license`-scoped officer's licence ADMITS; (c) a stranger naming the edge is refused `licensure_delegator_not_authority`, and nothing is stored; (d) the officer's licence folds as the board's. |
| I2966 | same body | **A URN in the dimension**, and a trailing-bits segment, are `MalformedRow(envelope_member_invalid)` at `put_attestation` AND at `apply_replicated_attestation`. A `delegates_to` whose caveat `infra:attest:licensure:<URN>` is malformed at the door. Nothing is stored. |

Mutation targets:
- `is_key_segment`'s trailing-bit check and its length check;
- the gate's `contains(IDENTITY_REF_PREFIX)` arm;
- `authority_of`'s `key_id_of_param` (dropping it reds I2963/I2965);
- `licensure_stem_of`'s `family_param_of` (dropping it makes I2965 (b)/(d) miss: the prefix query would ask for the URN).

## Lead's rulings (applied)

1. **Key-only in v62 (CC 3.4.9).**
   - Strict refusal at CP2 (arm 3, tied to `EARLIER_FORM_DOORS_SHUT`) stays as written. Nothing is special-cased.
   - **For F0 / synthesis to remove:** `src/federation/migration.rs:1571`, the literal `"moderation_track_record:ciris-canonical:v1"` in the exclusion-class reachability test. It is earlier-form data and no longer carries.
     - It is a pure classifier probe (`is_exclusion_bearing`) that passes through no door, so it does not go red under the gate.
     - It should still be rewritten to the canonical key's segment, or dropped, with the fixture flip.
2. **Scope tokens carry the segment.**
   - `check_dimension_key_segments` now also checks every `scope` token of the envelope (a bare string or an array) against `KEY_BEARING_SCOPE_STEMS = ["infra:attest:licensure:"]`, with the same three rules (URN anywhere; trailing bits; non-segment once the doors shut).
   - A token is admitted at the put, replicated, local and promotion doors, and the gate already runs at every one of them.
   - The bare parent `infra:attest:licensure` carries no parameter and is not matched.
   - **Producers and fixtures:** persist has NO producer of an `infra:attest:licensure:*` token (grepped). The only literals are the pure `scope_covers` tables in admission.rs tests (`…:acme`, `…:other`, lines ~20451–20627). They never reach a door, so they are left as they are; I2964 is the segment-form twin.
   - Producers I could not reach: none in persist. External producers (Server/Edge) must write the segment.

## What E2's tests can assume (licensure_chain_invariants.rs, affiliation_licence_invariants.rs)

- **Write** a v62 authority into a dimension with `licensure::licensure_stem_of(&authority_key_id)`, or `format!("licensure:{}:v1", kid_thumb(seed))` with E0's helper; both give the bare segment.
- **Ask** every API by the authority's KEY ID (its identity-ref). That covers `status_set_for(holder, &board)`, `licence_authority_set`, `licences_issued_under` and `resolve_licensure_authority`. `authority_of` returns the identity-ref.
- The door gates (`check_licensure_delegator_is_authority`, partner-record revision, licence audience, reconsideration duty-holders) all resolve the dimension's segment to the key id.
- A URN in a dimension is refused `MalformedRow(envelope_member_invalid)` at every door.
- Earlier-form authority ids (`acme`) keep working while `EARLIER_FORM_DOORS_SHUT == false` (open question 1).
- **Signer-seed trap:** `test_support::seed_for` seeds from the first 32 bytes of a key id, and every identity-ref shares 34. So identity-ref ids registered through `register`/`hybrid_pubkeys` all get the SAME keypair. No backend forbids a duplicate pubkey (V300 has no such unique index; read-checked), but two such keys sign alike. Use one per database, or E0's seeds.

## Assumed APIs

None from other agents. Verify `edition2::{IDENTITY_REF_PREFIX, is_identity_ref, identity_ref}` are present in the pinned 23.1.3 under `pqc`, which is always on. The fixtures `steward_liveness_test_support::{register, signed_row, store}` and `test_support::reseal` were read-checked. **E4 (admission.rs tests): keep those helper signatures.**

## Compile risks

1. **`licensure::authority_of` changed its return type, from `Option<&str>` to `Option<Cow<'_, str>>`.** Every caller on v62-syn0 is adapted (admission.rs and licensure.rs; grepped). **A caller in ANY other wave patch** (E2's licensure fixtures, E4/E7, K-lanes) that uses `authority_of` will not compile until it adds `.as_deref()` or `&*`. The lead checks this at synthesis.
2. `check_dimension_key_segments`: the `refuse` closure returns `Err(..)` and relies on the fn's return type for inference (the same pattern as `check_licence_audience`'s `refuse`). `if EARLIER_FORM_DOORS_SHUT` on a `const bool` may draw a clippy lint I don't know of.
3. I2965 (b): the officer edge is built with `signed_row` + `subject_key_ids` + `reseal`, copied from E2's `edge()` without its instant overrides. If (b) fails for a non-licensure reason, compare with `licensure_chain_invariants::bodies::edge`.

## Not done

- No CHANGELOG entry (R0). Suggested: "A key in a family name is its bare base64url thumbprint (CC rc21, CC 3.1; `namespace::key_segment`). `licensure::authority_of` reads it back as the identity-ref; a URN, or a second spelling of a key segment, in a `dimension` is refused `envelope_member_invalid` at every door."
- No other key-bearing family has a persist parser, so there is nothing else to route. `moderation_track_record:{community_key_id}` is matched by prefix only (migration.rs:612, steward_purge). `credits:…:{subject}` is a topic, not a key.
