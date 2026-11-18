# P1e: CC rc21 kernel admission on the payload lists

Base: `v62-syn0` @ 8f33957f, worktree `/home/emoore/CIRISPersist-wp-P1`. Nothing was built; every claim is BELIEVED, and "read-checked" marks what I confirmed by reading.

**`P1e.patch` is CUMULATIVE:** P1 + P1c + P1d + P1e, 14 files. Apply it INSTEAD of P1d / P1c / P1. The cut-B patches (`P1-cutb-ingest.patch`, `P1-cutb-custody.patch`) stay separate.

The source is `/home/emoore/cc-kept/rc21-admission/wire.md`, read as data.

## What changed

### `src/federation/edition2/payloads.rs`

- **New `Ty::Tstrs`** (`[* tstr]`): a set of text, sorted by encoding and unique; it may be empty, because emptiness is the verifier's rule, with its own token. **E0's exhaustive `typed_value` match needs an arm (messaged).**
- **New family `admission:unit`**:
  - members: `unit` (Digest, R), `capabilities` (Tstrs, R), `valid_until` (Ms, R); `refs.head` (O, counted only). `asserted_at`, `author` and `dimension` are common;
  - `sub`: `canonical:sha256:{hex}`;
  - authorship cell: counted where `refs.head` is present, authored otherwise; effects need a count; every signer a person; no delegate;
  - voices: counted, at least two persons, a shortfall held.
- **"Lands in"** is `ceg_statements` plus `federation_attestations` (the mapped `scores` row), with no typed plane. CC puts standing, the lease and the halt on the host's side ("read by the host, never by the verifier"), and persist has no admission table. Every non-key edition-2 row is mapped into `federation_attestations` by `put_statement`. (`attested_key_id` has no FK, read-checked in V300, so the tagged-text `sub` stores.)
- **Constants:** `ADMISSION_UNIT_FAMILY`, `ADMISSION_CAPABILITIES` (7, closed), `ADMISSION_EFFECTS` (5), `UNIT_LEASE_MAX_MS` (86 400 000), `ADMISSION_UNIT_SUB_PREFIX`, and `ADMISSION_UNIT_RULES` (token → rule, rendered).
- **`pub fn check_admission_unit(sub, payload)`**: the verifier's pure rules, each with ITS OWN token (not `edition2_payload_invalid`):
  - `admission_unit_malformed`: `author` XOR `refs.head`; also `sub` ≠ `canonical:sha256:{hex(unit)}`. The `sub` check is persist's reading of "sub = the unit digest", and the token choice is mine;
  - `admission_capability_unknown`: the set is empty or holds a value outside the 7;
  - `admission_lease_out_of_window`: not `asserted_at < valid_until <= asserted_at + 86 400 000`;
  - `admission_effect_needs_count`: an authored row names an effect.
- **New family `identity_amendment`**:
  - members `amendment_digest` (Digest, R) and `authorized_by` (Tstr, R: the approving response's row id, hex); `refs.prev` (O, absent on the base link);
  - `evidence_refs` is common, as a digest sequence;
  - this is persist's earlier members one to one, plus rc21's `prev`.
- **New family `deferral:response:{outcome}`**:
  - members `amendment_digest` (Digest, O) and `call_fingerprint` (Digest, O); `refs.target` (O, the request answered; earlier `references_attestation_id`);
  - leaves closed: `approved` | `rejected`;
  - prose rule: the two digests ride an `approved` response only.
- **`HASH_DIGEST_MEMBERS`** adds `call_fingerprint`, so it reads back as hex for the earlier gates and is converted by the emit side. `amendment_digest` was already there.
- **`render_markdown`** renders a "Verifier rules (each refused with its own token)" block under `admission:unit`.

### `src/federation/mod.rs` (foreign, `malformed_row`)

- Five reasons are added: `ADMISSION_UNIT_MALFORMED`, `ADMISSION_CAPABILITY_UNKNOWN`, `ADMISSION_LEASE_OUT_OF_WINDOW`, `ADMISSION_EFFECT_NEEDS_COUNT`, `ADMISSION_ISSUER_NOT_PERSON`.
- They are APPENDED to `malformed_row::ALL` after `COMPOSER_FAMILY_MISMATCH`, per that list's "appended, never inserted" rule.
- Other agents appending to `ALL` will conflict textually at the tail; resolve by concatenating, keeping the order.

### `src/federation/edition2/door.rs::pure_statement_gates`

- **Step 7**, after the payload list: an `admission:unit` statement runs `check_admission_unit(sub, payload)`, with `sub` read from CWT label 2 in the protected header.
- It is pure and runs before any directory read, so it covers the local, replicated and carried doors (as P1d).

### `src/federation/edition2/ingest.rs`

- **New `pub fn require_admission_signer_is_person(keys, row)`**: for `admission:unit` only. It reads the signing kid's live record at the row's instant from the held key plane the door already loaded; its `identity_type` must hold `user` or `accord_holder`. Otherwise the statement is refused `admission_issuer_not_person`.
- Either way, THIS statement is refused, which covers both cases in the spec: an authored row is Invalid, and a counted row's voice is refused alone.
- It is called after `admit_row` (after Verify's verdict and the key-of-issuer check, "after step 8") in `put_statement` and in `verify_carried`.

## NOT persisted, by design

- **The action review record:** node-local, carried in the trace, no row and no family (CC). Skipped.
- **The host tokens** (`admission_issuer_not_reached`, `admission_count_unmet`, `admission_none`, `admission_capability_not_admitted`, `admission_capability_not_held`, `admission_halted`): the loader's answers, never a row refusal. They are listed in the doc header only.
- **The profile digest** (`["CEG-profile/2", d0..dn]`) and its tokens (`profile_digest_mismatch`, `profile_contested`) are the agent's load check. Persist stores the links and does not compute the profile. **This is an open question for the lead:** whether persist should also serve "the chain at a head".

## P2's amendment gate and `refs.prev`: consistent (read-checked against P2.patch and `identity_amendment.rs`)

- The gate reads `authorized_by` (text), `evidence_refs` (the edition-2 digest sequence, projected to hex, which equals the response's row id hex) and `amendment_digest` (projected to hex through `HASH_DIGEST_MEMBERS`). It reads nothing under `refs`, so `refs.prev` neither feeds nor trips it.
- **"The base is authorised exactly as any amendment is":** the gate authorises each link independently, so the base and every later link meet the same rule. The spec asks no more of persist.
- **Two links naming one `prev`** are both stored. CC rules that neither counts for the profile, which is the agent's computation, not a storage refusal.
- **An approval carrying only `call_fingerprint`** (no `amendment_digest`) cannot authorise an amendment: P2's gate refuses `response_carries_no_amendment_digest`. That is consistent: a call approval is not a text approval.
- `amendment_digest` is now a digest member at the door (`[-16, bstr32]`). CC's note asks for exactly this; the earlier gates read its hex projection.

## Witnesses

| Inv | Test | What |
|---|---|---|
| I2921 | `i2921_an_admission_unit` | authored without effects passes; counted with effects passes; author+head and neither → `admission_unit_malformed`; wrong `sub` → `admission_unit_malformed`; empty and unknown capabilities → `admission_capability_unknown`; lease closed / before / over the max → `admission_lease_out_of_window`, and exactly the max passes; authored + `actuate` → `admission_effect_needs_count`; an unsorted set → `edition2_payload_invalid` (shape stays the list's) |
| I2922 | `i2922_an_admission_signer_is_a_person` | records holding `user` or `accord_holder` pass; `node`, `agent` and an unheld key → `admission_issuer_not_person`; another family is untouched. Over a hand-built `AdmittedRow` and a real `HeldKeys` |
| I2923 | `i2923_the_amendment_chain_and_the_call_fingerprint` | the base link has no prev; a later link has `refs.prev`; a top-level `prev` member is refused; `amendment_digest` is required; approved with both, either or neither digest passes; rejected without them passes; rejected with `call_fingerprint` is refused; outcome `maybe` is refused; `call_fingerprint` ∈ `HASH_DIGEST_MEMBERS` |
| I2919 | (P1d, extended) | `door_cases` gains the three families. Through `put_statement` with every directory method erroring, a broken payload is refused `edition2_payload_invalid` with zero reads and a valid one reaches the directory, on sqlite and pg. The `admission:unit` case signs with `sub = canonical:sha256:{hex}`, so its valid payload clears `check_admission_unit` too. `i2919_every_mapped_family_has_a_door_case` keeps every family covered |

- **No store-backed full admission of an `admission:unit` row:** the family is rc21's and not in the vendored namespace registry (read-checked), so Verify's verdict refuses it (`family_invalid`) before anything persist-side. That is also why I2922 is a unit test. Re-run on the rc21 vendor (registry + Verify).
- P1e invariants used: I2921–I2923. I2924–I2929 are free.

## Compile risks

1. **`Ty::Tstrs` breaks E0's exhaustive `match`** until its arm lands (messaged).
2. `ADMISSION_UNIT_RULES` references `crate::federation::malformed_row::ADMISSION_*` in a `const` slice: `&'static str` consts from `mod.rs`, so the foreign hunk must land with it.
3. In `require_admission_signer_is_person`, `r.identity_type.iter().any(|t| t == "user" ...)` compares `&String` with `&str` (`PartialEq` via deref). `Liveness::Live(Box<KeyRecord>)`; `identity_type` is a `Vec<String>` (`.join` is used on it in `ingest`, read-checked).

## Semantics to watch

- **The rc21 vendor:** until `admission:unit` is in the vendored registry, Verify refuses every such row (`family_invalid`), so only the pure gates and I2921–I2923 are live.
- **Closed maps for `identity_amendment` and `deferral:response`:** producers (CIRISServer's `agent_deferral`, E-lane fixtures) must state exactly these members. Free text goes in `body.note`; a reference to a row goes in `refs`. `authorized_by` stays a text member, the hex row id, for now. The CDDL rule "a member that names a row stands in refs" argues for moving it under `refs`; it is left as is so P2's gate reads it unchanged. This is a CC question for later.
- **`deferral:response`'s `refs.target`** keeps the earlier mapping (`attestation_of` writes `references_attestation_id` from `refs.target`). CDDL's `answers` role would fit "the row replied to" better. Unchanged; noted for CC.
