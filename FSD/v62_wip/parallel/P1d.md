# P1d: the payload lists enforced at the edition-2 door

Base: `v62-syn0` @ 8f33957f, worktree `/home/emoore/CIRISPersist-wp-P1` (shared with P1 and P1c). Nothing was built; every claim is BELIEVED, and "read-checked" marks what I confirmed by reading.

## Which patch to apply

- **`P1d.patch` is CUMULATIVE**: P1 + P1c + P1d, all 13 files, against v62-syn0. Apply it INSTEAD of `P1.patch` + `P1c.patch`.
- `P1.patch` (3 files) and `P1c.patch` (10 files) were regenerated from the same tree, so they are disjoint slices of `P1d.patch`. The P1d edits are inside them too (payloads in P1, door in P1c).
- The cut-B foreign hunks stay separate: `P1-cutb-ingest.patch` and `P1-cutb-custody.patch`.

## What changed

### `src/federation/edition2/payloads.rs`

- New `pub fn family_by_id(family_id) -> Option<&FamilyPayload>`. It matches the HEADER family id (label -70002, `{name}` → `.name`) through Verify's `namespace_match::family_id(f.family)`, the same mapping E0's `fixture_switch` uses (read-checked).
- All 11 `FAMILIES` keys are registry prefixes, one each (read-checked in `namespace_registry.json`).
- New `pub fn check_by_id(family_id, payload)`: `check` for the mapped family; `Ok` for a family with no list, as before.
- **The device_class vocabulary has ONE source.** `CLOSED_VALUES` no longer closes `identity:occurrence.device_class`: its vocabulary is `types::device_class::is_valid` (`admission::check_device_class`, token `federation_device_class_rejected`), which O1's `read_payload` calls.
  - Closing it in the list as well would have answered `edition2_payload_invalid` first and contradicted O1's token.
  - The list still requires the member and types it as tstr.

### `src/federation/edition2/door.rs::pure_statement_gates`

- **Step 6** (after the edition-1 refusal): the header's family id goes through `payloads::check_by_id(family, &payload)`.
  - A family with a list: an unknown member, a missing required member, a wrong type, a closed value or leaf, or a prose rule broken is refused `edition2_payload_invalid`.
  - No family in the header: `Ok`, and Verify's verdict names that fault.
- **The check is PURE and runs before any directory read on every path that runs the pure gates:**
  - `put_statement`, the one entry for local, **replicated** and tier ingest (the module doc says so; read-checked);
  - `admit_row` (cosign voices, the halt, every admit);
  - `verify_carried` and `check_carried_projection`. The JSON door's carrying rows are therefore checked first too, through `plan_put_attestation`'s first statement.

## O1's `read_payload` and the list: one source

- The list is the shape (presence, type, unknown members), checked at the door. `read_payload` runs later and adds rules the list cannot state:
  - `author == identity_key_id`;
  - `sub == occurrence_key_id`;
  - the `device_class` vocabulary (its own token);
  - the `valid_until` window;
  - the `transport_destination` / `encryption_pubkeys` internals;
  - `onion_relay == {opt_out: true}`;
  - key separation.
- Every member and type `read_payload` reads matches O1's list entry, because the entry is O1's, copied verbatim. The door never refuses a payload `read_payload` would admit for shape.
- I told O1 that `device_class` is no longer closed in the list.

## Witnesses

- **I2918**, adjusted: `device_class: "toaster"` now passes `check`. The vocabulary is `check_device_class`'s, refused at O1's door.
- **I2919** (`payloads_invariants.rs`):
  - `i2919_every_mapped_family_has_a_door_case` (unit): every `FAMILIES` entry has a case in `door_cases()`, so the door witness cannot silently skip a family that is added later.
  - `door::i2919_the_lists_are_enforced_at_the_door_sqlite` / `_postgres` (store-backed). The backend is wrapped in `FaultInjectingDirectory` with EVERY delegated method erroring (names read from the generated double), so any directory read answers `federation_backend`. For each of the 11 mapped families, one statement signed under the family's header id:
    - a broken payload is refused `edition2_payload_invalid` by `put_statement` with zero reads. The kinds of break, spread across the families: an unknown member (roster `charter_digest`, takedown `notice_terms`, receipt `K`), a missing required member (membership `effective_at`, revocation `revoked_at`), a wrong type (occurrence `device_class` uint, occurrence revocation text `reason`, key grant text `wrapped_dek`), a closed leaf (cosign `lineage_head`), and the closed custody map (`expires_at`);
    - a valid payload passes the pure gates and reaches the directory (the injected `federation_backend`);
    - a family with no list (`evidence:.suite:.kind:.cell:.prefix`, an arbitrary member) passes the payload check as before.
- **"A valid one admitted":** each family's valid payload is witnessed as passing the door's payload gate (reaching the read). Full storage per family needs family-specific setups that I could not build here (roster seats, duty-holders, grants). One full admission through the whole door of a family with a list is the natural S-lane follow-up.
- P1d invariants used: I2919. I2920–I2929 are free.

## Compile risks

1. `mod door` inside `payloads_invariants.rs` uses `use super::*` (the parent's private fixtures and imports) plus `super::super::door_invariants::fixture::{iref, key}`. The explicit import shadows the glob of the same item, so there is no ambiguity.
2. `include_str!("../directory_double.rs")` resolves relative to `src/federation/edition2/payloads_invariants.rs`.
3. `ciris_verify_core::namespace_match::family_id` used from `payloads.rs` (pub; E0 uses it).

## Semantics to watch at synthesis (the real risk)

- **Enforcement turns on for all eleven families at once.** Every edition-2 producer and fixture of a mapped family must now state exactly its list. Payloads built from EARLIER envelopes (E0's `statement_of`, cut-B's producers) carry earlier member names. Those are refused `edition2_payload_invalid` at the door:
  - roster: `family_key_id`, `family_name`, `prev_head_digest`, `charter_digest`, `policy_blob`;
  - key grant: `GrantWrap` fields, `cohort`, `community_id` as a family member;
  - membership and occurrence revocation: a text `reason`;
  - custody: `expires_at`, which the `P1-cutb-custody.patch` producers no longer emit.

  The S-lane must fix those producers and fixtures to the list, not loosen the list.
- **Tokens shift for shape faults the family doors used to name:**
  - a custody `here` without `size` was `custody_ack_malformed` and is now `edition2_payload_invalid`;
  - a key grant without `owner` on content was `key_grant_malformed` and is now `edition2_payload_invalid`;
  - an unknown takedown basis likewise.

  Witnesses asserting the old token on an EDITION-2 statement will flip; earlier-form JSON rows are unaffected. Grep for `custody_ack_malformed`, `key_grant` refusals and takedown shape refusals in edition-2 fixtures.
- **The cosign family's payload is the event's (`OVER_THE_EVENT`).** Only its leaf and `also` roles are checked; the event's members are checked under the event's own family.
- **The member-name mismatch** (`identity` / `occurrence` on occurrence_revocation vs `identity_key_id` / `occurrence_key_id` on occurrence) is left alone, pending CC.

---

## Addendum: CC's naming ruling, `identity:occurrence_revocation`

- **`payloads.rs`:** the revocation's members are renamed `identity` → `identity_key_id` and `occurrence` → `occurrence_key_id`. These are the occurrence record's own names, one to one; the types and presences are unchanged.
- **`docs/EDITION2_PAYLOADS.md`:** re-rendered (Python port; re-bless with `CIRIS_BLESS_PAYLOADS=1` if I2102 drifts), with a line added to the corrections list.
- **The door mapping that reads them:** none exists. No production code reads these payload members by name, on syn0 or at cut-B's tip (read-checked by grep for `get_text("identity")` / `get_text("occurrence")` across every wave worktree and `v62-cut-b`; `freshness.rs`'s `"occurrence"` is a target-kind string, not a payload member). The door's list (`payloads::check_by_id`) is therefore the only reader, and it reads the new names.
- **E0's fixture codec:** it derives member types from `FAMILIES`, so it follows the rename. Any producer or fixture still writing `identity` / `occurrence` on this family is refused `edition2_payload_invalid` at the door. The lead is relaying the rename to the E-agents.
- **Witnesses:**
  - the `occurrence_revocation()` fixtures (I2906, the I2919 door case) now use the new names;
  - **I2920** (new): the new names admit; the short spellings are refused as unlisted members; a missing `occurrence_key_id` is refused.
  - I2918's "short spelling" case is relabelled: `occurrence` is now a spelling no family uses.
- **Patches:** `P1d.patch` (cumulative) and `P1.patch` are regenerated; `P1c.patch` is unaffected.
- P1d invariants used: I2919, I2920. I2921–I2929 are free.
