# P1c: the edition-2 door runs its pure gates before any directory read

Base: `v62-syn0` @ 8f33957f, worktree `/home/emoore/CIRISPersist-wp-P1` (shared with P1). `P1c.patch` holds only the six P1c paths, so it applies independently of `P1.patch`. Nothing was built. Every claim is BELIEVED; "read-checked" marks the ones I confirmed by reading.

## The finding (E4) and the fix

- **Before:** `ingest::put_statement` called `require_statement_form` and then read the directory before any other check:
  - the accord roster (`halt::roster_in_force`), for an invocation;
  - otherwise the signer's key plane (`held_keys_for` → `edition2_statements_about`).

  The size and shape checks ran only inside `admit_row`, after that read, and there was no size gate at all ahead of the mapped row's `check_envelope_size_admission`. So an oversized statement from an unknown signer drew a read and answered the retryable `federation_attester_key_unknown`.
- **After:** the pure gates run first, at every edition-2 door that reads.

## What changed, file by file

### `src/federation/edition2/door.rs`

- New `pub const MAX_STATEMENT_BYTES = admission::MAX_ATTESTATION_ENVELOPE_BYTES` (1 MiB). It caps the statement's bytes as received ("the signed thing is the sized thing", CC#38's rule).
- New `pub fn pure_statement_gates(bytes, keys: &dyn KeyOwnership) -> Result<(), Error>`. It is a pure function of the bytes. In order:
  1. the form (`require_statement_form`, `earlier_form_object`);
  2. **the size**: over the cap is `Error::EnvelopeTooLarge { bytes, cap }` → `federation_envelope_too_large`;
  3. the decode: non-COSE bytes are `statement_invalid`, named by Verify's reader. This is the existing code moved; `keys` is used only for the label;
  4. an object typ is `not_a_row`;
  5. an edition-1 row-ref is `row_ref_edition_1`.
- `admit_row` now opens with `pure_statement_gates(bytes, keys)?`, which replaces its own copies of steps 1 and 3–5 (moved, not duplicated). Verify's verdict (`verify_row_in_family_with`), key-of-identity (`kid_not_of_iss`), row id, the key-record end rule and the names are untouched and in the same order.
- The module docs (step 1) note the size gate and the pure-first rule.

### `src/federation/edition2/ingest.rs`

- `put_statement`: `require_statement_form` is replaced by `pure_statement_gates(bytes, &HeldKeys::new())`. It sits ahead of the halt branch's roster read and ahead of `held_keys_for`.
- `verify_carried`: the same call ahead of its `held_keys_for`. That path is already bounded by the mapped envelope's size gate, so this is for consistency.

### `scripts/gen_directory_double.py` and the regenerated `src/federation/directory_double.rs` (foreign)

- **A second finding, fixed here.** The fault-injecting double did NOT delegate any edition-2 store method. Their defaults are "none held" or a `Backend` refusal, which the parser cannot tell from a composition. So through the double:
  - every edition-2 read answered empty;
  - a fault declared on `edition2_statements_about` was never seen;
  - any "zero reads" witness through the double could not fail.
- I added eight leaves to `DELEGATED_DEFAULTS`:
  - `edition2_statements_about`, `edition2_voices`, `edition2_rows_naming`, `edition2_objects`;
  - `put_edition2_object`, `put_edition2_statement`;
  - `upsert_edition2_key_projection`, `edition2_statements_since`.

  Each is overridden by both sqlite and postgres (read-checked: 9 matches per backend file).
- `key_edition` stays out: its default is a composition over `lookup_public_key`.
- I regenerated with `python3 scripts/gen_directory_double.py`; `--check` reports OK with 149 delegations (TESTED, python only).
- **At synthesis:** cut-B's tip changes the trait in `federation/mod.rs`, so rerun the generator on syn1. The list entries carry over.

### `src/federation/edition2/pure_gates_invariants.rs` (new) and `edition2/mod.rs` (registration)

Registered under `#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]`. The I2914 witnesses:

- `i2914_the_pure_gates_need_no_directory` is a pure unit test:
  - oversized → `federation_envelope_too_large`;
  - under the cap → passes;
  - edition-1 ref → `row_ref_edition_1`.
- `i2914_pure_gates_precede_the_directory_read_sqlite` / `_postgres` are store-backed:
  - the backend is wrapped in `FaultInjectingDirectory` with EVERY delegated `async fn` declared `erroring`. The names are read from the generated double via `include_str!`, so any directory read answers `federation_backend`.
  - **The instrument can fail:** an under-cap statement from an unknown signer draws `federation_backend`, because it reaches the key-plane read.
  - Then, with zero reads:
    - an oversized statement → `federation_envelope_too_large`;
    - an edition-1 name → `row_ref_edition_1`;
    - a JSON object → `earlier_form_object`.
  - The test also asserts that the double delegates `edition2_statements_about`.
- I2915–I2929 are unused.

## The existing witness, by reading

E4's rewritten `gate_order_test_support::assert_pure_envelope_gates_precede_the_directory_read` (E4.patch ~l.6762) runs this path: `offer(dir, &big, seed)` → `e2::statement_of` → `edition2::ingest::put_statement`. The row's envelope carries `"pad": "x" * 2 MiB`, so the statement is over 2 MiB and over `MAX_STATEMENT_BYTES`. `pure_statement_gates` refuses it with `Error::EnvelopeTooLarge`, whose `kind()` is `"federation_envelope_too_large"` (mod.rs:13778, read-checked), before `held_keys_for`. That is exactly what the witness asserts. BELIEVED GREEN.

The syn0 (pre-E4) body of that witness goes through `put_attestation` with an earlier-form row, and this change does not touch it.

## Refusal tokens

None new. The size refusal reuses `Error::EnvelopeTooLarge` / `federation_envelope_too_large`, the JSON door's own.

## Assumed APIs

None from other agents. Read-checked:
- `Error::EnvelopeTooLarge { bytes, cap }`;
- `HeldKeys::new()` and `impl KeyOwnership for HeldKeys`;
- `FaultInjectingDirectory::{new, erroring}`;
- `ingest::INGEST_TIER`;
- `malformed_row::{EDITION2_ROW_REF_EDITION_1, EDITION2_EARLIER_FORM_OBJECT}`;
- the fixtures `key`, `iref`, `map`, `ref1`;
- `sign_row_statement`.

## Compile risks

1. `pure_statement_gates(bytes, &HeldKeys::new())` relies on `&HeldKeys` coercing to `&dyn KeyOwnership`; inside, `verify_row_statement(bytes, keys)` relies on upcasting `&dyn KeyOwnership` to `&dyn KeyDirectory`. `admit_row` already did the latter.
2. `include_str!("../directory_double.rs")` resolves relative to `src/federation/edition2/`. The double is `cfg(any(test, feature="test-anchor"))` and the test module is test-only, so that is fine.
3. **The hunks may not apply cleanly at syn1.** Cut-B's tip rewrote much of `ingest.rs` and the trait. The anchors (`require_statement_form(bytes)?` in `put_statement`, and `let keys = held_keys_for(dir, &bytes)` in `verify_carried`) exist at cut-B's tip (read-checked), but the line numbers differ. Apply 3-way and regenerate the double.

## Semantics to watch

- **The double now reaches the edition-2 store.** Every existing test that wraps a backend in `FaultInjectingDirectory` and offers edition-2 statements now reads the backend's real statements instead of "none held". That is the correct behaviour, but a test that unknowingly leaned on the empty default could flip. Grep `FaultInjectingDirectory` users: `attester_key_unknown_invariants`, `attestation_apply*`, `operational`, `admission`, `rc5_adopts_invariants`, `attestation_query_invariants`, `store/test_hooks`.
- **A new cap on statements that never met a size gate before.** Key-plane statements, voices and accord invocations are now capped at 1 MiB. None is near that in practice.
- **(SUPERSEDED by part 3, which fixes it in production.)** Possible finding for E4's byte-dimension witness (`assert_byte_dimension_is_wired`, 900 KiB rows).**
  - A 900 KiB statement passes `MAX_STATEMENT_BYTES`. But the mapped row's envelope carries the statement again as hex (`ceg_statement`, two characters per byte), so its canonical size is about 2.7 MiB. `check_envelope_size_admission` in `plan_put_attestation` refuses that unless the per-peer byte quota (charged earlier) refuses first.
  - The witness expects every non-quota refusal to be `federation_cohort_scope_rejected`. It could see `federation_envelope_too_large` instead. This is independent of P1c, but worth a look in the S4 lane.
  - The structural answer is to size the mapped envelope without the carried statement, or to count it at its byte length.
- **Not moved ahead of the read:**
  - `valid_until > asserted_at`, and every other payload rule that Verify's verdict judges: moving them would reorder Verify's sequence (the brief says keep it).
  - `payloads::check`: it is wired nowhere yet, and wiring it is a new rule rather than a reorder.

## NOT done

- No change to the JSON doors.
- `cosign.rs:1500`'s `held_keys_for` on a held statement is unchanged: the statement is already held, not offered.

---

# P1c, part 2: the typed `weight` column (E1's finding)

## The fix (`src/federation/edition2/ingest.rs`)

- **The defect:** `attestation_of` rescaled the payload's fixed6 `weight` into the envelope JSON, but never set `Attestation.weight`. Every edition-2 row was stored with weight NULL, so the weighted folds (`topology::build_trust_topology` and `replication::trust_scoring`, both `weight.unwrap_or(1.0)`) read every edge at 1.0.
- New private `fixed6_real(payload, member) -> Option<f64>` (n / 10^6). It is now the one conversion, shared by the envelope rescale loop (`SCALED_MEMBERS`) and the column.
- **The column:** `a.weight = fixed6_real(&row.payload, "weight")`, or `None` when absent. A negative fixed6 (`Nint`) is a negative real.
- **The mirror:** the row mirror (`envelope.row`) now carries `weight` when the column is `Some`. This is required: `admission::check_row_column_binding` binds `row.weight` to `envelope.row.weight` in both directions, compared numerically (admission.rs ~l.8231-8268, read-checked). Without it, setting the column alone would make every weighted mapped row fail `typed_diverges_from_envelope`.
- **`verify_carried`:** the "is this row exactly the statement's projection" comparison now includes `expected.weight == row.weight`. Before, a carried row could ride the JSON door with any weight column.

## The other places a typed row is built from a statement (grep)

- `edition2::ingest::attestation_of` is the only statement → `Attestation` builder. Read-checked with `serde_json::from_value(...Attestation)` and `Attestation {` greps over `edition2/`, `cosign.rs` and `replication/`.
- `cosign.rs` puts rows it receives from `attestation_of` and holds voices as statements. `projection.rs` builds `federation_keys` / `federation_revocations` rows, which have no weight.
- The `key_plane.rs`, `self_roster.rs` and `occurrence_revocation_carrier.rs` builders are earlier-form carriers, not statements. No further omission was found.
- **"The kernel adapter reads it":** no kernel module reads `Attestation.weight` (read-checked). `kernel::trust::edge_rows` and `kernel::owner` build `KRow`s from ids, names and signers; the kernel's `weights` are a `weighted:` rubric's, from the group record. The column's readers are `topology` and `trust_scoring`, so the witness reads it back through `build_trust_topology`.

## Witness: I2915 (`src/federation/edition2/weight_column_invariants.rs`, registered in `edition2/mod.rs`)

- **`i2915_the_mapping_fills_the_weight_column` (pure).** It runs `attestation_of` over an `AdmittedRow` for a `self:delegates_to` row (`delegates_to` type, a real signed statement for `bytes`). The `AdmittedRow` is built by hand so Verify's family model is not in the loop.
  - weight 2_500_000 → `Some(2.5)`; the mirror `row.weight` is 2.5 and the envelope `weight` is 2.5;
  - `Nint(499_999)` → `Some(-0.5)`;
  - absent → `None`, and the mirror names no weight.
- **`i2915_the_weight_column_is_stored_and_read_sqlite` / `_postgres` (store-backed).**
  - A weighted (2_500_000) score row in Verify's vector family is offered through `put_statement` and stored with `weight == Some(2.5)`. `build_trust_topology` (granter = the signer) gives one edge of weight 2.5.
  - A fresh mapped row whose weight column was altered to 9.0 is refused `typed_diverges_from_envelope` through `put_attestation`, and nothing is stored.
- **Why the stored witness uses a score row, not a `delegates_to`.** A `delegates_to` admission runs the scope, node-agency and user-target steward gates, which need roster and identity setup I cannot run here. The mapping is family-agnostic (one code path), and the pure test covers the `delegates_to` shape.
  - **Suggested for the S-lane** once E0's `e2::put_key` / `statement_of` are in: the same assertion on a `delegates_to` produced with weight 2.5.
  - E1's `federation_directory_query_topology_direct_sqlite` (R4 in E1.md) should turn green with this fix, provided its producer states `weight` in the payload. Cut-B's `attestation_emit` writes `input.weight` into the envelope (cut-B emit.rs ~l.481), but E0's `statement_of` builds the payload from the ENVELOPE and does not carry the `weight` COLUMN. A fixture that sets only `Attestation.weight` therefore still produces no payload weight. BELIEVED; flagged to the synthesis lane (E0.md lines 123-124 record the same gap).

## Semantics to watch (part 2)

- **A carrier type now refused for weight.** `row_type.rs:216` refuses a carrier-type row whose `weight` column is `Some` (`CarriesWeight`). An edition-2 carrier whose payload carries `weight` used to pass, because the column was NULL; it is now refused. That is the gate's intent.
- **Key grants:** `key_grant.rs:671` requires the weight to be 1.0 when present. Payload weight 1_000_000 maps to 1.0, so this is unaffected.
- **The stored bytes change** for any mapped row with a weight: its `original_content_hash` changes because the mirror gains `weight`. v62 is unshipped, so no stored rows are affected.

## Compile risks (part 2)

1. In the test, `AdmittedRow { .. }` is built with every field listed. The field set was read-checked on syn0 and at cut-B's tip (13 fields).
2. `serde_json::json!(w)` for an `f64` under `arbitrary_precision`. The value is finite by construction (n / 1e6).
3. `insert_record` returns `Option<Digest32>`, and the test ignores it, as `ingest_invariants` does.

The P1c invariants used so far are I2914 and I2915 (see part 3 for I2916).

---

# P1c, part 3: the mapped envelope does not count the carried statement twice

## The bug

`attestation_of` puts the statement into the mapped row a second time, as hex (two characters per byte), under `ceg_statement`. `check_envelope_size_admission`, the earlier-form 1 MiB canonical cap that `plan_put_attestation` runs on the mapped row, counted that hex. So a 900 KiB statement, which is under the door's `MAX_STATEMENT_BYTES` (1 MiB), mapped to an envelope of about 2.7 MiB and was refused `federation_envelope_too_large`.

## The fix (`src/federation/admission.rs`, foreign: a small hunk at `check_envelope_size_admission`)

- **An envelope that carries a statement** (`ceg_statement` holding text):
  - the carried member is bounded on its own: hex length ≤ 2 × `MAX_STATEMENT_BYTES`, else `EnvelopeTooLarge { bytes: hex_len / 2, cap: MAX_STATEMENT_BYTES }`;
  - the rest of the envelope (a clone with the member removed) is measured against `MAX_ATTESTATION_ENVELOPE_BYTES` exactly as before.

  Both bounds stay, so the work a hostile JSON row can buy is still bounded: at most 1 MiB of rest plus 2 MiB of hex. A forged carrier is then refused by `verify_carried`.
- **An envelope with no carried statement** (every earlier-form JSON row) goes through the unchanged path (new private `check_envelope_canonical_size`, the old body).
- **A non-text `ceg_statement`** is treated as uncarried: the whole envelope is measured, and `verify_carried` names the fault (`envelope_member_invalid`).
- The public signature is unchanged, and every call site is unchanged.

## Witnesses: I2916 (in `src/federation/edition2/pure_gates_invariants.rs`)

- **`i2916_the_envelope_gate_does_not_count_the_carried_statement_twice` (unit):**
  - `{pad: 900 KiB, ceg_statement: 1.8 MiB hex}` admits;
  - a carried member over the statement cap is refused;
  - a carrying envelope whose rest is over 1 MiB is refused;
  - an earlier-form envelope over 1 MiB is refused, and one at 900 KiB admits (unchanged).
- **`i2916_a_900_kib_statement_is_stored_sqlite` / `_postgres` (store-backed):** a live `user` key's score row with a 900 KiB `pad` text member passes `put_statement` (every gate, the quota included) and is stored. The test asserts the fixture is over 900 KiB and ≤ `MAX_STATEMENT_BYTES`.

## Notes and risks (part 3)

- **Residual inflation:** `json_of` renders a `bstr` payload member as hex. A statement whose bulk is a byte string over about 512 KiB still maps to a rest-of-envelope over 1 MiB and is refused. Text, as in the witness and E4's pad, is unaffected. The structural answer is to size an edition-2 row only by its statement. Not done here, because the rest-cap is what bounds a hostile JSON carrier.
- **The per-peer byte quota still charges the stored envelope**, hex included (`envelope_charged_bytes`): a 900 KiB statement costs about 2.7 MB of the 9.2 MB burst. That is honest (it is what is stored). E4's byte witness binds sooner but still binds on the Bytes dimension. Unchanged.
- **The witness's `pad` is an extra member on the evidence family's score row.** Verify bounds only `body.note` (read-checked, `edition2/mod.rs:624`). If a persist evidence-shape gate refuses unknown members, swap in `attestation:self_verify` as E4 does. BELIEVED fine: E4's pad rows reach the cohort gate.
- **Compile:** `serde_json::json!({ STATEMENT_MEMBER: ... })` uses a const as a key expression (`Into<String>`, read-checked in serde_json's macro). `super::edition2::{ingest::STATEMENT_MEMBER, door::MAX_STATEMENT_BYTES}` from `admission.rs`: both modules are `pub`.

## Part 2 confirmation

The `Attestation.weight` fix (column from the payload's fixed6 `weight`, mirror `weight`, the `verify_carried` comparison) and its I2915 witness (2.5 stored and read back by `build_trust_topology`, sqlite and pg) are in `P1c.patch` (grep-checked in the regenerated patch).

P1c invariants used: I2914, I2915, I2916. I2917–I2929 are free.

---

# P1c, part 4: a carried statement is capped by its own bytes only

Part 3's "rest of the envelope ≤ 1 MiB" bound still refused a statement under the door cap whose bulk is a byte string, because `json_of` renders it as hex. That residual is now closed.

## `admission.rs::check_envelope_size_admission`

- **An envelope carrying a text `ceg_statement`** is capped by the STATEMENT BYTES only: `ceil(hex_len / 2) ≤ MAX_STATEMENT_BYTES`, else `EnvelopeTooLarge { bytes, cap: MAX_STATEMENT_BYTES }`. The earlier-form envelope cap is then NOT applied.
  - The derived envelope is a pure function of the capped statement (`attestation_of`), so its size is bounded by construction.
  - `verify_carried` refuses a carrier whose envelope is not exactly that projection.
- **No carried statement (every earlier-form JSON row), or a non-text member:** the unchanged 1 MiB canonical cap.

Part 3's helper `check_envelope_canonical_size` stays as the earlier-form path.

## I2916, extended

- **Unit:** the "rest over 1 MiB is refused" case is replaced by its opposite. A carrying envelope with a 1.8 MiB hex `blob` plus a 1.8 MiB carried statement admits. The case for a carried member over the cap (refused) and the earlier-form cases (unchanged) stay.
- **Store-backed, sqlite and pg:** `big_body` offers two 900 KiB statements from one live key, each admitted through `put_statement` and stored:
  - `pad`, a text member;
  - `blob`, a 900 KiB `bstr` member: about a 1.8 MiB derived envelope before the carried copy.

  Byte quota: the two rows charge about 2.7 MB + 3.7 MB of the 9.2 MB burst, so both fit (BELIEVED, by arithmetic over `envelope_charged_bytes`).

## Residual (accepted by the coordinator's ruling)

- A hostile JSON-door row may carry a small, valid `ceg_statement` beside a large forged rest. That rest is no longer size-capped at `check_envelope_size_admission`. It is refused by `verify_carried` (tier 3, `typed_diverges_from_envelope`), after the gates between pay for canonicalizing it.
- What bounds that work is the transport body caps (the 8 MiB HTTP ingest cap, AV-7) and the per-peer BYTE quota, which still charges the whole stored envelope. Persist's own door caps do not cover it.
- (CLOSED by part 5.)

P1c invariants used: I2914, I2915, I2916 (see part 5 for I2917).

---

# P1c, part 5: the carried-projection check runs first

## Production

- **`edition2/ingest.rs`:**
  - New `pub fn check_carried_projection(row: &Attestation) -> Result<(), Error>`. It is PURE: it takes no directory, verifies no signature, and does not canonicalize the offered envelope.
  - For a row carrying `ceg_statement`, in order:
    1. the carried hex decodes (else `envelope_member_invalid`, as before);
    2. the door's pure statement gates (form, the 1 MiB size cap, decode, not an object, no edition-1 name);
    3. the header and payload yield a row (else `edition2_statement_invalid`);
    4. the row id is hex and equals the statement's (else `edition2_row_id_mismatch`);
    5. the row equals `attestation_of` over the UNVERIFIED header and payload (else `typed_diverges_from_envelope`). The derived side is bounded by the statement cap, and the envelope comparison runs last among the fields.
  - `Ok` for a row that carries no statement.
  - New private helpers, shared with `verify_carried` so the two cannot drift:
    - `unverified_row(bytes) -> Option<AdmittedRow>`, with the header and payload fields `attestation_of` reads; `statement_id` is zeroed and `role` is `None`, since the mapping reads neither;
    - `offered_row_id`;
    - `require_projection` (the equality, `weight` included).
  - `verify_carried` (tier 3) is unchanged in effect: it still verifies the statement under the signer's held key plane and compares the VERIFIED projection.
- **`attestation_admit.rs::plan_put_attestation`:** `check_carried_projection(&row)?` is the FIRST statement, ahead of `validate_subject_key_ids`, the genesis-reserved gate, the held-row settle (a directory read), the tombstone read, the quota and the size gate. It is one shared plan for both backends.
- **`store/parity.rs` (foreign):** `("check_carried_projection", Class::Gate)` is added to `CALL_CLASSES`, because the from-disk parity scanner refuses an unclassified propagated call in the shared plan. The pinned order subsequence (`check_write` … `check_cohort_scope`) is unaffected: a new head does not break a subsequence (read-checked, parity.rs ~l.3203).

## Witness: I2917 (in `pure_gates_invariants.rs`)

- **`i2917_a_forged_envelope_beside_a_valid_statement_is_refused_for_pennies` (pure).** It starts from the honest mapped row of a small valid statement (`admit_row` under a held record, then `attestation_of`).
  - The honest row passes.
  - The forged row (the same carried statement plus a 3 MiB `pad`) is refused `typed_diverges_from_envelope`.
  - A different row id is refused `edition2_row_id_mismatch`.
  - With the carried member removed (earlier form), the row passes untouched.

  "Zero directory reads" holds by construction: the function has no directory parameter. "Before canonicalization": it canonicalizes only the derived envelope (statement-bounded), never the offered one.
- **`i2917_a_forged_carrier_is_refused_first_sqlite` / `_postgres` (store-backed).**
  - The forged row is also given a malformed subject (`subject_key_ids = [""]`), which the door's previous first gate refuses with its own error. It is offered through `put_attestation`.
  - The answer is `typed_diverges_from_envelope`, so the projection check leads the door. Nothing is stored.
- **Why not the counting double here:** `FaultInjectingDirectory::put_attestation` delegates to the INNER backend, whose plan reads through the backend itself, so the double cannot observe the plan's reads. The zero-read property is carried by the pure signature instead, and the ordering by the store witness.

## Risks (part 5)

- **The unverified derivation must read the header as Verify does** (`iss` CWT 1, `sub` CWT 2, type -70001, family -70002, `kid` 4, payload `asserted_at` / `author`). If Verify normalizes any of these, an honest carrier would be refused here. `RowId::of_statement` reads the same labels (read-checked), and the honest-row cases of I2917 and I2909's door witnesses would catch a mismatch.
- **Re-offers of an honest held row now pay one projection** (an `attestation_of` over at most 1 MiB) before the settle. Before, the settle came first.
- **Compile:** `statement_parts` is `pub(crate)` in `liveness` (already imported in `ingest`); `RowId::of_statement` is pub; `Value::as_bytes` / `get_int` are read-checked.

P1c invariants used: I2914–I2917; I2918–I2929 are free.
