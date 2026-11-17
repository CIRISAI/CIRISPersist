# v62 status: where the refactor stands (2026-11-17, spun down)

`release/62` is the unified v62 branch: everything built so far, plus the work in progress (as patches under `FSD/v62_wip/`). It is not a release yet. `CHANGELOG.md` `## [62.0.0] - UNRELEASED` carries each slice's changes, tests and adoption notes.

## The goal

v62 moves persist onto the CIRIS kernel crate and the CC v1.0-rc20 clean mesh. "Nothing carries": a v62 node accepts and produces only edition-2 (CBOR/COSE, composite-signed) statements, starts from `ceg-genesis-bundle/2`, and deletes its v61 store at upgrade. The same node module also runs in a browser (wasm32) and UEFI.

## Pins

| Dependency | Pin on this branch | Target for the v62 tag |
|---|---|---|
| ciris-kernel | tag `kernel-v0.2.0` | same |
| CIRISVerify | tag `v23.1.3` | `v23.3.0`, the halt-reader fix (not yet tagged); slice C bumps it |
| CC | rc20 read, not vendored | `v1.0-rc20` (tag d4bd2a6), vendored in slice C |

## Merged here (each slice's own tests green; full lib lane 4,993 at J0)

- **A: host seams.** Clock, executor and lifecycle (`src/host/`), so node code makes no direct clock, spawn, signal or `block_on` calls.
- **B: storage profile.**
  - the attestation read seeks V216 in order (two-phase on SQLite);
  - the host open profile (exclusive-first WAL, zero readers);
  - persist's own migration runner.
- **C: kernel adapter** (`src/kernel/`, kernel-v0.2.0).
  - consensus, owner_of, the trust edge leg and the cycle gate answer through the kernel, after `layers::kept`;
  - the departures are adopted;
  - benchmarks are at or near the pre-kernel baseline.
- **D: Verify 23.1.3.**
  - composite-only signatures; earlier-form objects are refused at the door;
  - the node/host feature split;
  - the wasm node gate, linking a module with exactly 3 `ciris:node/*` imports;
  - encrypted-kv on wasm.
- **E1: rc20 rules on the earlier wire.**
  - the identity-set exclusion;
  - canonical as a conferral; substrate_persist confers nothing;
  - X-Wing transit/hop keys, live only by rebind;
  - accord recovery (CC 4.2.6);
  - licensure waits for its quorum;
  - typed KeyRecordConflict;
  - the infrastructure carve-out re-keyed (a security fix).
- **E2a: the edition-2 door** (`federation::edition2`, `Engine::put_edition2_statement`).
  - row ids are node-computed; names come from `refs`;
  - HeldKeys liveness;
  - the generic parts of genesis bundle/2, and `put_genesis_bundle`;
  - the CDE purge digest.
- **E2b: the V300 edition-2 schema baseline,** equal to V001..V216, plus `delete_earlier_store` at open (legal-hold guard, dry run, refuses a foreign or other-owner schema).
- **J0: reconciliation.**
  - edition-2 keys and revocations are projected into `federation_keys` / `federation_revocations` as read models, with one fold;
  - the cross-form refusal `earlier_form_signer_is_edition2`;
  - the test codec (`edition2::codec`), the producer (`edition2::produce`) and `edition2_statements_since`.

The kernel performance work is upstream in CIRISKernel PR #3, released as `kernel-v0.2.0`.

## Work in progress (`FSD/v62_wip/`, not applied)

Both shutdown slices were stopped at spin-down. Neither compiles yet, so the pre-commit hook refused them. Apply each with `git apply --index` on a branch cut from this commit.

### `v62-cut-a.staged.patch` (JSON cut slice A: inbound doors)

**Done:**
- the switch `edition2::door::EARLIER_FORM_DOORS_SHUT = false`, with `refuse_earlier_form(plane)` / `refuse_earlier_form_row`;
- that refusal wired as the first line of 28 JSON doors;
- `apply_replicated_statement` (never compiled).

**To clear the hook:** the test-only `with_earlier_form_doors_shut` has no caller yet.

**Next, in design order:** `put_statement` builds the earlier Signed* struct from the verified voices, then runs the existing planned door inside a task-local "vouched" scope.
1. In that scope:
   - `verify_hybrid` accepts the composite;
   - the earlier-form refusal passes;
   - JSON row minting and the cosign hold are skipped.
2. Counted rows: store the statement, count the voices; short → `Pending`; met → the mapped row, then the projection.
3. The classifiers skip rows that carry `ceg_statement`.
4. `attestation_of` writes `references_attestation_id` from `refs.target`.
5. A composer whose target is not held waits (`WithdrawsTargetUnheld`).

**Halt** (CC 4.2.1.1):
- the roster is the bundle in force for `accord_root`; with none held, the halt waits;
- an unknown kid waits;
- `iss_not_holder` is refused;
- one holder's composite statement latches the halt.

**Also to build:**
- `edition2::payloads`, the payload mapping, which CC has adopted as the reading; plus `docs/EDITION2_PAYLOADS.md` for CC;
- `composer_family_mismatch`;
- the `accord_invocation_replayed` dedup (invocation_id / nonce within valid_until);
- `location_proof:v1`, with its witnesses ignored until Verify registers the family;
- `trust:blessing`.

**Open rulings:**
- delivery receipts: store the composite's halves in `HybridSignature`;
- later `group:roster` versions (the supersede path);
- typed tables for `revocation:{entity}` (non-key), `cosign:{state}` and `takedown_notice`.

### `v62-cut-b.staged.patch` (JSON cut slice B: producers and serving)

**Done:**
- the v31 re-stamp migration is deleted;
- the PQC cold path is mostly deleted.

**To finish the deletion:**
- remove the remaining `CompletePqc`, `AttachPqc` / `plan_key_attach_pqc` and `HybridPendingRow`;
- fix the tests that still call the deleted methods;
- drop the `.pyi` and FFI classification rows for `attach_*_pqc_signature` and `run_pqc_sweep`.

**Keep:** `adopt_scrub_upgrade` until slice C, because genesis seeding still uses it.

**Next:**
- `register_self_federation_key` writes a `key:record` and returns the identity-ref, dropping `roles`, `identity_ref` and `registration_envelope`;
- `local_derived_key_id()` returns the identity-ref;
- producers move to `sign_row` + `put_statement`;
- delegations use the CC-confirmed families:
  - `self:delegates_to`;
  - `ownership:{relation}:{target_kind}:{version}`, with the node as second voice;
  - `self:delegates_to:agent_occurrence`;
  - `trust:{job}:{version}`;
- withdraws / recants / supersedes carry the target's family;
- serving goes through `edition2_statements_since`, with lookups by row/statement id and the wire index keyed on statement_id;
- drafts become a CBOR payload plus Sig_structure.

### `w614-lts-floor.removal-floor.patch`

The 61.4 removal-floor work-in-progress (commits after v61.4.0 on `w614-lts-floor`). It is unreviewed and was never merged; re-target it to the kernel model before using it.

## Remaining to the v62 tag

1. Finish JSON-cut A and B (the patches above).
2. **C: genesis bundle/2 and boot.**
   - the producer and reader on Verify's `edition2::genesis` reader;
   - `test_ceremony_v2`; boot pre-genesis;
   - canonical = `serve_nodes` (ruling C);
   - the Verify 23.3.0 bump;
   - vendor CC rc20.
3. **D: PyO3, capsule and HTTP surfaces.**
4. **E: the fixture flip,** about 3,270 tests, using `statement_of` / `kid()` / `rid()`.
5. **F:** flip `EARLIER_FORM_DOORS_SHUT`, delete the dead earlier-form code (`TODO(json-cut)` sites) and the baked JSON genesis, and add a from-disk gate.
6. **Kernel second pass:**
   - fork-as-tip in `held_head_verdict`;
   - delete the 21 breaker gates and the single-owner gate;
   - windows and sweeps;
   - key_end liveness (`TODO(key_end)`).
7. **Release gates:**
   - full certify;
   - the wheel pytest;
   - the wasm gate;
   - the kernel benches against `pre-kernel` (baseline doc on branch `bench-pre-kernel`);
   - the adoption notes;
   - then `scripts/release.sh 62.0.0 --hold`.

## Owed to other teams at the pin

- **CC:**
  - the file and line of I1846, to close the divergence `persist/self:delegates_to/admission refusal`;
  - the edition-2 payload member lists.
- **Verify:** the v62 tag. Verify vendors `tests/vectors/accord_lineage/accord_lineage_v2.json` at SHA-256 `d3ace82c…7191`, so keep that file byte-identical.

## Branches pushed with this one (history and evidence)

The slice branches:
- `v62-seams`, `v62-native`, `v62-kernel`, `v62-verify`, `v62-rules`, `v62-wire`, `v62-baseline`, `v62-j0`.

Other branches:
- `bench-pre-kernel`: the pre-kernel benches and `BENCHMARKS-pre-kernel.md`;
- `wasm-uefi-probe`: `WASM_UEFI_READINESS.md`;
- `vec-accord-lineage`;
- `w614-lts-floor`.
