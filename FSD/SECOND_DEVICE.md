# The second device — v50.0.0 (CIRISPersist#919, #916, #920, #917)

Status: LOCKED 2026-09-26 (operator: "evaluate the impact … if everything looks good, lock it in and proceed"). Persist's release lead evaluated each interpretation against CC RC5, the FSDs and the shipped code; every one turned out to be already decided there, so this document records the basis and the build, not a new ruling.

The theme: CIRISServer's second-device flow ("sign in on a second device by approving on the first; files and chats just show up") was blocked three ways in persist, and CIRISEdge's attributed sync door booked a duplicate as a refusal. All four are one MAJOR because #920 and #917 change signatures.

## 0. The four interpretations, their basis, and their impact in practice

| # | Interpretation | Basis (already decided) | Impact in practice |
|---|---|---|---|
| #919 | A row naming a cohort target is never a widening candidate. | CC 5.2 structural invisibility applies to self/family; CC 3.1.9: `cohort_scope` is the emitter's per-envelope choice; `build_widening` (#801) carries the NEW placement's target, so a federation widening naming no room is correct. #530's repair is for rows STRANDED without a placement (traces, which name no room). | The self-room handshake (KeyPackage/Welcome/Commit) stays in the room; a second device joins. Family rows can no longer leave the family. #530's trace repair is unchanged: traces name no room. No wire change, no hash moves. |
| #916 | A member's new device receives exactly what the member holds. | CC 2 `history_on_join` governs a NEW MEMBER; CC 4.4.3.4.5 Option A: entitlement is what the member held during membership; the built self/family precedent `rekey_for_newcomers` grants a newcomer every blob the cohort already holds, idempotently. | History opens on the second device. A removed member's device gets nothing (the fold says not active). An evicted epoch is `ContentMiss`, fail-honest (CC 5.1 P4). Authority is the owner-binding, never the roster: the member's standing does not change. |
| #920 | On a software host the MLS-state key derives from the persisted software content master; the opener returns the custody kind. | `BLOB_ENCRYPTION_AT_REST.md` §4.3/§10.2: "a software fallback honest about being software"; `ContentMasterSource::SoftwareFallback`, `federation_content_master.key_kind`. CC 4.2.2.1: `hardware_class` is a measured claim; software is a class, not a failure. v49's opener departed from this (persist's error). | CI and dev hosts get a durable, truthfully labelled store. Hardware hosts (hardware row) are unchanged. One case moves: a TPM host whose row says SOFTWARE and that already holds a v49 store (CIRISEdge v32.1.0 keyed it from the hardware seed regardless of the row). v50 tries the software key first and then, never minting, the v49 hardware key; the store opens reported `hardware` with a `legacy-v49-hardware-keyed-under-software-row` descriptor and is not re-keyed. One root per posture (no seed file — that would be a third root on software hosts). `HardwareCustodyUnavailable` stays for §11.7 only. The opener's shape changes (MAJOR). |
| #917 | `put_attestation_synced` returns the typed `ReplicatedAttestationOutcome`. | Persist's own rule: clean-break API changes, bundled into the feature cut. Not a CC question. | Edge's ledger books a decoration-only re-delivery as a duplicate on both doors. The peer-origin metering is kept. Return type changes (MAJOR). |

Also locked, built elsewhere: #914 — disclosure sets are blobs (the ruling is on the issue; the store is the cut after v50). #751 closed as ruled 2026-08-19. #912's per-membership listing span is the CC's own wording (CC 2 field table) and stands as shipped in v49.

## 1. #919 — the sweep never widens a placed row

**Defect.** `list_widening_candidates` selects every `tier='federation' AND cohort_scope IN ('self','family')` row with no widening yet; the sweep (`Engine::promote_consented_backlog`, the widening-candidates pass) widens each to the audience of a covering grant, and the widening carries the new placement's target — none, for `federation`. A row `share` placed in a self room (`community_key_id = <owner>`, `cohort_scope = self`) is therefore re-published federation-wide without its room seconds later, and the room's own fold (`supersedes` stands for the claim, CC 4.4.3.3.1) finds nothing.

**Rule.** A candidate is a row whose signed envelope names NO cohort target (`admission::COHORT_TARGET_ENVELOPE_FIELDS`: `community_id`, `community_key_id`, `cohort_key_id`, `family_key_id`). The exclusion is applied in the same place on all three backends (sqlite, postgres, memory), by the same predicate, and the read is documented as "stranded rows only".

**Invariant I186** (memory, sqlite, postgres): a self-scoped row naming a self room plus a federation consent grant covering its dimension → after the sweep the row is unchanged and has no widening; a family-scoped row naming a family, same grant → unchanged; a self-scoped row naming NO target, same grant → widened (the #530 case still repairs). Also: the room's own reader still finds the placed row after the sweep.

## 2. #920 — the MLS-state root follows the content master

**Rule.** The MLS-state key = HKDF(root, `MLS_STATE_CONTEXT`) where `root` is what `content_master_key` / the persisted `federation_content_master` row resolves to on this host: the hardware-sealed seed (`key_kind='hardware'`) or the persisted software master (`key_kind='software'`). The persisted row wins (§10.2): a store created on a software host keeps opening after a TPM appears.

**Shape.** `Engine::open_mls_state(path) -> Result<(XChaChaKvStore, MlsStateCustody), _>` (or the equivalent on the backend), where `MlsStateCustody { kind: "hardware" | "software", descriptor }` is returned so hosts log the class by name. The bare `XChaChaKvStore::open_mls_state(path)` of v49 is REMOVED (clean break; it could only refuse on software hosts). `KVError::HardwareCustodyUnavailable` is kept for exactly the §11.7 case: the row says hardware and the seed is unreachable.

**Seed policy (as built — changed from v49).** First-open-may-seal is NOT kept for the MLS-state opener: under a hardware row it asks `create_seed_if_absent = false` on every open, including the first open of an empty store. The row proves a seed was sealed when it was written; an absent seed is §11.7's lost keyring, and minting there would also move the content master. The only moment the MLS/content path seals a seed is the content-master row's initialisation (the secrets store's own first migration, `derive_hardware_master_key`, also seals one) (which `open_mls_state` performs on a node with no row), and a process-wide lock in `secrets::hardware` serializes that exists-then-store so concurrent first writers seal one seed.

**v49 compatibility.** Under a software row, only when the store is in use and its verifier refuses the software-derived key, the opener tries v49's key, HKDF(hardware seed, `MLS_STATE_CONTEXT`), with `create_seed_if_absent = false`. On success: `kind = hardware`, descriptor `legacy-v49-hardware-keyed-under-software-row …`, nothing re-keyed. Both keys failing is `WrongPassphrase`. A fresh store under a software row is always `software`.

**Invariant I187**: on a software content master the store opens, reports `software`, survives a reopen, and derives a DIFFERENT key from the content master itself (domain separation); on a hardware row with no reachable seed it refuses `HardwareCustodyUnavailable` and writes nothing; the hardware branch over the storage double reports `hardware`; a software-created store reopens after the row is unchanged even when hardware becomes available (the row wins); and (compat, I187f) a v49 store keyed from the hardware seed under a software row opens reported `hardware` with the `legacy-v49-hardware-keyed-under-software-row` descriptor, not re-keyed, while a fresh store under that row stays `software`; if hardware-backed storage is present but that v49 seed is unusable the answer is `HardwareCustodyUnavailable` carrying the reason, never a mint; with NO hardware backing (v49 refused there, so no v49 store can exist) or when both keys were tried it is `WrongPassphrase`. The split is a typed result (`secrets::hardware::HardwareDeriveError` → `encrypted_kv::HardwareRootError`), never a message match.

## 3. #916 — a member's new device gets what the member holds

**Door.** `rekey_community_member_device_add(community_key_id, member_key_id, new_occurrence_key_id, authority)` on every backend, orchestrated in `at_rest_cascade` beside `rekey_family_member_add` / `rekey_self_occurrence_add`. It re-wraps to the new occurrence's content-KEM key every retained `(community, epoch)` DEK the member already holds a grant on (per-minter epochs, #848), idempotently (a grant already present is skipped). No epoch bump: the member set did not change.

**Authority.** The new occurrence must be bound to the member by the member's owner-binding (CONSENT_BY_HUMANS `for_key_id`; OCCURRENCE_PRINCIPAL), and the member must be ACTIVE by `authorized_community_roster_at` at the call's instant. A device claimed by a different owner, an unbound occurrence, a removed member, or an occurrence lacking `encryption_pubkeys` is refused by name (typed), never granted a plaintext fallback.

**Invariant I188** (memory, sqlite, postgres): a member with grants on epochs E1..E3 adds a device → the device holds grants on E1..E3 and can unwrap each; re-running adds nothing; a device bound to ANOTHER owner is refused; a removed member's device is refused; an epoch the node no longer retains is reported, not silently skipped.

## 4. #917 — the attributed sync door has a typed pre-write outcome

**Change.** `put_attestation_synced(record, peer)` runs `plan_replicated_attestation_apply` over `(existing, incoming)` and acts on the plan, returning `ReplicatedAttestationOutcome` (`Inserted` / `Unchanged` / `Deduplicated` / `Refused { reason }`) — the same enum the unattributed door returns — while keeping the `peer` argument and `shares_cohort_with(peer)` metering. A same-signed-assertion, different-decoration re-delivery is `already_present_identical` (a duplicate), never `Error::Conflict`; a different signed row is `conflicting_attestation`. `AttestationOutcome` remains for `put_attestation`.

**Invariant I189** (memory, sqlite, postgres): the same bytes through both doors yield the same outcome variant; a decoration-only re-delivery is `Deduplicated` on the attributed door; a different signed row under the same id is `Refused { conflicting_attestation }`; metering still refuses a non-cohort peer.

## 5. Not in scope

#914's store, `erase_object` and mint API (the next cut). Server#650's roster-book read. The `listed_members` capsule op (Server has not asked).

## 6. Verification

Per slice: witnesses RED first, then green on every backend; a mutation round on the new predicate/door (table appended below by the slice); an independent review against this document. Release: the full unfiltered lanes (sqlite, postgres, union), the gate chain, `certify.sh full` on the exact SHA.

## 7. Mutation tables (appended by each slice)

### #919 — the sweep never widens a placed row

**Triggers (determined, TESTED where marked).** Persist has one production widening builder: `Engine::widen_audience` (`crossing::build_widening` → sign → `FederationDirectory::widen_audience`). Its only automatic caller is the consent sweep's widening step (`Engine::sweep_widen`), which runs on both passes of `promote_consented_backlog`:
- pass 1 widens a LOCAL row straight after it enters the mesh, from the local page;
- pass 2 widens rows from `list_widening_candidates`.

The sweep itself fires at three points: chokepoint (c), right after this node emits its own consent grant (`emit_attestation_assemble`); chokepoint (a), every ingest batch (`receive_and_persist`, pyo3); and the host's tick. The other callers of `widen_audience` are the explicit pyo3 method `widen_audience` (a host's "publish this row wider") and test fixtures (`tier_ingest::test_support::widen`, the `bootstrap_admission` `exercise_*` bodies).

So the rule is applied twice:
- in the candidate read, on all three backends (pass 2's page);
- in `sweep_widen` (both passes; pass 1 never consults the candidate read). TESTED: a placed row still LOCAL when the sweep runs is entered into the mesh at `self` and not widened. Without the `sweep_widen` guard it is widened (M8).

`Engine::widen_audience` stays callable for a placed row. It is documented as the one deliberate path, and I186 pins that an explicit call still crosses.

**Where a row names its room (review of 4a973395, F1).** A row is placed if either of two things holds:
- a top-level `COHORT_TARGET_ENVELOPE_FIELDS` alias is populated. Chat rows name their room this way (Edge `chat.rs`), as does every targeted placement;
- a blob pointer's owner slot is non-empty: the `community_key_id` of a pointer-shaped member, at top level or as an array item (`blob_pointer::names_pointer_owner`, the same scan as `pointer_for`, with the discriminator shared). This is the room the bytes are held in.

Edge v32.1.0's self FILE rows name their room ONLY in the pointer's slot. A self room has no `cohort_target_field` (`scope_room.rs`), and Edge's own test asserts "a self row names no cohort target". Edge's self-room file read keys on `file.pointer.community_key_id` (`files.rs`). The first cut read only the aliases, so every Edge self file row was still a candidate and was still widened.

**SQL form of the pointer arm.** The member set is open: the Rust scan reads every member by construction. So the SQL walks the same two positions instead of a list of paths:
- SQLite: `json_tree` restricted to a top-level member (`path = '$'`, not the root) or an item of a top-level array (`path` = that array's `fullkey` from `json_each`). Nested `json_each` cannot be used here: SQLite evaluates a table-valued function's argument on every row, and a scalar member's value is not JSON.
- Postgres: `jsonb_each` plus `jsonb_array_elements` under a lateral join.

The pointer discriminator is the same in all three: a 64-hex `content_sha256` string and a non-empty string `community_key_id`. There is no generated column: that would need a migration, and a stored copy of the rule would need its own drift check. The scanned set is bounded by the self/family corpus (`tier='federation' AND cohort_scope IN ('self','family')`), not by the stranded rows. Placed rows are never widened, so they stay in that set permanently, and every sweep runs the pointer scan over each of them. The read already runs two correlated subqueries per row. If mobile sqlite shows the cost, the follow-up is a generated column holding the placement bit, pinned against `envelope_names_cohort_target`.

**Witness.** CIRISServer's self-files ladder, primary arm in Edge's REAL self-file shape:
- `file:v1`, with the pointer under `content`, the owner only in `content.community_key_id`, a `filename`, `evidence_refs`, and no top-level target;
- two of these rows in the mesh, and one still local;
- one `chat:key_package:v1` row naming the room at top level;
- a family file row naming `family_key_id`;
- a grant covering `file:`/`chat:` at `federation`.

The candidate-read fixture adds a pointer inside an array (`attachments`) and a pointer with an EMPTY owner slot (stranded).

Arm (d) models Edge's reads:
- `files::in_room`: `dimension = file:v1` and the pointer's owner slot is the room;
- `chat::rows_in_room`: top-level `community_key_id`;
- both under `LifecycleView::Live`, so any row a `supersedes` stands for is hidden.

It asserts every placed row's supersedes chain is empty and that the read lists exactly the originals. **RED before the pointer arm (commit 09cd8d99 on 4a973395):**
- sqlite and postgres sweep: `I186 (d): the supersedes chain of placed row … is not empty — Edge's live listing hides it, and the second device lists nothing`;
- memory, sqlite and postgres candidate read: the read returned `a-edge-attachment` and `a-edge-file`.

After the fix:
- no `supersedes` anywhere in the corpus stands for a placed row;
- no other row carries a placed file's filename;
- the stranded self file row (no target, no pointer owner) is widened to `federation` (#530 unchanged).

Lane: `scripts/pg_test_db.sh -- cargo nextest run -j 3 --no-fail-fast --features sqlite,postgres -E 'test(sweep_placement) | test(530) | test(widen) | test(promote_consented)'` (19 tests; the postgres legs ran against a live database). Every mutant was applied to a clean committed tree (3c6139ff) and reverted with `git checkout --` before the next. 15 of 15 killed; none OOM-killed. M14 and M15 (review L2) ran on 2a2cf889, which also tightened the rendering pin to the pointer arm's own spellings; re-run there, it fails on M10 and M11.

| Mutant | Killed by |
|---|---|
| M1 drop the read's exclusion (aliases and pointer) on all three backends, keep the sweep guard | I186 candidate read on memory, sqlite, postgres; I186 sweep on sqlite and postgres |
| M2 read only the `community_key_id` alias | the rendering pin; candidate read on all three; sweep on both |
| M3 exclude only when `cohort_scope = 'self'` | candidate read on all three (the family rows); sweep on both |
| M4 invert | candidate read on all three; sweep on both; `list_widening_candidates_filters_suppressed_scopes_530`; `consent_sweep_widens_a_row_that_entered_before_the_grant` |
| M5 drop the read's exclusion on memory only | candidate read on memory; (e) "sqlite and memory disagree" |
| M6 an EMPTY alias counts as a target | candidate read on all three (`c-empty-target`) |
| M7 drop the read's exclusion on postgres only | candidate read and sweep on postgres; (e) "postgres and memory disagree" |
| M8 drop the `sweep_widen` guard (pass 1's trigger) | sweep on sqlite and postgres |
| M9 drop the read's exclusion and the guard (d61614dc behaviour) | candidate read on all three; sweep on both |
| **M10 drop the pointer arm on all three** (Rust and both SQL forms) | the rendering pin; candidate read on all three; sweep on both, by (d): "the supersedes chain of placed row … is not empty" |
| **M11 the pointer arm on memory only** (both SQL forms lack it) | the rendering pin; candidate read on sqlite and postgres; (e) "sqlite and memory disagree"; sweep on both ("placed row … is a candidate") |
| M12 pointer arm without array items (Rust and both SQL forms) | candidate read on all three (`a-edge-attachment`) |
| M13 an EMPTY owner slot counts as a room (Rust and both SQL forms) | candidate read on all three (`c-pointer-no-owner`) |
| M14 sqlite reads a pointer at any depth (the `ptr.path` restriction dropped) | (e) "sqlite and memory disagree"; candidate read on sqlite (`c-pointer-nested` excluded) |
| M15 postgres recurses into every nested object (`jsonb_path_query(top.value, 'lax $.**')`) | (e) "postgres and memory disagree"; candidate read on postgres; the rendering pin (`jsonb_array_elements(` gone) |

**Deviation from §1, stated (F3).** §1 names only the four top-level aliases. Placement is now read from those aliases AND from a blob pointer's owner slot, because that slot is where Edge's self file rows name their room. The rule is still narrower than the issue's "or was placed by `share`": persist has no share marker. A row that names its room in neither place (for example a self row carrying no pointer and no alias) is still a candidate.

Two further readings:
1. "Populated" means a non-empty JSON string, both for an alias (the `envelope_cohort_target` reading, M6) and for an owner slot (M13). An empty or non-string value names no room.
2. §1 names the candidate read. The rule is also asked in `sweep_widen`, because pass 1 widens from the local page (#919's second comment: "cover every trigger"). A placed local row still enters the mesh at its own scope.

### #920 — the MLS-state root follows the content master

**Opener:** `Engine::open_mls_state(&self, path: impl AsRef<Path>) -> Result<(XChaChaKvStore, MlsStateCustody), KVError>` (async; gated on `encrypted-kv`), where `MlsStateCustody { kind: MlsStateCustodyKind /* Hardware | Software */, descriptor: String }` and `kind.as_str()` is `"hardware"` / `"software"`. It reads, or initialises, the row through the new `BlobStorage::load_or_init_content_master_row` (sqlite, postgres; `load_or_init_content_master` now resolves that row), then calls `XChaChaKvStore::open_mls_state_from_row` (`pub(crate)`, no backend import) on the blocking pool. v49's `XChaChaKvStore::open_mls_state(path)` is removed. The error type is `KVError`, so hosts match `HardwareCustodyUnavailable` directly; a row-load failure is `KVError::Backend`.

**Mechanism.** Both arms call CIRISVerify's `derive_symmetric_key` (HKDF-SHA-256, verify's salt, `info = MLS_STATE_CONTEXT`). The software arm passes the persisted master through an in-process, read-only, one-entry `SecureBlobStorage` that reports `is_hardware_backed() == false`. So the two arms share one mechanism and differ only in the root, and persist implements no KDF of its own.

**Deviation from §2.** §2 said first-open-may-seal is unchanged. It is not. Under a `hardware` row the opener asks `create_seed_if_absent = false` on every open, including the first open of an empty store. The row's existence proves a seed was sealed when the row was written. An absent seed is §11.7's lost keyring, and minting there would also move the content master and orphan the corpus. So the only moment a seed may be sealed is the content-master row's own initialisation, which `open_mls_state` performs on a node with no row. `open_rooted` still reports `first_open` and the I184 witnesses stand, but nothing grants a mint from it.

Lane: `scripts/pg_test_db.sh -- cargo nextest run -j 3 --features postgres,sqlite,encrypted-kv,secrets -E 'test(i184) | test(i187) | test(mls_state) | test(domain_separated) | test(content_master)'`. Baseline: 24/24 pass. Each mutant was applied to a clean committed tree and reverted before the next.

**Review round (after the independent review; tree at `c8e12b3a`).** The first round's six mutants were re-run on the reviewed code and four new ones were added. The lane gains `test(seed)`. Baseline: 66/66.

| # | Mutant | Result | Killed by |
|---|---|---|---|
| M1 | software arm derives under `CONTENT_MASTER_CONTEXT` | KILLED 65/66 | `i187_b_…domain_separated…` |
| M2 | software arm reports `kind: Hardware` | KILLED 57/66 | i187_a, i187_e, i187_f fresh-stays-software, and the sqlite+postgres Engine legs (software row, no-row, v49 compat) |
| M3 | §11.7 refusal replaced by minting (`hardware(true)`) | KILLED 63/66 | both i187_c tests, i187_d |
| M4 | row-wins dropped: hardware preferred whenever available | KILLED 58/66 | i187_a, i187_a malformed, i187_b, i187_e, both i187_f units, both Engine v49 legs |
| M5 | v49's may-mint-on-first-open (`hardware(!path.exists())`) | KILLED 63/66 | both i187_c tests, i187_d (in the combined run the mutant did not compile, so it was fixed and re-run alone) |
| M6 | software arm uses the master verbatim, no HKDF | KILLED 63/66 | i187_b, and the sqlite+postgres software legs |
| M7 | compat arm dropped (a v49 store under a software row is `WrongPassphrase`) | KILLED 62/66 | `i187_f_a_v49_store…`, `i187_f_the_compat_arm_never_mints`, both Engine v49 legs |
| M8 | compat arm PREFERRED: hardware key tried first under a software row | KILLED 59/66 | i187_a, malformed, i187_b, **i187_e**, fresh-stays-software, both Engine v49 legs |
| M9 | compat arm may mint (`hardware(true)`) | KILLED 64/66 | `i187_f_a_v49_store…` (asked to mint), `i187_f_the_compat_arm_never_mints` |
| M10 | `SEED_MINT_LOCK` dropped | KILLED 65/66 | `concurrent_first_derivations_seal_one_seed` |

10/10 killed; no `signal: 9`.

**Re-check round (tree at `80134b94`).** Three changes went in: sqlite's row init derives through `dispatch_blocking`; the compat arm's refusal is typed (`HardwareRootError`: no hardware backing → `WrongPassphrase`, seed unusable with backing present → `HardwareCustodyUnavailable` with the reason); and two twin witnesses were added. The affected mutants were re-run and two new ones added, all on the clean committed tree, each reverted before the next. Baseline: 69/69. M3 and M5 were rebased onto the new `hardware(false).map_err(…)` line; in the first pass their appliers did not match, so they were re-run alone.

| # | Mutant | Result | Killed by |
|---|---|---|---|
| M3 | §11.7 refusal mints (`hardware(true)`) | KILLED 66/69 | both i187_c tests, i187_d |
| M5 | may-mint-on-first-open (`hardware(!path.exists())`) | KILLED 66/69 | both i187_c tests, i187_d |
| M7 | compat arm dropped | KILLED 63/69 | four i187_f units (v49 store, both-keys, no-backing twin, never-mints) and both Engine v49 legs |
| M9 | compat arm may mint | KILLED 65/69 | four i187_f units |
| M10 | `SEED_MINT_LOCK` dropped | KILLED 68/69 | `concurrent_first_derivations_seal_one_seed` |
| M11 | compat arm drops the reason (`Unreachable` → `WrongPassphrase`) | KILLED 68/69 | `i187_f_the_compat_arm_never_mints` |
| M12 | no hardware backing collapsed into seed-absent (`NotHardwareBacked` → `HardwareCustodyUnavailable`) | KILLED 68/69 | `i187_f_no_hardware_backing_is_wrong_passphrase_not_custody` |

7/7 killed; no `signal: 9`.
