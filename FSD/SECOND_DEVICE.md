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

**Door.** `rekey_community_member_device_add(community_key_id, member_key_id, new_occurrence_key_id, authority_key_id)` on sqlite and postgres (the memory backend has no community DEK plane), orchestrated in `at_rest_cascade` beside `rekey_family_member_add` / `rekey_self_occurrence_add`. It re-wraps to the new occurrence's content-KEM key every retained `(community, minter, epoch)` DEK the member already holds a grant on (per-minter epochs, #848), idempotently (a grant already present is skipped; the insert, not the pre-check, decides what the result reports). No epoch bump: the member set did not change.

**The minter side.** Only an epoch's minter can sign the `KeyGrant` set that carries a wrap (`admit_replicated_key_grant`: signer == minter), so the host's door on the member's node reaches only the epochs that node minted; another node's epoch is reported `minted_elsewhere`. Every minter therefore re-wraps its OWN retained epochs to a member's device itself (`rewrap_own_epochs_to_member_devices`), from the receive doors every host uses and with no signer at the door: `FederationDirectory::apply_replicated_attestation` and `put_attestation_synced` on `Inserted` of an owner-binding, and the sqlite/postgres `put_identity_occurrence` on a signed occurrence, each call `FederationDirectory::rewrap_own_epochs_for_device` (default no-op; sqlite and postgres run the walk under their node key). It writes grant rows only; each grant leaves its epoch DIRTY in the V146 emission ledger, and the pending-set loop every host already runs (`Engine::emit_pending_key_grants`, PyEngine's `emit_pending_key_grants` and init sweep) signs and emits the set. Those loops first run the full walk, so a device whose occurrence arrives through a door with no hook (the trusted-local door) is covered at the next pass. `Engine::apply_replicated_attestation` also emits at once. PyEngine exposes the walk as `rewrap_own_epochs_to_member_devices_json`. Same authority, same idempotence. Cost of a full walk: communities × members × devices point reads (holders computed once per member); a wrap is computed only for an epoch a device does not yet hold.

**A member's device** (decided 2026-09-26) is the seal fan-out's definition — an ACTIVE identity occurrence of the member — with the member's live owner-binding over it as the authority. A node the member owns but does not speak through (infrastructure run for others) is not their device: the door refuses it (`device_rekey_not_an_occurrence`, retryable) and the walk never targets it.

**Own epochs only are emitted.** A grant written under a minter that is not this node's current key (a former node key, a pre-#876 row) is reported `local_only`, never `granted`: this node cannot sign that minter's set.

**Authority.** The owner-binding is the authority: the new occurrence must be bound to the member by the member's live owner-binding (CONSENT_BY_HUMANS `for_key_id`; OCCURRENCE_PRINCIPAL), and the member must be ACTIVE by `authorized_community_roster_at` at the call's instant. `authority_key_id` names who the host says is acting and must be that owner; it is not evidence of anything by itself. A device claimed by a different owner, an unbound occurrence (retryable: the binding may not have replicated yet), an owned node that is not the member's occurrence (retryable), a removed member, or an occurrence lacking `encryption_pubkeys` is refused by name (typed), never granted a plaintext fallback.

**What the member holds (ruling, 2026-09-26).** A removed-then-re-added member's new device DOES receive the epochs the member's devices already held before the removal — that is "exactly what the member holds", and CC 4.4.3.4.5 Option A (removed members retain extant grants). It must NEVER receive an epoch from the ABSENCE span, which the member never held. Built as: the holder set is the member key, the member's occurrences and the nodes the member owns, minus every key another party has ever held — any owner-binding over it by someone else (live, lapsed or withdrawn), or an identity row for it under someone else (#851). The span is cut by exclusion, not by instant: the only instants available are `asserted_at`s their signer chose (and a login anchor is re-asserted at every login), so a cut on them is forgeable backwards or drops real history. A shared or transferred device contributes nothing; the member's other devices still do.

**Reported, not skipped.** An epoch the member holds whose DEK this node cannot recover is in `content_miss` with one of three reasons: `destroyed` (ours, destroyed by policy), `lost_locally` (ours — minted under this node's key — with its row gone: escalate), `minted_elsewhere` (a peer's: its minter re-wraps it).

**Invariant I188** (sqlite, postgres): a member with grants on epochs E1..E3 adds a device → the device holds grants on E1..E3 and can unwrap each; re-running adds nothing; a device bound to ANOTHER owner is refused; a removed member's device is refused; an epoch the node no longer retains is reported, by reason; a re-added member's device gets what the member held before and nothing minted in the absence. Two-node: the minter re-wraps its own epochs to the device on the binding's arrival over the since-read (or in its pending sweep), the set crosses, and the device's wraps open on the member's node.

## 4. #917 — the attributed sync door has a typed pre-write outcome

**Change.** `put_attestation_synced(record, peer)` runs `plan_replicated_attestation_apply` over `(existing, incoming)` and acts on the plan, returning `ReplicatedAttestationOutcome` (`Inserted` / `Unchanged` / `Deduplicated` / `Refused { reason }`) — the same enum the unattributed door returns — while keeping the `peer` argument and `shares_cohort_with(peer)` metering. A same-signed-assertion, different-decoration re-delivery is `already_present_identical` (a duplicate), never `Error::Conflict`; a different signed row is `conflicting_attestation`. `AttestationOutcome` remains for `put_attestation`.

**Invariant I189** (memory, sqlite, postgres): the same bytes through both doors yield the same outcome variant; a decoration-only re-delivery is `Refused { already_present_identical }` (a duplicate, which CIRISEdge books as `Duplicate`) on the attributed door; a different signed row under the same id is `Refused { conflicting_attestation }`; metering still refuses a non-cohort peer.

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

### #916 — the device re-wrap (I188)

**Doors (final signatures).**
- Host's door: `at_rest_cascade::orchestrate::rekey_community_member_device_add(backend, community_key_id, member_key_id, new_occurrence_key_id, authority_key_id, as_of) -> Result<DeviceRekeyResult, federation::Error>`; `Engine::rekey_community_member_device_add(community_key_id, member_key_id, new_occurrence_key_id, authority_key_id)` (emits the epoch set of each `granted` epoch); `PyEngine.rekey_community_member_device_add_json`.
- Minter side: `at_rest_cascade::orchestrate::rewrap_own_epochs_to_member_devices(backend, minter_key_id, only: Option<(member, device)>, as_of) -> Result<MinterRewrapReport { changed, keyless }, Error>`. Reached by every host through `FederationDirectory::rewrap_own_epochs_for_device(owner, device)` (default no-op; sqlite/postgres run the walk under their node key; delegated by the directory double), called by the receive doors: `attestation_apply::apply_planned` (the one body both typed doors, `apply_replicated_attestation` and `put_attestation_synced`, run) on the store's `Inserted` for an owner-binding, after the §6.1 dedup re-read, and never on `Unchanged`, `Refused` or `AlreadyHeld` (#917 phase 2); and the sqlite/postgres signed `put_identity_occurrence` — writing grant rows only (dirtying their epochs). The full walk runs first in `Engine::emit_pending_key_grants`, PyEngine's `emit_pending_key_grants` and PyEngine's init sweep; `Engine::apply_replicated_attestation` emits the dirtied sets at once; `Engine::rewrap_own_epochs_to_member_devices(only)` / `PyEngine.rewrap_own_epochs_to_member_devices_json(member_key_id=None, device_key_id=None)` are the on-demand forms that also emit.
- `DeviceRekeyResult { epochs_scanned, granted (own epochs — emitted), local_only (written under a non-node minter — never emitted), already_held, content_miss: [EpochMiss { minter_key_id, epoch, reason: Destroyed | LostLocally | MintedElsewhere }] }`; the insert decides `granted`/`already_held` (`community_dek_put_member_grant` returns whether it inserted).
- Refusals: `Error::DeviceRekeyRefused { community_key_id, member_key_id, occurrence_key_id, rule }`, `kind()` `federation_device_rekey_refused`, Python `ValueError` `"<kind>: <rule>"` (as `RosterAuthorityUnauthorized` and `LocationAuthorityUnauthorized` now are). Rules `device_rekey_unbound` (retryable), `device_rekey_owner_mismatch`, `device_rekey_authority_not_owner`, `device_rekey_not_an_occurrence` (retryable), `device_rekey_member_not_active`, `device_rekey_no_encryption_pubkeys` (records `hard_case:recipient_excluded`).
- New floor read `community_dek_member_grant_epochs(community, member_key_ids)`. No `EnvelopeKind`, no hash moved.

**Through the capsule** (`dyn FederationDirectory` over the wire). Closed by #917 phase 2, witnessed by two-node (T4)/(T5). The typed doors cross whole through `ApplyReplicatedAttestation` and `ApplyReplicatedAttestationSynced`. The far side runs `attestation_apply::apply_planned` against its own backend, and that function holds the one re-wrap hook, so an owner-binding delivered through an `OpsDirectory` re-wraps on the far side's backend. The dirtied sets are emitted by the pending-set loop. `PutIdentityOccurrence` reaches the backend's hooked `put_identity_occurrence`. The pre-v50 untyped ops (`PutAttestation`, `PutAttestationSynced`) are the plain write door and never re-wrap.

**A host with no node key** (N1): the door refuses `device_rekey_node_key_unknown` (retryable) rather than misclassify; the backend hook logs the skip at warn. PyEngine init now sets the backend's node key from its signer, as the `Engine` constructors do; an `Engine` over a shared backend sets it before its #916 doors run. `Engine::apply_replicated_attestation` emits only the dirty sets (the backend hook already did the narrow walk); the narrow walk checks the device and the member's held epochs before folding any roster.

**Residual.** An epoch this node minted under a FORMER node key whose self-retention row is gone reports `minted_elsewhere` (the minter is not the current node key); nothing can re-wrap it either way. PyEngine's init sweep and on-demand loop call the same orchestrator but are not witnessed from a PyEngine (no Rust-side PyEngine construction pattern).

**Two-node delivery path (I188 two-node, sqlite and postgres; every row names its door).** Setup: A (alice's node) seals E1..E3 through `Engine::put_blob_scoped`; B seals one epoch and A admits B's set through `Engine::apply_replicated_key_grant`; A holds a self-retention under a foreign minter's name. Each device's binding is admitted on B by `put_attestation` and read off B's `list_attestations_since`.
- (T0) d0's anchor written on A by `put_identity_occurrence_local`; binding → `Engine::apply_replicated_attestation` on A → re-wrapped by the backend hook and the sets emitted at once (read off A's `list_attestations_since`).
- (T1) d1: anchor by `put_identity_occurrence_local` on A; binding → trait `FederationDirectory::apply_replicated_attestation(A)` → A holds grants on E1..E3, none on B's or the foreign epoch.
- (T2) d2: the same, binding → trait `FederationDirectory::put_attestation_synced(A, row, node_b)`.
- (T3) d3: binding → trait `apply_replicated_attestation(A)` first (no grant: d3 is no device of bob's on A yet); d3's anchor signed by d3 on B (`publish_signed_content_only_occurrence`) → B's `list_signed_identity_occurrences_since` → A's `put_identity_occurrence` → grants.
- Sets: A's pending-set loop as PyEngine spells it (`key_grant::dirty_axes` + `emit_key_grant_axis_with_local_signer` with A's LocalSigner) emits ≥ 3 sets; the sets carrying d1, d2, d3 are read off A's `list_attestations_since` → B's `key_grant::admit_replicated_key_grant`; on B each device's wrap (its kept private halves) opens to the DEK B's own wrap opens to (B's content-KEM private halves).
- (S) d4: binding → trait `apply_replicated_attestation(A)` (no anchor: nothing); anchor → `put_identity_occurrence_local` on A (no hook): nothing; `Engine::emit_pending_key_grants` re-wraps and emits.
- (D) d5: binding by `put_attestation` on A, anchor by `put_identity_occurrence_local` (no hooks) → `Engine::rekey_community_member_device_add` → `granted` A's three epochs, `local_only` the foreign one, `content_miss` B's as `minted_elsewhere`; sets for A's epochs carry d5; no set exists for the foreign minter.

**Mutation table** (lane `test(device_readd) | test(i188) | test(key_grant) | test(rekey) | test(epoch)`, `--features sqlite,postgres`, under `scripts/pg_test_db.sh`; 91 tests; each mutant reverted with `git checkout -- src/` before the next; no OOM):

| # | Mutant | Result | Caught by |
|---|---|---|---|
| M01 | owner-binding check dropped | KILLED | (c) |
| M02 | roster-active check dropped | KILLED | (e) |
| M03 | only the latest held epoch re-wrapped | KILLED | (a); two-node (T0) |
| M04 | each re-wrapped epoch's minter bumped | KILLED | (h) |
| M05 | keyless device returns `Ok` | KILLED | (f) |
| M06 | unretained epoch skipped silently | KILLED | (g); two-node (D) |
| M07 | authority check dropped | KILLED | (c') |
| M08 | keyless exclusion not recorded | KILLED | (f) recorded |
| M09 | already-held pre-check dropped | KILLED | (b) zero wraps computed on a re-run |
| M10 | trait `apply_replicated_attestation` hook dropped | KILLED (re-run at 35dc5c45) | two-node (T0) — the Engine door routes through the trait default |
| M11 | `put_attestation_synced` hook dropped | KILLED (re-run) | two-node (T2) |
| M12 | full walk dropped from `Engine::emit_pending_key_grants` | KILLED (re-run) | two-node (S) |
| M13 | door's emit loop deleted | KILLED | two-node (D) |
| M14 | door's own-minter emit filter inverted | KILLED | two-node (D) |
| M15 | other-party owner-binding filter dropped | KILLED | (i) absence-span epochs leak |
| M16 | other-identity filter dropped | KILLED | (i) absence-span epochs leak |
| M17 | miss reasons collapsed to `minted_elsewhere` | KILLED | (g) |
| M18 | insert result ignored | KILLED | (b'') two racing calls |
| M19 | signed `put_identity_occurrence` hook dropped (sqlite + postgres) | KILLED | two-node (T3) |
| M20 | hook stamps the epochs emitted after re-wrapping (the dirty mark lost) | KILLED (re-run) | two-node (T0) — no set emitted |
| M21 | door's identity-occurrence check dropped | KILLED | (j) |
| M22 | walk targets `nodes_owned_by` AND the occurrence check dropped | KILLED | (j) |
| M23 | `local_only` classification dropped | KILLED | (a); two-node (D) |
| M24 | `Engine::apply_replicated_attestation`'s dirty-set emission dropped | KILLED (re-run) | two-node (T0) |
| M25 | no node key: the door proceeds with an empty key instead of refusing | KILLED | `i188_no_node_key` (sqlite, postgres) |

25/25 killed (M10–M12, M20, M24 re-run and M25 added at 35dc5c45 on 93 lane tests); in every run the other 87–89 lane tests stayed green. Not run as separate mutants: the walk's candidate list alone switched to `nodes_owned_by` is equivalent while `is_member_device` also guards it (two layers, M22 removes both); the hoisted holder set computed without excluding the device is equivalent (the device is itself a clean holder, and its grants are already held).

### #917 — the attributed sync door (I189)

Signature as built:

```rust
async fn put_attestation_synced(
    &self,
    attestation: SignedAttestation,
    authenticated_peer_key_id: &str,
) -> Result<attestation_apply::ReplicatedAttestationOutcome, Error>;
```

Both typed doors run one body, `attestation_apply::apply_planned(dir, attestation, origin)`: `apply_replicated_attestation` passes `WriteOrigin::Wire`, `put_attestation_synced` passes `WriteOrigin::Sync { peer_key_id }`. Same bytes, same variant, by construction.

Deviations from §4, and why:

- A decoration-only re-delivery is `Refused { reason: AlreadyPresentIdentical }`, not the `Deduplicated` variant. `Deduplicated` is the CEG §6.1 composer replay and carries no reason; `Refused { AlreadyPresentIdentical }` is what the unattributed door already returns for these bytes, and CIRISEdge's `attestation_outcome_to_apply` already books it as `Duplicate`. §4's "same enum, same variant on both doors" decides it.
- The metering is unchanged for every row that reaches the write door. A row the plan resolves against the stored one (`Unchanged`, `Refused`) is decided before that door and charges no budget. The unattributed door has always worked this way, and any caller can already reach it. A stranger over budget sending a fresh row still gets `Error::RateLimited` from the synced door, the same error the wire door gives.
- There is no Engine wrapper and no pyo3 method for the synced door, so arm (g) has nothing to bind.
- **Corrected in review.** The first build said the plan ran on the near side of the capsule because "`get_attestation` crosses as its own op". That was wrong: `OpsDirectory::get_attestation` is `Unsupported`, so across the capsule the plan never ran. The body fell back to plan-free apply, reported a byte-identical re-offer as `Inserted`, and let a conflict cross as an untyped `Backend` string. The typed doors now cross whole, through two APPENDED ops (`ApplyReplicatedAttestation`, `ApplyReplicatedAttestationSynced`) that answer one APPENDED result (`ReplicatedAttestationOutcome`). The far side runs the typed door against its own backend. `OpsDirectory` overrides both trait methods to send them. Both wire digests are re-pinned as growth, and `DIRECTORY_ABI_VERSION` stays 5. The pre-v50 `PutAttestationSynced` op keeps its contract: the untyped stored-write door under the Sync origin, answering `AttestationOutcome`.

Review hardening (same slice):

- The store's own verdict is mapped rather than `Ok(_)`. `AlreadyHeld` means a lost plan/act race, or a plan-free re-offer of a held row, so it becomes `Unchanged`, never `Inserted`.
- When the id is held, `check_envelope_size_admission` runs before the plan. A settled row never reaches the write door's quota and size gate, so otherwise a replay of a held id with a huge envelope would be canonicalized for free. A fresh id is left to the write door, which meters before its own size gate, so that order is unchanged.
- `AlreadyPresentIdentical` now also requires the incoming envelope to hash to the `original_content_hash` it claims. A row that copies the held row's hash and producer pair onto another envelope is `ConflictingAttestation`, not a quiet duplicate.

RED on d61614dc: arm (c) returned `Err(Conflict("attestation … already exists with DIFFERENT content …"))`.

Mutation round. Lane: `test(synced_door) | test(i189) | test(replicated_attestation) | test(put_attestation) | test(reput) | test(attestation_apply) | test(804)`, `--features sqlite,postgres` under `scripts/pg_test_db.sh`. Baseline: 80/80 passed.

| # | Mutant | Result | Killed by |
|---|---|---|---|
| M1 | plan bypassed on the synced door: the old `persist_row_hash` verdict (`AlreadyHeld` → `Unchanged`, else `Inserted`, `Conflict` propagates) | KILLED 77/80 | I189 one_outcome ×3 backends, arm (c) |
| M2 | decoration-only mapped to `ConflictingAttestation` on the Sync origin only | KILLED 77/80 | I189 one_outcome ×3, arm (c) |
| M3 | `ConflictingAttestation` mapped to `Deduplicated` | KILLED 76/80 | I189 one_outcome ×3, arm (d); `apply_conflicting_row_is_refused_pre_write` |
| M4 | metering dropped: the synced door writes as `WriteOrigin::Authored` (a non-cohort peer is admitted) | KILLED 74/80 | I189 metered ×3, arm (f) (400 stranger rows never limited); `privileged_sync_door_*_804` ×3 |
| M5 | `Unchanged` reported as `Inserted` | KILLED 76/80 | I189 one_outcome ×3, arm (b); `apply_identical_reoffer_is_unchanged` |
| M6 | a decoration-only re-delivery overwrites the stored row (plan routes it to the write door; memory's re-put site replaces the row) | KILLED 78/80 | I189 one_outcome memory, arm (c) "stored row untouched"; `apply_without_a_plan_maps_duplicate_key_to_store_conflict`. Memory is the only backend that carries the overwrite half. |
| M7 | the synced door meters as the wire door (`WriteOrigin::Wire`, the peer ignored) | KILLED 74/80 | I189 metered ×3, arm (f) (cohort mate rate-limited: `peer_bytes_burst`); `privileged_sync_door_*_804` ×3 |

Mutation round 2, after review, on d3d45b5d. The lane adds `test(directory_capsule)`, and I189 gains the capsule arm (an `OpsDirectory` over each backend), (h) and (i). Baseline: 109/109 passed. All twelve killed.

| # | Mutant | Result | Killed by |
|---|---|---|---|
| M1–M5, M7 | as above | KILLED (103/109, 103, 102, 103, 102, 103) | as above, plus the capsule arm ×3 for M1, M2, M3, M5 |
| M6 | as above (memory overwrite) | KILLED 106/109 | I189 one_outcome and capsule, memory, arm (c); the plan-free unit test |
| M8 | capsule: far side of `ApplyReplicatedAttestationSynced` uses the untyped stored-write door | KILLED 106/109 | I189 capsule ×3, arm (c) |
| M9 | capsule: far side of `ApplyReplicatedAttestation` uses the untyped `put_attestation` | KILLED 106/109 | I189 capsule ×3, arm (e) (a conflict crossed as `backend: conflicts with existing row`) |
| M10 | store's `AlreadyHeld` reported as `Inserted` | KILLED 108/109 | `apply_without_a_plan_maps_duplicate_key_to_store_conflict` (plan-free held re-offer, both doors) |
| M11 | size gate before the plan removed | KILLED 103/109 | I189 one_outcome and capsule ×3, arm (i) |
| M12 | the claimed `original_content_hash` trusted again | KILLED 103/109 | I189 one_outcome and capsule ×3, arm (h) |

**Phase 2: #916's hook moved into `apply_planned`**, after rebasing onto f744d414. `owner_binding_of(incoming)` is read before the row is moved. `rewrap_after_admission` fires only on the store's `Ok(AttestationOutcome::Inserted)`, after the §6.1 dedup re-read and immediately before `Inserted` is returned. #916's two per-door hooks are gone. The occurrence hook in the sqlite/postgres `put_identity_occurrence` and the `rewrap_own_epochs_for_device` trait method stay. I188 two-node gains:

- (T4)/(T5): an owner-binding delivered through an `OpsDirectory` over A's backend, by `ApplyReplicatedAttestation` (d6) and `ApplyReplicatedAttestationSynced` (d7), re-wraps on A's backend, and A's pending-set loop emits sets carrying both devices, which open on B.
- (U): the same binding re-delivered through both typed doors is `Unchanged` and re-wraps nothing.

Mutation round 3, on 0b470523. Lane: the I189 lane plus #916's (`test(device_readd) | test(i188) | test(key_grant) | test(rekey) | test(epoch)`), `--features sqlite,postgres` under `scripts/pg_test_db.sh`. Baseline: 202/202 passed. 17/17 killed, and no mutant was OOM-killed.

| # | Mutant | Tests failed | Killed by |
|---|---|---|---|
| H1 | the hook dropped from `apply_planned` | 2 | two-node ×2 (T0) |
| H2 | the hook also fires on `Unchanged` | 2 | two-node ×2: (U) re-wraps d4, so the (S) precondition fails |
| H3 | the far side re-wraps only via the old untyped `PutAttestationSynced`: the new ops run the untyped door with no hook | 5 | two-node ×2 (T4); I189 capsule ×3 |
| H4 | #916 M10 re-pointed: the single site skips the `Wire` origin | 2 | two-node ×2 (T0) |
| H5 | #916 M11 re-pointed: the single site skips the `Sync` origin | 2 | two-node ×2 (T2) |
| M1 | synced door skips the plan | 8 | I189 direct and capsule ×6; two-node ×2 |
| M2 | decoration-only turned into a conflict on Sync | 6 | I189 direct and capsule ×6 |
| M3 | conflict reported as `Deduplicated` | 7 | I189 ×6; `apply_conflicting_row_is_refused_pre_write` |
| M4 | writes as `Authored` (no metering) | 6 | I189 metered ×3; `privileged_sync_door_*_804` ×3 |
| M5 | `Unchanged` reported as `Inserted` | 9 | I189 ×6; two-node ×2; `apply_identical_reoffer_is_unchanged` |
| M6 | memory overwrites the row | 3 | I189 memory ×2; plan-free unit test |
| M7 | meters as the wire door | 6 | I189 metered ×3; `privileged_sync_door_*_804` ×3 |
| M8 | capsule synced far side uses the untyped door | 5 | I189 capsule ×3; two-node ×2 |
| M9 | capsule unattributed far side uses the untyped door | 5 | I189 capsule ×3; two-node ×2 |
| M10 | `AlreadyHeld` reported as `Inserted` | 1 | plan-free unit test |
| M11 | size gate removed | 6 | I189 ×6 (i) |
| M12 | claimed hash trusted | 6 | I189 ×6 (h) |

## 8. rc5 adopts pulled into v50: #925, #927, #928

Three small CC 1.0-rc5 adopts (CIRISConstitution PR #113, read at its head `4b62451`), built on one branch and witnessed on every backend by `federation::rc5_adopts_invariants`.

### 8.1 #925 — infrastructure does not vote (CC 3.2 rc5, ruling on CIRISServer#537)

**Basis.** CC 3.2 "Infrastructure does not vote": a key whose `identity_type` includes `node` MUST NOT carry `role: founder` in an `infrastructure` community and MUST NOT be counted in its `consensus_protocol`. A substrate MUST refuse at admission a `community` row or `supersedes` that lists one as founder (`hard_case:community_consensus_protocol_violation`, CC 3.4.2), and a roster fold MUST drop such a seat. CC 3.4.7.3 Clause A: a key whose set contains `node` MUST NOT also contain `agent` or `user`.

**Built.**
- `node`-bearing (`federation::is_node_bearing_key`): the key's own `federation_keys` set contains `node`, or it is an ACTIVE occurrence of an identity whose set does (`active_identities_for_occurrence`).
- Admission (`admission::check_infrastructure_founders_not_node`, rule `node_bearing_founder`): at `put_community` on all three backends, at the supersede door (`group_amendment::supersede_community_signed`, so `supersede_community` / `supersede_community_with_quorum` / `supersede_affiliations`), and at `put_community_membership_widening` on all three backends (a widening that seats a founder is the supersede of the CC 3.2 ceremony). The replicated amendment route is covered because `put_community` runs the check on the offered record before `route_occupied_community`.
- Fold: `consensus::Seat` gains `node_bearing`; `consensus::eligible` drops a node-bearing seat in an `infrastructure` group whatever its role tag, so it neither votes nor counts in the denominator. The evaluator stays pure: the set is resolved from the roster reads (`federation::community_node_bearing_seats`, over the record's members and every widened member, only for an `infrastructure` community) and threaded in through `RosterRules::node_bearing` (`RosterRules::of_community(c, &nodes)` requires it, so no caller can forget it) and through `verify_membership_quorum`'s seat builder.
- Agreement (review H1). The occurrence gate admits a row whose signer is the IDENTITY itself (`check_signer_acts_for`), so the occurrence never has to consent. The first cut counted every active occurrence binding, which let any registered `node` key N sign `{identity: N, occurrence: H}` for a human founder H and strip H's vote in every infrastructure fold and every replay.
  - `is_node_bearing_key` now counts an occurrence binding only when the occurrence AGREED (`federation::occurrence_agreed_to`): either a stored signed occurrence row for the pair whose signer is the occurrence, or the occurrence's own live owner-binding naming the identity (`owner_of`).
  - A trusted-local (unsigned) row carries no agreement.
  - **Follow-up CIRISPersist#932:** #873's principal resolver (`active_identities_for_occurrence`, used by the hold-side audience and write-side principal resolution) has the same unilateral-claim shape. It is not changed here.
  - Witness: `identity_claim_alone_is_not_node_bearing_founder`.
- Clause A (`register::check_node_identity_exclusive`): run by every backend's `put_public_key` right after `validate_registration_pubkey`, so every mint (`register_federation_key` verifies, then stores through `put_public_key`) and every replicated `Insert` runs it. Typed refusal `Error::NodeIdentityNotExclusive` (`federation_node_identity_not_exclusive`, Python `ValueError`).
- Refusal type: `Error::CommunityConsensusProtocolViolation { community_key_id, rule, detail }`, `kind()` `federation_community_consensus_protocol_violation`, Display beginning `hard_case:community_consensus_protocol_violation:{community_key_id}`, Python `ValueError`.

**Witnesses** (memory, sqlite, postgres): `node_key_cannot_be_infrastructure_founder` (record door by own set and through the occurrence; conformant as member; supersede door; widening door); `node_founder_seat_does_not_vote` (a room admitted with `{human, install}` founders under `quorum:1/2`; the install's scrub admits a widening; once the install is bound as an occurrence of a `node` identity its scrub no longer admits one and the human's does); `clause_a_fused_key_is_not_minted`. Unit: `consensus::tests::node_founder_seat_is_not_eligible` (the `quorum:1/2` vector), `store::memory::tests::clause_a_node_key_cannot_carry_an_actor_role_at_mint`.

### 8.2 #927 — the family-quorum plane is the ceremony plane's family form (CC 3.2 T2, 3.4.7 rc5)

**Basis.** CC 3.2 T2 rc5: the ceremony plane is a co-scrub by a family roster reaching that family's `consensus_protocol`; the HUMANITY_ACCORD 2-of-3 is its shipped instance, a keyless family confers on it by the same mechanism, and the plane is named by the row's scrub set. CC 3.4.7: a keyless family's charter is `delegates_to(member → family_id)` bearing `trust:charter:v1` whose scrub set reaches the family's protocol, the family derived from the verified signers. CC 3.2 conformance: an `infrastructure` community's protocol MUST be `quorum:M/N`.

**Confirmed.** The code matches the text: `family_quorum_over` derives the family from the verified scrub set against this node's own rosters (no granter-declared field), and `check_family_charter_admission` refuses a charter naming a family that does not carry its quorum. The one observable divergence is the wire: `TrustedGrant::conferral_plane` serializes three values. `ConferralPlane` now documents the mapping (`Delegation` → delegation; `AccordCoScrub` → ceremony, shipped instance; `FamilyQuorum` → **ceremony plane, family form**). No rename.

**Built.** `admission::check_infrastructure_consensus_protocol` (rule `protocol_not_quorum_m_of_n`): an `infrastructure` community whose protocol is not `quorum:M/N` with `1 ≤ M ≤ N` (review M1: `quorum:0/N` parses but admits a change no founder signed) (`founder_only`, `unanimous`, bare `majority`, `weighted:`, `custom:`, `reverse_quorum:`) is refused at `put_community` and at the supersede door, not evaluated. `family_charter_threshold`'s floors stay (they are the family plane's reading) and its doc points at the new refusal. Witness: `infrastructure_protocol_must_be_quorum` (memory, sqlite, postgres; each non-conformant form refused and not stored, the same form admitted outside `infrastructure`, and a supersede to `majority` refused).

### 8.3 #928 — a 5-hop delegation default; 16 stays the ceiling (CC 4.1.1 rc5)

**Basis.** CC 4.1.1: traversal depth is capped at 5 hops by default (configurable); longer chains are `attestation:self_verify` only; a substrate MAY clamp any requested depth at a ceiling (16), which bounds the walk and does not raise the default.

**Built.**
- `topology::DEFAULT_DELEGATION_DEPTH = 5` and `effective_delegation_depth(Option<usize>)`. `MAX_DELEGATION_DEPTH` and `MAX_WITHDRAWS_DELEGATION_DEPTH` stay 16 and are documented as ceilings. `admission::MAX_MODERATION_DELEGATION_DEPTH` is now defined as `DEFAULT_DELEGATION_DEPTH`, so the two cannot drift.
- The general walk: `build_delegation_graph(dir, from_key, max_depth: Option<usize>)`. `None` walks 5 hops; `Some(n)` is the opt-in, clamped at 16. `DelegationGraph::depth_outcome` (`WithinCap` / `BeyondCapSelfVerify`, `#[serde(default)]`) reports a chain that continues past the cap.
- The withdraws walk: `resolve_withdraws_admission_rule` (the `put_attestation` gate, which has no caller depth) now runs rules 3 and 4 at the default instead of 16. A refusal carries `WithdrawsNotAdmitted::beyond_delegation_depth_cap`.
- The shared scoped walk (`scoped_delegation_reach`) records `beyond_cap`; `reachable_under_scope_with_reasons` returns the new `ReachabilityVerdict::BeyondDepthCap` (pyo3 token `beyond_depth_cap`). The precedence is `Reachable`, `RetractedAtRoot`, `MissingScope`, `NoTrustRoots`, then `BeyondDepthCap`, then `SignerUnreached`: an issuer with no edges at all is `NoTrustRoots` whatever the cap.
- "Beyond the cap" is detected, not guessed: a traversable recipient at the cap that itself emits an onward `delegates_to` (carrying the scope, under the lens, for the scoped walk). The probe reads that recipient's out-edges once and stops at the first hit.
- Surfaces: pyo3 `delegates_to_graph(from_key, max_depth=None)` (stub regenerated). The capsule op `BuildDelegationGraph { max_depth: u32 }` is unchanged and passes `Some(max_depth)`: capsule callers always name a depth, so no ABI bump.

**Witnesses** (memory, sqlite, postgres): `delegation_graph_defaults_to_five_hops`, `withdraws_walk_depth_defaults_to_five_hops`, `moderation_walk_depth_defaults_to_five_hops`. In each, a 6-hop chain does not confer at the default, is reported as beyond the cap, and confers at an explicit `max_depth = 6`. Controls: a 5-hop chain is `WithinCap`, a stranger's refusal carries `beyond_delegation_depth_cap: false`, and an unreached target inside the cap is still `SignerUnreached`.

### 8.4 Evidence

`evidence/cc_impl.tsv` gains 11 rows:
- CC 3.2 `CLM-infrastructure-does-not-vote`: `check_infrastructure_founders_not_node`, `consensus.rs#eligible`, `community_node_bearing_seats`.
- CC 3.2 `CLM-infrastructure-quorum-m-of-n`: `check_infrastructure_consensus_protocol`.
- CC 3.4.7.3 `CLM-node-exclusive-at-mint`: `check_node_identity_exclusive`.
- `CLM-family-root-charter`: CC 3.2 `ConferralPlane` and `family_quorum_over`; CC 3.4.7 `check_family_charter_admission`.
- CC 4.1.1 `CLM-delegation-depth-default`: `DEFAULT_DELEGATION_DEPTH`, `build_delegation_graph`, `resolve_withdraws_admission_rule`.

The exact-count pin in `evidence_cc_impl_rows_pin_the_current_crate_version` moves 80 → 91. Its message also said "expected 73", which was stale, and now says 91.

### 8.5 Deviations and what is not built

1. **The token did not exist.** Persist had no `hard_case:community_consensus_protocol_violation` refusal before this; nothing drew it (no `supersedes` rule refused a lowered infrastructure protocol). It is new here as a typed error whose message carries the CC token. It is a refusal, not a `hard_case:*` observability emission: no event row is written.
2. **Only the `node` half of the founder rule.** CC 3.2 rc5 also says a founder's set includes `user`. The issue asked for the `node` exclusion, and that is all that is built. `consensus_protocol_entrenched MUST be true` and `admission_quorum_basis: founders` are also not enforced (`Community` carries no entrenched field). These are open.
3. **Keyed on the label, for a record authored here** (review M6 narrows the record door; see §8.7). Both conformance gates fire on `cohort_subkind: infrastructure` whether or not the community is *authorized* (`is_authorized_infrastructure_community`). An unauthorized label gets the stricter treatment everywhere else, and a conformance rule that an unauthorized label could skip would be the weaker one.
4. **The widening door checks only the founder rule.** A widening is not a protocol change. A pre-gate stored infrastructure community with a non-`quorum:` protocol keeps admitting widenings under the protocol it stored. It is refused the next time its record is put or superseded.
5. **Superseded by review item 5 (§8.7): node-bearing is judged at each change's instant.** The first cut judged it from current state, so a binding asserted later overturned roster changes validly admitted before it, and a revocation gave the vote back for every past event.
6. **Clause A runs on every door that writes `identity_type`** (corrected after review H3; the first cut ran it only at `put_public_key`). The doors are:
   - `put_public_key`: every mint and every replicated `Insert`.
   - `adopt_scrub_upgrade`: the replicated `Upgrade` arm, which CAN change `identity_type`.
   - `supersede_canonical_record`: the replicated `Supersede` arm.
   - `adopt_genesis_reanchor`.
   - `seed_genesis_accord_holders`.
   - The rebind door (`register::prepare_rebind`).

   It is not in `verify_key_registration`: every door above runs it. A pre-gate fused key is refused any rewrite of its record (it re-mints), and Clause B still gates it where it sits. The Clause B witnesses (`hybrid_node_agent_key_still_refuses_agency_773`, `node_agent_hybrid_carries_agency_admitted{,_sqlite}`, `pg_node_agency_duplicate_identity_type_token`) now plant their fused key below the door, because the door now refuses to mint it. The upgrade and supersede doors are witnessed by `clause_a_on_the_rewrite_doors_{sqlite,postgres}`.
7. **"Infrastructure family" is not representable.** A `Family` has no `cohort_subkind`, so #927's refusal is on communities. `family_quorum_over` gains no identity filter: #925 is scoped to `infrastructure` communities.
8. **The withdraws WRITE gate walks 5 hops, and each stored row keeps the depth it was admitted under** (review H2; final check: the depth is persisted, V157).
   - **The write gate** (`check_withdraws_admission`) walks rules 3/4 at the node's `withdraws_delegation_depth()`: the CC 4.1.1 default (5), unless the host opted in with `set_withdraws_delegation_depth(n)`, clamped at 16. A NEW withdraws over a chain deeper than that is refused with `beyond_delegation_depth_cap: true`.
   - **The depth is recorded with the row, in ONE transaction.** V157 adds `federation_withdraws_admission_depths(attestation_id, depth)` on sqlite and postgres (the memory backend mirrors it under one lock). `put_attestation` writes the row and its depth in one transaction on both SQL dialects, so a failed depth write rolls the row back.
   - **Repair.** An identical re-put of a held `withdraws` whose depth is missing records it, on both `AlreadyHeld` paths (the structural-composer dedup and the id collision) on all three backends.
   - **The local-tier doors (3d)** (`attestation_insert_local` / `_upsert_local` → `sqlite_write_local_attestation`, `pg_write_local_attestation`, `memory_write_local_attestation`) also record the node's depth for a `withdraws` row, in their own transaction. A local row becomes a federation row IN PLACE at `enter_mesh`, where `list_attestations_referencing` sees it. The blob doors (`put_blob_with_scope`, `adopt_sealed_blob_at`) write `holds_bytes` rows and never a `withdraws`.
   - **Backfill.** Every `withdraws` stored before V157 was admitted under the 16-hop walk and is backfilled at 16. A row with nothing recorded reads as 16. The bytes are pinned in `evidence/migration_checksums.tsv`.
   - **The pub read form.** `admission::check_withdraws_admission_as_admitted(dir, row)` re-derives a STORED withdraws at the row's recorded depth (nothing recorded reads as 16). `blob_tombstone::retiring_composer` uses it. CIRISServer's `drive.rs` (`withdrawn_by`) and CIRISEdge's `blob_swarm/revocation.rs` must call it instead of the write form: the write form walks the node's current depth, so it un-retires. The capsule proxy forwards the recorded depth (op `WithdrawsAdmissionDepth`) and never guesses.
   - **The bytes-plane fold re-derives at the ROW's depth.** `blob_tombstone::retiring_composer` still re-walks the edges as they stand now (#853: re-derive, never read the stored rule), at `withdraws_admission_depth(row)`. So a pre-v50 withdraws keeps retiring what it retired. A NEW withdraws admitted by the deferred arm (target absent at admission) can no longer retire bytes through a chain deeper than the gate that admitted it walked, which closes the plane split the ceiling rule left open.
   - **Witnesses:**
     - `withdraws_retire_at_their_admission_depth` (memory, sqlite, postgres; the runner sets the opt-in):
       - (A) a deferred 6-hop withdraws recorded at 5 does not retire;
       - (B) with the target present it is refused, too deep;
       - (C) under an opt-in to 6 it is recorded at 6 and retires.
     - `sqlite::tests::withdraws_admission_depth_is_backfilled` (V156 → V157 migration witness): a pre-V157 withdraws gets 16; a non-withdraws row gets nothing.
     - (D) in the same body: the pub `check_withdraws_admission_as_admitted` admits a 16-depth row and a 6-depth opt-in row, and refuses (A)'s 5-depth deferred row.
     - `withdraws_depth_is_written_with_the_row_{sqlite,postgres}`: with the depth store broken, the put fails and leaves NO attestation row; healed, it lands at 5; with that depth deleted, an identical re-put is `AlreadyHeld` and restores it. `memory::tests::withdraws_depth_is_repaired_on_an_identical_reput_memory` covers the repair.
     - `local_withdraws_records_its_depth` (×3).
     - The capsule `withdraws_admission_depth_op_forwards_the_recorded_depth`.
   - **Mixed-fleet divergence (stated, until the fleet upgrades):** a v49 node admits a 6-to-16-hop withdraws that a v50 node refuses at its replicated door. The bytes it withdraws stay live on the v50 node until the fleet upgrades. This belongs in the release note.
9. **Fixtures.** Infrastructure community fixtures in memory, sqlite, postgres and `community_dek` declared `majority` / `founder_only` and now declare `quorum:1/1`, through `tier_ingest::test_support::fixture_protocol`.

### 8.6 Mutation table

Committed tree `ce4993be`. Lane: `test(consensus) | test(infrastructure) | test(founder) | test(charter) | test(delegation) | test(depth) | test(clause) | test(trust_root)`, `--features sqlite,postgres` under `scripts/pg_test_db.sh -- cargo nextest run -j 3`. Baseline: 133/133 passed, with the postgres legs running against a database (non-zero times). Each mutant was reverted (`git checkout -- src`, tree clean) before the next. **12/12 killed**, and no mutant was OOM-killed.

| # | Mutant | Failed | Killed by |
|---|---|---|---|
| M1 | node founder counted (`eligible` ignores `node_bearing`) | 4 | `node_founder_seat_is_not_eligible`; `node_founder_seat_does_not_vote` ×3 |
| M2 | Clause A refusal dropped | 4 | `clause_a_fused_key_is_not_minted` ×3; memory `clause_a_…_at_mint` |
| M3 | infra protocol floored instead of refused | 3 | `infrastructure_protocol_must_be_quorum` ×3 |
| M4 | default depth 16 | 9 | the three depth witnesses ×3 |
| M5a | graph over-cap chain reported as `WithinCap` (empty) | 3 | `delegation_graph_defaults_to_five_hops` ×3 |
| M5b | scoped walk never records `beyond_cap` | 6 | withdraws and moderation depth witnesses ×3 |
| M6 | moderation default decoupled (6) | 3 | `moderation_walk_depth_defaults_to_five_hops` ×3 |
| M7 | identity-type thread dropped (`node_bearing: false` in the fold's seat builder) | 3 | `node_founder_seat_does_not_vote` ×3 |
| M8 | supersede path unguarded | 6 | `node_key_cannot_be_infrastructure_founder` ×3; `infrastructure_protocol_must_be_quorum` ×3 |
| M9 | occurrence resolution dropped from `is_node_bearing_key` | 6 | `node_key_cannot_be_infrastructure_founder` ×3 (1b); `node_founder_seat_does_not_vote` ×3 |
| M10 | withdraws gate walks at the ceiling (16) | 3 | `withdraws_walk_depth_defaults_to_five_hops` ×3 |
| M11 | sqlite widening door unguarded | 1 | `node_key_cannot_be_infrastructure_founder` sqlite (4) |

**Round 2 (after review H1/H2/H3/M1), committed tree `a318d27d`.** Same lane. Baseline 141/141, postgres legs against a database. Mutants now come from a uniquely named script (`rc5s_mut.py`) with a clean-tree assertion. **17/17 killed**, none OOM-killed.

| # | Mutant | Failed | Killed by |
|---|---|---|---|
| N1 | H1 agreement check dropped (any active binding counts) | 3 | `identity_claim_alone_is_not_node_bearing_founder` ×3 |
| N2 | H2 bytes-plane re-derivation at the new default | 3 | `withdraws_admitted_under_the_old_depth_still_retires` ×3 |
| N3 | H3 Clause A dropped from sqlite `adopt_scrub_upgrade` | 1 | `clause_a_on_the_rewrite_doors_sqlite` |
| N4 | H3 Clause A dropped from postgres `supersede_canonical_record` | 1 | `clause_a_on_the_rewrite_doors_postgres` |
| N5 | M1 `quorum:0/N` conformant again | 3 | `infrastructure_protocol_must_be_quorum` ×3 |
| M1 | node founder counted | 4 | consensus unit; `node_founder_seat_does_not_vote` ×3 |
| M2 | Clause A refusal dropped | 6 | `clause_a_fused_key_is_not_minted` ×3; memory unit; `clause_a_on_the_rewrite_doors` ×2 |
| M3 | infra protocol floored | 3 | `infrastructure_protocol_must_be_quorum` ×3 |
| M4 | default depth 16 | 12 | the four depth witnesses ×3 |
| M5a | graph over-cap as `WithinCap` | 3 | `delegation_graph_defaults_to_five_hops` ×3 |
| M5b | scoped walk never records `beyond_cap` | 9 | withdraws, moderation and old-depth witnesses ×3 |
| M6 | moderation default decoupled | 3 | `moderation_walk_depth_defaults_to_five_hops` ×3 |
| M7 | identity-type thread dropped | 3 | `node_founder_seat_does_not_vote` ×3 |
| M8 | supersede path unguarded | 6 | founder and protocol witnesses ×3 each |
| M9 | occurrence resolution dropped | 9 | founder, fold-vector and H1 witnesses ×3 each |
| M10 | withdraws WRITE gate at the ceiling | 3 | `withdraws_admitted_under_the_old_depth_still_retires` ×3 (the new-withdraws refusal) |
| M11 | sqlite widening door unguarded | 1 | `node_key_cannot_be_infrastructure_founder` sqlite |

### 8.7 Review round 2 — item 5, M1–M6, H3 strengthened, LOWs (committed `8a3c1e66`)

**Item 5 — node-bearing is judged at the change's instant (the rule).** Node-bearing has two sources, judged differently (`federation::NodeBearingSeats`, built by `community_node_bearing_seats` / `node_bearing_of`):
- **The key's own `identity_type` contains `node`.** Fixed at mint: Clause A refuses a fused mint, and every rewrite door refuses moving `node` in or out (H3 strengthened, below). So it holds at every instant, and reading it from current state is right.
- **The key is an agreed occurrence of a `node` identity.** This is a relation with a start (the signed `asserted_at`) and an end (a revocation's `effective_at` in force against that assertion — the #421 re-establishment rule — or `valid_until`). It is the same kind of thing as a `moderate` delegation, so it is judged at the act's instant with no ending retroactive: v49, `FSD/ROOM_ROSTER_AUTHORITY.md` §2–§3 (I175/I175b).
  - The fold's seat builder asks `NodeBearingSeats::at(key, event.effective_at)` per event; the evaluator stays pure.
  - The widening door judges the new seat at the widening's `effective_at`; the record doors and the quorum-gated supersede judge now.
  - A node-local `admitted_at` is never used. `asserted_at` is signer-chosen and backdatable, which is why H1's agreement rule comes first: with the occurrence's own consent, a backdated claim is the key's statement about itself.
  - Witness `node_bearing_is_judged_at_the_change_instant` (memory, sqlite, postgres), steps (1)–(5) as ruled. `node_founder_seat_does_not_vote` now pins that `second`, admitted before the binding, still stands.
  - **Final over the assertions the plane keeps — not yet over every assertion.** The fold is final over the assertion the occurrence plane holds for each `(identity, occurrence)`: a later binding never reaches back past that assertion, and an ending never reaches back past its own instant. It is not yet final over every assertion ever made. The plane upserts the LATEST assertion per pair, so a re-assertion moves a binding's start forward, and an identity re-signing the row replaces the occurrence's own agreement row. Either can change an earlier verdict. The agreement check (`occurrence_agreed_to`) and its owner-binding arm are also current-state reads. Follow-up **CIRISPersist#930**: a per-assertion history table, V158+.

**M1 — one infrastructure quorum parser.** `admission::infrastructure_quorum(protocol) -> Option<(M, N)>`: `quorum:M/N` with `1 ≤ M ≤ N`, `N ≥ 1`, and `M ≥ 2` whenever `N ≥ 2` (CC 3.2: "a single founder must not be able to admit unilaterally"). `quorum:1/1` stays conformant. #926 folds onto this parser. An infrastructure record naming no founder is refused (`INFRA_RULE_NO_FOUNDER`). Witnessed: `0/1`, `0/3`, `1/2`, `1/3` refused; `1/1` and `2/3` admitted; no founder refused.

**M2 — a node-bearing founder has no founder power outside the ballot** (infrastructure only; the set is empty elsewhere), judged at each change's instant:
- **Moderation roots.** `root_authority_intervals` cuts the instants a founder bears `node` out of its authority, so it roots no `moderate` chain then. `moderator_roots_at` reads only those intervals, and `founder_candidates` is unchanged because a candidate with no interval roots nothing. An appointment made while the root held authority keeps standing after (v49's no-retroactive-ending ruling), so the witness binds before appointing.
- **The last-founder rule.** A node-bearing founder is neither a founder that can be lost nor the founder a change leaves behind.
- **Reverse-quorum duty holders.** A node-bearing founder is excluded.
- **Witnesses:** `node_bearing_founder_roots_no_moderation`, `node_bearing_founder_holds_no_last_founder_power` and `node_bearing_founder_is_no_reverse_quorum_duty_holder`, each on memory, sqlite and postgres.
  - The duty-holder witness runs two twin legacy infrastructure rooms (replicated data) under `reverse_quorum:1/7:60+escalate:0:3`. In each, the human removes `x`, one member objects in the window, the second founder UPHOLDS in the steward window, and three members OVERRULE.
  - Where the second founder is not node-bearing, it is a seated duty-holder: its ruling upholds, escalation never opens, and the removal is reversed.
  - Where it is node-bearing, nobody is seated: the tier escalates on the passed deadline, the respondents dismiss 3-to-1, and the removal stands. Its uphold counted only as one respondent ballot.

**M3 — `DIRECTORY_ABI_VERSION` 6.** `ReachabilityVerdict::BeyondDepthCap` is a new variant returned by an EXISTING op (`DirectoryOpResult::Reachability`), which is a payload-shape change. The reason is documented at the constant, and `abi_version_pinned_at_6` pins it. The two enum-body digests do not move: the verdict is a payload type outside their sight, as v3's was. `KeyRefusalReason` also grows (below) and rides the same bump.

**M5 — the replicated `Insert` admits a fused key minted elsewhere.**
- `put_public_key` is now the local-mint face of `put_public_key_at_door(record, KeyDoor)` on every backend. The replicated `Insert` arm reaches the same store step with `KeyDoor::ReplicatedInsert`, and Clause A gates `LocalMint` only. The admitted key is gated data: Clause B and the steward gates apply wherever it acts.
- The replicated `Upgrade` / `Supersede` arms map a Clause A or `node`-immutability refusal to typed `Refused { node_identity_fused | node_identity_changed }`, never an `Err`.
- The key-replication cursor lives in CIRISEdge. The NEW refusals on the apply door are typed (`Refused { node_identity_fused | node_identity_changed }`), so they are recorded and skipped rather than re-polled. Errors that predate this cut (for example a failed registration verify on the `Insert` arm) are unchanged.
- Witness `clause_a_replicated_insert_admits_a_fused_key` (×3 backends): a fused replicated insert → `Inserted`; a pubkey swap over it → `Refused { pubkey_swap }`; a local mint of a fused key → `NodeIdentityNotExclusive`.

**M6 (final check) — the DOOR, not the signer, decides (CIRISPersist#931, brought into v50).** The round-2 design told local from replicated by the signer, and it switched the gate OFF on every real host. The Engine always sets the node key, and an infrastructure record is normally signed by its HUMAN founder, so any human-signed record read as "authored elsewhere". The tests stayed green only because test directories left the node key unset.
- **Two doors, strict by default.**
  - `put_community` (the trait door on all three backends; pyo3 `put_community_json`; the Engine's `put_community_self_signed`) is the LOCAL door. It runs `admission::check_infrastructure_record_admission(dir, record)`, the full CC 3.2 infrastructure gate, whoever signed. An identical re-put (same `persist_row_hash`) settles.
  - `FederationDirectory::apply_replicated_community(record) -> ReplicatedCommunityOutcome` is the REPLICATED entry.
    - It returns `Inserted`, `Unchanged`, `Superseded`, or `Refused { conflicting_record | degrades_conformance }`.
    - A legacy non-conformant infrastructure record is admitted as data, and the fold's gates apply.
    - An occupied id routes through the existing amendment checks (`route_occupied_community`).
    - It is on the trait (default `Unsupported`), overridden by every backend, carried by the capsule op `ApplyReplicatedCommunity` / result `ReplicatedCommunityOutcome` (growth; both digests re-pinned), and exposed as pyo3 `apply_replicated_community_json`.
  - Both doors share one store step, `put_community_at_door(record, CommunityDoor)`. A replication bridge (CIRISEdge) moves to the replicated entry.
- **The local supersede doors are always judged.**
- **A conformant room never degrades through the replicated door** (final check). `admission::check_replicated_supersede_does_not_degrade` refuses a received record that would supersede a STORED infrastructure record which passes conformance with one that fails it: `founder_only`, bare `majority`, a node-bearing founder, `N` ≠ founders. This holds whatever founders' proof the record carries (CC 3.2: a weakening supersede MUST be rejected). The refusal is typed: `Refused { degrades_conformance }`. A legacy room — nothing stored, or the stored version already non-conformant — still syncs. Witness `replicated_supersede_never_degrades_a_conformant_room` (×3): a proof-carrying supersede of a conformant `quorum:2/2` room to `founder_only`, and one seating a `node` founder under `quorum:3/3`, are both refused and change nothing; a legacy `majority` room still takes a proof-carrying supersede (`Superseded`).
- **Witnesses:**
  - `infrastructure_record_authored_elsewhere_is_data` (two nodes, BOTH with their node key SET, ×3 backends):
    - a human-signed `founder_only` infrastructure record through the local door is refused;
    - the same record through the replicated entry is `Inserted`, and re-applied it is `Unchanged`;
    - an identical re-put through the local door settles, and a changed one is refused;
    - a supersede is refused;
    - the second node syncs the record through its replicated entry.
  - The capsule witness `apply_replicated_community_op_is_the_replicated_door`.
  - The P3, item-5, fold-vector and last-founder fixtures now plant their legacy rooms through `apply_replicated_community`.
- **Widening door unchanged.** It still refuses seating a node-bearing founder, whatever the signer, so a replicated legacy widening that seats one does not sync.

**M1 loophole (final check) — `N` is the founder count.** The evaluator reads `quorum:M/N` with an ABSOLUTE `M` and never compares `N` with the founders, so `quorum:1/1` over three founders let one of them admit alone.
- `check_infrastructure_consensus_protocol` now requires `N` == the record's founder count (`INFRA_RULE_QUORUM_N_NOT_FOUNDERS`), on top of the parser's `M ≥ 2 when N ≥ 2`.
- In a CONFORMANT infrastructure room, `check_infrastructure_founder_count_unchanged` refuses any widening (add, promote, demote) or revocation that would move the founder count, at the widening and revocation doors of all three backends. The founder set moves by a supersede that re-declares `N`.
- **Founder self-leave is exempt** (ruled 2026-09-27: v49's consent floor stands). A revocation signed by the removed founder is admitted, as `roster_event_standing` admits any self-leave. **Consequence (for the CHANGELOG):** N is the founder count AS ADMITTED. A self-leave may leave the remaining founders unable to reach M. The room is then frozen (no roster change, no supersede) until its conferring authority re-founds it; for `ciris-canonical`, that is an accord re-birth. The last-founder rule still refuses the last founder's leave.
- A legacy non-conformant room (replicated data) is not re-judged on its roster plane.
- The record checks run in this order: a founder exists, then the protocol and its `N`, then node-bearing founders.
- **Witnesses:**
  - `infrastructure_protocol_must_be_quorum`: `quorum:1/1` over 3 founders and `quorum:2/3` over 2 are refused; `2/3` over 3 is admitted.
  - `infrastructure_founder_count_is_fixed_by_the_record`: under `quorum:2/3` over 3 founders, two founders adding a fourth is refused, and two founders removing the third is refused. A plain member is admitted, and the third founder leaving on their own signature is admitted.

**H3's fifth door (final check) — `add_peer_record` is a local mint.** `check_peer_record_admission` runs Clause A on the record the door would write (a caller-supplied `identity_type`). It is reachable from pyo3 `add_peer_record_json` and the capsule op. Witness `clause_a_peer_record_is_a_local_mint` (×3). The rewrite doors' pure predicate `check_node_identity_unchanged` is pinned by the unit test `check_node_identity_unchanged_refuses_only_a_node_move`. The reanchor door's BELIEVED status rests on that tested predicate.

**LOW (final check).**
- `occurrence_agreed_to` has no owner-binding arm. It could only fire for a pre-gate fused identity, where it is unilateral again.
- The M5 sentence is corrected: the NEW refusals are typed (`node_identity_fused` / `node_identity_changed`, and on the community plane `conflicting_record` / `degrades_conformance`). Not every error of every apply arm is, and the replicated community outcome's doc says "the refusals are typed", not "every arm is Ok".
- The backdated-revocation clamp (a revocation's signer-chosen `effective_at` can reach back before the act it ends) is routed to **CIRISPersist#930** with the per-assertion occurrence history.

**H3 strengthened — `node` never moves on a rewrite.**
- `adopt_scrub_upgrade`, `supersede_canonical_record` and `adopt_genesis_reanchor` (sqlite, postgres; memory's `adopt_genesis_reanchor`) refuse a rewrite that adds or removes `node` (`Error::NodeIdentityImmutable`, `federation_node_identity_immutable`, `ValueError`). The stored row is unchanged.
- Witnessed on the upgrade and supersede doors (`clause_a_on_the_rewrite_doors_{sqlite,postgres}`: adding `node` to a `user` key, removing it from a `node` key).
- **`adopt_genesis_reanchor`: BELIEVED, not tested.** The check is kept, but it cannot be reached from any lane.
  - The door runs `verify_bundle_quorum` before the check. That function authenticates the bundle against `effective_accord_holder_records()`, which on every lane this repo certifies is the compiled-in production roster: hardware-held A1/B1/C1 keys whose private halves no test holds.
  - The only override is the `test-anchor` feature together with verify's runtime `CIRIS_TEST_TRUST_ROOT*` AND-gate. No certify lane compiles that feature, and even under it persist never holds the test root's private key: the harness signs.
  - Neither real ceremony artifact (`genesis_v2.json`, the canonical seed) moves `node`.
  - A fabricated bundle would prove a property of the fabrication (the #665-review rule).
  - The check sits beside the upgrade and supersede doors' identical, witnessed call.
- Rebind (#864) already refuses any `identity_type` change; its door also runs Clause A.

**LOWs.**
- `WithdrawsNotAdmitted`'s Display carries `beyond_delegation_depth_cap`, and the pyo3 reachability token list names `beyond_depth_cap`.
- The withdraws walk's caller opt-in up to the ceiling is `check_withdraws_admission_at` / `resolve_withdraws_admission_rule_at` (pub).
- Every witness key leads with its distinguishing part (`human-{tag}`, `install-{tag}`, `k{i}-{chain}-{tag}`, …), because test signers seed from a key id's first 32 bytes. This has been done since `a318d27d`, and the round below re-ran every mutant on it.
- The (1b) comment says `primitive`, and §8.3's precedence line is corrected.

**Merge prep (shared symbols #926 folds onto).**
- `admission::COHORT_SUBKIND_INFRASTRUCTURE` (the one constant) and `admission::infrastructure_quorum`.
- `federation::is_node_bearing_key` / `is_node_bearing_key_at` / `node_bearing_of` / `occurrence_agreed_to`.
- `Error::CommunityConsensusProtocolViolation` with rule constants `INFRA_RULE_NODE_BEARING_FOUNDER`, `INFRA_RULE_PROTOCOL_NOT_QUORUM`, `INFRA_RULE_NO_FOUNDER`, `INFRA_RULE_SUBKIND_NOT_INFRASTRUCTURE`, `INFRA_RULE_BASIS_NOT_FOUNDERS`, `INFRA_RULE_NOT_ENTRENCHED`, `INFRA_RULE_FOUNDER_NOT_CONFERRED`, `INFRA_RULE_GRADE_CHANGED`.

### 8.8 Surface changes (for the CHANGELOG)

- **Errors** (`kind()` token, Python type):
  - `CommunityConsensusProtocolViolation {community_key_id, rule, detail}`: `federation_community_consensus_protocol_violation`, ValueError.
  - `NodeIdentityNotExclusive {key_id, identity_type}`: `federation_node_identity_not_exclusive`, ValueError.
  - `NodeIdentityImmutable {key_id, stored, offered}`: `federation_node_identity_immutable`, ValueError.
  - `WithdrawsNotAdmitted` gains `beyond_delegation_depth_cap: bool` (in Display too).
- **Typed outcomes:**
  - `ReachabilityVerdict::BeyondDepthCap` (pyo3 `beyond_depth_cap`).
  - `KeyRefusalReason::NodeIdentityFused` (`node_identity_fused`) and `NodeIdentityChanged` (`node_identity_changed`), appended.
  - `DelegationGraph::depth_outcome: DelegationDepthOutcome {WithinCap, BeyondCapSelfVerify}` (`#[serde(default)]`).
- **Signatures:**
  - `build_delegation_graph(dir, from_key, max_depth: Option<usize>)`.
  - pyo3 `delegates_to_graph(from_key, max_depth=None)`.
  - `check_withdraws_admission_at` / `resolve_withdraws_admission_rule_at` (new pub).
  - `RosterRules::of_community(c, &NodeBearingSeats)` and the `RosterRules::node_bearing` field.
  - `community_roster_events(dir, c, &NodeBearingSeats)`.
  - `consensus::Seat::node_bearing`.
  - `admission::check_infrastructure_founders_not_node(dir, community, at)`.
- **New pub:**
  - `topology::DEFAULT_DELEGATION_DEPTH`, `effective_delegation_depth`, `DelegationDepthOutcome`.
  - `NodeBearingSeats`, `NO_NODE_BEARING_SEATS`, `InstantInterval`, `community_subkind`, `is_node_bearing_key{,_at}`, `node_bearing_of`, `occurrence_agreed_to`, `community_node_bearing_seats`.
  - `admission::{infrastructure_quorum, check_infrastructure_consensus_protocol, check_infrastructure_founders_not_node, check_infrastructure_community_conformance, check_infrastructure_record_admission}` and the rule constants.
  - `register::{check_node_identity_exclusive, check_node_identity_unchanged, KeyDoor}`.
- **Constants:** `MAX_MODERATION_DELEGATION_DEPTH` is now defined as `DEFAULT_DELEGATION_DEPTH` (value 5, unchanged). `DIRECTORY_ABI_VERSION` 5 → 6.
- **Behaviour:**
  - Infrastructure records authored here must be `quorum:M/N` (M ≥ 2 when N ≥ 2), name a founder, and seat no node-bearing founder.
  - A fused key can no longer be minted locally, and no local rewrite moves `node`.
  - The withdraws write gate walks 5 hops (the mixed-fleet divergence is in §8.5(8)).
  - A node-bearing seat in an infrastructure room neither votes nor holds founder powers, judged at each change's instant.

**Final-check additions:**
- **Trait:**
  - `FederationDirectory::apply_replicated_community`.
  - `withdraws_delegation_depth()` and `withdraws_admission_depth(id)`.
- **Types:**
  - `CommunityDoor {Local, ReplicatedApply}`.
  - `ReplicatedCommunityOutcome {Inserted, Unchanged, Superseded, Refused{reason}}`.
  - `ReplicatedCommunityRefusal {ConflictingRecord}` (`conflicting_record`).
- **Capsule:** op `ApplyReplicatedCommunity`, result `ReplicatedCommunityOutcome` (growth, digests re-pinned, ABI 6).
- **pyo3:** `apply_replicated_community_json(payload_json) -> str` (classified deontic).
- **Backends:** `set_withdraws_delegation_depth(n)`.
- **Migration:** V157 `federation_withdraws_admission_depths` (both dialects). #926 renumbers to V158 at its rebase.
- **Rule and gate:** rule constant `INFRA_RULE_QUORUM_N_NOT_FOUNDERS`; `admission::check_infrastructure_founder_count_unchanged`.
- **Changed signature:** `check_infrastructure_record_admission(dir, community)` (the authority parameter is removed).
- **Behaviour:**
  - `put_community` judges every new or changed infrastructure record, whoever signed it.
  - A replication bridge must call the replicated entry.
  - `add_peer_record` refuses a fused `identity_type`.
  - A conformant infrastructure room's founder count is fixed by its record.

**Final-check round 2 additions:**
- `admission::check_withdraws_admission_as_admitted` (pub).
- `admission::check_replicated_supersede_does_not_degrade` (pub).
- `ReplicatedCommunityRefusal::DegradesConformance` (`degrades_conformance`).
- Capsule op `WithdrawsAdmissionDepth` / result `WithdrawsAdmissionDepth(Option<u32>)` (growth; digests re-pinned; ABI 6).
- `check_infrastructure_founder_count_unchanged` gains a `self_leave` parameter.
- **Behaviour:**
  - The depth is written in the row's transaction and repaired on an identical re-put.
  - The local-tier doors record a `withdraws` row's depth.
  - A founder may self-leave a conformant infrastructure room (it may then freeze).
  - A conformant room never degrades through the replicated door.

### 8.9 Mutation round 3 (committed `8a3c1e66`)

Lane: the original eight words plus `test(rc5_adopts) | test(abi_version)`, `--features sqlite,postgres` under `scripts/pg_test_db.sh -- cargo nextest run -j 3`. Baseline 163/163, postgres legs against a database. Every mutant was re-run because the fold and the keypairs changed. The script is uniquely named (`rc5s_mut.py`, clean-tree assert). **30/31 killed at `8a3c1e66`; P3 then gained its witness and is killed at `86fd2b12` — 31/31**. None OOM-killed. "×3" = memory, sqlite, postgres.

| # | Mutant | Failed | Killed by |
|---|---|---|---|
| M1 | node founder counted in `eligible` | 7 | consensus unit; fold vector ×3; item-5 ×3 |
| M2 | Clause A dropped | 9 | Clause A mint ×3 + memory unit; rewrite doors ×2; replicated-insert ×3 (local-mint arm) |
| M3 | infrastructure protocol always conformant | 6 | protocol witness ×3; M6 witness ×3 |
| M4 | default depth 16 | 12 | the four depth witnesses ×3 |
| M5a | graph over-cap as `WithinCap` | 3 | graph witness ×3 |
| M5b | scoped walk never records `beyond_cap` | 9 | withdraws, moderation, old-depth ×3 |
| M6 | moderation default decoupled | 3 | moderation witness ×3 |
| M7 | fold seat `node_bearing: false` | 6 | fold vector ×3; item-5 ×3 |
| M8 | supersede door unguarded | 9 | protocol ×3; M6 ×3; founder ×3 |
| M9 | occurrence resolution dropped | 18 | every occurrence-based witness ×3 |
| M10 | withdraws write gate at 16 | 3 | old-depth witness ×3 |
| M11 | sqlite widening door unguarded | 1 | founder witness, sqlite |
| N1 | H1 agreement dropped | 3 | H1 witness ×3 |
| N2 | bytes-plane re-derivation at 5 | 3 | old-depth witness ×3 |
| N3 | sqlite `adopt_scrub_upgrade` Clause A dropped | 1 | rewrite doors sqlite |
| N4 | postgres `supersede_canonical_record` Clause A dropped | 1 | rewrite doors postgres |
| N5a | parser accepts `M = 0` | 3 | protocol witness ×3 |
| N5b | parser drops `M ≥ 2 when N ≥ 2` | 3 | protocol witness ×3 |
| I5a | item 5 judged at now | 6 | fold vector ×3; item-5 ×3 |
| I5b | revocation instant ignored | 3 | item-5 ×3 (step 4) |
| I5c | interval starts at the read instant (the `admitted_at` shape; `IdentityOccurrence` carries no `admitted_at`, so the node-local instant is emulated by now) | 18 | every occurrence-based witness ×3 |
| P1 | last-founder rule counts node-bearing founders | 3 | last-founder witness ×3 |
| P2 | root-authority cut dropped | 3 | moderation-root witness ×3 |
| P3 | reverse-quorum duty holders keep node-bearing founders | 0 — survived at `8a3c1e66`; **3 — KILLED** at `86fd2b12` | `node_bearing_founder_is_no_reverse_quorum_duty_holder` ×3 |
| R1 | ABI back to 5 | 1 | `abi_version_pinned_at_6` |
| R2 | sqlite replicated insert refuses fused keys | 1 | replicated-insert sqlite |
| R3 | authored-elsewhere never data | 12 | M6 ×3; the three keyed fold witnesses ×3 |
| R4 | identical re-put not settled | 3 | M6 ×3 (the rekeyed identical re-put) |
| R5 | no-founder refusal dropped | 3 | protocol witness ×3 |
| H3a | sqlite `adopt_scrub_upgrade` node-immutable dropped | 1 | rewrite doors sqlite |
| H3b | postgres `supersede_canonical_record` node-immutable dropped | 1 | rewrite doors postgres |

### 8.10 Mutation round 4 (final check, committed `c2b59b32`)

Lane: round 3's, plus `test(replicated_community) | test(backfilled) | test(node_move)`. Baseline 175/175, postgres legs against a database. The round covers every changed site, plus the round-3 mutants whose witnesses changed fixtures. **20/20 killed**, none OOM-killed.

| # | Mutant | Failed | Killed by |
|---|---|---|---|
| D1 | local door lenient (sqlite) | 4 | protocol, founder, H1 and door-split witnesses on sqlite |
| D2 | replicated entry strict (sqlite) | 5 | door-split; P3, item-5, fold-vector and last-founder legacy plants on sqlite |
| P5 | `add_peer_record` Clause A dropped | 3 | `clause_a_peer_record_is_a_local_mint` ×3 |
| U1 | `check_node_identity_unchanged` never refuses | 3 | the unit pin; rewrite doors ×2 |
| W1 | bytes-plane re-derivation at 16, ignoring the recorded depth | 3 | `withdraws_retire_at_their_admission_depth` ×3 (A) |
| W2 | sqlite records the default, ignoring the opt-in | 1 | the same witness, sqlite (C) |
| N6 | `N` not compared with the founder count | 3 | protocol witness ×3 |
| N7 | roster founder-count guard dropped | 3 | `infrastructure_founder_count_is_fixed_by_the_record` ×3 |
| M3b | protocol check dropped from record conformance | 7 | protocol ×3; door-split ×3; capsule door test |
| R4b | identical re-put not settled on the local door | 3 | door-split ×3 |
| R5 | no-founder refusal dropped | 3 | protocol witness ×3 |
| M1 | node founder counted | 7 | consensus unit; fold vector ×3; item-5 ×3 |
| M7 | fold seat `node_bearing: false` | 6 | fold vector ×3; item-5 ×3 |
| M9 | occurrence resolution dropped | 21 | every occurrence-based witness |
| N1 | agreement dropped | 3 | H1 witness ×3 |
| I5a | judged at now | 6 | fold vector ×3; item-5 ×3 |
| I5b | revocation instant ignored | 3 | item-5 ×3 |
| P1 | last-founder counts node-bearing founders | 3 | last-founder witness ×3 |
| P2 | root-authority cut dropped | 3 | moderation-root witness ×3 |
| P3 | duty holders keep node-bearing founders | 3 | duty-holder witness ×3 |

### 8.11 Mutation round 5 (final check round 2, committed `cf6ab4db`)

Lane: round 4's, plus `test(withdraws_depth) | test(withdraws_admission_depth_op)`. Baseline 185/185, postgres against a database. **11/11 killed**, none OOM-killed. W2 (the recorded value) is not re-run: its anchor now appears on two doors (put and local), and each has its own witness below.

| # | Mutant | Failed | Killed by |
|---|---|---|---|
| T1 | sqlite commits the row before the depth write | 1 | `withdraws_depth_is_written_with_the_row_sqlite` (the row survives a failed depth write) |
| T2 | postgres commits the row before the depth write | 1 | `withdraws_depth_is_written_with_the_row_postgres` |
| RP1 | sqlite dedup-path repair dropped | 1 | the same sqlite witness (the repair step) |
| AH1 | the pub read form walks the node's current depth | 3 | `withdraws_retire_at_their_admission_depth` ×3 (D) |
| CP1 | the capsule op returns `None` | 1 | `withdraws_admission_depth_op_forwards_the_recorded_depth` |
| DG1 | the degrade check dropped | 3 | `replicated_supersede_never_degrades_a_conformant_room` ×3 |
| SL1 | the self-leave exemption dropped | 3 | `infrastructure_founder_count_is_fixed_by_the_record` ×3 |
| LD1 | sqlite local door records no depth | 1 | `local_withdraws_records_its_depth` sqlite |
| D1 | local door lenient (re-run) | 4 | protocol, founder, H1 and door-split witnesses on sqlite |
| D2 | replicated entry strict (re-run) | 6 | door-split; the legacy plants; the degrade witness |
| N7 | roster founder-count guard dropped (re-run) | 3 | founder-count witness ×3 |

The id-collision repair path for a `withdraws` is reachable only when the structural-composer dedup does not match first. For an identical re-put, the dedup always matches first, so a mutant of that second repair would be equivalent. It is kept as a belt, and not claimed as witnessed.

### 8.12 PR review (Codex) fixes — F2, F3, F4

Codex reviewed PR #921 at 6a81b01b. F1 is recorded in §9. Every witness below was RED on 6a81b01b before its fix, on memory, sqlite and postgres.

**F2 (P1) — a transient read failure is never "legacy".** The replicated door's `check_replicated_supersede_does_not_degrade` re-judges the STORED infrastructure row to decide whether it is legacy. It took ANY error from that re-judgement as "already non-conformant" and let the offered row through, so a failed node-bearing or roster read let a degrading supersede of a conformant room in. Now only the typed `CommunityConsensusProtocolViolation` is legacy; the conformance check returns it for each of its rules (no founder, protocol not `quorum:M/N`, `N` not the founder count, a node-bearing founder). Any other error propagates. An audit of the #925/#927/#931 gates (`check_infrastructure_*`, the `is_node_bearing_key_at` callers, `community_node_bearing_seats`, `node_bearing_of`, `occurrence_agreed_to`, the three backends' door call sites) found no other swallowed directory read.

- (f2_a, the gate) Through the fault double with the occurrence read failing, the gate returns the read error, never the legacy pass. A room non-conformant by its protocol is decided before any read and stays legacy.
- (f2_b, the door) The occurrence read fails ONCE, inside the door, and succeeds after. A persistent fault cannot witness this, because the later quorum fold rereads the same plane and fails too. `apply_replicated_community` returns the error, not `Superseded`, and the stored row is unchanged. Offered again, it is refused `degrades_conformance`.

**F3 (P2) — the outcome is what the write did.** `apply_replicated_community` read the id, then wrote; a concurrent apply of the same record between the two made the write an idempotent no-op while the outcome still said `Inserted` or `Superseded`. The pre-read (`replicated_community_prior`) is gone. `put_community_at_door` returns `CommunityWrite` (`Inserted` / `Unchanged` / `Superseded`), decided under the write's own serialization:

- memory: the state lock around the insert;
- sqlite: `INSERT OR IGNORE` and the re-read in one writer closure;
- postgres: the `INSERT … ON CONFLICT DO NOTHING` row count;
- a supersede: its prior-hash check under the backend's lock.

A supersede that loses its race fails that check stale; if the row now held IS the offered version, the outcome is `Unchanged`, and a Conflict over any other row stays a refusal. The trust-root route reports versions written (`apply_trust_root_chain_counted`).

- (f3_a) A test hook inside each backend (`store::test_hooks`, `cfg(test)`) applies a rival copy of the same record at a named point: the door's first line, after the route said "insert", and at a community supersede's first line. Each time, the outcome is `Unchanged`.
- (f3_b) Two applies of one record, joined: `{Inserted, Unchanged}`, then `{Superseded, Unchanged}`. The join interleaves on sqlite and postgres, and was RED there on 6a81b01b. Memory futures never yield, so on memory it passes on either code, and f3_a pins the interleaving everywhere.

One residual: a trust-root chain whose apply writes some versions and then loses its race on a later one reports `Unchanged` when the offered version ends up held, not `Superseded`.

**F4 (P2) — a zero cap reports what it cut.** `build_delegation_graph(.., Some(0))` skipped the root before looking at its edges, so a root WITH delegations reported `WithinCap`. The cap probe (§8.3) is extracted (`delegates_onward`) and, under a zero cap, asked of the root: a root that delegates is `BeyondCapSelfVerify` with no edges. The scoped walk had the same early return, so the withdraws gate at depth 0 now refuses with `beyond_delegation_depth_cap: true`. `set_withdraws_delegation_depth(0)` reaches it. `reachable_under_scope_with_reasons` at 0 is now `BeyondDepthCap` when the issuer delegates the scope onward, and `SignerUnreached` when it does not. 0 is not rejected; the capsule op passes it through.

- (f4_a) Graph, moderation classifier and withdraws gate at depth 0, with and without a delegating root. The capsule op `BuildDelegationGraph { max_depth: 0 }` is witnessed on memory.

**Mutation table.** Lane and discipline as in §9.1. The baseline was 368/368 at f4443a0b. The final tree's lane has 374 tests, all passing in M4d's run.

| # | Mutant | Failed | Killed by |
|---|---|---|---|
| M2 | `.is_err()` restored (any error from the stored re-judgement is legacy) | 6 | f2_a ×3, f2_b ×3 |
| M3a | the outcome derived from a pre-read again (all three backends) | 5 | f3_a ×3; f3_b sqlite, postgres |
| M3b | a lost supersede race refused as a Conflict | 5 | f3_a ×3 (BeforeSupersede); f3_b sqlite, postgres |
| M3c | the insert arm's lost race reported `Inserted` | 4 | f3_a ×3 (BeforeInsert); f3_b sqlite. Survived before the inner rival points existed. |
| M4a | the graph's root probe dropped | 4 | f4_a ×3; the capsule op |
| M4b | the scoped walk's root probe dropped | 3 | f4_a ×3 |
| M4c | the classifier at 0 always `SignerUnreached` | 3 | f4_a ×3 |
| M4d | the root-epoch filter in the zero-cap probe dropped | 0 | equivalent by trace: the only lens with a root epoch is built at `MAX_MODERATION_DELEGATION_DEPTH` (5), never 0; kept for a future caller |

## 9. #926 — the ciris-canonical community row (ruling b)

**The ruling (operator, 2026-09-27): (b).** The `ciris-canonical` community row is a post-genesis `community` Contribution. It is signed 2-of-3 by the accord holders, admitted under the accord's quorum, and served beside the bundle on the CC 5.3.4 route. The pinned GenesisBundle is untouched: its bytes, `authorization_digest` and `verify_bundle_quorum` do not change, and `verify_bundle_quorum` stays the only root authority. The community row adds a roster, not a second root.

**Review ruling (2026-09-27, from CC 3.2; flagged to the operator): birth by the accord, amendment by the founders.** The accord holders' 2-of-3 is the row's BIRTH. On the ceremony plane it is also the conferral of each founder. After birth the row changes only by its FOUNDERS' quorum: its own entrenched `quorum:2/3` over the `founder` seats. This holds on every door:
- the local `supersede_community_with_quorum`;
- the replicated `put_community` of an amended version, which the receiver verifies as a chain link from the version it holds (or from the birth).

No door re-demands the accord count for an amendment. No door lets an amendment change the grade, `admission_quorum_basis`, `cohort_subkind` or the entrenched protocol. Every founder on every version is still accord-conferred, human and not node-bearing. A founder added by amendment needs its accord conferral to exist already.

**Second ruling (2026-09-27, re-check HIGH-3): founder seats move ONLY through the record.** The roster planes refuse every founder-seat change of a trust-root community, whoever signs it, the full founders' quorum included: seating a founder, re-roling one, revoking one. A founder enters by a founders' amendment. A founder exits by a founders' amendment, or by the accord withdrawing the conferral, which already stops the key counting. The planes admit and remove MEMBERS only. The reason: a fresh node verifies from the lineage alone, so the record must be the one source of who counts. Before this ruling the planes moved FOLDED seats that the record could never follow, so a founder revoked on the plane kept signing counted amendments and a plane-seated founder never could.

**Shape (CC 3.2).** The `Community` record has no `cohort_subkind` or entrenchment columns. `cohort_subkind` already lived in `policy_blob`, so the rest of the CC 3.2 fields sit beside it:

```
policy_blob: {
  cohort_subkind: "infrastructure",
  cohort_subkind_payload: { infrastructure_constraint: { service_class: "canonical", admission_quorum_basis: "founders" } },
  consensus_protocol_entrenched: true
}
consensus_protocol: "quorum:2/3"
members: founders (role: founder) = accord-conferred human steward keys; serve nodes (role: member)
```

**Grade and reservation.** A row is held to the trust-root grade if its id is exactly the bytes `ciris-canonical` or if it declares `infrastructure_constraint`. The reservation is an exact byte match: `CIRIS-Canonical`, `ciris-canonical ` and other spellings are ordinary ids, not the reserved one.

**The door** (`canonical_community::check_trust_root_community_admission`). It runs on BOTH community doors, as ONE predicate (`check_trust_root_at_door`, called by every backend's `put_community_at_door` after the authority scrub and every co-signature verify, and before any write):
- the local `put_community`;
- the replicated `apply_replicated_community` (#931's entry). It also enforces the lineage caps and walks the chain (`apply_trust_root_chain`), exactly as the local door does. A typed refusal crosses this entry as rc5's mapping gives it: `CommunityConsensusProtocolViolation` → `Ok(Refused { DegradesConformance })`, and `Conflict` → `Refused { ConflictingRecord }`. Any other error propagates, so a short birth is `Err(RosterAuthorityUnauthorized)` on both doors.
- The one difference is the ruled legacy allowance. On the replicated entry, a row at ANOTHER id that declares `infrastructure_constraint` but does not verify is kept as data: it reads `NotRooted`, resolves to nothing, and is never a trust root or a `trust:accepts` subject. The reserved id has no allowance on either door. I190 (q) witnesses both doors.

1. **Shape.** `cohort_subkind` is `infrastructure`, `admission_quorum_basis` is `founders`, the protocol is `quorum:M/N` with 1 ≤ M ≤ N, `consensus_protocol_entrenched` is true, and the row names at least one founder. A failure is #925's typed `Error::CommunityConsensusProtocolViolation { community_key_id, rule, detail }`, displayed as `hard_case:community_consensus_protocol_violation:{id} ({rule}): {detail}` (CC 3.4.2).
   - Shape rules use the `INFRA_RULE_*` consts.
   - The trust-root rules are new consts: `TRUST_ROOT_RULE_CHAIN` (`trust_root_chain`), `TRUST_ROOT_RULE_LINEAGE_CAP`, `TRUST_ROOT_RULE_FOUNDER_SEAT_ON_PLANE` (`founder_seat_on_plane`) and `TRUST_ROOT_RULE_RESIGNATION_BACKDATED` (`resignation_backdated`).
   - `is_row_verdict` and `eligible_founders` accept the typed variant.
   - rc5's conformance (`check_infrastructure_community_conformance`) also holds here: N equals the founder count, so a founders' amendment that changes the founder set is a SWAP (one founder out, one in). Adding or dropping a seat also moves N, which is the entrenched protocol, so it is refused.
2. **Founders.** Every founder is a human key: `user` is in its `identity_type` and it is not node-bearing (`federation::is_node_bearing_key_at`, #925). That also catches a key that is an active occurrence of a node identity. A link judges this at its `amended_at`, and the door judges it at now. Every founder is also an accord-conferred `steward` whose role has not been withdrawn (`has_accord_conferred_role_over_roster`).
3. **The chain (re-check HIGH-A).** The offered row travels with its `lineage`: the accord-born version, then every founders' amendment, in order. The door first re-judges what is already stored at the id (`stored_standing`, below).
   - **Nothing rooted there** (absent, or a row that never passed this door): the WHOLE chain must verify (`verify_chain`). Its first version is a BIRTH: it carries no proof, is conformant, and its scrub set (authority plus `SignedCommunity::cosignatures`, all over `Community::signing_envelope`) reaches the HUMANITY_ACCORD family's threshold, counted by the charter plane's own body (`family_quorum_holders_over_envelope`). Every later version is a verified founders' link, and every version's founders are eligible now. So a fresh node admits an amended row, and it never admits the latest version on its own proof.
   - **A rooted row, identical content:** the #758 no-op.
   - **A rooted row, different content:** the offered chain must EXTEND the held version (it appears in the chain), and every link after it must verify. A node that missed an intermediate version walks from what it holds. A chain that does not contain the held version (a re-birth, a fork) is refused. The accord count is not re-demanded.
   - A short birth gets `RosterAuthorityUnauthorized { rule: roster_consensus_insufficient }`, and so does a link short of the founders'.
   - `true` means an authorized infrastructure community, so the non-infrastructure steward-binding precondition is skipped (a serve node is a member without a steward, CC 3.2).

**A founders' link** (`verify_founders_link`) is verified from the PRIOR version alone, never from what the node happens to store:
- the proof names the prior version's content hash;
- the immutables hold: grade, basis, subkind and the entrenched protocol. The founder set MAY change: that is where founder seats move;
- the change envelope, bound by `canonical_community::bind_next_version` before the founders sign, carries three things:
  - every role the version records, so the founders the envelope names are exactly the version's, even when the founder set moves;
  - `next_persist_row_hash`, the version's content hash, so one proof admits exactly ONE body (re-check MEDIUM-B). Name, instants, non-founder roles and every `policy_blob` field are all bound;
  - `amended_at`, the link's signed instant. It is not before the previous link's instant or the prior version's `founded_at`, and not more than 60 s in the future (`COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS`, the substrate's one future-skew bound);
- the verified signers meet the prior version's protocol over its founder seats. A signer counts only if it is one of the prior version's RECORDED founders and counts at `amended_at`: human, accord-conferred, not withdrawn before that instant, and with no resignation in (`seated_since`, `amended_at`] (the counting rule, below). `seated_since` is read from the chain up to the prior version, so `verify_founders_link` takes that chain. Each is hybrid-verified against this node's pinned pubkeys;
- the version's authority is one of those counted founders, and its signature over the version verifies. Every lineage entry is judged this way.

The node-bearing half of "human" is #925's `is_node_bearing_key_at`, at the link's `amended_at`, at both sites (the door and `founder_counts`). A link's seats and the roster seats drop a founder that is node-bearing or does not count. Each seat carries `consensus::Seat.node_bearing`.

**Applying a chain.** The occupied-id route (`apply_trust_root_chain`) applies the offered chain VERSION BY VERSION through `supersede_group_row`, so every stored version is one a proof names exactly and the version history stays whole:
- from a rooted held version: the later links. The held version is located by POSITION and PROOF, not by content (`extends`, round 10): it sits at index `held.lineage.len()`, and the offered chain up to that index must be the held chain version for version (`same_version`: content hash, authority and founders' proof). The walk, and the lineage each applied version is stored with, is the chain this node HOLDS followed by the offered versions after the held one (`walk_from_held`, round 9). Storing the held versions is load-bearing: `same_version` does not compare signature bytes, so an offered prefix may carry bytes nobody verified (round 11, I190 (z′)). The door (`check_trust_root_community_admission`) decides the same way. An offered chain whose head has the held content is the #758 no-op;
- over a squat: from the birth, recorded as `accord_birth_replaces_unrooted`;
- over nothing: the caller inserts the offered row with its `lineage`.

The local door (`prepare_trust_root_supersede`, in `supersede_community_signed`) requires the new version to be a verified founders' link of the held one, and stores it carrying the held version's chain. For a trust root whose chain holds (`Rooted` or `Stalled`, `founders_link_is_the_quorum`), that link IS the local door's quorum: `supersede_community_with_quorum` skips the generic folded-roster `verify_membership_quorum`, so the local and replicated doors judge an amendment by one predicate. The folded roster would re-apply a resignation that a re-seat through the record has cleared (LOW-1), and the doors would then disagree: I190 (o) has the re-seated founder co-sign a later link on the local door. A `NotRooted` squat, an ordinary room and an absent row keep the generic quorum. The decision is taken before the prepare re-reads the standing, so it is passed down (`generic_quorum_skipped`): if the chain stopped holding in between, the prepare refuses rather than letting a non-grade version through with no quorum (review TOCTOU; I190 (t) calls the prepare with the flag over a NotRooted row, since the race itself cannot be driven deterministically). The `lineage` is persisted in V158 (`federation_communities.lineage`), served by the point read and the signed since-read, and never part of `signing_envelope()`.

**Chain caps.** At the door, before any signature is checked, a chain is refused if it has more than `MAX_LINEAGE_LEN` = 1024 versions (the violation token) or a `lineage` over `MAX_LINEAGE_BYTES` = 32 MiB (`Error::EnvelopeTooLarge`). The byte cap is sized so the LENGTH cap binds first, at about 15–20 KB per version. Past 1024 versions the chain restarts by compaction: the founders resign or the accord withdraws their conferrals, the row stalls, and an accord re-birth begins a new chain.

**Key rotation.** In persist a rotation is a NEW `key_id`. Persist has NO steward supersede door, so a founder's retirement is a plain accord WITHDRAW of the old key's steward conferral. The accord separately confers the successor, and the founders then swap it in through the record. `admit_response_withdrawals` therefore projects plain withdrawals only; it carries a `// FOLD(#926-rotation)` note for the day a supersede door is added. The old key record is kept, since founder key records are never deleted. A withdrawal un-counts a founder only for links whose `amended_at` is AFTER it, so the historical links that key signed keep verifying against its record. The bundle response serves the key record of every key the CHAIN names — every version's members, its authority and its proof signers — so a fresh node verifies historical links whose signers have since left.

**The withdrawal instant is node-independent (re-check MEDIUM-W).** A withdrawal un-counts a founder from the SIGNED `window_until` of the accord proposal it re-tallied. That instant is the same on every node; it is not `withdrawn_at`, the local clock at which each node recorded the row.
- A withdrawal whose proposal this node does not hold is dated MIN. That is fail-secure: a bare trusted-local write roots nothing it cannot prove. It does not merely un-count the founder from here on: every link that key signed stops verifying, so the row reads `NotRooted`, not `Stalled`. `NotRooted` opens the any-accord-birth path: any accord birth replaces the row, and it need not be founded later.
- The bundle response carries the accord evidence (proposal plus participations) of every steward withdrawal of a chain-named key, together with the co-signer key records. It is gathered by point reads (LOW-3): one `get_accord_proposal` per withdrawal digest, then the participations of those proposals only, never a scan of accord history on an unauthenticated GET. `pin_trust_from_bundle_response` admits that evidence through the ORDINARY evidence door (`apply_replicated_accord_evidence`, re-tallied against the consumer's own roster) and re-derives the withdrawals (`project_role_withdrawal_for_key`) before it admits the row.
- So a fresh consumer judges a retired-key fork exactly as the mesh does. A link signed after the window by a quorum that needs the retired key falls short, whenever the consumer happened to learn of the withdrawal.

Residuals, stated:
- `amended_at` is signer-chosen. A quorum of RETIRED founder keys could backdate a link to before the window. The link must still extend a version the node holds, or walk from the birth, with non-decreasing instants and prior's quorum. A node already holding the head refuses any fork that does not extend it; only a node that sees the backdated fork FIRST can be split.
- `window_until` is server-issued. A proposal with a long window keeps the retired key counting for links dated within it.
- An unsigned-freshness ROLLBACK is CC's freshness rule to write; #926 parked it. That is a server serving an older but valid prefix of the chain to a fresh consumer.

**Two rosters, on purpose.** A founder's conferral is judged against the COMPILED accord holder roster (`accord_holder_roster_key_ids`), the ceremony plane every key-plane conferral uses. The row's birth quorum is judged against the stored accord family's revocation-folded roster, the same roster the charter plane counts. These agree while no holder is removed from the family. A removed holder stops counting for a birth at once. It also stops counting for a conferral, but only once the compiled roster changes.

**Co-signatures.** Co-signatures on any community row are verified at the door, as a roster row's are (`verify_roster_cosignatures`: one that does not verify, or a doubled co-signer, is refused). They are persisted in V158 (`federation_communities.cosignatures`: pg JSONB, sqlite TEXT, default `'[]'`). Backends read them with the new point read `lookup_signed_community` and serve them on the signed since-read.

**A stored row is re-judged on every read (review MEDIUM-4, re-checks).** `stored_standing` answers `Rooted` only when:
- the signed row conforms in shape;
- its CHAIN (stored `lineage` plus the row) verifies from an accord birth, every link re-verified. There is no proof-only arm;
- EVERY RECORDED founder counts now.

If the chain verifies but a recorded founder no longer counts (a withdrawn or rotated conferral, or a resignation), the answer is `Stalled`. A stalled row is not resolved, served or trusted, but it is still the version the founders amend from: a founders' amendment retiring that seat roots it again.

**Recovery (re-check ruling).** An accord RE-BIRTH replaces a STALLED row: a chain whose first version is a birth reaching the accord quorum, founded LATER than the held chain's birth. The route records it as `accord_rebirth_replaces_stalled`. This is how a trust root whose founders can no longer reach their quorum comes back (two compromised or rotated founders, resignations). A re-birth NEVER replaces a ROOTED row. The accord's lever over live founders is withdrawing their conferrals, which stalls the row first; it has no override of a live record.

**The consent floor: a founder resigns.** A founder's OWN plane revocation, signed by that founder alone, is admitted as a RESIGNATION. It does not move the record. From its `effective_at` the founder no longer counts and is no longer a seat in any link or in the row's standing. A later version MAY still record them, but they count as nothing until the record re-seats them, and the row is Stalled meanwhile. Every resignation of a key is kept (not only the earliest), so a second resignation after a re-seat counts. The row stalls, the remaining founders amend the seat out or re-seat the key, and if resignations make the quorum unreachable, the accord re-birth is the way out.

**The counting rule (round 9 ruling, persist's call).** One rule judges links and the head alike:

> A founder counts on a version's link iff they are a founder of the PRIOR version and have no resignation in (`seated_since(F)`, `amended_at`], where `seated_since(F)` is the instant of the version that (re-)seated F: the birth's `founded_at`, or the `amended_at` of the link whose prior did not name F a founder. The head's standing applies the same rule with `now` in place of `amended_at`.

It replaces two round-7 mechanisms: the prior-instant floor of MEDIUM-R (b) and the `resignation_carried_forward` refusal (R2). The refusal is removed, with its const and its witness arm. The lapse R2 found came from the prior-instant floor, and the refusal was the wrong tool for it: it caused a permanent split (below).
- **The lapse, under the rule.** F resigns at t1, after the birth. The others' v6 (G + H, still recording F) is admitted; F counts as nothing, so the row is Stalled. At v6 → v7, t1 lies in (`seated_since(F)` = birth, t7], so F does not count and F + G is refused, although v6's instant is after t1. After a re-seat at v8 by the others' quorum, `seated_since(F)` = t8 > t1 and F counts again. A second resignation r2 > t8 un-counts F again. I190 (o″) walks this trace; (o‴) is the second resignation.
- **The split the refusal caused (review 4a), under the rule.** Node A holds H1 (t1). Node B holds H2 (t2), signed by F0 + F1 and still recording F2. F2 resigns at t_r, t1 < t_r ≤ t2, having NOT signed H2. A admits the resignation (t_r is after A's head). B refuses it as backdated (t_r ≤ t2). Under round 7, A then refused H2 as `resignation_carried_forward`, and every later version; A could only re-birth, and a re-birth never replaces B's Rooted row. That was a permanent split of the default root that nobody chose. Under the rule, A ADMITS H2 with F2 not counting: A is Stalled and B is Rooted. H3, which amends F2 out, is admitted by both, and both are Rooted. They converge with no re-birth. I190 (x) drives exactly this through the real doors on two nodes.
- **The held chain is the one walked, and the held version is found by position (rounds 9 and 10).** A node walking from a version it holds reads `seated_since` from the chain it holds. Content alone repeats: a re-seat back to the birth roster reproduces the birth's content byte for byte. Round 9 found the held version as the FIRST offered index with its content hash. A replica holding the re-seated head then replayed the old links after it, refused every later link as `trust_root_chain`, and, being Rooted, could never be replaced by a re-birth: the permanent split again. A LAST-occurrence match is no fix, because a node holding the first occurrence would skip the links that retired and re-seated a founder and read a stale `seated_since`. So the held version is matched at its own index, version for version. An offered lineage that reaches the held content by another signed path does not extend the held version at all. I190 (z) drives both arms through the real doors on three nodes; (y) offers the other path.
- **One predicate on the plane (the rc5 reconcile).** rc5's `check_infrastructure_founder_count_unchanged(.., self_leave)` returns early for a trust-root row. The trust-root guard (`check_trust_root_roster_change`) is then the only gate. It refuses every founder change on the plane (`founder_seat_on_plane`) except a founder's own self-leave, which it admits as the resignation. There is no double gate.
- **The last founder cannot resign on the plane.** The ordinary last-founder rule runs after the guard, and it refuses removing the only founder. A sole founder leaves through the accord (a withdrawal, then a re-birth).
- **No backdating (MEDIUM-R).** The resignation's `effective_at` is signer-chosen, so two rules bound it:
  - (a) The plane door refuses a resignation whose `effective_at` is not STRICTLY AFTER the stored head's instant: its link's `amended_at`, or `founded_at` for a birth. Equality is refused as well (re-check B): the head's own link judges resignations up to and including its `amended_at`, so a resignation dated exactly at a link head would have un-counted the founder's signature on that link and un-rooted the row mesh-wide. The refusal is the typed `resignation_backdated`. A founder therefore cannot date a resignation before a link they co-signed and so retroactively un-count that link.
  - (b) Superseded in round 9 by the counting rule above: the floor is `seated_since`, for links and the head alike. The round-5 and round-7 form, the PRIOR version's instant, is what let a resignation lapse (R2).
  - I190 (o′) witnesses (a) on all three backends; (o″), (x) and (y) witness the counting rule.
  - Residual, stated: a node holding an OLDER head admits a resignation dated between its head and a link it has not seen. If that link NEEDED the resigning founder's signature, the founder signed it and chose the divergence: that node then refuses the link, because its founders' count falls short. If the link did not need it, the node admits the link and reads Stalled until the next amendment amends the founder out (I190 (x)). The nodes that already hold the newer head refuse the resignation.
  - Residual, stated (review 4b): the plane floor reads the stored head, then the revocation is written. A concurrent `put_community` on the SAME node can store a newer head between the two. The resignation is then stored although it is not strictly after the new head. This is fail-secure, because the resignation only un-counts the founder on that node, and it is divergence, because a node that saw the new head first refuses the resignation. No code change: the plane door and the community door are separate writes, and the floor is a check on the resigning founder's own date.
- **A re-seat clears older resignations (LOW-1).** If the founders later seat the key again through the record, a resignation older than the re-seating version no longer applies: the standing counts the key from `seated_since`. `resolve_community` lists a trust root's founders from the RECORD, since `Rooted` has already established that each one counts now. Reading them off the folded plane roster would re-apply the old resignation against the member's original `joined_at`. I190 (o) re-seats the resigned founder.

The trade, stated: ONE founder can stall the default trust root. That is consent over availability, v49's floor. Dropping the seat does not change a `quorum:M/N` threshold, because M is absolute. It keeps the seat set honest for any count-relative protocol.

**Stated plainly: a single holder revocation un-roots the mesh's default trust root on every node until the accord re-signs.** The birth's accord quorum is re-derived now, so a revocation that drops the family's count below quorum un-roots every accord-born row on every node. This is CC T4 behaviour and loud by design.

**Cost (re-check MEDIUM-C), and how long a verdict holds (round 9).** Standing is cached per directory. Each real backend holds a `StandingCache`, reached by `FederationDirectory::trust_root_standing_cache`, and it is never shared across directories.

The verdict is judged at an explicit instant: `stored_standing_at(directory, id, now)`. `stored_standing` is that at the wall clock, and each door reads the clock once and passes it down. Nothing under `compute_standing` reads the wall clock. The blocker this fixes: the key fed INSTANTS, but the verdict evaluated them against the clock, so a future-dated input was cached as Rooted and served after its instant passed. It was found three times (a second resignation after a re-seat, an occurrence binding with a future `asserted_at`, and a withdrawal whose proposal arrived later).

The key is a digest of every input the verdict reads, AS STORED. It holds no value evaluated against the clock:
- the stored signed row with its lineage;
- the accord family record and its roster plane as stored: every holder widening and revocation, and their signers;
- the key record and steward withdrawal of every holder, every family member and widened member, and every key the chain names;
- for each withdrawal, its proposal's signed `window_until`, or a "no proposal" marker (2c: a proposal landing is a changed input);
- each such key's node-bearing inputs (`node_bearing_of`: its own `node` bit and the stored intervals in which it is an occurrence of a node identity);
- every self-signed resignation instant, past or future. The folded roster is no longer fed: it is a value at the clock, and the verdict never reads it.

Each entry carries the instant it was judged at and `valid_until`: the EARLIEST time-dependent boundary strictly after that instant, among every input the verdict compares against `now`. A hit is served only when `judged_at <= now < valid_until` (or `valid_until` is `None`). Otherwise the verdict is recomputed. The `Memo` carries `now`, and each site that compares an input against it registers the input's instant (`Memo::bound`). Every comparison against `now` or an evaluation instant on the verdict path, grepped:
- `founder_counts` at the head (`at` = `None`, so `when` = `now`):
  - resignation instants, `r > seated_since && r <= now`: each of the key's resignations after `now` is a boundary;
  - `founder_is_human_at(now)` through `node_bearing_at_with_next`: every occurrence-interval edge after `now` is a boundary. An interval is `[asserted_at, end)`, `end` the earliest of the binding's `valid_until` and a revocation `effective_at` (the identity-side revocations `node_bearing_of` reads);
  - the withdrawal arm, `at.is_some_and(|t| t < instant)`: with `at` = `None` any withdrawal un-counts, whatever its instant. No boundary; the proposal's `window_until` is fed into the key instead.
- The accord birth quorum: the family roster folded at `now` (`authorized_family_roster_at`, the fold `active_family_members` runs at the wall clock). Every holder widening and revocation `effective_at` after `now` is a boundary (`family_event_instants`).
- `verify_founders_link`'s future bound, `amended_at > now + 60 s`: `amended_at - 60 s` is a boundary. A link refused as too far ahead is admissible from then on.
- Evaluated at a fixed instant, so not bounded: `founder_counts` for a link (`amended_at`) or the birth (`founded_at`); the link seats' `is_node_bearing_key_at(amended_at)`; the `amended_at` floor against the prior's instant; `resigned_within`'s window; the withdrawal instant against `amended_at`.
- Not reachable here: the roster fold's reverse-quorum branch (`prepare_roster_events`) reads the wall clock, but only for a `reverse_quorum:` protocol, and the accord family's is `quorum:M/N`.
- Door checks outside the verdict read the door's own `now`: `check_founder_eligible`, and the plane's `resignation_backdated` floor.
- Round 10 review nit (iii), stated and not changed: `put_community` reads the clock in the door (`check_trust_root_community_admission`) and again in `apply_trust_root_chain`. This is benign: the later `now` only relaxes the links' future bound, and the door has already refused anything it would refuse. Passing the door's instant into the apply route means threading it through `route_occupied_community` on all three backends, which is not a one-line change.

Any change to the stored inputs is a new key; a holder revocation, a founder withdrawal or rotation, a resignation, a proposal landing and an amendment all are. A read with unchanged inputs before `valid_until` verifies no signature: the cache key costs only directory reads. Within one computation, each founder's conferral co-scrub is verified once (`Memo`). The cache drops everything past 256 entries.

I190 (u), (v), (w) and (m) witness the boundaries, each deterministic through a pinned `now`:
- (u) the 2a shape: F2 resigns, is retired and re-seated, then signs a second resignation dated now + 50 s. Judged at r − 1 s it is Rooted, and a second read there is a hit. Judged at r + 1 s it is Stalled, so the cache must miss.
- (v) the 2b shape: F2 agrees to be an occurrence of a `node` identity with `asserted_at` 120 s ahead. It is Rooted before and Stalled after.
- (w) the 2c shape: a trusted-local withdrawal of F2, whose proposal is not held, reads NotRooted. The proposal lands and the next read is Rooted.
- (m) a holder revocation dated 30 s ahead: Rooted just before, NotRooted just after.

Otherwise it answers `NotRooted { reason }`, for a pre-v50 squat, an unsigned row or a non-conformant row. A `NotRooted` row resolves to nothing. The route serves it as `community: null` with `community_withheld: <reason>`. It is not a `trust:accepts` subject and it is not a community root. An accord BIRTH replaces it: the occupied-id route applies the birth as a new version and records `accord_birth_replaces_unrooted: <prior hash>`. That row was never admissible, so it has no version to amend.

Correction to round 2: round 2's `stored_standing` accepted ONE eligible founder plus ANY unverified stored proof, and its residual note wrongly said "all founders". A v49 squat naming one real steward and two squatter founders with a squatter-signed proof would have read as rooted, and the birth could never have replaced it. The chain rule closes that: such a row's chain does not start at an accord birth. I190 (j) plants exactly that row.

**Supersede (CC 3.2).** `prepare_trust_root_supersede` runs in `supersede_community_signed` (every local supersede door). For a rooted or stalled row it requires a verified founders' link and founders who all count now. For anything else it refuses promotion into the grade: only a birth chain through `put_community` founds a trust root.

**Roster planes (HIGH-2, then the HIGH-3 ruling).** Both room roster doors, on every backend, run `check_community_roster_authority`, which calls `check_trust_root_roster_change` for a trust-root community. Any row that seats, re-roles or revokes a recorded or folded founder is refused, whoever signs. Rows about non-founder members follow the ordinary rule. The widening door's steward-binding probe honours a ROOTED trust root, so a serve node joins through the plane with no steward. The check is judged from the stored row, never the probe's label.

**Forks, stated plainly.** Where two versions extend the same held version, a node keeps the first it admits: a chain that does not contain the held version is refused, and a re-birth over a ROOTED row is refused. Since the content hash is bound (MEDIUM-B), only founder EQUIVOCATION can fork: the founders signing two different next versions.
- **The losing side holds a ROOTED version (LOW-4).** Nothing un-roots it by itself. It stalls only if the accord withdraws the equivocating founders' conferrals. The row then reads `Stalled` (or `NotRooted`, when the withdrawal predates a link it holds), and the recovery path opens: an accord re-birth over a stalled row, or any accord birth or the legitimate chain over a not-rooted one.
- **Equivocation to the same content (round 10 review, residual (i)).** The founders can reach the SAME content by two proofs with different `amended_at`. These are two versions. A node holding one refuses a chain through the other as not extending it, first-seen-wins like any equivocation fork; the next link's floor is never judged against the other path's instant. This arises only under founder equivocation.
- **A backdated link (round 10 review, residual (ii)).** A resigned founder F and another founder G can co-sign a link whose signer-chosen `amended_at` falls in (the prior's instant, F's resignation t1). F counts on it. This cannot be told apart from a link F and G pre-signed and withheld, and the plane floor already lets a founder sign links dated before their resignation. It launders nothing: while F is still recorded, the head reads Stalled, because the head judges F at now and t1 lies in (`seated_since`, now].
- **Fork, then evidence.** A consumer that meets a retired-key fork BEFORE the withdrawal evidence admits it, because its own state cannot tell the fork from a link. When the evidence then arrives, the fork's link counts a founder withdrawn before it, the chain stops verifying, and the row reads `NotRooted`. The legitimate chain then replaces it through the unrooted path. I190 (p) witnesses this.

**Trust (CC 3.2 T3, review MEDIUM-3).** `check_attested_subject_admission` now also knows a stored, ROOTED trust-root community. Before this cut the consumer's pin edge `delegates_to(consumer → ciris-canonical, trust:accepts:v1)` was unstorable. The widening applies to EVERY attestation type whose `attested_key_id` names such a community (a charter, a score, a delegation), not only `trust:accepts`. What a row may SAY about the community is still each type's own door's business. Any other community is still not a subject.

`trust_root_valid` gains `RootKind::Community` (a wire-visible enum variant, part of the v50.0.0 MAJOR):
- the user's edge names the community;
- the charter quorum, recovery, drill, halt and holder-hardware legs are the accord FAMILY's;
- the arm applies only while the community row is rooted.

So the community root is valid iff the family root is valid AND the row is rooted and conformant. With the family unchartered it is not valid. Withdrawing the one `trust:accepts:v1` row makes it not accepted, and the community row is untouched (trust ≠ membership).

**Resolve (CC 4.4.3.2.4).** `canonical_community::resolve_community` returns the folded roster. For a trust-root id it answers only while the row is `Rooted`, and its founders are exactly the RECORD's founders. `Rooted` requires every recorded founder to count now, so a withdrawn, resigned or non-human founder means no answer at all, not a shorter list. The members are the folded roster minus the recorded founders.

**Serve route (CC 5.3.4).** `GET /v1/trust-root/bundle` and `GET /v1/steward-key` are one handler on persist's axum router (`server` feature). The body is `TrustRootBundleResponse { bundle, authorization_digest, charter_root_key_id, community, community_withheld?, community_member_records }`:
- the bundle is the compiled-in artifact as carried;
- the rooted signed row sits beside it, never inside;
- the member key records travel with it.

The read is a point lookup. A failure returns a generic 500 body (`{"detail":"trust-root bundle unavailable"}`), and the detail is logged, not served. Persist did not serve these paths before this cut.

**The alias body differs from the registry's.** CIRISRegistry's v3 `/v1/steward-key` body is `{bundle, bundle_fingerprint, charter_root_key_id, served_by{node_key_id, accepts_this_root}}`. Persist's is the body above. It has no `served_by` or `bundle_fingerprint`, and it carries `authorization_digest`, `community`, `community_withheld` and `community_member_records`. The registry adopting persist's body, or not, is outside persist. The CI pre-flight reads the `bundle` key both bodies share.

**Consumer pin.** `pin_trust_from_bundle_response` works from one response:
1. `verify_bundle_quorum` against the consumer's OWN roster;
2. the member key records through the key door;
3. the row through the community door, which re-derives the accord quorum against the consumer's own pins;
4. resolve.

The records go in BEFORE the community because the door judges founders from this node's records. Each record passes the key door on its own terms (a founder's co-scrub is re-verified here; a serve node's record is a self-registration anyone may submit). A refused community therefore leaves behind only records this node would admit from anyone: never a community, never a conferral the accord did not sign.

**Host reach (review MEDIUM-5).** `put_community_json` takes a `cosignatures` list. A malformed list is refused with `ValueError`, and co-signatures without an authority signature are refused. There are three new bindings, classified in `scripts/ffi_taxonomy.tsv`, with `.pyi` stubs and `evidence/ffi_classification.tsv` regenerated:
- `resolve_community_json`: deontic;
- `trust_root_bundle_response_json`: empirical;
- `pin_trust_from_bundle_response_json`: deontic.

`put_community_json` hard-codes `supersede_proof: None` and an empty `lineage`. A Python host therefore relays a founders' amendment through `supersede_community_with_quorum`, and a chain through `pin_trust_from_bundle_response_json`, not through the plain put.

Witness: `tests/python/test_sqlite_engine.py::test_ciris_canonical_trust_root_surface_926`, run against a `maturin develop --features pyo3,sqlite` wheel: 45 passed, 10 skipped for the whole `tests/python` suite. On a genesis-seeded fresh engine the pin passes the REAL bundle's 2-of-3 and is then refused because nothing sits beside it. NOT proven through the wheel: the POSITIVE co-signature path (a quorate row put over Python). The witness shows only that a malformed list is refused and that a well-formed list reaches the door, because the genesis-seeded engine holds the real holder pubkeys and a test cannot sign as them.

**Fixture vs real row, stated plainly.** No real `ciris-canonical` row exists. `canonical_seed.json` still carries zero community rows, and a production node resolves `ciris-canonical` to nothing until the real row is admitted. The real row, and the `registry-steward-*` key records its founders need (accord-conferred `user,steward`), require one holder signing session. That session is outside persist. I190's fixture stands the trust root up on a bare directory with test-held keys under the genesis holder ids (`register_genesis_accord_roster`). It is the path a fresh install takes once the real row is signed. It is not that row.

**#809.** The Rust-side consumer gate was already a gate (`verify_bundle_quorum`), and I190 (f) witnesses it through the pin. The REPORTED-not-gated assertion #809 tracked was the release pre-flight in `.github/workflows/ci.yml`. It is now `scripts/preflight_trust_root.py` and GATED: an unparseable `consensus_protocol` is refused, and so are distinct seated authorizations short of M. The step runs a 12-fixture self-test first, including #809's `authorizations: []` row, which now exits 1. The live registry passed it on 2026-09-26 (2 ≥ 2; `accepts_this_root=false` warned). It counts authorizations and does not verify their signatures.

**Invariant I190** (memory, sqlite, postgres, 94 tests):
- (a) the fixture row admits under a 2-of-3 accord co-scrub, resolves, and its co-signature is served byte-exact;
- (b) 1-of-3, a founder co-signature and founders alone are refused; a forged co-scrub is refused even beside a quorum, and so is a doubled co-signer;
- (c) a node-bearing founder (#925), a self-declared steward, each shape clause, and a squatted reserved id are refused;
- (d) the community root is invalid while the family is unchartered, VALID (`RootKind::Community`, charter quorum met) once it is, and not accepted after the one-row un-trust; the row is untouched;
- (e) the response carries the row beside the bundle, a fresh consumer pins from that one response, and a genuinely fresh consumer given a row stripped of its co-signature gets the typed `RosterAuthorityUnauthorized` and pins nothing;
- (f) a bundle with 1 or 0 authorizations is refused, and the CI pre-flight gates it (from disk, script executed);
- (g) a supersede cannot rename without the founders' quorum; lifting entrenchment and moving the protocol are refused even under the founders' quorum; a room cannot be promoted into the grade;
- (h) node `a` amends twice by the founders' quorum: v2 adds a serve node; v3 adds another AND swaps a founder through the record (h′):
  - v3 carries its chain;
  - a FRESH node refuses v3 without its chain, a chain that skips v2, and a chain whose lineage authority signature is forged; it then pins v3 from `a`'s one response;
  - peer `b`, holding v1 and never shown v2, walks to v3 and applies v2 then v3;
  - refused on the local door: a single founder, a protocol move, an unconferred added founder;
  - refused on peer `c`: a short proof, a protocol move under a genuine proof, a BODY VARIANT under a genuine proof, a body keeping a founder the envelope demoted, a moved founder set the envelope does not bind, a proof-less version, an authority that is not a counted founder;
  - (h″) a proof counting a founder whose conferral was withdrawn before the link falls short; the founders then retire that founder through the record and the row is rooted again;
- (i) the roster planes admit and remove members only: a serve node joins with no steward; seating a founder (even an eligible one, even under every founder's signature), re-roling one, revoking one, and a founder leaving are all refused; a founder is then seated through the record; a moderator a founder appointed seats a member but never a founder (sqlite/postgres builds);
- (k) every recorded founder must count: a withdrawn conferral STALLS the row, naming the founder, and a founders' amendment retiring the seat roots it again;
- (l) a founder key rotation: F2 co-signs v2, F2 rotates to a successor, v3 seats the successor; node `a` still reads its chain rooted and a fresh node walks v1 → v3 with F2's record served beside the row;
- (m) a second read with unchanged inputs recomputes nothing; a holder revocation in the accord family, dated 30 s ahead, is a new key, the row is Rooted judged 1 s before it, and judged 1 s after it the cache misses and the row is un-rooted;
- (n) a chain over 1024 versions, or over 32 MiB, is refused at the door;
- (k′) two conferrals withdrawn through the accord stall the row:
  - the lone founder's amendment falls short;
  - a re-birth over the ROOTED row, and one not founded later, are refused;
  - the accord re-birth replaces the stalled row (`accord_rebirth_replaces_stalled`), and it is rooted again;
- (o) a founder resigns by their own plane revocation: the row stalls, a later link counting them falls short, and the others retire the seat through the record; the founders then RE-SEAT the key, the older resignation no longer applies (LOW-1), and the re-seated founder co-signs a later link on the local door (MEDIUM-R (b), and the one-quorum rule);
- (o′) F2 co-signs v2; F2's resignation dated between the birth and v2's `amended_at` is refused with `resignation_backdated`, and the row stays Rooted with every founder; the same resignation dated now is admitted and stalls the row (MEDIUM-R);
- (o′) additionally: a resignation dated EXACTLY at the link head's `amended_at` is refused and the row stays Rooted; one second later it is admitted and the row stalls;
- (o‴) every resignation counts: F2 resigns, is retired, is re-seated through the record, and resigns again after the re-seat head; the row stalls, naming F2;
- (o″) the counting rule and the lapse trace: F2 resigns; the other founders' v6 that still records F2 is ADMITTED on the replicated chain door and the row is Stalled, naming F2; F2 with F0 then produces no v7 (adding a member, or amending F2 out) on either door; F0 + F1 amend F2 out (Rooted), re-seat F2 (Rooted), and F2 then co-signs a later link;
- (u) a second resignation dated now + 50 s after a re-seat: Rooted and a cache hit at r − 1 s, Stalled and a cache miss at r + 1 s;
- (v) an agreed occurrence binding of F2 under a `node` identity, `asserted_at` 120 s ahead: Rooted and a cache hit before, Stalled and a cache miss after;
- (w) a withdrawal whose proposal is not held reads NotRooted; the proposal lands and the next read recomputes and is Rooted;
- (x) two nodes, the review's 4a split: `a` admits F2's resignation, `b` refuses it as backdated; `a` admits `b`'s H2 (still recording F2) and is Stalled while `b` is Rooted; H3 amends F2 out and both are Rooted on H3;
- (y) an offered lineage that reaches the held content by another signed path, re-seating F2 after the resignation, does not extend the held version (`does not extend`), whoever signs v4; over the held chain, v4 by F2 + F0 falls short and v4 by F0 + F1 is admitted and stored on the chain the node holds;
- (z) round 10, three nodes: `b` retires F2 (v2), re-seats F2 back to the birth's content (v3), and F2 + F0 sign v4; replica `c`, holding v3 (the LAST occurrence of that content), admits v4; `a`, holding the birth (the FIRST occurrence) and never shown v2 or v3, walks every link and admits v4; all three are Rooted on v4 with the whole chain stored;
- (z′) round 11: a correct extension over an offered prefix whose bytes are corrupted, (a) a birth co-signature, (b) a link's authority signature, is admitted; the row stays Rooted on its next re-judgement, and the stored lineage is the held chain byte for byte;
- (t) the TOCTOU arm: `prepare_trust_root_supersede` flagged as having skipped the generic quorum refuses over a NotRooted constraint row; unflagged it passes;
- (r) #925's node-bearing half on its own: a `user,steward` founder that becomes an agreed occurrence of a `node` identity stalls a Rooted row whose standing was already cached (naming the founder), and a birth naming such a founder is refused with `node_bearing_founder`;
- (q) both doors, one predicate: a reserved-id squat, a short birth, a body variant under a genuine proof and a role-binding replay are refused on `put_community` (the typed rule, via `assert_violation`) and on `apply_replicated_community` (`Refused { DegradesConformance }`, or the propagated insufficient-quorum error), and nothing moves; the accord birth is `Inserted`, its re-offer `Unchanged`, and a genuine founders' link `Superseded` through the replicated entry; another id's unverifying constraint row is refused locally and kept as data on the replicated entry (`NotRooted`, never resolved), and one founder of its `quorum:2/3` cannot supersede it into a plain room on the local door (the generic quorum still holds there);
- (p) a withdrawal through the accord with a short signed window:
  - the response carries its evidence;
  - a fresh consumer re-tallies it and REFUSES a retired-key fork signed after the window, although it recorded the withdrawal after the fork was signed;
  - a second fresh consumer pins through `pin_trust_from_bundle_response` and re-derives the withdrawal;
  - fork, then evidence (LOW-4): a third consumer admits the fork before the evidence (Rooted), the evidence un-roots it (`NotRooted`), and `a`'s legitimate head replaces it through the unrooted path;
- (h) additionally: a link with `amended_at` before the version it follows, or in the future, is refused; (e) the birth's co-signer record travels with the row;
- (j) three rows planted below the door on each backend: a non-conformant squat, a conformant row one founder signed alone, and one real steward plus two squatter founders with a squatter-signed "proof". Each resolves to nothing, is served as null with a named reason, is not a trust subject, and is replaced by the accord's birth chain, after which the consumer's root is valid.

Plus the server route test on both paths.

**Deviations.**
- Entrenchment, `cohort_subkind` and `infrastructure_constraint` live in `policy_blob`, not as record columns. `Community` has no such fields, and adding them would move every community's `persist_row_hash`.
- V158 (`community_cosignatures`, renumbered from V157 at the rebase: rc5-small's `withdraws_admission_depth` (#928, §8) took V157) is a new migration for the co-signatures and the `lineage`. It has not shipped. Its checksum rows are pinned in `evidence/migration_checksums.tsv` beside V157's.
- The chain grows with every amendment: each served row carries every prior version. That is linear in the amendment count and bounded by how often the founders amend.
- Founder seats of a trust-root community move only through the record (the HIGH-3 ruling). A LEGACY plane row that seated a founder before v50 does not count: links count recorded founders, and resolve lists recorded founders.
- The trust-root grade requires the HUMANITY_ACCORD's quorum for ANY row declaring `infrastructure_constraint`. An operator-minted infrastructure root under its own family is therefore not admissible by this door yet. Deriving the admitting family from the signer set is the follow-up.
- `is_authorized_infrastructure_community` still reads only the `substrate_persist` community key, so the read-time DEK Commons-plaintext opt-out and the moderator/federate re-checks treat an accord-admitted row as non-infrastructure. That is the stricter side. The admission-time and roster-plane steward-binding checks honour a rooted trust root.
- The #925 fold is done: the founder predicate is `user` plus `!is_node_bearing_key_at`, and every refusal is the typed `CommunityConsensusProtocolViolation`. No `FOLD(#925)` marker remains.
- Founder changes are swaps: rc5's N-equals-founder-count conformance holds for a trust root, so I190's founder moves are swaps and its rows use `quorum:3/3` where a 1/3 or a non-swap would now fail conformance first. `node` is exclusive of `user` at key mint (#925 Clause A), so the node-bearing founder fixture is `node,steward`.
- Rebase: the #926 history was squashed onto the release head 3d0df4e8 (a replay conflicted on every commit). The per-round history is kept on `v50-926-pre-rebase` (788d5926); the round SHAs below are on that branch.
- The first-round witnesses were written after the door, not RED first. The mutation rounds below are the RED evidence.
- `evidence_cc_impl_rows_pin_the_current_crate_version`'s exact count is 97: the base's 91 plus #926's 6 rows.

**Lanes (full, not filtered), on the last commit of each round.**
- Round 1 (00662bcd): `cargo nextest run -j 3 --features pyo3,sqlite --no-fail-fast` 3431/3431; `scripts/pg_test_db.sh -- cargo nextest run -j 3 --features postgres,sqlite --no-fail-fast` 3361/3361; `cargo test -q --features postgres,pyo3,server --lib` 2446 passed, 0 failed; `RUSTFLAGS="-D warnings" cargo test --no-run` with `server` and with `test-anchor,sqlite` both exit 0.
- Round 2 (90199b98): `pyo3,sqlite` 3443/3443; `postgres,sqlite` under `pg_test_db.sh` 3373/3373; `-D warnings` `--no-run` with `server` and with `test-anchor,sqlite` both exit 0. `cargo test -q --features postgres,pyo3,server --lib` ran on d790d5ca: 2454 passed, 0 failed. 90199b98 changes only the sqlite connection-model table, which that lane does not compile. The first `pyo3,sqlite` and `postgres,sqlite` runs of round 2, on d790d5ca, each had ONE red: `every_connection_touching_fn_in_sqlite_rs_is_classified`, the new sqlite point read being unclassified. 90199b98 classifies it. The `tests/python` suite against a `maturin develop --features pyo3,sqlite` wheel: 45 passed, 10 skipped.
- Round 3, the chain (59d402cf): `pyo3,sqlite` 3446/3446; `postgres,sqlite` under `pg_test_db.sh` 3376/3376; `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh` 2456 passed, 0 failed; `-D warnings` `--no-run` with `server` and with `test-anchor,sqlite` both exit 0. The Python wheel was not rebuilt for round 3: no pyo3 signature changed, and `put_community_json` passes an empty `lineage`.
- Round 4, the second ruling (2e1ba7e0): `pyo3,sqlite` 3455/3455; `postgres,sqlite` under `pg_test_db.sh` 3385/3385; `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh` 2462 passed, 0 failed; `-D warnings` `--no-run` with `server` and with `test-anchor,sqlite` both exit 0. The Python wheel was not rebuilt: no pyo3 signature changed.
- Round 5, recovery and resignation (b97978ce): `pyo3,sqlite` 3464/3464; `postgres,sqlite` under `pg_test_db.sh` 3394/3394; `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh` 2468 passed, 0 failed; `-D warnings` `--no-run` with `server` and with `test-anchor,sqlite` both exit 0. The Python wheel was not rebuilt: no pyo3 signature changed; the response gained an additive field.
- Round 6, the rebase and the fold (991f8857 on `v50-926`; the commit after it changes only this FSD): `cargo nextest run -j 3 --features pyo3,sqlite --no-fail-fast` in two partitions, 1774 + 1767 = 3541/3541; `scripts/pg_test_db.sh -- cargo nextest run -j 3 --features postgres,sqlite --no-fail-fast` in two partitions, 1739 + 1732 = 3471/3471 (233 s and 286 s: a database was present); `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh` 2520 passed, 0 failed, 1 ignored; `RUSTFLAGS="-D warnings" cargo check --features server` exit 0; `python3 scripts/pyi_surface.py check` exit 0; `python3 scripts/gen_directory_double.py --check` current (105 delegations). The Python wheel was not rebuilt: no pyo3 signature changed in the fold.
- Round 7, R2 and the TOCTOU (a5912f40; the commit after it changes only this FSD): `pyo3,sqlite` in two partitions, 1777 + 1770 = 3547/3547; `postgres,sqlite` under `pg_test_db.sh` in two partitions, 1742 + 1735 = 3477/3477 (238 s and 243 s: a database was present); `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh` 2524 passed, 0 failed, 1 ignored.
- Round 8, the strict floor and the cache key (e873a01c; the commit after it changes only this FSD): `pyo3,sqlite` in two partitions, 1778 + 1772 = 3550/3550; `postgres,sqlite` under `pg_test_db.sh` in two partitions, 1743 + 1737 = 3480/3480 (243 s and 241 s: a database was present); `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh` 2526 passed, 0 failed, 1 ignored.
- Round 9, `valid_until` and the counting rule (lanes ran on de40c205, whose code is 196f29c4's; the commit after it changes only this FSD): `pyo3,sqlite` in two partitions, 1786 + 1779 = 3565/3565; `postgres,sqlite` under `pg_test_db.sh`, partition 1 of 2 plus partition 2 of 2 run as shards 2 and 4 of 4 (the first partition took 581 s, near the 600 s cap), 1751 + 877 + 867 = 3495/3495 (581 s, 251 s and 338 s: a database was present); the 2 tests those counts leave out of the listed 3497 are `#[ignore]`d. `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh`: the first run had ONE red, `federation::scores_read_audit::tests::scores_read_log_parity_memory` ("the scores plane must emit exactly one log entry per read at each of its two doors; got []"), a file #926 does not touch; it passed 3 of 3 runs alone, and the re-run of the whole lane was 2536 passed, 0 failed, 1 ignored. It captures through a thread-local `tracing` subscriber inside one multi-threaded `cargo test` process, which is load-dependent; it is flagged, not fixed here. `RUSTFLAGS="-D warnings" cargo check --features server` exit 0; `python3 scripts/pyi_surface.py check` exit 0; `python3 scripts/gen_directory_double.py --check` current (105 delegations). No pyo3 signature changed.
- Round 10, the held version matched by position and proof (lanes ran on 39645d41, whose code is bb5bc2d0's; the commit after it changes only this FSD): `pyo3,sqlite` in two partitions, 1787 + 1781 = 3568/3568; `postgres,sqlite` under `pg_test_db.sh` in two partitions, 1752 + 1746 = 3498/3498 (236 s and 233 s: a database was present). In both lanes the 2 tests missing from the listing are `#[ignore]`d. `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh`: 2538 passed, 0 failed, 1 ignored, on the first run. `RUSTFLAGS="-D warnings" cargo check --features server` exit 0; `python3 scripts/pyi_surface.py check` exit 0; `python3 scripts/gen_directory_double.py --check` current (105 delegations). No pyo3 signature changed.

**Mutation table, round 1 (#926).** The round ran on 34fe6df5, with M12 re-run on dc2fa151.
- **Lane:** `test(i190) | test(canonical) | test(genesis) | test(bundle) | test(trust_root) | test(conferral)`, `--features sqlite,postgres`, under `scripts/pg_test_db.sh`.
- **Baseline:** 270/270 passed.
- **Result:** 12/12 killed.
- **M12 first survived.** (b)'s forged co-scrub was also short of the quorum, so the count refused it and the door's co-signature check was never measured. (b) gained a quorate row padded with one bad co-scrub, plus a doubled co-signer, and M12 was then killed.

**Mutation table, round 2 (review fixes).** The round ran on 455d541b, with survivors re-run on d790d5ca.
- **Lane:** the same.
- **Baseline:** 282/282 passed.
- **Discipline:** each mutant was reverted before the next, and no mutant was OOM-killed.
- **Result:** 23 of the 25 mutants below are killed outright, all 13 of the new ones included.
- **N2 and N3 are equivalent by design.** They are two layers of one rule, each covering the other. Killing both together (N2+N3) fails I190 (h) ×3.
- **N4 is equivalent to the pre-existing #910 rule.** A different version with no `supersede_proof` is refused by `admit_amendment` itself.
- **Four mutants first survived and were killed after d790d5ca:** N2 and N3 (now together), N11 and N13.
- **M4's first mutant did not compile** (a type annotation). It was re-written and killed.

| # | Mutant | Tests failed | Killed by |
|---|---|---|---|
| M1 | accord quorum check dropped (birth) | 6 | I190 (b), (e) ×3 |
| M2 | 1-of-3 admitted (birth) | 6 | I190 (b), (e) ×3 |
| M3 | entrenchment not required | 6 | I190 (c), (g) ×3 |
| M4 | the route serves no community | 3 | I190 (e) ×3 |
| M5 | #809 CI gate reverted to report | 1 | `i190_f_ci_preflight_gates_the_bundle_quorum` |
| M6 | founder human-key rule (#925) skipped | 6 | I190 (c), (i) ×3 |
| M7 | founder accord-conferral skipped | 9 | I190 (c), (h), (i) ×3 |
| M8 | local supersede without the founders' proof | 3 | I190 (g) ×3 |
| M9 | `ciris-canonical` not reserved | 6 | I190 (c) ×3, (j) ×3 |
| M10 | trust-root community not a `trust:accepts` subject | 6 | I190 (d) ×3, (j) ×3 |
| M11 | the consumer pin skips `verify_bundle_quorum` | 3 | I190 (f) ×3 |
| M12 | community co-signatures not verified at the door | 3 | I190 (b) ×3 |
| N1 | a peer re-demands the accord count on a founders' amendment | 3 | I190 (h) ×3 |
| N2 | the route's trust-root supersede check removed (`group_amendment.rs`) | 0 | equivalent alone: the gate's immutables cover it |
| N3 | the gate's amendment immutables removed | 0 | equivalent alone: the route's check covers it |
| N2+N3 | both layers removed | 3 | I190 (h) ×3 (a peer applies a protocol move under a genuine founders' proof) |
| N4 | the gate does not require a proof on an amendment | 0 | equivalent: `admit_amendment` (#910) refuses a proof-less different version |
| N5 | the roster-plane guard dropped | 6 | I190 (i), (i) moderator ×3 |
| N6 | roster-plane founder eligibility dropped | 3 | I190 (i) ×3 |
| N7 | roster-plane founders' quorum dropped (a moderator seats a founder) | 3 | I190 (i) moderator ×3 |
| N8 | the steward-binding probe ignores the accord door | 3 | I190 (i) ×3 |
| N9 | `resolve_community` does not re-judge the stored row | 3 | I190 (j) ×3 |
| N10 | read-side shape re-check dropped | 3 | I190 (j) ×3 |
| N11 | read-side accord re-check dropped | 0, then 3 | first round: none (the planted squat also failed its shape); after d790d5ca: I190 (j) ×3 (a conformant never-born row) |
| N12 | an accord birth does not replace a squat | 3 | I190 (j) ×3 |
| N13 | the community root is valid without its family | 0, then 3 | first form (only `root_self_declares` relaxed) was masked by the recovery leg and survived; rewritten to skip every family leg for a community root: I190 (d) ×3 (invalid before the accord is chartered) |

**Mutation table, round 3 (the chain).** The round ran on 242d1402. C2b and C5b were re-run on 59d402cf.
- **Lane:** the same.
- **Baseline:** 285/285 passed.
- **Discipline:** each mutant was reverted before the next, and no mutant was OOM-killed.
- **Result:** 31 mutants, all killed.
- **C2b and C5b first survived.** The chain skip had only been offered to a node whose stored version caught it through the backend's stale-proof check, and no record member's plane role differed from its recorded role. (h) gained a fresh node refusing a skipping chain, and (i) gained a plane demotion before an amendment.
- **Round 2's N1–N4 and N11–N12 are retired.** Their code (the one-hop amendment route and the proof-only arm) no longer exists. R1, C6 and C9 take their places.
- **An aborted first attempt at this round.** Its driver was stopped after M2 because the builder's role binding changed. The results below are from the full re-run.

| # | Mutant | Tests failed | Killed by |
|---|---|---|---|
| M1 | accord quorum check dropped (birth) | 9 | I190 (b), (e) ×3, (j) ×3 |
| M2 | 1-of-3 admitted (birth) | 6 | I190 (b), (e) ×3 |
| M3 | entrenchment not required | 6 | I190 (c), (g) ×3 |
| M4 | the route serves no community | 6 | I190 (e), (h) ×3 |
| M5 | #809 CI gate reverted to report | 1 | `i190_f_ci_preflight_gates_the_bundle_quorum` |
| M6 | founder human-key rule (#925) skipped | 6 | I190 (c), (i) ×3 |
| M7 | founder accord-conferral skipped | 9 | I190 (c), (i), (k) ×3 |
| M8 | the local door skips the founders' link | 6 | I190 (g), (h) ×3 |
| M9 | `ciris-canonical` not reserved | 6 | I190 (c) ×3, (j) ×3 |
| M10 | trust-root community not a `trust:accepts` subject | 6 | I190 (d) ×3, (j) ×3 |
| M11 | the consumer pin skips `verify_bundle_quorum` | 3 | I190 (f) ×3 |
| M12 | community co-signatures not verified at the door | 3 | I190 (b) ×3 |
| N5 | roster-plane guard dropped | 6 | I190 (i), (i) moderator ×3 |
| N6 | roster-plane founder eligibility dropped | 3 | I190 (i) ×3 |
| N7 | roster-plane founders' quorum dropped (a moderator seats a founder) | 3 | I190 (i) moderator ×3 |
| N8 | the steward-binding probe ignores the accord door | 3 | I190 (i) ×3 |
| N9 | `resolve_community` does not re-judge the row | 6 | I190 (j) ×3, (k) ×3 |
| N10 | read-side shape re-check dropped | 3 | I190 (j) ×3 |
| N13 | the community root is valid without its family | 3 | I190 (d) ×3 |
| R1 | a peer re-demands the accord count on an amendment | 3 | I190 (h) ×3 |
| C1 | chain walk skipped: a fresh node admits the latest version on its own proof | 3 | I190 (h) ×3 |
| C2 | a link's signers not verified (founders' quorum) | 3 | I190 (h) ×3 |
| C2b | a link's prior hash not checked | 0, then 3 | first round: none; after 59d402cf: I190 (h) ×3 (a fresh node given a skipping chain) |
| C3 | founder-set immutability dropped | 3 | I190 (h) ×3 (a demotion the founders themselves signed) |
| C4 | envelope role binding not checked | 3 | I190 (h) ×3 (a body keeping a founder the envelope demoted) |
| C5 | the builder does not bind roles | 6 | I190 (h), (i) ×3 |
| C5b | the builder binds the folded roster's roles, not the record's | 0, then 3 | first round: none; after 59d402cf: I190 (i) ×3 (a plane demotion before an amendment) |
| C6 | `stored_standing` proof-only arm | 3 | I190 (j) ×3 (one steward, two squatters, a squatter "proof") |
| C7 | `stored_standing` drops every-founder eligibility | 3 | I190 (k) ×3 |
| C8 | multi-hop apply skips intermediate versions | 3 | I190 (h) ×3 (a peer at v1 receiving v3) |
| C9 | a squat is not replaced by the birth chain | 3 | I190 (j) ×3 |

**Mutation table, round 4 (the second ruling).** The round ran on 2e1ba7e0.
- **Lane:** the same.
- **Baseline:** 294/294 passed.
- **Discipline:** each mutant was reverted before the next, and no mutant was OOM-killed.
- **Result:** 37 mutants, all killed on the first run.
- **Retired:** N6 and N7 (their plane quorum path is gone), C3 (founder-set immutability, lifted by the ruling), and C5 and C5b (the builder no longer binds roles; `bind_next_version` does).

| # | Mutant | Failed | Killed by (I190 arm) |
|---|---|---|---|
| M1 | accord quorum check dropped (birth) | 12 | (b), (e), (j), (m) |
| M2 | 1-of-3 admitted (birth) | 9 | (b), (e), (m) |
| M3 | entrenchment not required | 6 | (c), (g) |
| M4 | the route serves no community | 9 | (e), (h), (l) |
| M5 | #809 CI gate reverted to report | 1 | CI witness |
| M6 | founder human-key rule skipped at the door | 3 | (c) |
| M7 | founder accord-conferral skipped at the door | 6 | (c), (h) |
| M8 | the local door skips the founders' link | 6 | (g), (h) |
| M9 | `ciris-canonical` not reserved | 6 | (c), (j) |
| M10 | trust-root community not a `trust:accepts` subject | 6 | (d), (j) |
| M11 | the pin skips `verify_bundle_quorum` | 3 | (f) |
| M12 | co-signatures not verified at the door | 3 | (b) |
| N5 | roster-plane guard dropped | 6 | (i), (i) moderator |
| N8 | the steward-binding probe ignores the accord door | 3 | (i) |
| N9 | resolve does not re-judge the row | 9 | (j), (k), (m) |
| N10 | read-side shape re-check dropped | 3 | (j) |
| N13 | the community root is valid without its family | 3 | (d) |
| R1 | a peer re-demands the accord count | 3 | (h) |
| C1 | chain walk skipped on a fresh node | 3 | (h) |
| C2 | a link's founders' quorum not required | 3 | (h) |
| C2b | a link's prior hash not checked | 3 | (h) |
| C4 | envelope role binding not checked | 3 | (h) |
| C6 | `stored_standing` proof-only arm | 3 | (j) |
| C7 | every-recorded-founder counting dropped | 3 | (k) |
| C8 | multi-hop apply skips intermediate versions | 3 | (h) |
| C9 | a squat not replaced by the birth chain | 3 | (j) |
| P1 | the plane admits a founder-seat change | 6 | (i), (i) moderator |
| P2 | role binding skipped when the founder set moves | 3 | (h) |
| P3 | a link counts a withdrawn record founder | 6 | (h), (k) |
| P4 | the next-content hash binding dropped | 3 | (h) (a body variant) |
| P5 | the authority need not be a counted founder | 3 | (h) |
| P6 | a link's authority signature not verified | 3 | (h) (a forged lineage entry) |
| P7 | the standing cache keyed on the row alone | 6 | (k), (m) |
| P8 | lineage length cap dropped | 3 | (n) |
| P9 | lineage byte cap dropped | 3 | (n) |
| P10 | a rotation un-counts historical signatures | 9 | (h), (k), (l) |
| P11 | the bundle response serves only the current version's keys | 3 | (l) |

**Mutation table, round 5 (recovery, resignation, node-independent withdrawal).** The round ran on b97978ce.
- **Lane:** the same.
- **Baseline:** 303/303 passed.
- **Discipline:** each mutant was reverted before the next, and no mutant was OOM-killed.
- **Result:** 49 mutants. 48 killed. O3 survived, and it is EQUIVALENT: dropping a resigned seat from the link's seats cannot change a `quorum:M/N` verdict, because M is absolute. The only protocols a trust-root row admits are `quorum:M/N`. The seat drop is kept for honesty of the seat set, not for any verdict it changes today.
- **P3 and P10** were re-pointed at the new withdrawal-instant comparison.
- **Previously killed mutants re-run** (killed by):
  - M1 → (b), (e), (j), (m)
  - M2 → (b), (e), (m)
  - M3 → (c), (g)
  - M4 → (e), (h), (l), (p)
  - M5 → CI witness
  - M6 → (c)
  - M7 → (c), (h)
  - M8 → (g), (h)
  - M9 → (c), (j)
  - M10 → (d), (j)
  - M11 → (f)
  - M12 → (b)
  - N5 → (i), (i) moderator
  - N8 → (i)
  - N9 → (j), (k), (m)
  - N10 → (j)
  - N13 → (d)
  - R1 → (h)
  - C1 → (h), (p)
  - C2 → (h), (o), (p)
  - C2b, C4, C8 → (h)
  - C6, C9 → (j)
  - C7 → (k), (k′), (o)
  - P1 → (i), (i) moderator
  - P2, P4, P5, P6 → (h)
  - P3 → (h), (k), (k′), (p)
  - P7 → (k), (k′), (m)
  - P8, P9 → (n)
  - P10 → (h), (k), (k′), (l), (p)
  - P11 → (l)

| # | New mutant | Failed | Killed by |
|---|---|---|---|
| K1 | re-birth refused over a stalled row | 3 | (k′) |
| K2 | re-birth replaces a ROOTED row | 3 | (k′) |
| K3 | re-birth need not be founded later | 3 | (k′) |
| O1 | resignation ignored in `founder_counts` | 3 | (o) |
| O2 | resignation refused on the plane | 3 | (o) |
| O3 | a resigned seat kept in the link seats | 0 | equivalent (see above) |
| W1 | withdrawal instant from the local clock | 3 | (p) |
| W2 | the response omits the withdrawal evidence | 3 | (p) |
| W3 | the pin does not admit the withdrawal evidence | 3 | (p) |
| W4 | co-signer records not served | 3 | (e) |
| A1 | `amended_at` floor dropped | 3 | (h) |
| A2 | `amended_at` future bound dropped | 3 | (h) |

**Mutation table, round 6 (the rebase onto 3d0df4e8, the rc5 fold, MEDIUM-R, the LOWs).** B1–B4, D1–D3, L1, L2, and the first L3 and F1 runs ran on 55e32510 (baseline 347/347). Every other mutant, and the L3 and F1 re-runs, ran on 991f8857, which adds I190 (r) and (q)'s local-quorum leg. Its three survivors ran 350/350 green, which is that commit's baseline.
- **Lane:** `test(i190) | test(canonical) | test(genesis) | test(bundle) | test(trust_root) | test(conferral) | test(supersede)`, `--features sqlite,postgres --lib`, under `scripts/pg_test_db.sh`. Every run had a database.
- **Discipline:** each mutant was reverted before the next, and no mutant was OOM-killed.
- **Result:** 63 mutants. 60 killed. 3 are equivalent:
  - O3, as in round 5: M is absolute.
  - F2: a node-bearing founder is already dropped from the link seats by `founder_counts`, and the only other node-bearing seats are serve-node members, which `quorum:M/N` over founders never counts.
  - RC: the trust-root guard runs first and admits only member changes and a founder's own self-leave. rc5's gate admits both, and both refuse the last founder. The early return removes a second gate; it changes no verdict.
- **L3 and F1 first survived.**
  - L3: a data-kept constraint row at another id could be superseded locally with no quorum. (q) now asserts the generic quorum holds there.
  - F1: (c)'s node founder is `node,steward`, so the `user` half refused it and the node-bearing half was never measured. (r) makes a `user,steward` founder an agreed occurrence of a `node` identity. Both were then killed.
- **The required mutant B1** (MEDIUM-R's past floor dropped) is KILLED by (o′) on all three backends.
- **Round 5's mutants were re-run** on the folded code (anchors moved for M6, C7, O1, O2, O3, R1, W2).

| # | Mutant | Failed | Killed by (I190 arm) |
|---|---|---|---|
| B1 | MEDIUM-R (a): the plane's past floor dropped | 3 | (o′) |
| B2 | MEDIUM-R (b): a link counts a resignation older than its prior | 3 | (o) |
| B3 | LOW-1: the standing ignores the re-seat floor | 3 | (o) |
| B4 | LOW-1: resolve lists the plane roster's founders | 3 | (o) |
| D1 | the replicated entry skips the trust-root predicate | 3 | (q) |
| D2 | the replicated entry is lenient for the reserved id | 3 | (q) |
| D3 | the replicated legacy-as-data allowance dropped | 3 | (q) |
| L1 | a local trust-root amendment also runs the folded quorum | 6 | (h), (o) |
| L2 | the local door skips the folded quorum for every row | 3 | `engine::tests::quorum_supersede_protocol_decides` |
| L3 | the local door skips the folded quorum for a NotRooted constraint row | 0, then 3 | (q) |
| F1 | the founder's node-bearing half dropped (door and link instant) | 0, then 3 | (r) |
| F2 | link seats never node-bearing | 0 | equivalent (see above) |
| F3 | the standing cache key omits the node-bearing inputs | 3 | (r) |
| RC | rc5's founder-count gate also runs for a trust root | 0 | equivalent (see above) |
| M1 | accord quorum check dropped (birth) | 15 | (b), (e), (j), (m), (q) |
| M2 | 1-of-3 admitted (birth) | 12 | (b), (e), (m), (q) |
| M3 | entrenchment not required | 6 | (c), (g) |
| M4 | the route serves no community | 12 | (e), (h), (l), (p) |
| M5 | #809 CI gate reverted to report | 1 | CI witness |
| M6 | founder human-key rule skipped at the door | 3 | (c) |
| M7 | founder accord-conferral skipped at the door | 6 | (c), (h) |
| M8 | the local door skips the founders' link | 6 | (g), (h) |
| M9 | `ciris-canonical` not reserved | 9 | (c), (j), (q) |
| M10 | trust-root community not a `trust:accepts` subject | 6 | (d), (j) |
| M11 | the pin skips `verify_bundle_quorum` | 3 | (f) |
| M12 | co-signatures not verified at the door | 3 | (b) |
| N5 | roster-plane guard dropped | 9 | (i), (i) moderator, (o′) |
| N8 | the steward-binding probe ignores the accord door | 3 | (i) |
| N9 | resolve does not re-judge the row | 15 | (j), (k), (m), (q), (r) |
| N10 | read-side shape re-check dropped | 3 | (j) |
| N13 | the community root is valid without its family | 3 | (d) |
| R1 | a peer re-demands the accord count | 6 | (h), (q) |
| C1 | chain walk skipped on a fresh node | 6 | (h), (p) |
| C2 | a link's founders' quorum not required | 9 | (h), (o), (p) |
| C2b | a link's prior hash not checked | 3 | (h) |
| C4 | envelope role binding not checked | 6 | (h), (q) |
| C6 | `stored_standing` proof-only arm | 6 | (j), (p) |
| C7 | every-recorded-founder counting dropped | 15 | (k), (k′), (o), (o′), (r) |
| C8 | multi-hop apply skips intermediate versions | 6 | (h), (p) |
| C9 | a squat not replaced by the birth chain | 6 | (j), (p) |
| P1 | the plane admits a founder-seat change | 6 | (i), (i) moderator |
| P2 | role binding skipped when the founder set moves | 3 | (h) |
| P3 | a link counts a withdrawn record founder | 12 | (h), (k), (k′), (p) |
| P4 | the next-content hash binding dropped | 6 | (h), (q) |
| P5 | the authority need not be a counted founder | 3 | (h) |
| P6 | a link's authority signature not verified | 3 | (h) |
| P7 | the standing cache keyed on the row alone | 18 | (k), (k′), (m), (o′), (p), (r) |
| P8 | lineage length cap dropped | 3 | (n) |
| P9 | lineage byte cap dropped | 3 | (n) |
| P10 | a rotation un-counts historical signatures | 15 | (h), (k), (k′), (l), (p) |
| P11 | the bundle response serves only the current version's keys | 6 | (l), (p) |
| K1 | re-birth refused over a stalled row | 3 | (k′) |
| K2 | re-birth replaces a ROOTED row | 3 | (k′) |
| K3 | re-birth need not be founded later | 3 | (k′) |
| O1 | resignation ignored in `founder_counts` | 6 | (o), (o′) |
| O2 | resignation refused on the plane | 6 | (o), (o′) |
| O3 | a resigned seat kept in the link seats | 0 | equivalent (absolute M) |
| W1 | withdrawal instant from the local clock | 3 | (p) |
| W2 | the response omits the withdrawal evidence | 3 | (p) |
| W3 | the pin does not admit the withdrawal evidence | 3 | (p) |
| W4 | co-signer records not served | 3 | (e) |
| A1 | `amended_at` floor dropped | 3 | (h) |
| A2 | `amended_at` future bound dropped | 3 | (h) |

**Mutation round 7 (final review R2 and the TOCTOU).** The round ran on a5912f40, on the same lane as round 6. The O3 run, 356/356 green, is that commit's baseline. Each mutant was reverted before the next; there were no OOM kills, and every run had a database. 8 of 9 were killed; O3 is equivalent, as before.

| # | Mutant | Failed | Killed by (I190 arm) |
|---|---|---|---|
| X1 | R2: the carry-forward refusal dropped | 3 | (o″) |
| X3 | TOCTOU: the skipped-quorum flag ignored | 3 | (t) |
| B1 | MEDIUM-R (a): the plane's past floor dropped | 3 | (o′) |
| B2 | MEDIUM-R (b): a link counts a resignation older than its prior | 3 | (o) |
| B3 | LOW-1: the standing ignores the re-seat floor | 3 | (o) |
| B4 | LOW-1: resolve lists the plane roster's founders | 3 | (o) |
| O1 | resignation ignored in `founder_counts` (re-anchored on `resigned_within`) | 6 | (o), (o′) |
| O2 | resignation refused on the plane | 9 | (o), (o′), (o″) |
| O3 | a resigned seat kept in the link seats | 0 | equivalent (absolute M) |

- **B2's meaning changed.** Before R2 it was the only thing a lapse turned on, and its floor was what made the lapse possible. After R2 no admitted version carries a founder past their resignation, so B2 now guards only the re-seat. A re-seated founder's older resignation must not un-count a later link they co-sign. (o) is the arm that measures that.
- **Retired in round 9:** X1 and the refusal it measured. The counting rule replaced the carry-forward refusal.
- **Superseded by round 8:** this round's "not witnessed" note on keeping every resignation. (o‴) now witnesses it, and building (o‴) found that the standing cache key omitted the resignations.

**Mutation round 8 (re-check B, and every resignation).** The round ran on e873a01c, on the same lane as round 6 (359 tests; the full lanes above are its baseline). Each mutant was reverted before the next; there were no OOM kills, and every run had a database. All 4 were killed.

| # | Mutant | Failed | Killed by (I190 arm) |
|---|---|---|---|
| E1 | B: the plane floor at equality (`<=` reverted to `<`) | 3 | (o′) equality arm |
| B1 | MEDIUM-R (a): the plane's past floor dropped (re-anchored on `<=`) | 3 | (o′) |
| E2 | only the earliest resignation kept | 3 | (o‴) |
| E3 | the standing cache key omits the resignations | 3 | (o‴) |


**Mutation round 9 (the standing cache's `valid_until`, and the counting rule).** V1–V5, B1, S1, S2, B2′, E3 and the first H1 run ran on 9d1f5a16, whose lane baseline was 371/371. H1b and H1 + H1b ran on 196f29c4, which adds I190 (y); its lane baseline is 374/374. The lane is round 6's: `test(i190) | test(canonical) | test(genesis) | test(bundle) | test(trust_root) | test(conferral) | test(supersede)`, `--features sqlite,postgres --lib`, under `scripts/pg_test_db.sh`. Every run had a database; no leg ran at 0.00 s and none was OOM-killed. Each mutant was reverted with `git checkout --` before the next. 13 rows: 12 killed, and H1 alone is equivalent by design.

| # | Mutant | Failed | Killed by (I190 arm) |
|---|---|---|---|
| V1 | the cache ignores `valid_until` on a hit | 9 | (m), (u), (v) |
| V2 | occurrence-interval boundaries omitted from `valid_until` | 3 | (v) |
| V3 | resignation boundaries omitted from `valid_until` | 3 | (u) |
| V4 | the proposal's `window_until` dropped from the key | 3 | (w) |
| V5 | the family fold's holder boundaries omitted from `valid_until` | 3 | (m) |
| B1 | MEDIUM-R (a): the plane's past floor dropped | 6 | (o′), (x) |
| S1 | the counting rule's `seated_since` floor replaced by the prior-instant floor | 3 | (o″), the lapse |
| S2 | a resigned founder counts on a later link (the link ignores resignations) | 6 | (o), (o″) |
| B2′ | B2 re-derived: the link's `seated_since` floor dropped, so every resignation counts, even one before a re-seat | 6 | (o), (o″) |
| E3 | the standing cache key omits the resignations | 9 | (o′), (o‴), (u) |
| H1 | the door walks the offered prefix, not the held chain | 0 | equivalent alone: the apply route re-walks the held chain and refuses |
| H1b | the apply route walks, and stores, the offered prefix | 3 | (y) (the stored lineage is the offered one). Round 10 judged it equivalent; that was wrong, and round 11 kills it with (z′) |
| H1 + H1b | both layers walk the offered prefix | 3 | (y) (F2 + F0 over a forged re-seat is admitted) |

- **B2's meaning, re-derived.** Before round 9, B2 measured the prior-instant floor. That floor is gone, and S1 now measures putting it back. B2′ drops the floor altogether; (o) kills it, because the re-seated founder's older resignation would un-count their later link.
- **X1 is retired**, with the refusal it measured.
- The whole (o) family, (o), (o′), (o″) and (o‴), passes in both baselines on all three backends.

**Mutation round 10 (the held version matched by position and proof).** The round ran on bb5bc2d0, whose lane baseline is 377/377, on round 6's lane under `scripts/pg_test_db.sh`. Every run had a database; no leg ran at 0.00 s and none was OOM-killed. Each mutant was reverted with `git checkout --` before the next. R1 and R2 were killed. H1b is now equivalent.

| # | Mutant | Failed | Killed by (I190 arm) |
|---|---|---|---|
| R1 | the held version found as the FIRST offered index with its content (round 9's `extends_at`) | 6 | (z) arm 1: "the link's amended_at … is before the version it follows", the reviewer's trace; and (y) |
| R2 | the held version found as the LAST offered index with its content (`rposition`) | 6 | (z) arm 2: `roster_consensus_insufficient`, the stale `seated_since`; and (y) |
| H1b | the apply route walks, and stores, the offered prefix | 0 | survived round 10's lane; NOT equivalent (round 11 review). Killed in round 11 by (z′) |

- **Correction (round 11 review).** Round 10 called H1b equivalent and `walk_from_held` redundant. Both were wrong. `same_version` compares content, authority and the founders' proof (its `quorum_signatures` included), but not the authority scrub signature bytes or the co-signatures. The door walks only the links after the held version, so it never reads the offered prefix's signature bytes. If the apply route stored the offered prefix, one peer could flip bytes in it (a birth co-signature, a link's authority signature). The next `stored_standing` recounts them: the birth falls short of the accord quorum, or `verify_community_admission` fails on the link, and the row reads NotRooted, so any accord birth replaces it. The real code is safe because `walk_from_held` stores the HELD versions. It is load-bearing.

**Mutation round 11 (the stored prefix).** Run on 7d27fad6, whose lane baseline is 380/380, on round 6's lane under `scripts/pg_test_db.sh`. Every run had a database; no leg ran at 0.00 s and none was OOM-killed. Each mutant was reverted with `git checkout --` before the next. Both runs were killed. The first H1b run was taken on the same test code while it was staged but not committed (a clippy refusal of the commit); it was re-run on the committed tree, and the result below is that re-run.

| # | Mutant | Failed | Killed by (I190 arm) |
|---|---|---|---|
| H1b | the apply route walks, and stores, the offered prefix | 3 | (z′) sub-arm (a): "the birth's co-signature: the row stays Rooted on its next re-judgement" |
| H1b, sub-arm (b) alone | the same, with (z′)'s first sub-arm skipped (a test edit, to measure the second on its own) | 3 | (z′) sub-arm (b): "v2's authority signature: the row stays Rooted on its next re-judgement" |

- Round 11 changed no code. The full lanes run on the merged release SHA. This round ran only the I190 and mutation lane (380/380 on memory, sqlite and postgres).
### 9.1 PR review (Codex) fix — F1: a failed read is never a cache hit

**Finding (P1).** `standing_cache_key` read the accord family's record and roster plane with `.ok().flatten()` and `unwrap_or_default()`. A backend failure on any of those four reads keyed exactly as a genuinely empty plane does. A Rooted verdict cached over an empty plane was then served while the revocation state could not be read, and the verdict path's own error propagation never ran.

**Fix.** Every read in the key builder propagates its failure: no key, no lookup, nothing cached, and the caller gets the error. `Unsupported` is a structural answer (the directory cannot be asked), so it keys as its own marker, never equal to any answer. `family_roster_signers` is asked only when the family read returned a family, since it names an unknown family `InvalidArgument`. The remaining `unwrap_or_default` calls in the function are serialization, and its remaining `Unsupported` mappings mirror what the verdict path itself does for the same read.

**Witnesses (I190 f1, every backend).** The fault double now hands out the inner backend's standing cache (generator `DELEGATED_DEFAULTS`), so a verdict read through the double meets the cache while every key input still goes through the double's fault table.

- (f1_a) The canonical row is Rooted over an empty family plane and cached; a clean double hits the cache. With each of the four family reads failing, the read returns the error, and nothing is computed or served.
- (f1_b) With no accord family stored, the planted row reads NotRooted and is cached. With `lookup_family` failing, the read returns the error, not the cached NotRooted.
- (f1_c) A shape-refused squat is judged NotRooted before any family fold, so it is cached while the widenings read answers `Unsupported`. With the same read failing, the read returns the error, not that cached verdict.

**Mutants.** Lane: the brief's (`i190 | canonical | rc5 | infrastructure | replicated_community | delegation | topology | depth`) under `scripts/pg_test_db.sh`, every run with a database, none OOM-killed, each reverted with `git checkout --`.

| # | Mutant | Failed | Killed by |
|---|---|---|---|
| M1a | the widenings read swallowed (`unwrap_or_default`) | 3 | (f1_a) ×3 |
| M1b | the revocations read swallowed | 3 | (f1_a) ×3 |
| M1c | the family read swallowed (`.ok().flatten()`, the line as shipped at 6a81b01b) | 3 | (f1_b) ×3. Survived (f1_a) alone: with the family present, the failed read keys differently and the verdict's own read errors. |
| M1d | the roster-signers read swallowed | 3 | (f1_a) ×3: the seeded family's genuine signers answer equals the empty default |
| M1e | every error keyed as the `Unsupported` marker | 3 | (f1_c) ×3. Survived (f1_a) and (f1_b): the marker misses an answered key. |

## 10. #924 — the dimension grammar is manifest data (CC 1.0-rc5, released at c60d0a6)

**Why in this cut.** CIRISConstitution#112 (operator decision 2026-09-26) makes parsing and casing one rule across CC and every consumer, carried as data in the registry, and rides the wire break on the domain-label version. Persist ran four dimension matchers that disagreed with CC and with each other; v50.0.0 is the MAJOR that can absorb it.

**Inputs, vendored byte-for-byte** from CIRISConstitution commit `c60d0a6a0dfd3a0f2f2c3970b4148bf5b8777b3f` ("Cut CC 1.0-rc5, released as guidance (#125)" on `main`; the `v1.0-rc5` tag names this commit; `origin/main` at `3a2eaea` changed only the CHANGELOG since, so its manifests are byte-identical). Read with `git show`, never checked out:
`manifests/namespace_registry.json` → `src/federation/namespace/namespace_registry.json` (148 families, `_meta.registry_sha256 = 07e0c72538f3dd42451cac0c5f2529eed37bea3e8996640de2749aabb960b7fb`, `source_sha256 = 4f675532029663469f9c67694fb68d5d13742deb701d8337f1929ae8f6b7a907`) and `manifests/namespace_match_vectors.json` → `…/namespace_match_vectors.json` (962 vectors). CC ships no supersets file; `namespace_supersets.json` is not re-vendored by this slice. `namespace_match_binds.json` is persist-generated from the same commit (below). JSON has no comments, so the "header" is `registry.rs`'s `VENDORED_CC_COMMIT` / `VENDORED_REGISTRY_SHA256` doc. `vendored_registry_sha256_pins_the_cc_file` recomputes the grammar hash over the vendored bytes exactly as `tools/build_cc_namespace.py` does (Python `json.dumps(sort_keys, compact, ensure_ascii)` over `_meta` minus the two hashes plus `families`). `ACCORD_HEARTBEAT_DIMENSION` stays `accord:lifecycle:v1` (it resolves to the `accord:lifecycle` leaf).

**Re-vendor history.** The slice first vendored PR #113's unmerged head `4b624513458f2c9b236caf289dc2cd62aa048c24` (145 families, `registry_sha256 d6c87945…`, `source_sha256 f0568251…`, 785 vectors). CC then released rc5 from `main` with three more families, a closed `consent:{kind}`, full-match semantics and a moved reference matcher (§10.7). The released files replaced the pre-release ones byte-for-byte; nothing below describes the pre-release cut except where it says so.

### 10.1 Four matchers to one

| Site (v49) | What it did | v50 |
|---|---|---|
| `load_bearing::prefix_match_score` | arity-exact literal scoring over the SUPERSETS families | **deleted**; `family_for_dimension` = `match_family` → the registry family, then NAMED in the supersets vocabulary (identical key, else the `stem:*` it sits under; open vocabulary only to a supersets stem the registry registers nothing under). A refused dimension resolves to no family (Unknown = load-bearing; not retainable). |
| `registry::lookup` | longest literal prefix (`match_prefix`) | `match_family(...).family` → its entry, attributed even when refused. `match_prefix` is data only. |
| `registry::is_family_registered` | first-colon stem membership | family resolved and not `namespace_family_unregistered`; the stem question is the new `is_stem_registered`. |
| `consent_grammar::covers` | raw `starts_with` | grant prefix `starts_with` AND `match_family` refuses nothing (the prefix half stays byte-exact: it is the signed grant's own scoping string under `CONSENT_GRAMMAR_HASH`, which does not move). |
| `admission::contains_version_segment` (`:vN` anywhere), `schema_resolver::is_version_segment` (`^v[0-9]+$`), the ledger gate's `strip_prefix('v')` | three version parsers | **one**: `matcher::is_version_segment` / `trailing_version` / `is_version_exempt`, read from `_meta.case_rule.version_segment` (`pattern`, trailing, `required`, `exempt`). `is_attestation_ladder_dimension` and the canonical-binding probe in Layer 2b are deleted — the exempt list replaces both. |

`namespace::matcher::match_family(dimension) -> FamilyMatch { family, binds, refusal }` is a port of `tools/cc_namespace_match.py`: segments byte-exact, version tail stripped unless the family ends `{version}`, closed enumerations → `namespace_vocab_value_unregistered`, closed leaves and reserved stems → `namespace_family_unregistered`, a malformed form of a registered family (case-folded stem, uppercase/duplicated tail) → `namespace_dimension_case_malformed`, `multi` placeholders, variadic `*`, `external_standards`, Private Use. Every token is read from the manifest.

**Replay.** `namespace_match_vectors_replay` checks all 962 vectors two ways: CC's contract (family and refusal exact; the released vectors name exactly what the reference answers, CIRISConstitution#116 — the pre-release contract's "best-effort attribution" on case_malformed is gone), and the reference's own exact `(family, binds, refusal)` from `namespace_match_binds.json`, generated by `scripts/gen_namespace_match_binds.py <CC repo> c60d0a6` (runs the reference tool from the pinned commit over the vendored files, refuses unless both are byte-identical to CC's and every vector's family and refusal equal the reference's; `--check` re-verifies). The vectors carry no binds, which is why the second leg exists. `every_family_sample_round_trips_to_itself` replays the generator's own round-trip gate, skipping closed families (a wildcard, or a vocab-ended parent closed in its leaves) as the reference does. `reference_edges_beyond_the_vectors` pins eight reference answers no vector reaches (§10.7).

**Full match (`_meta.case_rule.match_semantics`).** `matcher::compile` wraps every manifest pattern as `^(?:p)$`, so an unanchored pattern cannot partial-match and a `$` never admits a trailing newline (`compile_is_a_full_match`). The manifest's declaration is asserted present and starting `full-match` (`the_manifest_declares_full_match_semantics`, and the registry drift gate). The reference's two hard-coded detectors (`VERSION_LIKE`, `VERSION_ATTEMPT`) are applied with Python `re.match` there, whose `$` tolerates one trailing newline; the port compiles them verbatim with `\n?\z` so a detector refuses exactly what the reference's does.

**The gates.** `check_dimension_case_rule` refuses the matcher's `case_malformed` and `vocab_value_unregistered` (so variadic tails are case-checked: `variadic_tail_segments_are_case_checked`). R2(b) (`check_namespace_family_registered`) refuses the matcher's `family_unregistered` in addition to persist's governed-but-rowless stems. Layer 2b refuses `missing_version_segment` unless the resolved family is exempt.

### 10.2 What moved (findings the re-vendor surfaced)

- **Families.** 116 → 145 at the pre-release cut (148 released, §10.7): 30 added (the six `accord:*` leaves, eight `consent:*` rows, media wildcards, `event:*`, `identity:canonical_binding:{canonical_hash}`, `topical_relation:{kind}`, …); `age_self_declared:{band}:{version}` retired → `age_self_declared:band:{band}:{version}` (moved to `RETIRED_FAMILIES`, as CC's generator lists it). `licensure:{authority_id}` is now `reserved: false` (CC ruling; persist already treated it open since v42 — its delegated-license-chain rule joins `RULES_NOT_ON_THE_ROW`). `session:{kind}` carries `occurrence-self-report` (CC 3.1.3.1).
- **Reserved stems close their leaves.** `detection:emergent_pattern:novel_signal:v1` and `accord:invoke:halt` were "open vocabulary inside a registered family" in v49's tests; CC now refuses both. The detector admit witness moved to a registered leaf.
- **`capacity:` / `detection:` rule pins retired** — CC's `reserved_stems` states them at the family (the CIRISConstitution#67 ask); `authority_for` answers a `kind: reserved` stem's rule for an unclaimed leaf rather than dropping the reservation.
- **Canonical binding (wire break).** CC: `identity:canonical_binding:{canonical_hash}`, one 64-lowercase-hex segment, version-exempt. Persist's fixtures bound the key-id spelling (`…:canonical:sha256:<hex>`, five segments), which now matches no row and fails T3. `parse_canonical_binding_hash` resolves through the matcher; the hash is re-spelled `canonical:sha256:<hex>` where it meets `subject_key_ids`.
- **Accord.** `accord:invoke:CONSTITUTIONAL:halt_id_42:v1` → `accord:invoke:constitutional:halt_id_42:v1`; `accord_invoke_old_uppercase_shape_fails_loudly` witnesses the old spelling refused `case_malformed` at the matcher and the case gate. Persist holds no `ciris.accord_invoke` canonical bytes (verify-core signs; the v17.1.0 pin still carries `.v1` / `CONSTITUTIONAL`), so the signature-level "old signature fails" witness is verify's.
- **Hardware.** `HardwareTypePlatform::as_platform` (exhaustive over the 13 keyring variants) equals the registry's closed `{platform}` set both ways (`hardware_type_platforms_equal_registry_values_107`); `hardware_class_multiplier` is CC 4.2.2's table, unlisted ⇒ 0.0; `hardware_class` stays a JSON property.
- **Minors (CC 5.4.6 / #111).** `check_minor_owner_binding_not_announced`: an owner-purpose `delegates_to` at `cohort_scope: federation` whose granter resolves `minor` refuses `WriteScopeRefused(MinorOwnerBindingAtFederation)` (`scope_minor_owner_binding_at_federation`), at every backend's put door and in the promotion stack. Invariant `exercise_minor_owner_binding_is_not_announced` beside `exercise_node_speaks_for_owner`, on memory/sqlite/postgres.
- **Polarity census.** The five `+1.0 only` accord leaves map to `[1.0, 1.0]` and join `PINNING_FAMILIES` (the contrast was 134 / 8 of 145 at the pre-release cut; 136 / 8 of 148 released, §10.7).
- **Manifest readers.** `every_manifest_family_column_has_a_reader_724` now accounts `_meta`, `_meta.case_rule`, `version_segment` and the per-segment keys; `reserved_prefix_rules_match_manifest_leaves` holds every hand-spelled reserved-rule prefix to a literal leaf of a vendored family or a CC reserved stem.
- `regex` is a direct, non-optional dependency (already in every build via `jsonschema`).

### 10.3 Deviations

1. **CC gap closed: the capacity companions are rows.** The pre-release rc5 registered no row for the CC 3.4.12 companions, and `CC_TEXT_LEAVES_WITHOUT_ROWS` stood R2(b) aside for their two prefixes behind a build-failing sentinel. The released rc5 registers `capacity_assurance:reversible_excluded:{domain}:{version}` and `…:reversible_pending:{domain}:{version}` (CIRISConstitution#117). The sentinel fired for the right reason (the rows resolve), and the carve-out is deleted. `capacity::reversible::parse_companion` now reads the one matcher (the row, no refusal) instead of hand-checking the grammar. R2(b) keeps refusing whatever the matcher rejects under a companion prefix, because companions ride `attestation_type`, which the case gate (envelope dimension only) never reads. Witness: `capacity_companions_resolve_to_their_cc_rows_117`.
2. **Evidence decimals.** Rows are keyed on CC's staged claim ids and THEIR decimals (`CLM-version-segment-suffix` 3.1.7, `CLM-reserved-leaves-closed` 3.4.1, `CLM-accord-invoke-lowercase` 4.2.1.1, `CLM-hardware-custody-vocabulary` 3.1.2, `CLM-minor-no-federation-binding` 5.4.6), not the 3.1.1 / 3.1.9 / 4.2.2 the brief listed. `CLM-device-roster-announced` is not claimed: persist does not implement the stranger-view `nodes_owned_by` projection.
3. **Edges no vector reaches.** The pre-release deviation "Rust `$` is stricter than Python `re.match`" is gone: the released reference uses `fullmatch` for every manifest pattern, so both refuse a trailing newline, and the port reproduces the detectors' `re.match` tolerance (§10.1). What remains: whitespace for the strip check is Unicode `White_Space` plus `\x1c`–`\x1f` (Python's `isspace`), and `str.lower()` / `to_lowercase()` agree on ASCII (every registered stem) but not on every non-ASCII code point, which only moves a DETECTION of a case-mutated stem.
4. **The ledger version** uses the one parser to recognise the segment, then still requires an integer (`v1.2` refuses): CC 3.3.10.1's id derivation keys on the version number.
5. **`registry::case_rule()` is deleted** (and the hand-implemented vocab-pattern test with it): the matcher compiles the manifest's patterns directly.

### 10.4 Adopter note (wire breaks — what a consumer must change)

- Dimensions are judged by the CC grammar at the door: an unversioned registered dimension (`capacity:composite`) fails T3; a version-shaped segment anywhere but last is no longer the version; `usd` for `{currency}` is malformed (`USD`); closed vocabularies refuse unlisted values (`hardware_custody:tpm:v1`); unnamed leaves under `accord:*` and unclaimed leaves under CC's reserved stems (`accord:`, `detection:`, `capacity:`, `age_assurance:`, `capacity_assurance:`, `transparency_log:cosigned:`, `age_self_declared:`) are `namespace_family_unregistered`.
- Emit `accord:invoke:{constitutional|notify|drill}:{id}:v1` (lowercase, with the id); sign invocations under `ciris.accord_invoke.v2` (verify-side).
- Emit `age_self_declared:band:{band}:v1`, `identity:canonical_binding:<64 hex>` (no `canonical:sha256:` inside the dimension), `hardware_custody:{snake_case HardwareType}:v1`.
- A minor's owner-binding must be held at `cohort_scope: self`. At `federation` it refuses `federation_write_scope_refused: scope_minor_owner_binding_at_federation`, and so does WIDENING it there (`widen_audience`'s `supersedes`, including the sweep's widening step and the pyo3 widen — review HIGH-1).
- **Follow-up, CIRISPersist#929 (minors × widening, peer side).** The gate recognises an announce by the widening's own body or by the prior it names. A receiving peer that does NOT hold the self-scope prior (usually: `self` is undiscoverable) can check only the body. If the prior is a purpose-only owner-binding (no `dimension`) and the widening stripped `delegation_purpose`, that peer would admit it. The origin's door refuses it, so the row needs a forgery written straight to a peer by the minor's own key.
- **Capacity companions are CC rows and carry the version tail** (CIRISConstitution#117, released rc5). Emit `capacity_assurance:reversible_excluded:{domain}:v1` / `capacity_assurance:reversible_pending:{domain}:v1`. Companions ride `attestation_type`, which T3 and the case gate (envelope dimension only) never read, so R2(b) (`check_namespace_family_registered`) is their only grammar gate, and its wire error is what an emitter sees:
  - the versionless v49 spelling: the matcher answers `missing_version_segment`, and R2(b) refuses `NamespaceFamilyUnregistered` with reason `family_unregistered`;
  - `…:Financial:v1`: the matcher answers `namespace_dimension_case_malformed`, and R2(b) refuses `InvalidArgument` carrying that token;
  - `…:a:b:c:v1` and `…:a:b:v1`: R2(b) refuses `NamespaceFamilyUnregistered` / `family_unregistered`. The matcher answers `namespace_dimension_case_malformed` for the first. For the second it answers `namespace_vocab_value_unregistered`: it used to be admitted as the rung row with `{level}` = `reversible_excluded`, but the released rc5 closes the rung row's `{level}` ∈ {provider, panel, government} and `{band}` ∈ {capacitated, incapacitated} (CLM-capacity-companion-rows: "neither reads as a level").
- **`consent:{kind}` is closed in its leaves (wire break).** The released rc5 lists ten consent leaves (`consent:community_trust`, `decay:{stage}`, `deletion_complete`, `deletion_sla:{days}`, `partnership_accept`, `partnership_grant`, `replication:{version}`, `scope:{kind}`, `state:{stance}`, `stream:{kind}`) and closes the parent. An unlisted kind that the open `{kind}` admitted before (`consent:made_up:v1`) now refuses `namespace_family_unregistered` at R2(b), and so does any unmatched descendant under `consent:` (`consent:totally:new:v1`). No consent grant covers either. CIRISAgent's live trace-capture grant `consent:community_trust:v1` keeps admitting, now on its own row (`consent_community_trust_admits_under_the_closed_consent_leaves`). Every consent spelling persist itself emits is a listed leaf.
- **Open vocabulary owes its version tail (wire change).** A dimension no row claims is still judged by R3's global version grammar: `no_such_family:leaf` refuses `missing_version_segment` (the manifest token, and persist's wire reason), `…:leaf:V1` / `…:leaf:v1beta` / `…:v1:v2` / a lone `v1` refuse `namespace_dimension_case_malformed`. A `v1beta` in last place on a registered family is malformed too.
- **Canonical BCP 47 locales.** `provenance:build_manifest:{target}:locale:{lang_code}` now takes canonical-cased RFC 5646 without extlang. Refused now (`case_malformed`): `en-us`, `EN`, `zh-hans-cn`, `zh-cmn-Hans-CN`, `sgn-BE-FR`. Admitted now: private use (`x-private`) and the five grandfathered tags without a preferred value (`i-default`, `i-enochian`, `i-mingo`, `cel-gaulish`, `zh-min`). `en-US` is unchanged (`provenance_locale_is_canonical_bcp47`).
- **CIRISVerify emits three `hardware_custody` dimensions v50 refuses** (no persist legacy arm; rc5 says refuse; the verify checklist item is filed by the release lead):
  | emitted today | refusal | emit instead |
  |---|---|---|
  | `hardware_custody:android` | `namespace_vocab_value_unregistered` (and no version tail) | `hardware_custody:android_keystore:v1` or `hardware_custody:android_strongbox:v1`, per the `HardwareType` the chain proves |
  | `hardware_custody:ios_secure_enclave` | `missing_version_segment` (token is legal) | `hardware_custody:ios_secure_enclave:v1` |
  | `hardware_custody:tpm` | `namespace_vocab_value_unregistered` (and no version tail) | `hardware_custody:tpm_discrete:v1` or `hardware_custody:tpm_firmware:v1` |
- **Stored rows are judged by the same grammar, and every consequence NARROWS (never widens).** A row stored before v50 on a pre-rc5 shape: (i) is covered by no consent grant (`covers` requires a refusal-free match), so `promote_consented_backlog` neither promotes nor widens it — it is now counted as `ConsentSweepReport::skipped_unmatched_dimension` with up to 8 `unmatched_dimension_examples` and a `warn` summary (review MEDIUM-3); (ii) resolves to no supersets family (`family_for_dimension` → None: `LoadBearing::Unknown`, treated as load-bearing; not subject-retainable); (iii) under `authority_for` resolves either to its family (attributed even when refused) or, off every row, to a reserved stem's rule or `ProducerSteward` — for an unrowed leaf under a non-reserved stem that is narrower than v49's literal-prefix attribution. None of these makes a row more visible, more transferable or more authoritative.
- **Canonical binding has no legacy arm** (review LOW-5, for the CHANGELOG wire-break list): a STORED `identity:canonical_binding:canonical:sha256:<hex>` row now parses to `None`, so `canonical_binding_hashes_for` drops it and the binding no longer widens its key's `withdraws` authority (rule 2). Fail-closed — authority is lost, never gained. No emitter of that shape was found outside persist's own tests; a holder re-emits `identity:canonical_binding:<64 hex>`.
- Rust API (clean break): `registry::case_rule` removed; `is_family_registered` is match-based (stems → `is_stem_registered`); `consent_grammar::covers` refuses malformed dimensions; `ScopeRefusalReason` gains `MinorOwnerBindingAtFederation`. Pin `VENDORED_REGISTRY_SHA256`. No hash outside the manifest moved (`REPLICATION_POLICY_HASH`, `CONSENT_GRAMMAR_HASH`, `ENVELOPE_VOCABULARY_SHA256`, capsule digests unchanged).

### 10.5 Mutation table (#924)

Lane (`--features sqlite,postgres --lib` under `scripts/pg_test_db.sh`, `-j 3`): the brief's filter `test(namespace) | test(matcher) | test(vector) | test(version_segment) | test(case_malformed) | test(hardware_type) | test(minor) | test(accord_invoke) | test(manifest)` widened with `test(variadic) | test(case_rule) | test(r2b) | test(covers) | test(dimension_resolves) | test(reserved_prefix) | test(canonical_binding) | test(retainab)` (the brief's filter matches none of the case-gate tests by name). Baseline 207/207 passed on 529aec0d; 209/209 after the three witnesses the round forced. Each mutant was applied to a committed tree and reverted before the next. No mutant was OOM-killed.

| # | Mutant | Result | Killed by |
|---|---|---|---|
| M1 | version tail KEPT on a `{version}`-less family | KILLED (16) | case-gate ×2, r2b, variadic, covers, hardware vocab, dimension_resolves, replay, … |
| M2 | closed leaf admitted | KILLED (5) | replay, accord_invoke, r2b, covers, is_family_registered |
| M3 | closed-vocabulary value admitted | KILLED (3) | replay, variadic (hardware_custody:tpm), hardware vocab |
| M4 | reserved stem admitted | KILLED (2) | replay, r2b |
| M5 | `version_segment.exempt` dropped | KILLED (6) | replay, version_segment ×2, canonical_binding_widens ×3 backends |
| M6 | variadic tail uncased | KILLED (3) | replay, variadic, accord_invoke |
| M7 | old longest-literal-prefix `lookup` reinstated | **SURVIVED**, then KILLED (1) after `lookup_resolves_through_the_one_matcher_924` | that test |
| M8 | `as_platform` off by one token (`yubihsm`) | KILLED (2) | hardware vocab, class mapping |
| M9 | minors refusal dropped | KILLED (3) | `minor_owner_binding_at_federation_is_refused_q5` ×3 backends |
| M10 | replay compares FAMILY only (both legs) + vocab refusal spelled case_malformed | KILLED (1) | variadic (token assertion) — the weakened replay alone would not have |
| M11 | case gate stops refusing `vocab_value_unregistered` | KILLED (1) | variadic |
| M12 | `covers` without the grammar check | KILLED (1) | `covers_refuses_what_the_grammar_refuses_924` |
| M13 | `family_for_dimension` ignores refusals | KILLED (1) | dimension_resolves |
| M14 | `trailing_version` accepts a version anywhere (the v49 scan) | KILLED (2) | version_segment ×2 |
| M15 | canonical-binding parse accepts any suffix | **SURVIVED**, then KILLED (1) after `canonical_binding_parse_goes_through_the_matcher_924` | that test |
| M16 | minors gate removed from the PROMOTION stack only | **SURVIVED**, then KILLED (3) after the invariant asked `check_promotion_admission` | minors ×3 backends |
| M17 | `authority_for` reserved-stem fallback removed | KILLED (1) | lookup_resolves |

17/17 killed on the final tree; three needed a witness written first.

**Review round (HIGH-1, MEDIUM-3) on 86440f47**, lane above plus `test(grammar_refuses)`, baseline 210/210:

| # | Mutant | Result | Killed by |
|---|---|---|---|
| M18 | minors gate skips SUPERSEDES (a widening is not re-checked) | KILLED (3) | `minor_owner_binding_at_federation_is_refused_q5` ×3 backends (the widening leg) |
| M19 | sweep's stranded-dimension accounting dropped | KILLED (1) | `sweep_counts_grant_covered_rows_the_grammar_refuses_924` |
| M9 (re-run) | minors refusal dropped | KILLED (3) | minors ×3 |
| M12 (re-run) | `covers` without the grammar check | KILLED (2) | covers test, the sweep witness |
| M16 (re-run) | minors gate removed from the promotion stack | KILLED (3) | minors ×3 |

**Review closure on ed13d7e5** (lane plus `test(cc_text_leaves) | test(capacity)`; baseline included in the mutant's 237):

| # | Mutant | Result | Killed by |
|---|---|---|---|
| M20 | companion carve-out ignores `parse_companion` (a malformed shape under the prefix is excused) | KILLED (1) | `cc_text_leaves_without_rows_are_still_rowless` |

(M20 measured a carve-out the released re-vendor deleted; M32 in §10.7 is its successor.)

### 10.6 For adopters at the tag (computed from the vendored files)

**Constants.** `VENDORED_N_FAMILIES` 116 → **148**. `VENDORED_CC_VERSION` stays `1.0-rc5`. `VENDORED_SOURCE_SHA256` `87aede50…b9a9f5` → `4f675532029663469f9c67694fb68d5d13742deb701d8337f1929ae8f6b7a907`. New: `VENDORED_REGISTRY_SHA256 = 07e0c72538f3dd42451cac0c5f2529eed37bea3e8996640de2749aabb960b7fb`, `VENDORED_CC_COMMIT = c60d0a6a0dfd3a0f2f2c3970b4148bf5b8777b3f`. (The pre-release slice pinned 145 / `f0568251…` / `d6c87945…` / `4b624513…`; none of those shipped.) `supersets::VENDORED_MANIFEST_VERSION` stays **`0.3.0`**: it versions the supersets walk (`namespace_supersets.json`), which this cut did not re-vendor. Its seed pin (`VENDORED_SEED_REGISTRY_SHA256`) still names the rc2 registry, and that lag is declared.

**Field-processor matrix and transform algebra: no shape change.** `TRANSFORM_ALGEBRA_HASH` is `b7bd779468f4ad1ab551a5fd2dc0392df01e6f2e0ed393f924a806ed49686b4b` at `ea14c27f` and at the tag. `transform_algebra_hash_is_pinned` recomputes it and passed in both full lanes on `6c731b25`: `pyo3,sqlite` started 2026-09-27 01:00:04 CDT (3432 passed) and `postgres,sqlite` started 01:09:08 CDT (3362 passed). `transform.rs` and `namespace_supersets.json` are byte-unchanged in this cut, so no processor kind or transform op was added, removed or re-typed. The only change in `supersets.rs` is a `DELETED_PENDING_REVENDOR` entry for the deleted `is_attestation_ladder_dimension` citation. The registry itself carries no processor column.

**Family diff, v49 → the pre-release cut** (`python3 scripts/manifest_diff.py ea14c27f d10c56b8`; committed so the next re-vendor reruns it). The released cut adds §10.7's diff on top: 148 families at the tag.

- **(a) Added: 30** (net +29). `accord:human_dignity`, `accord:invoke:constitutional:{halt_id}`, `accord:invoke:drill:{drill_id}`, `accord:invoke:notify:{notify_id}`, `accord:lifecycle`, `accord:lifecycle:active`, `age_self_declared:band:{band}:{version}`, `audio:*`, `blog:*`, `chat:*`, `consent:decay:{stage}`, `consent:deletion_complete`, `consent:deletion_sla:{days}`, `consent:partnership_accept`, `consent:partnership_grant`, `consent:replication:{version}`, `consent:scope:{kind}`, `consent:state:{stance}`, `consent:stream:{kind}`, `encyclopedia:*`, `event:attendance`, `event:lifecycle:{state}`, `event:rsvp_count`, `film:*`, `identity:canonical_binding:{canonical_hash}`, `image:*`, `model_3d:*`, `news:*`, `topical_relation:{kind}`, `video:*`.
- **(b) Removed or renamed: 1.** `age_self_declared:{band}:{version}` was renamed to `age_self_declared:band:{band}:{version}`. CC's generator lists it in `RETIRED_FAMILIES`, and persist's `RETIRED_FAMILIES` does too.
- **(c) Existing families that changed: 23.**
  - **Variadic wildcards:** `variadic: true` added on the `*` segment of `accord:*`, `dma:csdma:*`, `dma:dsdma:{domain}:*`, `dma:idma:*`, `dma:pdma:*` and `system:*`.
  - **Leaves:** the same six families gained `leaves` / `leaves_closed`. Only `accord:*` is closed, with the six leaves above. The dma and system families carry `[]` / `false`.
  - **Closed enumerations:** `age_assurance:{level}:{band}:{version}` `{level}` ∈ {provider, government} and `{band}` ∈ {minor, adult, under_13, 13_15, 16_17}; `hardware_custody:{platform}` ∈ the 13 `HardwareType` tokens.
  - **Open enumerations** (canonical values only):
    - `benchmark:he300:…` `{version}` {v1.0, v1.1, v1.2}
    - `detection:distributive:access:{resource_type}` {compute}
    - `fidelity:explainability_sla:{tier}` {l1_summary, l2_reasoning_trace, l3_full_dma_chain, l4_attested_chain}
    - `goal:{scale}` {self}
    - `locality:decision:{scale}` {local, regional, national, federation}
    - `moderation:{allegation_type}` {rogue_vote}
    - `multilateral_participation:{forum}:{kind}` {membership, voting, proposal_filing, observer_status}
    - `regime:{artifact}:{version}` {manifest}
  - **Patterns and standards:**
    - `bond_posted:{currency}` `^[A-Z]{3}$` (ISO 4217)
    - `provenance:build_manifest:{target}:locale:{lang_code}` (BCP 47 pattern)
    - `transparency_log:cosigned:{tree_size}` `^[0-9]+$`
    - `content_rating:{scheme}:{rating}` (standard named, no pattern)
  - **`multi` placeholders:** `detection:correlated_action:{axis}`, `provenance:skill_import:{source}`.
  - **Reserved rules:** `licensure:{authority_id}` went `reserved: true` (co-stewarded, CC 3.4.9) → `false`, with no rule. `session:{kind}`'s rule went `substrate-self-report` (CC 3.4.3) → `occurrence-self-report` (CC 3.1.3.1).
  - **Prose only** (on top of the grammar changes above): `age_assurance`, `benchmark:he300` and `hardware_custody` descriptions.
- **(d) `_meta.case_rule` gained** `external_standards`, `refusal_tokens`, `reserved_stems`, `version_segment` and `wildcard_rule`; `classes` and `placeholder_classes` changed. `reserved_stems` has six stems of `kind: reserved` (`accord:`, `transparency_log:cosigned:`, `detection:`, `capacity:`, `age_assurance:`, `capacity_assurance:`) and one of `kind: gated` (`age_self_declared:`). `version_segment` is: pattern `^v[0-9]+(\.[0-9]+)*$`, trailing, required, and exempt for the five attestation-ladder families plus `identity:canonical_binding:{canonical_hash}`. `_meta` also gained `registry_sha256`, and `n_families` / `per_component` moved.

### 10.7 The released rc5 re-vendor (4b624513 → c60d0a6)

**Family diff** (`python3 scripts/manifest_diff.py d10c56b8 <tag>`): 145 → 148, net +3.

- **(a) Added: 3.** `capacity_assurance:reversible_excluded:{domain}:{version}`, `capacity_assurance:reversible_pending:{domain}:{version}` (both `signed`, reserved, CC 3.4.12 "witness-reserved, subject-not-self, attester != steward", owner CIRISVerify/attestation), `consent:community_trust` (`positive-only`, reserved CC 3.4.5, owner CIRISAgent/accord-agent).
- **(b) Removed: 0.**
- **(c) Changed: 4.** `capacity_assurance:{level}:{domain}:{band}:{version}` closes `{level}` ∈ {provider, panel, government} and `{band}` ∈ {capacitated, incapacitated}. `consent:{kind}` gains the ten `leaves` and `leaves_closed: true`. `delivery_receipt:{stream_id}`'s rule moves from "substrate-self-report" (CC 3.4.3) to "subscriber-only (attesting_key_id is a current subscriber/member of the named stream; not a substrate self-report)" (CC 3.4.6); persist keys no gate on that rule text, `authority_for` reports it, and persist's receipts already verify the subscriber's signature. `provenance:build_manifest:{target}:locale:{lang_code}`'s pattern becomes canonical-cased RFC 5646 (§10.4).
- **(d) `_meta`.** `case_rule.match_semantics` added ("full-match: … a `$` anchor does not admit a trailing newline (CIRISConstitution#116)"); `case_rule.external_standards.lang_code` rewritten; `n_families` 145 → 148; `per_component` `accord-agent` 28 → 29, `attestation` 19 → 21.
- **Vectors:** 785 → 962. The contract is now exact on the family (#116).

**The reference matcher moved too, and the port moved with it** (`tools/cc_namespace_match.py`, 4b624513 → c60d0a6): every pattern `fullmatch`; `closed_stems` (a closed wildcard's prefix, or a closed vocab parent's first segment) fence unmatched descendants as reserved stems do; a closed parameterized parent (`consent:{kind}`) admits only its leaves; `VERSION_ATTEMPT` (`v1beta`, `V1x`) in last place is malformed, in `_resolve` (any absorbing class), the variadic tail and malformed detection; open vocabulary owes its version tail and refuses a duplicated tail or a lone version; a case-mutated fenced stem is malformed; a refused hit is re-attributed to the clean row it mutates (`detect_malformed(clean_only)`); a `multi` value's components take no version-shape test. All 962 vectors replayed on the first port; `reference_edges_beyond_the_vectors` pins eight further reference answers.

**What each hash pins (checked at the tag).** No discrepancy at `v1.0-rc5`, so there is no erratum to record. The tag's recipe is in `tools/build_cc_namespace.py`.
- `_meta.registry_sha256` (`07e0c725…60b7fb`) is not a file hash. It is SHA-256 over `json.dumps({"_meta": _meta minus source_sha256 and registry_sha256, "families": …}, sort_keys, compact, ensure_ascii)`. `vendored_registry_sha256_pins_the_cc_file` recomputes exactly that over the vendored bytes and holds it equal to both the meta value and `VENDORED_REGISTRY_SHA256`.
- `_meta.source_sha256` (`4f675532…a907`) equals the SHA-256 of `constitution/part_3_the_namespace.md` at c60d0a6, recomputed here. `VENDORED_SOURCE_SHA256` pins it.
- The whole-file byte hash is `17ba3ad7916c16dbf25cf24bd1b24a2890fc534ba0b18f8c3f21b99339e13a3a`. No constant pins it. Byte identity with the tag is checked by `scripts/gen_namespace_match_binds.py … --check`, which needs the CC checkout.
- CC has announced a post-tag "registry-hash fix". Persist vendors the TAG bytes and does not follow `main`. If CC re-tags with a different recipe, the recomputation test fails on re-vendor, and the recipe moves with the bytes.

**Unchanged.** `VENDORED_CC_VERSION` (`1.0-rc5`), `supersets::VENDORED_MANIFEST_VERSION` (`0.3.0`) and `TRANSFORM_ALGEBRA_HASH` (`b7bd7794…`): `namespace_supersets.json` and `transform.rs` are byte-unchanged, so the supersets walk did not move. `CONSENT_GRAMMAR_HASH`, `REPLICATION_POLICY_HASH`, `ENVELOPE_VOCABULARY_SHA256` and capsule digests are unchanged.

**Measured contrast.** `retaining_the_contradiction_count_pins_almost_the_whole_registry`: 136 / 8 of 148 (was 134 / 8 of 145). The two `signed` companions join the retained side. `consent:community_trust` is `positive-only`, like its sibling consent leaves, and pins on neither.

**Evidence.** `evidence/cc_impl.tsv` gains four rows for two claims CC stages on CIRISPersist#924 at c60d0a6: `CLM-capacity-companion-rows` (3.4.12: `capacity.rs#parse_companion`, `admission.rs#check_namespace_family_registered`) and `CLM-match-full-semantics` (3.1.7: `matcher.rs#compile`, `matcher.rs#match_family`). The exact-count gate moves 90 → 94. `CLM-consent-community-trust` (3.3.1) is staged on CIRISPersist#935 and claims the fold (owner-or-node emitter, positive-only, withdraws is a hard stop); this slice only admits the leaf, so it adds no row for it.

**Mutation round** on 83c4a5c5. Lane: `scripts/pg_test_db.sh -- cargo nextest run -j 3 --features sqlite,postgres --lib --no-fail-fast -E 'test(namespace) | test(matcher) | test(vector) | test(consent_grammar) | test(case_rule) | test(capacity)'`. Baseline 203/203 passed. Each mutant was applied to the committed tree and reverted with `git checkout -- .` before the next. No mutant was OOM-killed.

| # | Mutant | Result | Killed by |
|---|---|---|---|
| M21 | `compile` drops the `^(?:p)$` anchor | KILLED (1) | `compile_is_a_full_match` (the manifest's own patterns carry anchors, so only the unanchored probe sees it) |
| M22 | the manifest's `match_semantics` key removed | KILLED (4) | `the_manifest_declares_full_match_semantics`, registry drift gate, column accounting (stale pin), `vendored_registry_sha256_pins_the_cc_file` |
| M23 | closed-leaf check wildcard-only again (consent leaves reopened) | KILLED (3) | replay, `consent_community_trust_admits…`, `reference_edges_beyond_the_vectors` |
| M24 | `consent:community_trust` row removed from the registry | KILLED (42) | `consent_community_trust_admits…` (`(consent:{kind}, FamilyUnregistered)` instead of the row), replay, the registry count and sha gates, and every capacity/R2(b) store test that loads the registry |
| M25 | `VENDORED_REGISTRY_SHA256` stale (the pre-release `d6c87945…`) | KILLED (2) | `vendored_registry_sha256_pins_the_cc_file`, `vendored_vectors_name_the_vendored_grammar` |
| M26 | `parse_companion` admits a companion missing `{version}` | KILLED (1) | `capacity_companions_resolve_to_their_cc_rows_117` |
| M27 | closed-family stems no longer fence descendants | KILLED (2) | replay, `consent_community_trust_admits…` (`consent:totally:new:v1`) |
| M28 | open vocabulary no longer owes its version tail | KILLED (2) | replay, `reference_edges_beyond_the_vectors` |
| M29 | a refused hit is not re-attributed to the clean row it mutates | KILLED (1) | replay (the exact-family leg) |
| M30 | `VERSION_ATTEMPT` never matches | KILLED (2) | replay, `reference_edges_beyond_the_vectors` |
| M31 | the detectors lose Python `re.match`'s trailing-newline tolerance | KILLED (1) | `reference_edges_beyond_the_vectors` only; the 962 vectors alone would not have killed it, which is why that witness was written before the round |
| M32 | R2(b) stands aside for every companion shape (the carve-out, reborn) | KILLED (1) | `capacity_companions_resolve_to_their_cc_rows_117` |

12/12 killed on the final tree.

### 10.8 v51.0.0 — re-vendored at CIRISConstitution `651140a` (branch `rc6`; CIRISConstitution#129)

The ruling that registers Edge's `capacity:relay_delivery` (CC 3.1.4 edge-owned, CC 3.4.5 reserved: no-self-emit + `analyze` consent; never a factor of `capacity:composite`) landed on `rc6` at `651140a`. Persist pins `namespace_registry.json` + `namespace_match_vectors.json` at exactly that commit (byte-identical; `cmp`): 149 families, 968 vectors, `registry_sha256 c22dc0874b4c…`, `source_sha256 fbb6c32e…`, `cc_version 1.0-rc6`, `VENDORED_CC_COMMIT 651140a2…`. CC's reference matcher is unchanged since the rc5 tag (no port). **Recipe change:** CC's grammar hash (`tools/build_cc_namespace.py`) now excludes `cc_version` from the preimage ("a bump is not a grammar change"); persist's recomputation test follows it — the recipe moves with the bytes it hashes. `VENDORED_FAMILY_PREFIXES` gains the row. Witness: the replay asserts `capacity:relay_delivery:v1` admits, `:V1` case-malformed, the bare stem missing-version, `capacity:made_up:v1` unregistered. `rc6` is a branch: persist re-vendors the tag when rc6 is cut; until then the ruling's landing commit is the registry of record for this row (maintainer's sequence, CIRISEdge#702).

### 10.9 v51.0.0 — #929 (a widening never strips `delegation_purpose`)

| # | Mutant | Verdict | Killed by |
|---|---|---|---|
| P1 | delegation_purpose unprotected (the protected list shortened to 7, entry removed) | KILLED (rc=100) | engine::tests::a_widening_never_strips_the_delegation_purpose_marker |
