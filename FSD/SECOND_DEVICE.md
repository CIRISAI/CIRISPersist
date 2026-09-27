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
  - **Follow-up:** #873's principal resolver (`active_identities_for_occurrence`, used by the hold-side audience and write-side principal resolution) has the same unilateral-claim shape. It is left for a follow-up issue, not changed here.
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
- The shared scoped walk (`scoped_delegation_reach`) records `beyond_cap`; `reachable_under_scope_with_reasons` returns the new `ReachabilityVerdict::BeyondDepthCap` (pyo3 token `beyond_depth_cap`) before `NoTrustRoots` / `SignerUnreached`.
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
3. **Keyed on the label.** Both conformance gates fire on `cohort_subkind: infrastructure` whether or not the community is *authorized* (`is_authorized_infrastructure_community`). An unauthorized label gets the stricter treatment everywhere else, and a conformance rule that an unauthorized label could skip would be the weaker one.
4. **The widening door checks only the founder rule.** A widening is not a protocol change. A pre-gate stored infrastructure community with a non-`quorum:` protocol keeps admitting widenings under the protocol it stored. It is refused the next time its record is put or superseded.
5. **The fold judges node-bearing now, not at the event's instant.** Seats are resolved from the current key record and current active occurrences. A key that becomes node-bearing later (bound as an occurrence of a `node` identity) loses its vote in every replay. Roster events it alone admitted then stop standing, as the ruling's "drop such a seat" reads. `node_founder_seat_does_not_vote` exercises exactly that transition.
6. **Clause A runs on every door that writes `identity_type`** (corrected after review H3; the first cut ran it only at `put_public_key`). The doors are:
   - `put_public_key`: every mint and every replicated `Insert`.
   - `adopt_scrub_upgrade`: the replicated `Upgrade` arm, which CAN change `identity_type`.
   - `supersede_canonical_record`: the replicated `Supersede` arm.
   - `adopt_genesis_reanchor`.
   - `seed_genesis_accord_holders`.
   - The rebind door (`register::prepare_rebind`).

   It is not in `verify_key_registration`: every door above runs it. A pre-gate fused key is refused any rewrite of its record (it re-mints), and Clause B still gates it where it sits. The Clause B witnesses (`hybrid_node_agent_key_still_refuses_agency_773`, `node_agent_hybrid_carries_agency_admitted{,_sqlite}`, `pg_node_agency_duplicate_identity_type_token`) now plant their fused key below the door, because the door now refuses to mint it. The upgrade and supersede doors are witnessed by `clause_a_on_the_rewrite_doors_{sqlite,postgres}`.
7. **"Infrastructure family" is not representable.** A `Family` has no `cohort_subkind`, so #927's refusal is on communities. `family_quorum_over` gains no identity filter: #925 is scoped to `infrastructure` communities.
8. **The withdraws WRITE gate walks 5 hops. A stored row keeps the depth it was admitted under** (review H2, ruled: v49's "past actions validly decided stand").
   - **The write gate** (`check_withdraws_admission` → `resolve_withdraws_admission_rule`, which uses the new `_at` forms) takes the CC 4.1.1 default. A NEW withdraws over a 6-to-16-hop proxy chain is refused with `beyond_delegation_depth_cap: true`.
   - **Why the stored rule is not simply read.** The bytes-plane fold (`blob_tombstone::retiring_composer`) re-derives every stored withdraws at read time. It must: #853 ruled "re-derive, never read the stored rule", so a proxy edge withdrawn since stops the retirement.
   - **So it re-derives at the depth ceiling, `MAX_WITHDRAWS_DELEGATION_DEPTH` (16),** the walk every pre-v50 row was admitted under, not at the new default. A withdraws validly decided before v50 keeps retiring its bytes, and the attestation-plane fold keeps honouring the stored `withdraws_admission_rule` (arm 3) as before.
   - **Deviation from the literal ask.** The ruling says "honour the STORED admission rule/depth". No depth is stored per row, so the fold uses the ceiling that bounds every depth a stored row could have used. It keeps #853's liveness.
   - Witness: `withdraws_admitted_under_the_old_depth_still_retires` (memory, sqlite, postgres).
     - Its stored row is admitted by the deferred arm: its target is absent at admission, which is the read-time position of any pre-v50 row. It is not planted below the door with a rule recorded. The fold ignores the stored rule, so the two are equivalent for this fold.
     - It then shows a NEW 6-hop withdraws refused at admission.
   - **Mixed-fleet divergence (stated, until the fleet upgrades):** a v49 node admits a 6-to-16-hop withdraws that a v50 node refuses at its replicated door. The two nodes then disagree about that row until the v49 node upgrades. The v50 node never stores the row, so the bytes it withdraws stay live there. This belongs in the release note.
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
