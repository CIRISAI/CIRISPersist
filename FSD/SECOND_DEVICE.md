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

## 10. #924 — the dimension grammar is manifest data (CC rc5, PR #113 @ 4b624513)

**Why in this cut.** CIRISConstitution#112 (operator decision 2026-09-26) makes parsing and casing one rule across CC and every consumer, carried as data in the registry, and rides the wire break on the domain-label version. Persist ran four dimension matchers that disagreed with CC and with each other; v50.0.0 is the MAJOR that can absorb it.

**Inputs, vendored byte-for-byte** from CIRISConstitution commit `4b624513458f2c9b236caf289dc2cd62aa048c24` (branch `claude/backlog-integration-assignment-p3ydh0`, PR #113 — UNMERGED at vendor time; read with `git show`, never checked out):
`manifests/namespace_registry.json` → `src/federation/namespace/namespace_registry.json` (145 families, `_meta.registry_sha256 = d6c87945ea08d72cc1f83820e35f0e3fb72cce47ea49f2ed3321d43219642ea6`, `source_sha256 = f05682512c85c65c3f502e1ca81dfb032a6e6d24ab4206658fbf36ccaa702a75`) and `manifests/namespace_match_vectors.json` → `…/namespace_match_vectors.json` (785 vectors). JSON has no comments, so the "header" is `registry.rs`'s `VENDORED_CC_COMMIT` / `VENDORED_REGISTRY_SHA256` doc. `vendored_registry_sha256_pins_the_cc_file` recomputes the grammar hash over the vendored bytes exactly as `tools/build_cc_namespace.py` does (Python `json.dumps(sort_keys, compact, ensure_ascii)` over `_meta` minus the two hashes plus `families`). `ACCORD_HEARTBEAT_DIMENSION` stays `accord:lifecycle:v1` (it resolves to the `accord:lifecycle` leaf).

### 10.1 Four matchers to one

| Site (v49) | What it did | v50 |
|---|---|---|
| `load_bearing::prefix_match_score` | arity-exact literal scoring over the SUPERSETS families | **deleted**; `family_for_dimension` = `match_family` → the registry family, then NAMED in the supersets vocabulary (identical key, else the `stem:*` it sits under; open vocabulary only to a supersets stem the registry registers nothing under). A refused dimension resolves to no family (Unknown = load-bearing; not retainable). |
| `registry::lookup` | longest literal prefix (`match_prefix`) | `match_family(...).family` → its entry, attributed even when refused. `match_prefix` is data only. |
| `registry::is_family_registered` | first-colon stem membership | family resolved and not `namespace_family_unregistered`; the stem question is the new `is_stem_registered`. |
| `consent_grammar::covers` | raw `starts_with` | grant prefix `starts_with` AND `match_family` refuses nothing (the prefix half stays byte-exact: it is the signed grant's own scoping string under `CONSENT_GRAMMAR_HASH`, which does not move). |
| `admission::contains_version_segment` (`:vN` anywhere), `schema_resolver::is_version_segment` (`^v[0-9]+$`), the ledger gate's `strip_prefix('v')` | three version parsers | **one**: `matcher::is_version_segment` / `trailing_version` / `is_version_exempt`, read from `_meta.case_rule.version_segment` (`pattern`, trailing, `required`, `exempt`). `is_attestation_ladder_dimension` and the canonical-binding probe in Layer 2b are deleted — the exempt list replaces both. |

`namespace::matcher::match_family(dimension) -> FamilyMatch { family, binds, refusal }` is a port of `tools/cc_namespace_match.py`: segments byte-exact, version tail stripped unless the family ends `{version}`, closed enumerations → `namespace_vocab_value_unregistered`, closed leaves and reserved stems → `namespace_family_unregistered`, a malformed form of a registered family (case-folded stem, uppercase/duplicated tail) → `namespace_dimension_case_malformed`, `multi` placeholders, variadic `*`, `external_standards`, Private Use. Every token is read from the manifest.

**Replay.** `namespace_match_vectors_replay` checks all 785 vectors two ways: CC's contract (refusal exact; family exact except "best-effort attribution" on case_malformed), and the reference's own exact `(family, binds, refusal)` from `namespace_match_binds.json`, generated by `scripts/gen_namespace_match_binds.py <CC repo> 4b624513` (runs the reference tool from the pinned commit over the vendored files, refuses unless both are byte-identical to CC's; `--check` re-verifies). The reference itself names a different family than the published vector on 12 case_malformed vectors, which is why the second leg exists. `every_family_sample_round_trips_to_itself` replays the generator's own round-trip gate.

**The gates.** `check_dimension_case_rule` refuses the matcher's `case_malformed` and `vocab_value_unregistered` (so variadic tails are case-checked: `variadic_tail_segments_are_case_checked`). R2(b) (`check_namespace_family_registered`) refuses the matcher's `family_unregistered` in addition to persist's governed-but-rowless stems. Layer 2b refuses `missing_version_segment` unless the resolved family is exempt.

### 10.2 What moved (findings the re-vendor surfaced)

- **Families.** 116 → 145: 30 added (the six `accord:*` leaves, eight `consent:*` rows, media wildcards, `event:*`, `identity:canonical_binding:{canonical_hash}`, `topical_relation:{kind}`, …); `age_self_declared:{band}:{version}` retired → `age_self_declared:band:{band}:{version}` (moved to `RETIRED_FAMILIES`, as CC's generator lists it). `licensure:{authority_id}` is now `reserved: false` (CC ruling; persist already treated it open since v42 — its delegated-license-chain rule joins `RULES_NOT_ON_THE_ROW`). `session:{kind}` carries `occurrence-self-report` (CC 3.1.3.1).
- **Reserved stems close their leaves.** `detection:emergent_pattern:novel_signal:v1` and `accord:invoke:halt` were "open vocabulary inside a registered family" in v49's tests; CC now refuses both. The detector admit witness moved to a registered leaf.
- **`capacity:` / `detection:` rule pins retired** — CC's `reserved_stems` states them at the family (the CIRISConstitution#67 ask); `authority_for` answers a `kind: reserved` stem's rule for an unclaimed leaf rather than dropping the reservation.
- **Canonical binding (wire break).** CC: `identity:canonical_binding:{canonical_hash}`, one 64-lowercase-hex segment, version-exempt. Persist's fixtures bound the key-id spelling (`…:canonical:sha256:<hex>`, five segments), which now matches no row and fails T3. `parse_canonical_binding_hash` resolves through the matcher; the hash is re-spelled `canonical:sha256:<hex>` where it meets `subject_key_ids`.
- **Accord.** `accord:invoke:CONSTITUTIONAL:halt_id_42:v1` → `accord:invoke:constitutional:halt_id_42:v1`; `accord_invoke_old_uppercase_shape_fails_loudly` witnesses the old spelling refused `case_malformed` at the matcher and the case gate. Persist holds no `ciris.accord_invoke` canonical bytes (verify-core signs; the v17.1.0 pin still carries `.v1` / `CONSTITUTIONAL`), so the signature-level "old signature fails" witness is verify's.
- **Hardware.** `HardwareTypePlatform::as_platform` (exhaustive over the 13 keyring variants) equals the registry's closed `{platform}` set both ways (`hardware_type_platforms_equal_registry_values_107`); `hardware_class_multiplier` is CC 4.2.2's table, unlisted ⇒ 0.0; `hardware_class` stays a JSON property.
- **Minors (CC 5.4.6 / #111).** `check_minor_owner_binding_not_announced`: an owner-purpose `delegates_to` at `cohort_scope: federation` whose granter resolves `minor` refuses `WriteScopeRefused(MinorOwnerBindingAtFederation)` (`scope_minor_owner_binding_at_federation`), at every backend's put door and in the promotion stack. Invariant `exercise_minor_owner_binding_is_not_announced` beside `exercise_node_speaks_for_owner`, on memory/sqlite/postgres.
- **Polarity census.** The five `+1.0 only` accord leaves map to `[1.0, 1.0]` and join `PINNING_FAMILIES` (the contrast is now 134 / 8 of 145).
- **Manifest readers.** `every_manifest_family_column_has_a_reader_724` now accounts `_meta`, `_meta.case_rule`, `version_segment` and the per-segment keys; `reserved_prefix_rules_match_manifest_leaves` holds every hand-spelled reserved-rule prefix to a literal leaf of a vendored family or a CC reserved stem.
- `regex` is a direct, non-optional dependency (already in every build via `jsonschema`).

### 10.3 Deviations

1. **CC gap: the CC 3.4.12 capacity companions have no registry row.** CC 3.4.12 prescribes `capacity_assurance:reversible_excluded:{domain}` / `reversible_pending:{domain}` as mandatory, but rc5 registers only `capacity_assurance:{level}:{domain}:{band}:{version}` under that reserved stem, so the reference matcher refuses them. `CC_TEXT_LEAVES_WITHOUT_ROWS` stands R2(b) aside for exactly those two prefixes (the witness-reserved emitter rule still applies); `cc_text_leaves_without_rows_are_still_rowless` fails the build once CC registers them. **CC ask:** register the two companion rows.
2. **Evidence decimals.** Rows are keyed on CC's staged claim ids and THEIR decimals (`CLM-version-segment-suffix` 3.1.7, `CLM-reserved-leaves-closed` 3.4.1, `CLM-accord-invoke-lowercase` 4.2.1.1, `CLM-hardware-custody-vocabulary` 3.1.2, `CLM-minor-no-federation-binding` 5.4.6), not the 3.1.1 / 3.1.9 / 4.2.2 the brief listed. `CLM-device-roster-announced` is not claimed: persist does not implement the stranger-view `nodes_owned_by` projection.
3. **Stricter-than-reference edges (not in any vector).** Rust `regex` `$` is end-of-text where Python's `re.match` `$` also matches before a trailing newline, so a segment ending in `\n` is refused here and could pass the reference; whitespace for the strip check is Unicode `White_Space` plus `\x1c`–`\x1f` (Python's `isspace`).
4. **The ledger version** uses the one parser to recognise the segment, then still requires an integer (`v1.2` refuses): CC 3.3.10.1's id derivation keys on the version number.
5. **`registry::case_rule()` is deleted** (and the hand-implemented vocab-pattern test with it): the matcher compiles the manifest's patterns directly.

### 10.4 Adopter note (wire breaks — what a consumer must change)

- Dimensions are judged by the CC grammar at the door: an unversioned registered dimension (`capacity:composite`) fails T3; a version-shaped segment anywhere but last is no longer the version; `usd` for `{currency}` is malformed (`USD`); closed vocabularies refuse unlisted values (`hardware_custody:tpm:v1`); unnamed leaves under `accord:*` and unclaimed leaves under CC's reserved stems (`accord:`, `detection:`, `capacity:`, `age_assurance:`, `capacity_assurance:`, `transparency_log:cosigned:`, `age_self_declared:`) are `namespace_family_unregistered`.
- Emit `accord:invoke:{constitutional|notify|drill}:{id}:v1` (lowercase, with the id); sign invocations under `ciris.accord_invoke.v2` (verify-side).
- Emit `age_self_declared:band:{band}:v1`, `identity:canonical_binding:<64 hex>` (no `canonical:sha256:` inside the dimension), `hardware_custody:{snake_case HardwareType}:v1`.
- A minor's owner-binding must be held at `cohort_scope: self`; at `federation` it refuses `federation_write_scope_refused: scope_minor_owner_binding_at_federation`.
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
