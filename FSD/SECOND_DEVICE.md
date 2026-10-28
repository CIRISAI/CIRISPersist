# The second device (CIRISPersist#919, #916, #920, #917)

CIRISServer's second-device flow: "sign in on a second device by approving on the first; files and chats just show up". Four properties make it work in persist: a placed row is never widened out of its room (§1), the MLS-state store opens on every host with an honest custody label (§2), a member's new device receives what the member holds (§3), and the attributed sync door reports a duplicate as a duplicate (§4). Each rests on rules already in the CC and persist's FSDs; §0 states the basis.

## 0. The four rules, their basis, and their effect

| # | Rule | Basis | Effect |
|---|---|---|---|
| #919 | A row naming a cohort target is never a widening candidate. | CC 5.2 structural invisibility applies to self/family; CC 3.1.9: `cohort_scope` is the emitter's per-envelope choice; `build_widening` (#801) carries the NEW placement's target, so a federation widening naming no room is correct. #530's repair is for rows STRANDED without a placement (traces, which name no room). | The self-room handshake (KeyPackage/Welcome/Commit) stays in the room; a second device joins. Family rows cannot leave the family. #530's trace repair applies: traces name no room. No wire change. |
| #916 | A member's new device receives exactly what the member holds. | CC 2 `history_on_join` governs a NEW MEMBER; CC 4.4.3.4.5 Option A: entitlement is what the member held during membership; the self/family precedent `rekey_for_newcomers` grants a newcomer every blob the cohort already holds, idempotently. | History opens on the second device. A removed member's device gets nothing (the fold says not active). An evicted epoch is `ContentMiss`, fail-honest (CC 5.1 P4). Authority is the owner-binding, never the roster: the member's standing does not change. |
| #920 | On a software host the MLS-state key derives from the persisted software content master; the opener returns the custody kind. | `BLOB_ENCRYPTION_AT_REST.md` §4.3/§10.2: "a software fallback honest about being software"; `ContentMasterSource::SoftwareFallback`, `federation_content_master.key_kind`. CC 4.2.2.1: `hardware_class` is a measured claim; software is a class, not a failure. | CI and dev hosts get a durable, truthfully labelled store. Hardware hosts (hardware row) derive from the hardware seed. One root per posture (no seed file — that would be a third root on software hosts). `HardwareCustodyUnavailable` is for §11.7 only. |
| #917 | `put_attestation_synced` returns the typed `ReplicatedAttestationOutcome`. | Persist's own rule: one typed outcome for the replicated doors. | Edge's ledger books a decoration-only re-delivery as a duplicate on both doors. The peer-origin metering is kept. |

Related: #914 — disclosure sets are blobs (the decision is on the issue). #912's per-membership listing span is the CC's own wording (CC 2 field table; `ROOM_ROSTER_AUTHORITY.md` §11).

## 1. #919 — the sweep never widens a placed row

**The hazard.** `list_widening_candidates` reads `tier='federation' AND cohort_scope IN ('self','family')` rows with no widening yet; the sweep (`Engine::promote_consented_backlog`, the widening-candidates pass) widens each to the audience of a covering grant, and the widening carries the new placement's target — none, for `federation`. If a row `share` placed in a self room (`community_key_id = <owner>`, `cohort_scope = self`) were a candidate, it would be re-published federation-wide without its room, and the room's own fold (`supersedes` stands for the claim, CC 4.4.3.3.1) would find nothing.

**Rule.** A candidate is a row that names NO cohort target: no populated `admission::COHORT_TARGET_ENVELOPE_FIELDS` alias (`community_id`, `community_key_id`, `cohort_key_id`, `family_key_id`) and no blob pointer with a non-empty owner slot (§7, #919). The exclusion is applied in the same place on both backends (sqlite, postgres), by the same predicate, and the read is documented as "stranded rows only".

**Invariant I186** (sqlite, postgres): a self-scoped row naming a self room plus a federation consent grant covering its dimension → after the sweep the row is unchanged and has no widening; a family-scoped row naming a family, same grant → unchanged; a self-scoped row naming NO target, same grant → widened (the #530 case repairs). Also: the room's own reader still finds the placed row after the sweep.

## 2. #920 — the MLS-state root follows the content master

**Rule.** The MLS-state key = HKDF(root, `MLS_STATE_CONTEXT`) where `root` is what `content_master_key` / the persisted `federation_content_master` row resolves to on this host: the hardware-sealed seed (`key_kind='hardware'`) or the persisted software master (`key_kind='software'`). The persisted row wins (`BLOB_ENCRYPTION_AT_REST.md` §10.2): a store created on a software host keeps opening after a TPM appears.

**Shape.** `Engine::open_mls_state(path) -> Result<(XChaChaKvStore, MlsStateCustody), KVError>`, where `MlsStateCustody { kind: "hardware" | "software", descriptor }` is returned so hosts log the class by name. `KVError::HardwareCustodyUnavailable` is for exactly the §11.7 case: the row says hardware and the seed is unreachable.

**Seed policy.** The MLS-state opener never mints a seed: under a hardware row it asks `create_seed_if_absent = false` on every open, including the first open of an empty store. The row proves a seed was sealed when it was written; an absent seed is §11.7's lost keyring, and minting there would also move the content master. The only moment the MLS/content path seals a seed is the content-master row's initialisation (which `open_mls_state` performs on a node with no row; the secrets store's own first migration, `derive_hardware_master_key`, also seals one), and a process-wide lock in `secrets::hardware` (`SEED_MINT_LOCK`) serializes that exists-then-store so concurrent first writers seal one seed.

**Hardware-keyed store under a software row.** Under a software row, only when the store is in use and its verifier refuses the software-derived key, the opener tries HKDF(hardware seed, `MLS_STATE_CONTEXT`) with `create_seed_if_absent = false` — the key an earlier opener used regardless of the row. On success: `kind = hardware`, descriptor `legacy-v49-hardware-keyed-under-software-row …`, nothing re-keyed. Both keys failing is `WrongPassphrase`. A fresh store under a software row is always `software`.

**Invariant I187**: on a software content master the store opens, reports `software`, survives a reopen, and derives a DIFFERENT key from the content master itself (domain separation); on a hardware row with no reachable seed it refuses `HardwareCustodyUnavailable` and writes nothing; the hardware branch over the storage double reports `hardware`; a software-created store reopens with the row unchanged even when hardware becomes available (the row wins); and (I187f) a hardware-keyed store under a software row opens reported `hardware` with the `legacy-v49-hardware-keyed-under-software-row` descriptor, not re-keyed, while a fresh store under that row stays `software`; if hardware-backed storage is present but that seed is unusable the answer is `HardwareCustodyUnavailable` carrying the reason, never a mint; with NO hardware backing, or when both keys were tried, it is `WrongPassphrase`. The split is a typed result (`secrets::hardware::HardwareDeriveError` → `encrypted_kv::HardwareRootError`), never a message match.

## 3. #916 — a member's new device gets what the member holds

**Door.** `rekey_community_member_device_add(community_key_id, member_key_id, new_occurrence_key_id, authority_key_id)` on sqlite and postgres, orchestrated in `at_rest_cascade` beside `rekey_family_member_add` / `rekey_self_occurrence_add`. It re-wraps to the new occurrence's content-KEM key every retained `(community, minter, epoch)` DEK the member already holds a grant on (per-minter epochs, #848), idempotently (a grant already present is skipped; the insert, not the pre-check, decides what the result reports). No epoch bump: the member set did not change.

**The minter side.** Only an epoch's minter can sign the `KeyGrant` set that carries a wrap (`admit_replicated_key_grant`: signer == minter), so the host's door on the member's node reaches only the epochs that node minted; another node's epoch is reported `minted_elsewhere`. Every minter therefore re-wraps its OWN retained epochs to a member's device itself (`rewrap_own_epochs_to_member_devices`), from the receive doors every host uses and with no signer at the door: `attestation_apply::apply_planned` (the one body behind `apply_replicated_attestation` and `put_attestation_synced`) on `Inserted` of an owner-binding, and the sqlite/postgres `put_identity_occurrence` on a signed occurrence, each call `FederationDirectory::rewrap_own_epochs_for_device` (default no-op; sqlite and postgres run the walk under their node key). It writes grant rows only; each grant leaves its epoch DIRTY in the V146 emission ledger, and the pending-set loop every host runs (`Engine::emit_pending_key_grants`, PyEngine's `emit_pending_key_grants` and init sweep) signs and emits the set. Those loops first run the full walk, so a device whose occurrence arrives through a door with no hook (the trusted-local door) is covered at the next pass. `Engine::apply_replicated_attestation` also emits at once. PyEngine exposes the walk as `rewrap_own_epochs_to_member_devices_json`. Same authority, same idempotence. Cost of a full walk: communities × members × devices point reads (holders computed once per member); a wrap is computed only for an epoch a device does not yet hold.

**A member's device** is the seal fan-out's definition — an ACTIVE identity occurrence of the member — with the member's live owner-binding over it as the authority. A node the member owns but does not speak through (infrastructure run for others) is not their device: the door refuses it (`device_rekey_not_an_occurrence`, retryable) and the walk never targets it.

**Own epochs only are emitted.** A grant written under a minter that is not this node's current key (a former node key, a row written before the minter was named, #876) is reported `local_only`, never `granted`: this node cannot sign that minter's set.

**Authority.** The owner-binding is the authority: the new occurrence must be bound to the member by the member's live owner-binding (CONSENT_BY_HUMANS `for_key_id`; OCCURRENCE_PRINCIPAL), and the member must be ACTIVE by `authorized_community_roster_at` at the call's instant. `authority_key_id` names who the host says is acting and must be that owner; it is not evidence of anything by itself. A device claimed by a different owner, an unbound occurrence (retryable: the binding may not have replicated yet), an owned node that is not the member's occurrence (retryable), a removed member, or an occurrence lacking `encryption_pubkeys` is refused by name (typed), never granted a plaintext fallback.

**What the member holds.** A removed-then-re-added member's new device DOES receive the epochs the member's devices already held before the removal — that is "exactly what the member holds", and CC 4.4.3.4.5 Option A (removed members retain extant grants). It must NEVER receive an epoch from the ABSENCE span, which the member never held. The holder set is the member key, the member's occurrences and the nodes the member owns, minus every key another party has ever held — any owner-binding over it by someone else (live, lapsed or withdrawn), or an identity row for it under someone else (#851). The span is cut by exclusion, not by instant: the only instants available are `asserted_at`s their signer chose (and a login anchor is re-asserted at every login), so a cut on them is forgeable backwards or drops real history. A shared or transferred device contributes nothing; the member's other devices still do.

**Reported, not skipped.** An epoch the member holds whose DEK this node cannot recover is in `content_miss` with one of three reasons: `destroyed` (ours, destroyed by policy), `lost_locally` (ours — minted under this node's key — with its row gone: escalate), `minted_elsewhere` (a peer's: its minter re-wraps it).

**Invariant I188** (sqlite, postgres): a member with grants on epochs E1..E3 adds a device → the device holds grants on E1..E3 and can unwrap each; re-running adds nothing; a device bound to ANOTHER owner is refused; a removed member's device is refused; an epoch the node no longer retains is reported, by reason; a re-added member's device gets what the member held before and nothing minted in the absence. Two-node: the minter re-wraps its own epochs to the device on the binding's arrival over the since-read (or in its pending sweep), the set crosses, and the device's wraps open on the member's node.

## 4. #917 — the attributed sync door has a typed pre-write outcome

**Rule.** `put_attestation_synced(record, peer)` runs `plan_replicated_attestation_apply` over `(existing, incoming)` and acts on the plan, returning `ReplicatedAttestationOutcome` (`Inserted` / `Unchanged` / `Deduplicated` / `Refused { reason }`) — the same enum the unattributed door returns — while keeping the `peer` argument and `shares_cohort_with(peer)` metering. A same-signed-assertion, different-decoration re-delivery is `already_present_identical` (a duplicate), never `Error::Conflict`; a different signed row is `conflicting_attestation`. `AttestationOutcome` is the return of `put_attestation`.

**Invariant I189** (sqlite, postgres): the same bytes through both doors yield the same outcome variant; a decoration-only re-delivery is `Refused { already_present_identical }` (a duplicate, which CIRISEdge books as `Duplicate`) on the attributed door; a different signed row under the same id is `Refused { conflicting_attestation }`; metering still refuses a non-cohort peer.

## 5. Not in scope

#914's store, `erase_object` and mint API. Server#650's roster-book read. A `listed_members` capsule op.

## 6. Verification

Each property has its witnesses on both backends and a mutation table on its predicate or door (§7). The release gate runs the full unfiltered lanes (sqlite, postgres, union), the gate chain, and `certify.sh full` on the exact SHA.

## 7. Implementation notes and mutation tables

### #919 — the sweep never widens a placed row

**Triggers.** Persist has one production widening builder: `Engine::widen_audience` (`crossing::build_widening` → sign → `FederationDirectory::widen_audience`). Its only automatic caller is the consent sweep's widening step (`Engine::sweep_widen`), which runs on both passes of `promote_consented_backlog`:
- pass 1 widens a LOCAL row straight after it enters the mesh, from the local page;
- pass 2 widens rows from `list_widening_candidates`.

The sweep itself fires at three points: chokepoint (c), right after this node emits its own consent grant (`emit_attestation_assemble`); chokepoint (a), every ingest batch (`receive_and_persist`, pyo3); and the host's tick. The other callers of `widen_audience` are the explicit pyo3 method `widen_audience` (a host's "publish this row wider") and test fixtures (`tier_ingest::test_support::widen`, the `bootstrap_admission` `exercise_*` bodies).

So the rule is applied twice:
- in the candidate read, on both backends (pass 2's page);
- in `sweep_widen` (both passes; pass 1 never consults the candidate read). A placed row still LOCAL when the sweep runs is entered into the mesh at `self` and not widened (M8).

`Engine::widen_audience` stays callable for a placed row. It is documented as the one deliberate path, and I186 pins that an explicit call still crosses.

**Where a row names its room.** A row is placed if either of two things holds:
- a top-level `COHORT_TARGET_ENVELOPE_FIELDS` alias is populated. Chat rows name their room this way (Edge `chat.rs`), as does every targeted placement;
- a blob pointer's owner slot is non-empty: the `community_key_id` of a pointer-shaped member, at top level or as an array item (`blob_pointer::names_pointer_owner`, the same scan as `pointer_for`, with the discriminator shared). This is the room the bytes are held in.

Edge's self FILE rows name their room ONLY in the pointer's slot: a self room has no `cohort_target_field` (`scope_room.rs`), and Edge's self-room file read keys on `file.pointer.community_key_id` (`files.rs`). Reading the aliases alone would leave every Edge self file row a candidate.

**SQL form of the pointer arm.** The member set is open: the Rust scan reads every member by construction. So the SQL walks the same two positions instead of a list of paths:
- SQLite: `json_tree` restricted to a top-level member (`path = '$'`, not the root) or an item of a top-level array (`path` = that array's `fullkey` from `json_each`). Nested `json_each` cannot be used here: SQLite evaluates a table-valued function's argument on every row, and a scalar member's value is not JSON.
- Postgres: `jsonb_each` plus `jsonb_array_elements` under a lateral join.

The pointer discriminator is the same in Rust and both SQL forms: a 64-hex `content_sha256` string and a non-empty string `community_key_id`. There is no generated column: that would need a migration, and a stored copy of the rule would need its own drift check. The scanned set is bounded by the self/family corpus (`tier='federation' AND cohort_scope IN ('self','family')`), not by the stranded rows. Placed rows are never widened, so they stay in that set permanently, and every sweep runs the pointer scan over each of them. The read already runs two correlated subqueries per row. If mobile sqlite shows the cost, the follow-up is a generated column holding the placement bit, pinned against `envelope_names_cohort_target`.

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

It asserts every placed row's supersedes chain is empty and that the read lists exactly the originals; that no other row carries a placed file's filename; and that the stranded self file row (no target, no pointer owner) is widened to `federation` (#530).

Lane: `scripts/pg_test_db.sh -- cargo nextest run -j 3 --no-fail-fast --features sqlite,postgres -E 'test(sweep_placement) | test(530) | test(widen) | test(promote_consented)'`. Each mutant reverted before the next.

| Mutant | Killed by |
|---|---|
| M1 drop the read's exclusion (aliases and pointer) on both backends, keep the sweep guard | I186 candidate read and sweep on sqlite and postgres |
| M2 read only the `community_key_id` alias | the rendering pin; candidate read; sweep |
| M3 exclude only when `cohort_scope = 'self'` | candidate read (the family rows); sweep |
| M4 invert | candidate read; sweep; `list_widening_candidates_filters_suppressed_scopes_530`; `consent_sweep_widens_a_row_that_entered_before_the_grant` |
| M6 an EMPTY alias counts as a target | candidate read (`c-empty-target`) |
| M7 drop the read's exclusion on postgres only | candidate read and sweep on postgres; (e) the backends disagree |
| M8 drop the `sweep_widen` guard (pass 1's trigger) | sweep on sqlite and postgres |
| M9 drop the read's exclusion and the guard | candidate read; sweep |
| **M10 drop the pointer arm** (Rust and both SQL forms) | the rendering pin; candidate read; sweep, by (d): "the supersedes chain of placed row … is not empty" |
| M12 pointer arm without array items (Rust and both SQL forms) | candidate read (`a-edge-attachment`) |
| M13 an EMPTY owner slot counts as a room (Rust and both SQL forms) | candidate read (`c-pointer-no-owner`) |
| M14 sqlite reads a pointer at any depth (the `ptr.path` restriction dropped) | (e) the backends disagree; candidate read on sqlite (`c-pointer-nested` excluded) |
| M15 postgres recurses into every nested object (`jsonb_path_query(top.value, 'lax $.**')`) | (e) the backends disagree; candidate read on postgres; the rendering pin (`jsonb_array_elements(` gone) |

**Scope of the rule.** Placement is read from the four top-level aliases AND from a blob pointer's owner slot. Persist has no `share` marker, so a row that names its room in neither place (for example a self row carrying no pointer and no alias) is a candidate. Two further readings:
1. "Populated" means a non-empty JSON string, both for an alias (the `envelope_cohort_target` reading, M6) and for an owner slot (M13). An empty or non-string value names no room.
2. The rule is asked in the candidate read and in `sweep_widen`, because pass 1 widens from the local page ("cover every trigger"). A placed local row enters the mesh at its own scope.

### #920 — the MLS-state root follows the content master

**Opener:** `Engine::open_mls_state(&self, path: impl AsRef<Path>) -> Result<(XChaChaKvStore, MlsStateCustody), KVError>` (async; gated on `encrypted-kv`), where `MlsStateCustody { kind: MlsStateCustodyKind /* Hardware | Software */, descriptor: String }` and `kind.as_str()` is `"hardware"` / `"software"`. It reads, or initialises, the row through `BlobStorage::load_or_init_content_master_row` (sqlite, postgres; `load_or_init_content_master` resolves that row), then calls `XChaChaKvStore::open_mls_state_from_row` (`pub(crate)`, no backend import) on the blocking pool. The error type is `KVError`, so hosts match `HardwareCustodyUnavailable` directly; a row-load failure is `KVError::Backend`.

**Mechanism.** Both arms call CIRISVerify's `derive_symmetric_key` (HKDF-SHA-256, verify's salt, `info = MLS_STATE_CONTEXT`). The software arm passes the persisted master through an in-process, read-only, one-entry `SecureBlobStorage` that reports `is_hardware_backed() == false`. So the two arms share one mechanism and differ only in the root, and persist implements no KDF of its own.

**First open.** Under a `hardware` row the opener asks `create_seed_if_absent = false` on every open, including the first open of an empty store (§2). `open_rooted` reports `first_open` and the I184 witnesses stand, but nothing grants a mint from it.

Lane: `scripts/pg_test_db.sh -- cargo nextest run -j 3 --features postgres,sqlite,encrypted-kv,secrets -E 'test(i184) | test(i187) | test(mls_state) | test(domain_separated) | test(content_master) | test(seed)'`. Each mutant reverted before the next.

| # | Mutant | Killed by |
|---|---|---|
| M1 | software arm derives under `CONTENT_MASTER_CONTEXT` | `i187_b_…domain_separated…` |
| M2 | software arm reports `kind: Hardware` | i187_a, i187_e, i187_f fresh-stays-software, and the sqlite+postgres Engine legs (software row, no-row, hardware-keyed store under a software row) |
| M3 | §11.7 refusal replaced by minting (`hardware(true)`) | both i187_c tests, i187_d |
| M4 | row-wins dropped: hardware preferred whenever available | i187_a, i187_a malformed, i187_b, i187_e, both i187_f units, both Engine legs |
| M5 | may-mint-on-first-open (`hardware(!path.exists())`) | both i187_c tests, i187_d |
| M6 | software arm uses the master verbatim, no HKDF | i187_b, and the sqlite+postgres software legs |
| M7 | hardware-keyed-store arm dropped | four i187_f units (hardware-keyed store, both-keys, no-backing twin, never-mints) and both Engine legs |
| M8 | hardware-keyed-store arm PREFERRED: hardware key tried first under a software row | i187_a, malformed, i187_b, **i187_e**, fresh-stays-software, both Engine legs |
| M9 | hardware-keyed-store arm may mint (`hardware(true)`) | four i187_f units |
| M10 | `SEED_MINT_LOCK` dropped | `concurrent_first_derivations_seal_one_seed` |
| M11 | the arm drops the reason (`Unreachable` → `WrongPassphrase`) | `i187_f_the_compat_arm_never_mints` |
| M12 | no hardware backing collapsed into seed-absent (`NotHardwareBacked` → `HardwareCustodyUnavailable`) | `i187_f_no_hardware_backing_is_wrong_passphrase_not_custody` |

### #916 — the device re-wrap (I188)

**Doors (signatures).**
- Host's door: `at_rest_cascade::orchestrate::rekey_community_member_device_add(backend, community_key_id, member_key_id, new_occurrence_key_id, authority_key_id, as_of) -> Result<DeviceRekeyResult, federation::Error>`; `Engine::rekey_community_member_device_add(community_key_id, member_key_id, new_occurrence_key_id, authority_key_id)` (emits the epoch set of each `granted` epoch); `PyEngine.rekey_community_member_device_add_json`.
- Minter side: `at_rest_cascade::orchestrate::rewrap_own_epochs_to_member_devices(backend, minter_key_id, only: Option<(member, device)>, as_of) -> Result<MinterRewrapReport { changed, keyless }, Error>`. Reached by every host through `FederationDirectory::rewrap_own_epochs_for_device(owner, device)` (default no-op; sqlite/postgres run the walk under their node key; delegated by the directory double), called by the receive doors: `attestation_apply::apply_planned` (the one body both typed doors, `apply_replicated_attestation` and `put_attestation_synced`, run) on the store's `Inserted` for an owner-binding, after the §6.1 dedup re-read, and never on `Unchanged`, `Refused` or `AlreadyHeld`; and the sqlite/postgres signed `put_identity_occurrence` — writing grant rows only (dirtying their epochs). The full walk runs first in `Engine::emit_pending_key_grants`, PyEngine's `emit_pending_key_grants` and PyEngine's init sweep; `Engine::apply_replicated_attestation` emits the dirtied sets at once; `Engine::rewrap_own_epochs_to_member_devices(only)` / `PyEngine.rewrap_own_epochs_to_member_devices_json(member_key_id=None, device_key_id=None)` are the on-demand forms that also emit.
- `DeviceRekeyResult { epochs_scanned, granted (own epochs — emitted), local_only (written under a non-node minter — never emitted), already_held, content_miss: [EpochMiss { minter_key_id, epoch, reason: Destroyed | LostLocally | MintedElsewhere }] }`; the insert decides `granted`/`already_held` (`community_dek_put_member_grant` returns whether it inserted).
- Refusals: `Error::DeviceRekeyRefused { community_key_id, member_key_id, occurrence_key_id, rule }`, `kind()` `federation_device_rekey_refused`, Python `ValueError` `"<kind>: <rule>"` (as `RosterAuthorityUnauthorized` and `LocationAuthorityUnauthorized`). Rules `device_rekey_unbound` (retryable), `device_rekey_owner_mismatch`, `device_rekey_authority_not_owner`, `device_rekey_not_an_occurrence` (retryable), `device_rekey_member_not_active`, `device_rekey_no_encryption_pubkeys` (records `hard_case:recipient_excluded`).
- Floor read `community_dek_member_grant_epochs(community, member_key_ids)`. No `EnvelopeKind`.

**Through the capsule** (`dyn FederationDirectory` over the wire), witnessed by two-node (T4)/(T5). The typed doors cross whole through `ApplyReplicatedAttestation` and `ApplyReplicatedAttestationSynced`. The far side runs `attestation_apply::apply_planned` against its own backend, and that function holds the one re-wrap hook, so an owner-binding delivered through an `OpsDirectory` re-wraps on the far side's backend. The dirtied sets are emitted by the pending-set loop. `PutIdentityOccurrence` reaches the backend's hooked `put_identity_occurrence`. The untyped ops (`PutAttestation`, `PutAttestationSynced`) are the plain write door and never re-wrap.

**A host with no node key** (N1): the door refuses `device_rekey_node_key_unknown` (retryable) rather than misclassify; the backend hook logs the skip at warn. PyEngine init sets the backend's node key from its signer, as the `Engine` constructors do; an `Engine` over a shared backend sets it before its #916 doors run. `Engine::apply_replicated_attestation` emits only the dirty sets (the backend hook already did the narrow walk); the narrow walk checks the device and the member's held epochs before folding any roster.

**Residual.** An epoch this node minted under a FORMER node key whose self-retention row is gone reports `minted_elsewhere` (the minter is not the current node key); nothing can re-wrap it either way. PyEngine's init sweep and on-demand loop call the same orchestrator but are not witnessed from a PyEngine (no Rust-side PyEngine construction pattern).

**Two-node delivery path (I188 two-node, sqlite and postgres; every row names its door).** Setup: A (alice's node) seals E1..E3 through `Engine::put_blob_scoped`; B seals one epoch and A admits B's set through `Engine::apply_replicated_key_grant`; A holds a self-retention under a foreign minter's name. Each device's binding is admitted on B by `put_attestation` and read off B's `list_attestations_since`.
- (T0) d0's anchor written on A by `put_identity_occurrence_local`; binding → `Engine::apply_replicated_attestation` on A → re-wrapped by the backend hook and the sets emitted at once (read off A's `list_attestations_since`).
- (T1) d1: anchor by `put_identity_occurrence_local` on A; binding → trait `FederationDirectory::apply_replicated_attestation(A)` → A holds grants on E1..E3, none on B's or the foreign epoch.
- (T2) d2: the same, binding → trait `FederationDirectory::put_attestation_synced(A, row, node_b)`.
- (T3) d3: binding → trait `apply_replicated_attestation(A)` first (no grant: d3 is no device of bob's on A yet); d3's anchor signed by d3 on B (`publish_signed_content_only_occurrence`) → B's `list_signed_identity_occurrences_since` → A's `put_identity_occurrence` → grants.
- (T4)/(T5): an owner-binding delivered through an `OpsDirectory` over A's backend, by `ApplyReplicatedAttestation` (d6) and `ApplyReplicatedAttestationSynced` (d7), re-wraps on A's backend, and A's pending-set loop emits sets carrying both devices, which open on B.
- (U): the same binding re-delivered through both typed doors is `Unchanged` and re-wraps nothing.
- Sets: A's pending-set loop as PyEngine spells it (`key_grant::dirty_axes` + `emit_key_grant_axis_with_local_signer` with A's LocalSigner) emits ≥ 3 sets; the sets carrying d1, d2, d3 are read off A's `list_attestations_since` → B's `key_grant::admit_replicated_key_grant`; on B each device's wrap (its kept private halves) opens to the DEK B's own wrap opens to (B's content-KEM private halves).
- (S) d4: binding → trait `apply_replicated_attestation(A)` (no anchor: nothing); anchor → `put_identity_occurrence_local` on A (no hook): nothing; `Engine::emit_pending_key_grants` re-wraps and emits.
- (D) d5: binding by `put_attestation` on A, anchor by `put_identity_occurrence_local` (no hooks) → `Engine::rekey_community_member_device_add` → `granted` A's three epochs, `local_only` the foreign one, `content_miss` B's as `minted_elsewhere`; sets for A's epochs carry d5; no set exists for the foreign minter.

**Mutation table** (lane `test(device_readd) | test(i188) | test(key_grant) | test(rekey) | test(epoch)`, `--features sqlite,postgres`, under `scripts/pg_test_db.sh`; each mutant reverted before the next):

| # | Mutant | Caught by |
|---|---|---|
| M01 | owner-binding check dropped | (c) |
| M02 | roster-active check dropped | (e) |
| M03 | only the latest held epoch re-wrapped | (a); two-node (T0) |
| M04 | each re-wrapped epoch's minter bumped | (h) |
| M05 | keyless device returns `Ok` | (f) |
| M06 | unretained epoch skipped silently | (g); two-node (D) |
| M07 | authority check dropped | (c') |
| M08 | keyless exclusion not recorded | (f) recorded |
| M09 | already-held pre-check dropped | (b) zero wraps computed on a re-run |
| M13 | door's emit loop deleted | two-node (D) |
| M14 | door's own-minter emit filter inverted | two-node (D) |
| M15 | other-party owner-binding filter dropped | (i) absence-span epochs leak |
| M16 | other-identity filter dropped | (i) absence-span epochs leak |
| M17 | miss reasons collapsed to `minted_elsewhere` | (g) |
| M18 | insert result ignored | (b'') two racing calls |
| M19 | signed `put_identity_occurrence` hook dropped (sqlite + postgres) | two-node (T3) |
| M20 | hook stamps the epochs emitted after re-wrapping (the dirty mark lost) | two-node (T0) — no set emitted |
| M21 | door's identity-occurrence check dropped | (j) |
| M22 | walk targets `nodes_owned_by` AND the occurrence check dropped | (j) |
| M23 | `local_only` classification dropped | (a); two-node (D) |
| M24 | `Engine::apply_replicated_attestation`'s dirty-set emission dropped | two-node (T0) |
| M25 | no node key: the door proceeds with an empty key instead of refusing | `i188_no_node_key` (sqlite, postgres) |
| H1 | the hook dropped from `apply_planned` | two-node (T0) |
| H2 | the hook also fires on `Unchanged` | two-node: (U) re-wraps d4, so the (S) precondition fails |
| H3 | the far side re-wraps only via the untyped `PutAttestationSynced` | two-node (T4); I189 capsule |
| H4 | the single hook site skips the `Wire` origin | two-node (T0) |
| H5 | the single hook site skips the `Sync` origin | two-node (T2) |

Equivalent, not run as separate mutants: the walk's candidate list alone switched to `nodes_owned_by` is equivalent while `is_member_device` also guards it (two layers, M22 removes both); the hoisted holder set computed without excluding the device is equivalent (the device is itself a clean holder, and its grants are already held).

### #917 — the attributed sync door (I189)

Signature:

```rust
async fn put_attestation_synced(
    &self,
    attestation: SignedAttestation,
    authenticated_peer_key_id: &str,
) -> Result<attestation_apply::ReplicatedAttestationOutcome, Error>;
```

Both typed doors run one body, `attestation_apply::apply_planned(dir, attestation, origin)`: `apply_replicated_attestation` passes `WriteOrigin::Wire`, `put_attestation_synced` passes `WriteOrigin::Sync { peer_key_id }`. Same bytes, same variant, by construction.

Notes on §4:

- A decoration-only re-delivery is `Refused { reason: AlreadyPresentIdentical }`, not the `Deduplicated` variant. `Deduplicated` is the CEG §6.1 composer replay and carries no reason; `Refused { AlreadyPresentIdentical }` is what the unattributed door returns for these bytes, and CIRISEdge's `attestation_outcome_to_apply` books it as `Duplicate`. §4's "same enum, same variant on both doors" decides it.
- Metering applies to every row that reaches the write door. A row the plan resolves against the stored one (`Unchanged`, `Refused`) is decided before that door and charges no budget, as on the unattributed door. A stranger over budget sending a fresh row gets `Error::RateLimited` from the synced door, the same error the wire door gives.
- There is no Engine wrapper and no pyo3 method for the synced door, so arm (g) has nothing to bind.
- **Across the capsule.** `OpsDirectory::get_attestation` is `Unsupported`, so the plan cannot run on the near side of the capsule. The typed doors therefore cross whole, through two appended ops (`ApplyReplicatedAttestation`, `ApplyReplicatedAttestationSynced`) that answer one appended result (`ReplicatedAttestationOutcome`). The far side runs the typed door against its own backend; `OpsDirectory` overrides both trait methods to send them. The `PutAttestationSynced` op keeps its contract: the untyped stored-write door under the Sync origin, answering `AttestationOutcome`.
- The store's own verdict is mapped rather than `Ok(_)`. `AlreadyHeld` means a lost plan/act race, or a plan-free re-offer of a held row, so it becomes `Unchanged`, never `Inserted`.
- When the id is held, `check_envelope_size_admission` runs before the plan. A settled row never reaches the write door's quota and size gate, so otherwise a replay of a held id with a huge envelope would be canonicalized for free. A fresh id is left to the write door, which meters before its own size gate.
- `AlreadyPresentIdentical` also requires the incoming envelope to hash to the `original_content_hash` it claims. A row that copies the held row's hash and producer pair onto another envelope is `ConflictingAttestation`, not a quiet duplicate.

**Mutation table.** Lane: `test(synced_door) | test(i189) | test(replicated_attestation) | test(put_attestation) | test(reput) | test(attestation_apply) | test(804) | test(directory_capsule)` plus #916's lane, `--features sqlite,postgres` under `scripts/pg_test_db.sh`. I189 includes the capsule arm (an `OpsDirectory` over each backend), (h) and (i).

| # | Mutant | Killed by |
|---|---|---|
| M1 | synced door skips the plan | I189 direct and capsule; two-node |
| M2 | decoration-only turned into a conflict on Sync | I189 direct and capsule |
| M3 | conflict reported as `Deduplicated` | I189; `apply_conflicting_row_is_refused_pre_write` |
| M4 | writes as `Authored` (no metering) | I189 metered; `privileged_sync_door_*_804` |
| M5 | `Unchanged` reported as `Inserted` | I189; two-node; `apply_identical_reoffer_is_unchanged` |
| M7 | meters as the wire door | I189 metered; `privileged_sync_door_*_804` |
| M8 | capsule synced far side uses the untyped door | I189 capsule; two-node |
| M9 | capsule unattributed far side uses the untyped door | I189 capsule; two-node |
| M10 | `AlreadyHeld` reported as `Inserted` | plan-free unit test (`apply_without_a_plan_maps_duplicate_key_to_store_conflict`) |
| M11 | size gate before the plan removed | I189 (i) |
| M12 | claimed `original_content_hash` trusted | I189 (h) |

## 8. Three CC adopts: #925, #927, #928

Three CC 1.0-rc5 rules (CIRISConstitution PR #113), witnessed on both backends by `federation::rc5_adopts_invariants`.

### 8.1 #925 — infrastructure does not vote (CC 3.2, CIRISServer#537)

**Basis.** CC 3.2 "Infrastructure does not vote": a key whose `identity_type` includes `node` MUST NOT carry `role: founder` in an `infrastructure` community and MUST NOT be counted in its `consensus_protocol`. A substrate MUST refuse at admission a `community` row or `supersedes` that lists one as founder (`hard_case:community_consensus_protocol_violation`, CC 3.4.2), and a roster fold MUST drop such a seat. CC 3.4.7.3 Clause A: a key whose set contains `node` MUST NOT also contain `agent` or `user`.

**Implementation.**
- `node`-bearing (`federation::is_node_bearing_key`): the key's own `federation_keys` set contains `node`, or it is an ACTIVE, agreed occurrence of an identity whose set does (`active_identities_for_occurrence`, §8.7).
- Admission (`admission::check_infrastructure_founders_not_node`, rule `node_bearing_founder`): at `put_community` on both backends, at the supersede door (`group_amendment::supersede_community_signed`, so `supersede_community` / `supersede_community_with_quorum` / `supersede_affiliations`), and at `put_community_membership_widening` on both backends (a widening that seats a founder is the supersede of the CC 3.2 ceremony). The replicated amendment route is covered because `put_community` runs the check on the offered record before `route_occupied_community`.
- Fold: `consensus::Seat` carries `node_bearing`; `consensus::eligible` drops a node-bearing seat in an `infrastructure` group whatever its role tag, so it neither votes nor counts in the denominator. The evaluator stays pure: the set is resolved from the roster reads (`federation::community_node_bearing_seats`, over the record's members and every widened member, only for an `infrastructure` community) and threaded in through `RosterRules::node_bearing` (`RosterRules::of_community(c, &nodes)` requires it, so no caller can forget it) and through `verify_membership_quorum`'s seat builder.
- Agreement. The occurrence gate admits a row whose signer is the IDENTITY itself (`check_signer_acts_for`), so the occurrence never has to consent. Counting every active occurrence binding would let any registered `node` key N sign `{identity: N, occurrence: H}` for a human founder H and strip H's vote in every infrastructure fold and every replay.
  - `is_node_bearing_key` counts an occurrence binding only when the occurrence AGREED (`federation::occurrence_agreed_to`): either a stored signed occurrence row for the pair whose signer is the occurrence, or the occurrence's own live owner-binding naming the identity (`owner_of`).
  - A trusted-local (unsigned) row carries no agreement.
  - Open: CIRISPersist#932 — #873's principal resolver (`active_identities_for_occurrence`, used by the hold-side audience and write-side principal resolution) has the same unilateral-claim shape.
  - Witness: `identity_claim_alone_is_not_node_bearing_founder`.
- Clause A (`register::check_node_identity_exclusive`): run by every backend's `put_public_key` right after `validate_registration_pubkey`, so every local mint (`register_federation_key` verifies, then stores through `put_public_key`) runs it; the other doors that write `identity_type` are listed in §8.5(6). Typed refusal `Error::NodeIdentityNotExclusive` (`federation_node_identity_not_exclusive`, Python `ValueError`).
- Refusal type: `Error::CommunityConsensusProtocolViolation { community_key_id, rule, detail }`, `kind()` `federation_community_consensus_protocol_violation`, Display beginning `hard_case:community_consensus_protocol_violation:{community_key_id}`, Python `ValueError`.

**Witnesses** (sqlite, postgres): `node_key_cannot_be_infrastructure_founder` (record door by own set and through the occurrence; conformant as member; supersede door; widening door); `node_founder_seat_does_not_vote` (a room admitted with `{human, install}` founders under `quorum:1/2`; the install's scrub admits a widening; once the install is bound as an occurrence of a `node` identity its scrub no longer admits one and the human's does); `clause_a_fused_key_is_not_minted`. Unit: `consensus::tests::node_founder_seat_is_not_eligible` (the `quorum:1/2` vector).

### 8.2 #927 — the family-quorum plane is the ceremony plane's family form (CC 3.2 T2, 3.4.7)

**Basis.** CC 3.2 T2: the ceremony plane is a co-scrub by a family roster reaching that family's `consensus_protocol`; the HUMANITY_ACCORD 2-of-3 is its shipped instance, a keyless family confers on it by the same mechanism, and the plane is named by the row's scrub set. CC 3.4.7: a keyless family's charter is `delegates_to(member → family_id)` bearing `trust:charter:v1` whose scrub set reaches the family's protocol, the family derived from the verified signers. CC 3.2 conformance: an `infrastructure` community's protocol MUST be `quorum:M/N`.

**The plane.** `family_quorum_over` derives the family from the verified scrub set against this node's own rosters (no granter-declared field), and `check_family_charter_admission` refuses a charter naming a family that does not carry its quorum. On the wire `TrustedGrant::conferral_plane` serializes three values, and `ConferralPlane` documents the mapping (`Delegation` → delegation; `AccordCoScrub` → ceremony, shipped instance; `FamilyQuorum` → **ceremony plane, family form**).

**Gate.** `admission::check_infrastructure_consensus_protocol` (rule `protocol_not_quorum_m_of_n`): an `infrastructure` community whose protocol is not a conformant `quorum:M/N` (§8.7 M1; `founder_only`, `unanimous`, bare `majority`, `weighted:`, `custom:`, `reverse_quorum:` and `quorum:0/N` are not) is refused at `put_community` and at the supersede door, not evaluated. `family_charter_threshold`'s floors stay (they are the family plane's reading) and its doc points at this refusal. Witness: `infrastructure_protocol_must_be_quorum` (sqlite, postgres; each non-conformant form refused and not stored, the same form admitted outside `infrastructure`, and a supersede to `majority` refused).

### 8.3 #928 — a 5-hop delegation default; 16 is the ceiling (CC 4.1.1)

**Basis.** CC 4.1.1: traversal depth is capped at 5 hops by default (configurable); longer chains are `attestation:self_verify` only; a substrate MAY clamp any requested depth at a ceiling (16), which bounds the walk and does not raise the default.

**Implementation.**
- `topology::DEFAULT_DELEGATION_DEPTH = 5` and `effective_delegation_depth(Option<usize>)`. `MAX_DELEGATION_DEPTH` and `MAX_WITHDRAWS_DELEGATION_DEPTH` are 16 and are documented as ceilings. `admission::MAX_MODERATION_DELEGATION_DEPTH` is defined as `DEFAULT_DELEGATION_DEPTH`, so the two cannot drift.
- The general walk: `build_delegation_graph(dir, from_key, max_depth: Option<usize>)`. `None` walks 5 hops; `Some(n)` is the opt-in, clamped at 16. `DelegationGraph::depth_outcome` (`WithinCap` / `BeyondCapSelfVerify`, `#[serde(default)]`) reports a chain that continues past the cap.
- The withdraws walk: `resolve_withdraws_admission_rule` (the `put_attestation` gate, which has no caller depth) runs rules 3 and 4 at the default (§8.5(8)). A refusal carries `WithdrawsNotAdmitted::beyond_delegation_depth_cap`.
- The shared scoped walk (`scoped_delegation_reach`) records `beyond_cap`; `reachable_under_scope_with_reasons` returns `ReachabilityVerdict::BeyondDepthCap` (pyo3 token `beyond_depth_cap`). The precedence is `Reachable`, `RetractedAtRoot`, `MissingScope`, `NoTrustRoots`, then `BeyondDepthCap`, then `SignerUnreached`: an issuer with no edges at all is `NoTrustRoots` whatever the cap.
- "Beyond the cap" is detected, not guessed: a traversable recipient at the cap that itself emits an onward `delegates_to` (carrying the scope, under the lens, for the scoped walk). The probe reads that recipient's out-edges once and stops at the first hit. Under a zero cap the probe is asked of the root (§8.12, F4).
- Surfaces: pyo3 `delegates_to_graph(from_key, max_depth=None)`. The capsule op `BuildDelegationGraph { max_depth: u32 }` passes `Some(max_depth)`: capsule callers always name a depth.

**Witnesses** (sqlite, postgres): `delegation_graph_defaults_to_five_hops`, `withdraws_walk_depth_defaults_to_five_hops`, `moderation_walk_depth_defaults_to_five_hops`. In each, a 6-hop chain does not confer at the default, is reported as beyond the cap, and confers at an explicit `max_depth = 6`. Controls: a 5-hop chain is `WithinCap`, a stranger's refusal carries `beyond_delegation_depth_cap: false`, and an unreached target inside the cap is still `SignerUnreached`.

### 8.4 Evidence

`evidence/cc_impl.tsv` rows:
- CC 3.2 `CLM-infrastructure-does-not-vote`: `check_infrastructure_founders_not_node`, `consensus.rs#eligible`, `community_node_bearing_seats`.
- CC 3.2 `CLM-infrastructure-quorum-m-of-n`: `check_infrastructure_consensus_protocol`.
- CC 3.4.7.3 `CLM-node-exclusive-at-mint`: `check_node_identity_exclusive`.
- `CLM-family-root-charter`: CC 3.2 `ConferralPlane` and `family_quorum_over`; CC 3.4.7 `check_family_charter_admission`.
- CC 4.1.1 `CLM-delegation-depth-default`: `DEFAULT_DELEGATION_DEPTH`, `build_delegation_graph`, `resolve_withdraws_admission_rule`.

### 8.5 Scope notes and what is not built

1. **The refusal is typed.** `hard_case:community_consensus_protocol_violation` is a typed error whose message carries the CC token. It is a refusal, not a `hard_case:*` observability emission: no event row is written.
2. **Only the `node` half of the founder rule.** CC 3.2 also says a founder's set includes `user`; only the `node` exclusion is built. `consensus_protocol_entrenched MUST be true` and `admission_quorum_basis: founders` are enforced for the trust-root-grade row (§9) but not for every infrastructure community (`Community` carries no entrenched field). These are open.
3. **Keyed on the label, for a record authored here** (§8.7 M6 narrows the record door). Both conformance gates fire on `cohort_subkind: infrastructure` whether or not the community is *authorized* (`is_authorized_infrastructure_community`). An unauthorized label gets the stricter treatment everywhere else, and a conformance rule that an unauthorized label could skip would be the weaker one.
4. **The widening door checks only the founder rule.** A widening is not a protocol change. A stored infrastructure community with a non-`quorum:` protocol keeps admitting widenings under the protocol it stored. It is refused the next time its record is put or superseded.
5. **Node-bearing is judged at each change's instant** (§8.7 item 5), so a binding asserted later does not overturn roster changes validly admitted before it, and a revocation does not give the vote back for past events.
6. **Clause A runs on every door that writes `identity_type`.** The doors are:
   - `put_public_key`: every local mint (the replicated `Insert` arm is data — §8.7 M5).
   - `adopt_scrub_upgrade`: the replicated `Upgrade` arm, which CAN change `identity_type`.
   - `supersede_canonical_record`: the replicated `Supersede` arm.
   - `adopt_genesis_reanchor`.
   - `seed_genesis_accord_holders`.
   - The rebind door (`register::prepare_rebind`).
   - `add_peer_record` (§8.7, H3's fifth door).

   It is not in `verify_key_registration`: every door above runs it. A fused key stored before the gate is refused any rewrite of its record (it re-mints), and Clause B still gates it where it sits. The Clause B witnesses (`hybrid_node_agent_key_still_refuses_agency_773`, `node_agent_hybrid_carries_agency_admitted{,_sqlite}`, `pg_node_agency_duplicate_identity_type_token`) plant their fused key below the door, because the door refuses to mint it. The upgrade and supersede doors are witnessed by `clause_a_on_the_rewrite_doors_{sqlite,postgres}`.
7. **"Infrastructure family" is not representable.** A `Family` has no `cohort_subkind`, so #927's refusal is on communities. `family_quorum_over` has no identity filter: #925 is scoped to `infrastructure` communities.
8. **The withdraws WRITE gate walks 5 hops, and each stored row keeps the depth it was admitted under** (V157).
   - **The write gate** (`check_withdraws_admission`) walks rules 3/4 at the node's `withdraws_delegation_depth()`: the CC 4.1.1 default (5), unless the host opted in with `set_withdraws_delegation_depth(n)`, clamped at 16. A NEW withdraws over a chain deeper than that is refused with `beyond_delegation_depth_cap: true`.
   - **The depth is recorded with the row, in ONE transaction.** V157 holds `federation_withdraws_admission_depths(attestation_id, depth)` on sqlite and postgres. `put_attestation` writes the row and its depth in one transaction on both SQL dialects, so a failed depth write rolls the row back.
   - **Repair.** An identical re-put of a held `withdraws` whose depth is missing records it, on both `AlreadyHeld` paths (the structural-composer dedup and the id collision) on both backends.
   - **The local-tier doors** (`attestation_insert_local` / `_upsert_local` → `sqlite_write_local_attestation`, `pg_write_local_attestation`) also record the node's depth for a `withdraws` row, in their own transaction. A local row becomes a federation row IN PLACE at `enter_mesh`, where `list_attestations_referencing` sees it. The blob doors (`put_blob_with_scope`, `adopt_sealed_blob_at`) write holding claims and never a `withdraws`.
   - **Backfill.** V157 backfills every `withdraws` it finds at 16 (the walk those rows were admitted under). A row with nothing recorded reads as 16. The bytes are pinned in `evidence/migration_checksums.tsv`.
   - **The pub read form.** `admission::check_withdraws_admission_as_admitted(dir, row)` re-derives a STORED withdraws at the row's recorded depth (nothing recorded reads as 16). `blob_tombstone::retiring_composer` uses it. CIRISServer's `drive.rs` (`withdrawn_by`) and CIRISEdge's `blob_swarm/revocation.rs` must call it instead of the write form: the write form walks the node's current depth, so it un-retires. The capsule proxy forwards the recorded depth (op `WithdrawsAdmissionDepth`) and never guesses.
   - **The bytes-plane fold re-derives at the ROW's depth.** `blob_tombstone::retiring_composer` re-walks the edges as they stand now (#853: re-derive, never read the stored rule), at `withdraws_admission_depth(row)`. So a withdraws backfilled at 16 keeps retiring what it retired, and a withdraws admitted by the deferred arm (target absent at admission) cannot retire bytes through a chain deeper than the gate that admitted it walked.
   - **Witnesses:**
     - `withdraws_retire_at_their_admission_depth` (sqlite, postgres; the runner sets the opt-in):
       - (A) a deferred 6-hop withdraws recorded at 5 does not retire;
       - (B) with the target present it is refused, too deep;
       - (C) under an opt-in to 6 it is recorded at 6 and retires;
       - (D) the pub `check_withdraws_admission_as_admitted` admits a 16-depth row and a 6-depth opt-in row, and refuses (A)'s 5-depth deferred row.
     - `sqlite::tests::withdraws_admission_depth_is_backfilled` (V156 → V157 migration witness): a withdraws stored before V157 gets 16; a non-withdraws row gets nothing.
     - `withdraws_depth_is_written_with_the_row_{sqlite,postgres}`: with the depth store broken, the put fails and leaves NO attestation row; healed, it lands at 5; with that depth deleted, an identical re-put is `AlreadyHeld` and restores it.
     - `local_withdraws_records_its_depth`.
     - The capsule `withdraws_admission_depth_op_forwards_the_recorded_depth`.
   - **Mixed fleet.** A node whose withdraws gate walks 16 hops admits a 6-to-16-hop withdraws that this gate refuses at its replicated door; the bytes it withdraws stay live on this node.
9. **Fixtures.** Infrastructure community fixtures declare a conformant `quorum:` protocol through `tier_ingest::test_support::fixture_protocol`.

### 8.6 Mutation table

Lane: `test(consensus) | test(infrastructure) | test(founder) | test(charter) | test(delegation) | test(depth) | test(clause) | test(trust_root) | test(rc5_adopts) | test(abi_version) | test(replicated_community) | test(backfilled) | test(node_move) | test(withdraws_depth) | test(withdraws_admission_depth_op)`, `--features sqlite,postgres` under `scripts/pg_test_db.sh -- cargo nextest run -j 3`, the postgres legs against a database. Each mutant is applied to a clean tree and reverted before the next.

| # | Mutant | Killed by |
|---|---|---|
| M1 | node founder counted in `eligible` | consensus unit; fold vector; item-5 |
| M2 | Clause A dropped | Clause A mint; rewrite doors; replicated-insert (local-mint arm) |
| M3 | infrastructure protocol always conformant | protocol witness; M6 witness |
| M3b | protocol check dropped from record conformance | protocol; door-split; capsule door test |
| M4 | default depth 16 | the four depth witnesses |
| M5a | graph over-cap as `WithinCap` | graph witness |
| M5b | scoped walk never records `beyond_cap` | withdraws, moderation, admission-depth witnesses |
| M6 | moderation default decoupled | moderation witness |
| M7 | fold seat `node_bearing: false` | fold vector; item-5 |
| M8 | supersede door unguarded | protocol; M6; founder |
| M9 | occurrence resolution dropped | every occurrence-based witness |
| M10 | withdraws write gate at 16 | admission-depth witness |
| M11 | sqlite widening door unguarded | founder witness, sqlite |
| N1 | agreement dropped | H1 witness |
| N3 | sqlite `adopt_scrub_upgrade` Clause A dropped | rewrite doors sqlite |
| N4 | postgres `supersede_canonical_record` Clause A dropped | rewrite doors postgres |
| N5a | parser accepts `M = 0` | protocol witness |
| N5b | parser drops `M ≥ 2 when N ≥ 2` | protocol witness |
| N6 | `N` not compared with the founder count | protocol witness |
| N7 | roster founder-count guard dropped | `infrastructure_founder_count_is_fixed_by_the_record` |
| I5a | item 5 judged at now | fold vector; item-5 |
| I5b | revocation instant ignored | item-5 (step 4) |
| I5c | interval starts at the read instant (the node-local-instant shape) | every occurrence-based witness |
| P1 | last-founder rule counts node-bearing founders | last-founder witness |
| P2 | root-authority cut dropped | moderation-root witness |
| P3 | reverse-quorum duty holders keep node-bearing founders | `node_bearing_founder_is_no_reverse_quorum_duty_holder` |
| P5 | `add_peer_record` Clause A dropped | `clause_a_peer_record_is_a_local_mint` |
| R2 | sqlite replicated insert refuses fused keys | replicated-insert sqlite |
| R3 | authored-elsewhere never data | M6; the three keyed fold witnesses |
| R4 | identical re-put not settled on the local door | door-split |
| R5 | no-founder refusal dropped | protocol witness |
| H3a | sqlite `adopt_scrub_upgrade` node-immutable dropped | rewrite doors sqlite |
| H3b | postgres `supersede_canonical_record` node-immutable dropped | rewrite doors postgres |
| U1 | `check_node_identity_unchanged` never refuses | the unit pin; rewrite doors |
| D1 | local door lenient (sqlite) | protocol, founder, H1 and door-split witnesses on sqlite |
| D2 | replicated entry strict (sqlite) | door-split; the legacy plants; the degrade witness |
| DG1 | the degrade check dropped | `replicated_supersede_never_degrades_a_conformant_room` |
| SL1 | the self-leave exemption dropped | `infrastructure_founder_count_is_fixed_by_the_record` |
| W1 | bytes-plane re-derivation at 16, ignoring the recorded depth | `withdraws_retire_at_their_admission_depth` (A) |
| W2 | sqlite records the default, ignoring the opt-in | the same witness, sqlite (C) |
| T1 | sqlite commits the row before the depth write | `withdraws_depth_is_written_with_the_row_sqlite` |
| T2 | postgres commits the row before the depth write | `withdraws_depth_is_written_with_the_row_postgres` |
| RP1 | sqlite dedup-path repair dropped | the same sqlite witness (the repair step) |
| AH1 | the pub read form walks the node's current depth | `withdraws_retire_at_their_admission_depth` (D) |
| CP1 | the capsule op returns `None` | `withdraws_admission_depth_op_forwards_the_recorded_depth` |
| LD1 | sqlite local door records no depth | `local_withdraws_records_its_depth` sqlite |

The id-collision repair path for a `withdraws` is reachable only when the structural-composer dedup does not match first. For an identical re-put the dedup always matches first, so a mutant of that second repair is equivalent; it is kept as a belt and not claimed as witnessed.

### 8.7 Node-bearing at the change's instant; the infrastructure record gates

**Item 5 — node-bearing is judged at the change's instant.** Node-bearing has two sources, judged differently (`federation::NodeBearingSeats`, built by `community_node_bearing_seats` / `node_bearing_of`):
- **The key's own `identity_type` contains `node`.** Fixed at mint: Clause A refuses a fused mint, and every rewrite door refuses moving `node` in or out (H3, below). So it holds at every instant, and reading it from current state is right.
- **The key is an agreed occurrence of a `node` identity.** This is a relation with a start (the signed `asserted_at`) and an end (a revocation's `effective_at` in force against that assertion — the #421 re-establishment rule — or `valid_until`). It is the same kind of thing as a `moderate` delegation, so it is judged at the act's instant with no ending retroactive (`FSD/ROOM_ROSTER_AUTHORITY.md` §2–§3, I175/I175b).
  - The fold's seat builder asks `NodeBearingSeats::at(key, event.effective_at)` per event; the evaluator stays pure.
  - The widening door judges the new seat at the widening's `effective_at`; the record doors and the quorum-gated supersede judge now.
  - A node-local `admitted_at` is never used. `asserted_at` is signer-chosen and backdatable, which is why the agreement rule (§8.1) comes first: with the occurrence's own consent, a backdated claim is the key's statement about itself.
  - Witness `node_bearing_is_judged_at_the_change_instant` (sqlite, postgres), steps (1)–(5). `node_founder_seat_does_not_vote` pins that `second`, admitted before the binding, still stands.
  - **Final over every assertion (CIRISPersist#930).** The occurrence plane upserts the LATEST assertion per `(identity, occurrence)`, so a renewal moves a binding's start forward and an identity re-signing the pair replaces the occurrence's own agreement row. So the fold does not read that plane alone: V161 holds `federation_identity_occurrence_history`, append-only, and both put doors (signed and trusted-local) write every admitted assertion in the upsert's transaction, including one OLDER than the stored row (the upsert declines it; it is still a verified assertion). The fold (`node_bearing_of`) reads `list_identity_occurrence_history_by_occurrence`; each assertion contributes `[max(asserted_at, agreed_from), end)`, `end` as above; agreement is an INSTANT, the occurrence's first own signature (`occurrence_agreed_from`; `occurrence_agreed_to` is its `is_some()`). A trusted-local row bounds an interval and is never agreement. V161's backfill copies the rows the plane held, so verdicts over instants before V161 are the latest-assertion ones. Witnesses I270–I278 (sqlite, postgres).

**M1 — one infrastructure quorum parser.** `admission::infrastructure_quorum(protocol) -> Option<(M, N)>`: `quorum:M/N` with `1 ≤ M ≤ N`, `N ≥ 1`, and `M ≥ 2` whenever `N ≥ 2` (CC 3.2: "a single founder must not be able to admit unilaterally"). `quorum:1/1` is conformant. #926 folds onto this parser. An infrastructure record naming no founder is refused (`INFRA_RULE_NO_FOUNDER`). Witnessed: `0/1`, `0/3`, `1/2`, `1/3` refused; `1/1` and `2/3` admitted; no founder refused.

**`N` is the founder count.** The evaluator reads `quorum:M/N` with an ABSOLUTE `M` and never compares `N` with the founders, so `quorum:1/1` over three founders would let one of them admit alone.
- `check_infrastructure_consensus_protocol` requires `N` == the record's founder count (`INFRA_RULE_QUORUM_N_NOT_FOUNDERS`), on top of the parser's `M ≥ 2 when N ≥ 2`.
- In a CONFORMANT infrastructure room, `check_infrastructure_founder_count_unchanged` refuses any widening (add, promote, demote) or revocation that would move the founder count, at the widening and revocation doors of both backends. The founder set moves by a supersede that re-declares `N`.
- **Founder self-leave is exempt** (the consent floor of `ROOM_ROSTER_AUTHORITY.md` §2). A revocation signed by the removed founder is admitted, as `roster_event_standing` admits any self-leave. **Consequence:** N is the founder count AS ADMITTED. A self-leave may leave the remaining founders unable to reach M. The room is then frozen (no roster change, no supersede) until its conferring authority re-founds it; for `ciris-canonical`, that is an accord re-birth. The last-founder rule still refuses the last founder's leave.
- A legacy non-conformant room (replicated data) is not re-judged on its roster plane.
- The record checks run in this order: a founder exists, then the protocol and its `N`, then node-bearing founders.
- **Witnesses:**
  - `infrastructure_protocol_must_be_quorum`: `quorum:1/1` over 3 founders and `quorum:2/3` over 2 are refused; `2/3` over 3 is admitted.
  - `infrastructure_founder_count_is_fixed_by_the_record`: under `quorum:2/3` over 3 founders, two founders adding a fourth is refused, and two founders removing the third is refused. A plain member is admitted, and the third founder leaving on their own signature is admitted.

**M2 — a node-bearing founder has no founder power outside the ballot** (infrastructure only; the set is empty elsewhere), judged at each change's instant:
- **Moderation roots.** `root_authority_intervals` cuts the instants a founder bears `node` out of its authority, so it roots no `moderate` chain then. `moderator_roots_at` reads only those intervals, and `founder_candidates` is unchanged because a candidate with no interval roots nothing. An appointment made while the root held authority keeps standing after (no ending is retroactive), so the witness binds before appointing.
- **The last-founder rule.** A node-bearing founder is neither a founder that can be lost nor the founder a change leaves behind.
- **Reverse-quorum duty holders.** A node-bearing founder is excluded.
- **Witnesses:** `node_bearing_founder_roots_no_moderation`, `node_bearing_founder_holds_no_last_founder_power` and `node_bearing_founder_is_no_reverse_quorum_duty_holder`, each on sqlite and postgres.
  - The duty-holder witness runs two twin legacy infrastructure rooms (replicated data) under `reverse_quorum:1/7:60+escalate:0:3`. In each, the human removes `x`, one member objects in the window, the second founder UPHOLDS in the steward window, and three members OVERRULE.
  - Where the second founder is not node-bearing, it is a seated duty-holder: its ruling upholds, escalation never opens, and the removal is reversed.
  - Where it is node-bearing, nobody is seated: the tier escalates on the passed deadline, the respondents dismiss 3-to-1, and the removal stands. Its uphold counted only as one respondent ballot.

**M3 — the capsule ABI.** `ReachabilityVerdict::BeyondDepthCap` is a variant returned by an existing op (`DirectoryOpResult::Reachability`), a payload-shape change, so it moved `DIRECTORY_ABI_VERSION` (pinned by `abi_version_pinned_at_*`). The two enum-body digests do not see it: the verdict is a payload type outside their sight. `KeyRefusalReason`'s growth (below) rides the same version.

**M5 — the replicated `Insert` admits a fused key minted elsewhere.**
- `put_public_key` is the local-mint face of `put_public_key_at_door(record, KeyDoor)` on every backend. The replicated `Insert` arm reaches the same store step with `KeyDoor::ReplicatedInsert`, and Clause A gates `LocalMint` only. The admitted key is gated data: Clause B and the steward gates apply wherever it acts.
- The replicated `Upgrade` / `Supersede` arms map a Clause A or `node`-immutability refusal to typed `Refused { node_identity_fused | node_identity_changed }`, never an `Err`. The key-replication cursor lives in CIRISEdge; typed refusals are recorded and skipped rather than re-polled.
- Witness `clause_a_replicated_insert_admits_a_fused_key` (both backends): a fused replicated insert → `Inserted`; a pubkey swap over it → `Refused { pubkey_swap }`; a local mint of a fused key → `NodeIdentityNotExclusive`.

**M6 — the DOOR, not the signer, decides (CIRISPersist#931).** Telling local from replicated by the signer would switch the gate off on every real host: the Engine always sets the node key, and an infrastructure record is normally signed by its HUMAN founder, so any human-signed record would read as "authored elsewhere".
- **Two doors, strict by default.**
  - `put_community` (the trait door on both backends; pyo3 `put_community_json`; the Engine's `put_community_self_signed`) is the LOCAL door. It runs `admission::check_infrastructure_record_admission(dir, record)`, the full CC 3.2 infrastructure gate, whoever signed. An identical re-put (same `persist_row_hash`) settles.
  - `FederationDirectory::apply_replicated_community(record) -> ReplicatedCommunityOutcome` is the REPLICATED entry.
    - It returns `Inserted`, `Unchanged`, `Superseded`, or `Refused { conflicting_record | degrades_conformance }`.
    - A legacy non-conformant infrastructure record is admitted as data, and the fold's gates apply.
    - An occupied id routes through the amendment checks (`route_occupied_community`).
    - It is on the trait (default `Unsupported`), overridden by every backend, carried by the capsule op `ApplyReplicatedCommunity` / result `ReplicatedCommunityOutcome`, and exposed as pyo3 `apply_replicated_community_json`.
  - Both doors share one store step, `put_community_at_door(record, CommunityDoor)`. A replication bridge (CIRISEdge) uses the replicated entry.
- **The local supersede doors are always judged.**
- **A conformant room never degrades through the replicated door.** `admission::check_replicated_supersede_does_not_degrade` refuses a received record that would supersede a STORED infrastructure record which passes conformance with one that fails it: `founder_only`, bare `majority`, a node-bearing founder, `N` ≠ founders. This holds whatever founders' proof the record carries (CC 3.2: a weakening supersede MUST be rejected). The refusal is typed: `Refused { degrades_conformance }`. A legacy room — nothing stored, or the stored version already non-conformant — still syncs. Witness `replicated_supersede_never_degrades_a_conformant_room`: a proof-carrying supersede of a conformant `quorum:2/2` room to `founder_only`, and one seating a `node` founder under `quorum:3/3`, are both refused and change nothing; a legacy `majority` room still takes a proof-carrying supersede (`Superseded`).
- **Witnesses:**
  - `infrastructure_record_authored_elsewhere_is_data` (two nodes, BOTH with their node key SET):
    - a human-signed `founder_only` infrastructure record through the local door is refused;
    - the same record through the replicated entry is `Inserted`, and re-applied it is `Unchanged`;
    - an identical re-put through the local door settles, and a changed one is refused;
    - a supersede is refused;
    - the second node syncs the record through its replicated entry.
  - The capsule witness `apply_replicated_community_op_is_the_replicated_door`.
  - The fold-vector, item-5 and last-founder fixtures plant their legacy rooms through `apply_replicated_community`.
- **Widening door.** It refuses seating a node-bearing founder, whatever the signer, so a replicated legacy widening that seats one does not sync.

**H3 — `node` never moves on a rewrite.**
- `adopt_scrub_upgrade`, `supersede_canonical_record` and `adopt_genesis_reanchor` (sqlite, postgres) refuse a rewrite that adds or removes `node` (`Error::NodeIdentityImmutable`, `federation_node_identity_immutable`, `ValueError`). The stored row is unchanged.
- Witnessed on the upgrade and supersede doors (`clause_a_on_the_rewrite_doors_{sqlite,postgres}`: adding `node` to a `user` key, removing it from a `node` key). The pure predicate `check_node_identity_unchanged` is pinned by the unit test `check_node_identity_unchanged_refuses_only_a_node_move`.
- **`adopt_genesis_reanchor`: BELIEVED, not tested.** The check cannot be reached from any lane.
  - The door runs `verify_bundle_quorum` before the check. That function authenticates the bundle against `effective_accord_holder_records()`, which on every lane this repo certifies is the compiled-in production roster: hardware-held keys whose private halves no test holds.
  - The only override is the `test-anchor` feature together with verify's runtime `CIRIS_TEST_TRUST_ROOT*` AND-gate. No certify lane compiles that feature, and even under it persist never holds the test root's private key: the harness signs.
  - A fabricated bundle would prove a property of the fabrication.
  - The check sits beside the upgrade and supersede doors' identical, witnessed call.
- **The fifth door — `add_peer_record` is a local mint.** `check_peer_record_admission` runs Clause A on the record the door would write (a caller-supplied `identity_type`). It is reachable from pyo3 `add_peer_record_json` and the capsule op. Witness `clause_a_peer_record_is_a_local_mint`.
- Rebind (#864) refuses any `identity_type` change; its door also runs Clause A.

**Details.**
- `occurrence_agreed_to` has no owner-binding arm. It could only fire for a fused identity stored before the gate, where it is unilateral again.
- The NEW refusals on the apply doors are typed (`node_identity_fused` / `node_identity_changed`, and on the community plane `conflicting_record` / `degrades_conformance`). Not every error of every apply arm is, and the replicated community outcome's doc says "the refusals are typed", not "every arm is Ok".
- **Open:** a revocation's signer-chosen `effective_at` can reach back before the act it ends. A clamp needs an instant the revoker cannot choose, and the only such instant is the receiver's own clock, which differs per node. Which signed instant bounds it is an open question.
- `WithdrawsNotAdmitted`'s Display carries `beyond_delegation_depth_cap`, and the pyo3 reachability token list names `beyond_depth_cap`.
- The withdraws walk's caller opt-in up to the ceiling is `check_withdraws_admission_at` / `resolve_withdraws_admission_rule_at` (pub).
- Every witness key leads with its distinguishing part (`human-{tag}`, `install-{tag}`, `k{i}-{chain}-{tag}`, …), because test signers seed from a key id's first 32 bytes.

**Shared symbols (#926 folds onto them).**
- `admission::COHORT_SUBKIND_INFRASTRUCTURE` (the one constant) and `admission::infrastructure_quorum`.
- `federation::is_node_bearing_key` / `is_node_bearing_key_at` / `node_bearing_of` / `occurrence_agreed_to`.
- `Error::CommunityConsensusProtocolViolation` with rule constants `INFRA_RULE_NODE_BEARING_FOUNDER`, `INFRA_RULE_PROTOCOL_NOT_QUORUM`, `INFRA_RULE_NO_FOUNDER`, `INFRA_RULE_SUBKIND_NOT_INFRASTRUCTURE`, `INFRA_RULE_BASIS_NOT_FOUNDERS`, `INFRA_RULE_NOT_ENTRENCHED`, `INFRA_RULE_FOUNDER_NOT_CONFERRED`, `INFRA_RULE_GRADE_CHANGED`, `INFRA_RULE_QUORUM_N_NOT_FOUNDERS`.

### 8.8 Surface

- **Errors** (`kind()` token, Python type):
  - `CommunityConsensusProtocolViolation {community_key_id, rule, detail}`: `federation_community_consensus_protocol_violation`, ValueError.
  - `NodeIdentityNotExclusive {key_id, identity_type}`: `federation_node_identity_not_exclusive`, ValueError.
  - `NodeIdentityImmutable {key_id, stored, offered}`: `federation_node_identity_immutable`, ValueError.
  - `WithdrawsNotAdmitted` carries `beyond_delegation_depth_cap: bool` (in Display too).
- **Typed outcomes:**
  - `ReachabilityVerdict::BeyondDepthCap` (pyo3 `beyond_depth_cap`).
  - `KeyRefusalReason::NodeIdentityFused` (`node_identity_fused`) and `NodeIdentityChanged` (`node_identity_changed`), appended.
  - `DelegationGraph::depth_outcome: DelegationDepthOutcome {WithinCap, BeyondCapSelfVerify}` (`#[serde(default)]`).
  - `CommunityDoor {Local, ReplicatedApply}`; `ReplicatedCommunityOutcome {Inserted, Unchanged, Superseded, Refused{reason}}`; `ReplicatedCommunityRefusal {ConflictingRecord, DegradesConformance}` (`conflicting_record`, `degrades_conformance`).
- **Signatures:**
  - `build_delegation_graph(dir, from_key, max_depth: Option<usize>)`; pyo3 `delegates_to_graph(from_key, max_depth=None)`.
  - `check_withdraws_admission_at` / `resolve_withdraws_admission_rule_at` (pub); `admission::check_withdraws_admission_as_admitted` (pub).
  - `RosterRules::of_community(c, &NodeBearingSeats)` and the `RosterRules::node_bearing` field; `community_roster_events(dir, c, &NodeBearingSeats)`; `consensus::Seat::node_bearing`.
  - `admission::check_infrastructure_founders_not_node(dir, community, at)`; `check_infrastructure_record_admission(dir, community)`; `check_infrastructure_founder_count_unchanged` (with a `self_leave` parameter); `check_replicated_supersede_does_not_degrade`.
- **Pub items:**
  - `topology::DEFAULT_DELEGATION_DEPTH`, `effective_delegation_depth`, `DelegationDepthOutcome`.
  - `NodeBearingSeats`, `NO_NODE_BEARING_SEATS`, `InstantInterval`, `community_subkind`, `is_node_bearing_key{,_at}`, `node_bearing_of`, `occurrence_agreed_to`, `community_node_bearing_seats`.
  - `admission::{infrastructure_quorum, check_infrastructure_consensus_protocol, check_infrastructure_founders_not_node, check_infrastructure_community_conformance, check_infrastructure_record_admission}` and the rule constants.
  - `register::{check_node_identity_exclusive, check_node_identity_unchanged, KeyDoor}`.
- **Trait:** `FederationDirectory::apply_replicated_community`; `withdraws_delegation_depth()` and `withdraws_admission_depth(id)`. Backends: `set_withdraws_delegation_depth(n)`.
- **Capsule:** ops `ApplyReplicatedCommunity` (result `ReplicatedCommunityOutcome`) and `WithdrawsAdmissionDepth` (result `WithdrawsAdmissionDepth(Option<u32>)`).
- **pyo3:** `apply_replicated_community_json(payload_json) -> str` (classified deontic).
- **Constants:** `MAX_MODERATION_DELEGATION_DEPTH` is defined as `DEFAULT_DELEGATION_DEPTH` (5).
- **Migration:** V157 `federation_withdraws_admission_depths` (both dialects).
- **Behaviour:**
  - `put_community` judges every new or changed infrastructure record, whoever signed it: `quorum:M/N` (M ≥ 2 when N ≥ 2, N = the founder count), a founder named, no node-bearing founder. A replication bridge calls the replicated entry.
  - A fused key cannot be minted locally, no local rewrite moves `node`, and `add_peer_record` refuses a fused `identity_type`.
  - The withdraws write gate walks 5 hops; the depth is written in the row's transaction and repaired on an identical re-put; the local-tier doors record a `withdraws` row's depth.
  - A node-bearing seat in an infrastructure room neither votes nor holds founder powers, judged at each change's instant.
  - A conformant infrastructure room's founder count is fixed by its record; a founder may self-leave (the room may then freeze); a conformant room never degrades through the replicated door.

### 8.12 Read faults, write outcomes, and the zero cap (F2, F3, F4)

**F2 — a transient read failure is never "legacy".** The replicated door's `check_replicated_supersede_does_not_degrade` re-judges the STORED infrastructure row to decide whether it is legacy. Only the typed `CommunityConsensusProtocolViolation` is legacy; the conformance check returns it for each of its rules (no founder, protocol not `quorum:M/N`, `N` not the founder count, a node-bearing founder). Any other error propagates, so a failed node-bearing or roster read cannot let a degrading supersede of a conformant room in. The #925/#927/#931 gates (`check_infrastructure_*`, the `is_node_bearing_key_at` callers, `community_node_bearing_seats`, `node_bearing_of`, `occurrence_agreed_to`, the backends' door call sites) swallow no directory read.

- (f2_a, the gate) Through the fault double with the occurrence read failing, the gate returns the read error, never the legacy pass. A room non-conformant by its protocol is decided before any read and stays legacy.
- (f2_b, the door) The occurrence read fails ONCE, inside the door, and succeeds after. A persistent fault cannot witness this, because the later quorum fold rereads the same plane and fails too. `apply_replicated_community` returns the error, not `Superseded`, and the stored row is unchanged. Offered again, it is refused `degrades_conformance`.

**F3 — the outcome is what the write did.** `apply_replicated_community` does not pre-read the id: a concurrent apply of the same record between a read and the write would make the write an idempotent no-op while the outcome said `Inserted` or `Superseded`. `put_community_at_door` returns `CommunityWrite` (`Inserted` / `Unchanged` / `Superseded`), decided under the write's own serialization:

- sqlite: `INSERT OR IGNORE` and the re-read in one writer closure;
- postgres: the `INSERT … ON CONFLICT DO NOTHING` row count;
- a supersede: its prior-hash check under the backend's lock.

A supersede that loses its race fails that check stale; if the row now held IS the offered version, the outcome is `Unchanged`, and a Conflict over any other row stays a refusal. The trust-root route reports versions written (`apply_trust_root_chain_counted`).

- (f3_a) A test hook inside each backend (`store::test_hooks`, `cfg(test)`) applies a rival copy of the same record at a named point: the door's first line, after the route said "insert", and at a community supersede's first line. Each time, the outcome is `Unchanged`.
- (f3_b) Two applies of one record, joined: `{Inserted, Unchanged}`, then `{Superseded, Unchanged}`. The join interleaves on sqlite and postgres.

One residual: a trust-root chain whose apply writes some versions and then loses its race on a later one reports `Unchanged` when the offered version ends up held, not `Superseded`.

**F4 — a zero cap reports what it cut.** The cap probe (§8.3, `delegates_onward`) is asked of the root under a zero cap: `build_delegation_graph(.., Some(0))` on a root that delegates is `BeyondCapSelfVerify` with no edges. The scoped walk does the same, so the withdraws gate at depth 0 refuses with `beyond_delegation_depth_cap: true`; `set_withdraws_delegation_depth(0)` reaches it. `reachable_under_scope_with_reasons` at 0 is `BeyondDepthCap` when the issuer delegates the scope onward, and `SignerUnreached` when it does not. 0 is not rejected; the capsule op passes it through.

- (f4_a) Graph, moderation classifier and withdraws gate at depth 0, with and without a delegating root. The capsule op `BuildDelegationGraph { max_depth: 0 }` is witnessed.

**Mutation table** (lane and discipline as in §9.1).

| # | Mutant | Killed by |
|---|---|---|
| FM2 | any error from the stored re-judgement is legacy (`.is_err()`) | f2_a, f2_b |
| FM3a | the outcome derived from a pre-read | f3_a; f3_b sqlite, postgres |
| FM3b | a lost supersede race refused as a Conflict | f3_a (BeforeSupersede); f3_b sqlite, postgres |
| FM3c | the insert arm's lost race reported `Inserted` | f3_a (BeforeInsert); f3_b sqlite |
| FM4a | the graph's root probe dropped | f4_a; the capsule op |
| FM4b | the scoped walk's root probe dropped | f4_a |
| FM4c | the classifier at 0 always `SignerUnreached` | f4_a |
| FM4d | the root-epoch filter in the zero-cap probe dropped | equivalent by trace: the only lens with a root epoch is built at `MAX_MODERATION_DELEGATION_DEPTH` (5), never 0; kept for a future caller |

## 9. #926 — the ciris-canonical community row

**The row.** The `ciris-canonical` community row is a `community` Contribution. Its birth is signed 2-of-3 by the accord holders and admitted under the accord's quorum; the rooted row is served beside the bundle on the CC 5.3.4 route. `verify_bundle_quorum` is the only root authority: the community row adds a roster, not a second root.

**Birth by the accord, amendment by the founders (CC 3.2).** The accord holders' 2-of-3 is the row's BIRTH. On the ceremony plane it is also the conferral of each founder. After birth the row changes only by its FOUNDERS' quorum: its own entrenched `quorum:2/3` over the `founder` seats. This holds on every door:
- the local `supersede_community_with_quorum`;
- the replicated `put_community` of an amended version, which the receiver verifies as a chain link from the version it holds (or from the birth).

No door re-demands the accord count for an amendment. No door lets an amendment change the grade, `admission_quorum_basis`, `cohort_subkind` or the entrenched protocol. Every founder on every version is still accord-conferred, human and not node-bearing. A founder added by amendment needs its accord conferral to exist already.

**Founder seats move ONLY through the record.** The roster planes refuse every founder-seat change of a trust-root community, whoever signs it, the full founders' quorum included: seating a founder, re-roling one, revoking one. A founder enters by a founders' amendment. A founder exits by a founders' amendment, or by the accord withdrawing the conferral, which already stops the key counting. The planes admit and remove MEMBERS only. The reason: a fresh node verifies from the lineage alone, so the record must be the one source of who counts. A plane that moved FOLDED seats would diverge from the record: a founder revoked on the plane would keep signing counted amendments, and a plane-seated founder never could.

**Shape (CC 3.2).** The `Community` record has no `cohort_subkind` or entrenchment columns. `cohort_subkind` lives in `policy_blob`, and the rest of the CC 3.2 fields sit beside it:

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
- the replicated `apply_replicated_community` (#931's entry). It also enforces the lineage caps and walks the chain (`apply_trust_root_chain`), exactly as the local door does. A typed refusal crosses this entry as §8.7 M6 maps it: `CommunityConsensusProtocolViolation` → `Ok(Refused { DegradesConformance })`, and `Conflict` → `Refused { ConflictingRecord }`. Any other error propagates, so a short birth is `Err(RosterAuthorityUnauthorized)` on both doors.
- The one difference is the legacy allowance. On the replicated entry, a row at ANOTHER id that declares `infrastructure_constraint` but does not verify is kept as data: it reads `NotRooted`, resolves to nothing, and is never a trust root or a `trust:accepts` subject. The reserved id has no allowance on either door. I190 (q) witnesses both doors.

1. **Shape.** `cohort_subkind` is `infrastructure`, `admission_quorum_basis` is `founders`, the protocol is `quorum:M/N` with 1 ≤ M ≤ N, `consensus_protocol_entrenched` is true, and the row names at least one founder. A failure is #925's typed `Error::CommunityConsensusProtocolViolation { community_key_id, rule, detail }`, displayed as `hard_case:community_consensus_protocol_violation:{id} ({rule}): {detail}` (CC 3.4.2).
   - Shape rules use the `INFRA_RULE_*` consts.
   - The trust-root rules are the consts `TRUST_ROOT_RULE_CHAIN` (`trust_root_chain`), `TRUST_ROOT_RULE_LINEAGE_CAP`, `TRUST_ROOT_RULE_FOUNDER_SEAT_ON_PLANE` (`founder_seat_on_plane`) and `TRUST_ROOT_RULE_RESIGNATION_BACKDATED` (`resignation_backdated`).
   - `is_row_verdict` and `eligible_founders` accept the typed variant.
   - rc5's conformance (`check_infrastructure_community_conformance`) also holds here: N equals the founder count, so a founders' amendment that changes the founder set is a SWAP (one founder out, one in). Adding or dropping a seat also moves N, which is the entrenched protocol, so it is refused.
2. **Founders.** Every founder is a human key: `user` is in its `identity_type` and it is not node-bearing (`federation::is_node_bearing_key_at`, #925). That also catches a key that is an active occurrence of a node identity. A link judges this at its `amended_at`, and the door judges it at now. Every founder is also an accord-conferred `steward` whose role has not been withdrawn (`has_accord_conferred_role_over_roster`).
3. **The chain.** The offered row travels with its `lineage`: the accord-born version, then every founders' amendment, in order. The door first re-judges what is already stored at the id (`stored_standing`, below).
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
  - `next_persist_row_hash`, the version's content hash, so one proof admits exactly ONE body. Name, instants, non-founder roles and every `policy_blob` field are all bound;
  - `amended_at`, the link's signed instant. It is not before the previous link's instant or the prior version's `founded_at`, and not more than 60 s in the future (`COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS`, the substrate's one future-skew bound);
- the verified signers meet the prior version's protocol over its founder seats. A signer counts only if it is one of the prior version's RECORDED founders and counts at `amended_at`: human, accord-conferred, not withdrawn before that instant, and with no resignation in (`seated_since`, `amended_at`] (the counting rule, below). `seated_since` is read from the chain up to the prior version, so `verify_founders_link` takes that chain. Each is hybrid-verified against this node's pinned pubkeys;
- the version's authority is one of those counted founders, and its signature over the version verifies. Every lineage entry is judged this way.

The node-bearing half of "human" is #925's `is_node_bearing_key_at`, at the link's `amended_at`, at both sites (the door and `founder_counts`). A link's seats and the roster seats drop a founder that is node-bearing or does not count. Each seat carries `consensus::Seat.node_bearing`.

**Applying a chain.** The occupied-id route (`apply_trust_root_chain`) applies the offered chain VERSION BY VERSION through `supersede_group_row`, so every stored version is one a proof names exactly and the version history stays whole:
- from a rooted held version: the later links. The held version is located by POSITION and PROOF, not by content (`extends`): it sits at index `held.lineage.len()`, and the offered chain up to that index must be the held chain version for version (`same_version`: content hash, authority and founders' proof). The walk, and the lineage each applied version is stored with, is the chain this node HOLDS followed by the offered versions after the held one (`walk_from_held`). Storing the held versions is load-bearing: `same_version` does not compare signature bytes, so an offered prefix may carry bytes nobody verified (I190 (z′)). The door (`check_trust_root_community_admission`) decides the same way. An offered chain whose head has the held content is the #758 no-op;
- over a squat: from the birth, recorded as `accord_birth_replaces_unrooted`;
- over nothing: the caller inserts the offered row with its `lineage`.

The local door (`prepare_trust_root_supersede`, in `supersede_community_signed`) requires the new version to be a verified founders' link of the held one, and stores it carrying the held version's chain. For a trust root whose chain holds (`Rooted` or `Stalled`, `founders_link_is_the_quorum`), that link IS the local door's quorum: `supersede_community_with_quorum` skips the generic folded-roster `verify_membership_quorum`, so the local and replicated doors judge an amendment by one predicate. The folded roster would re-apply a resignation that a re-seat through the record has cleared, and the doors would then disagree: I190 (o) has the re-seated founder co-sign a later link on the local door. A `NotRooted` squat, an ordinary room and an absent row keep the generic quorum. The decision is taken before the prepare re-reads the standing, so it is passed down (`generic_quorum_skipped`): if the chain stopped holding in between, the prepare refuses rather than letting a non-grade version through with no quorum (the TOCTOU arm; I190 (t) calls the prepare with the flag over a NotRooted row, since the race itself cannot be driven deterministically). The `lineage` is persisted in V158 (`federation_communities.lineage`), served by the point read and the signed since-read, and never part of `signing_envelope()`.

**Chain caps.** At the door, before any signature is checked, a chain is refused if it has more than `MAX_LINEAGE_LEN` = 1024 versions (the violation token) or a `lineage` over `MAX_LINEAGE_BYTES` = 32 MiB (`Error::EnvelopeTooLarge`). The byte cap is sized so the LENGTH cap binds first, at about 15–20 KB per version. Past 1024 versions the chain restarts by compaction: the founders resign or the accord withdraws their conferrals, the row stalls, and an accord re-birth begins a new chain.

**Key rotation.** In persist a rotation is a NEW `key_id`. Persist has NO steward supersede door, so a founder's retirement is a plain accord WITHDRAW of the old key's steward conferral. The accord separately confers the successor, and the founders then swap it in through the record. `admit_response_withdrawals` therefore projects plain withdrawals only; it carries a `// FOLD(#926-rotation)` note for the day a supersede door is added. The old key record is kept, since founder key records are never deleted. A withdrawal un-counts a founder only for links whose `amended_at` is AFTER it, so the historical links that key signed keep verifying against its record. The bundle response serves the key record of every key the CHAIN names — every version's members, its authority and its proof signers — so a fresh node verifies historical links whose signers have since left.

**The withdrawal instant is node-independent.** A withdrawal un-counts a founder from the SIGNED `window_until` of the accord proposal it re-tallied. That instant is the same on every node; it is not `withdrawn_at`, the local clock at which each node recorded the row.
- A withdrawal whose proposal this node does not hold is dated MIN. That is fail-secure: a bare trusted-local write roots nothing it cannot prove. It does not merely un-count the founder from here on: every link that key signed stops verifying, so the row reads `NotRooted`, not `Stalled`. `NotRooted` opens the any-accord-birth path: any accord birth replaces the row, and it need not be founded later.
- The bundle response carries the accord evidence (proposal plus participations) of every steward withdrawal of a chain-named key, together with the co-signer key records. It is gathered by point reads: one `get_accord_proposal` per withdrawal digest, then the participations of those proposals only, never a scan of accord history on an unauthenticated GET. `pin_trust_from_bundle_response` admits that evidence through the ORDINARY evidence door (`apply_replicated_accord_evidence`, re-tallied against the consumer's own roster) and re-derives the withdrawals (`project_role_withdrawal_for_key`) before it admits the row.
- So a fresh consumer judges a retired-key fork exactly as the mesh does. A link signed after the window by a quorum that needs the retired key falls short, whenever the consumer happened to learn of the withdrawal.

Residuals, stated:
- `amended_at` is signer-chosen. A quorum of RETIRED founder keys could backdate a link to before the window. The link must still extend a version the node holds, or walk from the birth, with non-decreasing instants and prior's quorum. A node already holding the head refuses any fork that does not extend it; only a node that sees the backdated fork FIRST can be split.
- `window_until` is server-issued. A proposal with a long window keeps the retired key counting for links dated within it.
- An unsigned-freshness ROLLBACK — a server serving an older but valid prefix of the chain to a fresh consumer — is for CC's freshness rule; persist does not judge it here.

**Two rosters, on purpose.** A founder's conferral is judged against the COMPILED accord holder roster (`accord_holder_roster_key_ids`), the ceremony plane every key-plane conferral uses. The row's birth quorum is judged against the stored accord family's revocation-folded roster, the same roster the charter plane counts. These agree while no holder is removed from the family. A removed holder stops counting for a birth at once. It also stops counting for a conferral, but only once the compiled roster changes.

**Co-signatures.** Co-signatures on any community row are verified at the door, as a roster row's are (`verify_roster_cosignatures`: one that does not verify, or a doubled co-signer, is refused). They are persisted in V158 (`federation_communities.cosignatures`: pg JSONB, sqlite TEXT, default `'[]'`). Backends read them with the point read `lookup_signed_community` and serve them on the signed since-read.

**A stored row is re-judged on every read.** `stored_standing` answers `Rooted` only when:
- the signed row conforms in shape;
- its CHAIN (stored `lineage` plus the row) verifies from an accord birth, every link re-verified. There is no proof-only arm;
- EVERY RECORDED founder counts now.

If the chain verifies but a recorded founder no longer counts (a withdrawn or rotated conferral, or a resignation), the answer is `Stalled`. A stalled row is not resolved, served or trusted, but it is still the version the founders amend from: a founders' amendment retiring that seat roots it again.

**Recovery.** An accord RE-BIRTH replaces a STALLED row: a chain whose first version is a birth reaching the accord quorum, founded LATER than the held chain's birth. The route records it as `accord_rebirth_replaces_stalled`. This is how a trust root whose founders can no longer reach their quorum comes back (two compromised or rotated founders, resignations). A re-birth NEVER replaces a ROOTED row. The accord's lever over live founders is withdrawing their conferrals, which stalls the row first; it has no override of a live record.

**The consent floor: a founder resigns.** A founder's OWN plane revocation, signed by that founder alone, is admitted as a RESIGNATION. It does not move the record. From its `effective_at` the founder no longer counts and is no longer a seat in any link or in the row's standing. A later version MAY still record them, but they count as nothing until the record re-seats them, and the row is Stalled meanwhile. Every resignation of a key is kept (not only the earliest), so a second resignation after a re-seat counts. The row stalls, the remaining founders amend the seat out or re-seat the key, and if resignations make the quorum unreachable, the accord re-birth is the way out.

**The counting rule.** One rule judges links and the head alike:

> A founder counts on a version's link iff they are a founder of the PRIOR version and have no resignation in (`seated_since(F)`, `amended_at`], where `seated_since(F)` is the instant of the version that (re-)seated F: the birth's `founded_at`, or the `amended_at` of the link whose prior did not name F a founder. The head's standing applies the same rule with `now` in place of `amended_at`.

A refusal of any version that still records a resigned founder would split the mesh permanently (below); the counting rule does not.
- **The lapse, under the rule.** F resigns at t1, after the birth. The others' v6 (G + H, still recording F) is admitted; F counts as nothing, so the row is Stalled. At v6 → v7, t1 lies in (`seated_since(F)` = birth, t7], so F does not count and F + G is refused, although v6's instant is after t1. After a re-seat at v8 by the others' quorum, `seated_since(F)` = t8 > t1 and F counts again. A second resignation r2 > t8 un-counts F again. I190 (o″) walks this trace; (o‴) is the second resignation.
- **No permanent split, under the rule.** Node A holds H1 (t1). Node B holds H2 (t2), signed by F0 + F1 and still recording F2. F2 resigns at t_r, t1 < t_r ≤ t2, having NOT signed H2. A admits the resignation (t_r is after A's head). B refuses it as backdated (t_r ≤ t2). Were A to refuse H2 for still recording F2, A could only re-birth, and a re-birth never replaces B's Rooted row: a permanent split of the default root that nobody chose. Under the rule, A ADMITS H2 with F2 not counting: A is Stalled and B is Rooted. H3, which amends F2 out, is admitted by both, and both are Rooted. They converge with no re-birth. I190 (x) drives exactly this through the real doors on two nodes.
- **The held chain is the one walked, and the held version is found by position.** A node walking from a version it holds reads `seated_since` from the chain it holds. Content alone repeats: a re-seat back to the birth roster reproduces the birth's content byte for byte. Matching the held version as the FIRST offered index with its content hash would make a replica holding the re-seated head replay the old links after it, refuse every later link as `trust_root_chain`, and, being Rooted, never be replaced by a re-birth: the permanent split again. A LAST-occurrence match is no fix either, because a node holding the first occurrence would skip the links that retired and re-seated a founder and read a stale `seated_since`. So the held version is matched at its own index, version for version. An offered lineage that reaches the held content by another signed path does not extend the held version at all. I190 (z) drives both arms through the real doors on three nodes; (y) offers the other path.
- **One predicate on the plane.** `check_infrastructure_founder_count_unchanged(.., self_leave)` (§8.7) returns early for a trust-root row. The trust-root guard (`check_trust_root_roster_change`) is then the only gate. It refuses every founder change on the plane (`founder_seat_on_plane`) except a founder's own self-leave, which it admits as the resignation. There is no double gate.
- **The last founder cannot resign on the plane.** The ordinary last-founder rule runs after the guard, and it refuses removing the only founder. A sole founder leaves through the accord (a withdrawal, then a re-birth).
- **No backdating.** The resignation's `effective_at` is signer-chosen, so two rules bound it:
  - (a) The plane door refuses a resignation whose `effective_at` is not STRICTLY AFTER the stored head's instant: its link's `amended_at`, or `founded_at` for a birth. Equality is refused as well: the head's own link judges resignations up to and including its `amended_at`, so a resignation dated exactly at a link head would have un-counted the founder's signature on that link and un-rooted the row mesh-wide. The refusal is the typed `resignation_backdated`. A founder therefore cannot date a resignation before a link they co-signed and so retroactively un-count that link.
  - (b) For links and the head, the floor is `seated_since` (the counting rule above), not the PRIOR version's instant, which would let a resignation lapse.
  - I190 (o′) witnesses (a) on both backends; (o″), (x) and (y) witness the counting rule.
  - Residual, stated: a node holding an OLDER head admits a resignation dated between its head and a link it has not seen. If that link NEEDED the resigning founder's signature, the founder signed it and chose the divergence: that node then refuses the link, because its founders' count falls short. If the link did not need it, the node admits the link and reads Stalled until the next amendment amends the founder out (I190 (x)). The nodes that already hold the newer head refuse the resignation.
  - Residual, stated: the plane floor reads the stored head, then the revocation is written. A concurrent `put_community` on the SAME node can store a newer head between the two. The resignation is then stored although it is not strictly after the new head. This is fail-secure, because the resignation only un-counts the founder on that node, and it is divergence, because a node that saw the new head first refuses the resignation. No code change: the plane door and the community door are separate writes, and the floor is a check on the resigning founder's own date.
- **A re-seat clears older resignations.** If the founders later seat the key again through the record, a resignation older than the re-seating version no longer applies: the standing counts the key from `seated_since`. `resolve_community` lists a trust root's founders from the RECORD, since `Rooted` has already established that each one counts now. Reading them off the folded plane roster would re-apply the old resignation against the member's original `joined_at`. I190 (o) re-seats the resigned founder.

The trade, stated: ONE founder can stall the default trust root. That is consent over availability (`ROOM_ROSTER_AUTHORITY.md` §2). Dropping the seat does not change a `quorum:M/N` threshold, because M is absolute. It keeps the seat set honest for any count-relative protocol.

**Stated plainly: a single holder revocation un-roots the mesh's default trust root on every node until the accord re-signs.** The birth's accord quorum is re-derived now, so a revocation that drops the family's count below quorum un-roots every accord-born row on every node. This is CC T4 behaviour and loud by design.

**Cost, and how long a verdict holds.** Standing is cached per directory. Each real backend holds a `StandingCache`, reached by `FederationDirectory::trust_root_standing_cache`, and it is never shared across directories.

The verdict is judged at an explicit instant: `stored_standing_at(directory, id, now)`. `stored_standing` is that at the wall clock, and each door reads the clock once and passes it down. Nothing under `compute_standing` reads the wall clock. A key of instants with a verdict evaluated against the clock would cache a future-dated input as Rooted and serve it after its instant passed (a second resignation after a re-seat, an occurrence binding with a future `asserted_at`, a withdrawal whose proposal arrives later); `valid_until` below prevents that.

The key is a digest of every input the verdict reads, AS STORED. It holds no value evaluated against the clock:
- the stored signed row with its lineage;
- the accord family record and its roster plane as stored: every holder widening and revocation, and their signers;
- the key record and steward withdrawal of every holder, every family member and widened member, and every key the chain names;
- for each withdrawal, its proposal's signed `window_until`, or a "no proposal" marker (2c: a proposal landing is a changed input);
- each such key's node-bearing inputs (`node_bearing_of`: its own `node` bit and the stored intervals in which it is an occurrence of a node identity);
- every self-signed resignation instant, past or future. The folded roster is not fed: it is a value at the clock, and the verdict never reads it.

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
- Stated: `put_community` reads the clock in the door (`check_trust_root_community_admission`) and again in `apply_trust_root_chain`. This is benign: the later `now` only relaxes the links' future bound, and the door has already refused anything it would refuse. Passing the door's instant into the apply route means threading it through `route_occupied_community` on both backends.

Any change to the stored inputs is a new key; a holder revocation, a founder withdrawal or rotation, a resignation, a proposal landing and an amendment all are. A read with unchanged inputs before `valid_until` verifies no signature: the cache key costs only directory reads. Within one computation, each founder's conferral co-scrub is verified once (`Memo`). The cache drops everything past 256 entries.

I190 (u), (v), (w) and (m) witness the boundaries, each deterministic through a pinned `now`:
- (u) the 2a shape: F2 resigns, is retired and re-seated, then signs a second resignation dated now + 50 s. Judged at r − 1 s it is Rooted, and a second read there is a hit. Judged at r + 1 s it is Stalled, so the cache must miss.
- (v) the 2b shape: F2 agrees to be an occurrence of a `node` identity with `asserted_at` 120 s ahead. It is Rooted before and Stalled after.
- (w) the 2c shape: a trusted-local withdrawal of F2, whose proposal is not held, reads NotRooted. The proposal lands and the next read is Rooted.
- (m) a holder revocation dated 30 s ahead: Rooted just before, NotRooted just after.

Otherwise it answers `NotRooted { reason }`, for a squat (a row that never passed this door), an unsigned row or a non-conformant row. A `NotRooted` row resolves to nothing. The route serves it as `community: null` with `community_withheld: <reason>`. It is not a `trust:accepts` subject and it is not a community root. An accord BIRTH replaces it: the occupied-id route applies the birth as a new version and records `accord_birth_replaces_unrooted: <prior hash>`. That row was never admissible, so it has no version to amend.

A squat naming one real steward and two squatter founders with a squatter-signed proof does not read as rooted: its chain does not start at an accord birth, so the birth replaces it. I190 (j) plants exactly that row.

**Supersede (CC 3.2).** `prepare_trust_root_supersede` runs in `supersede_community_signed` (every local supersede door). For a rooted or stalled row it requires a verified founders' link and founders who all count now. For anything else it refuses promotion into the grade: only a birth chain through `put_community` founds a trust root.

**Roster planes.** Both room roster doors, on every backend, run `check_community_roster_authority`, which calls `check_trust_root_roster_change` for a trust-root community. Any row that seats, re-roles or revokes a recorded or folded founder is refused, whoever signs. Rows about non-founder members follow the ordinary rule. The widening door's steward-binding probe honours a ROOTED trust root, so a serve node joins through the plane with no steward. The check is judged from the stored row, never the probe's label.

**Forks, stated plainly.** Where two versions extend the same held version, a node keeps the first it admits: a chain that does not contain the held version is refused, and a re-birth over a ROOTED row is refused. Since the content hash is bound, only founder EQUIVOCATION can fork: the founders signing two different next versions.
- **The losing side holds a ROOTED version.** Nothing un-roots it by itself. It stalls only if the accord withdraws the equivocating founders' conferrals. The row then reads `Stalled` (or `NotRooted`, when the withdrawal predates a link it holds), and the recovery path opens: an accord re-birth over a stalled row, or any accord birth or the legitimate chain over a not-rooted one.
- **Equivocation to the same content.** The founders can reach the SAME content by two proofs with different `amended_at`. These are two versions. A node holding one refuses a chain through the other as not extending it, first-seen-wins like any equivocation fork; the next link's floor is never judged against the other path's instant. This arises only under founder equivocation.
- **A backdated link.** A resigned founder F and another founder G can co-sign a link whose signer-chosen `amended_at` falls in (the prior's instant, F's resignation t1). F counts on it. This cannot be told apart from a link F and G pre-signed and withheld, and the plane floor already lets a founder sign links dated before their resignation. It launders nothing: while F is still recorded, the head reads Stalled, because the head judges F at now and t1 lies in (`seated_since`, now].
- **Fork, then evidence.** A consumer that meets a retired-key fork BEFORE the withdrawal evidence admits it, because its own state cannot tell the fork from a link. When the evidence then arrives, the fork's link counts a founder withdrawn before it, the chain stops verifying, and the row reads `NotRooted`. The legitimate chain then replaces it through the unrooted path. I190 (p) witnesses this.

**Trust (CC 3.2 T3).** `check_attested_subject_admission` also knows a stored, ROOTED trust-root community, so the consumer's pin edge `delegates_to(consumer → ciris-canonical, trust:accepts:v1)` is storable. The widening applies to EVERY attestation type whose `attested_key_id` names such a community (a charter, a score, a delegation), not only `trust:accepts`. What a row may SAY about the community is still each type's own door's business. Any other community is still not a subject.

`trust_root_valid` has `RootKind::Community` (a wire-visible enum variant):
- the user's edge names the community;
- the charter quorum, recovery, drill, halt and holder-hardware legs are the accord FAMILY's;
- the arm applies only while the community row is rooted.

So the community root is valid iff the family root is valid AND the row is rooted and conformant. With the family unchartered it is not valid. Withdrawing the one `trust:accepts:v1` row makes it not accepted, and the community row is untouched (trust ≠ membership).

**Resolve (CC 4.4.3.2.4).** `canonical_community::resolve_community` returns the folded roster. For a trust-root id it answers only while the row is `Rooted`, and its founders are exactly the RECORD's founders. `Rooted` requires every recorded founder to count now, so a withdrawn, resigned or non-human founder means no answer at all, not a shorter list. The members are the folded roster minus the recorded founders.

**Serve route (CC 5.3.4).** `GET /v1/trust-root/bundle` and `GET /v1/steward-key` are one handler on persist's axum router (`server` feature). The body is `TrustRootBundleResponse { bundle, authorization_digest, charter_root_key_id, community, community_withheld?, community_member_records }`:
- the bundle is the compiled-in artifact as carried;
- the rooted signed row sits beside it, never inside;
- the member key records travel with it.

The read is a point lookup. A failure returns a generic 500 body (`{"detail":"trust-root bundle unavailable"}`), and the detail is logged, not served.

**The alias body differs from the registry's.** CIRISRegistry's v3 `/v1/steward-key` body is `{bundle, bundle_fingerprint, charter_root_key_id, served_by{node_key_id, accepts_this_root}}`. Persist's is the body above. It has no `served_by` or `bundle_fingerprint`, and it carries `authorization_digest`, `community`, `community_withheld` and `community_member_records`. The registry adopting persist's body, or not, is outside persist. The CI pre-flight reads the `bundle` key both bodies share.

**Consumer pin.** `pin_trust_from_bundle_response` works from one response:
1. `verify_bundle_quorum` against the consumer's OWN roster;
2. the member key records through the key door;
3. the row through the community door, which re-derives the accord quorum against the consumer's own pins;
4. resolve.

The records go in BEFORE the community because the door judges founders from this node's records. Each record passes the key door on its own terms (a founder's co-scrub is re-verified here; a serve node's record is a self-registration anyone may submit). A refused community therefore leaves behind only records this node would admit from anyone: never a community, never a conferral the accord did not sign.

**Host reach.** `put_community_json` takes a `cosignatures` list. A malformed list is refused with `ValueError`, and co-signatures without an authority signature are refused. Three bindings, classified in `scripts/ffi_taxonomy.tsv`, with `.pyi` stubs and `evidence/ffi_classification.tsv` regenerated:
- `resolve_community_json`: deontic;
- `trust_root_bundle_response_json`: empirical;
- `pin_trust_from_bundle_response_json`: deontic.

`put_community_json` hard-codes `supersede_proof: None` and an empty `lineage`. A Python host therefore relays a founders' amendment through `supersede_community_with_quorum`, and a chain through `pin_trust_from_bundle_response_json`, not through the plain put.

Witness: `tests/python/test_sqlite_engine.py::test_ciris_canonical_trust_root_surface_926`, run against a `maturin develop --features pyo3,sqlite` wheel. Not proven through the wheel: the POSITIVE co-signature path (a quorate row put over Python). The witness shows only that a malformed list is refused and that a well-formed list reaches the door, because the genesis-seeded engine holds the real holder pubkeys and a test cannot sign as them.

**Fixture vs real row.** The production `ciris-canonical` birth is carried by the pinned bundle and seeded at boot (`TRUST_ROOT_RC6.md` §9). I190's fixture stands the trust root up on a bare directory with test-held keys under the genesis holder ids (`register_genesis_accord_roster`): the same path, with keys a test can sign with.

**#809.** The Rust-side consumer gate was already a gate (`verify_bundle_quorum`), and I190 (f) witnesses it through the pin. The REPORTED-not-gated assertion #809 tracked was the release pre-flight in `.github/workflows/ci.yml`. It is `scripts/preflight_trust_root.py` and GATED: an unparseable `consensus_protocol` is refused, and so are distinct seated authorizations short of M. The step runs a 12-fixture self-test first, including #809's `authorizations: []` row, which exits 1. It counts authorizations and does not verify their signatures.

**Invariant I190** (sqlite, postgres):
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
- (o) a founder resigns by their own plane revocation: the row stalls, a later link counting them falls short, and the others retire the seat through the record; the founders then RE-SEAT the key, the older resignation no longer applies, and the re-seated founder co-signs a later link on the local door (the one-quorum rule);
- (o′) F2 co-signs v2; F2's resignation dated between the birth and v2's `amended_at` is refused with `resignation_backdated`, and the row stays Rooted with every founder; the same resignation dated now is admitted and stalls the row;
- (o′) additionally: a resignation dated EXACTLY at the link head's `amended_at` is refused and the row stays Rooted; one second later it is admitted and the row stalls;
- (o‴) every resignation counts: F2 resigns, is retired, is re-seated through the record, and resigns again after the re-seat head; the row stalls, naming F2;
- (o″) the counting rule and the lapse trace: F2 resigns; the other founders' v6 that still records F2 is ADMITTED on the replicated chain door and the row is Stalled, naming F2; F2 with F0 then produces no v7 (adding a member, or amending F2 out) on either door; F0 + F1 amend F2 out (Rooted), re-seat F2 (Rooted), and F2 then co-signs a later link;
- (u) a second resignation dated now + 50 s after a re-seat: Rooted and a cache hit at r − 1 s, Stalled and a cache miss at r + 1 s;
- (v) an agreed occurrence binding of F2 under a `node` identity, `asserted_at` 120 s ahead: Rooted and a cache hit before, Stalled and a cache miss after;
- (w) a withdrawal whose proposal is not held reads NotRooted; the proposal lands and the next read recomputes and is Rooted;
- (x) two nodes, the resignation split: `a` admits F2's resignation, `b` refuses it as backdated; `a` admits `b`'s H2 (still recording F2) and is Stalled while `b` is Rooted; H3 amends F2 out and both are Rooted on H3;
- (y) an offered lineage that reaches the held content by another signed path, re-seating F2 after the resignation, does not extend the held version (`does not extend`), whoever signs v4; over the held chain, v4 by F2 + F0 falls short and v4 by F0 + F1 is admitted and stored on the chain the node holds;
- (z) three nodes: `b` retires F2 (v2), re-seats F2 back to the birth's content (v3), and F2 + F0 sign v4; replica `c`, holding v3 (the LAST occurrence of that content), admits v4; `a`, holding the birth (the FIRST occurrence) and never shown v2 or v3, walks every link and admits v4; all three are Rooted on v4 with the whole chain stored;
- (z′) a correct extension over an offered prefix whose bytes are corrupted, (a) a birth co-signature, (b) a link's authority signature, is admitted; the row stays Rooted on its next re-judgement, and the stored lineage is the held chain byte for byte;
- (t) the TOCTOU arm: `prepare_trust_root_supersede` flagged as having skipped the generic quorum refuses over a NotRooted constraint row; unflagged it passes;
- (r) #925's node-bearing half on its own: a `user,steward` founder that becomes an agreed occurrence of a `node` identity stalls a Rooted row whose standing was already cached (naming the founder), and a birth naming such a founder is refused with `node_bearing_founder`;
- (q) both doors, one predicate: a reserved-id squat, a short birth, a body variant under a genuine proof and a role-binding replay are refused on `put_community` (the typed rule, via `assert_violation`) and on `apply_replicated_community` (`Refused { DegradesConformance }`, or the propagated insufficient-quorum error), and nothing moves; the accord birth is `Inserted`, its re-offer `Unchanged`, and a genuine founders' link `Superseded` through the replicated entry; another id's unverifying constraint row is refused locally and kept as data on the replicated entry (`NotRooted`, never resolved), and one founder of its `quorum:2/3` cannot supersede it into a plain room on the local door (the generic quorum still holds there);
- (p) a withdrawal through the accord with a short signed window:
  - the response carries its evidence;
  - a fresh consumer re-tallies it and REFUSES a retired-key fork signed after the window, although it recorded the withdrawal after the fork was signed;
  - a second fresh consumer pins through `pin_trust_from_bundle_response` and re-derives the withdrawal;
  - fork, then evidence: a third consumer admits the fork before the evidence (Rooted), the evidence un-roots it (`NotRooted`), and `a`'s legitimate head replaces it through the unrooted path;
- (h) additionally: a link with `amended_at` before the version it follows, or in the future, is refused; (e) the birth's co-signer record travels with the row;
- (j) three rows planted below the door on each backend: a non-conformant squat, a conformant row one founder signed alone, and one real steward plus two squatter founders with a squatter-signed "proof". Each resolves to nothing, is served as null with a named reason, is not a trust subject, and is replaced by the accord's birth chain, after which the consumer's root is valid.

Plus the server route test on both paths.

**Scope notes.**
- Entrenchment, `cohort_subkind` and `infrastructure_constraint` live in `policy_blob`, not as record columns. `Community` has no such fields, and adding them would move every community's `persist_row_hash`.
- V158 (`community_cosignatures`) holds the co-signatures and the `lineage`. Its checksum rows are pinned in `evidence/migration_checksums.tsv`.
- The chain grows with every amendment: each served row carries every prior version. That is linear in the amendment count and bounded by how often the founders amend.
- Founder seats of a trust-root community move only through the record. A plane row that seats a founder does not count: links count recorded founders, and resolve lists recorded founders.
- The trust-root grade requires the HUMANITY_ACCORD's quorum for ANY row declaring `infrastructure_constraint`. An operator-minted infrastructure root under its own family is therefore not admissible by this door. Deriving the admitting family from the signer set is open.
- `is_authorized_infrastructure_community` reads only the `substrate_persist` community key, so the read-time DEK Commons-plaintext opt-out and the moderator/federate re-checks treat an accord-admitted row as non-infrastructure. That is the stricter side. The admission-time and roster-plane steward-binding checks honour a rooted trust root.
- The founder predicate is `user` plus `!is_node_bearing_key_at` (#925), and every refusal is the typed `CommunityConsensusProtocolViolation`.
- Founder changes are swaps: the N-equals-founder-count conformance (§8.7) holds for a trust root, so I190's founder moves are swaps and its rows use `quorum:3/3` where a 1/3 or a non-swap would fail conformance first. `node` is exclusive of `user` at key mint (#925 Clause A), so the node-bearing founder fixture is `node,steward`.

**Lanes.** The full, unfiltered lanes: `cargo nextest run -j 3 --features pyo3,sqlite --no-fail-fast`; `scripts/pg_test_db.sh -- cargo nextest run -j 3 --features postgres,sqlite --no-fail-fast` (in partitions when a lane nears the 600 s cap); `cargo test -q --features postgres,pyo3,server --lib` under `pg_test_db.sh`; `RUSTFLAGS="-D warnings" cargo check --features server`; `python3 scripts/pyi_surface.py check`; `python3 scripts/gen_directory_double.py --check`; and the `tests/python` suite against a `maturin develop --features pyo3,sqlite` wheel when a pyo3 signature changes.

**Mutation table (#926).** Lane: `test(i190) | test(canonical) | test(genesis) | test(bundle) | test(trust_root) | test(conferral) | test(supersede)`, `--features sqlite,postgres --lib`, under `scripts/pg_test_db.sh`, every run with a database (no leg at 0.00 s). Each mutant is reverted before the next.

| # | Mutant | Killed by (I190 arm) |
|---|---|---|
| M1 | accord quorum check dropped (birth) | (b), (e), (j), (m), (q) |
| M2 | 1-of-3 admitted (birth) | (b), (e), (m), (q) |
| M3 | entrenchment not required | (c), (g) |
| M4 | the route serves no community | (e), (h), (l), (p) |
| M5 | #809 CI gate reverted to report | `i190_f_ci_preflight_gates_the_bundle_quorum` |
| M6 | founder human-key rule skipped at the door | (c) |
| M7 | founder accord-conferral skipped at the door | (c), (h) |
| M8 | the local door skips the founders' link | (g), (h) |
| M9 | `ciris-canonical` not reserved | (c), (j), (q) |
| M10 | trust-root community not a `trust:accepts` subject | (d), (j) |
| M11 | the pin skips `verify_bundle_quorum` | (f) |
| M12 | co-signatures not verified at the door | (b) — a quorate row padded with one bad co-scrub, and a doubled co-signer |
| N5 | roster-plane guard dropped | (i), (i) moderator, (o′) |
| N8 | the steward-binding probe ignores the accord door | (i) |
| N9 | resolve does not re-judge the row | (j), (k), (m), (q), (r) |
| N10 | read-side shape re-check dropped | (j) |
| N13 | the community root is valid without its family (every family leg skipped for a community root) | (d) |
| R1 | a peer re-demands the accord count | (h), (q) |
| C1 | chain walk skipped on a fresh node | (h), (p) |
| C2 | a link's founders' quorum not required | (h), (o), (p) |
| C2b | a link's prior hash not checked | (h) — a fresh node given a skipping chain |
| C4 | envelope role binding not checked | (h), (q) |
| C6 | `stored_standing` proof-only arm | (j), (p) |
| C7 | every-recorded-founder counting dropped | (k), (k′), (o), (o′), (r) |
| C8 | multi-hop apply skips intermediate versions | (h), (p) |
| C9 | a squat not replaced by the birth chain | (j), (p) |
| P1 | the plane admits a founder-seat change | (i), (i) moderator |
| P2 | role binding skipped when the founder set moves | (h) |
| P3 | a link counts a withdrawn record founder | (h), (k), (k′), (p) |
| P4 | the next-content hash binding dropped | (h), (q) |
| P5 | the authority need not be a counted founder | (h) |
| P6 | a link's authority signature not verified | (h) |
| P7 | the standing cache keyed on the row alone | (k), (k′), (m), (o′), (p), (r) |
| P8 | lineage length cap dropped | (n) |
| P9 | lineage byte cap dropped | (n) |
| P10 | a rotation un-counts historical signatures | (h), (k), (k′), (l), (p) |
| P11 | the bundle response serves only the current version's keys | (l), (p) |
| K1 | re-birth refused over a stalled row | (k′) |
| K2 | re-birth replaces a ROOTED row | (k′) |
| K3 | re-birth need not be founded later | (k′) |
| O1 | resignation ignored in `founder_counts` | (o), (o′) |
| O2 | resignation refused on the plane | (o), (o′), (o″) |
| O3 | a resigned seat kept in the link seats | equivalent: M is absolute, and a trust-root row admits only `quorum:M/N`; the seat drop is kept for honesty of the seat set |
| W1 | withdrawal instant from the local clock | (p) |
| W2 | the response omits the withdrawal evidence | (p) |
| W3 | the pin does not admit the withdrawal evidence | (p) |
| W4 | co-signer records not served | (e) |
| A1 | `amended_at` floor dropped | (h) |
| A2 | `amended_at` future bound dropped | (h) |
| B1 | the plane's past floor dropped | (o′), (x) |
| E1 | the plane floor at equality (`<=` reverted to `<`) | (o′) equality arm |
| B3 | the standing ignores the re-seat floor | (o) |
| B4 | resolve lists the plane roster's founders | (o) |
| D1 | the replicated entry skips the trust-root predicate | (q) |
| D2 | the replicated entry is lenient for the reserved id | (q) |
| D3 | the replicated legacy-as-data allowance dropped | (q) |
| L1 | a local trust-root amendment also runs the folded quorum | (h), (o) |
| L2 | the local door skips the folded quorum for every row | `engine::tests::quorum_supersede_protocol_decides` |
| L3 | the local door skips the folded quorum for a NotRooted constraint row | (q) |
| F1 | the founder's node-bearing half dropped (door and link instant) | (r) |
| F2 | link seats never node-bearing | equivalent: `founder_counts` already drops a node-bearing founder, and the only other node-bearing seats are serve-node members, which `quorum:M/N` over founders never counts |
| F3 | the standing cache key omits the node-bearing inputs | (r) |
| RC | the infrastructure founder-count gate also runs for a trust root | equivalent: the trust-root guard runs first and admits only member changes and a founder's own self-leave, both of which the other gate admits |
| X3 | the TOCTOU skipped-quorum flag ignored | (t) |
| E2 | only the earliest resignation kept | (o‴) |
| E3 | the standing cache key omits the resignations | (o′), (o‴), (u) |
| V1 | the cache ignores `valid_until` on a hit | (m), (u), (v) |
| V2 | occurrence-interval boundaries omitted from `valid_until` | (v) |
| V3 | resignation boundaries omitted from `valid_until` | (u) |
| V4 | the proposal's `window_until` dropped from the key | (w) |
| V5 | the family fold's holder boundaries omitted from `valid_until` | (m) |
| S1 | the counting rule's `seated_since` floor replaced by the prior-instant floor | (o″), the lapse |
| S2 | a resigned founder counts on a later link (the link ignores resignations) | (o), (o″) |
| B2′ | the link's `seated_since` floor dropped, so every resignation counts, even one before a re-seat | (o), (o″) |
| Z1 | the held version found as the FIRST offered index with its content | (z) arm 1; (y) |
| Z2 | the held version found as the LAST offered index with its content (`rposition`) | (z) arm 2 (`roster_consensus_insufficient`, the stale `seated_since`); (y) |
| H1 | the door walks the offered prefix, not the held chain | equivalent alone: the apply route re-walks the held chain and refuses |
| H1b | the apply route walks, and stores, the offered prefix | (y); (z′) sub-arms (a) a birth co-signature and (b) a link's authority signature: "the row stays Rooted on its next re-judgement" |
| H1 + H1b | both layers walk the offered prefix | (y) (F2 + F0 over a forged re-seat is admitted) |

Why H1b matters: `same_version` compares content, authority and the founders' proof (its `quorum_signatures` included), but not the authority scrub signature bytes or the co-signatures, and the door walks only the links after the held version. If the apply route stored the offered prefix, one peer could flip bytes in it; the next `stored_standing` would recount them, the birth would fall short of the accord quorum or `verify_community_admission` would fail on the link, and the row would read NotRooted, so any accord birth could replace it. `walk_from_held` stores the HELD versions, so this cannot happen.

### 9.1 A failed read is never a cache hit (F1)

**The hazard.** If `standing_cache_key` swallowed a failed read of the accord family's record or roster plane, the failure would key exactly as a genuinely empty plane does, and a Rooted verdict cached over an empty plane would be served while the revocation state could not be read.

**Rule.** Every read in the key builder propagates its failure: no key, no lookup, nothing cached, and the caller gets the error. `Unsupported` is a structural answer (the directory cannot be asked), so it keys as its own marker, never equal to any answer. `family_roster_signers` is asked only when the family read returned a family, since it names an unknown family `InvalidArgument`. The remaining `unwrap_or_default` calls in the function are serialization, and its remaining `Unsupported` mappings mirror what the verdict path itself does for the same read.

**Witnesses (I190 f1, both backends).** The fault double hands out the inner backend's standing cache (generator `DELEGATED_DEFAULTS`), so a verdict read through the double meets the cache while every key input still goes through the double's fault table.

- (f1_a) The canonical row is Rooted over an empty family plane and cached; a clean double hits the cache. With each of the four family reads failing, the read returns the error, and nothing is computed or served.
- (f1_b) With no accord family stored, the planted row reads NotRooted and is cached. With `lookup_family` failing, the read returns the error, not the cached NotRooted.
- (f1_c) A shape-refused squat is judged NotRooted before any family fold, so it is cached while the widenings read answers `Unsupported`. With the same read failing, the read returns the error, not that cached verdict.

**Mutants.** Lane: `i190 | canonical | rc5 | infrastructure | replicated_community | delegation | topology | depth` under `scripts/pg_test_db.sh`, every run with a database, each mutant reverted before the next.

| # | Mutant | Killed by |
|---|---|---|
| M1a | the widenings read swallowed (`unwrap_or_default`) | (f1_a) |
| M1b | the revocations read swallowed | (f1_a) |
| M1c | the family read swallowed (`.ok().flatten()`) | (f1_b). Survived (f1_a) alone: with the family present, the failed read keys differently and the verdict's own read errors. |
| M1d | the roster-signers read swallowed | (f1_a): the seeded family's genuine signers answer equals the empty default |
| M1e | every error keyed as the `Unsupported` marker | (f1_c). Survived (f1_a) and (f1_b): the marker misses an answered key. |

## 10. #924 — the dimension grammar is manifest data

**Rule.** Parsing and casing of a dimension is one rule across the CC and every consumer, carried as data in the CC registry (CIRISConstitution#112). Persist has ONE matcher, driven by the vendored manifest, and every gate asks it.

**Inputs, vendored byte-for-byte** from CIRISConstitution: `manifests/namespace_registry.json` → `src/federation/namespace/namespace_registry.json` and `manifests/namespace_match_vectors.json` → `…/namespace_match_vectors.json`. The commit and version are pinned in `registry.rs` (`VENDORED_CC_COMMIT`, `VENDORED_CC_VERSION`, `VENDORED_REGISTRY_SHA256`, `VENDORED_SOURCE_SHA256`); JSON has no comments, so that doc is the header. `namespace_match_binds.json` is persist-generated from the same commit (below). `vendored_registry_sha256_pins_the_cc_file` recomputes the grammar hash over the vendored bytes exactly as `tools/build_cc_namespace.py` does (Python `json.dumps(sort_keys, compact, ensure_ascii)` over `_meta` minus the two hashes plus `families`; `cc_version` is not part of the preimage — a version bump is not a grammar change), and holds it equal to the meta value and `VENDORED_REGISTRY_SHA256`. `_meta.source_sha256` is the SHA-256 of `constitution/part_3_the_namespace.md` at the vendored commit. Persist vendors a tagged or landed commit and recomputes on every re-vendor, so a recipe change surfaces as a failing test. `namespace_supersets.json` (the supersets walk, `supersets::VENDORED_MANIFEST_VERSION`) is a separate vendored file. `ACCORD_HEARTBEAT_DIMENSION` is `accord:lifecycle:v1` (it resolves to the `accord:lifecycle` leaf).

### 10.1 One matcher

`namespace::matcher::match_family(dimension) -> FamilyMatch { family, binds, refusal }` is a port of `tools/cc_namespace_match.py`: segments byte-exact, version tail stripped unless the family ends `{version}`, closed enumerations → `namespace_vocab_value_unregistered`, closed leaves, reserved stems and the descendants a closed family fences → `namespace_family_unregistered`, a malformed form of a registered family (case-folded stem, uppercase/duplicated tail, a `VERSION_ATTEMPT` such as `v1beta` in last place) → `namespace_dimension_case_malformed`, `multi` placeholders, variadic `*`, `external_standards`, Private Use. A refused hit is attributed to the clean row it mutates. Every token is read from the manifest.

| Reader | How it asks |
|---|---|
| `load_bearing::family_for_dimension` | `match_family` → the registry family, then NAMED in the supersets vocabulary (identical key, else the `stem:*` it sits under; open vocabulary only to a supersets stem the registry registers nothing under). A refused dimension resolves to no family (Unknown = load-bearing; not retainable). |
| `registry::lookup` | `match_family(...).family` → its entry, attributed even when refused. `match_prefix` is data only. |
| `registry::is_family_registered` | family resolved and not `namespace_family_unregistered`; the stem question is `is_stem_registered`. |
| `consent_grammar::covers` | grant prefix `starts_with` AND `match_family` refuses nothing (the prefix half is byte-exact: it is the signed grant's own scoping string under `CONSENT_GRAMMAR_HASH`). |
| version segments | ONE parser: `matcher::is_version_segment` / `trailing_version` / `is_version_exempt`, read from `_meta.case_rule.version_segment` (`pattern`, trailing, `required`, `exempt`). The exempt list covers the attestation-ladder families and `identity:canonical_binding:{canonical_hash}`. |

**Replay.** `namespace_match_vectors_replay` checks every vector two ways: CC's contract (family and refusal exact; the vectors name exactly what the reference answers, CIRISConstitution#116), and the reference's own exact `(family, binds, refusal)` from `namespace_match_binds.json`, generated by `scripts/gen_namespace_match_binds.py <CC repo> <commit>` (runs the reference tool from the pinned commit over the vendored files, refuses unless both are byte-identical to CC's and every vector's family and refusal equal the reference's; `--check` re-verifies). The vectors carry no binds, which is why the second leg exists. `every_family_sample_round_trips_to_itself` replays the generator's own round-trip gate, skipping closed families. `reference_edges_beyond_the_vectors` pins edges no vector reaches.

**Full match (`_meta.case_rule.match_semantics`).** `matcher::compile` wraps every manifest pattern as `^(?:p)$`, so an unanchored pattern cannot partial-match and a `$` never admits a trailing newline (`compile_is_a_full_match`). The manifest's declaration is asserted present and starting `full-match` (`the_manifest_declares_full_match_semantics`, and the registry drift gate). The reference's two hard-coded detectors (`VERSION_LIKE`, `VERSION_ATTEMPT`) are applied with Python `re.match` there, whose `$` tolerates one trailing newline; the port compiles them verbatim with `\n?\z` so a detector refuses exactly what the reference's does.

**The gates.** `check_dimension_case_rule` refuses the matcher's `case_malformed` and `vocab_value_unregistered` (so variadic tails are case-checked: `variadic_tail_segments_are_case_checked`). R2(b) (`check_namespace_family_registered`) refuses the matcher's `family_unregistered` in addition to persist's governed-but-rowless stems. Layer 2b refuses `missing_version_segment` unless the resolved family is exempt.

### 10.2 Consequences of the grammar

- **Reserved stems close their leaves.** Unclaimed leaves under CC's reserved stems (`accord:`, `transparency_log:cosigned:`, `detection:`, `capacity:`, `age_assurance:`, `capacity_assurance:`; `age_self_declared:` is gated) are `namespace_family_unregistered`. `authority_for` answers a `kind: reserved` stem's rule for an unclaimed leaf.
- **Canonical binding.** `identity:canonical_binding:{canonical_hash}` is one 64-lowercase-hex segment, version-exempt. `parse_canonical_binding_hash` resolves through the matcher; the hash is spelled `canonical:sha256:<hex>` where it meets `subject_key_ids`. A stored `identity:canonical_binding:canonical:sha256:<hex>` row parses to `None`, so `canonical_binding_hashes_for` drops it and it does not widen its key's `withdraws` authority (rule 2): fail-closed.
- **Accord.** `accord:invoke:{constitutional|notify|drill}:{id}:v1`, lowercase; `accord_invoke_old_uppercase_shape_fails_loudly` witnesses the uppercase spelling refused `case_malformed` at the matcher and the case gate.
- **Hardware.** `HardwareTypePlatform::as_platform` equals the registry's closed `{platform}` set both ways (`hardware_type_platforms_equal_registry_values_107`); `hardware_class_multiplier` is CC 4.2.2's table, unlisted ⇒ 0.0. Emit `hardware_custody:{snake_case HardwareType}:v1`.
- **Minors (CC 5.4.6).** `check_minor_owner_binding_not_announced`: an owner-purpose `delegates_to` at `cohort_scope: federation` whose granter resolves `minor` refuses `WriteScopeRefused(MinorOwnerBindingAtFederation)` (`scope_minor_owner_binding_at_federation`), at every backend's put door, in the promotion stack, and on a widening (`widen_audience`'s `supersedes`, including the sweep and the pyo3 widen). A minor's owner-binding is held at `cohort_scope: self`. Invariant `minor_owner_binding_at_federation_is_refused_q5`.
- **A widening never strips `delegation_purpose` (#929).** The gate recognises an announce by the widening's own body or by the prior it names; a receiving peer that does not hold the self-scope prior can check only the body, so `delegation_purpose` is on the list of members a widening may not strip. Witness `engine::tests::a_widening_never_strips_the_delegation_purpose_marker`.
- **Capacity companions are CC rows** (CC 3.4.12, CIRISConstitution#117): `capacity_assurance:reversible_excluded:{domain}:{version}` / `…:reversible_pending:{domain}:{version}`. `capacity::reversible::parse_companion` reads the one matcher. Companions ride `attestation_type`, which the case gate (envelope dimension only) never reads, so R2(b) is their only grammar gate. Witness: `capacity_companions_resolve_to_their_cc_rows_117`.
- **`consent:{kind}` is closed in its leaves.** An unlisted kind, or any unmatched descendant under `consent:`, refuses `namespace_family_unregistered` at R2(b), and no consent grant covers it. `consent:community_trust:v1` admits on its own row.
- **Open vocabulary owes its version tail.** A dimension no row claims is judged by the global version grammar: `no_such_family:leaf` refuses `missing_version_segment`; `…:leaf:V1`, `…:leaf:v1beta`, `…:v1:v2` and a lone `v1` refuse `namespace_dimension_case_malformed`.
- **Canonical BCP 47 locales** in `provenance:build_manifest:{target}:locale:{lang_code}` (`provenance_locale_is_canonical_bcp47`).
- **Stored rows narrow, never widen.** A stored row on a shape the grammar refuses is covered by no consent grant, so `promote_consented_backlog` neither promotes nor widens it (counted as `ConsentSweepReport::skipped_unmatched_dimension`, with up to 8 `unmatched_dimension_examples` and a `warn` summary); it resolves to no supersets family (load-bearing, not retainable); and `authority_for` resolves it to its family (attributed even when refused) or to a reserved stem's rule or `ProducerSteward`. None of these makes a row more visible or more transferable.
- **The ledger version** uses the one parser to recognise the segment, then requires an integer (`v1.2` refuses): CC 3.3.10.1's id derivation keys on the version number.
- **Edges.** Whitespace for the strip check is Unicode `White_Space` plus `\x1c`–`\x1f` (Python's `isspace`); `str.lower()` / `to_lowercase()` agree on ASCII (every registered stem) but not on every non-ASCII code point, which only moves a DETECTION of a case-mutated stem.
- `regex` is a direct, non-optional dependency. `every_manifest_family_column_has_a_reader_724` accounts every `_meta` and per-segment key; `reserved_prefix_rules_match_manifest_leaves` holds every hand-spelled reserved-rule prefix to a literal leaf of a vendored family or a CC reserved stem.

### 10.5 Mutation table (#924)

Lane: `--features sqlite,postgres --lib` under `scripts/pg_test_db.sh`, `-j 3`, filter `test(namespace) | test(matcher) | test(vector) | test(version_segment) | test(case_malformed) | test(hardware_type) | test(minor) | test(accord_invoke) | test(manifest) | test(variadic) | test(case_rule) | test(r2b) | test(covers) | test(dimension_resolves) | test(reserved_prefix) | test(canonical_binding) | test(retainab) | test(grammar_refuses) | test(consent_grammar) | test(capacity)`. Each mutant reverted before the next.

| # | Mutant | Killed by |
|---|---|---|
| M1 | version tail KEPT on a `{version}`-less family | case gate, r2b, variadic, covers, hardware vocab, dimension_resolves, replay |
| M2 | closed leaf admitted | replay, accord_invoke, r2b, covers, is_family_registered |
| M3 | closed-vocabulary value admitted | replay, variadic, hardware vocab |
| M4 | reserved stem admitted | replay, r2b |
| M5 | `version_segment.exempt` dropped | replay, version_segment, canonical_binding_widens |
| M6 | variadic tail uncased | replay, variadic, accord_invoke |
| M7 | longest-literal-prefix `lookup` | `lookup_resolves_through_the_one_matcher_924` |
| M8 | `as_platform` off by one token | hardware vocab, class mapping |
| M9 | minors refusal dropped | `minor_owner_binding_at_federation_is_refused_q5` |
| M10 | replay compares FAMILY only + vocab refusal spelled case_malformed | variadic (token assertion) |
| M11 | case gate stops refusing `vocab_value_unregistered` | variadic |
| M12 | `covers` without the grammar check | `covers_refuses_what_the_grammar_refuses_924`; the sweep witness |
| M13 | `family_for_dimension` ignores refusals | dimension_resolves |
| M14 | `trailing_version` accepts a version anywhere | version_segment |
| M15 | canonical-binding parse accepts any suffix | `canonical_binding_parse_goes_through_the_matcher_924` |
| M16 | minors gate removed from the promotion stack only | minors (via `check_promotion_admission`) |
| M17 | `authority_for` reserved-stem fallback removed | lookup_resolves |
| M18 | minors gate skips SUPERSEDES (a widening is not re-checked) | minors (the widening leg) |
| M19 | sweep's stranded-dimension accounting dropped | `sweep_counts_grant_covered_rows_the_grammar_refuses_924` |
| M21 | `compile` drops the `^(?:p)$` anchor | `compile_is_a_full_match` |
| M22 | the manifest's `match_semantics` key removed | `the_manifest_declares_full_match_semantics`, registry drift gate, column accounting, `vendored_registry_sha256_pins_the_cc_file` |
| M23 | closed-leaf check wildcard-only (consent leaves reopened) | replay, `consent_community_trust_admits…`, `reference_edges_beyond_the_vectors` |
| M24 | `consent:community_trust` row removed | `consent_community_trust_admits…`, replay, the registry count and sha gates |
| M25 | `VENDORED_REGISTRY_SHA256` stale | `vendored_registry_sha256_pins_the_cc_file`, `vendored_vectors_name_the_vendored_grammar` |
| M26 | `parse_companion` admits a companion missing `{version}` | `capacity_companions_resolve_to_their_cc_rows_117` |
| M27 | closed-family stems no longer fence descendants | replay, `consent_community_trust_admits…` |
| M28 | open vocabulary no longer owes its version tail | replay, `reference_edges_beyond_the_vectors` |
| M29 | a refused hit is not re-attributed to the clean row it mutates | replay (the exact-family leg) |
| M30 | `VERSION_ATTEMPT` never matches | replay, `reference_edges_beyond_the_vectors` |
| M31 | the detectors lose Python `re.match`'s trailing-newline tolerance | `reference_edges_beyond_the_vectors` (the vectors alone would not) |
| M32 | R2(b) stands aside for every companion shape | `capacity_companions_resolve_to_their_cc_rows_117` |
| P1 | `delegation_purpose` unprotected on a widening (#929) | `engine::tests::a_widening_never_strips_the_delegation_purpose_marker` |
