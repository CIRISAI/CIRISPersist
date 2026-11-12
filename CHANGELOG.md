# Changelog

All notable changes to ciris-persist, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). A rule persist
enforces cites the CIRIS Constitution section it implements, as "(CC 4.2.6)".

## [61.4.0] - 2026-11-12

Room moderation for rooms larger than two: a room moderator can take down a message or a file placed in the room (CIRISPersist#1260), and every room duty door is witnessed asking for an appointment, never for membership (CIRISPersist#1195).

### Added

- **`FederationDirectory::attestations_binding_content_with_placements(content_sha256)`** (CIRISPersist#1260). The rows that bind a content digest for the duty question: what `attestations_binding_content` returns, plus every federation-tier `supersedes` row at `community` or `affiliations` scope that binds the digest (the same `envelope_binds_content` predicate). One scan, newest first, on sqlite and postgres. The default body answers `Unsupported`, as the 61.1.0 reads do, so a directory implemented outside the crate still compiles; the capsule directory answers `Unsupported`. New read-counter door label `attestations_binding_content_with_placements`.
- **`Error::RosterAuthorityUnauthorized` carries the door's count under `roster_consensus_insufficient`** (CIRISPersist#1250, CC 4.4.3.4.2). A new field `shortfall: Option<consensus::ConsensusShortfall>` with `have` (distinct counted voices, persons per CIRISPersist#1198), `need` (what the protocol needs at this roster) and `eligible_signer_key_ids: Option<Vec<String>>` (one key per eligible person, sorted; the founders under `founder_only`; the named member left out of a removal they may not vote on; those who already signed included). The eligible signers are roster information (CC 5.2): they are told only when the primary signer is, or acts for, an active member of the group (at the retraction door, an issuer seated in the roster); every other caller gets the counts and `None` (`ConsensusShortfall::for_caller`). It is the evaluator's own count: `consensus::Verdict::Insufficient` gains the same `shortfall` field, set by each count arm (`majority`, `unanimous` and its removal rule, `quorum:M/N`, `founder_only`, a `reverse_quorum` addition, the `open:self_admit` floor, a `custom` role node), and `StandingVerdict::ConsensusShort` carries it to the door, as does `StandingVerdict::Refuse` (new `shortfall` field) when the count refused a signer who is no active member. `None` under every other rule, for a weighted rubric (its tally is a weight), for a short event that would also leave no founder, and for a trust root's accord charter quorum. The `kind()` token, the Display text and the Python exception (`ValueError`, message `"<kind>: <rule>"`) are unchanged. `consensus::Verdict::shortfall()` reads it.

### Changed

- **`quorum:M/N` below `M` counts the whole roster, and `M` latches once reached** (CIRISPersist#1201, CC 4.4.3.4.2.1). A room founded alone at `quorum:3/4` could not seat its second member: the gate asked three signatures of a room of one. While the roster is below `M` and the group's lineage has never held `M` members, the gate now needs every live member (at least one), the invitee's acceptance being the other consent; from the first act at which the roster reaches `M`, `M` binds absolutely and for good. A room that reached `M` and shrank below it is stalled, and its refusal says so (`roster_consensus_insufficient`, detail "stalled", `have`/`need` per #1250). "Ever reached `M`" is a fold over persisted roster history, never a stored flag: `authorized_roster_high_water_at` (the largest active roster the authorized fold held, the same replay as `authorized_roster_state_at`) and the directory read `community_roster_high_water_at`. No migration: the roster doors already replay the lineage, so the high water costs no extra read. One count for both readers: `consensus::quorum_need`, used by the evaluator and by the new `required_signatures_at` (`required_signatures` stays absolute). `consensus::Ballot` gains `high_water: Option<usize>`; `None`, which every caller that does not fold the lineage passes (the trust-root chain, a retraction of a roster event, a record change, the accord checks), keeps absolute `M`. `roster_event_standing` and `roster_event_verdict` take the high water. An `infrastructure` community never relaxes (CC 3.2 T7). Carrying the high water on the signed `group:roster` head is left to CIRISPersist#1253.

### Fixed

- **A room moderator could not take down room content** (CIRISPersist#1260, CC 4.5.3, CC 4.5.5 as ruled at CIRISConstitution 7b86bee: "Content is a community's where a live row places it at that community's scope, a `supersedes` that widens it included"). It was reachable in a room of two: a founder could not take down the other member's message. A message or file reaches its room as a `supersedes` widening of the author's `self` row (CC 4.4.3.3.1), and the takedown binding read only `scores` rows. So the only binding row was the author's original at `self` scope, the content bound into no community, and every founder and appointed moderator was refused `takedown_unauthorised` with `"communities": []`. A member's node, which holds only the widening, answered `takedown_content_unbound`. The review-holder read behind a takedown's reversal had the same gap. `takedown_tombstone::content_binding` now reads `FederationDirectory::attestations_binding_content_with_placements`: the `scores` rows as before, and the live federation-tier `supersedes` rows at `community` or `affiliations` scope binding the digest. A placement binds the content into the room it places it in, under the same liveness rule as any binding row (a `withdraws` of the widening takes it out). Its subjects are the original's (the widening door refuses a widening that changes them). The bytes plane and `subject_of_content` keep `attestations_binding_content`, unchanged. The capsule directory answers `Unsupported`, as it does for the read beside it.

### Adoption notes (CIRISEdge, CIRISServer)

- `consensus::Ballot` gains `high_water` (pass `None` for the pre-#1201 absolute count) and `roster_event_standing` / `roster_event_verdict` take a `high_water: usize` (fold it with `authorized_roster_high_water_at`). A room below its `quorum:M` now admits on its whole roster; a host that pre-checked counts with `required_signatures` should ask `required_signatures_at` with the high water, or read the door's `shortfall`.

- `Error::RosterAuthorityUnauthorized`, `consensus::Verdict::Insufficient` and `StandingVerdict::Refuse` each gain a `shortfall` field: a match written `{ rule, .. }` keeps compiling; one that names every field, or constructs the variant, adds `shortfall`. Edge's `WidenOutcome::NeedsCosign` can read `shortfall` for "have 1 of 2" and who may sign. The primary's own local door holds a short event instead (`RosterChangeNotLanded`, 61.3.0), which does not carry the count.
- A directory wrapper that implements `FederationDirectory` itself (Edge's test-only `CountingDirectory`) delegates `attestations_binding_content_with_placements`; without it, the takedown and reversal doors answer `Unsupported` through the wrapper.
- CIRISServer's `feat/room-takedown` (4d3f50b6) files the shape I1746 witnesses: a founder's or an appointed moderator's takedown of a room message or file, applied on each member's node that holds the placement. Not yet run against that branch.

### Tested

- **I1746** (two nodes; sqlite and postgres; CIRISPersist#1260): room content in CIRISEdge's row shape (a `chat:message:v1` message and a `file:v1` file, authored at `self` and `local` tier with a `community_dek` pointer and `evidence_refs`, entered into the mesh and placed by the author's `supersedes` widening). A is the author's node; B is the founder's and receives only the widenings, through `apply_replicated_attestation`. On B the founder takes the message down and its `takedown` deputy the file (`community_standards`); the same notices apply on A; both are tombstoned and withheld on both nodes. A plain member and another room's founder are refused `takedown_unauthorised` on both nodes. The `review` deputy's `reversed` ruling, placed at the room's scope, lifts the message's withholding; a plain member's is refused. A placement the author withdraws (the room-born `withdraws` delivered to B) binds no room on either node, and the founder is refused.
- **I1750** (two nodes; sqlite and postgres; CIRISPersist#1260, C536 (a)): a room of two, a founder and one member. The founder takes the member's placed message down on the founder's node, and the notice applies on the author's. The member takes down their own placed message on the founder's node, which holds only the placement: the content's signed subject signs the takedown (CC 4.5.5 (a); the takedown door has admitted the subject since v55, I786, and the placement now carries that standing to a member's node). The member cannot take the founder's message down.
- **I1747** (sqlite and postgres; CIRISPersist#1260): `attestations_binding_content_with_placements` returns the author's row and its room placement, and not a widening to `federation` scope; `attestations_binding_content` returns no `supersedes` row.
- **I1751** (sqlite and postgres; CIRISPersist#1201): a room founded alone at `quorum:3/4` seats its second member on the founder's signature, its third on both (one alone is `have 1, need 2`), and at three members `M` binds (two are `have 2, need 3`, three seat the fourth); after two resignations the room of two is stalled (`have 2, need 3`, "stalled"), and the high-water read answers 4. **I1752** (pure): `quorum_need`, `required_signatures_at` and the evaluator agree on every case, `None` and `infrastructure` included.
- **I1748** (sqlite and postgres; CIRISPersist#1250): at a node that does not speak for the primary, a `unanimous` room of three founders refuses one signature with `have 1, need 3` and two with `have 2, need 3`, naming the three founders; the third signature lands it. A `majority` room of four: `have 1, need 3`; a member removed from it who signs alone is told `have 0, need 2` and no eligible signers. A stranger's widening (`roster_authority_not_established`) carries no count. **I1749** (pure): each count arm's `have`, `need` and eligible keys, a no-signer ballot included; a self-signed admission, a weighted rubric and an admit carry none.
- **I1745** (sqlite and postgres; CIRISPersist#1195, CC 4.5.4): in a `majority` room a plain member, who may still sign for the room, is refused at the `moderation:*` act door, the takedown door and the takedown-reversal door; the founder and its `takedown`/`review` deputy pass all three. I1522 (61.0.2) covers the helpers and the community-scoped reconsideration door.

## [61.3.0] - 2026-11-11

A widening or removal of a quorum room or family no longer needs every signature in one offer: the door holds it and collects the rest (CIRISPersist#1252, CC 3.3.4). Until this cut a room of three or more could not widen or remove inside the mesh.

### Added

- **The cosign hold (CIRISPersist#1252, CC 3.3.4 step 2, CC 3.1.3 `cosign:{state}`).** A community or family widening or removal whose ONLY refusal is the consensus shortfall is held instead of refused. The verdict is read structurally: `roster_event_verdict` returns `StandingVerdict::{Admit, ConsensusShort, Refuse}`, and `ConsensusShort` means every signer is an active member at the event's signed instant and the last-founder rule holds as if the event were admitted. Every later check of the door still runs (the invitee's acceptance, the infrastructure founder gates, the steward binding). Only the local door of the node that speaks for the primary signer holds; a replicated under-signed event, and the same event at another node's local door, are refused exactly as before. The door returns the new `Error::RosterChangeNotLanded` (`federation_roster_change_not_landed`, Python `ValueError`).
- **`cosign:pending:v1` and `cosign:signature:v1` rows (CC 3.1.3, CC 2.4).** The pending row carries the event with no cosignature; its id is the quorum key, `sha256("ciris-persist/cosign-pending/v1" ‖ JCS(the event with no signature))`, and its scrub is the primary's own signature. A cosignature travels alone as a signature row: one signer, one `additional_scrubs` entry over the event's signing bytes, id `sha256("ciris-persist/cosign-signature/v1" ‖ quorum key ‖ signer)`. A stranger, the invitee or a removed member cannot fill a hold (`cosign_signer_not_member`), one proposer holds one open hold per group (`cosign_open_pending_exists`), and a self-roster `objection:assent` row is never read as a cosignature. Builders: `cosign::pending_row`, `cosign::signature_row`.
- **The cosign executor.** The admission hook and the sweep `Engine::execute_cosign_due` (pyo3 `execute_cosign_due`) union the held signature rows by signer and offer the merged event through the same typed door; it lands as the ordinary widening or removal row. The hold window is the governance table's `community_invite` / `community_remove` number (259 200 s) unless the community record sets `policy_blob.cosign_window_secs`; a value under 259 200 s is refused as policy (`GovernancePolicyRefused`, `cosign_window_below_floor`, CC 4.5.13). Families take the default. The window counts from THIS node's first receipt; expiry drops only the pending and signature rows, and the typed door never reads the window. An `open:self_admit` removal's receipt window is read against the hold's first receipt.
- **The rc18 bounds on a hold (CC 3.3.4, CC 2.6.7).** No hold BEGINS for a pending row whose event was signed more than one hold window before this node's receipt (`cosign_pending_too_old`, distinct from `cosign_pending_settled`), so no node holds a change later than two windows after its signed instant. A cosign row's signer who is no active member at receipt and signed more than W (259 200 s) before it is refused `asserted_at_stale` (`Error::AssertedAtStale`, plane `cosign`); a member still standing signs at any age. W is not added to the typed widening and removal doors (#1253 is out of this release).
- **Withdrawal.** The proposer's `withdraws` of the pending row ends the hold (`withdrawn`); a settled hold is not held again (`cosign_pending_settled`). A `withdraws` naming a signature row is refused (`cosign_signature_irrevocable`).
- **`wire_index::attestation_wire_hash(&Attestation) -> [u8; 32]`, the one ref rule for every attestation-plane row** (pyo3 `attestation_wire_hash(row_json)`). A cosigned widening or removal row is named by its act: the hash is over the row `plan_group_row` builds from the object with no cosignatures. Every other row keeps `sha256(bytes)`. The write path, both backends' point-read self-checks (`reload_record_hashed`), the rebuild and the subject refs use it. Assembled rows keep their `attestation_id`; their ref moves once, at open.
- **`ReplicatedAttestationOutcome::HeldEquivalent` (`"held_equivalent"`).** An assembled act this node holds under another row (another sufficient subset, other ML-DSA bytes), or the same signer's cosign row, settles held and books no refusal. Its id is recorded as an alias of the act, so a cosigned `withdraws` naming it retracts the row held here (CC 2.4.1.1 rule 0).
- **`Error::WithdrawsTargetUnheld` (`federation_withdraws_target_unheld`, Python `ValueError`).** A cosigned `withdraws` whose target is neither held nor an alias is refused retryably (the #858 ordering gap, beside `federation_attester_key_unknown`), never admitted inert.
- **A cosigned act's retraction holds from stored rows on every node (CC 2.4.1.1 rule 0).** `cosign::act_retracted` asks whether a held `withdraws` names any row of the act this node knows: a held row of any subset, an alias of its quorum key, or the offered id. The projection rebuild gate and the group-plane door ask it, so a rebuild keeps the retraction and no other subset's row lands the act again (it settles `held_equivalent`). The read lifecycle predicate resolves a composer through `federation_cosign_aliases`. V215 indexes the alias table by the held row, so the read seeks.
- **V214** (sqlite and postgres): `federation_cosign_pending` (one open hold per proposer per group, partial UNIQUE), `federation_cosign_signatures`, `federation_cosign_aliases`.

### Changed

- **`DIRECTORY_ABI_VERSION` 12 → 13**: `HeldEquivalent` is a new variant of a payload enum.
- **`may_receive` asks a new first arm for `cosign:*` rows**: served only to a member active at the event's signed instant AND still a member when served, in public rooms too. The invitee of a widening is not served it; the member a removal names is.
- **Every vendored CIRISConstitution file is re-vendored byte for byte from the `v1.0-rc18` tag** (`646df978`, from rc15 `ace6b74`), under the one `VENDORED_CC_COMMIT`: the namespace registry and its vectors (192 families: `cosign:{state}`, `ballot:moderator`, `ballot:moderator_acceptance` added), the governance policy table and its vectors (the rows' thresholds also stated as `enact_rule` / `cancel_rule` / `floor_rule`; a new `moderator_election` row, `ranked`, read as not two-path), `csd4_chain.json`, the topology vocabulary, the signed-object vectors and the six self-roster traces; `WIRE_VOCABULARY.md`'s pinned file hash moves (v1.0.3: `GoalDeclaration`, `GoalRetirement` and `FountainHoldingClaim` retired, none of which persist emits or decodes). `scripts/check_vendored_cc.sh v1.0-rc18` passes. `ballot:moderator*` and `moderator_election` are registered with no door (`RESERVED_AND_NOT_YET_GATED`).

### Adoption notes (CIRISEdge)

- Take every attestation ref from `wire_index::attestation_wire_hash`; never `sha256(wire_bytes)` of your own.
- Handle `ReplicatedAttestationOutcome::HeldEquivalent` (settled, nothing to re-offer).
- Park and re-offer `federation_withdraws_target_unheld` as you do `federation_attester_key_unknown`.
- Re-pin `DIRECTORY_ABI_VERSION` 13.
- The `cosign:*` dimensions are `cosign:pending:v1` and `cosign:signature:v1`; `may_receive` already scopes them.

### Tested

- **I1730–I1744** (sqlite and postgres): the shortfall holds; another refusal still refuses; only the primary's local door holds; one open hold per proposer; a stranger cannot fill a hold; the hold's audience; two nodes with different subsets land alike under one ref and settle each other's rows held; expiry; withdrawal; a pre-upgrade row's ref moves once; one hash derivation (from disk and round trip); the executor through the hook, through the sweep, and the open-room removal window; withdraws by id through the alias and its retryable gap; the window policy; the re-hold bound (I1737); a member removed since the signed instant is served nothing (I1735); freshness W on cosign rows (I1744).

## [61.2.3] - 2026-11-12

A macOS and iOS fix for 61.2.2. Every file-backed `SqliteBackend::open` with readers failed on Apple's system SQLite.

### Fixed

- **A file-backed SQLite store opens on macOS and iOS again (CIRISPersist#1261).** 61.2.2 refused it with `sqlite open readers: unable to open database file`. On Apple's SQLite, a read-only connection cannot create a WAL database's `-wal` and `-shm` files: its first access to the file fails with `SQLITE_CANTOPEN` (errno ENOENT; measured on macos-15 with SQLite 3.43.2, under rusqlite 0.31 and 0.41 alike). `journal_mode = WAL` does not create those files; the first connection to touch the database does. Before 61.2.2 the readers never touched the file while opening, and migrations on the writer created the files first. #1246's per-reader `PRAGMA cache_size` moved that first access into `ReadPool::open`. The writer now runs one read (`materialize_wal`) before any reader opens, so both files exist for as long as the writer is open. Hosts that set `CIRIS_PERSIST_SQLITE_READERS=0` as a stopgap can drop it.
- **The `sqlite open readers` error names the reader, the step that failed, SQLite's extended result code and the path.**

### Changed

- **CI: the darwin test job runs on every tag and opens file-backed SQLite stores.** 61.2.1's tag receipt skipped it on v61.2.2's tag run, but the receipt is a local certify, which runs only on Linux. The job built `--features server` only, which does not include `sqlite`, so no darwin job had ever compiled SQLite. It now also runs the SQLite connection-model witnesses against macOS's system SQLite.
- **`deny.toml` ignores RUSTSEC-2026-0487, 0489, 0490 and 0491 (hickory-proto 0.25.2).** They reach persist only through ciris-verify-core v22.2.0 → hickory-resolver 0.25, and persist calls none of Verify's DNS or HTTP paths. The fix (0.26.2) has to come from Verify (CIRISVerify#335).

### Tested

- **I1723:** the writer creates `-wal` and `-shm` before any reader opens; its first half shows that `journal_mode = WAL` alone does not. A no-op `materialize_wal` turns it red.
- **I1724:** a file-backed open with three readers succeeds, and every reader reads, on a new file and again on restart. This is the reproduction on the darwin job.
- **I1725:** a reader that cannot open reports extended code 14 and the path.

## [61.2.2] - 2026-11-10

61.2.1 was not tagged. Its CI and release-tooling changes ship here, together with #1246. The one change to the shipped crate is the SQLite connection tuning.

### Changed

- **SQLite connections get a 32 MiB page cache and memory-mapped reads (CIRISPersist#1246).** Every file-backed `SqliteBackend` connection now runs `PRAGMA cache_size = -32768` and `PRAGMA mmap_size`: the writer and each reader (`available_parallelism().clamp(2, 8)` of them, so 4 on a 4-vCPU host). Before this, each connection ran with SQLite's default page cache of about 2 MB and no mmap. On canonical-1 (a multi-GB store, 4 vCPU) `sqlite3_step` re-read pages from the OS page cache through `pread`, and `__x64_sys_pread64` took 11–15% of CPU. The mmap default is 1 GiB, or a quarter of the process's cgroup memory limit when that is smaller (512 MiB in canonical-1's 2 GiB container). Mapped pages are the same page cache a `pread` fills, and the container is charged for them either way. The page cache is allocated as it fills, up to `(readers + 1) × 32 MiB`, which is 160 MiB on 4 vCPU. Two knobs override the defaults: `CIRIS_PERSIST_SQLITE_MMAP_BYTES` (bytes, `0` turns mmap off) and `CIRIS_PERSIST_SQLITE_CACHE_KIB` (KiB, at least 1). A value that does not parse refuses the open rather than falling back to a default. In-memory databases are unchanged, and postgres sizes its cache server-side. With mmap on, an I/O error on the database file is a `SIGBUS` rather than `SQLITE_IOERR`; set `CIRIS_PERSIST_SQLITE_MMAP_BYTES=0` on storage where that matters. Measured at the SQLite level (system SQLite 3.45.1, a synthetic 1.7 GB attestation-shaped store, 7 rows per indexed lookup, warm OS cache, three interleaved rounds, a loaded host): read syscalls per query went from 14 to 3 with 1 GiB of mmap and to 5 with 512 MiB, and the median query from 29–36 µs to 22–23 µs (1 GiB) and 25–26 µs (512 MiB). This does not measure persist's row decoding, which does not change. I1720 (defaults, the cgroup scaling, malformed knobs refused), I1721 (a file-backed open tunes the writer and every reader, which still read the writer's commit), I1722 (`apply_tuning` sets exactly what it is given; in-memory is untouched).
- **A tag run takes its PR run as the receipt for its test legs.** The v61.1.0 tag run took 3h19m, and its longest job ran 71 min. The rest was runner queue: on the runner pool the CIRIS repos share, its Linux test legs waited 95–124 min for a runner and stood in front of the wheel (93 min wait), android (118–124 min) and darwin wheel (135 min) builds the release needs, re-testing bytes the PR run had already passed. CI's `tree` job (#1021) now also runs on `v*` tags. When the tagged commit is a merge whose tree equals its PR head's, and that PR run passed, the tag run skips the nine `linux-x86_64` rows other than `core-1`, `darwin-aarch64 (no postgres)` and the sqlite portability leg. The matrix `exclude` is derived from the workflow's own rows by `scripts/ci_tag_receipt.py`, and the PR `lint` job checks that it still derives. The tag run still runs everything a release needs, from its own run: `core-1` (the only Linux CIRISCache save, #895), every wheel, iOS and android build, `lint` and `license-audit` (mobile-release requires them, and an advisory can publish between the PR run and the tag, as RUSTSEC-2026-0459 did before v61.1.0), the manifest sign + register and the attestations. Provenance names the run that built the bytes, so no artifact is taken from the PR run. Any error falls back to the full run. A main push run's whole-run skip is unchanged.
- **`release_finish.sh` waits up to 360 min for the tag run** (`FINISH_TIMEOUT_MIN`, was 180). The v61.1.0 finish exited 12 with nothing wrong.

### Removed

- **Five `deny.toml` advisory ignores that matched no crate** (all features, every target): RUSTSEC-2026-0190 (anyhow 1.0.103 carries the fix), RUSTSEC-2025-0134 (rustls-pemfile), and RUSTSEC-2026-0098 / 0099 / 0104 (rustls-webpki). A stale ignore would silently re-cover its advisory if a dependency change brought an affected version back.

### Tested

- **I71's removal window no longer races a loaded box.** `i71_rotation_keys_on_effective_at` (sqlite, postgres) needs one epoch minted after a removal is recorded and before it takes effect. The window was 400 ms; under certify's co-tenant load the admit, bump and seal outran it and the premise assertion went red on postgres. The window is now 3 s, inside `COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS` (60 s), and the test sleeps until `effective_at` rather than a fixed 500 ms. What it witnesses is unchanged.

## [61.2.0] - 2026-11-09

### Security

- **RUSTSEC-2026-0459 is cleared: rusqlite 0.41.1 / libsqlite3-sys 0.39.1, with CIRISVerify v22.2.0 (CIRISPersist#1241).** Bundled SQLite before 3.54.0 reads uninitialized page-cache memory when a database is opened beside a crafted `-wal` file of another page size. Exploiting it needs local write access next to the database. 61.1.0 shipped with the advisory ignored because the fix could not land alone: `links = "sqlite3"` allows one libsqlite3-sys per graph, and CIRISVerify pinned rusqlite 0.31. CIRISVerify v22.2.0 moves to rusqlite 0.41, so persist's seven CIRISVerify pins move to that tag together. refinery 0.9.2 accepts rusqlite only up to 0.39, so refinery moves to 0.10. The bundled SQLite is now 3.54.1 on Android and Windows; other targets link the platform's SQLite, as before. The `deny.toml` ignore is gone. No persist source changed for rusqlite 0.41; the sqlite and postgres lib suites, encrypted-kv and the pyo3 lane pass unchanged.
- **MSRV 1.83 → 1.92.** refinery 0.10 needs Rust 1.92. The pinned toolchain stays 1.97.0. The higher MSRV in `clippy.toml` turns on `manual_is_multiple_of` and `manual_noop_waker`; their sites are fixed.


### Changed

- **A raw-layout capsule is named for the persist build that laid it out (CIRISPersist#1242).** Seven `PyEngine` capsules hand the consumer a raw Rust value that it reads with its own compiled copy of persist: `outbound_queue_capsule` and `blob_storage_capsule` (an `engine::BackendDispatch`, so `Arc<SqliteBackend>` / `Arc<PostgresBackend>`), `local_signer_capsule` (`Arc<LocalSigner>`), `keyring_signer_capsule` (`KeyringSignerHandle`), `federation_directory_capsule` and `trust_scoring_capsule` (`Arc<dyn FederationDirectory>` / `Arc<dyn TrustScoring>`, whose vtables are persist's build's), and `runtime_handle_capsule` (a `tokio::runtime::Handle`). Between two persist builds a moved private field is undefined behaviour that raises no error, and 61.1.0 moved one (`PostgresBackend`, #1231). Each is now named `ciris_persist::<capsule>@<CARGO_PKG_VERSION>`, for example `ciris_persist::outbound_queue@61.2.0`, from the constants in the new `ffi::capsule_names` (`OUTBOUND_QUEUE`, `BLOB_STORAGE`, `LOCAL_SIGNER`, `KEYRING_SIGNER`, `FEDERATION_DIRECTORY`, `TRUST_SCORING`, `RUNTIME_HANDLE`; `RAW_LAYOUT_CAPSULES` maps each method to its name). `ffi::capsule_names::checked_pointer(&capsule, expected)` is the consumer's unwrap: it returns the payload pointer only for a capsule named exactly `expected`, and otherwise raises a `TypeError` led by `capsule_version_skew` that names the consumer's persist version, the name it asked for and the name the capsule carries, before anything is dereferenced. A consumer that compiled persist 61.2.0 and runs beside a 61.3.0 wheel is refused at the unwrap instead of reading the wrong offsets. The version binds persist's types and, through the one CIRISVerify tag persist pins, `ciris-keyring`'s; it does not bind the consumer's `tokio` or `rustc`. The ABI-versioned capsules (`directory_ops_capsule`, `outbound_queue_ops_capsule`, `signer_ops_capsule`, `executor_capsule`) are unchanged, `_v1` names included. **A consumer that asks for the old unversioned name is refused, and one that passes the capsule's own name back to `pointer_checked` is not protected at all.** I1700 (every name carries the version), I1701 (another version, the unversioned name and a sibling's name are refused before any dereference), I1702 (the exact name is accepted), I1703 (every raw-layout capsule `PyEngine` builds carries its name, on sqlite and postgres), I1704 (no build site spells an unversioned name).

### Tested

- **The self-roster's late-joiner divergence is witnessed, not fixed (CIRISPersist#1159, still open).** On a device that joins later, its own add can arrive before an earlier one. The device then holds the earlier add as a pending proposal, which leaves that add's proposer with an open proposal and refuses a quorum-met eviction (`proposer_has_open_proposal`). CC 3.3.6.3 counts thresholds over the roster at the decision, and `asserted_at` is signer-chosen, so re-judging an add at its signed instant would let a stolen key backdate itself onto the roster. The divergence is bounded: the held add lands by the lone path after `W_self`, and the sweep then lands the eviction. I1710–I1712 (sqlite, postgres): three nodes in the T10 shape; the in-order node lands the eviction, a fresh node fed the whole stream agrees at once, and the late joiner refuses at first and converges after `W_self`. I1713: a backdated add is decided on the roster now. A fold that does not depend on arrival order needs new carried evidence or a CC ruling.

#### Adoption

- **Edge:** a raw-layout capsule unwraps only against the persist version Edge compiled. Build Edge against the same ciris-persist version as the wheel it runs beside, and unwrap with `ciris_persist::ffi::capsule_names::checked_pointer(&cap, ciris_persist::ffi::capsule_names::<CONST>)` (or `pointer_checked(Some(<CONST>))`) in place of passing `cap.name()` back, or move to `outbound_queue_ops_capsule` (CIRISEdge#960), which dispatches inside persist's `.so` and is not version-bound.

## [61.1.0] - 2026-11-09

### Added

- **A since-cursor feed of the announced roster (CIRISPersist#1163, CC 5.4.6).** `FederationDirectory::list_owner_bindings_since(since, limit)` pages the attestation serve stream (a `ServePosition`, `(admitted_at, attestation_id)`, exclusive, as `list_attestations_since`) over the rows that can change an owner binding: every owner-binding `delegates_to`, and every `withdraws` / `recants` / `supersedes` attested to a node an owner binding names. Each node the page touches comes back once, at its last row in the page, with its state folded now by the new `admission::announced_owner_state`: `Announced { owner_key_id }` (a live owner binding carried at `cohort_scope: federation`, and the node's one owner by `owner_of`), `NotAnnounced`, or `AmbiguousOwner`. A node whose fold fails at the read is `Unresolved { reason }`, an item and not a failed page, so one bad node cannot stall the cursor; the consumer keeps what it held for that node and re-asks `announced_owner_state`. The item is a state, not a delta, so a consumer upserts by node. A withdrawn or recanted binding is a row admitted at a new serve position, so the removal arrives through the same cursor as `NotAnnounced`. A page is at most 500 candidate rows, because each node it touches costs one fold; a page size outside [1, 500] is refused with a message led by `serve_limit_out_of_range`. The page is a `ServePage<OwnerBindingChange>` (`items`, `next_cursor`, `high_water`). The canonical's announced-relay pass walked every person each minute; it now applies the rows since its cursor. I1575 to I1578 and I1672 (the failed fold); I1674 holds the feed's owner-binding marker SQL equal to `admission::is_owner_binding_envelope` over a set of envelopes on sqlite and postgres. No migration.
- **`list_attestations_since` narrowed by family (CIRISPersist#1190, Edge v44, CIRISConstitution#198 §5).** `FederationDirectory::list_attestations_since_by_prefixes(since, family_prefixes, limit)` returns the served rows whose family starts with one of `family_prefixes`. The family is `row_type::claim_token`'s, the one every family-keyed gate asks (CC 2.4): a `scores` row's `dimension`, any other row's `attestation_type`, a composer's verb included. So both shapes of a family are selected by one prefix, and a non-`scores` row is never selected by a `dimension` it carries. Same `ServePosition` cursor as `list_attestations_since`, and the same serve rule (federation tier, no unregistered type under enforcement (CC 2.4), no purge-tombstoned row the tombstone is not void for), now spelled once (`read_plan::serve_rule_parts`) and used by `list_attestations_since` on both backends, the #1225 subject read and both new reads. A prefix is a byte prefix, matched as a half-open range, never `LIKE`. Refused, the message led by a stable token: no prefix, an empty prefix, more than 64 prefixes (`serve_prefixes_refused`); a page size outside [1, 10000] (`serve_limit_out_of_range`). The page is a `ServePage<ServedAttestation>`. Its `high_water` (where to resume once nothing remains: the stream's head, so a sparse family does not rescan every other family on each poll; `ServePosition::origin()` for an empty stream) is exact on sqlite, whose one writer assigns the serve position inside its transaction. On postgres the position is assigned before the write transaction, so rows commit out of position order and a high water at the head could skip a row that commits late: there the head is clamped to `read clock − 30 s`, below which every position has committed (a lag window, because in-flight positions are invisible to a reader; the 30 s bound is the write door's, BELIEVED, not enforced). A resume re-reads at most the last 30 s of the stream. Both new reads share one statement builder for both dialects (`read_plan::serve_stream_statement`) and walk V130's `federation_attestations_admitted` index. I1570 to I1579, I1670 (the selection is `claim_token`'s row for row), I1671 (postgres: a high water taken while a lower position is in flight does not pass it). No migration.
- **`high_water` on both pages.** `next_cursor` is present exactly when more remain. When none does, `high_water` is the stream's head at the read (read before the page), so a consumer of a sparse narrowing resumes past the rows it has already ruled out instead of rescanning every other row since its last match on each poll.

- **Read attribution by caller (CIRISPersist#1235, Bridge, Server).** Bridge's 61.0.4 harness recorded 187,251 reads in 45 minutes, 92% with no caller, and `attestation_query` alone moved 58.8 MB per 30 s. A host can now name who a read is for: `observe::Caller::new(label)` validates and interns a short label (1 to 48 bytes of `[a-z][a-z0-9_.:-]*`, not `unattributed`; a malformed label is refused, never counted as absent), and `observe::caller_scope(caller, fut)` credits every door read `fut` makes on its task to `(backend, door, caller)`. Nested scopes: the innermost wins. `observe::ThreadCallerScope` and `observe::set_thread_caller` do the same for a thread that drives persist's futures itself, which is how the PyO3 surface attributes: every Engine method polls its read on the calling thread. A task scope wins over a thread scope. Past 32 distinct labels per process every new label is counted under `other`. The directory capsule carries the caller in force at `build_op` onto the worker that polls the op. With no scope set a read costs one task-local probe and one thread-local read, and no atomic: the `unattributed` share is derived when the snapshot is taken. Witnesses I1580 to I1588 (sqlite and postgres for the door reads, the capsule on sqlite).

- **Split debuginfo for the linux wheels (CIRISPersist#1234, Bridge).** Each release now carries `ciris_persist-<v>-linux-{x86_64,aarch64}.abi3.so.debug`: the full symbol table and persist's line tables for the wheel's stripped `ciris_persist.abi3.so`, with the same GNU build-id, named by the `.so`'s `.gnu_debuglink`. Bridge's 61.0.4 harness put 31% of peak CPU in the native module and could not split it by function. The files are release assets, listed in `SHA256SUMS`, with SLSA build provenance like the wheels and tarballs. `scripts/verify_release.sh`, which `release_finish.sh` runs, verifies their provenance, checks their `SHA256SUMS` lines, and checks that each one's build-id is the build-id of the `.so` in its target's wheel. The linux wheel is built once, unstripped, and `scripts/split_wheel_debuginfo.py` derives the shipped stripped `.so` and the debug file from that one link before the wheel is uploaded, signed or registered, so the registered and attested hash is still the hash of the wheel that ships. Install and use: docs/RELEASE.md "Symbolizing persist frames".

- **An adversarial review checklist for federation trust and admission (CIRISPersist#1229).** `docs/ADVERSARIAL_REVIEW_CHECKLIST.md` takes the five questions an external review asked (can Sybil identities acquire trust, can quorum voting be manipulated, can a compromised steward capture authority, does revocation propagate across disconnected nodes, do SQLite and PostgreSQL enforce the same authorization) and ties each to its constitutional rule (CC 4.4.3.4.3, 4.4.3.8, 5.4.6; 4.5.13, 3.1.3.2, 6.1.9; 1.13.2, 4.2, 4.5.1; 2.4.1.1; the no-backend-only-door rule) and to the witnesses persist holds, by invariant and test name, with their backends. It adds the 61.1.0 rows: #1218 H1 (I1600, I1601, I1603, I1604), #1233 (I1560–I1568), #1174 (I1590–I1596, I1607), H3 (I1605/I1606), #1238 (I1660–I1663) and #1239 (I1569). Fifteen gaps are listed as gaps, not defects, among them no two-node partition-and-remerge test with a late revocation, no mesh story trace replayed on both backends, no witness for leaving or founding a root, and parity counts that are reported but not asserted. A docs row is added to the README.

### Changed

- **Hybrid-required is the only verifier policy a caller can pass (CIRISPersist#1233, CIRISEdge#957, CIRISAgent#1348; CC 5.3.2.4.3.1).** `Engine.verify_hybrid`, `Engine.verify_hybrid_via_directory`, and `verify_signed_key_record` / `verify_signed_attestation` / `verify_signed_revocation` (which route through it) refuse every `policy` except `"strict"` with `ValueError("verify_policy_violation")`, before any decode, directory lookup or crypto. The capsule op `DirectoryOp::VerifyHybridViaDirectory` refuses every `HybridPolicy` except `Strict` inside `HybridVerify`, with a message led by `verify_policy_violation`. The Rust API refuses them too: `verify::hybrid::verify_hybrid`, `verify_hybrid_via_directory` (before the directory lookup) and `verify::ed25519::verify_trace_hybrid` (before the trace is canonicalized) return the new `VerifyError::PolicyViolation { policy }`, whose `kind()` is `verify_policy_violation`. Every one of these paths asks the one check, `verify::hybrid::require_strict_policy`, which now returns that `VerifyError` instead of a `String`. Persist's two pinned classical-only planes (`audit::verify::verify_entry_signature` and `cirisnode::verify::verify_envelope_signed`) call a crate-private policy-taking twin and are unchanged. A Rust caller that matches `VerifyError` exhaustively needs an arm for the new variant. The arguments and the wire field stay until v62 removes them. I1560–I1563 cover the Python doors on sqlite and postgres, the capsule, and the wheel; I1568 covers the Rust API (unit, trace, and `verify_hybrid_via_directory` on sqlite and postgres).
- **The audit plane's hybrid gate is the signed tree head (CIRISPersist#1233; CC 5.3.1).** `merkle_store` refuses a NEW head without its ML-DSA-65 half where it is stored (`store_sth`), on sqlite and postgres. `HybridSignature` already makes a removed half undecodable; the new shape check (`require_hybrid_sth`) refuses an empty or wrong-length half, another PQC algorithm, and `mode: ClassicalOnly`, with `audit_sth_not_hybrid`. New `verify_audit_sth(sth, ed25519_pubkey_b64, ml_dsa_65_pubkey_b64)` verifies a head hybrid-Strict against the signer the verifier pinned, never the keys the head carries. A head already stored is served as itself (CC 2.6.1.8: an earlier form verifies as itself for rows anchored before the cutover): `latest_sth`, and so `AuditService::current_sth`, the trust-grant inclusion proof and `audit_chain_proof`, ask no shape gate, so a tenant whose head an earlier build stored keeps its proofs and can still append, and `verify_audit_sth` refuses that head. A head written after the gate cannot lack its half, since `store_sth` refuses it. I1564–I1566.
- **`audit_chain_proof` no longer serves an unreadable head as no head.** It folded every `current_sth` error to `head_signature: None`, so a stored head that did not decode came back as the chain with no head. That error now propagates. Only `audit::Error::NotImplemented` (an audit backend with no head surface) is still `None`. I1567 on sqlite and postgres: a genuine head is served; a stored head without its ML-DSA-65 half is served as itself and `verify_audit_sth` refuses it; a head that does not decode is an error.
- **The PINNED notes in `audit::verify` and `cirisnode::verify` say where the gate is.** Per-entry Ed25519 on an `AuditEntry` is an inner signature under the hybrid-signed head, not a gap. The cirisnode envelope check is a classical-only accommodation on federation-tier rows and becomes conformant in v62, when a `ContributorId` resolves to a hybrid `federation_keys` record. Neither policy argument changes; both now reach the verify through the crate-private `verify_hybrid_with_policy`, since the public `verify_hybrid` refuses `Ed25519Fallback`.

### Fixed

- **RUSTSEC-2026-0459 is ignored in `deny.toml` until CIRISPersist#1241.** Bundled SQLite before 3.54.0 can return uninitialized page-cache memory when a database is opened beside a crafted `-wal` of another page size. The attacker has to write files beside the database. The fix (rusqlite 0.41 / libsqlite3-sys 0.39) waits on a CIRISVerify tag off rusqlite 0.31, refinery 0.10.1 and Rust 1.92. A consumer's cargo-deny needs the same ignore until then.

- **A room counted keys, not people** (CIRISPersist#1198, CC 4.5.13, CC 3.3.6.3, `CLM-vote-once-per-person`). A tally now counts fedIDs: `federation::key_person` resolves a key to the self whose roster it belongs to, and every room vote reads that. On the reverse-quorum plane this covers ballots, objections, dismissals, recusal, the duty-holders' bench and every threshold's denominator. On the roster plane it covers `consensus::evaluate` in every protocol, for communities and families, `verify_membership_quorum` and the cosigned `withdraws` of a roster event. Two seats held by one self are one voice in the numerator and the denominator, and any key of a seated person votes and signs for them, seated or not. A key of another self counts for nothing, and neither does a key with a held revocation. An evicted device's seat stays its person's, so the person's other keys keep the voice. The trust-root chain and the licence quorum stay per key.

- **A steward tier's deadline is this node's window** (CIRISPersist#1198, as ruled). It ran from the action's signed instant; it now runs from the instant this node first held an objection to the action (V213), written in the objection's own transaction, so it closes once and never reopens, and a later objection cannot move it. A failed write of that instant fails the row, and a re-offer lands both. A held duty-holder's ruling decides at any time, including after the window closed. The tally is the same on every node holding the same rows; the tier is each node's until every window has closed. An objection held before this version keeps the earliest `admitted_at` of its action's objections.

- **A vote's count no longer depends on arrival or on a clock** (CIRISPersist#1198, CC 4.5.13 as ruled on the ticket). A person's agreeing live rows are one voice, and rows that disagree are no voice until a retraction leaves one. This retires the latest-instant fold of `governing_ballots`, including the tied instant that counted as upheld. Only a held revocation ends a key's voice: a revocation at or after the key's latest held assertion, whatever instant it names. Expiry ends nothing at the count, and `now` no longer bounds which ballots are counted, so a row dated ahead that passed the door's signed-instant gate counts at once.

- **Every verifiable vote row is admitted, and the fold voids it** (CIRISPersist#1198, as ruled). A ballot, objection or `withdraws` of one was refused by asking who its signer was, which answered by arrival order. A second device's ballot that arrives before its occurrence row is now held and counts the moment that row is held, on every node. The same holds for a ballot before its objection, an objection before its action, and a dismissal before its objection or its cosigners' standing: each is held and counts once the fold can resolve it, and one naming something never held counts for nothing. A dismissal short of its floor is held with no force, since the read re-counts it. The door still refuses a row filed against the wrong actor, one dated before a held action, and the actor's own key on a ballot, when the target is held. A `withdraws` of a ballot or a cohort objection by another key is admitted with no admission rule, and the fold honours it only from a key of the author's fedID. A `recants` retracts a vote row as a `withdraws` does. A self roster's objections are unchanged.

I1525–I1539 cover both planes on sqlite and postgres through the doors, and 720 orders of six rows fold to one answer.

- **A foreign copy of the Postgres checkout no longer spawns on a raw tokio `Handle` from persist (CIRISPersist#1231, Edge cohabitation SIGSEGV).** `PostgresBackend` kept the runtime it was built on as a raw `tokio::runtime::Handle` for the checkout's timer. Edge links persist as an rlib, so Edge's `.so` compiles its own copy of `checkout_bounded` against its own tokio. On persist's executor worker, where Edge's tokio has no runtime, that copy called `spawn` on a `Handle` laid out by persist's tokio (1.54 vs 1.53) and crashed in `OwnedTasks` (rc=-11 in every postgres conformance script that runs `init_edge_runtime`). The backend now holds an `Arc<dyn PersistRuntimeTimer>` that persist's `.so` builds. The timer's `sleep`, and the `poll` and `drop` of the future it returns, run at the vtable persist wrote, on persist's tokio. This is the shape of the #705 pool connector. A losing timer is aborted, as before. `get_client`'s retry backoff takes the same path when it is polled off a runtime, where `tokio::time::sleep` panicked. Callers on a runtime see no change.

- **A `withdraws` that arrived before its target could retire a row its subject may not withdraw** (CIRISPersist#1218, CC 2.4.1.1, CC rc15 standing rules). The door refuses a subject's `withdraws` of a `capacity:`, `detection:`, `licensure:`, `revocation:`, `moderation:`, `hard_case:`, `slashing:` or `takedown_notice:` row, and of a cosigned act, but it can ask only when the target is held. A `withdraws` that arrived first was admitted with no rule, and once the target landed the retraction fold retired it on the subject's word. The fold now asks the door's own predicate, `precedence::subject_withdraws_carved_out`, so such a target is retired only by its producer, or by a rule the door stamped that is not a subject rule (1, the producer's principal; 5, the CC 3.2 recovery ceremony). A subject's `withdraws` of such a row that an earlier version stamped rule 2, 3 or 4 no longer retires it. A cosigned group-plane row and an `identity:occurrence:v1` row keep their own planes' rules. The predicate classifies the row by `row_type::claim_token`, so a type-slot `capacity:*` row is carved out as its `scores` twin is (and `reverse_quorum::is_vote_row` classifies the same way).

- **A peer could supply a `withdraws` row's admission rule** (CIRISPersist#1218, CC 2.4.1.1). `withdraws_admission_rule` is this node's record of which rule its door admitted a `withdraws` under, and no signature covers it. The door overwrote it when the target was held, but kept the offered value when the target was not, so a `withdraws` replicated ahead of its target with a forged rule 1 or 5 retired a row its signer had no standing over. The door now writes the rule on every row it stores, through `put_attestation` and `apply_replicated_attestation` alike: unset for a `withdraws` whose target is not held, and for every other type.

- **Past its producer, only the door's stamp lets a `withdraws` retire a row** (CIRISPersist#1218 as ruled, CC 2.4.1.1, CC 3.2). A `withdraws` that arrived before its target carries no rule, and the retraction fold used to honour it anyway when its signer was named in the target's `subject_key_ids` (the subject arm). That arm had no door behind it. A node named as the subject of its own owner-binding could send its `withdraws` ahead of the binding and shed its owner once both were held, where in order the door sends that `withdraws` to the CC 3.2 recovery ceremony and refuses it. `precedence::retraction_entitled` now honours an unstamped `withdraws` only from the target's producer, for every target. The rule this node's door stamps at admission, with the target held, is the only other authority. A held row is never rewritten (FSD 5.8), so a deferred `withdraws` stays unstamped when its target arrives. The folds that read it (`retracted_edge_ids`, the owner-binding walk and `owner_of`, `goal_projection`, `community_trust_consent`) follow; `migration::fold_retractions` already asked for a stamp across attesters. **This is fail-closed and order-dependent, and v62 owns it:** an honest non-producer `withdraws` (a subject's of a plain row about them, a proxy's) that arrived before its target retires nothing on that node, while a node that received the two in order stamped it and retires. The bytes plane (`blob_tombstone::retiring_composer`) re-asks the door at read time (I150) and is unchanged. I1600–I1604 on sqlite and postgres; I1604 is the owner-binding case.

- **A self-roster proposal could be held without its window** (CIRISPersist#1220, CC 3.3.6.3, V199). The proposal's receipt, the instant this node first held it and so the start of its lone-path window, was written after the row committed, and a failed write left the proposal held with no window: it never landed and the sweep never found it. The receipt is now written in the row's own transaction on sqlite and postgres, so a failed receipt fails the row and a re-offer lands both. This follows the vote-window fix of CIRISPersist#1198. The after-commit note remains only to heal a proposal an earlier version held without its receipt, when that proposal is offered again.
- **Both receipt windows a row opens start at one instant.** A cohort objection's vote window (V213, CIRISPersist#1198) started at the door's receipt clock and a self-roster proposal's (V199) at a second clock read inside the plan. Both now take `attestation_admit::first_held_instant(received_at)`: the door's one clock read, at microseconds, the precision both backends store. The plan reads no clock of its own (CIRISPersist#934), and `store::parity`'s `PLAN_INSTANTS` pins the row. The sqlite spelling of both is `first_held_instant_text`.

- **A `scores`-form row meets every gate its classic-form twin meets (CIRISPersist#1174, the v62 family census).** Four gates keyed on the `attestation_type` slot or a prefix string, so a row carrying its family in the envelope `dimension` met none of them. Each now asks the one family classifier, `row_type::claim_token` (a `scores` row's `dimension`, any other row's type; `row_type::claim_token_of` over the two parts, `row_type::claim_token_under` for a stem):
  - the `health:liveness:` self-emission ban (CC 3.1.9.4): a service attesting its own liveness is refused `invariant_registry_self_emission_forbidden` in either form;
  - the `hard_case:` emitter rule (CC 3.1.9.4): in either form the signer's `identity_type` contains `substrate_persist` or `node` (`admission::HARD_CASE_EMITTER_IDENTITY_TYPES`; `node` is the key persist's own hard_case door signs with), and a row about another party needs `infra:record_hard_case` conferred. A peer's `scores` row about a third party no longer lands in `hard_case_events`. The classic form now also admits a `node` key's row about itself;
  - the substrate self-report families (`system:`, `audit_chain:`, `corpus_health:`, `identity_continuity:`, `federation_directory:`; CC 3.4.3) describe the substrate that signs them: a row whose `attested_key_id` is not its signer is refused `federation_dimension_rejected` / `substrate_self_report_names_another_party` (`admission::check_substrate_self_report_attester`; the token is appended to `dimension_rejected_reason::ALL`, terminal). **Enforced for a node's own writes** (the local-tier door, `put_attestation_authored`, the promotion that crosses a local row); **reported on replicated and peer-offered rows until v62** (`put_attestation`, `apply_replicated_attestation`, a sync: admitted, logged with the token, counted under `persist_substrate_self_report_would_refuse_total{type_stem}`, served by `row_type_report` as `substrate_self_report_would_refuse`), so a peer that has not upgraded is not cut off. `admission::check_substrate_self_report_attester_at` takes the door (`SelfReportDoor`). I1593 (refused at the node's own door), I1607 (a peer's admitted and reported; the local-tier door refuses);
  - `trace_summary:` (CC 3.1.5, the same CC 3.4.5 reserved rule as `trace:`): the signer must be among `subject_key_ids`, else `federation_trace_dimension_invalid`. The `trace:` gate also reads a row carrying `trace:*` in its type slot (`admission::trace_family_token`).
- The local write door refuses a `hard_case:` family in the type slot as well as in the dimension.

- **The cohort revoke door can carry the one-voice countersign (CIRISPersist#1226, CIRISConformance test_263; CC rc14 4.4.3.2.8, `CLM-affiliation-one-voice-countersign`).** `RevokeSpec` had one authority signature and no co-signature list, so `revoke_member` (PyO3 `cohort_revoke_member`, `cohort_swap_member`'s removal) could not remove a member from an affiliation with one deciding seat: the seat alone is refused `affiliation_countersign_missing`, and the designated official's countersign had nowhere to ride. `RevokeSpec` now takes `cosignatures`, the same `RosterCosignature` list `AdmitSpec` and `put_community_json` take, each over the same revocation `signing_envelope()`. `revoke_member` hands them to the family or community revocation door, which verifies each against its signer's registered keys and counts only verified signers toward the group's standing and the one-voice countersign. A `self` removal carrying a co-signature is refused with the new `federation::Error::RevokeMemberRefused { reason, detail }` (kind `federation_revoke_member_refused`; Python `ValueError("federation_revoke_member_refused: self_removal_cosignatures_refused")`), whose `reason` is the stable token `cohort::SELF_REMOVAL_COSIGNATURES_REFUSED`: that path has no gate to count it. `RevokeSpec::signing_envelope(cohort, group, removed)` is the bytes the authority and every co-signer sign, built by the same `RevokeSpec::family_revocation` / `community_revocation` the door stores, so a signer cannot sign a row the door does not build. The countersign is a second PERSON (CIRISPersist#1198 person counting): an official key that is a device on the seat holder's own self roster is one voice with the seat and is refused `affiliation_countersign_missing` (I1616). A removal the removed member co-signed is their own leave and needs no official (I1617).

- **A hard_case record over an id a peer's row holds was dropped in silence** (61.1 review H3). A hard_case row's id is derived from its event's `event_id`, and the writer inserts it if absent. Two nodes that observe one membership removal derive the same `event_id`, and a peer can pre-claim one, so a peer's replicated row under the id this node's record derives made `record_hard_case` (and every in-transaction emitter: an erasure, a peer removal, a membership change) return `Ok` having written nothing. On sqlite and postgres the writer now reads the held row's signer. When another key signed it, this node's record is written under an emitter-bound id, `hard_case::hard_case_attestation_id_for_emitter(emitter_key_id, event_id)` (a domain-separated preimage, `ciris:hard-case:emitter:v1:`, that the v1 derivation cannot produce and no other key can pre-claim), the write is logged with `hard_case_id_held_by_foreign_row` and counted (`persist_hard_case_foreign_occupant_fallback_total`), and the act commits. The foreign row stays where it is, for an operator to purge. A re-record of an event this node already holds under its own key is still a no-op. Readers ask both ids (`hard_case::hard_case_ids_for`, `hard_case::held_record_of`), the projection accepts a row at either, and `hard_case_events` (one row per `event_id`) keeps an emitter-bound row over the v1 row, then the lower id, in the live write and the rebuild alike (`hard_case::projection_outranks`). The v1 derivation is unchanged (v62 moves every record to an emitter-bound id, CIRISPersist#1237). I1605/I1606 on sqlite and postgres.

- **`FaultInjectingDirectory` reaches the backend's `list_attestations_naming_by_dimension` (CIRISPersist#1232, Edge).** 61.0.5 (#1225) added the read as a defaulted-`Unsupported` method but left it out of `DELEGATED_DEFAULTS` in `scripts/gen_directory_double.py`, so the double inherited the default and answered `Unsupported` with no fault declared. It is now delegated (the double is regenerated), and I1650/I1651 witness on sqlite and postgres that the un-faulted double serves the backend's pages and that a declared fault still answers first. The generator no longer depends on someone listing a new leaf: a defaulted method whose body is exactly `Err(Error::Unsupported { .. })` (after any `let _ = ...;` of its arguments) composes nothing through `self`, so it is found and delegated. `DELEGATED_DEFAULTS` keeps only the leaves whose default is something else (six: a no-op, `None`, "none held", a generic `Backend` error), and a new `NOT_DELEGATED` (empty) names any `Unsupported`-bodied default the double must still not delegate. The double now delegates 135 methods, up from 97: every method delegated before still is, and 38 `Unsupported`-defaulted leaves nobody had listed (the purge, consent-peer, announced-peer, scores, signed-community/family feed and `_v31` reseal reads and writes among them) now reach the backend instead of answering `Unsupported` with no fault declared.

- **A second process writing the same SQLite file no longer fails at once with `SQLITE_BUSY` (CIRISPersist#1238, Edge's darwin×sqlite cohabitation failure).** 65 write transactions in `sqlite.rs`, and one each in the secrets and telemetry stores, began with rusqlite's `Connection::transaction()`, which is `BEGIN DEFERRED`. A body that reads before it writes (`store_planned_key_record` reads `sqlite_next_key_serve_position`, then INSERTs) holds a read snapshot when it reaches its first write, and SQLite does not run the busy handler for that lock upgrade. So when another process held the write lock the upgrade failed within milliseconds, and `busy_timeout = 30000` never applied: with one process holding `BEGIN IMMEDIATE` for 2 s, Edge's `register_self_federation_key` failed `federation_backend` in 1–3 ms, 3 runs of 3, and 4 processes × 15 registrations gave 23 failures. Every write transaction now begins through one helper, `store::sqlite_conn_model::write_tx`, which is `BEGIN IMMEDIATE`: the write lock is taken at `BEGIN`, where the busy handler does run, so a second writer waits up to the busy timeout. That covers the 65 sites in `sqlite.rs`, plus the accord proposal's site, which already began `IMMEDIATE` and now uses the helper, and the secrets master-key rotation and the telemetry summary prune. The other sqlite stores (audit, Merkle, retention, ledgers, tickets, tasks and the rest) already began `IMMEDIATE`. The two read-only transactions, `stream_chunks` and `list_trace_summaries`, stay deferred, on read-only connections. A from-disk gate (I1661) refuses, anywhere in `src/`, a `.transaction()` that is not awaited (rusqlite, not tokio-postgres), an `unchecked_transaction()`, `TransactionBehavior::Deferred`, `transaction_with_behavior` passed anything but `Immediate`/`Exclusive`, and a `"BEGIN"` string that is not `BEGIN IMMEDIATE`/`EXCLUSIVE`. Each permitted site is named with its reason, and the helper is pinned to `Immediate`. The conn-model gate now also refuses a write verb, `write_tx` or a `HelperWrite` call inside a closure handed to the read door (I1663). I1660 (two connections, one file): another connection holds `BEGIN IMMEDIATE` for 1 s, and the key-record door and `put_attestation` each finish after it lets go, and succeed.
- **A backend error now reaches Python with its detail (CIRISPersist#1238).** `federation_err_to_py` raised `RuntimeError("federation_backend")` and sent the detail only to `tracing::warn!`, which has no subscriber on a PyO3 host, so Edge could not tell a locked file from anything else. The message is now `federation_backend: <detail>`, for example `federation_backend: key record write <key_id>: database is locked`. The type is still `RuntimeError`. I1662.
- **`Engine.verify_trace`, the dry-run, gives ingest's verdict (CIRISPersist#1239; CC 5.3.2.4.3.1).** It called `verify_trace_via_directory`, which checks the Ed25519 half only, while `receive_and_persist` verifies both halves under `HybridPolicy::Strict`. So the dry-run accepted a trace with no PQC half, or a bad one, that ingest refuses, although its docstring said the two agreed. Ingest's verify step is now one function, `ingest::verify_trace_for_admission` (signer key by `signature_key_id`, canonicalizer by the signed `trace_schema_version`, ML-DSA-65 key from the directory by `pqc_key_id`, `verify_trace_hybrid` under `Strict`, the #225 hard cut, the error mapping), and both `receive_and_persist` and `Engine.verify_trace` call it. The two Python surfaces raise through one mapping (`ingest_err_to_py`), so the same cause raises the same type and token. The dry-run still stores nothing, releases the GIL for the whole verify, and returns `{"verified": True, "schema_version": ...}`. The FFI's `TraceKeyDirectory` shim and its canonicalizer seam are gone (the rule is `ingest::trace_canonicalizer`), and the #580 GIL gate drops the exception and the clause that paid for the shim. I1569 runs one corpus (genuine hybrid at 2.7.0 and 3.0.0, no PQC half, a corrupted ML-DSA-65 signature, a corrupted Ed25519 signature, an unknown signer) through the dry-run, ingest's verify and `receive_and_persist` on sqlite and postgres, and asserts that the no-PQC trace, which passes the classical check v61.0.5's dry-run ran, is now refused.

- **The v61.0.0 mutation run left 22 survivors, and one kept the nightly job red four nights running (CIRISPersist#1188).** Each now has a witness that turns red under its mutation, or an allow-list entry. I1620 (sqlite, postgres) is the nightly's `check_cosigned_withdraws` `subject` (`!=` to `==`): a retraction names the member its row names and a record's withdrawal names none, so under `unanimous` every other member retracts a widening without the member it seated, and under `open:self_admit` two founders dissolve a public room and one does not (CC 3.1.3.2, CC 4.5.13). I1621 (pure) pins `consensus_protocol::founders_hold_authority` and `is_canonical_form` by truth table (`quorum:0/0`, `quorum:3/2`, an empty `custom:` tail). I1622 (pure): the supersede's held-head verdict reads the head's proof and names its group (CC 3.2 T6). I1623 (sqlite, postgres, two nodes): a stranger's `withdraws` of a room's record, held before the record and so unstamped, dissolves nothing (CIRISPersist#1218 H1, CC rc14 4.4.3.2.8). I1624 (sqlite, postgres): `live_standing_proposal` re-judges at the read: a public room not under `open:self_admit`, an invitation, a resigned founder and a stranger's early `withdraws` serve or retire nothing, and a founder's occurrence key signs a live one (CC 3.2). I1625 (sqlite, postgres): a family's record names its own audience to a node that holds nothing of the family (CC 6.1.5.3); I1521 already witnessed this and is now in the scope's filter. I1626 (sqlite, postgres): a transport route displaces only its own kind (CC 3.4.7.3). The match guard in `community_dissolved_at` is allow-listed as equivalent: a listed row's record is the listed community's, by `check_canonical_group_row`. The scope filters (`scope-s1-retire`, `scope-s2-rooms`, `scope-s3-shapes`, `scope-s4b-plans`) now select these witnesses. No production code changed.

### Adoption

- **A changed answer takes a retraction.** A ballot that disagrees with the same person's earlier ballot used to replace it; now the person has no voice until one row is withdrawn or recanted. A host that lets a member re-vote must retract the old row, from any of the person's keys for a `withdraws`, and show the at-odds state.
- **Rows that used to be refused are now admitted.** A stranger's or an evicted device's ballot or objection, a second objection by one key, a stranger's `withdraws` of a vote row, a vote row naming something not held, and a dismissal short of its floor are held and count for nothing until the fold can resolve them. **Five refusal tokens are removed:** `not_a_cohort_member`, `duplicate_objection`, `target_action_unknown`, `objection_unknown` and `dismissal_quorum_short` (the matching `ObjectionRefusalReason` variants). A host that branched on them must read the fold. `record_objection_dismissal` returning `Admitted` no longer means the dismissal has force: read `DismissalQuorum` or the fold. `ActorRecused` stays for the actor's exact key where the target is held, and the actor's other devices are admitted and voided. Rates and carriage bound what void rows cost (CC 5.3.3.5, 5.4.6).
- **A held dismissal can stop clearing.** One carried by two seats of one self now counts them as one voice at every read, so it may no longer meet its floor, and the objection it dismissed stands again. This is the rule working.
- **`steward_deadline` is this node's.** The field keeps its name and shape, and two nodes can now report different values. A late duty-holder's ruling now decides, where it used to count only as a respondent's ballot.
- **An expired device keeps its voice.** A host that relied on `valid_until` to end a device's vote must revoke the device.
- **`roster_size`, `required`, `distinct_objectors`, `respondents`, `duty_holders` and `DismissalQuorum` count persons.** The fields keep their names and JSON shape; a room with two seats for one self reports fewer. `counted_ballot_ids` and `counted_objection_ids` hold one row per person, the lowest id.
- **Public Rust shapes changed.** `consensus::Ballot`, `ReverseQuorumInputs` and `RosterRules` gained `persons` (`RosterRules::of_community` and `of_family` default to the per-key count; add `.with_persons`). `community_roster_events` and `family_roster_events` take the persons as an argument. New: `community_key_selves`, `family_key_selves`, `reverse_quorum::is_vote_row`.
- **Roster events already held stay in the fold.** One admitted under the per-key count stands, and a new one is judged by persons at the door. A node on 61.0.4 refuses such an event arriving from an older node, so the two can hold different rosters until the room acts under its protocol.
- **Pass `"strict"`.** Any other `policy` now raises `verify_policy_violation`; `soft_freshness_window_seconds` and `row_age_seconds` are ignored. The agent already passes `"strict"` (CIRISAgent#1348). A capsule consumer sending `Ed25519Fallback` or `SoftFreshness` gets `HybridVerify(Err("verify_policy_violation: …"))`. v62 removes the argument.
- **`audit_chain_proof` can now raise** where a tenant's stored head is refused or unreadable; it used to return the chain with no head.
- **New reads: `list_attestations_since_by_prefixes` and `list_owner_bindings_since`, their capsule ops `DirectoryOp::ListAttestationsSinceByPrefixes` and `DirectoryOp::ListOwnerBindingsSince` (results `ServedAttestationPage` and `OwnerBindingPage`), and the same two methods on the Python `Engine` (JSON).** Append-only growth on both enums; `DIRECTORY_ABI_VERSION` is unchanged at 12. A directory that does not override either method answers `Unsupported`.
- **What the owner-binding feed cannot see.** A binding's `expires_at` or `valid_until` passing, and a change to the granter's key record or roster, change the fold's answer with no row. A consumer that needs a clock-correct roster re-asks `admission::announced_owner_state` for the nodes it holds (a handful, not every person).
- **Resume from `high_water`, not from the last item,** when `next_cursor` is absent.
- **New telemetry door labels** `list_attestations_since_by_prefixes` and `list_owner_bindings_since` on the read counters. The owner-binding feed's per-node folds count under their own doors.
- **`observe::snapshot()` gains `callers`**, additive: `reads` and `folds` keep their keys and shapes. Each entry is `{backend, door, caller, reads, rows, bytes}`, listed for each `(backend, door)` per caller that read through it, plus one `unattributed` entry for the reads under no scope; a door's entries sum to its `reads` entry. Server's `/v1/node/diagnostics/reads` serves it as is. Rust code that builds a `TelemetrySnapshot` by struct literal adds `callers`.
- **Wrap each loop's work in `caller_scope`** (Rust) or `with ciris_persist.caller_scope("label"):` (Python; also `set_caller_scope(label) -> previous`). A task you spawn does not inherit the scope: carry it with `observe::current_caller()`. A thread scope set on an async runtime's worker credits every task that worker polls, so use the thread form only where the thread blocks on persist (`block_on`, the Python call).
- **Caller labels are not metric labels.** `emit_metrics` and the telemetry catalogue are unchanged: a host-chosen label is not a closed set.
- **A subject's early `withdraws` of an adverse or cosigned row no longer retires it.** A host that read such a row as withdrawn will now read it as live, which is what the door decides when the rows arrive in order. Its contest path is `reconsideration:{grounds}` (CC 4.5.5).
- **An offered `withdraws_admission_rule` is ignored.** The door writes its own. A host that stamped the field before offering a row should stop; the offered value no longer reaches storage.
- **A `withdraws` that arrived before its target retires nothing unless its signer produced the target.** A subject's or proxy's `withdraws` replicated ahead of its target is held with no rule and stays so; on that node the target stays live in every fold and in the Live listing (the bytes plane re-derives at read time and may still withdraw bytes). A node that received the two in order retires the target. Deliver a target before the retraction where you can; v62's fold derives entitlement for the early row. A held row is never re-stamped, so its `persist_row_hash` does not change.
- **A hard_case record whose v1 id a foreign row holds lands under its emitter-bound id.** The act commits, a warning carries `hard_case_id_held_by_foreign_row`, and the counter moves. Look a record up with `hard_case::held_record_of` (or both of `hard_case_ids_for`), not the v1 id alone. `hard_case_events` lists the emitter-bound record for that `event_id`. An operator may purge the foreign row; nothing depends on it.
- **After a node key rotation, a re-record of an event the old key recorded is foreign by signer**, so it lands under the emitter-bound id of the new key. This is expected: the event then has a record under each key.
- **A `self` removal with co-signatures is refused with `federation::Error::RevokeMemberRefused`**, a new variant: a Rust caller that matches `federation::Error` exhaustively needs an arm for it. Its `reason` is `self_removal_cosignatures_refused`; Python raises `ValueError` with that token after the kind. Match on the token, not the message.
- **`row_type_report` gains `substrate_self_report_would_refuse`**, additive. A peer's `system:*` (and the other four families) row about another key is admitted and counted there; the same row written by this node is refused.
- **A one-voice affiliation's countersign counts persons.** An official key that is the seat holder's own device no longer satisfies it; name an official who is another person.
- **A failed self-roster receipt now fails `put_attestation`, `apply_replicated_attestation` and the roster gate (`put_identity_occurrence`)** for the proposal row, where before it was logged and the row was kept. Retry the offer.
- **A `system:*` (and the other four substrate self-report families) row about another key is refused when this node writes it, and reported when a peer's arrives** (until v62 refuses both). Write it about the signer (`attested_key_id = attesting_key_id`).
- **A `hard_case:*` row is signed by a `substrate_persist` or `node` key in either form.** A node whose own key is registered under another `identity_type` records hard_case rows locally but cannot cross them; register the node key with `node`.
- **A `trace_summary:*` row names its signer in `subject_key_ids`.**
- **`revoke_spec_json` takes `cosignatures`.** A list of `{authority_key_id, scrub_signature_classical, scrub_signature_pqc?}`, each signed over the revocation envelope with `removed_at == effective_at`, as the primary is. Absent means none, so existing payloads decode unchanged. A malformed list now raises `ValueError` (before, the member was an unknown field and was dropped unread).
- **The linux wheel's `.so` bytes are produced differently.** It is now `objcopy --strip-all` of an unstripped link with line tables, plus a `.gnu_debuglink` section, where it was the linker's `-s` output. Its loaded segments are what the link produced; its build-id is the unstripped link's. The macOS and Windows wheels are built as before. `pyproject.toml` no longer sets `[tool.maturin] strip = true`; a source build is still stripped by `[profile.release] strip = "symbols"`.
- **No API change.** Edge's 44.1 defense (polling persist-executor futures inside an Edge tokio context) remains correct, but persist no longer depends on it. Any foreign caller that polls a checkout off a runtime it owns now reaches persist's runtime only through persist's own code.
- **Several processes can write one SQLite file.** A writer that finds the file locked now waits up to the busy timeout (30 s) instead of failing, so Edge can drop the serialized startup that CIRISConformance PR #106 added to work around this. The first migration of a NEW file is outside this fix: refinery runs it in its own transactions. Two processes that both create and migrate the same fresh file at once still race, so let one process migrate first. A long write in one process now delays the others by up to its own length.
- **Match a backend error on its leading kind.** The message is `federation_backend: <detail>`. A host that compared the whole string to `federation_backend` must match on the prefix (`str(e).startswith("federation_backend")`) or on the token before the first `:`. The detail is diagnostic text, not a stable token.
- **`Engine.verify_trace` now refuses what ingest refuses.** A trace with no PQC half raises `ValueError("verify_hybrid_required")`; a bad ML-DSA-65 or Ed25519 signature, or a failed read of the PQC key, raises `ValueError("verify_hybrid_failed")`; a PQC signature without a resolvable `pqc_key_id` raises `ValueError("verify_unknown_key")`. Before, the first two returned `{"verified": True}` if the Ed25519 half verified. `verify_signature_mismatch`, `verify_invalid_signature`, `verify_canonicalization_internal` and `verify_unsupported_schema_version` no longer come from this method (a canonicalization failure is `verify_hybrid_failed`, as in ingest). A failed read of the signer's key now raises `RuntimeError` with the store token (`store_backend`), as `receive_and_persist` does, where it was `ValueError("verify_invalid_signature")`. A caller that ran the dry-run before forwarding classical-only traces must have its producer hybrid-sign them (the fleet is 100% PQC).
- **`verify::verify_trace_via_directory` is removed from the public Rust API** (and from `prelude`). It checked the classical half only. A Rust caller that verified a trace with it should call `Engine::verify_trace` from Python or run ingest (`IngestPipeline::receive_and_persist_with`), which verify hybrid-Strict. `verify::verify_trace` (the Ed25519-half primitive) and `PublicKeyDirectory` stay public. No downstream repo on this machine (Edge, Server, Lens, Node) calls it.

## [61.0.5] - 2026-11-08

### Added

- **A read of the rows naming a key, under one dimension (CIRISPersist#1225, Edge, agent 2.20).** `FederationDirectory::list_attestations_naming_by_dimension(subject_key_id, dimension, cursor, limit)` returns the federation-tier rows whose `subject_key_ids` name the key, newest first by `(asserted_at, attestation_id)`, one page at a time; `next_cursor` is present exactly when another row exists. A relayed `membership:proposal:v1` names its invitee only as a subject, so a waking invitee could not find it except by a paced history read. It serves what `list_attestations_since` serves (federation tier, no unregistered type under enforcement, no purge-tombstoned row the tombstone is not void for), with no caller gate and no lifecycle folding: the caller's serve gate runs after it. It seeks V106's `attestation_subjects_seek`; no migration.

### Adoption

- **New read: `list_attestations_naming_by_dimension`, and its capsule op `DirectoryOp::ListAttestationsNamingByDimension` (result `Scores`).** Append-only op growth; `DIRECTORY_ABI_VERSION` is unchanged at 12. A directory that does not override the method answers `Unsupported`.
- **Order by the signer's instant.** A row dated behind a cursor already passed is found only by a read from the head, so a caller that must see late rows reads from the head each time. Anyone can name a key, so a page can be flooded: page to a budget, and treat one page as incomplete.
- **New telemetry door label** `list_attestations_naming_by_dimension` on the read counters.

## [61.0.4] - 2026-11-06

### Fixed

- **SQLite attestation reads reuse their prepared statement.** `execute_attestation_query` and the referencing read now use the statement cache, and each reader holds 128 statements. Bridge profiled a production-sized copy of the 0.5.245 candidate at 24% of CPU in `sqlite3_prepare_v2`.
- **The one-live-key route fold costs one owner read per key (Edge).** `fold_one_live_key` read `owner_of` for both keys of every pair on a destination, two attestation queries each, so a destination shared by k keys cost about k² read pairs. Production holds one with 3,281 live routes. The fold now keeps each key's owner for the call, and an ownerless row ends after its own read. Verdicts do not change.

## [61.0.3] - 2026-11-05

### Fixed

- **A room's founder could not take down chat content** (CIRISPersist#1199, CC 4.5.5). The takedown binding read a row's room only from `community_id`, and chat rows name it by `community_key_id`, so chat content bound no room and only its subjects held the duty. The binding now reads every cohort-target alias, as does the reconsideration door's read of its target. I1523 covers the founder, a delegate and another room's founder on memory, sqlite and postgres.

- **A moderator's signature alone could remove a member** (CIRISPersist#1200, CC 4.5.13). A removal is a roster change under the room's protocol, in every protocol. In a two-member `unanimous` room a delegate of one founder could remove the other. The roster door now refuses a new removal signed only by a moderator; a moderator can still admit, and can still act on content and standing to speak. Removals already admitted stay in the fold. I1524 covers the door on sqlite and postgres and the fold.

### Adoption

- **A moderator can no longer remove a member.** A host that offered this needs the room's protocol signatures instead. Removals already held stand. A node on 61.0.3 refuses such a removal arriving from an older node, so the two can hold different rosters until the room acts under its protocol. Accepted on #1200.

## [61.0.2] - 2026-11-04

### Fixed

- **A plain member of a room could moderate it** (CIRISPersist#1195, CC 4.5.4, 4.5.13). Outside `founder_only` and `open:self_admit`, `is_named_moderator`, `moderators_of` and the duty-holder reads used the room's signing set, which is its whole roster, as the holders of `moderate`, `takedown` and `review`. One member of a `majority` room could therefore act alone on any message. Holders are now the room's active, steward-bound founders and the keys they delegate each duty to, at every protocol. `community_authority_set_for` still answers who may sign, and the moderator-existence gate still asks whether the room can appoint. Roster changes and families are unchanged. I1522 covers `majority`, `unanimous` and `quorum:M/N` on sqlite and postgres, at the door.

- **Nobody could be removed from a `unanimous` room against their will** (CIRISPersist#1192, CC 3.1.3.2). The tally counted the removed member as a required voice. A removal now needs every other active member, and those voices must be a strict majority of the roster. At two members nobody is removable and resignation is the exit. A membership-change envelope that names no single member, and every admission, still needs every member. Covered at two, three and four members.

- **Evidence manifest corrected for the CC register** (CIRISPersist#1187). Five rows re-filed by decimal or claim, and two dropped rows CC already holds under other ids. No code change.

### Adoption

- **Moderation in a room with more than one member now needs an appointment.** A host that relied on any member holding a duty has its founder delegate it with `delegates_to`. A room with no active founder has no moderator and no way to appoint one yet; tracked on CIRISPersist#1195.

## [61.0.1] - 2026-11-03

### Adoption

- **An invitee's node receives the group's record while its proposal is live (CIRISPersist#1193).** No host change: CIRISEdge's park-and-re-ask of a refused `group:roster:v1` row now completes on the first offer after the proposal lands.
- **`federation::Error::KeyGrantRefused` gains `attestation_reason: Option<AttestationRefusalReason>`** (CIRISPersist#1184). When `reason` is `attestation_refused`, it carries the attestation plane's typed refusal of the carrier row (`NotInAudience`, `ConflictingAttestation`, …); for every other reason it is `None`. Python: the raised `ValueError` carries an `attestation_reason` attribute, the snake_case token or `None`. CIRISEdge branches on it instead of matching `NotInAudience` in the message (the message is unchanged). A consumer that constructs or exhaustively destructures the variant in Rust adds the field.
- **A family's record and membership events project like the retired framed planes** (CIRISPersist#1182). Before, a node could advertise these only when the row's attester was in its own publish set. Now any node holding a family's record advertises the family's record and membership events, each still narrowed per peer by `may_receive_group_plane`. CIRISEdge can drop its `attestation_is_advertised` override for group-plane dimensions and read `namespace::projection_for` instead.

### Fixed

- **An invitee's node could never receive a private family's (or a room's) record** (CIRISPersist#1193; found gating CIRISEdge v44). On 61.0.0 the #1148 receiver gate asked for the group's members from the STORED record, which the invitee's node lacks because it is the row being refused. So a proposal by the group's founder counted for nothing, and the record was `NotInAudience` forever. The record is now self-certifying on the door that judges it. `replication_audience::record_names_its_audience` admits a recipient holding a live, undeclined proposal naming one of its principals, authored by a member the OFFERED record lists (or that member's occurrence). This covers families and communities, including every non-founder joiner. A proposal by anyone the record does not list admits nothing. I1520 (two nodes, sqlite and postgres) covers the family path, its community twin and the negative leg.
- **A key-grant refusal by the attestation plane was a string** (CIRISPersist#1184). `admit_replicated_key_grant` flattened the plane's `ReplicatedAttestationOutcome::Refused { reason }` into `detail`. It now carries the reason typed (above). I1519 runs on sqlite and postgres: a conflicting copy of an admitted grant is refused with `attestation_reason: Some(ConflictingAttestation)`.
- **A family's removal reached only the members whose nodes sync with the remover's** (CIRISPersist#1182). At `cohort_scope: family`, `namespace::projection_for` resolved `group:roster:v1` and `membership:{widening,removal,resignation}:v1` to `SelfOwn`, so only the signer's nodes relayed them. A member syncing with another member's node kept the removed member on its roster. At `family` the record now projects `Cohort` and the three membership events `Global`, each still narrowed per peer by `may_receive_group_plane`. These are the four exact dimensions at `family` only: a room's rows, every other dimension and the tombstone ceiling are unchanged. I1521 covers this with three member nodes on sqlite and postgres: P removes R, Q's node receives the removal from R's node, and Q's fold drops R.
- **A postgres test could fail with `relation "cirislens.*" does not exist` under load.** `av26_concurrent_boot_advisory_lock` dropped every application schema of the shared test database to simulate a cold start, and only tests named `postgres_*` were serialized against it. It now boots in a fresh database of its own. Test harness only; no product change.

## [61.0.0] - 2026-11-02

### Adoption

- CIRISVerify 22 is required: `ciris-keyring`, `ciris-verify-core` and `ciris-crypto` are pinned at tag v22.0.0, and the wheel declares `ciris-verify>=22.0.0,<23`. A host that pins verify itself must move to 22 with persist.
- `ciris_verify_core::holonomic` is `ciris_verify_core::substrate` in verify 22, with no alias. A consumer that names verify's module directly must rename the path; persist's own re-export (`witness::admit::WitnessPreimageBuilder`) keeps its name.
- `federation::genesis::bundle::authorization_digest` returns the same 32 bytes for every bundle; a bundle it cannot project is refused `Error::GenesisBundleInvalid` in every case (a canonicalization failure was `Error::InvalidArgument`).
- New refusals: an optional signed envelope member written as an explicit JSON `null` (top level or inside the `row` mirror) is refused `federation_malformed_row` / `envelope_member_null` (Python `ValueError`); a `witnesses` member out of JCS-string order or carrying a repeat is refused `federation_set_semantics_unsorted`, and one that is not an array `envelope_member_invalid`. Producers omit an optional member instead of writing `null`, and write `witnesses[]` sorted and unique.
- `malformed_row::ALL` gains `envelope_member_null`, appended at the end; existing positions do not move.
- A family's or community's record, a membership widening and a membership revocation are rows on the attestation plane: `group:roster:v1` (attested by the group), `membership:widening:v1`, `membership:removal:v1`, and `membership:resignation:v1` when the leaving member signs the revocation. Persist mints each row from the signed object a `put_*` call stores, so the local `put_family`, `put_community`, `put_*_membership_revocation` and `put_*_membership_widening` calls are unchanged. The row carries the signed object (envelope member `group_record`, `widening` or `revocation`), its base signature is the object's authority signature, its co-signatures ride as `additional_scrubs`, and it is placed at the group: `cohort_scope` `family` or `community`, with `group_kind` and the group id (`family_key_id` / `community_key_id`) in the envelope. A `group:roster:v1` row also carries `prev_head_digest` and `charter_digest` when the record has them. A receiver re-derives the row from the object; a row that differs by one byte, or is missing a co-signature, is refused `federation_malformed_row`.
- The wire kinds `Family`, `Community`, `FamilyMembershipRevocation`, `CommunityMembershipRevocation`, `CommunityMembershipWidening` and `FamilyMembershipWidening` are retired (`RETIRED_FRAMED`). They keep their positions in the hashed vocabulary, so `REPLICATION_POLICY_HASH` does not move. An inbound object or advertisement of one of these kinds is refused `federation_envelope_kind_retired`. Their records replicate as the rows above, through `ApplyReplicatedAttestation` and the attestation cursor; their `signed_wire_index` and `known_wire_hashes` entries are deleted at migration.

  The old kind → new row mapping (also in `FSD/ROOM_ROSTER_PLANES.md` §7):

  | retired kind | row | attester → attested | `cohort_scope` | envelope member |
  |---|---|---|---|---|
  | `Family` | `group:roster:v1` | the record's signer → the family | `family` | `group_record` |
  | `Community` | `group:roster:v1` | the record's signer → the community | `community` | `group_record` |
  | `FamilyMembershipRevocation` | `membership:removal:v1` (`membership:resignation:v1` when the removed member signs) | the signer → the member removed | `family` | `revocation` |
  | `CommunityMembershipRevocation` | `membership:removal:v1` (`membership:resignation:v1` when the removed member signs) | the signer → the member removed | `community` | `revocation` |
  | `CommunityMembershipWidening` | `membership:widening:v1` | the signer → the member added | `community` | `widening` |
  | `FamilyMembershipWidening` | `membership:widening:v1` | the signer → the member added | `family` | `widening` |
- The wire kind `KeyGrant` is retired too (`RETIRED_FRAMED`, at its hashed position; `REPLICATION_POLICY_HASH` does not move). A key grant has been one `key_grant:{content,epoch,stream}:v1` `scores` row per recipient since v55.0.0, and those rows ride the `Attestation` kind. A peer's advertisement of a `KeyGrant` hash is refused `federation_envelope_kind_retired: key_grant`; V208 deletes any `signed_wire_index` or `known_wire_hashes` entry that names it. CIRISEdge matches `EnvelopeKind` exhaustively in `protocol.rs`, `serve_policy.rs`, `retention.rs` and `multimedia.rs`: the `KeyGrant` arms stay (the variant is kept), and they now name a kind that is never served, advertised or fetched framed. Treat it like the other retired kinds.
- The member listing is retired with no successor (the steward's final ruling: there is no outward member listing, and CC removes `listed`). The wire kind `CommunityMembershipListing` joins `RETIRED_FRAMED`, at its hashed position, and an advertisement of it is refused `federation_envelope_kind_retired: community_membership_listing`. These are removed with nothing replacing them: `FederationDirectory::put_community_membership_listing`, `list_community_membership_listings_for`, `listed_members` and `list_signed_community_membership_listings_since`; the capsule op `ListSignedCommunityMembershipListingsSince` and its result `SignedCommunityMembershipListings` (inside the ABI 12 break); the module `federation::listing` (`LISTED_PUBLIC` and the three `envelope_listed_*` rule tokens); the types `CommunityMembershipListing`, `SignedCommunityMembershipListing` and `ServedCommunityMembershipListing`; `verify_community_membership_listing_admission`; and `Error::MembershipListingRefused` (kind `federation_membership_listing_refused`). The listing never had a Python method. A host that served a roster view from `listed_members` serves none. A consumer that matches `federation::Error` exhaustively drops the arm.
- Persist no longer emits `listed`. `EnvelopeCore.listed` and `envelope::paths::LISTED` are removed, and `listed` leaves the envelope vocabulary's `universal_paths`. `ENVELOPE_VOCABULARY_SHA256` is now `4c5a5e8a019bc8c9c895a5b91693438aafe9066237305d07e04dd31d36596eff` (was `8064aafe…`), so CIRISServer and any consumer that asserts it re-pins.
- V209 deletes the listing kind's `signed_wire_index` and `known_wire_hashes` entries and drops `federation_community_membership_listings` (both dialects). Five upgraded local nodes held no rows when counted from disk. The rows of a node that did hold some are deleted, not migrated.
- CIRISEdge: the `CommunityMembershipListing` arms of its exhaustive `EnvelopeKind` matches (`protocol.rs`, `serve_policy.rs`, `retention.rs`, `multimedia.rs`) stay, since the variant is kept, and name a kind that is never served, advertised or fetched.
- `DIRECTORY_ABI_VERSION` is 12. These capsule ops and their results are removed: `ListSignedFamiliesSince`, `ListSignedCommunitiesSince`, `ListSignedFamilyMembershipRevocationsSince`, `ListSignedFamilyMembershipWideningsSince`, `ListSignedCommunityMembershipRevocationsSince`, `ListSignedCommunityMembershipWideningsSince` and `ApplyReplicatedCommunity` (result `ReplicatedCommunityOutcome`).
- These Python methods are removed: `Engine.list_signed_families_since`, `Engine.list_signed_communities_since`, `Engine.list_signed_family_membership_revocations_since`, `Engine.list_signed_community_membership_revocations_since` and `Engine.apply_replicated_community_json`.
- `AttestationRefusalReason` gains `GroupPlaneRefused` (`group_plane_refused`), appended. A group-plane row whose typed door did not apply its object is refused with it.
- The six `FederationDirectory::list_signed_*_since` reads for these kinds stay on the Rust trait as projection reads, now with a default body (`Unsupported`). They are no longer a replication surface. A backend that does not override one answers `Error::Unsupported`. A consumer that read a group's record or roster from these feeds reads it keyed by the group or member instead: `lookup_family` / `lookup_community`, `list_families_for_member` / `list_families_for_member_active`, `list_communities_for_member` / `list_communities_for_member_active`, and `list_family_membership_widenings_for` / `list_community_membership_widenings_for` (the revocations: `list_*_membership_revocations_for`). In Python: `lookup_family_json`, `lookup_community_json`, `list_families_for_member(_active)_json`, `list_communities_for_member(_active)_json` and `list_*_membership_revocations_for_json`. The widening reads have no Python method.
- Withdrawing a widening or removal row takes a cosigned `withdraws` under the group's `consensus_protocol`: the base scrub and `additional_scrubs`, counted over the active roster. One signature short is refused `federation_roster_authority_unauthorized` / `roster_consensus_insufficient`. A resignation can be withdrawn only by its signer. A `withdraws` of a `group:roster:v1` row means the group's dissolution, which v61 does not admit: it is refused `group_record_withdraws_refused` (Python `ValueError`), with any number of roster co-signatures, and stores nothing. Dissolution arrives with CIRISPersist#1143. An admitted retraction removes the roster event from the group's roster.
- A row of any type other than a minted `scores` row (or a `withdraws` / `recants`) that names one of the four group-plane dimensions is refused `federation_dimension_rejected` / `group_plane_row_shape`. `dimension_rejected_reason::ALL` gains the token, appended at the end (terminal, not retryable).
- `observation:access_assumption:v1` is registered at `+1.0` only (CC rc12): a row with any other score is refused `score_outside_declared_polarity`.
- `listed` is no longer a member persist types. CC rc13 removed it from CC 2.1 and the signed object; at admission it is an unknown envelope member like any other `signed:envelope-extra`: carried untyped and kept in the signed bytes, so a non-boolean value is admitted. `"listed": null` is refused `envelope_member_null` like any other explicit null.
- `membership:proposal` and `membership:acceptance` rows omit `role` when no role is offered; they wrote `"role": null` before. No cross-version break: `role: null` on those two families is still admitted and read as no role, the one exception to `envelope_member_null`, until it sunsets per CIRISPersist#1151.
- **A signed instant is `YYYY-MM-DDTHH:MM:SS.sssZ` and nothing else verifies (CC 2.6.2, the steward's strict ruling; `FSD/SIGNED_INSTANT_FORM.md`).** On an attestation, a CC 2.6.1.7 `rfc3339-ms` member (`asserted_at`, `expires_at`, `widened_at`, `valid_until`, `claimed_at`, `delegation_valid_from`, `delegation_valid_until`, `window_from`, `window_to`) or an `additional_scrubs[].cosigned_at` in any other form is refused `federation_malformed_row` / `envelope_member_invalid`, naming the member, at put, replication, the mint, promotion and the local write (the local write still stamps `expires_at` itself). There is no cut-over instant: a `+00:00` row from a v60 peer is refused. CC's `refuse_timestamp_form` vector now agrees.
- The key plane binds its instants `.sssZ`: `revocation_binding` renders `revoked_at`, `effective_at` and `scrub_timestamp` canonically and compares the raw JSON, a revocation column finer than a millisecond is refused `RevocationEnvelopeUnbound` ("sub-millisecond"; it was the microsecond), and a `revoked_after` in another form is `RevocationBoundRefusal::BoundNotRfc3339`. A key record's signed `valid_until` binds as bytes against the canonical render (v38.7.0 compared it as a parsed instant) and a sub-millisecond expiry is refused. `register_self_federation_key` writes the envelope's signed `valid_from` `.sssZ` (the record carries the same instant) and refuses a caller's `valid_from` in any other form `InvalidArgument` (Python `ValueError`); a host that passes its own `valid_from` must pass `YYYY-MM-DDTHH:MM:SS.sssZ`. v61 emits `.sssZ` `valid_from`; verification of the `valid_from` form follows the genesis re-sign in v62 (the compiled-in genesis signs it in offset form; CIRISPersist#1178). The identity occurrence's `asserted_at` / `valid_until`, the signed transport destination's `asserted_at` / `retired_at` and the touch claim's `fresh_as_of` admit only `.sssZ`. A revocation this node already holds is never re-judged and stays in force.
- `TransportDestination.asserted_at` and `retired_at` serialize `.sssZ` (`admission::signed_instant_serde`), so a producer that builds the signed route envelope from `serde_json::to_value(&route)` writes the canonical form; it must still hold the instant at the millisecond. CIRISEdge: a route envelope written with chrono's default digits (0, 3, 6 or 9) or `+00:00` is refused.
- **Key records and revocations that v59 or v60 signed are refused on form until they are re-signed.** A key record whose `registration_envelope` binds `valid_until` in any form other than `.sssZ` is refused at admission, naming the form. A revocation whose bound `revoked_at` / `effective_at` / `scrub_timestamp` is not the canonical millisecond render (v60 wrote six digits) is refused `RevocationEnvelopeUnbound`. Each arriving from a v59/v60 peer is refused until its signer re-signs it under v61. A revocation this node already holds stays in force, and it is not re-judged. A host that signs key records or revocations re-signs them on v61 before it replicates them.
- Persist's producers write `.sssZ`: `mesh_config_envelope`'s `valid_until`, the `hard_case` membership-change `effective_at` (added and removed), the founders' `amended_at`, the touch claim's `fresh_as_of`, the transform algebra's `round` on an instant (it wrote no fractional digits), and `register_self_federation_key`'s `valid_until`, which is now bound into the registration envelope (it was bound as absent while the record carried it).
- New domains for persist's own preimages; the old ones still verify as themselves. `ciris.trust.grant.v2` (`expires_at` `.sssZ`) and `ciris.trust.revocation.v2` (`revoked_at` `.sssZ`, was six digits): `admission::trust_grant_signing_bytes` / `trust_revocation_signing_bytes` return the v2 bytes and refuse a sub-millisecond instant, `trust_grant_signing_bytes_v1` / `trust_revocation_signing_bytes_v1` build the old ones, and the two doors verify v2, else v1. A signer of a trust grant or revocation signs v2. The trace scrub signature (`ingest::scrub_preimage`, #690) carries `domain: "ciris.scrub_envelope.v2"` and `scrub_timestamp` `.sssZ` (the signer truncates it to the millisecond); `ingest::scrub_preimage_v1` rebuilds the pre-v61 bytes. A verifier of trace scrub signatures (CIRISLens) rebuilds v2 for a v61 envelope.
- **Open-time pass (V211).** Every `Engine` constructor that opens a store settles stored attestation rows that fail the form (`federation::instant_form`, `Engine::settle_instant_forms`): this node's own federation-tier `scores` / `delegates_to` / `supersedes` rows are re-stated as a canonical `supersedes` naming each (the claim's own `asserted_at` kept); rows that take something away (composers, delegations, revocations, quarantine, moderation, reconsideration, slashing, objections, the accountability record, membership removal and resignation, a revoked consent) stay in force; any other row another producer signed is removed and recorded in the new ledger `federation_attestations_form_refused` (id, attester, row hash, member, value, instant; no body). Idempotent; never boot-fatal. `admission::signed_instant_form_violation` is the one predicate.
- **The Python `Engine(...)` open runs the pass too.** The first open after upgrading runs it (and the CIRISPersist#1122 agent-route sweep) on every host, through `Engine::settle_at_open`, the one leg the Rust constructors and the Python constructor share; before this the Python open ran the V211 DDL and never the pass. The counts are logged at `tracing::info` when the pass finds anything, and `Engine.settle_instant_forms_json()` (Python) runs the pass on demand and returns `{scanned, violations, healed, already_healed, heal_refused, own_left, kept_in_force, set_aside}`: idempotent, a second call re-states nothing (`healed` 0, earlier re-statements counted `already_healed`).
- **Partnership halves are `consent_record` rows (CIRISPersist#1126, CC 4.4.3.4.3.1).** `self_at_login` writes `consent:partnership_grant:v1` / `consent:partnership_accept:v1` as `{dimension, subject_kind: "consent_record", stance: "granted", subject_key_id: <the partner>, bilateral_pair_id, asserted_at}`; `kind` and `partner_occurrence_key_id` are gone. `self_at_login::partnership_grant_envelope` / `partnership_accept_envelope` take an `asserted_at`, and `partnership_envelope(dimension, partner, pair, stance, asserted_at)` builds either half or a `stance: "revoked"` end. A bare-`scores` half is refused at the federation and local doors: `federation_dimension_rejected` / `partnership_shape_retired` (appended to `dimension_rejected_reason::ALL`, terminal). Persist folds no partnership pair itself. The Python `self_at_login` output is unchanged.
- **A serve seat needs an announced owner (CIRISPersist#1101, CC 5.4.6, `CLM-serve-seat-announced`).** A widening that would seat an accord-scrubbed node in an infrastructure community without acceptance is refused `MembershipAcceptanceRefused` with rule `serve_seat_owner_unannounced` (retryable) unless a live owner binding for the node is carried at `cohort_scope: federation`, directly or by its granter's live widening. Judged at evaluation time: a later announcement satisfies it and a withdrawn one does not. The founding rule is unchanged (a genesis bundle carries no owner binding). `admission::serve_seat_owner_announced(dir, node)` and `Engine.serve_seat_owner_announced(node_key_id)` (Python) are the predicate a serve gate calls.
- **One destination, one live key; an agent announces no route (CIRISPersist#1122).** A route at an `agent`-typed key is refused `transport_destination_agent_key` (`InvalidArgument`, Python `ValueError`) at the signed apply and the unsigned local put; an occurrence write projects no route for an agent; and every route an agent key published before v61 is deleted at open. The three route reads (`list_transport_destinations_for`, `list_transport_destinations_by_destination`, `list_all_transport_destinations`) drop a route that a newer route on the same destination by a key with the same live owner displaces; keys with no owner tie still coexist (AV-42). The signed replication read is unchanged. A `FederationDirectory` implementer overrides the new `list_transport_destinations_for_unfolded`, `list_transport_destinations_by_destination_unfolded` and `list_all_transport_destinations_unfolded` (the stored rows); the public reads are default methods that fold over them. A split home retires its actor key's routes with the signed retirement it always had.
- **`register_self_federation_key` is idempotent on a restart (CIRISPersist#1146).** When the held row for the node's own key states the same Ed25519 and PQC pubkeys, `identity_type`, `identity_ref`, roles (as a set) and expiry, the call returns the `key_id` and writes nothing, so the row hash stays put. Any difference is still `Conflict`; the replicated put keeps its exact-hash rule.
- **The storage summary counts a table persist does not own (CIRISPersist#1156).** The time column is resolved against the table's real columns (`pragma_table_info` on SQLite, `information_schema.columns` with a timestamp type on Postgres), so a host's `audit_log (id, ts)` is counted with no instant and never fails the aggregate. On SQLite the bare PG spellings (`audit_log`, `detection_events`) are not persist's (`retention::ts_column_for_sqlite`). On Postgres a table outside persist's schemas (`retention::postgres::PERSIST_SCHEMAS`) is keyed by its qualified `schema.table` name and carries no instant; persist's own tables keep their bare keys. Table names are quoted, and a table dropped mid-walk is counted empty.
- `founder_only` is refused for a community above the family (CIRISPersist#1123, CC 4.5.13). `put_community` and `supersede_community` refuse a new or changed record that names it, with `federation_community_consensus_protocol_violation` (`Error::CommunityConsensusProtocolViolation`, Python `ValueError`), rule `founder_only_above_family`. This is the infrastructure token; there is no new one. Families keep `founder_only`, and so does a community record that declares `cohort_scope: affiliations` (CC 4.4.3.2.8). A room already stored under `founder_only` stays readable and folds as before, and admits exactly one event, its escape (below). A peer's version that would move a stored room onto `founder_only` is `ReplicatedCommunityOutcome::Refused { reason: DegradesConformance }`. A NEW `founder_only` room received from a peer is still admitted as data, so legacy rooms keep replicating. Counted read-only on 16 local node databases: one `founder_only` community, a CIRISServer chat room (`chat:room:v1:…`, 2026-10-31). CIRISServer creates rooms under `founder_only` and must choose another protocol.
- `open:self_admit` is a canonical `consensus_protocol` (CIRISPersist#1123; CC 4.4.3.2, 4.4.3.4.2). It is admissible only on a `public` community. A private room that names it is refused with rule `open_admission_not_public`, and a family with `federation_consensus_protocol_malformed`. V210 (both dialects) widens the `federation_communities.consensus_protocol` CHECK to admit it; on SQLite this is a staged table rebuild that keeps every row.
- Open admission is the protocol: `public_room::is_open_admission` now reads `consensus_protocol == "open:self_admit"`. The `policy_blob` member `admission` is retired (CC rc14 3.2: "there is no admission field"). A record that carries it is refused with rule `admission_member_retired`, and `public_room::PUBLIC_RULE_ADMISSION_MALFORMED` is removed. A `community:listing:v1` row still states `admission: "open"`, exactly when the room's protocol is `open:self_admit`. Counted on the same 16 databases: no public room and no `admission` member.
- Under `open:self_admit`:
  - A widening that seats one new key is admitted on that key's own signature, after their acceptance of the founder's standing proposal.
  - A founder signing for the joiner does not admit them.
  - A role change of a seated member and a removal each take at least two distinct eligible voices, not counting the member named (`consensus::OPEN_SELF_ADMIT_REMOVAL_FLOOR`).
  - A named moderator's standing does not remove anyone alone.
  - Only founders propose, and only founders sign on the room's behalf (`types::consensus_protocol::founders_hold_authority`).
  - Refusals are `federation_roster_authority_unauthorized` / `roster_consensus_insufficient`.
- Under every other protocol a self-signed admission is refused (`roster_consensus_insufficient`). This is a widening whose only signer is the member it seats or re-roles, including a seated member re-roling themselves.
- `consensus::Ballot` gains `subject: Option<&str>`, the one member a change names. A Rust consumer that builds a `Ballot` literal adds it.
- `public_room::live_standing_proposal(directory, community_key_id)` is new (CIRISPersist#1063; CC 3.2 "replicated on join, visible to everyone on request"). It is the read a member's node answers a non-member's request with. It returns a public `open:self_admit` room's live standing proposal: signed by a founder active now, not expired, not withdrawn or superseded by its proposer, the latest by signed instant. The row is servable to the requester's node, because a public room is a public group to `may_receive`, and that node admits it on its replicated door. A host serves it on request; nothing pushes it.
- Under a `reverse_quorum` protocol a membership WIDENING is reversible, as a removal already was (CIRISPersist#1100 item 2(i)). It uses the same objection fold, action reference, `m`, window and dismissals. An add's reversal must also reach the two-path count minimum of a community (2), so one objector never takes a member off. A roster that held an objected-to widening now folds without that member once enough objections land.
- Structural composers (`supersedes`, `withdraws`, `recants`) are idempotent on the ROW (CIRISPersist#1157 with #1155; CC rc14 3.1.9.4, `CLM-composer-convergent-rank`). Before, any second row with the same `(type, attester, references_attestation_id)` triple was silently dropped as a replay, so the first row a node held won and nodes that held different rows never converged. Now a replay is the same `attestation_id` with the same `original_content_hash`. A DISTINCT same-type row from the same attester on the same target is stored, and the `Live` view ranks it read-time within one audience (cohort scope and cohort target): the later `asserted_at` wins, and a tie goes to the lower `attestation_id`, bytewise. The loser stays stored and hidden, so a late-arriving winner flips every node the same way. A second edit of a placed chat message is no longer swallowed, and the latest edit is the visible head. `AttestationStore::composer_replay_held` (crate-private) now takes `(attestation_id, original_content_hash)`.
- A placement is idempotent per audience (CIRISPersist#1155). `widen_audience` answers `AlreadyWidened` when the same attester has already placed the prior in the SAME audience. Placing one `self` row into two rooms leaves BOTH placements live; before, the second room's placement was swallowed (`AlreadyWidened`, no row written). It was witnessed red on both backends before the fix. `ReplicatedAttestationOutcome::Deduplicated` stays in the enum; an exact replay of a held id resolves `Unchanged`.
- Replicated writes need the audience (CIRISPersist#1148). On a directory that has declared its node key (`FederationDirectory::node_key_id`; an `Engine` always does), the replicated doors refuse a row this node may not receive. They ask the same `may_receive` the serve side asks, for the node's own key, before any door runs:
  - `apply_replicated_attestation` and `put_attestation_synced` answer `ReplicatedAttestationOutcome::Refused { reason: NotInAudience }` (`not_in_audience`, retryable);
  - `apply_replicated_community` answers `ReplicatedCommunityOutcome::Refused { reason: NotInAudience }`.

  Key-plane rows are exempt, and so are `key_grant:{axis}:v1` rows. A key-grant row's audience is the key-grant door's own rule (`recipient_not_in_audience`), which admits it on every node hosting an occurrence of its recipient, so a self-axis grant reaches the person's other devices (I1519). The local doors are unchanged, and a directory with no node key keeps the pre-v61 behaviour.
  A replicated row is verified before its audience verdict. On the refusing branch the signature is checked first, so a forged row is `federation_federation_tier_unverified`, never `not_in_audience` (I1509). An in-audience row is verified once, by admission. On that branch a row whose attester key this node does not hold reports the retryable `AttesterKeyUnknown` instead of `NotInAudience`; a peer backs off on either. `AttestationRefusalReason` and `ReplicatedCommunityRefusal` each gain `NotInAudience`, appended (inside the ABI 12 break); a consumer that matches either exhaustively adds the arm. A group's record now names its own audience in `may_receive`: a public record reaches every peer, and a member it lists is in its audience before any node holds the record (`replication_audience::may_receive_community_record` is new).
- The owner-binding audience (CIRISPersist#1140; CC rc14 3.2, 2.4.1.2):
  - AV-84's `attested_party` arm no longer applies to a `delegates_to` row, whose attested key is the delegate by definition. Its `named_subject` arm is replaced by `subject_outside_audience` (below).
  - An owner may re-sign a node's owner-binding at any group's scope as a second owner-signed row alongside the `self` one, and every scope is an admissible audience. `owner_of` folds every live binding to the one owner.
  - The organisation-on-the-bond gate (CIRISPersist#1062) applies only to a binding of a non-node key. A NODE's binding naming a group is an audience, not an organisation's bond, and `affiliation_of_binding` ignores it.
  - A bounded-scope `delegates_to` whose attested key is a third party was refused `federation_cohort_standing_refused` / `attested_party`; it is now admitted.
- Room moderation in CC's 2026-11-01 shape is admitted at `community` scope as v61 stands (CIRISPersist#1161, I1512). A flag or `moderation:*` act names the flagged row by `references_attestation_id`, its `attested_key_id` is the moderator, and the author is not in `subject_key_ids`. Server and Edge re-shape their flag rows to this shape.
- The one-voice affiliation floor (CIRISPersist#1143; CC rc14 4.4.3.2.8, `CLM-affiliation-one-voice-countersign`). An affiliation with ONE deciding seat (its active founders, or its active members where it names no founder) removes a member only with a countersign from a key outside the seat, a designated official (`affiliation_config.designated_officials`) who is not the seat. Otherwise the removal is refused `federation_roster_authority_unauthorized` / `affiliation_countersign_missing`. A member's own resignation and a body of two or more seats are unchanged. Not built in this cut: the quarantine, slash and takedown planes, the review-holder of an overseeing body, and CC's "stands as a reconsideration proposal" held state (CIRISPersist#1186).
- Dissolution of a community or an affiliation is the `withdraws` of its `group:roster:v1` record row, cosigned under its `consensus_protocol` (judged as a whole-group change; under `open:self_admit`, two voices). It replaces S1's `group_record_withdraws_refused` for communities. From the withdrawal's signed instant the room's seats lapse (`active_community_members` is empty), and no new seat, removal or version is admitted (`federation_group_dissolved`, `Error::GroupDissolved`), so the DEK rotates no more. The record and its custody rows stand. `group_plane::community_dissolved_at` and `refuse_if_community_dissolved` are new. A FAMILY's record withdraws is still refused `group_record_withdraws_refused`, because a family dissolves by its own `dissolved_at` amendment. Not built in this cut: licences reading `lapsed` from the dissolution instant, and a dissolved authority's `trust:accepts:v1` edges ending (CIRISPersist#1186).
- Under `open:self_admit`, a change that names no one member (a dissolution, a whole-roster change) takes the two-voice floor. It was refused outright before.
- **Every Postgres checkout is bounded (CIRISPersist#1166).** `store::postgres::checkout_bounded` is the one pooled checkout; 204 sites that called deadpool's unbounded `get()` (outbound, read, telemetry, cirisnode, the ledgers and lens services, the engine, the Python surface, the audit Merkle store) go through it. A starved pool is now an error after the checkout wait on every family, where it was a hang. No API removed: `PostgresBackend::pool()` stays public, and `PgMerkleStore::from_pool` keeps its signature (it waits `POOL_WAIT_TIMEOUT`). A host that held a pooled client across a second persist call on a small pool now gets the exhaustion error instead of a wedge.
- **`PoolExhausted` is a variant of four exhaustive enums** (from v59.1.2, carried into v61; new to anyone on v60.1.0): `store::Error`, `federation::Error`, `audit::Error` and `secrets::SecretsError`. A consumer that matches any of them exhaustively adds the arm. It reports a starved pool, not a bad row (Python `ciris_persist.PoolExhausted`, a `RuntimeError`): the call may succeed once the pool drains.
- **`NotInAudience` is retryable; a peer should back off per (peer, row), not spin.** A peer whose replicated row or community record is refused `not_in_audience` should drop that row from this receiver's queue and re-offer it only after the receiver's audience changes (a membership or owner-binding row that admits it). The refusal is retryable by `AttestationRefusalReason::is_retryable`; it says nothing about the row's validity.
- **A `founder_only` room admits exactly one event: its escape (CIRISPersist#1123, CC 4.5.13).** A community stored under `founder_only` (above the family, not a declared affiliation) stays readable and replicating. On the local AND the replicated door it admits one thing: a `group:roster:v1` supersede (`supersede_community`, or a peer's version) that meets three conditions:
  - its only change is `consensus_protocol`, moving away from `founder_only`;
  - the members are unchanged;
  - it is signed under the OLD protocol, by at least one active founder of the stored room (counted with `count_distinct_roster_scrubs` over the record's signing envelope).

  Each of these is refused `federation_community_consensus_protocol_violation` / `founder_only_above_family` (on the replicated record door, `ReplicatedCommunityOutcome::Refused { reason: DegradesConformance }`):
  - a version that keeps `founder_only`;
  - an escape that also changes members;
  - an escape no founder signed;
  - a membership proposal, an acceptance, a widening, or a removal (a member's own resignation excepted).

  `admission::check_founder_only_escape` and `refuse_membership_event_under_founder_only` are the two gates (I1518, I1518b; sqlite and postgres). **Adoption (CIRISServer):** migrate every live room to `majority` with one supersede per room. Take the held record, change `consensus_protocol` from `founder_only` to `majority` and nothing else, chain `prev_head_digest` to the held head, and sign it as a founder of the room. Do this before any other membership change; until then the room refuses widenings, removals and proposals. Rename the room or change its members in a LATER version, under `majority`.
- `DirectoryOp` gains `ExecuteAttestationQuery`, `ListComposersReferencingAny`, `ListIdentityOccurrenceHistoryByOccurrence` and `ListIdentityOccurrencesByOccurrenceKey`, and `DirectoryOpResult` gains `AttestationQueryRows`, `AttestationRows`, `OccurrenceHistory` and `IdentityOccurrences` (from v59.1.2, #1162), appended after v61's removals inside the ABI 12 break; both capsule digests moved. A capsule host that matches the op exhaustively adds the four arms.
- **The removal window under `open:self_admit`** (CC 4.5.13). Each counted voice of a removal signs within 259 200 s (`consensus::OPEN_SELF_ADMIT_REMOVAL_WINDOW_SECS`) of the removal's `removed_at`. A `RosterCosignature` carries no signed instant of its own, so the bound falls back to the LOCAL door's receipt. A removal received more than the window from its `removed_at` is refused `federation_roster_authority_unauthorized` / `roster_removal_outside_window` (`ROSTER_REMOVAL_OUTSIDE_WINDOW`). The replicated door does not ask: a peer's clock is no witness to when the voices signed. A resignation is not bounded (I1515). **Adoption:** a host files an `open:self_admit` removal promptly after its voices sign, and does not queue it for days.
- **`subject_outside_audience` replaces AV-84's `named_subject`** (CIRISPersist#1161; CC rc15 2.1, `CLM-subject-within-audience`). A `family`/`community`/`affiliations` row that names a person in `subject_key_ids` is admitted when that person is inside the row's audience:
  - the producer itself;
  - a membership proposal's invitee;
  - a `key_grant` recipient;
  - the producer's own node;
  - a member of the targeted group by its authorized roster fold at the row's `asserted_at`;
  - a canonical id whose rule-3 proxy (a `consent_revocation` `delegates_to` chain) or `identity:canonical_binding` is such a member.

  Anyone else is refused `federation_cohort_standing_refused` with the reason token `subject_outside_audience`. `admission::CohortStandingRefusal::NamedSubject` is replaced by `SubjectOutsideAudience` (clean break; the enum is exhaustive). The Python message carries the new token. The `attested_party` arm is unchanged: it applies to every row type except `delegates_to` (narrowing it to `scores` reopens CIRISPersist#592 through `widen_audience`). The retraction classes change too. A named person still withdraws a peer's row about them (rule 2), but not a `moderation:*`, `hard_case:*`, `slashing:*` or `takedown_notice:*` act, nor a cosigned act. A cosigned act is one carrying an actor's `additional_scrubs` entry; a tier-crossing co-scrub, which is stamped `cosigned_at`, does not count. `SUBJECT_WITHDRAWS_CARVE_OUT` grows from 4 to 8 entries. I1494 (CC rc15's 14 signed-object vectors) now agrees with CC on `scores_subject_and_scope` and `refuse_subject_outside_audience`; I1516 runs on sqlite and postgres.
- **The CC 4.5.5 duty gate asks about the signer's identity** (CIRISPersist#1160). `admission::check_moderation_admission` first resolves the signer to the identity it is an active occurrence of (`active_identity_for_occurrence`). A federation-identity moderator's takedown notice, or `moderation:*` act, signed by one of its live occurrence keys is admitted (I1517). A NODE is never resolved to its owner here: a node holds no duty, so an owner's node key that signs a takedown or moderation act is refused (I1517). **The raw-pubkey `takedown_notice` Contribution is gone** (#803 "remove in v61"). A v59 peer's Contribution is refused `takedown_unauthorised` as retired on the replicated door too (I1171). These pub items are removed: `takedown_tombstone::NoticeOrigin` (so `takedown_terms` takes two arguments), `LEGACY_BASIS_SPELLINGS` and `cc_basis_spelling`.
- The dedup short-circuit's witness now probes the row-keyed replay key (#1157): a corrupt-signature copy of a held composer, under its own id and content hash, is refused on the signature on sqlite and postgres. No behaviour changed; the replay short-circuit still runs after the crypto gate.
- `silo_projection::SiloProjection` gains `Families`, `Communities`, `FamilyMembershipRevocations`, `CommunityMembershipRevocations`, `FamilyMembershipWidenings` and `CommunityMembershipWidenings` (the six group tables as projections, CIRISPersist#991). The enum is exhaustive. `replication_audience::Reason` is unchanged from v60.1.0 (the #1165 relay arm was reverted before release: CC rc15's first contact gives the forwarder no contact grant).
- The list above is checked against `scripts/api_break_report.sh v60.1.0` (cargo-semver-checks over the `postgres server pyo3 sqlite cirisaudit secrets cirisnode cirisgraph telemetry` set): 10 lints, 68 instances: 21 enum variants added and 17 removed, 6 functions, 1 module, 6 consts, 6 structs, 1 struct field and 4 trait methods removed, 4 functions whose arity changed and 1 struct field added (`consensus::Ballot.subject`). (Recounted by hand after the #1165 revert removed `Reason::Relay` and its two moved discriminants; the report was not re-run.) S2's close-out adds more breaks, named above and not in that count: `CohortStandingRefusal::NamedSubject` is replaced by `SubjectOutsideAudience`; `takedown_tombstone::NoticeOrigin`, `LEGACY_BASIS_SPELLINGS` and `cc_basis_spelling` are removed; `takedown_terms` loses an argument. Each is named in an entry here.
- **The CC pins moved (v1.0-rc9 at v60.1.0 → v1.0-rc15).** A consumer that asserts any of these re-pins:

  | constant | v60.1.0 | v61.0.0 |
  |---|---|---|
  | `namespace::registry::VENDORED_CC_VERSION` | `1.0-rc9` | `1.0-rc15` |
  | `VENDORED_CC_COMMIT` | `5d50c6bb…` | `ace6b74217b4496a67e47aef2258461517e4493c` (tag object `6869eb10`) |
  | `VENDORED_N_FAMILIES` | 176 | 189 |
  | `VENDORED_REGISTRY_SHA256` (CC's grammar hash) | `feeb06a0…` | `df79a1dde30a380380da83f0d776737e580705b6305741f037a5a78c2bef9898` |
  | `VENDORED_SOURCE_SHA256` (CC part 3) | — | `a930a011bd6dc0767f21a5589bb5181f6a189158b247a9d374868293af33999b` |
  | `cc_manifests::VENDORED_WIRE_VOCABULARY_FILE_SHA256` (new) | — | `baf75371f6f25c83c7cd2f6cd0774677f47e9fca5c9c555a09e662249e40a3ff` |

  `wire_vocabulary::WIRE_VOCABULARY_HASH` does not move (`c6bd6aa4…`).
- **The first open after the upgrade runs the instant-form pass** (V211, `Engine::settle_instant_forms`, above): it reads every stored attestation row once, so the first boot of an upgraded node with a large attestation table takes longer than later boots. It is idempotent and never boot-fatal.
- No wire or API change for the read-storm fix. V212 builds one index on `federation_attestations` (both backends) at upgrade. The first SQLite open after upgrade runs `ANALYZE` once, sampling at most 1,000 rows per index; measured at about 4 ms on a 2,401-row store of 15 KB envelopes. A Postgres open runs `ANALYZE federation_attestations` once when the table has never been analyzed (a fresh restore before autovacuum's first pass); Postgres samples a bounded number of rows (`default_statistics_target`) whatever the table's size. The pinned statements name their indexes, so a store missing V107, V178, V180, V181 or V212 refuses these reads with `no such index` instead of planning around it.
- The unheld-supersede refusal text is now uniform across backends: `supersede: unknown {cohort} group {key:?} (nothing to supersede)`, with the key and the cohort that was asked (SQLite omitted the key; Postgres said `community` for `affiliations`). Its kind is unchanged (`InvalidArgument`, Python `ValueError`). Match on the error kind, not the text (CIRISPersist#934 S4b).

### Changed

- CIRISConstitution v1.0-rc15 is vendored at its tag (`ace6b74`, which contains rc12, rc13 and rc14): the namespace registry (189 families; rc12 adds the six census families and the ballot tally, `deferral:request`, `deferral:response:{outcome}`, `identity_amendment`, `observation:access_assumption` and `rendezvous:route`; rc14 adds `evidence:{suite}:{kind}:{cell}:{prefix}`), its match vectors (1244), the governance policy table (rc14 appends the `affiliation_member_action` cosign row) and its vectors, the CSD/4 chain and atom vocabulary (v6), the 14 signed-object vectors (rc15 re-mints `scores_subject_and_scope` with its audience and adds its refusal twin `refuse_subject_outside_audience`) and the six self-roster traces, each pinned by SHA-256. `wa_adjudication:{state}` gains `petition`. The goal refusal reasons cite CC 3.1.9.7, where rc12 registers them. `WIRE_VOCABULARY_HASH` does not move; the tag's `WIRE_VOCABULARY.md` file hash is pinned beside the manifests. The CSD/4 catalogue fixtures stay at the CIRISServer v0.5.234 release, whose pin names the rc12 vocabulary, until a tagged Server release carries a catalogue on vocabulary v6.
- A bare `scope` token is read as the one-element set it denotes by every scope reader, and the stored envelope keeps the producer's bytes. CC's 13 signed-object vectors (CC 2.6.1.7) are vendored and replayed through the attestation door on both backends.
- The genesis bundle's authorization digest is CIRISVerify's `genesis_bundle::authorization_digest`; persist's own projection is removed and the threshold policy (`max(carried M, strict majority of the node's own roster)`) stays in persist. A byte-identity test pins the digest against verify's seven genesis-bundle vectors.
- Every write door that both backends spelled identically now runs on one shared plan, and each backend only executes it (CIRISPersist#934, S4a/S4b). This covers the accord evidence, the location / touch / witness doors, the erasure, fountain and byte writes, the chunk floor and stream records, the peer add, the known-hash sighting, the purge write, the trust revocation, the family doors, the group supersede, the transport-destination writes and the identity-occurrence writes. `store::parity::no_backend_door_reads_identical` keeps it that way. There is no wire or API change. The behaviour where the two backends differed now matches on both:
  - Postgres stamps a witness's and a fountain content's `admitted_at` with the door's receipt instant, as SQLite did; before, it took the column's `now()` default.
  - On a repeated family membership revocation, Postgres now runs the group-row sync too, as SQLite did. The sync is idempotent.
  - The local identity-occurrence door projects its route from the binding before the write, and the signed door reads the pair row's pointer before projecting the route.
  - The unheld-supersede refusal text is the same on both backends (Adoption, above).

### Fixed

- The read storm on a canonical-shaped SQLite store: the unpinned attestation listing, the custody reads and the composer fold no longer read pages in proportion to the store or to one key's history.
  - `list_attestations` and `list_scores` under the default `Live` view ran their lifecycle subquery as a full scan of `federation_attestations` for every candidate row. The correlated compare against a bare `attestation_id` column carried TEXT affinity, so V181's `federation_attestations_reference_seek` expression index was ineligible. The compare is now `= +outer.attestation_id`, and the subquery is pinned to `reference_seek` with `INDEXED BY`.
  - `list_attestations` with no attester, subject or dimension pinned (CIRISServer's equivocation detector: valid now, federation tier, keyset cursor) had no index in `(asserted_at, attestation_id)` order. Each page scanned the table and sorted every qualifying row before its `LIMIT`. V212 adds `federation_attestations_asserted_seek (asserted_at DESC, attestation_id DESC)` on both backends, and the sqlite statement is pinned to it. A page of 512 at a cursor 20,000 rows deep in a 42,000-row store costs what page 1 costs.
  - `list_attestations_by_dimension_citing` and every axis form of `list_composers_referencing_any` (attesting, attested, both, none) are pinned with `INDEXED BY` to V180's, V107's, V178's and V181's three-column indexes. Unpinned, SQLite preferred V004's single-column `federation_attestations_attesting` / `_attested` index because it also yields `ORDER BY asserted_at DESC`, with or without statistics, and every call walked the key's history. Against a 2,400-row own-key slice of 15 KB envelopes, `custody_acks_of` for one blob reads 31 pages. Unpinned, it read 10,202 pages against a smaller 2,002-row history.
  - The trigger is any caller of these reads once a key's history, or the store, outgrows the page cache. On the canonical that was the attestation listing and the composer fold, not the durability pass alone.
- A SQLite store is analyzed at open. When `sqlite_stat1` does not exist, the open runs `ANALYZE` once, bounded by `PRAGMA analysis_limit = 1000`, and every open then runs `PRAGMA optimize`. This is planner hygiene, not the storm fix: statistics did not move the statements above, which is why they are pinned. A failure is logged and the open proceeds.
- A Postgres store whose `federation_attestations` has never been analyzed (`pg_stat_user_tables` shows neither `last_analyze` nor `last_autoanalyze`) is analyzed once at open. Postgres has no `INDEXED BY`, and with no statistics it planned the unpinned `Live` listing as a bitmap AND of every visible row plus a sort: 12,319 buffers for one page over a 2,002-row history. Analyzed, the page walks V212's `federation_attestations_asserted_seek` with the `federation_attestations_reference_live` probe per row: 13 buffers. A failure is logged and the open proceeds.
- A node identity whose software-tier key a pre-20.3.0 keyring archived as `*.superseded-pre-v8` (leaving no live key) reopens with the same key instead of failing to boot; verify 22 restores the archived files on open.

### Security

- RUSTSEC-2026-0387 cleared: verify 22 moves k256/p256 to 0.14, the tree carries crypto-bigint 0.7, and the advisory ignore is removed.

## [60.1.0] - 2026-10-27

### Adoption

- No break: no Python method is removed or re-signed, no enum gains or loses a variant, and no wire byte moves. Additive only.
- New members: `RegisteredStreamEpoch.already_registered` (and the same key in `register_stream_epoch_dek`'s Python JSON), `ReackReport.restored`, and `DeploymentProfile`'s optional `calibration_version` and `pipeline_metadata` (`schema::AgentPipelineMetadata`). A Rust caller using an exhaustive struct literal for one of these must name the new member.
- `delegation_scope::INFRA_RELAY = "infra:relay"` is appended to `delegation_scope::ALL` (position 24) and `INFRA` (position 12).
- Narrowed meanings: `stream_epoch_dek_exists` now means exactly a different DEK for the `(stream, epoch)`; custody's `received` is ordered by the subscriber-signed `delivery_receipt:{stream_id}:v1` row's instant, not a stored receipt's storage stamp.
- New refusals under existing tokens: `identity_amendment_unauthorized` (under `federation_invalid_argument`, Python `ValueError`), and a delivery receipt whose `subscriber_key_id` or `stream_id` length does not fit a `u32` (`BlobError::InvalidArgument`).

### Added

- The accord threshold is a function (CC 4.2.6, CC 4.5.1.2): `federation::accord_threshold(n)` is the strict majority `⌊n/2⌋ + 1` that every accord gate counts through; `accord_threshold_over_roster`, `accord_threshold_now` and `Engine::accord_threshold` report `AccordThreshold { m, n }` over the standing roster. Python: `Engine.accord_threshold() -> (m, n)`, `accord_threshold_for(n)`.
- `infra:relay` (CC 5.4.6): a steward-conferred relay standing, conferred on the accord plane under the same co-scrub rule as `infra:serve` and read through `has_accord_conferred_role`.
- Retryability is answered by persist: `KeyGrantRefusalReason::is_retryable` / `from_token`, `admission::dimension_rejected_reason::{ALL, RETRYABLE, is_retryable}`; Python `key_grant_refusal_is_retryable(reason)`, `dimension_rejection_is_retryable(reason)` (`ValueError` on an unknown token).
- `identity_amendment:v1` admission gate (CC 3.1.5): `check_identity_amendment_admission` admits an amendment only when `authorized_by` names an admitted `deferral:response:approved:v1` about the same agent whose signer held a Wise Authority seat (the agent node's owner, or on a split home the `user` the signing key is an occurrence of) at its instant. Replicated amendments were previously admitted ungated.
- A reversed reconsideration reverses a takedown (CC 4.5.3): `takedown_tombstone::{takedown_reversal, is_reversal_of, REVERSED_OUTCOME}`; withheld is computed at read, a reversed takedown's bytes serve again, `purge_finalize` skips them, and `reack_own_claims` re-claims them (`ReackReport::restored`). Reconsideration of a takedown notice is judged by the content's communities (CC 4.5.5).
- `DeploymentProfile` parses the v2.8.0 members `calibration_version` (tri-state) and `pipeline_metadata` (closed); a profile carrying them no longer loses them on parse.
- `chat:call:v1` A/V call records (one self-subject `scores` row per attendee) are supported with no code change.

### Fixed

- `register_stream_epoch_dek`: re-supplying the held DEK is `Ok` with `already_registered: true` and writes nothing; persist compares the DEKs itself in constant time.
- The plaintext DAG doors refuse a version-1 manifest whose chunk carries `seq` or `epoch`, and an `External` chunk whose `size_bytes` mismatches its manifest entry, before storing anything.
- Takedown immediate removal: an Engine with no local signer can purge; a committed takedown whose holder action did not run resumes; every byte write door re-reads the address's tombstone inside its transaction (`steward_purge::standing_notice`, honoring reversals), so bytes can no longer land after their tombstone. A plaintext chunk shared with a live DAG is kept. A byte write below V187 still lands.
- `stream_receipt::try_receipt_signing_bytes` refuses an over-long length prefix instead of clamping it (CC 5.3.3.6); `verify_receipt_signature` uses it. In-range receipts sign the same bytes.
- `CryptoTier` docs now state self/family sealing is mandatory.

## [60.0.0] - 2026-10-26

Signed attestations are the only state: the cirisnode classes and Goals become `scores` rows, the organisation planes become affiliation rows, the key-record, consent and sweep doors decide in one shared plan each, and the in-process memory backend is removed. Migrations V202–V205.

### Changed

- The cirisnode classes are hybrid-signed, replicated `scores` rows: `contribution:{subject_kind}:v1`, `vote:{contribution_id}:v1`, `moderation:{allegation_type}:v1`, `slashing:{outcome}:v1`, `reconsideration:{grounds}:v1`, `credits:…:v1` / `expertise:…:v1`, and `takedown_notice:{basis}:v1` (admitted only from a CC 4.5.5 duty-holder over the content). `credits_ledger` / `expertise_ledger` are projections of this node's balance rows (`federation::ledger_projection`). `LegalBasis` decodes CC's spellings `dmca512` / `dsa_article16` only.
- A Goal is the declarer's `goal:{scale}:v1` row (CC 3.1.9.7): amend is `supersedes`, retire is `withdraws`, disown is `recants`; a declaration without a well-formed `meta_goal_alignment` is refused. `goals` is a rebuildable projection.
- An organisation is an affiliation (CC 3.3.9): a community record at `cohort_scope: affiliations`; a member is a `membership:{stage}` seat plus a `delegates_to`; a partner is a `licensure:{community_key_id}:v1` row carrying the `PartnerRecord` payload. Under a quorum protocol a licence is a cosigned row; it is judged at its signed instant, and a row signed more than 72 h ago must also hold standing at receipt (`asserted_at_stale`, now also on the consent, key_grant and owner_binding planes). Licences have no public default (`affiliation_config.licence_audiences`; re-emission via `reemission_of`). A subject's `withdraws` of a `licensure:*` or `revocation:*` row about itself is refused; the contest is `reconsideration:{grounds}`. An owner-binding naming a community must name a held affiliation and be cosigned under its protocol.
- Delegation terms (CC 4.4.3.2.8): a term-bearing `delegates_to` (`license`, `grant`, `moderate`, `takedown`, `review`, `slash`, `sub_delegation`, or naming an affiliation) must carry `delegation_valid_until` within 365 days and the affiliation's `role_term`, else `federation_delegation_term_required`. Edges signed before 2026-10-23 keep the earlier reading.
- The key-record write doors, the consent writes and reads, and the sweep selections each decide in one shared plan (`key_plane::plan_key_record_write`, `consent_admit`, `sweep_plan`); backend divergences in tie ordering, limits, race outcomes and genesis-seed scrub sets are fixed. The genesis re-anchor and bake anti-rollback compare instants at substrate resolution.
- CC v1.0-rc9 is vendored at its tag (176 families; adds `identity:occurrence_revocation` and `transport:canonical_rebind`). The CC 4.5.13 governance policy table is runtime data (`federation::governance_policy::PolicyTable`) and the self-roster door checks its corridor at admission (`federation_governance_policy_refused`).
- Three refusals move to the terminal `federation_malformed_row` with new reasons (CC 2.6.1.7): `content_hash_mismatch` (was `federation_tier_unverified`), `subject_key_id_malformed` (was `federation_invalid_argument`), `envelope_row_member_unknown`.
- `hard_case:*` rows replicate (CC 2.4.1.1, unpurgeable); `HardCaseEvent::emitter_key_id` and `HardCaseFilter::emitter_key_id` distinguish peers' events (V202).
- `nodes_owned_by` returns nodes announced by a roster key.
- `FederationDirectory::list_key_plane_wire_hashes_since(family, after, limit)` lists key-plane holdings by family (`DirectoryOp::ListKeyPlaneWireHashesSince`).
- Under `feature = "test-anchor"` only, `CIRIS_TEST_W_SELF_SECS` can shorten the self-roster window.

### Security

- RUSTSEC-2026-0386 (tokio) and RUSTSEC-2026-0385 (ctutils) cleared by lockfile bumps; RUSTSEC-2026-0387 (crypto-bigint 0.5, transitive via p256 in ciris-verify) ignored as unreachable.

### Adoption

- Replication: `EnvelopeKind::{Organization, OrgMembership, PartnerRecord}` join `RETIRED_FRAMED` and are refused `federation_envelope_kind_retired`; positions in `EnvelopeKind::ALL` are kept, so the manifest hash does not move. cirisnode classes and Goals cross as `scores` rows. A v59 peer's `takedown_notice` Contribution in a purge bundle is still applied through v60.x.
- Python removed: `cirisnode_list_takedowns_for_json`, the `cirisnode_*key_grant*` methods (use the `key_grant:{axis}:v1` plane), `put_organization`, `put_org_membership`, `put_partner_record` and their `list_*_for` / `list_*_since` / `list_signed_partner_records_since` reads.
- Python re-signed: the cirisnode writes (`cirisnode_put_contribution`, `cirisnode_cast_vote`, ledger updates, moderation, slashing, reconsideration) take a body JSON and return the row id; `cirisnode_list_contributions` / `cirisnode_list_votes` take a required id and return rows; `cirisnode_process_takedown_admission_json(notice_attestation_id)`; the goal methods take a body and use row ids (`scale`, not `scope_kind`); `grant_delegation` and `add_moderator` gain `delegation_valid_from` / `delegation_valid_until`.
- Python added: `cirisnode_rehome_ledgers`, `cirisnode_check_ledger_projection`, `cirisnode_amend_goal_json`, `cirisnode_recant_goal_json`, `cirisnode_rehome_goals`, `cirisnode_check_goal_projection`. Run both rehomes once after upgrading a node that held v59 ledgers or goals.
- Errors: new `Error::GovernancePolicyRefused`, `Error::DelegationTermRequired`, `cirisnode::Error::{Retired, Federation}`, `CeremonyOutputsRefusal::ScratchDirectory`; new `federation_invalid_argument` prefixes `licence_audience_refused:` and `owner_binding_affiliation_refused:`; `AssertedAtStale`'s `steward` field is `standing_for` and gains `plane`. Removed: `Error::{HardCaseReplicationHeld, OperationalAuthority, OperationalEnvelopeUnbound}`.
- Rust: `store::MemoryBackend` is removed; use `store::test_backend::test_backend()` (feature `sqlite`). The organisation and goal methods leave `FederationDirectory`; `get_goal` takes `&str`; `Engine::grant_delegation` / `add_moderator` take a `DelegationTermBounds`; `TwoPathPolicy::self_roster` is removed. `DIRECTORY_ABI_VERSION` is 11; rebuild capsule consumers.
- Genesis doors take a scratch backend (`verify_ceremony_outputs`, `install_genesis_bundle_roster`, `CeremonyState::finish`, `AmendState::{plan, finish}`); on PostgreSQL the configured role needs `CREATEDB`.
- Producers: sign a licence as a cosigned `licensure:{community_key_id}:v1` row, call `PartnerRecord::canonicalize_sets` before signing, and pass a term on every term-bearing `delegates_to`.
- Migrations: V202 (`hard_case_events.emitter_key_id`), V203 (drops eight cirisnode tables; ledgers gain `attestation_id`), V204 (`goals` rebuilt, `scope_kind` → `scale`), V205 (drops the organisation tables).
- Telemetry: the `backend` label set is `{sqlite, postgres}`.
## [59.1.2] - 2026-10-31

### Fixed — a capsule consumer's `AttestationQuery` reads reach the host's backend (#1162)

- **The shape** (field log, every phone and agent-embedded node). Edge gets
  its directory through `directory_ops_capsule` on the pyo3
  `init_edge_runtime` path, so every directory call crosses the capsule proxy.
  v56.0.0 (#1001) moved the attestation folds onto the typed bounded read
  `execute_attestation_query`, but the proxy answered it with
  `Error::Unsupported` ("directory ops proxy: method
  execute_attestation_query has no DirectoryOp"). The owner walk, `owner_of`
  and edge's chat reader all failed.
- **The fix.** `DirectoryOp::ExecuteAttestationQuery { query }` and
  `DirectoryOpResult::AttestationQueryRows` are APPENDED to the wire, and the
  proxy forwards the query. The host runs only the statement. Routing that op
  alone did not fix `owner_of` on a phone: the witness then failed on the
  next three stubs the owner walk reaches. Those are routed too, each an
  appended op with its result: `list_composers_referencing_any` (the
  retraction read, result `AttestationRows`),
  `list_identity_occurrence_history_by_occurrence` (`OccurrenceHistory`) and
  `list_identity_occurrences_by_occurrence_key` (`IdentityOccurrences`). The
  last two are `self_of_at`'s reads. The page cut,
  the cursor and the per-door count stay in the consumer's
  `query_attestations`, so a read is counted once, against the backend that
  ran it. `AttestationQuery` and what it carries, plus `QueryRows` and
  `StoreBackend`, now derive serde. `AttestationQuery`, `ScopeFilter` and
  `QueryRows` refuse unknown fields: a narrowing that an older host dropped
  would run a wider read than the one asked for.
- **Witnesses** (`ffi::directory_capsule`):
  - **`i1162_attestation_query_through_the_proxy_{sqlite,pg}`**: the owner
    walk's two queries (`to(node).types([delegates_to])` and its
    withdraws/recants read) run through the proxy over a real backend. Rows,
    bytes, backend and the served page equal a direct call, a cursor crosses,
    and `owner_of` resolves through the capsule.
  - **`i1162_attestation_query_serde_round_trips_every_field`**: every query
    field survives the capsule JSON. An unknown field and a zero page are
    refused.
  - **I1162, proxy parity**: a from-disk scan of the trait and the proxy
    impl. Every method the proxy answers `Unsupported`, through its own stub
    or an inherited default, must be on an allowlist with a reason, and every
    allowlisted method must still answer `Unsupported`.
    `list_attestations_by_dimension_citing` is allowlisted, not routed: Edge
    confirms no production edge path calls it.

### Fixed — a Postgres pool is never smaller than 16, starvation is a typed error, and no door holds a client across a second checkout

- **The shape** (field, v59.1.1 on 1-vCPU Postgres nodes).
  `PostgresBackend::connect` left deadpool's `PoolConfig` at its default:
  `2 × CPUs`, which is 2 on one vCPU, and no timeouts, so a checkout waited
  forever. Doors that held a pooled client across an await that checked out
  another wedged the node. Both connections sat idle in `ClientRead`, and
  `setup/root`, `setup/status` and agent memory init never returned. The
  likely culprit is the audit write: `record_entry` kept its client past the
  commit, then the Merkle hook (armed whenever a signer is installed) and
  the trust-grant projection each took another.
- **The fix.**
  - `pool_config`: `max_size` is `max(2 × CPUs, 16)` unless the caller sets
    one.
  - `PostgresBackend::checkout` bounds the whole checkout, including a new
    connection's create, at 30 s. deadpool's own wait, create and recycle
    timeouts stay off on purpose. deadpool runs them on a tokio timer on
    the thread that polls `pool.get()`. Edge polls persist's pool from its
    own tokio copy (#705), where that timer panics ("no reactor running"),
    and across two `.so` files a panic is an abort. So the bound runs its
    timer on persist's runtime: inline on a persist thread, otherwise
    spawned on the runtime captured when the backend was built.
  - A starved pool is `PoolExhausted { waited }` on the store, federation,
    audit and secrets error types (kinds `store_pool_exhausted`,
    `federation_pool_exhausted`, `audit_pool_exhausted`,
    `secrets_pool_exhausted`). In Python it is `ciris_persist.PoolExhausted`,
    a `RuntimeError` subclass: the backend arm it was carved from raised
    `RuntimeError`, so `except RuntimeError` still catches it. Exhaustion is
    not retried: one wait, not four.
  - Each nested door now drops its client before the helper that takes its
    own:
    - audit: `record_entry`, `try_claim_event`;
    - store: `store_pqc_completion`, `store_planned_community_widening` and
      `_listing`, `put_family_membership_widening`, `put_identity_occurrence`
      (and its re-wrap) and `_local`, `lookup_signed_record_by_content_hash`,
      `list_signed_accord_quorum_evidence_since`,
      `community_dek_evict_epoch_objects` (which also took a second client
      while holding the first), `put_stream_sth`;
    - secrets: `store_secret`, `retrieve_secret`, `recall_secret`,
      `forget_secret`, `get_service_stats`, `reencrypt_all`,
      `rotate_master_key`, `try_claim_secret`, `store_detected_secret`.
  - The secrets access-log write is `let _ =`. On a starved pool those doors
    returned Ok and lost the audit row without a trace.
- **Witnesses** (postgres):
  - **I1480**: the sizing function at 0, 1, 2, 7, 8 and 12 CPUs, and with
    an explicit size. deadpool's own timers are pinned OFF.
  - **I320c**: a starved pool polled from a thread with no persist runtime
    is `PoolExhausted` within the wait. With deadpool's timers it was a
    panic, and I320 went red.
  - **I1481**: on a held pool of one, a second checkout is `PoolExhausted`
    within one wait. Checked for the store, a federation door, `checkout`,
    and the audit and secrets conversions.
  - **I1482**: the occurrence door, the wire-index point read and the
    secrets doors finish on a one-connection pool with a 3 s wait. The
    secrets witness counts each access-log row.
  - **I1483**: two concurrent `record_entry` writers with a signer, on a
    pool of two, held together after the commit by a test barrier, plus
    `try_claim_event` on one connection.
  - Each of those drop points was removed by hand, and its witness went red.
    The other doors' drops have no witness of their own.
  - Mutation scope `scripts/mutants/scope-5912-pool.txt`: 2 mutants. One is
    caught. The other, `checkout` returning a default `Object`, is unviable.
    0 missed.

### Fixed — the boot audit self-check reads `cirislens.audit_log` on Postgres

- `boot_audit_self_verify` listed tenants from `cirislens_audit_log`, which
  is the SQLite table name. On Postgres the table is `cirislens.audit_log`
  (V014), so every Postgres boot logged "list tenants: db error" and
  verified no chain. Witness: `boot_audit_self_check_reads_the_postgres_table`
  lists the one audited tenant. It was red on the old name.

### Adoption

- A pin bump for Edge. `DIRECTORY_ABI_VERSION` stays 10: four appended ops
  and four appended results are growth, and no existing variant changed. Both enum-body digests
  are re-pinned for that growth. Both sides must be on 59.1.2: Edge's crate
  pin (the proxy) and the persist wheel the host loads (the dispatch). A
  59.1.2 proxy against a 59.1.1 host gets `federation_backend` (the host
  cannot decode the new op), not `Unsupported`. Other methods the proxy still
  answers `Unsupported` (for example `lookup_family`, `lookup_community`,
  `get_attestation`) are listed with their reasons in the I1162 allowlist.
- Pool fix: no API break. Hosts that catch `RuntimeError` keep working. A
  host that wants to tell starvation apart catches `PoolExhausted`, or keys
  on the `*_pool_exhausted` kind. A pool built with `from_pool` keeps the
  caller's configuration.

## [59.1.1] - 2026-10-27

### Fixed

- `self_collective::principals_of` drops a node's owner only when a held identity-occurrence revocation naming `(owner, node)` is effective. An occurrence row the node never agreed to resolves nothing and is not evidence either way, so the live owner binding still lifts the node to its owner; a pair-room invitation now reaches the invitee's node. A revoked occurrence beside a live owner binding still has no principal, and an occurrence agreed again after its revocation keeps the owner. The same fold serves `speaks_for`, the send set, the hold path and the read gate.
- `replication_audience::may_receive_group_plane` reads `principals_of`, so a split-home invitee's node receives the room's record and membership planes.
- `epoch_minter::resolve`: when several minters grant the reader, it keeps those that are the author or whose `principals_of` names the author. One survivor is the minter; with none or several it falls back to the author. A pair-room blob adopted after both members minted the same epoch binds to the author's sealer instead of a key that holds no DEK.

### Security

- RUSTSEC-2026-0386 (tokio 1.54.1), RUSTSEC-2026-0385 (ctutils 0.4.6), RUSTSEC-2026-0382 (rustls-webpki 0.103.16) and RUSTSEC-2026-0381 (webpki-roots 1.0.11) cleared by lockfile bumps; RUSTSEC-2026-0387 (crypto-bigint 0.5, transitive via p256 in ciris-verify) ignored as unreachable.

### Adoption

- No break: no wire, schema or Python change. `epoch_minter::resolve`, `adopt_cascade::resolve_adopt` and `adopt_cascade::resolve_provenance` gain a `FederationDirectory` bound.

## [59.1.0] - 2026-10-20

- The compiled-in production genesis bundle (`canonical_seed.json`) is the version-4 bundle produced by the 2-of-3 amend (CC 5.3.4), sha256 `d17c05c0…`. It carries the v3 contents byte for byte and adds `serve_transport_destinations` with the canonical serve node's transit pair, so a fresh node boots holding a Rooted transit pair for the canonical with no network (required under the all-or-nothing transit seal, CC 5.3.3.5).

## [59.0.0] - 2026-10-19

### Security

- An aggregate's sources must be distinct (CC 6.1.1): a repeated source id is refused `federation_malformed_row` / `aggregate_source_duplicate` at `descend_aggregated_sources` and at `fountain::member_commitment`, which now returns `Result<[u8; 32], federation::Error>`. New `store::Error::MalformedRow`.
- A key id names its own key (CC 2.6.8): at registration and first contact, a key whose `key_id` does not end in its own fingerprint (`-<fp>`) is refused `federation_malformed_row` / `key_id_fingerprint_mismatch`. Genesis holders, serve nodes and family ids are exempt; keys already held are grandfathered.

### Added

- The self-key roster door is two-path (CC 3.3.6.3): on a roster of two or more keys, a device addition or eviction is a proposal that lands by a strict majority of the roster, or alone after a 24 h window with no majority objection (and, for an eviction, target silence). `federation::two_path` is the shared pure decision (`decide`, `TwoPathPolicy`, `check_corridor`); CC's governance policy vectors replay through it. A held change returns `Error::SelfRosterNotLanded` (`federation_self_roster_not_landed`) and is stored as an `objection:proposal:v1` row; answers are `objection:assent:v1` / `objection:raised:v1`. Python: `Engine.self_roster_standing`, `Engine.execute_self_roster_due`, `Engine.self_roster_vote_envelope`. Migrations V199, V201. The genesis key is evictable by another live roster key through the two paths.
- A live roster key acts as its self's steward (`self_roster::acts_as_steward_at`); a row admitted on a roster key's past standing is refused `asserted_at_stale` when signed more than 72 h ago by a key no longer live (CC 2.6.7).
- `consent:community_trust:v1` admits an owner-authored grant (CC 3.3.1); every new grant's `subject_key_ids` must name the node, its owner and the agent key (`community_trust_subjects_incomplete`); other attesters are refused `community_trust_attester_not_owner`. Held v52-shape grants keep counting.
- `identity:occurrence_revocation:v1` carrier rows (CC 3.1.5) replace held framed occurrence revocations; a user self's carrier needs a strict-majority roster cosign (`carrier_without_roster_quorum`). `key_plane::occurrence_revoked_by` recognises both forms.
- Genesis bundle version 4 (CC 5.3.4): `GENESIS_BUNDLE_VERSION` 4 adds `serve_transport_destinations`, seeded at first open as Rooted transit pairs (`genesis_serve_transport_destination_invalid` on a bad row). The amend ceremony (`genesis::amend::AmendState`) re-authorizes a pinned bundle by holder quorum. A serve node's pair rotates by a holder-cosigned `transport:canonical_rebind:v1` row; a unilateral rotation is refused `serve_transit_pair_rotation_before_rebind`. `self_at_login::check_transit_kex_pair` is the exported key-separation rule.

### Changed

- Typed refusals: `AttestationRefusalReason::SelfRosterPending` (retryable) and `is_retryable()`; `Error::AssertedAtStale`; `Error::SignerDoesNotActFor` gains `reason: SignerNotActingReason` (`not_bound` / `genesis_evicted`); `replication_policy::ENVELOPE_KIND_RETIRED`.

### Removed

- The framed key-plane compat reads (every RNS byte is sealed under CC 5.3.3.5, so unsealed pre-v58 peers are unreachable): `list_signed_key_records_since`, `list_signed_revocations_since`, `list_signed_identity_occurrences_since`, `list_signed_identity_occurrence_revocations_since` / `_for`, `put_identity_occurrence_revocation` and their capsule ops and Python methods. Framed key-record replication and inbound advertisements of the four retired kinds are refused with `Error::EnvelopeKindRetired` (`federation_envelope_kind_retired`); a key replicates as its `key:record:v1` row.

### Adoption

- `DIRECTORY_ABI_VERSION` is 10. CIRISEdge adopts this release only in its sealed-transport build.
- At first open every verifiable legacy key record, revocation and occurrence is rehomed to its key-plane row; V200 marks held framed occurrence revocations `legacy_framed` (they stay revoked).
- A Rust match on `Error::SignerDoesNotActFor` naming every field must add `reason` or `..`.

## [58.0.0] - 2026-10-18

### Changed

- **Breaking:** the key plane is rows (CC 3.1.3, 3.3.6, 2.4.1.1). A key record, a key revocation and an identity occurrence are `scores` rows (`key:record:v1`, `key:revocation:v1`, `identity:occurrence:v1`) minted by persist from the signed object it verified, so no producer changes its wire; `federation_keys`, `federation_revocations` and `federation_identity_occurrences` are their projections (`federation::key_plane`). A receiver re-derives each row and refuses a byte difference. Any other row is admitted only once its signer's key is held (retryable `federation_attester_key_unknown`). An occurrence is revoked by a `withdraws` on its row.
- Key revocations: `revoked_after` only lowers (`bound_raised`); an Ed25519-only revocation is refused, and `put_revocation` signs the ML-DSA-65 half itself.
- The framed key-plane listings (`list_signed_key_records_since`, `list_signed_revocations_since`, `list_signed_identity_occurrences_since`, `list_signed_identity_occurrence_revocations_since`) and `put_identity_occurrence_revocation` still serve and accept v57-shaped bytes for pre-v58 peers, and replication offers both shapes.
- The halt latch is no longer a leg of the trust verdict (CC 3.2, 4.2.1.1): `trust_root_valid` ignores `halt_latched`, which stays on `TrustRootVerdict` as a reported signal.
- Art. 17 erasure of an adverse `detection:*` row is executed as its producer's `withdraws` (CC 4.5.3); the erasure tombstone replicates via `list_purge_bundles_since` / `apply_replicated_purge`. A row whose producer key is not held is refused with a reason: `ErasureSummary` / `DeleteSummary` gain `detection_rows_refused` (Python key `"detection_rows_refused"`). `detection:*` rows name their subject's canonical hash; `hard_case:trace_erasure:v1` carries counts only.
- A reconsideration filing is admitted from the subject of its target as well as a review-holder; rulings stay with review-holders (CC 4.5.5).
- CC v1.0-rc8.1 is vendored (174 families). New admission gate: a score outside its family's declared polarity class is refused `score_outside_declared_polarity` (`Error::DimensionRejected`). The six new rc8 families (retirement, preserve, archive release, lawful order, `takedown_notice:{basis}:v1`) are held shut (`registered_family_held_shut`). CC's own closed `prohibited` categories no longer trip the morally-charged-stem deny-list.

### Removed

- `attach_revocation_pqc_signature`, `list_hybrid_pending_revocations` and the revocation leg of `run_pqc_sweep`; `steward_purge::ART17_ERASURE_BASIS`, `art17_erasure_record_ids`, `art17_erasure_execution`, `hard_case::bind_erased_detection_rows`. `ErasureSummary` and `DeleteSummary` are no longer `Copy`.

### Adoption

- `DIRECTORY_ABI_VERSION` is 8 (`AttestationRefusalReason::KeyPlaneRefused`).
- Migrations: V196 deletes v57-shaped erasure hard-case rows and `art17_erasure` headers that named their subject; V198 adds `attestation_id` to the three key-plane tables. Pre-V198 records are rehomed to rows at the first key-plane write.
- Security: RUSTSEC-2026-0367, -0368, -0369 (zip) and RUSTSEC-2026-0370, -0371, -0372 (zbus unmaintained) are transitive and unreachable; ignored.

## [57.0.0] - 2026-10-15

### Changed

- `hard_case:{kind}:v1` rows (CC 3.1.9.4) and `detection:{detector}:v1` rows (CC 3.4.8) are on the attestation plane; `hard_case_events` and `detection_events` are their rebuildable projections (`silo_projection::check_projection_rebuild`, `Engine::check_silo_projection`). Read doors return the same rows. `hard_case:` rows are unpurgeable and do not yet replicate (`Error::HardCaseReplicationHeld`).
- `put_detection_event` refuses a signer whose `identity_type` is not `lenscore_detector` (`ValueError`).
- DSAR erasure hard-deletes a detection's signed row and leaves no `detection_events` remnant; a detection reached by a steward purge follows its trace.
- `federation::community_admit`: the community and roster doors share one plan per door. Gate functions now take an explicit instant (`received_at` / `at`); pass `chrono::Utc::now()` to keep prior behaviour: `reject_future_dated_community_revocation`, `reject_future_dated_community_widening`, `reject_future_dated_community_listing`, `check_community_membership_listing`, `check_infrastructure_record_admission`, `check_replicated_supersede_does_not_degrade`, `check_infrastructure_community_conformance`.

### Adoption

- A host must hold its own node key (`register_self_federation_key`) before any erasure, peer removal or `record_hard_case`; otherwise `Error::HardCaseAttesterUnavailable` (`federation_hard_case_attester_unavailable`), Python `ciris_persist.NodeIdentityRequired`.
- Requires CIRISVerify 20.2.0; the wheel's `Requires-Dist` is `ciris-verify>=20.2.0,<21`.
- Migrations V194 (`hard_case_events.attestation_id`) and V195 (`detection_events.attestation_id`); legacy rows are rehomed lazily at the first emitter, and `check_silo_projection` reads red until then.
- Internal: CI cache repair and build tooling.

## [56.0.0] - 2026-10-14

### Added

- trace_format v2.8.0 traces admit. `DeploymentProfile` gains signed
  `run_kind` and `trace_format_version` members, read by every run-kind gate
  through `CompleteTrace::signed_run_kind`; v2.7.x bytes are unchanged.
  A v2.8.0 trace validates against the vendored schema pinned by
  `schema::trace_format::TRACE_FORMAT_V2_8_0_PIN` (SHA-256
  `8c51028c8983741f0e14c89c32988df6aacc0981db5a173814e31d9f461c9f81`).
- `schema::trace::RUN_KINDS` is `production | prod-personal | prod-managed |
  qa | battery | mock`; only `mock` is refused. The vendored v2.8.0 schema
  still refuses the two new values inside a v2.8.0 profile.
- A signed `transport_destination` envelope may carry `transit_kex_pubkeys
  {x25519_base64, ml_kem_768_base64}` (CC 3.3.6.2). Malformed pairs are
  `Error::MalformedRow` (`transit_kex_half_pair`, `transit_kex_wrong_length`,
  `transit_kex_key_reuse`, `envelope_member_invalid`).
  `self_at_login::transit_kex_pair_for` resolves a relay's hop key from a live
  `Rooted` binding, or `None` on disagreement or key reuse. Content hashes and
  wire bytes are unchanged; no migration.

### Changed

- Attestation reads are one bounded, paged `AttestationQuery` through
  `AttestationReads::query_attestations`, answering
  `ReadOutcome::Served(Page)` or `NotServed(Refused | Fault)`, never a
  shortened page. `limit` is required (at most `MAX_PAGE` = 10,000).
- The attestation write doors decide admission in one shared plan per door,
  with explicit `PlanInstants { fold_at, received_at }`.
- The holding-claim re-ack signs at most 256 claims per pass, oldest first.

### Fixed

- A local upsert over an occupied `attestation_id` behaves the same on every
  backend (`Error::LocalAttestationIdOccupied` across dimensions), and a
  re-seal racing a tier crossing no longer overwrites the crossed row.

### Security

- rustls 0.23.46 (RUSTSEC-2026-0346, RUSTSEC-2026-0347); neither reaches
  persist's surface.

### Adoption

- **Breaking:** `list_attestations_by` / `_for` exist only under `test` or
  `test-anchor` (deleted in v57); the six
  `list_attestations_{by,for}_{dimension_prefix,type,types}` methods are
  removed. Implementers add `execute_attestation_query` and
  `list_attestations_by_dimension_citing`. Loop on `next` (or `.pages()`),
  treat `NotServed` as an error, and fetch retractions with a second
  type-filtered query.
- Python `Engine.list_attestations_by(attesting_key_id, limit, ...)` returns one
  `{"items", "next_cursor"}` page.
- Gate functions take explicit instants: pass `Utc::now()` for `received_at`
  and the row's `asserted_at` for `fold_at`.
- v2.8.0 producers send `trace_format_version: "2.8.0"` with
  `deployment_profile.run_kind` and `trace_schema_version` `"3.0.0"`.

## [55.0.0] - 2026-10-12

### Changed

- Vendors CIRISConstitution v1.0-rc7 (168 families). `ledger:*` rows admit when
  the signer acts for the owner; `settlement:*` rows admit and refuse
  payment-processor identifiers (CC 3.3.10);
  `membership:widening|removal|resignation:v1` are held shut
  (`registered_family_held_shut`).
- The one holding claim is `custody:ack:v1` `here` at the content's own scope
  (CC 3.1.3.3, 2.4); `holds_bytes` is retired. Claims are renewed at 24 h by
  `spawn_reack_sweeper` and lapse at 72 h. Migration `V190`.
- Key grants are one `scores` row per recipient on `key_grant:{content,epoch,
  stream}:v1` (CC 3.3.2), delivered only to the recipient's node and never
  withdrawn; the SET row types are retired. Migration `V192` re-emits held
  wraps as rows on first boot.
- A room stream is keyed per `(stream_id, epoch)` (CC 5.3.3.1, CC 5.1).
- `Error::MalformedRow` (kind `federation_malformed_row`) is the terminal
  refusal for unreadable signed rows. `purge_unauthorised` bodies carry a
  `reason` token and a `retryable` flag.

### Added

- `Engine::put_plaintext_dag_chunk` and `Engine::finalize_blob_chunks_signing`
  for incremental plaintext DAG writes.
- Takedown is one bytes-plane tombstone (`Engine::takedown_tombstone`,
  CC 4.5.3, CC 4.5.5), authorised by a duty-holder over the content's held
  bindings; taken-down or purged bytes are refused at every write
  (`blob_purged`).
- `public` rooms with open admission and the `community:listing:v1` door
  (CC 3.2).
- `register_stream_epoch_dek` accepts a caller-supplied stream epoch DEK
  (CC 5.3.3.2.5). Migration `V193`.
- `DurabilityDeficit` and `BlobCustody` gain `withheld`.

### Fixed

- Self and family content key grants reach the owner's other devices; a
  mis-built axis stays dirty and is reported as `misbuilt`.
- A purged v3 root takes its nested DAG; room retention never evicts an open
  stream epoch or orphans a retained manifest.

### Adoption

- **Breaking:** removed `MultimediaConfig`, the `holds_bytes` helpers,
  `SignedKeyGrantSet` and `process_takedown_admission_with_config`.
  `promote_adopted_manifest_to_dag` takes a required `disposition`;
  `BlobStorage` implementers add `put_dag_manifest_over_held` and
  `stream_dek_evict_room_chunks`. Build stream-keyed room chunk provenance with
  `BlobProvenance::for_stream_keyed_chunk`.
- New exhaustive variants include `Error::MalformedRow`,
  `KeyGrantRefusalReason::{RecipientNotInAudience, SetRetired}` and five
  stream-epoch `BlobError` variants.
- Upgrade the fleet together: v54 and v55 nodes do not read each other's
  holding claims or key grants.

## [54.1.1] - 2026-10-12

- Internal: fixes the Windows wheel CI job so the release carries its signed
  build manifests and attestations. No library change.

## [54.1.0] - 2026-10-10

### Added

- The steward purge door `federation::steward_purge` (CC 2.4.1.1, CC 3.3.2,
  CC 4.5.3): `Engine::{purge_dry_run, purge_rows, purge_status, purge_finalize,
  apply_replicated_purge, ...}`. A purge needs a quorum-cosigned
  `takedown_notice` over the selection digest, tombstones whole or not at all,
  and hard-deletes only after a 72 h dwell. It never touches a key or the
  accountability record, and refuses records whose subject is a person.
  Migration `V187`.
- Mock runs are refused at the federation tier (`trace_run_kind_mock`,
  CC 3.1.5); `run_kind` is a signed trace member.
- `capacity_consent_stance_with_basis` returns the rows that decided consent.
- An invalid stored Key row is replaced by a valid re-signed record
  (`InvalidReplaced`). Migration `V186`.

### Changed

- Unknown signers (`Error::AttesterKeyUnknown`) and missing bindings
  (`Error::SignerDoesNotActFor`) are retryable; `SignatureInvalid` is terminal.
- Accord proposal nonces are proposer-minted (CC 4.2.6); reuse is
  `Error::AccordProposalNonceReused`. Migrations `V188`, `V189`.

### Adoption

- **Breaking:** removed `issue_accord_nonce` and `accord_nonce_issued`. New
  exhaustive variants include `BlobError::Purged`, `Error::PurgeRefused`,
  `Error::AttesterKeyUnknown`, `Error::SignerDoesNotActFor` and
  `Error::LicensureDelegatorNotAuthority`.

## [54.0.0] - 2026-10-09

### Changed

- Requires CIRISVerify 20.1.0; the wheel's `Requires-Dist` is
  `ciris-verify>=20.1.0,<21`.
- `stream_seal::stream_nonce` delegates to verify and returns `[u8; 12]`; new
  `seal_stream_chunk` / `open_stream_chunk` are the stored construction.
- Licences are judged at their signed `asserted_at` and at receipt, the
  `license` and `grant` walks honour delegation terms, and a term over one year
  is not live (CC 4.4.3.2.8). New `Engine::licensure_status_set` and
  `Engine::licences_issued_under`.

### Added

- A `grant`-scoped delegate may issue a grant (CC 2.4.1.2.1).
- A cycle-closing capability `delegates_to` is refused
  (`Error::DelegationCycle`, CC 4.1.1).
- Affiliations declare their cohort and a typed `AffiliationConfig`
  (CC 4.4.3.2.8). Migration `V182`.
- `OutboundQueue::outbound_counts()` and `Engine::backfill_dag_chunk_links`
  (migration `V185`).

### Fixed

- A steward's shorter `retain` window bounds both retention sweeps.
- Plaintext blobs shared by several rooms keep every room (migration `V184`);
  the wire index keeps one hash per record (migration `V183`).
- The postgres outbound queue's `queue_id` doors work.

### Adoption

- **Breaking:** `tls` implies `postgres` and `pyo3-sqlite` implies `sqlite`;
  `seal_chunk` / `open_chunk` are removed. New exhaustive variants include
  `Error::DelegationCycle` and `ReplicatedKeyOutcome::ScrubsRehydrated`.

## [53.2.0] - 2026-10-08

### Added

- Releases are attested through Sigstore: SLSA build provenance over the abi3 desktop wheels and release tarballs, and a `https://ciris.ai/attestation/cc-conformance/v1` attestation over `evidence/cc_impl.tsv` with predicate `{cc_tag, registry_sha256, crate_version, merge_sha}`. `scripts/verify_release.sh v<ver>` checks them (needs gh 2.49+).
- `observe::emit_metrics()` and `Engine::emit_telemetry_metrics()` write every telemetry counter through the `metrics` 0.24 facade as `Counter::absolute(value)`, with its catalogued name, labels and unit; without an installed recorder they are no-ops.
- The telemetry catalogue is an OpenTelemetry Weaver registry under `telemetry/registry/` (`schema_url: https://ciris.ai/schemas/persist/telemetry/1.0.0`), rendered to `telemetry/catalog.json` and held equal to `TELEMETRY_CATALOG`. Attribute ids (`backend`, `door`, `fold`) are unprefixed.
- `scripts/release.sh` runs a release as resumable stages from a written CHANGELOG section to a pushed tag; `scripts/release_finish.sh` completes it after the tag run.

### Fixed

- The tag job signed a stale earlier-release wheel's hash for some targets (`x86_64-pc-windows-msvc` on 53.0.1 and 53.1.0–53.1.8; `aarch64-unknown-linux-gnu` on 53.1.8). `target/wheels/` is now cleared before the build, exactly one `ciris_persist-<v>-*.whl` is signed per target, and `scripts/bits_changed.sh` refuses a wheel whose hash matches the previous release or a known-stale hash. The affected registry rows are reposted through `.github/workflows/reregister-manifests.yml`. CIRISVerify 20.1.0 refuses a `binary_hash` that does not match `binary_version`.

### Adoption

- Hosts: install a recorder that resolves `metrics` 0.24 to receive counters. New dependency `metrics = 0.24`; no wire or ABI change.
- To verify a release before pinning, use predicate type `https://ciris.ai/attestation/cc-conformance/v1` with `--source-ref refs/tags/v<ver>`.
- Internal: release scripts, certify, CI matrix, mutation and feature-powerset tooling.

## [53.1.8] - 2026-10-07

### Fixed

- The capacity score emit gate now folds consent through the subject's principals, so a steward's grant naming the machine (`for_key_id`) admits the emission it already admitted at precheck. One fold, `consent_by_humans::capacity_consent_stance(directory, attester, subject, family, now)`, serves the gate and is exposed as `Engine::capacity_consent_stance` (Python `Engine.capacity_consent_stance(attester_key_id, subject_key_id, family, now_iso=None)`; unknown family token raises `ValueError`).
- The gate asks `analyze:<family>` (e.g. `analyze:capacity`), and its refusal names that scope. New `ConsentGatedFamily::from_token` and `ConsentGatedFamily::analyze_scope`.

### Added

- Always-on read telemetry in `crate::observe`: per-`(backend, door)` counters of reads, rows and decoded envelope bytes across 22 read doors, plus per-fold attribution for the consent, trust-root, audience and admission folds. Catalogued in `observe::catalog::TELEMETRY_CATALOG` (`ciris.persist.read.calls|rows|bytes`, `ciris.persist.fold.calls|reads|rows|bytes`).
- `Engine::telemetry_snapshot()` (`TelemetrySnapshot`), `Engine::cache_stats()` (`EngineCacheStats`) and `Engine::admission_cache_stats()` (currently `None`); Python mirrors return dicts.

### Adoption

- Pin-compatible with 53.1.7: no wire, ABI, migration or verify change. Scorers should use `capacity_consent_stance(canonical, agent, "capacity")` as their consent precheck.

## [53.1.7] - 2026-10-07

- V181 `federation_attestations_reference_seek` indexes `(references_attestation_id, attestation_type)` on both dialects, so `list_attestations_referencing` (called per conferral row by `trust_root::live_conferrals`) seeks instead of scanning the table.
- `list_attestations_for_type` on sqlite now seeks V178's `federation_attestations_attested_composer_ref` instead of walking the subject's slice.
- The trust-root walks (`trusted_roots_of`, `trust_root_valid`, the capability walk, `owner_granted_scope`, `transit_eligibility_walk`, `canonical_community::live_charter_rows`) read only the typed rows and composers they select from, through new `FederationDirectory` reads `list_attestations_for_types` and `list_attestations_by_types` (with dimension exclusion; defaulted bodies). Answers are unchanged.
- No API to call; the index builds at the first boot's migration.

## [53.1.6] - 2026-10-06

- Five hot-path reads no longer load an author's or subject's whole history: `send_set_for` / `owner_node_receives` (owner allow lists read once per owner via `replication_audience::OwnerAllowLists` / `OwnerAudience`), `may_receive_group_plane` / `live_invitees_of`, `live_delegation_granters`, the `config:*` renewal check, `custody_acks_of`, and `nodes_stewarded_by` / `nodes_owned_by`.
- New `FederationDirectory` reads with pin-compatible defaults: `list_targeted_by_dimension_prefix`, `list_attestations_for_type`, `list_attestations_by_type`, `list_attestations_by_dimension_citing`.
- V180 `custody_ack_citation_index` indexes `(attesting_key_id, dimension, evidence_refs[0])` on both dialects.
- Answers are unchanged; nothing to call.

## [53.1.5] - 2026-10-06

- `list_trace_summaries` is a two-phase read (page ids first, then aggregates over only those ids in one snapshot), so it no longer sorts every trace's payload before the `LIMIT`. V179 `trace_events_trace_ts_scope` makes the first phase covering. Pages and `next_cursor` are unchanged.
- `owner_allow_list`, `is_public_group` and the scoped consent fold read only the rows they can select or retire by, through new `FederationDirectory` reads `list_attestations_by_dimension_prefix`, `list_attestations_for_dimension_prefix` and `list_composers_referencing_any` (pin-compatible defaults). V178 `attested_seek_indexes` adds `(attested_key_id, dimension)` and `(attested_key_id, attestation_type, references_attestation_id)`.
- Answers are unchanged; nothing to call. Indexes build at the first boot's migration.

## [53.1.4] - 2026-10-05

- A canonical serve record held at the same signed instant but without the live accord quorum's co-scrub is now replaced by the quorum-signed record (an authority repair, not a rollback). Older records, and equal-instant records already quorum-signed, stay refused. `register::supersede_precheck` names its arm (`Newer | EqualInstant | Refuse`); one decision `decide_canonical_supersede` serves every supersede door.
- Every `federation_keys` UPDATE door (`adopt_scrub_upgrade`, `supersede_canonical_record`, `store_rebound_key_record`, `adopt_genesis_reanchor`) now writes the whole scrub set (`additional_scrubs`), not scrub #1 alone.
- Nodes seeded from the July bake now boot seated in the community leg.

## [53.1.3] - 2026-10-05

- `withdraw_location_proof` re-indexes the withdrawn row under its new content hash on every backend.
- Location-proof withdrawal is a compare-and-set on sqlite and postgres; the first withdrawal's instant and signature stand under concurrency.
- The custody row-target check reads a plaintext room's group (and `affiliations`) from the row's V177 group when there is no DEK binding.
- Plaintext room writes stamp `group_key_id`: `put_blob_with_scope` and `put_blob_signing_at` take a `group_key_id` argument.

## [53.1.2] - 2026-10-05

### Added

- V177 `federation_blobs.group_key_id` records the group a blob was sealed for; `store_blob_local` and `ManifestRowSpec` take `group_key_id`, and `BlobProvenanceRow.group_key_id` resolves a family blob's durability audience. No backfill.
- `FederationDirectory::withdraw_location_proof`: the attester re-signs the held proof with `withdrawn_at` set (CC 3.3.3); a replicated withdrawal offered to `put_location_proof` routes through the same check.

### Fixed

- Family rekeys and stream re-wraps are bounded by the group, so growing one family no longer wraps another family's content to the newcomer; a stream append naming another cohort is refused before any key moves.
- The accord version door bounds recovery exceptions to the charter in force, refuses a withdrawn named charter (`accord_charter_not_held`), and refuses a seat listed twice (`accord_roster_change_uncovered`). `canonical_community::live_charter_rows` is the one live-charter filter.
- Custody reports take the target from the held row, `custody_view` only folds the blob's own streams, `put_custody_ack` resolves the node key first (`custody_ack_here_node_key_unknown`), and `CeremonyState::from_json` validates instead of panicking.
- A subject may `withdraws` but not `recants` a row about them (CC 2.4.1.1; `recants_not_admitted`). A non-holder's rule-stamped `withdraws` of a `holds_bytes` row is refused (`custody_ack_withdraws_not_the_holder`).
- Importing a genesis bundle installs the accord head first, so a later imported ceremony survives a boot of an older compiled bundle.
- The certify clippy leg also runs `--all-features --all-targets`.

## [53.1.1] - 2026-10-05

- The final genesis is baked: `src/federation/genesis/canonical_seed.json` is the real ceremony's version-3 bundle (family `humanity-accord`, `quorum:2/3`, holders A1/B1/C1, serve node `ciris-canonical-1-d7bdeu223k`), `sha256 = db5e8e8391261dca10c7e701e18bcd26bd8f43ab8e5b8c11ede999ca0befe9f2`.
- At boot, an upgraded node's prior-genesis accord head and `ciris-canonical` birth are replaced by the bundle's (prior rows kept as superseded), so upgraded and fresh nodes hold one head. An imported bundle never replaces a rooted row, and a bake never rolls back a version chain (`RosterSource::{Bake, Import}`, `CommunityLegOutcome::Replaced`).
- An upgraded node keeps the earlier serve record for `ciris-canonical-1-d7bdeu223k`, because the final bundle's record carries the same signed `valid_from`; a fresh node holds the final bundle's. Same key and roles.
- `recover_accord_holder` refuses a non-accord family (`accord_recovery_not_an_accord_family`); `is_public_group` honours only the charter the family head names.
- `verify_ceremony_outputs` seeds its scratch node from the bundle under verification.
- A withdrawn DAG answers `BlobError::Withdrawn` from every door that reads it (`stream_chunks`, `serve_blob_to_peer` and the chunk serve door); hosts must handle `Withdrawn` on each path.
- Requires CIRISEdge 40.0.2 or newer; no wire change.

## [53.1.0] - 2026-10-04

### Added

- A chunk of a withdrawn file is judged by its file (CC 2.3). V176 `federation_dag_chunks(manifest_sha256, seq, chunk_sha256, stream_id)` is written by persist at seal and at `promote_adopted_manifest_to_dag`; a chunk is `Withdrawn` only when every manifest holding it is withdrawn.
- `Engine::evict_blob` on a withdrawn manifest also evicts its withdrawn chunks; `EvictBlobReport` gains `dag_chunks_evicted`.
- `Engine::chunks_of_manifest` and `Engine::dag_contains_chunk` (Python `chunks_of_manifest_json`, `dag_contains_chunk`).
- `genesis::install_accord_genesis_head` is the one accord-head installer for boot and import; a stale genesis head of the same accord whose charter is no longer live is replaced by the bundle's.
- `genesis::install_genesis_bundle_roster` (Engine `install_genesis_bundle_roster`, Python `install_genesis_bundle_roster_json`) imports a verified version-3 bundle and returns per-record outcomes (`installed`, `already_held`, `successor`, `refused`).

### Adoption

- New required trait methods: `FederationDirectory::dag_manifests_of_chunk`, `BlobStorage::dag_chunks_of_manifest`.
- DAGs sealed before 53.1.0 get their chunk relation when re-promoted; until then their chunks read `Unbound`.
- Hosts importing a trust root should call `install_genesis_bundle_roster_json` after `verify_bundle` instead of installing rows one by one.

## [53.0.1] - 2026-10-03

- A `custody:` row no longer counts as binding content (`admission::envelope_binds_content`), so a device's custody report cannot keep a withdrawn file live or make the device a subject of the content. Postgres's `attestations_binding_content` filters through the same predicate.

## [53.0.0] - 2026-10-03

### Adoption

- **Breaking:** no cross-version compatibility; v52 and v53 nodes do not interoperate on the changed wire shapes. Upgrade the fleet together.
- Occurrences must carry a real `device_class`: personal (`phone`, `laptop`) receives the owner's self/family content and keys; `server`, `embedded`, `service` and `agent` receive none unless listed. A re-class is admitted (last-signed-wins) and re-keys the device.
- Re-pin `REPLICATION_POLICY_HASH = 1860451cf166879431dadf433422f6fdb43a911b5c889b0f55ca491262393869` and `CONSENT_GRAMMAR_HASH = 4d473eac6f2bfde1a78b01e9a2ac8442fc9adb5207c7adeb51d509215b79e843`; route send/receive through `replication_audience::may_receive` and `may_receive_group_plane`.
- Family and community supersedes must set `prev_head_digest` to the held `persist_row_hash`; a charter is in force only when the head names it (`charter_digest`).
- `put_accord_decision` loses `steward_signatures` (V172 drops the column; Python refuses a non-null value).
- `pre_rotation_commitment` takes `&[CommittedKey]` and binds key material; re-commit before relying on a T3 recovery.
- `check_attach_freshness` takes an `AttachDoor` argument; `GenesisFault::Absent` and `GenesisPosture::PreGenesis` gain `reason: AbsentReason`.
- New required trait methods include `FederationDirectory::attestation_type_census` and `trust_direction_held_among`; the `DirectoryOp` digest moved (`TrustDirectionHeldAmong`).
- Acceptance edges must carry a `trust:accepts:v1` label and `attached_head_digest` (use `Engine::trust_acceptance_envelope`); unlabelled `delegates_to` rows outside the pinned genesis bundle give no acceptance and are no charter (V167 records the rows held at upgrade).
- Vendors CC `v1.0-rc6` (158 families); `file:{name}:v1`, unregistered `self:*`, `device:*` and `observation:*` leaves, and `key_grant:*` as a dimension are now refused.

### Added

- `custody:ack:v1` (CC 3.1.3.3): each device reports `here` or `none` for a blob; `Engine::put_custody_ack` (with `caller_aad`) and `Engine::custody_view` fold reports into `here` / `received` / `none` / `unknown` (72 h liveness). `blob_custody` gains `device_custody`.
- `federation::replication_audience` is the one audience resolver for send, hold and serve, with per-node `cohorts` allow lists on the owner's `consent:replication` grant. Keys follow the same audience (`device_rekey_not_in_audience`).
- Every-tier durability (CC 6.1.5.3): self/family bytes replicate among their audience; `federation::durability` adds `content_audience`, `durability_mode` and `Engine::durability_deficit` (Python `durability_deficit_json`).
- Self/family chunk streams use one DEK per `(stream, epoch)` (CC 5.3.3.1): V168, manifest v4, the `key_grant:stream:v1` plane, a zero-length terminator per epoch, `Engine::sealed_dag_readiness`, and the retryable `blob_chunk_key_not_yet_granted`. v2 DAGs still read. V175 indexes chunks by sha.
- `genesis::ceremony` assembles the version-3 genesis bundle from caller-stamped inputs (`plan`, `next_items`, `add_partial`, `finish`); the bundle carries the accord family record and `ciris-canonical` birth, and the separate community seed asset is removed.
- Accord holder recovery (CC 4.2.6): `draft_accord_recovery` / `recover_accord_holder` rotate one seat under a pre-committed recovery key; the accord charter requires `recovery_commitments`. Recoveries replicate.
- Accord roster changes are admitted as versions bound to authorized, closed `roster_change` decisions with a standing strict majority; seats go only to `accord_holder` keys.
- Lineage heads (CC 3.2 T6): V174 `prev_head_digest` / `charter_digest`; a version must agree with the roster fold (`lineage_version_disagrees_with_roster_fold`), and an uncovered roster row lags the head (`lineage_head_lags_roster`).
- Row types (CC 2.4) are classified against the CC registry in report mode (`ROW_TYPE_ENFORCEMENT = Report`; `Engine::row_type_report`); carrier row shape is enforced (`federation_carrier_row_malformed`).

### Changed

- A superseded grant hands standing to its successor and a withdrawn one has none (CC 3.2 T2); acceptance edges rotate the same way.
- `witness_quorum` absent or `0` means witnessed mode off; `DEFAULT_WITNESS_QUORUM` is removed and a quorum of 1 is refused.
- A peer does not re-judge another node's attach; seated accord holders found infrastructure communities, and accord-scrubbed nodes are seated without an acceptance.
- `Engine::from_shared` and `from_shared_with_local` set the backend's node key.
- The identity re-signing a pair no longer demotes the occurrence's consent.

## [52.0.2] - 2026-10-01

- The postgres pool's connector runs on persist's own tokio runtime (`store::postgres_runtime_connect::PersistRuntimeConnect`), so a thread without persist's runtime (another statically linked wheel's thread) gets a connection instead of aborting the process. A pool supplied through `PostgresBackend::from_pool` is not wrapped.
- No wire, hash, ABI or migration change.

## [52.0.1] - 2026-10-01

- Session liveness reads the signed lease: a `session:*` claim is live while `now < valid_until`, so a renewal that keeps `claimed_at` stays live (`session_claim::row_is_live`).
- A room that never rotated past epoch 0 is enumerated by `BlobStorage::community_dek_communities()` and re-wrapped for a member's late device.
- `persist_row_hash` truncates instant fractions the way postgres reads them back, so a stored row re-offered byte for byte hashes the same.
- No wire, hash or migration change.

## [52.0.0] - 2026-09-30

### Adoption

- **Breaking:** a revocation names its subject by `revoked_key_sha256_ed25519_raw` (SHA-256 of the raw Ed25519 key; `federation::key_digest::Sha256Ed25519Raw`); `revoked_key_id` becomes optional and the revocation binding has 8 members (`REVOCATION_BINDING_MEMBERS`). A digest-only revocation of an unheld key is admitted. V163 migrates; `FederationDirectory` implementors add `revocations_for_subject`; capsule `DIRECTORY_ABI_VERSION` is 7.
- **Breaking:** every roster growth needs the member's own signed acceptance of a live proposal (`membership:proposal:v1`, `membership:acceptance:v1`, `membership:decline:v1`; `Engine::propose_membership`, `reply_to_membership_proposal`). A founding record admits only members who signed it (`SignedFamily.cosignatures`, V162); a supersede never adds a member. Refusals are `federation_membership_acceptance_refused`.
- **Breaking:** manifests above the inline cap are written as a v3 root over v2 children (V160); pre-v52 peers refuse a v3 root. New doors `open_sealed_manifest_page_as`, `adopt_sealed_manifest_child`.
- `BlobStorage` implementors add `adopt_sealed_chunks_at`.
- Renamed: `store::accord_key_fingerprint` → `sha256_of_pubkey_base64_text`; `RotationCollision.existing_key_fingerprint` → `existing_key_sha256_of_pubkey_base64_text` (also the Python dict key).
- A byte-identical re-offer of a held record now settles as idempotent success before verification and quota (`replication_policy::settle_if_held`).

### Added

- A quorum family can dissolve (`Family.dissolved_at`, V166, a terminal amendment via `supersede_family_with_quorum`; later writes refused `federation_group_dissolved`), and a member can leave on their own signature.
- `Engine::abandon_stream` tombstones an unsealed stream (V160 `abandoned_at`).
- `adopt_sealed_chunks` adopts up to 64 chunks / 32 MiB of one stream in one transaction (Python `adopt_sealed_chunks_json`); V165 makes the per-epoch chunk cap O(1).
- `stream_sth::produce_stream_sth`, `Engine::sign_stream_sth` (Python `sign_stream_sth_json`) mint per-stream STHs; an inline blob has a one-leaf log named by `inline_blob_stream_id`.
- `BlobStorage::list_stored_delivery_receipts_for` returns `received_at` beside each receipt.
- The `consent:community_trust` gate and fold (CC 3.3.1; `Engine::community_trust_consent_for`).
- V161 keeps every identity-occurrence assertion in an append-only history, so a node-bearing verdict cannot change after the fact.
- `moderation:*` rows may name `subject_sha256_ed25519_raw`.

### Fixed

- `session:*` rows require `claimed_at` and `valid_until`, at most 86 400 s apart.
- Family seals carry `family_key_id` so family files publish; a family member's node is party to the family's content.
- An unknown `binding_provenance` token is refused instead of read as `Rooted`.
- The JCS signing form no longer deep-clones the envelope; no byte change.

## [51.3.0] - 2026-09-29

- A second device can read a sealed chunk-DAG file it adopted, not just its manifest: `Engine::open_sealed_manifest_as`, `Engine::promote_adopted_manifest_to_dag` (Python `open_sealed_manifest_json`, `promote_adopted_manifest_to_dag_json`).
- `Engine::put_blob_chunks_signing` (Python `put_blob_chunks_signing_json`) stores a plaintext chunk DAG under an author key and announces it.
- No wire, hash or migration change.

## [51.2.0] - 2026-09-29

- The Live listings honour every retraction the write door admitted (owner, subject and delegate `withdraws`), not only the author's own.
- An exact roster re-add is the idempotent no-op regardless of the spec.
- The principal resolver requires the occurrence's own agreement or a trusted-local binding, so a key cannot make itself another occurrence's principal.
- No wire, hash or migration change.

## [51.1.0] - 2026-09-29

- `Engine::blob_custody` (Python `blob_custody_json`) reports who can open a blob and how many copies are known; self/family copies are reported as not observable (`copies_observable: false`). No wire, hash or migration change.

## [51.0.0] - 2026-09-29

### Added

- Witnessed lineage (CC 3.2 T6): `ciris.lineage_head_cosign.v1` cosigns stored in V159 `federation_lineage_head_cosigns` via `FederationDirectory::put_lineage_head_cosign` (Engine and Python `put_lineage_head_cosign_json`). The current head is the latest witnessed version; competing witnessed heads freeze the lineage and emit `hard_case:lineage_equivocation`. `Engine::lineage_head` / `lineage_head_json`.
- Attach freshness (CC 3.2 T4a): charters carry `attach_window_secs`, `witness_cadence_secs`, `witness_quorum`; acceptance edges carry `attached_head_digest`; stale attaches are refused `trust_root_head_stale`.
- Liveness margin (CC 3.2 T7): a trust-root community needs M + 1 active founders to admit; a stalled root stays valid but refuses new members (`liveness_stalled_non_admitting`) and emits `hard_case:community_liveness_stalled` / `_restored`.
- The owner of a node may withdraw rows the node produced while they owned it (CC 3.4.7.3).
- Sealed media descriptors (CC 3.3.13): `MediaSource.sealed_descriptor`; `Engine::seal_descriptor_for_blob`, `open_descriptor_for_blob` (with `caller_aad`).

### Changed

- **Breaking:** `MediaSource.format` is `Option<String>`; `open_descriptor_for_blob` takes `caller_aad`.
- Self/family stream seals wrap the manifest and every chunk to one recipient set; `SealStreamScopedResult.chunk_key_grant_emissions`.
- Postgres attestation projections run inside the write transaction.
- `delegation_purpose` is a widening-protected member.
- Re-vendored CC registry (149 families) adds `capacity:relay_delivery`.

### Adoption

- Requires CIRISVerify 18.0.0 (`ciris-verify>=18.0.0,<19`).
- Re-pin `ENVELOPE_VOCABULARY_SHA256 = c9558c98bf871e97c2e73c428894e2dc642fcffec4de92da06ab5a9fa69ddca2`; directory-capsule digests move (ABI stays 6).
- Do not emit sealed descriptors until every reader runs v51; v50 nodes refuse an owner's withdraws that v51 admits.

## [50.0.0] - 2026-09-26

### Security

- The consent sweep never widens a placed row: a `self`/`family` row whose envelope names a cohort target (top-level alias or a blob pointer's `content.community_key_id`) is no longer republished federation-wide (`admission::envelope_names_cohort_target`). Rows already widened are not repaired.

### Added

- A member's new device receives what the member holds: `Engine::rekey_community_member_device_add` (Python `rekey_community_member_device_add_json`) re-wraps retained community epochs to the device with no epoch bump, and minter nodes do the same on every receive door. Refusals are `federation_device_rekey_refused` (`device_rekey_unbound` is retryable).
- The `ciris-canonical` trust root, born as a post-genesis community contribution under the accord quorum and amended by its founders' quorum: `SignedCommunity.cosignatures` and `lineage` (V158), `StoredStanding::{Rooted, Stalled, NotRooted}`, `RootKind::Community`, `GET /v1/trust-root/bundle`, `pin_trust_from_bundle_response`, `resolve_community`.
- `apply_replicated_community` is the replication entry for community records (`ReplicatedCommunityOutcome`); `put_community` is strict whoever signs.
- Node-bearing keys cannot found or govern `infrastructure` communities, and a `{node,user}` / `{node,agent}` key cannot be minted (`NodeIdentityNotExclusive`, `NodeIdentityImmutable`). Infrastructure communities must declare `quorum:M/N` with N equal to the founder count.
- Delegation walks default to 5 hops (`DEFAULT_DELEGATION_DEPTH`; 16 by opt-in); beyond-cap chains are reported (`ReachabilityVerdict::BeyondDepthCap`). V157 records each withdraws row's admitting depth; re-judge stored rows with `check_withdraws_admission_as_admitted`.

### Changed

- `Engine::open_mls_state(path) -> (XChaChaKvStore, MlsStateCustody)` derives the MLS-state key from the content master's root, hardware or software; `XChaChaKvStore::open_mls_state` is removed.
- `put_attestation_synced` returns `ReplicatedAttestationOutcome` (`Inserted` / `Unchanged` / `Deduplicated` / `Refused`), the same as `apply_replicated_attestation`.
- The dimension grammar is manifest data: one matcher, `namespace::matcher::match_family`, over the vendored CC rc5 registry (148 families); `prefix_match_score` and `registry::case_rule` are removed. Owner bindings by a minor at `federation` scope are refused (`MinorOwnerBindingAtFederation`).

### Adoption

- **Breaking:** `DIRECTORY_ABI_VERSION` 6; both capsule digests moved. `BlobStorage` gains required `load_or_init_content_master_row` and `community_dek_member_grant_epochs`.
- Rc5 grammar refuses shapes v49 admitted, including unversioned open-vocabulary dimensions, unlisted `consent:{kind}` leaves, the old `identity:canonical_binding` spelling, and CIRISVerify 17.1.0's `hardware_custody:{android|ios_secure_enclave|tpm}` entries (do not store them on 50).
- Replication bridges move community apply to `apply_replicated_community`; `RosterRules::of_community` and `community_roster_events` take the node-bearing seat set.

## [49.0.0] - 2026-09-25

### Changed

- **Breaking:** roster standing is the group's `consensus_protocol` (CC 4.4.3.2.3, 4.4.3.4.2): a widening or revocation on a community or family is admitted only when its signers meet the protocol over the authorized roster at `effective_at`. One evaluator, `federation::consensus::evaluate`, covers `founder_only`, `unanimous`, `majority`, `quorum:M/N`, `weighted:`, `custom:` and `reverse_quorum:`. A member may remove themselves; the last founder cannot be removed; the room key and record signer no longer have standing. Refusal: `federation_roster_authority_unauthorized`.
- Roster rows carry `cosignatures: Vec<RosterCosignature>` (V153); `rekey_community_member_revoke` takes co-signatures.
- `list_attestations` honours the lifecycle view (`AttestationFilter::lifecycle`, default `Live`).

### Added

- Family widening plane (`EnvelopeKind::FamilyMembershipWidening`, the 18th kind; V154) with re-admission; `add_family_member` grows a family without rewriting the record.
- Group amendments replicate with a `GroupSupersedeProof` (V155).
- The `listed` membership listing plane (`EnvelopeKind::CommunityMembershipListing`, the 19th kind; V156); `listed_members(room)` is the only roster view a non-member may be served.
- `XChaChaKvStore::open_mls_state(path)` keys the MLS state store from the hardware root (`KVError::HardwareCustodyUnavailable` when absent).
- Android custody attested at key generation: `AttestationEvidence::AndroidGenerationCustody`; `HardwareAttestationPolicy::check` and `check_structure` take the record's Ed25519 key.

### Security

- Federation-row Ed25519 verification uses `verify_strict`; operators holding rows from other producers should re-verify them once.

### Adoption

- Requires CIRISVerify 17.1.0 (`ciris-verify>=17.1.0,<18`).
- Re-pin `ENVELOPE_VOCABULARY_SHA256 = a6a84cc9d5f4d6bd6295cfc78b42bce35145d2bb9ff14391bfe32ab027116a6a`, `REPLICATION_POLICY_HASH = 5501d6b9621e0af400ed89c0c803515b33c084676be5cd5182c3629277d9714a`, `CONSENT_GRAMMAR_HASH = 8230589131945c4b4db3c2e7ca2187e6c02543cd8f084b0f8862eb951d2c82ac`. Append the 18th and 19th kinds; never insert.
- Producers must collect co-signatures per the group's protocol; family revocation resume ids are three-part.

## [48.0.0] - 2026-09-24

- **Breaking:** rooms grow through a community membership widening plane (`federation_community_membership_widenings`, `EnvelopeKind::CommunityMembershipWidening`, the 17th kind, appended). `add_community_member` signs over the widening row and never rewrites the community record; a scrub over the grown record is refused.
- V151 points membership revocations at their group tables, so keyless rooms and families can revoke; the community revocation key gains `effective_at` (re-added members can be removed again).
- One fold, `active_roster_at(record, widenings, revocations, as_of)`, backs every read-time roster gate.
- The promotion sweep and mesh crossing honour a bound steward's consent grant naming a claimed machine (`consent_by_humans::grant_is_authored_for`, `list_live_consent_grants_for`). V152 keys `consent_peer_set` by `(node_key_id, for_key_id, peer_key_id)`.
- New `FederationDirectory::as_dyn_directory()`.
- Re-pin `REPLICATION_POLICY_HASH = 9d62d3a86f7a0ab955969256a10c8160da73a390953ba3c87167a2da96828a19` and `CONSENT_GRAMMAR_HASH = 07a677bbcdff236e2018f0786e8d9b0d0ef6b5b7cc2b871d41459e26ff8864a9`; `DIRECTORY_ABI_VERSION` stays 5.

## [47.4.0] - 2026-09-24

- Persist mints the test-anchor block: `federation::genesis::mint_test_anchor_block` (feature `test-anchor`) and `cargo run --example mint_test_anchor --features test-anchor` print the `CIRIS_TEST_TRUST_ROOT*` block, now with a seventh value `CIRIS_TEST_TRUST_ROOT_MINTED_BY`.
- The seeder logs a warning at boot when a supplied scrub does not verify under the running persist/verify pair, and `root_binding_anchored` logs the full rejection detail.
- Consumers should delete their own minters and re-mint; existing shared-seed values are unchanged.

## [47.3.0] - 2026-09-24

- `trust_root_valid` gains a holder-hardware leg: every charter holder's key record must carry accepted hardware attestation evidence (structural check; YubiKey PIV chains walked against `yubico_root_der`). `TrustRootVerdict` gains `holders_hardware` and `holders_hardware_attested`, folded into `valid`.
- `HardwareAttestationPolicy::check_structure` (no clock) and `admit_key_record`; replicated key records carrying evidence are structurally checked where they land.
- **Breaking in effect:** a key root whose holder record carries no hardware evidence is no longer valid.

## [47.2.0] - 2026-09-24

- A withdrawn reference stops the bytes (CC 2.3): `read_blob_as`, `read_blob_range_as` and `serve_blob_to_peer` refuse a blob with no live binding row, as `BlobError::Withdrawn` (kind `blob_withdrawn`). Retraction authority is re-derived at read time (`blob_tombstone::binding_state`); one live binding keeps the bytes.
- New `FederationDirectory::list_attestations_referencing`; the content resolver matches both `evidence_refs` and typed `BlobPointer` members.
- `Engine::evict_blob(sha)` retracts this node's `holds_bytes` claims before deleting the bytes.

## [47.1.0] - 2026-09-23

- Family and community membership-revocation doors are idempotent on their key on every backend; a community repeat no longer rotates the DEK again, and a family repeat replaces the stored revocation only when it moves the removal earlier.
- `BlobError::SealDidNotOpen` (kind `blob_seal_did_not_open`) separates an authorized read whose seal did not verify from a backend error; Python raises `RuntimeError("blob_seal_did_not_open: <sha>")`.
- `TraceSummary.admitted_at` and `TraceFilter.admitted_window` expose and filter on each trace's admission instant.

## [47.0.0] - 2026-09-23

- **Breaking:** one scope classifier, `cohort_scope::Scope::placement()`, backs every gate, and `affiliations` is a room everywhere (CC 4.4.3.2.1, 4.4.3.2.8). `Audience::Affiliations` carries `community_key_id`; a room-less `affiliations` row is refused and stored ones become read-refused.
- New `ScopeRefusalReason::MembershipUnresolved` (`scope_membership_unresolved`) when the cohort's roster is not held yet; the Python AV-45 message reads `"<kind>: <reason>"`. `ConsentSweepReport` gains `awaiting_roster`.
- Before adopting, count `affiliations` rows with no room: `SELECT count(*) FROM federation_attestations WHERE cohort_scope = 'affiliations' AND cohort_target IS NULL`.

## [46.5.0] - 2026-09-23

- The targeted read gate checks the row's room, not the producer's key, so members can read their own `community` and `family` rows through `list_attestations`. V150 adds a generated `cohort_target` column with a partial index on `(cohort_scope, cohort_target)`; `CallerScope::admits` takes the row's `cohort_target`. A targeted row naming no room is readable by nobody.
- Internal: CI and release tooling.

## [46.4.0] - 2026-09-23

- `AttestationFilter::cohort_scope` filters the attestation plane by the row's cohort (a selection; the visibility gate still applies).
- `adopt_sealed_chunk_json` exposes `Engine::adopt_sealed_chunk` to Python.
- Internal: test provisioning, certify and release tooling.

## [46.3.1] - 2026-09-22

- A claimed node can read its own `self` rows again: the `self` read gate tests the row's target against the caller's self-collective (the caller, its identity, principals, and their active occurrences and owned nodes). Sensitive `config:admission` and `config:transport` leaves stay readable only by the target itself, and `local`-tier rows only by their producer.
- A revoked occurrence no longer inherits its owner through `principals_of`. `CallerScope::admits` takes the row's dimension.
- No wire, migration or vocabulary change.

## [46.3.0] - 2026-09-22

- `send_set_for(k, cohort_scope)` (Python `send_set_for_json`) returns the peers a `self`/`family` record reaches: consent peers plus the nodes owned by `k`'s principals (and, for `family`, by the family's members).
- `rekey_self_occurrence_add_json` and `rekey_family_member_add_json` expose the retroactive re-grant doors to Python.
- `minter_of_blob(sha)` (Python `minter_of_blob_json`) names who sealed a blob.
- A content key-grant set signed by the sealing node is admitted for a person-authored blob when the signer speaks for the author (`self_collective::speaks_for`); `is_audience` / `would_hold` judge `self` rows by principal.

## [46.2.0] - 2026-09-21

- Requires CIRISVerify 16.1.0 (`ciris-verify>=16.1.0,<17`). No persist API, wire, migration or vocabulary change.

## [46.1.0] - 2026-09-21

- `BlobProvenance::from_attestation` reads the key plane (`tier`, `community_key_id`, `epoch`) from a typed `BlobPointer` when the row references the blob that way; the row's placement and authorship still stand. Conflicting or unreadable pointers, and pointers naming another room, are refused.

## [46.0.0] - 2026-09-20

- **Breaking:** `BlobProvenance` gains `minter_key_id: Option<String>`. The minter of a `(community, epoch)` is resolved by `federation::epoch_minter`: the explicit minter, else the minter of the admitted `key_grant` set, else the author. A blob's key identity is `(community, minter, epoch)`.
- Bindings written under the wrong minter rebind when the naming `key_grant` set is admitted (`rebind_stranded_blob_epochs`).
- `BlobProvenance::from_attestation(row, sha256, epoch, minter)` (Python `blob_provenance_from_attestation_json`) builds provenance from the referencing row.

## [45.0.1] - 2026-09-20

- An occurrence resolves deterministically to its principal (the newest active non-singleton binding, then the singleton), so a claimed node is party to its owner's rooms. New `active_identities_for_occurrence` returns every live principal; audience checks union over all of them.

## [45.0.0] - 2026-09-19

- **Breaking:** every `holds_bytes` claim carries a signed `size` (CC 5.3.2.5); claims without a positive size are refused, and blob doors refuse a size that differs from the stored length. `PutBlobAttestation.size` and the FFI `put_blob_json` wire require it.
- **Breaking:** re-pin `ENVELOPE_VOCABULARY_SHA256` (adds `media`).
- The multimedia Source struct (CC 3.3.13): a typed `media` envelope member checked by `check_media_source` at every door, refused by member name (`Error::MediaSourceInvalid`).
- `derived_from` renditions are indexed in V149 `blob_renditions`; `list_derived_hex` (Python `list_derived_json`).
- `list_holders_sized` (Python `list_holders_sized_json`) and `store_plaintext_local`.

## [44.8.1] - 2026-09-19

- **Fixed:** `put_blob_with_scope` and `adopt_sealed_blob_at` index the
  `holds_bytes` claim they write (sqlite and postgres), as `put_attestation`
  does. Previously peers could see the claim advertised but could not fetch it
  until the holder restarted, so blob-backed bodies read `not_fetched`.

## [44.8.0] - 2026-09-18

- The envelope `scope` member carries a consent's scope; a
  `consent:scope:{kind}` companion row confers nothing.
- One scope-token grammar (`federation::consent_scope`, `parse_scope_token`,
  `covers`): `kind[:sub…]` with an open kind set (CC 3.3.1) and closed sub
  forms for `share:cohort:<cohort_scope>`, `analyze:<family>` and
  `retain:<n>d|<n>h`. Consent doors refuse a malformed token with
  `Error::ConsentScopeTokenInvalid`; unknown kinds are admitted.
- `retain:<window>` is honoured: `resolve_scoped_stance` (and
  `resolve_scoped_stance_by_principals`, also in Python) returns
  `ScopedStance { state, retain_until }`, reading `Expired` past the window;
  `resolve_scoped_consent` is now `resolve_scoped_stance(..).state`.
- Only `share` / `publish` grants authorize propagation; others are counted in
  `ConsentSweepReport.declined_by_principle`.
- `run_consent_expiry_sweep` (Python `run_consent_expiry_sweep_json`) emits
  `consent:state:expired` at each grant's lapse.
- `check_capacity_consent_admission` asks `analyze:capacity` (a bare
  `analyze` grant still covers).

## [44.7.0] - 2026-09-18

- A key's holder can re-sign its registration record without it becoming a
  new key: `ReplicatedKeyPlan::Rebind` admits a self-signed bound record over a
  self-signed unbound row with the same key, pubkeys and claim. A changed claim
  is refused with `RebindChangesRecord`.
- `Engine::rebind_key_record` and `Engine::rebind_self_federation_key` (Python
  mirrors of the same names) return
  `RebindOutcome { Rebound | Unchanged | Refused { reason } }`; anti-entropy
  applies rebinds on every backend.
- Migration `V148` adds `federation_key_registration_history`
  (`list_key_registration_history`).

## [44.6.0] - 2026-09-17

- `consent_peers_by_principals(k)` and
  `resolve_scoped_consent_by_principals(target, k, …)` resolve the consent of
  the humans behind any key, combined by `combine_principal_stances` (any
  `Revoked` wins, then `Granted`, then `Expired`).
- A human's consent names one machine: `for_key_id` joins the
  `consent:replication:v1` grammar and the `consent:state:*` envelope.
  Migration `V147` adds the `consent_peer_set_for` projection.
- **Breaking:** `CONSENT_GRAMMAR_HASH` re-pins to
  `ed2b0f2c8b5d3fc54450c180abce14f3d619074c24d5b8669663ff048d8bc482`.
- **Fixed:** steward resolution is deterministic when one occurrence key is
  bound under several identities.

## [44.5.0] - 2026-09-17

- `Engine::serve_blob_range_to_peer`: a ranged serve behind the same
  stop-tier and quarantine gates as `serve_blob_to_peer`.
- `self_at_login` with an `identity_signer` publishes device occurrences
  through the gated door; `SelfAtLoginOutcome` gains `occurrences_published`
  and `occurrences_local_only`.
- **Breaking (Rust):** `Engine::publish_self_occurrence` and
  `publish_self_occurrence_with_local_signer` take
  `valid_until: Option<DateTime<Utc>>` (pass `None`); Python gains a trailing
  `valid_until_iso` keyword.
- Requires CIRISVerify 15.2.0.

## [44.4.0] - 2026-09-15

### Changed
- `KeyGrant` admission asks whether the principal behind the minter is an
  active member: a device occurrence lifts to its identity, a node key to its
  live owner.
- The gated occurrence door admits a content-only signed occurrence, with
  every persisted field bound to the envelope and millisecond-exact instants.
- Subject key ids are validated on emit and ingest (CC 2.3.2.1): empty,
  whitespace, or a malformed `canonical:` id is refused.
- A `withdraws` naming a `key_grant:*` row is refused; rotate instead (CC 3).

### Added
- `Engine::publish_self_occurrence` / `PyEngine.publish_self_occurrence`
  publish the node's own replicable occurrence.

### Removed
- **Breaking:** no classical `holds_bytes` claim. Announcing doors take the
  node's PQC `LocalSigner` and refuse with `AttestationEmissionFailed` before
  storing anything without one; use `with_hardware_signer_hybrid` to announce
  from hardware.
- **Breaking:** a proxy write's holder claim names this node; the row still
  records the author.

## [44.3.0] - 2026-09-15

- `EnvelopeKind::KeyGrant`, the sixteenth kind: replicated epoch- and
  content-axis wrap sets (`key_grant:epoch:v1` / `key_grant:content:v1`), so a
  member's node can open a sealed blob it adopted.
  `Engine::apply_replicated_key_grant` (also Python) admits a set as a union;
  refusals are `Error::KeyGrantRefused`. Encrypted write doors emit;
  `emit_key_grant` and `emit_pending_key_grants` re-emit.
- An epoch belongs to its minter: community-DEK state is keyed
  `(community_key_id, minter_key_id, epoch)`. A minter rotates at its first
  seal after an admitted removal takes effect.
- Migrations `V145` (minter re-key; boot resolves the node key and aborts if it
  cannot) and `V146` (emission ledger, pending content sets).
- **Breaking:** `REPLICATION_POLICY_HASH` →
  `c1082c12db13b6d0f2240b910da2c0008a85b363df4f9b9b73a013ab28cb389d`;
  `CONSENT_GRAMMAR_HASH` →
  `79c74e4d4d04aeb624a7139d705d4882c25f32f6654e5bf017e2f5b99eec38ac`.
  Consumers mirroring `EnvelopeKind` add `KeyGrant`; an encrypted write now
  needs a node that can emit a federated attestation.

## [44.2.1] - 2026-09-14

- **Fixed:** encrypted-at-rest writes failed on SQLite below 3.42 (Debian
  bookworm, Ubuntu 22.04). The live schema's `subsec` defaults are rewritten
  at boot to an equivalent portable form; shipped migrations are unchanged.

## [44.2.0] - 2026-09-14

- `Engine::adopt_sealed_blob` / `adopt_sealed_chunk` (Python
  `adopt_sealed_blob_json`) store a sealed blob received from a peer verbatim,
  optionally announcing a `holds_bytes` claim.
- `Engine::would_hold` is the one accept decision; `Engine::hold_breadth`
  reports `OnDemand` or `ForCohort`. Migration `V144` adds
  `federation_blobs.author_key_id`.
- Cascade results gain `roster: RosterPartition { granted, excluded, absent }`
  and `readable_by_nobody()` (also in the Python JSON).
- **Behaviour change:** a node refuses content it is not party to
  (`BlobError::NotPartyTo`), with no relay exception (CC 4.4.3.2.1).
  `Engine::is_local_or_family_key` is removed.

## [44.1.1] - 2026-09-11

- **Fixed:** nodes that applied `V070` before v43.0.0 failed migration
  validation at boot. `V070` is byte-identical to its original again, and a
  node that recorded the edited checksum is repaired at boot.
- Every shipped migration's checksum is pinned in
  `evidence/migration_checksums.tsv`.

## [44.1.0] - 2026-09-10

- A stream belongs to its first append: migration `V143` adds
  `federation_streams`; a foreign cohort, community or writer is refused.
  `put_blob_chunk_scoped` takes the signer.
- A sealed chunk is bound to its position (`chunk_aad(caller_aad, stream_id,
  seq)`; sealed manifest v2 carries `stream_id` and `seq`).
- **Breaking:** a sealed stream chunk reads through the new
  `read_stream_chunk_as(stream_id, seq, viewer, aad)`, not by sha.

## [44.0.0] - 2026-09-10

- Encrypted chunked content: each chunk is its own sealed envelope and the
  manifest is sealed under the same DEK. Engine and Python gain
  `put_blob_chunk_scoped`, `seal_stream_scoped`, `read_blob_range_as` and
  `stream_chunks`. Migration `V142` adds `plaintext_size_bytes`.
- Caller-supplied associated data binds a seal to its row: `aad` on
  `put_blob_scoped` and `read_blob_as` (Python `aad_b64=None`). It is never
  stored; `aad` at a plaintext tier is refused.
- The transfer path never decrypts; a whole DAG read is capped at 64 MiB.

### Adoption
- **Breaking:** `ChunkManifest` gains schema version 2 for sealed DAGs; v1 is
  unchanged for plaintext DAGs.
- **Breaking (Rust):** `Engine::put_blob_scoped` and `Engine::read_blob_as`
  take a trailing `aad`; pass `None`.
- The JSON `tier` field of the scoped write doors uses the row spelling
  (`invisible_encrypted`, `community_dek`, `plaintext`).
- Requires CIRISVerify 15.1.0.

## [43.1.0] - 2026-09-10

- The sqlite backend runs one writer plus a pool of read-only WAL connections,
  off the async runtime; `CIRIS_PERSIST_SQLITE_READERS` sets the pool size
  (`0` = single connection).
- The retention sweep keeps an evicted blob's epoch binding (migration
  `V140`, `evicted_at`); `read_blob_as` returns `BlobError::Evicted` to an
  authorized viewer.
- `admitted_at` is `NOT NULL` on sqlite, as on postgres (migration `V141`).

## [43.0.0] - 2026-09-09

- Blob storage is encrypted at rest for the `self`, `family`, `community` and
  `affiliations` cohorts, from Rust and Python; commons tiers stay plaintext.
- Migration `V139` adds `federation_blobs.cohort_scope` and `crypto_tier`;
  reads dispatch on the recorded tier, never on bytes.
- One write door, `put_blob_scoped`, resolves the tier from the directory
  (CC 4.4.3.2.1) and seals; one read door, `read_blob_as(sha, viewer)`,
  authorizes first.
- Destroying an epoch deletes its key material atomically and cannot race a
  bind; eviction retracts this node's `holds_bytes` claims first.
- Lifecycle on Engine and Python: `community_dek_set_key_state`,
  `sweep_community_epochs`, `sweep_all_communities`, `retain_past_epochs`.
- **Breaking:** no body-taking write at an encrypted cohort; `BlobStorage`
  floor methods require a crate-private `StorageFloor` token.

## [42.1.0] - 2026-09-08

- **Fixed:** the dimension prefix filter is case-sensitive on every backend
  (CC 3.1.7 R3).
- Dimension reads are index-served (migration `V137`).

## [42.0.0] - 2026-09-06

### Changed
- The steward-binding predicate, admission gate and `steward_bindings_of` key
  on owner-binding edges alone (CC 3.2).
- `scope_covers(held, wanted)` makes scope matching directional at a `:`
  boundary: a parent token covers its child, never the reverse.
- Dimensions are case-sensitive per segment class (CC 3.1.7 R3,
  `check_dimension_case_rule`); the CC registry is re-vendored to `1.0-rc5`.
- Requires CIRISVerify 15.0.0; the wheel requires
  `ciris-verify>=15.0.0,<16`.

### Added
- `duty:{kind}` family, with `check_duty_admission` bounding a duty to the
  permission it attaches to.
- `federation::licensure`: a set-valued status fold (`revoked` absorbing)
  over rows from the authority or its `license` delegates.
- `session:{kind}` rows must be self-reports (CC 3.4.3); `config:` renewals
  must `supersedes`; `distinct_self_reporting_subjects`.
- `license` and `grant` delegated duty scopes.

### Adoption
- **Breaking:** an agent member with only a plain conferral is not
  steward-bound, so its community is refused (`UnstewardedCommunityMember`).
  Re-issue the edge with `delegation_purpose: "owner_binding"` (CC 2.4.1.2).
- **Breaking:** `config:admission` and `config:transport` rows above `self`
  are refused.

## [41.2.0] - 2026-09-05

- `TaskStatus` gains `Rejected`, accepted by every task door (migration
  `V136` widens the CHECK on both backends).

## [41.1.0] - 2026-09-04

- **Fixed:** an owner-binding already published at a discoverable scope is no
  longer a widening candidate, so `promote_consented_backlog` stops reporting
  a phantom `awaiting_actor`.

## [41.0.0] - 2026-09-04

- **Breaking:** `FederationDirectory` gains the required method
  `put_attestation_with_origin` (`WriteOrigin`), with default doors
  `put_attestation_authored` and `put_attestation_synced(row,
  authenticated_peer)`.
- A node's own writes are charged only the node ceiling, never a per-peer
  bucket; syncs from an authenticated cohort-mate share a sync budget
  (`SYNC_BUDGET_MULTIPLE`); strangers keep per-peer metering.
- Requires CIRISVerify 14.2.0.

## [40.0.0] - 2026-09-03

- A widening's `asserted_at` is the claim's instant, carried verbatim; the
  new signed member `widened_at` records when it was placed (CC 2.6.7).
- **Breaking:** `ENVELOPE_VOCABULARY_SHA256` re-pins to
  `e7135559a3d843ecff3ad34ee3b1a10acf92b33f199a327758139969e19f5699`.
- Widenings minted by v39.0.0 carry no `widened_at`.

## [39.0.0] - 2026-09-02

- **Breaking:** promotion no longer re-signs an actor's row with the node key.
  `promote_attestation`, `set_attestation_cohort_scope`,
  `attestation_promote`, `repair_stranded_scope_backlog` and related doors are
  removed; `ConsentSweepReport.rescoped` is replaced by `widened` and
  `awaiting_actor`.
- `enter_mesh` (CC 5.3.2.4.2) crosses a local row to federation over the same
  bytes, actor-signed or with an appended node co-scrub (`cosigned_at`).
- `widen_audience` (CC 4.4.3.3.1) writes an actor-signed `supersedes` at a
  strictly wider `cohort_scope`.
- `ContextualIntegrity` (the nine CC 4.5.1.1 axes) and `MeshCrossingOutcome`
  (`Crossed`, `AlreadyInMesh`, `AlreadyWidened`, `AwaitingActor`).
- Sign at write: `LocalAttestationInput::bind_for_signing`.
- Python: `enter_mesh`, `widen_audience`, `describe_crossing`.

### Adoption
- Signed instants are millisecond resolution (CC 2.6.2); truncate window
  bounds with `admission::truncate_to_substrate_resolution`.
- Type-keyed readers must resolve a widening through
  `references_attestation_id`.

## [38.8.0] - 2026-09-02

### Added

- `known_wire_hashes` (V134): the set of wire hashes a node knows exist in the federation but deliberately does not hold, with `insert_known_wire_hash`, `known_wire_hash_contains`, `list_known_wire_hashes_since` and `evict_known_wire_hashes` on all three backends. It is a separate table with no `record_key` and its own return type (`KnownWireHash`), and never feeds the holdings read: a known-only hash never makes a node think it already holds a record.
- Ageing is on `last_advertised_at`, bumped monotonically on every sighting; paging is by content hash. Eviction takes a caller-supplied cutoff instant; where the size bound and the cutoff conflict the cutoff wins and the overage is reported in `KnownHashEviction::over_bound_by`. Non-canonical (empty or mixed-case) hashes are refused. `advertised_by` is local-only and never replicated.
- The capsule ABI routes `list_wire_hashes_since` and the four new methods through `DirectoryOp`, with distinct `WireHashes` and `KnownWireHashes` result variants. Append-only growth: `DIRECTORY_ABI_VERSION` stays at 3.
- `resolve_serve_tier` (and an `_over_roster` variant) resolves `ServeTier { None, MeshServer, Canonical }`, ordered so consumers gate with `tier >= MeshServer`. `MeshServer` needs both the owner's `infra:serve` grant and the subject's own claim, and the subject must be a node. A read failure is an `Err`, never `ServeTier::None`. An expired key holds no serve tier.
- A build gate requires every column holding crypto material to declare its natural key.

### Changed

- V135 moves trace signatures to `trace_thought_signatures` (keyed by thought) and drops the per-event pubkey and signature columns from `trace_events`; reads rebuild both fields, so `TraceEventRow` is unchanged. Legacy classical-only rows sharing a thought id do not read back as PQC-signed.
- Trace admission resolves the PQC public key from the directory, fail-closed, rather than trusting the payload's key. A classical-only trace still gets `HybridRequired`.
- Requires CIRISVerify 14.1.0 (all Cargo pins together).

### Adoption

- **V135 is irreversible.** The backfill aborts the whole migration (one transaction) if any thought carries two signatures, but the column drop cannot be undone, and the freed space returns only after an operator `VACUUM`. Deploy it deliberately.

## [38.7.0] - 2026-08-30

### Fixed

- The destination prune ages rows on `last_seen_at` alone; quorum-asserted routes have no staleness clock and are kept until superseded. Callers must advance `last_seen_at` on confirming sightings.
- The expiry reaper has an `Engine` facade.
- `storage_summary()` no longer walks database pages; `storage_summary_with_table_bytes()` does so on request, and `bytes_measurable` reports which one you got.
- The subject-binding projection is built by CIRISVerify's own builder, so persist binds `valid_until`; `valid_until` compares as an instant. `bind_subject_into_envelope` omits an absent `valid_until` from the envelope, so no-expiry records keep their pre-14.0 signing bytes.

### Added

- `check_config_self_or_owner_admission`: a `config:{scope}` attestation must be authored by its subject or the subject's live `owner_of` (CC 3.4.5), enforced at `put_attestation` on all backends and at promotion. An ambiguous owner returns `Error::AmbiguousNodeOwner`.
- `list_wire_hashes_since(kind, after_content_hash, limit)` returns a kind's complete hash set from `signed_wire_index` without reading rows.
- The session-claim plane: a `session:*` registry row, `resolve_claim` (earliest `claimed_at`, ties to the lowest occurrence key id) and `handler_for`, keyed by `(community, session)`. An unclaimed exchange is never acted on, even by a single-node self.
- The `load.ceiling` mesh-config key (CC 4.2.1) lets an owner relieve a node; it can only lower load, and the most restrictive value wins across roots.

### Changed

- Requires CIRISVerify 14.0.0 (all Cargo pins and the wheel's `Requires-Dist`).

## [38.6.0] - 2026-08-26

- `check_node_agency_admission` tests membership: any key whose `identity_type` includes `node` cannot receive agency, including a `{node, agent}` hybrid (CC 3.4.7.3 Clause B).
- `may_act_through(agent, node)` (CC 3.4.7.3 Clause D): true when the node's single owner is among the agent's stewards. An unowned or ambiguously owned node is an `Err`, never `false`.
- Citations of CC 1.13.5 for the node-agency rule now point to CC 3.4.7.3, and the `NodeAgencyForbidden` message no longer says "node-only".

## [38.5.0] - 2026-08-26

- `put_attestation` returns `AttestationOutcome { Inserted, AlreadyHeld }`: re-delivering a row already held is a success, not an `Error::Backend`. A different row under an occupied id is a typed `Error::Conflict`.
- **Breaking:** `DIRECTORY_ABI_VERSION` 4 → 5; `DirectoryOpResult` gains `AttestationOutcome`.

## [38.4.0] - 2026-08-22

- `StorageSummary::tables` lists every table from the database catalogue, plus `dark_bytes` for unaccounted space. SQLite reports real per-table bytes (including indexes) via `dbstat`, with `bytes_measurable` saying whether that was possible.
- Bounded observation prunes: `prune_announced_peers_not_seen_since` and `prune_transport_destinations_not_seen_since`, with `Engine` facades. Replicated tombstones are never pruned.
- `reap_expired_attestations` deletes expired attestations in bounded batches through the per-row purge door, so `supersedes`, `withdraws`, `recants`, `delegates_to` and exclusion rows survive expiry. Dependent `signed_wire_index` and `consent_peer_set` rows go with them.
- SQLite sets `journal_size_limit = 64 MiB` so the WAL is truncated after a checkpoint instead of staying at its high-water mark.
- Fixed: the prune cutoff compared `+00:00` and `Z` spellings of the same instant as text, pruning rows that sat exactly on the cutoff.

## [38.3.0] - 2026-08-21

- `admission_identity_for_writer` resolves a writer to its principal: the active occurrence binding first, then the node's live single owner. The community write gate, the AV-84 standing check and trace-ingest `writer_admission` all use it, so a node can write to communities its owner belongs to. An unbound node inherits nothing.
- `nodes_owned_by(owner)` is the reverse owner-binding walk; `n ∈ nodes_owned_by(U)` exactly when `owner_of(n) == U`. Nodes with ambiguous ownership are skipped.

## [38.2.0] - 2026-08-21

### Added

- Community and family writes are signer-explicit: the put doors read the cohort target from the producer's signed envelope (`envelope_cohort_target`), so a member's own signed `cohort_scope: family|community` row is admitted with the author's signature intact. No schema or preimage change.
- A `chat:*` projection-registry row (`AttestationFamily::Chat`), capped at Cohort at every commons tier.

### Fixed

- Targeted cohort rows require federation tier, and the tier vocabulary is a closed set on every backend.
- `set_attestation_cohort_scope` and promotion run the same cohort gates as the put door, and cohort-target aliases must agree.
- Standing and membership use the active occurrence binding (`active_identity_for_occurrence`), so a revoked device loses its owner's write access. They also use active roster membership (`active_family_key_ids_for`, `active_community_key_ids_for`), so a revoked member cannot keep writing.
- The AV-84 cohort-standing check runs at the put door, not only at promotion.
- A replicated, byte-identical community row is an idempotent no-op on all three backends (`community_reput_verdict`); differing content is a `Conflict`. Memory no longer overwrites the stored row.
- Internal: macOS CI lane maintenance.

## [38.0.0] - 2026-08-20

### Added

- The `ledgers` table family (V132; CC 3.3.10.1): `ledger_heads`, `ledger_checkpoints`, `ledger_entry_ranges` and `ledger_fork_evidence`, with `LedgerService` and FFI verbs. Balances are stored as decimal text.
- `ledgers::standard` (always compiled): `derive_ledger_id`, entry hashing and chain validation, an integer conservation fold that reports every violation as a typed flag, and fork detection that records forks and never triggers `slashing:*`.
- `ledger:*` rows are refused at federation tier until the registry row is ratified; `check_ledger_binding_admission` requires a row's `ledger_id` to be the derivation of its triple.
- The `registry_key_escrows` table (V133) with `KeyEscrowService` and FFI verbs: custody metadata only (CC 4.4.3.2.8), never key material. Terminal states are final.

### Fixed

- Refused writes are counted: `refusals_by_budget` and a bounded `refused_keys_in_window`.
- The partner-licence quorum denominator excludes expired and revoked stewards.
- A cross-manifest agreement gate checks the two vendored manifests' `polarity`, and every registry family column must be read or declared inert.
- `resolve_projection_recipients` refuses scope-address ids (`cohort:*`, `av-stream:*`) with `GroupIdNotFederationKeyed`.

### Adoption

- **Breaking:** `ComposedVerdict.witness_diversity` is a band (`"established"` / `"not_established"`), not a float; this changes the directory-capsule op and `resolve_scores` JSON.
- **Breaking:** `grant_trust` takes `SignedTrustGrant` and `revoke_trust` takes `SignedTrustRevocation`, verified inside every backend; only the granter can revoke. `remove_peer_record` requires `reason` and records `acting_under_delegation_id`; both removal paths emit `admin_action:peer_removal`.
- **Breaking:** `purge_genesis_delegation_row_v31` takes a `GenesisPurgeAuthority` (`CompiledIn` | `QuorumVerified`); `verify_bundle_quorum` returns `QuorumVerifiedBundle`.
- **Breaking:** `TrustScoring::trust_score` drops `recursion_depth`; `AdmissionGate` and `ReplicationConfig` drop their depth settings.

## [37.1.0] - 2026-08-19

- `is_accord_family(attestation_type, dimension)` reports whether a row belongs to the `accord:*` family in either namespace (type or dimension), so a relay pre-filter no longer lets `accord:invoke:*` rows bypass the CC 4.2.1 relay gate. `accord_root_claim` uses the same predicate.
- `RelayVerdict::refusal_reason() -> Option<RelayRefusal>` returns the first applicable reason in precedence order, so "cannot judge" is never reported as "signer not seated". `NoEdgeToRoot` is reported last.
- `resolve_projection_recipients` returns `RecipientVerdict { set_resolvable, peer_in_set, basis }` for advertising holdings; `Projection::SelfOwn` is roster-bounded on every plane. `Cohort` at `species`, `biosphere` and `federation` withholds (`NoRosterForScope`) until scope-address tables exist; `Capability` and `Subject` audiences refuse with `NotRosterKeyed`.
- `holdings_authority` derives a holding's authority from persist's own verified state (via `is_trust_root`), never from the row or manifest.
- **Adoption:** adopt `holdings_authority` and `resolve_projection_recipients` together. A trust-root publisher now resolves `AccordCoScrub`, so `projection_for(FountainContent, "federation", …)` is `Global` rather than `Cohort`. Adopting only one of the two either hides canonical corpora at `federation` or advertises them with no recipient bound. Do not use this verb for `peer_has_serve_capability`.
- `is_trust_root` is a disjunction: demoting a canonical publisher requires both the canonical withdrawal and the `infra:attest` role tombstone.
- Requires CIRISVerify 13.6.1.

## [37.0.1] - 2026-08-18

- No projection value changes. The property-sweep corpus (`FAMILY_DIMS`) now includes the `accord:*`, `moderation:*` and `provenance:build_manifest:*` families, and a compile-time exhaustive match forces every future family to be added.
- The `moderation:*` Cohort ceiling is tested across all live dimensions, all authorities and the tombstone path. Its commons tiers are now listed explicitly in `projection_for`.

## [37.0.0] - 2026-08-18

All deferred permissive defaults are removed in this release.

### Added

- `accord_root`, a signed envelope key naming the accord an `accord:*` row belongs to, required at the write door. `accord:lifecycle:v1` rows may instead name the accord in `attested_key_id`; if both are present and disagree, the row is refused. `ENVELOPE_VOCABULARY_SHA256` is re-pinned to `e019ecb873f662399c13515414849a8d055d5ec2f0893e21f74cdccf6f60a111`.
- `may_relay_accord_attestation(&dir, self_key_id, &attestation)` reads the accord root and signer from signed bytes only.
- A field-set gate pins the serialized keys of `Family`, `Community`, both membership revocations and `LocationProof`, in both the fully populated and the minimal shape.
- `compute_persist_row_hash` is pinned to the V1 canonicalizer.

### Changed

- `HybridPolicy::Strict` replaces `Ed25519Fallback` on edge ingest, secrets and both cirisnode backends. `secrets/client.rs` fails locally on `PqcNotConfigured` instead of downgrading.
- `canonicalize_for_edge_signing` uses `ceg_produce_canonicalize` (JCS) instead of the V1 Python canonicalizer. ASCII-only payloads produce the same bytes either way, so a peer that has not upgraded fails only on non-ASCII or non-ES-float input.

### Fixed

- The PyO3 cold-path PQC signer (`cold_path_pqc_sign`) and `canonicalize_envelope_value` use the CEG-produce canonicalizer that every Rust verifier uses.
- `SignedLocationProof.authority_key_id` must be the subject or a live delegate of the subject (`topology::live_delegate_standing`). Refusals are typed: `..._no_delegation_edge` is retryable; `..._retracted` and `..._expired` are final.

### Removed

- The CEG 0.1 attestation-ladder transition: `AttestationLadderTransitionPolicy`, `admits_deprecated_form()` and `DimensionAdmissionPolicy::attestation_ladder_transition`. The old `attestation:l<N>:<mechanism>` form is refused with `federation::Error::DeprecatedAttestationLadderForm` (`federation_deprecated_attestation_ladder_form`, `PyValueError`), which names the canonical form to emit. Stored rows may still carry the old form.

### Adoption

- **Breaking:** upgrade edge and persist in the same window; if you must stagger them, upgrade persist first. Check the peer's canonicalizer by its build: an ASCII-only payload passes on both versions, so working ingest does not prove the peer upgraded.
- **Breaking:** Rust code that builds `DimensionAdmissionPolicy` by struct literal must drop the removed field.
- For `attestation_type`-shaped accord rows that are both unnamed and signed by a non-holder, the reported refusal is now `federation_accord_root_unnamed`.

## [36.3.0] - 2026-08-18

- `may_relay_accord_participation(&dir, self_key_id, &participation)` takes the accord root and signer from the signed `AccordParticipation` (`family_key_id`, `member_id`), so a caller cannot nominate the wrong root. An unheld root yields `roster_resolvable: false`. `may_relay_accord_object` remains as the lower-level form, and its `root_ref` must be the object's own.
- Requires CIRISVerify 13.5.0, which replaces 13.4.0's unusable scope-privacy API and corrects the mobile registry hostname to `eu.registry.ciris-services-1.ai`.

## [36.2.0] - 2026-08-17

- `active_roster_of(dir, root_ref) -> Option<Vec<String>>` returns the active roster of any trust root, from the family that root charters. `None` (cannot judge) is distinct from an empty roster.
- `may_relay_accord_object(dir, self_key, signer_key, root_ref) -> RelayVerdict` relays only when the signer holds a live seat and this node holds a live `delegates_to(self → root)` (CC 4.2.1). `roster_resolvable`, `signer_seated` and `edge_exists` are reported separately. It does not decide whether a halt binds this node.
- The `accord:*` projection row is `Global` at the commons tiers so partial quorum objects can assemble; relay is limited by the predicate above. `moderation:*` is Cohort, tombstones included.

## [36.1.0] - 2026-08-17

- `provenance:build_manifest:*` projects like `KeyRecord`: wide at species, biosphere and federation for trust-root emitters, Cohort otherwise. Other `provenance:*` families keep the conservative default.
- `attestation_family()` and `AttestationFamily` (`#[non_exhaustive]`) are public.
- **Correction to the 36.0.0 adoption notes:** do not replace a capability gate with `matches!(projection, Projection::Capability(_))`, because `trace:*` resolves `SelfOwn` below the commons tiers and the gate would stop applying there. Gate on `matches!(attestation_family(dimension), AttestationFamily::Trace)` instead. The same applies to `Subject`.
- `trace_manifest:*` stays a separate family from `trace:*`.

## [36.0.0] - 2026-08-17

### Changed

- The 15 remaining `list_signed_*_since` cursors take `Option<(DateTime<Utc>, String)>` and compare the pair, so rows sharing a timestamp are no longer skipped. New `Served*` wrappers carry a node-local `admitted_at` that never enters a content hash. V130 backfills it and adds pair indexes.
- V131 adds `federation_keys.mutated_at`; cursors read `GREATEST(admitted_at, mutated_at)`, so five key-mutating doors now move the serve position.
- `precedence::retired_ids` is the single retraction fold (entitlement gate plus §6.1 precedence); `tombstoned_ids` and `retracted_edge_ids` delegate to it. This closes two holes where an unentitled `withdraws` could sever a capability-conferral walk or empty a family charter's candidate set.
- `projection_for(plane: Plane<'_>, cohort_scope, authority, is_tombstone)`: `Plane::Attestation { dimension }` carries the dimension. `Projection` gains `Capability(CapabilityToken)` and `Subject`; `CapabilityToken::InfraServe.as_scope()` equals `delegation_scope::INFRA_SERVE`. Decided rows: `consent:*`, `trace:*`, `scores:*`, `capacity:*`, `content_class:*`, `transport:*` and `system:audit_chain:hash_continuity`. Undecided families cap at Cohort.
- An accord evidence bundle with more participations than roster seats, or duplicate `member_id`s, is refused before any other work with `AccordEvidenceCarrierMalformed`. `participations_admitted` is replaced by `effect: AccordAdmissionEffect` (`Duplicate` | `Supplied { novel_proposal, novel_participations }`).
- `retire_key_grants` returns `#[must_use]` `RetireKeyGrantsOutcome` (`Complete` | `Partial { failed }`); `supersedes_failed` is gone.
- Consent ordering is causal: the new signed envelope key `consent_supersedes` names the grant a revocation supersedes, and the result is the more restrictive of the causal and clock orderings. `withdraws` and `recants` now count in the consent fold. `resolve_consent_state` and `resolve_scoped_consent` share one implementation. `DEFAULT_MAX_TOUCH_SKEW` is unchanged.

### Added

- `apply_replicated_attestation` returns `inserted` | `unchanged` | `deduplicated` | `refused{conflicting_attestation | already_present_identical | store_conflict}`. `put_attestation` is unchanged.
- `log_scores_read` records every scores-plane read to `tracing` (CC 3.4.5) and cannot fail. `FEDERATION_READ_PREDICATE_REDACTED` is reserved.

### Fixed

- Python `apply_replicated_key_record` returns canonical JSON, so refusals are returned instead of raising `ValueError`.
- Postgres `put_accord_participation` handles concurrent duplicates as an idempotent no-op and still refuses a differing vote.
- Twelve `Row::get` calls that could panic on NULL.

### Adoption

- **Breaking:** `DIRECTORY_ABI_VERSION` 2 → 3; re-pin `ENVELOPE_VOCABULARY_SHA256` = `c159bc2ec76176c8573b24b4052c5f0b93e3dae75d615f2d221c1f460a2d7cac` (adds `consent_supersedes`).
- Resume cursors only from `resume_pair()`; callers must be idempotent by id, and `admitted_at` is node-local.
- Consent producers stamp `consent_supersedes` before signing when revoking a specific grant; leave it out for blanket revocations.
- Match on `admission.effect` (JSON `effect.kind`) instead of `participations_admitted`; read `RetireKeyGrantsOutcome.failed` instead of `supersedes_failed`.

## [35.0.0] - 2026-08-17

### Changed

- **Breaking:** `projection_for(plane: ObjectClass, cohort_scope, authority, is_tombstone)` takes the plane (`load_bearing::ObjectClass`, re-exported as `namespace::ObjectClass`), so each plane has its own projection row. `TransportDestination` is Cohort at species and biosphere and wide only at federation for trust roots. `FountainContent` is wide only at federation for trust roots. `HardCaseEvent` never widens past Cohort. `KeyRecord` stays wide at every commons tier for trust roots. `ReplicatedKind::projection_plane()` maps fetch kinds onto planes. The Attestation plane keeps its previous behaviour.
- **Breaking:** tombstones no longer always project Global. They project at `tombstone_ceiling(plane, authority)`, the widest live cell for that plane and authority: `KeyRecord` Global; `TransportDestination` and `FountainContent` Global only for trust roots; `HardCaseEvent` Global only for infra authorities.

### Removed

- **Breaking:** Python `Engine.wrap_dek_for_recipient_b64` and `Engine.unwrap_dek_b64` (the classical v1 wrap). Use `wrap_dek_for_recipient_v2_b64` / `unwrap_dek_v2_b64`. Pre-v34 v1-wrapped material must be unwrapped outside the substrate (with `ciris-crypto` or CIRISVerify).

### Fixed

- `unwrap_dek_v2_b64` requires and validates the envelope's `algorithm` field.
- `extract_key_grant_payload` refuses retired wrap spellings by name: the hyphenated v2 token (respelled; the error gives the current token) and both v1 tokens (removed).
- `canonicalize_envelope_for_signing` uses the same canonicalizer (`ceg_produce_canonicalize`) as the admission gates, so non-ASCII and non-ES-float payloads verify. The audit plane is pinned to the old rule via `canonicalize_envelope_for_signing_v1_pinned` so stored audit chains keep verifying.
- Internal: the CI and release-gate Python wheel is built with the same feature set as the shipped wheel.

## [34.0.0] - 2026-08-16

Scoped transit: peers get a rotating PQC transit passphrase through `key_grant`, with no hand-distributed shared secret.

### Changed

- `key_grant` addressing generalizes from `(stream_id, stream_epoch)` to `(scope_kind, scope_id, epoch)` (V129; columns renamed in place). `KeyGrantScope::TransitMembership` is a second epoch-addressed scope alongside streaming. A grant is addressed by `content_sha256` XOR `epoch`, and `scope_id` is required on every grant.
- `ifac_size` (`Option<u16>`, unwrapped) is required on transit-membership grants, refused on all others, and bounded to `IFAC_SIZE_MIN_BITS..=IFAC_SIZE_MAX_BITS` (8..=512).
- Supersession sentinels carry the prior grant's `ifac_size`.

### Added

- `KeyGrantScope::{ALL, from_wire_str, epoch_addressed_tokens}`.

### Removed

- `WrapAlgorithm::HpkeRfc9180BaseX25519AesGcm` (the classical v1 wrap) and `WrapAlgorithm::is_streaming_pqc_v2()`. A stored v1 grant fails at parse with a message naming the algorithm.

### Adoption

- **Breaking:** `list_key_grants_for_stream_epoch(stream_id, epoch)` → `list_key_grants_for_scope_epoch(scope_kind, scope_id, epoch)`; Python `Engine.cirisnode_list_key_grants_for_stream_epoch_json` → `cirisnode_list_key_grants_for_scope_epoch_json(scope_kind, scope_id, epoch)`. No aliases. An unknown or non-epoch `scope_kind` raises `ValueError`.
- **Breaking:** `KeyGrantPayload` wire fields `stream_id` → `scope_id` and `stream_epoch` → `epoch`. Payloads still using the old keys are refused with an error naming the replacement.

## [33.0.0] - 2026-08-16

- **Breaking:** `receive_and_persist` no longer scrubs what it stores: the stored `trace_events` rows hold the node's own unmodified record, and only the minted attestation (the object that replicates) is scrubbed. The scrub-required refusal now gates publication, not storage. `Engine(scrubber=…)` redacts only the federated copy, and stored rows' `scrub_*` columns report that no treatment was applied.

## [32.3.0] - 2026-08-15

- `ScrubTreatmentMismatch` carries `treated_as`, `ner_ran` and `model_digest`, so the error tells "no model staged" apart from "a model ran and reported no pass".
- Python scrubbers may return a 5-tuple `(scrubbed, modified_count, ner_ran, model_digest, applied_trace_level)`, and persist relabels the envelope to the stated level. Only downgrades are accepted (`TraceLevel::detail_rank`). The 4-tuple and 2-tuple shapes are unchanged.
- `TraceLevel` docs no longer list what each level contains (`detailed` carries no content fields); see the upstream trace wire spec.

## [32.2.0] - 2026-08-15

- `AttestationFilter::validate`, called by `Engine::list_attestations`, refuses window bounds outside years 1000–9999, as well as inverted or empty windows. Previously `DateTime::<Utc>::MAX_UTC` as an upper bound silently matched no rows. Use `OPEN_ENDED_WINDOW_END` for an open-ended window.
- Requires CIRISVerify 13.3.1.
- Internal: CI pulls postgres from a GHCR mirror.

## [32.1.0] - 2026-08-15

- `trace_events.admitted_at` (V128) is stamped by the backend through `monotonic_admission_instant`, once per batch; a caller-supplied value is overwritten and a re-delivery does not refresh it. It is exposed as `TableUsage::newest_admitted_at` beside `newest_ts`, so liveness no longer depends on the producer's clock. The column is nullable with no backfill, node-local, and never replicated or signed.
- Requires CIRISVerify 13.3.1.

## [32.0.0] - 2026-08-14

### Fixed

- **Security:** `list_signed_key_records_since` pages by local admission order (`federation_keys.admitted_at`, V126) rather than the producer's `scrub_timestamp`, so a late-replicated key record is no longer permanently skipped. The cursor compares the `(admitted_at, key_id)` pair. `admitted_at` lives in `ServedKeyRecord`, outside the content hash.

### Added

- `ScrubOutcome` carries `fields_modified`, `ner_ran`, `applied_trace_level` and `scrubber_model_digest`. The last three are signed into the scrub preimage and stored (V127: `scrub_ner_ran`, `scrub_applied_trace_level`, `scrub_model_digest`; nullable, `NULL` meaning no claim was made). A `full_traces` batch whose scrubber reports `ner_ran: false` is refused with `IngestError::ScrubTreatmentMismatch` (`scrub_treatment_mismatch`). Scrubbing at `detailed` and relabelling passes.
- A gate pins the `DirectoryOp` / `DirectoryOpResult` wire contract by digest.

### Adoption

- **Breaking:** `list_signed_key_records_since` takes `Option<(DateTime<Utc>, String)>` and returns `Vec<ServedKeyRecord>`. Python takes `(since_rfc3339, since_key_id, limit)` and refuses half a cursor.
- **Breaking:** `DIRECTORY_ABI_VERSION` 1 → 2.
- **Breaking:** `Scrubber::scrub_batch` returns `Result<ScrubOutcome, ScrubError>`; the count is `ScrubOutcome::fields_modified`.
- Python scrubber callables should return `(scrubbed, modified_count, ner_ran, model_digest)`. The legacy 2-tuple is read as `ner_ran=False`, so `full_traces` batches are refused with `ValueError("scrub_treatment_mismatch", …)`. Any other shape is refused.

## [31.5.0] - 2026-08-15

- **Security:** `namespace::is_trust_root` uses the tombstone-aware `is_canonical_effective` and `is_infra_attest_effective`, so a key whose trust-root role a quorum withdrew no longer projects Global. Both roles must be withdrawn to demote a key that carries both.
- Internal: the generated directory double is checked in CI and the pre-commit hook.

## [31.4.0] - 2026-08-14

- `federation::directory_double::FaultInjectingDirectory` (behind `test-anchor`) wraps a real directory and injects faults per method (e.g. `.unsupported("list_attestations_for")`), so consumers can test the `unreadable_roots` arm of `resolve_mesh_config`. It is generated from the trait by `scripts/gen_directory_double.py`.
- `tier_ingest::test_support` is public behind `test-anchor`, so downstream fixtures can register the keys their signed `AdmitSpec`s verify against (`register_hybrid_key`, `sign_envelope`, `seal_row_in_place`, `seal_revocation`, `stamp_mirror`). These helpers are for fixtures only, never production signing.

## [31.3.0] - 2026-08-14

- A source-level parity gate (`store::parity`) requires every backend door to run the same gates in the same order on memory, sqlite and postgres; allowed differences are declared in `DECLARED_DIVERGENCES`.
- Gate order now matches across backends for `attestation_upsert_local`, `attestation_insert_local`, `put_public_key`, `put_family_membership_revocation` and `reseal_attestation_v31`, so a row that violates several gates gets the same typed refusal on every backend.
- Internal: build checks for each feature axis without a backend and with each backend alone; corrected migration citations.

## [31.2.0] - 2026-08-14

- **Breaking, security:** `authorization_digest` covers each holder's and serve node's whole `KeyRecord` (excluding `persist_row_hash` and `pqc_completed_at`), not just its `key_id`. Fields added to `KeyRecord` later are bound by default. This invalidates existing genesis authorizations; the genesis seed is re-minted.
- **Breaking:** `authorization_digest` returns `SHA-256` of the canonical preimage (32 bytes, signable on hardware tokens) instead of the preimage itself.
- **Breaking:** the scrub set (`scrub_key_id`, scrub signatures, `scrub_timestamp`, `additional_scrubs`) is excluded from the digest, so holders' co-scrubs no longer invalidate earlier authorizations and a 2-of-3 ceremony can complete.
- The re-minted genesis seed is baked into `canonical_seed.json`; `accord_holder_seed.json` is unchanged.

## [31.1.0] - 2026-08-13

### Added

- **Security:** revocations and role withdrawals can be rebuilt on a node that lost them. `list_signed_revocations_since` serves revocations (cursor on the new `admitted_at`, V123; read type `ServedRevocation`), and they join `signed_wire_index` and `wire_refs_for_subject`. Role withdrawals are not replicated as verdicts: `list_signed_accord_quorum_evidence_since` serves the signed accord evidence, `apply_replicated_accord_evidence` re-tallies it against the receiver's own roster (failing with `Error::AccordEvidenceUnverified`), and each node re-derives its own withdrawals (`rematerialize_role_withdrawals`). V124 adds the `accord_proposal(payload_sha256)` index. Existing revocations are indexed automatically at boot.
- `EnvelopeKind::AccordQuorumEvidence` is appended as the 15th kind and is served by cursor only.
- `revocations_for` and evidence admission are routed through the FFI directory capsule.
- A conformance test fails the build when persist's subject binding diverges from CIRISVerify's.
- `Error::is_duplicate_key` recognises duplicate-key errors on every backend.

### Fixed

- V125 relaxes `federation_revocations.revocation_id` (and its quorum-state child) from `UUID` to text on postgres, matching the other backends, and fixes the postgres revocation cursor at timestamp ties.
- **Security:** the genesis delegation leg checks directly, with `family_quorum_over`, that the stored charter's verified holder co-signatures still reach the threshold, so a row with stripped co-signatures no longer reads `Entrenched`.
- **Security:** the compiled-in genesis bundle is a floor. A reserved genesis delegation row can be replaced only by a strictly newer row signed by this node's seated accord holders, from either the boot seed or `bake_assembled_genesis`, through a compare-and-delete. A newer re-ceremony is `Entrenched`; rollbacks, forged holder claims and corrupted signatures still refuse to serve. Equal-`asserted_at` cases are distinguished: identical signed content with damaged unsigned columns is `Repaired`; differing content is ambiguous, never `Entrenched`.
- Upgraded nodes holding a prior ceremony's verified delegation rows replace them at boot through `purge_genesis_delegation_row_v31`, gated by `check_genesis_rebake_purge_admission`. A lost insert race no longer leaves the plane half-seeded.
- **Security:** rows claiming a genesis id are charged as `WriteAdmissionClass::GenesisClaim` against the node budget, never the reserved quota. `check_genesis_attestation_reserved` runs before the quota. The node's own boot seed no longer counts as peer traffic.

### Adoption

- **Breaking:** re-pin `REPLICATION_POLICY_HASH` = `3af30bccf437679ecccba325e2db055824b4721eeac069fc30a38d7a0723bbef` and `CONSENT_GRAMMAR_HASH` = `b66870da9639c8560538a26c566168fea9759139eaa67ad4116ff8a5f290d69f`, and add `AccordQuorumEvidence` at the same position in any mirrored `EnvelopeKind` enum. No data migration or ceremony is needed.

## [31.0.0] - 2026-08-12

This release requires a fresh genesis: the signed envelope now carries every field that decides an outcome, and rows signed under v30 are refused. The previous baked seed does not load.

### Adoption

- **Breaking:** producers must re-mint attestations, organizations, org memberships, partner records, key registrations and revocations under the new preimages. Rows signed under v30 must be re-published by their producer. Envelopes that passed through a postgres JSONB column have already lost their original numeric literals, and only re-publishing recovers them.
- **Breaking:** requires CIRISVerify 13.1.0 (all Cargo pins together).
- **Breaking:** test-anchor harnesses must build `CIRIS_TEST_TRUST_ROOT_SCRUB[_PQC]` preimages with `federation::genesis::test_anchor_registration_envelope(key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64)`; the old `{"key_id", "test_anchor"}` literal no longer roots.
- **Breaking:** `add_family_member`, `add_community_member`, `add_member` and `swap_member` take a `cohort::AdmitSpec` (`authority_key_id`, `scrub_signature_classical`, `scrub_signature_pqc`) over the grown record. In Python, pass `admit_spec_json` to `cohort_add_member`, `cohort_swap_member` and `add_community_member`. The family re-key cascade no longer grows the roster; the caller does, and the cascade refuses newcomers the active roster does not name.
- **Breaking:** transit subject-side revocations must state their own `attestation_id` and bind their row mirror.
- **Breaking:** re-pin `ENVELOPE_VOCABULARY_SHA256` = `1213fd3cf3109df92805cb1f6b0e39ae7637812b4fba23206a7860ba381107b2` (adds `row`, `asserted_at`, `expires_at`, `delivery_mode`, `deletion_window` and the `row_members` list).
- **Breaking:** `check_consent_state_instant_binding` is renamed `check_instant_binding`. `Engine::emit_attestation`, `emit_attestation_self`, `assemble_attestation_self` and `attestation_emit::emit_with_local_signer` take their input by value and stamp the signed instants into it.
- **Breaking:** `promote_attestation` and `set_attestation_cohort_scope` take an `AttestationReseal`; `promote_attestation_transformed` is removed (use `promote_attestation` with a restricted base).
- **Breaking:** `Engine::with_signer_pre_genesis` replaces the `test-genesis-seam` feature, which is removed.
- **Breaking (test-anchor):** `operational::test_support::signed_canonical_record` and `signed_canonical_record_with_roles` take `pubkey_ed25519_base64, pubkey_ml_dsa_65_base64` after `identity_type`. Pass `PLACEHOLDER_SUBJECT_ED25519_BASE64, None` to keep the previous columns, and pass real keys through the helper instead of overwriting them afterwards.
- `persist_row_hash` changes value for rows with sub-microsecond timestamps.

### Security

- The subject binding covers `identity_type` as well as `key_id` and both public keys, matching CIRISVerify 13.1.0, so a relay cannot relabel a record's standing. An envelope that omits `pubkey_ml_dsa_65_base64` is accepted only when the row claims no PQC key (CEG §0.9). Provenance links and transport bindings (`attesting_key_id`) are bound through the shared `bind_subject_into_envelope`.
- `verify_key_registration` checks the subject binding first, on both the authority-signed and self-signed branches: a registration signature can no longer be lifted onto a different `key_id` or different public keys. The binding is required. `Engine::register_self_federation_key` binds its own subject.
- Accord co-scrubs bind their subject, so one co-scrub can no longer confer `canonical` on a different key.
- `revocation_envelope` must bind `revocation_id`, `revoked_key_id`, `revoking_key_id`, `reason` (null if unset), `revoked_at`, `effective_at` and `scrub_timestamp` (`REVOCATION_BINDING_MEMBERS`); otherwise the revocation is refused with `federation_revocation_envelope_unbound`. Producers use `bind_revocation_into_envelope`. The instants must be at microsecond resolution.
- `check_revocation_scrub_skew` refuses a revocation `scrub_timestamp` more than `DEFAULT_MAX_TOUCH_SKEW` in the future, so a key cannot make itself immune to later revocation. `RevocationBoundRefusal` gains `bound_sub_microsecond`.
- `SignedPartnerRecord.threshold` is signature-bound and must form a strict majority (`QuorumPolicy::validate`).
- The baked genesis delegation ids are reserved (`Error::GenesisAttestationReserved`): a row using one must be federation-tier and attested by a seated accord holder, at both the local and federation write doors.
- `attach_key_pqc_signature` verifies the attached ML-DSA-65 public key against the signed registration (`admission::check_key_pqc_attachment`); a row that bound a null PQC key may not attach one.
- `put_stream_sth` verifies every witness co-signature (`blobs::verify_stream_sth_witnesses`) and refuses the whole put on any failure. The audit `merkle_store` refuses non-empty witness sets.
- Doors that skipped gates their siblings run now run them: transit rows' typed columns are checked against the mirror, and promotion refuses to re-stamp a mismatched mirror. `reseal_attestation_v31` verifies the seal and keeps instants fixed (`check_reseal_seal_admission`). `put_blob` bounds `asserted_at` and cross-checks the caller's hash (`check_put_blob_admission`). Postgres `supersede_canonical_record` and `adopt_scrub_upgrade` run the role and hardware gates. `add_peer_record` runs the role-conferral gates and refuses `accord_holder` (`check_peer_record_admission`).
- `retracted_edge_ids` honours a `withdraws` or `recants` only from the target's attester, one of its subjects, or an authority the write door resolved.
- Memory runs the revocation `observed_region` and anti-rollback gates, in the same order as the SQL backends (`check_revocation_anti_rollback`), and all backends validate `original_content_hash` as hex (`check_content_hash_hex`).

### Fixed

- Genesis shape checks call `migration::classify_shape(row, row.asserted_at)`, so a lagging clock can no longer demote an entrenched root to `pre_genesis`.
- `put_blob` names `cohort_scope` explicitly instead of relying on a schema default.
- Attaching an attestation's PQC signature re-indexes `signed_wire_index`.
- `Engine::reseal_for_scope` stores the canonicalized envelope, so promoted and re-scoped rows hash to their `original_content_hash`.
- An envelope is sized after the row mirror and instants are stamped, so a row just under the size cap is no longer admitted locally and then refused by peers.
- **Security:** each organization, org-membership and partner-record envelope is installable at only one `attestation_id`, because the id is signature-bound.
- **Security:** `supersede_family`, `supersede_community` and `supersede_affiliations` verify authorship and store the caller's signature with the new roster.
- **Security:** `check_peer_deadmission` exempts only this node's own rows, so a de-admitted peer can no longer author de-admission rows about others.
- `signed_wire_index` entries for every kind are computed from the row as stored (`wire_index::entry_as_stored`), so a node never advertises a ref it cannot serve after postgres microsecond rounding or `consent_role` normalization. `LocationProof` locators use microsecond instants (`wire_index::locator_instant`). `compute_persist_row_hash` truncates instants to microseconds, so a row hashes the same on every backend.
- V122 (postgres) changes eleven signed-envelope columns from `JSONB` to `TEXT`. Number tokens already lost to JSONB cannot be recovered.

### Changed

- Every `put_attestation`, `put_public_key` and `put_revocation` stores the JCS-canonical envelope (`federation::canonical_at_rest::canonicalize_in_place`), so the stored column's SHA-256 equals `original_content_hash`. JCS converts numbers through IEEE-754 doubles, so integers above 2^53 must be sent as strings. Envelopes whose key order differs between UTF-8 and UTF-16 sorting are refused.
- Attestations carry a signed `envelope.row` mirror of `attestation_id`, `attesting_key_id`, `attestation_type`, `attested_key_id`, `subject_key_ids` (order-sensitive), `cohort_scope` and `weight` (compared numerically). `check_row_column_binding` refuses a row that is missing the mirror or does not match it, at every door including promotion. `attestation_id` is minted before signing.
- Every attestation's signed envelope must carry `asserted_at` equal to the column, and `expires_at` must agree in both directions (`check_instant_binding`), on all dimensions. Instants are bounded by `DEFAULT_MAX_TOUCH_SKEW` and must be at microsecond resolution. The consent fold breaks ties in favour of the restriction (`consent::fold_ordering_key`).
- Promotion and re-scoping re-sign the row with a re-stamped mirror (`RowMirror::restamp_for_scope`), so promoted rows are accepted by peers. The local write door stamps the mirror and instants (`envelope::stamp_signed_instants`); transit rows are checked, never stamped.
- `put_blob` builds the `holds_bytes` row with `holds_bytes_attestation_row`, binds `asserted_at` and writes `tier` explicitly.
- Organizations and org memberships verify their own hybrid signatures (`verify_organization_admission`, `verify_org_membership_admission`). `check_organization_binding`, `check_org_membership_binding` and `check_partner_record_binding` bind every decision-bearing column, including partner `revision`, and refuse with `Error::OperationalEnvelopeUnbound` (`federation_operational_envelope_unbound`).
- `transform::PROTECTED_ROOT_MEMBERS` gains `row`, `asserted_at`, `expires_at`, `deletion_window` and `delivery_mode`.

### Added

- `Engine::with_signer_pre_genesis` boots a node with no trust root, and `Engine::with_signer` no longer fails on an absent seed. `GenesisFault` distinguishes `Absent` and `Unreadable` (boot; root-requiring gates refuse with `Error::NoConstitutionalRootYet`, listed in `genesis::ROOT_REQUIRING_GATES`) from `Divergent` (refuses to boot). `Engine::genesis_posture()` / `NodeState::genesis` report `GenesisPosture` with a `banner()` and include the delegation plane (`GenesisLeg::Delegation`).
- `Error::ConstitutionalFamilyReserved`: the `humanity-accord` family id can be created only by the genesis seeder and the assemble ceremony. `check_family_charter_admission` no longer skips an absent family, and `mesh_config::root_quorum_reached` no longer falls back to a string comparison.
- Boot-time v31 corpus migration (`federation::migration`, run from `Engine::with_signer`): it re-stamps the final folded state, purges retracted rows, keeps tombstones and every exclusion-bearing class (`ExclusionClass`), never re-stamps co-scrubbed rows, and is idempotent and bounded per run. New `FederationDirectory` methods: `list_attestations_for_migration`, `reseal_attestation_v31` and `purge_attestation_v31` (which refuses exclusion-bearing rows). `load_bearing::load_bearing_closure` reports `ClosureCompleteness`.
- `delegation_scope::INFRA_CLASSIFY_CONTENT` (`infra:classify_content`) and `FederationDirectory::resolve_content_class_flag`: anyone may raise a `content_class:*` flag or retract their own, but only a holder of `infra:classify_content` conferred by a root this node trusts may clear someone else's. Refused attempts are listed in `refused_withdrawals`; dimensions match exactly.

## [30.12.0] - 2026-08-12

- `is_subject_retainable(dimension)` answers whether the data subject of a row carrying a dimension may keep a copy on its own node. It is an allowlist: `true` only where the subject is necessarily the author; unclassified, renamed or unknown families read `false`. A build-time test fails when the dimension manifest gains a self-emission family the list does not name.
- `wire_index::wire_refs_for_subject` returns every `(kind_token, content_hash, record_key)` the signed-wire index holds for a subject, hashed exactly as the index write hooks hash it, on all three backends. The kind token is the `EnvelopeKind` name (e.g. `"Key"`), the one `lookup_signed_record_by_content_hash` takes.
- `register_hybrid_key` truncates its timestamp to microseconds so the Key-plane hash matches on Postgres.
- Internal: the bench workflow builds one feature set once and no longer runs on pull requests.

## [30.11.0] - 2026-08-11

- `admission::DELEGATED_DUTY_SCOPES` is the canonical array of conferrable duty scopes; import it rather than hand-picking `DELEGATION_SCOPE_*` constants. `delegation_scope::MODERATION` is that same array and now has five rungs, including `takedown` and `consent_revocation`.
- `delegation_scope::ALL` now includes `consent_revocation` and `owner_binding_recovery`, with new aliases `SCOPE_CONSENT_REVOCATION` and `SCOPE_OWNER_BINDING_RECOVERY`.
- New `delegation_scope::RECOVERY` axis holds `owner_binding_recovery` (CC 3.2 succession standing), which is not a moderation action.
- The scope-classification gate scans the whole crate and classifies by value against `ALL`, so a scope minted in any module must be listed.

## [30.10.0] - 2026-08-10

- Federation-scope moderation has a duty-holder resolver: `duty_holders_for_federation` resolves from the live accord roster via `active_family_members`, so de-admitting a federation directory key is now expressible. A holder removed from the accord stops being a duty-holder immediately.
- Accord holders are not filtered by steward binding; `accord_holder` is hardware-attested at registration, which is stronger.
- An unresolvable accord roster is a typed refusal, never an empty holder set.
- The resolver is selected by scope: a community-less `quarantine:*` (`slash`) act is federation scope; `moderation:*` and `reconsideration:*` without a community stay refused as `DelegatedScopeUnauthorized`.

## [30.9.0] - 2026-08-10

- `AttestationFilter` key predicates are set-valued: new `attesting_key_ids` / `attested_key_ids`, OR-combined and pushed into the query (`IN (…)` / `= ANY(…)`). One moderation preview/commit can address a set of keys under one hash. The singular fields remain and are unioned with the sets; an empty predicate matches everything.
- Internal: CI builds cross-platform wheels on tags only and partitions the slowest test legs across runners.

## [30.8.0] - 2026-08-09

- Conferring a capability on a person is not becoming their steward. The user-target steward-binding gate and `steward_bindings_of` both key only on `delegation_purpose: "owner_binding"` (CC 2.4.1.2), so a quorum can confer a moderation duty on a named adult. An undeclared `delegates_to` to a person is a conferral and establishes no stewardship; `Engine::steward_bind_incapacity` declares custody.
- A duty scope that needs an age or assurance floor declares it on its own CC 4.5.5 row via the CC 3.4.11 ladders; today none does.
- New `sub_delegation_depth` on a `delegates_to` envelope bounds how many further hops the recipient's chain may run (with `sub_delegation: true`). The budget attenuates down the chain. Absent depth keeps the old meaning.
- **Breaking:** `put_revocation` of someone else's key requires `slash` conferred by a root this node trusts; self-revocation is unchanged. Hosts revoking third-party keys must hold that conferral.
- A trust root's charter scope does not bound what it may confer beyond the `[infra:serve, infra:attest]` minimum; an existing accord can confer `slash` without a new genesis ceremony.

## [30.7.0] - 2026-08-09

- The wire vocabularies enumerate, so pickers can read them: `delegation_scope::ALL`, `identity_type::ALL`, `attestation_type::ALL`, `cohort_scope::ALL`, and new `transmission_principle` and `consent_state` modules.
- `delegation_scope` also exports axis subsets `INFRA`, `AGENCY` and `MODERATION`, which partition `ALL` (a `node`-only key may carry `infra:*` and never `agency:*`, CC 4.4.3.4.3). `NON_MEMBERS` lists excluded constants such as `INFRA_PREFIX` with a reason.
- `consent_state::ALL` omits `Unspecified`. The consent grammar hash is unchanged.

## [30.6.0] - 2026-08-09

- Postgres nodes can store the production genesis bundle's symbolic attestation ids (`genesis-charter`, `genesis-grant:…`, `genesis-lifecycle`); genesis previously failed on every Postgres node.
- Migration `V121` relaxes `federation_attestations.attestation_id`, `attestation_subjects.attestation_id` and `identity_canonical_binding.binding_attestation_id` from `UUID` to `TEXT`, keeping FKs and existing values. SQLite already used `TEXT`.
- The Postgres store binds attestation ids as text; `get_attestation` with a non-UUID id no longer returns `None` on Postgres.
- `cirisnode.promotion_attestations` keeps its UUID ids.

## [30.5.0] - 2026-08-08

- There are no classical-only paths: a node identity missing its ML-DSA-65 half (`ml_dsa_65.seed`) is an error naming the path, and there is no opt-in for a classical-only node.
- `create_identity_if_missing=True` mints both halves (32 OS-CSPRNG bytes, mode `0600`) and refuses if it cannot restrict permissions.
- `local_sign` on a hardware-sealed key returns a permanent refusal pointing at `local_sign_hybrid`; new `LocalSigner::is_hardware_backed`.
- `getrandom` is a direct dependency.

## [30.4.1] - 2026-08-07

- Fixed the `pyo3-sqlite` build (`_pyffi` without `pyo3`), broken in 30.4.0 by a misplaced `cfg` on the keystore binding; this is the mobile PyO3 shape.
- CI gains a `cargo check` leg for that feature subset.

## [30.4.0] - 2026-08-07

- Python `Engine(...)` takes `identity_dir` + `keystore_alias` to use this node's own keystore-sealed identity, with no key material crossing the boundary. It opens an existing identity and never mints one unless `create_identity_if_missing=True`. Passing both these and the `local_*` kwargs is refused.
- PyPI publishing removed; consumers build from the git tag. CI still builds the abi3 wheels as artifacts.

## [30.3.1] - 2026-08-06

- Fixed the no-feature build failing on an unused `key_id` in `set_backend_node_key_id` under `-D warnings`.
- Internal: the certification script derives `RUSTFLAGS` from CI.

## [30.3.0] - 2026-08-06

- A `hard_case:` attestation about another party requires a live `trust:confers:v1` grant of the new `infra:record_hard_case` scope from a root this node trusts; a self-attested `hard_case:` row still needs no conferral. A self-asserted `substrate_persist` identity no longer suffices.
- `lookup_trusted_publisher_chain` returns only publishers holding a live `infra:publish_rating` conferral, resolved per read. A node without an identity set returns the typed refusal `NodeIdentityUnset` instead of an empty chain.
- README rewritten; it no longer hard-codes versions.

## [30.2.0] - 2026-08-06

- A self-asserted `witness` or `lenscore_detector` identity type no longer admits reserved-prefix rows (`age_assurance:`, `capacity_assurance:`, `transparency_log:cosigned:`, `detection:*`). `ReservedPrefixRule` gains `required_delegation_scope`; the door also requires a live conferral of `infra:attest_assurance` or `infra:detect` from a root this node trusts. `witness` is now `DelegatedFromTrustRoot` (CC 3.4.11).
- New `set_node_key_id()` on all backends, injected by `Engine` at construction; gated doors refuse when no node identity is present.
- Postgres tests each get an isolated database cloned from a migrated template, so the suite no longer needs `--test-threads=1`.

## [30.1.0] - 2026-08-05

- Fixed `set_attestation_cohort_scope` not updating the signed-wire index on all three backends, which left a re-scoped row advertised but unservable to peers.

## [30.0.1] - 2026-08-05

- No public API change. A build gate refuses any claim whose conferral mode defers enforcement to use from backing an identity-type membership test.
- Internal: test-suite serialization, certification legs derived from the CI matrix, and `cargo-mutants` configuration.

## [30.0.0] - 2026-08-05

### Changed

- **Breaking:** `redundancy.*` mesh-config keys split into four typed keys: `redundancy.k_repair_symbols`, `redundancy.min_viable_symbols` (`Symbols`) and `redundancy.target_holders`, `redundancy.min_viable_holders` (`Holders`). `MeshConfigUnit::Count` no longer covers symbols. The old `k_repair_target` default and the unsatisfiable `min_viable_floor` ceiling are gone.
- **Breaking:** a declared `delegation_id` must name the conferral that authorised the author. `root_authorizes_author` returns `AuthorAuthority::{Inherent, Conferred(ids), None}`; a mismatched id is refused `delegation_id_not_conferring`.
- `resolve_mesh_config` reports roots it could not read in `MeshConfigFold::unreadable_roots` instead of treating them as silent.

### Added

- `Engine::assemble_attestation_self` (`attestation_emit::assemble`) builds a signed attestation without storing it, under the same admission gates as the put path.
- `delegation_scope_set` is public.

### Fixed

- `list_attestations` honours `window`, `tier` and `attester_filter` on both SQL backends; `tier: None` keeps each handle's existing meaning.

## [29.0.0] - 2026-08-04

- **Breaking:** requires ciris-verify 13.0.0; the wheel's `Requires-Dist` is `ciris-verify>=13.0.0,<14`.
- **Breaking:** `ClassificationStanding` gains `Structural { breaks }`, mirroring verify's `Gating::Structural`: a constraint that cannot vary because the machine breaks, bound without a ratifying authority. `Purpose` is classified `Structural`.
- `ffi_taxonomy.tsv` gains a `frame` column from a closed vocabulary (`self_audit`, `log_commitment`, `delivery_event`, `equivocation_evidence`, `erasure_effect`, `upstream_attestation`). A `testimonial` row must declare a frame; the `list_signed_*_since` readers and `verify_trace` are reclassified `epistemic`.
- A durable `mesh_config` row is earned by quorum, not by ratifying a prior emergency, so a fresh mesh can hold durable settings (CC 4.2.1).

## [28.3.0] - 2026-08-04

- The `mesh_config` plane: knobs authored by the trust root on the CC 3.2 delegation plane (CC 4.2.1), never by the accord's ceremony plane. Each key declares which direction means more flow; the fold clamps so a root can only relieve within its ceiling, and the most restrictive root wins across roots.
- `regime:{artifact}:{version}` is a registered family, so the `namespace_family_unregistered` refusal no longer applies to it. Persist enforces no emitter rule on it.
- Removed the `content_rating:` → `trusted_publisher` and `content_class:` / `cw_class:` → `substrate_persist` emitter gates; CC 3.3.12 declares those families open vocabulary, and `content_class:` markings from `agent` identities are admitted (CC 3.4.14). `age_assurance:` stays reserved. The trusted-publisher chain still discriminates at read time.
- `vendored_private_use_prefix()` reads `_meta.private_use_prefix` from the vendored manifest and a gate checks it against `PRIVATE_USE_FAMILY_STEM`.
- The `PeerQuotaRefusal` reason now survives the Python boundary.
- Internal: test database tooling, pre-commit hook fixes and a doc-comment version gate.

## [28.2.0] - 2026-08-03

### Changed

- The consent-revocation proxy walk honours retractions: a `delegates_to` withdrawn by its granter no longer confers proxy authority under CEG 2.4.1.1 rule (3). `skip_withdrawn_edges` is removed; every walk applies the withdrawal gates.

### Adoption

- A proxy whose `consent_revocation` delegation was retracted now refuses. The subject cannot appoint a replacement; the granter must. Retracting one delegation to a recipient retracts every edge to that recipient across scopes. The refusal arrives as `WithdrawsNotAdmitted`.

### Added

- Python node-state bindings: `trust_root_verdict_json`, `resolve_key_statement_standing_json`, `resolve_quarantine_json`, `resolve_reverse_quorum_json`, `peer_quota_observation_json`, and `node_state_json`, a gauge folding all node-scoped signals into `green`/`yellow`/`red`/`unknown` bands with their typed tokens, `unknown[]`, `clock_dependent[]`, `targeted[]` and `as_of`.
- `list_consent_revocation_promotion_overdue_readonly_json` reads overdue consent promotions without writing `hard_case` rows.
- `peer_quota_observation` (defaulted `None` on `FederationDirectory`) reports `slot_denials` with `tracked_peers` and `process_local: true`.
- No migration.

### Fixed

- The crate builds again with no backend feature.

## [28.1.0] - 2026-08-03

- `ObjectClass` (closed, with `ALL`) and `object_class_policy` declare how every object class is reference-counted; `is_load_bearing` covers `transport_destination`, `fountain_content` and `hard_case_event`. Composite-keyed classes take `object_id2` and refuse a missing second key. `ObjectRef::from_parts` is the single parse path.
- New `Engine::may_release_copy` / `may_release_copy_json`: `is_load_bearing == No` and `anti_entropy_satisfied`, both reported. Persist cannot observe peer residence, so it always refuses release today; it releases nothing.
- `is_load_bearing_json` is three-valued; `"unknown"` is not `"no"`.

## [28.0.0] - 2026-08-03

### Changed

- Erasability is decided at mint: an erasable object carries salted disclosures beside the envelope, bound by digests inside it, so erasure drops a disclosure and alters nothing signed; the row still verifies and replicates. Everything minted before this is sealed and cannot be erased.
- **Behaviour change:** a `delegates_to` retracted by its subject, a canonical-bound claimant or a consent-revocation proxy (CEG §3.2.3 rules 2–4) no longer confers `moderate` / `takedown` / `review`. `reachable_under_scope`, `reachable_under_scope_with_reasons` (`RetractedAtRoot` / `SignerUnreached`), `is_named_moderator`, `moderators_of`, `appointed_moderators_of` and `check_moderation_admission` all read one shared walk (`scoped_delegation_reach`, with `retracted_edge_ids`). Read-time only; no migration.

### Added

- The Python type stub covers all 509 exported symbols, each classified in `scripts/ffi_taxonomy.tsv` (including a new `testimonial` class), checked by `scripts/pyi_surface.py`.
- `ReconsiderDosGuard`, `ScoringFactorStream`, `persist_field_conformance`, `namespace_manifest_version` and `transform_algebra_hash` are exported from the `ciris_persist` package.
- `MemoryBackend::attestation_read_counts` / `reset_attestation_read_counts`.

### Fixed

- The `Engine.__init__` stub matches the real constructor.
- The `*_json` adjudicators return a JSON string on both arms, so a refusal is truthy in Python; their stubs now say so, e.g. `is_named_moderator_json`, `resolve_transit_eligibility_json`, `service_token_revocation_check` (non-`None` means revoked).

## [27.0.0] - 2026-08-03

### Changed

- Requires ciris-verify 12.5.0.
- **Breaking:** `admission::MINTED_FAMILY_RULES_NOT_ON_THE_ROW` is removed; use `family_rules::RULES_NOT_ON_THE_ROW`, a superset listing every family persist rules on that the namespace registry does not. `family_rules::persist_ruled_prefixes()` derives that set from source; `admission::HARD_CODED_RESERVED_STEMS`, `admission::ATTESTATION_LADDER_DEPRECATED_PREFIX`, `invariant::NEWLY_ENFORCED_SELF_EMISSION_PREFIXES` and `registry::ACCORD_CO_SCRUB_MATCH_PREFIX` are public.
- **Behaviour change:** promoting or re-scoping a row into `family` / `community` requires that it names no party but its own producer; otherwise `Error::CohortStandingRefused` (`federation_cohort_standing_refused`, `CohortStandingRefusal::{attested_party, named_subject}`). Applies to `check_promotion_admission` (all promote paths) and `set_attestation_cohort_scope`. Broad-tier promotions are unaffected.
- **Behaviour change:** a subject-revoked `delegates_to` no longer confers stewardship. `is_steward_bound`, `steward_bindings_of`, `steward_binding_chain` and the ownership projection share `live_delegation_granters`. A commons whose moderator came only from such an edge loses it, and its federation rows are refused `federation_community_no_moderator` until a new steward binding is issued.
- Private Use range families (`x_private:*`) never admit at federation tier (CC 3.1.7). `regime:*` stays open vocabulary.
- Axis classification is per `(field, op)`, with `op` the row's `attestation_type` (CC 4.5.1.1). `references_attestation_id` confers no subject authority.

### Fixed

- `trace_manifest:v1.content_hash` must be `"sha256:"` plus 64 lowercase hex characters (CC 3.1.5).
- Absence claims in the vendored `namespace_supersets.json` are checked against declared falsifiers.

## [26.0.0] - 2026-08-03

### Changed

- Requires ciris-verify 12.1.0.
- **Breaking:** `FederationDirectory::promote_attestation` and `promote_attestation_transformed` take `cohort_scope`, written atomically with the tier flip; drop any preceding `set_attestation_cohort_scope` call. `(federation, self)` is refused by the primitive.
- A promotion re-runs the tier-4 authority stack (`check_promotion_admission`): CC 3.4.5 consent, no-moderator-federate, peer de-admission, the moderation/review/quarantine duty gate, reserved-prefix, node-agency and user-target steward checks. A row can no longer reach federation tier by entering at the local tier.
- **Breaking:** `put_attestation` refuses a `tier = "local"` row carrying a `capacity:*` dimension or attestation type (`check_capacity_never_local`).
- The namespace registry is re-vendored to CC 1.0-rc3 (109 families). A governed family with no registry row is refused `namespace_family_unregistered` (`Error::NamespaceFamilyUnregistered`, CC 3.1.7 R2). `ownership_reclaim::NAMESPACE_FAMILY` is spelled `wa_adjudication:{state}`; the wire stem is unchanged.
- **Breaking:** `resolve_reverse_quorum` takes `&dyn FederationDirectory`.

### Added

- Reverse-quorum steward tier: a policy may declare `reverse_quorum:{m}/{n}:{window}+escalate:{steward_secs}:{floor}`. If appointed moderators do not rule within `steward_secs`, an objection escalates to a quorum of respondents, floored at 3. New `StewardTierStanding`, `EscalationOutcome`, `fold_reverse_quorum_over`, `escalated_dismissal_required`, `ballot_envelope`, `record_objection_ballot`, `DIMENSION_UPHELD` / `DIMENSION_OVERRULED`, and refusal reasons `steward_tier_not_adopted`, `actor_recused`, `ballot_predates_action`.
- `admission::appointed_moderators_of` returns the appointed duty-holder set.
- Migration `V120` (Postgres) widens the reverse-quorum policy check; SQLite needs no change.
- `ClassificationStanding`, `classification_standing` and `standing_of::<C>()` say whether a verify classification may gate a persist decision; only documents in `PERSIST_RATIFYING_AUTHORITIES` bind.
- The Python package ships a `py.typed` marker and re-exports `engine_teardown_wait` and `engine_teardowns_in_flight`; the `reset_engine` stub returns `str`.

### Fixed

- `Engine.verify_trace` releases the GIL while it looks up keys, so a stalled connection no longer wedges the interpreter.
- The `secrets-server` feature compiles. CI derives its feature legs from `Cargo.toml` and runs clippy with `--all-features`.

## [25.1.0] - 2026-08-02

### Adoption

- Requires ciris-verify 12.0.0; the wheel's `Requires-Dist` now admits the verify major the crate links. `KEY_GRANT_ALGORITHM_V2` is the snake_case `x25519_mlkem768_…` form (CC 5.1).
- **Breaking:** ownerless-node reclaim is authorised by a CC 4.3 Wise-Authority quorum, not the accord roster. `ReclaimPolicy::humanity_accord_default` and `ReclaimQuorum` are removed; `ReclaimPolicy` names a WA body via `CIRIS_PERSIST_WA_ADJUDICATION_FAMILY_KEY_ID` (unset means nothing is reclaimable). The gated `withdraws` must carry a `wa_adjudication_ref`.
- **Breaking:** `admission::capacity_claim_family` → `consent_gated_claim` (returns `ConsentGatedClaim`); `CAPACITY_CONSENT_SCOPE` → `ANALYZE_CONSENT_SCOPE`. Consent refusals are `Error::ConsentGateRefused` (`federation_consent_gate_refused`) instead of `federation_invalid_argument`.

### Added

- `maintenance::vocabulary`: `Engine::tighten_vocabulary` (Python `maintenance_tighten_vocabulary`) retires a non-conformant wire value by superseding each affected row with a re-signed replacement plus a `supersedes` composer, never updating in place. Idempotent, `dry_run`, and reported in `VocabularyTighteningReport`.
- `federation::attestation_emit` holds the backend-generic emit recipe used by `Engine::emit_attestation`.
- Reclaim is a four-step ceremony: petition, WA finding (on `wa_adjudication:{state}`), gated `withdraws` leaving the node unowned, then a fresh owner-binding co-signed by the node. A single act can never transfer incumbent to claimant. New `Error::OwnershipReclaimRefused` (`federation_ownership_reclaim_refused`) with `ReclaimRefusal`. The 90-day abandonment floor is enforced; a seizure finding skips the abandonment window.
- Migration `V117` admits `withdraws_admission_rule` 5 on both SQL backends.
- `hard_case:admin_action` records require `{delegation_id, reason}` in `detail` (`AdminActionRefusal`, `Error::AdminActionUnattributed`).
- `DELEGATION_SCOPE_SLASH` (`SCOPE_SLASH`): the removal duty, walked like the other duty scopes and required for quarantine rows.
- Quarantine markers (`quarantine:withheld:v1` / `quarantine:released:v1`): `fold_quarantine` (restriction wins a timestamp tie), `QuarantineState`, `QuarantineRefusalReason`. `Engine::serve_blob_to_peer` refuses with `BlobError::QuarantineWithheld` and `list_attestation_log` filters withheld rows; markers themselves always replicate.
- `Revocation::revoked_after` (migration `V118`) bounds a revocation in time; it must match a signed `revoked_after` in the revocation envelope (`RevocationBoundRefusal`, `Error::RevocationBoundInvalid`). `resolve_key_statement_standing` returns `Stands` / `SuspectAfterBound` / `SuspectUnbounded`.
- The peer write quota meters bytes as well as rows, with eight new `PeerQuotaRefusal` tokens (`peer_bytes_burst` … `reserved_bytes_sustained`); the tracked-peer table cap is 8192 and `PeerWriteQuota::slot_denials()` reports overflow.

### Changed

- Consent-before-scoring gates `capacity:*` only (CC 3.4.5); artifact-verification families and `rollback_detected:*` are not consent-gated.

## [25.0.0] - 2026-08-02

- **Breaking:** requires ciris-verify 11.0.0 (all pins move together); consumers can now adopt verify past 10.6.3.
- `LocaleLeaf::leaf_hash` is fallible under verify's JCS canonical bytes, and `locale_merkle_root_hex` fails if any leaf fails.
- No behaviour change otherwise.

## [24.3.0] - 2026-08-02

- Engine teardown never blocks while holding the GIL: the last runtime reference is dropped on a dedicated thread, and the runtime winds down before the backend is released. New Python `Engine.close_blocking(timeout_seconds, force)`, `reset_engine(timeout_seconds)`, `engine_teardown_wait(timeout_seconds)` and `engine_teardowns_in_flight()`, returning `drained` / `deferred` / `timed_out` / `no_engine`. Fixture recipe: `reset_engine(); del engine; gc.collect(); engine_teardown_wait()`.
- `PeerWriteQuota` has sustained and node-wide budgets that survive restart; `check_write` takes the row. `Error::RateLimited` carries `reason: PeerQuotaRefusal` (tokens such as `peer_burst`, `peer_sustained`, `untracked_tail_burst`, `node_burst`, `reserved_burst`), re-exported at `federation::`.
- New `reverse_quorum:{m}/{n}:{window_secs}` consensus form for commons actions (`federation::reverse_quorum`): an action stands unless `m` current members object within the window. Raising an objection takes one member; dismissing someone else's needs at least a strict majority; a member may retract their own. Objections are `scores` rows on `objection:raised:v1` / `objection:dismissed:v1`, folded at read time by `resolve_reverse_quorum` into `ReverseQuorumFold`; the objected-to row is never altered. Refusals are `ObjectionRefusalReason`. Forward-threshold readers treat the form as unanimity.
- Migration `V116` admits the new form in `federation_communities.consensus_protocol` on both backends.

## [24.2.0] - 2026-07-31

- **Breaking:** `ReplicatedKeyOutcome::Refused { reason: KeyRefusalReason }` names the branch that refused: `PubkeySwap`, `Downgrade`, `ConflictingVersion`, `ReScrub`, `AlreadyAnchoredIdentical`, `UnverifiableSignature`, `OwnerAbsent`, `OwnerAmbiguous`, `StoreConflict`. `as_str()` equals the serde token and the set is append-only. Over the directory capsule it is `{"refused":{"reason":"<token>"}}`.
- Re-offering the baked canonical seed now reports `AlreadyAnchoredIdentical` instead of a re-scrub.
- New `is_load_bearing` (`Engine::is_load_bearing`, Python `is_load_bearing_json`) returns `LoadBearing::{Yes { because }, No, Unknown { family, reason }}`; `Unknown` is treated as load-bearing. `consent:*` grants count retained peer rows, `trust:*` is always load-bearing, and other families are declared `undeclared` in the manifest axis. It releases nothing.

## [24.1.0] - 2026-07-30

- New `resolve_transit_eligibility` / `resolve_transit_eligibility_over_roster` (`Engine::resolve_transit_eligibility`, Python `resolve_transit_eligibility_json`, capsule op `ResolveTransitEligibility`) returns `TransitEligibility { eligible, valid_until, via_root }`. A peer is a usable relay hop if it is in the directory, is a `node`, offers `infra:transport`, and validly trusts a root the user also trusts, drawn only from the user's own `trust:accepts` edges. `valid_until` is the cache bound; every error resolves `eligible: false`.
- `TrustRootVerdict` gains `bounded_until` (additive).
- Ticket status `proposed` (migration `V115`) marks work not yet authorised; `TicketStatus::is_authorized()` is false only for it. Approval is an ordinary status transition.
- Postgres startup migrations run once per DSN per process, set a 120 s `lock_timeout` unless the session already has one, and wait on the advisory lock with a bounded budget and progress logs; timeout is `Error::MigrationLockTimeout`.
- Fixed: the signed-wire index is updated by `adopt_scrub_upgrade`, `supersede_canonical_record`, `adopt_genesis_reanchor`, `attach_key_pqc_signature` and `set_consent_role` (via `wire_index::key_entry`), so an advertised Key ref is always servable.
- Additive; no stored row, hash or signature changes.

## [24.0.0] - 2026-07-30

### Changed

- A trust root may be a threshold: when `trust_root_valid`'s `root_ref` names a keyless constitutional family, the edge, charter, drill and halt legs are evaluated against the family, and the charter must carry co-signatures reaching the family's `consensus_protocol` threshold, floored at a strict majority of this node's own roster and re-derived at read time. The family halt latch now reaches the root.
- A capability grant acts for a family when its own verified signer set meets the threshold (`ConferralPlane::FamilyQuorum`); there is no field naming the family to forge.
- `check_family_charter_admission` refuses a below-quorum family charter (`CharterInvalid`).
- Single-key roots remain valid and the baked genesis is unchanged.

### Added

- `Attestation.additional_scrubs` (migration `V113`, both SQL backends) carries co-signatures over the same preimage; `Attestation::scrubs()` / `distinct_scrub_count()`. Every co-signature is verified at federation-tier ingest; promotion clears unverified co-signatures. Empty is wire-absent, so existing rows are unchanged.
- `TrustRootVerdict` gains `root_kind: {Key, Family}` and `charter_quorum`.
- Migration `V114` lets `attested_key_id` name a keyless family; the subject rule moves to `check_attested_subject_admission` on all backends.

### Adoption

- **Breaking:** `trust_root_valid`'s third parameter is `root_ref`. Exhaustive matches and struct literals must handle the new `TrustRootVerdict` fields, `ConferralPlane::FamilyQuorum` and `Attestation.additional_scrubs`. Postgres refuses an attestation whose `attested_key_id` is neither a key nor a family.

## [23.1.0] - 2026-07-30

- The production trust root is baked: `canonical_seed.json` (sha256 `5c474b7993d0c148336da47fd7958baa0a0840521faaf0c2d534a2df9e766972`) carries the A1/B1/C1 accord holders with real custody evidence, the canonical serve node, the charter, serve grant and lifecycle rows, and the 2-of-3 authorizations.
- `AttestationEvidence::GenerationCustody` accepts custody attested at key generation (e.g. YubiKey PIV), in CIRISVerify's `accord_custody_attestation` shape. `HardwareAttestationPolicy::check` pins schema and kind, binds the holder key id, allowlists `accepted_custody_tiers` (default `{portable_2fa}`), requires `ExternalSecureElement`, and recomputes the certificate sha256 bindings. Refusals are typed.
- `verify_bundle_quorum` applies the same holder-evidence policy as `put_public_key`, via new `FederationDirectory::hardware_attestation_policy()`, so a bundle that verifies also installs.

## [23.0.0] - 2026-07-30

### Changed

- The genesis seed is a `GenesisBundle`, the same artifact a ceremony emits: `canonical_genesis_records()` → `canonical_genesis_bundle()`, and `parse_genesis_bundle()` is the only parse path. A legacy bare `[{record}]` seed is refused with `Error::GenesisBundleInvalid`.
- The three `delegates_to` jobs have dimensions: `trust:charter:v1` (`R → R`), `trust:confers:v1` (`R → subject, scope`) and `trust:accepts:v1` (`node → R`). A row labelled with another job's dimension is refused by the predicate reading it; unlabelled rows are inferred by direction as before. No migration.
- A trust root's drill is a signal, not a gate: `TrustRootVerdict.lifecycle_active` is replaced by `last_drill_at` and `drill_freshness: DrillFreshness` (`Green` < 90 days, `Yellow` < 180, `Red` otherwise or never). `valid` depends only on edge, charter, recovery and halt, so a stale-drilled root keeps serving.
- The conferral planes are named `ConferralPlane::{AccordCoScrub, Delegation}`.

### Adoption

- **Breaking renames, no aliases:** `has_effective_role` → `has_accord_conferred_role` (also the Python method), `has_effective_role_over_roster` → `has_accord_conferred_role_over_roster`, `has_delegated_capability_role` → `has_root_delegated_role`, `KeyRecord.roles` → `KeyRecord.capability_roles` (wire name stays `roles`), `ACCORD_LIFECYCLE_DIMENSION` → `ACCORD_HEARTBEAT_DIMENSION` (wire stays `accord:lifecycle:v1`), `ACCORD_LIFECYCLE_FRESHNESS_DAYS` → `DRILL_GREEN_MAX_DAYS` + `DRILL_YELLOW_MAX_DAYS`.
- Consumers deserializing `TrustRootVerdict` must adopt the drill fields. No stored row, signed envelope or row hash changes.

## [22.1.0] - 2026-07-30

- The capability walk reads the ceremony plane: a verified accord co-scrub conferring a scope makes the subject a root candidate, so the baked genesis canonical can serve traces. The candidate still needs this node's own trust edge and a valid charter, so withdrawing the one edge still revokes trust.
- New `capability_roots_to_trusted_root_over_roster`; `TrustedGrant.conferral_plane` (additive).

## [22.0.1] - 2026-07-30

- Fixed: `put_public_key` refused the test-anchor genesis synthesizer's own accord holders. `AttestationEvidence` is an enum, `Hardware(Box<HardwareCustodyEvidence>)` (unchanged wire shape) or `SoftwareOnlyTest(SoftwareOnlyTestMarker)`; the test marker admits only under a live test anchor and is otherwise refused with a typed reason.

## [22.0.0] - 2026-07-29

### Adoption

- **Breaking:** `ConfidenceBand::WellEstablished` requires a `witness_diversity:*` attestation, so fewer scores reach the top band.
- **Breaking:** `duty_holders_from_signed_subjects` is removed; duty-holder authority is re-derived from the directory.
- **Breaking:** new put-gates refuse self-attested `capacity:*` (on both wire shapes), self-asserted authority-conferring `identity_type`s, and writes from a de-admitted peer.
- **Breaking:** a federation-tier `capacity:*` claim about a subject is refused unless the subject's live `consent:scope:analyze` covers the attester; `emit_attestation` has no bypass.
- **Breaking:** `delivery_mode` is a closed vocabulary; unknown values are refused at write.
- **Breaking:** `tier` and `promoted_at` are persisted on both SQL backends, so local-tier rows read back as `local`.

### Added

- `AUTHORITY_CONFERRING_IDENTITY_TYPES` with a required `ConferralMode` per claim.
- `revocation:peer_admission:v1`: a signed, scoped, revocable de-admission that refuses a peer's writes. `Engine::set_self_key_id` / `self_key_id` (and Python bindings) enable it.
- `PeerWriteQuota` ahead of the put-gates, which now run cheapest-first with hybrid verification before database-walking authority checks.
- `run_deletion_window_watch` (`Engine::run_deletion_window_watch`, Python binding) emits `hard_case:deletion_window_breach` evidence when a deletion window expires without proof.
- `substrate_machine`: a model-based property test of op sequences across memory, SQLite and Postgres.

### Fixed

- The idempotent-replay dedup no longer skips hybrid verification and the write-scope gate.
- The memory backend enforces `attestation_id` uniqueness, the peer de-admission gate and SCORES envelope-schema validation, matching the SQL backends.
- The hybrid KEM check compares both halves as a pair.
- `adopt_scrub_upgrade` runs the hardware gate and `supersede_canonical_record` runs the role gates.

## [21.17.1] - 2026-07-29

- **Security:** unsigned local writers can no longer desynchronise a signed row from its own envelope. On a signed `transport_destination` an unsigned writer may advance only `last_seen_at`; a signed `identity_occurrence` is never mutated by `put_identity_occurrence_local`.
- **Security:** `verify_signed_identity_occurrence` compares both the X25519 and ML-KEM-768 halves of the content KEM key; it previously accepted a diverged post-quantum half.
- The memory backend refuses a duplicate identity-occurrence revocation, matching the SQL backends.

## [21.17.0] - 2026-07-28

- `establish_trust_root` (test support, `test-anchor`) returns `Err` unless the capability walk it promises actually succeeds; `establish_trust_root_side` checks its root-side postcondition. No wire or schema change.

## [21.16.0] - 2026-07-28

- `establish_trust_root` works for a real engine-backed user: it sets up the root side and only attempts the user→root edge for a synthetic user, never forging it. New `establish_trust_root_side` for callers that emit their own edge. Test support only.

## [21.15.0] - 2026-07-28

- New test-support helpers `establish_trust_root` and `grant_scope` (`test-anchor`) stand up a valid trust root with real signatures on any backend, so the full trace-serve gate can be tested in-process.
- `confer_roles` documents that `infra:serve` conferral requires FIPS custody and only verifies under the test anchor.

## [21.14.0] - 2026-07-28

- The accord-conferral test helpers work on SQLite and Postgres as well as memory: `register_accord_holder` self-scrubs for real, and new `test_support::confer_roles` confers roles through a genuine 2-of-3 accord co-scrub. Test support only.

## [21.13.0] - 2026-07-28

- A build gate refuses any wire field serving more than one CI axis without a classification. `ci_axes_for_field()` derives each field's axes from the vendored manifest; tracked fusions are pinned in `KNOWN_AXIS_FUSIONS`, and persist's own classifications live in `PERSIST_AUTHORED_AXIS_CLASSIFICATIONS`.
- `distinct_real_processors()` reports every processor of a field.

## [21.12.0] - 2026-07-27

- New `Engine::repair_stranded_scope_backlog` (and Python binding) re-scopes federation-tier rows stuck at `self`/`family` that a live consent grant covers, so they are offered again. It only broadens visibility, does not re-sign, and is idempotent. Page source `list_stranded_federation_attestations` on all backends; `ConsentSweepReport` gains `rescoped`.
- Hosts that see `stranded_covered_rows > 0` should run the repair once; `promote_consented_backlog` remains the motion for new rows.

## [21.11.0] - 2026-07-27

- **Breaking:** `EmitAttestationInput::with_envelope` takes `cohort_scope` as a required argument, and an empty `cohort_scope` is refused instead of defaulting to `federation`.
- `reconsideration:*` and `moderation:*` scores rows admit only from the community's named moderators (`duty_holders_for_community`), not from self-named subjects.
- For `capacity:*` and `detection:*`, a subject can no longer withdraw a score about itself; only the attester may.
- SQLite and Postgres compute the capacity factor rollup the same way (trace-weighted means and counts).

## [21.10.0] - 2026-07-27

- `SignerForm::NOfMCosigned` touch claims are a real m-of-n tally: co-signatures ride `freshness::TOUCH_COSIGNATURES_FIELD`, each hybrid-verified, distinct and independent of the target, with at least `NOFM_MIN_COSIGNERS` beyond the primary.
- `evidence/cc_impl.tsv` lists persist's code evidence pointers, checked against source by the build.

## [21.9.0] - 2026-07-27

- `delivery_mode` and `deletion_window` are typed `EnvelopeCore` fields (`paths::DELIVERY_MODE`, `paths::DELETION_WINDOW`); canonical bytes and existing signatures are unchanged.
- New `federation::deletion_window::deletion_window_status` judges a row's erasure deadline as `NoWindow`, `MalformedWindow`, `WithinWindow`, `DeletedInTime` or `BreachedNotDeleted`.

## [21.8.0] - 2026-07-27

- New `federation::ownership_reclaim`: a third-party `withdraws` against a live owner-binding is admitted only when the owner is provably abandoned (a freshness floor that existed and went stale) and a verified m-of-n reclaim quorum signs (CC 3.2). An absent floor is never abandonment.
- Default policy `ReclaimPolicy::humanity_accord_default`: the accord holder quorum with a 180-day window. Admitted reclaims are stamped `withdraws_admission_rule` 5.

## [21.7.0] - 2026-07-27

- `federation::invariant` reads the vendored invariant registry and enforces its persist-owned subset at reserved-prefix admission; `health:liveness:` self-emission is refused.
- **Breaking:** `Engine::promote_attestation_with_strips` → `promote_attestation_with_transforms`, applying the grant's full transform pipeline. Behaviour for strip-only grants and the consent grammar hash are unchanged.
- New Python functions `persist_field_conformance()`, `namespace_manifest_version()` and `transform_algebra_hash()` for conformance harnesses.

## [21.6.0] - 2026-07-27

- New `federation::transform`: a closed, strictly terminating transform algebra (`TransformOp`, exhaustive `apply`). Twelve live opcodes (`truncate`, `prefix`, `suffix`, `bucket`, `round`, `concat`, `redact`, `strip_field`, `salted_hash`, `gte`, `lt`, `in_range`); `commit`, `nullifier` and `bbs_derive` are declared and return `NotYetImplemented`. Pinned `TRANSFORM_ALGEBRA_HASH = b7bd779468f4ad1ab551a5fd2dc0392df01e6f2e0ed393f924a806ed49686b4b`.
- New `federation::freshness`: a signed `fresh_as_of` lower bound. `SignedTouchClaim` (`SignerForm { SelfTouch, WitnessTouch, NOfMCosigned }`), `put_touch_claim` / `lookup_freshness_floor` on all backends (migration `V112`); the floor only advances, and `verify_signed_touch_claim` refuses claims beyond `DEFAULT_MAX_TOUCH_SKEW`. Touch claims are cohort-scoped and consent-gated. `coalesce_touch_ts` buckets producer timestamps.
- `NOfMCosigned` verifies as a single witness touch in this release.

## [21.5.0] - 2026-07-26

- **Breaking:** `Engine::attestation_promote` and the Python `attestation_promote` take a required `cohort_scope`; promotion stamps the placement before flipping the tier and refuses `(federation, self)`. `promote_consented_backlog` passes the grant's audience atomically, and self-at-login delegations promote at `federation` scope.
- `namespace_supersets.json` (manifest v0.3.0) is vendored as Registry-of-Record under `federation::namespace::supersets`, pinned by version, constitution revision and seed-registry hash. A build gate refuses any placement field with no processor beyond `KNOWN_UNASSIGNED_FIELDS`.

## [21.4.0] - 2026-07-26

- A signed route wins the shared `(occurrence_key_id, transport_kind)` key on all backends: an unsigned write never demotes a signed route, a content-changing unsigned write over a signed row is a no-op, a signed write supersedes an unsigned row regardless of clock, and an unsigned put cannot resurrect a signed retirement.
- Requires ciris-verify 10.6.3.
- Test-support custody simulation: `verify_member_fips_custody_against` and `check_canonical_role_admission_over_roster_with_custody_root` (under `test-anchor`) accept an injected mock custody root; production keeps the pinned root.

## [21.3.0] - 2026-07-26

- Minting a new trust root requires at least `max(strict_majority, 3)` distinct co-scrubbers (`CANONICAL_MIN_COSCRUBBERS`), each with a verified FIPS 140-3 YubiKey custody attestation chaining to the pinned `YUBICO_ATTESTATION_ROOT_1_DER`; `verify_member_fips_custody` is public. The baked genesis canonical keeps its existing bar.
- Fixed: `OccurrenceTransportBinding::project_route` stores the route destination as lowercase hex, not base64, and an unsigned put with identical content preserves a signed route's signature.
- `root_binding`, `root_binding_anchored` and `provenance_chain` accept `&dyn FederationDirectory`.

## [21.2.0] - 2026-07-25

- Payloads follow the consent edge: `Engine::promote_consented_backlog()` (Python verb returning `{promoted, skipped}`) promotes local-tier attestations covered by a live self-authored `consent:replication:v1` grant. It runs after a self-authored grant is emitted and after every ingest batch. Third-party grants never trigger it.
- The closed consent grammar: `ConsentTransferPolicy` (`direction`, `kinds`, `attestation_prefixes`, `principle`, `audience`, `purpose`, `valid_until`, `restrictions`), validated at `put_attestation` and fail-closed on anything unknown. `strip_field` restrictions are applied before signing (`promote_attestation_transformed`). Pinned `CONSENT_GRAMMAR_HASH = 2064b567c60062fe9583ea983224d977db7440c8d240d6902a2db50e3e157d05`.
- New directory methods `list_live_consent_grants_by`, `list_local_tier_attestations`, `set_attestation_cohort_scope`.
- Since-cursor bulk reads for the five primary signed planes: `list_signed_key_records_since`, `list_signed_identity_occurrences_since`, `list_signed_transport_destinations_since`, `list_attestations_since` (federation-tier only, cursored on `COALESCE(promoted_at, asserted_at)`), `list_signed_identity_occurrence_revocations_since`.
- `lookup_signed_record_by_content_hash(kind, hash)` point-reads a signed record by its wire hash, backed by migration `V111` (`signed_wire_index`); `rebuild_signed_wire_index()` backfills.

## [21.1.0] - 2026-07-24

- Signed since-cursor bulk reads for the keyless planes: `list_signed_families_since`, `list_signed_communities_since`, `list_signed_location_proofs_since`, `list_signed_family_membership_revocations_since`, `list_signed_community_membership_revocations_since`. They return the signed wrapper byte-exact and only rows carrying an authority signature; available on all backends, the directory capsule and Python.

## [21.0.0] - 2026-07-25

### Changed

- Replication admission is CEG-driven: state changes only through a hybrid-verified claim by a signer resolved from this node's own directory. `federation::replication_policy` gives every `EnvelopeKind` a `KindPolicy` by exhaustive match, with trust roots as `SignerSource` variants; pinned as `REPLICATION_POLICY_MANIFEST` / `REPLICATION_POLICY_HASH`.
- `put_revocation` verifies the scrub signature against the revoking key's registered pubkeys.
- A freshly replicated peer key passes the hybrid proof-of-possession gate.
- Keyless declarations (`Family`, `Community`, membership revocations, `LocationProof`) must carry and verify an authority signature, persisted in migration `V110`. `put_family_json` / `put_community_json` self-sign when no signature is supplied (`Engine::put_{family,community}_self_signed`).
- Trust-root walks ignore non-federation-tier rows.
- `list_consent_peers` folds `withdraws` / `recants`, so a revoked consent peer stops receiving replication.
- A replicated `trace:complete:v1` attestation materialises its `trace_events` rows, so mesh-delivered traces are scorer-readable.

### Adoption

- **Breaking:** the three operational `put_*` trait methods and their Python verbs drop the caller-supplied roster parameters; the steward roster resolves from this node's registered keys.
- Producers must sign `Signed{Family,Community,…}` with `authority_key_id` and a hybrid signature, or persist refuses them.
- Cross-repo pins: `REPLICATION_POLICY_HASH`, `ENVELOPE_VOCABULARY_SHA256`, `TRACE_SUMMARY_EXTRACTION_SHA256`, `WIRE_VOCABULARY_HASH`.

## [20.1.0] - 2026-07-24

- `TraceSummary.agent_key_id` carries the emitter's registered federation `key_id` (the key that signed the trace); it is `None` only for `TrustPreVerified` relay corpora whose producer has not federated. Additive serde field, both backends.
- `Engine::backfill_trace_attestations` (and its Python verb) mints the envelope-native `scores` attestation for every pre-18.0 trace that has projection rows but no attestation, using the same deterministic `trace_attestation_id` as the live mint so backfill and replay converge; unregistered producers are skipped with per-item accounting in `TraceBackfillReport`.
- `get_trace_detail`, `fetch_trace_events_page` and feature/classification enrichment are projection-pinned: they read the projection, and the signed envelope is never mutated.

## [20.0.0] - 2026-07-24

- The two opaque `serde_json::Value` boundary payloads are replaced by typed contracts whose serde names are the projection paths, so cross-boundary field drift is a build or test failure.
- `federation::envelope::EnvelopeCore` types the universal attestation envelope keys (`dimension`, `references_attestation_id`, `scope`, charter fields, `withdrawal_reason`); dimension-specific payload rides a lossless flattened `extra`. Every SQL read and Rust accessor of a universal key reads through one `paths` constant.
- The `consent:*` dimension prefixes are single-sourced (`federation::consent::consent_dimension`) and used by the revocation SQL.
- `ENVELOPE_VOCABULARY_SHA256` is pinned and served by the Python `envelope_vocabulary` verb, for `/v1/health` beside the other contract hashes.
- Typed per-event trace payload structs (`ThoughtStartPayload`, `DmaResultsPayload`, `IdmaResultPayload`, `ConscienceResultPayload`, `ActionResultPayload`) back the extraction manifest; sqlite and postgres are tested to produce equal scoring feature matrices.
- Opaque blobs (`PeerPolicyBlob`, scope blobs, `registration_envelope`, operational `signed_envelope`) stay untyped by design.

### Adoption

- **Breaking:** `EmitAttestationInput.attestation_envelope` and `LocalAttestationInput.attestation_envelope` are now `EnvelopeCore`; Rust producers construct envelopes instead of spelling JSON keys. The wire/FFI JSON shape and stored rows are unchanged.
- Hosts should serve `envelope_vocabulary().sha256` and `trace_summary_extraction().sha256` on `/v1/health`; `TRACE_SUMMARY_EXTRACTION_SHA256` is unchanged by this release.

## [19.2.0] - 2026-07-24

- `Engine::self_enc_pubkeys()` (LocalSigner, Engine and Python verb) returns the node's x25519 + ML-KEM-768 content-tier self-encryption pubkeys, derived from the engine's own signing seed via `ciris_crypto::self_enc`, so the published encryption key always matches the decrypting key. Hardware-custodied identities refuse with `SelfEncRequiresSoftwareSeed`.
- `trace_summary_contract` is the single extraction manifest shared with the emitter; both backends derive their SELECT from it. Exposed as `extraction_manifest_json()`, the pinned `TRACE_SUMMARY_EXTRACTION_SHA256`, and the Python `trace_summary_extraction` verb.
- `task_description` extraction is now gated to the `detailed` trace tier.

## [19.1.1] - 2026-07-23

- Requires ciris-verify 10.6.1, whose `INFRA_SCOPES` matches persist's RC3 delegation-scope vocabulary (the `hold_*_membership` tokens; `infra:join_communities` retired). Python Requires-Dist range unchanged.
- A differential test now fails persist CI if persist's and verify's infra scope vocabularies differ.
- Internal: Android NDK CI provisioning hardening.

## [19.1.0] - 2026-07-23

- `federation::genesis::{GenesisBundle, bake_assembled_genesis, verify_bundle_quorum, GenesisBakeReport}`, `Engine::bake_assembled_genesis` and its Python verb land a genesis ceremony artifact. The holder quorum is verified against this node's own roster and directory (hybrid Ed25519 + ML-DSA-65 over the `authorization_digest`, threshold at least a strict majority of the roster); bundle-carried holder records are never the authority.
- `FederationDirectory::adopt_genesis_reanchor` is the only path that replaces an anchored canonical record; it re-verifies the quorum and requires an identical pubkey and a strictly newer `valid_from`. Re-baking is a no-op, a saved artifact can be imported after the fact, and an unverifiable bundle writes nothing (`Error::GenesisBundleInvalid`, kind `federation_genesis_bundle_invalid`).
- `canonical_seed.json` is the re-blessed 2-of-3 co-scrubbed record carrying `roles:["infra:serve"]`, so a fresh canonical receives traces; existing nodes bake the bundle to re-anchor.

## [19.0.0] - 2026-07-22

- Envelope-attested roles lift into `KeyRecord.roles` at `put_public_key` and `adopt_scrub_upgrade` (union, then gate): a lifted gated role still faces its co-scrub gate, and lifting grants visibility, never conferral.
- A root charter (`delegates_to(root -> root, infra:*)`) must carry a `pre_rotation_commitment` (sha256 of the pre-committed successor key set); a recovery declaration (`recovers` + `successor_keys`) must hash to the predecessor's commitment, and the new root must be a member. Enforced at every attestation write (`check_trust_charter_admission`, kind `federation_charter_invalid`).
- A root must self-declare both `infra:serve` and `infra:attest`, and an expired `delegates_to` edge counts as dead in the trust walk.
- Requires ciris-verify 10.6.0 (`canonical:sha256:<hex>` canonical-hash subject codec, CC 2.3.2.1).

### Adoption

- **Breaking:** `TrustRootVerdict` gains `charter_has_recovery`, and `valid` requires it.
- **Breaking:** `INFRA_JOIN_COMMUNITIES` (`infra:join_communities`) is removed, with no alias; use `INFRA_HOLD_COMMUNITY_MEMBERSHIP` (`infra:hold_community_membership`) or `INFRA_HOLD_FAMILY_MEMBERSHIP` (`infra:hold_family_membership`).

## [18.3.0] - 2026-07-21

- `capability_roots_to_trusted_root` answers whether a subject holds a delegation scope granted by a root the user trusts, returning a `TrustedGrant` (root, grant id, `TrustRootVerdict`); capsule op `CapabilityRootsToTrustedRoot`.
- `federation::accord_test_support` (behind the `test-anchor` feature) exports `Identity`, `signed_canonical_record[_with_roles]` and `register_accord_holder`, so consumers can test the `has_effective_role` allow path.
- A `canonical,node` record that also carries `roles:["infra:serve"]` passes the 2-of-3 canonical admission gate and reads both roles as effective.

## [18.2.0] - 2026-07-20

- `federation::trust_root::trust_root_valid` (capsule op `DirectoryOp::TrustRootValid`) is the shared trust-root predicate: a live `delegates_to(user -> root)` with `root != user`, a root self-declaration carrying `infra:attest`/`infra:serve`, an `accord:lifecycle:v1` attestation within `ACCORD_LIFECYCLE_FRESHNESS_DAYS` (90), and no latched accord halt. It returns a per-check `TrustRootVerdict`; a `withdraws`/`recants` tombstone makes an edge absent.
- Self-root attestations and self-referential root delegations admit; delegation scope tokens are distinct from the co-scrub-gated `infra:attest` key role. No new object kind.

## [18.1.0] - 2026-07-20

- `check_trace_dimension_admission` runs at every attestation write: `trace:*` rows must be self-emitted (`attesting_key_id` in `subject_key_ids`) and carry a non-empty `trace_id` and `agent_id_hash` plus exactly one of an inline `trace` or a `trace_manifest:v1` manifest. Refusal is `Error::TraceDimensionInvalid`, kind `federation_trace_dimension_invalid` (Python `ValueError`).

## [18.0.0] - 2026-07-20

- A trace is a CEG-native object: `receive_and_persist` mints one local-tier `scores` attestation per verified trace (dimension `trace:complete:v1`, self-subject, `cohort_scope = self`) before its `trace_events` projection rows land. Consent promotes it via `attestation_promote`, and replication is pure CEG state.
- The attestation id is deterministic per `trace_id`, and the local-write funnels honour a caller-supplied id with conflict-ignore, so replay creates no duplicates. `LocalAttestationInput` gains an optional `attestation_id`.
- An envelope within `MAX_ATTESTATION_ENVELOPE_BYTES` carries the trace inline; a larger trace gets a manifest envelope (content hash, byte length, component count).
- A relay (`TrustPreVerified`) ingest whose producer key is not yet in the directory skips the mint; `BatchSummary` gains `trace_attestations_minted` and `trace_attestations_skipped`.
- **Breaking:** `IngestPipeline<B>` and the ingest queue require `B: Backend + FederationDirectory`.

## [17.9.0] - 2026-07-16

- `MAX_ATTESTATION_ENVELOPE_BYTES` (1 MiB of canonical JCS bytes) is enforced first at every attestation write by `check_envelope_size_admission`; larger payloads ride a manifest envelope. Refusal is `Error::EnvelopeTooLarge { bytes, cap }`, kind `federation_envelope_too_large` (Python `ValueError`).

## [17.8.0] - 2026-07-16

- `record_announced_peer` / `list_announced_peers` (V108 `announced_peers` table, capsule ops) record LAN announces that do not root as advisory, non-canonical peers. The table is never consulted by admission, quorum or rooting; repeat announces refresh liveness, a pubkey change for the same key id is `Error::Conflict`, and admitted keys drop out of the listing.
- Gating tests pin `resolve_scores`' candidate cap and `list_scores`' page-bounded seek over the V106 index; a criterion bench covers the scores read surface.

## [17.7.0] - 2026-07-16

- `Engine.local_sign_hybrid(message)` (Python) returns `{"classical_sig", "pqc_sig"}` via `LocalSigner::sign_hybrid`, so consumers no longer hand-compose the bound hybrid rule.
- `audit/merkle_store::hash_leaf` delegates to ciris-verify's `transparency::hash_leaf`, and Ed25519 strict verification routes through `ciris_crypto::Ed25519Verifier::verify_strict`.

## [17.6.0] - 2026-07-16

- Requires ciris-verify 10.5.0 (Python floor unchanged at `>=10.0.0,<11`).
- `root_binding` delegates provenance chain cryptography to `ciris_verify_core::provenance::verify_provenance_chain_with_policy_and_terminus`; the forked chain verifier is deleted and error kinds are unchanged.

### Security

- The trust-root binding gate requires hybrid signatures (`RequireHybrid`) and rejects a classical-only provenance link (F-AV-14 / AV-8). Production genesis is already fully hybrid. No public API change.

## [17.5.2] - 2026-07-15

- Requires ciris-verify 10.3.0, whose reentrancy-safe keyring bridge fixes a `block_on` panic during mobile fold boot.
- Fixed: `list_attestations` ignored `dimension_exact`; both backends now apply it, combined with any prefix filter.
- Internal: CI disk reclaim for the wheel build.

## [17.5.1] - 2026-07-15

- No crate change from 17.5.0; 17.5.0 did not reach PyPI, so this is the first published 17.5.x release.
- Internal: CI cache-restore and release-path speedups.

## [17.5.0] - 2026-07-15

- `FederationDirectory::list_attestation_log(subject_key_id, cursor, limit)` (capsule op, ops-proxy route) is the owner-scope replication read: no caller gate, lifecycle-blind (returns superseded, withdrawn and recanted rows), byte-faithful, federation tier only.
- `resolve_scores` folds at most the newest `RESOLVE_CANDIDATE_CAP` (4096) rows and reports `candidates_truncated` in its trace; sqlite work runs on `spawn_blocking`.
- V107 adds an index on `(attesting_key_id, attestation_type, references_attestation_id)` on both backends for composer and retraction lookups.

## [17.4.0] - 2026-07-15

- V106 adds the `attestation_subjects` projection with an ordered seek index `(subject_key_id, dimension, asserted_at DESC, attestation_id)`, a generated `dimension` column, and (postgres) a GIN index on `evidence_refs`; it is backfilled and maintained on every attestation write.
- `AttestationFilter` gains `dimension_exact`, `window`, `tier` (Local/Federation/Any, default Federation), `lifecycle` (default Live) and `attester_filter` (`AttesterSet`).
- `FederationDirectory::list_scores` and `resolve_scores` (Python and capsule) run the caller gate and per-attester latest-wins fold inside persist and return `ScoresPage` / `ComposedVerdict` with a qualitative `ConfidenceBand`, contributor counts and an open `trace`. Both take a mandatory `caller_occurrence_key_id`, and gated rows are excluded from the aggregate.

## [17.3.0] - 2026-07-14

- Fixed: sealed trace delivery failed on the embedded/pyo3 path because `resolve_encryption_keys` hit an unsupported capsule call. New capsule ops `ResolveEncryptionKeys` (the whole revocation-aware lookup, run inside persist) and `ListIdentityOccurrenceRevocationsFor`.

## [17.2.0] - 2026-07-14

- Under the `test-anchor` feature, `CIRIS_TEST_TRUST_ROOT_PQC` makes the seeded test holder PQC-complete, and `CIRIS_TEST_TRUST_ROOT_SCRUB` / `CIRIS_TEST_TRUST_ROOT_SCRUB_PQC` supply verifying self-scrubs, so a node blessed by a software test root is admitted under the strict hybrid gate and roots. Production builds are unchanged.

## [17.1.0] - 2026-07-14

- New cargo feature `test-anchor` (forwards to `ciris-verify-core/test-anchor`): when verify's test-anchor override is live (`CIRIS_TESTING_MODE=true`, outside production), genesis seeds synthesized software test-root accord holders instead of the baked roster and skips the baked canonical. `effective_accord_holder_records()` selects the roster everywhere. Production builds compile the relaxation out.

## [17.0.2] - 2026-07-14

- Requires ciris-verify 10.2.0 (Python `ciris-verify>=10.0.0,<11` unchanged). No persist behaviour change.

## [17.0.1] - 2026-07-13

- Fixed: an accepted identity occurrence's `transport_binding` now projects into `transport_destinations` (`OccurrenceTransportBinding::project_route`) on all three backends, as a local derived row that does not replicate on its own, rides the occurrence's clock (`epoch = 0`), and is retired when the occurrence is revoked. No schema change.
- This is the first published 17.x release.

## [17.0.0] - 2026-07-13

- This version did not reach PyPI; use 17.0.1.
- `transport_destinations` is a superseding route table keyed by `(occurrence_key_id, transport_kind)` (V105 collapses existing duplicates). `TransportDestination` gains `epoch: u64`, and every backend guards writes on `(epoch, asserted_at)`, so an older assertion cannot clobber a newer one.
- `put_signed_transport_destination` / `verify_signed_transport_destination` authenticate replicated routes: the signed envelope is the authority, verified hybrid against the attester's pinned keys, and the signer must act for the occurrence. Retirement is a signed put with `retired_at` at a higher epoch. New capsule ops `PutSignedTransportDestination`, `ListSignedTransportDestinationsFor`.
- `identity_type::REGISTRY` and `identity_type::VERIFY` name the co-stewards of `licensure:{authority_id}` (CC 3.4.9), conferred by accord co-scrub via `check_accord_role_admission_over_roster`; `withdraw_accord_role` tombstones a role (V104); `has_effective_role(key_id, role)` (Rust and Python) re-derives conferral from the stored row. New error kinds `role_not_accord_conferred`, `role_withdrawn`.
- Fixed: postgres `list_federation_keys` returned empty `roles`.

### Adoption

- **Breaking:** the `list_signed_records` TransportDestination arm emits only `SignedTransportDestination` rows, and replication refuses a bare unsigned `TransportDestination`; local rows no longer replicate.
- **Breaking:** a `roles=[...]` claim runs the same accord-conferral gates as the scalar `identity_type` (`KeyRecord::claims_role`), so `canonical`, `infra:*` or `accord_holder` cannot be self-claimed through `roles` (CC 4.5.8.1).

## [16.1.1] - 2026-07-12

- `resolve_scoped_consent`: a non-grant consent row naming no valid scope is a blanket revocation that matches every scoped query; a grant naming no valid scope matches nothing. A newer scoped re-grant re-opens that scope.

## [16.1.0] - 2026-07-12

- `FederationDirectory::resolve_scoped_consent(target, subject, scope, qualifier, now) -> ConsentState` folds only `consent:state:*` rows naming the queried scope (and `content_class` when given), so an unrelated revocation does not close a scoped grant (CC 4.5.13).
- Requires ciris-verify 10.1.1 (no persist behaviour change).

## [16.0.0] - 2026-07-12

- Occurrence revocations are signed: `SignedIdentityOccurrenceRevocation` carries `{attesting_key_id, signed_envelope, signature}` and is hybrid-verified, and the signer must act for the identity (V103). Revocation is not terminal: `IdentityOccurrenceRevocation::revokes(occ, now)` kills occurrences asserted at or before it, and a fresh signed occurrence re-establishes. Adds `put_identity_occurrence_revocation_local`, `list_signed_identity_occurrence_revocations_for` and the routed capsule op `PutIdentityOccurrenceRevocation`.
- `infra:attest` can be withdrawn by accord quorum (`OP_WITHDRAW_INFRA_ATTEST`, `is_infra_attest_effective`) via the generic role-withdrawal table `federation_role_withdrawals` (V104).
- Wholeness witnesses are exposed on the Engine and Python: `wholeness_witness_root_hex`, `put_wholeness_witness_json`, `compare_wholeness_witnesses_json`, `list_witness_equivocations_json` (CC 6.1.1).
- `cirisnode_put_key_grant` (Python `cirisnode_put_key_grant_json`) writes epoch-keyed `(stream_id, epoch)` key grants with mandatory v2 PQC wrap (CC 5.1).
- `Engine::steward_bind_incapacity` (and Python) emits adult-incapacity guardianship bindings (CC 3.4.12).
- `list_consent_revocation_promotion_overdue` (default SLA 86400 s) flags local-tier consent revocations not promoted in time (CC 5.3.2.2).
- Aggregated-tier admission also requires `passes_multiplicity_gate`; new wire fields `max_source_multiplicity` and `mass_commitment_hex`, reject token `aggregation_meta_multiplicity` (CC 6.1.2.1.2).

### Adoption

- **Breaking:** `SignedIdentityOccurrenceRevocation` gains signature fields; unsigned revocations are refused.
- Pre-v3 aggregated tiers fail closed.
- Requires ciris-verify 10.1.0 (Python `ciris-verify>=10.0.0,<11`).

## [15.1.2] - 2026-07-12

- Requires ciris-verify 9.0.2. No API or schema change.

## [15.1.1] - 2026-07-12

- Requires ciris-verify 9.0.1. No API or schema change.

## [15.1.0] - 2026-07-11

- New module `federation::namespace` resolves replication policy from a signed envelope instead of per-object planes: `authority_for(dimension)` (over a vendored, CC-generated `namespace_registry.json`), `projection_for(cohort_scope, authority, is_tombstone)` (any withdraw or revocation projects Global), `lifetime_class`, `visibility_for` and `is_trust_root`.
- `list_signed_records(kind, subject_key_id)` reads every `ReplicatedKind` through one call (capsule op `ListSignedRecords`). No schema change.

## [15.0.0] - 2026-07-11

- `infra:attest` in `roles` is accord-conferred: `check_infra_attest_role_admission` requires a strict majority of the live accord roster to co-scrub the record, at every key write path, refusing with `Error::InfraAttestRoleNotAccordConferred` (kind `infra_attest_role_not_accord_conferred`). `is_infra_attest(key_id)` resolves it; canonical and `infra:attest` share `verify_accord_family_coscrub`.
- **Breaking:** requires ciris-verify 9.0.0 (Python `ciris-verify>=9.0.0,<10`). Consumers that build `ScrubTarget` must supply its new `roles` field.

## [14.1.0] - 2026-07-11

- `FederationDirectory::list_signed_identity_occurrences_for(identity_key_id)` (capsule op, Python `list_signed_identity_occurrences_for_json`) returns signed-put occurrences byte-exact, so a replicator can re-publish them without re-signing; trusted-local rows are omitted.

## [14.0.0] - 2026-07-10

### Security

- `put_identity_occurrence` verifies a hybrid signature over the occurrence's `signed_envelope` (via `verify_transport_binding`) before writing, enforces transport/content key separation and the RNS destination hash, rejects a typed projection that differs from the envelope, and requires the signer to act for the identity. This closes a content-encryption key substitution by a replication peer.
- Occurrences are last-signed-wins on strictly newer `asserted_at`, and `resolve_encryption_keys` excludes revoked occurrences.

### Adoption

- **Breaking:** `SignedIdentityOccurrence` gains `attesting_key_id`, `signed_envelope` and `signature`; `IdentityOccurrence` gains `transport_binding`. The wire path rejects unsigned occurrences; engine-internal writes use `put_identity_occurrence_local`. Migration V102.
- Requires ciris-verify 8.12.0.

## [13.9.1] - 2026-07-10

- Fixed: V101 drops the `transport_destinations` foreign key to `federation_keys`, so advisory bindings for not-yet-rooted keys persist across restarts.

## [13.9.0] - 2026-07-10

- `TransportDestination.binding_provenance` (`BindingProvenance::{Rooted, Advisory}`, V100, default `rooted`) records trust provenance. Competing claims for one destination are stored side by side and listed by `list_transport_destinations_by_destination()`; consumers prefer `Rooted` (CC 3.3.6.2).

## [13.8.0] - 2026-07-10

- `TransportDestination.transport_x25519_pubkey_base64` (V099) persists the transport KEX key, and `list_all_transport_destinations()` (with capsule op) reloads every binding at boot, so replication can seal after a restart.

## [13.7.0] - 2026-07-10

- A canonical record re-scrubbed with a strictly newer signed `valid_from` supersedes the stored one in place (`ReplicatedKeyPlan::Supersede`, `ReplicatedKeyOutcome::Superseded`, `supersede_canonical_record`), so a canonical address can move without re-baking or rotating keys. Admission requires the same key id and pubkey, the `canonical` role, a newer envelope `valid_from`, and the accord quorum re-verified from the node's own state.
- Fixed: the genesis canonical seed no longer fails boot when the node already holds a different anchor-scrubbed record; it supersedes or skips instead.
- Includes the 13.6.2 changes.

## [13.6.2] - 2026-07-10

- Not tagged separately; ships in 13.7.0.
- `verify_coord` derives `N_REGIONS` and `QUORUM_WRITE_THRESHOLD` from `region::ALL`; the write quorum is a replication durability floor, not an authorization vote.

## [13.6.1] - 2026-07-10

- Fixed: the baked `canonical_seed.json` carried the read-API port 4243; it is re-baked with the re-scrubbed 2-of-3 record dialing the Reticulum transport port `108.61.242.236:4242`. Same key.

## [13.6.0] - 2026-07-09

- `PyEngine.canonical_bootstrap_hints()` returns the canonical servers' signed transport hints as JSON (`key_id`, `kind`, `destination`).

## [13.5.0] - 2026-07-09

- `lookup_identity_for_occurrence` is routed through the directory capsule (`DirectoryOp::LookupIdentityForOccurrence`) and logs its outcome.
- `TransportDestination.transport_ed25519_pubkey_base64` (V098) stores the transport-tier Ed25519 key needed to prime a peer that cannot announce.
- Internal: CI deduplicates same-commit runs.

## [13.4.3] - 2026-07-09

- Requires ciris-verify 8.10.1; the Rust toolchain is pinned to exactly 1.97.0.

## [13.4.2] - 2026-07-08

- Fixed: the canonical seed upgrades a node's own self-signed row via `adopt_scrub_upgrade` (now on `FederationDirectory`) instead of aborting boot; the co-scrub gate still applies.
- Requires ciris-verify 8.10.0, which carries the RUSTSEC-2026-0204 fix (crossbeam-epoch 0.9.20).

## [13.4.1] - 2026-07-08

- Fixed: the Python `Engine` constructor now seeds the accord family and canonical server like `Engine::with_signer`, through the shared `genesis::seed_family_and_canonical`.

## [13.4.0] - 2026-07-06

- The genesis seed bakes the 2-of-3 accord-co-scrubbed canonical server record, admitted through `check_canonical_role_admission`, so a fresh install trusts it with no ceremony.

## [13.3.1] - 2026-07-06

- `Engine::with_signer_no_genesis_seed`, behind the test-only `test-genesis-seam` feature, skips the genesis seed for downstream integration tests. Production always seeds.

## [13.3.0] - 2026-07-06

- First boot seeds the entrenched `humanity-accord` family row (quorum 2/3), so `lookup_family("humanity-accord")` resolves on a fresh node.
- A family is keyless: V097 drops the `family_key_id` foreign key, and `put_family` validates that every member is a registered key.
- Fixed: the single-owner admission gate also recognises CC owner bindings marked `delegation_purpose: "owner_binding"` (CC 3.2, CC 2.4.1.2).

## [13.2.0] - 2026-07-05

- `KeyRecord.additional_scrubs: Vec<ScrubSig>` (V096) carries extra accord scrubs, and canonical admission requires a strict majority of the live accord roster, each scrub verified via `verify_quorum_policy`. Canonical withdraw and supersede thresholds derive from the live roster.
- The Engine/FFI exposes single-owner binding: a `delegation_purpose` argument on `grant_delegation`/`steward_bind`, and `owner_of`/`owner_of_json` (CC 3.2).
- `detection:*` is a reserved prefix for `lenscore_detector` keys (CC 3.4.8).
- Requires ciris-verify 8.9.0.

### Adoption

- **Breaking:** the 1-of-N canonical genesis seed is removed; a fresh node starts with no canonical servers. A single-scrub `canonical` record is refused.

## [13.1.0] - 2026-07-05

- The genesis seed bakes an A1-conferred canonical server (`canonical_seed.json`), admitted through `check_canonical_role_admission`.
- Canonical withdraw and supersede: a quorum-verified tombstone (`canonical_role_withdrawal`, V095) that canonical admission consults, so withdrawal defeats re-add over anti-entropy. Authority is re-derived from the node's own verified accord participations. Engine/FFI `withdraw_canonical_role`, `supersede_canonical`, `list_canonical_withdrawals`; errors `CanonicalRoleWithdrawn`, `CanonicalWithdrawalAuthorityInvalid`.
- `TransportHint { kind, destination }`, `KeyRecord::transport_hints()` and `Engine::canonical_bootstrap_hints()` read reachability hints from the signed registration envelope.
- `trace_events` dedup is sharded by an FNV-1a `shard_key` across `TRACE_DEDUP_SHARD_COUNT` (64) subtrees to cut index contention (V094, with backfill); dedup semantics are unchanged.
- `evidence/cc_impl.tsv` publishes the CC implementation-evidence manifest.
- Requires ciris-verify 8.8.0.

## [13.0.1] - 2026-07-04

- `apply_replicated_key_record` is a `FederationDirectory` trait method (default: first-seen insert) and a capsule op `ApplyReplicatedKeyRecord`, so `dyn` and capsule consumers reach the upgrade-aware apply. No wire or schema change.

## [13.0.0] - 2026-07-04

- Subject-side consent revocations are accepted as non-durable transit local-tier rows when their bound-hybrid signature verifies (CC 5.3.2.2); a local-tier signature bypass in `put_attestation` is closed.
- `sweep_consent_decay_once` evicts fountain content on a 14-day/90-day consent-decay clock (CC 4.4.3.5.1).
- `KeyRecord.consent_role` with `set_consent_role` / `consent_role_json`, excluded from the record hash (CC 3.4.7.2, V092).
- `detection:*` dimensions are admitted only from `lenscore_detector` keys (CC 3.4.8); reserved-prefix admission uses set membership on `identity_type` (CC 3.4.7.1).
- An age-assurance witness can graduate another subject's band via `attested_key_id`; self-graduation is rejected (CC 3.4.11-13).
- The no-moderator federate gate covers every community-reference shape, with a `check_no_moderator_federate_json` probe (CC 4.5.4).
- `install_storage_budget_v1` (V093, anti-rollback) and cache-before-pinned capacity eviction (CC 6.1.5.2).
- `apply_replicated_key_record` lets an anchor-scrubbed record upgrade a stale self-signed row over replication.
- The `canonical` identity type is accord-conferred: admitted only on an anchor-scrub-signed record, else `canonical_role_not_accord_conferred`; `is_canonical` and `list_canonical_servers` resolve it (CC 3.4.7.1).

### Adoption

- **Breaking (Rust only):** `KeyRecord` literals must add `consent_role`; `check_local_tier_eligibility` and `check_consent_record_admission` return `LocalTierDisposition`; `LocalAttestationInput` gains optional scrub-signature fields; `federation::Error` gains `CommunityHasNoModerator`, `CanonicalRoleNotAccordConferred`, `AgeAssuranceSelfEmissionRejected`; `StorageContentionError` gains `RevisionRollback`; `EvictionCandidate` gains `media_type`. Wire/JSON unchanged.

## [12.6.0] - 2026-07-04

- A node has exactly one owner (CC 1.13.3.3, CC 3.2): `check_single_node_owner_admission` refuses a second distinct owner binding (`delegates_to` with dimension `ownership:responsible_party:node:v1`) with `Error::NodeAlreadyOwned`; a same-owner refresh is idempotent and ownership transfers after withdrawal or lapse.
- `owner_of(node)` returns the single owner, or `Error::AmbiguousNodeOwner` so consumers fail closed.

## [12.5.0] - 2026-07-04

- Four-band age (`AgeBandFine`, `age_band_fine()`, `Engine.age_band_fine_json`) alongside the binary `AgeBand`.
- Capacity assurance (`capacity_assurance:{level}:{domain}:{band}:v1`, witness-only) with `capacity_state()` and `Engine.capacity_state_json` (CC 3.4.11-13).
- `check_adult_incapacity_binding` admits steward binding of an adult only under a live incapacitated capacity attestation from an independent attester, within attested domains, never over protected domains, with a `binding_legitimacy_source` and a `valid_until` of at most `T2_REVIEW_CADENCE_DAYS` (90). A lapsed binding returns the adult to self-sovereignty.
- `check_no_moderator_federate_admission` / `_apply` refuse to federate a community with no live moderator (`Error::CommunityHasNoModerator`, CC 4.5.4). The memory backend implements `list_consent_revocations`.
- A storage-budget pin never prevents revocation hard-delete (CC 6.1.5.2).

## [12.4.0] - 2026-07-04

- Python `Engine.build_storage_budget_v1`, `build_corpus_want_v1`, `verify_storage_budget_v1`, `verify_corpus_want_v1`, `storage_budget_supersedes` and `corpus_want_admits` wrap ciris-verify's signed storage-contention shapes (CC 6.1.5.2); they are verified at ingest, not stored.
- Fixed: a panic in the executor capsule's C-ABI spawn is contained instead of aborting the host.
- Requires ciris-verify 8.7.0.

## [12.3.0] - 2026-07-03

- Fixed: the Python engine caches its directory, outbound-queue, signer and executor capsules, closing a use-after-free crash in consumers. `CIRIS_PERSIST_TRACE` enables boundary tracing.
- Aggregation tiers carry a signed effective source count `n_eff` (v2 preimage); admission rejects a dominated fold below `MIN_DOMINANCE_RATIO` (0.5) with `aggregation_meta_dominated`, and version-1 tiers fail closed.
- Removed the unused vendored `openssl` and direct `bytes` dependencies.
- Requires ciris-verify 8.6.0.

### Security

- RUSTSEC-2026-0118 (hickory-proto NSEC3) is ignored: persist does not use DNSSEC validation and no patched version exists.

## [12.2.0] - 2026-07-03

- `Engine::adopt_scrub_upgrade(record)` (and Python) upgrades a node's self-signed own-key row in place to an accord-holder-scrubbed record after verifying the scrub. It refuses a pubkey change, a downgrade or re-anchor, and a missing row; `AdoptScrubOutcome::{Upgraded, AlreadyAdopted}`.

## [12.1.0] - 2026-07-03

- `FountainHeldMeta` gains `content_bytes` (bytes actually held) and `cohort_scope` (from the signed envelope; `fountain::cohort_scope_from_envelope`). No migration.

## [12.0.2] - 2026-07-03

- First boot seeds the three signed HUMANITY_ACCORD holder records (A1/B1/C1) as the rooting anchor (`seed_genesis_accord_holders`, `verify_anchor_seeded`); a node that cannot seed fails with `EngineError::GenesisSeed`.

## [12.0.1] - 2026-07-02

- Requires ciris-verify 8.5.0. No persist code change.

## [12.0.0] - 2026-07-02

### Security

- `root_binding` requires the chain terminus to be a pinned HUMANITY_ACCORD holder key, else `RootingRejection::TerminusNotInAnchor` (kind `rooting_terminus_not_in_anchor`); `accord_holder` termini qualify alongside `steward`.
- Fixed: rooting verified scrub signatures over the content hash instead of the canonical `registration_envelope` the producer signs; it now verifies over the canonical envelope and checks its hash.

### Adoption

- **Breaking:** `RootingRejection` gains `TerminusNotInAnchor`; `ProvenanceLink` gains `registration_envelope`; new `root_binding_anchored(dir, key_id, pubkey, anchor)`; `root_binding` enforces the accord anchor.
- Requires ciris-verify 8.4.0.

## [11.9.1] - 2026-07-02

- Fixed: sqlite-only builds (including mobile) no longer pull `openssl` or `tokio-postgres`; each backend feature enables its own refinery backend.

## [11.9.0] - 2026-07-01

- New `wire_vocabulary` module: `TRACE_BATCH_KIND = 0x0005_0001` (payload is canonical `schema::BatchEnvelope` JSON), `trace_batch_payload_bytes`, `PERSIST_KIND_RANGE`, `is_persist_kind()` and the pinned `WIRE_VOCABULARY_HASH`; `WIRE_VOCABULARY_KINDS.md` documents persist's kind range. DSAR stays Tier-1.

## [11.8.2] - 2026-07-01

- `DirectoryOp` gains `AddPeerRecord`, `RemovePeerRecord`, `UpdatePeerAlias`, `UpdatePeerTrust`, `UpdatePeerNotes` and `UpdatePeerPolicy`, so the ops proxy covers every directory method a cohabiting edge calls.

## [11.8.1] - 2026-07-01

- `ffi::directory_capsule::build_ops_directory` wraps a received directory capsule and executor capsule into a `Result<Arc<dyn FederationDirectory>, Error>` proxy; methods without an op return `Error::Unsupported` (kind `federation_ops_proxy_unsupported`), and a skewed ABI version is refused.

## [11.8.0] - 2026-07-01

- New cargo feature `pyo3-sqlite` builds the same Python FFI without postgres (and so without openssl); a `postgresql://` DSN is rejected with `ValueError` in that build. The `pyo3` feature and published wheel are unchanged.

## [11.7.0] - 2026-07-01

- `outbound_queue_ops_capsule` (`ciris_persist::outbound_queue_ops_v1`) and `signer_ops_capsule` (`ciris_persist::signer_ops_v1`) dispatch serialized ops inside persist's library, so a consumer built against another persist version cannot misdispatch a queue call or sign with the wrong key or algorithm. Consumers must check `OUTBOUND_QUEUE_ABI_VERSION` / `SIGNER_ABI_VERSION`.
- The raw `outbound_queue_capsule` and `keyring_signer_capsule` are deprecated.

## [11.6.1] - 2026-07-01

- Composite capsule ops `VerifyHybridViaDirectory` (hybrid verification runs inside persist; result `HybridVerify`) and `BuildDelegationGraph` complete the ABI-stable directory surface. `HybridPolicy` and `VerifyOutcome` are serde types.

## [11.6.0] - 2026-07-01

- `PyEngine::directory_ops_capsule` (`ciris_persist::directory_ops_v1`) exposes the directory as a C-ABI serialized-op dispatcher (`DirectoryOp` / `DirectoryOpResult`, `DIRECTORY_ABI_VERSION = 1`) that runs inside persist's library, fixing cross-library vtable misdispatch.
- `federation_directory_capsule` is deprecated; consumers must move to `directory_ops_capsule`.

## [11.5.0] - 2026-06-27

- Fixed: `age_self_declared:level:*` is refused on the `attestation_type` path too (CC 3.4.11).
- `age_band(directory, key) -> AgeBand { Minor, Adult, Unknown }` (Python `Engine.age_band_json`): witness `age_assurance:*` outranks self-declaration, and a self-declared adult is ignored.
- `check_user_target_steward_binding_admission` admits a `delegates_to` targeting a user only as guardianship of a proven minor by a proven adult, else `Error::UserTargetStewardBindingForbidden` (CC 3.2). A proven minor is steward-bound only through a live adult steward edge.

## [11.4.0] - 2026-06-27

- `affiliations` is the fourth rostered `cohort_scope` (`Cohort::Affiliations`), sharing community storage, membership lifecycle and CommunityDek epochs; adds `supersede_affiliations` / `supersede_affiliations_with_quorum` (CC 4.4.3.2.8).
- Python `cohort_scope_crypto_tier(cohort_scope, cohort_subkind=None)` returns the crypto tier name.

## [11.3.0] - 2026-06-27

- Dimensions `age_self_declared:level` and `age_self_declared:level:*` are refused with `self_declared_level_reserved` (CC 3.4.11).

## [11.2.0] - 2026-06-27

- Occurrences of one identity may share a derived content-encryption pubkey, and `rekey_for_newcomers` wraps the DEK once per distinct pubkey pair.
- Requires ciris-verify 8.3.0.

## [11.1.0] - 2026-06-26

- Accord live-quorum storage (V091, `accord_quorum` module, 12 `FederationDirectory` methods, all backends): `accord_proposal`, `accord_participation` (verified before write, deduplicated by pinned pubkey, server-stamped arrival), immutable `accord_decision`, `accord_active_halt` and `accord_issued_nonce`. Recovery supersede is not supported.
- Requires ciris-verify 8.2.0.

## [11.0.1] - 2026-06-26

- Requires ciris-verify 8.1.0. No API change.

## [11.0.0] - 2026-06-26

- `Engine::nodes_stewarded_by` (Python `nodes_stewarded_by_json`) lists the nodes a user stewards, the inverse of `steward_bindings_of`.
- **Breaking:** "owner" is renamed to "steward" across the steward-binding surface (CC 3.2), with no aliases: `owner_bind` is now `steward_bind`; `owner_bindings_of[_json]` is `steward_bindings_of[_json]`; `owner_binding_chain[_json]` is `steward_binding_chain[_json]`; `is_owner_bound[_json]` is `is_steward_bound[_json]`; `Error::UnownedCommunityMember` (kind `federation_unowned_community_member`) is `UnstewardedCommunityMember` (kind `federation_unstewarded_community_member`). Lease and data-recipient "owner" fields are unchanged.

## [10.7.0] - 2026-06-26

- **Breaking:** requires ciris-verify 8.0.0 (Python `ciris-verify>=8.0.0,<9`). The keyring's `tpm` feature no longer exists (TPM is a runtime plugin by default), and `libtss2-dev` is no longer a build dependency. No persist code change.

## [10.6.0] - 2026-06-26

- Python `Engine.local_derived_key_id()` returns the registered, verifiable federation key id; `local_key_id()` is the bare keystore alias.
- Requires ciris-verify 7.6.0.

## [10.5.0] - 2026-06-25

- Fixed: `emit_attestation` and `emit_attestation_self` reject `subject_key_ids` elements that are empty or contain uppercase (`federation::validate_subject_key_ids`, CC 2.6.3).

## [10.4.0] - 2026-06-25

- Python `Engine.put_community_json(payload_json)` creates a community, symmetric with `put_family_json`.

## [10.3.0] - 2026-06-25

- Fixed: `admission::check_reserved_prefix_admission` enforces reserved `attestation_type` prefixes at `put_attestation` on all backends: `accord:*` only from `accord_holder`, `system:*` and other substrate self-report prefixes per the rule table, `hard_case:*` only from `substrate_persist`, and `capacity:*` never self-emitted (`Error::CapacitySelfEmissionRejected`) (CC 3.4.1, 3.4.3, 3.4.5).

## [10.2.2] - 2026-06-25

- Requires ciris-verify 7.5.0. No persist code change.

## [10.2.1] - 2026-06-25

- Fixed: postgres `audit_log.action_type` accepts `consent_event` and `wisdom_based_deferral` (V090; no-op on sqlite).

## [10.2.0] - 2026-06-25

- Python `Engine.audit_next_chain_position(tenant_id)` (feature `cirisaudit`) returns the next `sequence_number` and `prev_hash` for building a chained audit entry.

## [10.1.2] - 2026-06-24

- Requires ciris-verify 7.4.0. No persist code change.

## [10.1.1] - 2026-06-24

- Fixed: `Engine::register_self_federation_key` stores the ML-DSA-65 pubkey and a hybrid self-signature when a PQC identity is configured, so the node's federation-tier emissions (including eviction `withdraws`) verify.

## [10.1.0] - 2026-06-24

- `federation::register::validate_registration_pubkey` refuses any `pubkey_ed25519_base64` that is not 32 bytes, at every `put_public_key` and in `verify_key_registration`.
- Fixed: `receive_and_persist` stamps the derived federation key id as `scrub_key_id`, and `Engine::local_derived_key_id` errors on a non-Ed25519 signer.

## [10.0.2] - 2026-06-24

- Fixed: the Python engine uses its Ed25519 local signer as the federation identity when the platform signer is not Ed25519, so a P-256 key is never registered as an Ed25519 pubkey.

## [10.0.1] - 2026-06-24

- Fixed: `Engine::register_self_federation_key` registers the engine's composed-signer identity under its derived key id, so `put_blob_signing` and eviction `withdraws` resolve their key reference. Blob emission errors include the underlying cause.
- **Breaking:** `register_self_federation_key` returns the derived key id (`<label>-<fingerprint>`), not the bare alias; use it as `attesting_key_id`.

## [10.0.0] - 2026-06-23

- `list_held_fountain_content`, `evict_fountain_content_to_tier` and `evict_fountain_content_hard_delete` are required `FederationDirectory` methods, so fountain consumers can work against `Arc<dyn FederationDirectory>`.
- Python `put_scope_blob(...)` / `get_scope_blob(record_id, symbol_index)` expose scope blobs.
- `reachable_under_scope_with_reasons` (free function, Engine, FFI) returns a typed `ReachabilityVerdict` (`Reachable`, `RetractedAtRoot`, `MissingScope`, `SignerUnreached`, `SubstrateUnavailable`, `NoTrustRoots`).
- `ceg_produce_canonicalize` is re-exported through `crate::verify` and `crate::prelude`.
- **Breaking:** external `impl FederationDirectory` must add the three fountain methods.

## [9.11.0] - 2026-06-23

- **Breaking:** requires CIRISVerify 7.x (all six verify crates re-pinned to 7.2.0; wheel `Requires-Dist` is `ciris-verify>=7.0.0,<8`).
- The `accord_holder` hardware-attestation gate admits FIPS YubiKey PIV holders: `platform_to_hardware_type` maps `ExternalSecureElement` to `HardwareType::ExternalSecureElement`.

## [9.10.2] - 2026-06-22

- Re-pins CIRISVerify 6.13.0 (real-hardware YubiKey PKCS#11 provisioning fixes); no change to the APIs persist consumes.

## [9.10.1] - 2026-06-22

- Re-pins CIRISVerify 6.12.0 (`ciris-keyring`'s `pkcs11` backend builds on all targets).

## [9.10.0] - 2026-06-21

- `Backend::list_held_fountain_content(publisher_key_id)` / `Engine::list_held_fountain_content` (Python `list_held_fountain_content`) lists the fountain-coded content held for a publisher, with each item's current symbol count, so a publisher can watch its content fade without fetching symbols.

## [9.9.1] - 2026-06-21

- Re-pins CIRISVerify 6.11.0 (the `accord:lifecycle:active` reactivation scope and the pinned HUMANITY_ACCORD genesis recognition root).

## [9.9.0] - 2026-06-21

- `Engine::rekey_community_member_revoke` records a community membership revocation and bumps the community DEK epoch, so later content is sealed to the remaining members only (CC 4.4.3.2.2).
- Cohort `add_member` / `revoke_member` (and so `swap_member`) emit `family_membership_change` / `community_membership_change` hard-case events, idempotent on the event id.

## [9.8.0] - 2026-06-21

- `FederationDirectory::verify_membership_quorum` composes CIRISVerify 6.9.0's `verify_membership_change`: besides the M-of-N count it now refuses a roster that seats one human under two key ids and a change whose `supersedes.prior_member_key_ids` does not match the live roster (anti-replay).
- `FederationDirectory::build_membership_change_envelope` builds the canonical membership-change payload.

## [9.7.1] - 2026-06-21

- Re-pins CIRISVerify 6.9.0 (role-agnostic `build_membership_change` / `verify_membership_change`).

## [9.7.0] - 2026-06-21

- A membership change to a `quorum:M/N` family or community must carry at least M valid hybrid member cosignatures: `FederationDirectory::verify_membership_quorum`, and `supersede_family_with_quorum` / `supersede_community_with_quorum`, which verify against the prior group and record the change envelope and signatures with the superseded version.

## [9.6.0] - 2026-06-21

- Rostered groups can be superseded and versioned: migration `V089` adds a `version` column to `federation_families` / `federation_communities` (outside `persist_row_hash`) and a version-history table; `supersede_family` / `supersede_community` change the threshold or re-baseline the roster in one transaction, and `list_group_versions` reads the history.

## [9.5.0] - 2026-06-21

- New `federation::cohort` module (`Cohort` = `self` / `family` / `community`, `RosterMember`, `GroupRef`, `RevokeSpec`) and seven default `FederationDirectory` methods that treat the three as one rostered-group surface, with parity across Postgres, SQLite and memory.

## [9.4.2] - 2026-06-21

- Re-pins CIRISVerify 6.8.0 (growable M-of-N accord family genesis).

## [9.4.1] - 2026-06-20

- Re-pins CIRISVerify 6.7.1 (accord-holder custody attestation module).

## [9.4.0] - 2026-06-20

- `Engine::emit_attestation_self` (Python `emit_attestation_self`) emits a federation-tier row about the node itself with its configured signer, so hardware-signed engines can emit.
- `emit_attestation` accepts weighted scores.

## [9.3.1] - 2026-06-20

- Re-pins CIRISVerify 6.6.1; no change to the APIs persist consumes.

## [9.3.0] - 2026-06-20

- `Engine::local_derived_key_id()`, `LocalSigner::derived_key_id()` and `LocalSigner::ed25519_public_key_bytes()` resolve a node's derived wire key id (`<label>-<fp>`), fixing writes that referenced the keystore alias instead of the `federation_keys` row.
- `emit_attestation` signs and stores a typed attestation; graph readers and enumerators are exposed over FFI, with typed `delegates_to` and moderation emit helpers.

## [9.2.2] - 2026-06-20

- Re-pins CIRISVerify 6.6.0; no change to the APIs persist consumes.

## [9.2.1] - 2026-06-19

- Re-pins CIRISVerify 6.5.0; no change to the APIs persist consumes.

## [9.2.0] - 2026-06-19

- `EncryptedKVStore` trait and `XChaChaKvStore` (feature `encrypted-kv`): an encrypted local key/value store over the bundled SQLite, with XChaCha20-Poly1305 values and HMAC-SHA3-256-blinded keys and namespaces. It is app-layer AEAD, not SQLCipher.

## [9.1.0] - 2026-06-19

- `BlobStorage::put_scope_blob`, a read path and LRU eviction store anonymous-tier scope-privacy ciphertext (CC 1.13.3); persist stores opaque bytes only, with no trust lookup or admission gate.
- Re-pins CIRISVerify 6.3.0.

## [9.0.3] - 2026-06-19

- Fixes the wheel's `Requires-Dist` to `ciris-verify>=6,<7`, matching the Cargo pin.

## [9.0.2] - 2026-06-18

- Re-pins CIRISVerify 6.2.0.

## [9.0.1] - 2026-06-18

- Re-pins CIRISVerify 6.1.1.

## [9.0.0] - 2026-06-18

- **Breaking:** federation-tier ingest requires a verified hybrid signature (CC 5.3.2.4.3) through `federation::verify_federation_tier_ingest`; requires CIRISVerify 6.0.0.
- Adds `identity_type::NODE` and the `infra:*` / `agency:*` delegation scopes (CC 3.4.7.1), the community DEK cascade with rotation on removal (CC 4.4.3.2.1, 4.4.3.2.2), and an owner-binding precondition on community membership.
- Security fixes from an adversarial review.

## [8.8.0] - 2026-06-17

- `Engine::register_federation_key(SignedKeyRecord)` is the single public admission gate for a peer's key (hybrid-verified before any store), and `Engine::deregister_federation_key(SignedRevocation)` removes it when consent is withdrawn.

## [8.7.2] - 2026-06-17

- The subject half of moderation authority is taken from signed content provenance, `subject_of(content_sha256)`, not from subject ids declared in the takedown payload; a malformed hash binds nothing.

## [8.7.1] - 2026-06-17

- Moderation, takedown and reconsideration rows are admitted only if the signer holds the duty itself or by a delegation chain from an owner-bound duty holder; the `on_behalf_of` field and its absent-means-self admit path are removed.

## [8.7.0] - 2026-06-17

- Admission enforces the `moderate` / `takedown` / `review` delegated-duty scopes through a scope-parameterized delegation walk (`delegation_scope_grants`, `check_delegated_duty_admission`).

## [8.6.0] - 2026-06-16

- Re-pins CIRISVerify 5.11.0 and handles its `EjectAggregatedTierOnly { tier }` verdict as `EjectionAction::EjectAggregatedTierOnly(u32)`, shedding one aggregation tier.

## [8.5.0] - 2026-06-16

- `ffi::pyo3::register(py, m)` registers persist's full Python surface into another crate's module; the standalone `ciris_persist` module uses it too.

## [8.4.0] - 2026-06-16

- `put_aggregated_tier` verifies `aggregation_meta` with the bound-hybrid gate before storing it; requires CIRISVerify 5.10.0.

## [8.3.0] - 2026-06-16

- Migration `V086` adds `content_aggregation`, and `put_aggregated_tier` stores an aggregate of fountain content in one transaction through the existing fountain admission gate.

## [8.2.0] - 2026-06-16

- Migration `V085` adds `wholeness_witness_corpus`, a verify-before-persist WholenessWitness store, and routes witness divergence to quorum handling.
- Fountain retention decisions are wired to the eviction path; requires CIRISVerify 5.9.0.

## [8.1.0] - 2026-06-16

- `evict_fountain_content_hard_delete(content_id, corpus_kind)` deletes every symbol of withdrawn or consent-revoked content, never consulting `retention_priority`; the manifest is kept.
- Re-pins CIRISVerify 5.8.0.

## [8.0.0] - 2026-06-16

- Fountain-coded content primitive: migration `V084` adds `content_manifest` (a signed, always-retained manifest) and its symbol table; persist stores, evicts to a tier and reads symbols, while encoding stays with the consumer. Additive, cut as a major.

## [7.2.0] - 2026-06-15

- **Breaking:** under `VerifyMode::Full`, ingest verifies the per-trace envelope signature as Ed25519 + ML-DSA-65 (`verify_trace_hybrid`, strict); migration `V083` adds nullable `signature_ml_dsa_65`, `pubkey_ml_dsa_65`, `pqc_key_id` to `trace_events`.

## [7.1.0] - 2026-06-15

- `Engine::with_hardware_signer_hybrid` signs hybrid (Ed25519 + ML-DSA-65) while the Ed25519 key stays sealed in the TPM or secure enclave.
- `local_identity_aggregate` works for a hardware-signed engine.

## [7.0.0] - 2026-06-15

- **Breaking:** removed the unimplemented `Backend` stubs `append_audit_entry`, `record_correlation`, `upsert_task`, `try_claim_shared_task`, `add_graph_node`.
- TimescaleDB is removed; the scoring rollup works the same on plain Postgres and SQLite.
- Adds a GDPR Art. 17 trace-erasure primitive.

## [6.8.2] - 2026-06-14

- Re-pins CIRISVerify 5.6.0 (security-audit remediation release).

## [6.8.1] - 2026-06-14

- Fixes the no-backend build under `-D warnings`.

## [6.8.0] - 2026-06-14

- Scoring-factor rollup (migration `V079`) and a streaming aggregate for `aggregate_scoring_factors_batch`.
- Disk pressure: an operator cache-size knob and proactive pressure handling.

## [6.7.2] - 2026-06-14

- Re-pins CIRISVerify 5.4.0.

## [6.7.1] - 2026-06-14

- `build_delegation_graph` reads array-shaped delegation `scope`, so self-at-login delegations appear in the graph.

## [6.7.0] - 2026-06-14

- Membership removal emits the membership-change hard-case event; a `consent_record` admission gate admits consent rows; no migration.
- Re-pins CIRISVerify 5.3.1.

## [6.6.1] - 2026-06-14

- Re-pins CIRISVerify 5.3.0.

## [6.6.0] - 2026-06-14

- `Engine::with_hardware_signer(signer, dsn)` builds an engine whose federation signing key stays in TPM, Secure Enclave or StrongBox.

## [6.5.0] - 2026-06-13

- Self-at-login substrate: one `Engine` flow that partners an app and an agent as two occurrences of one identity sharing a Self DEK, with delegation at login.

## [6.4.0] - 2026-06-13

- The `withdraws` admission gate enforces subject authority, so a subject can withdraw a row about them.

## [6.3.0] - 2026-06-13

- `Engine::list_attestations` and `Engine::list_takedowns_for` (with `TakedownFilter`) expose federation reads for multimedia detectors.

## [6.2.0] - 2026-06-13

- Adding a device or family member re-wraps existing at-rest content keys to the newcomer (`rekey_self_occurrence_add`, `rekey_family_member_add`); `add_family_member` grows a family roster.

## [6.1.0] - 2026-06-13

- Python `Engine.set_retention` / `get_retention` / `list_retention` / `run_retention`, with JSON shapes that keep u64 byte values exact.
- An injection-gate rejection is a permanent error, not retryable.

## [6.0.1] - 2026-06-13

- **Breaking:** pyo3 0.28 to 0.29; MSRV 1.83. Clears RUSTSEC-2026-0176 and RUSTSEC-2026-0177.

## [5.9.0] - 2026-06-13

- Pressure-gated retention: `set_retention` / `get_retention` / `list_retention` / `run_retention` and migration `V076` `retention_policies`; rows younger than `min_keep_secs` are never deleted, and the sweep runs only above the pressure trigger.
- Re-pins CIRISVerify 5.2.0.

## [5.8.0] - 2026-06-13

- `FederationDirectory::run_consent_sla_watch` emits hard-case signals when a producer keeps using content after a subject revoked consent; `list_consent_revocations(since)` lists revocations.

## [5.7.0] - 2026-06-13

- Migration `V075` `hard_case_events` with `record_hard_case` / `list_hard_case_events`, and `FederationDirectory::resolve_consent_state`, which returns a subject's effective consent stance (latest unexpired `consent:state:*`).

## [5.6.0] - 2026-06-12

- `SharedInstanceLease`: cross-process leader election (`try_acquire_shared_instance`, `heartbeat_shared_instance`, `lookup_shared_instance_lease`, `release_shared_instance_lease`) so one worker owns the shared network sockets.

## [5.5.5] - 2026-06-12

- Re-pins CIRISVerify 5.1.3.
- Raises the Postgres stack floors for RUSTSEC-2026-0178, RUSTSEC-2026-0179 and RUSTSEC-2026-0180.

## [5.5.4] - 2026-06-12

- Traces carrying a deferral component no longer fail to seal: adds `ComponentType::DeferralRouted`, and `ComponentType::Unknown` takes unknown variants.
- Adds a Windows wheel.

## [5.5.3] - 2026-06-12

- `PostgresBackend` retries a failed connection acquisition up to four times with short backoff.

## [5.5.2] - 2026-06-11

- cargo-deny ignores RUSTSEC-2026-0177 (pyo3 `new_closure`, an API persist does not use).
- Builds on Windows (`shutdown_signal` and one other Unix-only site are cfg-split).

## [5.5.0] - 2026-06-11

- `Engine::local_identity_aggregate` accepts caller-supplied transport pubkeys (`transport_x25519_b64`, `transport_ed25519_b64`, both or neither) and refuses a transport x25519 equal to the content-KEM key.

## [5.4.0] - 2026-06-11

- `federation::identity_aggregate::LocalIdentityAggregate` (version 1) returns the node's signing, content-KEM and transport keys in one call.

## [5.3.0] - 2026-06-11

- `aggregate_scoring_factors_batch` is cached (LRU + TTL); `ScoringFactorAggregate` gains `evaluated_at_unix_ms` and `cache_hit`.

## [5.2.0] - 2026-06-10

- Migration `V072`: `put_partner_record` keeps the steward signature set and threshold, so a partner record can be re-emitted byte-identically.

## [5.1.1] - 2026-06-10

- CI-only fix; the library is identical to 5.1.0.

## [5.1.0] - 2026-06-10

- Migration `V071` adds organizations, org memberships and partner records with `put_organization` / `put_org_membership` / `put_partner_record`, each checking clock skew, signature and quorum before admission.

## [5.0.0] - 2026-06-10

- The agent-facing local-tier attestation surface is complete: adds Python `attestation_upsert_local_many` / `attestation_insert_local_many` for batched local writes.

## [4.15.0] - 2026-06-09

- **Breaking:** signing canonicalization switches to RFC 8785 JCS; verification uses JCS for signed trace schema version 3.0.0 and later.

## [4.14.0] - 2026-06-09

- At-rest encryption for `self` / `family` content: a per-write AES-256-GCM DEK wrapped to each recipient as a key grant; migration `V070` adds `federation_blob_key_grants` and `federation_content_master`.

## [4.13.0] - 2026-06-10

- Migration `V069` adds nullable `pubkey_x25519_base64` and `pubkey_ml_kem_768_base64` to `federation_identity_occurrences`, so content keys can be wrapped to recipients.

## [4.12.1] - 2026-06-10

- The cdylib embeds `CIRIS_PERSIST_BUILD_VERSION` (`"ciris-persist <version>"`), which survives stripping.

## [4.12.0] - 2026-06-10

- `CryptoTier` classifies `cohort_scope` into `InvisibleEncrypted`, `CommunityDek` or plaintext tiers for at-rest encryption.

## [4.11.0] - 2026-06-09

- Geographic communities: `put_community` checks every member's location proof against the community's H3 cell; adds `communities_containing`.

## [4.10.0] - 2026-06-09

- Migration `V068` adds `federation_location_proofs`; location claims are limited to H3 resolution 7 or coarser.

## [4.9.0] - 2026-06-09

- Python `Engine.attestation_promote(attestation_id)` promotes a local-tier row to federation tier.

## [4.8.0] - 2026-06-09

- Migration `V067` adds append-only revocation tables for identity occurrences, family memberships and community memberships; a revoked member loses read access.

## [4.7.0] - 2026-06-09

- `register_public_key` returns `{status, key_id, existing_key_fingerprint?}` with status `registered`, `already_registered` or `rotation_collision`; a same-key-id, different-pubkey registration is reported instead of silently ignored.

## [4.6.1] - 2026-06-09

- Re-pins CIRISVerify 5.0.0.

## [4.6.0] - 2026-06-09

- `JcsCanonicalizer` (RFC 8785) and a signed-epoch version gate; `Engine::attestation_promote`.
- Fixes a Postgres UUID serialization bug on the deferred-PQC completion path.

## [4.5.0] - 2026-06-09

- `AttestationFilter` gains query fields, including prefix-matched `dimension_prefixes`.

## [4.4.0] - 2026-06-08

- Local-tier attestation writes and a tier-aware read gate on `federation_attestations`; requires CIRISVerify 4.11.0.

## [4.3.0] - 2026-06-07

- Streaming epoch-DEK `key_grant` cascade with `wrap_algorithm: v2` (PQC); v1 grants are refused at ingest. Requires CIRISVerify 4.10.0.

## [4.2.0] - 2026-06-07

- Streaming: `put_delivery_receipt` records hybrid-signed delivery receipts.

## [4.1.0] - 2026-06-06

- Streaming substrate (streams, epochs, chunks); requires CIRISVerify 4.8.1.

## [4.0.1] - 2026-06-06

- Fixes the pyo3 build with no backend feature.

## [4.0.0] - 2026-06-05

- **Breaking:** the Data Access Surface: a scope-aware read/write API where each row carries its `cohort_scope` and target, with write-side admission and migration `V060`. No aliases for the old API.

## [3.14.3] - 2026-06-05

- Internal: Postgres merkle-store test fixture fix.

## [3.14.2] - 2026-06-05

- Internal: SQLite merkle-store test fixture fix.

## [3.14.1] - 2026-06-05

- Internal: clippy fixes after the `parking_lot::Mutex` switch.

## [3.14.0] - 2026-06-04

- The SQLite backend runs synchronously inline (no `spawn_blocking`, `parking_lot::Mutex<Connection>`), fixing failures when persist is driven through the executor capsule.

## [3.13.0] - 2026-06-04

- **Breaking:** `executor_capsule`, an ABI-stable C vtable, replaces `runtime_handle_capsule`.

## [3.12.2] - 2026-06-04

- Adds the `debug-tools` feature (off by default) and a migration-timing log.

## [3.12.1] - 2026-06-04

- Fixes the Postgres `V059` partial index, which used `NOW()` and was rejected.

## [3.12.0] - 2026-06-04

- Migration `V059`: identity occurrence (devices and agents that are the same identity) and family tables.

## [3.11.0] - 2026-06-04

- Migration `V058`: per-revocation propagation observation and a deterministic three-tier quorum-write merge with anti-rollback admission.

## [3.10.0] - 2026-06-03

- Re-pins CIRISVerify 4.8.0; no API change.

## [3.9.3] - 2026-06-01

- `FederationKeyFilter.cohort_scope` filters `list_federation_keys` by peer cohort.

## [3.9.2] - 2026-06-01

- `self` / `family` content never emits a `holds_bytes` attestation (`cohort_scope::suppresses_holds_bytes`).

## [3.9.1] - 2026-06-01

- `admission::check_cohort_scope` refuses a `cohort_scope` outside `{self, family, community, affiliations, species, biosphere, federation}`.

## [3.9.0] - 2026-05-31

- Migration `V056`: `federation_attestations.cohort_scope` (default `federation`) plus consent-record, canonical-binding and SLA-watcher tables.

## [3.8.0] - 2026-05-31

- Re-pins CIRISVerify 4.7.1 and exposes five verify surfaces on the Python `Engine`.

## [3.7.0] - 2026-05-31

- Migration `V055`: `subject_key_ids` and `withdraws_admission_rule` on `federation_attestations`.

## [3.6.9] - 2026-05-30

- Re-pins CIRISVerify 4.4.3 and adds a macOS check that the wheel does not bundle libsqlite3.

## [3.6.8] - 2026-05-30

- Every signing Python method prefers the in-memory local signer, fixing `evict_actor_json` on locked-keychain hosts.

## [3.6.7] - 2026-05-30

- CI-only re-roll of 3.6.6; functionally identical to 3.6.5.

## [3.6.6] - 2026-05-30

- This version did not reach PyPI; use 3.6.7.
- CI-only: restores the build-manifest gate for the M-of-N steward key.

## [3.6.5] - 2026-05-30

- Python `put_blob_signing` uses the in-memory local signer, removing the per-call keyring signing cost.

## [3.6.4] - 2026-05-30

- `list_holders` again returns locally held blobs regardless of TTL.

## [3.6.3] - 2026-05-29

- Ships the 3.6.2 wheel fix; auditwheel picks the manylinux tag itself.

## [3.6.2] - 2026-05-29

- This version did not reach PyPI; use 3.6.3.
- The Linux wheel excludes `libsqlite3.so.0`, fixing a crash when loaded beside another wheel; hosts must provide libsqlite3.

## [3.6.1] - 2026-05-30

- Ships the 3.5.4 and 3.6.0 changes, with the wheel check accepting the bundled libsqlite3 on macOS.

## [3.6.0] - 2026-05-30

- This version did not reach PyPI; use 3.6.1.
- Migration `V054`: two new `subject_kind` values, a `LegalBasis` split, three `NodeCoreService` queries, a perceptual-hash hook at `put_blob_signing`, a takedown handler with `MultimediaConfig`, `retire_key_grants`, `lookup_trusted_publisher_chain`, reserved dimension prefixes and five `external_content` sub-kinds.

## [3.5.4] - 2026-05-30

- Requires CIRISVerify 4.4.2 (`ciris-verify>=4.4.2,<5`); carries the 3.5.3 fixes.

## [3.5.3] - 2026-05-30

- This version did not reach PyPI; use 3.5.4.

## [3.5.2] - 2026-05-29

- Fixes a crash when persist and another wheel each bundled libsqlite3, adds `list_local_holders`, and fixes a schema-wipe race at concurrent boot.

## [3.5.1] - 2026-05-29

- Withdrawn: never reached PyPI; use 3.5.2.

## [3.5.0] - 2026-05-29

- `list_held_by` and `evict_actor` list and evict a given actor's data; opt-in canonical-form rejection validators.

## [3.4.3] - 2026-05-29

- Python type stubs cover the blob, attestation, canonicalize and `verify_hybrid` methods.

## [3.4.2] - 2026-05-29

- Re-pins CIRISVerify 4.2.0.

## [3.4.1] - 2026-05-29

- `FederationDirectory::peer_metadata_for` reads the peer policy row.

## [3.4.0] - 2026-05-29

- Replication policy: a `TrustScoring` trait, an `AdmissionGate` on blob writes, migration `V053` (`last_accessed_at`, `access_count`), an `EvictionSweeper` ranked by popularity times freshness that emits signed `withdraws`, and `ReplicationConfig`.

## [3.3.1] - 2026-05-29

- Internal: benchmark calibration.

## [3.3.0] - 2026-05-29

- `BlobStorage::put_blob_signing` (with `Engine` and Python mirrors) stores a blob and signs its `holds_bytes` envelope in one call, using persist's own canonicalizer so callers cannot sign with a mismatched one.

## [3.2.0] - 2026-05-29

- `BlackholeRules` trait and migration `V052` `blackhole_rules`: a durable per-identity transport deny-list with hit counting (`hits` is excluded from `persist_row_hash`).

## [3.1.1] - 2026-05-28

- Python `put_edge_detection_event` and `local_signer_capsule()`.

## [3.1.0] - 2026-05-28

- Six `FederationDirectory` peer-management methods (`add_peer_record` and others) and migration `V051` `federation_peer_metadata` for operator-local peer metadata, with trust levels and typed errors.

## [3.0.0] - 2026-05-28

- **Breaking:** conformance to the Coherence Epistemic Graph 0.2 spec; requires CIRISVerify 4.0.0.
- Concurrent-write precedence and dedup, reserved-prefix admission rules (accepting both 0.1 and 0.2 shapes), and a 24-hour `holds_bytes` TTL with content-miss feedback.

## [2.13.0] - 2026-05-28

- Three `Engine` methods to read and subscribe to detection events, with Python readers.

## [2.12.0] - 2026-05-28

- `Engine::sign_hybrid(message)` with a typed `SignError`; the local signer now propagates to shared engines.

## [2.11.0] - 2026-05-28

- `blob_storage_capsule` exposes `BlobStorage` to sibling modules; re-pins CIRISVerify 3.9.0.

## [2.10.0] - 2026-05-28

- Typed `Goal` with `MetaGoalAlignment`, stored via migration `V050` and exposed on `FederationDirectory` and Python.

## [2.9.0] - 2026-05-28

- Re-pins CIRISVerify 3.7.0, which renames the attestation ladder (`attestation:l1:self_verify` becomes `attestation:self_verify`).
- Adds per-occurrence mandate fidelity.

## [2.8.0] - 2026-05-28

- `runtime_handle_capsule` fixes cross-cdylib runtime statics.

## [2.7.0] - 2026-05-28

- Three aggregate queries for UIs on the Python `Engine`, and capsule accessors (`federation_directory_capsule`, `outbound_queue_capsule` and one more) for sibling wheels.

## [2.6.0] - 2026-05-28

- `FederationDirectory::list_keys_by_identity_type`, `Engine::federation_directory()`, `persist_row_hash` on federation reads, and engine retention primitives.

## [2.5.0] - 2026-05-27

- An envelope-schema validation hook and hardware-attestation `attestation_evidence` on registry rows.

## [2.4.0] - 2026-05-27

- **Breaking:** the `attestation_type` vocabulary is replaced; `identity_type` is extended, and a wire-enforced admission gate is added.

## [2.3.0] - 2026-05-27

- Content-addressed `federation_blobs` (migration `V047`) with a `BlobStorage` trait; storing a blob emits a `holds_bytes:sha256:*` attestation.

## [2.2.0] - 2026-05-27

- `federation_announcement` subject kind and the `federation_delivery_attestations` table; `list_contributions` gains filters.

## [2.0.2] - 2026-05-22

- Fixes the wheel's `Requires-Dist` to CIRISVerify 3.x.

## [2.0.1] - 2026-05-22

- Rust accessors on the Python `Engine` so a sibling cdylib can share its backend; `lookup_grant_id_by_chain_event` is tenant-aware.

## [2.0.0] - 2026-05-22

- **Breaking:** requires CIRISVerify 3.0.1. The federation surface is stable; adds relay skip-verify and `audit_service()`, with concurrency hardening across substrates.

## [1.13.0] - 2026-05-22

- `current_rust_engine()` returns the process-singleton `Arc<Engine>` for co-resident Rust consumers.
- **Breaking:** `Engine::signer()` changes return type; `extension-module` is its own feature.

## [1.12.0] - 2026-05-22

- `root_binding` roots a cold-start binding, and `provenance_chain` returns it for verification.

## [1.11.1] - 2026-05-22

- Migration `V042` adds covering indexes for scoring analytics.

## [1.11.0] - 2026-05-22

- `Engine::receive_and_persist` and `node_core_service()`.

## [1.10.3] - 2026-05-22

- Re-pins CIRISVerify 2.8.0 (faster secrets-at-rest AEAD).

## [1.10.2] - 2026-05-21

- `reencrypt_all` re-encrypts in bounded chunks; re-pins CIRISVerify 2.7.0.

## [1.10.1] - 2026-05-21

- `ciris_persist.reset_engine()` resets the process singleton without a handle; migration `V041` adds analytics indexes.

## [1.10.0] - 2026-05-21

- `SecretsService::migrate_to_hardware_key` moves secrets-at-rest to a hardware-backed key, auto-detected on every platform, with the crypto in CIRISVerify.

## [1.9.0] - 2026-05-21

- Change-feed subscription methods on `Engine` notify co-resident consumers of writes.

## [1.8.1] - 2026-05-21

- `audit_list_entries` accepts an empty-`last_id` cursor on Postgres.

## [1.8.0] - 2026-05-21

- SQLite implements all of `ReadEngine` and `DerivedSchema` (migration `V040`), matching Postgres.

## [1.7.6] - 2026-05-21

- Internal: test fix for Postgres-only wheels.

## [1.7.5] - 2026-05-20

- Fixes sequence and occurrence errors labelled permanent, a `close()` / `register_consumer` race, an unbounded consumer registry, and a sequence counter decode.

## [1.7.4] - 2026-05-20

- `register_consumer` validates substrate names; `Engine.substrate_owner(substrate)`.

## [1.7.3] - 2026-05-20

- `OccurrenceService`: occurrence registration and liveness heartbeats (migration `V039`).

## [1.7.2] - 2026-05-20

- The engine lifecycle exceptions are exported from the Python package.

## [1.7.1] - 2026-05-20

- An atomic per-identity monotonic sequence (migration `V038`).

## [1.7.0] - 2026-05-20

- `Engine.engine_handle()` and a consumer registry with lifecycle refcounting.

## [1.6.8] - 2026-05-20

- `Engine` is a process singleton: a second construction with a different config raises, `close()` tears it down, and forks are guarded; typed exceptions.

## [1.6.7] - 2026-05-20

- SQLite validates `incident_id` / `metric_id` as UUIDs, as Postgres does.

## [1.6.6] - 2026-05-20

- Legacy graph migration maps a non-UUID `edge_id` to a deterministic UUID.

## [1.6.5] - 2026-05-20

- `run_legacy_graph_migration` handles `timestamp without time zone` columns; `LegacyMigrationStats` gains `first_error_message`.

## [1.6.4] - 2026-05-19

- `run_legacy_graph_migration` imports the agent's legacy graph.

## [1.6.3] - 2026-05-19

- `task_upsert` / `thought_upsert` keep a caller-supplied `created_at` on update.

## [1.6.2] - 2026-05-19

- Task, conversation, trace and audit summary rollups on `TelemetryService`, read through `query_summary_nodes`.

## [1.6.1] - 2026-05-19

- `NodeFilter.attribute_match` filters graph nodes by JSON-path equality or array containment, with an injection guard on the path.

## [1.6.0] - 2026-05-19

- Telemetry period queries, pruning and edge histograms on both backends.

## [1.5.25] - 2026-05-19

- Graph `NodeExcludeRule`, `count_nodes`, `count_edges` and `count_nodes_by_type`.

## [1.5.24] - 2026-05-19

- `secrets_store_detected_secret`.

## [1.5.23] - 2026-05-19

- `ServiceTokenRevocationService` (migration `V037`) stores revoked service tokens, replacing the agent's separate SQLite file.

## [1.5.22] - 2026-05-19

- Migration `V036` adds a partial unique index so a task with the same `correlation_id` is not duplicated.
- **Breaking:** `task_upsert` returns an outcome envelope.

## [1.5.21] - 2026-05-19

- `task_list` / `thought_list` accept `created_before` / `created_after`.

## [1.5.20] - 2026-05-19

- `thought_delete(thought_id)`, and deleting a task deletes its thoughts (migration `V035`).

## [1.5.19] - 2026-05-18

- `WaCertService` (seven methods) stores WA certificates.
- The agent's whole engine database is now held by persist: eleven substrates added from 1.5.9 to 1.5.19.

## [1.5.18] - 2026-05-18

- `FeedbackMappingService` (migration `V033`).

## [1.5.17] - 2026-05-18

- `ContinuityAwarenessService`, keyed to graph nodes by a composite foreign key.

## [1.5.16] - 2026-05-18

- `CreationCeremonyService` (migration `V031`) records identity-creation ceremonies.

## [1.5.15] - 2026-05-18

- `MaintenanceLockService`: generic maintenance locks with expiry that behaves the same on both backends.

## [1.5.14] - 2026-05-18

- `DeferralReportService` (migration `V029`).

## [1.5.13] - 2026-05-18

- `TicketService` (migration `V028`).

## [1.5.12] - 2026-05-18

- `ScheduledTaskService` (migration `V027`).

## [1.5.11] - 2026-05-18

- `CorrelationService` stores service correlations and metrics.

## [1.5.10] - 2026-05-18

- `ThoughtService` (migration `V025`).

## [1.5.9] - 2026-05-18

- `TaskService` and typed `Task`, the first agent table stored by persist so only persist opens the engine database.

## [1.5.8] - 2026-05-18

- SQLite supports `get_classifications` and `get_features` and their write paths (migration `V023`).

## [1.5.7] - 2026-05-18

- `SecretsService::process_incoming_text` runs the full detection pipeline.

## [1.5.6] - 2026-05-18

- A clearer error when graph node attributes fail UTF-8 decoding.

## [1.5.5] - 2026-05-17

- Migration `V022` adds nullable incident fields and extends the incident enums.

## [1.5.4] - 2026-05-17

- Python helpers return the audit chain's canonical bytes, and a bridge entry is permitted in the audit chain.

## [1.5.3] - 2026-05-17

- `register_federation_key` builds and stores a signed key record in one call.

## [1.5.2] - 2026-05-17

- Re-pins CIRISVerify 2.4.0 (`load_steward_seed` renamed `load_local_seed`).

## [1.5.1] - 2026-05-17

- Every Python method works on SQLite; none panics for want of Postgres.

## [1.5.0] - 2026-05-16

- **Breaking:** trust grants are signed contribution events on the audit chain with per-tenant Merkle transparency (migration `V021`); nine new `Engine` methods and a `TrustPurpose` enum. The old API is removed without aliases.

## [1.4.0] - 2026-05-16

- **Breaking:** API rename with no aliases; the federation surface works on SQLite.

## [1.3.3] - 2026-05-16

- Fixes the 1.3.2 wheel build.

## [1.3.2] - 2026-05-16

- `bulk_import` mode for graph writes and a typed `AttributesTooLarge` error.

## [1.3.1] - 2026-05-16

- Documents the audit-chain bridge and preserves caller timestamps on graph import.

## [1.3.0] - 2026-05-15

- Trust hierarchy types (`TrustType`, `TrustRelationship` and others, migration `V020`) with role-tag enforcement.

## [1.2.1] - 2026-05-15

- Fixes the Postgres maintenance operations.

## [1.2.0] - 2026-05-15

- Database maintenance operations (vacuum, archive expired rows) with retention defaults.

## [1.1.2] - 2026-05-15

- `ReasoningEventType::Unknown` accepts unknown event types; re-pins CIRISVerify 2.1.5.

## [1.1.1] - 2026-05-15

- Fixes the build with no features.

## [1.1.0] - 2026-05-14

- A polymorphic `Pipeline`, substrate constructors independent of `Engine`, a `POST /api/v1/pipeline/ingest` route, secrets-server routes and `FederatedSecretsClient`.

## [1.0.3] - 2026-05-14

- Fixes the Python re-export of the typed exceptions.

## [1.0.2] - 2026-05-14

- Internal: Python smoke-test fix.

## [1.0.1] - 2026-05-14

- The first usable 1.x wheel on PyPI; fixes migration `V019`.

## [1.0.0] - 2026-05-14

- Every agent service bound for persist is reachable from the wheel on both backends.

## [0.9.4] - 2026-05-14

- `NodeCoreService` on SQLite.

## [0.9.3] - 2026-05-13

- `SecretsService` on SQLite.

## [0.9.2] - 2026-05-14

- CI registers a build manifest for each of four targets.

## [0.9.1] - 2026-05-14

- Re-pins CIRISVerify 2.0.5.

## [0.9.0] - 2026-05-13

- Six agent services on both SQLite and Postgres, with iOS build hardening.

## [0.8.7] - 2026-05-13

- `IncidentService` on SQLite.

## [0.8.6] - 2026-05-13

- `TelemetryService` on SQLite.

## [0.8.5] - 2026-05-13

- `AuditService` on SQLite, with the same hash-chain rules.

## [0.8.4] - 2026-05-13

- The graph service on SQLite; rusqlite is conditional on iOS.

## [0.8.3] - 2026-05-13

- `IncidentService`: incident records with correlation-keyed dedup.

## [0.8.2] - 2026-05-13

- `TelemetryService`: telemetry and time-series consolidation on Postgres.

## [0.8.1] - 2026-05-13

- `AuditService`: a hash-chained audit log with a per-tenant monotonic `sequence_number` and SHA-256 `prev_hash`.

## [0.8.0] - 2026-05-13

- The graph service (`cirisgraph`): nodes and edges on Postgres with recursive-CTE traversal.

## [0.7.5] - 2026-05-13

- A pipeline orchestrator and `PipelineEnvelope` wire types.

## [0.7.4] - 2026-05-13

- `receive_and_persist` runs feature extraction.

## [0.7.3] - 2026-05-13

- Republishes 0.7.2 to PyPI after a macOS build failure.

## [0.7.2] - 2026-05-13

- A canonical-promotion attestation sets `is_canonical` on contributions and votes.

## [0.7.1] - 2026-05-12

- `verify_envelope_signature` verifies envelope signatures cryptographically.

## [0.7.0] - 2026-05-12

- **Breaking:** stores the six federation-consensus row classes (Contribution, Vote and others).

## [0.6.1] - 2026-05-12

- A federated `SecretsService` behind its own feature flag.

## [0.6.0] - 2026-05-12

- A post-ingest scrub, extract and classify pipeline with per-stage Cargo features.

## [0.5.8] - 2026-05-12

- `put_revocation` and `put_attestation` bind ids as UUIDs, fixing rejected writes on Postgres.

## [0.5.7] - 2026-05-12

- Internal: test fixture fix.

## [0.5.6] - 2026-05-12

- Internal: test fixture fix.

## [0.5.5] - 2026-05-11

- Federation reads: task-grouped trace listing, LLM call reads, corpus shape, scrub observability and bulk federation observability.

## [0.5.4] - 2026-05-11

- Every Postgres row read uses `PgRowExt::safe_get`, and every FFI call catches panics.

## [0.5.3] - 2026-05-11

- Panics unwind instead of aborting and are returned to Python as `LensQueryError`; re-pins CIRISVerify 2.0.2.

## [0.5.2] - 2026-05-11

- Re-pins CIRISVerify 2.0.0.

## [0.5.1] - 2026-05-11

- `aggregate_scoring_factors` no longer panics on an empty baseline window.

## [0.5.0] - 2026-05-10

- Federation read primitives on `ReadEngine` and Python: trace listing, trace detail, coherence ratchet inputs and scoring factor aggregates.

## [0.4.7] - 2026-05-09

- Documentation only: threat model updates.

## [0.4.6] - 2026-05-09

- Legacy traces take `attempt_index` by schema version; ingest separates schema errors from store errors, and `IngestError::detail()` names the field.

## [0.4.5] - 2026-05-09

- Re-pins CIRISVerify 1.13.2.

## [0.4.4] - 2026-05-08

- Internal: CI fixes and git hooks.

## [0.4.3] - 2026-05-08

- `DerivedSchema` trait (migration `V008`) for lens-derived schemas, and restored ingest of 2.7 legacy traces.

## [0.4.2] - 2026-05-03

- `signing::StewardSigner` is public Rust API.

## [0.4.1] - 2026-05-03

- Public Rust `verify::verify_hybrid_via_directory`, `verify::canonicalize_envelope_for_signing`, `verify::body_sha256`, and a `ciris_persist::prelude`.

## [0.4.0] - 2026-05-03

- Edge outbound queue and the full verify surface on `Engine`; the `accord_public_keys` dual-read fallback is removed.

## [0.3.6] - 2026-05-03

- `Engine.verify_hybrid` verifies arbitrary canonical bytes.
- **Breaking:** DSAR deletion is scoped per key.

## [0.3.5] - 2026-05-03

- `Engine.delete_traces_for_agent` (GDPR Art. 17) and `Engine.fetch_trace_events_page` (page-cursor reads).

## [0.3.4] - 2026-05-03

- Trace schema 2.7.9 carries a deployment-profile block, strictly parsed and stored on `trace_events`.

## [0.3.3] - 2026-05-03

- LLM_CALL events link to their parent at schema 2.7.9.

## [0.3.2] - 2026-05-02

- A cold-path PQC sweep, and a read-only database role for analytical consumers.

## [0.3.1] - 2026-05-02

- Persist fills in the ML-DSA-65 signature for pending keys on the cold path.

## [0.3.0] - 2026-05-02

- **Breaking:** trace wire format 2.7.9, dispatched by schema version, with cross-shape field-injection checks.

## [0.2.4] - 2026-05-02

- Installing the wheel installs `ciris-verify>=1.8.6,<2`.

## [0.2.3] - 2026-05-02

- Re-pins CIRISVerify 1.8.5; corrects the ML-DSA-65 signature size docs.

## [0.2.2] - 2026-05-02

- Adds a second signing identity, the lens steward key, separate from the scrub key.

## [0.2.1] - 2026-05-02

- `Engine.sign(message)` and `Engine.canonicalize_envelope(envelope_json)`; `lookup_public_key` reads both the new and old key tables.

## [0.2.0] - 2026-05-02

- The federation directory (`federation_keys` and related tables) with hybrid keys: Ed25519 written immediately and ML-DSA-65 attached later through `attach_key_pqc_signature`.

## [0.1.21] - 2026-05-02

- A SQLite backend with Phase 1 parity, for sovereign and small deployments.

## [0.1.20] - 2026-05-02

- Fixes canonical-byte drift in signature verification by keeping the received bytes rather than reproducing them.

## [0.1.19] - 2026-05-02

- An attempted fix for canonical-byte drift; replaced by 0.1.20.

## [0.1.18] - 2026-05-02

- Signature mismatches log diagnostic detail.

## [0.1.17] - 2026-05-02

- Unknown-key rejections log diagnostic detail.

## [0.1.16] - 2026-05-02

- Signature decoding tries both base64 alphabets.

## [0.1.15] - 2026-05-01

- Signatures are decoded with the URL-safe base64 alphabet, fixing rejected batches.

## [0.1.14] - 2026-05-01

- Persist is the runtime keyring authority on its host; fixes a multi-worker bootstrap race.

## [0.1.13] - 2026-05-01

- Wheels for multiple architectures on PyPI.

## [0.1.12] - 2026-05-01

- Published to PyPI through OIDC trusted publishing.

## [0.1.11] - 2026-05-01

- CI registers each build.

## [0.1.10] - 2026-05-01

- Fixes the wheel platform tag.

## [0.1.9] - 2026-05-01

- Requires CIRISVerify 1.8.0: `storage_descriptor()`, `BuildPrimitive::Persist`, and CI manifest signing with `ciris-build-sign`.

## [0.1.8] - 2026-05-01

- `schema::WireDateTime` keeps timestamps canonical, fixing rejection of zero-microsecond timestamps.

## [0.1.7] - 2026-05-01

- Benchmarks, a warning when the keyring is ephemeral, and `Engine.keyring_path()`.

## [0.1.6] - 2026-05-01

- Internal: stricter CI and an MSRV pin.

## [0.1.5] - 2026-05-01

- Fixes a race when several workers construct `Engine` at once; migration errors include the SQLSTATE.

## [0.1.4] - 2026-05-01

- Internal: a QA stress harness in CI.

## [0.1.3] - 2026-05-01

- **Breaking:** the Python `Engine(...)` constructor requires `signing_key_id`. Scrubbed traces are signed, with one key for signing, identity and addressing.

## [0.1.2] - 2026-05-01

- Fixes a memory leak from unrecognized schema versions and reconciles the schema.

## [0.1.1] - 2026-05-01

- Internal: CI fixes.

## [0.1.0] - 2026-05-01

- Initial release.
